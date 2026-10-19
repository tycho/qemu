/*
 *  APIC support
 *
 *  Copyright (c) 2004-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>
 */
#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "qemu/main-loop.h"
#include "hw/core/qdev-properties.h"
#include "qemu/error-report.h"
#include "hw/i386/apic_internal.h"
#include "hw/i386/apic.h"
#include "hw/intc/ioapic.h"
#include "hw/intc/i8259.h"
#include "hw/intc/kvm_irqcount.h"
#include "hw/pci/msi.h"
#include "qemu/host-utils.h"
#include "system/kvm.h"
#include "system/mshv.h"
#include "system/physmem.h"
#include "trace.h"
#include "hw/i386/apic-msidef.h"
#include "exec/cpu-common.h"
#include "qapi/error.h"
#include "qom/object.h"
#include "hw/core/qdev-properties.h"
#include "qemu/event_notifier.h"
#include "qemu/timer.h"
#include "system/runstate.h"

#define SYNC_FROM_VAPIC                 0x1
#define SYNC_TO_VAPIC                   0x2
#define SYNC_ISR_IRR_TO_VAPIC           0x4

static APICCommonState **local_apics;
/*
 * An xAPIC ID differs from its initial one: x-posted resolves physical
 * destinations under the BQL from then on (the IDs it reads without the
 * BQL are fixed until then).
 */
static bool apic_ids_moved;
static uint32_t max_apics;
static uint32_t max_apic_words;

#define TYPE_APIC "apic"
/*This is reusing the APICCommonState typedef from APIC_COMMON */
DECLARE_INSTANCE_CHECKER(APICCommonState, APIC,
                         TYPE_APIC)

static void apic_set_irq(APICCommonState *s, int vector_num, int trigger_mode);
static void apic_update_irq(APICCommonState *s);
static void apic_get_delivery_bitmask(uint32_t *deliver_bitmask,
                                      uint32_t dest, uint8_t dest_mode);

void apic_set_max_apic_id(uint32_t max_apic_id)
{
    int word_size = 32;

    /* round up the max apic id to next multiple of words */
    max_apics = (max_apic_id + word_size - 1) & ~(word_size - 1);

    local_apics = g_malloc0(sizeof(*local_apics) * max_apics);
    max_apic_words = max_apics >> 5;
}


/* Find first bit starting from msb */
static int apic_fls_bit(uint32_t value)
{
    return 31 - clz32(value);
}

/* Find first bit starting from lsb */
static int apic_ffs_bit(uint32_t value)
{
    return ctz32(value);
}

static inline void apic_reset_bit(uint32_t *tab, int index)
{
    int i, mask;
    i = index >> 5;
    mask = 1 << (index & 0x1f);
    tab[i] &= ~mask;
}

/* return -1 if no bit is set */
static int get_highest_priority_int(uint32_t *tab)
{
    int i;
    for (i = 7; i >= 0; i--) {
        if (tab[i] != 0) {
            return i * 32 + apic_fls_bit(tab[i]);
        }
    }
    return -1;
}

static void apic_sync_vapic(APICCommonState *s, int sync_type)
{
    VAPICState vapic_state;
    size_t length;
    off_t start;
    int vector;

    if (!s->vapic_paddr) {
        return;
    }
    if (sync_type & SYNC_FROM_VAPIC) {
        physical_memory_read(s->vapic_paddr, &vapic_state,
                                 sizeof(vapic_state));
        s->tpr = vapic_state.tpr;
    }
    if (sync_type & (SYNC_TO_VAPIC | SYNC_ISR_IRR_TO_VAPIC)) {
        start = offsetof(VAPICState, isr);
        length = offsetof(VAPICState, enabled) - offsetof(VAPICState, isr);

        if (sync_type & SYNC_TO_VAPIC) {
            assert(qemu_cpu_is_self(CPU(s->cpu)));

            vapic_state.tpr = s->tpr;
            vapic_state.enabled = 1;
            start = 0;
            length = sizeof(VAPICState);
        }

        vector = get_highest_priority_int(s->isr);
        if (vector < 0) {
            vector = 0;
        }
        vapic_state.isr = vector & 0xf0;

        vapic_state.zero = 0;

        vector = get_highest_priority_int(s->irr);
        if (vector < 0) {
            vector = 0;
        }
        vapic_state.irr = vector & 0xff;

        address_space_write_rom(&address_space_memory,
                                s->vapic_paddr + start,
                                MEMTXATTRS_UNSPECIFIED,
                                ((void *)&vapic_state) + start, length);
    }
}

static void apic_vapic_base_update(APICCommonState *s)
{
    apic_sync_vapic(s, SYNC_TO_VAPIC);
}

static void apic_local_deliver(APICCommonState *s, int vector)
{
    uint32_t lvt = s->lvt[vector];
    int trigger_mode;

    trace_apic_local_deliver(vector, (lvt >> 8) & 7);

    if (lvt & APIC_LVT_MASKED)
        return;

    switch ((lvt >> 8) & 7) {
    case APIC_DM_SMI:
        cpu_interrupt(CPU(s->cpu), CPU_INTERRUPT_SMI);
        break;

    case APIC_DM_NMI:
        cpu_interrupt(CPU(s->cpu), CPU_INTERRUPT_NMI);
        break;

    case APIC_DM_EXTINT:
        cpu_interrupt(CPU(s->cpu), CPU_INTERRUPT_HARD);
        break;

    case APIC_DM_FIXED:
        trigger_mode = APIC_TRIGGER_EDGE;
        if ((vector == APIC_LVT_LINT0 || vector == APIC_LVT_LINT1) &&
            (lvt & APIC_LVT_LEVEL_TRIGGER))
            trigger_mode = APIC_TRIGGER_LEVEL;
        apic_set_irq(s, lvt & 0xff, trigger_mode);
    }
}

void apic_deliver_pic_intr(APICCommonState *s, int level)
{
    if (level) {
        apic_local_deliver(s, APIC_LVT_LINT0);
    } else {
        uint32_t lvt = s->lvt[APIC_LVT_LINT0];

        switch ((lvt >> 8) & 7) {
        case APIC_DM_FIXED:
            if (!(lvt & APIC_LVT_LEVEL_TRIGGER))
                break;
            apic_reset_bit(s->irr, lvt & 0xff);
            /* fall through */
        case APIC_DM_EXTINT:
            apic_update_irq(s);
            break;
        }
    }
}

static void apic_external_nmi(APICCommonState *s)
{
    apic_local_deliver(s, APIC_LVT_LINT1);
}

#define foreach_apic(apic, deliver_bitmask, code) \
{\
    int __i, __j;\
    for (__i = 0; __i < max_apic_words; __i++) {\
        uint32_t __mask = deliver_bitmask[__i];\
        if (__mask) {\
            for (__j = 0; __j < 32; __j++) {\
                if (__mask & (1U << __j)) {\
                    apic = local_apics[__i * 32 + __j];\
                    if (apic) {\
                        code;\
                    }\
                }\
            }\
        }\
    }\
}

static void apic_bus_deliver(const uint32_t *deliver_bitmask,
                             uint8_t delivery_mode, uint8_t vector_num,
                             uint8_t trigger_mode)
{
    APICCommonState *apic_iter;

    switch (delivery_mode) {
        case APIC_DM_LOWPRI:
            /* XXX: search for focus processor, arbitration */
            {
                int i, d;
                d = -1;
                for (i = 0; i < max_apic_words; i++) {
                    if (deliver_bitmask[i]) {
                        d = i * 32 + apic_ffs_bit(deliver_bitmask[i]);
                        break;
                    }
                }
                if (d >= 0) {
                    apic_iter = local_apics[d];
                    if (apic_iter) {
                        apic_set_irq(apic_iter, vector_num, trigger_mode);
                    }
                }
            }
            return;

        case APIC_DM_FIXED:
            break;

        case APIC_DM_SMI:
            foreach_apic(apic_iter, deliver_bitmask,
                cpu_interrupt(CPU(apic_iter->cpu), CPU_INTERRUPT_SMI)
            );
            return;

        case APIC_DM_NMI:
            foreach_apic(apic_iter, deliver_bitmask,
                cpu_interrupt(CPU(apic_iter->cpu), CPU_INTERRUPT_NMI)
            );
            return;

        case APIC_DM_INIT:
            /* normal INIT IPI sent to processors */
            foreach_apic(apic_iter, deliver_bitmask,
                         cpu_interrupt(CPU(apic_iter->cpu),
                                       CPU_INTERRUPT_INIT)
            );
            return;

        case APIC_DM_EXTINT:
            /* handled in I/O APIC code */
            break;

        default:
            return;
    }

    foreach_apic(apic_iter, deliver_bitmask,
                 apic_set_irq(apic_iter, vector_num, trigger_mode) );
}

static void apic_deliver_irq(uint32_t dest, uint8_t dest_mode,
                             uint8_t delivery_mode, uint8_t vector_num,
                             uint8_t trigger_mode)
{
    g_autofree uint32_t *deliver_bitmask = g_new(uint32_t, max_apic_words);

    trace_apic_deliver_irq(dest, dest_mode, delivery_mode, vector_num,
                           trigger_mode);

    apic_get_delivery_bitmask(deliver_bitmask, dest, dest_mode);
    apic_bus_deliver(deliver_bitmask, delivery_mode, vector_num, trigger_mode);
}

bool is_x2apic_mode(APICCommonState *s)
{
    return s->apicbase & MSR_IA32_APICBASE_EXTD;
}

static int apic_set_base_check(APICCommonState *s, uint64_t val)
{
    /* Enable x2apic when x2apic is not supported by CPU */
    if (!cpu_has_x2apic_feature(&s->cpu->env) &&
        val & MSR_IA32_APICBASE_EXTD) {
        return -1;
    }

    /*
     * Transition into invalid state
     * (s->apicbase & MSR_IA32_APICBASE_ENABLE == 0) &&
     * (s->apicbase & MSR_IA32_APICBASE_EXTD) == 1
     */
    if (!(val & MSR_IA32_APICBASE_ENABLE) &&
        (val & MSR_IA32_APICBASE_EXTD)) {
        return -1;
    }

    /* Invalid transition from disabled mode to x2APIC */
    if (!(s->apicbase & MSR_IA32_APICBASE_ENABLE) &&
        !(s->apicbase & MSR_IA32_APICBASE_EXTD) &&
        (val & MSR_IA32_APICBASE_ENABLE) &&
        (val & MSR_IA32_APICBASE_EXTD)) {
        return -1;
    }

    /* Invalid transition from x2APIC to xAPIC */
    if ((s->apicbase & MSR_IA32_APICBASE_ENABLE) &&
        (s->apicbase & MSR_IA32_APICBASE_EXTD) &&
        (val & MSR_IA32_APICBASE_ENABLE) &&
        !(val & MSR_IA32_APICBASE_EXTD)) {
        return -1;
    }

    return 0;
}

static int apic_set_base(APICCommonState *s, uint64_t val)
{
    if (apic_set_base_check(s, val) < 0) {
        return -1;
    }

    s->apicbase = (val & MSR_IA32_APICBASE_BASE) |
        (s->apicbase & (MSR_IA32_APICBASE_BSP | MSR_IA32_APICBASE_ENABLE));
    if (!(val & MSR_IA32_APICBASE_ENABLE)) {
        s->apicbase &= ~MSR_IA32_APICBASE_ENABLE;
        cpu_clear_apic_feature(&s->cpu->env);
        s->spurious_vec &= ~APIC_SV_ENABLE;
    }

    /* Transition from disabled mode to xAPIC */
    if (!(s->apicbase & MSR_IA32_APICBASE_ENABLE) &&
        (val & MSR_IA32_APICBASE_ENABLE)) {
        s->apicbase |= MSR_IA32_APICBASE_ENABLE;
        cpu_set_apic_feature(&s->cpu->env);
    }

    /* Transition from xAPIC to x2APIC */
    if (cpu_has_x2apic_feature(&s->cpu->env) &&
        !(s->apicbase & MSR_IA32_APICBASE_EXTD) &&
        (val & MSR_IA32_APICBASE_EXTD)) {
        s->apicbase |= MSR_IA32_APICBASE_EXTD;

        s->log_dest = ((s->initial_apic_id & 0xffff0) << 16) |
                      (1 << (s->initial_apic_id & 0xf));
    }

    return 0;
}

static void apic_set_tpr(APICCommonState *s, uint8_t val)
{
    /* Updates from cr8 are ignored while the VAPIC is active */
    if (!s->vapic_paddr) {
        s->tpr = val << 4;
        apic_update_irq(s);
    }
}

int apic_get_highest_priority_irr(APICCommonState *s)
{
    if (!s) {
        /* no interrupts */
        return -1;
    }
    return get_highest_priority_int(s->irr);
}

static uint8_t apic_get_tpr(APICCommonState *s)
{
    apic_sync_vapic(s, SYNC_FROM_VAPIC);
    return s->tpr >> 4;
}

int apic_get_ppr(APICCommonState *s)
{
    int tpr, isrv, ppr;

    tpr = (s->tpr >> 4);
    isrv = get_highest_priority_int(s->isr);
    if (isrv < 0)
        isrv = 0;
    isrv >>= 4;
    if (tpr >= isrv)
        ppr = s->tpr;
    else
        ppr = isrv << 4;
    return ppr;
}

static int apic_get_arb_pri(APICCommonState *s)
{
    /* XXX: arbitration */
    return 0;
}


/*
 * <0 - low prio interrupt,
 * 0  - no interrupt,
 * >0 - interrupt number
 */
static int apic_irq_pending(APICCommonState *s)
{
    int irrv, ppr;

    if (!(s->spurious_vec & APIC_SV_ENABLE)) {
        return 0;
    }

    irrv = get_highest_priority_int(s->irr);
    if (irrv < 0) {
        return 0;
    }
    ppr = apic_get_ppr(s);
    if (ppr && (irrv & 0xf0) <= (ppr & 0xf0)) {
        return -1;
    }

    return irrv;
}

/* signal the CPU if an irq is pending */
static void apic_update_irq(APICCommonState *s)
{
    CPUState *cpu;

    cpu = CPU(s->cpu);
    if (!qemu_cpu_is_self(cpu)) {
        cpu_interrupt(cpu, CPU_INTERRUPT_POLL);
    } else if (apic_irq_pending(s) > 0) {
        cpu_interrupt(cpu, CPU_INTERRUPT_HARD);
    } else if (!apic_accept_pic_intr(s) || !pic_get_output(isa_pic)) {
        cpu_reset_interrupt(cpu, CPU_INTERRUPT_HARD);
    }
}

static void apic_timer(void *opaque);

/*
 * x-posted: fixed, edge-triggered IPIs written to the x2APIC ICR or
 * SELF_IPI register, for a physical unicast destination or a shorthand,
 * are posted without the BQL.  The sender sets the vector in the target's
 * pir with a sequentially consistent RMW (ordering the sender's earlier
 * guest stores before it), raises CPU_INTERRUPT_POLL and asks the target
 * to leave generated code; the target's POLL pass, under the BQL, moves
 * pir into IRR (apic_pir_drain), from where it is delivered as any other
 * edge interrupt.  The target clears POLL before it drains, so a post
 * that lands after the drain raises it again.
 *
 * A halted target is woken under the BQL (apic_kick_locked): the sender
 * raises POLL, then, after a full barrier, reads halted and halt_polling;
 * the target stores them, then, after a full barrier, checks for work.
 * One of the two sees the other's store.
 *
 * Logical and broadcast destinations, other delivery modes and level
 * interrupts take the BQL path, as do all destinations once the guest
 * changes an xAPIC ID (apic_ids_moved).  An unplugged APIC is freed after
 * an RCU grace period (apic_unrealize): senders hold no lock.
 */
static bool apic_match_dest(APICCommonState *apic, uint32_t dest);

static void apic_pir_drain(APICCommonState *s)
{
    for (int w = 0; w < ARRAY_SIZE(s->pir); w++) {
        uint64_t bits;

        if (!qatomic_read(&s->pir[w])) {
            continue;
        }
        bits = qatomic_xchg(&s->pir[w], 0);
        while (bits) {
            int vec = w * 64 + ctz64(bits);

            bits &= bits - 1;
            /* as apic_set_irq's edge delivery */
            apic_set_bit(s->irr, vec);
            apic_reset_bit(s->tmr, vec);
        }
    }
}

static void apic_kick_locked(APICCommonState *s);

/* Post @vec to @t; @self: the sender is @t's own vCPU. */
static void apic_post(APICCommonState *t, int vec, bool self)
{
    CPUState *cs = CPU(t->cpu);

    qatomic_fetch_or(&t->pir[vec >> 6], 1ULL << (vec & 63));
    cpu_set_interrupt(cs, CPU_INTERRUPT_POLL);
    qatomic_store_release(&cs->neg.icount_decr.u16.high, -1);
    if (self) {
        return;
    }
    smp_mb(); /* the request before halted: the vCPU orders the reverse */
    if (qatomic_read(&cs->halted) && !qatomic_read(&cs->halt_polling)) {
        apic_kick_locked(t);
    }
}

/* An ICR write by @s's own vCPU, without the BQL: true if posted. */
static bool apic_icr_post(APICCommonState *s, uint32_t lo, uint32_t dest)
{
    int vec = lo & 0xff, mode = (lo >> 8) & 7, shorthand = (lo >> 18) & 3;
    APICCommonState *apic_iter;

    if (!s->posted || s->vapic_paddr || mode != APIC_DM_FIXED ||
        (lo & (1 << 15)) || vec < 16) {
        return false;
    }
    switch (shorthand) {
    case 1:
        apic_post(s, vec, true);
        return true;
    case 2:
    case 3:
        for (int i = 0; i < max_apic_words * 32; i++) {
            apic_iter = qatomic_read(&local_apics[i]);
            if (apic_iter && !(shorthand == 3 && apic_iter == s)) {
                apic_post(apic_iter, vec, apic_iter == s);
            }
        }
        return true;
    default:
        if (lo & (1 << 11)) {
            return false;   /* logical destination */
        }
        if (dest == (is_x2apic_mode(s) ? 0xffffffff : 0xff)) {
            return false;   /* physical broadcast */
        }
        if (qatomic_read(&apic_ids_moved)) {
            return false;   /* an xAPIC ID changed: resolve under the BQL */
        }
        {
            /* every matching APIC, as apic_get_delivery_bitmask */
            APICCommonState *match[64];
            int n = 0;

            for (int i = 0; i < max_apic_words * 32; i++) {
                apic_iter = qatomic_read(&local_apics[i]);
                if (apic_iter && apic_match_dest(apic_iter, dest)) {
                    if (n == ARRAY_SIZE(match)) {
                        return false;
                    }
                    match[n++] = apic_iter;
                }
            }
            for (int i = 0; i < n; i++) {
                apic_post(match[i], vec, match[i] == s);
            }
            return n > 0;
        }
    }
}

bool apic_msr_write_lockless(APICCommonState *s, int index, uint64_t val)
{
    if (!s || !s->posted || !is_x2apic_mode(s)) {
        return false;
    }
    switch (index) {
    case 0x30:
        if (apic_icr_post(s, (uint32_t)val, val >> 32)) {
            s->icr[0] = val;
            s->icr[1] = val >> 32;
            return true;
        }
        return false;
    case 0x3f:
        if ((val & 0xff) < 16) {
            return false;
        }
        apic_post(s, val & 0xff, true);
        return true;
    default:
        return false;
    }
}

void apic_poll_irq(APICCommonState *s)
{
    if (s->posted) {
        apic_pir_drain(s);
    }
    /*
     * x-vcpu-timer: the deadline thread found an expiry; only a hint:
     * the timer may have been reprogrammed, cancelled or reset since it
     * claimed it, so fire only a timer that is armed and due now.
     */
    if (s->vcpu_timer && qatomic_xchg(&s->timer_due, 0) &&
        s->timer_expiry != -1 &&
        qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) >= s->next_time) {
        apic_timer(s);
    }
    /* only a hint: the timer device checks its own expiries */
    if (qatomic_xchg(&s->xdue, 0) && s->xtimer_cb) {
        s->xtimer_cb(s->xtimer_opaque);
    }
    apic_sync_vapic(s, SYNC_FROM_VAPIC);
    apic_update_irq(s);
}

/*
 * x-vcpu-timer: the timer fires on the vCPU that owns it, not on the
 * main loop.  Arming it records its expiry in vdeadline and pokes one
 * deadline thread, which sleeps (qemu_poll_ns) until the earliest expiry
 * of all vCPUs.  At an expiry it sets timer_due, raises
 * CPU_INTERRUPT_POLL and asks the vCPU to leave generated code (without
 * exit_request: no return to the vCPU's outer loop); the vCPU's POLL
 * pass, under the BQL it takes itself, fires the timer (apic_timer):
 * LVT delivery and rearming.  The main loop, and its BQL hand-off to the
 * vCPU, are out of the path.
 *
 * A halted vCPU is woken under the BQL, as cpu_interrupt does: it checks
 * for work and waits on halt_cond with the BQL held.  The thread sets
 * POLL with a sequentially consistent RMW, then reads halted after a
 * full barrier; the vCPU stores halted, and has a full barrier before it
 * checks for work (mttcg_cpu_thread_fn): one of the two sees the other's
 * store, so a vCPU that halts as its timer expires is woken either way.
 */
static EventNotifier vcpu_timer_notifier;
static QemuThread vcpu_timer_thread;
static bool vcpu_timer_started;

/*
 * Wake @s's halted vCPU, as cpu_interrupt does, under the BQL; not if the
 * CPU was unplugged meanwhile (apic_unrealize, under the BQL, removes it
 * from local_apics first).
 */
static void apic_kick_locked(APICCommonState *s)
{
    bql_lock();
    if (qatomic_read(&local_apics[s->initial_apic_id]) == s) {
        qemu_cpu_kick(CPU(s->cpu));
    }
    bql_unlock();
}

static void apic_vcpu_timer_fire(APICCommonState *s, int *due)
{
    CPUState *cs = CPU(s->cpu);

    qatomic_set(due, 1);
    cpu_set_interrupt(cs, CPU_INTERRUPT_POLL);
    qatomic_store_release(&cs->neg.icount_decr.u16.high, -1);
    smp_mb(); /* the request before halted: the vCPU orders the reverse */
    if (qatomic_read(&cs->halted) && !qatomic_read(&cs->halt_polling)) {
        apic_kick_locked(s);
    }
}

static void *apic_vcpu_timer_thread(void *opaque)
{
    rcu_register_thread();
    for (;;) {
        int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        int64_t first = INT64_MAX, timeout;
        GPollFD pfd = {
            .fd = event_notifier_get_fd(&vcpu_timer_notifier),
            .events = G_IO_IN,
        };

        /* the APICs stay allocated while we look (apic_unrealize) */
        WITH_RCU_READ_LOCK_GUARD()
        for (int i = 0; i < max_apic_words * 32; i++) {
            APICCommonState *s = qatomic_read(&local_apics[i]);
            int64_t d;

            if (!s || !s->vcpu_timer) {
                continue;
            }
            d = qatomic_read(&s->vdeadline);
            if (d <= now) {
                if (qatomic_cmpxchg(&s->vdeadline, d, INT64_MAX) == d) {
                    apic_vcpu_timer_fire(s, &s->timer_due);
                }
            } else if (d < first) {
                first = d;
            }
            /* and another timer device's deadline (apic_xtimer_mod) */
            d = qatomic_read(&s->xdeadline);
            if (d <= now) {
                if (qatomic_cmpxchg(&s->xdeadline, d, INT64_MAX) == d) {
                    apic_vcpu_timer_fire(s, &s->xdue);
                }
            } else if (d < first) {
                first = d;
            }
        }
        timeout = first == INT64_MAX ? -1 : first - now;
        if (!runstate_is_running()) {
            /* the clock is stopped: wait for the VM to run (apic_vm_state) */
            timeout = -1;
        }
        if (qemu_poll_ns(&pfd, 1, timeout) > 0) {
            event_notifier_test_and_clear(&vcpu_timer_notifier);
        }
    }
    return NULL;
}

static void apic_vm_state(void *opaque, bool running, RunState state)
{
    if (running) {
        event_notifier_set(&vcpu_timer_notifier);
    }
}

static void apic_vcpu_timer_arm(APICCommonState *s, int64_t deadline)
{
    qatomic_set(&s->vdeadline, deadline);
    if (deadline != INT64_MAX) {
        event_notifier_set(&vcpu_timer_notifier);
    }
}

static void apic_xtimer_expired(void *opaque)
{
    APICCommonState *s = opaque;

    qatomic_set(&s->xdue, 1);
    cpu_interrupt(CPU(s->cpu), CPU_INTERRUPT_POLL);
}

/*
 * A per-vCPU timer device outside the APIC (Hyper-V's synthetic timers)
 * runs @cb on the vCPU, in its POLL pass with the BQL held, once a
 * deadline set with apic_xtimer_mod has passed, and @eoi after every EOI
 * (an interrupt it raised may have been handled).  So the device's state
 * is only ever touched by its own vCPU.
 */
void apic_xtimer_init(APICCommonState *s, void (*cb)(void *),
                      void (*eoi)(void *), void *opaque)
{
    s->xtimer_cb = cb;
    s->xtimer_eoi = eoi;
    s->xtimer_opaque = opaque;
    if (!s->vcpu_timer && !s->xtimer) {
        s->xtimer = timer_new_ns(QEMU_CLOCK_VIRTUAL, apic_xtimer_expired, s);
    }
}

/*
 * @deadline on QEMU_CLOCK_VIRTUAL, or INT64_MAX for none.  BQL held.
 * With x-vcpu-timer, the deadline thread wakes the vCPU, as for the APIC
 * timer.
 */
void apic_xtimer_mod(APICCommonState *s, int64_t deadline)
{
    if (s->vcpu_timer) {
        qatomic_set(&s->xdeadline, deadline);
        if (deadline != INT64_MAX) {
            event_notifier_set(&vcpu_timer_notifier);
        }
    } else if (deadline == INT64_MAX) {
        timer_del(s->xtimer);
    } else {
        timer_mod(s->xtimer, deadline);
    }
}

/* A fixed, edge-triggered vector from this vCPU's own devices.  BQL held. */
void apic_set_local_irq(APICCommonState *s, int vector)
{
    apic_set_irq(s, vector, APIC_TRIGGER_EDGE);
}

static void apic_set_irq(APICCommonState *s, int vector_num, int trigger_mode)
{
    kvm_report_irq_delivered(!apic_get_bit(s->irr, vector_num));

    apic_set_bit(s->irr, vector_num);
    if (trigger_mode)
        apic_set_bit(s->tmr, vector_num);
    else
        apic_reset_bit(s->tmr, vector_num);
    if (s->vapic_paddr) {
        apic_sync_vapic(s, SYNC_ISR_IRR_TO_VAPIC);
        /*
         * The vcpu thread needs to see the new IRR before we pull its current
         * TPR value. That way, if we miss a lowering of the TRP, the guest
         * has the chance to notice the new IRR and poll for IRQs on its own.
         */
        smp_wmb();
        apic_sync_vapic(s, SYNC_FROM_VAPIC);
    }
    apic_update_irq(s);
}

static void apic_eoi(APICCommonState *s)
{
    int isrv;
    isrv = get_highest_priority_int(s->isr);
    if (isrv < 0)
        return;
    apic_reset_bit(s->isr, isrv);
    if (!(s->spurious_vec & APIC_SV_DIRECTED_IO) && apic_get_bit(s->tmr, isrv)) {
        ioapic_eoi_broadcast(isrv);
    }
    if (s->xtimer_eoi) {
        s->xtimer_eoi(s->xtimer_opaque);
    }
    apic_sync_vapic(s, SYNC_FROM_VAPIC | SYNC_TO_VAPIC);
    apic_update_irq(s);
}

static bool apic_match_dest(APICCommonState *apic, uint32_t dest)
{
    if (is_x2apic_mode(apic)) {
        return apic->initial_apic_id == dest;
    } else {
        return apic->id == (uint8_t)dest;
    }
}

static void apic_find_dest(uint32_t *deliver_bitmask, uint32_t dest)
{
    APICCommonState *apic = NULL;
    int i;

    for (i = 0; i < max_apics; i++) {
        apic = local_apics[i];
        if (apic && apic_match_dest(apic, dest)) {
            apic_set_bit(deliver_bitmask, i);
        }
    }
}

/*
 * Deliver interrupt to x2APIC CPUs if it is x2APIC broadcast.
 * Otherwise, deliver interrupt to xAPIC CPUs if it is xAPIC
 * broadcast.
 */
static void apic_get_broadcast_bitmask(uint32_t *deliver_bitmask,
                                       bool is_x2apic_broadcast)
{
    int i;
    APICCommonState *apic_iter;

    for (i = 0; i < max_apics; i++) {
        apic_iter = local_apics[i];
        if (apic_iter) {
            bool apic_in_x2apic = is_x2apic_mode(apic_iter);

            if (is_x2apic_broadcast && apic_in_x2apic) {
                apic_set_bit(deliver_bitmask, i);
            } else if (!is_x2apic_broadcast && !apic_in_x2apic) {
                apic_set_bit(deliver_bitmask, i);
            }
        }
    }
}

static void apic_get_delivery_bitmask(uint32_t *deliver_bitmask,
                                      uint32_t dest, uint8_t dest_mode)
{
    APICCommonState *apic;
    int i;

    memset(deliver_bitmask, 0x00, max_apic_words * sizeof(uint32_t));

    /*
     * x2APIC broadcast is delivered to all x2APIC CPUs regardless of
     * destination mode. In case the destination mode is physical, it is
     * broadcasted to all xAPIC CPUs too. Otherwise, if the destination
     * mode is logical, we need to continue checking if xAPIC CPUs accepts
     * the interrupt.
     */
    if (dest == 0xffffffff) {
        if (dest_mode == APIC_DESTMODE_PHYSICAL) {
            memset(deliver_bitmask, 0xff, max_apic_words * sizeof(uint32_t));
            return;
        } else {
            apic_get_broadcast_bitmask(deliver_bitmask, true);
        }
    }

    if (dest_mode == APIC_DESTMODE_PHYSICAL) {
        apic_find_dest(deliver_bitmask, dest);
        /* Any APIC in xAPIC mode will interpret 0xFF as broadcast */
        if (dest == 0xff) {
            apic_get_broadcast_bitmask(deliver_bitmask, false);
        }
    } else {
        /* XXX: logical mode */
        for (i = 0; i < max_apics; i++) {
            apic = local_apics[i];
            if (apic) {
                /* x2APIC logical mode */
                if (apic->apicbase & MSR_IA32_APICBASE_EXTD) {
                    if ((dest >> 16) == (apic->extended_log_dest >> 16) &&
                        (dest & apic->extended_log_dest & 0xffff)) {
                        apic_set_bit(deliver_bitmask, i);
                    }
                    continue;
                }

                /* xAPIC logical mode */
                dest = (uint8_t)dest;
                if (apic->dest_mode == APIC_DESTMODE_LOGICAL_FLAT) {
                    if (dest & apic->log_dest) {
                        apic_set_bit(deliver_bitmask, i);
                    }
                } else if (apic->dest_mode == APIC_DESTMODE_LOGICAL_CLUSTER) {
                    /*
                     * In cluster model of xAPIC logical mode IPI, 4 higher
                     * bits are used as cluster address, 4 lower bits are
                     * the bitmask for local APICs in the cluster. The IPI
                     * is delivered to an APIC if the cluster address
                     * matches and the APIC's address bit in the cluster is
                     * set in bitmask of destination ID in IPI.
                     *
                     * The cluster address ranges from 0 - 14, the cluster
                     * address 15 (0xf) is the broadcast address to all
                     * clusters.
                     */
                    if ((dest & 0xf0) == 0xf0 ||
                        (dest & 0xf0) == (apic->log_dest & 0xf0)) {
                        if (dest & apic->log_dest & 0x0f) {
                            apic_set_bit(deliver_bitmask, i);
                        }
                    }
               }
            }
        }
    }
}

static void apic_startup(APICCommonState *s, int vector_num)
{
    s->sipi_vector = vector_num;
    cpu_interrupt(CPU(s->cpu), CPU_INTERRUPT_SIPI);
}

void apic_sipi(APICCommonState *s)
{
    if (!s->wait_for_sipi)
        return;
    cpu_x86_load_seg_cache_sipi(s->cpu, s->sipi_vector);
    s->wait_for_sipi = 0;
}

static void apic_deliver(APICCommonState *s, uint32_t dest, uint8_t dest_mode,
                         uint8_t delivery_mode, uint8_t vector_num,
                         uint8_t trigger_mode, uint8_t dest_shorthand)
{
    APICCommonState *apic_iter;
    uint32_t deliver_bitmask_size = max_apic_words * sizeof(uint32_t);
    g_autofree uint32_t *deliver_bitmask = g_new(uint32_t, max_apic_words);

    switch (dest_shorthand) {
    case 0:
        apic_get_delivery_bitmask(deliver_bitmask, dest, dest_mode);
        break;
    case 1:
        memset(deliver_bitmask, 0x00, deliver_bitmask_size);
        /*
         * The self and all-but-self cases do not use apic_match_dest() and
         * directly fill in deliver_bitmask; the bitmask's indexes in turn
         * map to local_apics[] slots which are never changed even if the
         * xAPIC id is modified.  So use s->initial_apic_id instead of s->id.
         */
        apic_set_bit(deliver_bitmask, s->initial_apic_id);
        break;
    case 2:
        memset(deliver_bitmask, 0xff, deliver_bitmask_size);
        break;
    case 3:
        memset(deliver_bitmask, 0xff, deliver_bitmask_size);
        apic_reset_bit(deliver_bitmask, s->initial_apic_id);
        break;
    }

    switch (delivery_mode) {
        case APIC_DM_INIT:
            {
                int trig_mode = (s->icr[0] >> 15) & 1;
                int level = (s->icr[0] >> 14) & 1;
                if (level == 0 && trig_mode == 1) {
                    foreach_apic(apic_iter, deliver_bitmask,
                                 apic_iter->arb_id = apic_iter->id );
                    return;
                }
            }
            break;

        case APIC_DM_SIPI:
            foreach_apic(apic_iter, deliver_bitmask,
                         apic_startup(apic_iter, vector_num) );
            return;
    }

    apic_bus_deliver(deliver_bitmask, delivery_mode, vector_num, trigger_mode);
}

static bool apic_check_pic(APICCommonState *s)
{
    if (!apic_accept_pic_intr(s) || !pic_get_output(isa_pic)) {
        return false;
    }
    apic_deliver_pic_intr(s, 1);
    return true;
}

int apic_get_interrupt(APICCommonState *s)
{
    int intno;

    /* if the APIC is installed or enabled, we let the 8259 handle the
       IRQs */
    if (!s)
        return -1;
    if (!(s->spurious_vec & APIC_SV_ENABLE))
        return -1;

    apic_sync_vapic(s, SYNC_FROM_VAPIC);
    intno = apic_irq_pending(s);

    /* if there is an interrupt from the 8259, let the caller handle
     * that first since ExtINT interrupts ignore the priority.
     */
    if (intno == 0 || apic_check_pic(s)) {
        apic_sync_vapic(s, SYNC_TO_VAPIC);
        return -1;
    } else if (intno < 0) {
        apic_sync_vapic(s, SYNC_TO_VAPIC);
        return s->spurious_vec & 0xff;
    }
    apic_reset_bit(s->irr, intno);
    apic_set_bit(s->isr, intno);
    apic_sync_vapic(s, SYNC_TO_VAPIC);

    apic_update_irq(s);

    return intno;
}

int apic_accept_pic_intr(APICCommonState *s)
{
    uint32_t lvt0;

    if (!s)
        return -1;

    lvt0 = s->lvt[APIC_LVT_LINT0];

    if ((s->apicbase & MSR_IA32_APICBASE_ENABLE) == 0 ||
        (lvt0 & APIC_LVT_MASKED) == 0)
        return isa_pic != NULL;

    return 0;
}

static void apic_timer_update(APICCommonState *s, int64_t current_time)
{
    if (s->vcpu_timer) {
        apic_vcpu_timer_arm(s, apic_next_timer(s, current_time) ?
                               s->next_time : INT64_MAX);
        return;
    }
    if (apic_next_timer(s, current_time)) {
        timer_mod(s->timer, s->next_time);
    } else {
        timer_del(s->timer);
    }
}

static void apic_timer(void *opaque)
{
    APICCommonState *s = opaque;

    apic_local_deliver(s, APIC_LVT_TIMER);
    apic_timer_update(s, s->next_time);
}

static int apic_register_read(APICCommonState *s, int index, uint64_t *value)
{
    uint32_t val;
    int ret = 0;

    /* x-posted: posted vectors become visible in IRR, ISR and PPR here */
    if (s->posted && (index == 0x0a || (index >= 0x10 && index <= 0x27))) {
        apic_pir_drain(s);
    }

    switch(index) {
    case 0x02: /* id */
        if (is_x2apic_mode(s)) {
            val = s->initial_apic_id;
        } else {
            val = s->id << 24;
        }
        break;
    case 0x03: /* version */
        val = s->version | ((APIC_LVT_NB - 1) << 16);
        break;
    case 0x08:
        apic_sync_vapic(s, SYNC_FROM_VAPIC);
        if (apic_report_tpr_access) {
            cpu_report_tpr_access(&s->cpu->env, TPR_ACCESS_READ);
        }
        val = s->tpr;
        break;
    case 0x09:
        val = apic_get_arb_pri(s);
        break;
    case 0x0a:
        /* ppr */
        val = apic_get_ppr(s);
        break;
    case 0x0b:
        val = 0;
        break;
    case 0x0d:
        if (is_x2apic_mode(s)) {
            val = s->extended_log_dest;
        } else {
            val = s->log_dest << 24;
        }
        break;
    case 0x0e:
        if (is_x2apic_mode(s)) {
            val = 0;
            ret = -1;
        } else {
            val = (s->dest_mode << 28) | 0xfffffff;
        }
        break;
    case 0x0f:
        val = s->spurious_vec;
        break;
    case 0x10 ... 0x17:
        val = s->isr[index & 7];
        break;
    case 0x18 ... 0x1f:
        val = s->tmr[index & 7];
        break;
    case 0x20 ... 0x27:
        val = s->irr[index & 7];
        break;
    case 0x28:
        val = s->esr;
        break;
    case 0x30:
    case 0x31:
        val = s->icr[index & 1];
        break;
    case 0x32 ... 0x37:
        val = s->lvt[index - 0x32];
        break;
    case 0x38:
        val = s->initial_count;
        break;
    case 0x39:
        val = apic_get_current_count(s);
        break;
    case 0x3e:
        val = s->divide_conf;
        break;
    default:
        s->esr |= APIC_ESR_ILLEGAL_ADDRESS;
        val = 0;
        ret = -1;
        break;
    }

    trace_apic_register_read(index, val);
    *value = val;
    return ret;
}

/*
 * x-lockless-tpr: the APIC's MMIO region is lockless_io.  A vCPU's reads
 * and writes of its own TPR take no BQL (XP's HAL makes one at every
 * IRQL change); every other access takes it here.
 *
 * Only the owning vCPU writes its TPR and ISR, and other threads change
 * its IRR under the BQL and then ask it to re-evaluate (CPU_INTERRUPT_POLL,
 * see apic_update_irq), so the owner may read IRR without the lock: a
 * bit it misses is evaluated at that poll.  A TPR write needs
 * apic_update_irq only if it can change the CPU's interrupt line: when
 * an interrupt is now deliverable, or CPU_INTERRUPT_HARD is raised (a
 * higher TPR can mask it).
 */
static bool apic_tpr_lockless(APICCommonState *s, hwaddr addr, unsigned size)
{
    return s && s->lockless_tpr && size >= 4 && addr <= 0xfff &&
           ((addr >> 4) & 0xff) == 0x08 &&
           (s->apicbase & MSR_IA32_APICBASE_ENABLE) && !is_x2apic_mode(s) &&
           !s->vapic_paddr && !apic_report_tpr_access;
}

static void apic_tpr_write_lockless(APICCommonState *s, uint8_t val)
{
    CPUState *cpu = CPU(s->cpu);

    qatomic_set(&s->tpr, val);
    if (!(qatomic_read(&cpu->interrupt_request) & CPU_INTERRUPT_HARD) &&
        apic_irq_pending(s) <= 0) {
        return;
    }
    BQL_LOCK_GUARD();
    apic_update_irq(s);
}

/*
 * A vCPU's own TPR write through CR8, without the BQL where x-lockless-tpr
 * allows it, as for its MMIO TPR above; in x2APIC mode too, as CR8 writes
 * the same register either way.  Returns false if the caller must take
 * the BQL and use cpu_set_apic_tpr.
 */
bool cpu_set_apic_tpr_lockless(APICCommonState *s, uint8_t val)
{
    if (!s || !s->lockless_tpr ||
        !(s->apicbase & MSR_IA32_APICBASE_ENABLE) ||
        s->vapic_paddr || apic_report_tpr_access) {
        return false;
    }
    apic_tpr_write_lockless(s, val << 4);
    return true;
}

static uint64_t apic_mem_read_locked(void *opaque, hwaddr addr,
                                     unsigned size)
{
    APICCommonState *s = cpu_get_current_apic();
    uint64_t val;
    int index;

    if (size < 4) {
        return 0;
    }

    if (!s) {
        return -1;
    }

    /* if the xAPIC is disabled, return early. */
    if (!(s->apicbase & MSR_IA32_APICBASE_ENABLE)) {
        return 0xffffffff;
    }

    if (is_x2apic_mode(s)) {
        return 0xffffffff;
    }

    index = (addr >> 4) & 0xff;
    apic_register_read(s, index, &val);

    return val;
}

/*
 * x-posted with x-lockless-tpr: the vCPU's own xAPIC ICR, as its x2APIC
 * ICR MSRs: ICR reads and ICR2 writes take no lock (only the owner writes
 * them), and ICR writes are posted where they can be.
 */
static bool apic_posted_mmio(APICCommonState *s, hwaddr addr, unsigned size)
{
    return s && s->posted && s->lockless_tpr && size >= 4 && addr <= 0xfff &&
           !s->vapic_paddr && (s->apicbase & MSR_IA32_APICBASE_ENABLE) &&
           !is_x2apic_mode(s);
}

static uint64_t apic_mem_read(void *opaque, hwaddr addr, unsigned size)
{
    APICCommonState *s = cpu_get_current_apic();
    APICCommonState *self = opaque;

    if (apic_tpr_lockless(s, addr, size)) {
        return qatomic_read(&s->tpr);
    }
    if (apic_posted_mmio(s, addr, size)) {
        int index = (addr >> 4) & 0xff;

        if (index == 0x30 || index == 0x31) {
            return s->icr[index & 1];
        }
    }
    if (self->lockless_tpr) {
        BQL_LOCK_GUARD();
        return apic_mem_read_locked(opaque, addr, size);
    }
    return apic_mem_read_locked(opaque, addr, size);
}

int apic_msr_read(APICCommonState *s, int index, uint64_t *val)
{
    if (!s) {
        return -1;
    }

    if (!is_x2apic_mode(s)) {
        return -1;
    }

    return apic_register_read(s, index, val);
}

static void apic_send_msi(MSIMessage *msi)
{
    uint64_t addr = msi->address;
    uint32_t data = msi->data;
    uint32_t dest = (addr & MSI_ADDR_DEST_ID_MASK) >> MSI_ADDR_DEST_ID_SHIFT;
    /*
     * The higher 3 bytes of destination id is stored in higher word of
     * msi address. See x86_iommu_irq_to_msi_message()
     */
    dest = dest | (addr >> 32);
    uint8_t vector = (data & MSI_DATA_VECTOR_MASK) >> MSI_DATA_VECTOR_SHIFT;
    uint8_t dest_mode = (addr >> MSI_ADDR_DEST_MODE_SHIFT) & 0x1;
    uint8_t trigger_mode = (data >> MSI_DATA_TRIGGER_SHIFT) & 0x1;
    uint8_t delivery = (data >> MSI_DATA_DELIVERY_MODE_SHIFT) & 0x7;
    /* XXX: Ignore redirection hint. */
#ifdef CONFIG_MSHV
    if (mshv_enabled()) {
        mshv_request_interrupt(mshv_state, delivery, vector, dest,
                               dest_mode, trigger_mode);
        return;
    }
#endif
    apic_deliver_irq(dest, dest_mode, delivery, vector, trigger_mode);
}

static int apic_register_write(APICCommonState *s, int index, uint64_t val)
{
    trace_apic_register_write(index, val);

    switch(index) {
    case 0x02:
        if (is_x2apic_mode(s)) {
            return -1;
        }

        s->id = (val >> 24);
        if (s->id != s->initial_apic_id) {
            qatomic_set(&apic_ids_moved, true);
        }
        break;
    case 0x03:
        break;
    case 0x08:
        if (apic_report_tpr_access) {
            cpu_report_tpr_access(&s->cpu->env, TPR_ACCESS_WRITE);
        }
        s->tpr = val;
        apic_sync_vapic(s, SYNC_TO_VAPIC);
        apic_update_irq(s);
        break;
    case 0x09:
    case 0x0a:
        break;
    case 0x0b: /* EOI */
        apic_eoi(s);
        break;
    case 0x0d:
        if (is_x2apic_mode(s)) {
            return -1;
        }

        s->log_dest = val >> 24;
        break;
    case 0x0e:
        if (is_x2apic_mode(s)) {
            return -1;
        }

        s->dest_mode = val >> 28;
        break;
    case 0x0f:
        s->spurious_vec = val & 0x1ff;
        apic_update_irq(s);
        break;
    case 0x10 ... 0x17:
    case 0x18 ... 0x1f:
    case 0x20 ... 0x27:
    case 0x28:
        break;
    case 0x30: {
        uint32_t dest;

        s->icr[0] = val;
        if (is_x2apic_mode(s)) {
            s->icr[1] = val >> 32;
            dest = s->icr[1];
        } else {
            dest = (s->icr[1] >> 24) & 0xff;
        }

        apic_deliver(s, dest, (s->icr[0] >> 11) & 1,
                     (s->icr[0] >> 8) & 7, (s->icr[0] & 0xff),
                     (s->icr[0] >> 15) & 1, (s->icr[0] >> 18) & 3);
        break;
    }
    case 0x31:
        if (is_x2apic_mode(s)) {
            return -1;
        }

        s->icr[1] = val;
        break;
    case 0x32 ... 0x37:
        {
            int n = index - 0x32;
            s->lvt[n] = val;
            if (n == APIC_LVT_TIMER) {
                apic_timer_update(s, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
            } else if (n == APIC_LVT_LINT0 && apic_check_pic(s)) {
                apic_update_irq(s);
            }
        }
        break;
    case 0x38:
        s->initial_count = val;
        s->initial_count_load_time = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        apic_timer_update(s, s->initial_count_load_time);
        break;
    case 0x39:
        break;
    case 0x3e:
        {
            int v;
            s->divide_conf = val & 0xb;
            v = (s->divide_conf & 3) | ((s->divide_conf >> 1) & 4);
            s->count_shift = (v + 1) & 7;
        }
        break;
    case 0x3f: {
        int vector = val & 0xff;

        if (!is_x2apic_mode(s)) {
            return -1;
        }

        /*
         * Self IPI is identical to IPI with
         * - Destination shorthand: 1 (Self)
         * - Trigger mode: 0 (Edge)
         * - Delivery mode: 0 (Fixed)
         */
        apic_deliver(s, 0, 0, APIC_DM_FIXED, vector, 0, 1);

        break;
    }
    default:
        s->esr |= APIC_ESR_ILLEGAL_ADDRESS;
        return -1;
    }

    return 0;
}

static void apic_mem_write_locked(void *opaque, hwaddr addr, uint64_t val,
                                  unsigned size)
{
    APICCommonState *s = cpu_get_current_apic();
    int index = (addr >> 4) & 0xff;

    if (size < 4) {
        return;
    }

    if (addr > 0xfff || !index) {
        /*
         * MSI and MMIO APIC are at the same memory location,
         * but actually not on the global bus: MSI is on PCI bus
         * APIC is connected directly to the CPU.
         * Mapping them on the global bus happens to work because
         * MSI registers are reserved in APIC MMIO and vice versa.
         */
        MSIMessage msi = { .address = addr, .data = val };
        apic_send_msi(&msi);
        return;
    }

    if (!s) {
        return;
    }

    apic_register_write(s, index, val);
}

static void apic_mem_write(void *opaque, hwaddr addr, uint64_t val,
                           unsigned size)
{
    APICCommonState *s = cpu_get_current_apic();
    APICCommonState *self = opaque;

    if (apic_tpr_lockless(s, addr, size)) {
        apic_tpr_write_lockless(s, val);
        return;
    }
    if (apic_posted_mmio(s, addr, size)) {
        int index = (addr >> 4) & 0xff;

        if (index == 0x31) {
            s->icr[1] = val;
            return;
        }
        if (index == 0x30 && apic_icr_post(s, val, (s->icr[1] >> 24) & 0xff)) {
            s->icr[0] = val;
            return;
        }
    }
    /* MSI writes come from any thread, with no APIC of their own. */
    if (self->lockless_tpr) {
        BQL_LOCK_GUARD();
        apic_mem_write_locked(opaque, addr, val, size);
        return;
    }
    apic_mem_write_locked(opaque, addr, val, size);
}

int apic_msr_write(APICCommonState *s, int index, uint64_t val)
{
    if (!s) {
        return -1;
    }

    if (!is_x2apic_mode(s)) {
        return -1;
    }

    return apic_register_write(s, index, val);
}

static void apic_pre_save(APICCommonState *s)
{
    if (s->posted) {
        apic_pir_drain(s);
    }
    apic_sync_vapic(s, SYNC_FROM_VAPIC);
}

static void apic_post_load(APICCommonState *s)
{
    if (s->vcpu_timer) {
        apic_vcpu_timer_arm(s, s->timer_expiry != -1 ? s->timer_expiry
                                                    : INT64_MAX);
        return;
    }
    if (s->timer_expiry != -1) {
        timer_mod(s->timer, s->timer_expiry);
    } else {
        timer_del(s->timer);
    }
}

static const MemoryRegionOps apic_io_ops = {
    .read = apic_mem_read,
    .write = apic_mem_write,
    .impl.min_access_size = 1,
    .impl.max_access_size = 4,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void apic_realize(DeviceState *dev, Error **errp)
{
    APICCommonState *s = APIC(dev);

    if (kvm_enabled()) {
        warn_report("Userspace local APIC is deprecated for KVM.");
        warn_report("Do not use kernel-irqchip except for the -M isapc machine type.");
    }

    memory_region_init_io(&s->io_memory, OBJECT(s), &apic_io_ops, s, "apic-msi",
                          APIC_SPACE_SIZE);

    /*
     * apic-msi's apic_mem_write can call into ioapic_eoi_broadcast, which can
     * write back to apic-msi. As such mark the apic-msi region re-entrancy
     * safe.
     */
    s->io_memory.disable_reentrancy_guard = true;
    if (s->lockless_tpr) {
        memory_region_enable_lockless_io(&s->io_memory);
    }

    s->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, apic_timer, s);
    s->vdeadline = INT64_MAX;
    s->xdeadline = INT64_MAX;
    if (s->vcpu_timer && !vcpu_timer_started) {
        vcpu_timer_started = true;
        event_notifier_init(&vcpu_timer_notifier, false);
        qemu_add_vm_change_state_handler(apic_vm_state, NULL);
        qemu_thread_create(&vcpu_timer_thread, "apic-timer",
                           apic_vcpu_timer_thread, NULL,
                           QEMU_THREAD_DETACHED);
    }
    if (s->vcpu_timer || s->posted) {
        /*
         * The deadline thread and posting vCPUs read this APIC and its CPU
         * without the BQL, under RCU: keep both until apic_unrealize's
         * grace period has passed.
         */
        object_ref(OBJECT(s));
        object_ref(OBJECT(s->cpu));
    }

    /*
     * The --machine none does not call apic_set_max_apic_id before creating
     * apic, so we need to call it here and set it to 1 which is the max cpus
     * in machine none.
     */
    if (!local_apics) {
        apic_set_max_apic_id(1);
    }
    local_apics[s->initial_apic_id] = s;

    msi_nonbroken = true;
}

typedef struct APICPut {
    struct rcu_head rcu;
    APICCommonState *s;
} APICPut;

static void apic_lockless_put(APICPut *p)
{
    object_unref(OBJECT(p->s->cpu));
    object_unref(OBJECT(p->s));
    g_free(p);
}

static void apic_unrealize(DeviceState *dev)
{
    APICCommonState *s = APIC(dev);

    timer_free(s->timer);
    if (s->xtimer) {
        timer_free(s->xtimer);
    }
    qatomic_set(&local_apics[s->initial_apic_id], NULL);
    if (s->vcpu_timer || s->posted) {
        APICPut *p = g_new(APICPut, 1);

        p->s = s;
        call_rcu(p, apic_lockless_put, rcu);
    }
}

static const Property apic_properties[] = {
    DEFINE_PROP_BOOL("x-lockless-tpr", APICCommonState, lockless_tpr, false),
    DEFINE_PROP_BOOL("x-vcpu-timer", APICCommonState, vcpu_timer, false),
    DEFINE_PROP_BOOL("x-posted", APICCommonState, posted, false),
};

static void apic_class_init(ObjectClass *klass, const void *data)
{
    APICCommonClass *k = APIC_COMMON_CLASS(klass);
    DeviceClass *dc = DEVICE_CLASS(klass);

    k->realize = apic_realize;
    k->unrealize = apic_unrealize;
    k->set_base = apic_set_base;
    k->set_tpr = apic_set_tpr;
    k->get_tpr = apic_get_tpr;
    k->vapic_base_update = apic_vapic_base_update;
    k->external_nmi = apic_external_nmi;
    k->pre_save = apic_pre_save;
    k->post_load = apic_post_load;
    k->send_msi = apic_send_msi;
    device_class_set_props(dc, apic_properties);
}

static const TypeInfo apic_info = {
    .name          = TYPE_APIC,
    .instance_size = sizeof(APICCommonState),
    .parent        = TYPE_APIC_COMMON,
    .class_init    = apic_class_init,
};

static void apic_register_types(void)
{
    type_register_static(&apic_info);
}

type_init(apic_register_types)
