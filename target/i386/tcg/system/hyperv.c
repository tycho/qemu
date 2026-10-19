/*
 * x86 TCG: the Hyper-V interface for the enlightenments TCG implements
 * (tcg_hyperv, TCG_HYPERV_FEATURES): the partition's MSRs, the hypercall
 * page and the reference TSC page.
 *
 * Reference time is the TSC of a vCPU whose offset is the shared base
 * (x86_tsc_counter_partition), in 100 ns units: with tcg_tsc_counter the
 * TSC counts ns.  The reference TSC page turns a vCPU's TSC into it with
 * scale 2^64 / 100 and an offset, valid while every vCPU has the same TSC
 * offset; otherwise the page says so (sequence 0) and the guest reads the
 * TIME_REF_COUNT MSR.
 *
 * With x-hvtimers, also the SynIC's message page and the synthetic
 * timers, run on the vCPU that owns them (apic_xtimer_mod): see below.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/host-utils.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "tcg/startup.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "system/runstate.h"
#include "hw/core/cpu.h"
#include "exec/helper-proto.h"
#include "hw/hyperv/hyperv-proto.h"
#include "hw/i386/apic.h"
#include "qemu/timer.h"
#include "qemu/error-report.h"
#include "tcg/helper-tcg.h"

#define HV_HYPERCALL_LOCKED     (1u << 1)
#define HV_HYPERCALL_GPA_MASK   (~(uint64_t)0xfff)
#define HV_REFTSC_ENABLE        (1u << 0)
#define HV_REFTSC_GPA_MASK      (~(uint64_t)0xfff)

/* 2^64 / 100: the TSC in ns to 100 ns units, as a 64.64 multiplier. */
#define HV_REFTSC_SCALE         0x028f5c28f5c28f5cull

/* Hyper-V's TSC and APIC timer frequencies: both count ns. */
#define HV_FREQUENCY            1000000000ull

static uint32_t hv_tsc_sequence;

static void hv_stimer_resume(void);

static uint64_t hv_reference_time(void)
{
    uint64_t lo, hi;

    mulu64(&lo, &hi, x86_tsc_counter_partition(), HV_REFTSC_SCALE);
    return hi;
}

/* The partition's MSRs live in every vCPU's env, for migration. */
#define HV_SET_ALL(field, val) do {                     \
        CPUState *cs_;                                  \
        CPU_FOREACH(cs_) {                              \
            X86_CPU(cs_)->env.field = (val);            \
        }                                               \
    } while (0)

static void hv_write_hypercall_page(CPUX86State *env, hwaddr gpa)
{
    /* VMCALL or VMMCALL, then RET; RAX holds the result. */
    static const uint8_t vmcall[] = { 0x0f, 0x01, 0xc1, 0xc3 };
    static const uint8_t vmmcall[] = { 0x0f, 0x01, 0xd9, 0xc3 };

    address_space_write(&address_space_memory, gpa, MEMTXATTRS_UNSPECIFIED,
                        IS_AMD_CPU(env) ? vmmcall : vmcall, sizeof(vmcall));
}

/*
 * Rewrite the reference TSC page: valid with the shared TSC offset, or
 * sequence 0 if the vCPUs' offsets differ.  The sequence is written 0
 * first and last, so that a guest reading the page meanwhile retries or
 * falls back to the MSR (TLFS, "Reference TSC page").  BQL held.
 */
static void hv_update_tsc_page(void)
{
    CPUState *cs = first_cpu;
    uint64_t msr = X86_CPU(cs)->env.msr_hv_tsc;
    int64_t off = X86_CPU(cs)->env.tsc_counter_offset;
    hwaddr gpa = msr & HV_REFTSC_GPA_MASK;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    AddressSpace *as = &address_space_memory;
    bool same = true;

    if (!(msr & HV_REFTSC_ENABLE)) {
        return;
    }
    CPU_FOREACH(cs) {
        same &= X86_CPU(cs)->env.tsc_counter_offset == off;
    }
    address_space_stl_le(as, gpa, 0, attrs, NULL);
    if (!same) {
        return;
    }
    smp_wmb(); /* sequence 0 before the new scale and offset */
    address_space_stq_le(as, gpa + 8, HV_REFTSC_SCALE, attrs, NULL);
    address_space_stq_le(as, gpa + 16, (x86_tsc_counter_base() - off) / 100,
                         attrs, NULL);
    smp_wmb(); /* the new scale and offset before the new sequence */
    if (++hv_tsc_sequence == 0 || hv_tsc_sequence == UINT32_MAX) {
        hv_tsc_sequence = 1;
    }
    address_space_stl_le(as, gpa, hv_tsc_sequence, attrs, NULL);
}

/* After loadvm or migration: the TSC offsets, and so the page, may differ. */
static void hv_vm_state(void *opaque, bool running, RunState state)
{
    if (running && first_cpu && x86_tcg_hyperv(X86_CPU(first_cpu))) {
        hv_update_tsc_page();
        hv_stimer_resume();
    }
}

void x86_tcg_hyperv_init(void)
{
    static bool done;

    if (!done) {
        done = true;
        qemu_add_vm_change_state_handler(hv_vm_state, NULL);
    }
}

/* A vCPU's TSC offset changed (IA32_TSC, IA32_TSC_ADJUST). */
void x86_tcg_hyperv_tsc_changed(CPUX86State *env)
{
    if (x86_tcg_hyperv(env_archcpu(env))) {
        bql_lock();
        hv_update_tsc_page();
        bql_unlock();
    }
}

/*
 * The SynIC and synthetic timers (hv-synic, hv-stimer, hv-stimer-direct;
 * x-hvtimers).  Their MSRs are the vCPU's own, so everything here runs on
 * the vCPU that owns them, with the BQL held: MSR accesses, APIC EOIs,
 * and expiries, which the local APIC runs in the vCPU's POLL pass
 * (apic_xtimer_mod); the VM-state handler runs while the vCPUs are
 * stopped.  Messages are thus written while the guest isn't running on
 * that vCPU.
 *
 * Times are reference time, 100 ns units (hv_reference_time).  A one-shot
 * timer's COUNT is its expiry, a periodic one's its period.  An expiry
 * disables a one-shot timer; in message mode it queues the timer's
 * message (one per timer) on its SINT, and the SINT's queue moves into
 * the message page's slot whenever that is free: after an expiry, an EOM,
 * an APIC EOI, and the SynIC or its page being enabled.  The slot's
 * pending flag says whether more messages wait.
 *
 * SCONTROL resets with the SynIC enabled.  The TLFS documents 0, but
 * Windows never writes SCONTROL and expects its timers' messages.
 */
#define HV_STIMER_ENABLE        (1u << 0)
#define HV_STIMER_PERIODIC      (1u << 1)
#define HV_STIMER_AUTOENABLE    (1u << 3)
#define HV_STIMER_VECTOR(c)     (((c) >> 4) & 0xff)
#define HV_STIMER_DIRECT        (1u << 12)
#define HV_STIMER_SINT(c)       (((c) >> 16) & 0xf)
#define HV_STIMER_CONFIG_MASK   0xf1fffull
#define HV_SINT_POLLING         (1u << 18)
#define HV_SINT_MASK            (HV_SINT_VECTOR_MASK | HV_SINT_MASKED | \
                                 HV_SINT_AUTO_EOI | HV_SINT_POLLING)
#define HV_PAGE_MSR_MASK        (~(uint64_t)0xffe)
#define HV_PAGE_GPA(msr)        ((msr) & ~(uint64_t)0xfff)
#define HV_TIMER_PAYLOAD_SIZE   24
#define HV_NEVER                UINT64_MAX

static void hv_stimer_poll(void *opaque);
static void hv_synic_eoi(void *opaque);

static bool hv_synic_usable(CPUX86State *env)
{
    return (env->msr_hv_synic_control & HV_SYNIC_ENABLE) &&
           (env->msr_hv_synic_msg_page & HV_SIMP_ENABLE);
}

/* The local APIC runs our expiries and EOI hook on this vCPU. */
static bool hv_stimer_attach(X86CPU *cpu)
{
    if (!cpu->apic_state) {
        return false;
    }
    if (!cpu->hv_stimer_attached) {
        apic_xtimer_init(cpu->apic_state, hv_stimer_poll, hv_synic_eoi, cpu);
        cpu->hv_stimer_attached = true;
    }
    return true;
}

static void hv_stimer_rearm(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    uint64_t first = HV_NEVER, now;
    int64_t deadline = INT64_MAX;

    if (!hv_stimer_attach(cpu)) {
        return;
    }
    for (int n = 0; n < HV_STIMER_COUNT; n++) {
        first = MIN(first, env->hv_stimer_expiry[n]);
    }
    if (first != HV_NEVER) {
        now = hv_reference_time();
        deadline = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        if (first > now) {
            /* far deadlines are rechecked when they fire */
            deadline += MIN(first - now, (uint64_t)INT32_MAX) * 100;
        }
    }
    apic_xtimer_mod(cpu->apic_state, deadline);
}

/*
 * Move SINT @sint's first queued message into its slot if the slot is
 * free, flagging it pending if more wait; flag a busy slot pending.
 */
static void hv_synic_flush_sint(X86CPU *cpu, int sint)
{
    CPUX86State *env = &cpu->env;
    AddressSpace *as = &address_space_memory;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    uint64_t sintr = env->msr_hv_synic_sint[sint];
    int first = -1, more = 0;
    MemTxResult r;
    hwaddr slot;

    for (int n = 0; n < HV_STIMER_COUNT; n++) {
        if (env->hv_stimer_msg_sint[n] == sint + 1) {
            if (first < 0) {
                first = n;
            } else {
                more++;
            }
        }
    }
    if (first < 0 || !hv_synic_usable(env)) {
        return;
    }
    slot = HV_PAGE_GPA(env->msr_hv_synic_msg_page) +
           sint * sizeof(struct hyperv_message);
    if (address_space_ldl_le(as, slot, attrs, &r) != HV_MESSAGE_NONE) {
        uint8_t flags = address_space_ldub(as, slot + 5, attrs, NULL);

        if (r != MEMTX_OK) {
            return;
        }
        if (!(flags & HV_MESSAGE_FLAG_PENDING)) {
            address_space_stb(as, slot + 5, flags | HV_MESSAGE_FLAG_PENDING,
                              attrs, NULL);
        }
        /*
         * A consumer frees the slot (message type), then reads the pending
         * flag to decide on EOM: with a full barrier on both sides, either
         * it sees the flag or we see the free slot.
         */
        smp_mb();
        if (address_space_ldl_le(as, slot, attrs, NULL) != HV_MESSAGE_NONE) {
            return;
        }
    }
    /* The payload: timer index, reserved, expiration and delivery time. */
    address_space_stl_le(as, slot + 16, first, attrs, NULL);
    address_space_stl_le(as, slot + 20, 0, attrs, NULL);
    address_space_stq_le(as, slot + 24, env->hv_stimer_msg_exp[first],
                         attrs, NULL);
    address_space_stq_le(as, slot + 32, hv_reference_time(), attrs, NULL);
    /* The header, its type last: size, flags (pending if more wait). */
    address_space_stl_le(as, slot + 4, HV_TIMER_PAYLOAD_SIZE |
                         (more ? HV_MESSAGE_FLAG_PENDING << 8 : 0),
                         attrs, NULL);
    address_space_stq_le(as, slot + 8, 0, attrs, NULL);
    smp_wmb(); /* the message before its type, for other vCPUs */
    address_space_stl_le(as, slot, HV_MESSAGE_TIMER_EXPIRED, attrs, NULL);
    env->hv_stimer_msg_sint[first] = 0;
    if (!(sintr & (HV_SINT_MASKED | HV_SINT_POLLING)) &&
        (sintr & HV_SINT_VECTOR_MASK) >= 16) {
        apic_set_local_irq(cpu->apic_state, sintr & HV_SINT_VECTOR_MASK);
    }
}

static void hv_synic_flush(X86CPU *cpu)
{
    uint32_t sints = 0;

    for (int n = 0; n < HV_STIMER_COUNT; n++) {
        if (cpu->env.hv_stimer_msg_sint[n]) {
            sints |= 1u << (cpu->env.hv_stimer_msg_sint[n] - 1);
        }
    }
    while (sints) {
        int s = ctz32(sints);

        hv_synic_flush_sint(cpu, s);
        sints &= ~(1u << s);
    }
}

/* Timer @n expired at @exp. */
static void hv_stimer_expire(X86CPU *cpu, int n, uint64_t exp)
{
    CPUX86State *env = &cpu->env;
    uint64_t cfg = env->msr_hv_stimer_config[n];

    if (cfg & HV_STIMER_DIRECT) {
        if (HV_STIMER_VECTOR(cfg) >= 16) {
            apic_set_local_irq(cpu->apic_state, HV_STIMER_VECTOR(cfg));
        }
    } else if (hv_synic_usable(env) && !env->hv_stimer_msg_sint[n]) {
        /* else no destination, or its last message still waits */
        env->hv_stimer_msg_sint[n] = HV_STIMER_SINT(cfg) + 1;
        env->hv_stimer_msg_exp[n] = exp;
        hv_synic_flush_sint(cpu, HV_STIMER_SINT(cfg));
    }
}

/* The vCPU's POLL pass: the timers that have expired. */
static void hv_stimer_poll(void *opaque)
{
    X86CPU *cpu = opaque;
    CPUX86State *env = &cpu->env;
    uint64_t now = hv_reference_time();

    for (int n = 0; n < HV_STIMER_COUNT; n++) {
        uint64_t cfg = env->msr_hv_stimer_config[n];
        uint64_t exp = env->hv_stimer_expiry[n];

        if (exp > now) {
            continue;
        }
        if (!(cfg & HV_STIMER_ENABLE)) {
            env->hv_stimer_expiry[n] = HV_NEVER;
            continue;
        }
        if (cfg & HV_STIMER_PERIODIC) {
            /* The next period, skipping missed ones. */
            uint64_t period = env->msr_hv_stimer_count[n];

            env->hv_stimer_expiry[n] = exp + period;
            if (env->hv_stimer_expiry[n] <= now ||
                env->hv_stimer_expiry[n] < exp) {
                env->hv_stimer_expiry[n] =
                    now > HV_NEVER - period ? HV_NEVER : now + period;
            }
        } else {
            env->msr_hv_stimer_config[n] &= ~(uint64_t)HV_STIMER_ENABLE;
            env->hv_stimer_expiry[n] = HV_NEVER;
        }
        hv_stimer_expire(cpu, n, exp);
    }
    hv_stimer_rearm(cpu);
}

/* An APIC EOI: a slot may have been freed without an EOM. */
static void hv_synic_eoi(void *opaque)
{
    hv_synic_flush(opaque);
}

/* Timer @n's next expiry from CONFIG and COUNT. */
static void hv_stimer_arm(X86CPU *cpu, int n)
{
    CPUX86State *env = &cpu->env;
    uint64_t cfg = env->msr_hv_stimer_config[n];
    uint64_t count = env->msr_hv_stimer_count[n];
    uint64_t now = hv_reference_time();

    env->hv_stimer_expiry[n] = HV_NEVER;
    if ((cfg & HV_STIMER_ENABLE) && count) {
        if (!(cfg & HV_STIMER_PERIODIC)) {
            env->hv_stimer_expiry[n] = count;
        } else if (now <= HV_NEVER - count) {
            env->hv_stimer_expiry[n] = now + count;
        }
    }
}

/*
 * Enabling a SynIC page at a new address: it starts out zeroed, as the
 * hypervisor's overlay would (re-enabling it in place keeps it).
 */
static void hv_synic_page(uint64_t *msr, uint64_t val)
{
    val &= HV_PAGE_MSR_MASK;
    if ((val & 1) && (!*msr || HV_PAGE_GPA(val) != HV_PAGE_GPA(*msr))) {
        static const uint8_t zero[4096];

        address_space_write(&address_space_memory, HV_PAGE_GPA(val),
                            MEMTXATTRS_UNSPECIFIED, zero, sizeof(zero));
    }
    *msr = val;
}

/* CPU reset: the SynIC enabled, its SINTs masked, no timers. */
void x86_tcg_hyperv_reset(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;

    if (!x86_tcg_hyperv(cpu) || !hyperv_feat_enabled(cpu, HYPERV_FEAT_SYNIC)) {
        return;
    }
    env->msr_hv_synic_control = HV_SYNIC_ENABLE;
    for (int i = 0; i < ARRAY_SIZE(env->msr_hv_synic_sint); i++) {
        env->msr_hv_synic_sint[i] = HV_SINT_MASKED;
    }
    for (int n = 0; n < HV_STIMER_COUNT; n++) {
        env->hv_stimer_expiry[n] = HV_NEVER;
        env->hv_stimer_msg_sint[n] = 0;
    }
    if (cpu->hv_stimer_attached) {
        apic_xtimer_mod(cpu->apic_state, INT64_MAX);
    }
}

/*
 * The VM resumes: convert the timers' expiries to the host clock again.
 * An enabled timer without an expiry or a queued message comes from a
 * migration stream without TCG's timer state: start it from CONFIG and
 * COUNT (a periodic one restarts its period).
 */
static void hv_stimer_resume(void)
{
    CPUState *cs;

    CPU_FOREACH(cs) {
        X86CPU *cpu = X86_CPU(cs);
        CPUX86State *env = &cpu->env;
        bool any = false;

        if (!x86_tcg_hyperv(cpu) ||
            !hyperv_feat_enabled(cpu, HYPERV_FEAT_STIMER)) {
            continue;
        }
        for (int n = 0; n < HV_STIMER_COUNT; n++) {
            if ((env->msr_hv_stimer_config[n] & HV_STIMER_ENABLE) &&
                env->hv_stimer_expiry[n] == HV_NEVER &&
                !env->hv_stimer_msg_sint[n]) {
                hv_stimer_arm(cpu, n);
            }
            any |= env->hv_stimer_expiry[n] != HV_NEVER ||
                   env->hv_stimer_msg_sint[n];
        }
        if (any || cpu->hv_stimer_attached) {
            hv_stimer_rearm(cpu);
            hv_synic_flush(cpu);
        }
    }
}

static bool hv_synic_rdmsr(X86CPU *cpu, uint32_t msr, uint64_t *val)
{
    CPUX86State *env = &cpu->env;

    if (msr >= HV_X64_MSR_SCONTROL && msr <= HV_X64_MSR_SINT15 &&
        !hyperv_feat_enabled(cpu, HYPERV_FEAT_SYNIC)) {
        return false;
    }
    if (msr >= HV_X64_MSR_STIMER0_CONFIG &&
        msr <= HV_X64_MSR_STIMER3_COUNT &&
        !hyperv_feat_enabled(cpu, HYPERV_FEAT_STIMER)) {
        return false;
    }
    switch (msr) {
    case HV_X64_MSR_SCONTROL:
        *val = env->msr_hv_synic_control;
        return true;
    case HV_X64_MSR_SVERSION:
        *val = HV_SYNIC_VERSION;
        return true;
    case HV_X64_MSR_SIEFP:
        *val = env->msr_hv_synic_evt_page;
        return true;
    case HV_X64_MSR_SIMP:
        *val = env->msr_hv_synic_msg_page;
        return true;
    case HV_X64_MSR_EOM:
        *val = 0;
        return true;
    case HV_X64_MSR_SINT0 ... HV_X64_MSR_SINT15:
        *val = env->msr_hv_synic_sint[msr - HV_X64_MSR_SINT0];
        return true;
    case HV_X64_MSR_STIMER0_CONFIG ... HV_X64_MSR_STIMER3_COUNT: {
        int n = (msr - HV_X64_MSR_STIMER0_CONFIG) / 2;

        *val = (msr & 1) ? env->msr_hv_stimer_count[n]
                         : env->msr_hv_stimer_config[n];
        return true;
    }
    }
    return false;
}

/* 1 if handled, 0 if not ours, -1 for #GP. */
static int hv_synic_wrmsr(X86CPU *cpu, uint32_t msr, uint64_t val)
{
    CPUX86State *env = &cpu->env;
    int n;

    if (msr >= HV_X64_MSR_SCONTROL && msr <= HV_X64_MSR_SINT15 &&
        !hyperv_feat_enabled(cpu, HYPERV_FEAT_SYNIC)) {
        return 0;
    }
    if (msr >= HV_X64_MSR_STIMER0_CONFIG &&
        msr <= HV_X64_MSR_STIMER3_COUNT &&
        !hyperv_feat_enabled(cpu, HYPERV_FEAT_STIMER)) {
        return 0;
    }
    switch (msr) {
    case HV_X64_MSR_SVERSION:
        return -1;
    case HV_X64_MSR_SINT0 ... HV_X64_MSR_SINT15:
        if (!(val & HV_SINT_MASKED) && (val & HV_SINT_VECTOR_MASK) < 16) {
            return -1;
        }
        if ((val & HV_SINT_AUTO_EOI) && !(val & HV_SINT_MASKED)) {
            /* the guest wouldn't EOI: its later interrupts would block */
            error_report("x-hvtimers: SINT%u with AutoEOI, unimplemented",
                         msr - HV_X64_MSR_SINT0);
            exit(1);
        }
        env->msr_hv_synic_sint[msr - HV_X64_MSR_SINT0] = val & HV_SINT_MASK;
        return 1;
    case HV_X64_MSR_SCONTROL:
    case HV_X64_MSR_SIEFP:
    case HV_X64_MSR_SIMP:
    case HV_X64_MSR_EOM:
    case HV_X64_MSR_STIMER0_CONFIG ... HV_X64_MSR_STIMER3_COUNT:
        break;
    default:
        return 0;
    }

    bql_lock();
    switch (msr) {
    case HV_X64_MSR_SCONTROL:
        env->msr_hv_synic_control = val & HV_SYNIC_ENABLE;
        hv_synic_flush(cpu);
        break;
    case HV_X64_MSR_SIEFP:
        hv_synic_page(&env->msr_hv_synic_evt_page, val);
        break;
    case HV_X64_MSR_SIMP:
        hv_synic_page(&env->msr_hv_synic_msg_page, val);
        hv_synic_flush(cpu);
        break;
    case HV_X64_MSR_EOM:
        hv_synic_flush(cpu);
        break;
    default:
        n = (msr - HV_X64_MSR_STIMER0_CONFIG) / 2;
        if (msr & 1) {
            env->msr_hv_stimer_count[n] = val;
            if (!val) {
                env->msr_hv_stimer_config[n] &= ~(uint64_t)HV_STIMER_ENABLE;
            } else if (env->msr_hv_stimer_config[n] & HV_STIMER_AUTOENABLE) {
                env->msr_hv_stimer_config[n] |= HV_STIMER_ENABLE;
            }
        } else {
            val &= HV_STIMER_CONFIG_MASK;
            if (!hyperv_feat_enabled(cpu, HYPERV_FEAT_STIMER_DIRECT)) {
                val &= ~(uint64_t)HV_STIMER_DIRECT;
            }
            env->msr_hv_stimer_config[n] = val;
        }
        if (!(env->msr_hv_stimer_config[n] & HV_STIMER_DIRECT) &&
            !HV_STIMER_SINT(env->msr_hv_stimer_config[n])) {
            /* message mode needs a SINT other than 0 */
            env->msr_hv_stimer_config[n] &= ~(uint64_t)HV_STIMER_ENABLE;
        }
        hv_stimer_arm(cpu, n);
        hv_stimer_rearm(cpu);
        break;
    }
    bql_unlock();
    return 1;
}

bool x86_tcg_hyperv_rdmsr(CPUX86State *env, uint32_t msr, uint64_t *val)
{
    X86CPU *cpu = env_archcpu(env);

    if (!x86_tcg_hyperv(cpu)) {
        return false;
    }
    switch (msr) {
    case HV_X64_MSR_GUEST_OS_ID:
        *val = env->msr_hv_guest_os_id;
        return true;
    case HV_X64_MSR_HYPERCALL:
        *val = env->msr_hv_hypercall;
        return true;
    case HV_X64_MSR_VP_INDEX:
        if (!hyperv_feat_enabled(cpu, HYPERV_FEAT_VPINDEX)) {
            return false;
        }
        *val = env_cpu(env)->cpu_index;
        return true;
    case HV_X64_MSR_TIME_REF_COUNT:
        if (!hyperv_feat_enabled(cpu, HYPERV_FEAT_TIME)) {
            return false;
        }
        *val = hv_reference_time();
        return true;
    case HV_X64_MSR_REFERENCE_TSC:
        if (!hyperv_feat_enabled(cpu, HYPERV_FEAT_TIME)) {
            return false;
        }
        *val = env->msr_hv_tsc;
        return true;
    case HV_X64_MSR_TSC_FREQUENCY:
    case HV_X64_MSR_APIC_FREQUENCY:
        if (!hyperv_feat_enabled(cpu, HYPERV_FEAT_FREQUENCIES)) {
            return false;
        }
        *val = HV_FREQUENCY;
        return true;
    }
    return hv_synic_rdmsr(cpu, msr, val);
}

/*
 * Writes to the read-only MSRs, and to MSRs of enlightenments TCG doesn't
 * implement, are ignored, as are unknown MSRs.  Returns 1 if the MSR is
 * Hyper-V's, 0 if not, and -1 for #GP.
 */
int x86_tcg_hyperv_wrmsr(CPUX86State *env, uint32_t msr, uint64_t val)
{
    X86CPU *cpu = env_archcpu(env);

    if (!x86_tcg_hyperv(cpu)) {
        return 0;
    }
    switch (msr) {
    case HV_X64_MSR_GUEST_OS_ID:
        bql_lock();
        HV_SET_ALL(msr_hv_guest_os_id, val);
        if (!val) {
            /* No hypercalls without a guest OS ID. */
            HV_SET_ALL(msr_hv_hypercall,
                       env->msr_hv_hypercall & ~(uint64_t)HV_HYPERCALL_ENABLE);
        }
        bql_unlock();
        return 1;
    case HV_X64_MSR_HYPERCALL:
        bql_lock();
        if (!(env->msr_hv_hypercall & HV_HYPERCALL_LOCKED)) {
            val &= HV_HYPERCALL_GPA_MASK | HV_HYPERCALL_LOCKED |
                   HV_HYPERCALL_ENABLE;
            if (!env->msr_hv_guest_os_id) {
                val &= ~(uint64_t)HV_HYPERCALL_ENABLE;
            }
            if (val & HV_HYPERCALL_ENABLE) {
                hv_write_hypercall_page(env, val & HV_HYPERCALL_GPA_MASK);
            }
            HV_SET_ALL(msr_hv_hypercall, val);
        }
        bql_unlock();
        return 1;
    case HV_X64_MSR_REFERENCE_TSC:
        if (!hyperv_feat_enabled(cpu, HYPERV_FEAT_TIME)) {
            return 0;
        }
        bql_lock();
        HV_SET_ALL(msr_hv_tsc, val & (HV_REFTSC_GPA_MASK | HV_REFTSC_ENABLE));
        hv_update_tsc_page();
        bql_unlock();
        return 1;
    case HV_X64_MSR_VP_INDEX:
    case HV_X64_MSR_TIME_REF_COUNT:
    case HV_X64_MSR_TSC_FREQUENCY:
    case HV_X64_MSR_APIC_FREQUENCY:
        return 1;
    }
    return hv_synic_wrmsr(cpu, msr, val);
}

/*
 * A hypercall: VMCALL or VMMCALL at CPL 0 outside SVM guest mode, with
 * x-hyperv.  #UD while the hypercall page is disabled, as without
 * Hyper-V.  The control word is in RCX (in EDX:EAX outside 64-bit mode)
 * and the result goes to RAX (EDX:EAX).  Hypercalls of enlightenments
 * TCG doesn't implement return HV_STATUS_INVALID_HYPERCALL_CODE.
 */
void helper_hyperv_hypercall(CPUX86State *env)
{
    bool code64 = env->hflags & HF_CS64_MASK;
    uint64_t control, status;

    if (!x86_tcg_hyperv(env_archcpu(env)) ||
        !(env->msr_hv_hypercall & HV_HYPERCALL_ENABLE)) {
        raise_exception(env, EXCP06_ILLOP);
    }
    if (code64) {
        control = env->regs[R_ECX];
    } else {
        control = deposit64((uint32_t)env->regs[R_EAX], 32, 32,
                            env->regs[R_EDX]);
    }

    switch (control & 0xffff) {
    case HV_NOTIFY_LONG_SPIN_WAIT:
        status = HV_STATUS_SUCCESS;
        break;
    default:
        status = HV_STATUS_INVALID_HYPERCALL_CODE;
        break;
    }

    if (code64) {
        env->regs[R_EAX] = status;
    } else {
        env->regs[R_EAX] = (uint32_t)status;
        env->regs[R_EDX] = status >> 32;
    }
}
