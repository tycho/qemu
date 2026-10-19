/*
 * QEMU System Emulator, accelerator interfaces
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2014 Red Hat Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "system/tcg.h"
#include "exec/replay-core.h"
#include "exec/icount.h"
#include "tcg/startup.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/accel.h"
#include "qemu/atomic.h"
#include "qapi/qapi-types-common.h"
#include "qapi/qapi-builtin-visit.h"
#include "qapi/qapi-visit-common.h"
#include "qemu/units.h"
#include "qemu/target-info.h"
#ifndef CONFIG_USER_ONLY
#include "hw/core/boards.h"
#include "exec/tb-flush.h"
#include "system/runstate.h"
#endif
#include "accel/accel-ops.h"
#include "accel/accel-cpu-ops.h"
#include "accel/tcg/cpu-ops.h"
#include "internal-common.h"
#include "qapi/visitor.h"
#include "tcg-accel-ops-mttcg.h"


struct TCGState {
    AccelState parent_obj;

    OnOffAuto mttcg_enabled;
    bool one_insn_per_tb;
    int splitwx_enabled;
    unsigned long tb_size;
    int hostpoll;
    uint32_t haltpoll_us;
    OnOffAuto apictimer;
    OnOffAuto apicpost;
};
typedef struct TCGState TCGState;

#define TYPE_TCG_ACCEL ACCEL_CLASS_NAME("tcg")

DECLARE_INSTANCE_CHECKER(TCGState, TCG_STATE,
                         TYPE_TCG_ACCEL)

#ifndef CONFIG_USER_ONLY
bool qemu_tcg_mttcg_enabled(void)
{
    TCGState *s = TCG_STATE(current_accel());
    return s->mttcg_enabled == ON_OFF_AUTO_ON;
}
#endif /* !CONFIG_USER_ONLY */

static void tcg_accel_instance_init(Object *obj)
{
    TCGState *s = TCG_STATE(obj);

    /* If debugging enabled, default "auto on", otherwise off. */
#if defined(CONFIG_DEBUG_TCG) && !defined(CONFIG_USER_ONLY)
    s->splitwx_enabled = -1;
#else
    s->splitwx_enabled = 0;
#endif
    s->apictimer = ON_OFF_AUTO_OFF;
    s->apicpost = ON_OFF_AUTO_OFF;
}

bool one_insn_per_tb;

#ifndef CONFIG_USER_ONLY
static void tcg_vm_change_state(void *opaque, bool running, RunState state)
{
    if (state == RUN_STATE_RESTORE_VM) {
        /*
         * loadvm will update the content of RAM, bypassing the usual
         * mechanisms that ensure we flush TBs for writes to memory
         * we've translated code from, so we must flush all TBs.
         *
         * vm_stop() has just stopped all cpus, so we are exclusive.
         */
        assert(!running);
        tb_flush__exclusive_or_serial();
    }
}
#endif

static int tcg_init_machine(AccelState *as, MachineState *ms)
{
    TCGState *s = TCG_STATE(as);
    unsigned max_threads = 1;

#ifndef CONFIG_USER_ONLY
    CPUClass *cc = CPU_CLASS(object_class_by_name(target_cpu_type()));
    bool mttcg_supported = cc->tcg_ops->mttcg_supported;

    switch (s->mttcg_enabled) {
    case ON_OFF_AUTO_AUTO:
        /*
         * We default to false if we know other options have been enabled
         * which are currently incompatible with MTTCG. Otherwise when each
         * guest (target) has been updated to support:
         *   - atomic instructions
         *   - memory ordering primitives (barriers)
         * they can set the appropriate CONFIG flags in ${target}-softmmu.mak
         *
         * Once a guest architecture has been converted to the new primitives
         * there is one remaining limitation to check:
         *   - The guest can't be oversized (e.g. 64 bit guest on 32 bit host)
         */
        if (mttcg_supported && !icount_enabled()) {
            s->mttcg_enabled = ON_OFF_AUTO_ON;
            max_threads = ms->smp.max_cpus;
        } else {
            s->mttcg_enabled = ON_OFF_AUTO_OFF;
        }
        break;
    case ON_OFF_AUTO_ON:
        if (!mttcg_supported) {
            warn_report("Guest not yet converted to MTTCG - "
                        "you may get unexpected results");
        }
        max_threads = ms->smp.max_cpus;
        break;
    case ON_OFF_AUTO_OFF:
        break;
    default:
        g_assert_not_reached();
    }

    qemu_add_vm_change_state_handler(tcg_vm_change_state, NULL);

    /*
     * x-apictimer: the x86 local APIC timer fires on its vCPU (from a
     * deadline thread), not on the main loop.  x-apicpost: fixed edge
     * IPIs are posted to their targets without the BQL.  Both need
     * multi-threaded TCG without icount or record/replay; auto means on
     * where they can be.  Compat properties, so an explicit -global
     * still wins.
     */
    {
        static GlobalProperty apictimer_props[] = {
            { "apic", "x-vcpu-timer", "on" },
        };
        static GlobalProperty apicpost_props[] = {
            { "apic", "x-posted", "on" },
        };
        AccelClass *ac = ACCEL_GET_CLASS(as);
        bool can = s->mttcg_enabled == ON_OFF_AUTO_ON && !icount_enabled() &&
                   replay_mode == REPLAY_MODE_NONE;

        if (!can && (s->apictimer == ON_OFF_AUTO_ON ||
                     s->apicpost == ON_OFF_AUTO_ON)) {
            error_report("x-apictimer and x-apicpost need multi-threaded TCG "
                         "without icount or record/replay");
            return -EINVAL;
        }
        if (can && !ac->compat_props) {
            ac->compat_props = g_ptr_array_new();
        }
        if (can && s->apictimer != ON_OFF_AUTO_OFF) {
            compat_props_add(ac->compat_props, apictimer_props,
                             G_N_ELEMENTS(apictimer_props));
        }
        if (can && s->apicpost != ON_OFF_AUTO_OFF) {
            compat_props_add(ac->compat_props, apicpost_props,
                             G_N_ELEMENTS(apicpost_props));
        }
    }

    /* x-haltpoll: how long a halted vCPU spins before it sleeps */
    mttcg_haltpoll_ns = (int64_t)s->haltpoll_us * 1000;

    /* x-hostpoll: how the main loop waits for a timeout (no ppoll) */
    qemu_host_poll = s->hostpoll;
#endif

    tcg_allowed = true;

    as->gdbstub.sstep_flags = SSTEP_ENABLE;
    if (replay_mode == REPLAY_MODE_NONE) {
        /*
         * In replay mode all events will come from the log and can't be
         * suppressed otherwise we would break determinism. However as those
         * events are tied to the number of executed instructions we won't see
         * them occurring every time we single step.
         */
        as->gdbstub.sstep_flags |= SSTEP_NOIRQ | SSTEP_NOTIMER;
    }
    if (replay_mode == REPLAY_MODE_PLAY) {
        as->gdbstub.can_reverse = true;
    }

    page_init();
    tb_htable_init();
    tcg_init(s->tb_size * MiB, s->splitwx_enabled, max_threads);

#if defined(CONFIG_SOFTMMU)
    /*
     * There's no guest base to take into account, so go ahead and
     * initialize the prologue now.
     */
    tcg_prologue_init();
#endif

#ifdef CONFIG_USER_ONLY
    qdev_create_fake_machine();
#endif

    return 0;
}

static const char * const tcg_hostpoll_names[] = {
    [QEMU_HOST_POLL_POLL] = "poll",
    [QEMU_HOST_POLL_KQUEUE] = "kqueue",
    [QEMU_HOST_POLL_SPIN] = "spin",
};

static char *tcg_get_hostpoll(Object *obj, Error **errp)
{
    return g_strdup(tcg_hostpoll_names[TCG_STATE(obj)->hostpoll]);
}

static void tcg_set_hostpoll(Object *obj, const char *value, Error **errp)
{
    for (int i = 0; i < ARRAY_SIZE(tcg_hostpoll_names); i++) {
        if (!strcmp(value, tcg_hostpoll_names[i])) {
            if (i != QEMU_HOST_POLL_POLL && !QEMU_HOST_POLL_KQUEUE_SUPPORTED) {
                error_setg(errp, "x-hostpoll: '%s' needs kqueue timers in "
                           "nanoseconds, which this host lacks", value);
                return;
            }
            TCG_STATE(obj)->hostpoll = i;
            return;
        }
    }
    error_setg(errp, "Invalid 'x-hostpoll' value: %s (poll, kqueue, spin)",
               value);
}

static void tcg_get_haltpoll(Object *obj, Visitor *v, const char *name,
                             void *opaque, Error **errp)
{
    uint32_t value = TCG_STATE(obj)->haltpoll_us;

    visit_type_uint32(v, name, &value, errp);
}

static void tcg_set_haltpoll(Object *obj, Visitor *v, const char *name,
                             void *opaque, Error **errp)
{
    uint32_t value;

    if (!visit_type_uint32(v, name, &value, errp)) {
        return;
    }
    if (value > 10000) {
        error_setg(errp, "x-haltpoll: at most 10000 microseconds");
        return;
    }
    TCG_STATE(obj)->haltpoll_us = value;
}

static void tcg_get_apicpost(Object *obj, Visitor *v, const char *name,
                             void *opaque, Error **errp)
{
    OnOffAuto value = TCG_STATE(obj)->apicpost;

    visit_type_OnOffAuto(v, name, &value, errp);
}

static void tcg_set_apicpost(Object *obj, Visitor *v, const char *name,
                             void *opaque, Error **errp)
{
    visit_type_OnOffAuto(v, name, &TCG_STATE(obj)->apicpost, errp);
}

static void tcg_get_apictimer(Object *obj, Visitor *v, const char *name,
                              void *opaque, Error **errp)
{
    OnOffAuto value = TCG_STATE(obj)->apictimer;

    visit_type_OnOffAuto(v, name, &value, errp);
}

static void tcg_set_apictimer(Object *obj, Visitor *v, const char *name,
                              void *opaque, Error **errp)
{
    visit_type_OnOffAuto(v, name, &TCG_STATE(obj)->apictimer, errp);
}

static char *tcg_get_thread(Object *obj, Error **errp)
{
    TCGState *s = TCG_STATE(obj);

    return g_strdup(s->mttcg_enabled == ON_OFF_AUTO_ON ? "multi" : "single");
}

static void tcg_set_thread(Object *obj, const char *value, Error **errp)
{
    TCGState *s = TCG_STATE(obj);

    if (strcmp(value, "multi") == 0) {
        if (icount_enabled()) {
            error_setg(errp, "No MTTCG when icount is enabled");
        } else {
            s->mttcg_enabled = ON_OFF_AUTO_ON;
        }
    } else if (strcmp(value, "single") == 0) {
        s->mttcg_enabled = ON_OFF_AUTO_OFF;
    } else {
        error_setg(errp, "Invalid 'thread' setting %s", value);
    }
}

static void tcg_get_tb_size(Object *obj, Visitor *v,
                            const char *name, void *opaque,
                            Error **errp)
{
    TCGState *s = TCG_STATE(obj);
    uint32_t value = s->tb_size;

    visit_type_uint32(v, name, &value, errp);
}

static void tcg_set_tb_size(Object *obj, Visitor *v,
                            const char *name, void *opaque,
                            Error **errp)
{
    TCGState *s = TCG_STATE(obj);
    uint32_t value;

    if (!visit_type_uint32(v, name, &value, errp)) {
        return;
    }

    s->tb_size = value;
}

static bool tcg_get_splitwx(Object *obj, Error **errp)
{
    TCGState *s = TCG_STATE(obj);
    return s->splitwx_enabled;
}

static void tcg_set_splitwx(Object *obj, bool value, Error **errp)
{
    TCGState *s = TCG_STATE(obj);
    s->splitwx_enabled = value;
}

static bool tcg_get_one_insn_per_tb(Object *obj, Error **errp)
{
    TCGState *s = TCG_STATE(obj);
    return s->one_insn_per_tb;
}

static void tcg_set_one_insn_per_tb(Object *obj, bool value, Error **errp)
{
    TCGState *s = TCG_STATE(obj);
    s->one_insn_per_tb = value;
    /* Set the global also: this changes the behaviour */
    qatomic_set(&one_insn_per_tb, value);
}

static void tcg_accel_class_init(ObjectClass *oc, const void *data)
{
    AccelClass *ac = ACCEL_CLASS(oc);
    ac->name = "tcg";
    ac->init_machine = tcg_init_machine;
    ac->cpu_common_realize = tcg_exec_realizefn;
    ac->cpu_common_unrealize = tcg_exec_unrealizefn;
    ac->get_stats = tcg_get_stats;
    ac->allowed = &tcg_allowed;

    object_class_property_add_str(oc, "thread",
                                  tcg_get_thread,
                                  tcg_set_thread);

    object_class_property_add(oc, "tb-size", "uint32",
        tcg_get_tb_size, tcg_set_tb_size,
        NULL, NULL);
    object_class_property_set_description(oc, "tb-size",
        "TCG translation block cache size");

    object_class_property_add_bool(oc, "split-wx",
        tcg_get_splitwx, tcg_set_splitwx);
    object_class_property_set_description(oc, "split-wx",
        "Map jit pages into separate RW and RX regions");

    object_class_property_add_bool(oc, "one-insn-per-tb",
                                   tcg_get_one_insn_per_tb,
                                   tcg_set_one_insn_per_tb);
    object_class_property_set_description(oc, "one-insn-per-tb",
        "Only put one guest insn in each translation block");

    object_class_property_add_str(oc, "x-hostpoll",
                                  tcg_get_hostpoll, tcg_set_hostpoll);
    object_class_property_set_description(oc, "x-hostpoll",
        "how the main loop waits for its next timer on hosts without "
        "ppoll: poll (milliseconds, rounded up), kqueue (a nanosecond "
        "kqueue timer), spin (kqueue, waking early and polling until the "
        "deadline)");

    object_class_property_add(oc, "x-haltpoll", "uint32",
                              tcg_get_haltpoll, tcg_set_haltpoll, NULL, NULL);
    object_class_property_set_description(oc, "x-haltpoll",
        "multi-threaded TCG: the longest a halted vCPU spins, watching for "
        "an interrupt, before it sleeps (microseconds; 0, the default, "
        "never spins); the spin adapts below it");

    object_class_property_add(oc, "x-apicpost", "OnOffAuto",
                              tcg_get_apicpost, tcg_set_apicpost, NULL, NULL);
    object_class_property_set_description(oc, "x-apicpost",
        "x86: fixed edge IPIs written to the ICR are posted to their "
        "targets without the BQL (off, on, auto: on with multi-threaded "
        "TCG, without icount or record/replay)");

    object_class_property_add(oc, "x-apictimer", "OnOffAuto",
                              tcg_get_apictimer, tcg_set_apictimer, NULL, NULL);
    object_class_property_set_description(oc, "x-apictimer",
        "x86: the local APIC timer fires on its vCPU, woken by a deadline "
        "thread, instead of on the main loop (off, on, auto: as x-apicpost)");
}

static const TypeInfo tcg_accel_type = {
    .name = TYPE_TCG_ACCEL,
    .parent = TYPE_ACCEL,
    .instance_init = tcg_accel_instance_init,
    .class_init = tcg_accel_class_init,
    .instance_size = sizeof(TCGState),
};
module_obj(TYPE_TCG_ACCEL);

static void register_accel_types(void)
{
    type_register_static(&tcg_accel_type);
}

type_init(register_accel_types);
