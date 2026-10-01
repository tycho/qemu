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
#include "system/tcg.h"
#include "exec/replay-core.h"
#include "exec/icount.h"
#include "tcg/startup.h"
#include "host/fpenv.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/accel.h"
#include "qemu/atomic.h"
#include "qapi/qapi-types-common.h"
#include "qapi/qapi-builtin-visit.h"
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
#include "qemu/xtcg-stats.h"


struct TCGState {
    AccelState parent_obj;

    OnOffAuto mttcg_enabled;
    bool one_insn_per_tb;
    int splitwx_enabled;
    unsigned long tb_size;
    bool kvmvapic;
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

static void xtcg_fork_defaults(TCGState *s);

static void tcg_accel_instance_init(Object *obj)
{
    TCGState *s = TCG_STATE(obj);

    /* If debugging enabled, default "auto on", otherwise off. */
#if defined(CONFIG_DEBUG_TCG) && !defined(CONFIG_USER_ONLY)
    s->splitwx_enabled = -1;
#else
    s->splitwx_enabled = 0;
#endif
    s->kvmvapic = true;
    xtcg_fork_defaults(s);
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
     * x-kvmvapic=off: no kvmvapic option ROM behind the x86 local APIC.
     * It patches a guest's TPR accesses into port I/O so that KVM avoids
     * an exit per access; under TCG each one becomes an I/O exit and its
     * state updates invalidate code on the ROM page.  As an accelerator
     * compat property it yields to -global apic.vapic=on.
     */
    if (!s->kvmvapic) {
        static GlobalProperty novapic[] = {
            { "apic", "vapic", "off" },
        };
        AccelClass *ac = ACCEL_GET_CLASS(as);

        if (!ac->compat_props) {
            ac->compat_props = g_ptr_array_new();
        }
        compat_props_add(ac->compat_props, novapic, G_N_ELEMENTS(novapic));
    }
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

unsigned tcg_tlb_grow;

static void tcg_get_tlb_grow(Object *obj, Visitor *v, const char *name,
                             void *opaque, Error **errp)
{
    uint32_t value = tcg_tlb_grow;

    visit_type_uint32(v, name, &value, errp);
}

static void tcg_set_tlb_grow(Object *obj, Visitor *v, const char *name,
                             void *opaque, Error **errp)
{
    uint32_t value;

    if (!visit_type_uint32(v, name, &value, errp)) {
        return;
    }
    tcg_tlb_grow = value;
}

bool tcg_ijmp_inline;

static char *tcg_get_ijmp(Object *obj, Error **errp)
{
    return g_strdup(tcg_ijmp_inline ? "inline" : "helper");
}

static void tcg_set_ijmp(Object *obj, const char *value, Error **errp)
{
    if (!strcmp(value, "inline")) {
        tcg_ijmp_inline = true;
    } else if (!strcmp(value, "helper")) {
        tcg_ijmp_inline = false;
    } else {
        error_setg(errp, "Invalid 'x-ijmp' value: %s", value);
    }
}

static void tcg_get_tso_promote(Object *obj, Visitor *v,
                                const char *name, void *opaque,
                                Error **errp)
{
    uint32_t value = tcg_tso_promote;

    visit_type_uint32(v, name, &value, errp);
}

static void tcg_set_tso_promote(Object *obj, Visitor *v,
                                const char *name, void *opaque,
                                Error **errp)
{
    uint32_t value;

    if (!visit_type_uint32(v, name, &value, errp)) {
        return;
    }
    tcg_tso_promote = value;
}

static bool tcg_get_pferr_hw(Object *obj, Error **errp)
{
    return tcg_pferr_hw;
}

static void tcg_set_pferr_hw(Object *obj, bool value, Error **errp)
{
    tcg_pferr_hw = value;
}

static bool tcg_get_vecmem(Object *obj, Error **errp)
{
    return tcg_vecmem;
}

static void tcg_set_vecmem(Object *obj, bool value, Error **errp)
{
    tcg_vecmem = value;
}

static bool tcg_get_vperm(Object *obj, Error **errp)
{
    return tcg_vperm;
}

static void tcg_set_vperm(Object *obj, bool value, Error **errp)
{
    tcg_vperm = value;
}

static bool tcg_get_ldstkeep(Object *obj, Error **errp)
{
    return tcg_ldstkeep;
}

static void tcg_set_ldstkeep(Object *obj, bool value, Error **errp)
{
    tcg_ldstkeep = value;
}

static bool tcg_get_region(Object *obj, Error **errp)
{
    return tcg_region;
}

static void tcg_set_region(Object *obj, bool value, Error **errp)
{
    tcg_region = value;
}

static bool tcg_get_vecglobal(Object *obj, Error **errp)
{
    return tcg_vecglobal;
}

static void tcg_set_vecglobal(Object *obj, bool value, Error **errp)
{
    tcg_vecglobal = value;
}

static bool tcg_get_lazysync(Object *obj, Error **errp)
{
    return tcg_lazysync;
}

static void tcg_set_lazysync(Object *obj, bool value, Error **errp)
{
    tcg_lazysync = value;
}

static bool tcg_get_dse(Object *obj, Error **errp)
{
    return tcg_dse;
}

static void tcg_set_dse(Object *obj, bool value, Error **errp)
{
    tcg_dse = value;
}

static bool tcg_get_vecld(Object *obj, Error **errp)
{
    return tcg_vecld;
}

static void tcg_set_vecld(Object *obj, bool value, Error **errp)
{
    tcg_vecld = value;
}

static char *tcg_get_ssefp(Object *obj, Error **errp)
{
    return g_strdup(tcg_ssefp_native ? "native" :
                    tcg_ssefp_vec ? "vec" : "soft");
}

static void tcg_set_ssefp(Object *obj, const char *value, Error **errp)
{
    if (!strcmp(value, "native")) {
        if (!host_fpenv_native()) {
            error_setg(errp, "x-ssefp=native is not supported on this host");
            return;
        }
        tcg_ssefp_native = true;
        tcg_ssefp_vec = false;
    } else if (!strcmp(value, "auto")) {
        /* native where the host can take the guest's FP mode, else vec */
        tcg_ssefp_native = host_fpenv_native();
        tcg_ssefp_vec = !tcg_ssefp_native;
    } else if (!strcmp(value, "vec")) {
        tcg_ssefp_vec = true;
        tcg_ssefp_native = false;
    } else if (!strcmp(value, "soft")) {
        tcg_ssefp_vec = false;
        tcg_ssefp_native = false;
    } else {
        error_setg(errp, "Invalid 'x-ssefp' value: %s", value);
    }
}

static char *tcg_get_jitwx(Object *obj, Error **errp)
{
#ifdef CONFIG_DARWIN
    return g_strdup(qemu_thread_jit_lazy ? "lazy" : "always");
#else
    return g_strdup("always");
#endif
}

static void tcg_set_jitwx(Object *obj, const char *value, Error **errp)
{
    bool lazy = !strcmp(value, "lazy");

    if (!lazy && strcmp(value, "always")) {
        error_setg(errp, "Invalid 'x-jitwx' value: %s", value);
        return;
    }
#ifdef CONFIG_DARWIN
    qemu_thread_jit_lazy = lazy;
#endif
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

static bool tcg_get_kvmvapic(Object *obj, Error **errp)
{
    return TCG_STATE(obj)->kvmvapic;
}

static void tcg_set_kvmvapic(Object *obj, bool value, Error **errp)
{
    TCG_STATE(obj)->kvmvapic = value;
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

static const char * const tcg_tso_names[] = {
    [TCG_TSO_BARRIER] = "barrier",
    [TCG_TSO_ACQREL] = "acqrel",
    [TCG_TSO_NONE] = "none",
};

static char *tcg_get_tso(Object *obj, Error **errp)
{
    return g_strdup(tcg_tso_names[tcg_tso_mode]);
}

static void tcg_set_tso(Object *obj, const char *value, Error **errp)
{
    if (!strcmp(value, "auto")) {
        tcg_tso_mode = tcg_can_ldst_acqrel() ? TCG_TSO_ACQREL
                                             : TCG_TSO_BARRIER;
        return;
    }
    for (int i = 0; i < ARRAY_SIZE(tcg_tso_names); i++) {
        if (tcg_tso_names[i] && !strcmp(value, tcg_tso_names[i])) {
            if (i == TCG_TSO_ACQREL && !tcg_can_ldst_acqrel()) {
                error_setg(errp, "x-tso=acqrel is not supported on this host");
                return;
            }
            tcg_tso_mode = i;
            return;
        }
    }
    error_setg(errp, "Invalid 'x-tso' value: %s", value);
}

static bool tcg_get_xtcg_stats(Object *obj, Error **errp)
{
    return xtcg_stats;
}

static void tcg_set_xtcg_stats(Object *obj, bool value, Error **errp)
{
    xtcg_stats_enable(value);
}

/*
 * Fork defaults ([DEV], not for upstream): the adopted x- settings are on
 * where they have been validated, on aarch64 hosts, each as far as the
 * host supports it; on other hosts every setting keeps QEMU's default.
 * Properties given on the command line or in QEMU_XTCG still override
 * these (x-tso=barrier,x-ssefp=soft,... for QEMU's behaviour).
 */
static void xtcg_fork_defaults(TCGState *s)
{
#if defined(__aarch64__)
    tcg_tso_mode = tcg_can_ldst_acqrel() ? TCG_TSO_ACQREL : TCG_TSO_BARRIER;
    tcg_ssefp_native = host_fpenv_native();
    tcg_ssefp_vec = !tcg_ssefp_native;
    tcg_ijmp_inline = true;
    tcg_tlb_grow = 1;
    tcg_vecld = true;
    tcg_vperm = true;
    tcg_dse = true;
    tcg_ldstkeep = true;
    tcg_vecmem = true;
    tcg_lazysync = true;
    tcg_vecglobal = true;
    tcg_region = true;
    tcg_pferr_hw = true;
    s->kvmvapic = false;
#ifdef CONFIG_DARWIN
    qemu_thread_jit_lazy = true;
#endif
#endif
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

    object_class_property_add_str(oc, "x-tso", tcg_get_tso, tcg_set_tso);
    object_class_property_set_description(oc, "x-tso",
        "Guest memory ordering: barrier (default), "
        "acqrel (load-acquire/store-release accesses), "
        "auto (acqrel where the host supports it, else barrier), "
        "none (no barriers: unsafe, for measurement)");

    object_class_property_add(oc, "x-tso-promote", "uint32",
        tcg_get_tso_promote, tcg_set_tso_promote, NULL, NULL);
    object_class_property_set_description(oc, "x-tso-promote",
        "With x-tso=acqrel: retranslate a guest insn whose access crossed "
        "a 16-byte boundary this many times with a branch-free form "
        "(0: never; default 1)");

    object_class_property_add_bool(oc, "x-stats",
                                   tcg_get_xtcg_stats,
                                   tcg_set_xtcg_stats);
    object_class_property_set_description(oc, "x-stats",
        "xtcg: count TCG events and print them to stderr at exit");

    object_class_property_add(oc, "x-tlb-grow", "uint32",
        tcg_get_tlb_grow, tcg_set_tlb_grow, NULL, NULL);
    object_class_property_set_description(oc, "x-tlb-grow",
        "Grow a softmmu TLB between flushes once it has had this many "
        "times its size in fills within 100 ms while over 70% used "
        "(0: resize only at flushes, the default)");

    object_class_property_add_bool(oc, "x-kvmvapic",
                                   tcg_get_kvmvapic, tcg_set_kvmvapic);
    object_class_property_set_description(oc, "x-kvmvapic",
        "x86 system: the kvmvapic option ROM behind the local APIC (on, "
        "the default; off avoids an I/O exit per guest TPR access)");

    object_class_property_add_str(oc, "x-ijmp", tcg_get_ijmp, tcg_set_ijmp);
    object_class_property_set_description(oc, "x-ijmp",
        "Look up the next TB at an indirect or cross-page jump: helper "
        "(default) or inline (probe the jump cache in generated code, "
        "call the helper on a miss)");

    object_class_property_add_str(oc, "x-ssefp", tcg_get_ssefp, tcg_set_ssefp);
    object_class_property_set_description(oc, "x-ssefp",
        "SIMD floating point: soft (default, lane by lane), vec (compute "
        "whole vectors on the host FPU when that gives the same results "
        "and flags), native (run with the guest's FP mode in the host "
        "FPU; needs a host that can express it) or auto (native where "
        "possible, else vec)");

    object_class_property_add_str(oc, "x-jitwx", tcg_get_jitwx, tcg_set_jitwx);
    object_class_property_set_description(oc, "x-jitwx",
        "macOS MAP_JIT write/execute toggles: always (default) or lazy "
        "(skip the calls that wouldn't change the thread's mode); "
        "no effect on other hosts");

    object_class_property_add_bool(oc, "x-vecld",
                                   tcg_get_vecld, tcg_set_vecld);
    object_class_property_set_description(oc, "x-vecld",
        "Build guest vector loads in a host vector register instead of "
        "storing them to CPU state in pieces");

    object_class_property_add_bool(oc, "x-vecmem",
                                   tcg_get_vecmem, tcg_set_vecmem);
    object_class_property_set_description(oc, "x-vecmem",
        "Load and store guest vectors with host vector loads and stores "
        "where the access needs no more than 64-bit atomicity");

    object_class_property_add_bool(oc, "x-vperm",
                                   tcg_get_vperm, tcg_set_vperm);
    object_class_property_set_description(oc, "x-vperm",
        "Generate guest vector shuffles, unpacks and blends with constant "
        "operands as host permutes instead of helper calls");

    object_class_property_add_bool(oc, "x-dse",
                                   tcg_get_dse, tcg_set_dse);
    object_class_property_set_description(oc, "x-dse",
        "Remove stores to CPU state that a later store in the same "
        "extended basic block overwrites before anything can read them");

    object_class_property_add_bool(oc, "x-ldstkeep",
                                   tcg_get_ldstkeep, tcg_set_ldstkeep);
    object_class_property_set_description(oc, "x-ldstkeep",
        "Keep vector values in registers across guest memory accesses; "
        "the accesses' slow paths save them");

    object_class_property_add_bool(oc, "x-region",
                                   tcg_get_region, tcg_set_region);
    object_class_property_set_description(oc, "x-region",
        "Let a translation block loop back to its own start instead of "
        "chaining to itself");

    object_class_property_add_bool(oc, "x-vecglobal",
                                   tcg_get_vecglobal, tcg_set_vecglobal);
    object_class_property_set_description(oc, "x-vecglobal",
        "Keep guest vector registers in host registers within a "
        "translation block");

    object_class_property_add_bool(oc, "x-lazysync",
                                   tcg_get_lazysync, tcg_set_lazysync);
    object_class_property_set_description(oc, "x-lazysync",
        "Keep dirty guest registers in host registers across guest memory "
        "accesses; a faulting access stores them (aarch64 hosts)");

    object_class_property_add_bool(oc, "x-pferr-hw",
                                   tcg_get_pferr_hw, tcg_set_pferr_hw);
    object_class_property_set_description(oc, "x-pferr-hw",
        "Report page-fault error codes as hardware does (x86: a "
        "read-modify-write faults as a write)");
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
