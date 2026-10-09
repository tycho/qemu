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
#include "host/counter.h"
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


struct TCGState {
    AccelState parent_obj;

    OnOffAuto mttcg_enabled;
    bool one_insn_per_tb;
    bool i386_runtime;
    int splitwx_enabled;
    unsigned long tb_size;
    bool iofast;
    bool hosttime;
    bool pause_hint;
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

/*
 * [DEV] The fork's defaults: on aarch64 hosts, every adopted setting is
 * on, host-aware ("auto" where a setting has it).  Applied through the
 * properties, so a default behaves exactly as the same setting given on
 * the command line or in QEMU_XTCG, which can still override it.
 */
static void xtcg_fork_defaults(Object *obj)
{
#if defined(__aarch64__)
    static const char *const defaults[][2] = {
        { "x-tso", "auto" },
        { "x-tso-vec", "none" },
        { "x-tso-stack", "on" },
        { "x-ssefp", "auto" },
        { "x-simd", "on" },
        { "x-regcache", "on" },
        { "x-pin", "on" },
        { "x-lazyinc", "on" },
        { "x-region", "on" },
        { "x-superblock", "4" },
        { "x-tblookup", "on" },
        { "x-i386-runtime", "on" },
        { "x-addr32", "on" },
        { "x-iofast", "on" },
        { "x-hosttime", "on" },
        { "x-tlb-grow", "1" },
        { "x-pause", "hint" },
        { "x-cr3-flush", "nonglobal" },
#ifdef CONFIG_DARWIN
        { "x-jitwx", "lazy" },
#endif
    };

    for (int i = 0; i < ARRAY_SIZE(defaults); i++) {
        object_property_parse(obj, defaults[i][0], defaults[i][1],
                              &error_abort);
    }
#endif
}

static void tcg_accel_instance_init(Object *obj)
{
    TCGState *s = TCG_STATE(obj);

    /* If debugging enabled, default "auto on", otherwise off. */
#if defined(CONFIG_DEBUG_TCG) && !defined(CONFIG_USER_ONLY)
    s->splitwx_enabled = -1;
#else
    s->splitwx_enabled = 0;
#endif
    xtcg_fork_defaults(obj);
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
    CPUClass *cc = CPU_CLASS(object_class_by_name(target_cpu_type()));
    unsigned max_threads = 1;

#ifndef CONFIG_USER_ONLY
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
     * x-iofast: TBs end after instructions known to do I/O; a TB ends to
     * let an interrupt be taken only when one is pending; MMIO from
     * generated code to lockless_io regions skips the BQL; the x86 local
     * APIC serves a vCPU's own TPR accesses and the MC146818 RTC its
     * index writes and update-in-progress polls without the BQL; and the
     * local APIC has no kvmvapic option ROM, which patches a guest's TPR
     * accesses into port I/O so that KVM avoids an exit per access, but
     * under TCG makes each one an I/O exit and invalidates code on its
     * ROM page.  The device settings are accelerator compat properties,
     * so an explicit -global still wins.
     */
    if (s->iofast) {
        static GlobalProperty iofast_props[] = {
            { "apic", "x-lockless-tpr", "on" },
            { "apic", "vapic", "off" },
            { "mc146818rtc", "x-lockless-uip", "on" },
        };
        AccelClass *ac = ACCEL_GET_CLASS(as);

        tcg_iolast = true;
        tcg_mmio_lockless = true;
        tcg_exit_irq_only = true;
        if (!ac->compat_props) {
            ac->compat_props = g_ptr_array_new();
        }
        compat_props_add(ac->compat_props, iofast_props,
                         G_N_ELEMENTS(iofast_props));
    }
#endif

    /*
     * x-hosttime: QEMU's clock from CLOCK_MONOTONIC_RAW, and the x86 TSC
     * from the host's constant-rate counter.  Not the TSC with icount,
     * where it must follow the instruction count so that record and
     * replay see the same values.
     */
    if (s->hosttime) {
#if QEMU_CLOCK_RAW_SUPPORTED
        qemu_clock_use_raw();
#endif
        tcg_tsc_counter = HOST_COUNTER_SUPPORTED && !icount_enabled();
    }

    /*
     * x-pause=hint: only where no other vCPU shares the thread (with
     * round-robin TCG the exit is how the others get to run).
     */
#ifdef CONFIG_USER_ONLY
    tcg_pause_hint = s->pause_hint;
#else
    tcg_pause_hint = s->pause_hint &&
                     (s->mttcg_enabled == ON_OFF_AUTO_ON ||
                      ms->smp.max_cpus == 1);
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

    tcg_fpcheck_runtime = s->i386_runtime;
    tcg_iopl_runtime = s->i386_runtime;

    tcg_jcgen = cc->tcg_ops->jmp_cache_salt;
#ifndef CONFIG_USER_ONLY
    tcg_jc_global = tcg_jcgen && tcg_ijmp_inline &&
                    tcg_cr3_flush == TCG_CR3_FLUSH_NONGLOBAL;
#else
    tcg_jc_ctx = tcg_jcgen && tcg_ijmp_inline;
#endif
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

bool tcg_ijmp_inline;
bool tcg_jcgen;
bool tcg_jc_keep_pcrel;
bool tcg_jc_global;
bool tcg_jc_ctx;

bool tcg_iolast;
bool tcg_mmio_lockless;
bool tcg_exit_irq_only;

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

static bool tcg_get_i386_runtime(Object *obj, Error **errp)
{
    return TCG_STATE(obj)->i386_runtime;
}

static void tcg_set_i386_runtime(Object *obj, bool value, Error **errp)
{
    TCG_STATE(obj)->i386_runtime = value;
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

static bool tcg_get_tso_stack(Object *obj, Error **errp)
{
    return tcg_tso_stack;
}

static void tcg_set_tso_stack(Object *obj, bool value, Error **errp)
{
    tcg_tso_stack = value;
}

static char *tcg_get_tso_vec(Object *obj, Error **errp)
{
    return g_strdup(tcg_tso_vec_none ? "none" :
                    tcg_tso_vec_group ? "group" : "strict");
}

static void tcg_set_tso_vec(Object *obj, const char *value, Error **errp)
{
    if (!strcmp(value, "strict")) {
        tcg_tso_vec_group = false;
        tcg_tso_vec_none = false;
    } else if (!strcmp(value, "group")) {
        tcg_tso_vec_group = true;
        tcg_tso_vec_none = false;
    } else if (!strcmp(value, "none")) {
        tcg_tso_vec_group = true;
        tcg_tso_vec_none = true;
    } else {
        error_setg(errp, "Invalid 'x-tso-vec' value: %s", value);
    }
}

static bool tcg_get_simd(Object *obj, Error **errp)
{
    return tcg_vecld && tcg_vecmem && tcg_vperm && tcg_vpermvar && tcg_vint;
}

static void tcg_set_simd(Object *obj, bool value, Error **errp)
{
    tcg_vecld = value;
    tcg_vecmem = value;
    tcg_vperm = value;
    tcg_vpermvar = value;
    tcg_vint = value;
}

static char *tcg_get_ssefp(Object *obj, Error **errp)
{
    return g_strdup(tcg_ssefp_native ? "native" :
                    tcg_ssefp_vec ? "vec" : "soft");
}

/*
 * Whether "auto" picks the softfloat vector fast paths where the host
 * can't run guest floating point natively: they are tuned for AArch64
 * hosts, and elsewhere "auto" keeps the lane-by-lane helpers.
 */
static bool tcg_ssefp_auto_vec(void)
{
#ifdef HOST_AARCH64
    return true;
#else
    return false;
#endif
}

static void tcg_set_ssefp(Object *obj, const char *value, Error **errp)
{
    bool native, vec;

    if (!strcmp(value, "native")) {
        if (!host_fpenv_native()) {
            error_setg(errp, "x-ssefp=native is not supported on this host");
            return;
        }
        native = true;
        vec = false;
    } else if (!strcmp(value, "auto")) {
        native = host_fpenv_native();
        vec = !native && tcg_ssefp_auto_vec();
    } else if (!strcmp(value, "vec")) {
        native = false;
        vec = true;
    } else if (!strcmp(value, "soft")) {
        native = false;
        vec = false;
    } else {
        error_setg(errp, "Invalid 'x-ssefp' value: %s", value);
        return;
    }
    tcg_ssefp_native = native;
    tcg_ssefp_vec = vec;
}

static bool tcg_get_regcache(Object *obj, Error **errp)
{
    return tcg_dse && tcg_ldstkeep && tcg_lazysync
           && tcg_vecglobal && tcg_ymmglobal && tcg_vregs_all;
}

static void tcg_set_regcache(Object *obj, bool value, Error **errp)
{
    tcg_dse = value;
    tcg_ldstkeep = value;
    tcg_lazysync = value;
    tcg_vecglobal = value;
    tcg_ymmglobal = value;
    tcg_vregs_all = value;
}

static bool tcg_get_pin(Object *obj, Error **errp)
{
    return tcg_pin;
}

static void tcg_set_pin(Object *obj, bool value, Error **errp)
{
    tcg_pin = value;
}

static bool tcg_get_region(Object *obj, Error **errp)
{
    return tcg_region;
}

static void tcg_set_region(Object *obj, bool value, Error **errp)
{
    tcg_region = value;
}

static bool tcg_get_tblookup(Object *obj, Error **errp)
{
    return tcg_ijmp_inline;
}

static void tcg_set_tblookup(Object *obj, bool value, Error **errp)
{
    tcg_ijmp_inline = value;
    tcg_tbpack = value;
    tcg_jc_keep_pcrel = value;
    tcg_tb_flags_canon = value;
}

static bool tcg_get_addr32(Object *obj, Error **errp)
{
    return tcg_addr32;
}

static void tcg_set_addr32(Object *obj, bool value, Error **errp)
{
    tcg_addr32 = value;
}

static bool tcg_get_iofast(Object *obj, Error **errp)
{
    return TCG_STATE(obj)->iofast;
}

static void tcg_set_iofast(Object *obj, bool value, Error **errp)
{
    TCG_STATE(obj)->iofast = value;
}

static bool tcg_get_hosttime(Object *obj, Error **errp)
{
    return TCG_STATE(obj)->hosttime;
}

static void tcg_set_hosttime(Object *obj, bool value, Error **errp)
{
    if (value && !QEMU_CLOCK_RAW_SUPPORTED && !HOST_COUNTER_SUPPORTED) {
        error_setg(errp, "x-hosttime: not supported on this host");
        return;
    }
    TCG_STATE(obj)->hosttime = value;
}

static char *tcg_get_pause(Object *obj, Error **errp)
{
    return g_strdup(TCG_STATE(obj)->pause_hint ? "hint" : "exit");
}

static void tcg_set_pause(Object *obj, const char *value, Error **errp)
{
    TCGState *s = TCG_STATE(obj);

    if (strcmp(value, "hint") == 0) {
        s->pause_hint = true;
    } else if (strcmp(value, "exit") == 0) {
        s->pause_hint = false;
    } else {
        error_setg(errp, "Invalid 'x-pause' value: %s (exit, hint)", value);
    }
}

static char *tcg_get_flags(Object *obj, Error **errp)
{
    return g_strdup(tcg_flags_guess ? "guess" : "off");
}

static void tcg_set_flags(Object *obj, const char *value, Error **errp)
{
    if (!strcmp(value, "guess")) {
        tcg_flags_guess = true;
    } else if (!strcmp(value, "off")) {
        tcg_flags_guess = false;
    } else {
        error_setg(errp, "Invalid 'x-flags' value: %s", value);
    }
}

static bool tcg_get_lazy_incdec(Object *obj, Error **errp)
{
    return tcg_lazy_incdec;
}

static void tcg_set_lazy_incdec(Object *obj, bool value, Error **errp)
{
    tcg_lazy_incdec = value;
}

static void tcg_get_superblock(Object *obj, Visitor *v, const char *name,
                               void *opaque, Error **errp)
{
    uint32_t value = tcg_superblock;

    visit_type_uint32(v, name, &value, errp);
}

static void tcg_set_superblock(Object *obj, Visitor *v, const char *name,
                               void *opaque, Error **errp)
{
    uint32_t value;

    if (!visit_type_uint32(v, name, &value, errp)) {
        return;
    }
    tcg_superblock = value;
}

static const char * const tcg_cr3_flush_names[] = {
    [TCG_CR3_FLUSH_ALL] = "all",
    [TCG_CR3_FLUSH_PAGING] = "paging",
    [TCG_CR3_FLUSH_NONGLOBAL] = "nonglobal",
};

static char *tcg_get_cr3_flush(Object *obj, Error **errp)
{
    return g_strdup(tcg_cr3_flush_names[tcg_cr3_flush]);
}

static void tcg_set_cr3_flush(Object *obj, const char *value, Error **errp)
{
    for (int i = 0; i < ARRAY_SIZE(tcg_cr3_flush_names); i++) {
        if (!strcmp(value, tcg_cr3_flush_names[i])) {
            tcg_cr3_flush = i;
            return;
        }
    }
    error_setg(errp, "Invalid 'x-cr3-flush' value: %s "
               "(all, paging, nonglobal)", value);
}

static bool tcg_get_pcid(Object *obj, Error **errp)
{
    return tcg_pcid;
}

static void tcg_set_pcid(Object *obj, bool value, Error **errp)
{
    tcg_pcid = value;
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

    object_class_property_add_bool(oc, "x-i386-runtime",
                                   tcg_get_i386_runtime,
                                   tcg_set_i386_runtime);
    object_class_property_set_description(oc, "x-i386-runtime",
        "x86 system mode: leave CR0.MP/EM/TS and EFLAGS.IOPL out of the "
        "TB flags and check them at run time, so one translation serves "
        "every FPU and IOPL state");

    object_class_property_add_str(oc, "x-tso", tcg_get_tso, tcg_set_tso);
    object_class_property_set_description(oc, "x-tso",
        "Guest memory ordering: barrier (default), "
        "acqrel (load-acquire/store-release accesses), "
        "auto (acqrel where the host supports it, else barrier), "
        "none (no barriers: unsafe, for measurement)");

    object_class_property_add_str(oc, "x-tso-vec", tcg_get_tso_vec,
                                  tcg_set_tso_vec);
    object_class_property_set_description(oc, "x-tso-vec",
        "Guest accesses wider than 8 bytes the guest doesn't make atomic: "
        "strict (each ordered, default), group (with x-tso=acqrel, "
        "barriers only where a run of them begins and ends: not exact), "
        "none (as group, and accesses to and from vector and "
        "floating-point registers unordered unless atomic: not exact)");

    object_class_property_add_bool(oc, "x-tso-stack",
                                   tcg_get_tso_stack, tcg_set_tso_stack);
    object_class_property_set_description(oc, "x-tso-stack",
        "qemu-user: guest accesses to the thread's own stack (x86: RSP-based, "
        "push/pop/call/ret) get no memory-order constraint");

    object_class_property_add_bool(oc, "x-simd", tcg_get_simd, tcg_set_simd);
    object_class_property_set_description(oc, "x-simd",
        "Keep guest vector code in host vector registers where the host "
        "backend can: vector loads and stores as host vector accesses, "
        "permutes and element inserts as host permutes and table lookups, "
        "integer vector operations as host vector operations");

    object_class_property_add_str(oc, "x-ssefp", tcg_get_ssefp, tcg_set_ssefp);
    object_class_property_set_description(oc, "x-ssefp",
        "SIMD floating point: soft (default, lane by lane), vec (compute "
        "whole vectors on the host FPU when that gives the same results "
        "and flags), native (run with the guest's FP mode in the host "
        "FPU; needs a host that can express it) or auto (native where "
        "possible, else vec on AArch64 hosts and soft elsewhere)");

    object_class_property_add_bool(oc, "x-regcache",
                                   tcg_get_regcache, tcg_set_regcache);
    object_class_property_set_description(oc, "x-regcache",
        "Keep guest registers in host registers: remove dead stores to CPU "
        "state, keep dirty and vector values in registers across guest "
        "memory accesses, and the x86 vector registers as TCG globals");

    object_class_property_add_bool(oc, "x-pin", tcg_get_pin, tcg_set_pin);
    object_class_property_set_description(oc, "x-pin",
        "Keep the guest's most used registers in host registers across "
        "TBs (user mode, where the host supports it)");

    object_class_property_add_bool(oc, "x-region",
                                   tcg_get_region, tcg_set_region);
    object_class_property_set_description(oc, "x-region",
        "Let a translation block loop back to its own start instead of "
        "chaining to itself, keeping the loop's guest registers in host "
        "registers (not with plugins or icount)");

    object_class_property_add_bool(oc, "x-tblookup",
                                   tcg_get_tblookup, tcg_set_tblookup);
    object_class_property_set_description(oc, "x-tblookup",
        "Find the next TB from generated code: probe the jump cache at "
        "indirect jumps (in a short helper call at direct jumps to "
        "another page), and pack TB structs next to their code (x86 "
        "guests)");

    object_class_property_add_bool(oc, "x-addr32",
                                   tcg_get_addr32, tcg_set_addr32);
    object_class_property_set_description(oc, "x-addr32",
        "Translate with 32-bit guest addresses where the target allows "
        "(x86 outside long mode): no zero-extension per access");

    object_class_property_add_bool(oc, "x-iofast",
                                   tcg_get_iofast, tcg_set_iofast);
    object_class_property_set_description(oc, "x-iofast",
        "System mode: end TBs after instructions known to do I/O (not "
        "with icount), MMIO to lockless_io regions without the BQL, the "
        "x86 APIC's TPR and the RTC's update polls without the BQL, and "
        "no kvmvapic option ROM");

    object_class_property_add_bool(oc, "x-hosttime",
                                   tcg_get_hosttime, tcg_set_hosttime);
    object_class_property_set_description(oc, "x-hosttime",
        "QEMU's clock from CLOCK_MONOTONIC_RAW (unadjusted, and on macOS "
        "finer than 1 us), and the x86 TSC from the host's constant-rate "
        "counter, read inline, invariant, with IA32_TSC_ADJUST (not with "
        "icount)");

    object_class_property_add(oc, "x-tlb-grow", "uint32",
        tcg_get_tlb_grow, tcg_set_tlb_grow, NULL, NULL);
    object_class_property_set_description(oc, "x-tlb-grow",
        "Grow a softmmu TLB between flushes once it has had this many "
        "times its size in fills within 100 ms while over 70% used "
        "(0: resize only at flushes, the default)");

    object_class_property_add_str(oc, "x-jitwx", tcg_get_jitwx, tcg_set_jitwx);
    object_class_property_set_description(oc, "x-jitwx",
        "macOS MAP_JIT write/execute toggles: always (default) or lazy "
        "(skip the calls that wouldn't change the thread's mode); "
        "no effect on other hosts");

    object_class_property_add_str(oc, "x-pause", tcg_get_pause, tcg_set_pause);
    object_class_property_set_description(oc, "x-pause",
        "x86 PAUSE: leave the execution loop (exit, QEMU's) or a host "
        "spin hint inline (hint; with a thread per vCPU)");

    object_class_property_add_str(oc, "x-flags", tcg_get_flags,
                                  tcg_set_flags);
    object_class_property_set_description(oc, "x-flags",
        "Guest condition codes at block entry: off (compute them with the "
        "front end's helper) or guess (inline code for the state the "
        "block was translated in, tested at run time)");

    object_class_property_add_bool(oc, "x-lazyinc",
                                   tcg_get_lazy_incdec,
                                   tcg_set_lazy_incdec);
    object_class_property_set_description(oc, "x-lazyinc",
        "x86: INC and DEC after an unknown flags state keep that state "
        "for CF rather than computing it");

    object_class_property_add(oc, "x-superblock", "uint32",
        tcg_get_superblock, tcg_set_superblock, NULL, NULL);
    object_class_property_set_description(oc, "x-superblock",
        "With x-region: after this many profile samples (one per ms) in a "
        "loop, translate the loop's blocks that have run as one translation "
        "block (0: never, the default)");

    object_class_property_add_str(oc, "x-cr3-flush",
                                  tcg_get_cr3_flush, tcg_set_cr3_flush);
    object_class_property_set_description(oc, "x-cr3-flush",
        "x86: what a CR3 write flushes from the TLB: all (every mmu index), "
        "paging (not the physical-address ones, which don't depend on "
        "CR3), or nonglobal (as paging, but keep global pages, as a MOV "
        "to CR3 without PCIDs does)");

    object_class_property_add_bool(oc, "x-pcid", tcg_get_pcid, tcg_set_pcid);
    object_class_property_set_description(oc, "x-pcid",
        "x86: offer process-context identifiers (CPUID PCID and INVPCID)");
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
