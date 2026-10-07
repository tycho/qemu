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
    return false;
}

/*
 * Writes to the read-only MSRs, and to MSRs of enlightenments TCG doesn't
 * implement, are ignored, as are unknown MSRs.
 */
bool x86_tcg_hyperv_wrmsr(CPUX86State *env, uint32_t msr, uint64_t val)
{
    X86CPU *cpu = env_archcpu(env);

    if (!x86_tcg_hyperv(cpu)) {
        return false;
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
        return true;
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
        return true;
    case HV_X64_MSR_REFERENCE_TSC:
        if (!hyperv_feat_enabled(cpu, HYPERV_FEAT_TIME)) {
            return false;
        }
        bql_lock();
        HV_SET_ALL(msr_hv_tsc, val & (HV_REFTSC_GPA_MASK | HV_REFTSC_ENABLE));
        hv_update_tsc_page();
        bql_unlock();
        return true;
    case HV_X64_MSR_VP_INDEX:
    case HV_X64_MSR_TIME_REF_COUNT:
    case HV_X64_MSR_TSC_FREQUENCY:
    case HV_X64_MSR_APIC_FREQUENCY:
        return true;
    }
    return false;
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
