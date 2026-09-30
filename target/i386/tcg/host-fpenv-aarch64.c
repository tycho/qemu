/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * x86 MXCSR on an AArch64 host FPU with FEAT_AFP.  See host-fpenv.h.
 *
 * With FPCR.AH set, AArch64 floating point behaves as x86's: which NaN an
 * operation returns, the default NaN, the denormal-operand flag, tininess
 * detected after rounding, and FMIN/FMAX on NaNs and zeros.  FPCR.FIZ is
 * MXCSR.DAZ, FPCR.FZ is MXCSR.FTZ, and FPCR.NEP makes scalar operations
 * keep the upper lanes of the destination.
 *
 * AH and NEP are part of QEMU's own FP mode on a vCPU thread
 * (HOST_FP_CONTROL_QEMU), so a guest with the default MXCSR needs no FPCR
 * write on entry to cpu_exec.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "fpu/softfloat.h"
#include "tcg/startup.h"
#include "accel/tcg/host-fp.h"
#include "host/fpenv.h"
#include "host-fpenv.h"

extern bool float_force_soft;

static uint64_t guest_fpcr(uint32_t mxcsr)
{
    /* x86 RC: nearest, down, up, zero; FPCR.RMode: nearest, up, down, zero. */
    static const uint8_t rmode[4] = { 0, 2, 1, 3 };
    uint64_t fpcr = HOST_FP_CONTROL_QEMU;

    fpcr |= (uint64_t)rmode[(mxcsr >> 13) & 3] << HOST_FPCR_RMODE_SHIFT;
    if (mxcsr & 0x8000) {
        fpcr |= HOST_FPCR_FZ;
    }
    if (mxcsr & 0x0040) {
        fpcr |= HOST_FPCR_FIZ;
    }
    if (float_force_soft) {
        /* [DEV] Trap every host FP exception: none is the guest's. */
        fpcr |= 0x9f00;
    }
    return fpcr;
}

static uint64_t fpsr_from_flags(int flags)
{
    return (flags & float_flag_invalid ? HOST_FPSR_IOC : 0) |
           (flags & float_flag_divbyzero ? HOST_FPSR_DZC : 0) |
           (flags & float_flag_overflow ? HOST_FPSR_OFC : 0) |
           (flags & float_flag_underflow ? HOST_FPSR_UFC : 0) |
           (flags & float_flag_inexact ? HOST_FPSR_IXC : 0) |
           (flags & float_flag_input_denormal_used ? HOST_FPSR_IDC : 0);
}

static uint64_t guest_fpsr(CPUX86State *env)
{
    return fpsr_from_flags(get_float_exception_flags(&env->sse_status));
}

static int flags_from_fpsr(uint64_t fpsr)
{
    return (fpsr & HOST_FPSR_IOC ? float_flag_invalid : 0) |
           (fpsr & HOST_FPSR_DZC ? float_flag_divbyzero : 0) |
           (fpsr & HOST_FPSR_OFC ? float_flag_overflow : 0) |
           (fpsr & HOST_FPSR_UFC ? float_flag_underflow : 0) |
           (fpsr & HOST_FPSR_IXC ? float_flag_inexact : 0) |
           (fpsr & HOST_FPSR_IDC ? float_flag_input_denormal_used : 0);
}

void x86_host_fp_enter(CPUX86State *env)
{
    if (tcg_ssefp_native) {
        tcg_host_fp_acquire(env_cpu(env), guest_fpcr(env->mxcsr),
                            guest_fpsr(env));
    }
}

void x86_host_fp_fold(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);

    if (cs->host_fp_guest) {
        int flags = flags_from_fpsr(tcg_host_fp_status(cs));

        if (flags & ~get_float_exception_flags(&env->sse_status)) {
            float_raise(flags, &env->sse_status);
        }
    }
}

void x86_host_fp_exit(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);

    if (cs->host_fp_guest) {
        x86_host_fp_fold(env);
        tcg_host_fp_release(cs);
    }
}

void x86_host_fp_sync(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);

    if (cs->host_fp_guest) {
        tcg_host_fp_load(cs, guest_fpcr(env->mxcsr), guest_fpsr(env));
    }
}
