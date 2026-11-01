/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Host floating-point control and status registers for AArch64.
 */

#ifndef HOST_FPENV_H
#define HOST_FPENV_H

#include "host/cpuinfo.h"

#define HOST_FPCR_FIZ           (1u << 0)   /* FEAT_AFP: flush inputs */
#define HOST_FPCR_AH            (1u << 1)   /* FEAT_AFP: alternate handling */
#define HOST_FPCR_NEP           (1u << 2)   /* FEAT_AFP: scalar ops merge */
#define HOST_FPCR_RMODE_SHIFT   22
#define HOST_FPCR_FZ            (1u << 24)

#define HOST_FPSR_IOC           (1u << 0)
#define HOST_FPSR_DZC           (1u << 1)
#define HOST_FPSR_OFC           (1u << 2)
#define HOST_FPSR_UFC           (1u << 3)
#define HOST_FPSR_IXC           (1u << 4)
#define HOST_FPSR_IDC           (1u << 7)
#define HOST_FPSR_FLAGS         (HOST_FPSR_IOC | HOST_FPSR_DZC | \
                                 HOST_FPSR_OFC | HOST_FPSR_UFC | \
                                 HOST_FPSR_IXC | HOST_FPSR_IDC)

/*
 * True if a target can run guest floating point on the host FPU in the
 * guest's own FP mode: with FEAT_AFP, FPCR can express x86's.
 */
static inline bool host_fpenv_native(void)
{
    return cpuinfo & CPUINFO_AFP;
}

/*
 * QEMU's own FP mode on a thread that runs guest FP natively.  AH and NEP
 * don't change what C code computes on ordinary values, and having them
 * set means a guest in its default FP mode needs no control register
 * write around cpu_exec().
 */
#define HOST_FP_CONTROL_QEMU    (HOST_FPCR_AH | HOST_FPCR_NEP)

static inline uint64_t host_fp_control_read(void)
{
    uint64_t v;

    asm volatile("mrs %0, fpcr" : "=r"(v));
    return v;
}

static inline void host_fp_control_write(uint64_t v)
{
    asm volatile("msr fpcr, %0" : : "r"(v));
}

/* The cumulative exception flags; FPSR.QC is nobody's state. */
static inline uint64_t host_fp_status_read(void)
{
    uint64_t v;

    asm volatile("mrs %0, fpsr" : "=r"(v));
    return v & HOST_FPSR_FLAGS;
}

static inline void host_fp_status_write(uint64_t v)
{
    asm volatile("msr fpsr, %0" : : "r"(v));
}

#endif /* HOST_FPENV_H */
