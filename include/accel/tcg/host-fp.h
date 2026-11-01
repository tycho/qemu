/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The host floating-point environment as guest state.
 *
 * A target may load the guest's FP mode and cumulative exception flags
 * into the host's FP control and status registers for the time a vCPU
 * thread spends in cpu_exec(), so that guest floating point can run on the
 * host FPU with nothing to set up or collect around each operation.
 *
 * While it does, host floating point executed by QEMU's own C code reads
 * the guest's mode and raises the guest's flags.  There are two ways to
 * live with that:
 *
 * - C code that implements guest floating point executes a host FP
 *   instruction only on values it has validated with integer tests, so
 *   that any flag it raises is one the guest operation raises too.
 *   Softfloat's hardfloat paths do; its vector fast paths
 *   (fpu/softfloat-vec.h) compute first and check afterwards, so they
 *   can't be used.
 *
 * - C code that can't vouch for what it calls (translation, device
 *   emulation, libm) brackets the call with tcg_host_fp_suspend() and
 *   tcg_host_fp_resume().  Between them the thread has QEMU's own FP
 *   environment, and what happens to the FP status there is discarded.
 *   Brackets nest.  One left by longjmp is closed when cpu_exec() catches
 *   the jump.
 */

#ifndef ACCEL_TCG_HOST_FP_H
#define ACCEL_TCG_HOST_FP_H

#include "hw/core/cpu.h"

/*
 * cpu_exec() entry: the host registers hold guest state from here on.
 * @control and @status are host register values.
 */
void tcg_host_fp_acquire(CPUState *cpu, uint64_t control, uint64_t status);
/* cpu_exec() exit: back to QEMU's own FP mode; the status is left as is. */
void tcg_host_fp_release(CPUState *cpu);
/* The guest's FP mode or flags changed other than by host FP operations. */
void tcg_host_fp_load(CPUState *cpu, uint64_t control, uint64_t status);
/* The host status register as the guest sees it. */
uint64_t tcg_host_fp_status(CPUState *cpu);

void tcg_host_fp_do_suspend(CPUState *cpu);
void tcg_host_fp_do_resume(CPUState *cpu);
/* Close the brackets a longjmp to cpu->jmp_env left open. */
void tcg_host_fp_unwind(CPUState *cpu);

static inline void tcg_host_fp_suspend(CPUState *cpu)
{
    if (cpu->host_fp_guest) {
        tcg_host_fp_do_suspend(cpu);
    }
}

static inline void tcg_host_fp_resume(CPUState *cpu)
{
    if (cpu->host_fp_guest) {
        tcg_host_fp_do_resume(cpu);
    }
}

static inline CPUState *tcg_host_fp_auto_suspend(CPUState *cpu)
{
    tcg_host_fp_suspend(cpu);
    return cpu;
}

static inline void tcg_host_fp_auto_resume(CPUState **cpu)
{
    tcg_host_fp_resume(*cpu);
}

/* Suspend until the end of the enclosing block. */
#define TCG_HOST_FP_SUSPEND_GUARD(cpu)                                  \
    CPUState *glue(tcg_host_fp_guard_, __COUNTER__)                     \
        __attribute__((cleanup(tcg_host_fp_auto_resume), unused)) =     \
        tcg_host_fp_auto_suspend(cpu)

#endif /* ACCEL_TCG_HOST_FP_H */
