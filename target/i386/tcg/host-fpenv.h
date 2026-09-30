/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Running x86 SSE floating point on the host FPU in the guest's FP mode
 * (x-ssefp=native).
 *
 * While a vCPU thread is in cpu_exec, the host FP control register holds
 * the guest's MXCSR mode (rounding, DAZ, FTZ) and the host's cumulative
 * exception flags are the guest's: MXCSR flags are those of
 * env->sse_status plus the host's.  Outside cpu_exec the thread has
 * QEMU's own FP mode, which is the mode of the default MXCSR.
 *
 * accel/tcg/host-fp.h has the rules this puts on C code inside cpu_exec.
 */

#ifndef I386_TCG_HOST_FPENV_H
#define I386_TCG_HOST_FPENV_H

#include "cpu.h"

#ifdef HOST_AARCH64
/* cpu_exec entry and exit. */
void x86_host_fp_enter(CPUX86State *env);
void x86_host_fp_exit(CPUX86State *env);
/* Add the host's exception flags to env->sse_status. */
void x86_host_fp_fold(CPUX86State *env);
/* The guest wrote MXCSR: load its mode and flags into the host. */
void x86_host_fp_sync(CPUX86State *env);
#else
static inline void x86_host_fp_enter(CPUX86State *env) {}
static inline void x86_host_fp_exit(CPUX86State *env) {}
static inline void x86_host_fp_fold(CPUX86State *env) {}
static inline void x86_host_fp_sync(CPUX86State *env) {}
#endif

#endif /* I386_TCG_HOST_FPENV_H */
