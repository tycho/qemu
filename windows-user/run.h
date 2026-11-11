/*
 * xtajit: running guest code until an exit Windows has to see, as one
 * core that each module's loop builds on.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef WINDOWS_USER_RUN_H
#define WINDOWS_USER_RUN_H

#include "qemu/atomic.h"
#include "hw/core/cpu.h"
#include "accel/tcg/cpu-loop.h"
#include "xtajit.h"

/* exec.c: the core's slow paths */
bool xt_run_handled(XtThread *t, int trapnr);
void xt_run_exit(XtThread *t, int trapnr, XtExit *x);

/*
 * Run guest code until an exit Windows has to see; the engine owns the
 * thread throughout.  Handled here, without leaving ownership: kicks
 * (exit requests, queued work such as flushes), the timer (int 0x81) and
 * the serial step of an atomic operation (EXCP_ATOMIC).  The system-call
 * stub's exit captures the number and argument pointer and completes the
 * stub's return (EIP from the stack, ESP + 4) before it is published.
 *
 * XT_EXCP_NATIVE for a transfer to native code (at t->native_target);
 * any other exit's trap number, or XT_EXCP_SUSPEND for a suspension
 * request, is xt_run_exit's to describe.  No XtExit on the way: the
 * build zero-fills automatic variables, which a transfer to native code
 * would pay for at every call.
 */
static inline QEMU_ALWAYS_INLINE int xt_run_core(XtThread *t)
{
    CPUState *cs = t->cpu;
    bool stepping;
    int trapnr;

    for (;;) {
        /*
         * A suspension request is checked here, between runs, as well as
         * ending the run (cpu_exit): qemu_process_cpu_events clears an
         * exit request that arrives after cpu_exec has returned.
         */
        if (unlikely(qatomic_read(&t->suspend_req))) {
            return XT_EXCP_SUSPEND;
        }
        t->after_suspend = false;
        t->gfault.code = 0;
        /* Past a breakpoint (xt_import): one instruction, stepped. */
        stepping = t->bp_skip;
        if (unlikely(stepping)) {
            t->bp_skip = false;
            cpu_single_step(cs, SSTEP_ENABLE | SSTEP_NOIRQ | SSTEP_NOTIMER);
        }
        t->active = XT_ACT_EXEC;
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        t->active = XT_ACT_NONE;
        if (unlikely(stepping)) {
            cpu_single_step(cs, 0);
            if (trapnr == EXCP_DEBUG) {
                continue;
            }
        }
        /*
         * Clears exit_request and runs queued work, as linux-user's loop.
         * Work is listed before its kick sets the request
         * (queue_work_on_cpu, cpu_exit's release): with no request seen
         * there is no work to run yet, and a later kick's request stays
         * set for the next cpu_exec.
         */
        if (qatomic_load_acquire(&cs->exit_request)) {
            qemu_process_cpu_events(cs);
        }
        if (unlikely(xt_diag)) {
            xt_event(t, XT_EV_EXIT, trapnr, t->env->eip);
            xt_check(t, XT_ENGINE, 10);
        }
#ifdef TARGET_X86_64
        if (likely(trapnr == XT_EXCP_NATIVE)) {
            return trapnr;
        }
#endif
        if (!xt_run_handled(t, trapnr)) {
            return trapnr;
        }
    }
}

#endif
