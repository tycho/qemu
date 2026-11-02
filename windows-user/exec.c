/*
 * xtajit: the engine's run loop and its typed exits.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "hw/core/cpu.h"
#include "cpu.h"
#include "accel/tcg/cpu-loop.h"
#include "exec/cpu-common.h"
#include "xtajit.h"

uintptr_t xt_bop;

static uint64_t read_cntvct(void)
{
    uint64_t v;

    asm volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}

/*
 * The exception record of a guest exception, and its continuation EIP,
 * as 32-bit Windows reports each (FEX's Common/Exception.h table).
 */
static void guest_exception(XtThread *t, int trapnr, XtExit *x)
{
    CPUX86State *env = t->env;
    EXCEPTION_RECORD *r = &x->rec;

    memset(r, 0, sizeof(*r));
    x->kind = XT_EXIT_EXCEPTION;
    x->trapnr = trapnr;
    r->ExceptionAddress = (void *)(uintptr_t)env->eip;

    switch (trapnr) {
    case EXCP0E_PAGE:
        r->ExceptionCode = t->gfault.code ? t->gfault.code
                                          : STATUS_ACCESS_VIOLATION;
        r->NumberParameters = 2;
        r->ExceptionInformation[0] =
            env->error_code & PG_ERROR_W_MASK ? 1 :
            env->error_code & PG_ERROR_I_D_MASK ? 8 : 0;
        r->ExceptionInformation[1] = (uint32_t)env->cr[2];
        break;
    case EXCP11_ALGN:
        r->ExceptionCode = STATUS_DATATYPE_MISALIGNMENT;
        break;
    case EXCP03_INT3:
        /* EIP is past the int3; wow64 adjusts the dispatched context. */
        r->ExceptionCode = STATUS_BREAKPOINT;
        r->ExceptionAddress = (void *)(uintptr_t)(uint32_t)(env->eip - 1);
        r->NumberParameters = 1;
        break;
    case EXCP01_DB:
    case EXCP_DEBUG:
        r->ExceptionCode = STATUS_SINGLE_STEP;
        break;
    case EXCP00_DIVZ:
        r->ExceptionCode = STATUS_INTEGER_DIVIDE_BY_ZERO;
        break;
    case EXCP04_INTO:
        r->ExceptionCode = STATUS_INTEGER_OVERFLOW;
        break;
    case EXCP05_BOUND:
        r->ExceptionCode = STATUS_ARRAY_BOUNDS_EXCEEDED;
        break;
    case EXCP06_ILLOP:
        r->ExceptionCode = STATUS_ILLEGAL_INSTRUCTION;
        break;
    case EXCP0B_NOSEG:
    case EXCP0C_STACK:
        r->ExceptionCode = STATUS_ACCESS_VIOLATION;
        r->NumberParameters = 2;
        r->ExceptionInformation[1] = 0xffffffff;
        break;
    case 0x29:
        /* __fastfail: not continuable; the code is in ECX. */
        env->eip -= 2;
        r->ExceptionAddress = (void *)(uintptr_t)env->eip;
        r->ExceptionCode = STATUS_STACK_BUFFER_OVERRUN;
        r->ExceptionFlags = EXCEPTION_NONCONTINUABLE;
        r->NumberParameters = 1;
        r->ExceptionInformation[0] = env->regs[R_ECX];
        break;
    case 0x2c:
        env->eip -= 2;
        r->ExceptionAddress = (void *)(uintptr_t)env->eip;
        r->ExceptionCode = STATUS_ASSERTION_FAILURE;
        break;
    case 0x2d:
        /* The debug service skips the byte after int 0x2d. */
        env->eip += 1;
        r->ExceptionAddress = (void *)(uintptr_t)env->eip;
        r->ExceptionCode = STATUS_BREAKPOINT;
        r->NumberParameters = 1;
        r->ExceptionInformation[0] = env->regs[R_EAX];
        break;
    case EXCP0D_GPF:
        r->ExceptionCode = STATUS_PRIVILEGED_INSTRUCTION;
        break;
    case EXCP10_COPR:
        r->ExceptionCode = STATUS_FLOAT_INVALID_OPERATION;
        break;
    case 19:            /* #XM */
        r->ExceptionCode = STATUS_FLOAT_MULTIPLE_TRAPS;
        break;
    default:
        r->ExceptionCode = STATUS_ILLEGAL_INSTRUCTION;
        break;
    }
}

/*
 * Run guest code until an exit Windows has to see; the engine owns the
 * thread throughout.  Handled here, without leaving ownership: kicks
 * (exit requests, queued work such as flushes), the timer (int 0x81) and
 * the serial step of an atomic operation (EXCP_ATOMIC).  The system-call
 * stub's exit captures the number and argument pointer and completes the
 * stub's return (EIP from the stack, ESP + 4) before it is published.
 */
void xt_run(XtThread *t, XtExit *x)
{
    CPUState *cs = t->cpu;
    CPUX86State *env = t->env;
    int trapnr;

    for (;;) {
        /*
         * A suspension request is checked here, between runs, as well as
         * ending the run (cpu_exit): qemu_process_cpu_events clears an
         * exit request that arrives after cpu_exec has returned.
         */
        if (qatomic_read(&t->suspend_req)) {
            qatomic_set(&t->suspend_req, 0);
            t->suspensions++;
            t->after_suspend = true;
            xt_event(t, XT_EV_SUSPEND_SEEN, 0, env->eip);
            x->kind = XT_EXIT_SUSPEND;
            x->trapnr = EXCP_INTERRUPT;
            return;
        }
        t->after_suspend = false;
        t->gfault.code = 0;
        t->active = XT_ACT_EXEC;
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        t->active = XT_ACT_NONE;
        /* Clears exit_request and runs queued work, as linux-user's loop. */
        qemu_process_cpu_events(cs);
        xt_event(t, XT_EV_EXIT, trapnr, env->eip);
        xt_check(t, XT_ENGINE, 10);

        switch (trapnr) {
        case EXCP_INTERRUPT:
            continue;
        case EXCP_ATOMIC:
            xt_event(t, XT_EV_ATOMIC, 0, env->eip);
            xt_inject(t, XT_INJ_ATOMIC);
            t->active = XT_ACT_ATOMIC;
            cpu_exec_step_atomic(cs);
            t->active = XT_ACT_NONE;
            continue;
        case 0x81: {
            uint64_t v = read_cntvct();

            env->regs[R_EAX] = (uint32_t)v;
            env->regs[R_EDX] = v >> 32;
            xt_event(t, XT_EV_INT81, v, env->eip);
            continue;
        }
        case 0x2e:
            if (xt_bop && env->eip == xt_bop + 2) {
                uint32_t esp = env->regs[R_ESP], ret;

                if (!xt_guest_read(t, esp, &ret, 4)) {
                    env->eip = xt_bop;
                    env->cr[2] = esp;
                    env->error_code = PG_ERROR_U_MASK;
                    t->gfault.code = STATUS_ACCESS_VIOLATION;
                    guest_exception(t, EXCP0E_PAGE, x);
                    return;
                }
                x->kind = XT_EXIT_SYSCALL;
                x->trapnr = trapnr;
                x->nr = env->regs[R_EAX];
                x->args = esp + 8;
                env->eip = ret;
                env->regs[R_ESP] = esp + 4;
                return;
            }
            break;
        case EXCP03_INT3:
            if (t->stop_at_int3) {
                x->kind = XT_EXIT_STOP;
                x->trapnr = trapnr;
                return;
            }
            break;
        default:
            break;
        }
        guest_exception(t, trapnr, x);
        return;
    }
}
