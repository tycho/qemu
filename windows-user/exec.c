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

/* The bytes at ADDR, as many of up to 15 as are readable. */
static int fetch_insn(XtThread *t, vaddr addr, uint8_t *buf)
{
    int n = 0;

    while (n < 15 && xt_guest_read(t, addr + n, &buf[n], 1)) {
        n++;
    }
    return n;
}

/* Past the legacy prefixes; the segment override in *SEG, else -1. */
static int skip_prefixes(const uint8_t *b, int n, int *seg)
{
    int i;

    *seg = -1;
    for (i = 0; i < n; i++) {
        switch (b[i]) {
        case 0x26:
            *seg = R_ES;
            break;
        case 0x2e:
            *seg = R_CS;
            break;
        case 0x36:
            *seg = R_SS;
            break;
        case 0x3e:
            *seg = R_DS;
            break;
        case 0x64:
            *seg = R_FS;
            break;
        case 0x65:
            *seg = R_GS;
            break;
        case 0x66: case 0x67: case 0xf0: case 0xf2: case 0xf3:
            break;
        default:
            return i;
        }
    }
    return i;
}

/*
 * Whether the instruction at EIP is one that #GP(0)s at CPL 3 for being
 * privileged, which Windows reports as STATUS_PRIVILEGED_INSTRUCTION; any
 * other #GP is an access violation.
 */
static bool insn_privileged(XtThread *t, CPUX86State *env)
{
    uint8_t b[15];
    int n = fetch_insn(t, env->eip, b), seg, i = skip_prefixes(b, n, &seg);
    int reg = i + 2 < n ? (b[i + 2] >> 3) & 7 : -1;

    if (i >= n) {
        return false;
    }
    switch (b[i]) {
    case 0xf4:                          /* hlt */
    case 0xfa: case 0xfb:               /* cli, sti */
    case 0x6c ... 0x6f:                 /* ins, outs */
    case 0xe4 ... 0xe7:                 /* in, out imm8 */
    case 0xec ... 0xef:                 /* in, out dx */
        return true;
    case 0x0f:
        if (i + 1 >= n) {
            return false;
        }
        switch (b[i + 1]) {
        case 0x06:                      /* clts */
        case 0x08: case 0x09:           /* invd, wbinvd */
        case 0x20 ... 0x23:             /* mov to/from cr, dr */
        case 0x30: case 0x32:           /* wrmsr, rdmsr */
        case 0x33:                      /* rdpmc */
        case 0x35:                      /* sysexit */
            return true;
        case 0x00:                      /* lldt, ltr */
            return reg == 2 || reg == 3;
        case 0x01:                      /* lgdt, lidt, lmsw, invlpg */
            return reg == 2 || reg == 3 || reg == 6 ||
                   (reg == 7 && (b[i + 2] >> 6) != 3);
        }
        return false;
    }
    return false;
}

/*
 * For #DE: whether the divide at EIP has a nonzero divisor, so that the
 * quotient overflowed.  Windows tells the two apart this way, reporting
 * STATUS_INTEGER_OVERFLOW for the second.  32-bit addressing only.
 */
static bool div_overflowed(XtThread *t, CPUX86State *env)
{
    uint8_t b[15];
    int n = fetch_insn(t, env->eip, b), seg, i = skip_prefixes(b, n, &seg);
    bool opsize16 = false, addr16 = false;
    int size, mod, reg, rm, p;
    uint32_t ea = 0, v = 0;

    for (int k = 0; k < i; k++) {
        opsize16 |= b[k] == 0x66;
        addr16 |= b[k] == 0x67;
    }
    if (i + 1 >= n || (b[i] != 0xf6 && b[i] != 0xf7) || addr16) {
        return false;
    }
    size = b[i] == 0xf6 ? 1 : opsize16 ? 2 : 4;
    mod = b[i + 1] >> 6;
    reg = (b[i + 1] >> 3) & 7;
    rm = b[i + 1] & 7;
    if (reg != 6 && reg != 7) {
        return false;
    }
    if (mod == 3) {
        v = size == 1 ? env->regs[rm & 3] >> (rm & 4 ? 8 : 0)
                      : env->regs[rm];
    } else {
        p = i + 2;
        if (rm == 4) {
            int sib, base, index;

            if (p >= n) {
                return false;
            }
            sib = b[p++];
            base = sib & 7;
            index = (sib >> 3) & 7;
            if (index != 4) {
                ea += env->regs[index] << (sib >> 6);
            }
            if (base == 5 && mod == 0) {
                mod = 2;            /* disp32, no base */
            } else {
                ea += env->regs[base];
            }
            if (seg < 0 && (base == R_ESP || (base == R_EBP && mod))) {
                seg = R_SS;
            }
        } else if (rm == 5 && mod == 0) {
            mod = 2;
        } else {
            ea += env->regs[rm];
        }
        if (mod == 1) {
            if (p >= n) {
                return false;
            }
            ea += (int8_t)b[p];
        } else if (mod == 2) {
            uint32_t d;

            if (p + 4 > n) {
                return false;
            }
            memcpy(&d, &b[p], 4);
            ea += d;
        }
        if (seg >= 0) {
            ea += env->segs[seg].base;
        }
        if (!xt_guest_read(t, ea, &v, size)) {
            return false;
        }
    }
    v &= size == 4 ? 0xffffffff : (1u << (size * 8)) - 1;
    return v != 0;
}

/* The status of an unmasked x87 exception, as Windows picks it. */
static NTSTATUS x87_status(CPUX86State *env)
{
    int pending = env->fpus & ~env->fpuc & 0x3f;

    if (pending & 0x01) {
        return env->fpus & 0x40 ? STATUS_FLOAT_STACK_CHECK
                                : STATUS_FLOAT_INVALID_OPERATION;
    }
    if (pending & 0x02) {
        return STATUS_FLOAT_DENORMAL_OPERAND;
    }
    if (pending & 0x04) {
        return STATUS_FLOAT_DIVIDE_BY_ZERO;
    }
    if (pending & 0x08) {
        return STATUS_FLOAT_OVERFLOW;
    }
    if (pending & 0x10) {
        return STATUS_FLOAT_UNDERFLOW;
    }
    if (pending & 0x20) {
        return STATUS_FLOAT_INEXACT_RESULT;
    }
    return STATUS_FLOAT_INVALID_OPERATION;
}

/*
 * The exception record of a guest exception, and its continuation EIP,
 * as 32-bit Windows reports each.  Delivery clears TF, as the processor
 * does entering the handler.
 */
static void guest_exception(XtThread *t, int trapnr, XtExit *x)
{
    CPUX86State *env = t->env;
    EXCEPTION_RECORD *r = &x->rec;

    memset(r, 0, sizeof(*r));
    x->kind = XT_EXIT_EXCEPTION;
    x->trapnr = trapnr;
    /* User mode's #DB leaves DR6 alone: a trap with TF set is a step. */
    if (trapnr == EXCP01_DB && (env->eflags & TF_MASK)) {
        env->dr[6] |= DR6_BS;
    }
    env->eflags &= ~TF_MASK;
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
        r->ExceptionCode = div_overflowed(t, env)
                           ? STATUS_INTEGER_OVERFLOW
                           : STATUS_INTEGER_DIVIDE_BY_ZERO;
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
    case 0x2e:
        /* The system-call gate outside the stub: as a gate that #GPs. */
        env->eip -= 2;
        r->ExceptionAddress = (void *)(uintptr_t)env->eip;
        r->ExceptionCode = STATUS_ACCESS_VIOLATION;
        r->NumberParameters = 2;
        r->ExceptionInformation[1] = 0xffffffff;
        break;
    case EXCP0B_NOSEG:
    case EXCP0C_STACK:
        r->ExceptionCode = STATUS_ACCESS_VIOLATION;
        r->NumberParameters = 2;
        r->ExceptionInformation[1] = 0xffffffff;
        break;
    case EXCP0D_GPF:
        /*
         * A selector or gate in the error code (segment loads, far
         * transfers, int n through a kernel gate), or #GP(0) of anything
         * but a privileged instruction (misaligned SSE operands, for
         * instance): an access violation at an unknown address.
         */
        if (env->error_code == 0 && insn_privileged(t, env)) {
            r->ExceptionCode = STATUS_PRIVILEGED_INSTRUCTION;
        } else {
            r->ExceptionCode = STATUS_ACCESS_VIOLATION;
            r->NumberParameters = 2;
            r->ExceptionInformation[1] = 0xffffffff;
        }
        break;
    case EXCP10_COPR:
        r->ExceptionCode = x87_status(env);
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
