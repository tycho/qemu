/*
 * xtajit: the x64 CONTEXT and CPUX86State (x86_64).  The import honours
 * ContextFlags; the floating-point state is FltSave (FXSAVE format: x87,
 * MXCSR, XMM0-15).  The export writes everything.  DR0-DR3 that DR7
 * enables for execution are QEMU breakpoints, as for WOW64.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "cpu.h"
#include "xtajit.h"

/*
 * x64 user mode's selectors: in long mode only FS and GS have bases, and
 * x64 Windows' GS is the thread's TEB.
 */
static void load_seg(XtThread *t, X86Seg r, int sel)
{
    CPUX86State *env = t->env;
    uint64_t *gdt = (uint64_t *)(uintptr_t)env->gdt.base;
    uint64_t d;
    uint64_t base = r == R_GS ? (uintptr_t)t->teb : 0;
    uint32_t limit;

    sel &= 0xffff;
    if ((sel & ~7) == 0 || (sel | 7) > env->gdt.limit || (sel & 4)) {
        cpu_x86_load_seg_cache(env, r, sel, base, 0, 0);
        return;
    }
    d = gdt[sel >> 3];
    limit = (d & 0xffff) | ((d >> 32) & 0xf0000);
    if (d & ((uint64_t)DESC_G_MASK << 32)) {
        limit = (limit << 12) | 0xfff;
    }
    cpu_x86_load_seg_cache(env, r, sel, base, limit, (d >> 32) & 0x00f0ff00);
}

static void set_breakpoints(XtThread *t, const CONTEXT *c)
{
    const DWORD64 dr[4] = { c->Dr0, c->Dr1, c->Dr2, c->Dr3 };

    for (int i = 0; i < 4; i++) {
        bool on = ((c->Dr7 >> (2 * i)) & 3) &&
                  !((c->Dr7 >> (16 + 4 * i)) & 3);

        if (t->bp_on[i] && (!on || t->bp[i] != dr[i])) {
            cpu_breakpoint_remove(t->cpu, t->bp[i], BP_GDB);
            t->bp_on[i] = false;
        }
        if (on && !t->bp_on[i]) {
            cpu_breakpoint_insert(t->cpu, dr[i], BP_GDB, NULL);
            t->bp[i] = dr[i];
            t->bp_on[i] = true;
        }
    }
}

#define EFLAGS_FROM_CONTEXT (TF_MASK | AC_MASK | ID_MASK | NT_MASK | \
                             DF_MASK | CC_O | CC_S | CC_Z | CC_A | CC_P | \
                             CC_C)

void xt_import(XtThread *t, const CONTEXT *c)
{
    CPUX86State *env = t->env;
    uint8_t fx[512] QEMU_ALIGNED(16);
    DWORD f = c->ContextFlags;

    if ((f & CONTEXT_INTEGER) == CONTEXT_INTEGER) {
        env->regs[R_EAX] = c->Rax;
        env->regs[R_ECX] = c->Rcx;
        env->regs[R_EDX] = c->Rdx;
        env->regs[R_EBX] = c->Rbx;
        env->regs[R_ESI] = c->Rsi;
        env->regs[R_EDI] = c->Rdi;
        env->regs[8] = c->R8;
        env->regs[9] = c->R9;
        env->regs[10] = c->R10;
        env->regs[11] = c->R11;
        env->regs[12] = c->R12;
        env->regs[13] = c->R13;
        env->regs[14] = c->R14;
        env->regs[15] = c->R15;
    }
    if ((f & CONTEXT_CONTROL) == CONTEXT_CONTROL) {
        env->regs[R_ESP] = c->Rsp;
        env->regs[R_EBP] = c->Rbp;
        env->eip = c->Rip;
        /* As xt_import for WOW64: all of EFLAGS in env->eflags. */
        env->eflags = (env->eflags & ~EFLAGS_FROM_CONTEXT) |
                      (c->EFlags & EFLAGS_FROM_CONTEXT) | 0x2;
        CC_SRC = c->EFlags & (CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
        CC_OP = CC_OP_EFLAGS;
        env->df = 1 - (2 * ((c->EFlags >> 10) & 1));
        t->bp_skip = (c->EFlags & RF_MASK) ||
                     (t->bp_hit && c->Rip == t->bp_hit);
        t->bp_hit = 0;
    }
    if ((f & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS) {
        set_breakpoints(t, c);
    }
    if ((f & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS) {
        load_seg(t, R_DS, c->SegDs);
        load_seg(t, R_ES, c->SegEs);
        load_seg(t, R_FS, c->SegFs);
        load_seg(t, R_GS, c->SegGs);
    }
    if ((f & CONTEXT_CONTROL) == CONTEXT_CONTROL) {
        /* CS before the FP state: FXRSTOR's XMM count follows CS.L. */
        load_seg(t, R_CS, c->SegCs);
        load_seg(t, R_SS, c->SegSs);
    }
    if ((f & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT) {
        memcpy(fx, &c->FltSave, sizeof(fx));
        /* MXCSR's reserved bits would make the restore fault. */
        *(uint32_t *)(fx + 24) &= 0xffff;
        cpu_x86_fxrstor(env, fx, sizeof(fx));
    }
}

void xt_export(XtThread *t, CONTEXT *c)
{
    CPUX86State *env = t->env;
    uint8_t fx[512] QEMU_ALIGNED(16);

    c->ContextFlags |= CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS |
                       CONTEXT_FLOATING_POINT;
    c->Rax = env->regs[R_EAX];
    c->Rcx = env->regs[R_ECX];
    c->Rdx = env->regs[R_EDX];
    c->Rbx = env->regs[R_EBX];
    c->Rsp = env->regs[R_ESP];
    c->Rbp = env->regs[R_EBP];
    c->Rsi = env->regs[R_ESI];
    c->Rdi = env->regs[R_EDI];
    c->R8 = env->regs[8];
    c->R9 = env->regs[9];
    c->R10 = env->regs[10];
    c->R11 = env->regs[11];
    c->R12 = env->regs[12];
    c->R13 = env->regs[13];
    c->R14 = env->regs[14];
    c->R15 = env->regs[15];
    c->Rip = env->eip;
    c->EFlags = cpu_compute_eflags(env);
    if (env->dr[6] & (DR6_BS | 0xf)) {
        c->ContextFlags |= CONTEXT_DEBUG_REGISTERS;
        c->Dr6 = 0xffff0ff0 | (env->dr[6] & (DR6_BS | 0xf));
        env->dr[6] = 0;
    }
    c->SegCs = env->segs[R_CS].selector;
    c->SegSs = env->segs[R_SS].selector;
    c->SegDs = env->segs[R_DS].selector;
    c->SegEs = env->segs[R_ES].selector;
    c->SegFs = env->segs[R_FS].selector;
    c->SegGs = env->segs[R_GS].selector;

    memset(fx, 0, sizeof(fx));
    cpu_x86_fxsave(env, fx, sizeof(fx));
    memcpy(&c->FltSave, fx, sizeof(fx));
    c->MxCsr = env->mxcsr;
}
