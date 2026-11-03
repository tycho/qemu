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

#ifdef __arm64ec__
/*
 * ARM64EC's register mapping: where native code keeps each x64 register
 * (RAX x8, RCX x0, RDX x1, RBX x27, RSP sp, RBP fp, RSI x25, RDI x26,
 * R8-R11 x2-x5, R12-R15 x19-x22, XMM0-15 v0-v15).
 */
static uint64_t *ec_gpr(ARM64_NT_CONTEXT *n, int reg)
{
    static const int8_t map[16] = {
        8, 0, 1, 27, -1, 29, 25, 26, 2, 3, 4, 5, 19, 20, 21, 22,
    };

    return reg == R_ESP ? &n->Sp : &n->X[map[reg]];
}

/* EFLAGS' SF, ZF, CF, OF and TF as NZCV and PSTATE.SS, as Windows maps them. */
static uint32_t ec_cpsr(uint32_t eflags)
{
    return (eflags & CC_S ? 1u << 31 : 0) | (eflags & CC_Z ? 1u << 30 : 0) |
           (eflags & CC_C ? 1u << 29 : 0) | (eflags & CC_O ? 1u << 28 : 0) |
           (eflags & TF_MASK ? 1u << 21 : 0);
}

static uint32_t ec_eflags(uint32_t cpsr)
{
    return (cpsr & (1u << 31) ? CC_S : 0) | (cpsr & (1u << 30) ? CC_Z : 0) |
           (cpsr & (1u << 29) ? CC_C : 0) | (cpsr & (1u << 28) ? CC_O : 0) |
           (cpsr & (1u << 21) ? TF_MASK : 0);
}

/*
 * The guest's state as native code keeps it (the packed form): x64
 * registers in their ARM64EC places, the MMX registers where Windows
 * looks for them (FEX's ARM64EC module packs them the same way), NZCV and
 * SS from EFLAGS, FPCR and FPSR from MXCSR; nothing in x13, x14, x18,
 * x23, x24 or x28.  The rest of EFLAGS and the x87 control state have no
 * place here.
 */
void xt_ec_pack(XtThread *t, ARM64_NT_CONTEXT *n)
{
    static const int8_t mm_lo[8] = { 30, 6, 7, 9, 10, 11, 12, 15 };
    CPUX86State *env = t->env;
    uint32_t mx = env->mxcsr;
    uint64_t hi16 = 0, hi17 = 0;
    CONTEXT c;

    memset(&c, 0, sizeof(c));
    xt_export(t, &c);
    memset(n, 0, sizeof(*n));
    n->ContextFlags = CONTEXT_ARM64_FULL;
    for (int i = 0; i < 16; i++) {
        *ec_gpr(n, i) = (&c.Rax)[i];
    }
    n->Pc = c.Rip;
    n->Cpsr = ec_cpsr(c.EFlags);
    memcpy(n->V, c.FltSave.XmmRegisters, 16 * sizeof(n->V[0]));
    for (int i = 0; i < 8; i++) {
        const M128A *mm = &c.FltSave.FloatRegisters[i];

        n->X[mm_lo[i]] = mm->Low;
        if (i < 4) {
            hi16 |= (uint64_t)(mm->High & 0xffff) << (16 * i);
        } else {
            hi17 |= (uint64_t)(mm->High & 0xffff) << (16 * (i - 4));
        }
    }
    n->X16 = hi16;
    n->X17 = hi17;
    /* RC: x86 down 1, up 2; Arm RP (up) 1, RM (down) 2. */
    n->Fpcr = ((((mx >> 13) & 3) == 1 ? 2 : ((mx >> 13) & 3) == 2 ? 1 :
                (mx >> 13) & 3) << 22) | (mx & 0x8000 ? 1u << 24 : 0);
    n->Fpsr = (mx & 1 ? 1 : 0) | (mx & 4 ? 2 : 0) | (mx & 8 ? 4 : 0) |
              (mx & 0x10 ? 8 : 0) | (mx & 0x20 ? 0x10 : 0) |
              (mx & 2 ? 0x80 : 0);
}

/*
 * A call or jump into x64 code from native code: the x64 registers from
 * their ARM64EC places, RIP the target, x64 Windows' selectors.  EFLAGS'
 * SF, ZF, CF, OF and TF come from NZCV and SS, the rest (DF, PF, AF) is
 * the engine's, as it was at the last exit; the x87 state and MXCSR stay
 * the engine's.  Into C for xt_acquire.
 */
void xt_ec_call_context(XtThread *t, ARM64_NT_CONTEXT *n, CONTEXT *c)
{
    memset(c, 0, sizeof(*c));
    xt_export(t, c);
    for (int i = 0; i < 16; i++) {
        (&c->Rax)[i] = *ec_gpr(n, i);
    }
    c->Rip = n->Pc;
    c->EFlags = (c->EFlags & ~(CC_S | CC_Z | CC_C | CC_O | TF_MASK)) |
                ec_eflags(n->Cpsr);
    memcpy(c->FltSave.XmmRegisters, n->V, 16 * sizeof(n->V[0]));
    c->SegCs = 0x33;
    c->SegDs = c->SegEs = c->SegSs = c->SegGs = 0x2b;
    c->SegFs = 0x53;
    c->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS |
                      CONTEXT_FLOATING_POINT;
}
#endif
