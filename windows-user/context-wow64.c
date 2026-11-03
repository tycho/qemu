/*
 * xtajit: the WOW64 context and CPUX86State (i386).
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
 * The WOW64 context and CPUX86State.  The import honours ContextFlags:
 * the floating-point state comes from ExtendedRegisters (FXSAVE format,
 * x87 tags, TOP, status, MXCSR and XMM) when present, else from FloatSave
 * (FSAVE format).  The export writes both.  DR0-DR7 stay in the WOW64
 * context; the import takes execute breakpoints from them
 * (set_breakpoints), and the export reports in DR6 what trapped: a
 * single step (BS) or a breakpoint (B0-B3).
 */
static uint32_t seg_base(XtThread *t, int sel)
{
    if ((sel & ~3) == 0x38 || (sel & ~3) == 0x50) {
        /* The 32-bit TEB: WowTebOffset at TEB + 0x180c. */
        return (uintptr_t)t->teb + *(int32_t *)((char *)t->teb + 0x180c);
    }
    return 0;
}

static void load_seg(XtThread *t, X86Seg r, int sel)
{
    CPUX86State *env = t->env;
    uint64_t *gdt = (uint64_t *)(uintptr_t)env->gdt.base;
    uint64_t d;
    uint32_t base, limit;

    sel &= 0xffff;
    if ((sel & ~7) == 0 || (sel | 7) > env->gdt.limit || (sel & 4)) {
        cpu_x86_load_seg_cache(env, r, sel, 0, 0, 0);
        return;
    }
    d = gdt[sel >> 3];
    base = seg_base(t, sel);
    limit = (d & 0xffff) | ((d >> 32) & 0xf0000);
    if (d & ((uint64_t)DESC_G_MASK << 32)) {
        limit = (limit << 12) | 0xfff;
    }
    cpu_x86_load_seg_cache(env, r, sel, base, limit,
                           (d >> 32) & 0x00f0ff00);
}

/*
 * DR0-DR3 that DR7 enables with R/W 00 are execute breakpoints, QEMU's
 * (BP_GDB: user mode ends cpu_exec with EXCP_DEBUG at one).  Data
 * breakpoints aren't supported: QEMU's user mode has no watchpoints.
 */
static void set_breakpoints(XtThread *t, const WOW64_CONTEXT *c)
{
    const DWORD dr[4] = { c->Dr0, c->Dr1, c->Dr2, c->Dr3 };

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

void xt_import(XtThread *t, const WOW64_CONTEXT *c)
{
    CPUX86State *env = t->env;
    uint8_t fx[512] QEMU_ALIGNED(16);

    env->regs[R_EAX] = c->Eax;
    env->regs[R_ECX] = c->Ecx;
    env->regs[R_EDX] = c->Edx;
    env->regs[R_EBX] = c->Ebx;
    env->regs[R_ESP] = c->Esp;
    env->regs[R_EBP] = c->Ebp;
    env->regs[R_ESI] = c->Esi;
    env->regs[R_EDI] = c->Edi;
    env->eip = c->Eip;
    /*
     * Outside cpu_exec all of EFLAGS lives in env->eflags (cpu_exec_enter
     * moves the arithmetic flags and DF out); CC_SRC and CC_OP agree, as
     * cpu_compute_eflags combines them.
     */
    env->eflags = (env->eflags & ~(TF_MASK | AC_MASK | ID_MASK | NT_MASK |
                                   DF_MASK | CC_O | CC_S | CC_Z | CC_A |
                                   CC_P | CC_C)) |
                  (c->EFlags & (TF_MASK | AC_MASK | ID_MASK | NT_MASK |
                                DF_MASK | CC_O | CC_S | CC_Z | CC_A | CC_P |
                                CC_C)) | 0x2;
    CC_SRC = c->EFlags & (CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
    CC_OP = CC_OP_EFLAGS;
    env->df = 1 - (2 * ((c->EFlags >> 10) & 1));
    set_breakpoints(t, c);
    /*
     * As x86's RF: resuming with it set, or at the breakpoint just
     * reported, runs the instruction there without its breakpoint.
     */
    t->bp_skip = (c->EFlags & RF_MASK) ||
                 (t->bp_hit && c->Eip == t->bp_hit);
    t->bp_hit = 0;

    load_seg(t, R_CS, c->SegCs);
    load_seg(t, R_SS, c->SegSs);
    load_seg(t, R_DS, c->SegDs);
    load_seg(t, R_ES, c->SegEs);
    load_seg(t, R_FS, c->SegFs);
    load_seg(t, R_GS, c->SegGs);

    if ((c->ContextFlags & WOW64_CONTEXT_EXTENDED_REGISTERS) ==
        WOW64_CONTEXT_EXTENDED_REGISTERS) {
        memcpy(fx, c->ExtendedRegisters, sizeof(fx));
        /* MXCSR's reserved bits would make the restore fault. */
        *(uint32_t *)(fx + 24) &= 0xffff;
        cpu_x86_fxrstor(env, fx, sizeof(fx));
    } else if ((c->ContextFlags & WOW64_CONTEXT_FLOATING_POINT) ==
               WOW64_CONTEXT_FLOATING_POINT) {
        memcpy(fx, &c->FloatSave, 108);
        cpu_x86_frstor(env, fx, 108);
    }
}

void xt_export(XtThread *t, WOW64_CONTEXT *c)
{
    CPUX86State *env = t->env;
    uint8_t fx[512] QEMU_ALIGNED(16);

    c->ContextFlags |= WOW64_CONTEXT_FULL | WOW64_CONTEXT_FLOATING_POINT |
                       WOW64_CONTEXT_EXTENDED_REGISTERS;
    c->Eax = env->regs[R_EAX];
    c->Ecx = env->regs[R_ECX];
    c->Edx = env->regs[R_EDX];
    c->Ebx = env->regs[R_EBX];
    c->Esp = env->regs[R_ESP];
    c->Ebp = env->regs[R_EBP];
    c->Esi = env->regs[R_ESI];
    c->Edi = env->regs[R_EDI];
    c->Eip = env->eip;
    c->EFlags = cpu_compute_eflags(env);
    if (env->dr[6] & (DR6_BS | 0xf)) {
        c->ContextFlags |= WOW64_CONTEXT_DEBUG_REGISTERS;
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
    memcpy(c->ExtendedRegisters, fx, sizeof(fx));
    memset(fx, 0, 108);
    cpu_x86_fsave_noinit(env, fx, 108);
    memcpy(&c->FloatSave, fx, 108);
    c->FloatSave.Cr0NpxState = 0;
}
