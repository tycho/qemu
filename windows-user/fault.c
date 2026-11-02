/*
 * xtajit: host faults on behalf of the guest, and their continuation.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "hw/core/cpu.h"
#include "cpu.h"
#include "tcg/tcg.h"
#include "exec/mmap-lock.h"
#include "exec/page-protection.h"
#include "exec/translation-block.h"
#include "accel/tcg/cpu-loop.h"
#include "accel/tcg/helper-retaddr.h"
#include "user/cpu_loop.h"
#include "user/page-protection.h"
#include "xtajit.h"

NTSTATUS NTAPI NtContinue(PCONTEXT, BOOLEAN);

extern IMAGE_DOS_HEADER __ImageBase;

static uint32_t n_faults;

uint32_t xt_fault_count(void)
{
    return qatomic_read(&n_faults);
}

/* Whether ADDR is on a page of the TB being translated. */
static bool on_tb_pages(const TranslationBlock *tb, vaddr addr)
{
    vaddr page = addr & TARGET_PAGE_MASK;
    vaddr p0 = tb_page_addr0(tb) & TARGET_PAGE_MASK;

    return page == p0 || page == p0 + TARGET_PAGE_SIZE;
}

/*
 * The continuation, entered by NtContinue on the faulting thread's stack
 * with the fault in T's record.  From here the recovery is QEMU's own: a
 * write to a page QEMU protected for its translations is unprotected and
 * retried (page_unprotect: the original context again, or a precise exit
 * if the current TB was invalidated); anything else is a guest fault,
 * which restores the guest state from the host pc and leaves through
 * cpu_exec's jump target, whose cleanup releases the translation state.
 */
static void G_NORETURN xt_fault_continue(XtThread *t, XtActive prev)
{
    XtFault *f = &t->fault;
    CPUState *cs = t->cpu;
    bool maperr;

    xt_event(t, XT_EV_RESUME, f->kind, f->addr);

    if (f->kind == XT_FK_ADAPTER) {
        f->busy = 0;
        siglongjmp(t->adapter_jmp, 1);
    }
    if (f->is_write && f->code == STATUS_ACCESS_VIOLATION &&
        f->kind != XT_FK_TRANSLATE) {
        int r = page_unprotect(cs, f->addr, f->host_pc);

        xt_event(t, XT_EV_SMC, r, f->addr);
        if (r == 1) {
            t->active = prev;
            f->busy = 0;
            NtContinue(&f->ctx, FALSE);
        } else if (r == 2) {
            t->active = prev;
            f->busy = 0;
            cpu_loop_exit_noexc(cs);
        }
    }
    t->gfault.code = f->code;
    t->active = prev;
    f->busy = 0;
    maperr = !(page_get_flags(f->addr) & PAGE_VALID);
    cpu_loop_exit_sigsegv(cs, f->addr, f->access, maperr, f->host_pc);
}

/* Entered with x0 = T, x1 = the active state to restore. */
static void G_NORETURN xt_fault_entry(XtThread *t, uint64_t prev)
{
    xt_fault_continue(t, prev);
}

/*
 * Classify a host exception (from BTCpuResetToConsistentState, inside
 * Windows' exception dispatch, or the native harness's vectored handler),
 * and if it is the engine's, redirect CTX to the continuation and return
 * true; the caller then NtContinue()s CTX.  Nothing here allocates, takes
 * a lock or formats: the fault is copied into the thread's preallocated
 * record and the work happens in the continuation.
 *
 * The engine's faults are those linux-user's host_sigsegv_handler takes
 * (user-exec.c adjust_signal_pc): a guest access from generated code
 * (helper_retaddr 0, the pc in the code buffer), from a helper (the
 * helper's saved return address), an instruction fetch through
 * cpu_ld*_code_mmu (helper_retaddr 1); and two more: the translator
 * reading guest code (the mmap lock held by this thread, the address on
 * the pages of the TB being generated; the pc is wherever memcpy is,
 * ntdll's here), which QEMU's page flags normally prevent but Windows can
 * change under them, and the adapter's own guarded reads.  Anything else
 * is not ours, and dispatch continues.
 */
bool xt_fault_redirect(EXCEPTION_RECORD *er, CONTEXT *ctx)
{
    XtThread *t = xt_self;
    XtFault *f;
    XtFaultKind kind;
    MMUAccessType access;
    uintptr_t pc, hpc;
    vaddr addr;
    bool is_write;

    if (!t || t->fault.busy) {
        return false;
    }
    switch (er->ExceptionCode) {
    case STATUS_ACCESS_VIOLATION:
    case STATUS_GUARD_PAGE_VIOLATION:
    case STATUS_IN_PAGE_ERROR:
        break;
    default:
        return false;
    }
    if (er->NumberParameters < 2) {
        return false;
    }
    is_write = er->ExceptionInformation[0] == 1;
    addr = er->ExceptionInformation[1];
    if (addr > guest_addr_max) {
        return false;
    }
    pc = ctx->Pc;

    switch (t->active) {
    case XT_ACT_ADAPTER:
        kind = XT_FK_ADAPTER;
        hpc = 0;
        access = MMU_DATA_LOAD;
        break;
    case XT_ACT_EXEC:
    case XT_ACT_ATOMIC:
        if (helper_retaddr == 0 &&
            !in_code_gen_buffer((void *)(pc - tcg_splitwx_diff))) {
            if (have_mmap_lock() && tcg_ctx->gen_tb &&
                on_tb_pages(tcg_ctx->gen_tb, addr)) {
                kind = XT_FK_TRANSLATE;
                hpc = 0;
                access = MMU_INST_FETCH;
                break;
            }
            return false;
        }
        kind = helper_retaddr == 0 ? XT_FK_GEN
             : helper_retaddr == 1 ? XT_FK_FETCH : XT_FK_HELPER;
        hpc = pc;
        access = adjust_signal_pc(&hpc, is_write);
        break;
    default:
        return false;
    }

    f = &t->fault;
    f->busy = 1;
    f->kind = kind;
    f->code = er->ExceptionCode;
    f->is_write = is_write;
    f->access = access;
    f->addr = addr;
    f->host_pc = hpc;
    f->ctx = *ctx;
    qatomic_inc(&n_faults);
    xt_event(t, XT_EV_FAULT,
             (uint64_t)kind << 56 | ((pc - (uintptr_t)&__ImageBase) &
                                     0xffffffffffffffull >> 8), addr);

    ctx->X0 = (uintptr_t)t;
    ctx->X1 = t->active;
    ctx->Lr = pc;
    ctx->Sp &= ~(uint64_t)15;
    ctx->Pc = (uintptr_t)xt_fault_entry;
    t->active = XT_ACT_FAULT;
    return true;
}
