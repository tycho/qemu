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
#include "tcg/startup.h"
#include "exec/mmap-lock.h"
#include "exec/page-protection.h"
#include "exec/translation-block.h"
#include "accel/tcg/cpu-loop.h"
#include "accel/tcg/helper-retaddr.h"
#include "user/cpu_loop.h"
#include "user/page-protection.h"
#include "host/cpuinfo.h"
#include "tcg/tcg-cache.h"
#include "xtajit.h"

extern IMAGE_DOS_HEADER __ImageBase;

PVOID NTAPI RtlAddVectoredExceptionHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
ULONG NTAPI RtlRemoveVectoredExceptionHandler(PVOID);
NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID *, ULONG_PTR, PSIZE_T,
                                       ULONG, ULONG);
NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE, PVOID *, PSIZE_T, ULONG);

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
 * A fault in generated code: store the pinned globals (tcg_pin_user) and
 * the dirty globals a guest access left in host registers
 * (tcg_lazysync_user) from the registers of the fault, before anything
 * reads env, as linux-user's signal handler does (host_signal_lazysync).
 * A retry that resumes the fault's context doesn't need them, and is
 * unharmed.  The context has every register: the installed modules get
 * the full native context (ResetToConsistentState), and where a host
 * gives less, both flags are off (xt_fault_context_partial), unless the
 * native harness's override asks for them for a run that doesn't fault.
 */
static void xt_fault_lazysync(const XtNativeContext *ctx)
{
    uint64_t regs[64][2];

    if (!(tcg_lazysync_user || tcg_pin_user) ||
        !in_code_gen_buffer((void *)(ctx->Pc - tcg_splitwx_diff))) {
        return;
    }
    memset(regs, 0, sizeof(regs));
    for (int i = 0; i < 29; i++) {
        regs[i][0] = ctx->X[i];
    }
    regs[29][0] = ctx->Fp;
    regs[30][0] = ctx->Lr;
    regs[31][0] = ctx->Sp;
    for (int i = 0; i < 32; i++) {
        regs[32 + i][0] = ctx->V[i].Low;
        regs[32 + i][1] = ctx->V[i].High;
    }
    tcg_pinned_unwind(regs, 64);
    tb_lazysync_unwind(ctx->Pc, regs, 64);
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
    /*
     * The check a TB emits of its own code, at its entry, read a page gone
     * since: resume at the TB's path that discards it, with the registers
     * of the fault.  A guard page's guard, which the read took, is put
     * back for the guest's own fetch.
     */
    if (f->kind == XT_FK_GEN && !f->is_write) {
        uintptr_t stale = tb_smc_inline_fault(f->ctx.Pc, f->addr);

        if (stale) {
            if (f->code == STATUS_GUARD_PAGE_VIOLATION &&
                !xt_guard_restore(f->addr)) {
                xt_event(t, XT_EV_CHECK, 1, f->addr);
            }
            xt_event(t, XT_EV_SMC, 3, f->addr);
            t->active = prev;
            f->busy = 0;
            f->ctx.Pc = stale;
            xt_continue_native(&f->ctx);
        }
    }
    /*
     * A TB's entry check read a page gone since: the TB is stale, and
     * translating it again meets the guest's own fetch fault, if any.  A
     * guard page's guard, which the read took, is put back for that.
     */
    if (f->kind == XT_FK_SMC) {
        if (f->code == STATUS_GUARD_PAGE_VIOLATION &&
            !xt_guard_restore(f->addr)) {
            xt_event(t, XT_EV_CHECK, 1, f->addr);
        }
        t->active = prev;
        f->busy = 0;
        tb_smc_check_fault(cs);
    }
    xt_fault_lazysync(&f->ctx);
    /*
     * An ordered access crossing 16 bytes: promote its guest insn, whose
     * next translation handles any alignment, and run the insn again
     * (tcg_tso_cross_fault, as linux-user's SIGBUS handler).
     */
    if (f->kind == XT_FK_CROSS) {
        t->active = prev;
        f->busy = 0;
        if (tcg_tso_cross_fault(cs, f->ctx.Pc, f->host_pc)) {
            xt_event(t, XT_EV_CROSS, f->code, cs->cc->get_pc(cs));
            cpu_loop_exit_noexc(cs);
        }
        /*
         * xt_fault_redirect found an ordered access in generated code, so
         * only a TB missing for it fails here: nothing to give the guest.
         */
        xt_event(t, XT_EV_CHECK, 2, f->ctx.Pc);
        xt_log_flush(t);
        g_assert_not_reached();
    }
    /*
     * QEMU's write protection, page_unprotect's to lift; not a write to a
     * page whose flags are stale, which page_unprotect would take for
     * another thread's unprotect and resume for ever.
     */
    if (f->is_write && f->code == STATUS_ACCESS_VIOLATION &&
        f->kind != XT_FK_TRANSLATE && !xt_mem_stale_write(f->addr)) {
        int r = page_unprotect(cs, f->addr, f->host_pc);

        xt_event(t, XT_EV_SMC, r, f->addr);
        if (r == 1) {
            t->active = prev;
            f->busy = 0;
            xt_continue_native(&f->ctx);
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
 * change under them, and the adapter's own guarded reads.  With
 * tcg_tso_cross_faults, also an ordered access in generated code (LDAPR,
 * STLR, LDAPUR, STLUR) that faults because it crosses 16 bytes: Windows
 * may give no access-violation parameters for it, and its code may be a
 * misalignment's or an illegal instruction's (a data abort Windows doesn't
 * classify).  Promoting the access is correct whatever the cause, so the
 * code needn't say which.  Anything else is not ours, and dispatch
 * continues.
 */
bool xt_fault_redirect(EXCEPTION_RECORD *er, XtNativeContext *ctx)
{
    XtThread *t;
    XtFault *f;
    XtFaultKind kind;
    MMUAccessType access;
    uintptr_t pc, hpc;
    vaddr addr;
    bool is_write, cross = false;

    /*
     * A read by one of the translation cache's guarded routines
     * (tcg-cache.h), wherever it reads: back to its caller with a fault
     * code.  Before anything else, the thread's own state included.
     */
    if ((er->ExceptionCode == STATUS_ACCESS_VIOLATION ||
         er->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION ||
         er->ExceptionCode == STATUS_IN_PAGE_ERROR) &&
        er->NumberParameters >= 2 && er->ExceptionInformation[0] == 0 &&
        tcg_cache_guard_pc(ctx->Pc)) {
        ctx->X0 = TCG_CACHE_GFAULT |
                  (er->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION ?
                   TCG_CACHE_GFAULT_GUARD : 0) |
                  (er->ExceptionInformation[1] &
                   (TCG_CACHE_GFAULT_GUARD - 1));
        ctx->Pc = ctx->Lr;
        return true;
    }
    t = xt_self;
    if (!t || t->fault.busy) {
        return false;
    }
    switch (er->ExceptionCode) {
    case STATUS_ACCESS_VIOLATION:
    case STATUS_GUARD_PAGE_VIOLATION:
    case STATUS_IN_PAGE_ERROR:
        if (er->NumberParameters < 2) {
            return false;
        }
        break;
    case STATUS_DATATYPE_MISALIGNMENT:
    case STATUS_ILLEGAL_INSTRUCTION:
        if (!tcg_tso_cross_faults) {
            return false;
        }
        cross = true;
        break;
    default:
        return false;
    }
    is_write = er->NumberParameters >= 2 && er->ExceptionInformation[0] == 1;
    addr = er->NumberParameters >= 2 ? er->ExceptionInformation[1] : 0;
    /*
     * A 32-bit guest's accesses are below 4 GiB.  x64 code reaches the
     * whole 64-bit space, the kernel's half and non-canonical addresses
     * included, and its faults there are its own.
     */
    if (TARGET_LONG_BITS == 32 && addr > guest_addr_max) {
        return false;
    }
    pc = ctx->Pc;

    switch (t->active) {
    case XT_ACT_ADAPTER:
        if (cross) {
            return false;
        }
        kind = XT_FK_ADAPTER;
        hpc = 0;
        access = MMU_DATA_LOAD;
        break;
    case XT_ACT_EXEC:
    case XT_ACT_ATOMIC:
        if (xt_cross_inject && tcg_tso_cross_faults &&
            er->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
            cross = true;
        }
        if (cross) {
            if (helper_retaddr == 0 &&
                in_code_gen_buffer((void *)(pc - tcg_splitwx_diff)) &&
                tcg_insn_is_acqrel_ldst(pc)) {
                /* An injected fault, as a misalignment's: no parameters. */
                if (er->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
                    is_write = false;
                    addr = 0;
                }
                kind = XT_FK_CROSS;
                hpc = pc;
                access = adjust_signal_pc(&hpc, is_write);
                break;
            }
            if (er->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION) {
                return false;
            }
        }
        if (t->cpu && t->cpu->smc_check_tb) {
            kind = XT_FK_SMC;
            hpc = 0;
            access = MMU_INST_FETCH;
            break;
        }
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

bool xt_cross_inject;

/*
 * The probe's accesses: X10 to or from [X9] (LDAPUR and STLUR: [X9, #-1]),
 * as encodings, which an assembler without FEAT_LRCPC2 takes too.
 */
#define XPROBE_LDAPR_X  "0xf8bfc12a"
#define XPROBE_LDAPR_W  "0xb8bfc12a"
#define XPROBE_LDAPRH   "0x78bfc12a"
#define XPROBE_STLR_X   "0xc89ffd2a"
#define XPROBE_STLR_W   "0x889ffd2a"
#define XPROBE_STLRH    "0x489ffd2a"
#define XPROBE_LDAPUR_X "0xd95ff12a"
#define XPROBE_LDAPUR_W "0x995ff12a"
#define XPROBE_STLUR_X  "0xd91ff12a"
#define XPROBE_STLUR_W  "0x991ff12a"
#define XPROBE_LDAPURH  "0x595ff12a"
#define XPROBE_STLURH   "0x591ff12a"
#define XPROBE_LDAPURSH_W "0x59dff12a"
#define XPROBE_LDAPURSH_X "0x599ff12a"
#define XPROBE_LDAPURSW "0x999ff12a"

/* The probe's access in flight (its pc), on this thread only. */
static uintptr_t xprobe_pc;
static __thread bool xprobe_here;
static uint32_t xprobe_code;

/*
 * An exception at the access being tried, on the probing thread: note its
 * code, move *PC past the access and return true.  Anything else isn't the
 * probe's.  The x64 module meets it in ResetToConsistentState, since it
 * starts the engine inside the emulator's dispatch, where vectored
 * handlers see the x64 guest's context; elsewhere in xprobe_veh.
 */
bool xt_cross_probe_take(uint32_t code, uint64_t *pc)
{
    /* The pc first: unrelated exceptions then never touch the TLS. */
    if (!xprobe_pc || *pc != xprobe_pc || !xprobe_here) {
        return false;
    }
    switch (code) {
    case STATUS_DATATYPE_MISALIGNMENT:
    case STATUS_ILLEGAL_INSTRUCTION:
    case STATUS_ACCESS_VIOLATION:
    case STATUS_IN_PAGE_ERROR:
        break;
    default:
        return false;
    }
    xprobe_code = code;
    *pc += 4;
    return true;
}

static LONG CALLBACK xprobe_veh(PEXCEPTION_POINTERS p)
{
#ifdef TARGET_X86_64
    /* An ARM64EC process: handlers see the x64 view of native code. */
    ARM64EC_NT_CONTEXT *ctx = (ARM64EC_NT_CONTEXT *)p->ContextRecord;
#else
    CONTEXT *ctx = p->ContextRecord;
#endif
    uint64_t pc = ctx->Pc;

    if (!xt_cross_probe_take(p->ExceptionRecord->ExceptionCode, &pc)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    ctx->Pc = pc;
    return EXCEPTION_CONTINUE_EXECUTION;
}

#define XPROBE(INSN, ADDR, VAL)                                         \
    do {                                                                \
        register uint64_t x9_ __asm__("x9") = (uintptr_t)(ADDR);        \
        register uint64_t x10_ __asm__("x10") = (VAL);                  \
        uintptr_t pc_;                                                  \
                                                                        \
        __asm__ volatile("adr %[pc], 1f\n\t"                            \
                         "str %[pc], [%[slot]]\n\t"                     \
                         "1: .inst " INSN "\n\t"                        \
                         "str xzr, [%[slot]]"                           \
                         : [pc] "=&r"(pc_), "+r"(x10_)                  \
                         : "r"(x9_), [slot] "r"(&xprobe_pc)             \
                         : "memory");                                   \
        (VAL) = x10_;                                                   \
    } while (0)

static void xprobe_ldapr_x(uint8_t *a, uint64_t *v)
{
    XPROBE(XPROBE_LDAPR_X, a, *v);
}

static void xprobe_ldapr_w(uint8_t *a, uint64_t *v)
{
    XPROBE(XPROBE_LDAPR_W, a, *v);
}

static void xprobe_ldaprh(uint8_t *a, uint64_t *v)
{
    XPROBE(XPROBE_LDAPRH, a, *v);
}

static void xprobe_stlr_x(uint8_t *a, uint64_t *v)
{
    XPROBE(XPROBE_STLR_X, a, *v);
}

static void xprobe_stlr_w(uint8_t *a, uint64_t *v)
{
    XPROBE(XPROBE_STLR_W, a, *v);
}

static void xprobe_stlrh(uint8_t *a, uint64_t *v)
{
    XPROBE(XPROBE_STLRH, a, *v);
}

static void xprobe_ldapur_x(uint8_t *a, uint64_t *v)
{
    XPROBE(XPROBE_LDAPUR_X, a, *v);
}

static void xprobe_ldapur_w(uint8_t *a, uint64_t *v)
{
    XPROBE(XPROBE_LDAPUR_W, a, *v);
}

static void xprobe_stlur_x(uint8_t *a, uint64_t *v)
{
    XPROBE(XPROBE_STLUR_X, a, *v);
}

static void xprobe_stlur_w(uint8_t *a, uint64_t *v)
{
    XPROBE(XPROBE_STLUR_W, a, *v);
}

static void xprobe_ldapurh(uint8_t *a, uint64_t *v)
{
    XPROBE(XPROBE_LDAPURH, a, *v);
}

static void xprobe_stlurh(uint8_t *a, uint64_t *v)
{
    XPROBE(XPROBE_STLURH, a, *v);
}

static void xprobe_ldapursh_w(uint8_t *a, uint64_t *v)
{
    XPROBE(XPROBE_LDAPURSH_W, a, *v);
}

static void xprobe_ldapursh_x(uint8_t *a, uint64_t *v)
{
    XPROBE(XPROBE_LDAPURSH_X, a, *v);
}

static void xprobe_ldapursw(uint8_t *a, uint64_t *v)
{
    XPROBE(XPROBE_LDAPURSW, a, *v);
}

/*
 * Whether ordered accesses that cross 16 bytes fault here.  Windows
 * doesn't say whether it runs with SCTLR_EL1.nAA set (a crossing LDAPR or
 * STLR performed, not faulted), so each form generated code uses, of each
 * size that can cross, crosses a 16-byte boundary inside one page of
 * private memory, under a vectored handler that takes only an exception at
 * that access on this thread.  A form is good if it didn't fault and moved
 * exactly its bytes.  FAULT_TEST (testing) adds a crossing LDAPR into a
 * reserved page, which faults whatever the host.
 */
int xt_cross_probe(bool fault_test, char *desc, size_t len)
{
    static const struct {
        const char *name;
        void (*fn)(uint8_t *a, uint64_t *v);
        int size, off;      /* bytes; offset from a 16-byte boundary */
        bool store, unscaled;
    } forms[] = {
        { "ldapr-x", xprobe_ldapr_x, 8, 12 },
        { "ldapr-w", xprobe_ldapr_w, 4, 14 },
        { "ldaprh", xprobe_ldaprh, 2, 15 },
        { "stlr-x", xprobe_stlr_x, 8, 9, true },
        { "stlr-w", xprobe_stlr_w, 4, 13, true },
        { "stlrh", xprobe_stlrh, 2, 15, true },
        { "ldapur-x", xprobe_ldapur_x, 8, 15, false, true },
        { "ldapur-w", xprobe_ldapur_w, 4, 13, false, true },
        { "stlur-x", xprobe_stlur_x, 8, 11, true, true },
        { "stlur-w", xprobe_stlur_w, 4, 15, true, true },
        { "ldapurh", xprobe_ldapurh, 2, 15, false, true },
        { "stlurh", xprobe_stlurh, 2, 15, true, true },
        { "ldapursh-w", xprobe_ldapursh_w, 2, 15, false, true },
        { "ldapursh-x", xprobe_ldapursh_x, 2, 15, false, true },
        { "ldapursw", xprobe_ldapursw, 4, 14, false, true },
    };
    static uint8_t buf[64] __attribute__((aligned(16)));
    int bad = 0, pos = 0;
    PVOID h;

    if (!(cpuinfo & CPUINFO_LRCPC)) {
        snprintf(desc, len, "untried: no FEAT_LRCPC");
        return -1;
    }
    h = RtlAddVectoredExceptionHandler(1, xprobe_veh);
    if (!h) {
        snprintf(desc, len, "untried: no vectored handler");
        return -1;
    }
    xprobe_here = true;
    for (int i = 0; i < ARRAY_SIZE(forms); i++) {
        uint8_t *a = buf + 16 + forms[i].off;
        uint64_t mask = forms[i].size == 8 ? ~0ull
                        : (1ull << (8 * forms[i].size)) - 1;
        uint64_t val = 0x8877665544332211ull & mask, want = 0;
        bool ok = true;

        if (forms[i].unscaled && !(cpuinfo & CPUINFO_LRCPC2)) {
            continue;
        }
        for (int k = 0; k < sizeof(buf); k++) {
            buf[k] = 0xa0 + k;
        }
        for (int k = forms[i].size - 1; k >= 0; k--) {
            want = want << 8 | a[k];
        }
        xprobe_code = 0;
        /* LDAPUR and STLUR take [X9, #-1]. */
        forms[i].fn(a + forms[i].unscaled, &val);
        if (forms[i].store) {
            for (int k = 0; k < sizeof(buf); k++) {
                int j = buf + k - a;
                uint8_t e = j >= 0 && j < forms[i].size
                            ? (uint8_t)(0x8877665544332211ull >> (8 * j))
                            : 0xa0 + k;

                ok &= buf[k] == e;
            }
        } else {
            ok = (val & mask) == want;
        }
        if (xprobe_code || !ok) {
            bad++;
            pos += snprintf(desc + pos, len - pos, "%s %s %08x; ",
                            forms[i].name,
                            xprobe_code ? "faulted" : "wrong bytes",
                            xprobe_code);
            if (pos >= len) {
                pos = len - 1;
            }
        }
    }
    if (fault_test) {
        PVOID base = NULL, page;
        SIZE_T size = 8192, psize = 4096, zero = 0;
        uint64_t val = 0;
        bool ran = false;

        if (NtAllocateVirtualMemory(GetCurrentProcess(), &base, 0, &size,
                                    MEM_RESERVE, PAGE_NOACCESS) >= 0) {
            page = base;
            if (NtAllocateVirtualMemory(GetCurrentProcess(), &page, 0, &psize,
                                        MEM_COMMIT, PAGE_READWRITE) >= 0) {
                xprobe_code = 0;
                xprobe_ldapr_x((uint8_t *)base + 4092, &val);
                ran = true;
            }
            NtFreeVirtualMemory(GetCurrentProcess(), &base, &zero,
                                MEM_RELEASE);
        }
        /* Inconclusive without its fault, as with one. */
        bad++;
        pos += snprintf(desc + pos, len - pos,
                        "ldapr-x into a reserved page %s %08x; ",
                        !ran ? "untried" :
                        xprobe_code ? "faulted" : "DIDN'T FAULT", xprobe_code);
        if (pos >= len) {
            pos = len - 1;
        }
    }
    xprobe_here = false;
    RtlRemoveVectoredExceptionHandler(h);
    if (!bad) {
        snprintf(desc, len, "every crossing performed");
    } else if (pos >= 2) {
        desc[pos - 2] = 0;
    }
    return bad;
}
