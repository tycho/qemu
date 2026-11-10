/*
 * xtajit: the native test harness's entry points.  A native ARM64 process
 * loads the module and drives one engine thread per calling thread, with
 * the boundary that WOW64 uses (acquire, run, publish) but contexts the
 * caller passes and a vectored handler in place of wow64.dll's hook.
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
#include "exec/tb-flush.h"
#include "exec/page-protection.h"
#include "user/page-protection.h"
#include "accel/tcg/helper-retaddr.h"
#include "accel/tcg/tb-context.h"
#include "xtajit.h"


NTSTATUS NTAPI NtContinue(PCONTEXT, BOOLEAN);
PVOID NTAPI RtlAddVectoredExceptionHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);

struct XtTestExit {
    int kind;               /* XtExitKind */
    int trapnr;
    uint32_t nr, args;      /* system call */
    uint32_t code, addr;    /* exception */
    uint32_t info0, info1;
    uint32_t flags;
};

struct XtTestState {
    uint32_t violations;
    uint32_t faults;
    uint32_t mmap_locked;
    uint32_t gen_tb;
    uint64_t helper_retaddr;
    uint32_t state, active, rcu, busy;
    uint32_t flushes, suspensions;
    uint32_t counts[XT_EV__MAX];
};

static LONG CALLBACK xt_veh(EXCEPTION_POINTERS *p)
{
    if (xt_fault_redirect(p->ExceptionRecord, p->ContextRecord)) {
        NtContinue(p->ContextRecord, FALSE);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

XTEXPORT int xt_test_init(int *rejected)
{
    xt_diag = true;
    xt_process_init(false);
    RtlAddVectoredExceptionHandler(1, xt_veh);
    return xt_settings_applied(rejected);
}

/* An engine thread for the calling thread; int3 ends a run. */
XTEXPORT void *xt_test_thread(void)
{
    XtThread *t = xt_self ? xt_self : xt_thread_new(false);

    t->stop_at_int3 = true;
    t->cpu->opaque = t;
    return t;
}

XTEXPORT int xt_test_run(WOW64_CONTEXT *ctx, XtTestExit *out)
{
    XtThread *t = xt_self;
    XtExit x;

    t->activation++;
    xt_event(t, XT_EV_ACTIVATE, t->activation, ctx->Eip);
    xt_acquire(t, ctx);
    xt_run(t, &x);
    xt_event(t, XT_EV_PUBLISH, x.kind, t->env->eip);
    xt_publish(t, ctx);
    memset(out, 0, sizeof(*out));
    out->kind = x.kind;
    out->trapnr = x.trapnr;
    out->nr = x.nr;
    out->args = x.args;
    if (x.kind == XT_EXIT_EXCEPTION) {
        out->code = x.rec.ExceptionCode;
        out->addr = (uintptr_t)x.rec.ExceptionAddress;
        out->info0 = x.rec.ExceptionInformation[0];
        out->info1 = x.rec.ExceptionInformation[1];
        out->flags = x.rec.ExceptionFlags;
    }
    return x.kind;
}

/* Import and export without running: the context round trip. */
XTEXPORT void xt_test_roundtrip(const WOW64_CONTEXT *in, WOW64_CONTEXT *out)
{
    XtThread *t = xt_self;

    xt_acquire(t, in);
    xt_publish(t, out);
}

XTEXPORT void xt_test_invalidate(void *addr, size_t len)
{
    xt_invalidate((uintptr_t)addr, len);
}

/* Drop QEMU's page flags for a range, as a memory notification does. */
XTEXPORT void xt_test_forget(void *addr, size_t len)
{
    vaddr start = (uintptr_t)addr, last = start + len - 1;

    mmap_lock();
    page_set_flags(start & TARGET_PAGE_MASK, last | ~TARGET_PAGE_MASK, 0,
                   PAGE_VALID);
    mmap_unlock();
}

XTEXPORT int xt_test_page_flags(void *addr)
{
    return page_get_flags((uintptr_t)addr);
}

XTEXPORT void xt_test_state(XtTestState *s)
{
    XtThread *t = xt_self;

    memset(s, 0, sizeof(*s));
    s->violations = t->violations;
    s->faults = xt_fault_count();
    s->mmap_locked = have_mmap_lock();
    s->gen_tb = tcg_ctx->gen_tb != NULL;
    s->helper_retaddr = helper_retaddr;
    s->state = t->state;
    s->active = t->active;
    s->rcu = t->rcu_registered;
    s->busy = t->fault.busy;
    s->flushes = qatomic_read(&tb_ctx.tb_flush_count);
    s->suspensions = t->suspensions;
    for (int i = 0; i < XT_EV__MAX; i++) {
        s->counts[i] = t->counts[i];
    }
}

XTEXPORT void xt_test_dump(void *handle)
{
    xt_dump(xt_self, handle);
}

/* The cross-thread request BTCpuSuspendLocalThread makes. */
XTEXPORT int xt_test_suspend(DWORD tid)
{
    CPUState *cs;
    int found = 0;

    cpu_list_lock();
    CPU_FOREACH(cs) {
        XtThread *t = cs->opaque;

        if (t && t->tid == tid) {
            qatomic_set(&t->suspend_req, 1);
            cpu_exit(cs);
            found = 1;
        }
    }
    cpu_list_unlock();
    return found;
}

/*
 * A flush of all translations, when thread TID (0: this one) next leaves
 * generated code.
 */
XTEXPORT int xt_test_flush(DWORD tid)
{
    CPUState *cs;
    int found = 0;

    if (!tid) {
        queue_tb_flush(xt_self->cpu);
        return 1;
    }
    cpu_list_lock();
    CPU_FOREACH(cs) {
        XtThread *t = cs->opaque;

        if (t && t->tid == tid) {
            queue_tb_flush(cs);
            found = 1;
        }
    }
    cpu_list_unlock();
    return found;
}

XTEXPORT int xt_test_guest_read(uint32_t addr, void *buf, uint32_t len)
{
    return xt_guest_read(xt_self, addr, buf, len);
}

XTEXPORT uintptr_t xt_test_bop(void)
{
    return xt_bop;
}
