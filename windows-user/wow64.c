/*
 * xtajit: the WOW64 CPU module interface (BTCpu*), as wow64.dll calls it
 * on Windows on Arm.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/rcu.h"
#include "qemu/atomic.h"
#include "hw/core/cpu.h"
#include "cpu.h"
#include "exec/mmap-lock.h"
#include "exec/page-protection.h"
#include "user/page-protection.h"
#include "tcg/tcg.h"
#include "xtajit.h"

#define WOW64_TLS_WOW64INFO 10
#define WOW64_CPUFLAGS_SOFTWARE 0x02
#define TEB_TLS_SLOTS 0x1480

NTSTATUS NTAPI RtlWow64GetCurrentCpuArea(USHORT *, void **, void **);
NTSTATUS NTAPI NtContinue(PCONTEXT, BOOLEAN);
NTSTATUS NTAPI NtSuspendThread(HANDLE, PULONG);
NTSTATUS NTAPI NtOpenThread(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                            PCLIENT_ID);
NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);
NTSTATUS NTAPI NtDelayExecution(BOOLEAN, PLARGE_INTEGER);
NTSTATUS NTAPI NtYieldExecution(void);
NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID *, ULONG_PTR, PSIZE_T,
                                       ULONG, ULONG);
NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE, PVOID *, PSIZE_T, ULONG,
                                      PULONG);
NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE, PVOID, int, PVOID, SIZE_T,
                                    PSIZE_T);
NTSTATUS NTAPI RtlQueryEnvironmentVariable(PVOID, PCWSTR, SIZE_T, PWSTR,
                                           SIZE_T, PSIZE_T);

#ifndef XT_SCAFFOLD
#define XT_SCAFFOLD "one-insn-per-tb=on"
#endif

/*
 * wow64.dll's side, resolved at process init rather than imported, so the
 * native test harness can load this module too.
 */
static NTSTATUS (WINAPI *p_Wow64SystemServiceEx)(UINT, UINT *);
static void (WINAPI *p_Wow64ProcessPendingCrossProcessItems)(void);
static NTSTATUS (WINAPI *p_Wow64RaiseException)(int, EXCEPTION_RECORD *);
static void (WINAPI *p_Wow64NotifyUnsimulateComplete)(void);

static WOW64_CONTEXT *cpu_area_context(void)
{
    WOW64_CONTEXT *c = NULL;

    RtlWow64GetCurrentCpuArea(NULL, (void **)&c, NULL);
    return c;
}

static void find_query_nr(void);
static void fix_query(uint32_t *args);
static void forget(int kind, ULONG prot, vaddr start, vaddr len);
static uint32_t nr_query_vm = ~0u;    /* NtQueryVirtualMemory's number */
static uint32_t nr_protect_vm = ~0u;  /* NtProtectVirtualMemory's */
static void guard_added(uint32_t *args);
static void bring_out(DWORD tid, void *teb, bool retire);

static XtThread *thread_of_teb(void *teb)
{
    return qatomic_read(&((XtThread **)((char *)teb + TEB_TLS_SLOTS))[16]);
}

/*
 * An adapter entry on a WOW64 thread that Windows owns, which takes the
 * engine's locks (the mmap lock, the CPU list): slot 2 bit 0 is set for its
 * duration, so that a suspension, and a termination, which suspends first,
 * takes the cooperative path and waits for the notification at the end
 * instead of stopping the thread inside a lock.  Wow64NotifyUnsimulateComplete
 * holds the thread there if a suspension is waiting, and does nothing
 * otherwise.  WOW64 says it is the thread of a CPU area: a thread before its
 * record exists (BTCpuThreadInit) or after (its own BTCpuThreadTerm) too.
 */
static uint64_t *own_slot2(void)
{
    USHORT machine;
    void *area = NULL;

    if (!p_Wow64NotifyUnsimulateComplete ||
        RtlWow64GetCurrentCpuArea(&machine, &area, NULL) < 0 || !area) {
        return NULL;
    }
    return (uint64_t *)((char *)NtCurrentTeb() + TEB_TLS_SLOTS + 2 * 8);
}

static bool adapter_begin(void)
{
    uint64_t *f = own_slot2();

    if (!f || (qatomic_read(f) & 1)) {
        return false;
    }
    qatomic_or(f, 1);
    /* Bit 0 before the scope's first lock: a suspender sees it set. */
    smp_mb();
    return true;
}

static void adapter_end(bool began)
{
    if (began) {
        qatomic_and(own_slot2(), ~(uint64_t)1);
        /* Bit 0 clear before the notification looks for a suspender. */
        smp_mb();
        p_Wow64NotifyUnsimulateComplete();
        xt_park_if_terminating(xt_tls_ready() ? xt_self : NULL);
    }
}

/* Settings: the scaffold, then XTAJIT_SETTINGS, which may override it. */
static char *settings_string(void)
{
    WCHAR w[1024];
    SIZE_T n = 0;
    GString *s = g_string_new(XT_SCAFFOLD);

    if (RtlQueryEnvironmentVariable(NULL, L"XTAJIT_SETTINGS", 15, w,
                                    ARRAY_SIZE(w) - 1, &n) >= 0 && n) {
        g_string_append_c(s, ',');
        for (SIZE_T i = 0; i < n; i++) {
            g_string_append_c(s, (char)w[i]);
        }
    }
    if (RtlQueryEnvironmentVariable(NULL, L"XTAJIT_INJECT", 13, w,
                                    ARRAY_SIZE(w) - 1, &n) >= 0 && n) {
        xt_inject_point = w[0] - '0';
    }
    return g_string_free(s, false);
}

/* The system-call stub, int 0x2e, below 2 GiB (BTCpuGetBopCode). */
static void make_bop(void)
{
    PVOID base = NULL, p;
    SIZE_T size = 4096;
    ULONG old;

    NtAllocateVirtualMemory(GetCurrentProcess(), &base, 0x7fffffff, &size,
                            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    *(uint32_t *)base = 0x2ecd2ecd;
    p = base;
    NtProtectVirtualMemory(GetCurrentProcess(), &p, &size, PAGE_EXECUTE_READ,
                           &old);
    xt_bop = (uintptr_t)base;
}

static int init_applied, init_rejected;

NTSTATUS xt_continue_native(XtNativeContext *ctx)
{
    return NtContinue(ctx, FALSE);
}


extern IMAGE_DOS_HEADER __ImageBase;

/* Process-wide bring-up shared by WOW64 and the native harness. */
int xt_process_init(bool wow64)
{
    char *settings;

    /*
     * The runtime first (the allocator, which allocates above the guest's
     * address space; the constructors, QEMU's RCU thread among them), with
     * this thread's TLS block already in place.
     */
    xt_tls_attach();
    xt_crt_process_init();
    settings = settings_string();
    xt_log_open();
    xt_engine_init(settings, &init_applied, &init_rejected);
    /*
     * QEMU's RCU constructor registered this thread as a reader; readers
     * exist only while the engine owns a thread (xt_acquire).
     */
    rcu_unregister_thread();
    make_bop();
    xt_gevent(XT_EV_THREAD_INIT, init_applied, init_rejected);
    xt_placement("module", &__ImageBase);
    xt_placement("code buffer", tcg_ctx->code_gen_buffer);
    xt_placement("settings string", settings);
    return 0;
}

int xt_settings_applied(int *rejected)
{
    *rejected = init_rejected;
    return init_applied;
}

XTEXPORT NTSTATUS WINAPI BTCpuProcessInit(void)
{
    HMODULE w = GetModuleHandleW(L"wow64.dll");
    void **slots = (void **)((char *)NtCurrentTeb() + TEB_TLS_SLOTS);

    p_Wow64SystemServiceEx = (void *)GetProcAddress(w, "Wow64SystemServiceEx");
    p_Wow64ProcessPendingCrossProcessItems =
        (void *)GetProcAddress(w, "Wow64ProcessPendingCrossProcessItems");
    p_Wow64RaiseException = (void *)GetProcAddress(w, "Wow64RaiseException");
    p_Wow64NotifyUnsimulateComplete =
        (void *)GetProcAddress(w, "Wow64NotifyUnsimulateComplete");
    if (!p_Wow64SystemServiceEx || !p_Wow64RaiseException) {
        return STATUS_ENTRYPOINT_NOT_FOUND;
    }
    xt_process_init(true);
    find_query_nr();
    /*
     * A software CPU: wow64.dll then sets up the cross-process work list
     * and suspends this process's threads cooperatively (slot 2).
     */
    ((ULONG *)slots[WOW64_TLS_WOW64INFO])[1] = WOW64_CPUFLAGS_SOFTWARE;
    return STATUS_SUCCESS;
}

/*
 * A process ends its other threads first (a null handle) and runs its
 * DLLs' detach code, guest code among it, on the last one.  Windows kills
 * those threads wherever they are; one killed inside the engine would
 * still count as running, and the exclusive work of the last thread's
 * guest code (start_exclusive) would wait for it forever, or would hold
 * an engine lock.  So each leaves the engine first, and stays suspended
 * outside it.
 */
typedef struct XtThreadRef {
    DWORD tid;
    void *teb;
} XtThreadRef;

static void bring_out_others(void)
{
    DWORD me = GetCurrentThreadId();
    GArray *threads = g_array_sized_new(FALSE, FALSE, sizeof(XtThreadRef), 8);
    bool began = adapter_begin();
    CPUState *cs;

    /* The records stay while held, though their threads may exit. */
    xt_record_hold();
    cpu_list_lock();
    CPU_FOREACH(cs) {
        XtThread *t = cs->opaque;

        if (t && t->wow64 && t->tid != me) {
            XtThreadRef r = { t->tid, t->teb };

            g_array_append_val(threads, r);
        }
    }
    cpu_list_unlock();
    adapter_end(began);
    for (guint i = 0; i < threads->len; i++) {
        XtThreadRef *r = &g_array_index(threads, XtThreadRef, i);

        bring_out(r->tid, r->teb, false);
    }
    xt_record_release();
    g_array_free(threads, TRUE);
}

XTEXPORT void WINAPI BTCpuProcessTerm(HANDLE h, BOOL after, ULONG status)
{
    if (!after && !h && xt_tls_ready()) {
        bring_out_others();
    }
    /* A process ending itself never returns from the "before" call. */
    if (xt_log_handle() && xt_tls_ready()) {
        if (xt_self) {
            xt_log_flush(xt_self);
        }
        xt_dump(NULL, NULL);
    }
}

XTEXPORT NTSTATUS WINAPI BTCpuThreadInit(void)
{
    bool began;

    xt_tls_attach();
    began = adapter_begin();
    xt_reap();
    xt_thread_new(true);
    adapter_end(began);
    return STATUS_SUCCESS;
}

static DWORD thread_id(HANDLE thread, void **teb)
{
    XtThreadBasicInfo tbi;

    /* wow64.dll names the calling thread with a null handle. */
    if (!thread || thread == GetCurrentThread()) {
        *teb = NtCurrentTeb();
        return GetCurrentThreadId();
    }
    if (NtQueryInformationThread(thread, 0, &tbi, sizeof(tbi), NULL) < 0) {
        return 0;
    }
    *teb = tbi.TebBaseAddress;
    return (DWORD)(uintptr_t)tbi.ClientId.UniqueThread;
}

/*
 * Another thread is about to be terminated (NtTerminateThread follows).
 * It must first stop where neither the engine nor wow64.dll has anything
 * of its: in Windows' hands, outside an adapter entry and outside
 * wow64.dll's own critical regions.  These are what Windows' cooperative
 * suspension tests: slot 2 bits 0 (this module's: guest code, adapter
 * entries) and 1 (wow64.dll's, while it initializes a thread), and slot 6
 * (wow64.dll's, around its cross-process work list and its lock).  It
 * is told to stop there (terminating: it parks at its next acquire, or
 * at the end of the adapter entry it is in; an exit request gets it out
 * of guest code), then suspended until it is found so.  The
 * suspension is kept: if the termination succeeds the thread never runs
 * again.  Windows' cooperative suspension isn't used: another thread's
 * suspension of the same target would be in its way.  The record is read
 * only while the target is suspended, so its own exit, which waits for
 * the record's users, can't be waiting on this.
 */
/*
 * Bring another thread out of the engine before Windows ends it: suspend
 * it where it owns no engine state (outside simulation, not inside an
 * adapter's locks or wow64.dll's), else ask it to leave and try again.
 * Then retire its record (it is being terminated alone), or leave it
 * suspended there (the whole process is ending).
 */
static void bring_out(DWORD tid, void *teb, bool retire)
{
    OBJECT_ATTRIBUTES oa = { .Length = sizeof(oa) };
    CLIENT_ID cid = { .UniqueThread = (HANDLE)(uintptr_t)tid };
    CONTEXT ctx = { .ContextFlags = CONTEXT_CONTROL };
    LARGE_INTEGER tick = { .QuadPart = -10000 };
    uint64_t *slot2 = (uint64_t *)((char *)teb + TEB_TLS_SLOTS + 2 * 8);
    uint64_t *slot6 = (uint64_t *)((char *)teb + TEB_TLS_SLOTS + 6 * 8);
    HANDLE h;
    XtThread *t;
    int tries;

    if (!thread_of_teb(teb)) {
        /* Not ours, or a second notification for the same thread. */
        xt_gevent(XT_EV_THREAD_TERM, tid, 0);
        return;
    }
    if (NtOpenThread(&h, SYNCHRONIZE | THREAD_SUSPEND_RESUME |
                     THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                     &oa, &cid) < 0) {
        xt_gevent(XT_EV_THREAD_TERM, tid, 1);
        return;
    }
    for (tries = 0;; tries++) {
        if (NtSuspendThread(h, NULL) < 0) {
            break;
        }
        /* The suspension takes effect by the time the context is read. */
        NtGetContextThread(h, &ctx);
        t = thread_of_teb(teb);
        if (!t) {
            /* Its own exit has begun: let it finish. */
            NtResumeThread(h, NULL);
            break;
        }
        if (t->state == XT_WINDOWS && !(qatomic_read(slot2) & 3) &&
            !qatomic_read(slot6)) {
            bool began;

            qatomic_set(&t->terminating, 1);
            xt_gevent(XT_EV_THREAD_TERM, tid, 2 | tries << 8 | !retire << 4);
            if (!retire) {
                NtClose(h);
                return;
            }
            /* A scope: the reaper's lock, if this thread is terminated too. */
            began = adapter_begin();
            xt_thread_retire(t, h);
            adapter_end(began);
            return;
        }
        qatomic_set(&t->terminating, 1);
        qatomic_set(&t->suspend_req, 1);
        cpu_exit(t->cpu);
        NtResumeThread(h, NULL);
        /* A sleep lasts a timer tick (15.6 ms): yield first. */
        if (tries < 64) {
            NtYieldExecution();
        } else {
            NtDelayExecution(FALSE, &tick);
        }
    }
    xt_gevent(XT_EV_THREAD_TERM, tid, 3);
    NtClose(h);
}

/*
 * The suspension of another thread is outside an adapter scope: two
 * threads terminating each other would otherwise each wait for the
 * other's notification.
 */
XTEXPORT void WINAPI BTCpuThreadTerm(HANDLE thread, LONG code)
{
    void *teb = NULL;
    DWORD tid = thread_id(thread, &teb);
    XtThread *t = xt_tls_ready() ? xt_self : NULL;
    bool began;

    xt_enter();
    began = adapter_begin();
    xt_reap();
    if (t && tid == t->tid) {
        xt_thread_free(t);
    }
    adapter_end(began);
    /*
     * The thread's allocator heap goes back for the next thread to take;
     * allocations after this one (ntdll's exit may notify) start a new
     * one.
     */
    if (t && tid == t->tid) {
        xt_crt_thread_fini();
    }
    if (tid && tid != GetCurrentThreadId()) {
        bring_out(tid, teb, true);
    }
}

XTEXPORT void *WINAPI BTCpuGetBopCode(void)
{
    return (void *)xt_bop;
}

static void notify(XtThread *t)
{
    xt_inject(t, XT_INJ_CALLBACK);
    if (p_Wow64NotifyUnsimulateComplete) {
        p_Wow64NotifyUnsimulateComplete();
        xt_event(t, XT_EV_NOTIFY, 0, 0);
    }
}

/*
 * Run the thread's guest code; never returns.  Every exit that hands the
 * thread to Windows publishes first (xt_publish: export, then clear slot
 * 2 bit 0) and notifies, and every return acquires again (set bit 0, then
 * import), so a context Windows changed meanwhile takes effect.  A nested
 * callback enters here afresh; an activation Windows abandons (a callback
 * return, NtContinue) holds nothing of the engine's.
 */
XTEXPORT void WINAPI BTCpuSimulate(void)
{
    XtThread *t = xt_self;
    WOW64_CONTEXT *c = cpu_area_context();
    XtExit x;

    t->activation++;
    xt_event(t, XT_EV_ACTIVATE, t->activation, c->Eip);
    xt_acquire(t, c);
    for (;;) {
        xt_run(t, &x);
        xt_event(t, XT_EV_PUBLISH, x.kind, t->env->eip);
        switch (x.kind) {
        case XT_EXIT_SYSCALL: {
            NTSTATUS st;

            xt_publish(t, c);
            notify(t);
            if (p_Wow64ProcessPendingCrossProcessItems) {
                p_Wow64ProcessPendingCrossProcessItems();
            }
            st = p_Wow64SystemServiceEx(x.nr, (UINT *)(uintptr_t)x.args);
            if (x.nr == nr_query_vm && st >= 0) {
                fix_query((uint32_t *)(uintptr_t)x.args);
            } else if (x.nr == nr_protect_vm && st >= 0) {
                guard_added((uint32_t *)(uintptr_t)x.args);
            }
            c = cpu_area_context();
            xt_acquire(t, c);
            t->env->regs[R_EAX] = st;
            xt_event(t, XT_EV_SYSCALL, x.nr, st);
            break;
        }
        case XT_EXIT_SUSPEND:
            xt_publish(t, c);
            notify(t);
            c = cpu_area_context();
            xt_acquire(t, c);
            break;
        case XT_EXIT_EXCEPTION:
        case XT_EXIT_STOP:
        default:
            xt_publish(t, c);
            notify(t);
            xt_event(t, XT_EV_RAISE,
                     x.rec.ExceptionCode |
                     (uint64_t)x.rec.ExceptionInformation[0] << 32,
                     (uintptr_t)x.rec.ExceptionAddress |
                     (uint64_t)x.rec.ExceptionInformation[1] << 32);
            xt_log_flush(t);
            /*
             * Points the context at the guest's KiUserExceptionDispatcher;
             * for a software interrupt wow64.dll makes the record.
             */
            if (x.vector >= 0) {
                p_Wow64RaiseException(x.vector, NULL);
            } else {
                p_Wow64RaiseException(-1, &x.rec);
            }
            c = cpu_area_context();
            xt_acquire(t, c);
            break;
        }
    }
}

/*
 * Another thread suspends THREAD, which runs guest code (slot 2 bit 0
 * set): wow64.dll has suspended it already, and resumes it after this
 * returns, then waits for its Wow64NotifyUnsimulateComplete.  With
 * REQUEST set (wow64.dll passes 1; Windows' own module acts only then),
 * ask it to leave the engine at its next TB boundary: an exit request,
 * release stores only.  A thread in an adapter entry (adapter_begin)
 * notifies at its end without being asked.
 */
XTEXPORT NTSTATUS WINAPI BTCpuSuspendLocalThread(HANDLE thread, void *info,
                                                 void *unk1, ULONG request)
{
    XtThreadBasicInfo tbi;
    XtThread *t;

    if (!p_Wow64NotifyUnsimulateComplete) {
        /* Wine: (HANDLE, ULONG *count), the thread not yet suspended. */
        return NtSuspendThread(thread, info);
    }
    if (NtQueryInformationThread(thread, 0, &tbi,
                                 sizeof(tbi), NULL) < 0) {
        return STATUS_SUCCESS;
    }
    /*
     * The target is suspended, so its record can't be freed under us by
     * its own exit; a terminated thread's is freed by another, which
     * waits for this use to end.
     */
    xt_record_hold();
    t = thread_of_teb(tbi.TebBaseAddress);
    if (t && request) {
        qatomic_set(&t->suspend_req, 1);
        cpu_exit(t->cpu);
    }
    xt_gevent(XT_EV_SUSPEND_SEEN, (uintptr_t)tbi.ClientId.UniqueThread,
              t ? t->state : -1);
    xt_record_release();
    return STATUS_SUCCESS;
}

/*
 * Every native exception in the process reaches this first, inside
 * Windows' dispatch.  The engine's own faults continue (NtContinue) into
 * QEMU's recovery; the rest return, and dispatch carries on.
 */
XTEXPORT NTSTATUS WINAPI BTCpuResetToConsistentState(EXCEPTION_POINTERS *p)
{
    /* Threads that never entered the engine have no TLS block. */
    if (xt_tls_ready() &&
        xt_fault_redirect(p->ExceptionRecord, p->ContextRecord)) {
        NtContinue(p->ContextRecord, FALSE);
    }
    xt_log_native(p->ExceptionRecord, p->ContextRecord);
    return STATUS_SUCCESS;
}

typedef struct Unprotect {
    vaddr start, last;
    vaddr found;
} Unprotect;

/* The first page in the range that QEMU write-protected. */
static int find_protected(void *opaque, vaddr start, vaddr end, int flags)
{
    Unprotect *u = opaque;

    if (!(flags & PAGE_WRITE_ORG) || (flags & PAGE_WRITE) ||
        end - 1 < u->start || start > u->last) {
        return 0;
    }
    u->found = MAX(start, u->start);
    return 1;
}

/*
 * The guest's NtQueryVirtualMemory goes to Windows, which reports QEMU's
 * write protection of translated pages.  For MemoryBasicInformation of
 * this process the result is corrected: the queried page's protection is
 * the one QEMU replaced (xt_guest_prot), and the region the run of pages
 * around it with the same answer, the same allocation, state and type.
 * Native ntdll's stub gives the system call's number (the x86 one uses
 * the same).
 *
 * wow64.dll doesn't notify a protection change that adds PAGE_GUARD to
 * executable memory, so translations would run on without touching the
 * page and the guard would never fault; such a change is forgotten here.
 */
static uint32_t syscall_nr(const char *name)
{
    uint32_t *f = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                         name);

    return f && (*f & 0xffe0001f) == 0xd4000001 ? (*f >> 5) & 0xffff : ~0u;
}

static void find_query_nr(void)
{
    nr_query_vm = syscall_nr("NtQueryVirtualMemory");
    nr_protect_vm = syscall_nr("NtProtectVirtualMemory");
}

typedef struct Mbi32 {
    uint32_t base, alloc_base, alloc_prot, size, state, prot, type;
} Mbi32;

/* The guest's view of PAGE: Windows' answer, QEMU's protection undone. */
static bool page_view(vaddr page, Mbi32 *v)
{
    MEMORY_BASIC_INFORMATION mbi;
    ULONG saved;

    if (NtQueryVirtualMemory(GetCurrentProcess(), (void *)(uintptr_t)page, 0,
                             &mbi, sizeof(mbi), NULL) < 0) {
        return false;
    }
    saved = xt_guest_prot(page);
    v->alloc_base = (uintptr_t)mbi.AllocationBase;
    v->state = mbi.State;
    v->type = mbi.Type;
    v->prot = saved ? saved : mbi.Protect;
    return true;
}

static bool same_view(const Mbi32 *a, const Mbi32 *b)
{
    return a->alloc_base == b->alloc_base && a->state == b->state &&
           a->type == b->type && a->prot == b->prot;
}

static void fix_query(uint32_t *args)
{
    Mbi32 *m = (Mbi32 *)(uintptr_t)args[3], q, v;
    vaddr page = args[1] & ~(vaddr)0xfff, start, end;
    Unprotect u;
    bool began;

    if (args[0] != 0xffffffff || args[2] != 0 || args[4] < sizeof(Mbi32) ||
        !m) {
        return;
    }
    began = adapter_begin();
    mmap_lock();
    u = (Unprotect){ m->base, m->base + m->size - 1 };
    if ((walk_memory_regions(&u, find_protected) || xt_guest_prot(page)) &&
        page_view(page, &q)) {
        start = page;
        for (int i = 0; i < 0x10000 && start > q.alloc_base; i++) {
            if (!page_view(start - 0x1000, &v) || !same_view(&q, &v)) {
                break;
            }
            start -= 0x1000;
        }
        end = page + 0x1000;
        for (int i = 0; i < 0x10000 && end <= guest_addr_max; i++) {
            if (!page_view(end, &v) || !same_view(&q, &v)) {
                break;
            }
            end += 0x1000;
        }
        m->base = start;
        m->size = end - start;
        m->prot = q.prot;
    }
    mmap_unlock();
    adapter_end(began);
}

static void guard_added(uint32_t *args)
{
    uint32_t base, size;

    if (args[0] != 0xffffffff || !(args[3] & PAGE_GUARD) ||
        !args[1] || !args[2]) {
        return;
    }
    base = *(uint32_t *)(uintptr_t)args[1];
    size = *(uint32_t *)(uintptr_t)args[2];
    forget(2, args[3], base, size);
}

/*
 * Memory notifications.  QEMU's page flags for the range are dropped
 * (with the translations of executable pages) and refilled from Windows
 * when next probed (xt_mem_refresh):
 * - after a change that keeps the range the caller's (an allocation, a
 *   protection change, a view mapped): Windows' protection is then what
 *   the caller asked for, except on pages QEMU write-protected since for
 *   their new translations.  Those keep their flags: dropping them would
 *   lose that the protection is QEMU's, and the next write would be the
 *   guest's fault;
 * - before a free or an unmap, while the range is still the caller's:
 *   after it, another thread may have it already.
 */
static bool protected_since(vaddr page, ULONG prot)
{
    MEMORY_BASIC_INFORMATION mbi;

    return NtQueryVirtualMemory(GetCurrentProcess(), (void *)(uintptr_t)page,
                                0, &mbi, sizeof(mbi), NULL) >= 0 &&
           (mbi.Protect & 0xff) != (prot & 0xff);
}

static void forget(int kind, ULONG prot, vaddr start, vaddr len)
{
    vaddr from, last;
    bool began, keep = kind == 1 || kind == 2 || kind == 4;

    if (xt_tls_ready() && xt_self) {
        xt_event(xt_self, XT_EV_MEMNOTE, (uint64_t)kind << 56 |
                 (uint64_t)(prot & 0xffffff) << 32 | (len & 0xffffffff),
                 start);
    }
    if (!len || start > guest_addr_max) {
        return;
    }
    from = start & TARGET_PAGE_MASK;
    last = MIN(start + len - 1, (vaddr)guest_addr_max) | ~TARGET_PAGE_MASK;
    began = adapter_begin();
    mmap_lock();
    while (keep && from <= last) {
        Unprotect u = { from, last };
        vaddr page;

        if (!walk_memory_regions(&u, find_protected)) {
            break;
        }
        page = u.found & TARGET_PAGE_MASK;
        if (protected_since(page, prot)) {
            if (page > from) {
                page_set_flags(from, page - 1, 0, PAGE_VALID);
                xt_guest_prot_forget(from, page - 1);
            }
        } else {
            page_set_flags(from, page | ~TARGET_PAGE_MASK, 0, PAGE_VALID);
            xt_guest_prot_forget(from, page | ~TARGET_PAGE_MASK);
        }
        from = page + TARGET_PAGE_SIZE;
    }
    if (from <= last) {
        page_set_flags(from, last, 0, PAGE_VALID);
        xt_guest_prot_forget(from, last);
    }
    mmap_unlock();
    adapter_end(began);
}

/* Translations of [start, start + len) go, as for a host write. */
static void invalidate(vaddr start, vaddr len)
{
    bool began = adapter_begin();

    if (xt_tls_ready() && xt_self) {
        xt_event(xt_self, XT_EV_MEMNOTE, (uint64_t)6 << 56 |
                 (len & 0xffffffff), start);
    }

    xt_invalidate(start, len);
    adapter_end(began);
}

XTEXPORT void WINAPI BTCpuFlushInstructionCache2(const void *addr, SIZE_T len)
{
    xt_enter();
    invalidate((uintptr_t)addr, len);
}

XTEXPORT void WINAPI BTCpuFlushInstructionCacheHeavy(const void *addr,
                                                     SIZE_T len)
{
    xt_enter();
    invalidate((uintptr_t)addr, len);
}

XTEXPORT void WINAPI BTCpuNotifyMemoryDirty(void *addr, SIZE_T len)
{
    xt_enter();
    invalidate((uintptr_t)addr, len);
}

XTEXPORT void WINAPI BTCpuNotifyMemoryAlloc(void *addr, SIZE_T len, ULONG type,
                                            ULONG prot, BOOL after,
                                            ULONG status)
{
    xt_enter();
    if (after && !status && !(type & (MEM_RESET | MEM_RESET_UNDO))) {
        forget(1, prot, (uintptr_t)addr, len);
    }
}

/*
 * Before the guest changes a protection, pages QEMU write-protected for
 * their translations get their write permission back (page_unprotect: the
 * translations go), so that the old protection Windows reports is the
 * guest's, not QEMU's.  Queries (NtQueryVirtualMemory) still see QEMU's.
 */
static void unprotect_range(vaddr start, vaddr len)
{
    Unprotect u = { start, MIN(start + len - 1, (vaddr)guest_addr_max) };

    bool began;

    if (!len || start > guest_addr_max) {
        return;
    }
    began = adapter_begin();
    mmap_lock();
    while (walk_memory_regions(&u, find_protected)) {
        page_unprotect(NULL, u.found, 0);
    }
    mmap_unlock();
    adapter_end(began);
}

XTEXPORT void WINAPI BTCpuNotifyMemoryProtect(void *addr, SIZE_T len,
                                              ULONG prot, BOOL after,
                                              ULONG status)
{
    xt_enter();
    if (!after) {
        unprotect_range((uintptr_t)addr, len);
    } else if (!status) {
        forget(2, prot, (uintptr_t)addr, len);
    }
}

/* The allocation ADDR is in: its base and extent. */
static vaddr allocation_extent(void *addr, vaddr *len)
{
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t base, p;

    *len = 0;
    if (NtQueryVirtualMemory(GetCurrentProcess(), addr, 0, &mbi,
                             sizeof(mbi), NULL) < 0) {
        return 0;
    }
    base = (uintptr_t)mbi.AllocationBase;
    for (p = base;; p += mbi.RegionSize) {
        if (NtQueryVirtualMemory(GetCurrentProcess(), (void *)p, 0, &mbi,
                                 sizeof(mbi), NULL) < 0 ||
            (uintptr_t)mbi.AllocationBase != base) {
            break;
        }
    }
    *len = p - base;
    return base;
}

/* Before: a released allocation with no size given goes whole. */
XTEXPORT void WINAPI BTCpuNotifyMemoryFree(void *addr, SIZE_T len,
                                           ULONG type, BOOL after,
                                           ULONG status)
{
    vaddr start = (uintptr_t)addr, n = len;

    xt_enter();
    if (after) {
        return;
    }
    if (!n && (type & MEM_RELEASE)) {
        start = allocation_extent(addr, &n);
    }
    forget(3, 0, start, n);
}

XTEXPORT NTSTATUS WINAPI BTCpuNotifyMapViewOfSection(void *unk1, void *addr,
                                                     void *unk2, SIZE_T len,
                                                     ULONG type, ULONG prot)
{
    xt_enter();
    forget(4, prot, (uintptr_t)addr, len);
    return STATUS_SUCCESS;
}

/* Before: the whole view. */
XTEXPORT void WINAPI BTCpuNotifyUnmapViewOfSection(void *addr, BOOL after,
                                                   ULONG status)
{
    vaddr start, len;

    xt_enter();
    if (!after) {
        start = allocation_extent(addr, &len);
        forget(5, 0, start, len);
    }
}

/*
 * Before: pages QEMU write-protected in the buffer get write back (their
 * translations go), or the kernel's write into them fails the read.
 */
XTEXPORT void WINAPI BTCpuNotifyReadFile(HANDLE h, void *addr, SIZE_T len,
                                         BOOL after, NTSTATUS status)
{
    xt_enter();
    if (!after) {
        unprotect_range((uintptr_t)addr, len);
    } else if (!status) {
        invalidate((uintptr_t)addr, len);
    }
}

/*
 * What CPUID says, for IsProcessorFeaturePresent in 32-bit code.  As
 * Windows' own x86 emulator: no PAE, DAZ or fast-fail feature (int 0x29
 * still ends the process).
 */
XTEXPORT BOOLEAN WINAPI BTCpuIsProcessorFeaturePresent(UINT feature)
{
    CPUState *cs = first_cpu;
    CPUX86State *env = cs ? cpu_env(cs) : NULL;
    uint32_t edx, ecx, ext2;

    if (!env) {
        return FALSE;
    }
    edx = env->features[FEAT_1_EDX];
    ecx = env->features[FEAT_1_ECX];
    ext2 = env->features[FEAT_8000_0001_EDX];
    switch (feature) {
    case PF_COMPARE_EXCHANGE_DOUBLE:
        return !!(edx & CPUID_CX8);
    case PF_MMX_INSTRUCTIONS_AVAILABLE:
        return !!(edx & CPUID_MMX);
    case PF_XMMI_INSTRUCTIONS_AVAILABLE:
        return !!(edx & CPUID_SSE);
    case PF_RDTSC_INSTRUCTION_AVAILABLE:
        return !!(edx & CPUID_TSC);
    case PF_XMMI64_INSTRUCTIONS_AVAILABLE:
        return !!(edx & CPUID_SSE2);
    case PF_NX_ENABLED:
        return !!(ext2 & CPUID_EXT2_NX);
    case PF_SSE3_INSTRUCTIONS_AVAILABLE:
        return !!(ecx & CPUID_EXT_SSE3);
    case PF_COMPARE_EXCHANGE128:
        return !!(ecx & CPUID_EXT_CX16);
    case PF_RDTSCP_INSTRUCTION_AVAILABLE:
        return !!(ext2 & CPUID_EXT2_RDTSCP);
    case PF_SSSE3_INSTRUCTIONS_AVAILABLE:
        return !!(ecx & CPUID_EXT_SSSE3);
    case PF_SSE4_1_INSTRUCTIONS_AVAILABLE:
        return !!(ecx & CPUID_EXT_SSE41);
    case PF_SSE4_2_INSTRUCTIONS_AVAILABLE:
        return !!(ecx & CPUID_EXT_SSE42);
    default:
        return FALSE;
    }
}

/*
 * The processor's identity for 32-bit code (GetSystemInfo and
 * NtQuerySystemInformation): x86, level the CPUID family, revision its
 * model and stepping, as x86 Windows derives them.  Windows fills in the
 * rest of SYSTEM_CPU_INFORMATION.
 */
XTEXPORT void BTCpuUpdateProcessorInformation(void *info)
{
    CPUState *cs = first_cpu;
    uint32_t eax, ebx, ecx, edx, family, model;
    USHORT *f = info;

    if (!cs) {
        return;
    }
    cpu_x86_cpuid(cpu_env(cs), 1, 0, &eax, &ebx, &ecx, &edx);
    family = (eax >> 8) & 0xf;
    model = (eax >> 4) & 0xf;
    if (family == 0xf) {
        family += (eax >> 20) & 0xff;
    }
    if (family == 6 || family >= 0xf) {
        model |= ((eax >> 16) & 0xf) << 4;
    }
    f[0] = PROCESSOR_ARCHITECTURE_INTEL;
    f[1] = family;
    f[2] = model << 8 | (eax & 0xf);
}
