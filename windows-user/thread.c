/*
 * xtajit: per-thread state, the ownership transitions, the event ring and
 * the context conversion.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/rcu.h"
#include "qom/object.h"
#include "qemu/atomic.h"
#include "hw/core/cpu.h"
#include "cpu.h"
#include "tcg/tcg.h"
#include "tcg/startup.h"
#include "tcg/helper-tcg.h"
#include "exec/mmap-lock.h"
#include "accel/tcg/helper-retaddr.h"
#include "xtajit.h"

NTSTATUS NTAPI NtCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                            PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG,
                            ULONG, ULONG, PVOID, ULONG);
NTSTATUS NTAPI NtWriteFile(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK,
                           PVOID, ULONG, PLARGE_INTEGER, PULONG);
NTSTATUS NTAPI RtlQueryEnvironmentVariable(PVOID, PCWSTR, SIZE_T, PWSTR,
                                           SIZE_T, PSIZE_T);
NTSTATUS NTAPI NtDelayExecution(BOOLEAN, PLARGE_INTEGER);
NTSTATUS NTAPI NtYieldExecution(void);
NTSTATUS NTAPI NtOpenThread(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                            PCLIENT_ID);
NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE, PVOID *, PSIZE_T, ULONG);
NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE, PVOID, int, PVOID, SIZE_T,
                                    PSIZE_T);

__thread XtThread *xt_self;
uint32_t xt_inject_point;

/* The TEB's ThreadLocalStoragePointer (TEB + 0x58); its process id. */
#define TEB_TLS_POINTER 0x58
#define TEB_CLIENT_ID 0x40

#ifndef TARGET_X86_64
extern char _tls_start, _tls_end;
extern uint64_t _tls_index;
#endif

/*
 * Memory above 4 GiB, outside the guest's address space, whatever the
 * process: Windows takes a missing upper bound in a WOW64 process to be
 * the 32-bit space's, so both bounds are given.
 */
void *xt_alloc_high(size_t len)
{
    XtBasicInfo sbi;
    MEM_ADDRESS_REQUIREMENTS req = { 0 };
    MEM_EXTENDED_PARAMETER ext = { 0 };
    PVOID base = NULL;
    SIZE_T size = len;

    if (NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi),
                                 NULL) < 0) {
        return NULL;
    }
    req.LowestStartingAddress = (void *)0x100000000ull;
    req.HighestEndingAddress = (void *)sbi.MaximumUserModeAddress;
    ext.Type = MemExtendedParameterAddressRequirements;
    ext.Pointer = &req;
    if (NtAllocateVirtualMemoryEx(GetCurrentProcess(), &base, &size,
                                  MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE,
                                  &ext, 1) < 0) {
        return NULL;
    }
    return base;
}

#ifdef TARGET_X86_64
/*
 * The x64 module's thread-local variables are emulated, in storage of its
 * own (runtime/emutls.c): usable on any thread, at any time.
 */
bool xt_tls_ready(void)
{
    return true;
}

void xt_tls_attach(void)
{
    xt_emutls_init();
}

/* A thread's storage goes with xt_emutls_reap, record or not. */
static void *tls_alloc_of(void *teb)
{
    return NULL;
}
#else
/*
 * Whether this thread can use the module's thread-local variables: in a
 * WOW64 process the native loader sets up no PE TLS for the CPU module, so
 * xt_tls_attach does, on every thread that enters the engine.
 */
bool xt_tls_ready(void)
{
    void **tlsp = *(void ***)((char *)NtCurrentTeb() + TEB_TLS_POINTER);

    return tlsp && tlsp[_tls_index];
}

/*
 * The thread's TLS block, from the module's template, in a
 * ThreadLocalStoragePointer array of its own if the thread has none (a
 * WOW64 thread's native TEB, a thread started without loader
 * initialization).  Where the loader did it (a native process), nothing.
 */
/* This thread's TLS allocation, where xt_tls_attach made it. */
static __thread void *tls_mine;

void xt_tls_attach(void)
{
    void ***slot = (void ***)((char *)NtCurrentTeb() + TEB_TLS_POINTER);
    size_t len = &_tls_end - &_tls_start;
    size_t arr = (_tls_index + 1) * sizeof(void *);
    char *p;

    if (*slot && (*slot)[_tls_index]) {
        return;
    }
    p = xt_alloc_high(QEMU_ALIGN_UP(arr, 64) + len);
    if (!p) {
        return;
    }
    memcpy(p + QEMU_ALIGN_UP(arr, 64), &_tls_start, len);
    if (*slot) {
        (*slot)[_tls_index] = p + QEMU_ALIGN_UP(arr, 64);
    } else {
        ((void **)p)[_tls_index] = p + QEMU_ALIGN_UP(arr, 64);
        *slot = (void **)p;
    }
    tls_mine = p;
}

/* The TLS allocation xt_tls_attach made for the thread of TEB, if any. */
static void *tls_alloc_of(void *teb)
{
    void **tlsp = *(void ***)((char *)teb + TEB_TLS_POINTER);
    void **own = *(void ***)((char *)NtCurrentTeb() + TEB_TLS_POINTER);
    ptrdiff_t off = (char *)&tls_mine - (char *)own[_tls_index];

    if (!tlsp || !tlsp[_tls_index]) {
        return NULL;
    }
    return *(void **)((char *)tlsp[_tls_index] + off);
}

#endif

/* WOW64's TLS slots, in the 64-bit TEB's TlsSlots (TEB + 0x1480). */
#define TEB_TLS_SLOTS 0x1480
#define WOW64_TLS_CPURESERVED_FLAGS 2   /* bit 0: running guest code */
#define XT_TLS_THREAD 16                /* ours; unused by wow64.dll */

static void **tls_slots(void *teb)
{
    return (void **)((char *)teb + TEB_TLS_SLOTS);
}

static uint64_t read_cntvct(void)
{
    uint64_t v;

    asm volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}

static uint64_t ev_seq;

/*
 * The per-thread event ring: written only by its thread, from any context
 * including the exception handler (no locks, no allocation, no
 * formatting); formatted only at safe points (xt_dump).
 */
void xt_event(XtThread *t, XtEv kind, uint64_t a, uint64_t b)
{
    XtEvent *e = &t->ring[t->ring_pos++ % XT_RING];

    e->seq = qatomic_fetch_inc(&ev_seq);
    e->cnt = read_cntvct();
    e->kind = kind;
    e->state = t->state;
    e->active = t->active;
    e->activation = t->activation;
    e->a = a;
    e->b = b;
    t->counts[kind]++;
}

/* Events of threads without a record (suspenders), lock-free. */
static XtEvent gring[XT_RING];
static unsigned gring_pos;

void xt_gevent(XtEv kind, uint64_t a, uint64_t b)
{
    XtEvent *e = &gring[qatomic_fetch_inc(&gring_pos) % XT_RING];

    e->seq = qatomic_fetch_inc(&ev_seq);
    e->cnt = read_cntvct();
    e->kind = kind;
    e->state = 0;
    e->active = 0;
    e->activation = GetCurrentThreadId();
    e->a = a;
    e->b = b;
}

/*
 * The placement invariant: the module, its runtime, the code buffer and
 * its threads' memory live above 4 GiB, outside the guest's address space.
 * A violation is counted and logged, not fatal.
 */
uint32_t xt_low_placements;

void xt_placement(const char *what, const void *p)
{
    if ((uintptr_t)p <= UINT32_MAX) {
        qatomic_inc(&xt_low_placements);
    }
    xt_gevent(XT_EV_PLACE, (uintptr_t)what, (uintptr_t)p);
}

XtThread *xt_thread_new(bool wow64)
{
    XtThread *t = g_new0(XtThread, 1);

    t->tid = GetCurrentThreadId();
    t->teb = NtCurrentTeb();
    t->wow64 = wow64;
    t->state = XT_WINDOWS;
    if (xt_spare_cpu) {
        t->cpu = qatomic_xchg(&xt_spare_cpu, NULL);
    }
    if (!t->cpu) {
        t->cpu = xt_cpu_new();
    }
    t->env = cpu_env(t->cpu);
    t->cpu->opaque = t;
    /* The thread runs this CPU until its record is freed (tcg_cpu_bound). */
    current_cpu = t->cpu;
    t->heap = xt_heap_current();
    tcg_register_thread();
    xt_self = t;
    if (wow64) {
        tls_slots(t->teb)[XT_TLS_THREAD] = t;
    }
    xt_event(t, XT_EV_THREAD_INIT, t->cpu->cpu_index, (uintptr_t)t->teb);
    xt_placement("thread record", t);
    xt_placement("TLS block", &xt_self);
    return t;
}

/*
 * Records found through a TEB by another thread (BTCpuSuspendLocalThread,
 * which runs on a thread of Windows' own, without a TLS block) are used
 * between xt_record_hold and xt_record_release.  A record is unlinked
 * from its TEB first, and freed only once no user is left: a user that
 * found it before the unlink is still counted.
 */
static int record_users;

void xt_record_hold(void)
{
    qatomic_inc(&record_users);
    /* The count before the record's look-up (pairs with the unlink). */
    smp_mb();
}

void xt_record_release(void)
{
    /* The record's last use before the count drops. */
    smp_mb();
    qatomic_dec(&record_users);
}

static void wait_record_users(void)
{
    /* The unlink before the count is read (pairs with the hold). */
    smp_mb();
    while (qatomic_read(&record_users)) {
        NtYieldExecution();
    }
}

static void unlink_record(XtThread *t)
{
    if (t->wow64) {
        qatomic_set(&tls_slots(t->teb)[XT_TLS_THREAD], NULL);
    }
}

/*
 * The CPU leaves the CPU list and is freed (xt_cpu_free), as in
 * linux-user's exit, with an RCU reader of the calling thread's: in the
 * WOW64 module registered for the duration (a thread Windows owns has
 * none), in the x64 module for the thread's life (xt_rcu_ensure).  The
 * thread T belonged to no longer runs it; its allocator heap goes back,
 * from whatever thread this is (the loader may have freed T's TLS, or T
 * may have been terminated).
 */
static void free_record(XtThread *t)
{
    CPUState *cs = t->cpu;
    void *heap = t->heap;

    xt_log_flush(t);
#ifdef TARGET_X86_64
    xt_rcu_ensure();
    xt_cpu_free(cs);
#else
    rcu_register_thread();
    xt_cpu_free(cs);
    rcu_unregister_thread();
#endif
    g_free(t);
    xt_heap_release(heap);
}

/*
 * What threads leave behind for after they have ended: a TLS block, and
 * for a thread another one terminated, its record.  A thread runs on after
 * its own BTCpuThreadTerm (into ntdll's exit, which may call back here),
 * and a termination can fail after BTCpuThreadTerm, so each is freed only
 * once Windows reports the thread ended (its handle signalled), by the
 * next thread to start or end.
 */
typedef struct XtReap {
    HANDLE thread;
    void *tls;
    XtThread *t;
    struct XtReap *next;
} XtReap;

static XtReap *reap_list;
static int reap_lock;

static void reap_add(HANDLE thread, void *tls, XtThread *t)
{
    XtReap *r = g_new0(XtReap, 1);

    r->thread = thread;
    r->tls = tls;
    r->t = t;
    while (qatomic_xchg(&reap_lock, 1)) {
        NtYieldExecution();
    }
    r->next = reap_list;
    reap_list = r;
    qatomic_store_release(&reap_lock, 0);
}

int xt_reap(void)
{
    LARGE_INTEGER zero = { .QuadPart = 0 };
    XtReap **pp, *dead = NULL, *r;
    int n = 0, nrec = 0;

#ifdef TARGET_X86_64
    xt_emutls_reap();
#endif

    if (!qatomic_read(&reap_list)) {
        return 0;
    }
    while (qatomic_xchg(&reap_lock, 1)) {
        NtYieldExecution();
    }
    for (pp = &reap_list; (r = *pp);) {
        if (NtWaitForSingleObject(r->thread, FALSE, &zero) == STATUS_SUCCESS) {
            *pp = r->next;
            r->next = dead;
            dead = r;
        } else {
            pp = &r->next;
        }
    }
    qatomic_store_release(&reap_lock, 0);
    if (dead) {
        wait_record_users();
    }
    while ((r = dead)) {
        dead = r->next;
        if (r->t) {
            free_record(r->t);
            nrec++;
        }
        if (r->tls) {
            SIZE_T size = 0;
            void *base = r->tls;

            NtFreeVirtualMemory(GetCurrentProcess(), &base, &size,
                                MEM_RELEASE);
        }
        NtClose(r->thread);
        g_free(r);
        n++;
    }
    if (n) {
        xt_gevent(XT_EV_REAP, nrec, n);
    }
    return n;
}

#ifndef TARGET_X86_64
static HANDLE open_thread(DWORD tid)
{
    OBJECT_ATTRIBUTES oa = { .Length = sizeof(oa) };
    CLIENT_ID cid = { .UniqueThread = (HANDLE)(uintptr_t)tid };
    HANDLE h = NULL;

    if (NtOpenThread(&h, SYNCHRONIZE | THREAD_SUSPEND_RESUME |
                     THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                     &oa, &cid) < 0) {
        return NULL;
    }
    return h;
}
#endif

/*
 * A thread's own exit: the record and CPU go now, the TLS block once the
 * thread has ended.  A suspension that found the record first finishes
 * before it is freed.
 */
void xt_thread_free(XtThread *t)
{
#ifndef TARGET_X86_64
    HANDLE self = open_thread(t->tid);
#endif

    xt_event(t, XT_EV_THREAD_TERM, 0, 0);
    unlink_record(t);
    wait_record_users();
    if (xt_self == t) {
        xt_self = NULL;
    }
    free_record(t);
#ifndef TARGET_X86_64
    if (self) {
        reap_add(self, tls_mine, NULL);
    }
#endif
}

/*
 * Another thread's termination, before Windows terminates it: the thread
 * is suspended already, in Windows' hands and holding nothing of the
 * engine's (bring_out).  Its record is
 * unlinked, so later suspensions find none, and freed with its TLS block
 * once the thread has ended.  If the termination fails, the thread stays
 * suspended and the record stays.
 */
/*
 * A thread another one is terminating stops here, where it holds nothing
 * of the engine's and slot 2 bit 0 is clear, until Windows ends it.
 */
void xt_park_if_terminating(XtThread *t)
{
    LARGE_INTEGER tick = { .QuadPart = -100000 };

    while (t && qatomic_read(&t->terminating)) {
        NtDelayExecution(FALSE, &tick);
    }
}

/*
 * Whether Windows will end THREAD for its caller: this thread, or one of
 * this process through a handle with THREAD_TERMINATE.  ThreadTerm and
 * BTCpuThreadTerm run before Windows checks the handle, and a thread whose
 * termination fails must be left as it was.
 */
bool xt_terminates(HANDLE thread)
{
    PUBLIC_OBJECT_BASIC_INFORMATION obi;
    XtThreadBasicInfo tbi;
    HANDLE pid = *(HANDLE *)((char *)NtCurrentTeb() + TEB_CLIENT_ID);

    if (!thread || thread == GetCurrentThread()) {
        return true;
    }
    if (NtQueryObject(thread, ObjectBasicInformation, &obi, sizeof(obi),
                      NULL) < 0 ||
        !(obi.GrantedAccess & THREAD_TERMINATE)) {
        return false;
    }
    return NtQueryInformationThread(thread, 0, &tbi, sizeof(tbi), NULL) >= 0 &&
           tbi.ClientId.UniqueProcess == pid;
}

/* An allocation of a thread's (MEM_RELEASE), freed once the thread ended. */
void xt_reap_later(void *thread_handle, void *alloc)
{
    reap_add(thread_handle, alloc, NULL);
}

void xt_thread_retire(XtThread *t, void *thread_handle)
{
    xt_event(t, XT_EV_THREAD_TERM, 1, 0);
    unlink_record(t);
    reap_add(thread_handle, tls_alloc_of(t->teb), t);
}

/*
 * Every export that can run on any thread starts here: the thread's TLS
 * block (a native thread of wow64.dll's may never have entered the
 * engine) and its TCG context pointer.
 */
void xt_enter(void)
{
    xt_tls_attach();
    if (!tcg_ctx) {
        tcg_register_thread();
    }
}

void xt_set_slot2(XtThread *t, bool running)
{
    uint64_t *f = (uint64_t *)&tls_slots(t->teb)[WOW64_TLS_CPURESERVED_FLAGS];

    if (!t->wow64) {
        return;
    }
    if (running) {
        qatomic_or(f, 1);
    } else {
        qatomic_and(f, ~(uint64_t)1);
    }
}

static bool slot2_running(XtThread *t)
{
    if (!t->wow64) {
        return t->state != XT_WINDOWS;
    }
    return qatomic_read((uint64_t *)
                        &tls_slots(t->teb)[WOW64_TLS_CPURESERVED_FLAGS]) & 1;
}

/*
 * The invariants of each state, checked at every transition.  A failure
 * is an event (and a count); XTAJIT_STRICT makes it fatal at the next
 * safe point.
 */
enum {
    XT_BAD_STATE = 1 << 0,
    XT_BAD_SLOT2 = 1 << 1,
    XT_BAD_MMAP_LOCK = 1 << 2,
    XT_BAD_RETADDR = 1 << 3,
    XT_BAD_ACTIVE = 1 << 4,
    XT_BAD_RCU = 1 << 5,
    XT_BAD_RUNNING = 1 << 6,
    XT_BAD_FAULT = 1 << 7,
};

uint32_t xt_check(XtThread *t, XtState expect, int where)
{
    uint32_t bad = 0;
#ifndef TARGET_X86_64
    bool engine = expect == XT_ACQUIRING || expect == XT_ENGINE ||
                  expect == XT_PUBLISHING;
#endif

    if (t->state != expect) {
        bad |= XT_BAD_STATE;
    }
    if (slot2_running(t) != (expect != XT_WINDOWS)) {
        bad |= XT_BAD_SLOT2;
    }
    if (have_mmap_lock()) {
        bad |= XT_BAD_MMAP_LOCK;
    }
    if (helper_retaddr) {
        bad |= XT_BAD_RETADDR;
    }
    if (t->active != XT_ACT_NONE) {
        bad |= XT_BAD_ACTIVE;
    }
#ifdef TARGET_X86_64
    /*
     * Registered for the thread's life once it first entered: the engine
     * owns it only after that; where Windows owns it, outside any read
     * section.
     */
    {
        struct rcu_reader_data *r = get_ptr_rcu_reader();

        if (expect == XT_ENGINE &&
            (xt_emutls_reader_get() != r || !r->node.le_prev)) {
            bad |= XT_BAD_RCU;
        }
        if (expect == XT_WINDOWS && (r->depth || qatomic_read(&r->ctr))) {
            bad |= XT_BAD_RCU;
        }
    }
#else
    if (t->rcu_registered != engine) {
        bad |= XT_BAD_RCU;
    }
#endif
    if (t->cpu->running) {
        bad |= XT_BAD_RUNNING;
    }
    if (t->fault.busy) {
        bad |= XT_BAD_FAULT;
    }
    if (bad) {
        t->violations++;
        xt_event(t, XT_EV_CHECK, bad, where);
    }
    return bad;
}

/*
 * XTAJIT_INJECT: at the chosen transition, wait (up to 50 ms) for a
 * suspension request, so that a test suspending a thread in a loop lands
 * one there.  Around a suspension exit's publish and the acquire after
 * it, where a test suspending in a loop asks next; publish and notify
 * also on any exit of a thread that has been suspended before, since
 * Windows serializes the suspensions of a thread and a second request
 * never arrives during a suspension's own handshake.  Not on other
 * threads' system calls.  Where Windows owns the thread the suspension is
 * plain and the wait just times out.
 */
void xt_inject(XtThread *t, int point)
{
    uint64_t freq, end;
    bool exit_point = point == XT_INJ_PUBLISH || point == XT_INJ_CALLBACK;

    if (xt_inject_point != point ||
        !(t->after_suspend || (exit_point && t->suspensions))) {
        return;
    }
    asm volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    /* By the counter: a sleep lasts at least a timer tick (15.6 ms). */
    end = read_cntvct() + freq / 20;
    while (!qatomic_read(&t->suspend_req) && read_cntvct() < end) {
        NtYieldExecution();
    }
    xt_event(t, XT_EV_INJECT, point, qatomic_read(&t->suspend_req));
}

/*
 * WINDOWS -> ACQUIRING -> ENGINE.  Slot 2 bit 0 is set before the import,
 * so a suspension from here on takes the cooperative path and waits for
 * this thread's next notification.  The WOW64 module registers the RCU
 * reader here, for as long as the engine owns the thread; the x64 module
 * registers it once, for the thread's life (xt_rcu_ensure).
 * xt_acquire_begin and xt_acquire_end are the two
 * halves, for a caller that imports the state itself in between.
 */
void xt_acquire_begin(XtThread *t)
{
    xt_park_if_terminating(t);
    if (xt_diag) {
        xt_check(t, XT_WINDOWS, 1);
    }
    t->state = XT_ACQUIRING;
    xt_set_slot2(t, true);
#ifdef TARGET_X86_64
    if (!t->rcu_registered) {
        xt_rcu_ensure();
        t->rcu_registered = true;
    }
#else
    rcu_register_thread();
    t->rcu_registered = true;
#endif
    xt_inject(t, XT_INJ_ACQUIRE);
}

void xt_acquire_end(XtThread *t)
{
    t->state = XT_ENGINE;
    if (xt_diag) {
        xt_event(t, XT_EV_ACQUIRE, t->env->eip, t->env->regs[R_ESP]);
        xt_check(t, XT_ENGINE, 2);
    }
}

void xt_acquire(XtThread *t, const XtGuestContext *c)
{
    xt_acquire_begin(t);
    xt_import(t, c);
    xt_acquire_end(t);
}

/*
 * ENGINE -> PUBLISHING -> WINDOWS: the exit's architectural effect is
 * complete; export (into C, unless it is NULL: a caller that takes the
 * state from the CPU itself), then end the RCU reader (the WOW64 module;
 * the x64 module's stays registered, outside any read section), then
 * clear bit 0.
 * The caller notifies (Wow64NotifyUnsimulateComplete) after.
 */
void xt_publish(XtThread *t, XtGuestContext *c)
{
    if (xt_diag) {
        xt_check(t, XT_ENGINE, 3);
    }
    t->state = XT_PUBLISHING;
    if (c) {
        xt_export(t, c);
    }
    xt_inject(t, XT_INJ_PUBLISH);
#ifndef TARGET_X86_64
    rcu_unregister_thread();
    t->rcu_registered = false;
#endif
    t->state = XT_WINDOWS;
    xt_set_slot2(t, false);
    if (xt_diag) {
        xt_check(t, XT_WINDOWS, 4);
    }
}

/*
 * A guest access by the adapter outside cpu_exec (the system-call
 * arguments): a fault comes back here through the continuation
 * (XT_FK_ADAPTER) instead of ending the process.
 */
bool xt_guest_read(XtThread *t, vaddr addr, void *buf, size_t len)
{
    volatile XtActive prev = t->active;

    if (addr > guest_addr_max || len > guest_addr_max - addr + 1) {
        return false;
    }
    if (sigsetjmp(t->adapter_jmp, 0)) {
        t->active = prev;
        return false;
    }
    t->active = XT_ACT_ADAPTER;
    memcpy(buf, (void *)(uintptr_t)addr, len);
    t->active = prev;
    return true;
}

/* Logging: XTAJIT_LOG names a directory; one file per process. */
static HANDLE log_handle;
NTSTATUS xt_log_status = -1;

void *xt_log_handle(void)
{
    return log_handle;
}

void xt_log_open(void)
{
    WCHAR dir[260], path[300];
    SIZE_T n = 0;
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK io;
    char name[64];
    int k;

    xt_log_status = RtlQueryEnvironmentVariable(NULL, L"XTAJIT_LOG", 10, dir,
                                                ARRAY_SIZE(dir) - 1, &n);
    if (xt_log_status < 0 || !n) {
        return;
    }
    snprintf(name, sizeof(name), "\\xtajit-%lu.log", GetCurrentProcessId());
    k = 0;
    for (const char *p = "\\??\\"; *p; p++) {
        path[k++] = *p;
    }
    for (SIZE_T i = 0; i < n && k < (int)ARRAY_SIZE(path) - 64; i++) {
        path[k++] = dir[i];
    }
    for (int i = 0; name[i]; i++) {
        path[k++] = name[i];
    }
    path[k] = 0;
    us.Buffer = path;
    us.Length = k * sizeof(WCHAR);
    us.MaximumLength = us.Length + sizeof(WCHAR);
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    xt_log_status = NtCreateFile(&log_handle, FILE_APPEND_DATA | SYNCHRONIZE,
                                 &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 FILE_OVERWRITE_IF,
                                 FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (xt_log_status < 0) {
        log_handle = NULL;
    } else {
        xt_diag = true;
    }
}

static const char *const ev_names[XT_EV__MAX] = {
    [XT_EV_NONE] = "-",
    [XT_EV_THREAD_INIT] = "thread-init",
    [XT_EV_ACTIVATE] = "activate",
    [XT_EV_ACQUIRE] = "acquire",
    [XT_EV_EXIT] = "exit",
    [XT_EV_PUBLISH] = "publish",
    [XT_EV_NOTIFY] = "notify",
    [XT_EV_SYSCALL] = "syscall",
    [XT_EV_RAISE] = "raise",
    [XT_EV_FAULT] = "fault",
    [XT_EV_RESUME] = "resume",
    [XT_EV_RETRY] = "retry",
    [XT_EV_SMC] = "smc",
    [XT_EV_SUSPEND_SEEN] = "suspend",
    [XT_EV_ATOMIC] = "atomic",
    [XT_EV_INT81] = "int81",
    [XT_EV_CHECK] = "CHECK",
    [XT_EV_INJECT] = "inject",
    [XT_EV_THREAD_TERM] = "thread-term",
    [XT_EV_PLACE] = "place",
    [XT_EV_MEMNOTE] = "memnote",
    [XT_EV_REFRESH] = "refresh",
    [XT_EV_REAP] = "reap",
    [XT_EV_CROSS] = "cross",
};

static void put(HANDLE h, const char *s, int n)
{
    IO_STATUS_BLOCK io;

    if (h) {
        NtWriteFile(h, NULL, NULL, NULL, &io, (void *)s, n, NULL, NULL);
    } else {
        fwrite(s, 1, n, stderr);
    }
}

/* With XTAJIT_LOG, a line of text as it is. */
void xt_log_text(const char *s)
{
    if (log_handle) {
        put(log_handle, s, strlen(s));
    }
}

static void dump_range(HANDLE h, const XtEvent *ring, unsigned start,
                       unsigned pos, const char *who)
{
    char line[200];

    for (unsigned i = start; i < pos; i++) {
        const XtEvent *e = &ring[i % XT_RING];
        int n;

        if (e->kind == XT_EV_PLACE) {
            n = snprintf(line, sizeof(line), "%s %8llu place %s %llx%s\n",
                         who, (unsigned long long)e->seq,
                         (const char *)(uintptr_t)e->a,
                         (unsigned long long)e->b,
                         e->b <= UINT32_MAX ? " BELOW 4 GiB" : "");
            put(h, line, n);
            continue;
        }
        n = snprintf(line, sizeof(line),
                         "%s %8llu %16llx %-11s st%u act%u #%u %llx %llx\n",
                         who, (unsigned long long)e->seq,
                         (unsigned long long)e->cnt,
                         e->kind < XT_EV__MAX ? ev_names[e->kind] : "?",
                         e->state, e->active, e->activation,
                         (unsigned long long)e->a, (unsigned long long)e->b);
        put(h, line, n);
    }
}

/*
 * Format T's ring (and the process ring) to HANDLE, or the log, or
 * stderr.  Only at safe points: never from the exception handler.
 */
static void dump_ring(HANDLE h, const XtEvent *ring, unsigned pos,
                      const char *who)
{
    dump_range(h, ring, pos > XT_RING ? pos - XT_RING : 0, pos, who);
}

/*
 * With XTAJIT_LOG, a thread's new events, at safe points where a later
 * hang or crash would lose them (guest exceptions, thread end).
 */
void xt_log_flush(XtThread *t)
{
    char who[32];

    if (!log_handle || t->ring_pos == t->logged) {
        return;
    }
    snprintf(who, sizeof(who), "t%lu", (unsigned long)t->tid);
    dump_range(log_handle, t->ring, MAX(t->logged, t->ring_pos > XT_RING ?
                                         t->ring_pos - XT_RING : 0),
               t->ring_pos, who);
    t->logged = t->ring_pos;
}

/*
 * With XTAJIT_LOG, a native exception that isn't the engine's, written at
 * once (dispatch may end the process): its code, address, and the pc and
 * lr as offsets into the allocations (modules) holding them.  Diagnostic
 * only: it formats in the exception path.
 */
void xt_log_native(EXCEPTION_RECORD *er, XtNativeContext *ctx)
{
    MEMORY_BASIC_INFORMATION pm, lm;
    char line[200];
    int n;

    if (!log_handle) {
        return;
    }
    if (NtQueryVirtualMemory(GetCurrentProcess(), (void *)ctx->Pc, 0, &pm,
                             sizeof(pm), NULL) < 0) {
        pm.AllocationBase = NULL;
    }
    if (NtQueryVirtualMemory(GetCurrentProcess(), (void *)ctx->Lr, 0, &lm,
                             sizeof(lm), NULL) < 0) {
        lm.AllocationBase = NULL;
    }
    n = snprintf(line, sizeof(line),
                 "native t%lu code %08lx addr %llx info %llx %llx "
                 "pc %llx (%p+%llx) lr %llx (%p+%llx) sp %llx\n",
                 GetCurrentThreadId(), er->ExceptionCode,
                 (unsigned long long)(uintptr_t)er->ExceptionAddress,
                 (unsigned long long)er->ExceptionInformation[0],
                 (unsigned long long)er->ExceptionInformation[1],
                 ctx->Pc, pm.AllocationBase,
                 ctx->Pc - (uintptr_t)pm.AllocationBase, ctx->Lr,
                 lm.AllocationBase, ctx->Lr - (uintptr_t)lm.AllocationBase,
                 ctx->Sp);
    put(log_handle, line, n);
}

void xt_dump(XtThread *t, void *handle)
{
    HANDLE h = handle ? handle : log_handle;
    char who[32], line[400];
    int n;

    if (t) {
        snprintf(who, sizeof(who), "t%lu", (unsigned long)t->tid);
        n = snprintf(line, sizeof(line),
                     "%s: cpu %d, %u activations, %u invariant failures, "
                     "%u events\n", who, t->cpu->cpu_index, t->activation,
                     t->violations, t->ring_pos);
        put(h, line, n);
        dump_ring(h, t->ring, t->ring_pos, who);
    } else {
        dump_ring(h, gring, gring_pos, "g");
    }
}
