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

__thread XtThread *xt_self;
uint32_t xt_inject_point;

NTSTATUS NTAPI NtAllocateVirtualMemoryEx(HANDLE, PVOID *, PSIZE_T, ULONG,
                                         ULONG, MEM_EXTENDED_PARAMETER *,
                                         ULONG);

/* The TEB's ThreadLocalStoragePointer (TEB + 0x58). */
#define TEB_TLS_POINTER 0x58

extern char _tls_start, _tls_end;
extern uint64_t _tls_index;

/*
 * Memory above 4 GiB, outside the guest's address space, whatever the
 * process: Windows takes a missing upper bound in a WOW64 process to be
 * the 32-bit space's, so both bounds are given.
 */
typedef struct XtBasicInfo {
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} XtBasicInfo;

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
}

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
 * A thread's own exit: its CPU leaves the CPU list and is freed, as
 * linux-user's exit does, with an RCU reader for the duration (the thread
 * is in Windows' hands, so it has none otherwise).  The record goes too;
 * another thread suspending this one concurrently is not handled yet.
 */
void xt_thread_free(XtThread *t)
{
    CPUState *cs = t->cpu;

    xt_event(t, XT_EV_THREAD_TERM, 0, 0);
    xt_log_flush(t);
    if (t->wow64) {
        tls_slots(t->teb)[XT_TLS_THREAD] = NULL;
    }
    rcu_register_thread();
    object_unparent(OBJECT(cs));
    object_unref(OBJECT(cs));
    rcu_unregister_thread();
    if (xt_self == t) {
        xt_self = NULL;
    }
    g_free(t);
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
    bool engine = expect == XT_ACQUIRING || expect == XT_ENGINE ||
                  expect == XT_PUBLISHING;

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
    if (t->rcu_registered != engine) {
        bad |= XT_BAD_RCU;
    }
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
 * The WOW64 context and CPUX86State.  The import honours ContextFlags:
 * the floating-point state comes from ExtendedRegisters (FXSAVE format,
 * x87 tags, TOP, status, MXCSR and XMM) when present, else from FloatSave
 * (FSAVE format).  The export writes both.  Debug registers are not
 * carried: DR0-DR7 stay as set in the WOW64 context and no hardware
 * breakpoint fires; a single-step trap reports DR6.BS, as x86 does.
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
    if (env->dr[6] & DR6_BS) {
        c->ContextFlags |= WOW64_CONTEXT_DEBUG_REGISTERS;
        c->Dr6 = 0xffff0ff0 | DR6_BS;
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
 * this thread's next notification; the RCU reader exists only while the
 * engine owns the thread.
 */
void xt_acquire(XtThread *t, const WOW64_CONTEXT *c)
{
    xt_check(t, XT_WINDOWS, 1);
    t->state = XT_ACQUIRING;
    xt_set_slot2(t, true);
    rcu_register_thread();
    t->rcu_registered = true;
    xt_inject(t, XT_INJ_ACQUIRE);
    xt_import(t, c);
    t->state = XT_ENGINE;
    xt_event(t, XT_EV_ACQUIRE, t->env->eip, t->env->regs[R_ESP]);
    xt_check(t, XT_ENGINE, 2);
}

/*
 * ENGINE -> PUBLISHING -> WINDOWS: the exit's architectural effect is
 * complete; export, then end the RCU reader, then clear bit 0.  The caller
 * notifies (Wow64NotifyUnsimulateComplete) after.
 */
void xt_publish(XtThread *t, WOW64_CONTEXT *c)
{
    xt_check(t, XT_ENGINE, 3);
    t->state = XT_PUBLISHING;
    xt_export(t, c);
    xt_inject(t, XT_INJ_PUBLISH);
    rcu_unregister_thread();
    t->rcu_registered = false;
    t->state = XT_WINDOWS;
    xt_set_slot2(t, false);
    xt_check(t, XT_WINDOWS, 4);
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

    if (RtlQueryEnvironmentVariable(NULL, L"XTAJIT_LOG", 10, dir,
                                    ARRAY_SIZE(dir) - 1, &n) < 0 || !n) {
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
    if (NtCreateFile(&log_handle, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &io,
                     NULL, FILE_ATTRIBUTE_NORMAL,
                     FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OVERWRITE_IF,
                     FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0) < 0) {
        log_handle = NULL;
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
