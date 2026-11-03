/*
 * xtajit: the x64 CPU module's interface, as ntdll calls it in an x64
 * process on Windows on Arm, whose native code is ARM64EC.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/rcu.h"
#include "hw/core/cpu.h"
#include "cpu.h"
#include "tcg/tcg.h"
#include "exec/mmap-lock.h"
#include "accel/tcg/tb-context.h"
#include "exec/page-protection.h"
#include "user/page-protection.h"
#include "xtajit.h"
#include "arm64ec.h"

NTSTATUS NTAPI NtContinue(PCONTEXT, BOOLEAN);
PVOID NTAPI RtlAddVectoredExceptionHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
PVOID NTAPI RtlImageDirectoryEntryToData(PVOID, BOOLEAN, USHORT, PULONG);
NTSTATUS NTAPI RtlQueryEnvironmentVariable(PVOID, PCWSTR, SIZE_T, PWSTR,
                                           SIZE_T, PSIZE_T);

extern IMAGE_DOS_HEADER __ImageBase;

#ifndef XT_SCAFFOLD
#define XT_SCAFFOLD "one-insn-per-tb=on"
#endif

/*
 * System calls the module makes directly, with svc: ntdll's exports in an
 * ARM64EC process take x64 contexts (NtContinue, NtRaiseException), whose
 * conversion loses the registers the ARM64EC ABI forbids, and they may be
 * hot-patched x64 code.  The numbers vary between Windows builds and are
 * found at process init (find_syscall_nr).  arm64ec.S: a table of 512
 * "svc #n; ret".
 */
#define XT_SVC_TABLE_ENTRIES 512
NTSTATUS xt_syscall(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                    uint64_t a4, uint64_t a5, uint64_t nr);

static int64_t nr_continue = -1, nr_raise = -1, nr_alloc = -1,
               nr_protect = -1;

/* ntdll's native KiUserExceptionDispatcher, for the guest's system calls. */
static uintptr_t ki_exception_dispatcher;

/* An x64 ret instruction, for native callees on an unaligned stack. */
uintptr_t xt_x64_ret;

/* For the call checker (arm64ec.S): ntdll's x64 entries to native code. */
uintptr_t xt_ntdll_base;
uint32_t *xt_ntdll_lut;
uint32_t xt_ntdll_lut_size;

static const XtEcMetadata *ec_metadata(uintptr_t base)
{
    ULONG size;
    IMAGE_LOAD_CONFIG_DIRECTORY64 *lc =
        RtlImageDirectoryEntryToData((void *)base, TRUE,
                                     IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &size);

    if (!lc || size < offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64,
                               CHPEMetadataPointer) + 8 ||
        !lc->CHPEMetadataPointer) {
        return NULL;
    }
    return (const XtEcMetadata *)(uintptr_t)lc->CHPEMetadataPointer;
}

/* The native code behind one of ntdll's x64 exports, else 0. */
static uintptr_t ntdll_native(const XtEcMetadata *md, const char *name)
{
    const XtEcRedirection *r =
        (const XtEcRedirection *)(xt_ntdll_base + md->RedirectionMetadata);
    uintptr_t ffs = (uintptr_t)GetProcAddress((HMODULE)xt_ntdll_base, name);

    if (!ffs) {
        return 0;
    }
    for (ULONG i = 0; i < md->RedirectionMetadataCount; i++) {
        if (r[i].Source == ffs - xt_ntdll_base) {
            return xt_ntdll_base + r[i].Destination;
        }
    }
    return 0;
}

/*
 * A system call's number: the index of its native code in ntdll's
 * __arm64ec_syscall_ffs table (as FEX's ARM64EC module finds it), if
 * within the svc table.
 */
static int64_t find_syscall_nr(const XtEcMetadata *md, const char *name)
{
    const uintptr_t *ffs = (const uintptr_t *)GetProcAddress(
        (HMODULE)xt_ntdll_base, "__arm64ec_syscall_ffs");
    const uint32_t *count = (const uint32_t *)GetProcAddress(
        (HMODULE)xt_ntdll_base, "__arm64ec_syscall_ffs_size");
    uintptr_t native = ntdll_native(md, name);

    if (!ffs || !count || !native) {
        return -1;
    }
    for (uint32_t i = 0; i < *count && i < XT_SVC_TABLE_ENTRIES; i++) {
        if (ffs[i] == native) {
            return i;
        }
    }
    return -1;
}

NTSTATUS xt_continue_native(XtNativeContext *ctx)
{
    return xt_syscall((uintptr_t)ctx, FALSE, 0, 0, 0, 0, nr_continue);
}

static NTSTATUS alloc_direct(void **base, SIZE_T *size, ULONG type, ULONG prot)
{
    return xt_syscall((uintptr_t)GetCurrentProcess(), (uintptr_t)base, 0,
                      (uintptr_t)size, type, prot, nr_alloc);
}

static NTSTATUS protect_direct(void **base, SIZE_T *size, ULONG prot,
                               ULONG *old)
{
    return xt_syscall((uintptr_t)GetCurrentProcess(), (uintptr_t)base,
                      (uintptr_t)size, prot, (uintptr_t)old, 0, nr_protect);
}

/* Write a pointer into this module's ARM64EC metadata (its checker slots). */
static void write_module_slot(ULONG rva, void *value)
{
    void *addr = (char *)&__ImageBase + rva, *p = addr;
    SIZE_T size = sizeof(void *);
    ULONG old;

    if (!rva) {
        return;
    }
    protect_direct(&p, &size, PAGE_READWRITE, &old);
    *(void **)addr = value;
    protect_direct(&p, &size, old, &old);
}

/*
 * The module's own calls go through the ARM64EC call checker, which
 * enters the x64 emulator for x64 code: a hot-patched ntdll export would
 * re-enter this module.  The replacement (xt_check_call) maps ntdll's x64
 * entries to their native code, through a table from ntdll's redirection
 * metadata, and calls anything else as it is.  First of all at process
 * init, before the runtime.
 */
static bool init_syscalls(void)
{
    const XtEcMetadata *md, *own;
    const XtEcRedirection *r;
    SIZE_T size;

    if (xt_ntdll_lut) {
        return true;
    }
    xt_ntdll_base = (uintptr_t)GetModuleHandleW(L"ntdll.dll");
    md = xt_ntdll_base ? ec_metadata(xt_ntdll_base) : NULL;
    own = ec_metadata((uintptr_t)&__ImageBase);
    if (!md || !own || !md->RedirectionMetadataCount) {
        return false;
    }
    nr_continue = find_syscall_nr(md, "NtContinue");
    nr_raise = find_syscall_nr(md, "NtRaiseException");
    nr_alloc = find_syscall_nr(md, "NtAllocateVirtualMemory");
    nr_protect = find_syscall_nr(md, "NtProtectVirtualMemory");
    ki_exception_dispatcher = ntdll_native(md, "KiUserExceptionDispatcher");
    if (nr_continue < 0 || nr_raise < 0 || nr_alloc < 0 || nr_protect < 0 ||
        !ki_exception_dispatcher) {
        return false;
    }

    r = (const XtEcRedirection *)(xt_ntdll_base + md->RedirectionMetadata);
    for (ULONG i = 0; i < md->RedirectionMetadataCount; i++) {
        xt_ntdll_lut_size = MAX(xt_ntdll_lut_size, r[i].Source + 1);
    }
    size = xt_ntdll_lut_size * sizeof(uint32_t);
    if (alloc_direct((void **)&xt_ntdll_lut, &size, MEM_COMMIT | MEM_RESERVE,
                     PAGE_READWRITE) < 0) {
        return false;
    }
    for (ULONG i = 0; i < md->RedirectionMetadataCount; i++) {
        xt_ntdll_lut[r[i].Source] = r[i].Destination;
    }
    write_module_slot(own->os_arm64x_dispatch_call, xt_check_call);
    write_module_slot(own->os_arm64x_dispatch_icall, xt_check_call);
    write_module_slot(own->os_arm64x_dispatch_icall_cfg, xt_check_call);
    return true;
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
    return g_string_free(s, false);
}

static int init_applied, init_rejected;

static void ec_register(XtThread *t);
static unsigned __stdcall doorbell_watcher(void *arg);

/*
 * The engine's process-wide bring-up.  It needs the module's thread-local
 * variables (QEMU's, the allocator's), which in an x64 process the loader
 * sets up for this module after ProcessInit and the first thread's
 * ThreadInit: so it runs at a thread's first entry (enter_engine), or in
 * the harness's own init.
 */
static int process_init(void)
{
    char *settings;

    xt_tls_attach();
    xt_crt_process_init();
    settings = settings_string();
    xt_log_open();
    xt_engine_init(settings, &init_applied, &init_rejected);
    /* Readers exist only while the engine owns a thread (xt_acquire). */
    rcu_unregister_thread();
    xt_gevent(XT_EV_THREAD_INIT, init_applied, init_rejected);
    xt_placement("module", &__ImageBase);
    xt_placement("code buffer", tcg_ctx->code_gen_buffer);
    if (!_beginthreadex(NULL, 0, doorbell_watcher, NULL, 0, NULL)) {
        return -1;
    }
    return 0;
}

static int engine_state;    /* 0 none, 1 starting, 2 ready, -1 failed */

/*
 * The engine, once per process, and the calling thread's record, once
 * per thread: at a thread's first entry, when the loader has set up the
 * module's TLS.  Another thread's first entry waits for the bring-up.
 */
static XtThread *enter_engine(void)
{
    XtCpuArea *area = xt_cpu_area(NtCurrentTeb());
    XtThread *t;

    if (qatomic_read(&engine_state) != 2) {
        if (qatomic_cmpxchg(&engine_state, 0, 1) == 0) {
            qatomic_store_release(&engine_state,
                                  process_init() < 0 ? -1 : 2);
        }
        while (qatomic_load_acquire(&engine_state) == 1) {
            NtYieldExecution();
        }
        if (qatomic_read(&engine_state) < 0) {
            return NULL;
        }
    }
    t = xt_self;
    if (!t) {
        t = xt_thread_new(false);
        t->cpu->opaque = t;
        t->ec_doorbell = area->SuspendDoorbell;
        area->EmulatorData[0] = t;
        ec_register(t);
    }
    return t;
}

/*
 * ntdll's calls.  ProcessInit and ThreadInit do what needs no thread-local
 * variables (enter_engine does the rest, at a thread's first entry).
 * The entries are in arm64ec.S (DispatchJump, RetToEntryThunk, ExitToX64,
 * BeginSimulation), and xt_ec_enter and xt_ec_begin below; REACHED
 * records which of ProcessInit and ThreadInit ran, for the harness.
 */
static uint32_t reached;

XTEXPORT NTSTATUS ProcessInit(void)
{
    reached |= 0x40;
    if (!init_syscalls()) {
        return STATUS_NOT_SUPPORTED;
    }
    {
        void *p = NULL;
        SIZE_T size = 0x1000;
        ULONG old;

        if (alloc_direct(&p, &size, MEM_RESERVE | MEM_COMMIT,
                         PAGE_READWRITE) < 0) {
            return STATUS_NO_MEMORY;
        }
        *(uint8_t *)p = 0xc3;
        protect_direct(&p, &size, PAGE_EXECUTE_READ, &old);
        xt_x64_ret = (uintptr_t)p;
    }
    reached |= 0x80;
    xt_ec_probe_process_init();
    return STATUS_SUCCESS;
}

XTEXPORT void ProcessTerm(HANDLE h, BOOL after, NTSTATUS status)
{
}

#define XT_EMULATOR_STACK (256 * 1024)
#define XT_EC_THREAD_PAGE 0x1000

/*
 * A thread's emulator stack, above a page of its own (XtEcFrame): the
 * doorbell word Windows sets to ask a simulating thread to stop
 * (SuspendDoorbell), and the native registers of an entry or exit.
 */
XTEXPORT NTSTATUS ThreadInit(void)
{
    XtCpuArea *area = xt_cpu_area(NtCurrentTeb());
    PVOID mem = NULL;
    SIZE_T size = XT_EC_THREAD_PAGE + XT_EMULATOR_STACK;
    uintptr_t stack;

    reached |= 0x100;
    if (!area || alloc_direct(&mem, &size, MEM_RESERVE | MEM_COMMIT,
                              PAGE_READWRITE) < 0) {
        return STATUS_NO_MEMORY;
    }
    stack = (uintptr_t)mem + XT_EC_THREAD_PAGE;
    area->SuspendDoorbell = &((XtEcFrame *)mem)->doorbell;
    area->EmulatorStackLimit = stack;
    area->EmulatorStackBase = stack + XT_EMULATOR_STACK;
    area->EmulatorData[0] = NULL;
    area->EmulatorData[1] = mem;
    return STATUS_SUCCESS;
}

XTEXPORT NTSTATUS ThreadTerm(HANDLE thread, LONG code)
{
    return STATUS_SUCCESS;
}

/*
 * ntdll's call at any exception in an ARM64EC thread, before its
 * dispatch, with the full native context (x13, x14, x23, x24, x28 and
 * v16-v31 included).  Continued here, with that context:
 * - the doorbell found set at an exit to native code (arm64ec.S): the
 *   exit stub is consistent there, so continuing it completes the
 *   suspension;
 * - a fault the engine recovers (xt_fault_redirect: generated code,
 *   helpers, translation), while it owns the thread.
 * Anything else goes on to the dispatch.
 */
XTEXPORT NTSTATUS ResetToConsistentState(EXCEPTION_RECORD *er, CONTEXT *guest,
                                         ARM64_NT_CONTEXT *native)
{
    XtCpuArea *area = xt_cpu_area(NtCurrentTeb());
    XtThread *t = area ? area->EmulatorData[0] : NULL;

    if (xt_ec_probe_rtcs(er, guest, native)) {
        xt_continue_native(native);
    }
    if (native->Pc == (uintptr_t)xt_ec_exit_suspend_point) {
        qatomic_set(area->SuspendDoorbell, 0);
        native->Pc = (uintptr_t)xt_ec_exit_resume_point;
        xt_continue_native(native);
    }
    if (t && t == xt_self && t->state != XT_WINDOWS) {
        bool prev = area->InSyscallCallback;
        bool handled;

        area->InSyscallCallback = 1;
        handled = xt_fault_redirect(er, native);
        area->InSyscallCallback = prev;
        if (handled) {
            xt_continue_native(native);
        }
    }
    return STATUS_SUCCESS;
}

XTEXPORT void NotifyMemoryAlloc(void *addr, SIZE_T len, ULONG type, ULONG prot,
                                BOOL after, NTSTATUS status)
{
}

XTEXPORT void NotifyMemoryFree(void *addr, SIZE_T len, ULONG type, BOOL after,
                               NTSTATUS status)
{
}

XTEXPORT void NotifyMemoryProtect(void *addr, SIZE_T len, ULONG prot,
                                  BOOL after, NTSTATUS status)
{
}

XTEXPORT NTSTATUS NotifyMapViewOfSection(void *unk1, void *addr, void *unk2,
                                         SIZE_T len, ULONG type, ULONG prot)
{
    return STATUS_SUCCESS;
}

XTEXPORT void NotifyUnmapViewOfSection(void *addr, BOOL after, NTSTATUS status)
{
}

XTEXPORT void FlushInstructionCacheHeavy(const void *addr, SIZE_T len)
{
}

XTEXPORT void BTCpu64FlushInstructionCache(const void *addr, SIZE_T len)
{
}

XTEXPORT void BTCpu64NotifyMemoryDirty(void *addr, SIZE_T len)
{
}

XTEXPORT void BTCpu64NotifyReadFile(HANDLE h, void *addr, SIZE_T len,
                                    BOOL after, NTSTATUS status)
{
}

XTEXPORT BOOLEAN BTCpu64IsProcessorFeaturePresent(UINT feature)
{
    return FALSE;
}

XTEXPORT void UpdateProcessorInformation(void *info)
{
}

NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);

/*
 * The doorbell: Windows rings it to stop a thread that is simulating or
 * on its emulator stack, and waits (up to about 10 s) until the thread is
 * consistent: off that stack, InSimulation clear, its guest state in its
 * native context.  Generated code doesn't look at the word; this thread
 * does, and asks the engine to stop (cpu_exit), which then leaves with
 * the guest's context (leave_suspend).
 */
#define XT_EC_MAX_THREADS 4096
static XtThread *ec_threads[XT_EC_MAX_THREADS];
static int ec_nthreads;

static unsigned __stdcall doorbell_watcher(void *arg)
{
    LARGE_INTEGER tick = { .QuadPart = -10000 };

    for (;;) {
        int n = MIN(qatomic_read(&ec_nthreads), XT_EC_MAX_THREADS);

        NtDelayExecution(FALSE, &tick);
        xt_record_hold();
        for (int i = 0; i < n; i++) {
            XtThread *t = qatomic_read(&ec_threads[i]);

            if (t && qatomic_read(&t->state) == XT_ENGINE &&
                qatomic_read(t->ec_doorbell) &&
                !qatomic_read(&t->suspend_req)) {
                qatomic_set(&t->suspend_req, 1);
                cpu_exit(t->cpu);
            }
        }
        xt_record_release();
    }
    return 0;
}

static void ec_register(XtThread *t)
{
    int i = qatomic_fetch_inc(&ec_nthreads);

    if (i < XT_EC_MAX_THREADS) {
        qatomic_set(&ec_threads[i], t);
    }
}

/*
 * The guest's system call (syscall, int 0x2e): ntdll's native
 * KiUserExceptionDispatcher performs it from the packed context, with
 * STATUS_EMULATION_SYSCALL, then continues at RIP, which is past the
 * instruction already.  The frame is its stack, as an exception's.
 */
typedef struct QEMU_ALIGNED(16) XtKiFrame {
    ARM64_NT_CONTEXT ctx;
    uint64_t pad[4];
    EXCEPTION_RECORD rec;
    uint64_t align;
    uint64_t redzone[2];
} XtKiFrame;

#ifndef STATUS_EMULATION_SYSCALL
#define STATUS_EMULATION_SYSCALL ((NTSTATUS)0x40000039)
#endif

/*
 * The end of an activation: the engine gives the thread back (publish),
 * the guest state goes into the packed context, and EFLAGS it can't carry
 * are kept for the re-entry that continues it.
 */
static void leave(XtThread *t, ARM64_NT_CONTEXT *n)
{
    XtGuestContext c;

    memset(&c, 0, sizeof(c));
    xt_publish(t, &c);
    xt_ec_pack(t, n);
    t->aux_valid = true;
    t->aux_rip = n->Pc;
    t->aux_rsp = n->Sp;
    t->aux_eflags = cpu_compute_eflags(t->env);
    xt_log_flush(t);
}

static G_NORETURN void leave_native(XtThread *t, XtEcFrame *f,
                                       vaddr target)
{
    leave(t, &f->ctx);
    t->aux_valid = false;
    f->ctx.Pc = target;
    xt_ec_exit_native(&f->ctx);
}

static G_NORETURN void leave_syscall(XtThread *t)
{
    XtKiFrame k;

    memset(&k.rec, 0, sizeof(k.rec));
    leave(t, &k.ctx);
    k.rec.ExceptionCode = STATUS_EMULATION_SYSCALL;
    xt_cpu_area(NtCurrentTeb())->InSimulation = 0;
    xt_ec_jump_set_stack(ki_exception_dispatcher, (uintptr_t)&k);
}

/*
 * A guest exception, raised with the packed context as x64 Windows
 * reports it: a breakpoint at the int3, a fast fail second chance.
 */
static G_NORETURN void leave_exception(XtThread *t, XtExit *x)
{
    EXCEPTION_RECORD *r = &x->rec;
    ARM64_NT_CONTEXT n;
    BOOLEAN first = TRUE;

    switch (x->vector) {
    case -1:
        break;
    case EXCP03_INT3:
    case 0x2d:
        t->env->eip -= x->vector == EXCP03_INT3 ? 1 : 0;
        r->ExceptionCode = STATUS_BREAKPOINT;
        r->NumberParameters = 1;
        break;
    case 0x29:
        r->ExceptionCode = STATUS_STACK_BUFFER_OVERRUN;
        r->ExceptionFlags = EXCEPTION_NONCONTINUABLE;
        r->NumberParameters = 1;
        r->ExceptionInformation[0] = t->env->regs[R_ECX];
        first = FALSE;
        break;
    case 0x2c:
        r->ExceptionCode = STATUS_ASSERTION_FAILURE;
        break;
    default:
        r->ExceptionCode = STATUS_ACCESS_VIOLATION;
        r->NumberParameters = 2;
        r->ExceptionInformation[1] = ~0ull;
        break;
    }
    if (r->ExceptionCode == STATUS_WX86_SINGLE_STEP) {
        r->ExceptionCode = STATUS_SINGLE_STEP;
    }
    r->ExceptionAddress = (void *)(uintptr_t)t->env->eip;
    leave(t, &n);
    xt_cpu_area(NtCurrentTeb())->InSimulation = 0;
    xt_syscall((uintptr_t)r, (uintptr_t)&n, first, 0, 0, 0, nr_raise);
    NtTerminateProcess(GetCurrentProcess(), STATUS_ASSERTION_FAILURE);
    __builtin_unreachable();
}

/*
 * A suspension: continue at the guest's own context, consistent, where
 * Windows completes the suspension; resuming re-enters through
 * BeginSimulation.
 */
static G_NORETURN void leave_suspend(XtThread *t, XtEcFrame *f)
{
    ARM64_NT_CONTEXT n;

    leave(t, &n);
    qatomic_set(&f->doorbell, 0);
    xt_cpu_area(NtCurrentTeb())->InSimulation = 0;
    xt_continue_native(&n);
    NtTerminateProcess(GetCurrentProcess(), STATUS_ASSERTION_FAILURE);
    __builtin_unreachable();
}

static G_NORETURN void ec_run(XtThread *t, XtEcFrame *f)
{
    XtExit x;

    for (;;) {
        xt_run(t, &x);
        switch (x.kind) {
        case XT_EXIT_NATIVE:
            leave_native(t, f, x.target);
        case XT_EXIT_SYSCALL:
            xt_event(t, XT_EV_SYSCALL, x.nr, 0);
            leave_syscall(t);
        case XT_EXIT_SUSPEND:
            leave_suspend(t, f);
        default:
            leave_exception(t, &x);
        }
    }
}

static XtThread *ec_thread(void)
{
    XtThread *t = enter_engine();

    if (!t) {
        NtTerminateProcess(GetCurrentProcess(),
                           !xt_log_handle() && xt_log_status < 0 ?
                           xt_log_status : STATUS_NOT_SUPPORTED);
    }
    t->activation++;
    return t;
}

/*
 * A call, jump or return into x64 code (ExitToX64, DispatchJump,
 * RetToEntryThunk in arm64ec.S): the x64 registers are in their ARM64EC
 * places in F, the return address on the stack already.
 */
void xt_ec_enter(XtEcFrame *f)
{
    XtThread *t = ec_thread();
    CONTEXT c;

    t->aux_valid = false;
    xt_ec_call_context(t, &f->ctx, &c);
    xt_acquire(t, &c);
    ec_run(t, f);
}

/*
 * KiUserEmulationDispatcher's entry, after a continuation at x64 code:
 * the CPU area's AMD64 context is authoritative, with what the packed
 * form couldn't carry from the exit it continues (the same RIP, RSP and
 * NZCV).  The x87 state and MXCSR stay the engine's.
 */
void xt_ec_begin(void)
{
    XtCpuArea *area = xt_cpu_area(NtCurrentTeb());
    XtThread *t = ec_thread();
    const CONTEXT *w = (const CONTEXT *)area->ContextAmd64;
    const uint32_t nzcv = CC_S | CC_Z | CC_C | CC_O | TF_MASK;
    CONTEXT c;

    memset(&c, 0, sizeof(c));
    xt_export(t, &c);
    if ((w->ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER) {
        memcpy(&c.Rax, &w->Rax, 16 * sizeof(c.Rax));
    }
    if ((w->ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL) {
        c.Rip = w->Rip;
        c.Rsp = w->Rsp;
        c.Rbp = w->Rbp;
        c.SegCs = w->SegCs;
        c.SegSs = w->SegSs;
        c.EFlags = w->EFlags;
        if (t->aux_valid && w->Rip == t->aux_rip && w->Rsp == t->aux_rsp &&
            (w->EFlags & nzcv) == (t->aux_eflags & nzcv)) {
            c.EFlags = (t->aux_eflags & ~nzcv) | (w->EFlags & nzcv);
        }
    }
    if ((w->ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS) {
        c.SegDs = w->SegDs;
        c.SegEs = w->SegEs;
        c.SegFs = w->SegFs;
        c.SegGs = w->SegGs;
    }
    if ((w->ContextFlags & CONTEXT_FLOATING_POINT) ==
        CONTEXT_FLOATING_POINT) {
        memcpy(c.FltSave.XmmRegisters, w->FltSave.XmmRegisters,
               sizeof(c.FltSave.XmmRegisters));
    }
    t->aux_valid = false;
    c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS |
                     CONTEXT_FLOATING_POINT;
    if ((w->ContextFlags & CONTEXT_DEBUG_REGISTERS) ==
        CONTEXT_DEBUG_REGISTERS) {
        c.ContextFlags |= CONTEXT_DEBUG_REGISTERS;
        c.Dr0 = w->Dr0;
        c.Dr1 = w->Dr1;
        c.Dr2 = w->Dr2;
        c.Dr3 = w->Dr3;
        c.Dr7 = w->Dr7;
    }
    area->InSimulation = 1;
    xt_acquire(t, &c);
    ec_run(t, (XtEcFrame *)area->EmulatorData[1]);
}

/*
 * The test harness: an ARM64EC process loads the module and drives one
 * engine thread per calling thread with contexts it passes, as P1's
 * native harness does.  Faults reach a vectored handler with the x64 view
 * of the native context (ARM64EC_NT_CONTEXT), which has no x13, x14, x23,
 * x24, x28 or v16-v31.  That is enough for a fault in a helper, which is
 * ARM64EC code, below generated code that keeps nothing in those across
 * the call; a retried fault in generated code needs the module's own
 * entry (ResetToConsistentState), which sees the full native context.
 */
struct XtEcTestExit {
    int kind;
    int trapnr;
    uint32_t code;
    uint64_t addr, info0, info1;
};

static void from_ec_view(const ARM64EC_NT_CONTEXT *ec, ARM64_NT_CONTEXT *n)
{
    uint32_t f = ec->AMD64_EFlags;

    memset(n, 0, sizeof(*n));
    n->ContextFlags = CONTEXT_ARM64_FULL;
    n->X0 = ec->X0;
    n->X1 = ec->X1;
    n->X2 = ec->X2;
    n->X3 = ec->X3;
    n->X4 = ec->X4;
    n->X5 = ec->X5;
    n->X6 = ec->X6;
    n->X7 = ec->X7;
    n->X8 = ec->X8;
    n->X9 = ec->X9;
    n->X10 = ec->X10;
    n->X11 = ec->X11;
    n->X12 = ec->X12;
    n->X15 = ec->X15;
    n->X16 = (uint64_t)ec->X16_3 << 48 | (uint64_t)ec->X16_2 << 32 |
             (uint64_t)ec->X16_1 << 16 | ec->X16_0;
    n->X17 = (uint64_t)ec->X17_3 << 48 | (uint64_t)ec->X17_2 << 32 |
             (uint64_t)ec->X17_1 << 16 | ec->X17_0;
    n->X19 = ec->X19;
    n->X20 = ec->X20;
    n->X21 = ec->X21;
    n->X22 = ec->X22;
    n->X25 = ec->X25;
    n->X26 = ec->X26;
    n->X27 = ec->X27;
    n->Fp = ec->Fp;
    n->Lr = ec->Lr;
    n->Sp = ec->Sp;
    n->Pc = ec->Pc;
    /* NZCV from SF, ZF, CF and OF, as Windows maps them. */
    n->Cpsr = (f & 0x80 ? 1u << 31 : 0) | (f & 0x40 ? 1u << 30 : 0) |
              (f & 0x01 ? 1u << 29 : 0) | (f & 0x800 ? 1u << 28 : 0);
    memcpy(n->V, ec->V, sizeof(ec->V));
    {
        uint64_t fpcr, fpsr;

        asm volatile("mrs %0, fpcr" : "=r"(fpcr));
        asm volatile("mrs %0, fpsr" : "=r"(fpsr));
        n->Fpcr = fpcr;
        n->Fpsr = fpsr;
    }
}

static LONG CALLBACK xt_ec_veh(EXCEPTION_POINTERS *p)
{
    ARM64EC_NT_CONTEXT *ec = (ARM64EC_NT_CONTEXT *)p->ContextRecord;
    ARM64_NT_CONTEXT n;

    from_ec_view(ec, &n);
    if (!xt_fault_redirect(p->ExceptionRecord, &n)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    /* The continuation's entry: what xt_fault_redirect changed. */
    ec->X0 = n.X0;
    ec->X1 = n.X1;
    ec->Lr = n.Lr;
    ec->Sp = n.Sp;
    ec->Pc = n.Pc;
    NtContinue(p->ContextRecord, FALSE);
    return EXCEPTION_CONTINUE_SEARCH;
}

XTEXPORT int xt_ec_test_init(int *rejected)
{
    if (!init_syscalls() || process_init() < 0) {
        return -1;
    }
    qatomic_set(&engine_state, 2);
    RtlAddVectoredExceptionHandler(1, xt_ec_veh);
    *rejected = init_rejected;
    return init_applied;
}

XTEXPORT void *xt_ec_test_thread(void)
{
    XtThread *t = xt_self ? xt_self : xt_thread_new(false);

    t->stop_at_int3 = true;
    t->cpu->opaque = t;
    return t;
}

XTEXPORT int xt_ec_test_run(CONTEXT *ctx, XtEcTestExit *out)
{
    XtThread *t = xt_self;
    XtExit x;

    t->activation++;
    xt_acquire(t, ctx);
    xt_run(t, &x);
    xt_publish(t, ctx);
    memset(out, 0, sizeof(*out));
    out->kind = x.kind;
    out->trapnr = x.trapnr;
    if (x.kind == XT_EXIT_EXCEPTION) {
        out->code = x.rec.ExceptionCode;
        out->addr = (uintptr_t)x.rec.ExceptionAddress;
        out->info0 = x.rec.ExceptionInformation[0];
        out->info1 = x.rec.ExceptionInformation[1];
    }
    return x.kind;
}

/* TCG's code buffer: Windows must count it as EC code. */
XTEXPORT void *xt_ec_test_code_buffer(void)
{
    return tcg_ctx->code_gen_buffer;
}

/*
 * Write code for the harness: QEMU's write protection of translated pages
 * comes off first (page_unprotect, as for a guest write, which also drops
 * their translations).
 */
XTEXPORT void xt_ec_test_load(void *dst, const void *src, size_t len)
{
    uintptr_t p = (uintptr_t)dst & TARGET_PAGE_MASK;

    mmap_lock();
    for (; p < (uintptr_t)dst + len; p += TARGET_PAGE_SIZE) {
        if (page_get_flags(p) & PAGE_WRITE_ORG) {
            page_unprotect(NULL, p, 0);
        }
    }
    memcpy(dst, src, len);
    mmap_unlock();
    xt_invalidate((uintptr_t)dst, len);
}

/* Drop translations of a range the harness rewrote. */
XTEXPORT void xt_ec_test_invalidate(void *addr, size_t len)
{
    xt_invalidate((uintptr_t)addr, len);
}

/* Process-wide counts: faults continued, translations flushed. */
XTEXPORT void xt_ec_test_counts(uint32_t *faults, uint32_t *flushes)
{
    *faults = xt_fault_count();
    *flushes = qatomic_read(&tb_ctx.tb_flush_count);
}

/* What init found: the direct system calls' numbers, the checker's table. */
XTEXPORT void xt_ec_test_syscalls(int64_t nr[4], uint32_t *lut_size)
{
    nr[0] = nr_continue;
    nr[1] = nr_raise;
    nr[2] = nr_alloc;
    nr[3] = nr_protect;
    *lut_size = xt_ntdll_lut_size;
}

/* The entries ntdll made: bits 6-8 as xt_ec_entry_stub reports them. */
XTEXPORT uint32_t xt_ec_test_reached(void)
{
    return reached;
}
