/*
 * xtajit: the x64 CPU module's interface, as ntdll calls it in an x64
 * process on Windows on Arm, whose native code is ARM64EC.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/units.h"
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
#define XT_SCAFFOLD "smc=check"
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

/*
 * Work other processes queued for this one's emulator (a flush of code
 * they wrote): ntdll delivers it through the notification exports, when
 * asked at each entry and system call.
 */
static void (*cross_process_work)(void);

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

/* Whether ProcessInit has found the system calls the module makes itself. */
bool xt_syscalls_ready(void)
{
    return nr_alloc >= 0;
}

/*
 * Memory through the system call itself, no code of ntdll's on the way:
 * nothing reaches the module's callbacks (emutls.c's cold path).
 */
void *xt_alloc_direct(size_t len)
{
    void *p = NULL;
    SIZE_T size = len;

    if (alloc_direct(&p, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) < 0) {
        return NULL;
    }
    return p;
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
    cross_process_work = (void (*)(void))
        ntdll_native(md, "ProcessPendingCrossProcessEmulatorWork");
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
    xt_emutls_init();
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

NTSTATUS NTAPI NtSuspendThread(HANDLE, PULONG);
NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE,
                                 ACCESS_MASK, ULONG, ULONG);

static void ec_unregister(XtThread *t);

/*
 * A thread's end, by itself or by another thread (THREAD), before Windows
 * terminates it.  Another thread is suspended and its context read first,
 * as FEX's module does: that waits for it to answer the doorbell, so it
 * is outside the engine, holding none of its locks; it stays suspended
 * for Windows to end.  Then the record leaves the watcher's list and goes:
 * the thread's own at once, another's once its handle is signalled
 * (xt_reap), as the emulator stack and its page.  A thread Windows won't
 * end (xt_terminates) is left alone.
 */
XTEXPORT NTSTATUS ThreadTerm(HANDLE thread, LONG code)
{
    XtThreadBasicInfo tbi;
    XtCpuArea *area;
    XtThread *t;
    HANDLE h, dup;
    bool self;

    if (qatomic_load_acquire(&engine_state) != 2 || !xt_terminates(thread)) {
        return STATUS_SUCCESS;
    }
    xt_enter();
    xt_reap();
    if (!thread || thread == GetCurrentThread()) {
        tbi.TebBaseAddress = NtCurrentTeb();
        self = true;
    } else if (NtQueryInformationThread(thread, 0, &tbi, sizeof(tbi),
                                        NULL) < 0) {
        return STATUS_SUCCESS;
    } else {
        self = tbi.TebBaseAddress == NtCurrentTeb();
    }
    area = xt_cpu_area(tbi.TebBaseAddress);
    if (!area || !qatomic_read(&area->EmulatorData[0])) {
        return STATUS_SUCCESS;
    }
    h = self ? GetCurrentThread() : thread;
    if (!self) {
        CONTEXT c = { .ContextFlags = CONTEXT_CONTROL };

        NtSuspendThread(h, NULL);
        NtGetContextThread(h, &c);
    }
    t = qatomic_xchg(&area->EmulatorData[0], NULL);
    if (!t) {
        return STATUS_SUCCESS;
    }
    ec_unregister(t);
    if (NtDuplicateObject(GetCurrentProcess(), h, GetCurrentProcess(), &dup,
                          0, 0, DUPLICATE_SAME_ACCESS) >= 0) {
        xt_reap_later(dup, area->EmulatorData[1]);
    }
    if (self) {
        xt_thread_free(t);
        xt_crt_thread_fini();
    } else if (NtDuplicateObject(GetCurrentProcess(), h, GetCurrentProcess(),
                                 &dup, 0, 0, DUPLICATE_SAME_ACCESS) >= 0) {
        xt_thread_retire(t, dup);
    }
    return STATUS_SUCCESS;
}

/*
 * The memory service's work (memory.c), from any thread.  Before the engine
 * is up there are no translations or page flags to keep current.
 */
static bool note_ready(void)
{
    if (qatomic_load_acquire(&engine_state) != 2) {
        return false;
    }
    xt_enter();
    return true;
}

/*
 * ntdll's call at any exception in an ARM64EC thread, before its
 * dispatch, with the full native context (x13, x14, x23, x24, x28 and
 * v16-v31 included).  Continued here, with that context:
 * - the doorbell found set at an exit to native code (arm64ec.S): the
 *   exit stub is consistent there, so continuing it completes the
 *   suspension;
 * - a fault the engine recovers (xt_fault_redirect: generated code,
 *   helpers, translation), while it owns the thread;
 * - otherwise, native code's store into a page QEMU write-protected for
 *   its translations, such as a runtime patching its own x64 code: the
 *   page gets its write permission back and the store is retried.
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
    /* The module's int3, past the debugger: at the int3 for the dispatch. */
    if (t && t->int3_rip && er->ExceptionCode == STATUS_BREAKPOINT &&
        native->Pc == t->int3_rip) {
        native->Pc--;
        if (guest) {
            guest->Rip--;
        }
        t->int3_rip = 0;
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
        /* An exception in the engine it doesn't recover: logged. */
        xt_event(t, XT_EV_FAULT, (uint64_t)t->fault.busy << 32 | t->active,
                 er->ExceptionInformation[1]);
        xt_log_native(er, native);
        xt_log_flush(t);
    } else if (er->ExceptionCode == STATUS_ACCESS_VIOLATION &&
               er->NumberParameters >= 2 && er->ExceptionInformation[0] == 1 &&
               note_ready() &&
               xt_unprotect_for_native(er->ExceptionInformation[1])) {
        xt_continue_native(native);
    }
    return STATUS_SUCCESS;
}

/*
 * The engine's own work outside simulation (memory.c's): with
 * InSyscallCallback set, as FEX's module sets it around its own.
 */
bool xt_adapter_begin(void)
{
    XtCpuArea *area = xt_cpu_area(NtCurrentTeb());

    if (!area || area->InSyscallCallback) {
        return false;
    }
    area->InSyscallCallback = 1;
    return true;
}

void xt_adapter_end(bool began)
{
    if (began) {
        xt_cpu_area(NtCurrentTeb())->InSyscallCallback = 0;
    }
}

XTEXPORT void NotifyMemoryAlloc(void *addr, SIZE_T len, ULONG type, ULONG prot,
                                BOOL after, NTSTATUS status)
{
    if (note_ready()) {
        xt_note_alloc(addr, len, type, prot, after, status);
    }
}

XTEXPORT void NotifyMemoryFree(void *addr, SIZE_T len, ULONG type, BOOL after,
                               NTSTATUS status)
{
    if (note_ready()) {
        xt_note_free(addr, len, type, after, status);
    }
}

XTEXPORT void NotifyMemoryProtect(void *addr, SIZE_T len, ULONG prot,
                                  BOOL after, NTSTATUS status)
{
    if (note_ready()) {
        xt_note_protect(addr, len, prot, after, status);
    }
}

XTEXPORT NTSTATUS NotifyMapViewOfSection(void *unk1, void *addr, void *unk2,
                                         SIZE_T len, ULONG type, ULONG prot)
{
    if (note_ready()) {
        xt_note_map(addr, len, prot);
    }
    return STATUS_SUCCESS;
}

XTEXPORT void NotifyUnmapViewOfSection(void *addr, BOOL after, NTSTATUS status)
{
    if (note_ready()) {
        xt_note_unmap(addr, after);
    }
}

XTEXPORT void FlushInstructionCacheHeavy(const void *addr, SIZE_T len)
{
    if (note_ready()) {
        xt_note_flush(addr, len);
    }
}

XTEXPORT void BTCpu64FlushInstructionCache(const void *addr, SIZE_T len)
{
    if (note_ready()) {
        xt_note_flush(addr, len);
    }
}

XTEXPORT void BTCpu64NotifyMemoryDirty(void *addr, SIZE_T len)
{
    if (note_ready()) {
        xt_note_flush(addr, len);
    }
}

XTEXPORT void BTCpu64NotifyReadFile(HANDLE h, void *addr, SIZE_T len,
                                    BOOL after, NTSTATUS status)
{
    if (note_ready()) {
        xt_note_read_file(addr, len, after, status);
    }
}

/*
 * The processor as x64 code sees it.  Windows asks for the features while
 * the process starts, before the engine is up: they are the CPU model's
 * until the first entry makes a CPU.  The processor information needs
 * that CPU.
 */
XTEXPORT BOOLEAN BTCpu64IsProcessorFeaturePresent(UINT feature)
{
    return xt_feature_present(feature);
}

XTEXPORT void UpdateProcessorInformation(void *info)
{
    if (qatomic_load_acquire(&engine_state) == 2) {
        xt_processor_info(info, PROCESSOR_ARCHITECTURE_AMD64);
    }
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

/* A free slot, else a new one. */
static void ec_register(XtThread *t)
{
    int n = MIN(qatomic_read(&ec_nthreads), XT_EC_MAX_THREADS), i;

    for (i = 0; i < n; i++) {
        if (qatomic_cmpxchg(&ec_threads[i], NULL, t) == NULL) {
            return;
        }
    }
    i = qatomic_fetch_inc(&ec_nthreads);
    if (i < XT_EC_MAX_THREADS) {
        qatomic_set(&ec_threads[i], t);
    }
}

/* Out of the watcher's list; it may have it still until the next hold. */
static void ec_unregister(XtThread *t)
{
    int n = MIN(qatomic_read(&ec_nthreads), XT_EC_MAX_THREADS);

    for (int i = 0; i < n; i++) {
        if (qatomic_read(&ec_threads[i]) == t) {
            qatomic_set(&ec_threads[i], NULL);
        }
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
 * EFLAGS kept for a re-entry through a context at RSP: records deeper
 * than a new one are dead (the stack has unwound past them), and taking
 * one drops the deeper ones too.
 */
static void aux_push(XtThread *t, vaddr rsp, uint32_t eflags)
{
    int n = 0;

    for (int i = 0; i < t->naux; i++) {
        if (t->aux[i].rsp > rsp) {
            t->aux[n++] = t->aux[i];
        }
    }
    if (n == ARRAY_SIZE(t->aux)) {
        memmove(&t->aux[0], &t->aux[1], --n * sizeof(t->aux[0]));
    }
    t->aux[n].rsp = rsp;
    t->aux[n].eflags = eflags;
    t->naux = n + 1;
}

static bool aux_take(XtThread *t, vaddr rsp, uint32_t *eflags)
{
    for (int i = t->naux - 1; i >= 0; i--) {
        if (t->aux[i].rsp == rsp) {
            *eflags = t->aux[i].eflags;
            t->naux = i;
            return true;
        }
    }
    return false;
}

/*
 * The end of an activation: the engine gives the thread back (publish)
 * and the guest state goes into the packed context; for an exit that
 * re-enters through a context (CONTEXT_EXIT), EFLAGS it can't carry are
 * kept.
 */
static void leave(XtThread *t, ARM64_NT_CONTEXT *n, bool context_exit)
{
    xt_publish(t, NULL);
    xt_ec_pack(t, n);
    if (context_exit) {
        aux_push(t, n->Sp, cpu_compute_eflags(t->env));
    }
    xt_log_flush(t);
}

static G_NORETURN void leave_native(XtThread *t, XtEcFrame *f,
                                       vaddr target)
{
    leave(t, &f->ctx, false);
    f->ctx.Pc = target;
    if (xt_ec_ymm(t)) {
        xt_ec_exit_native_ymm(&f->ctx);
    }
    xt_ec_exit_native(&f->ctx);
}

static G_NORETURN void leave_syscall(XtThread *t)
{
    XtKiFrame k;

    memset(&k.rec, 0, sizeof(k.rec));
    leave(t, &k.ctx, true);
    if (cross_process_work) {
        cross_process_work();
    }
    k.rec.ExceptionCode = STATUS_EMULATION_SYSCALL;
    xt_cpu_area(NtCurrentTeb())->InSimulation = 0;
    xt_ec_jump_set_stack(ki_exception_dispatcher, (uintptr_t)&k);
}

/*
 * A guest exception, raised with the packed context as x64 Windows
 * reports it: a fast fail second chance; a breakpoint at the int3.  The
 * int3 is raised with RIP past it, as x64 hardware leaves it: Windows
 * shows a debugger an x64 breakpoint's RIP one byte back, as x64's kernel
 * backs it up, but dispatches the context as raised, so the dispatch's
 * entry (ResetToConsistentState) backs it up there.
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
        t->env->eip -= 2;
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
    r->ExceptionAddress = (void *)(uintptr_t)(t->env->eip -
                                              (x->vector == EXCP03_INT3));
    t->int3_rip = x->vector == EXCP03_INT3 ? t->env->eip : 0;
    leave(t, &n, true);
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

    leave(t, &n, true);
    qatomic_set(&f->doorbell, 0);
    t->ec_suspended = true;
    xt_cpu_area(NtCurrentTeb())->InSimulation = 0;
    xt_ec_continue_kept(&n, nr_continue);
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

    t->ec_suspended = false;
    if (cross_process_work) {
        cross_process_work();
    }
    xt_acquire_begin(t);
    xt_ec_import_call(t, &f->ctx);
    xt_acquire_end(t);
    ec_run(t, f);
}

/*
 * Windows treats a thread as consistent from KiUserEmulationDispatcher's
 * entry until CpuDispatchEmulation sets InSimulation: on the guest stack,
 * the x64 state still in the native context there, from which the AMD64
 * context is converted.  A suspension in that window reads and writes the
 * native registers, so an edit made then reaches BeginSimulation only in
 * the registers the dispatcher keeps (saved in the frame by
 * BeginSimulation): R12-R15, RBX, RSI and RDI.  A suspension's
 * continuation loads them from its context (xt_ec_continue_kept), and
 * native code keeps them up to BeginSimulation, so they differ from the
 * AMD64 context only by such an edit, and are taken from there.  An edit
 * to any other register in the window is lost (under Prism too).
 */
static void ec_window_edits(const ARM64_NT_CONTEXT *kept, CONTEXT *c)
{
    c->R12 = kept->X19;
    c->R13 = kept->X20;
    c->R14 = kept->X21;
    c->R15 = kept->X22;
    c->Rsi = kept->X25;
    c->Rdi = kept->X26;
    c->Rbx = kept->X27;
}

/*
 * KiUserEmulationDispatcher's entry, after a continuation at x64 code:
 * the CPU area's AMD64 context is authoritative, with what the packed
 * form couldn't carry from the exit it continues (the one at the same
 * RSP; a handler may move RIP past a faulting instruction): EFLAGS but
 * NZCV and TF.  The YMM upper halves come from its extended part, which
 * Windows fills from the continued context; v16-v31 hold nothing here
 * after a system call.  The x87 state stays the engine's: Windows
 * carries no control, status or tag word.
 */
#define MXCSR_CARRIED 0xe03f
void xt_ec_begin(void)
{
    XtCpuArea *area = xt_cpu_area(NtCurrentTeb());
    XtThread *t = ec_thread();
    const CONTEXT *w = (const CONTEXT *)area->ContextAmd64;
    const uint32_t nzcv = CC_S | CC_Z | CC_C | CC_O | TF_MASK;
    uint32_t kept;
    CONTEXT c;

    if (cross_process_work) {
        cross_process_work();
    }

    memset(&c, 0, sizeof(c));
    xt_export(t, &c);
    if ((w->ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER) {
        memcpy(&c.Rax, &w->Rax, 16 * sizeof(c.Rax));
        if (t->ec_suspended) {
            ec_window_edits(&((XtEcFrame *)area->EmulatorData[1])->ctx, &c);
        }
    }
    t->ec_suspended = false;
    if ((w->ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL) {
        c.Rip = w->Rip;
        c.Rsp = w->Rsp;
        c.Rbp = w->Rbp;
        c.SegCs = w->SegCs;
        c.SegSs = w->SegSs;
        c.EFlags = w->EFlags;
        if (aux_take(t, w->Rsp, &kept)) {
            c.EFlags = (kept & ~nzcv) | (w->EFlags & nzcv);
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
        /*
         * MXCSR's rounding, flush-to-zero and flags travel (as FPCR and
         * FPSR); changed there, they are an edit.  Its exception masks
         * and DAZ don't, and stay the engine's.
         */
        uint32_t edited = MXCSR_CARRIED & (w->MxCsr ^ c.MxCsr);

        memcpy(c.FltSave.XmmRegisters, w->FltSave.XmmRegisters,
               sizeof(c.FltSave.XmmRegisters));
        if (edited) {
            c.MxCsr = (c.MxCsr & ~MXCSR_CARRIED) |
                      (w->MxCsr & MXCSR_CARRIED);
            c.FltSave.MxCsr = c.MxCsr;
        }
    }
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
    xt_acquire_begin(t);
    xt_import(t, &c);
    if (xt_ec_ymm(t)) {
        xt_ec_import_ymm(t, w);
    }
    xt_acquire_end(t);
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

/*
 * A thread-local variable larger than a root's storage, page-aligned and
 * with an initial value, for the harness to check from many threads at
 * once (emutls.c): 1 if this thread's copy is aligned, holds the initial
 * value at its first use and stays the thread's own.  With REAP 1: the
 * roots left after a sweep of the ended threads' instead; 2: the sweep
 * alone (the count is safe only while nothing else sweeps).
 */
static __thread uint8_t test_tls[80 * KiB] __attribute__((aligned(4096))) = {
    0x5a, 0xa5,
};

XTEXPORT int xt_ec_test_tls(int reap)
{
    /* The TEB's own address tells threads apart. */
    uintptr_t tid = (uintptr_t)NtCurrentTeb();
    uint8_t *p;

    if (reap) {
        xt_emutls_reap();
        return reap == 1 ? xt_emutls_roots() : 0;
    }
    /* The variable's first use, by the harness's threads at once. */
    p = test_tls;
    if ((uintptr_t)p & 4095) {
        return -1;
    }
    if (p[0] != 0x5a || p[1] != 0xa5 || p[2] || p[sizeof(test_tls) - 1]) {
        return -2;
    }
    memcpy(p + 2, &tid, sizeof(tid));
    NtYieldExecution();
    if (test_tls != p || memcmp(p + 2, &tid, sizeof(tid))) {
        return -3;
    }
    return 1;
}

/* The emulated TLS's test hooks (xt_emutls_test). */
XTEXPORT long xt_ec_test_tls_hook(int what, long arg)
{
    return xt_emutls_test(what, arg);
}

/* A thread-local variable's access, ARG times, for its cost. */
static __thread long test_tls_count;

static __attribute__((noinline)) void test_tls_touch(void)
{
    test_tls_count++;
}

static long test_global_count;

static __attribute__((noinline)) void test_global_touch(void)
{
    qatomic_set(&test_global_count, test_global_count + 1);
}

XTEXPORT long xt_ec_test_tls_cost(int tls, long n)
{
    for (long i = 0; i < n; i++) {
        if (tls) {
            test_tls_touch();
        } else {
            test_global_touch();
        }
    }
    return tls ? test_tls_count : test_global_count;
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
