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
    if (nr_continue < 0 || nr_raise < 0 || nr_alloc < 0 || nr_protect < 0) {
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
        area->EmulatorData[0] = t;
    }
    return t;
}

/*
 * ntdll's calls.  ProcessInit and ThreadInit do what needs no thread-local
 * variables (enter_engine does the rest).  For now the entries
 * (DispatchJump, RetToEntryThunk, ExitToX64, BeginSimulation in
 * arm64ec.S) bring the engine up and end the process, recording which was
 * reached first.
 */
static uint32_t reached;

XTEXPORT NTSTATUS ProcessInit(void)
{
    reached |= 0x40;
    if (!init_syscalls()) {
        return STATUS_NOT_SUPPORTED;
    }
    reached |= 0x80;
    return STATUS_SUCCESS;
}

XTEXPORT void ProcessTerm(HANDLE h, BOOL after, NTSTATUS status)
{
}

#define XT_EMULATOR_STACK (256 * 1024)
#define XT_EC_THREAD_PAGE 0x1000

/*
 * A thread's emulator stack, above a page of its own: the doorbell word
 * Windows sets to ask a simulating thread to stop (SuspendDoorbell).
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
    area->SuspendDoorbell = mem;
    area->EmulatorStackLimit = stack;
    area->EmulatorStackBase = stack + XT_EMULATOR_STACK;
    area->EmulatorData[0] = NULL;
    return STATUS_SUCCESS;
}

XTEXPORT NTSTATUS ThreadTerm(HANDLE thread, LONG code)
{
    return STATUS_SUCCESS;
}

XTEXPORT NTSTATUS ResetToConsistentState(EXCEPTION_RECORD *er, CONTEXT *guest,
                                         ARM64_NT_CONTEXT *native)
{
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

void xt_ec_entry_stub(int which, uint64_t target)
{
    XtThread *t = enter_engine();

    if (t) {
        xt_event(t, XT_EV_PLACE, (uintptr_t)"entry", target);
        xt_log_flush(t);
    }
    /*
     * Bits 6, 7: ProcessInit entered, succeeded; 8: ThreadInit entered;
     * 4: the engine and this thread's record are up; 5: the event log is
     * open.
     */
    NtTerminateProcess(GetCurrentProcess(),
                       !xt_log_handle() && xt_log_status < 0 ? xt_log_status :
                       0xEC000000 | which | reached | (t ? 0x10 : 0) |
                       (xt_log_handle() ? 0x20 : 0));
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
