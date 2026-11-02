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
NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
NTSTATUS NTAPI NtSuspendThread(HANDLE, PULONG);
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

static XtThread *thread_of_teb(void *teb)
{
    return ((XtThread **)((char *)teb + TEB_TLS_SLOTS))[16];
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


extern IMAGE_DOS_HEADER __ImageBase;

/* FEX::Windows::InitCRTProcess(): rpmalloc, constructors, TLS callbacks. */
void _ZN3FEX7Windows14InitCRTProcessEv(void);

/* Process-wide bring-up shared by WOW64 and the native harness. */
int xt_process_init(bool wow64)
{
    char *settings;

    /*
     * The runtime first (rpmalloc, which allocates above the guest's
     * address space once initialized; the constructors, QEMU's RCU thread
     * among them), with this thread's TLS block already in place.
     */
    xt_tls_attach();
    _ZN3FEX7Windows14InitCRTProcessEv();
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
    /*
     * A software CPU: wow64.dll then sets up the cross-process work list
     * and suspends this process's threads cooperatively (slot 2).
     */
    ((ULONG *)slots[WOW64_TLS_WOW64INFO])[1] = WOW64_CPUFLAGS_SOFTWARE;
    return STATUS_SUCCESS;
}

XTEXPORT void WINAPI BTCpuProcessTerm(HANDLE h, BOOL after, ULONG status)
{
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
    xt_tls_attach();
    xt_thread_new(true);
    return STATUS_SUCCESS;
}

static DWORD thread_id(HANDLE thread)
{
    XtThreadBasicInfo tbi;

    /* wow64.dll names the calling thread with a null handle. */
    if (!thread || thread == GetCurrentThread()) {
        return GetCurrentThreadId();
    }
    if (NtQueryInformationThread(thread, 0, &tbi, sizeof(tbi), NULL) < 0) {
        return 0;
    }
    return (DWORD)(uintptr_t)tbi.ClientId.UniqueThread;
}

XTEXPORT void WINAPI BTCpuThreadTerm(HANDLE thread, LONG code)
{
    DWORD tid = thread_id(thread);
    XtThread *t = xt_tls_ready() ? xt_self : NULL;

    /* Remote termination is not handled yet: the record stays. */
    if (t && tid == t->tid) {
        xt_thread_free(t);
    } else {
        xt_gevent(XT_EV_THREAD_TERM, tid, code);
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
            if (x.rec.ExceptionFlags & EXCEPTION_NONCONTINUABLE) {
                NtTerminateProcess(GetCurrentProcess(), x.rec.ExceptionCode);
            }
            /* Points the context at the guest's KiUserExceptionDispatcher. */
            p_Wow64RaiseException(-1, &x.rec);
            c = cpu_area_context();
            xt_acquire(t, c);
            break;
        }
    }
}

/*
 * Another thread suspends THREAD, which runs guest code (slot 2 bit 0
 * set): wow64.dll has suspended it already, and resumes it after this
 * returns, then waits for its Wow64NotifyUnsimulateComplete.  Ask it to
 * leave the engine at its next TB boundary: an exit request, release
 * stores only.
 */
XTEXPORT NTSTATUS WINAPI BTCpuSuspendLocalThread(HANDLE thread, void *info,
                                                 void *unk1, ULONG unk2)
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
    t = thread_of_teb(tbi.TebBaseAddress);
    if (t) {
        qatomic_set(&t->suspend_req, 1);
        cpu_exit(t->cpu);
    }
    xt_gevent(XT_EV_SUSPEND_SEEN, (uintptr_t)tbi.ClientId.UniqueThread,
              t ? t->state : -1);
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
    return STATUS_SUCCESS;
}

/*
 * Memory notifications.  After a successful change Windows' protection is
 * what the guest asked for, so QEMU's page flags for the range are dropped
 * (with the translations of executable pages) and refilled from Windows
 * when next probed (xt_mem_refresh).
 */
static void forget(int kind, ULONG prot, vaddr start, vaddr len)
{
    vaddr last;

    if (xt_tls_ready() && xt_self) {
        xt_event(xt_self, XT_EV_MEMNOTE, (uint64_t)kind << 56 |
                 (uint64_t)(prot & 0xffffff) << 32 | (len & 0xffffffff),
                 start);
    }
    if (!len || start > guest_addr_max) {
        return;
    }
    last = MIN(start + len - 1, (vaddr)guest_addr_max);
    mmap_lock();
    page_set_flags(start & TARGET_PAGE_MASK, last | ~TARGET_PAGE_MASK, 0,
                   PAGE_VALID);
    mmap_unlock();
}

XTEXPORT void WINAPI BTCpuFlushInstructionCache2(const void *addr, SIZE_T len)
{
    xt_enter();
    xt_invalidate((uintptr_t)addr, len);
}

XTEXPORT void WINAPI BTCpuFlushInstructionCacheHeavy(const void *addr,
                                                     SIZE_T len)
{
    xt_enter();
    xt_invalidate((uintptr_t)addr, len);
}

XTEXPORT void WINAPI BTCpuNotifyMemoryDirty(void *addr, SIZE_T len)
{
    xt_enter();
    xt_invalidate((uintptr_t)addr, len);
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
 * Before the guest changes a protection, pages QEMU write-protected for
 * their translations get their write permission back (page_unprotect: the
 * translations go), so that the old protection Windows reports is the
 * guest's, not QEMU's.  Queries (NtQueryVirtualMemory) still see QEMU's.
 */
static void unprotect_range(vaddr start, vaddr len)
{
    Unprotect u = { start, MIN(start + len - 1, (vaddr)guest_addr_max) };

    if (!len || start > guest_addr_max) {
        return;
    }
    mmap_lock();
    while (walk_memory_regions(&u, find_protected)) {
        page_unprotect(NULL, u.found, 0);
    }
    mmap_unlock();
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

XTEXPORT void WINAPI BTCpuNotifyMemoryFree(void *addr, SIZE_T len,
                                           ULONG type, BOOL after,
                                           ULONG status)
{
    xt_enter();
    if (after && !status) {
        forget(3, 0, (uintptr_t)addr, len);
    }
}

XTEXPORT NTSTATUS WINAPI BTCpuNotifyMapViewOfSection(void *unk1, void *addr,
                                                     void *unk2, SIZE_T len,
                                                     ULONG type, ULONG prot)
{
    xt_enter();
    forget(4, prot, (uintptr_t)addr, len);
    return STATUS_SUCCESS;
}

/* The view's extent, found before the unmap. */
static __thread vaddr unmap_start, unmap_len;

XTEXPORT void WINAPI BTCpuNotifyUnmapViewOfSection(void *addr, BOOL after,
                                                   ULONG status)
{
    xt_enter();
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t p;

    if (!after) {
        unmap_start = unmap_len = 0;
        if (NtQueryVirtualMemory(GetCurrentProcess(), addr, 0, &mbi,
                                 sizeof(mbi), NULL) < 0) {
            return;
        }
        unmap_start = (uintptr_t)mbi.AllocationBase;
        for (p = unmap_start;; p += mbi.RegionSize) {
            if (NtQueryVirtualMemory(GetCurrentProcess(), (void *)p, 0, &mbi,
                                     sizeof(mbi), NULL) < 0 ||
                (uintptr_t)mbi.AllocationBase != unmap_start) {
                break;
            }
        }
        unmap_len = p - unmap_start;
    } else if (!status) {
        forget(5, 0, unmap_start, unmap_len);
    }
}

XTEXPORT void WINAPI BTCpuNotifyReadFile(HANDLE h, void *addr, SIZE_T len,
                                         BOOL after, NTSTATUS status)
{
    xt_enter();
    if (after && !status) {
        xt_invalidate((uintptr_t)addr, len);
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
