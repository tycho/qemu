/*
 * xtajit: the POSIX and C runtime services the engine uses, on Windows'
 * terms: the engine's internal threads, mmap and mprotect, and large
 * aligned allocations.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/units.h"
#include "exec/page-protection.h"
#include "user/page-protection.h"
#include "user/host-mman.h"
#include "xtajit.h"

NTSTATUS NTAPI NtCreateThreadEx(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T,
                                SIZE_T, PVOID);
NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);
NTSTATUS NTAPI NtAlertThread(HANDLE);
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x01
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x02
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x04
#define THREAD_CREATE_FLAGS_SKIP_LOADER_INIT 0x20
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x40

/*
 * The engine's internal threads, registered: each slot is claimed before
 * the thread is created, created suspended, given its id, then let run, so
 * that a look at the registry (xt_internal_threads) never misses a running
 * internal thread nor mistakes one for another of the process's.  A slot
 * still being created (XT_INTERNAL_CREATING) is to be waited for.  The
 * thread marks itself (xt_internal_self) before anything of its own runs,
 * and is running from just before its routine.  At the process's end a
 * thread asked to stop (xt_internal_stop) parks for good where it holds
 * nothing (xt_internal_park), and one returning from its routine then
 * parks instead of ending, since a thread's end runs the CRT's and
 * Windows' teardown.
 */
#define XT_INTERNAL_MAX 64

static XtInternal internals[XT_INTERNAL_MAX];
static bool internal_stop;
__thread bool xt_internal_self;

typedef struct ThreadStart {
    unsigned (__stdcall *fn)(void *);
    void *arg;
    XtInternal *slot;
} ThreadStart;

const XtInternal *xt_internal_threads(int *n)
{
    *n = XT_INTERNAL_MAX;
    return internals;
}

/*
 * Wake every registered thread from an alertable sleep (their sleeps are,
 * g_usleep's included), so that one asked to park sees it at once rather
 * than after its period, which Windows' timer may stretch to 15.6 ms.
 */
void xt_internal_alert(void)
{
    for (int i = 0; i < XT_INTERNAL_MAX; i++) {
        uint32_t state = qatomic_load_acquire(&internals[i].state);
        HANDLE h = qatomic_read(&internals[i].h);

        if (state != XT_INTERNAL_FREE && state != XT_INTERNAL_CREATING &&
            h) {
            NtAlertThread(h);
        }
    }
}

void xt_internal_stop(void)
{
    qatomic_set(&internal_stop, true);
    xt_internal_alert();
}

bool xt_internal_stopping(void)
{
    return qatomic_read(&internal_stop);
}

/* The calling internal thread's slot: found by id (a thread knows its own). */
static XtInternal *internal_mine(void)
{
    DWORD me = GetCurrentThreadId();

    for (int i = 0; i < XT_INTERNAL_MAX; i++) {
        if (qatomic_read(&internals[i].tid) == me) {
            return &internals[i];
        }
    }
    return NULL;
}

void xt_internal_park(void)
{
    LARGE_INTEGER forever = { .QuadPart = INT64_MIN };
    XtInternal *slot = internal_mine();

#ifdef TARGET_X86_64
    /* No longer exempt from a closed gate: parked, it enters nothing. */
    xt_gate_end_internal();
#endif
    if (slot) {
        qatomic_store_release(&slot->state, XT_INTERNAL_PARKED);
    }
    for (;;) {
        NtDelayExecution(FALSE, &forever);
    }
}

static NTSTATUS NTAPI thread_start(void *p)
{
    ThreadStart s = *(ThreadStart *)p;
    unsigned code;

#ifdef TARGET_X86_64
    /* Its gate before anything that could call back into the module. */
    xt_gate_install_internal();
#endif
    xt_tls_attach();
    xt_internal_self = true;
    xt_crt_thread_init();
    g_free(p);
    xt_placement("internal thread stack", &s);
    qatomic_store_release(&s.slot->state, XT_INTERNAL_RUNNING);
    code = s.fn(s.arg);
    if (xt_internal_stopping()) {
        xt_internal_park();
    }
#ifdef TARGET_X86_64
    /* Leaving the registry, it leaves the exemption first. */
    xt_gate_end_internal();
#endif
    qatomic_set(&s.slot->tid, 0);
    if (s.slot->h) {
        NtClose(s.slot->h);
        s.slot->h = NULL;
    }
    qatomic_store_release(&s.slot->state, XT_INTERNAL_FREE);
    RtlExitUserThread(code);
    return 0;
}

/*
 * The engine's internal threads (QEMU's RCU thread): native threads that
 * skip the loader's initialization.  In a WOW64 process a thread the
 * loader initializes becomes a WOW64 thread, with a CPU and guest state;
 * these get their TLS block from xt_tls_attach instead.
 */
uintptr_t __cdecl _beginthreadex(void *security, unsigned stack,
                                 unsigned (__stdcall *fn)(void *),
                                 void *arg, unsigned flags, unsigned *tid)
{
    ThreadStart *s = g_new(ThreadStart, 1);
    XtThreadBasicInfo tbi;
    XtInternal *slot = NULL;
    DWORD id = 0;
    HANDLE h;

    for (int i = 0; i < XT_INTERNAL_MAX && !slot; i++) {
        if (qatomic_cmpxchg(&internals[i].state, XT_INTERNAL_FREE,
                            XT_INTERNAL_CREATING) == XT_INTERNAL_FREE) {
            slot = &internals[i];
        }
    }
    if (!slot) {
        g_free(s);
        return 0;
    }
    s->fn = fn;
    s->arg = arg;
    s->slot = slot;
    if (NtCreateThreadEx(&h, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(),
                         thread_start, s,
                         THREAD_CREATE_FLAGS_CREATE_SUSPENDED |
                         THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH |
                         THREAD_CREATE_FLAGS_SKIP_LOADER_INIT |
                         THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE |
                         THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
                         0, stack, 0, NULL) < 0) {
        g_free(s);
        qatomic_store_release(&slot->state, XT_INTERNAL_FREE);
        return 0;
    }
    if (NtQueryInformationThread(h, 0, &tbi, sizeof(tbi), NULL) >= 0) {
        id = (DWORD)(uintptr_t)tbi.ClientId.UniqueThread;
    }
    qatomic_set(&slot->tid, id);
    if (NtDuplicateObject(GetCurrentProcess(), h, GetCurrentProcess(),
                          &slot->h, 0, 0, DUPLICATE_SAME_ACCESS) < 0) {
        slot->h = NULL;
    }
    qatomic_store_release(&slot->state, XT_INTERNAL_STARTING);
    if (!(flags & CREATE_SUSPENDED)) {
        NtResumeThread(h, NULL);
    }
    if (tid) {
        *tid = id;
    }
    return (uintptr_t)h;
}

void __cdecl _endthreadex(unsigned code)
{
    RtlExitUserThread(code);
    __builtin_unreachable();
}

XT_IMPORT_SLOT(_beginthreadex);
XT_IMPORT_SLOT(_endthreadex);

NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE, PVOID, int, PVOID, SIZE_T,
                                    PSIZE_T);

static ULONG nt_prot(int prot)
{
    switch (prot & 7) {
    case 0:
        return PAGE_NOACCESS;
    case PROT_READ:
        return PAGE_READONLY;
    case PROT_WRITE:
    case PROT_READ | PROT_WRITE:
        return PAGE_READWRITE;
    case PROT_EXEC:
    case PROT_EXEC | PROT_READ:
        return PAGE_EXECUTE_READ;
    default:
        return PAGE_EXECUTE_READWRITE;
    }
}

/*
 * mmap: anonymous private mappings only (the return stack ring), and
 * munmap of a whole mapping.
 */
void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
    PVOID base = addr;
    SIZE_T size = len;

    if (fd != -1 || NtAllocateVirtualMemory(GetCurrentProcess(), &base, 0,
                                            &size, MEM_RESERVE | MEM_COMMIT,
                                            nt_prot(prot)) < 0) {
        errno = ENOMEM;
        return MAP_FAILED;
    }
    return base;
}

int munmap(void *addr, size_t len)
{
    PVOID base = addr;
    SIZE_T size = 0;

    if (NtFreeVirtualMemory(GetCurrentProcess(), &base, &size,
                            MEM_RELEASE) < 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

/*
 * mprotect, for QEMU's write protection of pages with translated code
 * (tb_lock_page0, page_unprotect), called with the mmap lock held.  Two
 * differences from POSIX:
 *
 * - A Linux host never executes guest pages, so QEMU asks for no execute
 *   permission; here the protection is also what the guest sees
 *   (VirtualQuery, and QEMU's page flags refilled from Windows), so a
 *   page QEMU's flags give PAGE_EXEC keeps it.
 * - NtProtectVirtualMemory takes one allocation at a time, and an image's
 *   pages may need the write-copy form of a writable protection: the work
 *   is page by page, and giving write back restores exactly the protection
 *   QEMU's took away.
 *
 * The result is reported, though QEMU's callers don't look at it yet.
 */
/*
 * The protection Windows had on each page QEMU write-protected for its
 * translations (mprotect without PROT_WRITE), restored exactly when QEMU
 * gives write back, and what the guest's queries see (xt_guest_prot).
 * Under the mmap lock, as QEMU's calls are.
 */
static GHashTable *saved_prot;

static bool writable(ULONG p)
{
    switch (p & 0xff) {
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    }
    return false;
}

ULONG xt_guest_prot(uintptr_t page)
{
    return saved_prot ? GPOINTER_TO_UINT(g_hash_table_lookup(
                            saved_prot, GUINT_TO_POINTER(page))) : 0;
}

void xt_guest_prot_forget(uintptr_t start, uintptr_t last)
{
    if (!saved_prot || !g_hash_table_size(saved_prot)) {
        return;
    }
    for (uintptr_t p = start & ~(uintptr_t)0xfff; p <= last; p += 0x1000) {
        g_hash_table_remove(saved_prot, GUINT_TO_POINTER(p));
        if (p + 0x1000 < p) {
            break;
        }
    }
}

int mprotect(void *addr, size_t len, int prot)
{
    uintptr_t p = (uintptr_t)addr & ~(uintptr_t)0xfff;
    uintptr_t end = (uintptr_t)addr + len;
    int ret = 0;

    if (!saved_prot) {
        saved_prot = g_hash_table_new(NULL, NULL);
    }
    if (prot && (page_get_flags(p) & PAGE_EXEC)) {
        prot |= PROT_EXEC;
    }
    for (; p < end; p += 0x1000) {
        MEMORY_BASIC_INFORMATION mbi;
        PVOID base = (PVOID)p;
        SIZE_T size = 0x1000;
        ULONG old, saved = xt_guest_prot(p), np = nt_prot(prot), mods = 0;
        NTSTATUS st;

        if ((prot & PROT_WRITE) && saved) {
            np = saved;
        }
        /*
         * The page's modifiers stay: QEMU protects a page before it reads
         * the code there, and a guard must still fault that read.
         */
        if (NtQueryVirtualMemory(GetCurrentProcess(), base, 0, &mbi,
                                 sizeof(mbi), NULL) >= 0) {
            mods = mbi.Protect & (PAGE_GUARD | PAGE_NOCACHE |
                                  PAGE_WRITECOMBINE);
        }
        np |= mods;
        st = NtProtectVirtualMemory(GetCurrentProcess(), &base, &size, np,
                                    &old);
        if (st < 0 && ((np & 0xff) == PAGE_READWRITE ||
                       (np & 0xff) == PAGE_EXECUTE_READWRITE)) {
            base = (PVOID)p;
            size = 0x1000;
            st = NtProtectVirtualMemory(GetCurrentProcess(), &base, &size,
                                        ((np & 0xff) == PAGE_READWRITE ?
                                         PAGE_WRITECOPY :
                                         PAGE_EXECUTE_WRITECOPY) | mods,
                                        &old);
        }
        if (st < 0) {
            ret = -1;
        } else if (!(prot & PROT_WRITE)) {
            if (writable(old) && !saved) {
                g_hash_table_insert(saved_prot, GUINT_TO_POINTER(p),
                                    GUINT_TO_POINTER(old & 0xff));
            }
        } else {
            g_hash_table_remove(saved_prot, GUINT_TO_POINTER(p));
        }
    }
    return ret;
}

#define BIG_ALIGNED (256 * KiB)
#define BIG_MAGIC 0x786a7462616c6e67ull
#define VM_GRANULE (64 * KiB)

/*
 * Large aligned allocations (the per-CPU jump cache, 1 MiB at 16 KiB)
 * come from Windows directly: rpmalloc commits 64 MiB for each.  A block
 * starts one allocation granule (64 KiB, which every alignment up to it
 * needs no more than) after a header naming it; smaller ones, and
 * alignments past the granule, stay the allocator's.  Above 4 GiB, as the
 * allocator's.
 */

void *__cdecl _aligned_malloc(size_t size, size_t align)
{
    void *base;

    if (size < BIG_ALIGNED || align > VM_GRANULE) {
        return xt_heap_aligned(size, align);
    }
    base = xt_alloc_high(size + VM_GRANULE);
    if (!base) {
        return NULL;
    }
    *(uint64_t *)base = BIG_MAGIC;
    return (char *)base + VM_GRANULE;
}

void __cdecl _aligned_free(void *p)
{
    MEMORY_BASIC_INFORMATION mbi;
    char *base = (char *)p - VM_GRANULE;

    if (p && !((uintptr_t)p & (VM_GRANULE - 1)) &&
        NtQueryVirtualMemory(GetCurrentProcess(), base, 0, &mbi,
                             sizeof(mbi), NULL) >= 0 &&
        mbi.AllocationBase == base && *(uint64_t *)base == BIG_MAGIC) {
        SIZE_T len = 0;
        void *b = base;

        *(uint64_t *)base = 0;
        NtFreeVirtualMemory(GetCurrentProcess(), &b, &len, MEM_RELEASE);
        return;
    }
    free(p);
}

XT_IMPORT_SLOT(_aligned_malloc);
XT_IMPORT_SLOT(_aligned_free);
