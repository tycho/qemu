/*
 * xtajit: runtime services the module owns rather than takes from the
 * frozen runtime: the engine's internal threads, mprotect and large
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
#include "xtajit.h"

NTSTATUS NTAPI NtCreateThreadEx(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T,
                                SIZE_T, PVOID);
void NTAPI RtlExitUserThread(NTSTATUS);

/* FEX::Windows::InitCRTThread(): rpmalloc's per-thread state. */
void _ZN3FEX7Windows13InitCRTThreadEv(void);

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x01
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x02
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x04
#define THREAD_CREATE_FLAGS_SKIP_LOADER_INIT 0x20
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x40

typedef struct ThreadStart {
    unsigned (__stdcall *fn)(void *);
    void *arg;
} ThreadStart;

static NTSTATUS NTAPI thread_start(void *p)
{
    ThreadStart s = *(ThreadStart *)p;

    xt_tls_attach();
    _ZN3FEX7Windows13InitCRTThreadEv();
    g_free(p);
    xt_placement("internal thread stack", &s);
    RtlExitUserThread(s.fn(s.arg));
    return 0;
}

/*
 * The engine's internal threads (QEMU's RCU thread, the region sampler):
 * native threads that skip the loader's initialization, as FEX's do.  In a
 * WOW64 process a thread the loader initializes becomes a WOW64 thread,
 * with a CPU and guest state; these get their TLS block from
 * xt_tls_attach instead.  Linked ahead of the frozen runtime's version.
 */
uintptr_t __cdecl _beginthreadex(void *security, unsigned stack,
                                 unsigned (__stdcall *fn)(void *),
                                 void *arg, unsigned flags, unsigned *tid)
{
    ThreadStart *s = g_new(ThreadStart, 1);
    XtThreadBasicInfo tbi;
    HANDLE h;

    s->fn = fn;
    s->arg = arg;
    if (NtCreateThreadEx(&h, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(),
                         thread_start, s,
                         THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH |
                         THREAD_CREATE_FLAGS_SKIP_LOADER_INIT |
                         THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE |
                         THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER |
                         ((flags & CREATE_SUSPENDED) ?
                          THREAD_CREATE_FLAGS_CREATE_SUSPENDED : 0),
                         0, stack, 0, NULL) < 0) {
        g_free(s);
        return 0;
    }
    if (tid) {
        *tid = 0;
        if (NtQueryInformationThread(h, 0, &tbi, sizeof(tbi), NULL) >= 0) {
            *tid = (unsigned)(uintptr_t)tbi.ClientId.UniqueThread;
        }
    }
    return (uintptr_t)h;
}

uintptr_t (__cdecl *__imp__beginthreadex)(void *, unsigned,
                                          unsigned (__stdcall *)(void *),
                                          void *, unsigned,
                                          unsigned *) = _beginthreadex;

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
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
 * mprotect, for QEMU's write protection of pages with translated code
 * (tb_lock_page0, page_unprotect), called with the mmap lock held.  Two
 * differences from POSIX:
 *
 * - A Linux host never executes guest pages, so QEMU asks for no execute
 *   permission; here the protection is also what the guest sees
 *   (VirtualQuery, and QEMU's page flags refilled from Windows), so a
 *   page QEMU's flags give PAGE_EXEC keeps it.
 * - NtProtectVirtualMemory takes one allocation at a time, and an image's
 *   pages may need the write-copy form of a writable protection.
 *
 * The result is reported, though QEMU's callers don't look at it yet.
 */
int mprotect(void *addr, size_t len, int prot)
{
    uintptr_t p = (uintptr_t)addr, end = p + len;
    int ret = 0;

    if (prot && (page_get_flags(p) & PAGE_EXEC)) {
        prot |= PROT_EXEC;
    }
    while (p < end) {
        MEMORY_BASIC_INFORMATION mbi;
        PVOID base = (PVOID)p;
        SIZE_T size;
        ULONG old, np = nt_prot(prot);
        NTSTATUS st;

        if (NtQueryVirtualMemory(GetCurrentProcess(), base, 0, &mbi,
                                 sizeof(mbi), NULL) < 0) {
            return -1;
        }
        size = MIN(end, (uintptr_t)mbi.BaseAddress + mbi.RegionSize) - p;
        st = NtProtectVirtualMemory(GetCurrentProcess(), &base, &size, np,
                                    &old);
        if (st < 0 && (np == PAGE_READWRITE || np == PAGE_EXECUTE_READWRITE)) {
            base = (PVOID)p;
            size = MIN(end, (uintptr_t)mbi.BaseAddress + mbi.RegionSize) - p;
            st = NtProtectVirtualMemory(GetCurrentProcess(), &base, &size,
                                        np == PAGE_READWRITE ?
                                        PAGE_WRITECOPY :
                                        PAGE_EXECUTE_WRITECOPY, &old);
        }
        if (st < 0) {
            ret = -1;
        }
        p = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    return ret;
}

#define BIG_ALIGNED (256 * KiB)
#define BIG_MAGIC 0x786a7462616c6e67ull
#define VM_GRANULE (64 * KiB)

NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE, PVOID *, PSIZE_T, ULONG);

/*
 * Large aligned allocations (the per-CPU jump cache, 1 MiB at 16 KiB)
 * come from Windows directly: the frozen runtime's allocator commits 64
 * MiB for each.  A block starts one allocation granule (64 KiB, which
 * every alignment up to it needs no more than) after a header naming it;
 * smaller ones, and alignments past the granule, stay the runtime's
 * (rpmalloc, as its _aligned_malloc).  Above 4 GiB, as the runtime's.
 */

void *__cdecl _aligned_malloc(size_t size, size_t align)
{
    void *base;

    if (size < BIG_ALIGNED || align > VM_GRANULE) {
        return rpaligned_alloc(align, size);
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
    rpfree(p);
}

void *(__cdecl *__imp__aligned_malloc)(size_t, size_t) = _aligned_malloc;
void (__cdecl *__imp__aligned_free)(void *) = _aligned_free;
