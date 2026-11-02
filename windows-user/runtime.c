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
#include "xtajit.h"

NTSTATUS NTAPI NtCreateThreadEx(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T,
                                SIZE_T, PVOID);
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
    xt_crt_thread_init();
    g_free(p);
    xt_placement("internal thread stack", &s);
    RtlExitUserThread(s.fn(s.arg));
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

void __cdecl _endthreadex(unsigned code)
{
    RtlExitUserThread(code);
    __builtin_unreachable();
}

XT_IMPORT_SLOT(_beginthreadex);
XT_IMPORT_SLOT(_endthreadex);

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

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
