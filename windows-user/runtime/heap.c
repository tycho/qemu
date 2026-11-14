/*
 * The module's allocator: rpmalloc (rpmalloc/, public domain or MIT, as
 * FEX-Emu/rpmalloc ed22744 carries it), with its memory above 4 GiB.
 *
 * In a WOW64 process everything below 4 GiB is the guest's address
 * space, so the allocator maps its spans above it, as xt_alloc_high
 * does.  rpmalloc reserves a span and commits its pages as it uses them.
 * Its per-thread heap pointer is a thread-local variable of the module.
 * A thread's heap is given back when its record goes (xt_heap_release,
 * which works from any thread: a thread's TLS may be gone by then), or
 * at its exit (xt_crt_thread_fini), for the next thread to take.  A
 * thread allocating after that (ntdll's exit path notifies the module)
 * uses one shared heap, under a lock: a heap of its own would never be
 * given back.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <winternl.h>
#include "runtime.h"
#define RPMALLOC_FIRST_CLASS_HEAPS 1
#include "rpmalloc/rpmalloc.h"

#define HIGH_BASE 0x100000000ull

static void *high_map(size_t size, size_t align, size_t *offset,
                      size_t *mapped_size)
{
    XtBasicInfo sbi;
    MEM_ADDRESS_REQUIREMENTS req = { 0 };
    MEM_EXTENDED_PARAMETER ext = { 0 };
    PVOID base = NULL;
    SIZE_T len = size;

    if (NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi),
                                 NULL) < 0) {
        return NULL;
    }
    req.LowestStartingAddress = (void *)HIGH_BASE;
    req.HighestEndingAddress = (void *)sbi.MaximumUserModeAddress;
    /* Any power of two from the allocation granule up. */
    req.Alignment = align > sbi.AllocationGranularity ? align : 0;
    ext.Type = MemExtendedParameterAddressRequirements;
    ext.Pointer = &req;
    if (NtAllocateVirtualMemoryEx(GetCurrentProcess(), &base, &len,
                                  MEM_RESERVE, PAGE_READWRITE, &ext, 1) < 0) {
        return NULL;
    }
    *offset = 0;
    *mapped_size = len;
    return base;
}

static void high_commit(void *addr, size_t size)
{
    PVOID base = addr;
    SIZE_T len = size;

    if (NtAllocateVirtualMemory(GetCurrentProcess(), &base, 0, &len,
                                MEM_COMMIT, PAGE_READWRITE) < 0) {
        xt_fatal("heap: commit failed");
    }
}

static void high_decommit(void *addr, size_t size)
{
    PVOID base = addr;
    SIZE_T len = size;

    NtFreeVirtualMemory(GetCurrentProcess(), &base, &len, MEM_DECOMMIT);
}

static void high_unmap(void *addr, size_t offset, size_t mapped_size)
{
    PVOID base = (char *)addr - offset;
    SIZE_T len = 0;

    NtFreeVirtualMemory(GetCurrentProcess(), &base, &len, MEM_RELEASE);
}

static rpmalloc_interface_t high_memory = {
    .memory_map = high_map,
    .memory_commit = high_commit,
    .memory_decommit = high_decommit,
    .memory_unmap = high_unmap,
};

void xt_heap_init(void)
{
    rpmalloc_initialize(&high_memory);
}

void xt_heap_thread_init(void)
{
    rpmalloc_thread_initialize();
}

static __thread bool heap_given_back;
static rpmalloc_heap_t *late_heap;
static int late_lock;

void xt_heap_thread_fini(void)
{
    rpmalloc_thread_finalize();
    heap_given_back = true;
}

/* The calling thread's heap, NULL before its first allocation. */
void *xt_heap_current(void)
{
    return rpmalloc_thread_heap();
}

/* A thread's heap given back; the calling thread's own, or another's. */
void xt_heap_release(void *heap)
{
    if (heap && heap == rpmalloc_thread_heap()) {
        heap_given_back = true;
    }
    rpmalloc_thread_heap_release(heap);
}

static rpmalloc_heap_t *late_begin(void)
{
    while (__atomic_exchange_n(&late_lock, 1, __ATOMIC_ACQUIRE)) {
        NtYieldExecution();
    }
    if (!late_heap) {
        late_heap = rpmalloc_heap_acquire();
    }
    return late_heap;
}

static void late_end(void)
{
    __atomic_store_n(&late_lock, 0, __ATOMIC_RELEASE);
}

void *__cdecl malloc(size_t size)
{
    void *p;

    if (!heap_given_back) {
        return rpmalloc(size);
    }
    p = rpmalloc_heap_alloc(late_begin(), size);
    late_end();
    return p;
}

void *__cdecl calloc(size_t n, size_t size)
{
    void *p;

    if (!heap_given_back) {
        return rpcalloc(n, size);
    }
    p = rpmalloc_heap_calloc(late_begin(), n, size);
    late_end();
    return p;
}

void *__cdecl realloc(void *p, size_t size)
{
    void *q;

    if (!heap_given_back) {
        return rprealloc(p, size);
    }
    q = rpmalloc_heap_realloc(late_begin(), p, size, 0);
    late_end();
    return q;
}

void __cdecl free(void *p)
{
    rpfree(p);
}

/* Small aligned blocks; xt_aligned_malloc (runtime.c) takes large ones. */
void *xt_heap_aligned(size_t size, size_t align)
{
    void *p;

    if (!heap_given_back) {
        return rpaligned_alloc(align, size);
    }
    p = rpmalloc_heap_aligned_alloc(late_begin(), align, size);
    late_end();
    return p;
}

XT_IMPORT_SLOT(malloc);
XT_IMPORT_SLOT(calloc);
XT_IMPORT_SLOT(realloc);
XT_IMPORT_SLOT(free);
