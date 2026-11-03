/*
 * The module's allocator: rpmalloc (rpmalloc/, public domain or MIT, as
 * FEX-Emu/rpmalloc ed22744 carries it), with its memory above 4 GiB.
 *
 * In a WOW64 process everything below 4 GiB is the guest's address
 * space, so the allocator maps its spans above it, as xt_alloc_high
 * does.  rpmalloc reserves a span and commits its pages as it uses them.
 * Its per-thread heap pointer is a thread-local variable of the module;
 * a thread's heap is given back at its exit (xt_crt_thread_fini).
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <winternl.h>
#include "runtime.h"
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

void xt_heap_thread_fini(void)
{
    rpmalloc_thread_finalize();
}

void *__cdecl malloc(size_t size)
{
    return rpmalloc(size);
}

void *__cdecl calloc(size_t n, size_t size)
{
    return rpcalloc(n, size);
}

void *__cdecl realloc(void *p, size_t size)
{
    return rprealloc(p, size);
}

void __cdecl free(void *p)
{
    rpfree(p);
}

/* Small aligned blocks; xt_aligned_malloc (runtime.c) takes large ones. */
void *xt_heap_aligned(size_t size, size_t align)
{
    return rpaligned_alloc(align, size);
}

XT_IMPORT_SLOT(malloc);
XT_IMPORT_SLOT(calloc);
XT_IMPORT_SLOT(realloc);
XT_IMPORT_SLOT(free);
