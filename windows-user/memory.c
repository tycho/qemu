/*
 * xtajit: what both CPU modules do about the guest's memory as Windows
 * reports changes to it, and what they tell Windows of the processor.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "cpu.h"
#include "exec/mmap-lock.h"
#include "exec/page-protection.h"
#include "user/page-protection.h"
#include "xtajit.h"

NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE, PVOID, int, PVOID, SIZE_T,
                                    PSIZE_T);

/* The first page in the range that QEMU write-protected. */
int xt_find_protected(void *opaque, vaddr start, vaddr end, int flags)
{
    XtUnprotect *u = opaque;

    if (!(flags & PAGE_WRITE_ORG) || (flags & PAGE_WRITE) ||
        end - 1 < u->start || start > u->last) {
        return 0;
    }
    u->found = MAX(start, u->start);
    return 1;
}

/*
 * Memory notifications.  QEMU's page flags for the range are dropped
 * (with the translations of executable pages) and refilled from Windows
 * when next probed (xt_mem_refresh):
 * - after a change that keeps the range the caller's (an allocation, a
 *   protection change, a view mapped): Windows' protection is then what
 *   the caller asked for, except on pages QEMU write-protected since for
 *   their new translations.  Those keep their flags: dropping them would
 *   lose that the protection is QEMU's, and the next write would be the
 *   guest's fault;
 * - before a free or an unmap, while the range is still the caller's:
 *   after it, another thread may have it already.
 */
static bool protected_since(vaddr page, ULONG prot)
{
    MEMORY_BASIC_INFORMATION mbi;

    return NtQueryVirtualMemory(GetCurrentProcess(), (void *)(uintptr_t)page,
                                0, &mbi, sizeof(mbi), NULL) >= 0 &&
           (mbi.Protect & 0xff) != (prot & 0xff);
}

void xt_mem_forget(int kind, ULONG prot, vaddr start, vaddr len)
{
    vaddr from, last;
    bool began, keep = kind == 1 || kind == 2 || kind == 4;

    if (xt_tls_ready() && xt_self) {
        xt_event(xt_self, XT_EV_MEMNOTE, (uint64_t)kind << 56 |
                 (uint64_t)(prot & 0xffffff) << 32 | (len & 0xffffffff),
                 start);
    }
    if (!len || start > guest_addr_max) {
        return;
    }
    from = start & TARGET_PAGE_MASK;
    last = MIN(start + len - 1, (vaddr)guest_addr_max) | ~TARGET_PAGE_MASK;
    began = xt_adapter_begin();
    mmap_lock();
    while (keep && from <= last) {
        XtUnprotect u = { from, last };
        vaddr page;

        if (!walk_memory_regions(&u, xt_find_protected)) {
            break;
        }
        page = u.found & TARGET_PAGE_MASK;
        if (protected_since(page, prot)) {
            if (page > from) {
                page_set_flags(from, page - 1, 0, PAGE_VALID);
                xt_guest_prot_forget(from, page - 1);
            }
        } else {
            page_set_flags(from, page | ~TARGET_PAGE_MASK, 0, PAGE_VALID);
            xt_guest_prot_forget(from, page | ~TARGET_PAGE_MASK);
        }
        from = page + TARGET_PAGE_SIZE;
    }
    if (from <= last) {
        page_set_flags(from, last, 0, PAGE_VALID);
        xt_guest_prot_forget(from, last);
    }
    mmap_unlock();
    xt_adapter_end(began);
}

/* Translations of [start, start + len) go, as for a host write. */
static void invalidate(vaddr start, vaddr len)
{
    bool began = xt_adapter_begin();

    if (xt_tls_ready() && xt_self) {
        xt_event(xt_self, XT_EV_MEMNOTE, (uint64_t)6 << 56 |
                 (len & 0xffffffff), start);
    }

    xt_invalidate(start, len);
    xt_adapter_end(began);
}

/*
 * Before the guest changes a protection, pages QEMU write-protected for
 * their translations get their write permission back (page_unprotect: the
 * translations go), so that the old protection Windows reports is the
 * guest's, not QEMU's.  Queries (NtQueryVirtualMemory) still see QEMU's.
 */
static void unprotect_range(vaddr start, vaddr len)
{
    XtUnprotect u = { start, MIN(start + len - 1, (vaddr)guest_addr_max) };

    bool began;

    if (!len || start > guest_addr_max) {
        return;
    }
    began = xt_adapter_begin();
    mmap_lock();
    while (walk_memory_regions(&u, xt_find_protected)) {
        page_unprotect(NULL, u.found, 0);
    }
    mmap_unlock();
    xt_adapter_end(began);
}

/* The allocation ADDR is in: its base and extent. */
static vaddr allocation_extent(void *addr, vaddr *len)
{
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t base, p;

    *len = 0;
    if (NtQueryVirtualMemory(GetCurrentProcess(), addr, 0, &mbi,
                             sizeof(mbi), NULL) < 0) {
        return 0;
    }
    base = (uintptr_t)mbi.AllocationBase;
    for (p = base;; p += mbi.RegionSize) {
        if (NtQueryVirtualMemory(GetCurrentProcess(), (void *)p, 0, &mbi,
                                 sizeof(mbi), NULL) < 0 ||
            (uintptr_t)mbi.AllocationBase != base) {
            break;
        }
    }
    *len = p - base;
    return base;
}

/*
 * The notifications both modules get, as Windows describes them: before
 * (AFTER false) and after a change, with its status.
 */
void xt_note_flush(const void *addr, SIZE_T len)
{
    invalidate((uintptr_t)addr, len);
}

void xt_note_alloc(void *addr, SIZE_T len, ULONG type, ULONG prot, BOOL after,
                   NTSTATUS status)
{
    if (after && !status && !(type & (MEM_RESET | MEM_RESET_UNDO))) {
        xt_mem_forget(1, prot, (uintptr_t)addr, len);
    }
}

void xt_note_protect(void *addr, SIZE_T len, ULONG prot, BOOL after,
                     NTSTATUS status)
{
    if (!after) {
        unprotect_range((uintptr_t)addr, len);
    } else if (!status) {
        xt_mem_forget(2, prot, (uintptr_t)addr, len);
    }
}

/* Before: a released allocation with no size given goes whole. */
void xt_note_free(void *addr, SIZE_T len, ULONG type, BOOL after,
                  NTSTATUS status)
{
    vaddr start = (uintptr_t)addr, n = len;

    if (after) {
        return;
    }
    if (!n && (type & MEM_RELEASE)) {
        start = allocation_extent(addr, &n);
    }
    xt_mem_forget(3, 0, start, n);
}

void xt_note_map(void *addr, SIZE_T len, ULONG prot)
{
    xt_mem_forget(4, prot, (uintptr_t)addr, len);
}

/* Before: the whole view. */
void xt_note_unmap(void *addr, BOOL after)
{
    vaddr start, len;

    if (!after) {
        start = allocation_extent(addr, &len);
        xt_mem_forget(5, 0, start, len);
    }
}

/*
 * Before: pages QEMU write-protected in the buffer get write back (their
 * translations go), or the kernel's write into them fails the read.
 */
void xt_note_read_file(void *addr, SIZE_T len, BOOL after, NTSTATUS status)
{
    if (!after) {
        unprotect_range((uintptr_t)addr, len);
    } else if (!status) {
        invalidate((uintptr_t)addr, len);
    }
}

/*
 * What CPUID says, for IsProcessorFeaturePresent in the guest's code.  As
 * Windows' own x86 emulator: no PAE, DAZ or fast-fail feature (int 0x29
 * still ends the process).
 */
BOOLEAN xt_feature_present(UINT feature)
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
 * The processor's identity for the guest's code (GetSystemInfo and
 * NtQuerySystemInformation): ARCH, level the CPUID family, revision its
 * model and stepping, as x86 Windows derives them.  Windows fills in the
 * rest of SYSTEM_CPU_INFORMATION.
 */
void xt_processor_info(void *info, USHORT arch)
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
    f[0] = arch;
    f[1] = family;
    f[2] = model << 8 | (eax & 0xf);
}
