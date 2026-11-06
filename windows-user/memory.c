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

/*
 * Put back the guard on ADDR's page, which a read by the engine itself
 * took (Windows removes it as it raises the fault).  Not atomic: a
 * protection change by another thread or process between the query and
 * the change is overwritten, and another access in between finds no
 * guard.  False if the guard couldn't be put back.
 */
bool xt_guard_restore(vaddr addr)
{
    MEMORY_BASIC_INFORMATION mbi;
    PVOID base = (PVOID)(uintptr_t)(addr & TARGET_PAGE_MASK);
    SIZE_T size = TARGET_PAGE_SIZE;
    ULONG old;

    return NtQueryVirtualMemory(GetCurrentProcess(), base, 0, &mbi,
                                sizeof(mbi), NULL) >= 0 &&
           mbi.State == MEM_COMMIT &&
           NtProtectVirtualMemory(GetCurrentProcess(), &base, &size,
                                  mbi.Protect | PAGE_GUARD, &old) >= 0;
}

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

/*
 * A store by native code, outside the engine, into a page QEMU
 * write-protected for its translations: the page gets its write
 * permission back and its translations go (page_unprotect, as for a
 * guest write), so that the store can be retried.  False if QEMU hadn't
 * protected the page.
 */
bool xt_unprotect_for_native(vaddr addr)
{
    bool began, done;

    if (addr > guest_addr_max) {
        return false;
    }
    began = xt_adapter_begin();
    done = page_unprotect(NULL, addr, 0) != 0;
    xt_adapter_end(began);
    return done;
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
    /* No address: the whole process, as FlushInstructionCache's NULL. */
    if (!addr) {
        invalidate(0, (vaddr)guest_addr_max + 1);
        return;
    }
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
 * What CPUID says, for IsProcessorFeaturePresent in the guest's code, as
 * a mask of PF_ numbers: the leaves the guest reads, since OSXSAVE follows
 * CR4 rather than a feature word.  As Windows' own x86 emulator: no PAE,
 * DAZ or fast-fail feature (int 0x29 still ends the process).
 */
static uint64_t cpuid_features(CPUX86State *env)
{
    static const struct {
        uint8_t pf;
        uint8_t word;
        uint32_t bit;
    } map[] = {
        { PF_COMPARE_EXCHANGE_DOUBLE, 0, CPUID_CX8 },
        { PF_MMX_INSTRUCTIONS_AVAILABLE, 0, CPUID_MMX },
        { PF_XMMI_INSTRUCTIONS_AVAILABLE, 0, CPUID_SSE },
        { PF_RDTSC_INSTRUCTION_AVAILABLE, 0, CPUID_TSC },
        { PF_XMMI64_INSTRUCTIONS_AVAILABLE, 0, CPUID_SSE2 },
        { PF_NX_ENABLED, 2, CPUID_EXT2_NX },
        { PF_SSE3_INSTRUCTIONS_AVAILABLE, 1, CPUID_EXT_SSE3 },
        { PF_COMPARE_EXCHANGE128, 1, CPUID_EXT_CX16 },
        { PF_RDTSCP_INSTRUCTION_AVAILABLE, 2, CPUID_EXT2_RDTSCP },
        { PF_SSSE3_INSTRUCTIONS_AVAILABLE, 1, CPUID_EXT_SSSE3 },
        { PF_SSE4_1_INSTRUCTIONS_AVAILABLE, 1, CPUID_EXT_SSE41 },
        { PF_SSE4_2_INSTRUCTIONS_AVAILABLE, 1, CPUID_EXT_SSE42 },
        { PF_XSAVE_ENABLED, 1, CPUID_EXT_OSXSAVE },
        { PF_AVX2_INSTRUCTIONS_AVAILABLE, 3, CPUID_7_0_EBX_AVX2 },
    };
    uint32_t words[4], max, unused;
    uint64_t m = 0;

    cpu_x86_cpuid(env, 0, 0, &max, &unused, &unused, &unused);
    cpu_x86_cpuid(env, 1, 0, &unused, &unused, &words[1], &words[0]);
    cpu_x86_cpuid(env, 0x80000001, 0, &unused, &unused, &unused, &words[2]);
    /* Past the maximum leaf, CPUID answers the maximum's (qemu32: 4). */
    words[3] = 0;
    if (max >= 7) {
        cpu_x86_cpuid(env, 7, 0, &unused, &words[3], &unused, &unused);
    }
    for (int i = 0; i < ARRAY_SIZE(map); i++) {
        if (words[map[i].word] & map[i].bit) {
            m |= 1ull << map[i].pf;
        }
    }
    if ((words[1] & (CPUID_EXT_AVX | CPUID_EXT_OSXSAVE)) ==
        (CPUID_EXT_AVX | CPUID_EXT_OSXSAVE)) {
        m |= 1ull << PF_AVX_INSTRUCTIONS_AVAILABLE;
    }
    return m;
}

/*
 * The CPU model's features (xt_cpu_model), for the questions asked before
 * the first CPU exists: Windows asks x64 code's while the process starts,
 * and keeps the answers.  The first CPU's CPUID must say the same.
 */
#define MODEL_FEATURES                                                   \
    (1ull << PF_COMPARE_EXCHANGE_DOUBLE |                                \
     1ull << PF_MMX_INSTRUCTIONS_AVAILABLE |                             \
     1ull << PF_XMMI_INSTRUCTIONS_AVAILABLE |                            \
     1ull << PF_RDTSC_INSTRUCTION_AVAILABLE |                            \
     1ull << PF_XMMI64_INSTRUCTIONS_AVAILABLE |                          \
     1ull << PF_NX_ENABLED |                                             \
     1ull << PF_SSE3_INSTRUCTIONS_AVAILABLE |                            \
     1ull << PF_COMPARE_EXCHANGE128 |                                    \
     1ull << PF_RDTSCP_INSTRUCTION_AVAILABLE |                           \
     1ull << PF_SSSE3_INSTRUCTIONS_AVAILABLE |                           \
     1ull << PF_SSE4_1_INSTRUCTIONS_AVAILABLE |                          \
     1ull << PF_SSE4_2_INSTRUCTIONS_AVAILABLE)
#define MODEL_FEATURES_AVX2                                              \
    (MODEL_FEATURES | 1ull << PF_XSAVE_ENABLED |                         \
     1ull << PF_AVX_INSTRUCTIONS_AVAILABLE |                             \
     1ull << PF_AVX2_INSTRUCTIONS_AVAILABLE)

#ifdef TARGET_X86_64
NTSTATUS NTAPI RtlQueryEnvironmentVariable(PVOID, PCWSTR, SIZE_T, PWSTR,
                                           SIZE_T, PSIZE_T);

/*
 * XTAJIT_CPU selects the x64 module's model (a development switch): avx2
 * or unset, the AVX2 model; sse, the SSE model.  Decided at the first
 * question, which may come before the engine exists.
 */
bool xt_cpu_avx(void)
{
    static int avx = -1;

    if (avx < 0) {
        WCHAR w[8];
        SIZE_T n = 0;

        avx = RtlQueryEnvironmentVariable(NULL, L"XTAJIT_CPU", 10, w,
                                          ARRAY_SIZE(w) - 1, &n) < 0 ||
              (n == 4 && !memcmp(w, L"avx2", 4 * sizeof(WCHAR)));
    }
    return avx;
}
#else
bool xt_cpu_avx(void)
{
    return false;
}
#endif

BOOLEAN xt_feature_present(UINT feature)
{
    CPUState *cs = first_cpu;
    uint64_t model = xt_cpu_avx() ? MODEL_FEATURES_AVX2 : MODEL_FEATURES;
    uint64_t m = model;

    if (cs) {
        m = cpuid_features(cpu_env(cs));
        assert(m == model);
    }
    return feature < 64 && (m >> feature) & 1;
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
