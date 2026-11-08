/*
 * xtajit: what the translation cache (tcg-cache.h) needs from Windows:
 * which guest pages hold image code, which image each is in, and the
 * follow-up of a guarded routine's fault.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "tcg/tcg-cache.h"
#include "exec/mmap-lock.h"
#include "accel/tcg/tb-context.h"
#include "exec/page-protection.h"
#include "user/page-protection.h"
#include "xtajit.h"

NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE, PVOID, int, PVOID, SIZE_T,
                                    PSIZE_T);
NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID *, ULONG_PTR, PSIZE_T,
                                       ULONG, ULONG);
NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE, PVOID *, PSIZE_T, ULONG);

#define MEMORY_MAPPED_FILENAME_INFORMATION 2

/*
 * The catalogue, under mmap_lock: the regions queried so far (Windows'
 * runs of pages with one protection), each with the image its allocation
 * is, or none; and the images, one per allocation base.  An image's
 * identity hashes its file's path, upper-cased, and its PE header's
 * TimeDateStamp, SizeOfImage and CheckSum.  The memory notifications
 * drop what they reach (xt_cache_forget).
 */
typedef struct XtImage {
    uintptr_t base;
    uint64_t id;
    unsigned gen;
} XtImage;

typedef struct XtRegion {
    uintptr_t start, last;
    XtImage *img;           /* NULL: not an image's */
} XtRegion;

static XtRegion *regions;
static size_t n_regions, max_regions;
static XtImage **images;
static size_t n_images, max_images;
static unsigned image_gen;
static int last_region = -1;

int xt_cache_inj;
static unsigned inj_count;
static ULONG inj_old;
static bool inj_on;

XtCacheStats xt_cache_stats;

static uint64_t fnv(uint64_t h, const void *p, size_t n)
{
    const uint8_t *b = p;

    for (size_t i = 0; i < n; i++) {
        h = (h ^ b[i]) * 0x100000001b3ull;
    }
    return h;
}

/* The identity of the image at BASE, false if it can't be read. */
static bool image_identity(uintptr_t base, uint64_t *id)
{
    union {
        UNICODE_STRING us;
        uint8_t raw[1024];
    } name;
    uint8_t dos[64], nt[4 + 20 + 72];
    uint32_t lfanew, stamp, size, sum;
    uint64_t h = 0xcbf29ce484222325ull;
    int64_t r;

    if (NtQueryVirtualMemory(GetCurrentProcess(), (void *)base,
                             MEMORY_MAPPED_FILENAME_INFORMATION, &name,
                             sizeof(name) - sizeof(WCHAR), NULL) < 0) {
        return false;
    }
    for (USHORT i = 0; i < name.us.Length / sizeof(WCHAR); i++) {
        WCHAR c = name.us.Buffer[i];

        if (c >= 'a' && c <= 'z') {
            c -= 'a' - 'A';
        }
        h = fnv(h, &c, sizeof(c));
    }
    r = tcg_cache_gcopy(dos, (void *)base, sizeof(dos));
    if (r) {
        xt_cache_fault(r);
        return false;
    }
    memcpy(&lfanew, dos + 0x3c, 4);
    if (dos[0] != 'M' || dos[1] != 'Z' || lfanew > 4096 - sizeof(nt)) {
        return false;
    }
    r = tcg_cache_gcopy(nt, (void *)(base + lfanew), sizeof(nt));
    if (r) {
        xt_cache_fault(r);
        return false;
    }
    if (memcmp(nt, "PE\0\0", 4)) {
        return false;
    }
    /* FileHeader.TimeDateStamp; OptionalHeader.SizeOfImage, CheckSum. */
    memcpy(&stamp, nt + 4 + 4, 4);
    memcpy(&size, nt + 24 + 56, 4);
    memcpy(&sum, nt + 24 + 64, 4);
    h = fnv(h, &stamp, 4);
    h = fnv(h, &size, 4);
    *id = fnv(h, &sum, 4);
    return true;
}

static XtImage *image_at(uintptr_t base)
{
    XtImage *img;
    uint64_t id;
    int64_t t0 = get_clock();

    for (size_t i = 0; i < n_images; i++) {
        if (images[i]->base == base) {
            return images[i];
        }
    }
    xt_cache_stats.identities++;
    if (!image_identity(base, &id)) {
        xt_cache_stats.identity_fail++;
        xt_cache_stats.query_ns += get_clock() - t0;
        return NULL;
    }
    img = g_new(XtImage, 1);
    *img = (XtImage){ .base = base, .id = id, .gen = ++image_gen };
    if (n_images == max_images) {
        max_images = max_images ? max_images * 2 : 64;
        images = g_renew(XtImage *, images, max_images);
    }
    images[n_images++] = img;
    xt_cache_stats.query_ns += get_clock() - t0;
    return img;
}

/* The index of the region holding ADDR, or -1. */
static int region_find(uintptr_t addr)
{
    int lo = 0, hi = (int)n_regions - 1, at = -1;

    if (last_region >= 0 && last_region < n_regions &&
        regions[last_region].start <= addr &&
        addr <= regions[last_region].last) {
        return last_region;
    }
    while (lo <= hi) {
        int mid = (lo + hi) / 2;

        if (regions[mid].start <= addr) {
            at = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    if (at >= 0 && addr <= regions[at].last) {
        last_region = at;
        return at;
    }
    return -1;
}

/* Drop the regions that overlap [START, LAST], or that are IMG's. */
static void regions_drop(uintptr_t start, uintptr_t last, XtImage *img)
{
    size_t j = 0;

    for (size_t i = 0; i < n_regions; i++) {
        XtRegion *r = &regions[i];

        if ((img && r->img == img) ||
            (!img && r->start <= last && start <= r->last)) {
            continue;
        }
        regions[j++] = *r;
    }
    n_regions = j;
    last_region = -1;
}

static int region_add(uintptr_t start, uintptr_t last, XtImage *img)
{
    size_t at = 0;

    regions_drop(start, last, NULL);
    while (at < n_regions && regions[at].start < start) {
        at++;
    }
    if (n_regions == max_regions) {
        max_regions = max_regions ? max_regions * 2 : 256;
        regions = g_renew(XtRegion, regions, max_regions);
    }
    memmove(&regions[at + 1], &regions[at],
            (n_regions - at) * sizeof(*regions));
    regions[at] = (XtRegion){ start, last, img };
    n_regions++;
    return at;
}

/*
 * A page is eligible when its translations are never checked
 * (PAGE_FIXED_CODE: committed image memory that isn't writable, outside
 * this module), it is executable, nothing can write it, and it is in an
 * image the catalogue could identify.
 */
static bool page_image(vaddr page, TCGCacheImage *out)
{
    int want = PAGE_VALID | PAGE_EXEC | PAGE_FIXED_CODE;
    MEMORY_BASIC_INFORMATION mbi;
    XtImage *img = NULL;
    int i;

    if ((page_get_flags(page) & (want | PAGE_WRITE | PAGE_WRITE_ORG))
        != want) {
        return false;
    }
    i = region_find(page);
    if (i < 0) {
        int64_t t0 = get_clock();

        xt_cache_stats.queries++;
        if (NtQueryVirtualMemory(GetCurrentProcess(), (void *)(uintptr_t)page,
                                 0, &mbi, sizeof(mbi), NULL) < 0) {
            xt_cache_stats.query_ns += get_clock() - t0;
            return false;
        }
        xt_cache_stats.query_ns += get_clock() - t0;
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE &&
            !xt_is_own_image(mbi.AllocationBase)) {
            img = image_at((uintptr_t)mbi.AllocationBase);
        }
        i = region_add((uintptr_t)mbi.BaseAddress,
                       (uintptr_t)mbi.BaseAddress + mbi.RegionSize - 1, img);
        last_region = i;
    }
    img = regions[i].img;
    if (!img) {
        return false;
    }
    out->id = img->id;
    out->base = img->base;
    return true;
}

/* A guarded routine's fault: a guard page's guard goes back. */
void xt_cache_fault(int64_t code)
{
    vaddr addr = code & (TCG_CACHE_GFAULT_GUARD - 1);

    xt_cache_stats.faults++;
    if (code & TCG_CACHE_GFAULT_GUARD) {
        if (xt_guard_restore(addr)) {
            xt_cache_stats.guard_back++;
        } else {
            tcg_cache_stats.guard_lost++;
        }
    }
}

/*
 * Testing (cacheinj=): every eighth comparison of a candidate's bytes, a
 * native change to the page Windows doesn't notify, undone afterwards:
 * the page inaccessible, a guard added, or one byte changed.
 */
static void inject(vaddr addr, bool before)
{
    PVOID base = (PVOID)(uintptr_t)(addr & TARGET_PAGE_MASK);
    SIZE_T size = TARGET_PAGE_SIZE;
    MEMORY_BASIC_INFORMATION mbi;
    ULONG old;

    if (before) {
        if (++inj_count % 8 ||
            NtQueryVirtualMemory(GetCurrentProcess(), base, 0, &mbi,
                                 sizeof(mbi), NULL) < 0) {
            return;
        }
        inj_old = mbi.Protect;
        switch (xt_cache_inj) {
        case XT_CACHE_INJ_NOACCESS:
            inj_on = NtProtectVirtualMemory(GetCurrentProcess(), &base, &size,
                                            PAGE_NOACCESS, &old) >= 0;
            break;
        case XT_CACHE_INJ_GUARD:
            inj_on = NtProtectVirtualMemory(GetCurrentProcess(), &base, &size,
                                            inj_old | PAGE_GUARD, &old) >= 0;
            break;
        case XT_CACHE_INJ_BYTE:
            inj_on = NtProtectVirtualMemory(GetCurrentProcess(), &base, &size,
                                            PAGE_EXECUTE_READWRITE,
                                            &old) >= 0;
            if (inj_on) {
                *(uint8_t *)(uintptr_t)addr ^= 0x40;
            }
            break;
        }
        xt_cache_stats.injected += inj_on;
        return;
    }
    if (!inj_on) {
        return;
    }
    inj_on = false;
    if (xt_cache_inj == XT_CACHE_INJ_GUARD &&
        NtQueryVirtualMemory(GetCurrentProcess(), base, 0, &mbi, sizeof(mbi),
                             NULL) >= 0 && (mbi.Protect & PAGE_GUARD)) {
        xt_cache_stats.inj_guard_seen++;
    }
    if (xt_cache_inj == XT_CACHE_INJ_BYTE) {
        *(uint8_t *)(uintptr_t)addr ^= 0x40;
    }
    NtProtectVirtualMemory(GetCurrentProcess(), &base, &size, inj_old, &old);
}

static const TCGCacheHost xt_cache_host = {
    .page_image = page_image,
    .copy = tcg_cache_gcopy,
    .compare = tcg_cache_gcmp,
    .fault = xt_cache_fault,
};

static const TCGCacheHost xt_cache_host_inj = {
    .page_image = page_image,
    .copy = tcg_cache_gcopy,
    .compare = tcg_cache_gcmp,
    .fault = xt_cache_fault,
    .inject = inject,
};

static void out_log(const char *line)
{
    xt_log_text(line);
}

void xt_cache_init(void)
{
    tcg_cache_host = xt_cache_inj ? &xt_cache_host_inj : &xt_cache_host;
    if (xt_log_handle()) {
        tcg_cache_out = out_log;
    }
}

/*
 * A memory notification reached [START, LAST]: the regions it overlaps
 * go, and on a free or an unmap (kinds 3 and 5) the images based there
 * with all their regions.  Called with mmap_lock held.
 */
void xt_cache_forget(int kind, vaddr start, vaddr last)
{
    if (!n_regions && !n_images) {
        return;
    }
    regions_drop(start, last, NULL);
    if (kind != 3 && kind != 5) {
        return;
    }
    for (size_t i = 0; i < n_images;) {
        XtImage *img = images[i];

        if (img->base >= start && img->base <= last) {
            regions_drop(0, 0, img);
            images[i] = images[--n_images];
            g_free(img);
            xt_cache_stats.images_dropped++;
        } else {
            i++;
        }
    }
}

void xt_cache_print_stats(void)
{
    XtCacheStats *t = &xt_cache_stats;

    fprintf(stderr, "xtcg-cache: catalogue: queries %" PRIu64 " identities %"
            PRIu64 " (failed %" PRIu64 ") %.3f ms, images %zu (dropped %"
            PRIu64 "), regions %zu; guarded faults %" PRIu64
            " (guard back %" PRIu64 "); injected %" PRIu64
            " (guard seen back %" PRIu64 "); flushes completed %u\n",
            t->queries, t->identities, t->identity_fail, t->query_ns / 1e6,
            n_images, t->images_dropped, n_regions, t->faults, t->guard_back,
            t->injected, t->inj_guard_seen,
            qatomic_read(&tb_ctx.tb_flush_count));
}

static void dump_one(void *opaque, uint64_t id, uint64_t rva, uint64_t base,
                     const void *art, size_t len)
{
    char line[200];

    if (tcg_cache_dump_line(line, sizeof(line), id, rva, base, art, len)) {
        xt_log_text(line);
    }
}

void xt_cache_dump(void)
{
    if (xt_log_handle()) {
        tcg_cache_store_foreach(dump_one, NULL);
    }
}

/*
 * Testing (cacheselftest): the guarded routines, on two pages above
 * 4 GiB whose second is inaccessible, then with a guard; and the fault
 * follow-up when the guard can't go back.
 */
void xt_cache_selftest(void)
{
    PVOID base = (PVOID)0x6f00000000ull, p2;
    SIZE_T size = 2 * TARGET_PAGE_SIZE, one = TARGET_PAGE_SIZE;
    MEMORY_BASIC_INFORMATION mbi;
    uint8_t buf[32];
    int fails;
    ULONG old;
    int64_t r;

    if (NtAllocateVirtualMemory(GetCurrentProcess(), &base, 0, &size,
                                MEM_RESERVE | MEM_COMMIT,
                                PAGE_READWRITE) < 0) {
        base = NULL;
        size = 2 * TARGET_PAGE_SIZE;
        if (NtAllocateVirtualMemory(GetCurrentProcess(), &base, 0, &size,
                                    MEM_RESERVE | MEM_COMMIT,
                                    PAGE_READWRITE) < 0) {
            fprintf(stderr, "xtcg-cache selftest: no memory\n");
            return;
        }
    }
    p2 = (uint8_t *)base + TARGET_PAGE_SIZE;
    NtProtectVirtualMemory(GetCurrentProcess(), &p2, &one, PAGE_NOACCESS,
                           &old);
    fails = tcg_cache_selftest(base, TARGET_PAGE_SIZE);

    /* A guard: the fault code says so, and the guard goes back. */
    p2 = (uint8_t *)base + TARGET_PAGE_SIZE;
    one = TARGET_PAGE_SIZE;
    NtProtectVirtualMemory(GetCurrentProcess(), &p2, &one,
                           PAGE_READWRITE | PAGE_GUARD, &old);
    r = tcg_cache_gcopy(buf, (uint8_t *)base + TARGET_PAGE_SIZE - 4, 16);
    if (!(r & TCG_CACHE_GFAULT) || !(r & TCG_CACHE_GFAULT_GUARD)) {
        fprintf(stderr, "xtcg-cache selftest: guard: %" PRIx64 "\n", r);
        fails++;
    } else {
        xt_cache_fault(r);
        if (NtQueryVirtualMemory(GetCurrentProcess(), p2, 0, &mbi,
                                 sizeof(mbi), NULL) < 0 ||
            !(mbi.Protect & PAGE_GUARD)) {
            fprintf(stderr, "xtcg-cache selftest: guard not back\n");
            fails++;
        }
    }
    fprintf(stderr, "xtcg-cache selftest: guard address %" PRIx64
            " (page %p)\n", r & (TCG_CACHE_GFAULT_GUARD - 1), p2);

    /* The guard can't go back to freed memory: counted, not fatal. */
    size = 0;
    NtFreeVirtualMemory(GetCurrentProcess(), &base, &size, MEM_RELEASE);
    {
        uint64_t lost = tcg_cache_stats.guard_lost;

        xt_cache_fault(r);
        if (tcg_cache_stats.guard_lost != lost + 1) {
            fprintf(stderr, "xtcg-cache selftest: lost guard not counted\n");
            fails++;
        }
        tcg_cache_stats.guard_lost = lost;
    }
    fprintf(stderr, "xtcg-cache selftest (module): %d failed\n", fails);
}
