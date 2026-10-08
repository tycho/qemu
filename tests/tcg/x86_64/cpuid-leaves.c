/*
 * CPUID leaves that software walks by subleaf end the way the architecture
 * says (leaf 4 and 0x8000001D at cache type 0, 0xB, 0x1F and 0x80000026
 * at level type 0, leaves with a maximum subleaf in subleaf 0's EAX with
 * zeros above it), subleaves far past the last level give the invalid
 * level, and leaves above the reported maximum answer as the vendor's
 * processors do: zeros on AMD and Hygon, the highest basic leaf on Intel.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CAP 256

struct regs {
    uint32_t a, b, c, d;
};

static int failed;

static struct regs cpuid(uint32_t leaf, uint32_t sub)
{
    struct regs r;

    asm volatile("cpuid"
                 : "=a"(r.a), "=b"(r.b), "=c"(r.c), "=d"(r.d)
                 : "a"(leaf), "c"(sub));
    return r;
}

static void fail(const char *what, uint32_t leaf, uint32_t sub)
{
    printf("FAIL: leaf 0x%x subleaf %u: %s\n", leaf, sub, what);
    failed = 1;
}

static int cache_type_0(struct regs r)
{
    return (r.a & 0x1f) == 0;
}

static int level_type_0(struct regs r)
{
    return ((r.c >> 8) & 0xff) == 0;
}

static int topo_end(struct regs r)
{
    return ((r.c >> 8) & 0xff) == 0 && (r.b & 0xffff) == 0;
}

/* The walk must end within CAP subleaves. */
static void check_walk(uint32_t leaf, int (*stop)(struct regs))
{
    for (uint32_t s = 0; s < CAP; s++) {
        if (stop(cpuid(leaf, s))) {
            return;
        }
    }
    fail("walk doesn't end", leaf, CAP);
}

/* Subleaf 0's EAX is the last subleaf; the next ones are zero. */
static void check_max_sub(uint32_t leaf)
{
    uint32_t max = cpuid(leaf, 0).a;

    if (max > CAP) {
        fail("maximum subleaf too large", leaf, 0);
        return;
    }
    for (uint32_t s = max + 1; s <= max + 4; s++) {
        struct regs r = cpuid(leaf, s);

        if (r.a || r.b || r.c || r.d) {
            fail("non-zero above the maximum subleaf", leaf, s);
        }
    }
}

/* Subleaves far past the last level: the invalid-level answer. */
static void check_high_sub(uint32_t leaf)
{
    static const uint32_t subs[] = { 6, 64, 255 };

    for (unsigned i = 0; i < sizeof(subs) / sizeof(subs[0]); i++) {
        struct regs r = cpuid(leaf, subs[i]);

        if (r.a || (r.b & 0xffff) || ((r.c >> 8) & 0xff) ||
            (r.c & 0xff) != subs[i]) {
            fail("not the invalid level", leaf, subs[i]);
        }
    }
}

int main(void)
{
    struct regs r0 = cpuid(0, 0), top;
    uint32_t maxb = r0.a, maxe = cpuid(0x80000000, 0).a;
    char vendor[13];
    int amd;

    memcpy(vendor, &r0.b, 4);
    memcpy(vendor + 4, &r0.d, 4);
    memcpy(vendor + 8, &r0.c, 4);
    vendor[12] = 0;
    amd = !strcmp(vendor, "AuthenticAMD") || !strcmp(vendor, "HygonGenuine");

    if (maxb >= 0x4 && !amd) {
        check_walk(0x4, cache_type_0);
    }
    if (maxb >= 0x7) {
        check_max_sub(0x7);
    }
    if (maxb >= 0xb) {
        check_walk(0xb, level_type_0);
        check_high_sub(0xb);
    }
    if (maxb >= 0x1f) {
        check_walk(0x1f, level_type_0);
        check_high_sub(0x1f);
    }
    if (maxe >= 0x8000001d && amd) {
        check_walk(0x8000001d, cache_type_0);
    }
    if (amd) {
        /* Walked on AMD whatever the maximum extended leaf says. */
        check_walk(0x80000026, topo_end);
        if (maxe >= 0x80000026) {
            check_high_sub(0x80000026);
        }
    }

    /* Above the maximum: zeros on AMD, the highest basic leaf on Intel. */
    top = cpuid(maxb, 0);
    for (int i = 0; i < 2; i++) {
        uint32_t leaf = i ? maxe + 1 : maxb + 1;
        struct regs r = cpuid(leaf, 0);

        if (amd && (r.a || r.b || r.c || r.d)) {
            fail("not zero above the maximum", leaf, 0);
        }
        if (!amd && memcmp(&r, &top, sizeof(r))) {
            fail("not the highest basic leaf above the maximum", leaf, 0);
        }
    }
    return failed;
}
