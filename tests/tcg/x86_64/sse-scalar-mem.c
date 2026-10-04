/*
 * Scalar SSE, AVX and FMA instructions read only their 32- or 64-bit
 * memory operand: placed in the last bytes of a page followed by an
 * unmapped page, they must not fault, and must compute what the same
 * instruction computes from a register.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096

typedef struct {
    uint64_t lo, hi;
} xmm;

static const xmm src1 = { 0x4008000040400000ull, 0x3ff8000040a00000ull };
static const xmm src2 = { 0x40000000c0e00000ull, 0xbff000003f000000ull };

/* Destination src1; source src2 in %xmm0, or its low bytes at p.  */
#define TEST(name, insn, size)                                          \
    static void name##_reg(xmm *d)                                      \
    {                                                                   \
        asm("movdqu %1, %%xmm1\n\t"                                     \
            "movdqu %2, %%xmm2\n\t"                                     \
            "movdqu %2, %%xmm0\n\t"                                     \
            insn " %%xmm0, %%xmm1\n\t"                                  \
            "movdqu %%xmm1, %0"                                         \
            : "=m"(*d) : "m"(src1), "m"(src2) : "xmm0", "xmm1", "xmm2"); \
    }                                                                   \
    static void name##_mem(xmm *d, const void *p)                       \
    {                                                                   \
        asm("movdqu %1, %%xmm1\n\t"                                     \
            "movdqu %1, %%xmm2\n\t"                                     \
            insn " (%2), %%xmm1\n\t"                                    \
            "movdqu %%xmm1, %0"                                         \
            : "=m"(*d) : "m"(src1), "r"(p) : "xmm1", "xmm2", "memory"); \
    }

#define TEST3(name, insn, size)                                         \
    static void name##_reg(xmm *d)                                      \
    {                                                                   \
        asm("movdqu %1, %%xmm1\n\t"                                     \
            "movdqu %1, %%xmm2\n\t"                                     \
            "movdqu %2, %%xmm0\n\t"                                     \
            insn " %%xmm0, %%xmm2, %%xmm1\n\t"                          \
            "movdqu %%xmm1, %0"                                         \
            : "=m"(*d) : "m"(src1), "m"(src2) : "xmm0", "xmm1", "xmm2"); \
    }                                                                   \
    static void name##_mem(xmm *d, const void *p)                       \
    {                                                                   \
        asm("movdqu %1, %%xmm1\n\t"                                     \
            "movdqu %1, %%xmm2\n\t"                                     \
            insn " (%2), %%xmm2, %%xmm1\n\t"                            \
            "movdqu %%xmm1, %0"                                         \
            : "=m"(*d) : "m"(src1), "r"(p) : "xmm1", "xmm2", "memory"); \
    }

TEST(addss, "addss", 4)
TEST(subss, "subss", 4)
TEST(mulss, "mulss", 4)
TEST(divss, "divss", 4)
TEST(minss, "minss", 4)
TEST(maxss, "maxss", 4)
TEST(sqrtss, "sqrtss", 4)
TEST(cvtss2sd, "cvtss2sd", 4)
TEST(addsd, "addsd", 8)
TEST(divsd, "divsd", 8)
TEST(sqrtsd, "sqrtsd", 8)
TEST(cvtsd2ss, "cvtsd2ss", 8)
TEST3(vdivss, "vdivss", 4)
TEST3(vmulsd, "vmulsd", 8)
TEST3(vfmadd231ss, "vfmadd231ss", 4)
TEST3(vfnmsub132ss, "vfnmsub132ss", 4)
TEST3(vfmadd213sd, "vfmadd213sd", 8)
TEST3(vfmsub231sd, "vfmsub231sd", 8)

static const struct {
    const char *name;
    void (*reg)(xmm *);
    void (*mem)(xmm *, const void *);
    int size;
    int avx;
} tests[] = {
#define T(name, size, avx) { #name, name##_reg, name##_mem, size, avx }
    T(addss, 4, 0), T(subss, 4, 0), T(mulss, 4, 0), T(divss, 4, 0),
    T(minss, 4, 0), T(maxss, 4, 0), T(sqrtss, 4, 0), T(cvtss2sd, 4, 0),
    T(addsd, 8, 0), T(divsd, 8, 0), T(sqrtsd, 8, 0), T(cvtsd2ss, 8, 0),
    T(vdivss, 4, 1), T(vmulsd, 8, 1),
    T(vfmadd231ss, 4, 2), T(vfnmsub132ss, 4, 2),
    T(vfmadd213sd, 8, 2), T(vfmsub231sd, 8, 2),
};

static int has_avx_fma(int need)
{
    uint32_t a, b, c, d;

    if (!need) {
        return 1;
    }
    asm("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
    if (!(c & (1u << 28))) {
        return 0;
    }
    return need < 2 || (c & (1u << 12));
}

int main(void)
{
    char *page = mmap(NULL, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int bad = 0;

    if (page == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }
    munmap(page + PAGE_SIZE, PAGE_SIZE);

    for (int i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        char *p = page + PAGE_SIZE - tests[i].size;
        xmm r, m;

        if (!has_avx_fma(tests[i].avx)) {
            continue;
        }
        memcpy(p, &src2, tests[i].size);
        tests[i].reg(&r);
        tests[i].mem(&m, p);
        if (memcmp(&r, &m, sizeof(r))) {
            printf("%s: register %016llx%016llx, memory %016llx%016llx\n",
                   tests[i].name,
                   (unsigned long long)r.hi, (unsigned long long)r.lo,
                   (unsigned long long)m.hi, (unsigned long long)m.lo);
            bad++;
        }
    }
    return bad ? EXIT_FAILURE : EXIT_SUCCESS;
}
