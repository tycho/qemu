/*
 * AVX masked loads and stores (VMASKMOVPS/PD, VPMASKMOVD/Q, 128 and 256
 * bits) access only the elements whose mask bit is set: with the vector
 * placed so that its enabled elements end a page followed by an unmapped
 * page, they must not fault, and the loads must zero the other elements.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <cpuid.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096

#define LOAD(insn, reg)                                                 \
    static void ld_##insn##_##reg(const void *p, const uint8_t *mask,  \
                                  uint8_t *out)                        \
    {                                                                   \
        asm volatile("vmovdqu (%1), %%" #reg "1\n\t"                    \
                     "vpcmpeqd %%" #reg "0, %%" #reg "0, %%" #reg "0\n\t" \
                     #insn " (%0), %%" #reg "1, %%" #reg "0\n\t"        \
                     "vmovdqu %%" #reg "0, (%2)"                        \
                     : : "r"(p), "r"(mask), "r"(out)                    \
                     : "xmm0", "xmm1", "memory");                       \
    }

#define STORE(insn, reg)                                                \
    static void st_##insn##_##reg(void *p, const uint8_t *mask,        \
                                  const uint8_t *in)                   \
    {                                                                   \
        asm volatile("vmovdqu (%1), %%" #reg "1\n\t"                    \
                     "vmovdqu (%2), %%" #reg "0\n\t"                    \
                     #insn " %%" #reg "0, %%" #reg "1, (%0)"            \
                     : : "r"(p), "r"(mask), "r"(in)                     \
                     : "xmm0", "xmm1", "memory");                       \
    }

#define BOTH(insn, reg) LOAD(insn, reg) STORE(insn, reg)

BOTH(vmaskmovps, xmm)
BOTH(vmaskmovps, ymm)
BOTH(vmaskmovpd, xmm)
BOTH(vmaskmovpd, ymm)
BOTH(vpmaskmovd, xmm)
BOTH(vpmaskmovd, ymm)
BOTH(vpmaskmovq, xmm)
BOTH(vpmaskmovq, ymm)

#define CASE(insn, reg, bytes, esize) \
    { #insn " " #reg, ld_##insn##_##reg, st_##insn##_##reg, bytes, esize }

static const struct {
    const char *name;
    void (*ld)(const void *, const uint8_t *, uint8_t *);
    void (*st)(void *, const uint8_t *, const uint8_t *);
    int bytes, esize;
} cases[] = {
    CASE(vmaskmovps, xmm, 16, 4),
    CASE(vmaskmovps, ymm, 32, 4),
    CASE(vmaskmovpd, xmm, 16, 8),
    CASE(vmaskmovpd, ymm, 32, 8),
    CASE(vpmaskmovd, xmm, 16, 4),
    CASE(vpmaskmovd, ymm, 32, 4),
    CASE(vpmaskmovq, xmm, 16, 8),
    CASE(vpmaskmovq, ymm, 32, 8),
};

int main(void)
{
    unsigned a, b, c, d;
    uint8_t *m;
    int i, k, e, ret = EXIT_SUCCESS;

    if (!__get_cpuid_count(7, 0, &a, &b, &c, &d) || !(b & bit_AVX2)) {
        printf("SKIP: no AVX2\n");
        return EXIT_SUCCESS;
    }
    m = mmap(NULL, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED || munmap(m + PAGE_SIZE, PAGE_SIZE)) {
        perror("mmap");
        return EXIT_FAILURE;
    }
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int esize = cases[i].esize;

        /* k enabled elements end the page; the rest would cross it. */
        for (k = 1; k < cases[i].bytes / esize; k++) {
            uint8_t *p = m + PAGE_SIZE - k * esize;
            uint8_t mask[32] = { 0 }, want[32] = { 0 }, out[32], in[32];

            for (e = 0; e < k * esize; e++) {
                p[e] = want[e] = 0x40 + i * 16 + e;
                in[e] = 0xa0 + e;
            }
            for (e = 0; e < k; e++) {
                mask[e * esize + esize - 1] = 0x80;
            }
            memset(out, 0x55, sizeof(out));
            cases[i].ld(p, mask, out);
            if (memcmp(out, want, cases[i].bytes)) {
                printf("FAIL %s load, %d elements\n", cases[i].name, k);
                ret = EXIT_FAILURE;
            }
            cases[i].st(p, mask, in);
            if (memcmp(p, in, k * esize)) {
                printf("FAIL %s store, %d elements\n", cases[i].name, k);
                ret = EXIT_FAILURE;
            }
        }
    }
    return ret;
}
