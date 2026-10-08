/*
 * VEX encodings the architecture leaves undefined must raise #UD:
 * VEX forms without a 66 prefix of opcodes that are MMX instructions in
 * their legacy encoding without it (PINSRW, PEXTRW, MOVD), and VEX.L = 1
 * forms of instructions defined for VEX.128 only.  Their VEX.128 forms
 * with 66 are run as controls.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <cpuid.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

static sigjmp_buf jmp;

static void sigill(int sig)
{
    siglongjmp(jmp, 1);
}

#define INSN(name, ...)                                              \
    static void name(void)                                           \
    {                                                                \
        asm volatile(".byte " #__VA_ARGS__ : : : "eax", "xmm1");     \
    }

/* eax and xmm1 (ModRM 0xc8: reg xmm1, rm eax), xmm2 (vvvv) */
INSN(vpinsrw_66,     0xc4, 0xe1, 0x69, 0xc4, 0xc8, 0x00)
INSN(vpinsrw_00,     0xc4, 0xe1, 0x68, 0xc4, 0xc8, 0x00)
INSN(vpextrw_66,     0xc4, 0xe1, 0x79, 0xc5, 0xc1, 0x00)
INSN(vpextrw_00,     0xc4, 0xe1, 0x78, 0xc5, 0xc1, 0x00)
INSN(vmovd_to_66,    0xc4, 0xe1, 0x79, 0x6e, 0xc8)
INSN(vmovd_to_00,    0xc4, 0xe1, 0x78, 0x6e, 0xc8)
INSN(vmovd_from_66,  0xc4, 0xe1, 0x79, 0x7e, 0xc8)
INSN(vmovd_from_00,  0xc4, 0xe1, 0x78, 0x7e, 0xc8)
INSN(vmovd_from_l1,  0xc4, 0xe1, 0x7d, 0x7e, 0xc8)

static const struct {
    const char *name;
    void (*fn)(void);
    int ud;
} tests[] = {
    { "vpinsrw (66)", vpinsrw_66, 0 },
    { "vpinsrw (no 66)", vpinsrw_00, 1 },
    { "vpextrw (66)", vpextrw_66, 0 },
    { "vpextrw (no 66)", vpextrw_00, 1 },
    { "vmovd xmm, r32 (66)", vmovd_to_66, 0 },
    { "vmovd xmm, r32 (no 66)", vmovd_to_00, 1 },
    { "vmovd r32, xmm (66)", vmovd_from_66, 0 },
    { "vmovd r32, xmm (no 66)", vmovd_from_00, 1 },
    { "vmovd r32, xmm (VEX.L = 1)", vmovd_from_l1, 1 },
};

int main(void)
{
    unsigned int a, b, c, d;
    struct sigaction sa;
    int err = 0;

    if (!__get_cpuid(1, &a, &b, &c, &d) || !(c & bit_AVX)) {
        printf("SKIP: no AVX\n");
        return 0;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigill;
    sigaction(SIGILL, &sa, NULL);

    for (int i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        int ud = 0;

        if (sigsetjmp(jmp, 1)) {
            ud = 1;
        } else {
            tests[i].fn();
        }
        if (ud != tests[i].ud) {
            printf("FAIL: %s: %s\n", tests[i].name,
                   ud ? "#UD" : "no #UD");
            err = 1;
        }
    }
    return err;
}
