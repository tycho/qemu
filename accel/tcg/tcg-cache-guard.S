/*
 * The translation cache's guarded routines (tcg-cache.h), for aarch64
 * hosts on Linux and Windows, the ARM64EC build included.
 *
 * The source loads are at the tcg_cache_gload* labels, which
 * tcg_cache_gloads lists; nothing else in the routines may fault on the
 * caller's behalf, and they keep LR, SP and the callee-saved registers,
 * so that a handler can return to LR with a fault code in x0.  Results:
 * 0 copied or equal, 1 different.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * In an ARM64EC build (whose compiler defines __arm64ec__, not
 * __aarch64__) C code calls a native function by the name "#name"; its
 * plain name is the C compiler's alias for it.
 */
#ifdef __arm64ec__
#define GCOPY "#tcg_cache_gcopy"
#define GCMP  "#tcg_cache_gcmp"
#else
#define GCOPY tcg_cache_gcopy
#define GCMP  tcg_cache_gcmp
#endif

        .text
        .balign 16
        .globl  GCOPY
#ifdef __ELF__
        .type   GCOPY, %function
#else
        .def    GCOPY; .scl 2; .type 32; .endef
#endif
GCOPY:
        cmp     x2, #8
        b.lo    2f
1:
        .globl  tcg_cache_gload0
tcg_cache_gload0:
        ldr     x3, [x1], #8
        str     x3, [x0], #8
        sub     x2, x2, #8
        cmp     x2, #8
        b.hs    1b
2:
        cbz     x2, 4f
3:
        .globl  tcg_cache_gload1
tcg_cache_gload1:
        ldrb    w3, [x1], #1
        strb    w3, [x0], #1
        subs    x2, x2, #1
        b.ne    3b
4:
        mov     x0, #0
        ret

        .balign 16
        .globl  GCMP
#ifdef __ELF__
        .type   GCMP, %function
#else
        .def    GCMP; .scl 2; .type 32; .endef
#endif
GCMP:
        cmp     x2, #8
        b.lo    2f
1:
        .globl  tcg_cache_gload2
tcg_cache_gload2:
        ldr     x3, [x0], #8
        .globl  tcg_cache_gload3
tcg_cache_gload3:
        ldr     x4, [x1], #8
        cmp     x3, x4
        b.ne    5f
        sub     x2, x2, #8
        cmp     x2, #8
        b.hs    1b
2:
        cbz     x2, 4f
3:
        .globl  tcg_cache_gload4
tcg_cache_gload4:
        ldrb    w3, [x0], #1
        .globl  tcg_cache_gload5
tcg_cache_gload5:
        ldrb    w4, [x1], #1
        cmp     w3, w4
        b.ne    5f
        subs    x2, x2, #1
        b.ne    3b
4:
        mov     x0, #0
        ret
5:
        mov     x0, #1
        ret

        .data
        .balign 8
        .globl  tcg_cache_gloads
tcg_cache_gloads:
        .quad   tcg_cache_gload0, tcg_cache_gload1, tcg_cache_gload2
        .quad   tcg_cache_gload3, tcg_cache_gload4, tcg_cache_gload5

#ifdef __ELF__
        .section .note.GNU-stack, "", %progbits
#endif
