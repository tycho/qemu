/*
 * xtajit: setjmp and longjmp for ARM64EC code, which never unwind the
 * stack (generated code has no unwind data).  mingw-w64 builds its
 * __mingw_setjmp and __mingw_longjmp for AArch64 only.  The buffer holds
 * x19-x30, sp and d8-d15, 168 bytes of the 256 in an x64 jmp_buf.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

    .text
    .balign 4

    .globl "#__mingw_setjmp"
    .def "#__mingw_setjmp"; .scl 2; .type 32; .endef
"#__mingw_setjmp":
    stp     x19, x20, [x0, #0]
    stp     x21, x22, [x0, #16]
    stp     x23, x24, [x0, #32]
    stp     x25, x26, [x0, #48]
    stp     x27, x28, [x0, #64]
    stp     x29, x30, [x0, #80]
    mov     x16, sp
    str     x16, [x0, #96]
    stp     d8, d9, [x0, #104]
    stp     d10, d11, [x0, #120]
    stp     d12, d13, [x0, #136]
    stp     d14, d15, [x0, #152]
    mov     w0, #0
    ret

    .globl "#__mingw_longjmp"
    .def "#__mingw_longjmp"; .scl 2; .type 32; .endef
"#__mingw_longjmp":
    ldp     x19, x20, [x0, #0]
    ldp     x21, x22, [x0, #16]
    ldp     x23, x24, [x0, #32]
    ldp     x25, x26, [x0, #48]
    ldp     x27, x28, [x0, #64]
    ldp     x29, x30, [x0, #80]
    ldr     x16, [x0, #96]
    mov     sp, x16
    ldp     d8, d9, [x0, #104]
    ldp     d10, d11, [x0, #120]
    ldp     d12, d13, [x0, #136]
    ldp     d14, d15, [x0, #152]
    cmp     w1, #0
    csinc   w0, w1, wzr, ne
    ret
