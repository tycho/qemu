/*
 * xtajit: the x64 module's capture probe (test only).  xt_cap_loop fills
 * every general-purpose and vector register it may with a known value,
 * spins, and stores them all back, so the harness can see what an
 * interruption (suspension, a context change, an APC, a fault) kept.  It
 * is position-independent: the harness runs it in place and from an
 * executable allocation, as generated code would be.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* XtCapRun, test-ec.c */
#define CAP_IN_X        0x000
#define CAP_IN_V        0x0f0
#define CAP_OUT_X       0x2f0
#define CAP_OUT_V       0x3e0
#define CAP_ITERS       0x5e0
#define CAP_DOORBELL    0x5e8
#define CAP_REQ         0x5f0
#define CAP_RESIM       0x5f4
#define CAP_STACK       0x5f8
#define CAP_SAVED_SP    0x600

#define TEB_CPU_AREA    0x1788

    .text
    .balign 16

/*
 * void xt_cap_loop(XtCapRun *r): x19 holds r; x29 and x30 are the loop's
 * scratch registers; x18 is the TEB.  Every other register, x0-x28 and
 * v0-v31, holds r's value throughout.  Each iteration:
 *   - with r->doorbell set, a nonzero doorbell word executes xt_cap_trap;
 *   - a nonzero r->req loads from that address, at xt_cap_fault;
 * the module's ResetToConsistentState continues either at xt_cap_cont,
 * which sets InSimulation again when r->resim asks for it.
 */
    .globl xt_cap_loop
xt_cap_loop:
    stp     x29, x30, [sp, #-160]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x25, x26, [sp, #64]
    stp     x27, x28, [sp, #80]
    stp     d8, d9, [sp, #96]
    stp     d10, d11, [sp, #112]
    stp     d12, d13, [sp, #128]
    stp     d14, d15, [sp, #144]
    mov     x19, x0
    mov     x9, sp
    str     x9, [x19, #CAP_SAVED_SP]
    ldr     x9, [x19, #CAP_STACK]
    cbz     x9, 1f
    mov     sp, x9
1:
    add     x9, x19, #CAP_IN_V
    ldp     q0, q1, [x9, #0]
    ldp     q2, q3, [x9, #32]
    ldp     q4, q5, [x9, #64]
    ldp     q6, q7, [x9, #96]
    ldp     q8, q9, [x9, #128]
    ldp     q10, q11, [x9, #160]
    ldp     q12, q13, [x9, #192]
    ldp     q14, q15, [x9, #224]
    ldp     q16, q17, [x9, #256]
    ldp     q18, q19, [x9, #288]
    ldp     q20, q21, [x9, #320]
    ldp     q22, q23, [x9, #352]
    ldp     q24, q25, [x9, #384]
    ldp     q26, q27, [x9, #416]
    ldp     q28, q29, [x9, #448]
    ldp     q30, q31, [x9, #480]
    ldp     x0, x1, [x19, #0]
    ldp     x2, x3, [x19, #16]
    ldp     x4, x5, [x19, #32]
    ldp     x6, x7, [x19, #48]
    ldp     x8, x9, [x19, #64]
    ldp     x10, x11, [x19, #80]
    ldp     x12, x13, [x19, #96]
    ldp     x14, x15, [x19, #112]
    ldp     x16, x17, [x19, #128]
    ldp     x20, x21, [x19, #160]
    ldp     x22, x23, [x19, #176]
    ldp     x24, x25, [x19, #192]
    ldp     x26, x27, [x19, #208]
    ldr     x28, [x19, #224]

    .globl xt_cap_loop_top
xt_cap_loop_top:
    ldr     x29, [x19, #CAP_DOORBELL]
    cbz     x29, 2f
    ldr     w29, [x29]
    cbnz    w29, xt_cap_trap
2:
    ldr     w29, [x19, #CAP_REQ]
    cbnz    w29, xt_cap_fault
    ldr     x29, [x19, #CAP_ITERS]
    subs    x29, x29, #1
    str     x29, [x19, #CAP_ITERS]
    b.ne    xt_cap_loop_top
    b       3f

    .globl xt_cap_trap
xt_cap_trap:
    brk     #0xcafe

    .globl xt_cap_fault
xt_cap_fault:
    ldr     x29, [x29]

    .globl xt_cap_cont
xt_cap_cont:
    ldr     w29, [x19, #CAP_RESIM]
    cbz     w29, xt_cap_loop_top
    ldr     x30, [x18, #TEB_CPU_AREA]
    strb    w29, [x30]
    b       xt_cap_loop_top

3:
    add     x29, x19, #CAP_OUT_X
    stp     x0, x1, [x29, #0]
    stp     x2, x3, [x29, #16]
    stp     x4, x5, [x29, #32]
    stp     x6, x7, [x29, #48]
    stp     x8, x9, [x29, #64]
    stp     x10, x11, [x29, #80]
    stp     x12, x13, [x29, #96]
    stp     x14, x15, [x29, #112]
    stp     x16, x17, [x29, #128]
    stp     x20, x21, [x29, #160]
    stp     x22, x23, [x29, #176]
    stp     x24, x25, [x29, #192]
    stp     x26, x27, [x29, #208]
    str     x28, [x29, #224]
    add     x29, x19, #CAP_OUT_V
    stp     q0, q1, [x29, #0]
    stp     q2, q3, [x29, #32]
    stp     q4, q5, [x29, #64]
    stp     q6, q7, [x29, #96]
    stp     q8, q9, [x29, #128]
    stp     q10, q11, [x29, #160]
    stp     q12, q13, [x29, #192]
    stp     q14, q15, [x29, #224]
    stp     q16, q17, [x29, #256]
    stp     q18, q19, [x29, #288]
    stp     q20, q21, [x29, #320]
    stp     q22, q23, [x29, #352]
    stp     q24, q25, [x29, #384]
    stp     q26, q27, [x29, #416]
    stp     q28, q29, [x29, #448]
    stp     q30, q31, [x29, #480]
    ldr     x9, [x19, #CAP_SAVED_SP]
    mov     sp, x9
    ldp     x19, x20, [sp, #16]
    ldp     x21, x22, [sp, #32]
    ldp     x23, x24, [sp, #48]
    ldp     x25, x26, [sp, #64]
    ldp     x27, x28, [sp, #80]
    ldp     d8, d9, [sp, #96]
    ldp     d10, d11, [sp, #112]
    ldp     d12, d13, [sp, #128]
    ldp     d14, d15, [sp, #144]
    ldp     x29, x30, [sp], #160
    ret
    .globl xt_cap_loop_end
xt_cap_loop_end:

/*
 * An entry while the probe has xt_cap_entry_mode set (arm64ec.S's
 * entries come here first, with x16 = which, x9 = the target): record
 * which, the target, sp, lr and InSimulation, and count.  A call
 * (ExitToX64) or jump (DispatchJump) to x64 code returns to lr, as if the
 * x64 code had returned at once; the others can't, and end the process.
 */
    .globl xt_cap_entry
xt_cap_entry:
    adrp    x17, xt_cap_entry_rec
    add     x17, x17, :lo12:xt_cap_entry_rec
    str     x16, [x17, #0]
    str     x9, [x17, #8]
    mov     x16, sp
    str     x16, [x17, #16]
    str     x30, [x17, #24]
    ldr     x16, [x18, #TEB_CPU_AREA]
    ldrb    w16, [x16]
    str     x16, [x17, #32]
    ldr     x16, [x17, #40]
    add     x16, x16, #1
    str     x16, [x17, #40]
    ldr     x16, [x17, #0]
    cmp     x16, #3
    b.eq    1f
    cmp     x16, #1
    b.eq    1f
    mov     x0, x16
    bl      "#xt_cap_entry_end"
1:
    ret
