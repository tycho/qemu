/*
 * xtajit: the x64 CPU module's assembly (ARM64EC): direct system calls
 * and the call checker.  The checker's logic follows FEX's ARM64EC module
 * (Source/Windows/ARM64EC/Module.S, MIT).
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

    .text
    .balign 16

/*
 * "svc #n; ret" for n below 512: a system call by its number, which
 * Windows changes between builds.
 */
    .globl xt_svc_table
xt_svc_table:
    .set nr, 0
    .rept 512
    svc     #nr
    ret
    .set nr, nr + 1
    .endr

/*
 * NTSTATUS xt_syscall(a0, a1, a2, a3, a4, a5, nr): the arguments stay in
 * x0-x5; the caller has checked nr against the table.
 */
    .globl "#xt_syscall"
    .def "#xt_syscall"; .scl 2; .type 32; .endef
"#xt_syscall":
    adrp    x16, xt_svc_table
    add     x16, x16, :lo12:xt_svc_table
    add     x16, x16, x6, lsl #3
    br      x16

/*
 * The module's call checker (__os_arm64x_dispatch_call, _icall and
 * _icall_cfg): called with the target in x11 and its exit thunk in x10,
 * it returns in x11 what to call.  One of ntdll's x64 entries (fast-
 * forward sequences, which an application may patch) becomes its native
 * code, through xt_ntdll_lut; anything else is called as it is.  Only x9
 * and x16-x17 are scratch.
 */
    .globl xt_check_call
xt_check_call:
    adrp    x9, xt_ntdll_base
    ldr     x9, [x9, :lo12:xt_ntdll_base]
    subs    x16, x11, x9
    b.lo    1f
    adrp    x17, xt_ntdll_lut_size
    ldr     w17, [x17, :lo12:xt_ntdll_lut_size]
    cmp     x16, x17
    b.hs    1f
    adrp    x17, xt_ntdll_lut
    ldr     x17, [x17, :lo12:xt_ntdll_lut]
    ldr     w16, [x17, x16, lsl #2]
    cbz     w16, 1f
    add     x11, x16, x9
1:
    ret

/*
 * The four entries ntdll copies into every ARM64EC module's metadata
 * (__os_arm64x_x64_jump, _dispatch_ret, _dispatch_call_no_redirect, and
 * KiUserEmulationDispatcher's BeginSimulation).  While the capture probe
 * sets xt_cap_entry_mode, xt_cap_entry (test-ec.S) takes them instead.
 * x16 and x17 are free at each; x9 holds the target where there is one.
 */
.macro cap_check which
    adrp    x17, xt_cap_entry_mode
    ldr     w17, [x17, :lo12:xt_cap_entry_mode]
    cbz     w17, 1f
    mov     x16, #\which
    b       xt_cap_entry
1:
.endm

/* XtEcFrame.ctx: an ARM64_NT_CONTEXT 16 bytes into the frame. */
#define F_X(n)      (0x10 + 0x08 + 8 * (n))
#define F_CPSR      (0x10 + 0x04)
#define F_SP        (0x10 + 0x100)
#define F_PC        (0x10 + 0x108)
#define F_V         (0x10 + 0x110)
#define C_X(n)      (0x08 + 8 * (n))
#define C_SP        0x100
#define C_PC        0x108
#define C_V         0x110

#define TEB_PEB         0x60
#define TEB_CPU_AREA    0x1788
#define PEB_EC_BITMAP   0x368
#define AREA_STACK_BASE 0x08
#define AREA_DOORBELL   0x20
#define AREA_FRAME      0x38    /* EmulatorData[1] */

    .globl DispatchJump
DispatchJump:
    cap_check 1
    str     lr, [sp, #-8]!      /* the x64 return address */
    b       2f

    .globl RetToEntryThunk
RetToEntryThunk:
    cap_check 2
    mov     x9, lr
2:
    /* Native code (the EC bitmap) is reached without the engine. */
    ldr     x16, [x18, #TEB_PEB]
    ldr     x16, [x16, #PEB_EC_BITMAP]
    lsr     x17, x9, #18
    ldr     x16, [x16, x17, lsl #3]
    lsr     x17, x9, #12
    lsr     x16, x16, x17
    tbnz    x16, #0, xt_ec_exit_dispatch
    b       3f

    .globl ExitToX64
ExitToX64:
    cap_check 3
    str     lr, [sp, #-8]!      /* the x64 return address */
3:
    /* InSimulation first: from here Windows waits for the doorbell. */
    ldr     x17, [x18, #TEB_CPU_AREA]
    mov     w16, #1
    strb    w16, [x17]
    ldr     x16, [x17, #AREA_FRAME]
    stp     x0, x1, [x16, #F_X(0)]
    stp     x2, x3, [x16, #F_X(2)]
    stp     x4, x5, [x16, #F_X(4)]
    stp     x6, x7, [x16, #F_X(6)]
    stp     x8, x9, [x16, #F_X(8)]
    stp     x10, x11, [x16, #F_X(10)]
    str     x12, [x16, #F_X(12)]
    str     x15, [x16, #F_X(15)]
    stp     x19, x20, [x16, #F_X(19)]
    stp     x21, x22, [x16, #F_X(21)]
    stp     x25, x26, [x16, #F_X(25)]
    str     x27, [x16, #F_X(27)]
    stp     x29, x30, [x16, #F_X(29)]
    mov     x0, sp
    str     x0, [x16, #F_SP]
    str     x9, [x16, #F_PC]
    mrs     x0, nzcv
    str     w0, [x16, #F_CPSR]
    add     x0, x16, #F_V
    stp     q0, q1, [x0, #0]
    stp     q2, q3, [x0, #32]
    stp     q4, q5, [x0, #64]
    stp     q6, q7, [x0, #96]
    stp     q8, q9, [x0, #128]
    stp     q10, q11, [x0, #160]
    stp     q12, q13, [x0, #192]
    stp     q14, q15, [x0, #224]
    ldr     x0, [x17, #AREA_STACK_BASE]
    mov     sp, x0
    mov     x0, x16
    bl      "#xt_ec_enter"
    brk     #0xf000

    .globl BeginSimulation
BeginSimulation:
    cap_check 4
    /* The registers the dispatcher keeps, for xt_ec_begin. */
    ldr     x17, [x18, #TEB_CPU_AREA]
    ldr     x16, [x17, #AREA_FRAME]
    stp     x19, x20, [x16, #F_X(19)]
    stp     x21, x22, [x16, #F_X(21)]
    stp     x25, x26, [x16, #F_X(25)]
    str     x27, [x16, #F_X(27)]
    ldr     x16, [x17, #AREA_STACK_BASE]
    mov     sp, x16
    bl      "#xt_ec_begin"
    brk     #0xf000

/*
 * void xt_ec_exit_native(ARM64_NT_CONTEXT *n): leave the engine for
 * native code at n->Pc, with the packed guest state of N (xt_ec_pack):
 * the x64 registers in their places, sp the guest's.  The _ymm entry
 * loads v16-v31 too, so the thread's context shows the YMM upper halves
 * until native code changes them.  The engine has
 * given the thread back; no frame of the emulator stack is live.
 */
    .globl "#xt_ec_exit_native_ymm"
    .def "#xt_ec_exit_native_ymm"; .scl 2; .type 32; .endef
"#xt_ec_exit_native_ymm":
    mov     x16, x0
    add     x17, x16, #C_V
    ldp     q16, q17, [x17, #256]
    ldp     q18, q19, [x17, #288]
    ldp     q20, q21, [x17, #320]
    ldp     q22, q23, [x17, #352]
    ldp     q24, q25, [x17, #384]
    ldp     q26, q27, [x17, #416]
    ldp     q28, q29, [x17, #448]
    ldp     q30, q31, [x17, #480]
    b       1f

    .globl "#xt_ec_exit_native"
    .def "#xt_ec_exit_native"; .scl 2; .type 32; .endef
"#xt_ec_exit_native":
    mov     x16, x0
    add     x17, x16, #C_V
1:
    ldp     q0, q1, [x17, #0]
    ldp     q2, q3, [x17, #32]
    ldp     q4, q5, [x17, #64]
    ldp     q6, q7, [x17, #96]
    ldp     q8, q9, [x17, #128]
    ldp     q10, q11, [x17, #160]
    ldp     q12, q13, [x17, #192]
    ldp     q14, q15, [x17, #224]
    ldp     x0, x1, [x16, #C_X(0)]
    ldp     x2, x3, [x16, #C_X(2)]
    ldp     x4, x5, [x16, #C_X(4)]
    ldp     x6, x7, [x16, #C_X(6)]
    ldr     x8, [x16, #C_X(8)]
    ldp     x10, x11, [x16, #C_X(10)]
    ldr     x12, [x16, #C_X(12)]
    ldr     x15, [x16, #C_X(15)]
    ldp     x19, x20, [x16, #C_X(19)]
    ldp     x21, x22, [x16, #C_X(21)]
    ldp     x25, x26, [x16, #C_X(25)]
    ldr     x27, [x16, #C_X(27)]
    ldp     x29, x30, [x16, #C_X(29)]
    ldr     x9, [x16, #C_PC]
    ldr     x17, [x16, #C_SP]
    mov     sp, x17

/*
 * Native code reached from x64 code, the x64 state in its ARM64EC places
 * and the target in x9: out of simulation, then, if the doorbell rang,
 * a trap that ResetToConsistentState continues at the resume point (the
 * thread is consistent there, so the suspension completes).  Then, as
 * FEX's ARM64EC module does: a target right after a "blr x16" is a return
 * into an exit thunk; anything else is a call, through the entry thunk
 * whose offset precedes the function, with the return address in lr (or
 * on the stack, where popping it would misalign sp, with lr a ret) and
 * x4 the x64 stack pointer (R10, which the x64 ABI doesn't preserve).
 */
    .globl xt_ec_exit_dispatch
xt_ec_exit_dispatch:
    ldr     x17, [x18, #TEB_CPU_AREA]
    strb    wzr, [x17]
    ldr     x17, [x17, #AREA_DOORBELL]
    cbz     x17, 4f
    ldr     w17, [x17]
    cbnz    w17, xt_ec_exit_suspend_point
4:
    .globl xt_ec_exit_resume_point
xt_ec_exit_resume_point:
    mov     x17, x9
    mov     w16, #0x0200
    movk    w16, #0xd63f, lsl #16       /* blr x16 */
    ldursw  x23, [x17, #-4]
    cmp     w23, w16
    b.eq    6f
    and     x23, x23, #-4
    add     x17, x17, x23
    /* An entry thunk finds the stack arguments at x4 + 0x20. */
    mov     x4, sp
    tbz     x4, #3, 5f
    ldr     lr, [x4], #8
    mov     sp, x4
6:
    br      x17
5:
    adrp    lr, xt_x64_ret
    ldr     lr, [lr, :lo12:xt_x64_ret]
    br      x17

    .globl xt_ec_exit_suspend_point
xt_ec_exit_suspend_point:
    brk     #0xcafe

/*
 * void xt_ec_continue_kept(ARM64_NT_CONTEXT *n, nr): NtContinue at N with
 * x19-x22 and x25-x27 holding N's values already, so they hold them at
 * whatever native code runs before the continuation reaches x64 code.
 * Returns only if NtContinue fails, with those registers lost.
 */
    .globl "#xt_ec_continue_kept"
    .def "#xt_ec_continue_kept"; .scl 2; .type 32; .endef
"#xt_ec_continue_kept":
    ldp     x19, x20, [x0, #C_X(19)]
    ldp     x21, x22, [x0, #C_X(21)]
    ldp     x25, x26, [x0, #C_X(25)]
    ldr     x27, [x0, #C_X(27)]
    mov     x6, x1
    mov     x1, #0
    b       "#xt_syscall"

/* void xt_ec_jump_set_stack(pc, sp) */
    .globl "#xt_ec_jump_set_stack"
    .def "#xt_ec_jump_set_stack"; .scl 2; .type 32; .endef
"#xt_ec_jump_set_stack":
    mov     sp, x1
    br      x0

    .section .drectve, "yn"
    .ascii " -export:DispatchJump,DATA"
    .ascii " -export:RetToEntryThunk,DATA"
    .ascii " -export:ExitToX64,DATA"
    .ascii " -export:BeginSimulation,DATA"
