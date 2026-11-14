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
 * Until InSimulation is set, the entry works in registers an x64 context
 * keeps: Windows applies one to a thread outside simulation on its own
 * stack (a special APC, SetThreadContext) and zeroes those it has no x64
 * place for (x13, x14, x23, x24, x28).  x10-x12 are the admission's
 * scratch and w15 carries the entry's kind to the frame: the places of
 * MM4-MM7's mantissas, which no entry takes (the engine keeps the x87
 * state) and which are no argument of any entry, so native code reached
 * by the bypass below can't depend on them either.  The x64 registers go
 * into the CPU state when the frame names it (XtEcFrame.env), else into
 * the frame; NZCV is read before any instruction that sets flags, and the
 * guest's sp after the return address's push.  The MMX places and v16-v31
 * are not taken: the engine keeps the x87 state and the YMM upper halves.
 */
/* MMn's mantissa (ST(n) from the stack top in w0, the x87 registers at x1). */
.macro mm_load i, r
    add     w2, w0, #\i
    and     x2, x2, #7
    add     x2, x1, x2, lsl #4
    ldr     x\r, [x2]
.endm

/*
 * The capture probe's entries (xt_cap_entry), or with XT_EC_ENTRY_INJECT
 * (bit 31) the copies with the test points.
 */
.macro cap_check which
    adrp    x17, xt_cap_entry_mode
    ldr     w17, [x17, :lo12:xt_cap_entry_mode]
    cbz     w17, 1f
    mov     x16, #\which
.if \which == 1
    tbnz    w17, #31, xt_ec_inj_jump
.elseif \which == 2
    tbnz    w17, #31, xt_ec_inj_ret
.elseif \which == 3
    tbnz    w17, #31, xt_ec_inj_call
.else
    tbnz    w17, #31, xt_ec_inj_begin
.endif
    b       xt_cap_entry
1:
.endm

/*
 * XtEcFrame: the entry's record (its kind, XT_EC_ENTRY_*; NZCV; whether the
 * registers went into the CPU state; the target and lr), env, the CPU
 * state, and ctx, an ARM64_NT_CONTEXT 0x30 bytes into the frame.
 */
#define F_ENTRY     0x04
#define F_NZCV      0x08
#define F_SAVED     0x0c
#define F_PCLR      0x10
#define F_ENV       0x20
#define F_ARMED     0x28
#define F_X(n)      (0x30 + 0x08 + 8 * (n))
#define F_SP        (0x30 + 0x100)
#define F_V         (0x30 + 0x110)
#define C_X(n)      (0x08 + 8 * (n))
#define C_SP        0x100
#define C_PC        0x108
#define C_V         0x110

/*
 * The CPU state's layout (CPUX86State), as arm64ec.c checks it: regs[]
 * from 0 (RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8-R15), the x87 stack
 * top and registers (16 bytes each, the mantissa first), XMM registers
 * 64 bytes apart (YMMn's upper half 16 bytes into XMMn's).
 */
#define E_FPSTT     0x2e0
#define E_FPREGS    0x2f0
#define E_XMM       0x3d0

/*
 * The thread's gate (arm64ec.h's XtGate, EmulatorData[3]): its admission
 * word, its own closure and whether it is an internal thread.
 */
#define AREA_GATE       0x48
#define G_ADM           0x00
#define G_CLOSED        0x08
#define G_INTERNAL      0x0c
#define G_CHECKING      0x18

#define TEB_TID         0x48
#define TEB_PEB         0x60
#define TEB_CPU_AREA    0x1788
#define PEB_EC_BITMAP   0x368
#define AREA_STACK_BASE 0x08
#define AREA_DOORBELL   0x20
#define AREA_FRAME      0x38    /* EmulatorData[1] */

/*
 * XTAJIT_INJECT's test point N (XtStubInject): when it is the chosen one,
 * and the thread has been suspended before or the point is always taken,
 * wait its ticks, then count the wait, and the doorbell if it is set.
 * Only x\a and x\b change; NZCV is kept.
 */
.macro inj_point n, a, b
    adrp    x\a, xt_stub_inject
    add     x\a, x\a, :lo12:xt_stub_inject
    ldr     w\b, [x\a, #0]
    sub     w\b, w\b, #\n
    cbnz    w\b, .Linj_out\@
    ldr     w\b, [x\a, #4]
    cbnz    w\b, .Linj_go\@
    ldr     x\b, [x18, #TEB_CPU_AREA]
    ldr     x\b, [x\b, #AREA_FRAME]
    ldr     w\b, [x\b, #F_ARMED]
    cbz     w\b, .Linj_out\@
.Linj_go\@:
    ldr     x\b, [x\a, #8]
    mrs     x\a, cntvct_el0
    add     x\a, x\a, x\b
.Linj_spin\@:
    yield
    mrs     x\b, cntvct_el0
    sub     x\b, x\a, x\b
    tbz     x\b, #63, .Linj_spin\@
    adrp    x\a, xt_stub_inject
    add     x\a, x\a, :lo12:xt_stub_inject
    ldr     x\b, [x\a, #(0x10 + 8 * \n)]
    add     x\b, x\b, #1
    str     x\b, [x\a, #(0x10 + 8 * \n)]
    ldr     x\b, [x18, #TEB_CPU_AREA]
    ldr     x\b, [x\b, #AREA_DOORBELL]
    cbz     x\b, .Linj_out\@
    ldr     w\b, [x\b]
    cbz     w\b, .Linj_out\@
    ldr     x\b, [x\a, #(0x50 + 8 * \n)]
    add     x\b, x\b, #1
    str     x\b, [x\a, #(0x50 + 8 * \n)]
.Linj_out\@:
.endm

/*
 * The thread gates' test points (test-tp.c), in the inject copies only:
 * point ID of a route (TP_JUMP, TP_RET, TP_CALL; 1-6 the admission's
 * windows, 7 after the entry's kind).  When the control block arms ID
 * (for its thread, at its NTH pass), the thread is held at the point:
 * x13, x14, x23 and x24 recorded (and every register but x16-x18 and
 * x28, at its number's place in GPR_BEFORE), x28 set to the block's
 * canary, the hit published, a spin until the controller releases it, and
 * the same recorded again.  What the controller does meanwhile (an APC,
 * a context edit, a suspension) and what the registers show is its test.
 * Nothing here uses sp as a base (an entry's sp may be 8 off 16) or sets
 * flags, and only x16, x17 (saved and restored) and x28 (dead in the
 * stubs) change; the frame below sp keeps an interruption's pushes off the
 * save.  No C is called: a call would change what is measured.
 */
#define TP_JUMP         0x10
#define TP_RET          0x20
#define TP_CALL         0x30
#define TP_BYPASS       0x40
#define TP_BEGIN        0x50

#define TP_ASM_POINT    0x08
#define TP_ASM_STATE    0x0c
#define TP_CANARY       0x10
#define TP_TID_FILTER   0x18
#define TP_HITS         0x20
#define TP_NTH          0x28
#define TP_TID          0x30
#define TP_SPIN_PC      0x38
#define TP_ORIG_SP      0x40
#define TP_X16          0x48
#define TP_X17          0x50
#define TP_BEFORE       0x58
#define TP_AFTER        0x80
#define TP_RELEASE      0xa8
#define TP_FORCE_ZERO   0x1d0
#define TP_GPR_BEFORE   0x200
#define TP_GPR_AFTER    0x300

.macro tp_gprs
    stp     x0, x1, [x17, #0]
    stp     x2, x3, [x17, #16]
    stp     x4, x5, [x17, #32]
    stp     x6, x7, [x17, #48]
    stp     x8, x9, [x17, #64]
    stp     x10, x11, [x17, #80]
    stp     x12, x13, [x17, #96]
    stp     x14, x15, [x17, #112]
    stp     x19, x20, [x17, #152]
    stp     x21, x22, [x17, #168]
    stp     x23, x24, [x17, #184]
    stp     x25, x26, [x17, #200]
    str     x27, [x17, #216]
    stp     x29, x30, [x17, #232]
.endm

.macro tp_point id
    sub     sp, sp, #96
    add     x28, sp, #96
    stp     x16, x17, [x28, #-16]
    adrp    x16, xt_tp_block
    ldr     x16, [x16, :lo12:xt_tp_block]
    cbz     x16, .Ltp_out\@
    ldr     w17, [x16, #TP_ASM_POINT]
    sub     w17, w17, #(\id)
    cbnz    w17, .Ltp_out\@
    ldr     x17, [x16, #TP_TID_FILTER]
    cbz     x17, .Ltp_count\@
    ldr     x28, [x18, #TEB_TID]
    sub     x17, x17, x28
    cbnz    x17, .Ltp_out\@
.Ltp_count\@:
    add     x16, x16, #TP_HITS
    mov     x17, #1
    ldadd   x17, x17, [x16]
    sub     x16, x16, #TP_HITS
    add     x17, x17, #1
    ldr     w28, [x16, #TP_NTH]
    sub     x17, x17, x28
    cbnz    x17, .Ltp_out\@
    /* Armed (1) to held (2): this hit's alone. */
    add     x16, x16, #TP_ASM_STATE
    mov     w17, #1
    mov     w28, #2
    cas     w17, w28, [x16]
    sub     x16, x16, #TP_ASM_STATE
    sub     w17, w17, #1
    cbnz    w17, .Ltp_out\@
    ldr     x17, [x18, #TEB_TID]
    str     x17, [x16, #TP_TID]
    adr     x17, .Ltp_spin\@
    str     x17, [x16, #TP_SPIN_PC]
    add     x28, sp, #96
    str     x28, [x16, #TP_ORIG_SP]
    ldr     x17, [x28, #-16]
    str     x17, [x16, #TP_X16]
    ldr     x17, [x28, #-8]
    str     x17, [x16, #TP_X17]
    stp     x13, x14, [x16, #TP_BEFORE]
    stp     x23, x24, [x16, #(TP_BEFORE + 16)]
    add     x17, x16, #TP_GPR_BEFORE
    tp_gprs
    ldr     x28, [x16, #TP_CANARY]
    str     x28, [x16, #(TP_BEFORE + 32)]
    /* Published (3), then held until released. */
    add     x16, x16, #TP_ASM_STATE
    mov     w17, #3
    stlr    w17, [x16]
    sub     x16, x16, #TP_ASM_STATE
.Ltp_spin\@:
    yield
    ldr     w17, [x16, #TP_RELEASE]
    cbz     w17, .Ltp_spin\@
    /* FORCE_ZERO bit 0: what Windows does to these, applying a context. */
    ldr     w17, [x16, #TP_FORCE_ZERO]
    tbz     w17, #0, .Ltp_kept\@
    mov     x13, xzr
    mov     x14, xzr
    mov     x23, xzr
    mov     x24, xzr
.Ltp_kept\@:
    stp     x13, x14, [x16, #TP_AFTER]
    stp     x23, x24, [x16, #(TP_AFTER + 16)]
    str     x28, [x16, #(TP_AFTER + 32)]
    add     x17, x16, #TP_GPR_AFTER
    tp_gprs
    /*
     * FORCE_ZERO bit 1: a fault here, a nested entry of the module's
     * (ResetToConsistentState's) with the full native context; lr kept in
     * the frame, x16 reloaded.
     */
    ldr     w17, [x16, #TP_FORCE_ZERO]
    tbz     w17, #1, .Ltp_nofault\@
    add     x17, sp, #64
    str     x30, [x17]
    bl      "#xt_tp_fault"
    add     x17, sp, #64
    ldr     x30, [x17]
    adrp    x16, xt_tp_block
    ldr     x16, [x16, :lo12:xt_tp_block]
.Ltp_nofault\@:
    /* Done (4). */
    add     x16, x16, #TP_ASM_STATE
    mov     w17, #4
    stlr    w17, [x16]
.Ltp_out\@:
    add     x28, sp, #96
    ldp     x16, x17, [x28, #-16]
    mov     sp, x28
.endm

/*
 * An entry's admission (arm64ec-gate.c's adm_enter): the level pushed by
 * one compare-and-swap; over a level already admitted (its byte in
 * CHECKING clear) it inherits, else its own byte is set before the push,
 * the gate read after it, the word re-read (parked or poisoned meanwhile,
 * or a level leaked above, it parks), and the byte cleared last: the store
 * that admits it.  Before the entry writes anything of the engine's, in
 * x10-x12, x16 and x17, with no instruction that sets flags, so NZCV is
 * still the guest's when entry_tail reads it.  The
 * push is relaxed: the owner's flush of every processor's writes is the
 * pair's other half.  A refusal, a parked or poisoned word, 32 levels, or a
 * SEQ that would wrap, goes to C, which never returns; x11 then holds the
 * COUNT the level was pushed over.  With TP (the inject copies), the
 * harness's test points TP + 1 to TP + 6 in its windows.
 */
.macro adm_enter tp=0
    ldr     x16, [x18, #TEB_CPU_AREA]
    ldr     x16, [x16, #AREA_GATE]
    cbz     x16, xt_ec_adm_nogate
.Ladm_try\@:
    ldr     x17, [x16, #G_ADM]
    tbnz    x17, #60, xt_ec_adm_park_entry
    tbnz    x17, #61, xt_ec_adm_park_entry
    mvn     w12, w17
    cbz     w12, xt_ec_adm_poison_entry
    ubfx    x11, x17, #32, #14
    lsr     x12, x11, #5
    cbnz    x12, xt_ec_adm_poison_entry
.if \tp
    tp_point (\tp + 1)
.endif
    /*
     * w10 1 if it reads the gate (no level, or the innermost one's byte
     * set), 0 if it inherits; its own byte set before the push if 1.
     */
    add     x12, x16, x11
    mov     w10, #1
    cbz     x11, .Ladm_mark\@
    ldrb    w10, [x12, #(G_CHECKING - 1)]
    cbz     w10, .Ladm_push\@
.Ladm_mark\@:
    strb    w10, [x12, #G_CHECKING]
.Ladm_push\@:
.if \tp
    tp_point (\tp + 2)
.endif
    /* COUNT+1, SEQ+1. */
    movz    x12, #1, lsl #32
    add     x12, x17, x12
    add     x12, x12, #1
    mov     x11, x17
    cas     x11, x12, [x16]
.if \tp
    tp_point (\tp + 3)
.endif
    sub     x11, x11, x17
    cbnz    x11, .Ladm_try\@
    ubfx    x11, x17, #32, #14
    cbz     w10, .Ladm_admit\@
.if \tp
    tp_point (\tp + 4)
.endif
    ldr     w17, [x16, #G_CLOSED]
    cbnz    w17, xt_ec_adm_reject_entry
    adrp    x17, xt_gate_closed_by
    ldr     x17, [x17, :lo12:xt_gate_closed_by]
    cbz     x17, .Ladm_reread\@
    sub     x17, x17, x16
    cbz     x17, .Ladm_reread\@
    ldr     w17, [x16, #G_INTERNAL]
    cbz     w17, xt_ec_adm_reject_entry
.Ladm_reread\@:
    ldr     x17, [x16, #G_ADM]
    tbnz    x17, #60, xt_ec_adm_park_entry
    tbnz    x17, #61, xt_ec_adm_park_entry
    ubfx    x12, x17, #32, #14
    sub     x12, x12, x11
    sub     x12, x12, #1
    cbnz    x12, xt_ec_adm_poison_entry
.if \tp
    tp_point (\tp + 5)
.endif
.Ladm_admit\@:
    add     x12, x16, x11
.if \tp
    tp_point (\tp + 6)
.endif
    strb    wzr, [x12, #G_CHECKING]
.endm

/*
 * An exit's withdrawal (xt_adm_exit): the innermost level popped, with
 * release, after the engine's last access.  With no admitted level to pop
 * (none, or the innermost's byte still set: a pairing error), or a SEQ that
 * would wrap, the word is poisoned instead.  x16, x17, and RA, RB, RC
 * (x14, x23, x24 by default: protected where InSimulation is set; the
 * bypass, outside simulation, passes x10-x12) only.  With TP (the
 * inject copy of the bypass), the harness's test points TP + 1 after the
 * word's read and TP + 3 after the compare-and-swap.
 */
.macro adm_exit ra=14, rb=23, rc=24, tp=0
    ldr     x16, [x18, #TEB_CPU_AREA]
    ldr     x16, [x16, #AREA_GATE]
    cbz     x16, .Ladm_out\@
.Ladm_pop\@:
    ldr     x17, [x16, #G_ADM]
.if \tp
    tp_point (\tp + 1)
.endif
    ubfx    x\ra, x17, #32, #14
    cbz     x\ra, .Ladm_bad\@
    add     x\rc, x16, x\ra
    ldrb    w\rc, [x\rc, #(G_CHECKING - 1)]
    cbnz    w\rc, .Ladm_bad\@
    mvn     w\rc, w17
    cbz     w\rc, .Ladm_bad\@
    movz    x\rb, #1, lsl #32
    sub     x\rc, x17, x\rb
    add     x\rc, x\rc, #1
    mov     x\rb, x17
    casl    x\rb, x\rc, [x16]
.if \tp
    tp_point (\tp + 3)
.endif
    sub     x\rb, x\rb, x17
    cbnz    x\rb, .Ladm_pop\@
    b       .Ladm_out\@
.Ladm_bad\@:
    orr     x\rc, x17, #0x2000000000000000
    mov     x\rb, x17
    casl    x\rb, x\rc, [x16]
    sub     x\rb, x\rb, x17
    cbnz    x\rb, .Ladm_pop\@
.Ladm_out\@:
.endm

/* The entries' common part; with INJ, XTAJIT_INJECT's points 1-3. */
.macro entry_tail inj
.if \inj
    inj_point 1, 16, 17
.endif
    /* InSimulation first: from here Windows waits for the doorbell. */
    ldr     x17, [x18, #TEB_CPU_AREA]
    mov     w16, #1
    strb    w16, [x17]
    mrs     x24, nzcv
.if \inj
    inj_point 2, 14, 16
.endif
    ldr     x16, [x17, #AREA_FRAME]
    ldr     x14, [x16, #F_ENV]
    str     w15, [x16, #F_ENTRY]
    str     w24, [x16, #F_NZCV]
    stp     x9, x30, [x16, #F_PCLR]
    cbz     x14, 7f
    /* The x64 registers into the CPU state (xt_ec_exit_native_env's places). */
    mov     w24, #1
    str     w24, [x16, #F_SAVED]
    mov     x23, sp
    stp     x8, x0, [x14, #0x00]        /* RAX, RCX */
    stp     x1, x27, [x14, #0x10]       /* RDX, RBX */
    stp     x23, x29, [x14, #0x20]      /* RSP, RBP */
    stp     x25, x26, [x14, #0x30]      /* RSI, RDI */
    stp     x2, x3, [x14, #0x40]        /* R8-R11 */
    stp     x4, x5, [x14, #0x50]
    stp     x19, x20, [x14, #0x60]      /* R12-R15 */
    stp     x21, x22, [x14, #0x70]
    .irp    r, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    str     q\r, [x14, #(E_XMM + \r * 64)]
    .endr
    b       8f
7:
    /* No CPU state yet (the thread's first entry): into the frame. */
    str     wzr, [x16, #F_SAVED]
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
    add     x0, x16, #F_V
    stp     q0, q1, [x0, #0]
    stp     q2, q3, [x0, #32]
    stp     q4, q5, [x0, #64]
    stp     q6, q7, [x0, #96]
    stp     q8, q9, [x0, #128]
    stp     q10, q11, [x0, #160]
    stp     q12, q13, [x0, #192]
    stp     q14, q15, [x0, #224]
8:
.if \inj
    inj_point 3, 0, 1
.endif
    ldr     x0, [x17, #AREA_STACK_BASE]
    mov     sp, x0
    mov     x0, x16
    bl      "#xt_ec_enter"
    brk     #0xf000

.endm

    .globl DispatchJump
DispatchJump:
    cap_check 1
    adm_enter
    str     lr, [sp, #-8]!      /* the x64 return address */
    mov     w15, #1             /* XT_EC_ENTRY_CALL */
    b       2f

    .globl RetToEntryThunk
RetToEntryThunk:
    cap_check 2
    adm_enter
    mov     x9, lr
    mov     w15, #2             /* XT_EC_ENTRY_RETURN */
2:
    /* Native code (the EC bitmap) is reached without the engine. */
    ldr     x16, [x18, #TEB_PEB]
    ldr     x16, [x16, #PEB_EC_BITMAP]
    lsr     x17, x9, #18
    ldr     x16, [x16, x17, lsl #3]
    lsr     x17, x9, #12
    lsr     x16, x16, x17
    tbnz    x16, #0, xt_ec_bypass_dispatch
    b       3f

    .globl ExitToX64
ExitToX64:
    cap_check 3
    adm_enter
    str     lr, [sp, #-8]!      /* the x64 return address */
    mov     w15, #1             /* XT_EC_ENTRY_CALL */
3:
    entry_tail 0

/*
 * The entries' copies with XTAJIT_INJECT's test points, reached from
 * cap_check.
 */
xt_ec_inj_jump:
    adm_enter TP_JUMP
    str     lr, [sp, #-8]!
    mov     w15, #1
    tp_point (TP_JUMP + 7)
    b       2f

xt_ec_inj_ret:
    adm_enter TP_RET
    mov     x9, lr
    mov     w15, #2
    tp_point (TP_RET + 7)
2:
    ldr     x16, [x18, #TEB_PEB]
    ldr     x16, [x16, #PEB_EC_BITMAP]
    lsr     x17, x9, #18
    ldr     x16, [x16, x17, lsl #3]
    lsr     x17, x9, #12
    lsr     x16, x16, x17
    tbnz    x16, #0, xt_ec_bypass_dispatch_inj
    b       3f

xt_ec_inj_call:
    adm_enter TP_CALL
    str     lr, [sp, #-8]!
    mov     w15, #1
    tp_point (TP_CALL + 7)
3:
    entry_tail 1

/* The registers the dispatcher keeps, for xt_ec_begin, which never returns. */
.macro begin_tail
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
.endm

    .globl BeginSimulation
BeginSimulation:
    cap_check 4
    adm_enter
    begin_tail

/* Its inject copy, with the harness's test points. */
xt_ec_inj_begin:
    adm_enter TP_BEGIN
    begin_tail

/*
 * void xt_ec_exit_native_env(env, target, ymm): leave the engine for
 * native code at TARGET with the guest state of ENV in its ARM64EC places
 * (xt_ec_pack's, without the frame): the x64 registers, sp the guest's;
 * MM0-7's mantissas from the x87 stack top on, in x30, x6, x7, (x9),
 * x10-x12 and x15, where x9 takes the target and the dispatch may replace
 * lr; with YMM, v16-v31 the upper halves, so the thread's context shows
 * them until native code changes them.  The arguments are taken before
 * the registers they arrive in are loaded.  The engine has given the
 * thread back; no frame of the emulator stack is live.
 */
.macro exit_loads
    mov     x16, x0
    mov     x9, x1
    cbz     w2, 1f
    .irp    r, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
    ldr     q\r, [x16, #(E_XMM + 16 + (\r - 16) * 64)]
    .endr
1:
    .irp    r, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    ldr     q\r, [x16, #(E_XMM + \r * 64)]
    .endr
    ldr     w0, [x16, #E_FPSTT]
    add     x1, x16, #E_FPREGS
    mm_load 0, 30
    mm_load 1, 6
    mm_load 2, 7
    mm_load 4, 10
    mm_load 5, 11
    mm_load 6, 12
    mm_load 7, 15
    ldp     x8, x0, [x16, #0x00]        /* RAX, RCX */
    ldp     x1, x27, [x16, #0x10]       /* RDX, RBX */
    ldp     x17, x29, [x16, #0x20]      /* RSP, RBP */
    ldp     x25, x26, [x16, #0x30]      /* RSI, RDI */
    ldp     x2, x3, [x16, #0x40]        /* R8-R11 */
    ldp     x4, x5, [x16, #0x50]
    ldp     x19, x20, [x16, #0x60]      /* R12-R15 */
    ldp     x21, x22, [x16, #0x70]
    mov     sp, x17
.endm

    .globl "#xt_ec_exit_native_env"
    .def "#xt_ec_exit_native_env"; .scl 2; .type 32; .endef
"#xt_ec_exit_native_env":
    exit_loads

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
    adm_exit
xt_ec_exit_withdrawn:
    ldr     x17, [x18, #TEB_CPU_AREA]
    strb    wzr, [x17]
    ldr     x17, [x17, #AREA_DOORBELL]
    cbz     x17, 4f
    ldr     w17, [x17]
    cbnz    w17, xt_ec_exit_suspend_point
4:
    .globl xt_ec_exit_resume_point
xt_ec_exit_resume_point:
    ldursw  x16, [x9, #-4]
    mov     w17, #0x0200
    movk    w17, #0xd63f, lsl #16       /* blr x16 */
    cmp     w16, w17
    mov     x17, x9
    b.eq    6f
    and     x16, x16, #-4
    add     x17, x9, x16
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

/*
 * The bypass's withdrawal: native code reached from an entry, outside
 * simulation, so in registers an x64 context keeps (x10-x12, dead at the
 * entry); then the dispatch, after the engine exit's withdrawal.
 */
xt_ec_bypass_dispatch:
    adm_exit 10, 11, 12
    b       xt_ec_exit_withdrawn

/* Its inject copy, for the inject entries' bypass. */
xt_ec_bypass_dispatch_inj:
    adm_exit 10, 11, 12, TP_BYPASS
    b       xt_ec_exit_withdrawn

    .globl xt_ec_exit_suspend_point
xt_ec_exit_suspend_point:
    brk     #0xcafe

/*
 * Admission's ends in C (arm64ec-gate.c), none of which returns: a
 * refused attempt, a parked or poisoned word, a COUNT full or a SEQ that
 * would wrap.  sp is aligned first, wherever the entry found it.  A
 * thread with no gate never got its ThreadInit: a module fault.
 */
xt_ec_adm_reject_entry:
    mov     x0, x16
    add     x1, x11, #1
    mov     x17, sp
    and     x17, x17, #0xfffffffffffffff0
    mov     sp, x17
    bl      "#xt_adm_reject"
xt_ec_adm_park_entry:
    mov     x0, x16
    mov     x17, sp
    and     x17, x17, #0xfffffffffffffff0
    mov     sp, x17
    bl      "#xt_adm_park"
xt_ec_adm_poison_entry:
    mov     x0, x16
    mov     x17, sp
    and     x17, x17, #0xfffffffffffffff0
    mov     sp, x17
    bl      "#xt_adm_poison_park"
xt_ec_adm_nogate:
    brk     #0xf0a0

/*
 * xt_ec_exit_native_env and the dispatch's start with XTAJIT_INJECT's
 * test points; a suspension at the doorbell resumes in the original.
 */
    .globl "#xt_ec_exit_native_env_inj"
    .def "#xt_ec_exit_native_env_inj"; .scl 2; .type 32; .endef
"#xt_ec_exit_native_env_inj":
    inj_point 4, 3, 4
    exit_loads
    inj_point 5, 16, 17
    adm_exit
    ldr     x17, [x18, #TEB_CPU_AREA]
    strb    wzr, [x17]
    ldr     x17, [x17, #AREA_DOORBELL]
    cbz     x17, 4f
    ldr     w17, [x17]
    cbnz    w17, xt_ec_exit_suspend_point
4:
    inj_point 6, 16, 17
    b       xt_ec_exit_resume_point

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


/*
 * uint64_t xt_tp_jump_asm(target, arg) (test-tp.c's xt_tp_jump): TARGET
 * entered through DispatchJump, as an adjustor thunk enters a possibly
 * x64 function, with ARG in RCX and the return right after a "blr x16"
 * (a return into an exit thunk, to the dispatch).  x64 code keeps what
 * the AArch64 convention needs kept but x23, x24 and x28, which ARM64EC
 * code doesn't use; 32 bytes of home space under the return address.
 */
    .globl "#xt_tp_jump_asm"
    .def "#xt_tp_jump_asm"; .scl 2; .type 32; .endef
"#xt_tp_jump_asm":
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    sub     sp, sp, #32
    mov     x9, x0
    mov     x0, x1
    adrp    x16, DispatchJump
    add     x16, x16, :lo12:DispatchJump
    blr     x16
    mov     x0, x8
    add     sp, sp, #32
    ldp     x29, x30, [sp], #16
    ret

/*
 * void xt_tp_fault(void) (the test points' fault action): one load that
 * faults, at xt_tp_fault_pc, which the module's exception paths recognise
 * and continue past (ResetToConsistentState, or test-tp.c's handler).
 * It changes x16 alone.
 */
    .globl "#xt_tp_fault"
    .def "#xt_tp_fault"; .scl 2; .type 32; .endef
"#xt_tp_fault":
    mov     x16, #8
    .globl  xt_tp_fault_pc
xt_tp_fault_pc:
    ldr     x16, [x16]
    ret

    .section .drectve, "yn"
    .ascii " -export:DispatchJump,DATA"
    .ascii " -export:RetToEntryThunk,DATA"
    .ascii " -export:ExitToX64,DATA"
    .ascii " -export:BeginSimulation,DATA"
