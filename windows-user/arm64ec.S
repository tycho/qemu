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
#define F_RESUME    0x3c0
#define F_RESUME_GO 0x3c8
#define F_KIND      0x3d0
#define F_FR_KEY    0x3e0       /* x-ecfast's resume in assembly */
#define F_FR_LAND   0x3e8
#define F_FR_RSP    0x3f0
#define F_FR_NEXT   0x3f8       /* then fr_slot */
#define F_FR_T      0x408       /* then fr_cs */
#define F_FR_READER 0x418
#define F_FR_FLUSH  0x420
#define F_FR_LO     0x428       /* then fr_hi */
#define F_DEP_FPSR  0x3d8
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
#define E_EIP       0x100
#define E_CC_SRC    0x118
#define E_CC_OP     0x128
#define E_EFLAGS_IN_TCG 0x3c50  /* X86CPU's, from env */
#define E_MXCSR     0x3c0
#define E_DR6       0x34d8
#define E_RETSP     0x3c38
#define E_SEGS      0x138       /* ES-GS: selector, then base at 8 */
#define E_SEG       0x18

/*
 * What x-ecfast's resume in assembly reads and writes of the thread's
 * record (XtThread), its CPU (CPUState), its RCU reader and the code
 * buffer's context (TBContext), as arm64ec.c checks them; XtState's and
 * XtActive's values.
 */
#define T_STATE         0x20
#define T_ACTIVE        0x24
#define T_ACTIVATION    0x28
#define T_SUSPEND_REQ   0x2c
#define T_TERMINATING   0x30
#define T_GFAULT_CODE   0x34
#define T_AFTER_SUSPEND 0x3a
#define T_BP_SKIP       0x3b
#define T_EC_SUSPENDED  0x3d
#define T_BP_HIT        0x40
#define T_READER        0x10
#define T_TEB           0x18
#define T_EC_SEEN       0x3c
#define T_NATIVE_TARGET 0x48
#define T_FAULT_BUSY    0xb0
#define T_CO_RSP        0x6d0
#define T_CO_FLUSH      0x6d8
#define CS_HOST_FP      0x208   /* host_fp_guest, then host_fp_suspended */
#define CS_SSTEP        0xe4
#define CS_BREAKPOINTS  0x280
#define CS_CAN_DO_IO    0x4344
#define R_WAITING       0x04
#define AREA_RECORD     0x30    /* EmulatorData[0] */
#define CS_RUNNING      0xc4
#define CS_EXIT_REQUEST 0xd7
#define CS_CFLAGS_NEXT  0xdc
#define CS_INTERRUPT_REQUEST 0xe0
#define CS_EXCEPTION_INDEX 0x300
#define CS_ICOUNT_HIGH  0x4342
#define R_CTR           0x00
#define R_DEPTH         0x08
#define TBC_FLUSH_COUNT 0x28
#define XT_ACQUIRING    1
#define XT_ENGINE       2
#define XT_ACT_EXEC     1
#define FPCR_QEMU       6       /* HOST_FP_CONTROL_QEMU */
#define XT_EC_FAST_START 1
#define XT_EC_FAST_CLEAR 2
#define XT_EC_TAIL_RCU  1
#define XT_EC_TAIL_EXCL 2

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

/*
 * The entries' common part; with INJ, XTAJIT_INJECT's points 1-3.  With
 * SLOW, x-ecfast's resume in assembly where it can't finish: the same,
 * with xt_ec_fast_slow(frame, w6) for xt_ec_enter.
 */
.macro entry_tail inj, slow=0
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
    /*
     * Below a TB's frame left for native code (x-ecinline), which the
     * entry then resumes or discards; else from the stack's base.
     */
    ldr     x0, [x16, #F_RESUME]
    cbnz    x0, 9f
    ldr     x0, [x17, #AREA_STACK_BASE]
9:
    mov     sp, x0
    mov     x0, x16
.if \slow
    mov     w1, w6
    bl      "#xt_ec_fast_slow"
.else
    bl      "#xt_ec_enter"
.endif
    /*
     * Returned: a resume (x-ecinline), by a jump, so that the host's
     * return predictor holds what it held when the TB left:
     * tcg_ec_resume_entry(env, code, the frame's sp).
     */
    ldr     x17, [x18, #TEB_CPU_AREA]
    ldr     x16, [x17, #AREA_FRAME]
    mov     x1, x0
    ldr     x0, [x16, #F_ENV]
    ldr     x2, [x16, #F_RESUME_GO]
    adrp    x16, tcg_ec_resume_entry
    ldr     x16, [x16, :lo12:tcg_ec_resume_entry]
    br      x16

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
    /* A return: x-ecfast's resume in assembly, if it can. */
    tbnz    w15, #1, xt_ec_fast_resume
    b       xt_ec_entry_tail

    .globl ExitToX64
ExitToX64:
    cap_check 3
    adm_enter
    str     lr, [sp, #-8]!      /* the x64 return address */
    mov     w15, #1             /* XT_EC_ENTRY_CALL */
xt_ec_entry_tail:
    entry_tail 0

/*
 * x-ecfast's resume (ec_fast_asm_ok, ec_fast_frame): the return of a call
 * a TB left for native code (x-ecinline) with its frame kept
 * XT_EC_KEPT_FAST, and nothing for the engine to do, goes back into the
 * TB's code without C, the host FP state still held from the departure.
 * After entry_tail's first steps (InSimulation set, NZCV saved), the
 * checks of the C resume (ec_enter_kept), in registers the x64 state
 * doesn't use (x6, x7, x10-x14, x16, x17, x23, x24), with the return
 * address in x9 and the entry's kind in w15 untouched: the frame kept
 * XT_EC_KEPT_FAST with a key (not 0), the key the return address, RSP
 * past it, no single step coming in (NZCV's bit 21), FPCR still QEMU's
 * mode, no test injection.  A failure goes to
 * entry_tail, with NZCV as it came.  Then ec_resume's acquisition, the
 * activation counted first (ec_thread): the record's state, cpu_exec_start
 * (its barrier membarrier's placeholder), the RCU read section; under
 * ownership ec_resume_clear's checks.  An exclusive section pending, or a
 * check failing, goes to xt_ec_fast_slow, through entry_tail's capture.
 * Then the frame consumed and the landing taken (the departure found
 * them: fr_next, fr_slot), the import (xt_ec_import_fast: EIP, the flags
 * from NZCV with PF and AF 0, CC_OP_EFLAGS), the record's state; then the
 * incoming registers moved into the TBs' and tcg_ec_resume_fast_entry
 * returns to the landing on the TB's frame.
 */
xt_ec_fast_resume:
    ldr     x17, [x18, #TEB_CPU_AREA]
    mov     w16, #1
    strb    w16, [x17]
    mrs     x24, nzcv
    ldr     x16, [x17, #AREA_FRAME]
    ldr     x10, [x16, #F_FR_KEY]
    ldr     x12, [x16, #F_FR_RSP]
    ldr     x13, [x16, #F_RESUME]
    ldr     w11, [x16, #F_KIND]
    mov     x14, sp
    cmp     x10, x9
    ccmp    x12, x14, #0, eq
    ccmp    w11, #1, #0, eq             /* XT_EC_KEPT_FAST */
    b.ne    .Lfr_decline
    cbz     x10, .Lfr_decline
    cbz     x13, .Lfr_decline
    tbnz    w24, #21, .Lfr_decline
    mrs     x10, fpcr
    cmp     x10, #FPCR_QEMU
    b.ne    .Lfr_decline
    adrp    x10, xt_inject_point
    ldr     w10, [x10, :lo12:xt_inject_point]
    cbnz    w10, .Lfr_decline
    ldr     x12, [x16, #F_FR_T]         /* the record */
    ldr     x13, [x16, #(F_FR_T + 8)]   /* the CPU */
    ldr     x14, [x16, #F_FR_READER]
    ldr     w10, [x12, #T_ACTIVATION]
    add     w10, w10, #1
    str     w10, [x12, #T_ACTIVATION]
    strb    wzr, [x12, #T_EC_SUSPENDED]
    mov     w10, #XT_ACQUIRING
    mov     w11, #XT_ACT_EXEC
    stp     w10, w11, [x12, #T_STATE]
    mov     w10, #1
    strb    w10, [x13, #CS_RUNNING]
    adrp    x10, pending_cpus
    ldr     w10, [x10, :lo12:pending_cpus]
    cbnz    w10, .Lfr_start
    ldr     w10, [x14, #R_DEPTH]
    add     w11, w10, #1
    str     w11, [x14, #R_DEPTH]
    cbnz    w10, 1f
    adrp    x10, rcu_gp_ctr
    ldr     w10, [x10, :lo12:rcu_gp_ctr]
    str     w10, [x14, #R_CTR]
1:
    ldr     w10, [x12, #T_SUSPEND_REQ]
    ldr     w11, [x12, #T_TERMINATING]
    orr     w10, w10, w11
    ldrb    w11, [x13, #CS_EXIT_REQUEST]
    orr     w10, w10, w11
    ldr     w11, [x13, #CS_INTERRUPT_REQUEST]
    orr     w10, w10, w11
    ldr     w11, [x13, #CS_CFLAGS_NEXT]
    add     w11, w11, #1                /* -1: none */
    orr     w10, w10, w11
    ldr     w11, [x13, #CS_EXCEPTION_INDEX]
    mvn     w11, w11
    orr     w10, w10, w11, lsr #31      /* none: below 0 */
    add     x11, x13, #(CS_ICOUNT_HIGH & ~0xfff)
    ldrh    w11, [x11, #(CS_ICOUNT_HIGH & 0xfff)]
    orr     w10, w10, w11
    adrp    x11, tb_ctx
    add     x11, x11, :lo12:tb_ctx
    ldr     w11, [x11, #TBC_FLUSH_COUNT]
    ldr     w23, [x16, #F_FR_FLUSH]
    eor     w11, w11, w23
    orr     w10, w10, w11
    cbnz    w10, .Lfr_clear
    /* The frame consumed, its landing taken. */
    ldr     x10, [x16, #F_RESUME]
    str     xzr, [x16, #F_RESUME]
    str     x10, [x16, #F_RESUME_GO]
    str     wzr, [x16, #F_KIND]
    str     xzr, [x16, #F_FR_KEY]
    ldr     x10, [x16, #F_FR_NEXT]
    ldr     x11, [x16, #(F_FR_NEXT + 8)]
    str     x10, [x11]
    /* The import. */
    ldr     x10, [x16, #F_ENV]
    str     x9, [x10, #E_EIP]
    ubfx    w11, w24, #30, #2           /* N, Z: SF, ZF */
    lsl     w11, w11, #6
    ubfx    w23, w24, #29, #1           /* C: CF */
    orr     w11, w11, w23
    ubfx    w23, w24, #28, #1           /* V: OF */
    orr     w11, w11, w23, lsl #11
    str     x11, [x10, #E_CC_SRC]
    str     wzr, [x10, #E_CC_OP]        /* CC_OP_EFLAGS */
    add     x11, x10, #(E_EFLAGS_IN_TCG & ~0xfff)
    mov     w23, #1
    strb    w23, [x11, #(E_EFLAGS_IN_TCG & 0xfff)]
    strb    wzr, [x12, #T_BP_SKIP]
    str     xzr, [x12, #T_BP_HIT]
    mov     w11, #XT_ENGINE
    str     w11, [x12, #T_STATE]
    strb    wzr, [x12, #T_AFTER_SUSPEND]
    str     wzr, [x12, #T_GFAULT_CODE]
    /*
     * The incoming registers into the TBs': each source read before its
     * register is written, the RAX/R14 pair through x17.
     */
    mov     x11, x20                    /* R13 */
    mov     x10, x22                    /* R15 */
    mov     x23, x27                    /* RBX */
    mov     x24, x1                     /* RDX */
    mov     x12, x3                     /* R9 */
    mov     x13, x4                     /* R10 */
    mov     x14, x2                     /* R8 */
    mov     x15, x5                     /* R11 */
    mov     x9, x29                     /* RBP */
    mov     x20, sp                     /* RSP */
    mov     x22, x26                    /* RDI */
    mov     x26, x19                    /* R12 */
    mov     x27, x25                    /* RSI */
    mov     x25, x0                     /* RCX */
    mov     x17, x21
    mov     x21, x8                     /* RAX */
    mov     x8, x17                     /* R14 */
    mov     v23.16b, v15.16b            /* XMM0-15 into v8-v23 */
    mov     v22.16b, v14.16b
    mov     v21.16b, v13.16b
    mov     v20.16b, v12.16b
    mov     v19.16b, v11.16b
    mov     v18.16b, v10.16b
    mov     v17.16b, v9.16b
    mov     v16.16b, v8.16b
    mov     v15.16b, v7.16b
    mov     v14.16b, v6.16b
    mov     v13.16b, v5.16b
    mov     v12.16b, v4.16b
    mov     v11.16b, v3.16b
    mov     v10.16b, v2.16b
    mov     v9.16b, v1.16b
    mov     v8.16b, v0.16b
    ldr     x0, [x16, #F_ENV]
    ldr     x1, [x16, #F_FR_LAND]
    ldr     x2, [x16, #F_RESUME_GO]
    adrp    x17, tcg_ec_resume_fast_entry
    ldr     x17, [x17, :lo12:tcg_ec_resume_fast_entry]
    br      x17
.Lfr_decline:
    msr     nzcv, x24
    b       xt_ec_entry_tail
.Lfr_start:
    mov     w6, #XT_EC_FAST_START
    b       .Lfr_slow
.Lfr_clear:
    mov     w6, #XT_EC_FAST_CLEAR
.Lfr_slow:
    msr     nzcv, x24
    entry_tail 0, 1

/*
 * x-ecfast's departure (tcg_ec_callout_fast_fn): a TB's call-out to
 * native code, with the default FP control, keeps the TB's frame
 * XT_EC_KEPT_FAST and leaves without C, as ec_callout's x-ecfast branch
 * does.  Entered from tcg_ec_callout_entry with the TB boundary's state
 * stored to env and still in the TBs' registers (ec_fast_asm_ok's
 * placement), env in x19, sp the TB's frame, and x0 the entry's call of
 * ec_callout, where it goes, having written nothing, if it can't leave:
 * not ready (xt_ec_fast_asm), a test injection, a target that isn't EC
 * code (the EC bitmap), any of ec_callout's declines (a kept frame, a
 * fault continuation, one-shot cflags, a request), the FP state not the
 * default (held, MXCSR's control default), the segments not as an
 * entry loads them, single stepping or a breakpoint, or no landing on
 * the return stack's top (x28, in the ring the C departure found, fr_lo
 * and fr_hi: 0 before).  Scratch: x0-x7, x16, x17 and x30.  Then
 * ec_callout's bookkeeping and ec_fast_frame's, the release (the RCU read
 * section, cpu_exec_end, their barriers membarrier's placeholders) with
 * any tail owed in C (xt_ec_fast_depart_tail, FPSR kept across it, after
 * which the registers go from env as xt_ec_exit_native_env's), the frame
 * kept, xt_publish's end state, DR6's clear; then the registers moved to
 * their ARM64EC places and xt_ec_exit_dispatch.
 */
    .globl xt_ec_fast_depart
xt_ec_fast_depart:
    adrp    x16, xt_ec_fast_asm
    ldrb    w16, [x16, :lo12:xt_ec_fast_asm]
    adrp    x17, xt_inject_point
    ldr     w17, [x17, :lo12:xt_inject_point]
    eor     w16, w16, #1
    orr     w16, w16, w17
    cbnz    w16, .Lfd_decline
    ldr     x1, [x19, #E_EIP]
    lsr     x17, x1, #47
    cbnz    x17, .Lfd_decline
    ldr     x16, [x18, #TEB_PEB]
    ldr     x16, [x16, #PEB_EC_BITMAP]
    lsr     x17, x1, #18
    ldr     x16, [x16, x17, lsl #3]
    lsr     x17, x1, #12
    lsr     x16, x16, x17
    tbz     x16, #0, .Lfd_decline
    ldr     x2, [x18, #TEB_CPU_AREA]
    ldr     x3, [x2, #AREA_FRAME]
    ldr     x4, [x2, #AREA_RECORD]
    ldr     x5, [x4]                    /* the record's CPU */
    ldr     x16, [x3, #F_RESUME]
    ldr     w17, [x4, #T_FAULT_BUSY]
    orr     x16, x16, x17
    ldr     w17, [x4, #T_SUSPEND_REQ]
    orr     x16, x16, x17
    ldr     w17, [x5, #CS_CFLAGS_NEXT]
    add     w17, w17, #1                /* -1: none */
    orr     x16, x16, x17
    ldrb    w17, [x5, #CS_EXIT_REQUEST]
    orr     x16, x16, x17
    add     x17, x5, #(CS_ICOUNT_HIGH & ~0xfff)
    ldrh    w17, [x17, #(CS_ICOUNT_HIGH & 0xfff)]
    orr     x16, x16, x17
    ldrh    w17, [x5, #CS_HOST_FP]
    eor     w17, w17, #1                /* held, not suspended */
    orr     x16, x16, x17
    ldr     w17, [x19, #E_MXCSR]
    mov     w30, #0xe040                /* RC, FTZ, DAZ */
    and     w17, w17, w30
    orr     x16, x16, x17
    ldr     w17, [x5, #CS_SSTEP]
    and     w17, w17, #1                /* SSTEP_ENABLE */
    orr     x16, x16, x17
    ldr     x17, [x5, #CS_BREAKPOINTS]
    orr     x16, x16, x17
    /* The segments as an entry loads them (xt_ec_segs_loaded). */
    add     x2, x19, #E_SEGS
    ldr     w17, [x2, #(0 * E_SEG)]     /* ES */
    ldr     x30, [x2, #(0 * E_SEG + 8)]
    sub     w17, w17, #0x2b
    orr     x17, x17, x30
    orr     x16, x16, x17
    ldr     w17, [x2, #(1 * E_SEG)]     /* CS */
    ldr     x30, [x2, #(1 * E_SEG + 8)]
    sub     w17, w17, #0x33
    orr     x17, x17, x30
    orr     x16, x16, x17
    ldr     w17, [x2, #(2 * E_SEG)]     /* SS */
    ldr     x30, [x2, #(2 * E_SEG + 8)]
    sub     w17, w17, #0x2b
    orr     x17, x17, x30
    orr     x16, x16, x17
    ldr     w17, [x2, #(3 * E_SEG)]     /* DS */
    ldr     x30, [x2, #(3 * E_SEG + 8)]
    sub     w17, w17, #0x2b
    orr     x17, x17, x30
    orr     x16, x16, x17
    ldr     w17, [x2, #(4 * E_SEG)]     /* FS */
    ldr     x30, [x2, #(4 * E_SEG + 8)]
    sub     w17, w17, #0x53
    orr     x17, x17, x30
    orr     x16, x16, x17
    ldr     w17, [x2, #(5 * E_SEG)]     /* GS, its base the TEB */
    ldr     x30, [x2, #(5 * E_SEG + 8)]
    ldr     x6, [x4, #T_TEB]
    sub     w17, w17, #0x2b
    eor     x30, x30, x6
    orr     x17, x17, x30
    orr     x16, x16, x17
    cbnz    x16, .Lfd_decline
    ldr     x16, [x3, #F_FR_LO]
    ldr     x17, [x3, #(F_FR_LO + 8)]
    cmp     x28, x16
    ccmp    x28, x17, #2, hs
    b.hs    .Lfd_decline
    ldp     x6, x7, [x28]               /* the top's key and landing */
    cmp     x7, #1
    b.le    .Lfd_decline
    /* ec_callout's bookkeeping. */
    strb    wzr, [x4, #T_EC_SEEN]
    str     x1, [x4, #T_NATIVE_TARGET]
    str     x20, [x4, #T_CO_RSP]        /* RSP */
    adrp    x16, tb_ctx
    add     x16, x16, :lo12:tb_ctx
    ldr     w16, [x16, #TBC_FLUSH_COUNT]
    str     w16, [x4, #T_CO_FLUSH]
    mov     w17, #-1
    str     w17, [x5, #CS_EXCEPTION_INDEX]
    add     x17, x5, #(CS_CAN_DO_IO & ~0xfff)
    mov     w30, #1
    strb    w30, [x17, #(CS_CAN_DO_IO & 0xfff)]
    mrs     x17, fpsr
    mov     w30, #0x9f                  /* HOST_FPSR_FLAGS */
    and     x17, x17, x30
    str     x17, [x3, #F_DEP_FPSR]
    mov     w17, #1                     /* XT_EC_KEPT_FAST */
    str     w17, [x3, #F_KIND]
    /* The return's, for the resume. */
    str     x6, [x3, #F_FR_KEY]
    str     x7, [x3, #F_FR_LAND]
    add     x17, x20, #8
    str     x17, [x3, #F_FR_RSP]
    add     x17, x28, #16
    str     x17, [x3, #F_FR_NEXT]
    str     w16, [x3, #F_FR_FLUSH]
    add     x17, x19, #(E_RETSP & ~0xfff)
    add     x17, x17, #(E_RETSP & 0xfff)
    str     x17, [x3, #(F_FR_NEXT + 8)] /* fr_slot */
    ldr     x6, [x4, #T_READER]
    str     x4, [x3, #F_FR_T]
    str     x5, [x3, #(F_FR_T + 8)]     /* fr_cs */
    str     x6, [x3, #F_FR_READER]
    /* The release: rcu_read_unlock_reader, cpu_exec_end. */
    mov     w2, #0
    ldr     w16, [x6, #R_DEPTH]
    sub     w16, w16, #1
    str     w16, [x6, #R_DEPTH]
    cbnz    w16, 1f
    stlr    wzr, [x6]                   /* ctr */
    ldrb    w16, [x6, #R_WAITING]
    cbz     w16, 1f
    orr     w2, w2, #XT_EC_TAIL_RCU
1:
    strb    wzr, [x5, #CS_RUNNING]
    adrp    x16, pending_cpus
    ldr     w16, [x16, :lo12:pending_cpus]
    cbz     w16, 2f
    orr     w2, w2, #XT_EC_TAIL_EXCL
2:
    str     wzr, [x4, #T_ACTIVE]        /* XT_ACT_NONE */
    mov     x16, sp
    str     x16, [x3, #F_RESUME]
    str     wzr, [x4, #T_STATE]         /* XT_WINDOWS */
    add     x16, x19, #(E_DR6 & ~0xfff)
    ldr     x17, [x16, #(E_DR6 & 0xfff)]
    mov     w30, #0x400f                /* DR6_BS | B0-B3 */
    tst     x17, x30
    b.eq    3f
    str     xzr, [x16, #(E_DR6 & 0xfff)]
3:
    cbnz    w2, .Lfd_tail
    /*
     * The registers into their ARM64EC places: each source read before
     * its register is written, the RAX/R14 pair through x17.
     */
    mov     x16, x1                     /* the target */
    mov     x0, x25                     /* RCX */
    mov     x1, x24                     /* RDX */
    mov     x2, x14                     /* R8 */
    mov     x3, x12                     /* R9 */
    mov     x4, x13                     /* R10 */
    mov     x5, x15                     /* R11 */
    mov     x25, x27                    /* RSI */
    mov     x27, x23                    /* RBX */
    mov     x29, x9                     /* RBP */
    mov     x19, x26                    /* R12 */
    mov     x26, x22                    /* RDI */
    mov     x22, x10                    /* R15 */
    mov     sp, x20                     /* RSP */
    mov     x20, x11                    /* R13 */
    mov     x17, x21
    mov     x21, x8                     /* R14 */
    mov     x8, x17                     /* RAX */
    mov     x9, x16
    mov     v0.16b, v8.16b              /* XMM0-15 from v8-v23 */
    mov     v1.16b, v9.16b
    mov     v2.16b, v10.16b
    mov     v3.16b, v11.16b
    mov     v4.16b, v12.16b
    mov     v5.16b, v13.16b
    mov     v6.16b, v14.16b
    mov     v7.16b, v15.16b
    mov     v8.16b, v16.16b
    mov     v9.16b, v17.16b
    mov     v10.16b, v18.16b
    mov     v11.16b, v19.16b
    mov     v12.16b, v20.16b
    mov     v13.16b, v21.16b
    mov     v14.16b, v22.16b
    mov     v15.16b, v23.16b
    b       xt_ec_exit_dispatch
.Lfd_tail:
    /* FPSR is still the guest's: kept in x20 (RSP, in env) across C. */
    mrs     x20, fpsr
    mov     x0, x4
    mov     w1, w2
    bl      "#xt_ec_fast_depart_tail"
    msr     fpsr, x20
    mov     x0, x19
    ldr     x1, [x19, #E_EIP]
    mov     w2, #2                      /* no YMM, no MMX */
    b       "#xt_ec_exit_native_env"
.Lfd_decline:
    br      x0

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
 * void xt_ec_exit_native_env(env, target, how): leave the engine for
 * native code at TARGET with the guest state of ENV in its ARM64EC places
 * (xt_ec_pack's, without the frame): the x64 registers, sp the guest's;
 * MM0-7's mantissas from the x87 stack top on, in x30, x6, x7, (x9),
 * x10-x12 and x15, where x9 takes the target and the dispatch may replace
 * lr, unless HOW's bit 1 (x-ecfast's call-out: they are volatile across
 * a call); with HOW's bit 0 (YMM), v16-v31 the upper halves, so the
 * thread's context shows them until native code changes them.  The
 * arguments are taken before the registers they arrive in are loaded.
 * The engine has given the thread back; no frame of the emulator stack
 * is live.
 */
.macro exit_loads
    mov     x16, x0
    mov     x9, x1
    mov     w13, w2
    tbz     w13, #0, 1f
    .irp    r, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
    ldr     q\r, [x16, #(E_XMM + 16 + (\r - 16) * 64)]
    .endr
1:
    .irp    r, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    ldr     q\r, [x16, #(E_XMM + \r * 64)]
    .endr
    tbnz    w13, #1, 2f
    ldr     w0, [x16, #E_FPSTT]
    add     x1, x16, #E_FPREGS
    mm_load 0, 30
    mm_load 1, 6
    mm_load 2, 7
    mm_load 4, 10
    mm_load 5, 11
    mm_load 6, 12
    mm_load 7, 15
2:
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
