/* SPDX-License-Identifier: MIT */
/*
 * Target independent opcode generation functions.
 *
 * Copyright (c) 2008 Fabrice Bellard
 */

#ifndef TCG_TCG_OP_COMMON_H
#define TCG_TCG_OP_COMMON_H

#include "tcg/tcg.h"
#include "exec/helper-proto-common.h"
#include "exec/helper-gen-common.h"

QEMU_RET_NONNULL
TCGv_i32 tcg_constant_i32(int32_t val);
QEMU_RET_NONNULL
TCGv_i64 tcg_constant_i64(int64_t val);
QEMU_RET_NONNULL
TCGv_vaddr tcg_constant_vaddr(uintptr_t val);
QEMU_RET_NONNULL
TCGv_vec tcg_constant_vec(TCGType type, unsigned vece, int64_t val);
QEMU_RET_NONNULL
TCGv_vec tcg_constant_vec_matching(TCGv_vec match, unsigned vece, int64_t val);

QEMU_RET_NONNULL
TCGv_i128 tcg_zero_i128(void);

QEMU_RET_NONNULL
TCGv_i32 tcg_temp_new_i32(void);
QEMU_RET_NONNULL
TCGv_i64 tcg_temp_new_i64(void);
QEMU_RET_NONNULL
TCGv_ptr tcg_temp_new_ptr(void);
QEMU_RET_NONNULL
TCGv_i128 tcg_temp_new_i128(void);
QEMU_RET_NONNULL
TCGv_vec tcg_temp_new_vec(TCGType type);
QEMU_RET_NONNULL
TCGv_vec tcg_temp_new_vec_matching(TCGv_vec match);

QEMU_RET_NONNULL
TCGv_i32 tcg_global_mem_new_i32(TCGv_ptr reg, intptr_t off, const char *name);
QEMU_RET_NONNULL
TCGv_i64 tcg_global_mem_new_i64(TCGv_ptr reg, intptr_t off, const char *name);
QEMU_RET_NONNULL
TCGv_ptr tcg_global_mem_new_ptr(TCGv_ptr reg, intptr_t off, const char *name);

/* Generic ops.  */
static inline void tcg_gen_insn_start(uint64_t pc, uint64_t a1,
                                      uint64_t a2)
{
    TCGOp *op = tcg_emit_op(INDEX_op_insn_start, INSN_START_WORDS);
    tcg_set_insn_start_param(op, 0, pc);
    tcg_set_insn_start_param(op, 1, a1);
    tcg_set_insn_start_param(op, 2, a2);
}

QEMU_ARG_NONNULL void gen_set_label(TCGLabel *l);
QEMU_ARG_NONNULL void tcg_gen_br(TCGLabel *l);
void tcg_gen_mb(TCGBar);

/**
 * tcg_gen_exit_tb() - output exit_tb TCG operation
 * @tb: The TranslationBlock from which we are exiting
 * @idx: Direct jump slot index, or exit request
 *
 * See tcg/README for more info about this TCG operation.
 * See also tcg.h and the block comment above TB_EXIT_MASK.
 *
 * For a normal exit from the TB, back to the main loop, @tb should
 * be NULL and @idx should be 0.  Otherwise, @tb should be valid and
 * @idx should be one of the TB_EXIT_ values.
 */
void tcg_gen_exit_tb(const TranslationBlock *tb, unsigned idx);

/**
 * tcg_gen_goto_tb() - output goto_tb TCG operation
 * @idx: Direct jump slot index (0 or 1)
 *
 * See tcg/README for more info about this TCG operation.
 *
 * NOTE: In system emulation, direct jumps with goto_tb are only safe within
 * the pages this TB resides in because we don't take care of direct jumps when
 * address mapping changes, e.g. in tlb_flush(). In user mode, there's only a
 * static address translation, so the destination address is always valid, TBs
 * are always invalidated properly, and direct jumps are reset when mapping
 * changes.
 */
void tcg_gen_goto_tb(unsigned idx);

/**
 * tcg_gen_lookup_and_goto_ptr() - look up the current TB, jump to it if valid
 * @addr: Guest address of the target TB
 *
 * If the TB is not valid, jump to the epilogue.
 *
 * This operation is optional. If the TCG backend does not implement goto_ptr,
 * this op is equivalent to calling tcg_gen_exit_tb() with 0 as the argument.
 */
void tcg_gen_lookup_and_goto_ptr(void);

void tcg_gen_plugin_cb(unsigned from);
QEMU_ARG_NONNULL
void tcg_gen_plugin_mem_cb(TCGv_i64 addr, unsigned meminfo);

/*
 * Construct operations from templates.
 */

#define DEF1(NAME, T1) \
    QEMU_ARG_NONNULL void glue(glue(tcg_gen_,NAME),TExt)(T1);
#define DEF2(NAME, T1, T2) \
    QEMU_ARG_NONNULL void glue(glue(tcg_gen_,NAME),TExt)(T1, T2);
#define DEF3(NAME, T1, T2, T3) \
    QEMU_ARG_NONNULL void glue(glue(tcg_gen_,NAME),TExt)(T1, T2, T3);
#define DEF4(NAME, T1, T2, T3, T4) \
    QEMU_ARG_NONNULL void glue(glue(tcg_gen_,NAME),TExt)(T1, T2, T3, T4);
#define DEF5(NAME, T1, T2, T3, T4, T5) \
    QEMU_ARG_NONNULL void glue(glue(tcg_gen_,NAME),TExt)(T1, T2, T3, T4, T5);
#define DEF6(NAME, T1, T2, T3, T4, T5, T6) \
    QEMU_ARG_NONNULL void glue(glue(tcg_gen_,NAME),TExt)(T1, T2, T3, T4, T5, T6);
#define DEF7(NAME, T1, T2, T3, T4, T5, T6, T7) \
    QEMU_ARG_NONNULL void glue(glue(tcg_gen_,NAME),TExt)(T1, T2, T3, T4, T5, T6, T7);

#define TCGV  glue(TCGv,TExt)
#define TExt  _i32
#define TINT  int32_t

#include "tcg-op-def.h.inc"

#undef TExt
#undef TINT

#define TExt  _i64
#define TINT  int64_t

#include "tcg-op-def.h.inc"

#undef TExt
#undef TINT
#undef TCGV

#undef DEF1
#undef DEF2
#undef DEF3
#undef DEF4
#undef DEF5
#undef DEF6
#undef DEF7

/* 32 bit ops */

QEMU_ARG_NONNULL
void tcg_gen_mulsu2_i32(TCGv_i32 rl, TCGv_i32 rh, TCGv_i32 arg1, TCGv_i32 arg2);
QEMU_ARG_NONNULL
void tcg_gen_bswap32_i32(TCGv_i32 ret, TCGv_i32 arg);
QEMU_ARG_NONNULL
void tcg_gen_hswap_i32(TCGv_i32 ret, TCGv_i32 arg);
QEMU_ARG_NONNULL
void tcg_gen_revbit32_i32(TCGv_i32 ret, TCGv_i32 arg);

/* 64 bit ops */

QEMU_ARG_NONNULL
void tcg_gen_addN_i64(int n, TCGv_i64 *r, TCGv_i64 *a, TCGv_i64 *b);
QEMU_ARG_NONNULL
void tcg_gen_mulsu2_i64(TCGv_i64 rl, TCGv_i64 rh, TCGv_i64 arg1, TCGv_i64 arg2);
QEMU_ARG_NONNULL
void tcg_gen_ext32s_i64(TCGv_i64 ret, TCGv_i64 arg);
QEMU_ARG_NONNULL
void tcg_gen_ext32u_i64(TCGv_i64 ret, TCGv_i64 arg);
QEMU_ARG_NONNULL
void tcg_gen_bswap32_i64(TCGv_i64 ret, TCGv_i64 arg, unsigned flags);
QEMU_ARG_NONNULL
void tcg_gen_bswap64_i64(TCGv_i64 ret, TCGv_i64 arg);
QEMU_ARG_NONNULL
void tcg_gen_hswap_i64(TCGv_i64 ret, TCGv_i64 arg);
QEMU_ARG_NONNULL
void tcg_gen_wswap_i64(TCGv_i64 ret, TCGv_i64 arg);
QEMU_ARG_NONNULL
void tcg_gen_revbit32_i64(TCGv_i64 ret, TCGv_i64 arg, unsigned flags);
QEMU_ARG_NONNULL
void tcg_gen_revbit64_i64(TCGv_i64 ret, TCGv_i64 arg);

QEMU_ARG_NONNULL
void tcg_gen_st32_i64(TCGv_i64 arg1, TCGv_ptr arg2, tcg_target_long offset);

QEMU_ARG_NONNULL
void tcg_gen_ld32u_i64(TCGv_i64 ret, TCGv_ptr arg2, tcg_target_long offset);
QEMU_ARG_NONNULL
void tcg_gen_ld32s_i64(TCGv_i64 ret, TCGv_ptr arg2, tcg_target_long offset);

/* Size changing operations.  */

QEMU_ARG_NONNULL
void tcg_gen_extu_i32_i64(TCGv_i64 ret, TCGv_i32 arg);
QEMU_ARG_NONNULL
void tcg_gen_ext_i32_i64(TCGv_i64 ret, TCGv_i32 arg);
QEMU_ARG_NONNULL
void tcg_gen_concat_i32_i64(TCGv_i64 dest, TCGv_i32 low, TCGv_i32 high);
QEMU_ARG_NONNULL
void tcg_gen_extrl_i64_i32(TCGv_i32 ret, TCGv_i64 arg);
QEMU_ARG_NONNULL
void tcg_gen_extrh_i64_i32(TCGv_i32 ret, TCGv_i64 arg);
QEMU_ARG_NONNULL
void tcg_gen_extr_i64_i32(TCGv_i32 lo, TCGv_i32 hi, TCGv_i64 arg);
QEMU_ARG_NONNULL
void tcg_gen_extr32_i64(TCGv_i64 lo, TCGv_i64 hi, TCGv_i64 arg);
QEMU_ARG_NONNULL
void tcg_gen_concat32_i64(TCGv_i64 ret, TCGv_i64 lo, TCGv_i64 hi);

QEMU_ARG_NONNULL
void tcg_gen_extr_i128_i64(TCGv_i64 lo, TCGv_i64 hi, TCGv_i128 arg);
QEMU_ARG_NONNULL
void tcg_gen_concat_i64_i128(TCGv_i128 ret, TCGv_i64 lo, TCGv_i64 hi);

/* 128 bit ops */

QEMU_ARG_NONNULL
void tcg_gen_mov_i128(TCGv_i128 dst, TCGv_i128 src);
QEMU_ARG_NONNULL
void tcg_gen_ld_i128(TCGv_i128 ret, TCGv_ptr base, tcg_target_long offset);
QEMU_ARG_NONNULL
void tcg_gen_st_i128(TCGv_i128 val, TCGv_ptr base, tcg_target_long offset);

QEMU_ARG_NONNULL
void tcg_gen_qemu_ld_chk_i128(TCGv_i128, TCGTemp *, TCGArg, MemOp, TCGType);
QEMU_ARG_NONNULL
void tcg_gen_qemu_st_chk_i128(TCGv_i128, TCGTemp *, TCGArg, MemOp, TCGType);

QEMU_ARG_NONNULL
void tcg_gen_atomic_cmpxchg_chk_i128(TCGv_i128, TCGTemp *, TCGv_i128,
                                     TCGv_i128, TCGArg, MemOp, TCGType);
QEMU_ARG_NONNULL
void tcg_gen_nonatomic_cmpxchg_chk_i128(TCGv_i128, TCGTemp *, TCGv_i128,
                                        TCGv_i128, TCGArg, MemOp, TCGType);
QEMU_ARG_NONNULL
void tcg_gen_atomic_xchg_chk_i128(TCGv_i128, TCGTemp *, TCGv_i128,
                                  TCGArg, MemOp, TCGType);
QEMU_ARG_NONNULL
void tcg_gen_atomic_fetch_and_chk_i128(TCGv_i128, TCGTemp *, TCGv_i128,
                                       TCGArg, MemOp, TCGType);
QEMU_ARG_NONNULL
void tcg_gen_atomic_fetch_or_chk_i128(TCGv_i128, TCGTemp *, TCGv_i128,
                                      TCGArg, MemOp, TCGType);

/* Vector ops */

QEMU_ARG_NONNULL
void tcg_gen_mov_vec(TCGv_vec, TCGv_vec);
QEMU_ARG_NONNULL
void tcg_gen_dup_i32_vec(unsigned vece, TCGv_vec, TCGv_i32);
QEMU_ARG_NONNULL
void tcg_gen_dup_i64_vec(unsigned vece, TCGv_vec, TCGv_i64);
QEMU_ARG_NONNULL
void tcg_gen_dup_mem_vec(unsigned vece, TCGv_vec, TCGv_ptr, tcg_target_long);
QEMU_ARG_NONNULL
void tcg_gen_dupi_vec(unsigned vece, TCGv_vec, uint64_t);
QEMU_ARG_NONNULL
void tcg_gen_add_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
QEMU_ARG_NONNULL
void tcg_gen_sub_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
QEMU_ARG_NONNULL
void tcg_gen_mul_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
QEMU_ARG_NONNULL
void tcg_gen_and_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
QEMU_ARG_NONNULL
void tcg_gen_or_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
QEMU_ARG_NONNULL
void tcg_gen_xor_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
QEMU_ARG_NONNULL
void tcg_gen_andc_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
QEMU_ARG_NONNULL
void tcg_gen_orc_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
QEMU_ARG_NONNULL
void tcg_gen_nand_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
QEMU_ARG_NONNULL
void tcg_gen_nor_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
QEMU_ARG_NONNULL
void tcg_gen_eqv_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
QEMU_ARG_NONNULL
void tcg_gen_not_vec(unsigned vece, TCGv_vec r, TCGv_vec a);
QEMU_ARG_NONNULL
void tcg_gen_neg_vec(unsigned vece, TCGv_vec r, TCGv_vec a);
QEMU_ARG_NONNULL
void tcg_gen_abs_vec(unsigned vece, TCGv_vec r, TCGv_vec a);
QEMU_ARG_NONNULL
void tcg_gen_ssadd_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
QEMU_ARG_NONNULL
void tcg_gen_usadd_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
QEMU_ARG_NONNULL
void tcg_gen_sssub_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
QEMU_ARG_NONNULL
void tcg_gen_ussub_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
QEMU_ARG_NONNULL
void tcg_gen_smin_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
QEMU_ARG_NONNULL
void tcg_gen_umin_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
QEMU_ARG_NONNULL
void tcg_gen_smax_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
QEMU_ARG_NONNULL
void tcg_gen_umax_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);

QEMU_ARG_NONNULL
void tcg_gen_shli_vec(unsigned vece, TCGv_vec r, TCGv_vec a, int64_t i);
QEMU_ARG_NONNULL
void tcg_gen_shri_vec(unsigned vece, TCGv_vec r, TCGv_vec a, int64_t i);
QEMU_ARG_NONNULL
void tcg_gen_sari_vec(unsigned vece, TCGv_vec r, TCGv_vec a, int64_t i);
QEMU_ARG_NONNULL
void tcg_gen_rotli_vec(unsigned vece, TCGv_vec r, TCGv_vec a, int64_t i);
QEMU_ARG_NONNULL
void tcg_gen_rotri_vec(unsigned vece, TCGv_vec r, TCGv_vec a, int64_t i);

QEMU_ARG_NONNULL
void tcg_gen_shls_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_i32 s);
QEMU_ARG_NONNULL
void tcg_gen_shrs_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_i32 s);
QEMU_ARG_NONNULL
void tcg_gen_sars_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_i32 s);
QEMU_ARG_NONNULL
void tcg_gen_rotls_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_i32 s);

QEMU_ARG_NONNULL
void tcg_gen_shlv_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec s);
QEMU_ARG_NONNULL
void tcg_gen_shrv_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec s);
QEMU_ARG_NONNULL
void tcg_gen_sarv_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec s);
QEMU_ARG_NONNULL
void tcg_gen_rotlv_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec s);
QEMU_ARG_NONNULL
void tcg_gen_rotrv_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec s);

QEMU_ARG_NONNULL
void tcg_gen_cmp_vec(TCGCond cond, unsigned vece, TCGv_vec r,
                     TCGv_vec a, TCGv_vec b);

/*
 * Host floating point on MO_32 or MO_64 elements, in the host's FP
 * environment.  There are no fallbacks: check tcg_can_emit_vec_op() first.
 */
void tcg_gen_fadd_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
void tcg_gen_fsub_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
void tcg_gen_fmul_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
void tcg_gen_fdiv_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
void tcg_gen_fmin_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
void tcg_gen_fmax_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
void tcg_gen_fsqrt_vec(unsigned vece, TCGv_vec r, TCGv_vec a);
void tcg_gen_fneg_vec(unsigned vece, TCGv_vec r, TCGv_vec a);
void tcg_gen_fmla_vec(unsigned vece, TCGv_vec r, TCGv_vec a,
                      TCGv_vec b, TCGv_vec c);
void tcg_gen_fmls_vec(unsigned vece, TCGv_vec r, TCGv_vec a,
                      TCGv_vec b, TCGv_vec c);
void tcg_gen_fcmp_vec(TCGCond cond, unsigned vece, TCGv_vec r,
                      TCGv_vec a, TCGv_vec b);
void tcg_gen_scvtf_vec(unsigned vece, TCGv_vec r, TCGv_vec a);
void tcg_gen_fcvtzs_vec(unsigned vece, TCGv_vec r, TCGv_vec a);
void tcg_gen_frintx_vec(unsigned vece, TCGv_vec r, TCGv_vec a);
/*
 * How frint_vec rounds: to nearest even, down, up, toward zero, or as set.
 * With TCG_FRINT_EXACT added to one of the first four, the rounding also
 * signals inexact, as frintx_vec does, where the result differs from the
 * input.
 */
typedef enum {
    TCG_FRINT_NEAREST,
    TCG_FRINT_DOWN,
    TCG_FRINT_UP,
    TCG_FRINT_ZERO,
    TCG_FRINT_CURRENT,
    TCG_FRINT_EXACT = 8,
} TCGFrint;
void tcg_gen_frint_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGFrint mode);
/*
 * The same on element 0 of 128-bit vectors.  The result's other elements
 * are those of the first input.
 */
void tcg_gen_fadds_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
void tcg_gen_fsubs_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
void tcg_gen_fmuls_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
void tcg_gen_fdivs_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
void tcg_gen_fmins_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
void tcg_gen_fmaxs_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
void tcg_gen_fsqrts_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
void tcg_gen_fmadds_vec(unsigned vece, TCGv_vec r, TCGv_vec a,
                        TCGv_vec b, TCGv_vec c);
void tcg_gen_fmsubs_vec(unsigned vece, TCGv_vec r, TCGv_vec a,
                        TCGv_vec b, TCGv_vec c);
void tcg_gen_fnmadds_vec(unsigned vece, TCGv_vec r, TCGv_vec a,
                         TCGv_vec b, TCGv_vec c);
void tcg_gen_fnmsubs_vec(unsigned vece, TCGv_vec r, TCGv_vec a,
                         TCGv_vec b, TCGv_vec c);
void tcg_gen_fcmps_vec(TCGCond cond, unsigned vece, TCGv_vec r,
                       TCGv_vec a, TCGv_vec b);
void tcg_gen_fcvts_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
void tcg_gen_movs_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
/*
 * Element 0 against general registers.  fcmp3: r = 0, 1, 2 or 3 for a
 * less than, equal to, greater than or unordered with b; signaling (any
 * NaN is invalid) or quiet.  scvtfs: element 0 of r = the signed integer
 * i (32 or 64 bits wide), the other elements a's.  fcvtzsi: the signed
 * integer (32 or 64 bits wide, as r is) of element 0 of a, rounded toward
 * zero; what an out-of-range value or a NaN gives is the host's choice.
 */
void tcg_gen_fcmp3_vec(unsigned vece, TCGv_i32 r, TCGv_vec a, TCGv_vec b,
                       bool signaling);
void tcg_gen_scvtfs_i32_vec(unsigned vece, TCGv_vec r, TCGv_vec a,
                            TCGv_i32 i);
void tcg_gen_scvtfs_i64_vec(unsigned vece, TCGv_vec r, TCGv_vec a,
                            TCGv_i64 i);
void tcg_gen_fcvtzsi_i32_vec(unsigned vece, TCGv_i32 r, TCGv_vec a);
void tcg_gen_fcvtzsi_i64_vec(unsigned vece, TCGv_i64 r, TCGv_vec a);
/*
 * Estimates of 1/x and 1/sqrt(x) with a relative error of at most
 * 1.5 * 2^-12; the scalar forms on element 0, the other elements from a.
 */
void tcg_gen_frecpe_vec(unsigned vece, TCGv_vec r, TCGv_vec a);
void tcg_gen_frsqrte_vec(unsigned vece, TCGv_vec r, TCGv_vec a);
void tcg_gen_frecpes_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);
void tcg_gen_frsqrtes_vec(unsigned vece, TCGv_vec r, TCGv_vec a, TCGv_vec b);

QEMU_ARG_NONNULL
void tcg_gen_bitsel_vec(unsigned vece, TCGv_vec r, TCGv_vec a,
                        TCGv_vec b, TCGv_vec c);
QEMU_ARG_NONNULL
void tcg_gen_cmpsel_vec(TCGCond cond, unsigned vece, TCGv_vec r,
                        TCGv_vec a, TCGv_vec b, TCGv_vec c, TCGv_vec d);

QEMU_ARG_NONNULL
void tcg_gen_ld_vec(TCGv_vec r, TCGv_ptr base, TCGArg offset);
QEMU_ARG_NONNULL
void tcg_gen_st_vec(TCGv_vec r, TCGv_ptr base, TCGArg offset);
QEMU_ARG_NONNULL
void tcg_gen_stl_vec(TCGv_vec r, TCGv_ptr base, TCGArg offset, TCGType t);

/* Host pointer ops */

TCGv_ptr tcg_constant_ptr_int(intptr_t x);
#define tcg_constant_ptr(X)  tcg_constant_ptr_int((intptr_t)(X))

QEMU_ARG_NONNULL void tcg_gen_ld_ptr(TCGv_ptr r, TCGv_ptr a, intptr_t o);
QEMU_ARG_NONNULL void tcg_gen_st_ptr(TCGv_ptr r, TCGv_ptr a, intptr_t o);
QEMU_ARG_NONNULL void tcg_gen_discard_ptr(TCGv_ptr a);
QEMU_ARG_NONNULL void tcg_gen_add_ptr(TCGv_ptr r, TCGv_ptr a, TCGv_ptr b);
QEMU_ARG_NONNULL void tcg_gen_addi_ptr(TCGv_ptr r, TCGv_ptr a, intptr_t b);
QEMU_ARG_NONNULL void tcg_gen_mov_ptr(TCGv_ptr d, TCGv_ptr s);
QEMU_ARG_NONNULL void tcg_gen_movi_ptr(TCGv_ptr d, intptr_t s);
QEMU_ARG_NONNULL void tcg_gen_brcondi_ptr(TCGCond cond, TCGv_ptr a,
                                          intptr_t b, TCGLabel *label);
QEMU_ARG_NONNULL void tcg_gen_ext_i32_ptr(TCGv_ptr r, TCGv_i32 a);
QEMU_ARG_NONNULL void tcg_gen_trunc_i64_ptr(TCGv_ptr r, TCGv_i64 a);
QEMU_ARG_NONNULL void tcg_gen_extu_ptr_i64(TCGv_i64 r, TCGv_ptr a);
QEMU_ARG_NONNULL void tcg_gen_trunc_ptr_i32(TCGv_i32 r, TCGv_ptr a);

#endif /* TCG_TCG_OP_COMMON_H */
