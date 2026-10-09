/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Define target-specific opcode support
 * Copyright (c) 2013 Huawei Technologies Duesseldorf GmbH
 */

#ifndef TCG_TARGET_HAS_H
#define TCG_TARGET_HAS_H

#include "host/cpuinfo.h"

#define have_lse    (cpuinfo & CPUINFO_LSE)
#define have_lse2   (cpuinfo & CPUINFO_LSE2)
#define have_lrcpc  (cpuinfo & CPUINFO_LRCPC)
#define have_lrcpc2 (cpuinfo & CPUINFO_LRCPC2)
#define have_lrcpc3 (cpuinfo & CPUINFO_LRCPC3)

/*
 * MO_ACQ_REL guest accesses: LDAPR/STLR.  Unaligned ones rely on FEAT_LSE2
 * (they must not cross 16 bytes; the backend checks).
 */
#define TCG_TARGET_HAS_qemu_ldst_acqrel (have_lrcpc && have_lse2)
/* 16-byte aligned, single-copy atomic acquire/release: LDIAPP/STILP */
#define TCG_TARGET_HAS_qemu_ldst_i128_acqrel \
    (TCG_TARGET_HAS_qemu_ldst_acqrel && have_lrcpc3)
/* 16-byte aligned vector load-acquire/store-release: LDAPUR/STLUR (Q) */
#define TCG_TARGET_HAS_qemu_ldst_vec_acqrel \
    (TCG_TARGET_HAS_qemu_ldst_acqrel && have_lrcpc3)

/* optional instructions */
#define TCG_TARGET_HAS_extr_i64_i32     0

/*
 * Without FEAT_LSE2, we must use LDXP+STXP to implement atomic 128-bit load,
 * which requires writable pages.  We must defer to the helper for user-only,
 * but in system mode all ram is writable for the host.
 */
#ifdef CONFIG_USER_ONLY
#define TCG_TARGET_HAS_qemu_ldst_i128   have_lse2
#else
#define TCG_TARGET_HAS_qemu_ldst_i128   1
#endif

#define TCG_TARGET_HAS_tst              1

#define TCG_TARGET_HAS_v64              1
#define TCG_TARGET_HAS_v128             1
#define TCG_TARGET_HAS_v256             0

#define TCG_TARGET_HAS_andc_vec         1
#define TCG_TARGET_HAS_orc_vec          1
#define TCG_TARGET_HAS_nand_vec         0
#define TCG_TARGET_HAS_nor_vec          0
#define TCG_TARGET_HAS_eqv_vec          0
#define TCG_TARGET_HAS_not_vec          1
#define TCG_TARGET_HAS_neg_vec          1
#define TCG_TARGET_HAS_abs_vec          1
#define TCG_TARGET_HAS_roti_vec         0
#define TCG_TARGET_HAS_rots_vec         0
#define TCG_TARGET_HAS_rotv_vec         0
#define TCG_TARGET_HAS_shi_vec          1
#define TCG_TARGET_HAS_shs_vec          0
#define TCG_TARGET_HAS_shv_vec          1
#define TCG_TARGET_HAS_mul_vec          1
#define TCG_TARGET_HAS_sat_vec          1
#define TCG_TARGET_HAS_minmax_vec       1
#define TCG_TARGET_HAS_bitsel_vec       1
#define TCG_TARGET_HAS_cmpsel_vec       0
#define TCG_TARGET_HAS_extract_vec      1
#define TCG_TARGET_HAS_insert_vec       1
#define TCG_TARGET_HAS_movz_vec         1
#define TCG_TARGET_HAS_tst_vec          1
#define TCG_TARGET_HAS_fp_vec           1
#define TCG_TARGET_HAS_concat_vec       1
#define TCG_TARGET_HAS_qemu_ldst_vec    1
#define TCG_TARGET_HAS_perm_vec         1
#define TCG_TARGET_HAS_tbl_vec          1
#define TCG_TARGET_HAS_zip_vec          1
#define TCG_TARGET_HAS_ext_vec          1
#define TCG_TARGET_HAS_widen_vec        1
#define TCG_TARGET_HAS_mulw_vec         1
#define TCG_TARGET_HAS_addp_vec         1
#define TCG_TARGET_HAS_narrow_vec       1
#define TCG_TARGET_HAS_abd_vec          1
#define TCG_TARGET_HAS_addlp_vec        1
#define TCG_TARGET_HAS_avgr_vec         1

#define TCG_TARGET_extract_valid(type, ofs, len)   1
#define TCG_TARGET_sextract_valid(type, ofs, len)  1
#define TCG_TARGET_deposit_valid(type, ofs, len)   1

#endif
