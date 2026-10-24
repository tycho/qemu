/*
 * Memory helpers that will be used by TCG generated code.
 *
 * Copyright (c) 2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef TCG_LDST_H
#define TCG_LDST_H

/* Value zero-extended to tcg register size.  */
tcg_target_ulong helper_ldub_mmu(CPUArchState *env, uint64_t addr,
                                 MemOpIdx oi, uintptr_t retaddr);
tcg_target_ulong helper_lduw_mmu(CPUArchState *env, uint64_t addr,
                                 MemOpIdx oi, uintptr_t retaddr);
tcg_target_ulong helper_ldul_mmu(CPUArchState *env, uint64_t addr,
                                 MemOpIdx oi, uintptr_t retaddr);
uint64_t helper_ldq_mmu(CPUArchState *env, uint64_t addr,
                        MemOpIdx oi, uintptr_t retaddr);
Int128 helper_ld16_mmu(CPUArchState *env, uint64_t addr,
                       MemOpIdx oi, uintptr_t retaddr);

/* Value sign-extended to tcg register size.  */
tcg_target_ulong helper_ldsb_mmu(CPUArchState *env, uint64_t addr,
                                 MemOpIdx oi, uintptr_t retaddr);
tcg_target_ulong helper_ldsw_mmu(CPUArchState *env, uint64_t addr,
                                 MemOpIdx oi, uintptr_t retaddr);
tcg_target_ulong helper_ldsl_mmu(CPUArchState *env, uint64_t addr,
                                 MemOpIdx oi, uintptr_t retaddr);

/*
 * Value extended to at least uint32_t, so that some ABIs do not require
 * zero-extension from uint8_t or uint16_t.
 */
void helper_stb_mmu(CPUArchState *env, uint64_t addr, uint32_t val,
                    MemOpIdx oi, uintptr_t retaddr);
void helper_stw_mmu(CPUArchState *env, uint64_t addr, uint32_t val,
                    MemOpIdx oi, uintptr_t retaddr);
void helper_stl_mmu(CPUArchState *env, uint64_t addr, uint32_t val,
                    MemOpIdx oi, uintptr_t retaddr);
void helper_stq_mmu(CPUArchState *env, uint64_t addr, uint64_t val,
                    MemOpIdx oi, uintptr_t retaddr);
void helper_st16_mmu(CPUArchState *env, uint64_t addr, Int128 val,
                     MemOpIdx oi, uintptr_t retaddr);

/*
 * An MO_ACQ_REL access of guest insn @site crossed a 16-byte boundary:
 * count it, maybe retranslate its TB with the insn promoted, and perform
 * the access.  Loads return the value zero-extended, like helper_ld*_mmu
 * above.
 */
tcg_target_ulong helper_tso_cross_ld(CPUArchState *env, uint64_t addr,
                                     MemOpIdx oi, uintptr_t retaddr,
                                     uint64_t site);
void helper_tso_cross_st(CPUArchState *env, uint64_t addr, uint64_t val,
                         MemOpIdx oi, uintptr_t retaddr, uint64_t site);

/*
 * tcg_slowthunk: the descriptor of an MO_ACQ_REL access, in its slow
 * path's code after the call to the thunk: the access's return address,
 * relative to the descriptor; its MemOpIdx; its insn's guest pc (low,
 * high); and a word of flags, with the address register in bits 0-4,
 * the data register in bits 5-9, and in bits 16-31 the env offset of the
 * TLB fast descriptor whose mask and table the thunk loads on its way
 * back (0: none).
 */
#define TSO_THUNK_DESC_WORDS    5
#define TSO_THUNK_IS_LD         (1u << 10)
#define TSO_THUNK_ADDR32        (1u << 11)  /* zero-extend the address */
#define TSO_THUNK_DATA64        (1u << 12)  /* a 64-bit load result */
#define TSO_THUNK_DIRECT        (1u << 13)  /* back to the return address */

/*
 * tcg_slowthunk: perform the access of descriptor @desc, whose address
 * and stored value are in @regs, the host's general registers by number
 * as the thunk saved them; a load's result goes there too.  Returns
 * where the thunk goes on: the access's return address
 * (TSO_THUNK_DIRECT), else the code after the descriptor.
 */
uintptr_t helper_tso_cross_thunk(CPUArchState *env, uint64_t *regs,
                                 const uint32_t *desc);

#endif /* TCG_LDST_H */
