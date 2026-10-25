/*
 * internal execution defines for qemu
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef EXEC_TB_HASH_H
#define EXEC_TB_HASH_H

#include "exec/vaddr.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "qemu/xxhash.h"
#include "tb-jmp-cache.h"
#include "internal-common.h"

#ifdef CONFIG_SOFTMMU

/*
 * The jump cache's slots come in groups of TB_JMP_PAGE_SIZE, and every pc
 * of a guest page hashes into one group, so that a TLB flush of the page
 * clears only that group.  The group comes from the pc above both the
 * page and the group's size (TB_JMP_GROUP_SHIFT), mixed with the bits
 * TB_JMP_MIX_SHIFT higher; the slot from the pc's low TB_JMP_PAGE_BITS,
 * folded with the bits up to the page's size where a page is larger
 * (TB_JMP_FOLD_SHIFT).  With 4 KiB pages the offset folds two bits, so
 * code on one page seldom conflicts with itself; with the default 64K
 * slots, a group's entries are 16 KiB, one host page where pages are
 * that size.
 */
#if TB_JMP_CACHE_BITS < 7
#error "TB_JMP_CACHE_BITS: at least 7, for 64 groups of 2 or more slots"
#endif
#define TB_JMP_PAGE_BITS (TB_JMP_CACHE_BITS - 6)
#define TB_JMP_PAGE_SIZE (1 << TB_JMP_PAGE_BITS)
#define TB_JMP_ADDR_MASK (TB_JMP_PAGE_SIZE - 1)
#define TB_JMP_PAGE_MASK (TB_JMP_CACHE_SIZE - TB_JMP_PAGE_SIZE)
#define TB_JMP_GROUP_SHIFT MAX(TARGET_PAGE_BITS, TB_JMP_PAGE_BITS)
#define TB_JMP_FOLD_SHIFT (TB_JMP_GROUP_SHIFT - TB_JMP_PAGE_BITS)
#define TB_JMP_MIX_SHIFT (TB_JMP_CACHE_BITS - TB_JMP_PAGE_BITS)

static inline unsigned int tb_jmp_cache_hash_page(vaddr pc)
{
    vaddr tmp = pc ^ (pc >> TB_JMP_MIX_SHIFT);

    return ((tmp >> TB_JMP_GROUP_SHIFT) << TB_JMP_PAGE_BITS) & TB_JMP_PAGE_MASK;
}

static inline unsigned int tb_jmp_cache_hash_func(vaddr pc)
{
    unsigned fold = TB_JMP_FOLD_SHIFT;
    vaddr off = fold ? pc ^ (pc >> fold) : pc;

    return tb_jmp_cache_hash_page(pc) | (off & TB_JMP_ADDR_MASK);
}

#else

/*
 * In user-mode we can get better hashing because we do not have a TLB.
 * With the inline lookup, the pc's low bits alone: guest code spreads
 * over them, and the generated code takes them in one host insn.
 */
static inline unsigned int tb_jmp_cache_hash_func(vaddr pc)
{
    if (tcg_ijmp_inline) {
        return pc & (TB_JMP_CACHE_SIZE - 1);
    }
    return (pc ^ (pc >> TB_JMP_CACHE_BITS)) & (TB_JMP_CACHE_SIZE - 1);
}

#endif /* CONFIG_SOFTMMU */

static inline
uint32_t tb_hash_func(tb_page_addr_t phys_pc, vaddr pc,
                      uint32_t flags, uint64_t flags2, uint32_t cf_mask)
{
    return qemu_xxhash8(phys_pc, pc, flags2, flags, cf_mask);
}

#endif
