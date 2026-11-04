/*
 * Internal execution defines for qemu (target agnostic)
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef ACCEL_TCG_INTERNAL_COMMON_H
#define ACCEL_TCG_INTERNAL_COMMON_H

#include "exec/cpu-common.h"
#include "qemu/bswap.h"
#include "qemu/crc32c.h"
#include "exec/translation-block.h"
#include "exec/mmap-lock.h"
#include "accel/tcg/tb-cpu-state.h"

extern int64_t max_delay;
extern int64_t max_advance;

extern bool one_insn_per_tb;

/*
 * x-smc=check (user mode): self-modifying code is detected by a CRC32C of
 * each TB's guest bytes at its entry, not by write-protecting its pages.
 */
extern bool tcg_smc_check;

/*
 * x-smc=check: the checksum of a TB's guest code bytes, taken when it is
 * translated and again at its entry.  It reads exactly LEN bytes from P,
 * no more (the code may end at an unmapped page), in overlapping
 * little-endian words: two CRC32C steps for up to 16 bytes, and for
 * longer code three independent chains over interleaved 8-byte words,
 * folded into one at the end.  Any change confined to one chain changes
 * the result.
 */
static inline uint32_t tb_code_sum(const uint8_t *p, uint32_t len)
{
    uint32_t c0 = 0xffffffff, c1 = 0xffffffff, c2 = 0xffffffff;
    const uint8_t *last;

    if (len < 4) {
        if (len & 2) {
            c0 = crc32c_u16(c0, lduw_le_p(p));
            p += 2;
        }
        return len & 1 ? crc32c_u8(c0, *p) : c0;
    }
    if (len <= 8) {
        c0 = crc32c_u32(c0, ldl_le_p(p));
        return crc32c_u32(c0, ldl_le_p(p + len - 4));
    }
    last = p + len - 8;
    for (; p + 24 <= last; p += 24) {
        c0 = crc32c_u64(c0, ldq_le_p(p));
        c1 = crc32c_u64(c1, ldq_le_p(p + 8));
        c2 = crc32c_u64(c2, ldq_le_p(p + 16));
    }
    for (; p < last; p += 8) {
        c0 = crc32c_u64(c0, ldq_le_p(p));
    }
    c0 = crc32c_u64(c0, ldq_le_p(last));
    return len < 32 ? c0 : crc32c_u32(crc32c_u32(c0, c1), c2);
}

extern bool icount_align_option;

/*
 * Return true if CS is not running in parallel with other cpus, either
 * because there are no other cpus or we are within an exclusive context.
 */
static inline bool cpu_in_serial_context(CPUState *cs)
{
    return !tcg_cflags_has(cs, CF_PARALLEL) || cpu_in_exclusive_context(cs);
}

/**
 * cpu_plugin_mem_cbs_enabled() - are plugin memory callbacks enabled?
 * @cs: CPUState pointer
 *
 * The memory callbacks are installed if a plugin has instrumented an
 * instruction for memory. This can be useful to know if you want to
 * force a slow path for a series of memory accesses.
 */
static inline bool cpu_plugin_mem_cbs_enabled(const CPUState *cpu)
{
#ifdef CONFIG_PLUGIN
    return !!cpu->neg.plugin_mem_cbs;
#else
    return false;
#endif
}

TranslationBlock *tb_gen_code(CPUState *cpu, TCGTBCPUState s);
void page_init(void);
void tb_htable_init(void);
void tb_reset_jump(TranslationBlock *tb, int n);
TranslationBlock *tb_link_page(TranslationBlock *tb);
void cpu_restore_state_from_tb(CPUState *cpu, TranslationBlock *tb,
                               uintptr_t host_pc);

/**
 * tlb_init - initialize a CPU's TLB
 * @cpu: CPU whose TLB should be initialized
 */
void tlb_init(CPUState *cpu);
/**
 * tlb_destroy - destroy a CPU's TLB
 * @cpu: CPU whose TLB should be destroyed
 */
void tlb_destroy(CPUState *cpu);

bool tcg_exec_realizefn(CPUState *cpu, Error **errp);
void tcg_exec_unrealizefn(CPUState *cpu);

/*
 * Current cflags for hashing/comparison.  Everything that feeds into the
 * value is folded into CPUState::tcg_cflags when it changes, by
 * tcg_update_cflags(), so that TB dispatch only has to load it.
 */
static inline uint32_t curr_cflags(CPUState *cpu)
{
    return cpu->tcg_cflags;
}

void tb_check_watchpoint(CPUState *cpu, uintptr_t retaddr);

/**
 * get_page_addr_code_hostp()
 * @env: CPUArchState
 * @addr: guest virtual address of guest code
 *
 * See get_page_addr_code() (full-system version) for documentation on the
 * return value.
 *
 * Sets *@hostp as follows.
 * If the return value is -1, sets *@hostp to NULL. Otherwise, sets *@hostp
 * to the host address where @addr's content is kept.
 *
 * Note: this function can trigger an exception.
 */
tb_page_addr_t get_page_addr_code_hostp(CPUArchState *env, vaddr addr,
                                        void **hostp);

/**
 * get_page_addr_code()
 * @env: CPUArchState
 * @addr: guest virtual address of guest code
 *
 * If we cannot translate and execute from the entire RAM page, or if
 * the region is not backed by RAM, returns -1. Otherwise, returns the
 * ram_addr_t corresponding to the guest code at @addr.
 *
 * Note: this function can trigger an exception.
 */
static inline tb_page_addr_t get_page_addr_code(CPUArchState *env,
                                                vaddr addr)
{
    void *discard;
    return get_page_addr_code_hostp(env, addr, &discard);
}

/*
 * Access to the various translations structures need to be serialised
 * via locks for consistency.  In user-mode emulation access to the
 * memory related structures are protected with mmap_lock.
 * In !user-mode we use per-page locks.
 */
#ifdef CONFIG_USER_ONLY
#define assert_memory_lock() tcg_debug_assert(have_mmap_lock())
#else
#define assert_memory_lock()
#endif

#if defined(CONFIG_SOFTMMU) && defined(CONFIG_DEBUG_TCG)
void assert_no_pages_locked(void);
#else
static inline void assert_no_pages_locked(void) { }
#endif

#ifdef CONFIG_USER_ONLY
static inline void page_table_config_init(void) { }
#else
void page_table_config_init(void);
#endif

#ifndef CONFIG_USER_ONLY
G_NORETURN void cpu_io_recompile(CPUState *cpu, uintptr_t retaddr);
#endif /* CONFIG_USER_ONLY */

void tb_phys_invalidate(TranslationBlock *tb, tb_page_addr_t page_addr);
void tb_set_jmp_target(TranslationBlock *tb, int n, uintptr_t addr);

void tcg_get_stats(AccelState *accel, GString *buf);

#endif
