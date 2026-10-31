/*
 *  x86 memory access helpers
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

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "accel/tcg/cpu-ldst.h"
#include "qemu/int128.h"
#include "qemu/atomic128.h"
#include "tcg/tcg.h"
#include "helper-tcg.h"
#include "accel/tcg/probe.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "accel/tcg/helper-retaddr.h"
#ifdef CONFIG_USER_ONLY
#include "exec/page-protection.h"
#include "user/page-protection.h"
#include "user/guest-host.h"
#endif

void helper_boundw(CPUX86State *env, target_ulong a0, int v)
{
    int low, high;

    low = cpu_ldsw_le_data_ra(env, a0, GETPC());
    high = cpu_ldsw_le_data_ra(env, a0 + 2, GETPC());
    v = (int16_t)v;
    if (v < low || v > high) {
        if (env->hflags & HF_MPX_EN_MASK) {
            env->bndcs_regs.sts = 0;
        }
        raise_exception_ra(env, EXCP05_BOUND, GETPC());
    }
}

void helper_boundl(CPUX86State *env, target_ulong a0, int v)
{
    int low, high;

    low = cpu_ldl_le_data_ra(env, a0, GETPC());
    high = cpu_ldl_le_data_ra(env, a0 + 4, GETPC());
    if (v < low || v > high) {
        if (env->hflags & HF_MPX_EN_MASK) {
            env->bndcs_regs.sts = 0;
        }
        raise_exception_ra(env, EXCP05_BOUND, GETPC());
    }
}

/*
 * Fast REP STOS and REP MOVS (x-repstr): as many whole elements as the
 * guest pages allow, with the widest host stores (memset, memmove), the
 * way a CPU with fast string operations does them.  The pages must be
 * plain RAM the guest may access as it is now: not code that self-
 * modifying-code tracking protects, not I/O, no watchpoints; at the first
 * page that isn't, or at REP_FAST_MAX bytes, stop, and the instruction's
 * element loop (or its next run) goes on from there.  Returns whether
 * any element was done; RCX, RDI and RSI are updated to match.
 *
 * With the direction flag set, each round goes down from the element at
 * RDI (RSI) to the start of its page; that element must lie within the
 * page.
 */
#define REP_FAST_MAX (64 * KiB)

static vaddr rep_linear(target_ulong reg, uint64_t amask, bool base,
                        target_ulong segbase, bool code64)
{
    vaddr a = reg & amask;

    if (base) {
        a += segbase;
    }
    return code64 ? a : (uint32_t)a;
}

/* Host address of [addr, addr + len) for @type, within one page, or NULL. */
static void *rep_host(CPUX86State *env, vaddr addr, int len,
                      MMUAccessType type, int mmu_idx, uintptr_t ra)
{
#ifdef CONFIG_USER_ONLY
    int need = type == MMU_DATA_STORE ? PAGE_WRITE : PAGE_READ;

    if ((page_get_flags(addr) & (PAGE_VALID | need)) != (PAGE_VALID | need)) {
        return NULL;
    }
    return g2h(env_cpu(env), addr);
#else
    void *host;
    int flags = probe_access_flags(env, addr, len, type, mmu_idx, true,
                                   &host, ra);

    return flags ? NULL : host;
#endif
}

/*
 * How many elements from the one at @addr (register value @reg) stay
 * within its page without wrapping the register or a 32-bit address: up
 * to the end of the page, or (@down) down to its start, the first
 * element lying within the page.
 */
static uint64_t rep_room(vaddr addr, target_ulong reg, uint64_t amask,
                         int size, bool code64, bool down)
{
    uint64_t off = addr & ~TARGET_PAGE_MASK;
    uint64_t n;

    if (!down) {
        n = (TARGET_PAGE_SIZE - off) / size;
        n = MIN(n, (amask - reg) / size + 1);
        if (!code64) {
            n = MIN(n, (UINT32_MAX - (uint32_t)addr) / size + 1);
        }
        return n;
    }
    if (off + size > TARGET_PAGE_SIZE) {
        return 0;
    }
    n = off / size + 1;
    n = MIN(n, reg / size + 1);
    if (!code64) {
        n = MIN(n, (uint32_t)addr / size + 1);
    }
    return n;
}

uint32_t helper_rep_fast(CPUX86State *env, uint32_t desc)
{
    MemOp ot = extract32(desc, 0, 2);
    MemOp aflag = extract32(desc, 2, 2);
    bool movs = extract32(desc, 4, 1);
    int src_seg = extract32(desc, 5, 3);
    bool dst_base = extract32(desc, 8, 1);
    bool src_base = extract32(desc, 9, 1);
    bool code64 = extract32(desc, 10, 1);
    int mmu_idx = extract32(desc, 11, 5);
    int size = 1 << ot;
    uint64_t amask = MAKE_64BIT_MASK(0, 8 << aflag);
    uint64_t count = env->regs[R_ECX] & amask;
    uint64_t pat = 0;
    uint64_t done = 0;
    uintptr_t ra = GETPC();
    /* Other vCPUs or threads see the stores in order with the rest. */
    bool order = env_cpu(env)->tcg_cflags & CF_PARALLEL;
    bool down = env->df != 1;

    /*
     * With fast strings disabled, the stores within one REP STOS or REP
     * MOVS are seen in order: leave them to the element loop.
     */
    if (!(env->msr_ia32_misc_enable & MSR_IA32_MISC_ENABLE_FASTSTRING)) {
        return 0;
    }
    if (!movs) {
        for (int i = 0; i < 8; i += size) {
            pat |= (env->regs[R_EAX] & MAKE_64BIT_MASK(0, 8 * size)) << 8 * i;
        }
    }
    if (order) {
        /* The bulk stores come after the guest's earlier accesses. */
        smp_mb();
    }
    while (count && done < REP_FAST_MAX) {
        target_ulong rdi = env->regs[R_EDI] & amask;
        target_ulong rsi = env->regs[R_ESI] & amask;
        vaddr dst = rep_linear(rdi, amask, dst_base,
                               env->segs[R_ES].base, code64);
        vaddr src = rep_linear(rsi, amask, src_base,
                               env->segs[src_seg].base, code64);
        uint64_t n = count;
        uint64_t bytes;
        void *hd, *hs = NULL;

        /* Within a page, without wrapping the register or the address. */
        n = MIN(n, rep_room(dst, rdi, amask, size, code64, down));
        n = MIN(n, (REP_FAST_MAX - done) / size);
        if (movs) {
            n = MIN(n, rep_room(src, rsi, amask, size, code64, down));
        }
        if (n == 0) {
            break;
        }
        bytes = n * size;
        /* Down, the round's lowest element comes first in memory. */
        hd = rep_host(env, down ? dst - (bytes - size) : dst, bytes,
                      MMU_DATA_STORE, mmu_idx, ra);
        if (movs) {
            hs = rep_host(env, down ? src - (bytes - size) : src, bytes,
                          MMU_DATA_LOAD, mmu_idx, ra);
        }
        if (!hd || (movs && !hs)) {
            break;
        }
        /*
         * A destination just past the source in the copy's direction (above
         * it upward, below it down) repeats what the copy wrote: copy at
         * most the distance at a time, as x86's element by element copy
         * does.  Host addresses, so that two virtual addresses of one page
         * count too (in system mode; in user mode, two shared mappings of
         * the same memory don't).  Down, the round keeps its top element.
         */
        if (movs && (down ? (uintptr_t)hs > (uintptr_t)hd
                          : (uintptr_t)hd > (uintptr_t)hs)) {
            uintptr_t dist = down ? (uintptr_t)hs - (uintptr_t)hd
                                  : (uintptr_t)hd - (uintptr_t)hs;

            if (dist < bytes) {
                uint64_t keep = dist / size * size;

                if (keep == 0) {
                    break;
                }
                if (down) {
                    hd += bytes - keep;
                    hs += bytes - keep;
                }
                n = keep / size;
                bytes = keep;
            }
        }
        set_helper_retaddr(ra);
        if (movs) {
            memmove(hd, hs, bytes);
        } else if (size == 1) {
            memset(hd, (uint8_t)pat, bytes);
        } else {
            uint64_t i;

            for (i = 0; i + 8 <= bytes; i += 8) {
                memcpy(hd + i, &pat, 8);
            }
            memcpy(hd + i, &pat, bytes - i);
        }
        clear_helper_retaddr();
        /* Writing a 32-bit address register zero-extends it, as x86 does. */
        env->regs[R_EDI] = (down ? rdi - bytes : rdi + bytes) & amask;
        if (movs) {
            env->regs[R_ESI] = (down ? rsi - bytes : rsi + bytes) & amask;
        }
        count -= n;
        env->regs[R_ECX] = count;
        done += bytes;
    }
    if (order) {
        /* And before its later ones. */
        smp_mb();
    }
    return done != 0;
}

