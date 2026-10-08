/*
 * Tiny Code Generator for QEMU: definitions used by runtime startup
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

#ifndef TCG_STARTUP_H
#define TCG_STARTUP_H

/*
 * x86 guests: CR0.MP, EM and TS are not part of the TB flags; the first
 * instruction in a TB that depends on them checks them at run time.
 */
extern bool tcg_fpcheck_runtime;

/*
 * x86 guests outside virtual-8086 mode: EFLAGS.IOPL is not part of the TB
 * flags; the instructions that depend on it test it at run time.
 */
extern bool tcg_iopl_runtime;

/*
 * How guest memory ordering is implemented for ordinary guest loads and
 * stores (accel property x-tso).
 */
typedef enum TCGTsoMode {
    TCG_TSO_BARRIER,    /* a barrier before each access (default) */
    TCG_TSO_ACQREL,     /* load-acquire / store-release accesses */
    TCG_TSO_NONE,       /* no barriers at all: UNSAFE, for measurement */
} TCGTsoMode;

extern TCGTsoMode tcg_tso_mode;

/*
 * Guest accesses wider than 8 bytes that the guest doesn't make atomic
 * (accel property x-tso-vec): each ordered like any access (false, the
 * default), or, under TCG_TSO_ACQREL, as runs with barriers only where a
 * run begins and ends (true).  Not exact: see tcg_tso_run_end().
 */
extern bool tcg_tso_vec_group;

/*
 * In qemu-user, guest accesses the front end marks as thread-private
 * (TCGContext.ldst_private: x86 RSP-based and implicit stack accesses)
 * get no memory-order constraint (accel property x-tso-stack).
 */
extern bool tcg_tso_stack;

/*
 * With TCG_TSO_ACQREL, a guest insn whose MO_ACQ_REL accesses have crossed
 * a 16-byte boundary is promoted: retranslated with MO_ACQ_REL_CROSS, a
 * form that handles any alignment without a data-dependent branch.
 *
 * tcg_tso_cross_count counts one crossing at guest insn @pc, and returns
 * true once the insn is promoted; tcg_tso_cross_promoted returns true if
 * it has been.
 */
bool tcg_tso_cross_count(uint64_t pc);
bool tcg_tso_cross_promoted(uint64_t pc);

/* True if the host backend can emit MO_ACQ_REL accesses. */
bool tcg_can_ldst_acqrel(void);

/**
 * tcg_init: Initialize the TCG runtime
 * @tb_size: translation buffer size
 * @splitwx: use separate rw and rx mappings
 * @max_threads: number of vcpu threads in system mode
 *
 * Allocate and initialize TCG resources, especially the JIT buffer.
 * In user-only mode, @max_threads is unused.
 */
void tcg_init(size_t tb_size, int splitwx, unsigned max_threads);

/**
 * tcg_register_thread: Register this thread with the TCG runtime
 *
 * All TCG threads except the parent (i.e. the one that called the TCG
 * accelerator's init_machine() method) must register with this
 * function before initiating translation.
 */
void tcg_register_thread(void);

/**
 * tcg_prologue_init(): Generate the code for the TCG prologue
 *
 * In softmmu this is done automatically as part of the TCG
 * accelerator's init_machine() method, but for user-mode, the
 * user-mode code must call this function after it has loaded
 * the guest binary and the value of guest_base is known.
 */
void tcg_prologue_init(void);

/*
 * tcg_vecld: a guest vector load puts the loaded value in a host vector
 * register (when the backend can build one from general registers), so
 * that it is stored to CPU state in one piece.
 */
extern bool tcg_vecld;

/*
 * tcg_vecmem: 128-bit guest vector loads and stores use qemu_ld_vec and
 * qemu_st_vec where tcg_can_qemu_ldst_vec() allows.
 */
extern bool tcg_vecmem;

/*
 * tcg_vperm: guest permutes by a constant (shuffles, unpacks, blends,
 * element inserts) are generated with perm_vec where the backend has it.
 */
extern bool tcg_vperm;

/*
 * tcg_vpermvar: permutes by indices in a register (x86 vpermd, vpermps,
 * pshufb) as host table lookups (tbl_vec) instead of helper calls.
 */
extern bool tcg_vpermvar;

/*
 * tcg_vint: guest integer vector operations that TCG has no single op for
 * (unpacks of bytes, byte shifts and aligns, widening and narrowing,
 * pairwise sums, ...) as sequences of host vector ops instead of helper
 * calls, where the backend has them.
 */
extern bool tcg_vint;

#endif
