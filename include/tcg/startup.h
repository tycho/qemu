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
 * [EXP] x-tso-exp: UNSAFE attribution experiments for x-tso=acqrel.
 * Each bit removes one cost; not for merging.
 */
#define TCG_TSO_EXP_SSE_PLAIN   1   /* no barriers around 128-bit accesses */
#define TCG_TSO_EXP_CROSS_PLAIN 2   /* 16-byte-crossing fallback: plain op */
#define TCG_TSO_EXP_PLAIN       4   /* LDR/STR instead of LDAPR/STLR */
#define TCG_TSO_EXP_NOCHECK     8   /* with PLAIN: no crossing check */
#define TCG_TSO_EXP_ORACLE_ONLY 16  /* no check except x-split-pcs sites:
                                       an unlisted crossing faults */
#define TCG_TSO_EXP_SPLIT_HALF  32  /* x-split-pcs loads: LDR; DMB ISHLD */
extern unsigned tcg_tso_exp;

/*
 * [EXP] crossing-site oracle: guest pcs listed (hex, one per line, an
 * optional "SITE " prefix) in the file named by x-split-pcs (or the
 * XTCG_SPLIT_PCS env var) get the branch-free acqrel form.  tcg_xtcg_insn_pc is the pc of the guest insn
 * being translated.
 */
extern __thread uint64_t tcg_xtcg_insn_pc;
bool tcg_tso_split_pc(uint64_t pc);
extern char *tcg_split_pcs_path;

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

#endif
