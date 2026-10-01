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
 * x-tso-promote: with x-tso=acqrel, a guest insn whose access has crossed
 * a 16-byte boundary this many times is retranslated with a branch-free
 * form (MO_ACQ_REL_CROSS); 0 disables it.
 */
extern unsigned tcg_tso_promote;

/* Count one crossing at guest insn @pc; true once it is promoted. */
bool tcg_tso_cross_count(uint64_t pc);
/* True if guest insn @pc has been promoted. */
bool tcg_tso_cross_promoted(uint64_t pc);

/*
 * x-pferr-hw: targets report page-fault error codes as hardware does where
 * TCG's access pattern would differ (x86: the load of a read-modify-write
 * insn faults as a write; qemu-user: a PROT_NONE page is not present).
 */
extern bool tcg_pferr_hw;

/*
 * x-ssefp=vec: target SIMD floating-point helpers try the softfloat vector
 * fast paths (float32_add_vec etc.) before computing lane by lane.
 */
extern bool tcg_ssefp_vec;

/*
 * x-ssefp=native: on hosts whose FPU can take the guest's FP mode
 * (host_fpenv_native()), the vCPU thread runs with it while in cpu_exec,
 * so generated code can use host FP instructions for guest FP.  Other
 * hosts get tcg_ssefp_vec instead; the two are never both set, as the
 * vector fast paths run host FP on unvalidated values.
 */
extern bool tcg_ssefp_native;

/*
 * x-vecld: a guest vector load puts the loaded value in a host vector
 * register (when the backend can build one from general registers), so
 * that it is stored to CPU state in one piece.
 */
extern bool tcg_vecld;

/*
 * x-vperm: guest permutes by a constant (shuffles, unpacks, blends) are
 * generated with perm_vec where the backend has it.
 */
extern bool tcg_vperm;

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
