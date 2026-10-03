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

/*
 * x-tso-stack: in qemu-user, guest accesses the front end marks as
 * thread-private (TCGContext.ldst_private: x86 RSP-based and implicit
 * stack accesses) get no memory-order constraint.
 */
extern bool tcg_tso_stack;

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
 * x-tbpack: where tcg_tb_alloc puts a TB's struct and its code.
 * OFF: each in its own instruction-cache lines.
 * ON: the struct right below the code, 16-byte aligned.
 * CODELINE: the code at a line boundary, the struct right below it.
 */
typedef enum {
    TCG_TBPACK_OFF,
    TCG_TBPACK_ON,
    TCG_TBPACK_CODELINE,
} TCGTbPack;

extern TCGTbPack tcg_tbpack;

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
 * x-vperm: guest permutes by a constant (shuffles, unpacks, blends,
 * element inserts) are generated with perm_vec where the backend has it.
 */
extern bool tcg_vperm;

/*
 * x-vpermvar: permutes by indices in a register (x86 vpermd/vpermps) as
 * host table lookups (tbl_vec) instead of helper calls.
 */
extern bool tcg_vpermvar;

/*
 * x-vecmem: 128-bit guest vector loads and stores use qemu_ld_vec and
 * qemu_st_vec where tcg_can_qemu_ldst_vec() allows.
 */
extern bool tcg_vecmem;

/*
 * x-dse: before liveness, remove stores to CPUArchState that are
 * overwritten later in the same extended basic block before any
 * operation could read them.
 */
extern bool tcg_dse;

/*
 * x-ldstkeep: values stay in the registers a guest memory access's slow
 * path saves, instead of being spilled around every access (where the
 * backend's slow path saves them).
 */
extern bool tcg_ldstkeep;

/*
 * x-lazysync: guest memory accesses leave dirty globals in registers;
 * their slow paths store them before anything can observe env, and save
 * the call-clobbered registers in use, where the backend supports it.
 * In user mode, where an access faults on its fast path, also where the
 * host signal handler supports it (tcg_lazysync_user).
 */
extern bool tcg_lazysync;

/*
 * User mode: the host signal handler stores the dirty globals a faulting
 * guest access had in registers (tb_lazysync_unwind), so x-lazysync can
 * apply.
 */
extern bool tcg_lazysync_user;

/*
 * x-vecglobal: front ends keep vector registers in env_alias vector
 * globals (tcg_global_mem_new_vec), so TCG holds them in host registers
 * within a TB.
 */
extern bool tcg_vecglobal;

/*
 * x-ymmglobal: with x-vecglobal, the upper 128 bits of each ymm register
 * as vector globals too.
 */
extern bool tcg_ymmglobal;

/*
 * Translate x86 PAUSE as a host spin hint inline (spin_hint) instead of
 * a helper that leaves the execution loop; for MTTCG, where each vCPU
 * has its own thread.
 */
extern bool tcg_pause_hint;

/*
 * x86 guests: the TSC from the host's constant-rate counter
 * (host/counter.h) plus a per-vCPU offset, instead of
 * cpu_get_ticks(); with IA32_TSC and IA32_TSC_ADJUST, invariant TSC and
 * CPUID leaf 0x15.
 */
extern bool tcg_tsc_counter;

/*
 * x86 guests: CR0.MP, EM and TS are not part of the TB flags; the first
 * instruction in a TB that depends on them checks them at run time.
 */
extern bool tcg_fpcheck_runtime;

/*
 * x-addr32: a target with 64-bit addresses may translate a TB with 32-bit
 * ones (x86 outside long mode), and the optimizer lets an extrl_i64_i32
 * read through an extension of the low 32 bits.
 */
extern bool tcg_addr32;

/*
 * x86 guests outside virtual-8086 mode: EFLAGS.IOPL is not part of the TB
 * flags; the instructions that depend on it test it at run time.
 */
extern bool tcg_iopl_runtime;

/*
 * x86 guests: CR0.EM and TS raise the exceptions hardware raises: EM
 * before TS (#UD) for MMX and SSE, including EMMS and FEMMS; EM does not
 * apply to VEX instructions.
 */
extern bool tcg_cr0exc_hw;

/*
 * x-region: a TB whose direct jump returns to its first insn branches
 * back within the TB instead of chaining to itself.
 */
extern bool tcg_region;

/*
 * The front end's scratch area in env, [ofs, ofs + size): values there
 * live only within one guest instruction, so a fault or an exit never
 * observes them (x-dse may remove stores to it across guest memory
 * accesses and before exits).
 */
void tcg_set_env_scratch(intptr_t ofs, intptr_t size);

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
