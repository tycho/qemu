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
 * User mode: when the last thread but one exits, the remaining CPU goes
 * back to serial code, as before the first thread was created (x-tso=auto).
 */
extern bool tcg_reserial;

/*
 * Guest accesses wider than 8 bytes that the guest doesn't make atomic
 * (accel property x-tso-vec): each ordered like any access (false, the
 * default), or, under TCG_TSO_ACQREL, as runs with barriers only where a
 * run begins and ends (true).  Not exact: see tcg_tso_run_end().
 */
extern bool tcg_tso_vec_group;

/*
 * x-tso-vec=none: guest accesses the front end marks as moving vector or
 * floating-point register data (TCGContext.ldst_vector) get no
 * memory-order constraint, unless the guest makes them atomic as a whole.
 * Implies tcg_tso_vec_group for the remaining wide accesses.
 */
extern bool tcg_tso_vec_none;

/*
 * x-tso-vec=atomic: as x-tso-vec=none, but the front end keeps the
 * whole atomicity, and so the order, of the vector accesses a guest may
 * use as 16-byte atomic loads and stores.  With x-tso-vec=none it makes
 * vector accesses atomic only in parts.
 */
extern bool tcg_tso_vec_atomic;

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

/*
 * User mode: the host's alignment-fault handler deals with MO_ACQ_REL
 * accesses that cross 16 bytes (LDAPR and STLR fault on them), so the
 * backend emits no inline check.  tcg_insn_is_acqrel_ldst tells whether
 * the generated insn at host address @pc is such an access.
 */
extern bool tcg_tso_cross_faults;
bool tcg_insn_is_acqrel_ldst(uintptr_t pc);

/* True if the host backend can emit MO_ACQ_REL accesses. */
bool tcg_can_ldst_acqrel(void);

/*
 * tcg_atomic: guest atomic read-modify-write accesses (xchg, add, and, or,
 * xor, cmpxchg, up to 64 bits) in parallel mode are host atomic insns
 * after the guest access's own checks, with the out-of-line helper only
 * for what those checks don't pass, on backends that support it
 * (tcg_atomic_supported).
 */
extern bool tcg_atomic;
bool tcg_atomic_supported(void);

/*
 * Target SIMD floating-point helpers try the softfloat vector fast paths
 * (float32_add_vec etc.) before computing lane by lane.
 */
extern bool tcg_ssefp_vec;

/*
 * On hosts whose FPU can take the guest's FP mode (host_fpenv_native()),
 * the vCPU thread runs with it while in cpu_exec, so generated code can
 * use host FP instructions for guest FP.  Never set together with
 * tcg_ssefp_vec, as the vector fast paths run host FP on unvalidated
 * values.
 */
extern bool tcg_ssefp_native;

/*
 * Before liveness, remove stores to CPUArchState that are overwritten
 * later in the same extended basic block before any operation could
 * read them.
 */
extern bool tcg_dse;

/*
 * Values stay in the registers that a guest memory access's slow path
 * saves, instead of being spilled around every access (where the
 * backend's slow path saves them).
 */
extern bool tcg_ldstkeep;

/*
 * Guest memory accesses leave dirty globals in registers; their slow
 * paths store them before anything can observe env, and save the
 * call-clobbered registers in use, where the backend supports it.
 * In user mode, where an access faults on its fast path, also where the
 * host signal handler supports it (tcg_lazysync_user).
 */
extern bool tcg_lazysync;

/*
 * User mode: the host signal handler stores the dirty globals a faulting
 * guest access had in registers (tb_lazysync_unwind), so tcg_lazysync
 * can apply.
 */
extern bool tcg_lazysync_user;

/*
 * tcg_pin: a front end pins its most used guest registers (tcg_temp_pin).
 * tcg_pin_user: user mode sets it where the host signal handler can store
 * pinned globals (tcg_pinned_unwind) and no plugin reads guest registers;
 * pinning applies only then.
 * tcg_pin_vec: with tcg_pin_user, a front end pins its vector registers
 * too, where the backend has registers for them.
 * tcg_pin_cc: with tcg_pin_user, a front end pins the global that holds
 * its lazy condition-code operation, when a register is left after its
 * guest registers.
 */
extern bool tcg_pin;
extern bool tcg_pin_user;
extern bool tcg_pin_vec;
extern bool tcg_pin_cc;

/*
 * tcg_pin_system_ok: whether the backend can pin guest registers in system
 * mode (TCG_TARGET_NB_PIN_REGS_SYSTEM: callee-saved registers only, which
 * calls keep); system mode then sets tcg_pin_user from tcg_pin when the
 * first vCPU is created, before the front end creates its globals and
 * before the prologue, which loads and stores them.
 */
bool tcg_pin_system_ok(void);

/*
 * tcg_cc_regs: with tcg_pin_user, a front end keeps the operands of its
 * lazy condition codes in host registers between TBs (boundary globals,
 * tcg_boundary_global_add), where the backend has registers for them.
 */
extern bool tcg_cc_regs;

/*
 * Front ends keep vector registers in env_alias vector
 * globals (tcg_global_mem_new_vec), so TCG holds them in host registers
 * within a TB.
 */
extern bool tcg_vecglobal;

/*
 * With tcg_vecglobal, the upper 128 bits of each ymm register as
 * vector globals too.
 */
extern bool tcg_ymmglobal;

/*
 * Let the register allocator use the host vector registers whose low
 * halves the host ABI makes callee-saved (AArch64 v8-v15): the prologue
 * then saves and restores them for its caller.
 */
extern bool tcg_vregs_all;

/*
 * The front end's scratch area in env, [ofs, ofs + size): values there
 * live only within one guest instruction, so a fault or an exit never
 * observes them (tcg_dse may remove stores to it across guest memory
 * accesses and before exits).
 */
void tcg_set_env_scratch(intptr_t ofs, intptr_t size);

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

/*
 * tcg_vexzero: x86 VEX.128 writes leave the upper half of their ymm
 * register pending zero until the state is next visible, so that a block
 * zeroes each register's upper half once.
 */
extern bool tcg_vexzero;

/*
 * tcg_crypto: guest SHA-1 and AES round insns as TCG's SHA-1 and AES
 * vector ops (sha1c_vec, aese_vec, ...) where the backend has them, instead
 * of helper calls.
 */
extern bool tcg_crypto;

#endif
