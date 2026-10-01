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

#endif
