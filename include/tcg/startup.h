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
 * tcg_tbpack: tcg_tb_alloc puts a TB's struct right below its code, both
 * 16-byte aligned, instead of each in its own instruction-cache lines.
 */
extern bool tcg_tbpack;

/*
 * tcg_retstack: guest calls and returns through a return stack in host
 * code (tcg_gen_push_ret).  The front end sets tcg_retsp_off, the offset
 * in env where the stack's top is kept outside generated code, and
 * tcg_retstack_addr64 if all its guest addresses are 64-bit; the backend
 * sets tcg_retstack_reg, the host register that holds the top in
 * generated code, if it has one to spare, else -1.
 */
extern bool tcg_retstack;

/*
 * tcg_goto_tb_cold: a goto_tb's unlinked path goes to the end of the TB,
 * so that the TB's code on its linked paths is contiguous and each goto_tb
 * is one branch where the backend allows (TCG_TARGET_HAS_GOTO_TB_COLD).
 */
extern bool tcg_goto_tb_cold;
extern intptr_t tcg_retsp_off;
extern int tcg_retstack_reg;
extern bool tcg_retstack_addr64;
#define TCG_RETSTACK_SIZE (16 * 1024)
void tcg_retstack_reset(CPUState *cpu);
/*
 * A fault at @addr in generated code: if it is on a guard page of @cpu's
 * return stack (pushed or popped past an end), the top to retry with,
 * else 0.
 */
uintptr_t tcg_retstack_fault(CPUState *cpu, uintptr_t addr);

/*
 * tcg_tb_flags_canon: targets leave out of a TB's flags the state that
 * can't change its code in the current mode, so one TB serves them all
 * (x86: SS.B in 64-bit code).
 */
extern bool tcg_tb_flags_canon;

#endif
