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
 * x-lean: leaner code for common guest patterns, where the host allows:
 * guest accesses whose address is a register plus a shifted register or
 * an offset use the host's addressing modes (qemu_ld_x, qemu_st_x); an
 * operation whose result is only zero-extended from 32 bits is a 32-bit
 * operation, and so are compares and right shifts of 32-bit extensions,
 * whose extensions are then dropped; a shift feeding an add is an add
 * with a shifted operand (shladd).
 */
extern bool tcg_lean;

/*
 * tcg_lean_narrow32: tcg_lean, on a host whose 32-bit operations
 * zero-extend into the 64-bit register: a front end can leave a 64-bit
 * result whose only use is its low 32 bits to be computed in 32 bits.
 */
bool tcg_lean_narrow32(void);

/*
 * tcg_alignfold: a guest access's alignment check is dropped where an
 * earlier check on the same globals plus a constant implies it.
 */
extern bool tcg_alignfold;

/*
 * x-zext32: in user mode with no guest base, a guest whose addresses are
 * all 32-bit (tcg_guest_addr32) accesses memory at its address register
 * itself.  The backend then keeps every defined, live 32-bit value in a
 * host register zero-extended at each op's boundary, extending where a
 * value could otherwise carry other bits above it.  TCG_ZEXT32_CHECK
 * also tests the register before each such access, and traps if its
 * high half isn't zero.
 */
typedef enum TCGZext32Mode {
    TCG_ZEXT32_OFF,
    TCG_ZEXT32_ON,
    TCG_ZEXT32_CHECK,
} TCGZext32Mode;

extern TCGZext32Mode tcg_zext32;

/*
 * Development switches for TCG_ZEXT32_CHECK's own tests: tcg_zext32_poison
 * puts other bits above every 32-bit value the backend zero-extends for
 * x-zext32 before it does so, and tcg_zext32_nofix leaves them there;
 * tcg_zext32_report (implied by either) says on stderr, once the prologue
 * is generated, whether the checks are active.
 */
extern bool tcg_zext32_poison;
extern bool tcg_zext32_nofix;
extern bool tcg_zext32_report;

/*
 * Set by the front end, before the prologue is generated, if every guest
 * address is a 32-bit (I32) temp.
 */
extern bool tcg_guest_addr32;

/* Whether x-zext32 applies, decided when the prologue is generated. */
extern bool tcg_zext32_active;

/* Whether x-zext32 can be on: user mode on a host that supports it. */
bool tcg_can_zext32(void);

/*
 * The host register named by a failed TCG_ZEXT32_CHECK trap at host @pc
 * (a synchronous trap in generated code), or -1 if @pc isn't one.
 */
int tcg_zext32_trap(uintptr_t pc);

#endif
