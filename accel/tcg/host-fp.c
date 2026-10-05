/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The host floating-point environment as guest state.
 * See accel/tcg/host-fp.h.
 */

#include "qemu/osdep.h"
#include "tcg/tcg.h"
#include "accel/tcg/host-fp.h"
#include "host/fpenv.h"

/*
 * Changing the control register, or setting a status flag that is clear,
 * costs tens of cycles on current hosts; reading either register is cheap.
 * So write only what differs.
 */
static void load_control(uint64_t control)
{
    if (host_fp_control_read() != control) {
        host_fp_control_write(control);
    }
}

static void load_status(uint64_t status)
{
    if (host_fp_status_read() != status) {
        host_fp_status_write(status);
    }
}

void tcg_host_fp_acquire(CPUState *cpu, uint64_t control, uint64_t status)
{
    tcg_debug_assert(!cpu->host_fp_guest);
    cpu->host_fp_guest = true;
    cpu->host_fp_suspended = 0;
    load_control(control);
    load_status(status);
}

void tcg_host_fp_release(CPUState *cpu)
{
    tcg_debug_assert(cpu->host_fp_guest && !cpu->host_fp_suspended);
    cpu->host_fp_guest = false;
    load_control(HOST_FP_CONTROL_QEMU);
}

void tcg_host_fp_load(CPUState *cpu, uint64_t control, uint64_t status)
{
    tcg_debug_assert(cpu->host_fp_guest);
    if (cpu->host_fp_suspended) {
        cpu->host_fp_control = control;
        cpu->host_fp_status = status;
    } else {
        load_control(control);
        load_status(status);
    }
}

uint64_t tcg_host_fp_status(CPUState *cpu)
{
    tcg_debug_assert(cpu->host_fp_guest);
    return cpu->host_fp_suspended ? cpu->host_fp_status
                                  : host_fp_status_read();
}

void tcg_host_fp_do_suspend(CPUState *cpu)
{
    if (cpu->host_fp_suspended++ == 0) {
        cpu->host_fp_control = host_fp_control_read();
        cpu->host_fp_status = host_fp_status_read();
        if (cpu->host_fp_control != HOST_FP_CONTROL_QEMU) {
            host_fp_control_write(HOST_FP_CONTROL_QEMU);
        }
    }
}

void tcg_host_fp_do_resume(CPUState *cpu)
{
    tcg_debug_assert(cpu->host_fp_suspended);
    if (--cpu->host_fp_suspended == 0) {
        load_status(cpu->host_fp_status);
        if (cpu->host_fp_control != HOST_FP_CONTROL_QEMU) {
            host_fp_control_write(cpu->host_fp_control);
        }
    }
}

void tcg_host_fp_unwind(CPUState *cpu)
{
    if (cpu->host_fp_suspended) {
        cpu->host_fp_suspended = 1;
        tcg_host_fp_do_resume(cpu);
    }
}
