/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The host's constant-rate counter, scaled to nanoseconds (aarch64).
 */

#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "host/counter.h"

uint64_t host_counter_mult = 1;
unsigned host_counter_shift;

static void __attribute__((constructor)) host_counter_init(void)
{
    uint64_t freq;

    asm("mrs %0, cntfrq_el0" : "=r"(freq));
    if (freq == 0 || freq == NANOSECONDS_PER_SECOND) {
        return;
    }
    /* 32 fractional bits: exact enough for any counter of 1 MHz or more. */
    host_counter_shift = 32;
    host_counter_mult = (uint64_t)(((unsigned __int128)NANOSECONDS_PER_SECOND
                                    << 32) / freq);
}
