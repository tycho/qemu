/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The host's constant-rate counter, scaled to nanoseconds (aarch64).
 */

#ifndef AARCH64_HOST_COUNTER_H
#define AARCH64_HOST_COUNTER_H

/*
 * The generic timer's virtual counter (cntvct_el0): constant rate,
 * synchronized across cores, readable from user space in a few cycles.
 * host_counter_ns() scales it to nanoseconds with factors computed once
 * from CNTFRQ_EL0: ns = (ticks * mult) >> shift, the product taken to
 * 128 bits.  With a 1 GHz counter, mult is 1 and shift 0.
 */
#define HOST_COUNTER_SUPPORTED 1

extern uint64_t host_counter_mult;
extern unsigned host_counter_shift;

static inline uint64_t host_counter_ticks(void)
{
    uint64_t v;

    asm volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}

static inline uint64_t host_counter_ns(void)
{
    uint64_t t = host_counter_ticks();

    if (host_counter_shift == 0) {
        return t * host_counter_mult;
    }
    return (uint64_t)(((unsigned __int128)t * host_counter_mult) >>
                      host_counter_shift);
}

#endif /* AARCH64_HOST_COUNTER_H */
