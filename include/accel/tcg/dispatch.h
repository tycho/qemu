/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The steps of cpu_exec()'s loop, for a user-mode front end that runs
 * some round trips through generated code by its own dispatch and leaves
 * everything else to cpu_exec().  Each is the loop's own code.
 */

#ifndef ACCEL_TCG_DISPATCH_H
#define ACCEL_TCG_DISPATCH_H

#ifndef CONFIG_TCG
#error Can only include this header with TCG
#endif

#include "accel/tcg/tb-cpu-state.h"

/*
 * The state the next TB is looked up for, with the current cflags: for a
 * caller that has checked that no one-shot cflags are pending
 * (cpu->cflags_next_tb is -1).
 */
TCGTBCPUState cpu_exec_tb_state(CPUState *cpu);

/*
 * The TB for @s if the jump cache holds it, else NULL; NULL too when the
 * loop samples the next TB it runs (a region sample deferred from a
 * requested exit), which only the loop does.  It never looks further,
 * translates or faults.
 */
TranslationBlock *cpu_exec_tb_cached(CPUState *cpu, TCGTBCPUState s);

/*
 * The loop's check before each TB: unless the next TB is a one-shot
 * CF_NOIRQ one, clear the kick (icount_decr.u16.high) and handle the
 * requests behind it.  True, with cpu->exception_index set, when the
 * loop must stop.  It may clear *@last_tb.
 */
bool cpu_exec_interrupted(CPUState *cpu, TranslationBlock **last_tb);

#endif
