/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xtcg development aid, not for upstream: sample each vCPU's guest state
 * from a thread, without stopping it.  XTCG_PSAMPLE=FILE[,MICROSECONDS]
 * (default 1000) appends one 32-byte record per vCPU and period:
 *
 *   uint64_t ns;        host CLOCK_REALTIME
 *   uint32_t cpu;       cpu_index
 *   uint32_t flags;     bit 0 halted, bits 1-2 CPL, bit 3 paging on
 *   uint64_t pc;        CS base + EIP: with PC-relative TBs, the start of
 *                       the TB the vCPU executes (or a later instruction
 *                       where a helper synced EIP)
 *   uint64_t cr3;
 *
 * The reads race with the vCPU threads: a record may mix two moments,
 * which sampling tolerates.
 */

#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "qemu/rcu.h"
#include "qemu/timer.h"
#include "cpu.h"
#include "hw/core/cpu.h"
#include "tcg/helper-tcg.h"

typedef struct PSampleRecord {
    uint64_t ns;
    uint32_t cpu;
    uint32_t flags;
    uint64_t pc;
    uint64_t cr3;
} PSampleRecord;

static FILE *psample_file;
static unsigned psample_us;

static void psample_flush(void)
{
    fflush(psample_file);
}

static void *psample_thread(void *opaque)
{
    rcu_register_thread();
    for (;;) {
        CPUState *cs;

        g_usleep(psample_us);
        RCU_READ_LOCK_GUARD();
        CPU_FOREACH(cs) {
            CPUX86State *env = cpu_env(cs);
            PSampleRecord r = {
                .ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME),
                .cpu = cs->cpu_index,
                .flags = (qatomic_read(&cs->halted) ? 1 : 0) |
                         ((qatomic_read(&env->hflags) & HF_CPL_MASK) << 1) |
                         ((qatomic_read(&env->cr[0]) & CR0_PG_MASK) ? 8 : 0),
                .pc = qatomic_read(&env->segs[R_CS].base) +
                      qatomic_read(&env->eip),
                .cr3 = qatomic_read(&env->cr[3]),
            };

            fwrite(&r, sizeof(r), 1, psample_file);
        }
    }
    return NULL;
}

void x86_tcg_psample_start(void)
{
    static bool started;
    const char *spec = getenv("XTCG_PSAMPLE");
    g_autofree char *path = NULL;
    const char *comma;
    QemuThread thread;

    if (started || !spec || !*spec) {
        return;
    }
    started = true;
    comma = strchr(spec, ',');
    path = comma ? g_strndup(spec, comma - spec) : g_strdup(spec);
    psample_us = comma ? atoi(comma + 1) : 1000;
    psample_file = fopen(path, "ab");
    if (!psample_file || !psample_us) {
        fprintf(stderr, "XTCG_PSAMPLE: can't use %s\n", spec);
        return;
    }
    setvbuf(psample_file, NULL, _IOFBF, 1 << 20);
    atexit(psample_flush);
    qemu_thread_create(&thread, "psample", psample_thread, NULL,
                       QEMU_THREAD_DETACHED);
}
