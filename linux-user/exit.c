/*
 *  exit support for qemu
 *
 *  Copyright (c) 2018 Alex Bennée <alex.bennee@linaro.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "tcg/perf.h"
#include "gdbstub/syscalls.h"
#include "qemu.h"
#include "user-internals.h"
#include "qemu/plugin.h"
#include "tcg/tcg-cache.h"
#include "accel/tcg/tb-context.h"

#ifdef CONFIG_GCOV
extern void __gcov_dump(void);
#endif

/* XTCG_CACHE_DUMP: a line for each stored artifact, on stderr. */
static void cache_dump(void *opaque, uint64_t id, uint64_t rva, uint64_t base,
                       const void *art, size_t len)
{
    char line[200];

    if (tcg_cache_dump_line(line, sizeof(line), id, rva, base, art, len)) {
        fputs(line, stderr);
    }
}

void preexit_cleanup(CPUArchState *env, int code)
{
#ifdef CONFIG_GCOV
        __gcov_dump();
#endif
        gdb_exit(code);
        qemu_plugin_user_exit();
        perf_exit();
        if (tcg_cache_mode && getenv("XTCG_CACHE_STATS")) {
            tcg_cache_print_stats();
            fprintf(stderr, "xtcg-cache: flushes completed %u\n",
                    qatomic_read(&tb_ctx.tb_flush_count));
        }
        if (tcg_cache_mode == TCG_CACHE_ON && getenv("XTCG_CACHE_DUMP")) {
            tcg_cache_store_foreach(cache_dump, NULL);
        }
}
