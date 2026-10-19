/*
 * QEMU TCG Multi Threaded vCPUs implementation
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2014 Red Hat Inc.
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

#include "qemu/osdep.h"
#include "exec/cpu-common.h"
#include "system/tcg.h"
#include "system/replay.h"
#include "exec/icount.h"
#include "qemu/main-loop.h"
#include "qemu/notify.h"
#include "qemu/guest-random.h"
#include "hw/core/boards.h"
#include "accel/tcg/cpu-loop.h"
#include "tcg/startup.h"
#include "tcg-accel-ops.h"
#include "tcg-accel-ops-mttcg.h"
#include "system/cpus.h"
#include "qemu/processor.h"
#include "qemu/timer.h"

typedef struct MttcgForceRcuNotifier {
    Notifier notifier;
    CPUState *cpu;
} MttcgForceRcuNotifier;

static void do_nothing(CPUState *cpu, run_on_cpu_data d)
{
}

static void mttcg_force_rcu(Notifier *notify, void *data)
{
    CPUState *cpu = container_of(notify, MttcgForceRcuNotifier, notifier)->cpu;

    /*
     * Called with rcu_registry_lock held, using async_run_on_cpu() ensures
     * that there are no deadlocks.
     */
    async_run_on_cpu(cpu, do_nothing, RUN_ON_CPU_NULL);
}

/*
 * x-haltpoll: before a halted vCPU's thread sleeps on its halt condition,
 * it drops the BQL and spins for a while, watching for anything that
 * would wake it: a new interrupt request, a kick (exit_request), a stop
 * or queued work.  A wakeup that comes within the spin costs no thread
 * wakeup, which on some hosts takes several microseconds.  The spin
 * window adapts per vCPU as KVM's halt_poll_ns does: a halt that ended
 * after the window but within mttcg_haltpoll_ns doubles it (from
 * HALTPOLL_START_NS), a longer one halves it, so vCPUs that stay idle
 * don't keep burning host CPU.
 */
int64_t mttcg_haltpoll_ns;

#define HALTPOLL_START_NS 10000
/* after a wakeup, how long to spin for the BQL before sleeping on it */
#define HALTPOLL_BQL_SPIN_NS 20000

static __thread int64_t haltpoll_window;

/* Spin for the window; true if something arrived (no sleep needed). */
static bool mttcg_halt_poll(CPUState *cpu)
{
    uint32_t ir;
    int64_t deadline;
    bool woken = false;

    if (!haltpoll_window) {
        return false;
    }
    /*
     * While halt_polling is set, a thread that raises an interrupt
     * request without the BQL may skip kicking us: we see the request
     * here.  It raises the request, then (full barrier) reads
     * halt_polling; we clear halt_polling, then (full barrier) check for
     * work under the BQL in qemu_process_cpu_events: one of the two sees
     * the other's store.
     */
    qatomic_set(&cpu->halt_polling, true);
    smp_mb(); /* halt_polling before we sample the requests */
    ir = qatomic_read(&cpu->interrupt_request);
    /* as qemu_process_cpu_events does before it waits */
    qatomic_set_mb(&cpu->exit_request, false);
    deadline = get_clock() + haltpoll_window;
    bql_unlock();
    do {
        if (qatomic_read(&cpu->interrupt_request) != ir ||
            qatomic_read(&cpu->exit_request) || qatomic_read(&cpu->stop) ||
            !cpu_work_list_empty(cpu)) {
            woken = true;
            break;
        }
        cpu_relax();
    } while (get_clock() < deadline);
    qatomic_set(&cpu->halt_polling, false);
    smp_mb(); /* halt_polling cleared before the check for work */
    if (woken) {
        /*
         * Whoever woke us may still hold the BQL (an IPI's sender does);
         * a blocked waiter sleeps in the kernel, the wakeup we just
         * avoided, so spin for it a little first.
         */
        deadline = get_clock() + HALTPOLL_BQL_SPIN_NS;
        do {
            if (bql_trylock()) {
                return true;
            }
            cpu_relax();
        } while (get_clock() < deadline);
    }
    bql_lock();
    return woken;
}

/*
 * In the multi-threaded case each vCPU has its own thread. The TLS
 * variable current_cpu can be used deep in the code to find the
 * current CPUState for a given thread.
 */

static void *mttcg_cpu_thread_fn(void *arg)
{
    MttcgForceRcuNotifier force_rcu;
    CPUState *cpu = arg;

    assert(tcg_enabled());
    g_assert(!icount_enabled());

    rcu_register_thread();
    force_rcu.notifier.notify = mttcg_force_rcu;
    force_rcu.cpu = cpu;
    rcu_add_force_rcu_notifier(&force_rcu.notifier);
    tcg_register_thread();

    bql_lock();
    qemu_thread_get_self(cpu->thread);

    cpu->thread_id = qemu_get_thread_id();
    cpu->neg.can_do_io = true;
    current_cpu = cpu;
    cpu_thread_signal_created(cpu);
    qemu_guest_random_seed_thread_part2(cpu->random_seed);

    do {
        int64_t halt_start = 0;
        bool polled = false;

        /*
         * Order our halted store before the checks for work below (and
         * in qemu_process_cpu_events), for threads that raise an
         * interrupt request without the BQL and then read halted.
         */
        smp_mb();
        if (mttcg_haltpoll_ns && cpu_thread_is_idle(cpu)) {
            halt_start = get_clock();
            polled = mttcg_halt_poll(cpu);
        }
        qemu_process_cpu_events(cpu);
        if (halt_start && !polled) {
            int64_t halted = get_clock() - halt_start;
            if (halted <= mttcg_haltpoll_ns) {
                haltpoll_window = MIN(MAX(haltpoll_window * 2,
                                          HALTPOLL_START_NS),
                                      mttcg_haltpoll_ns);
            } else {
                haltpoll_window /= 2;
            }
        }

        if (cpu_can_run(cpu)) {
            int excp;

            bql_unlock();
            excp = tcg_cpu_exec(cpu);
            bql_lock();
            switch (excp) {
            case EXCP_DEBUG:
                cpu_handle_guest_debug(cpu);
                break;
            case EXCP_HALTED:
                /*
                 * Usually cpu->halted is set, but may have already been
                 * reset by another thread by the time we arrive here.
                 */
                break;
            case EXCP_ATOMIC:
                bql_unlock();
                cpu_exec_step_atomic(cpu);
                bql_lock();
            default:
                /* Ignore everything else? */
                break;
            }
        }
    } while (!cpu->unplug || cpu_can_run(cpu));

    tcg_cpu_destroy(cpu);
    bql_unlock();
    rcu_remove_force_rcu_notifier(&force_rcu.notifier);
    rcu_unregister_thread();
    return NULL;
}

void mttcg_start_vcpu_thread(CPUState *cpu)
{
    char thread_name[VCPU_THREAD_NAME_SIZE];

    g_assert(tcg_enabled());
    tcg_cpu_init_cflags(cpu, current_machine->smp.max_cpus > 1);

    /* create a thread per vCPU with TCG (MTTCG) */
    snprintf(thread_name, VCPU_THREAD_NAME_SIZE, "CPU %d/TCG",
             cpu->cpu_index);

    qemu_thread_create(cpu->thread, thread_name, mttcg_cpu_thread_fn,
                       cpu, QEMU_THREAD_JOINABLE);
}
