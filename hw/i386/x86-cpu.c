/*
 * Copyright (c) 2003-2004 Fabrice Bellard
 * Copyright (c) 2019, 2024 Red Hat, Inc.
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
#include "system/whpx.h"
#include "system/mshv.h"
#include "system/cpu-timers.h"
#include "system/runstate.h"
#include "host/counter.h"
#include "tcg/startup.h"
#include "trace.h"

#include "hw/i386/x86.h"
#include "target/i386/cpu.h"
#include "hw/intc/i8259.h"
#include "hw/core/irq.h"
#include "system/kvm.h"

/* TSC handling */

#if HOST_COUNTER_SUPPORTED
/*
 * tcg_tsc_counter: the TSC is the host counter in ns plus a per-vCPU
 * offset.  The TSC must not advance while the VM is stopped: at a stop
 * the counter's value is kept, and at the next start every offset loses
 * the stopped interval.  New vCPUs start from tsc_counter_base, so all
 * of them agree.
 */
static int64_t tsc_counter_base;
static uint64_t tsc_counter_stopped_at;
static bool tsc_counter_stopped = true;

static uint64_t tsc_counter_now(void)
{
    return tsc_counter_stopped ? tsc_counter_stopped_at : host_counter_ns();
}

static void tsc_counter_vm_state(void *opaque, bool running, RunState state)
{
    uint64_t now = host_counter_ns();
    int64_t d;
    CPUState *cs;

    if (!running) {
        if (!tsc_counter_stopped) {
            tsc_counter_stopped_at = now;
            tsc_counter_stopped = true;
        }
        return;
    }
    if (tsc_counter_stopped) {
        d = now - tsc_counter_stopped_at;
        tsc_counter_base -= d;
        CPU_FOREACH(cs) {
            X86_CPU(cs)->env.tsc_counter_offset -= d;
        }
        tsc_counter_stopped = false;
    }
}

static void tsc_counter_init_once(void)
{
    static bool done;

    if (!done) {
        done = true;
        tsc_counter_stopped_at = host_counter_ns();
        tsc_counter_base = -(int64_t)tsc_counter_stopped_at;
        qemu_add_vm_change_state_handler(tsc_counter_vm_state, NULL);
    }
}
#endif

uint64_t cpu_get_tsc(CPUX86State *env)
{
#if HOST_COUNTER_SUPPORTED
    if (tcg_tsc_counter) {
        return tsc_counter_now() + env->tsc_counter_offset;
    }
#endif
    return cpus_get_elapsed_ticks();
}

/* Make the vCPU's TSC read @tsc now (tcg_tsc_counter). */
void x86_tsc_counter_set(CPUX86State *env, uint64_t tsc)
{
#if HOST_COUNTER_SUPPORTED
    env->tsc_counter_offset = tsc - tsc_counter_now();
#endif
}

/* A vCPU's TSC at reset: the shared base, so that all vCPUs agree. */
void x86_tsc_counter_reset(CPUX86State *env)
{
#if HOST_COUNTER_SUPPORTED
    if (tcg_tsc_counter) {
        tsc_counter_init_once();
        env->tsc_counter_offset = tsc_counter_base;
    }
#endif
}

/* IRQ handling */
static void pic_irq_request(void *opaque, int irq, int level)
{
    CPUState *cs = first_cpu;
    X86CPU *cpu = X86_CPU(cs);

    trace_x86_pic_interrupt(irq, level);

    if (mshv_irqchip_in_kernel()) {
        return;
    }

    if (cpu_is_apic_enabled(cpu->apic_state) && !kvm_irqchip_in_kernel() &&
        !whpx_irqchip_in_kernel()) {
        CPU_FOREACH(cs) {
            cpu = X86_CPU(cs);
            if (apic_accept_pic_intr(cpu->apic_state)) {
                apic_deliver_pic_intr(cpu->apic_state, level);
            }
        }
    } else {
        if (level) {
            cpu_interrupt(cs, CPU_INTERRUPT_HARD);
        } else {
            cpu_reset_interrupt(cs, CPU_INTERRUPT_HARD);
        }
    }
}

qemu_irq x86_allocate_cpu_irq(void)
{
    return qemu_allocate_irq(pic_irq_request, NULL, 0);
}

int cpu_get_pic_interrupt(CPUX86State *env)
{
    X86CPU *cpu = env_archcpu(env);
    int intno;

    if (!kvm_irqchip_in_kernel() && !whpx_irqchip_in_kernel()) {
        intno = apic_get_interrupt(cpu->apic_state);
        if (intno >= 0) {
            return intno;
        }
        /* read the irq from the PIC */
        if (!apic_accept_pic_intr(cpu->apic_state)) {
            return -1;
        }
    }

    intno = pic_read_irq(isa_pic);
    return intno;
}

APICCommonState *cpu_get_current_apic(void)
{
    if (current_cpu) {
        X86CPU *cpu = X86_CPU(current_cpu);
        return cpu->apic_state;
    } else {
        return NULL;
    }
}
