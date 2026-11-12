/*
 * xtajit: the x64 module's capture probe (test only), for a harness run
 * with this module as its process's x64 emulator.  The loop (test-ec.S)
 * keeps known values in the registers while the harness interrupts it;
 * the module's ResetToConsistentState logs every call it gets, says
 * whether the native context still holds the loop's values, and continues
 * the loop's own trap and fault.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "xtajit.h"
#include "arm64ec.h"

NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
NTSTATUS NTAPI RtlQueryEnvironmentVariable(PVOID, PCWSTR, SIZE_T, PWSTR,
                                           SIZE_T, PSIZE_T);

/* The loop's registers in and out, its requests and what its traps did. */
struct XtCapRun {
    uint64_t in_x[29];      /* x0-x28; x18 and x19 unused */
    uint64_t pad0;
    uint64_t in_v[64];      /* v0-v31 */
    uint64_t out_x[29];
    uint64_t pad1;
    uint64_t out_v[64];
    uint64_t iters;
    ULONG *doorbell;        /* polled when set */
    uint32_t req;           /* nonzero: fault at this address */
    uint32_t resim;         /* InSimulation again after a continuation */
    uint64_t stack;         /* the loop's sp, when nonzero */
    uint64_t saved_sp;
    uint64_t traps, faults; /* continued by ResetToConsistentState */
};

QEMU_BUILD_BUG_ON(offsetof(XtCapRun, in_v) != 0x0f0);
QEMU_BUILD_BUG_ON(offsetof(XtCapRun, out_x) != 0x2f0);
QEMU_BUILD_BUG_ON(offsetof(XtCapRun, out_v) != 0x3e0);
QEMU_BUILD_BUG_ON(offsetof(XtCapRun, iters) != 0x5e0);
QEMU_BUILD_BUG_ON(offsetof(XtCapRun, doorbell) != 0x5e8);
QEMU_BUILD_BUG_ON(offsetof(XtCapRun, req) != 0x5f0);
QEMU_BUILD_BUG_ON(offsetof(XtCapRun, resim) != 0x5f4);
QEMU_BUILD_BUG_ON(offsetof(XtCapRun, stack) != 0x5f8);
QEMU_BUILD_BUG_ON(offsetof(XtCapRun, saved_sp) != 0x600);

/* One call of ResetToConsistentState. */
struct XtCapEvent {
    uint32_t code;
    uint32_t flags;         /* XT_CAP_EV_* */
    uint64_t pc, sp, lr;
    uint64_t guest_rip, guest_rsp;
    uint32_t lost;          /* XT_CAP_LOST_*: the native context's */
    uint32_t tid;
};

enum {
    XT_CAP_EV_INSIM = 1,        /* InSimulation set at the call */
    XT_CAP_EV_INCB = 2,         /* InSyscallCallback set */
    XT_CAP_EV_LOOP = 4,         /* pc in the armed loop */
    XT_CAP_EV_GUEST = 8,        /* a guest context was passed */
    XT_CAP_EV_CONTINUED = 16,   /* the probe continued it */
    XT_CAP_EV_DOORBELL = 32,    /* the doorbell word was set */
};

enum {
    XT_CAP_LOST_X13 = 1, XT_CAP_LOST_X14 = 2, XT_CAP_LOST_X23 = 4,
    XT_CAP_LOST_X24 = 8, XT_CAP_LOST_X28 = 16, XT_CAP_LOST_V16_31 = 32,
    XT_CAP_LOST_OTHER_X = 64, XT_CAP_LOST_V0_15 = 128,
};

/* test-ec.S's entry record: which, target, sp, lr, InSimulation, count. */
uint32_t xt_cap_entry_mode;
uint64_t xt_cap_entry_rec[6];

static const char *cap_code = xt_cap_loop;
static XtCapRun *cap_run;
static int cap_clear_sim;
static XtCapEvent cap_events[1024];
static uint32_t cap_calls;

void xt_cap_entry_end(uint64_t which)
{
    NtTerminateProcess(GetCurrentProcess(), 0xEC0C0000 | (uint32_t)which);
}

static uint32_t lost_regs(const XtCapRun *r, const ARM64_NT_CONTEXT *n)
{
    uint32_t lost = 0;

    for (int i = 0; i < 29; i++) {
        if (i == 18 || i == 19 || n->X[i] == r->in_x[i]) {
            continue;
        }
        lost |= i == 13 ? XT_CAP_LOST_X13 : i == 14 ? XT_CAP_LOST_X14 :
                i == 23 ? XT_CAP_LOST_X23 : i == 24 ? XT_CAP_LOST_X24 :
                i == 28 ? XT_CAP_LOST_X28 : XT_CAP_LOST_OTHER_X;
    }
    for (int i = 0; i < 32; i++) {
        if (n->V[i].Low != r->in_v[2 * i] ||
            (uint64_t)n->V[i].High != r->in_v[2 * i + 1]) {
            lost |= i >= 16 ? XT_CAP_LOST_V16_31 : XT_CAP_LOST_V0_15;
        }
    }
    return lost;
}

/*
 * From ResetToConsistentState: log the call; continue the loop's trap
 * and fault (returning true, with NATIVE to continue with).
 */
bool xt_ec_probe_rtcs(EXCEPTION_RECORD *er, CONTEXT *guest,
                      ARM64_NT_CONTEXT *native)
{
    XtCpuArea *area = xt_cpu_area(NtCurrentTeb());
    uint32_t n = qatomic_fetch_inc(&cap_calls);
    XtCapRun *r = qatomic_read(&cap_run);
    uintptr_t pc = native->Pc, base = (uintptr_t)cap_code;
    bool in_loop = r && pc >= base + (xt_cap_loop_top - xt_cap_loop) &&
                   pc < base + (xt_cap_loop_end - xt_cap_loop);
    XtCapEvent *ev = n < ARRAY_SIZE(cap_events) ? &cap_events[n] : NULL;
    bool cont = false;

    if (ev) {
        ev->code = er->ExceptionCode;
        ev->flags = (area->InSimulation ? XT_CAP_EV_INSIM : 0) |
                    (area->InSyscallCallback ? XT_CAP_EV_INCB : 0) |
                    (in_loop ? XT_CAP_EV_LOOP : 0) |
                    (guest ? XT_CAP_EV_GUEST : 0) |
                    (area->SuspendDoorbell && *area->SuspendDoorbell ?
                     XT_CAP_EV_DOORBELL : 0);
        ev->pc = pc;
        ev->sp = native->Sp;
        ev->lr = native->Lr;
        ev->guest_rip = guest ? guest->Rip : 0;
        ev->guest_rsp = guest ? guest->Rsp : 0;
        ev->lost = in_loop ? lost_regs(r, native) : 0;
        ev->tid = GetCurrentThreadId();
    }
    if (in_loop && pc == base + (xt_cap_trap - xt_cap_loop)) {
        r->traps++;
        if (area->SuspendDoorbell) {
            *area->SuspendDoorbell = 0;
        }
        if (cap_clear_sim) {
            area->InSimulation = 0;
        }
        cont = true;
    } else if (in_loop && pc == base + (xt_cap_fault - xt_cap_loop) &&
               er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        r->req = 0;
        r->faults++;
        cont = true;
    }
    if (cont) {
        native->Pc = base + (xt_cap_cont - xt_cap_loop);
        if (ev) {
            ev->flags |= XT_CAP_EV_CONTINUED;
        }
    }
    return cont;
}

/*
 * The loop to run: in place (WHERE 0) or copied into executable memory
 * from the runtime's VirtualAlloc, which marks it ARM64EC code (1).
 */
XTEXPORT void *xt_ec_cap_prepare(int where)
{
    size_t len = xt_cap_loop_end - xt_cap_loop;
    char *p;

    if (!where) {
        cap_code = xt_cap_loop;
        return (void *)cap_code;
    }
    p = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE,
                     PAGE_EXECUTE_READWRITE);
    if (!p) {
        return NULL;
    }
    memcpy(p, xt_cap_loop, len);
    FlushInstructionCache(GetCurrentProcess(), p, len);
    cap_code = p;
    return p;
}

/*
 * Arm (R) or disarm (NULL) the continuation of the loop's trap and fault;
 * arming starts a new log.
 */
XTEXPORT void xt_ec_cap_arm(XtCapRun *r, int clear_sim)
{
    cap_clear_sim = clear_sim;
    if (r) {
        qatomic_set(&cap_calls, 0);
    }
    qatomic_set(&cap_run, r);
}

/* ResetToConsistentState's calls so far; the first MAX logged into OUT. */
XTEXPORT uint32_t xt_ec_cap_events(XtCapEvent *out, uint32_t max)
{
    uint32_t n = qatomic_read(&cap_calls);

    memcpy(out, cap_events,
           MIN(MIN(n, max), ARRAY_SIZE(cap_events)) * sizeof(*out));
    return n;
}

/*
 * At process init: with XTAJIT_CAPTURE set, entries return at once from
 * the start (the harness's C runtime calls x64 code before main).
 */
void xt_ec_probe_process_init(void)
{
    WCHAR w[8];
    SIZE_T n = 0;

    if (RtlQueryEnvironmentVariable(NULL, L"XTAJIT_CAPTURE", 14, w,
                                    ARRAY_SIZE(w) - 1, &n) >= 0 && n) {
        xt_cap_entry_mode = 1;
    }
}

/* Entries go to xt_cap_entry while MODE is set; REC gets its record. */
XTEXPORT void xt_ec_cap_entry(int mode, uint64_t rec[6])
{
    qatomic_set(&xt_cap_entry_mode,
                mode | (qatomic_read(&xt_cap_entry_mode) & XT_EC_ENTRY_INJECT));
    if (rec) {
        memcpy(rec, xt_cap_entry_rec, sizeof(xt_cap_entry_rec));
    }
}

XtStubInject xt_stub_inject;

/*
 * At process init: XTAJIT_INJECT=sN or SN, with N from 1 to 6, and
 * optionally ",MS" for the wait in milliseconds (1 by default).  A digit
 * alone is xt_inject_point's, as in the 32-bit module.
 */
void xt_ec_stub_inject_init(void)
{
    WCHAR w[16];
    SIZE_T n = 0;
    uint64_t freq, ms = 1;

    if (RtlQueryEnvironmentVariable(NULL, L"XTAJIT_INJECT", 13, w,
                                    ARRAY_SIZE(w) - 1, &n) < 0 || !n) {
        return;
    }
    w[n] = 0;
    if (w[0] >= '1' && w[0] <= '9') {
        xt_inject_point = w[0] - '0';
        return;
    }
    if ((w[0] != 's' && w[0] != 'S') || n < 2 || w[1] < '1' || w[1] > '6') {
        return;
    }
    if (n > 3 && w[2] == ',') {
        ms = 0;
        for (SIZE_T i = 3; i < n && w[i] >= '0' && w[i] <= '9'; i++) {
            ms = ms * 10 + w[i] - '0';
        }
    }
    asm volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    xt_stub_inject.ticks = freq * ms / 1000;
    xt_stub_inject.always = w[0] == 'S';
    xt_stub_inject.point = w[1] - '0';
    qatomic_or(&xt_cap_entry_mode, XT_EC_ENTRY_INJECT);
}

/* At the process's end: the stubs' test points' waits, if any. */
void xt_ec_stub_inject_report(void)
{
    static bool reported;
    char line[160];
    int k;

    if (!xt_stub_inject.point || reported) {
        return;
    }
    reported = true;
    k = snprintf(line, sizeof(line), "stubinject: point %u%s; waits",
                 xt_stub_inject.point, xt_stub_inject.always ? " always" : "");
    for (int i = 1; i <= 6 && k < sizeof(line); i++) {
        uint64_t h = qatomic_read(&xt_stub_inject.hits[i]);
        uint64_t r = qatomic_read(&xt_stub_inject.rung[i]);

        k += snprintf(line + k, sizeof(line) - k, " %llu/%llu",
                      (unsigned long long)h, (unsigned long long)r);
    }
    if (k < sizeof(line) - 1) {
        strcpy(line + k, "\n");
    }
    fputs(line, stderr);
    xt_log_text(line);
}
