/*
 * xtajit: the x64 module's test points for the thread gates (test only).
 * A controller process shares a page with this one (XtTpBlock), its
 * section's handle inherited and named by XTAJIT_TP (hexadecimal).  The
 * page is mapped at process init, before the first gate (no notification
 * of the module's follows a view's mapping); after that nothing here
 * allocates.  The controller arms a
 * point of the entries' admission (arm64ec.S's tp_point, in the inject
 * copies, which XTAJIT_TP selects), and the thread that reaches it is held
 * there while the controller acts on it.  The C points (XT_TP) hold a
 * thread the same way, in an alertable wait, so that an APC queued to it
 * runs there; the failure sites (XT_TP_FAIL) make a call fail; the notes
 * (XT_TP_NOTE) log what the module did, where the controller reads it.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "xtajit.h"
#include "arm64ec.h"

NTSTATUS NTAPI RtlQueryEnvironmentVariable(PVOID, PCWSTR, SIZE_T, PWSTR,
                                           SIZE_T, PSIZE_T);
NTSTATUS NTAPI LdrGetProcedureAddress(PVOID module, PANSI_STRING name,
                                      ULONG ordinal, void **address);
VOID NTAPI RtlInitAnsiString(PANSI_STRING, PCSZ);
NTSTATUS NTAPI NtMapViewOfSection(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T,
                                  PLARGE_INTEGER, PSIZE_T, DWORD, ULONG,
                                  ULONG);

XtTpBlock *xt_tp_block;

/* Whether the section holds the whole block (stage 1's held one page). */
static bool tp_full;

QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, asm_point) != 0x08);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, asm_state) != 0x0c);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, canary) != 0x10);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, tid_filter) != 0x18);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, hits) != 0x20);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, nth) != 0x28);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, tid) != 0x30);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, spin_pc) != 0x38);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, orig_sp) != 0x40);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, x16) != 0x48);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, x17) != 0x50);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, before) != 0x58);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, after) != 0x80);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, release) != 0xa8);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, force_zero) != 0x1d0);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, gpr_before) != 0x200);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, gpr_after) != 0x300);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, c_armed) != 0x400);
QEMU_BUILD_BUG_ON(sizeof(XtTpSlot) != 0x90);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, addr) != 0x448);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, slots) != 0x948);
QEMU_BUILD_BUG_ON(offsetof(XtTpBlock, log) != 0xdc8);
QEMU_BUILD_BUG_ON(sizeof(XtTpBlock) > 0x11000);
QEMU_BUILD_BUG_ON(sizeof(XtTpBlock) > XT_TP_SIZE);

/*
 * The special APC the controller queues to a held thread (by
 * NtQueueApcThreadEx2, from its own process): native code, which never
 * enters the engine, acknowledging GEN with its thread.
 */
static void tp_apc(ULONG_PTR gen, ULONG_PTR unused1, ULONG_PTR unused2)
{
    XtTpBlock *b = xt_tp_block;

    qatomic_set(&b->ack_tid, (uint64_t)GetCurrentThreadId());
    qatomic_store_release(&b->ack, (uint64_t)gen);
}

/*
 * A native APC routine for the controller: it ends its own thread through
 * ntdll (so with its ThreadTerm), exit code CODE.
 */
static void tp_apc_end(ULONG_PTR code, ULONG_PTR unused1, ULONG_PTR unused2)
{
    NtTerminateThread(GetCurrentThread(), (NTSTATUS)code);
}

/*
 * The fault action's fault, where no ResetToConsistentState took it (a
 * thread inside a notification, say): noted, and continued past.
 */
static LONG CALLBACK tp_veh(PEXCEPTION_POINTERS p)
{
    ARM64EC_NT_CONTEXT *ec = (ARM64EC_NT_CONTEXT *)p->ContextRecord;

    if (ec->Pc != (uintptr_t)xt_tp_fault_pc) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    xt_tp_note(XT_TPN_FAULT, 2, 0, 0);
    ec->Pc += 4;
    return EXCEPTION_CONTINUE_EXECUTION;
}

/*
 * For the controller's subject: TARGET called with ARG through
 * DispatchJump (its x64 route, or with a native target the bypass), and a
 * native function to call so.
 */
XTEXPORT uint64_t xt_tp_jump(uint64_t target, uint64_t arg)
{
    return xt_tp_jump_asm(target, arg);
}

XTEXPORT uint64_t xt_tp_native_add(uint64_t arg)
{
    return arg + 1;
}

/*
 * A native thread's loop for the subject (its start, through CreateThread):
 * CTL[1], an x64 function (CTL[4] bit 0), and a native one (bit 1): the
 * export tp_native_add of the ARM64EC module CTL[5], or xt_tp_native_add.
 * Each is entered through DispatchJump, until CTL[0] is set; CTL[2] counts
 * the rounds, CTL[3] the wrong results.
 */
XTEXPORT DWORD WINAPI xt_tp_jump_worker(void *arg)
{
    /* Shared with the subject's x64 threads, which stop the loop. */
    volatile uint64_t *ctl = arg;
    uint64_t native = (uint64_t)(uintptr_t)xt_tp_native_add;

    if (ctl[5]) {
        ANSI_STRING name;
        PVOID p = NULL;

        RtlInitAnsiString(&name, "tp_native_add");
        if (LdrGetProcedureAddress((PVOID)(uintptr_t)ctl[5], &name, 0,
                                   &p) < 0) {
            ctl[3]++;
            return 1;
        }
        native = (uint64_t)(uintptr_t)p;
    }
    while (!ctl[0]) {
        if (((ctl[4] & 1) && xt_tp_jump_asm(ctl[1], 5) != 22) ||
            ((ctl[4] & 2) && xt_tp_jump_asm(native, 41) != 42)) {
            ctl[3]++;
        }
        ctl[2]++;
    }
    return 0;
}

/*
 * Time for a hold's deadline, in 100 ns units: KUSER_SHARED_DATA's
 * interrupt time, a read and no call.
 */
static uint64_t tp_now(void)
{
    /* The kernel updates it: each word read anew, the high one twice. */
    volatile uint32_t *it = (volatile uint32_t *)0x7ffe0008;
    uint32_t hi, lo;

    do {
        hi = it[1];
        lo = it[0];
    } while (hi != it[2]);
    return (uint64_t)hi << 32 | lo;
}

#define TP_HOLD_LIMIT (60 * 10000000ull)

/* A held thread's command on gate G (XtTpSlot.cmd): the word it left. */
static uint64_t tp_cmd(XtGate *g, uint32_t cmd, uint64_t arg)
{
    uint64_t w, n;

    if (!g) {
        return 0;
    }
    do {
        w = qatomic_read(&g->adm);
        switch (cmd) {
        case XT_TPC_POISON:
            n = w | XT_ADM_POISONED;
            break;
        case XT_TPC_SEQ:
            if ((w & XT_ADM_SEQ_MASK) >= arg) {
                return w;
            }
            n = (w & ~XT_ADM_SEQ_MASK) | (arg & XT_ADM_SEQ_MASK);
            break;
        case XT_TPC_FAULT:
            xt_tp_fault();
            return qatomic_read(&g->adm);
        case XT_TPC_SEQ_STEP:
            if ((w & XT_ADM_SEQ_MASK) == XT_ADM_SEQ_MASK) {
                return w;
            }
            n = w + 1;
            break;
        default:
            return w;
        }
    } while (qatomic_cmpxchg(&g->adm, w, n) != w);
    return n;
}

/*
 * The hold, for slot S claimed by this thread: the record published, then
 * an alertable wait until the controller releases this generation, running
 * its commands meanwhile.  An APC that runs during the wait doesn't end
 * it; the deadline doesn't restart.
 */
static void tp_hold(XtTpBlock *b, XtTpSlot *s, XtGate *g, uint64_t tid,
                    uint64_t arg)
{
    LARGE_INTEGER ms = { .QuadPart = -10000 };
    uint64_t gen = qatomic_fetch_inc(&b->hold_gen) + 1;
    uint64_t deadline = tp_now() + TP_HOLD_LIMIT;

    s->gen = gen;
    s->tid = tid;
    s->gate = (uintptr_t)g;
    s->word = g ? qatomic_read(&g->adm) : 0;
    s->arg = arg;
    qatomic_store_release(&s->state, XT_TPS_HELD);
    for (;;) {
        uint32_t seq = qatomic_load_acquire(&s->cmd_seq);

        if (seq != s->cmd_done) {
            s->cmd_result = tp_cmd(g, s->cmd, s->cmd_arg);
            qatomic_store_release(&s->cmd_done, seq);
        }
        if (qatomic_load_acquire(&s->release) == gen) {
            break;
        }
        if (tp_now() > deadline) {
            qatomic_set(&s->expired, 1);
            break;
        }
        NtDelayExecution(TRUE, &ms);
    }
    s->word_after = g ? qatomic_read(&g->adm) : 0;
    qatomic_store_release(&s->done, gen);
    qatomic_store_release(&s->state, s->every ? XT_TPS_ARMED : XT_TPS_DONE);
}

/*
 * Point ID reached, with GATE (or NULL) and ARG: held if a slot armed for
 * it matches, at its NTH matching hit (or each from it, with EVERY).  A
 * slot already holding counts the hit BUSY and lets it pass.  With EVERY
 * XT_TP_EVERY_ACT, each such hit runs the slot's command instead, without
 * holding, its argument CMD_ARG plus the hit's number, and is noted.
 */
void xt_tp_hit(unsigned id, void *gate, uint64_t arg)
{
    XtTpBlock *b = xt_tp_block;
    uint64_t tid = GetCurrentThreadId();

    if (!tp_full || id >= XT_TP_IDS ||
        !(qatomic_read(&b->c_armed[id / 64]) >> (id % 64) & 1)) {
        return;
    }
    for (int i = 0; i < XT_TP_SLOTS; i++) {
        XtTpSlot *s = &b->slots[i];
        uint32_t st = qatomic_load_acquire(&s->state);
        uint64_t n;

        if (st == XT_TPS_IDLE || st == XT_TPS_DONE ||
            qatomic_read(&s->point) != id ||
            (s->gate_filter && s->gate_filter != (uintptr_t)gate) ||
            (s->tid_filter && s->tid_filter != tid)) {
            continue;
        }
        if (st != XT_TPS_ARMED) {
            qatomic_inc(&s->busy);
            continue;
        }
        n = qatomic_fetch_inc(&s->hits) + 1;
        if (n < MAX(s->nth, 1) || (n > MAX(s->nth, 1) && !s->every)) {
            continue;
        }
        if (s->every == XT_TP_EVERY_ACT) {
            /* No hold: the command, its argument moved by the hit's number. */
            uint64_t w = tp_cmd(gate, s->cmd, s->cmd_arg + n);

            xt_tp_note(XT_TPN_ACT, id, arg, w);
            return;
        }
        if (qatomic_cmpxchg(&s->state, XT_TPS_ARMED, XT_TPS_CLAIMED) !=
            XT_TPS_ARMED) {
            qatomic_inc(&s->busy);
            continue;
        }
        tp_hold(b, s, gate, tid, arg);
        return;
    }
}

/* Whether failure site ID fails now: its F_NTH hit, or each after it. */
bool xt_tp_fail(unsigned id)
{
    XtTpBlock *b = xt_tp_block;
    uint32_t n, nth;

    if (!tp_full || id >= XT_TP_IDS ||
        !(qatomic_read(&b->f_armed[id / 64]) >> (id % 64) & 1)) {
        return false;
    }
    n = qatomic_fetch_inc(&b->f_hits[id]) + 1;
    nth = MAX(qatomic_read(&b->f_nth[id]), 1);
    return n == nth ||
           (n > nth && (qatomic_read(&b->f_every[id / 64]) >> (id % 64) & 1));
}

/*
 * A note in the log, its KIND stored last; past the log's end, dropped.
 * The last few entries are kept for the exit's note, which a flood of
 * others never crowds out.
 */
void xt_tp_note(unsigned kind, uint64_t a, uint64_t b, uint64_t c)
{
    XtTpBlock *blk = xt_tp_block;
    uint64_t i;
    XtTpLog *l;

    if (!tp_full || (kind != XT_TPN_EXIT &&
                     qatomic_read(&blk->log_next) >= XT_TP_LOG - 16)) {
        return;
    }
    i = qatomic_fetch_inc(&blk->log_next);
    if (i >= XT_TP_LOG) {
        return;
    }
    l = &blk->log[i];
    l->tid = GetCurrentThreadId();
    l->a = a;
    l->b = b;
    l->c = c;
    qatomic_store_release(&l->kind, kind);
}

/* Where counter I is, for the controller's reads. */
void xt_tp_publish(unsigned i, const void *p)
{
    if (xt_tp_block && tp_full && i < ARRAY_SIZE(xt_tp_block->addr)) {
        xt_tp_block->addr[i] = (uintptr_t)p;
    }
}

/*
 * For the subject's x64 code, through a native DLL of its own (x64 code
 * can't call the module's exports): a level of the calling thread's left
 * outstanding.  Admitted (entered and never withdrawn), or uncommitted
 * (pushed with its byte left set, XT_TP_LEAK_UNCOMMITTED); with
 * XT_TP_LEAK_REC a record user held as well.  It stands in for an unwind
 * that skips a level's withdrawal.  The level, or the word left.  With
 * XT_TP_LEAK_ROOT, no level: a root of kind FLAGS >> 8 left pending (a
 * page at XT_TP_LEAK_ROOT_ADDR by its kind), as an operation's first half
 * whose second half never comes leaves it.  With XT_TP_LEAK_PAIRED,
 * nothing is left: an ordinary entry and exit, whose level (with
 * XT_ADM_ATTEMPT if it read the gate rather than inheriting) is returned.
 */
XTEXPORT uint64_t xt_tp_leak(uint64_t flags)
{
    XtGate *g = xt_gate_self();

    if (flags & XT_TP_LEAK_PAIRED) {
        uint32_t level = xt_adm_enter(g);

        xt_adm_exit(g);
        return level;
    }
    if (flags & XT_TP_LEAK_ROOT) {
        uint32_t kind = (flags >> 8) & 0xff;

        xt_root_push(g, kind, XT_TP_LEAK_ROOT_ADDR + kind * 0x1000ull, 0x1000);
        return qatomic_read(&g->adm);
    }

    if (flags & XT_TP_LEAK_REC) {
        xt_record_hold();
    }
    if (flags & XT_TP_LEAK_UNCOMMITTED) {
        return xt_adm_leak_uncommitted(g);
    }
    return xt_adm_enter(g);
}

/* At process init, before the first gate: the controller's page. */
void xt_tp_process_init(void)
{
    WCHAR w[24];
    SIZE_T n = 0, size = 0;
    uint64_t h = 0;
    void *base = NULL;
    XtTpBlock *b;

    if (RtlQueryEnvironmentVariable(NULL, L"XTAJIT_TP", 9, w,
                                    ARRAY_SIZE(w) - 1, &n) < 0 || !n) {
        return;
    }
    for (SIZE_T i = 0; i < n; i++) {
        WCHAR c = w[i];

        h = h * 16 + (c >= '0' && c <= '9' ? c - '0' :
                      c >= 'a' && c <= 'f' ? c - 'a' + 10 :
                      c >= 'A' && c <= 'F' ? c - 'A' + 10 : 0);
    }
    if (NtMapViewOfSection((HANDLE)(uintptr_t)h, GetCurrentProcess(), &base,
                           0, 0, NULL, &size, 2 /* ViewUnmap */, 0,
                           PAGE_READWRITE) < 0) {
        return;
    }
    b = base;
    if (qatomic_read(&b->magic) != XT_TP_MAGIC) {
        return;
    }
    tp_full = size >= sizeof(XtTpBlock);
    b->apc_routine = (uint64_t)(uintptr_t)tp_apc;
    b->module_base = (uint64_t)(uintptr_t)&__ImageBase;
    b->live_layout = 2;
    if (tp_full) {
        b->addr[XT_TPA_APC_END] = (uintptr_t)tp_apc_end;
        RtlAddVectoredExceptionHandler(1, tp_veh);
    }
    qatomic_store_release(&xt_tp_block, b);
    qatomic_or(&xt_cap_entry_mode, XT_EC_ENTRY_INJECT);
    qatomic_store_release(&b->ready, 1);
}
