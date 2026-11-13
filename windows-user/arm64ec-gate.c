/*
 * xtajit: the x64 module's gates (arm64ec.h, XtGate).
 *
 * A gate is a thread's record of what another thread needs before it may
 * take the thread as holding nothing of the engine's.  Gates come from a
 * pool that is never freed, so that a gate found once stays valid for
 * the process's life, and each belongs to one thread, found by its
 * identity (its thread ID and creation time, which together never recur
 * in a process) in a registry that only grows.  A thread caches its own
 * gate in its CPU area; another thread finds it through the registry,
 * from the identity of a handle it holds, and never reads or writes the
 * other thread's TEB.
 *
 * Both live in memory the module allocates with the system call itself
 * (xt_ec_alloc_direct), which no notification of the module's sees, so
 * that installing a gate never re-enters the module.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "xtajit.h"
#include "arm64ec.h"

NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE,
                                 ACCESS_MASK, ULONG, ULONG);
NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);

/*
 * The pool: XT_GATE_POOL_MAX gates reserved at start, committed a block at
 * a time as they are handed out.  The registry: XT_GATE_REG_SLOTS gate
 * pointers, open addressing with linear probing, insert-only; it refuses
 * an insert past three quarters full.
 */
#define XT_GATE_POOL_MAX (1u << 20)
#define XT_GATE_COMMIT_BLOCK 0x10000
#define XT_GATE_REG_SLOTS (1u << 20)

static XtGate *gate_pool;
static uint32_t gate_used;
static uintptr_t gate_committed;        /* bytes of the pool committed */
static XtGate **gate_reg;
static uint32_t gate_registered;

/* The initial thread's, published by ProcessInit before anything else. */
static XtGate gate_initial;

bool xt_gate_init_process(void)
{
    SIZE_T size = (SIZE_T)XT_GATE_POOL_MAX * sizeof(XtGate);
    void *p = NULL;

    if (xt_ec_alloc_direct(&p, &size, MEM_RESERVE, PAGE_READWRITE) < 0) {
        return false;
    }
    gate_pool = p;
    p = NULL;
    size = (SIZE_T)XT_GATE_REG_SLOTS * sizeof(XtGate *);
    if (xt_ec_alloc_direct(&p, &size, MEM_RESERVE | MEM_COMMIT,
                           PAGE_READWRITE) < 0) {
        return false;
    }
    gate_reg = p;
    return true;
}

/* A fresh gate from the pool, zeroed; NULL when the pool is spent. */
static XtGate *gate_alloc(void)
{
    uint32_t i = qatomic_fetch_inc(&gate_used);
    uintptr_t end = (uintptr_t)(i + 1) * sizeof(XtGate);
    uintptr_t done;

    if (i >= XT_GATE_POOL_MAX) {
        return NULL;
    }
    while ((done = qatomic_load_acquire(&gate_committed)) < end) {
        uintptr_t to = ROUND_UP(end, XT_GATE_COMMIT_BLOCK);
        void *p = (char *)gate_pool + done;
        SIZE_T size = to - done;

        /* Committing a range twice is harmless: a racing thread may. */
        if (xt_ec_alloc_direct(&p, &size, MEM_COMMIT, PAGE_READWRITE) < 0) {
            return NULL;
        }
        qatomic_cmpxchg(&gate_committed, done, to);
    }
    return &gate_pool[i];
}

static uint32_t gate_hash(uint32_t tid, uint64_t create_time)
{
    uint64_t h = (create_time ^ ((uint64_t)tid << 32 | tid)) *
                 0x9e3779b97f4a7c15ull;

    return (uint32_t)(h >> 40) & (XT_GATE_REG_SLOTS - 1);
}

/*
 * The registered gate of (TID, CREATE_TIME), or NULL.  A gate is inserted
 * into the first empty slot of its probe sequence, and slots are never
 * emptied, so a registered gate lies before the sequence's first empty
 * slot.
 */
XtGate *xt_gate_lookup(uint32_t tid, uint64_t create_time)
{
    uint32_t i = gate_hash(tid, create_time);

    for (uint32_t n = 0; n < XT_GATE_REG_SLOTS; n++) {
        XtGate *g = qatomic_load_acquire(&gate_reg[i]);

        if (!g) {
            return NULL;
        }
        if (g->tid == tid && g->create_time == create_time) {
            return g;
        }
        i = (i + 1) & (XT_GATE_REG_SLOTS - 1);
    }
    return NULL;
}

/*
 * G registered for its identity, or the gate registered for it first, which
 * the caller then uses instead (G, never published, is abandoned).
 * Two threads registering one identity race for the same first empty slot
 * of the same sequence: the loser finds the winner's gate there.  NULL if
 * the registry is full.
 */
static XtGate *gate_register(XtGate *g)
{
    uint32_t i = gate_hash(g->tid, g->create_time);

    if (qatomic_fetch_inc(&gate_registered) >= XT_GATE_REG_SLOTS / 4 * 3) {
        return NULL;
    }
    for (uint32_t n = 0; n < XT_GATE_REG_SLOTS; n++) {
        XtGate *old = qatomic_load_acquire(&gate_reg[i]);

        if (!old) {
            /* The fields filled before: a release, as the reader's acquire. */
            old = qatomic_cmpxchg(&gate_reg[i], NULL, g);
            if (!old) {
                qatomic_store_release(&g->published, 1);
                return g;
            }
        }
        if (old->tid == g->tid && old->create_time == g->create_time) {
            if (g->thread) {
                NtClose(g->thread);
                g->thread = NULL;
            }
            qatomic_dec(&gate_registered);
            return old;
        }
        i = (i + 1) & (XT_GATE_REG_SLOTS - 1);
    }
    return NULL;
}

/* The identity of the thread behind H: its ID and creation time. */
bool xt_gate_identity(HANDLE h, uint32_t *tid, uint64_t *create_time)
{
    XtThreadBasicInfo tbi;
    LARGE_INTEGER times[4];

    if (NtQueryInformationThread(h, 0 /* ThreadBasicInformation */, &tbi,
                                 sizeof(tbi), NULL) < 0 ||
        NtQueryInformationThread(h, 1 /* ThreadTimes */, times,
                                 sizeof(times), NULL) < 0) {
        return false;
    }
    *tid = (uint32_t)(uintptr_t)tbi.ClientId.UniqueThread;
    *create_time = times[0].QuadPart;
    return true;
}

/*
 * A gate for the thread behind H, filled but not registered: its handle
 * (one that can be waited on, from H), CLOSED and INTERNAL as given.
 */
static XtGate *gate_new(HANDLE h, uint32_t tid, uint64_t create_time,
                        bool closed, bool internal)
{
    XtGate *g = gate_alloc();

    if (!g) {
        return NULL;
    }
    g->tid = tid;
    g->create_time = create_time;
    g->closed = closed;
    g->internal = internal;
    /* The reaper waits on it: a gate without one could never retire. */
    if (NtDuplicateObject(GetCurrentProcess(), h, GetCurrentProcess(),
                          &g->thread, SYNCHRONIZE, 0, 0) < 0) {
        g->thread = NULL;
        return NULL;
    }
    return g;
}

/*
 * The calling thread's gate, cached in its CPU area by compare-and-swap
 * from NULL: an interrupt that cached it first cached the same one.
 */
static XtGate *gate_cache(XtGate *g)
{
    XtCpuArea *area = xt_cpu_area(NtCurrentTeb());
    XtGate *old;

    old = qatomic_cmpxchg((XtGate **)&area->EmulatorData[XT_EC_GATE], NULL, g);
    return old ? old : g;
}

/*
 * The calling thread's gate where its CPU area has none yet: the one
 * registered for its identity (a thread ending it may have made it), else
 * a new one.  The process's first call (ProcessInit) gets the static one
 * before the registry exists.  A thread that can get none ends the
 * process: a notification can't be skipped, and the engine can't be
 * entered without one.
 */
XtGate *xt_gate_self_slow(void)
{
    uint32_t tid = GetCurrentThreadId();
    uint64_t create_time;
    XtGate *g, *r;

    if (!xt_cpu_area(NtCurrentTeb())) {
        NtTerminateProcess(GetCurrentProcess(), STATUS_NO_MEMORY);
    }
    if (!gate_reg) {
        gate_initial.tid = tid;
        return gate_cache(&gate_initial);
    }
    if (!xt_gate_identity(GetCurrentThread(), &tid, &create_time)) {
        NtTerminateProcess(GetCurrentProcess(), STATUS_NO_MEMORY);
    }
    g = xt_gate_lookup(tid, create_time);
    if (!g) {
        g = gate_new(GetCurrentThread(), tid, create_time, false, false);
        r = g ? gate_register(g) : NULL;
        if (!r) {
            NtTerminateProcess(GetCurrentProcess(), STATUS_NO_MEMORY);
        }
        g = r;
    }
    return gate_cache(g);
}

/*
 * The initial thread's static gate, registered once the registry exists
 * (ProcessInit, which runs before any other thread).
 */
bool xt_gate_register_initial(void)
{
    if (!xt_gate_identity(GetCurrentThread(), &gate_initial.tid,
                          &gate_initial.create_time) ||
        NtDuplicateObject(GetCurrentProcess(), GetCurrentThread(),
                          GetCurrentProcess(), &gate_initial.thread,
                          SYNCHRONIZE, 0, 0) < 0) {
        return false;
    }
    if (gate_register(&gate_initial) != &gate_initial) {
        return false;
    }
    return true;
}

/*
 * An internal thread's gate, installed first thing in its start
 * (runtime.c's thread_start), before its TLS: INTERNAL set.
 */
void xt_gate_install_internal(void)
{
    qatomic_set(&xt_gate_self()->internal, 1);
}

/*
 * The gate of the thread behind H (which another thread holds), from the
 * registry; with CREATE_CLOSED, one is made and registered closed if it
 * has none yet, which the thread adopts at its first call (or the one it
 * has is closed).  NULL with *ST set if its identity can't be read or no
 * gate can be had.
 */
XtGate *xt_gate_for(HANDLE h, bool create_closed, NTSTATUS *st)
{
    uint32_t tid;
    uint64_t create_time;
    XtGate *g, *r;

    *st = STATUS_SUCCESS;
    if (!qatomic_load_acquire(&gate_reg)) {
        /* Before ProcessInit: no thread has run the module's code. */
        return NULL;
    }
    if (!xt_gate_identity(h, &tid, &create_time)) {
        *st = STATUS_INVALID_HANDLE;
        return NULL;
    }
    g = xt_gate_lookup(tid, create_time);
    if (g || !create_closed) {
        if (g && create_closed) {
            qatomic_set(&g->closed, 1);
        }
        return g;
    }
    g = gate_new(h, tid, create_time, true, false);
    r = g ? gate_register(g) : NULL;
    if (!r) {
        *st = STATUS_NO_MEMORY;
        return NULL;
    }
    qatomic_set(&r->closed, 1);
    return r;
}

/*
 * Admission (XtGate.adm): every way into the module's code pushes a level
 * of its own and pops exactly that level on every way out.  An entry made
 * while the innermost level is committed inherits it (a callback of the
 * engine's own work, an exception inside it) and checks no gate.  Any
 * other entry is an attempt: it pushes its level uncommitted, then reads
 * the gate, then commits, or, refused, parks for good.  An entry that
 * interrupts an attempt finds that level uncommitted, so it never
 * inherits it, and the attempt's level stays until the attempt itself
 * commits or parks: a thread ending the process never sees the thread
 * idle in between.
 */
XtGate *xt_gate_closed_by;

QEMU_BUILD_BUG_ON(offsetof(XtGate, adm) != 0);
QEMU_BUILD_BUG_ON(offsetof(XtGate, closed) != 8);
QEMU_BUILD_BUG_ON(offsetof(XtGate, internal) != 12);

#define ADM_ONE_COUNT (1ull << XT_ADM_COUNT_SHIFT)
#define ADM_ONE_UNC (1ull << XT_ADM_UNC_SHIFT)

static bool adm_cas(XtGate *g, uint64_t old, uint64_t new)
{
    return qatomic_cmpxchg(&g->adm, old, new) == old;
}

/* W's successor N, with SEQ moved; false if SEQ would wrap. */
static bool adm_next(uint64_t w, uint64_t *n)
{
    if ((w & XT_ADM_SEQ_MASK) == XT_ADM_SEQ_MASK) {
        return false;
    }
    *n += 1;
    return true;
}

/* G's word poisoned, for good: the thread is never taken as idle again. */
static void adm_poison(XtGate *g)
{
    uint64_t w;

    do {
        w = qatomic_read(&g->adm);
    } while (!(w & XT_ADM_POISONED) && !adm_cas(g, w, w | XT_ADM_POISONED));
}

G_NORETURN void xt_adm_poison_park(XtGate *g)
{
    adm_poison(g);
    xt_adm_park(g);
}

G_NORETURN void xt_adm_park(XtGate *g)
{
    LARGE_INTEGER forever = { .QuadPart = INT64_MIN };

    for (;;) {
        NtDelayExecution(FALSE, &forever);
    }
}

/*
 * Whether G's thread may not enter: its own closure, or the process's
 * end's, which neither the end's owner nor an internal thread meets.
 */
static bool adm_closed_for(XtGate *g)
{
    XtGate *owner = qatomic_read(&xt_gate_closed_by);

    if (qatomic_read(&g->closed)) {
        return true;
    }
    return owner && owner != g && !qatomic_read(&g->internal);
}

/*
 * An attempt at LEVEL refused: parked if it was the only level, poisoned
 * if anything else is outstanding (an attempt it interrupted, or a level
 * an interruption left above it), and parked either way.
 */
G_NORETURN void xt_adm_reject(XtGate *g, uint32_t level)
{
    uint64_t w, n;

    do {
        w = qatomic_read(&g->adm);
        if (XT_ADM_COUNT(w) == 1 && XT_ADM_UNC(w) == 1 && level == 1) {
            n = (w - ADM_ONE_COUNT - ADM_ONE_UNC) | XT_ADM_PARKED;
            if (!adm_next(w, &n)) {
                n = w | XT_ADM_POISONED;
            }
        } else {
            n = w | XT_ADM_POISONED;
        }
    } while (!adm_cas(g, w, n));
    xt_adm_park(g);
}

/* The attempt at LEVEL commits, if its level is still the innermost. */
static void adm_commit(XtGate *g, uint32_t level)
{
    uint64_t w, n;

    do {
        w = qatomic_read(&g->adm);
        n = w - ADM_ONE_UNC;
        if (w & (XT_ADM_PARKED | XT_ADM_POISONED)) {
            /* An interruption poisoned it meanwhile: no engine work now. */
            xt_adm_park(g);
        }
        if (XT_ADM_COUNT(w) != level || XT_ADM_UNC(w) != level ||
            !adm_next(w, &n)) {
            adm_poison(g);
            xt_adm_park(g);
        }
    } while (!adm_cas(g, w, n));
}

/*
 * The newest root that isn't free (the highest push count), or -1.  All
 * of them are scanned: completing one never hides another.
 */
static int root_newest(XtGate *g)
{
    int best = -1;
    uint64_t gen = 0;

    for (int i = 0; i < XT_GATE_ROOTS; i++) {
        if (qatomic_load_acquire(&g->roots[i].state) != XT_ROOT_FREE &&
            (best < 0 || g->roots[i].gen > gen)) {
            best = i;
            gen = g->roots[i].gen;
        }
    }
    return best;
}

/*
 * An entry's level pushed, with the gate checked if it's an attempt; with
 * KIND (a notification's second half), an attempt first tries to claim the
 * newest root, if that one is pending and of its kind, and if it does it
 * commits whatever the gate says: it finishes an operation its first half
 * began.  The level, with XT_ADM_ATTEMPT if it was an attempt; *CLAIMED
 * the root claimed, or -1.
 */
static uint32_t adm_enter(XtGate *g, uint32_t kind, uint64_t addr,
                          uint64_t len, int *claimed)
{
    *claimed = -1;
    for (;;) {
        uint64_t w = qatomic_read(&g->adm), n;
        uint32_t count = XT_ADM_COUNT(w), unc = XT_ADM_UNC(w);

        if (w & (XT_ADM_PARKED | XT_ADM_POISONED)) {
            xt_adm_park(g);
        }
        if (count == XT_ADM_FIELD_MASK) {
            adm_poison(g);
            xt_adm_park(g);
        }
        n = w + ADM_ONE_COUNT;
        if (count == unc) {
            n += ADM_ONE_UNC;
        }
        if (!adm_next(w, &n)) {
            adm_poison(g);
            xt_adm_park(g);
        }
        if (!adm_cas(g, w, n)) {
            continue;
        }
        if (count > unc) {
            return count + 1;
        }
        /* The level published before the gate is read (part of a pair). */
        barrier();
        if (kind) {
            int i = root_newest(g);

            if (i >= 0 && g->roots[i].kind == kind &&
                qatomic_cmpxchg(&g->roots[i].state, XT_ROOT_PENDING,
                                XT_ROOT_CLAIMED) == XT_ROOT_PENDING) {
                /*
                 * Still the newest, or an interruption between the choice
                 * and the claim left a newer one: then it is given back.
                 */
                if (root_newest(g) == i) {
                    *claimed = i;
                } else {
                    qatomic_store_release(&g->roots[i].state,
                                          XT_ROOT_PENDING);
                }
            }
        }
        if (*claimed < 0 && adm_closed_for(g)) {
            xt_adm_reject(g, count + 1);
        }
        adm_commit(g, count + 1);
        return (count + 1) | XT_ADM_ATTEMPT;
    }
}

uint32_t xt_adm_enter(XtGate *g)
{
    int claimed;

    return adm_enter(g, 0, 0, 0, &claimed);
}

/*
 * A notification's second half entering: the root it claimed (its first
 * half's), or -1, inherited levels claiming nothing.
 */
int xt_adm_enter_claim(XtGate *g, uint32_t kind, uint64_t addr, uint64_t len)
{
    int claimed;

    adm_enter(g, kind, addr, len, &claimed);
    return claimed;
}

/*
 * A notification's first half, entered as an attempt, leaves its operation
 * for its second: the fields first, then PENDING with a release.  With
 * every root taken, the word is poisoned: the thread can't be taken as
 * idle with an operation nobody would see.
 */
void xt_root_push(XtGate *g, uint32_t kind, uint64_t addr, uint64_t len)
{
    for (int i = 0; i < XT_GATE_ROOTS; i++) {
        XtGateRoot *r = &g->roots[i];

        if (qatomic_read(&r->state) == XT_ROOT_FREE) {
            r->kind = kind;
            r->addr = addr;
            r->len = len;
            r->gen = ++g->root_gen;
            qatomic_store_release(&r->state, XT_ROOT_PENDING);
            return;
        }
    }
    adm_poison(g);
}

/* Claimed root I released, after the second half's last access. */
void xt_root_release(XtGate *g, int i)
{
    qatomic_store_release(&g->roots[i].state, XT_ROOT_FREE);
}

/*
 * The innermost level popped.  None committed to pop is a pairing error:
 * the word is poisoned, so the thread is never taken as idle.
 */
void xt_adm_exit(XtGate *g)
{
    uint64_t w, n;

    do {
        w = qatomic_read(&g->adm);
        n = w - ADM_ONE_COUNT;
        if (XT_ADM_COUNT(w) <= XT_ADM_UNC(w) || !adm_next(w, &n)) {
            adm_poison(g);
            return;
        }
    } while (!adm_cas(g, w, n));
}

