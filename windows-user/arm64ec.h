/*
 * xtajit: what the x64 CPU module shares with ntdll in an ARM64EC process:
 * the per-thread CPU area and the images' ARM64EC metadata.  The layouts
 * are Windows' (as Wine's and FEX's headers have them; mingw-w64 has
 * neither).
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef WINDOWS_USER_ARM64EC_H
#define WINDOWS_USER_ARM64EC_H

/* The CPU area, at TEB + 0x1788 (ChpeV2CpuAreaInfo). */
typedef struct XtCpuArea {
    BOOLEAN InSimulation;               /* 0x00 */
    BOOLEAN InSyscallCallback;          /* 0x01 */
    ULONG64 EmulatorStackBase;          /* 0x08 */
    ULONG64 EmulatorStackLimit;         /* 0x10 */
    ARM64EC_NT_CONTEXT *ContextAmd64;   /* 0x18 */
    ULONG *SuspendDoorbell;             /* 0x20 */
    ULONG64 LoadingModuleModflag;       /* 0x28 */
    void *EmulatorData[4];              /* 0x30 */
    ULONG64 EmulatorDataInline;         /* 0x50 */
} XtCpuArea;

#define XT_TEB_CPU_AREA 0x1788
/* PEB->EcCodeBitMap: a bit per 4 KiB page below 2^47, set for EC code. */
#define XT_PEB_EC_BITMAP 0x368
#define XT_EC_BITMAP_LIMIT (1ull << 47)

/* IMAGE_LOAD_CONFIG_DIRECTORY64's CHPEMetadataPointer, for ARM64EC. */
typedef struct XtEcMetadata {
    ULONG Version;
    ULONG CodeMap;
    ULONG CodeMapCount;
    ULONG CodeRangesToEntryPoints;
    ULONG RedirectionMetadata;
    ULONG os_arm64x_dispatch_call_no_redirect;
    ULONG os_arm64x_dispatch_ret;
    ULONG os_arm64x_dispatch_call;
    ULONG os_arm64x_dispatch_icall;
    ULONG os_arm64x_dispatch_icall_cfg;
    ULONG AlternateEntryPoint;
    ULONG AuxiliaryIAT;
    ULONG CodeRangesToEntryPointsCount;
    ULONG RedirectionMetadataCount;
    ULONG GetX64InformationFunctionPointer;
    ULONG SetX64InformationFunctionPointer;
    ULONG ExtraRFETable;
    ULONG ExtraRFETableSize;
    ULONG os_arm64x_dispatch_fptr;
    ULONG AuxiliaryIATCopy;
} XtEcMetadata;

/* An x64 entry point (fast-forward sequence) and its native code, as RVAs. */
typedef struct XtEcRedirection {
    ULONG Source;
    ULONG Destination;
} XtEcRedirection;

static inline XtCpuArea *xt_cpu_area(void *teb)
{
    return *(XtCpuArea **)((char *)teb + XT_TEB_CPU_AREA);
}

NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

/*
 * The PEB's bitmap word for ADDR's 64 pages (256 KiB), bit n for page n;
 * 0 where Windows has committed no bitmap (no EC code there).
 */
static inline uint64_t xt_ec_bitmap_word(uint64_t addr)
{
    const uint64_t *bitmap;
    uint64_t w = 0;
    SIZE_T n;

    if (addr >= XT_EC_BITMAP_LIMIT) {
        return 0;
    }
    bitmap = *(const uint64_t **)
        ((char *)NtCurrentTeb()->ProcessEnvironmentBlock + XT_PEB_EC_BITMAP);
    if (NtReadVirtualMemory(GetCurrentProcess(), (void *)&bitmap[addr >> 18], &w,
                            sizeof(w), &n) < 0) {
        return 0;
    }
    return w;
}

/*
 * Whether ADDR is EC code (native), by the PEB's bitmap.  ntdll's test
 * checks the address against the bitmap's range and reads the bitmap
 * directly, with no system call: it runs on every transfer to native code.
 */
static inline bool xt_is_ec_code(uint64_t addr)
{
    return RtlIsEcCode(addr);
}

/* arm64ec.S */
void xt_check_call(void);

/*
 * The page below a thread's emulator stack (ThreadInit): its doorbell, an
 * entry's record (arm64ec.S writes it: the kind, NZCV, the target and lr,
 * and where the registers went), the native registers of an entry that
 * had no CPU state to store them into, and that CPU state, ENV: NULL
 * until the thread's record exists (enter_engine), and again from when
 * the record is taken (its own end, or the reaper's after another thread
 * ended it), so that when it is set it is EmulatorData[0]'s.
 */
typedef struct XtEcFrame {
    ULONG doorbell;
    uint32_t entry;             /* XT_EC_ENTRY_*, at offset 4 */
    uint32_t nzcv;              /* at entry, as the Cpsr's */
    uint32_t saved_to_env;      /* the registers in ENV, not in CTX */
    uint64_t pc, lr;            /* the target (x9), lr at entry */
    CPUArchState *env;
    uint32_t inj_armed;         /* XTAJIT_INJECT=sN: suspended before */
    ARM64_NT_CONTEXT ctx;
    /*
     * x-ecinline: the sp of a TB's frame left for native code (0: none);
     * the entries run below it until it is resumed or discarded.
     */
    uint64_t resume_sp;
    uint64_t resume_go;         /* the resume's sp, for entry_tail */
    /*
     * x-ecfast: what the departure that kept the frame left (read only
     * while resume_sp is set): XT_EC_KEPT_C, the flags materialized and
     * the host FP state released (ec_callout's way); XT_EC_KEPT_FAST, the
     * flags lazy and the host FP state held, with FPSR as it was at the
     * departure in dep_fpsr.
     */
    uint32_t resume_kind;
    uint32_t resume_pad;
    uint64_t dep_fpsr;
    /*
     * x-ecfast's resume in assembly (arm64ec.S), from a departure that
     * kept the frame XT_EC_KEPT_FAST and found it can (else fr_key 0,
     * which is also what consuming, discarding or normalizing the frame
     * leaves): the return it takes, by its address (the return stack's
     * top entry's key) and RSP past it; the entry's landing, and the top
     * once it is popped, with the env slot that holds the top; the code
     * buffer's flush count; and the records the resume takes ownership
     * of.  The departure in assembly (xt_ec_fast_depart) writes them all
     * but the ring's bounds (fr_lo, fr_hi), which the departure in C that
     * finds a landing sets for it, and a record's making or end clears.
     */
    uint64_t fr_key;
    uint64_t fr_land;
    uint64_t fr_rsp;
    uint64_t *fr_next;
    uint64_t **fr_slot;
    struct XtThread *fr_t;
    CPUState *fr_cs;
    struct rcu_reader_data *fr_reader;
    uint32_t fr_flush;
    uint32_t fr_pad;
    uint64_t *fr_lo, *fr_hi;
} XtEcFrame;

#define XT_EC_KEPT_C        0
#define XT_EC_KEPT_FAST     1

/*
 * The operation a notification's two halves surround (XtGateRoot.kind).
 * The first four never block; a read may block for good, and whoever
 * certifies the thread meanwhile takes its range over.
 */
#define XT_MEMOP_NONE       0
#define XT_MEMOP_ALLOC      1
#define XT_MEMOP_PROTECT    2
#define XT_MEMOP_FREE       3
#define XT_MEMOP_UNMAP      5
#define XT_MEMOP_READ       6

/* XtEcFrame.entry: a call or jump into x64 code, or a return to it */
#define XT_EC_ENTRY_CALL    1
#define XT_EC_ENTRY_RETURN  2

/* arm64ec.c: the entries' C halves, on the emulator stack */
uintptr_t xt_ec_enter(XtEcFrame *f);
/* x-ecfast's resume in assembly, where it can't finish (XT_EC_FAST_*) */
uintptr_t xt_ec_fast_slow(XtEcFrame *f, int why);
#define XT_EC_FAST_START    1   /* cpu_exec_start found an exclusive */
#define XT_EC_FAST_CLEAR    2   /* a request or a flush, under ownership */
/* x-ecfast's departure in assembly: its C tails (XT_EC_TAIL_*) */
extern const char xt_ec_fast_depart[];
void xt_ec_fast_depart_tail(struct XtThread *t, unsigned tails);
#define XT_EC_TAIL_RCU      1   /* a writer waits for the reader */
#define XT_EC_TAIL_EXCL     2   /* an exclusive section is pending */
void xt_ec_begin(void);

/* arm64ec.S: transfers out of the engine; neither returns */
G_NORETURN void xt_ec_exit_native_env(CPUArchState *env, uintptr_t target,
                                      bool ymm);
G_NORETURN void xt_ec_jump_set_stack(uintptr_t pc, uintptr_t sp);
/* NtContinue, keeping registers for BeginSimulation; returns on failure */
void xt_ec_continue_kept(ARM64_NT_CONTEXT *n, int64_t nr_continue);
extern uintptr_t xt_x64_ret;
extern const char xt_ec_exit_suspend_point[], xt_ec_exit_resume_point[];

/* test-ec.S: the capture probe's loop and its labels; its entry path. */
extern const char xt_cap_loop[], xt_cap_loop_top[], xt_cap_trap[],
                  xt_cap_fault[], xt_cap_cont[], xt_cap_loop_end[];
extern uint32_t xt_cap_entry_mode;
extern uint64_t xt_cap_entry_rec[6];
void xt_cap_entry_end(uint64_t which);

/*
 * XTAJIT_INJECT=sN or SN (test-ec.c): the stubs' test points.  With
 * XT_EC_ENTRY_INJECT in xt_cap_entry_mode, the entries take copies of
 * themselves (arm64ec.S) that wait TICKS at point N: 1 before
 * InSimulation is set, 2 after it, 3 after the registers' stores; and
 * the exit, through xt_ec_exit_native_env_inj: 4 before the registers'
 * loads, 5 after them, 6 after InSimulation is cleared.  With sN, only in
 * a thread suspended before (XtEcFrame.inj_armed); with SN, always.
 * HITS counts the waits, RUNG those that ended with the doorbell set.
 */
#define XT_EC_ENTRY_INJECT  0x80000000u

typedef struct XtStubInject {
    uint32_t point, always;
    uint64_t ticks;
    uint64_t hits[8], rung[8];
} QEMU_ALIGNED(128) XtStubInject;

extern XtStubInject xt_stub_inject;
G_NORETURN void xt_ec_exit_native_env_inj(CPUArchState *env,
                                          uintptr_t target, bool ymm);
void xt_ec_stub_inject_init(void);
void xt_ec_stub_inject_report(void);

/*
 * The thread gates' test points (test-tp.c, arm64ec.S's tp_point): a
 * section shared with a controller process, which arms points, waits for
 * a thread to be held at one, acts on it, and releases it.
 *
 * The stubs' point (arm64ec.S): STATE 0 idle, 1 armed, 2 held (claimed),
 * 3 published, 4 done.  BEFORE and AFTER hold x13, x14, x23, x24 and x28
 * (the canary) around the hold, GPR_BEFORE and GPR_AFTER every register
 * but x16-x18 and x28, by number.  FORCE_ZERO has the hold zero x13, x14,
 * x23 and x24 itself (bit 0), or makes a fault after the hold, a nested
 * entry (bit 1); LIVE_LAYOUT says which registers the entries'
 * admission keeps its state in (2: x10-x12, the kind in w15).  The
 * subject's native APC routine, and what it last acknowledged; its
 * harness's words.
 *
 * The C points (XT_TP, XtTpId): C_ARMED has a bit a point; a hit on an
 * armed point looks for an armed slot of it (XtTpSlot) whose filters
 * match, and the NTH such hit (or, with EVERY, each from the NTH) holds
 * the thread.  A hit on a slot already holding (a nested hit) counts BUSY
 * and passes.  The failure sites (XT_TP_FAIL, XtTpFail): F_ARMED a bit a
 * site, failing at its F_NTH[] hit, or every hit from it with F_EVERY.
 * The notes (XT_TP_NOTE, XtTpNote): a log the controller reads, even
 * after the subject has ended.  ADDR[] (XtTpAddr) is where the module's
 * counters are, in the subject, for the controller's reads.
 */
#define XT_TP_SIZE 0x20000
#define XT_TP_SLOTS 8
#define XT_TP_IDS 128
#define XT_TP_LOG 2048

typedef struct XtTpSlot {
    uint32_t point, state;          /* XT_TPS_* */
    uint32_t nth, every;
    uint64_t gate_filter, tid_filter;
    uint64_t hits, busy;
    /* The hold: its generation, thread, gate, word and argument. */
    uint64_t gen, tid, gate, word, arg, word_after;
    /* Released when RELEASE is GEN; CMD_SEQ moves for a command (CMD). */
    uint64_t release;
    uint32_t cmd, cmd_seq, cmd_done, expired;
    uint64_t cmd_arg, cmd_result;
    uint64_t done;                  /* the last hold's GEN, once it ends */
} XtTpSlot;

typedef struct XtTpLog {
    uint32_t kind, tid;
    uint64_t a, b, c;
} XtTpLog;

typedef struct XtTpBlock {
    uint32_t magic, version;
    uint32_t asm_point, asm_state;
    uint64_t canary, tid_filter, hits;
    uint32_t nth, gen;
    uint64_t tid, spin_pc, orig_sp, x16, x17;
    uint64_t before[5], after[5];
    uint32_t release, ready;
    uint64_t apc_routine, module_base;
    uint64_t ack, ack_tid;
    uint64_t harness[32];
    uint32_t force_zero, live_layout;
    uint64_t pad[5];
    uint64_t gpr_before[32], gpr_after[32];
    /* 0x400 */
    uint64_t c_armed[XT_TP_IDS / 64], f_armed[XT_TP_IDS / 64];
    uint64_t f_every[XT_TP_IDS / 64];
    uint64_t log_next, hold_gen;
    uint64_t pad2[1];
    uint64_t addr[32];
    uint32_t f_nth[XT_TP_IDS], f_hits[XT_TP_IDS];
    XtTpSlot slots[XT_TP_SLOTS];
    XtTpLog log[XT_TP_LOG];
} XtTpBlock;

/* XtTpSlot.state */
enum {
    XT_TPS_IDLE,
    XT_TPS_ARMED,
    XT_TPS_CLAIMED,
    XT_TPS_HELD,
    XT_TPS_DONE,
};

/* XtTpSlot.every: hold at each hit from the Nth, or act at each, unheld. */
#define XT_TP_EVERY_ACT 2

/* XtTpSlot.cmd: what the held thread does, on its own gate. */
enum {
    XT_TPC_POISON = 1,              /* POISONED set, the rest kept */
    XT_TPC_SEQ,                     /* SEQ moved forward to CMD_ARG */
    XT_TPC_SEQ_STEP,                /* SEQ moved forward by one */
    XT_TPC_FAULT,                   /* a fault, a nested entry (xt_tp_fault) */
};

/* xt_tp_leak's flags. */
#define XT_TP_LEAK_UNCOMMITTED  1   /* the byte left set */
#define XT_TP_LEAK_REC          2   /* a record user held */
#define XT_TP_LEAK_ROOT         4   /* a pending root, kind (FLAGS >> 8) */
#define XT_TP_LEAK_PAIRED       8   /* no leak: a level entered and left */
#define XT_TP_LEAK_ROOT_ADDR    0x7e570000ull   /* + kind * 0x1000 */

#define XT_TP_MAGIC 0x50545458u     /* "XTTP" */

NTSTATUS NTAPI NtTerminateThread(HANDLE, NTSTATUS);
PVOID NTAPI RtlAddVectoredExceptionHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);

extern XtTpBlock *xt_tp_block;
void xt_tp_process_init(void);
uint64_t xt_tp_jump_asm(uint64_t target, uint64_t arg);
void xt_tp_fault(void);
extern const char xt_tp_fault_pc[];
XTEXPORT uint64_t xt_tp_jump(uint64_t target, uint64_t arg);
XTEXPORT uint64_t xt_tp_native_add(uint64_t arg);
XTEXPORT DWORD WINAPI xt_tp_jump_worker(void *arg);
XTEXPORT uint64_t xt_tp_leak(uint64_t flags);

/*
 * A thread's gate (arm64ec-gate.c): what another thread needs to know
 * before it may take the thread as holding nothing of the engine's, kept
 * for the process's life so that a pointer to it never dangles.  Each
 * thread has one, found by its identity (the thread ID and creation time)
 * in a registry that only grows, and cached in its CPU area's
 * EmulatorData[XT_EC_GATE] for itself.
 *
 * ADM is the admission word (XT_ADM_*): the levels of the module's code
 * the thread is in, a sequence number every change moves, and two sticky
 * states.  CHECKING, the thread's own, has a byte a level, set from the
 * level's push until its entry has read the gate (adm_enter).
 * ROOTS are the operations a notification's first half left for its
 * second.  CLOSED is the thread's own closure, set by a thread ending it;
 * INTERNAL marks one of the engine's internal threads until it parks or
 * ends.  RET is the retirement's state (XT_RET_*), the reaper's once the
 * thread has ended (THREAD, a handle that can be waited on).
 */
#define XT_EC_GATE 3
#define XT_GATE_ROOTS 8

typedef struct XtGateRoot {
    uint32_t state;             /* XT_ROOT_* */
    uint32_t kind;              /* XT_MEMOP_* */
    uint64_t gen;               /* the gate's push count when pushed */
    uint64_t addr, len;
} XtGateRoot;

typedef struct XtGate {
    uint64_t adm;
    uint32_t closed;
    uint32_t internal;
    uint32_t ret;
    uint32_t published;         /* registered: readable by a scan */
    uint8_t checking[32];       /* [I]: level I + 1 not yet admitted */
    uint64_t root_gen;
    XtGateRoot roots[XT_GATE_ROOTS];
    uint32_t tid;
    uint64_t create_time;
    HANDLE thread;
    void *rec, *frame;
} XtGate;

/*
 * XtGate.adm, changed only by compare-and-swap, so that a transition an
 * interruption made in between is never written over: SEQ moves on every
 * change (one that would wrap it poisons the word instead), COUNT is the
 * levels outstanding, PARKED and POISONED stick.  arm64ec.S's stubs use the
 * same layout.
 */
#define XT_ADM_SEQ_MASK     0xffffffffull
#define XT_ADM_COUNT_SHIFT  32
#define XT_ADM_FIELD_MASK   0x3fffull
#define XT_ADM_MAX_LEVELS   32      /* XtGate.checking's bytes */
#define XT_ADM_PARKED       (1ull << 60)
#define XT_ADM_POISONED     (1ull << 61)
#define XT_ADM_COUNT(w)     (((w) >> XT_ADM_COUNT_SHIFT) & XT_ADM_FIELD_MASK)

/*
 * The gate every thread's fresh entry checks: NULL while open, the exit
 * owner's gate once the process's end has closed it.
 */
extern XtGate *xt_gate_closed_by;

/* XtGateRoot.state */
#define XT_ROOT_FREE        0
#define XT_ROOT_PENDING     1
#define XT_ROOT_CLAIMED     2
#define XT_ROOT_TAKEN       3

/* xt_adm_enter's result: the level, and whether it was an attempt. */
#define XT_ADM_ATTEMPT      0x80000000u

uint32_t xt_adm_enter(XtGate *g);
bool xt_adm_alone(XtGate *g);
int xt_adm_enter_claim(XtGate *g, uint32_t kind, uint64_t addr, uint64_t len);
G_NORETURN void xt_adm_park_terminal(XtGate *g);
void xt_root_push(XtGate *g, uint32_t kind, uint64_t addr, uint64_t len);
void xt_root_release(XtGate *g, int i);
void xt_adm_exit(XtGate *g);
G_NORETURN void xt_adm_park(XtGate *g);
G_NORETURN void xt_adm_poison_park(XtGate *g);
G_NORETURN void xt_adm_reject(XtGate *g, uint32_t level);
uint64_t xt_adm_leak_uncommitted(XtGate *g);

NTSTATUS xt_ec_alloc_direct(void **base, SIZE_T *size, ULONG type,
                            ULONG prot);
bool xt_gate_init_process(void);
void xt_gate_report(char *line, size_t size);

/*
 * What a thread whose handle has signalled left on its gate
 * (xt_gate_death): nothing (CLEAN), an operation's second half that never
 * ran (UNFINISHED), or a level of the module's work still held (OWNED:
 * it may have died holding any of the engine's resources).
 */
typedef enum XtDeath {
    XT_DEATH_CLEAN,
    XT_DEATH_UNFINISHED,
    XT_DEATH_OWNED,
} XtDeath;

XtDeath xt_gate_death(XtGate *g);
void xt_gate_find_deaths(uint32_t *owned, uint32_t *unfinished);
void xt_gate_tp_publish(void);
bool xt_gate_quarantine(XtGate *g);
XtGate *xt_gate_retire_next(uint32_t *cursor, bool *quarantined);
void xt_gate_mark_retired(XtGate *g);
void xt_gate_retire_abort(XtGate *g);
extern uint32_t xt_gate_read_open;
bool xt_gate_register_initial(void);
XtGate *xt_gate_self_slow(void);
bool xt_gate_identity(HANDLE h, uint32_t *tid, uint64_t *create_time);
XtGate *xt_gate_lookup(uint32_t tid, uint64_t create_time);
XtGate *xt_gate_for(HANDLE h, bool create_closed, NTSTATUS *st);

/* The calling thread's gate, installed on its first need. */
static inline XtGate *xt_gate_self(void)
{
    XtCpuArea *area = xt_cpu_area(NtCurrentTeb());
    XtGate *g = area ? qatomic_load_acquire((XtGate **)
                                            &area->EmulatorData[XT_EC_GATE])
                     : NULL;

    return likely(g) ? g : xt_gate_self_slow();
}

#endif
