/*
 * xtajit: QEMU's user-mode engine as the 32-bit x86 CPU module of
 * Windows on Arm's WOW64 layer.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef WINDOWS_USER_XTAJIT_H
#define WINDOWS_USER_XTAJIT_H

#include <winternl.h>
#include "exec/cpu-common.h"
#include "exec/mmu-access-type.h"
#include "user/guest-host.h"
#include "cpu.h"

/*
 * Who owns a thread's guest state.  Windows owns it outside simulation:
 * the WOW64 context in the thread's CPU area is authoritative, and another
 * thread may read, change or suspend it.  The engine owns it from the
 * import to the export, and CPUX86State is authoritative.
 *
 *   WINDOWS -> ACQUIRING   set WOW64 TLS slot 2 bit 0, then import
 *   ACQUIRING -> ENGINE    import done; RCU reader registered
 *   ENGINE -> PUBLISHING   the exit's architectural effect is complete
 *   PUBLISHING -> WINDOWS  export, unregister, clear bit 0, then notify
 */
typedef enum XtState {
    XT_WINDOWS,
    XT_ACQUIRING,
    XT_ENGINE,
    XT_PUBLISHING,
} XtState;

/*
 * What the engine is doing while it owns the thread, and so which
 * recovery a host fault gets (xt_fault_redirect).
 */
typedef enum XtActive {
    XT_ACT_NONE,
    XT_ACT_EXEC,        /* in cpu_exec: its jmp_env is the recovery target */
    XT_ACT_ATOMIC,      /* in cpu_exec_step_atomic: likewise */
    XT_ACT_ADAPTER,     /* a guarded adapter access (xt_guest_read) */
    XT_ACT_FAULT,       /* the fault continuation is running */
} XtActive;

/* Event kinds of the per-thread ring. */
typedef enum XtEv {
    XT_EV_NONE,
    XT_EV_THREAD_INIT,      /* a = cpu index, b = TEB */
    XT_EV_ACTIVATE,         /* a = activation id */
    XT_EV_ACQUIRE,          /* a = eip, b = esp after the import */
    XT_EV_EXIT,             /* a = trapnr, b = eip */
    XT_EV_PUBLISH,          /* a = exit kind, b = eip */
    XT_EV_NOTIFY,           /* Wow64NotifyUnsimulateComplete returned */
    XT_EV_SYSCALL,          /* a = number, b = status */
    XT_EV_RAISE,            /* a = info[0] << 32 | code, b = info[1] << 32 | address */
    XT_EV_FAULT,            /* a = kind << 56 | host pc offset, b = addr */
    XT_EV_RESUME,           /* a = kind, b = addr: continuation entered */
    XT_EV_RETRY,            /* a = addr: flags refreshed, access retried */
    XT_EV_SMC,              /* a = page_unprotect result, b = addr */
    XT_EV_SUSPEND_SEEN,     /* a suspension request ended the run */
    XT_EV_ATOMIC,           /* cpu_exec_step_atomic, b = eip */
    XT_EV_INT81,
    XT_EV_CHECK,            /* a = failed invariants, b = where */
    XT_EV_INJECT,           /* a = injection point, b = suspended there */
    XT_EV_THREAD_TERM,
    XT_EV_PLACE,            /* a = what (string), b = address */
    XT_EV_MEMNOTE,          /* a = kind << 56 | prot << 32 | length, b = address */
    XT_EV_REFRESH,          /* a = old flags << 16 | new flags, b = address */
    XT_EV__MAX,
} XtEv;

typedef struct XtEvent {
    uint64_t seq;           /* process-wide order */
    uint64_t cnt;           /* CNTVCT_EL0 */
    uint16_t kind;
    uint8_t state;
    uint8_t active;
    uint32_t activation;
    uint64_t a, b;
} XtEvent;

#define XT_RING 1024

/* The fault being continued: filled by the handler, read by the continuation. */
typedef enum XtFaultKind {
    XT_FK_GEN = 1,      /* generated code: host pc + GETPC_ADJ */
    XT_FK_HELPER,       /* a helper: helper_retaddr */
    XT_FK_FETCH,        /* instruction fetch through cpu_ld*_code_mmu */
    XT_FK_TRANSLATE,    /* the translator reading guest code */
    XT_FK_ADAPTER,      /* xt_guest_read */
} XtFaultKind;

typedef struct XtFault {
    int busy;
    XtFaultKind kind;
    uint32_t code;          /* the native exception code */
    bool is_write;
    MMUAccessType access;
    vaddr addr;
    uintptr_t host_pc;      /* for cpu_restore_state, 0 for none */
    CONTEXT ctx;            /* the native context, for a retry */
} XtFault;

/* What a guest #PF carries to Wow64RaiseException besides CR2. */
typedef struct XtGuestFault {
    uint32_t code;          /* native code, or 0 for ACCESS_VIOLATION */
} XtGuestFault;

/* Why xt_run returned: the exits Windows has to see. */
typedef enum XtExitKind {
    XT_EXIT_SYSCALL,
    XT_EXIT_EXCEPTION,
    XT_EXIT_SUSPEND,
    XT_EXIT_STOP,           /* the harness asked to stop (int3 in tests) */
} XtExitKind;

typedef struct XtExit {
    XtExitKind kind;
    int trapnr;
    uint32_t nr;            /* system call number */
    uint32_t args;          /* guest address of the arguments */
    EXCEPTION_RECORD rec;
} XtExit;

typedef struct XtThread {
    CPUState *cpu;
    CPUX86State *env;
    DWORD tid;
    void *teb;
    bool wow64;             /* under wow64.dll: slot 2, the CPU area */
    bool stop_at_int3;      /* the native harness: int3 ends a run */
    XtState state;
    XtActive active;
    bool rcu_registered;
    uint32_t activation;
    int suspend_req;        /* set by another thread (cpu_exit after) */
    uint32_t suspensions;   /* suspension exits taken */
    bool after_suspend;     /* the last exit was a suspension */
    XtGuestFault gfault;
    XtFault fault;
    sigjmp_buf adapter_jmp;
    uint32_t violations;
    uint64_t counts[XT_EV__MAX];
    unsigned ring_pos;
    unsigned logged;        /* events written to the log so far */
    XtEvent ring[XT_RING];
} XtThread;

extern __thread XtThread *xt_self;
extern uintptr_t xt_bop;            /* the system-call stub (int 0x2e) */
extern uint32_t xt_inject_point;    /* XTAJIT_INJECT: see xt_inject */

/* engine.c */
extern CPUState *xt_spare_cpu;      /* made at init, for the first thread */
int xt_engine_init(const char *settings, int *applied, int *rejected);
CPUState *xt_cpu_new(void);
extern const char *xt_cpu_model;   /* -cpu syntax; set before init */
void *xt_alloc_low(size_t len);
bool xt_mem_refresh(vaddr addr, MMUAccessType access);
void xt_invalidate(vaddr start, vaddr len);

/* thread.c */
void *xt_alloc_high(size_t len);
bool xt_tls_ready(void);
void xt_tls_attach(void);
void xt_enter(void);
void xt_placement(const char *what, const void *p);
XtThread *xt_thread_new(bool wow64);
void xt_thread_free(XtThread *t);
void xt_event(XtThread *t, XtEv kind, uint64_t a, uint64_t b);
void xt_gevent(XtEv kind, uint64_t a, uint64_t b);
uint32_t xt_check(XtThread *t, XtState expect, int where);
void xt_import(XtThread *t, const WOW64_CONTEXT *c);
void xt_export(XtThread *t, WOW64_CONTEXT *c);
void xt_set_slot2(XtThread *t, bool running);
void xt_acquire(XtThread *t, const WOW64_CONTEXT *c);
void xt_publish(XtThread *t, WOW64_CONTEXT *c);
void xt_dump(XtThread *t, void *handle);
void xt_log_flush(XtThread *t);
void xt_log_open(void);
void *xt_log_handle(void);
bool xt_guest_read(XtThread *t, vaddr addr, void *buf, size_t len);

/* Points where XTAJIT_INJECT waits for a suspension request. */
enum {
    XT_INJ_ACQUIRE = 1,
    XT_INJ_EXECUTE,
    XT_INJ_TRANSLATE,
    XT_INJ_HELPER,
    XT_INJ_ATOMIC,
    XT_INJ_FLUSH,
    XT_INJ_PUBLISH,
    XT_INJ_CALLBACK,
};
void xt_inject(XtThread *t, int point);

/* exec.c */
void xt_run(XtThread *t, XtExit *x);

/* fault.c */
bool xt_fault_redirect(EXCEPTION_RECORD *er, CONTEXT *ctx);
uint32_t xt_fault_count(void);

/* Status codes winnt.h leaves to ntstatus.h. */
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif
#ifndef STATUS_ENTRYPOINT_NOT_FOUND
#define STATUS_ENTRYPOINT_NOT_FOUND ((NTSTATUS)0xC0000139)
#endif
#ifndef STATUS_ASSERTION_FAILURE
#define STATUS_ASSERTION_FAILURE ((NTSTATUS)0xC0000420)
#endif
#ifndef STATUS_STACK_BUFFER_OVERRUN
#define STATUS_STACK_BUFFER_OVERRUN ((NTSTATUS)0xC0000409)
#endif

typedef struct XtThreadBasicInfo {
    NTSTATUS ExitStatus;
    void *TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} XtThreadBasicInfo;

#define XTEXPORT __declspec(dllexport)

/* wow64.c: the module's interface to wow64.dll */
int xt_process_init(bool wow64);
int xt_settings_applied(int *rejected);
XTEXPORT NTSTATUS WINAPI BTCpuProcessInit(void);
XTEXPORT void WINAPI BTCpuProcessTerm(HANDLE h, BOOL after, ULONG status);
XTEXPORT NTSTATUS WINAPI BTCpuThreadInit(void);
XTEXPORT void WINAPI BTCpuThreadTerm(HANDLE thread, LONG code);
XTEXPORT void *WINAPI BTCpuGetBopCode(void);
XTEXPORT void WINAPI BTCpuSimulate(void);
XTEXPORT NTSTATUS WINAPI BTCpuSuspendLocalThread(HANDLE thread, void *info,
                                        void *unk1, ULONG unk2);
XTEXPORT NTSTATUS WINAPI BTCpuResetToConsistentState(EXCEPTION_POINTERS *p);
XTEXPORT void WINAPI BTCpuFlushInstructionCache2(const void *addr, SIZE_T len);
XTEXPORT void WINAPI BTCpuFlushInstructionCacheHeavy(const void *addr, SIZE_T len);
XTEXPORT void WINAPI BTCpuNotifyMemoryDirty(void *addr, SIZE_T len);
XTEXPORT void WINAPI BTCpuNotifyMemoryAlloc(void *addr, SIZE_T len, ULONG type,
                                   ULONG prot, BOOL after, ULONG status);
XTEXPORT void WINAPI BTCpuNotifyMemoryProtect(void *addr, SIZE_T len, ULONG prot,
                                     BOOL after, ULONG status);
XTEXPORT void WINAPI BTCpuNotifyMemoryFree(void *addr, SIZE_T len, ULONG type,
                                  BOOL after, ULONG status);
XTEXPORT NTSTATUS WINAPI BTCpuNotifyMapViewOfSection(void *unk1, void *addr,
                                            void *unk2, SIZE_T len,
                                            ULONG type, ULONG prot);
XTEXPORT void WINAPI BTCpuNotifyUnmapViewOfSection(void *addr, BOOL after,
                                          ULONG status);
XTEXPORT void WINAPI BTCpuNotifyReadFile(HANDLE h, void *addr, SIZE_T len, BOOL after,
                                NTSTATUS status);
XTEXPORT BOOLEAN WINAPI BTCpuIsProcessorFeaturePresent(UINT feature);
XTEXPORT void BTCpuUpdateProcessorInformation(void *info);

/* test.c: the native harness's entry points */
typedef struct XtTestExit XtTestExit;
typedef struct XtTestState XtTestState;
XTEXPORT int xt_test_init(int *rejected);
XTEXPORT void *xt_test_thread(void);
XTEXPORT int xt_test_run(WOW64_CONTEXT *ctx, XtTestExit *out);
XTEXPORT void xt_test_roundtrip(const WOW64_CONTEXT *in, WOW64_CONTEXT *out);
XTEXPORT void xt_test_invalidate(void *addr, size_t len);
XTEXPORT void xt_test_forget(void *addr, size_t len);
XTEXPORT int xt_test_page_flags(void *addr);
XTEXPORT void xt_test_state(XtTestState *s);
XTEXPORT void xt_test_dump(void *handle);
XTEXPORT int xt_test_suspend(DWORD tid);
XTEXPORT int xt_test_flush(DWORD tid);
XTEXPORT int xt_test_guest_read(uint32_t addr, void *buf, uint32_t len);
XTEXPORT uintptr_t xt_test_bop(void);

#endif
