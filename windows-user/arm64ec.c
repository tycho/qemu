/*
 * xtajit: the x64 CPU module's interface, as ntdll calls it in an x64
 * process on Windows on Arm, whose native code is ARM64EC.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/atomic.h"
#include "qemu/rcu.h"
#include "qemu/log.h"
#include "hw/core/cpu.h"
#include "cpu.h"
#include "tcg/tcg.h"
#include "tcg/tcg-cache.h"
#include "tcg/startup.h"
#include "tcg/host-fpenv.h"
#include "host/fpenv.h"
#include "accel/tcg/dispatch.h"
#include "exec/mmap-lock.h"
#include "accel/tcg/cpu-loop.h"
#include "accel/tcg/tb-context.h"
#include "exec/page-protection.h"
#include "user/page-protection.h"
#include "xtajit.h"
#include "arm64ec.h"
#include "run.h"
#include "qemu/timer.h"
#include "accel/tcg/internal-common.h"
#include "exec/tb-flush.h"
#include "accel/tcg/helper-retaddr.h"

/* The layouts arm64ec.S's offsets (F_*, C_*, TEB_CPU_AREA, AREA_*) assume. */
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, entry) != 0x04);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, nzcv) != 0x08);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, saved_to_env) != 0x0c);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, pc) != 0x10);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, lr) != 0x18);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, env) != 0x20);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, inj_armed) != 0x28);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, ctx) != 0x30);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, resume_sp) != 0x3c0);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, resume_go) != 0x3c8);
/* x-ecfast's resume in assembly (arm64ec.S's fast_resume) */
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, resume_kind) != 0x3d0);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, fr_key) != 0x3e0);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, fr_land) != 0x3e8);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, fr_rsp) != 0x3f0);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, fr_next) != 0x3f8);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, fr_slot) != 0x400);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, fr_t) != 0x408);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, fr_cs) != 0x410);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, fr_reader) != 0x418);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, fr_flush) != 0x420);
QEMU_BUILD_BUG_ON(XT_EC_KEPT_FAST != 1);
QEMU_BUILD_BUG_ON(XT_EC_FAST_START != 1 || XT_EC_FAST_CLEAR != 2);
QEMU_BUILD_BUG_ON(offsetof(XtThread, state) != 0x20);
QEMU_BUILD_BUG_ON(offsetof(XtThread, active) != 0x24);
QEMU_BUILD_BUG_ON(offsetof(XtThread, activation) != 0x28);
QEMU_BUILD_BUG_ON(offsetof(XtThread, suspend_req) != 0x2c);
QEMU_BUILD_BUG_ON(offsetof(XtThread, terminating) != 0x30);
QEMU_BUILD_BUG_ON(offsetof(XtThread, gfault.code) != 0x34);
QEMU_BUILD_BUG_ON(sizeof(((XtThread *)0)->gfault.code) != 4);
QEMU_BUILD_BUG_ON(offsetof(XtThread, after_suspend) != 0x3a);
QEMU_BUILD_BUG_ON(offsetof(XtThread, bp_skip) != 0x3b);
QEMU_BUILD_BUG_ON(offsetof(XtThread, ec_suspended) != 0x3d);
QEMU_BUILD_BUG_ON(offsetof(XtThread, bp_hit) != 0x40);
QEMU_BUILD_BUG_ON(sizeof(XtState) != 4 || sizeof(XtActive) != 4);
QEMU_BUILD_BUG_ON(XT_ACQUIRING != 1 || XT_ENGINE != 2 || XT_ACT_EXEC != 1);
QEMU_BUILD_BUG_ON(offsetof(CPUState, running) != 0xc4);
QEMU_BUILD_BUG_ON(offsetof(CPUState, exit_request) != 0xd7);
QEMU_BUILD_BUG_ON(offsetof(CPUState, cflags_next_tb) != 0xdc);
QEMU_BUILD_BUG_ON(offsetof(CPUState, interrupt_request) != 0xe0);
QEMU_BUILD_BUG_ON(offsetof(CPUState, exception_index) != 0x300);
QEMU_BUILD_BUG_ON(offsetof(CPUState, neg.icount_decr.u16.high) != 0x4342);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, eip) != 0x100);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, cc_src) != 0x118);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, cc_op) != 0x128);
QEMU_BUILD_BUG_ON(offsetof(X86CPU, eflags_in_tcg) -
                  offsetof(X86CPU, env) != 0x3c50);
QEMU_BUILD_BUG_ON(CC_OP_EFLAGS != 0);
QEMU_BUILD_BUG_ON(CC_C != 0x1 || CC_Z != 0x40 || CC_S != 0x80 ||
                  CC_O != 0x800);
QEMU_BUILD_BUG_ON(offsetof(struct rcu_reader_data, ctr) != 0);
QEMU_BUILD_BUG_ON(sizeof(((struct rcu_reader_data *)0)->ctr) != 4);
QEMU_BUILD_BUG_ON(sizeof(rcu_gp_ctr) != 4);
QEMU_BUILD_BUG_ON(offsetof(struct rcu_reader_data, depth) != 8);
QEMU_BUILD_BUG_ON(offsetof(TBContext, tb_flush_count) != 0x28);
QEMU_BUILD_BUG_ON(HOST_FP_CONTROL_QEMU != 6);
/* ... and its departure (xt_ec_fast_depart) */
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, dep_fpsr) != 0x3d8);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, fr_lo) != 0x428);
QEMU_BUILD_BUG_ON(offsetof(XtEcFrame, fr_hi) != 0x430);
QEMU_BUILD_BUG_ON(offsetof(XtCpuArea, EmulatorData[0]) != 0x30);
QEMU_BUILD_BUG_ON(offsetof(XtThread, cpu) != 0);
QEMU_BUILD_BUG_ON(offsetof(XtThread, rcu_reader) != 0x10);
QEMU_BUILD_BUG_ON(offsetof(XtThread, ec_seen) != 0x3c);
QEMU_BUILD_BUG_ON(offsetof(XtThread, native_target) != 0x48);
QEMU_BUILD_BUG_ON(offsetof(XtThread, fault.busy) != 0xb0);
QEMU_BUILD_BUG_ON(sizeof(((XtThread *)0)->fault.busy) != 4);
QEMU_BUILD_BUG_ON(offsetof(XtThread, co_rsp) != 0x6d0);
QEMU_BUILD_BUG_ON(offsetof(XtThread, co_flush) != 0x6d8);
QEMU_BUILD_BUG_ON(XT_WINDOWS != 0 || XT_ACT_NONE != 0);
QEMU_BUILD_BUG_ON(offsetof(CPUState, host_fp_guest) != 0x208);
QEMU_BUILD_BUG_ON(offsetof(CPUState, host_fp_suspended) != 0x209);
QEMU_BUILD_BUG_ON(sizeof(((CPUState *)0)->host_fp_guest) != 1 ||
                  sizeof(((CPUState *)0)->host_fp_suspended) != 1);
QEMU_BUILD_BUG_ON(offsetof(CPUState, neg.can_do_io) != 0x4344);
QEMU_BUILD_BUG_ON(sizeof(((CPUState *)0)->neg.can_do_io) != 1);
QEMU_BUILD_BUG_ON(offsetof(CPUState, singlestep_flags) != 0xe4);
QEMU_BUILD_BUG_ON(SSTEP_ENABLE != 1);
QEMU_BUILD_BUG_ON(offsetof(CPUState, breakpoints) != 0x280);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, mxcsr) != 0x3c0);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, dr[6]) != 0x34d8);
QEMU_BUILD_BUG_ON(sizeof(((CPUX86State *)0)->dr[6]) != 8);
QEMU_BUILD_BUG_ON((DR6_BS | 0xf) != 0x400f);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, retsp) != 0x3c38);
QEMU_BUILD_BUG_ON(offsetof(struct rcu_reader_data, waiting) != 4);
QEMU_BUILD_BUG_ON(sizeof(((struct rcu_reader_data *)0)->waiting) != 1);
QEMU_BUILD_BUG_ON(HOST_FPSR_FLAGS != 0x9f);
QEMU_BUILD_BUG_ON(XT_EC_TAIL_RCU != 1 || XT_EC_TAIL_EXCL != 2);
QEMU_BUILD_BUG_ON(offsetof(XtThread, teb) != 0x18);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, segs) != 0x138);
QEMU_BUILD_BUG_ON(sizeof(SegmentCache) != 0x18);
QEMU_BUILD_BUG_ON(offsetof(SegmentCache, selector) != 0 ||
                  offsetof(SegmentCache, base) != 8);
QEMU_BUILD_BUG_ON(R_ES != 0 || R_CS != 1 || R_SS != 2 || R_DS != 3 ||
                  R_FS != 4 || R_GS != 5);
QEMU_BUILD_BUG_ON(offsetof(XtStubInject, ticks) != 0x08);
QEMU_BUILD_BUG_ON(offsetof(XtStubInject, hits) != 0x10);
QEMU_BUILD_BUG_ON(offsetof(XtStubInject, rung) != 0x50);
QEMU_BUILD_BUG_ON(sizeof(XtEcFrame) > 0x1000);
QEMU_BUILD_BUG_ON(XT_EC_ENTRY_CALL != 1 || XT_EC_ENTRY_RETURN != 2);
QEMU_BUILD_BUG_ON(offsetof(ARM64_NT_CONTEXT, Cpsr) != 0x04);
QEMU_BUILD_BUG_ON(offsetof(ARM64_NT_CONTEXT, X) != 0x08);
QEMU_BUILD_BUG_ON(offsetof(ARM64_NT_CONTEXT, Sp) != 0x100);
QEMU_BUILD_BUG_ON(offsetof(ARM64_NT_CONTEXT, Pc) != 0x108);
QEMU_BUILD_BUG_ON(offsetof(ARM64_NT_CONTEXT, V) != 0x110);
QEMU_BUILD_BUG_ON(sizeof(((ARM64_NT_CONTEXT *)0)->V[0]) != 16);
QEMU_BUILD_BUG_ON(XT_TEB_CPU_AREA != 0x1788);
QEMU_BUILD_BUG_ON(offsetof(XtCpuArea, EmulatorStackBase) != 0x08);
QEMU_BUILD_BUG_ON(offsetof(XtCpuArea, SuspendDoorbell) != 0x20);
QEMU_BUILD_BUG_ON(offsetof(XtCpuArea, EmulatorData[1]) != 0x38);
/* And the CPU state's (E_*: the entries' stores, the native exit's loads). */
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, regs) != 0);
QEMU_BUILD_BUG_ON(sizeof(((CPUX86State *)0)->regs[0]) != 8);
QEMU_BUILD_BUG_ON(R_EAX != 0 || R_ECX != 1 || R_EDX != 2 || R_EBX != 3 ||
                  R_ESP != 4 || R_EBP != 5 || R_ESI != 6 || R_EDI != 7);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, fpstt) != 0x2e0);
QEMU_BUILD_BUG_ON(sizeof(((CPUX86State *)0)->fpstt) != 4);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, fpregs) != 0x2f0);
QEMU_BUILD_BUG_ON(sizeof(FPReg) != 16 || offsetof(floatx80, low) != 0);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, xmm_regs) != 0x3d0);
QEMU_BUILD_BUG_ON(sizeof(ZMMReg) != 64);

NTSTATUS NTAPI NtContinue(PCONTEXT, BOOLEAN);
PVOID NTAPI RtlImageDirectoryEntryToData(PVOID, BOOLEAN, USHORT, PULONG);
NTSTATUS NTAPI RtlQueryEnvironmentVariable(PVOID, PCWSTR, SIZE_T, PWSTR,
                                           SIZE_T, PSIZE_T);

extern IMAGE_DOS_HEADER __ImageBase;

#ifndef XT_SCAFFOLD
/* The fork's defaults for the module; XTAJIT_SETTINGS overrides them. */
#define XT_SCAFFOLD "smc=check,retalign=on,cache=files,ecinline=on,partrans=on,ecfast=on"
#endif

/*
 * System calls the module makes directly, with svc: ntdll's exports in an
 * ARM64EC process take x64 contexts (NtContinue, NtRaiseException), whose
 * conversion loses the registers the ARM64EC ABI forbids, and they may be
 * hot-patched x64 code.  The numbers vary between Windows builds and are
 * found at process init (find_syscall_nr).  arm64ec.S: a table of 512
 * "svc #n; ret".
 */
#define XT_SVC_TABLE_ENTRIES 512
NTSTATUS xt_syscall(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                    uint64_t a4, uint64_t a5, uint64_t nr);

static int64_t nr_flush_buffers = -1;
static int64_t nr_continue = -1, nr_raise = -1, nr_alloc = -1,
               nr_protect = -1;

/* ntdll's native KiUserExceptionDispatcher, for the guest's system calls. */
static uintptr_t ki_exception_dispatcher;

/*
 * Work other processes queued for this one's emulator (a flush of code
 * they wrote, a protection change): ntdll delivers it through the
 * notification exports when asked, which takes a lock of its own.  Asked
 * where what it reports matters to the engine: before a translation
 * (ec_foreign_pc), at a system call and at a continuation (xt_ec_begin);
 * not at every call to or return from native code.
 */
static void (*cross_process_work)(void);

/* An x64 ret instruction, for native callees on an unaligned stack. */
uintptr_t xt_x64_ret;

/* For the call checker (arm64ec.S): ntdll's x64 entries to native code. */
uintptr_t xt_ntdll_base;
uint32_t *xt_ntdll_lut;
uint32_t xt_ntdll_lut_size;

static const XtEcMetadata *ec_metadata(uintptr_t base)
{
    ULONG size;
    IMAGE_LOAD_CONFIG_DIRECTORY64 *lc =
        RtlImageDirectoryEntryToData((void *)base, TRUE,
                                     IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &size);

    if (!lc || size < offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64,
                               CHPEMetadataPointer) + 8 ||
        !lc->CHPEMetadataPointer) {
        return NULL;
    }
    return (const XtEcMetadata *)(uintptr_t)lc->CHPEMetadataPointer;
}

/* The native code behind one of ntdll's x64 exports, else 0. */
static uintptr_t ntdll_native(const XtEcMetadata *md, const char *name)
{
    const XtEcRedirection *r =
        (const XtEcRedirection *)(xt_ntdll_base + md->RedirectionMetadata);
    uintptr_t ffs = (uintptr_t)GetProcAddress((HMODULE)xt_ntdll_base, name);

    if (!ffs) {
        return 0;
    }
    for (ULONG i = 0; i < md->RedirectionMetadataCount; i++) {
        if (r[i].Source == ffs - xt_ntdll_base) {
            return xt_ntdll_base + r[i].Destination;
        }
    }
    return 0;
}

/*
 * A system call's number: the index of its native code in ntdll's
 * __arm64ec_syscall_ffs table (as FEX's ARM64EC module finds it), if
 * within the svc table.
 */
static int64_t find_syscall_nr(const XtEcMetadata *md, const char *name)
{
    const uintptr_t *ffs = (const uintptr_t *)GetProcAddress(
        (HMODULE)xt_ntdll_base, "__arm64ec_syscall_ffs");
    const uint32_t *count = (const uint32_t *)GetProcAddress(
        (HMODULE)xt_ntdll_base, "__arm64ec_syscall_ffs_size");
    uintptr_t native = ntdll_native(md, name);

    if (!ffs || !count || !native) {
        return -1;
    }
    for (uint32_t i = 0; i < *count && i < XT_SVC_TABLE_ENTRIES; i++) {
        if (ffs[i] == native) {
            return i;
        }
    }
    return -1;
}

NTSTATUS xt_continue_native(XtNativeContext *ctx)
{
    return xt_syscall((uintptr_t)ctx, FALSE, 0, 0, 0, 0, nr_continue);
}

NTSTATUS xt_ec_alloc_direct(void **base, SIZE_T *size, ULONG type,
                            ULONG prot)
{
    return xt_syscall((uintptr_t)GetCurrentProcess(), (uintptr_t)base, 0,
                      (uintptr_t)size, type, prot, nr_alloc);
}

/*
 * Every processor running a thread of the process made to see this one's
 * writes, and to have its own seen (FlushProcessWriteBuffers): the
 * process's end's half of the barrier pair whose other half, a thread's
 * entry, costs it nothing (arm64ec-gate.c).
 */
static NTSTATUS ec_flush_write_buffers(void)
{
    if (nr_flush_buffers < 0) {
        return STATUS_NOT_SUPPORTED;
    }
    return xt_syscall(0, 0, 0, 0, 0, 0, nr_flush_buffers);
}

/* Whether ProcessInit has found the system calls the module makes itself. */
bool xt_syscalls_ready(void)
{
    return nr_alloc >= 0;
}

/*
 * Memory through the system call itself, no code of ntdll's on the way:
 * nothing reaches the module's callbacks (emutls.c's cold path).
 */
void *xt_alloc_direct(size_t len)
{
    void *p = NULL;
    SIZE_T size = len;

    if (xt_ec_alloc_direct(&p, &size, MEM_RESERVE | MEM_COMMIT,
                           PAGE_READWRITE) < 0) {
        return NULL;
    }
    return p;
}

static NTSTATUS protect_direct(void **base, SIZE_T *size, ULONG prot,
                               ULONG *old)
{
    return xt_syscall((uintptr_t)GetCurrentProcess(), (uintptr_t)base,
                      (uintptr_t)size, prot, (uintptr_t)old, 0, nr_protect);
}

/* Write a pointer into this module's ARM64EC metadata (its checker slots). */
static void write_module_slot(ULONG rva, void *value)
{
    void *addr = (char *)&__ImageBase + rva, *p = addr;
    SIZE_T size = sizeof(void *);
    ULONG old;

    if (!rva) {
        return;
    }
    protect_direct(&p, &size, PAGE_READWRITE, &old);
    *(void **)addr = value;
    protect_direct(&p, &size, old, &old);
}

/*
 * The module's own calls go through the ARM64EC call checker, which
 * enters the x64 emulator for x64 code: a hot-patched ntdll export would
 * re-enter this module.  The replacement (xt_check_call) maps ntdll's x64
 * entries to their native code, through a table from ntdll's redirection
 * metadata, and calls anything else as it is.  First of all at process
 * init, before the runtime.
 */
static bool init_syscalls(void)
{
    const XtEcMetadata *md, *own;
    const XtEcRedirection *r;
    SIZE_T size;

    if (xt_ntdll_lut) {
        return true;
    }
    xt_ntdll_base = (uintptr_t)GetModuleHandleW(L"ntdll.dll");
    md = xt_ntdll_base ? ec_metadata(xt_ntdll_base) : NULL;
    own = ec_metadata((uintptr_t)&__ImageBase);
    if (!md || !own || !md->RedirectionMetadataCount) {
        return false;
    }
    nr_continue = find_syscall_nr(md, "NtContinue");
    nr_raise = find_syscall_nr(md, "NtRaiseException");
    nr_alloc = find_syscall_nr(md, "NtAllocateVirtualMemory");
    nr_protect = find_syscall_nr(md, "NtProtectVirtualMemory");
    nr_flush_buffers = find_syscall_nr(md, "NtFlushProcessWriteBuffers");
    ki_exception_dispatcher = ntdll_native(md, "KiUserExceptionDispatcher");
    cross_process_work = (void (*)(void))
        ntdll_native(md, "ProcessPendingCrossProcessEmulatorWork");
    if (nr_continue < 0 || nr_raise < 0 || nr_alloc < 0 || nr_protect < 0 ||
        !ki_exception_dispatcher) {
        return false;
    }

    r = (const XtEcRedirection *)(xt_ntdll_base + md->RedirectionMetadata);
    for (ULONG i = 0; i < md->RedirectionMetadataCount; i++) {
        xt_ntdll_lut_size = MAX(xt_ntdll_lut_size, r[i].Source + 1);
    }
    size = xt_ntdll_lut_size * sizeof(uint32_t);
    if (xt_ec_alloc_direct((void **)&xt_ntdll_lut, &size,
                           MEM_COMMIT | MEM_RESERVE,
                           PAGE_READWRITE) < 0) {
        return false;
    }
    for (ULONG i = 0; i < md->RedirectionMetadataCount; i++) {
        xt_ntdll_lut[r[i].Source] = r[i].Destination;
    }
    write_module_slot(own->os_arm64x_dispatch_call, xt_check_call);
    write_module_slot(own->os_arm64x_dispatch_icall, xt_check_call);
    write_module_slot(own->os_arm64x_dispatch_icall_cfg, xt_check_call);
    return true;
}

/* Settings: the scaffold, then XTAJIT_SETTINGS, which may override it. */
static char *settings_string(void)
{
    WCHAR w[1024];
    SIZE_T n = 0;
    GString *s = g_string_new(XT_SCAFFOLD);

    if (RtlQueryEnvironmentVariable(NULL, L"XTAJIT_SETTINGS", 15, w,
                                    ARRAY_SIZE(w) - 1, &n) >= 0 && n) {
        g_string_append_c(s, ',');
        for (SIZE_T i = 0; i < n; i++) {
            g_string_append_c(s, (char)w[i]);
        }
    }
    return g_string_free(s, false);
}

static int init_applied, init_rejected;

static void ec_register(XtThread *t);
static unsigned __stdcall doorbell_watcher(void *arg);

/*
 * The engine's process-wide bring-up.  It needs the module's thread-local
 * variables (QEMU's, the allocator's), which in an x64 process the loader
 * sets up for this module after ProcessInit and the first thread's
 * ThreadInit: so it runs at a thread's first entry (enter_engine), or in
 * the harness's own init.
 */
/*
 * tcg_foreign_pc: native code is EC code (the PEB's bitmap); a lookup
 * skips it, and the exit to it is XT_EXCP_NATIVE, without the fetch fault
 * a translation of it would take (cpu_loop_exit_sigsegv).  The exit's
 * call follows a tb_lookup of the same PC that found no TB, whose own
 * call has just classified it: that answer is kept for it.  Guest code
 * that found no TB is translated next, so work other processes queued
 * (cross_process_work) is asked for first.
 */
static bool ec_foreign_pc(CPUState *cs, vaddr pc, bool exit)
{
    XtThread *t = cs->opaque;

    if (!exit) {
        t->ec_seen = xt_is_ec_code(pc);
        t->ec_seen_pc = pc;
        return t->ec_seen;
    }
    if (!(t->ec_seen && t->ec_seen_pc == pc) && !xt_is_ec_code(pc)) {
        if (cross_process_work) {
            cross_process_work();
        }
        return false;
    }
    t->ec_seen = false;
    t->native_target = pc;
    cs->exception_index = XT_EXCP_NATIVE;
    return true;
}

static bool ec_foreign_code(vaddr pc)
{
    return xt_is_ec_code(pc);
}

/*
 * tcg_foreign_goto (x-ecinline): an indirect exit to native code leaves
 * through the call-out (ec_callout), unless it returns to a native caller
 * (a return address past a "blr x16", the call through the dispatch or an
 * exit thunk), which never comes back to the TB's frame.  The word before
 * the target is read guarded (tcg_cache_gcopy): EC code needn't be
 * readable, and a fault here would be the engine's.  Unread, it is taken
 * for a call.  The answer for the thread's last target is kept: it only
 * chooses between two correct exits (a call-out whose frame the next
 * entry discards, or the exit through the epilogue).
 */
static const void *ec_foreign_goto(CPUState *cs)
{
    XtThread *t = cs->opaque;
    uint64_t pc = t->native_target;
    uint32_t insn;

    if (!tcg_ecinline || !tcg_ec_callout_entry) {
        return NULL;
    }
    if (pc != t->fg_pc) {
        t->fg_pc = pc;
        t->fg_ret = tcg_cache_gcopy(&insn, (const void *)(uintptr_t)(pc - 4),
                                    4) == 0 &&
                    insn == 0xd63f0200;
    }
    return t->fg_ret ? NULL : tcg_ec_callout_entry;
}

/*
 * RCU readers for a thread's life (the x64 module, whose thread-local
 * storage is its own, runtime/emutls.c): a thread registers once, at its
 * first need (xt_rcu_ensure), and stays registered while Windows owns it,
 * where it is never inside a read section, so it holds up no grace period.
 * A thread never unregisters itself: it may be terminated anywhere, and
 * one terminated holding the registry's lock would stop every grace
 * period.  The retirer, a thread of the module's, unregisters each reader
 * once its thread has ended, while its TLS root keeps the reader's
 * storage; the root goes after (xt_emutls_reap).
 *
 * Registration is ordered so that a thread terminated at any point leaves
 * a state the retirer completes: the root is marked first (the sweep keeps
 * it), then the retirer's node is listed, then the reader is named, then
 * registered.  A mark with no reader named has nothing to unregister, and
 * rcu_unregister_reader takes a reader that never reached the registry.
 * Only a termination inside rcu_register_thread, holding the registry's
 * lock, isn't recovered; a root marked but not listed is kept for good.
 */
typedef struct XtReaderNode {
    void *root;
    struct XtReaderNode *next;
} XtReaderNode;

static XtReaderNode *readers;

static void readers_push(XtReaderNode *n)
{
    XtReaderNode *head;

    do {
        head = qatomic_read(&readers);
        n->next = head;
    } while (qatomic_cmpxchg(&readers, head, n) != head);
}

/*
 * Testing (the setting keyword rcuinj=N): every 7th registration made
 * outside an activation, where Windows may end the thread at any point (a
 * reaper's free_record), ends its thread right after step N (1 marked, 2
 * listed, 3 named, 4 registered).  An activation's own registration is
 * protected: a termination waits for it (xt_park_if_terminating).
 */
static void rcu_inj(int step)
{
    static int count;
    XtThread *t = xt_self;

    if (xt_rcu_inj_step == step && (!t || t->state == XT_WINDOWS) &&
        qatomic_fetch_inc(&count) % 7 == 6) {
        /* The current thread's pseudo-handle, -2. */
        NtTerminateThread((HANDLE)~(uintptr_t)1, 0);
    }
}

void xt_rcu_ensure(void)
{
    XtReaderNode *n;

    if (xt_emutls_reader_get()) {
        return;
    }
    n = g_new0(XtReaderNode, 1);
    n->root = xt_emutls_reader_intent();
    rcu_inj(1);
    readers_push(n);
    rcu_inj(2);
    xt_emutls_reader_set(get_ptr_rcu_reader());
    rcu_inj(3);
    rcu_register_thread();
    rcu_inj(4);
}

static unsigned __stdcall reader_retirer(void *arg)
{
    LARGE_INTEGER tick = { .QuadPart = -20 * 10000 };   /* 20 ms */

    for (;;) {
        XtReaderNode *n, *keep = NULL;

        /* The process's end: here it holds nothing. */
        if (xt_internal_stopping()) {
            xt_internal_park();
        }
        n = qatomic_xchg(&readers, NULL);

        while (n) {
            XtReaderNode *next = n->next;
            void *reader = xt_emutls_reader_ended(n->root);

            if (reader) {
                if (reader != XT_EMUTLS_READER_INTENT) {
                    rcu_unregister_reader(reader);
                }
                xt_emutls_reader_retired(n->root);
                g_free(n);
            } else {
                n->next = keep;
                keep = n;
            }
            n = next;
        }
        while (keep) {
            XtReaderNode *next = keep->next;

            readers_push(keep);
            keep = next;
        }
        NtDelayExecution(TRUE, &tick);
    }
    return 0;
}

/*
 * Testing (the setting keyword rcustress): grace periods back to back on a
 * thread of the module's, while threads register and their readers are
 * retired.  A watchdog ends the process if none completes for 5 s, and
 * the process's end reports how many did (ProcessTerm).
 */
static uint64_t rcu_stress_done;

static unsigned __stdcall rcu_stress(void *arg)
{
    LARGE_INTEGER ms = { .QuadPart = -10000 };

    for (;;) {
        if (xt_internal_stopping()) {
            xt_internal_park();
        }
        synchronize_rcu();
        qatomic_inc(&rcu_stress_done);
        NtDelayExecution(TRUE, &ms);
    }
    return 0;
}

/*
 * The watchdog sleeps in slices, so that the process's end, which may wait
 * longer than 5 s for a thread to stop, disarms it first.
 */
static unsigned __stdcall rcu_stress_watchdog(void *arg)
{
    LARGE_INTEGER slice = { .QuadPart = -10 * 10000 };      /* 10 ms */
    uint64_t seen = 0;

    for (;;) {
        for (int i = 0; i < 500; i++) {
            if (xt_internal_stopping()) {
                xt_internal_park();
            }
            NtDelayExecution(TRUE, &slice);
        }
        if (qatomic_read(&rcu_stress_done) == seen) {
            fputs("rcustress: no grace period completed in 5 s\n", stderr);
            xt_log_text("rcustress: no grace period completed in 5 s\n");
            NtTerminateProcess(GetCurrentProcess(), STATUS_ASSERTION_FAILURE);
        }
        seen = qatomic_read(&rcu_stress_done);
    }
    return 0;
}

static TCGEcCallout ec_callout(uintptr_t sp, void *envp);
static bool ec_fast_asm_ok(void);

/*
 * x-ecfast's departure and resume in assembly can run (ec_fast_asm_ok,
 * at init; arm64ec.S reads it).
 */
bool xt_ec_fast_asm;
/* Their rare ways through C, for exitreport: XT_EC_TAIL_*, XT_EC_FAST_* */
static unsigned ec_fast_tails[4], ec_fast_slows[3];

static int process_init(void)
{
    char *settings;

    xt_tls_attach();
    xt_crt_process_init();
    settings = settings_string();
    xt_log_open();
    tcg_ec_callout_fn = ec_callout;
    tcg_ec_callout_fast_fn = xt_ec_fast_depart;
    /* The stubs' test points (ProcessInit's xt_ec_stub_inject_init). */
    tcg_ec_leave_fn = xt_stub_inject.point ?
                      (const void *)xt_ec_exit_native_env_inj :
                      (const void *)xt_ec_exit_native_env;
    xt_engine_init(settings, &init_applied, &init_rejected);
    xt_ec_fast_asm = ec_fast_asm_ok();
    tcg_foreign_pc = ec_foreign_pc;
    tcg_foreign_goto = ec_foreign_goto;
    tcg_foreign_code = ec_foreign_code;
    /* A thread's reader is registered at its first need (xt_rcu_ensure). */
    rcu_unregister_thread();
    xt_gevent(XT_EV_THREAD_INIT, init_applied, init_rejected);
    xt_placement("module", &__ImageBase);
    xt_placement("code buffer", tcg_ctx->code_gen_buffer);
    if (!_beginthreadex(NULL, 0, doorbell_watcher, NULL, 0, NULL) ||
        !_beginthreadex(NULL, 0, reader_retirer, NULL, 0, NULL) ||
        (xt_rcu_stress &&
         (!_beginthreadex(NULL, 0, rcu_stress, NULL, 0, NULL) ||
          !_beginthreadex(NULL, 0, rcu_stress_watchdog, NULL, 0, NULL)))) {
        return -1;
    }
    return 0;
}

/*
 * 0 none, 1 starting, 2 ready; -1 failed, -2 the bring-up's thread ended
 * before it was done (ec_engine_up).
 */
static int engine_state;
static void ec_tp_publish(void);

/*
 * The bring-up's thread, by a handle that can be waited on: the first
 * entrant to swap its own in from NULL brings the engine up, alone.
 */
static HANDLE engine_starter;

/*
 * The engine brought up, once per process, at a thread's first entry
 * (when the loader has set up the module's TLS): 2, or the failed state.
 * A thread that finds none yet offers to bring it up, by publishing its
 * own handle; every other first entry waits for the one that did.  A
 * waiter that finds the bring-up's thread ended (it is killed, or ends
 * itself, with no notification of the module's) fails the bring-up,
 * which can't be finished from another thread: a waiter never waits
 * forever.  A thread that can't make a handle waits for another's, if
 * there is one.
 */
static int ec_engine_up(void)
{
    LARGE_INTEGER zero = { .QuadPart = 0 };
    HANDLE me = NULL;
    int s, unwatched = 0;

    if (!qatomic_load_acquire(&engine_starter)) {
        if (!XT_TP_FAIL(XT_TPF_DUP_STARTER) &&
            NtDuplicateObject(GetCurrentProcess(), GetCurrentThread(),
                              GetCurrentProcess(), &me, SYNCHRONIZE, 0,
                              0) >= 0 &&
            qatomic_cmpxchg(&engine_starter, NULL, me) == NULL) {
            XT_TP(XT_TP_ENGINE_ELECTED, xt_gate_self(), 0);
            qatomic_store_release(&engine_state, 1);
            XT_TP(XT_TP_ENGINE_STARTING, xt_gate_self(), 1);
            s = process_init() < 0 ? -1 : 2;
            qatomic_store_release(&engine_state, s);
            return s;
        }
        if (me) {
            NtClose(me);
        }
    }
    while ((s = qatomic_load_acquire(&engine_state)) == 0 || s == 1) {
        HANDLE h = qatomic_load_acquire(&engine_starter);

        XT_TP(XT_TP_ENGINE_WAIT, NULL, s);
        if (!h) {
            /*
             * No starter yet, and this thread can't be one: another's may
             * be on its way (a moment), else nothing will bring it up.
             */
            if (++unwatched > 1000) {
                return -1;
            }
            NtYieldExecution();
            continue;
        }
        if (NtWaitForSingleObject(h, FALSE, &zero) == STATUS_SUCCESS) {
            /* The bring-up's thread is gone; a failed swap reads again. */
            qatomic_cmpxchg(&engine_state, s, -2);
            continue;
        }
        NtYieldExecution();
    }
    return s;
}

/*
 * The engine, once per process (ec_engine_up), and the calling thread's
 * record, once per thread.  The record is found through the CPU area,
 * without the module's TLS: EmulatorData[0] is the thread's record from
 * here until its own end takes it, or, once another thread has ended it,
 * the reaper.  NULL if the engine couldn't be brought up.
 */
static XtThread *enter_engine(void)
{
    XtCpuArea *area = xt_cpu_area(NtCurrentTeb());
    XtThread *t;

    if (qatomic_load_acquire(&engine_state) != 2 && ec_engine_up() != 2) {
        return NULL;
    }
    t = area->EmulatorData[0];
    if (!t) {
        t = xt_thread_new(false);
        t->cpu->opaque = t;
        t->ec_doorbell = area->SuspendDoorbell;
        area->EmulatorData[0] = t;
        /* For the reaper, once the thread has ended (ec_reap_gates). */
        qatomic_store_release(&xt_gate_self()->rec, t);
        ec_register(t);
        /* From here the entries store the registers into the CPU state. */
        qatomic_set(&((XtEcFrame *)area->EmulatorData[1])->env, t->env);
        /* x-ecfast's departure in assembly: until a C departure, none. */
        ((XtEcFrame *)area->EmulatorData[1])->fr_lo = NULL;
        ((XtEcFrame *)area->EmulatorData[1])->fr_hi = NULL;
    }
    return t;
}

/*
 * ntdll's calls.  ProcessInit and ThreadInit do what needs no thread-local
 * variables (enter_engine does the rest, at a thread's first entry).
 * The entries are in arm64ec.S (DispatchJump, RetToEntryThunk, ExitToX64,
 * BeginSimulation), and xt_ec_enter and xt_ec_begin below; REACHED
 * records which of ProcessInit and ThreadInit ran, for the harness.
 */
static uint32_t reached;

static NTSTATUS ec_process_init(void)
{
    reached |= 0x40;
    if (!init_syscalls()) {
        return STATUS_NOT_SUPPORTED;
    }
    xt_tp_process_init();
    if (!xt_gate_init_process() || !xt_gate_register_initial()) {
        return STATUS_NO_MEMORY;
    }
    ec_tp_publish();
    xt_emutls_init();
{
        void *p = NULL;
        SIZE_T size = 0x1000;
        ULONG old;

        if (xt_ec_alloc_direct(&p, &size, MEM_RESERVE | MEM_COMMIT,
                         PAGE_READWRITE) < 0) {
            return STATUS_NO_MEMORY;
        }
        *(uint8_t *)p = 0xc3;
        protect_direct(&p, &size, PAGE_EXECUTE_READ, &old);
        xt_x64_ret = (uintptr_t)p;
    }
    reached |= 0x80;
    xt_ec_probe_process_init();
    xt_ec_stub_inject_init();
    return STATUS_SUCCESS;
}

#define XT_EMULATOR_STACK (256 * 1024)
#define XT_EC_THREAD_PAGE 0x1000

/*
 * A thread's emulator stack, above a page of its own (XtEcFrame): the
 * doorbell word Windows sets to ask a simulating thread to stop
 * (SuspendDoorbell), and the native registers of an entry or exit.
 */
static NTSTATUS ec_thread_init(void)
{
    XtCpuArea *area = xt_cpu_area(NtCurrentTeb());
    PVOID mem = NULL;
    SIZE_T size = XT_EC_THREAD_PAGE + XT_EMULATOR_STACK;
    uintptr_t stack;

    reached |= 0x100;
    if (!area) {
        return STATUS_NO_MEMORY;
    }
    if (xt_ec_alloc_direct(&mem, &size, MEM_RESERVE | MEM_COMMIT,
                           PAGE_READWRITE) < 0) {
        return STATUS_NO_MEMORY;
    }
    stack = (uintptr_t)mem + XT_EC_THREAD_PAGE;
    area->SuspendDoorbell = &((XtEcFrame *)mem)->doorbell;
    area->EmulatorStackLimit = stack;
    area->EmulatorStackBase = stack + XT_EMULATOR_STACK;
    area->EmulatorData[0] = NULL;
    area->EmulatorData[1] = mem;
    qatomic_store_release(&xt_gate_self()->frame, mem);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtSuspendThread(HANDLE, PULONG);
NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);
NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE,
                                 ACCESS_MASK, ULONG, ULONG);

static void ec_unregister(XtThread *t);

/*
 * How long a thread still inside the module is waited for, let go to
 * finish, before its stop fails (ec_term_other, ec_freeze).
 */
#define EC_STOP_ACTIVE_MS 200

NTSTATUS NTAPI NtGetNextThread(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG,
                               PHANDLE);
NTSTATUS NTAPI NtCompareObjects(HANDLE, HANDLE);

/*
 * Whether the thread behind H is already ending: Windows then neither
 * suspends it nor gives its context, and its CPU area is gone.  It holds
 * nothing of the engine's, as long as whatever ended it stopped it first
 * (ThreadTerm), or it ended itself; a termination that didn't is counted
 * there (ec_unsafe_term).
 */
static bool ec_thread_ending(HANDLE h)
{
    ULONG ended = 0;

    return NtQueryInformationThread(h, 20 /* ThreadIsTerminated */, &ended,
                                    sizeof(ended), NULL) >= 0 && ended;
}

/*
 * Whether the thread behind H (which must allow SYNCHRONIZE) has ended, by
 * its handle's signal, within TIMEOUT_MS: "ending" is set before its
 * termination runs, and only the signal says its code has stopped.
 */
static bool ec_thread_dead(HANDLE h, uint32_t timeout_ms)
{
    LARGE_INTEGER t = { .QuadPart = -(int64_t)timeout_ms * 10000 };

    return NtWaitForSingleObject(h, FALSE, &t) == STATUS_SUCCESS;
}

/*
 * Terminations Windows went ahead with although the thread wasn't stopped
 * outside the engine (the stop failed, or the thread couldn't be found):
 * such a thread may have died holding anything, so the process's end
 * counts them (ProcessTerm).  Counted before ThreadTerm returns, so before
 * Windows can act; a termination Windows then refuses is counted all the
 * same.
 */
static uint32_t ec_unsafe_terms;

static void ec_unsafe_term(DWORD tid, NTSTATUS st)
{
    qatomic_inc(&ec_unsafe_terms);
    XT_TP_NOTE(XT_TPN_UNSAFE, tid, (uint32_t)st, 0);
    xt_gevent(XT_EV_THREAD_TERM, tid, 4 | (uint64_t)(uint32_t)st << 32);
}

/*
 * THREAD, if it is another thread of this process, opened with what a
 * stop needs; else NULL.  Found by its id where THREAD can be queried,
 * else as the same object among the process's threads (TerminateThread
 * needs THREAD_TERMINATE alone).  *FOUND_NOT says whether NULL means
 * "not one of ours" rather than "couldn't tell".
 */
static HANDLE ec_open_thread(HANDLE thread, bool *found_not)
{
    const ACCESS_MASK want = THREAD_SUSPEND_RESUME |
                             THREAD_QUERY_INFORMATION | SYNCHRONIZE;
    HANDLE h = NULL, next;

    *found_not = false;
    if (XT_TP_FAIL(XT_TPF_OPEN)) {
        return NULL;
    }
    for (;;) {
        NTSTATUS st = NtGetNextThread(GetCurrentProcess(), h, want, 0, 0,
                                      &next);

        if (h) {
            NtClose(h);
        }
        if (st < 0) {
            /* The end of the list: not a thread of this process. */
            *found_not = st == STATUS_NO_MORE_ENTRIES;
            return NULL;
        }
        h = next;
        if (NtCompareObjects(thread, h) == 0) {
            return h;
        }
    }
}

static bool watcher_stop, watcher_fast;
static uint32_t lock_misses;      /* lockcheck's (xt_lock_checked) */
static void *lock_miss_caller;
static void ec_ring_doorbells(void);

/*
 * The process's end, at Windows' first call (NULL, before), on the exiting
 * thread: every other thread of the process is certified out of the
 * engine, for good, so that what runs after Windows has ended them (DLL
 * detach code, on this thread) waits for none of them.
 *
 * - One thread owns it, the first to swap its gate into xt_gate_closed_by,
 *   which closes the gate to every other thread (arm64ec-gate.c); every
 *   processor's writes are flushed next.  Another thread ending the
 *   process the same way at once parks at the gate.
 * - The engine's internal threads (the registry, runtime.c) are asked to
 *   park: the module's helpers at the top of their loops, rcustress's
 *   watchdog before it could misread a long stop as a stall.
 * - The freeze: every other thread, found with NtGetNextThread, is asked
 *   to suspend and its doorbell rung, to bring it out of the engine
 *   sooner, and certified from its gate (ec_certify), with no context
 *   read; those still inside the module are let go to finish, for up to
 *   EC_STOP_ACTIVE_MS.  A read one is in is taken over.  Passes repeat
 *   until one finds no thread it hasn't certified.  A slot of the
 *   registry still being created is waited for first, so that an internal
 *   thread is never mistaken for another.  A budget (EC_FREEZE_MS) is
 *   checked after each pass.
 * - Then the doorbell watcher and the region sampler park, and every
 *   registered thread must be parked, or be call_rcu's worker.
 * - Every translation goes: a native thread may have written code with
 *   its flush's notification never made.
 * - Then call_rcu's work is drained and its worker left at rest
 *   (rcu_worker_resting).  These last steps run only if all went well.
 *
 * A failure is counted and logged, and the exit goes on (unless the
 * setting keyword exitstrict makes it fatal): the detach code runs as it
 * would have.  A termination ThreadTerm let through uncertified
 * (ec_unsafe_terms) is one.  After the freeze nothing here writes to the
 * standard streams, whose reader may be a stopped thread; the outcome is
 * printed at the last call with the keyword exitreport.
 */
#define EC_FREEZE_MS 30000
#define EC_PARK_MS 1000
#define EC_WRITER_MS 2000

enum {
    EC_EXIT_STOP = 1 << 0,          /* a thread not stopped so */
    EC_EXIT_UNSAFE = 1 << 1,        /* ThreadTerm let one through */
    EC_EXIT_BUDGET = 1 << 2,        /* the freeze ran out of time */
    EC_EXIT_CREATING = 1 << 3,      /* an internal thread's creation hung */
    EC_EXIT_HELPER = 1 << 4,        /* an internal thread didn't park */
    EC_EXIT_RCU = 1 << 5,           /* call_rcu's worker not at rest */
    EC_EXIT_FLUSH = 1 << 6,         /* the write-buffer flush failed */
    EC_EXIT_SELF = 1 << 7,          /* the owner's word: not its level alone */
    EC_EXIT_DIED = 1 << 8,          /* a thread died inside, or mid-operation */
    EC_EXIT_CACHE = 1 << 9,         /* the cache's writer didn't settle */
    EC_EXIT_WRITER = 1 << 10,       /* nor, after a failure, park */
    EC_EXIT_DONE = 1u << 31,
};

static uint32_t ec_exit_outcome;
static uint32_t ec_exit_frozen, ec_exit_passes, ec_exit_refrozen;
/*
 * The end's time, and the time elapsed from its start at four points: the
 * freeze, the parks, the flush and the cache's quiesce done (reported as
 * the order they run in: freeze, parks, cache, flush).
 */
static int64_t ec_exit_ns, ec_exit_phase[4];
static NTSTATUS ec_exit_first_fail;
static int ec_exit_first_why;

typedef struct EcFrozen {
    HANDLE h;
    DWORD tid;
    bool suspended;         /* by the freeze, and not undone */
} EcFrozen;

typedef struct EcRead {
    vaddr addr, len;
} EcRead;

static DWORD ec_thread_id(HANDLE h)
{
    XtThreadBasicInfo tbi;

    if (NtQueryInformationThread(h, 0, &tbi, sizeof(tbi), NULL) < 0) {
        return 0;
    }
    return (DWORD)(uintptr_t)tbi.ClientId.UniqueThread;
}

/* Whether TID is a registered internal thread's (one not yet ended). */
static bool ec_is_internal(DWORD tid)
{
    int n;
    const XtInternal *r = xt_internal_threads(&n);

    for (int i = 0; i < n; i++) {
        if (qatomic_load_acquire(&r[i].state) != XT_INTERNAL_FREE &&
            qatomic_read(&r[i].tid) == tid) {
            return true;
        }
    }
    return false;
}

/* Until DEADLINE: no slot of the registry still being created. */
static bool ec_wait_creations(int64_t deadline)
{
    int n;
    const XtInternal *r = xt_internal_threads(&n);

    for (int i = 0; i < n; i++) {
        while (qatomic_load_acquire(&r[i].state) == XT_INTERNAL_CREATING) {
            if (get_clock() > deadline) {
                return false;
            }
            NtYieldExecution();
        }
    }
    return true;
}

static bool ec_is_frozen(GArray *frozen, DWORD tid)
{
    for (guint i = 0; i < frozen->len; i++) {
        if (g_array_index(frozen, EcFrozen, i).tid == tid) {
            return true;
        }
    }
    return false;
}

/* A thread the freeze couldn't stop (TID, 0 if unknown), with ST and WHY. */
static void ec_freeze_failed(DWORD tid, NTSTATUS st, int why)
{
    ec_exit_outcome |= EC_EXIT_STOP;
    if (!ec_exit_first_fail) {
        ec_exit_first_fail = st;
        ec_exit_first_why = why;
    }
    xt_gevent(XT_EV_THREAD_TERM, tid, 8 | (uint64_t)(uint32_t)st << 32);
}

/*
 * A certificate (ec_certify): the thread has no level in the module and
 * no operation outstanding that isn't handed over, and the gate keeps it
 * out from here on.  Or it can't be had yet (active), or ever (failed).
 */
static uint32_t ec_died_owned, ec_died_unfinished;

typedef enum EcCert {
    EC_CERT_ACTIVE,
    EC_CERT_FAILED,
    EC_CERT_IDLE,
    EC_CERT_PARKED,
    EC_CERT_TAKEN,          /* idle or parked, a read taken over */
    EC_CERT_NEW,            /* no gate yet: its first call meets the gate */
    EC_CERT_ENDING,         /* Windows says it is ending */
} EcCert;

static uint32_t ec_certs[EC_CERT_ENDING + 1];

/*
 * G's certificate, from a snapshot: its admission word, every root, the
 * word again.  The word's sequence number moves on every change and never
 * recurs, so equal words mean the thread made no admission change in
 * between; each root stands on its own: free, or taken (its range, for a
 * read pending since its first half, is the taker's, added to READS, or
 * left on its root for the reaper without READS).  Called with the gate
 * closed and every processor's writes flushed.  A word that keeps changing
 * between the reads is taken as active, so that the call is bounded.
 */
static EcCert ec_certify(XtGate *g, GArray *reads)
{
    /* A thread changing its word all the while is still active. */
    for (int tries = 0; tries < 64; tries++) {
        uint64_t w1 = qatomic_load_acquire(&g->adm), w2;
        uint32_t state[XT_GATE_ROOTS];
        bool taken = false;

        for (int i = 0; i < XT_GATE_ROOTS; i++) {
            state[i] = qatomic_load_acquire(&g->roots[i].state);
        }
        XT_TP(XT_TP_FREEZE_CERT, g, tries);
        w2 = qatomic_load_acquire(&g->adm);
        if (w1 != w2) {
            continue;
        }
        if (w1 & XT_ADM_POISONED) {
            return EC_CERT_FAILED;
        }
        if (XT_ADM_COUNT(w1) && !(w1 & XT_ADM_PARKED)) {
            return EC_CERT_ACTIVE;
        }
        for (int i = 0; i < XT_GATE_ROOTS; i++) {
            XtGateRoot *r = &g->roots[i];

            if (state[i] == XT_ROOT_FREE || state[i] == XT_ROOT_TAKEN) {
                continue;
            }
            if (state[i] == XT_ROOT_PENDING && r->kind == XT_MEMOP_READ &&
                qatomic_cmpxchg(&r->state, XT_ROOT_PENDING,
                                XT_ROOT_TAKEN) == XT_ROOT_PENDING) {
                XT_TP(XT_TP_ROOT_TAKEN, g, i);
                if (reads) {
                    EcRead rd = { r->addr, r->len };

                    g_array_append_val(reads, rd);
                } else {
                    /* Left on its root, for the reaper once it has ended. */
                    qatomic_inc(&xt_gate_read_open);
                }
                taken = true;
                continue;
            }
            /* Another operation owed: a parked thread never finishes it. */
            return w1 & XT_ADM_PARKED ? EC_CERT_FAILED : EC_CERT_ACTIVE;
        }
        if (taken) {
            return EC_CERT_TAKEN;
        }
        return w1 & XT_ADM_PARKED ? EC_CERT_PARKED : EC_CERT_IDLE;
    }
    return EC_CERT_ACTIVE;
}

/*
 * The thread behind H's certificate: through its gate, found by its
 * identity; none registered yet is a thread whose first call will meet the
 * gate.  An identity that can't be read is a failure, unless Windows says
 * the thread is ending.
 */
/*
 * The certificate of an ending thread (H, its gate G or NULL): none until
 * its handle has signalled; then, from its gate, a failure if it died
 * inside the module or with an operation unfinished (xt_gate_death),
 * quarantined and counted, else ENDING.
 */
static EcCert ec_cert_ended(HANDLE h, XtGate *g)
{
    XtDeath d;

    if (!ec_thread_dead(h, 0)) {
        return EC_CERT_ACTIVE;
    }
    d = g ? xt_gate_death(g) : XT_DEATH_CLEAN;
    if (d == XT_DEATH_CLEAN) {
        return EC_CERT_ENDING;
    }
    /* Counted once: the freeze may meet it again in a later pass. */
    if (xt_gate_quarantine(g)) {
        qatomic_inc(d == XT_DEATH_OWNED ? &ec_died_owned
                                        : &ec_died_unfinished);
        XT_TP_NOTE(XT_TPN_DIED, (uintptr_t)g, d, 0);
    }
    return EC_CERT_FAILED;
}

static EcCert ec_certify_thread(HANDLE h, GArray *reads)
{
    NTSTATUS st;
    XtGate *g = xt_gate_for(h, false, &st);

    if (ec_thread_ending(h)) {
        return st < 0 ? EC_CERT_FAILED : ec_cert_ended(h, g);
    }
    if (st < 0) {
        return EC_CERT_FAILED;
    }
    return g ? ec_certify(g, reads) : EC_CERT_NEW;
}

static void ec_freeze(DWORD me, GArray *frozen, GArray *reads)
{
    const ACCESS_MASK want = THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION |
                             SYNCHRONIZE;
    int64_t deadline = get_clock() + (int64_t)EC_FREEZE_MS * SCALE_MS;
    GArray *pending = g_array_sized_new(FALSE, FALSE, sizeof(EcFrozen), 32);

    for (;;) {
        HANDLE h = NULL, next;
        bool fresh = false;
        NTSTATUS st;
        int64_t until;

        ec_exit_passes++;
        if (!ec_wait_creations(deadline)) {
            ec_exit_outcome |= EC_EXIT_CREATING;
            return;
        }
        /*
         * Every new thread asked to suspend, and the doorbells rung at
         * once: a thread in the engine leaves it at its next consistent
         * point (leave_suspend, which pops its level), one in the module's
         * other code finishes, and native code stays still.  None of that
         * is the certificate; it gets threads to one sooner.
         */
        while ((st = NtGetNextThread(GetCurrentProcess(), h, want, 0, 0,
                                     &next)) >= 0) {
            EcFrozen f = { NULL, 0, false };

            if (h) {
                NtClose(h);
            }
            h = next;
            f.tid = ec_thread_id(h);
            if (!f.tid) {
                /* Passed over only once ended: the gates' walk judges it. */
                if (!ec_thread_dead(h, EC_STOP_ACTIVE_MS)) {
                    ec_freeze_failed(0, STATUS_INVALID_HANDLE, 0x400);
                }
                continue;
            }
            if (f.tid == me || ec_is_internal(f.tid) ||
                ec_is_frozen(frozen, f.tid) ||
                ec_is_frozen(pending, f.tid)) {
                continue;
            }
            /* Only a thread that is ending may be passed over. */
            st = NtDuplicateObject(GetCurrentProcess(), h,
                                   GetCurrentProcess(), &f.h, 0, 0,
                                   DUPLICATE_SAME_ACCESS);
            if (st < 0) {
                if (!ec_thread_dead(h, EC_STOP_ACTIVE_MS)) {
                    ec_freeze_failed(f.tid, st, 0x100);
                }
                continue;
            }
            if (XT_TP_FAIL(XT_TPF_SUSPEND_FREEZE) ||
                NtSuspendThread(f.h, NULL) < 0) {
                f.suspended = false;
            } else {
                f.suspended = true;
            }
            g_array_append_val(pending, f);
        }
        if (st != STATUS_NO_MORE_ENTRIES) {
            /* The list ended early: a thread after it was never seen. */
            ec_freeze_failed(0, st, 0x200);
        }
        if (h) {
            NtClose(h);
            h = NULL;
        }
        ec_ring_doorbells();
        /*
         * Each certified from its gate, no context read; those still
         * active are let go together, their suspensions undone, to finish
         * what they are in, and certified as they do, until
         * EC_STOP_ACTIVE_MS has gone by.
         */
        until = get_clock() + (int64_t)EC_STOP_ACTIVE_MS * SCALE_MS;
        for (bool released = false;;) {
            bool active = false;

            for (guint i = 0; i < pending->len; i++) {
                EcFrozen *f = &g_array_index(pending, EcFrozen, i);
                EcCert c;

                if (!f->h) {
                    continue;
                }
                c = ec_certify_thread(f->h, reads);
                if (c == EC_CERT_ACTIVE) {
                    active = true;
                    continue;
                }
                qatomic_inc(&ec_certs[c]);
                if (c == EC_CERT_FAILED) {
                    ec_freeze_failed(f->tid, STATUS_UNSUCCESSFUL, 0x800);
                    NtClose(f->h);
                } else {
                    g_array_append_val(frozen, *f);
                    ec_exit_frozen++;
                    fresh = true;
                }
                f->h = NULL;
            }
            if (!active) {
                break;
            }
            if (get_clock() > until) {
                for (guint i = 0; i < pending->len; i++) {
                    EcFrozen *f = &g_array_index(pending, EcFrozen, i);

                    if (f->h) {
                        qatomic_inc(&ec_certs[EC_CERT_ACTIVE]);
                        ec_freeze_failed(f->tid, STATUS_TIMEOUT, 0x1000);
                        NtClose(f->h);
                        f->h = NULL;
                    }
                }
                break;
            }
            if (!released) {
                for (guint i = 0; i < pending->len; i++) {
                    EcFrozen *f = &g_array_index(pending, EcFrozen, i);

                    if (f->h && f->suspended) {
                        NtResumeThread(f->h, NULL);
                        f->suspended = false;
                    }
                }
                released = true;
            }
            /* Not a timed wait: Windows' timer would make it 15.6 ms. */
            NtYieldExecution();
        }
        g_array_set_size(pending, 0);
        if (get_clock() > deadline) {
            ec_exit_outcome |= EC_EXIT_BUDGET;
            return;
        }
        if (!fresh) {
            /*
             * A pass that found no thread it hadn't certified: every
             * certificate holds while the gate is closed, as a thread let
             * run again meets the gate at its next way in.
             */
            return;
        }
    }
}

/*
 * Set for good when a thread was ended unsafely and its gate couldn't be
 * found to quarantine it: the reaper then reclaims nothing more, as it
 * can't tell which record that thread may have left in use.
 */
static bool ec_reap_held;

/*
 * Gates whose threads have ended, retired (arm64ec-gate.c): the thread's
 * record unlinked and handed to the reaper with its TLS block, its frame
 * and emulator stack likewise, a read taken from it invalidated.  Only
 * once its handle has signalled: the thread runs nothing more, and a read
 * it was blocked in has completed or been cancelled with it, though one
 * Windows doesn't tie to the thread (overlapped, a completion port's) may
 * still write later.  A quarantined gate keeps its record and frame: its
 * thread ended unsafely.  On a thread at its only level in the module.
 */
static void ec_reap_gates(void)
{
    uint32_t cursor = 0;
    bool quarantined;
    XtGate *g;

    if (qatomic_read(&ec_reap_held)) {
        return;
    }
    while ((g = xt_gate_retire_next(&cursor, &quarantined))) {
        HANDLE hr = NULL, hf = NULL;
        XtThread *t;
        XtEcFrame *f;

        XT_TP(XT_TP_REAP_PASS, g, quarantined);

        /*
         * Read after this gate's thread was seen ended: a terminator that
         * couldn't find its target's gate set the hold before Windows ended
         * that target, so a pass already running sees it here.
         */
        if (qatomic_load_acquire(&ec_reap_held)) {
            xt_gate_retire_abort(g);
            return;
        }

        /* The handles the reaper waits on, before anything is taken. */
        if (!quarantined &&
            (XT_TP_FAIL(XT_TPF_DUP_REAP1) ||
             NtDuplicateObject(GetCurrentProcess(), g->thread,
                               GetCurrentProcess(), &hr, 0, 0,
                               DUPLICATE_SAME_ACCESS) < 0 ||
             XT_TP_FAIL(XT_TPF_DUP_REAP2) ||
             NtDuplicateObject(GetCurrentProcess(), g->thread,
                               GetCurrentProcess(), &hf, 0, 0,
                               DUPLICATE_SAME_ACCESS) < 0)) {
            if (hr) {
                NtClose(hr);
            }
            xt_gate_retire_abort(g);
            continue;
        }
        for (int i = 0; i < XT_GATE_ROOTS; i++) {
            XtGateRoot *r = &g->roots[i];

            if (qatomic_load_acquire(&r->state) == XT_ROOT_TAKEN) {
                xt_invalidate(r->addr, r->len);
                XT_TP_NOTE(XT_TPN_INVALIDATE, r->addr, r->len, (uintptr_t)g);
                XT_TP(XT_TP_RETIRE_INVALIDATED, g, i);
                qatomic_store_release(&r->state, XT_ROOT_FREE);
            }
        }
        t = quarantined ? NULL : qatomic_xchg((XtThread **)&g->rec, NULL);
        f = quarantined ? NULL : qatomic_xchg((XtEcFrame **)&g->frame, NULL);
        if (t) {
            if (f) {
                qatomic_set(&f->env, NULL);
            }
            ec_unregister(t);
            xt_thread_retire(t, hr);
            hr = NULL;
        }
        if (f) {
            xt_reap_later(hf, f);
            hf = NULL;
        }
        if (hr) {
            NtClose(hr);
        }
        if (hf) {
            NtClose(hf);
        }
        xt_gate_mark_retired(g);
    }
}

static void ec_frame_normalize(XtThread *t, XtEcFrame *f, uint64_t fpsr);

/*
 * The calling thread's own end, at its only level: its record goes now,
 * its frame and emulator stack once the thread has ended (the reaper), and
 * its thread-affine cleanup runs here.
 */
static void ec_term_self(XtGate *g)
{
    XtCpuArea *area = xt_cpu_area(NtCurrentTeb());
    HANDLE stack_ref = NULL;
    XtEcFrame *f;
    XtThread *t;
    bool began;

    began = xt_adapter_begin();
    if (!area || !qatomic_read(&area->EmulatorData[0]) ||
        XT_TP_FAIL(XT_TPF_DUP_SELF) ||
        NtDuplicateObject(GetCurrentProcess(), GetCurrentThread(),
                          GetCurrentProcess(), &stack_ref, 0, 0,
                          DUPLICATE_SAME_ACCESS) < 0) {
        goto out;
    }
    t = qatomic_xchg(&area->EmulatorData[0], NULL);
    qatomic_set((XtThread **)&g->rec, NULL);
    if (!t) {
        goto out;
    }
    f = area->EmulatorData[1];
    /* A kept frame of x-ecfast's gives back the host FP state first. */
    if (f->resume_sp) {
        ec_frame_normalize(t, f, host_fp_status_read());
    }
    f->fr_lo = f->fr_hi = NULL;
    qatomic_set((XtEcFrame **)&g->frame, NULL);
    /* Before the CPU state goes: no entry of this thread's is storing. */
    qatomic_set(&f->env, NULL);
    ec_unregister(t);
    xt_reap_later(stack_ref, f);
    stack_ref = NULL;
    xt_thread_free(t);
    xt_crt_thread_fini();
out:
    if (stack_ref) {
        NtClose(stack_ref);
    }
    xt_adapter_end(began);
}

/* An unsafe termination counted, where logging it could take a lock. */
static void ec_unsafe_term_quiet(void)
{
    qatomic_inc(&ec_unsafe_terms);
    XT_TP_NOTE(XT_TPN_UNSAFE, 0, 0, 1);
}

/*
 * Another thread's end, through OWN (TID): its gate closed, found by its
 * identity (one made closed if it has none yet, which it adopts at its
 * first call), every processor's writes flushed, so that from here its
 * entries park.  Then, at the caller's own level (admitted), it is
 * suspended and the doorbells rung, to bring it out of the engine sooner.
 * If the caller's level is its only one, it is popped (*POPPED) before the
 * wait: the caller holds nothing while it waits, and anyone may certify
 * it meanwhile, so two threads ending each other don't wait on each other.
 * The thread is certified from its gate as the process's end does (a read
 * it is in is taken, its range left on its root for the reaper), let go
 * to finish while it is still inside the module, for up to
 * EC_STOP_ACTIVE_MS.  Certified, it is let run again (its closure keeps it
 * out of the engine) and Windows ends it; its record goes with the reaper
 * once it has.  Not certified, or one of the engine's internal threads
 * (whose work no level counts), it is quarantined and counted; Windows ends
 * it all the same.  A thread whose gate can't be found holds the reaper
 * for good.
 */
static void ec_term_other(HANDLE own, DWORD tid, XtGate *me, uint32_t level,
                          bool *popped)
{
    int64_t until;
    bool suspended, released = false;
    NTSTATUS st;
    XtGate *g = xt_gate_for(own, true, &st);
    EcCert c;

    if (!g) {
        if (st < 0 && !ec_thread_dead(own, 0)) {
            qatomic_store_release(&ec_reap_held, true);
            XT_TP_NOTE(XT_TPN_REAP_HELD, tid, 0, 0);
            ec_unsafe_term(tid, st);
        }
        return;
    }
    XT_TP(XT_TP_TERM_CLOSED, g, tid);
    if (qatomic_read(&g->internal) || ec_is_internal(tid)) {
        /* Its creator registers it before it runs: startup included. */
        xt_gate_quarantine(g);
        ec_unsafe_term(tid, STATUS_UNSUCCESSFUL);
        return;
    }
    if (XT_TP_FAIL(XT_TPF_FLUSH_TERM) || ec_flush_write_buffers() < 0) {
        xt_gate_quarantine(g);
        ec_unsafe_term(tid, STATUS_UNSUCCESSFUL);
        return;
    }
    suspended = !XT_TP_FAIL(XT_TPF_SUSPEND_TERM) &&
                NtSuspendThread(own, NULL) >= 0;
    XT_TP(XT_TP_TERM_SUSPENDED, g, suspended);
    if (qatomic_load_acquire(&engine_state) == 2) {
        ec_ring_doorbells();
    }
    if ((level & ~XT_ADM_ATTEMPT) == 1) {
        xt_adm_exit(me);
        *popped = true;
    }
    until = get_clock() + (int64_t)EC_STOP_ACTIVE_MS * SCALE_MS;
    for (;;) {
        c = ec_thread_ending(own) ? ec_cert_ended(own, g) : ec_certify(g, NULL);
        XT_TP(XT_TP_TERM_CERT, g, c);
        if (c != EC_CERT_ACTIVE || get_clock() > until) {
            break;
        }
        if (suspended && !released) {
            NtResumeThread(own, NULL);
            released = true;
        }
        NtYieldExecution();
    }
    if (suspended && !released) {
        NtResumeThread(own, NULL);
    }
    if (c == EC_CERT_ACTIVE || c == EC_CERT_FAILED) {
        xt_gate_quarantine(g);
        if (*popped) {
            ec_unsafe_term_quiet();
        } else {
            ec_unsafe_term(tid, STATUS_UNSUCCESSFUL);
        }
    }
}

/* Gates of threads already ended retired, and the reaper's other work. */
static void ec_reap_all(void)
{
    bool began;

    xt_enter();
    began = xt_adapter_begin();
    xt_reap();
    ec_reap_gates();
    xt_adapter_end(began);
}

/*
 * A thread's end, by itself or by another thread (THREAD), before Windows
 * terminates it, at the caller's LEVEL on its gate ME.  Windows calls
 * this before it checks THREAD's access, and ends nothing through a real
 * handle without THREAD_TERMINATE: such a call changes nothing here.
 *
 * - The caller's own end (NULL, its pseudo-handle, or a handle to the same
 *   object as its gate's), told apart without the record lists: nested
 *   inside the engine's own work (an outer level), or on an internal
 *   thread, it is quarantined and counted, as it would end holding what
 *   that work holds and the lists' upkeep could wait on it; at its only
 *   level, the reaper's work, then ec_term_self, and *OWN_END is set.
 * - Another thread is found through its record's own handle
 *   (xt_terminated_thread) at the caller's only level, else among the
 *   process's threads (ec_open_thread), which takes no lock of the
 *   engine's, and ended as ec_term_other has it, before the engine is up
 *   too: a thread can enter it before Windows ends it.  One that can't be
 *   found holds the reaper.
 */
static NTSTATUS ec_thread_term(HANDLE thread, LONG code, XtGate *me,
                               uint32_t level, bool *popped, bool *own_end)
{
    PUBLIC_OBJECT_BASIC_INFORMATION obi;
    bool nested = (level & ~XT_ADM_ATTEMPT) > 1;
    int state = qatomic_load_acquire(&engine_state);
    bool not_ours = false;
    HANDLE own = NULL;
    void *teb = NULL;
    DWORD tid = 0;

    XT_TP_NOTE(XT_TPN_THREAD_TERM, (uintptr_t)thread, level, 0);
    if (thread && thread != GetCurrentThread() &&
        (NtQueryObject(thread, ObjectBasicInformation, &obi, sizeof(obi),
                       NULL) < 0 ||
         !(obi.GrantedAccess & THREAD_TERMINATE)) &&
        !XT_TP_FAIL(XT_TPF_TERMACCESS)) {
        return STATUS_SUCCESS;
    }
    if (!thread || thread == GetCurrentThread() ||
        (me->thread && NtCompareObjects(thread, me->thread) == 0)) {
        goto self;
    }
    if (state == 2 && !nested) {
        ec_reap_all();
        tid = xt_terminated_thread(thread, &teb, &own);
    }
    if (!own) {
        own = ec_open_thread(thread, &not_ours);
        if (!own) {
            if (!not_ours) {
                qatomic_store_release(&ec_reap_held, true);
                XT_TP_NOTE(XT_TPN_REAP_HELD, 0, 0, 0);
                ec_unsafe_term(0, STATUS_UNSUCCESSFUL);
            }
            return STATUS_SUCCESS;
        }
        tid = ec_thread_id(own);
    }
    if (tid == GetCurrentThreadId()) {
        NtClose(own);
        goto self;
    }
    ec_term_other(own, tid, me, level, popped);
    /* A suspension, if any is left, outlives the handle. */
    NtClose(own);
    return STATUS_SUCCESS;

self:
    XT_TP(XT_TP_TERM_SELF, me, level);
    /* The live word, not the level returned: a leak may sit above it. */
    if (nested || qatomic_read(&me->internal) || !xt_adm_alone(me)) {
        xt_gate_quarantine(me);
        ec_unsafe_term_quiet();
    } else {
        if (state == 2) {
            ec_reap_all();
            ec_term_self(me);
        }
        if (unlikely(xt_term_hold_us)) {
            int64_t until = get_clock() + (int64_t)xt_term_hold_us * SCALE_US;

            while (get_clock() < until) {
                /* Spinning: no kernel entry inside ntdll's callback. */
            }
        }
        *own_end = !xt_term_noanswer;
    }
    return STATUS_SUCCESS;
}

/*
 * Until EC_PARK_MS: every registered thread parked, or call_rcu's worker,
 * or the translation cache's writer, which the cache's quiesce stops next.
 */
static bool ec_wait_parked(void)
{
    int64_t deadline = get_clock() + (int64_t)EC_PARK_MS * SCALE_MS;
    int n;
    const XtInternal *r = xt_internal_threads(&n);

    for (int i = 0; i < n; i++) {
        for (;;) {
            uint32_t state = qatomic_load_acquire(&r[i].state);
            DWORD tid = qatomic_read(&r[i].tid);
            int rcu_tid, sampler_tid, writer_tid;
            bool sampler_parked = translator_region_sampler_parked(
                &sampler_tid);

            rcu_worker_resting(&rcu_tid);
            tcg_cache_dir_writer_settled(&writer_tid);
            if (state == XT_INTERNAL_FREE || state == XT_INTERNAL_PARKED ||
                (tid && tid == (DWORD)rcu_tid) ||
                (tid && tid == (DWORD)writer_tid) ||
                (tid && tid == (DWORD)sampler_tid && sampler_parked)) {
                break;
            }
            if (get_clock() > deadline) {
                return false;
            }
            NtYieldExecution();
        }
    }
    return true;
}

/*
 * Until @ms: the translation cache's writer holding nothing for good
 * (none, parked, or blocked on the work a quiesce holds).
 */
static bool ec_wait_writer(int ms)
{
    int64_t deadline = get_clock() + (int64_t)ms * SCALE_MS;
    int tid;

    while (!tcg_cache_dir_writer_settled(&tid)) {
        if (get_clock() > deadline) {
            return false;
        }
        NtYieldExecution();
    }
    return true;
}

/* Until EC_PARK_MS: call_rcu's worker waiting, with nothing counted. */
static bool ec_wait_rcu_rest(void)
{
    int64_t deadline = get_clock() + (int64_t)EC_PARK_MS * SCALE_MS;
    int tid;

    while (!rcu_worker_resting(&tid)) {
        if (get_clock() > deadline) {
            return false;
        }
        NtYieldExecution();
    }
    return true;
}

/*
 * Every translation goes, as one flush: on this thread's CPU, exclusively
 * of the others, which are stopped outside the engine.  The flush walks
 * every CPU, so it is only for an end whose steps all went well: after a
 * failure (a thread ended without a stop may have left its CPU behind), or
 * on a thread with no CPU (one that never ran x64 code ends the process),
 * they are dropped range by range instead, which costs more.
 */
static void ec_exit_flush(void)
{
    XtCpuArea *area = xt_cpu_area(NtCurrentTeb());
    XtThread *t = area ? area->EmulatorData[0] : NULL;
    CPUState *prev = current_cpu;

    if (!t || ec_exit_outcome) {
        xt_invalidate(0, (vaddr)guest_addr_max + 1);
        return;
    }
    current_cpu = t->cpu;
    start_exclusive();
    tb_flush__exclusive_or_serial();
    end_exclusive();
    current_cpu = prev;
}

/*
 * NS in milliseconds, its whole part and tenths, rounded half up: the
 * exit's report formats integers only, which neither allocates nor locks
 * (a float's conversion does both), as a thread that died inside the
 * module may hold either.
 */
static uint64_t ec_ms_whole(int64_t ns)
{
    return (uint64_t)(ns + 50000) / 1000000;
}

static uint32_t ec_ms_tenth(int64_t ns)
{
    return (uint32_t)((uint64_t)(ns + 50000) / 100000 % 10);
}

static void ec_exit_line(char *line, size_t size)
{
    int n = snprintf(line, size, "exit: outcome 0x%x, %u threads stopped "
                     "(%u again), %u passes, %u unsafe terminations, "
                     "%llu.%u ms (freeze %llu.%u, parks %llu.%u, cache "
                     "%llu.%u, flush %llu.%u), first stop failure 0x%lx "
                     "why 0x%x; "
                     "certified idle %u parked %u taken %u new %u ending %u, "
                     "failed %u, still active %u; died inside %u, "
                     "mid-operation %u\n",
                     ec_exit_outcome & ~EC_EXIT_DONE, ec_exit_frozen,
                     ec_exit_refrozen, ec_exit_passes,
                     qatomic_read(&ec_unsafe_terms),
                     (unsigned long long)ec_ms_whole(ec_exit_ns),
                     ec_ms_tenth(ec_exit_ns),
                     (unsigned long long)ec_ms_whole(ec_exit_phase[0]),
                     ec_ms_tenth(ec_exit_phase[0]),
                     (unsigned long long)ec_ms_whole(ec_exit_phase[1]),
                     ec_ms_tenth(ec_exit_phase[1]),
                     (unsigned long long)ec_ms_whole(ec_exit_phase[3]),
                     ec_ms_tenth(ec_exit_phase[3]),
                     (unsigned long long)ec_ms_whole(ec_exit_phase[2]),
                     ec_ms_tenth(ec_exit_phase[2]),
                     (unsigned long)ec_exit_first_fail, ec_exit_first_why,
                     ec_certs[EC_CERT_IDLE], ec_certs[EC_CERT_PARKED],
                     ec_certs[EC_CERT_TAKEN], ec_certs[EC_CERT_NEW],
                     ec_certs[EC_CERT_ENDING], ec_certs[EC_CERT_FAILED],
                     ec_certs[EC_CERT_ACTIVE], qatomic_read(&ec_died_owned),
                     qatomic_read(&ec_died_unfinished));

    if (xt_lock_check && n > 0 && (size_t)n < size) {
        n += snprintf(line + n, size - n, "lockcheck: %u acquisitions "
                      "outside protection, the first from %p (module %p)\n",
                      qatomic_read(&lock_misses),
                      qatomic_read(&lock_miss_caller), &__ImageBase);
    }
    if (xt_gate_check && n > 0 && (size_t)n < size) {
        xt_gate_report(line + n, size - n);
    }
}

/* Testing: where the counts are, for the test points' controller. */
static void ec_tp_publish(void)
{
    xt_gate_tp_publish();
    xt_record_tp_publish();
    xt_tp_publish(XT_TPA_UNSAFE, &ec_unsafe_terms);
    xt_tp_publish(XT_TPA_REAP_HELD, &ec_reap_held);
    xt_tp_publish(XT_TPA_CERTS, ec_certs);
    xt_tp_publish(XT_TPA_EXIT_OUTCOME, &ec_exit_outcome);
    xt_tp_publish(XT_TPA_ENGINE_STATE, &engine_state);
}

static void ec_exit_begin(void)
{
    DWORD me = GetCurrentThreadId();
    XtGate *g = xt_gate_self();
    XtGate *owner = qatomic_cmpxchg(&xt_gate_closed_by, NULL, g);
    GArray *frozen, *reads;
    int64_t t0 = get_clock();
    char line[1024];
    bool began;

    if (owner == g) {
        return;
    }
    if (owner) {
        /*
         * Another thread is ending the process and has closed the gate:
         * this thread parks for good in one terminal transition, parked
         * if this call's level is all it has (certified with the rest),
         * poisoned if it holds an outer level (a failed stop).
         */
        xt_adm_park_terminal(g);
    }
    /*
     * The gate closed (the swap above, which also elected this thread),
     * then every processor's writes flushed: from here a thread's entry
     * either sees the gate closed, or its level is visible to ec_freeze.
     */
    XT_TP(XT_TP_EXIT_ELECTED, g, 0);
    /*
     * The translation cache's diagnostics (cachedebug, for development) go
     * to the standard error stream, which from here may have a stopped
     * thread for reader: none starts after this.  One the writer has
     * already begun can still block it, and the quiesce behind it, if that
     * reader is stopped.
     */
    qatomic_set(&tcg_cache_debug, false);
    if (XT_TP_FAIL(XT_TPF_FLUSH_PROCESS) || ec_flush_write_buffers() < 0) {
        ec_exit_outcome |= EC_EXIT_FLUSH;
    }
    began = xt_adapter_begin();
    frozen = g_array_sized_new(FALSE, FALSE, sizeof(EcFrozen), 32);
    reads = g_array_sized_new(FALSE, FALSE, sizeof(EcRead), 8);
    xt_internal_stop();
    qatomic_set(&watcher_fast, true);
    xt_internal_alert();
    ec_freeze(me, frozen, reads);
    ec_exit_phase[0] = get_clock() - t0;
    if (qatomic_read(&ec_unsafe_terms)) {
        ec_exit_outcome |= EC_EXIT_UNSAFE;
    }
    qatomic_set(&watcher_stop, true);
    translator_region_sampler_park();
    xt_internal_alert();
    if (!ec_wait_parked()) {
        ec_exit_outcome |= EC_EXIT_HELPER;
    }
    ec_exit_phase[1] = get_clock() - t0;
    /*
     * The rest relies on every other thread being out of the engine, and on
     * this one holding only this call's level (read live: an interruption
     * may have left one above it): after a failure none of it runs (a
     * failed thread may hold what it needs).
     */
    XT_TP(XT_TP_EXIT_SELF, g, 0);
    if (!xt_adm_alone(g)) {
        ec_exit_outcome |= EC_EXIT_SELF;
    }
    /*
     * Threads that died unannounced, which the freeze may not list: only
     * with every other thread certified out (the outcome still 0), when
     * no gate is being retired and no gate's handle closed.
     */
    if (!ec_exit_outcome) {
        uint32_t owned = 0, unfinished = 0;

        xt_gate_find_deaths(&owned, &unfinished);
        qatomic_add(&ec_died_owned, owned);
        qatomic_add(&ec_died_unfinished, unfinished);
    }
    if (qatomic_read(&ec_died_owned) || qatomic_read(&ec_died_unfinished)) {
        ec_exit_outcome |= EC_EXIT_DIED;
    }
    /*
     * The translation cache's writer finishes its round and stops, holding
     * nothing, and what the captures hold is published: every lock its
     * round and the drain wait on is a module thread's, the others
     * certified out.
     */
    if (!ec_exit_outcome) {
        tcg_cache_dir_quiesce();
        if (!ec_wait_writer(EC_PARK_MS)) {
            ec_exit_outcome |= EC_EXIT_CACHE;
        }
    }
    ec_exit_phase[3] = get_clock() - t0;
    if (!ec_exit_outcome && qatomic_load_acquire(&engine_state) == 2) {
        xt_enter();
        for (guint i = 0; i < reads->len; i++) {
            EcRead *r = &g_array_index(reads, EcRead, i);

            xt_invalidate(r->addr, r->len);
            XT_TP_NOTE(XT_TPN_INVALIDATE, r->addr, r->len, 0);
        }
        /* A flush's notification may be what a stopped thread missed. */
        ec_exit_flush();
    }
    ec_exit_phase[2] = get_clock() - t0;
    if (!ec_exit_outcome) {
        drain_call_rcu();
        if (!ec_wait_rcu_rest()) {
            ec_exit_outcome |= EC_EXIT_RCU;
        }
    }
    /*
     * After a failure no cache publication begins: captures close, and
     * the writer, asked to stop after its round, gets a bounded wait (a
     * thread that wasn't stopped may hold what its round needs).
     */
    if (ec_exit_outcome) {
        tcg_cache_dir_abandon();
        if (!ec_wait_writer(EC_WRITER_MS)) {
            ec_exit_outcome |= EC_EXIT_WRITER;
        }
    }
    ec_exit_ns = get_clock() - t0;
    XT_TP_NOTE(XT_TPN_EXIT, ec_exit_outcome, ec_exit_frozen,
               qatomic_read(&ec_unsafe_terms));
    ec_exit_line(line, sizeof(line));
    xt_log_text(line);
    qatomic_store_release(&ec_exit_outcome, ec_exit_outcome | EC_EXIT_DONE);
    if ((ec_exit_outcome & ~EC_EXIT_DONE) && xt_exit_strict) {
        NtTerminateProcess(GetCurrentProcess(), STATUS_ASSERTION_FAILURE);
    }
    xt_adapter_end(began);
}

/* @h names this process. */
static bool ec_is_self(HANDLE h)
{
    PROCESS_BASIC_INFORMATION pbi;

    return h == GetCurrentProcess() ||
           (NtQueryInformationProcess(h, ProcessBasicInformation, &pbi,
                                      sizeof(pbi), NULL) >= 0 &&
            (DWORD)(uintptr_t)pbi.UniqueProcessId == GetCurrentProcessId());
}

/*
 * Windows' calls at the process's end, on the exiting thread: (NULL,
 * before), with the other threads still running; (NULL, after), once it
 * has ended them; then (the process, before), this process's last, where
 * the translation cache publishes what the detach code added (without
 * allocating or waiting; nothing after a failed end, which abandoned it).
 * Also the last for a direct termination of the process, which skips the
 * first two.  What writes to the standard streams runs before the first
 * call's freeze (ec_exit_begin), or, for testing (exitreport), at the
 * last, the other threads gone.
 */
static void ec_process_term(HANDLE h, BOOL after, NTSTATUS status)
{
    static bool cache_stats_done;

    if (!h && !after) {
        /*
         * The translation cache's statistics and dump (testing), while
         * no other thread can have been stopped holding a lock they take.
         */
        if (tcg_cache_mode && !cache_stats_done &&
            (tcg_cache_stats_at_exit || getenv("XTCG_CACHE_STATS"))) {
            cache_stats_done = true;
            tcg_cache_print_stats();
            xt_cache_print_stats();
        }
        if (tcg_cache_mode == TCG_CACHE_ON && cache_dump) {
            cache_dump = false;
            WITH_MMAP_LOCK_GUARD() {
                xt_cache_dump();
            }
        }
        xt_ec_stub_inject_report();
        if (xt_exit_report && tcg_ecfast) {
            char line[160];

            snprintf(line, sizeof(line), "ecfast: assembly %s; departure "
                     "tails rcu %u exclusive %u both %u; resume in C "
                     "exclusive %u request %u\n",
                     xt_ec_fast_asm ? "on" : "off",
                     qatomic_read(&ec_fast_tails[XT_EC_TAIL_RCU]),
                     qatomic_read(&ec_fast_tails[XT_EC_TAIL_EXCL]),
                     qatomic_read(&ec_fast_tails[XT_EC_TAIL_RCU |
                                                 XT_EC_TAIL_EXCL]),
                     qatomic_read(&ec_fast_slows[XT_EC_FAST_START]),
                     qatomic_read(&ec_fast_slows[XT_EC_FAST_CLEAR]));
            fputs(line, stderr);
            xt_log_text(line);
        }
        if (xt_exit_report && tcg_nzcv) {
            char line[80];

            snprintf(line, sizeof(line), "nzcv: %u TBs translated again "
                     "without the host's flags\n",
                     qatomic_read(&tcg_nzcv_retries));
            fputs(line, stderr);
            xt_log_text(line);
        }
        if (xt_rcu_stress) {
            char line[64];

            snprintf(line, sizeof(line), "rcustress: %llu grace periods\n",
                     (unsigned long long)qatomic_read(&rcu_stress_done));
            fputs(line, stderr);
            xt_log_text(line);
        }
        /* A failed bring-up (state below 0) has no engine to keep. */
        if (qatomic_load_acquire(&engine_state) > 0) {
            ec_exit_begin();
        }
    }
    if (h && !after && qatomic_load_acquire(&engine_state) == 2 &&
        ec_is_self(h)) {
        bool began = xt_adapter_begin();

        tcg_cache_dir_exit();
        xt_adapter_end(began);
    }
    if (h && !after && xt_exit_report &&
        (qatomic_load_acquire(&ec_exit_outcome) & EC_EXIT_DONE) &&
        qatomic_read(&xt_gate_closed_by) == xt_gate_self()) {
        char line[1024];

        ec_exit_line(line, sizeof(line));
        fputs(line, stderr);
    }
}

/*
 * The memory service's work (memory.c), from any thread.  Before the engine
 * is up there are no translations or page flags to keep current.
 */
static bool note_ready(void)
{
    if (qatomic_load_acquire(&engine_state) != 2) {
        return false;
    }
    xt_enter();
    return true;
}

/*
 * ntdll's call at any exception in an ARM64EC thread, before its
 * dispatch, with the full native context (x13, x14, x23, x24, x28 and
 * v16-v31 included).  Continued here, with that context:
 * - the doorbell found set at an exit to native code (arm64ec.S): the
 *   exit stub is consistent there, so continuing it completes the
 *   suspension;
 * - a read by the translation cache's guarded routines, whatever the
 *   thread's state (xt_cache_guard_fault);
 * - a fault the engine recovers (xt_fault_redirect: generated code,
 *   helpers, translation), while it owns the thread;
 * - otherwise, native code's store into a page QEMU write-protected for
 *   its translations, such as a runtime patching its own x64 code: the
 *   page gets its write permission back and the store is retried.
 * Anything else goes on to the dispatch.
 */
/*
 * A continuation of this exception that leaves its level: popped first (an
 * outer level, the engine's own work it interrupted, stays), and a
 * continuation that fails ends the process rather than go on with the
 * level gone.
 */
static G_NORETURN void ec_continue_level(XtGate *g, ARM64_NT_CONTEXT *native)
{
    if (g) {
        xt_adm_exit(g);
    }
    if (!XT_TP_FAIL(XT_TPF_CONTINUE)) {
        xt_continue_native(native);
    }
    NtTerminateProcess(GetCurrentProcess(), STATUS_ASSERTION_FAILURE);
    __builtin_unreachable();
}

XTEXPORT NTSTATUS ResetToConsistentState(EXCEPTION_RECORD *er, CONTEXT *guest,
                                         ARM64_NT_CONTEXT *native)
{
    XtCpuArea *area = xt_cpu_area(NtCurrentTeb());
    uint32_t level;
    XtThread *t;
    XtGate *g;

    /*
     * The exit stub's trap at a rung doorbell (arm64ec.S), redirected to
     * its resume point, where the suspension completes: the stub has
     * popped its level already, and this touches only the thread's own
     * frame and doorbell.
     */
    if (native->Pc == (uintptr_t)xt_ec_exit_suspend_point) {
        ((XtEcFrame *)area->EmulatorData[1])->inj_armed = 1;
        qatomic_set(area->SuspendDoorbell, 0);
        native->Pc = (uintptr_t)xt_ec_exit_resume_point;
        ec_continue_level(NULL, native);
    }
    /* The start-up probes (xt_cross_probe), before any gate can close. */
    if (xt_cross_probe_take(er->ExceptionCode, &native->Pc) ||
        xt_ec_probe_rtcs(er, guest, native)) {
        ec_continue_level(NULL, native);
    }
    g = xt_gate_self();
    level = xt_adm_enter(g);
    /* Testing: the test points' fault action, a nested entry, continued. */
    if (unlikely(xt_tp_block) && native->Pc == (uintptr_t)xt_tp_fault_pc) {
        XT_TP_NOTE(XT_TPN_FAULT, 1, level, qatomic_read(&g->adm));
        XT_TP(XT_TP_FAULT_NESTED, g, level);
        native->Pc += 4;
        ec_continue_level(g, native);
    }
    t = area ? area->EmulatorData[0] : NULL;
    /* The module's int3, past the debugger: at the int3 for the dispatch. */
    if (t && t->int3_rip && er->ExceptionCode == STATUS_BREAKPOINT &&
        native->Pc == t->int3_rip) {
        native->Pc--;
        if (guest) {
            guest->Rip--;
        }
        t->int3_rip = 0;
    }
    /*
     * A read by one of the translation cache's guarded routines: theirs
     * to contain in whatever state the thread is, not only the engine's.
     */
    if (xt_cache_guard_fault(er, native)) {
        ec_continue_level(g, native);
    }
    /*
     * Generated code's return stack push or pop ran into its ring's guard
     * pages: back to the ring's middle, as linux-user's signal handler
     * does.  Its top is in tcg_retstack_reg, which the full native context
     * carries.
     */
    if (t && t == xt_self && t->state != XT_WINDOWS && tcg_retstack_reg >= 0 &&
        er->ExceptionCode == STATUS_ACCESS_VIOLATION &&
        er->NumberParameters >= 2 &&
        in_code_gen_buffer((void *)(uintptr_t)native->Pc)) {
        uintptr_t top = tcg_retstack_fault(t->cpu, native->Pc,
                                           er->ExceptionInformation[1]);

        if (top) {
            native->X[tcg_retstack_reg] = top;
            ec_continue_level(g, native);
        }
    }
    if (t && t == xt_self && t->state != XT_WINDOWS) {
        bool prev = area->InSyscallCallback;
        bool handled;

        area->InSyscallCallback = 1;
        handled = xt_fault_redirect(er, native);
        area->InSyscallCallback = prev;
        if (handled) {
            ec_continue_level(g, native);
        }
        /* An exception in the engine it doesn't recover: logged. */
        xt_event(t, XT_EV_FAULT, (uint64_t)t->fault.busy << 32 | t->active,
                 er->ExceptionInformation[1]);
        xt_log_native(er, native);
        xt_log_flush(t);
    } else if (er->ExceptionCode == STATUS_ACCESS_VIOLATION &&
               er->NumberParameters >= 2 && er->ExceptionInformation[0] == 1 &&
               note_ready() &&
               xt_unprotect_for_native(er->ExceptionInformation[1])) {
        ec_continue_level(g, native);
    }
    xt_adm_exit(g);
    return STATUS_SUCCESS;
}

/*
 * Testing (lockcheck): the mmap lock taken where a stop of this thread
 * would not wait for its release: outside simulation (InSimulation, or the
 * emulator stack, which BeginSimulation's C runs on before it sets the
 * flag), outside an adapter scope, and not on one of the engine's own
 * threads.  The process's end relies on there being none.
 */
void xt_lock_checked(void *caller)
{
    XtCpuArea *area = xt_cpu_area(NtCurrentTeb());
    uintptr_t sp = (uintptr_t)__builtin_frame_address(0);

    if (xt_internal_self || !area || area->InSimulation ||
        area->InSyscallCallback ||
        (sp >= area->EmulatorStackLimit && sp < area->EmulatorStackBase)) {
        return;
    }
    if (qatomic_fetch_inc(&lock_misses) == 0) {
        qatomic_set(&lock_miss_caller, caller);
    }
}

/*
 * The engine's own work outside simulation (memory.c's): with
 * InSyscallCallback set, as FEX's module sets it around its own.
 */
bool xt_adapter_begin(void)
{
    XtCpuArea *area = xt_cpu_area(NtCurrentTeb());

    if (!area || area->InSyscallCallback) {
        return false;
    }
    area->InSyscallCallback = 1;
    return true;
}

void xt_adapter_end(bool began)
{
    if (began) {
        xt_cpu_area(NtCurrentTeb())->InSyscallCallback = 0;
    }
}

static void ec_notify_memory_alloc(void *addr, SIZE_T len, ULONG type,
                                   ULONG prot, BOOL after, NTSTATUS status)
{
    if (note_ready()) {
        xt_note_alloc(addr, len, type, prot, after, status);
    }
}

static void ec_notify_memory_free(void *addr, SIZE_T len, ULONG type,
                                  BOOL after, NTSTATUS status)
{
    if (note_ready()) {
        xt_note_free(addr, len, type, after, status);
    }
}

static void ec_notify_memory_protect(void *addr, SIZE_T len, ULONG prot,
                                     BOOL after, NTSTATUS status)
{
    if (note_ready()) {
        xt_note_protect(addr, len, prot, after, status);
    }
}

static NTSTATUS ec_notify_map_view_of_section(void *unk1, void *addr,
                                              void *unk2, SIZE_T len,
                                              ULONG type, ULONG prot)
{
    if (note_ready()) {
        xt_note_map(addr, len, prot);
    }
    return STATUS_SUCCESS;
}

static void ec_notify_unmap_view_of_section(void *addr, BOOL after,
                                            NTSTATUS status)
{
    if (note_ready()) {
        xt_note_unmap(addr, after);
    }
}

static void ec_flush_instruction_cache_heavy(const void *addr, SIZE_T len)
{
    if (note_ready()) {
        xt_note_flush(addr, len);
    }
}

static void ec_btcpu64_flush_instruction_cache(const void *addr, SIZE_T len)
{
    if (note_ready()) {
        xt_note_flush(addr, len);
    }
}

static void ec_btcpu64_notify_memory_dirty(void *addr, SIZE_T len)
{
    if (note_ready()) {
        xt_note_flush(addr, len);
    }
}

static void ec_btcpu64_notify_read_file(HANDLE h, void *addr, SIZE_T len,
                                        BOOL after, NTSTATUS status)
{
    if (note_ready()) {
        xt_note_read_file(addr, len, after, status);
    }
}

/*
 * The processor as x64 code sees it.  Windows asks for the features while
 * the process starts, before the engine is up: they are the CPU model's
 * until the first entry makes a CPU.  The processor information needs
 * that CPU.
 */
static BOOLEAN ec_btcpu64_is_processor_feature_present(UINT feature)
{
    return xt_feature_present(feature);
}

static void ec_update_processor_information(void *info)
{
    if (qatomic_load_acquire(&engine_state) == 2) {
        xt_processor_info(info, PROCESSOR_ARCHITECTURE_AMD64);
    }
}

NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);

/*
 * The doorbell: Windows rings it to stop a thread that is simulating or
 * on its emulator stack, and waits (up to about 10 s) until the thread is
 * consistent: off that stack, InSimulation clear, its guest state in its
 * native context.  Generated code doesn't look at the word; this thread
 * does, and asks the engine to stop (cpu_exit), which then leaves with
 * the guest's context (leave_suspend).
 */
#define XT_EC_MAX_THREADS 4096
static XtThread *ec_threads[XT_EC_MAX_THREADS];
static int ec_nthreads;

/*
 * The watcher's round: each engine thread whose doorbell Windows rang is
 * asked to stop.  Also the process's end's, right after it has asked
 * Windows to suspend every thread, so as not to wait for the watcher's
 * next tick.
 */
static void ec_ring_doorbells(void)
{
    int n = MIN(qatomic_read(&ec_nthreads), XT_EC_MAX_THREADS);

    xt_record_hold();
    for (int i = 0; i < n; i++) {
        XtThread *t = qatomic_read(&ec_threads[i]);

        if (t && qatomic_read(&t->state) == XT_ENGINE &&
            qatomic_read(t->ec_doorbell) &&
            !qatomic_read(&t->suspend_req)) {
            qatomic_set(&t->suspend_req, 1);
            cpu_exit(t->cpu);
        }
    }
    xt_record_release();
}

static unsigned __stdcall doorbell_watcher(void *arg)
{
    LARGE_INTEGER tick = { .QuadPart = -10000 };

    for (;;) {
        /*
         * The process's end needs it to stop the other threads, so it
         * stops on its own request, last; here it holds nothing.
         */
        if (qatomic_read(&watcher_stop)) {
            xt_internal_park();
        }
        /*
         * While the process's end stops threads, Windows rings their
         * doorbells as it waits for them: looked at without the timer's
         * 15.6 ms granularity.
         */
        if (qatomic_read(&watcher_fast)) {
            NtYieldExecution();
        } else {
            NtDelayExecution(TRUE, &tick);
        }
        ec_ring_doorbells();
    }
    return 0;
}

/* A free slot, else a new one. */
static void ec_register(XtThread *t)
{
    int n = MIN(qatomic_read(&ec_nthreads), XT_EC_MAX_THREADS), i;

    for (i = 0; i < n; i++) {
        if (qatomic_cmpxchg(&ec_threads[i], NULL, t) == NULL) {
            return;
        }
    }
    i = qatomic_fetch_inc(&ec_nthreads);
    if (i < XT_EC_MAX_THREADS) {
        qatomic_set(&ec_threads[i], t);
    }
}

/* Out of the watcher's list; it may have it still until the next hold. */
static void ec_unregister(XtThread *t)
{
    int n = MIN(qatomic_read(&ec_nthreads), XT_EC_MAX_THREADS);

    for (int i = 0; i < n; i++) {
        if (qatomic_read(&ec_threads[i]) == t) {
            qatomic_set(&ec_threads[i], NULL);
        }
    }
}

/*
 * The guest's system call (syscall, int 0x2e): ntdll's native
 * KiUserExceptionDispatcher performs it from the packed context, with
 * STATUS_EMULATION_SYSCALL, then continues at RIP, which is past the
 * instruction already.  The frame is its stack, as an exception's.
 */
typedef struct QEMU_ALIGNED(16) XtKiFrame {
    ARM64_NT_CONTEXT ctx;
    uint64_t pad[4];
    EXCEPTION_RECORD rec;
    uint64_t align;
    uint64_t redzone[2];
} XtKiFrame;

#ifndef STATUS_EMULATION_SYSCALL
#define STATUS_EMULATION_SYSCALL ((NTSTATUS)0x40000039)
#endif

/*
 * EFLAGS kept for a re-entry through a context at RSP: records deeper
 * than a new one are dead (the stack has unwound past them), and taking
 * one drops the deeper ones too.
 */
static void aux_push(XtThread *t, vaddr rsp, uint32_t eflags)
{
    int n = 0;

    for (int i = 0; i < t->naux; i++) {
        if (t->aux[i].rsp > rsp) {
            t->aux[n++] = t->aux[i];
        }
    }
    if (n == ARRAY_SIZE(t->aux)) {
        memmove(&t->aux[0], &t->aux[1], --n * sizeof(t->aux[0]));
    }
    t->aux[n].rsp = rsp;
    t->aux[n].eflags = eflags;
    t->naux = n + 1;
}

static bool aux_take(XtThread *t, vaddr rsp, uint32_t *eflags)
{
    for (int i = t->naux - 1; i >= 0; i--) {
        if (t->aux[i].rsp == rsp) {
            *eflags = t->aux[i].eflags;
            t->naux = i;
            return true;
        }
    }
    return false;
}

/*
 * The end of an activation: the engine gives the thread back (publish)
 * and the guest state goes into the packed context; for an exit that
 * re-enters through a context (CONTEXT_EXIT), EFLAGS it can't carry are
 * kept.
 */
static void leave(XtThread *t, ARM64_NT_CONTEXT *n, bool context_exit)
{
    xt_publish(t, NULL);
    xt_ec_pack(t, n);
    if (context_exit) {
        aux_push(t, n->Sp, xt_ec_eflags(t->env));
    }
    if (xt_log_handle()) {
        xt_log_flush(t);
    }
}

/*
 * Inline in the entries (ec_run), as their run loop is: each call between
 * them is one per native call.  leave()'s, with the registers loaded
 * straight from the CPU state (xt_ec_exit_native_env).  DR6's
 * single-step and breakpoint bits have no place there, and end here as
 * xt_ec_pack ends them.
 */
static inline QEMU_ALWAYS_INLINE void leave_native_prep(XtThread *t)
{
    CPUX86State *env = t->env;

    xt_publish(t, NULL);
    if (env->dr[6] & (DR6_BS | 0xf)) {
        env->dr[6] = 0;
    }
    if (xt_log_handle()) {
        xt_log_flush(t);
    }
}

static inline QEMU_ALWAYS_INLINE G_NORETURN
void leave_native(XtThread *t, vaddr target)
{
    CPUX86State *env = t->env;

    leave_native_prep(t);
    if (unlikely(xt_stub_inject.point)) {
        xt_ec_exit_native_env_inj(env, target, xt_ec_ymm(t));
    }
    xt_ec_exit_native_env(env, target, xt_ec_ymm(t));
}

static G_NORETURN void leave_syscall(XtThread *t)
{
    XtKiFrame k;

    memset(&k.rec, 0, sizeof(k.rec));
    leave(t, &k.ctx, true);
    if (cross_process_work) {
        cross_process_work();
    }
    k.rec.ExceptionCode = STATUS_EMULATION_SYSCALL;
    xt_cpu_area(NtCurrentTeb())->InSimulation = 0;
    /* K is ntdll's from here: the engine's last access is behind. */
    xt_adm_exit(xt_gate_self());
    xt_ec_jump_set_stack(ki_exception_dispatcher, (uintptr_t)&k);
}

/*
 * A guest exception, raised with the packed context as x64 Windows
 * reports it: a fast fail second chance; a breakpoint at the int3.  The
 * int3 is raised with RIP past it, as x64 hardware leaves it: Windows
 * shows a debugger an x64 breakpoint's RIP one byte back, as x64's kernel
 * backs it up, but dispatches the context as raised, so the dispatch's
 * entry (ResetToConsistentState) backs it up there.
 */
static G_NORETURN void leave_exception(XtThread *t, XtExit *x)
{
    EXCEPTION_RECORD *r = &x->rec;
    ARM64_NT_CONTEXT n;
    BOOLEAN first = TRUE;

    switch (x->vector) {
    case -1:
        break;
    case EXCP03_INT3:
    case 0x2d:
        r->ExceptionCode = STATUS_BREAKPOINT;
        r->NumberParameters = 1;
        break;
    case 0x29:
        r->ExceptionCode = STATUS_STACK_BUFFER_OVERRUN;
        r->ExceptionFlags = EXCEPTION_NONCONTINUABLE;
        r->NumberParameters = 1;
        r->ExceptionInformation[0] = t->env->regs[R_ECX];
        first = FALSE;
        break;
    case 0x2c:
        t->env->eip -= 2;
        r->ExceptionCode = STATUS_ASSERTION_FAILURE;
        break;
    default:
        r->ExceptionCode = STATUS_ACCESS_VIOLATION;
        r->NumberParameters = 2;
        r->ExceptionInformation[1] = ~0ull;
        break;
    }
    if (r->ExceptionCode == STATUS_WX86_SINGLE_STEP) {
        r->ExceptionCode = STATUS_SINGLE_STEP;
    }
    r->ExceptionAddress = (void *)(uintptr_t)(t->env->eip -
                                              (x->vector == EXCP03_INT3));
    t->int3_rip = x->vector == EXCP03_INT3 ? t->env->eip : 0;
    leave(t, &n, true);
    xt_cpu_area(NtCurrentTeb())->InSimulation = 0;
    xt_adm_exit(xt_gate_self());
    xt_syscall((uintptr_t)r, (uintptr_t)&n, first, 0, 0, 0, nr_raise);
    NtTerminateProcess(GetCurrentProcess(), STATUS_ASSERTION_FAILURE);
    __builtin_unreachable();
}

/*
 * A suspension: continue at the guest's own context, consistent, where
 * Windows completes the suspension; resuming re-enters through
 * BeginSimulation.
 */
static G_NORETURN void leave_suspend(XtThread *t, XtEcFrame *f)
{
    ARM64_NT_CONTEXT n;

    leave(t, &n, true);
    qatomic_set(&f->doorbell, 0);
    f->inj_armed = 1;
    t->ec_suspended = true;
    xt_cpu_area(NtCurrentTeb())->InSimulation = 0;
    xt_adm_exit(xt_gate_self());
    xt_ec_continue_kept(&n, nr_continue);
    NtTerminateProcess(GetCurrentProcess(), STATUS_ASSERTION_FAILURE);
    __builtin_unreachable();
}

/* Every exit but a transfer to native code, with its XtExit. */
static G_NORETURN __attribute__((noinline))
void ec_leave(XtThread *t, XtEcFrame *f, int trapnr)
{
    XtExit x;

    xt_run_exit(t, trapnr, &x);
    switch (x.kind) {
    case XT_EXIT_SYSCALL:
        xt_event(t, XT_EV_SYSCALL, x.nr, 0);
        leave_syscall(t);
    case XT_EXIT_SUSPEND:
        leave_suspend(t, f);
    default:
        leave_exception(t, &x);
    }
}

/* The exit for xt_run_core's TRAPNR. */
static inline QEMU_ALWAYS_INLINE G_NORETURN
void ec_exit(XtThread *t, XtEcFrame *f, int trapnr)
{
    if (likely(trapnr == XT_EXCP_NATIVE)) {
        leave_native(t, t->native_target);
    }
    ec_leave(t, f, trapnr);
}

static inline QEMU_ALWAYS_INLINE G_NORETURN
void ec_run(XtThread *t, XtEcFrame *f)
{
    ec_exit(t, f, xt_run_core(t));
}

static __attribute__((noinline)) XtThread *ec_thread_first(void)
{
    XtThread *t = enter_engine();

    if (!t) {
        int s = qatomic_read(&engine_state);

        /* The log's status only once process_init failed opening it. */
        NtTerminateProcess(GetCurrentProcess(),
                           s == -2 ? STATUS_THREAD_IS_TERMINATING :
                           s == -1 && !xt_log_handle() && xt_log_status < 0 ?
                           xt_log_status : STATUS_NOT_SUPPORTED);
    }
    return t;
}

/*
 * The calling thread's record, from the CPU area once the engine is up
 * and the thread has one (enter_engine), else from the bring-up.
 */
static inline QEMU_ALWAYS_INLINE XtThread *ec_thread(void)
{
    XtThread *t = NULL;

    if (likely(qatomic_read(&engine_state) == 2)) {
        t = xt_cpu_area(NtCurrentTeb())->EmulatorData[0];
    }
    if (unlikely(!t)) {
        t = ec_thread_first();
    }
    t->activation++;
    return t;
}

/*
 * x-retalign: an entry from native code keeps the return stack in step.
 * A return resumes past the call that left for native code, whose entry
 * goes if it is on top.  A call pushes an entry with no landing for its
 * return address, so that the x64 callee's return to native code takes
 * that one and not an older entry.
 */
static void ec_retstack_entry(XtThread *t, const XtEcFrame *f)
{
    if (f->entry == XT_EC_ENTRY_RETURN) {
        tcg_retstack_pop_key(t->cpu, f->pc);
    } else if (f->entry == XT_EC_ENTRY_CALL) {
        tcg_retstack_push_key(t->cpu, f->lr);
    }
}

/*
 * The dispatch: an entry from native code whose first TB the jump cache
 * holds, and which leaves that TB for native code, runs without
 * cpu_exec's activation.  It takes the run loop's own steps
 * (accel/tcg/dispatch.h) and xt_run_core's, in their order, with the
 * activation's resources taken directly: the record's RCU reader, the
 * host FP state, cpu->jmp_env.  Anything else ends the activation where
 * cpu_exec would have ended, with the same work done, and goes on as
 * xt_run_core would from there (ec_dispatch_fallback).
 *
 * An entry is dispatched (ec_dispatch_ready) when it has nothing for
 * the run's preamble or cpu_exec's first steps to do: its registers in
 * the CPU state, the thread's reader registered, no termination or
 * suspension request, no breakpoint to step past (xt_ec_import_entry's
 * RF and bp_hit), no single step or breakpoints, no one-shot cflags or
 * pending exception, the selectors loaded, no diagnostics or execution
 * log.  It fails before anything is written, and the entry is
 * xt_ec_enter's as before.
 */
static inline QEMU_ALWAYS_INLINE bool ec_dispatch_ready(XtThread *t,
                                                        const XtEcFrame *f)
{
    CPUState *cs = t->cpu;
    CPUX86State *env = t->env;

    return likely(f->saved_to_env && t->rcu_reader &&
                  !qatomic_read(&t->terminating) &&
                  !qatomic_read(&t->suspend_req) &&
                  !(env->eflags & RF_MASK) &&
                  (!t->bp_hit || t->bp_hit != f->pc) &&
                  !cpu_single_stepping(cs) &&
                  QTAILQ_EMPTY(&cs->breakpoints) &&
                  cs->cflags_next_tb == -1 && cs->exception_index < 0 &&
                  !xt_diag &&
                  !qemu_loglevel_mask(CPU_LOG_TB_CPU | CPU_LOG_EXEC) &&
                  xt_ec_segs_loaded(t));
}

/* Out of the lazy flags, as cpu_exec's exit leaves them (x86_cpu_exec_exit). */
static inline QEMU_ALWAYS_INLINE void ec_dispatch_flags_out(CPUX86State *env)
{
    env->eflags = cpu_compute_eflags(env);
    env_archcpu(env)->eflags_in_tcg = false;
}

/*
 * The end of the activation: cpu_exec's, then xt_run_exec's.  With
 * KEEP_LAZY (x-ecfast's departure), the flags stay lazy and the host FP
 * state held.
 */
static inline QEMU_ALWAYS_INLINE void ec_dispatch_end_how(XtThread *t,
                                                          CPUState *cs,
                                                          CPUX86State *env,
                                                          bool keep_lazy)
{
    if (!keep_lazy) {
        ec_dispatch_flags_out(env);
        x86_host_fp_exit(env);
    }
    rcu_read_unlock_reader(t->rcu_reader);
    cpu_exec_end(cs);
    t->active = XT_ACT_NONE;
}

static inline QEMU_ALWAYS_INLINE void ec_dispatch_end(XtThread *t,
                                                      CPUState *cs,
                                                      CPUX86State *env)
{
    ec_dispatch_end_how(t, cs, env, false);
}

typedef enum EcFallback {
    EC_FB_MISS,     /* no TB to run here: the request check, then a run */
    EC_FB_TRAP,     /* cpu_exec's TRAPNR: the completion */
    EC_FB_RETRY,    /* a longjmp with no exception: cpu_exec again */
} EcFallback;

/*
 * After ec_dispatch_end: xt_run_core's remaining steps, from where the
 * activation ended, without the import or the preamble again (both are
 * done), then the exit for the trap number it returns.  A miss, before
 * or after a TB, is where cpu_exec would have looked further or
 * translated: the completion's request check, then xt_run_core.  A trap
 * number (a pending exception consumed, or a request found between TBs)
 * goes to the completion, with the fault's details intact.  A longjmp
 * without an exception (an SMC or crossing retry, with cflags_next_tb
 * kept) is cpu_exec's re-entry into its loop: the run, then the
 * completion.
 */
static G_NORETURN __attribute__((noinline))
void ec_dispatch_fallback(XtThread *t, XtEcFrame *f, EcFallback how,
                          int trapnr)
{
    CPUState *cs = t->cpu;

    switch (how) {
    case EC_FB_TRAP:
        if (xt_run_complete(t, cs, trapnr, false)) {
            ec_exit(t, f, trapnr);
        }
        break;
    case EC_FB_RETRY:
        trapnr = xt_run_exec(t, cs);
        if (xt_run_complete(t, cs, trapnr, false)) {
            ec_exit(t, f, trapnr);
        }
        break;
    default:
        if (qatomic_load_acquire(&cs->exit_request)) {
            qemu_process_cpu_events(cs);
        }
        break;
    }
    ec_run(t, f);
}

/*
 * The dispatch's round trip: xt_ec_enter's ownership and import, with
 * cpu_exec's entry into the lazy flags (xt_ec_import_engine); the
 * preamble's (a suspension request seen there leaves as the preamble
 * would); xt_run_exec's and cpu_exec's entry; the loop's request check
 * and the jump cache's TB; the TB, through the prologue; the loop's work
 * after it.  A TB that left for native code, by helper_lookup_tb_ptr's
 * exit (XT_EXCP_NATIVE) or by an exit slot to EC code (tb_lookup's
 * classification, ec_foreign_pc's, without the cache's miss), ends the
 * activation as cpu_exec and the completion do, then leaves.
 */
static G_NORETURN __attribute__((noinline))
void ec_dispatch(XtThread *t, XtEcFrame *f)
{
    CPUState *cs = t->cpu;
    CPUX86State *env = t->env;
    TranslationBlock *tb, *last_tb = NULL;
    uintptr_t ret;
    int tb_exit, trapnr;
    vaddr pc;

    t->ec_suspended = false;
    t->state = XT_ACQUIRING;
    xt_inject(t, XT_INJ_ACQUIRE);
    xt_ec_import_engine(t, f->pc, f->nzcv);
    t->state = XT_ENGINE;
    if (tcg_retalign) {
        ec_retstack_entry(t, f);
    }

    if (unlikely(qatomic_read(&t->suspend_req))) {
        ec_dispatch_flags_out(env);
        ec_leave(t, f, XT_EXCP_SUSPEND);
    }
    t->after_suspend = false;
    t->gfault.code = 0;

    t->active = XT_ACT_EXEC;
    cpu_exec_start(cs);
    if (!tcg_cpu_bound) {
        current_cpu = cs;
    }
    rcu_read_lock_reader(t->rcu_reader);
    x86_host_fp_enter(env);
    if (unlikely(sigsetjmp(cs->jmp_env, 0) != 0)) {
        cpu_exec_longjmp_cleanup(cs);
        if (cs->exception_index >= 0) {
            goto trap;
        }
        ec_dispatch_end(t, cs, env);
        ec_dispatch_fallback(t, f, EC_FB_RETRY, 0);
    }

    if (unlikely(cpu_exec_interrupted(cs, &last_tb))) {
        goto trap;
    }
    tb = cpu_exec_tb_cached(cs, cpu_exec_tb_state(cs));
    if (unlikely(!tb)) {
        goto miss;
    }
#ifdef CONFIG_DEBUG_TCG
    tcg_retstack_check(cs);
#endif
    qemu_thread_jit_execute();
    ret = tcg_qemu_tb_exec(env, tb->tc.ptr);
    cpu_exec_tb_done(cs, ret, &last_tb, &tb_exit);

    if (cs->exception_index >= 0 ||
        unlikely(cpu_exec_interrupted(cs, &last_tb))) {
        goto trap;
    }
    pc = env->hflags & HF_CS64_MASK ? env->eip
                                    : (uint32_t)(env->segs[R_CS].base +
                                                 env->eip);
    if (unlikely(cs->cflags_next_tb != -1)) {
        goto miss;
    }
    if (!xt_is_ec_code(pc)) {
        /*
         * Guest code, which cpu_exec runs: first the loop's link from
         * this exit to the TB the jump cache holds for it, which the loop
         * makes before running that TB and cpu_exec, entered afresh,
         * can't.  The next round trip goes on through the link.
         */
        if (last_tb) {
            TCGTBCPUState s = cpu_exec_tb_state(cs);

            /* A keyed exit links only to the TB with its key. */
            tb = cpu_exec_tb_keyed(cs, last_tb, tb_exit, s);
            if (!tb) {
                tb = cpu_exec_tb_cached(cs, s);
            }
            if (tb) {
                cpu_exec_tb_link(last_tb, tb_exit, tb);
            }
        }
        goto miss;
    }
    t->ec_seen = false;
    t->native_target = pc;

native:
    ec_dispatch_end(t, cs, env);
    if (qatomic_load_acquire(&cs->exit_request)) {
        qemu_process_cpu_events(cs);
    }
    leave_native(t, t->native_target);

trap:
    cpu_exec_exception(cs, &trapnr);
    if (likely(trapnr == XT_EXCP_NATIVE)) {
        goto native;
    }
    ec_dispatch_end(t, cs, env);
    ec_dispatch_fallback(t, f, EC_FB_TRAP, trapnr);

miss:
    ec_dispatch_end(t, cs, env);
    ec_dispatch_fallback(t, f, EC_FB_MISS, 0);
}

/*
 * x-ecinline: a TB that leaves for native code (a direct jump to EC code,
 * translator_use_foreign_call, or an indirect one, ec_foreign_goto) calls
 * out from inside the run (tcg_ec_callout_entry, permanent code beside
 * the epilogue), its state in env.  The call-out ends the activation as
 * ec_dispatch's exit to native code does, keeps the run's frames on the
 * emulator stack (the frame's resume_sp, where the next entry's C frames
 * go, below them), and leaves.  The next entry, if it is the return the
 * call-out recorded (ec_resume_ready), takes the activation back and goes
 * on in generated code at the return address, through the resume entry,
 * whose frame returns to the run's owner (cpu_exec or ec_dispatch) as any
 * TB does.  It takes nothing of the call's but the frame: the registers
 * are the entry's, the code the call's own return stack landing or a
 * fresh lookup, the ownership and the code buffer's generation checked
 * under ownership.  Any other entry discards the frame (ec_discard):
 * everything shared was published at the call-out, and the entry runs
 * from the stack's base.
 *
 * The host's return predictor stays in step: the call-out returns to its
 * stub, which jumps to native code (tcg_ec_leave_fn), and the resume
 * returns to entry_tail, which jumps to the resume entry, so that the
 * landing's return is predicted by the call that pushed it.
 *
 * The call-out declines (the stub then leaves through the epilogue to the
 * exit as before) where the boundary has work in hand: a fault
 * continuation, one-shot cflags, a frame already kept, or a request
 * pending.  A destination that is no longer native code declines with no
 * exit, so that the run looks it up as guest code.
 */
/*
 * x-ecfast: the host FP state is the guest's, in QEMU's own mode (MXCSR's
 * default control: guest_fpcr's HOST_FP_CONTROL_QEMU); the live FPCR is
 * that mode; the live FPSR.
 */
static inline QEMU_ALWAYS_INLINE bool ec_fp_default(CPUState *cs,
                                                    CPUX86State *env)
{
    return cs->host_fp_guest && !cs->host_fp_suspended &&
           !(env->mxcsr & 0xe040);
}

static inline QEMU_ALWAYS_INLINE bool ec_fpcr_default(void)
{
    return host_fp_control_read() == HOST_FP_CONTROL_QEMU;
}

/*
 * x-ecfast's resume in assembly (arm64ec.S's fast_resume) moves the
 * incoming registers straight into the ones the TBs hold them in, so it
 * is built for one placement: the general registers in
 * tcg_target_pin_regs in the x86 front end's pin order, XMM0-15's low
 * halves in v8-v23, nothing else pinned (it stores EIP and CC_OP to
 * env), and the return stack's top in x28 (tcg_ec_resume_fast_entry
 * loads it).  It runs only if the TBs use that placement, and only where
 * the C resume would have nothing more to do: current_cpu bound
 * (tcg_cpu_bound), the barriers process-wide (membarrier: none of its
 * own), the return stack's landings.
 */
static bool ec_fast_asm_ok(void)
{
    static const int8_t gpr[CPU_NB_REGS] = {
        [R_EAX] = TCG_REG_X21, [R_ECX] = TCG_REG_X25, [R_EDX] = TCG_REG_X24,
        [R_EBX] = TCG_REG_X23, [R_ESP] = TCG_REG_X20, [R_EBP] = TCG_REG_X9,
        [R_ESI] = TCG_REG_X27, [R_EDI] = TCG_REG_X22, [8] = TCG_REG_X14,
        [9] = TCG_REG_X12, [10] = TCG_REG_X13, [11] = TCG_REG_X15,
        [12] = TCG_REG_X26, [13] = TCG_REG_X11, [14] = TCG_REG_X8,
        [15] = TCG_REG_X10,
    };

#ifndef CONFIG_MEMBARRIER
    return false;
#endif
    if (!tcg_ecfast || !tcg_ecinline || !tcg_retalign || !tcg_cpu_bound ||
        xt_diag || xt_log_handle() || xt_stub_inject.point ||
        tcg_retstack_reg != TCG_REG_X28 || !tcg_ec_resume_fast_entry ||
        tcg_pinned_reg(offsetof(CPUX86State, eip)) >= 0 ||
        tcg_pinned_reg(offsetof(CPUX86State, cc_op)) >= 0) {
        return false;
    }
    for (int i = 0; i < CPU_NB_REGS; i++) {
        if (tcg_pinned_reg(offsetof(CPUX86State, regs[i])) != gpr[i] ||
            tcg_pinned_reg(offsetof(CPUX86State, xmm_regs[i].ZMM_X(0))) !=
            TCG_REG_V8 + i) {
            return false;
        }
    }
    return true;
}

/*
 * x-ecfast's departure: what the resume in assembly needs, if it can take
 * the return (else fr_key 0, and the C resume does): the return stack's
 * top entry with its landing (the return's key, as the C resume's
 * tcg_retstack_take_landing takes it), and no single step or breakpoint,
 * which the C resume handles.
 */
static inline QEMU_ALWAYS_INLINE void ec_fast_frame(XtThread *t,
                                                    CPUState *cs,
                                                    XtEcFrame *f,
                                                    uint64_t rsp)
{
    uint64_t *lo, *hi;

    f->fr_key = 0;
    if (!xt_ec_fast_asm || cpu_single_stepping(cs) ||
        !QTAILQ_EMPTY(&cs->breakpoints)) {
        return;
    }
    f->fr_land = tcg_retstack_peek_landing(cs, &f->fr_key, &f->fr_slot,
                                           &f->fr_next, &lo, &hi);
    if (!f->fr_land) {
        f->fr_key = 0;
        return;
    }
    f->fr_rsp = rsp + 8;
    f->fr_flush = t->co_flush;
    f->fr_t = t;
    f->fr_cs = cs;
    f->fr_reader = t->rcu_reader;
    f->fr_lo = lo;
    f->fr_hi = hi;
}

/*
 * x-ecfast's departure in assembly (arm64ec.S's xt_ec_fast_depart), once
 * ownership's fast parts are given back, where they found a writer
 * waiting for the RCU reader or an exclusive section pending: the
 * release's tails, in rcu_read_unlock_reader's then cpu_exec_end's order.
 */
void xt_ec_fast_depart_tail(XtThread *t, unsigned tails)
{
    qatomic_inc(&ec_fast_tails[tails]);
    if (tails & XT_EC_TAIL_RCU) {
        rcu_read_unlock_finish(t->rcu_reader);
    }
    if (tails & XT_EC_TAIL_EXCL) {
        cpu_exec_end_finish(t->cpu);
    }
}

static TCGEcCallout ec_callout(uintptr_t sp, void *envp)
{
    CPUX86State *env = envp;
    CPUState *cs = env_cpu(env);
    XtThread *t = cs->opaque;
    XtEcFrame *f = xt_cpu_area(NtCurrentTeb())->EmulatorData[1];
    uint64_t target = env->eip;
    uint64_t rsp = env->regs[R_ESP];

    /*
     * A direct jump's destination was native code when it was translated;
     * if it is the guest's now (its allocation freed and reused), its
     * lookup, as any other TB's exit.
     */
    if (unlikely(!xt_is_ec_code(target))) {
        t->ec_seen = false;
        cs->exception_index = -1;
        return (TCGEcCallout){ 0, 0 };
    }
    t->native_target = target;
#ifdef CONFIG_DEBUG_TCG
    /* Neither is held at a TB boundary. */
    assert(!have_mmap_lock() && !tb_gen_active() && !helper_retaddr);
#endif
    if (!tcg_ecinline || f->resume_sp || t->fault.busy ||
        cs->cflags_next_tb != -1 || qatomic_read(&t->suspend_req) ||
        qatomic_read(&cs->exit_request) ||
        qatomic_read(&cs->neg.icount_decr.u16.high)) {
        cs->exception_index = XT_EXCP_NATIVE;
        return (TCGEcCallout){ 0, 0 };
    }
    t->ec_seen = false;
    t->co_rsp = rsp;
    t->co_flush = qatomic_read(&tb_ctx.tb_flush_count);
    cs->exception_index = -1;
    cs->neg.can_do_io = true;
    /*
     * x-ecfast: with the default FP control the guest's FP mode is QEMU's
     * own, so the host FP state stays held across the call, and the flags
     * stay lazy: the return takes them from the incoming state.
     */
    if (tcg_ecfast && ec_fp_default(cs, env) && xt_ec_segs_loaded(t)) {
        f->dep_fpsr = host_fp_status_read();
        f->resume_kind = XT_EC_KEPT_FAST;
        ec_fast_frame(t, cs, f, rsp);
        ec_dispatch_end_how(t, cs, env, true);
        f->resume_sp = sp;
        leave_native_prep(t);
        /* The release's tails are C: FPSR as it was, the guest's. */
        host_fp_status_write(f->dep_fpsr);
        /* Neither YMM's upper halves nor MMX: volatile across a call. */
        return (TCGEcCallout){ target, 2 };
    }
    f->resume_kind = XT_EC_KEPT_C;
    f->fr_key = 0;
    ec_dispatch_end(t, cs, env);
    f->resume_sp = sp;
    leave_native_prep(t);
    return (TCGEcCallout){ target, xt_ec_ymm(t) };
}

/*
 * A kept frame of x-ecfast's (XT_EC_KEPT_FAST) at an entry that doesn't
 * resume it fast: the host FP state released, folding FPSR as the caller
 * gives it (the thread's own, at an entry; the departure's, where the
 * entry has no FP state of its own), so that C finds it as ec_callout
 * leaves it.  The flags need nothing: every entry takes them from its
 * incoming state.
 */
static void ec_frame_normalize(XtThread *t, XtEcFrame *f, uint64_t fpsr)
{
    if (f->resume_kind == XT_EC_KEPT_FAST) {
        x86_host_fp_exit_fpsr(t->env, fpsr);
        f->resume_kind = XT_EC_KEPT_C;
        f->fr_key = 0;
    }
}

/* A kept frame no longer resumable: its ring entries are the abandoned. */
static void ec_discard(XtThread *t, XtEcFrame *f)
{
    ec_frame_normalize(t, f, host_fp_status_read());
    f->resume_sp = 0;
    f->resume_kind = XT_EC_KEPT_C;
    f->fr_key = 0;
    if (tcg_retalign) {
        tcg_retstack_settle(t->cpu);
    }
}

/*
 * No request pending and the code buffer the call-out's: ec_resume's
 * check, under ownership (cpu_exec_start may have waited for a flush).
 */
static inline QEMU_ALWAYS_INLINE bool ec_resume_clear(XtThread *t,
                                                      CPUState *cs)
{
    return !qatomic_read(&t->suspend_req) && !qatomic_read(&t->terminating) &&
           !qatomic_read(&cs->exit_request) &&
           !qatomic_read(&cs->neg.icount_decr.u16.high) &&
           !cs->interrupt_request && cs->cflags_next_tb == -1 &&
           cs->exception_index < 0 &&
           qatomic_read(&tb_ctx.tb_flush_count) == t->co_flush;
}

/*
 * The entry looks like the call-out's return (a return, RSP past the
 * return address the call left on top), with nothing for the entry's
 * work to do (ec_dispatch_ready).  A false match is a fresh entry that
 * reuses the frame: the resume takes the entry's registers and its own
 * lookup, and a landing only if its key is the return address.
 */
static inline QEMU_ALWAYS_INLINE bool ec_resume_ready(XtThread *t,
                                                      const XtEcFrame *f)
{
    return f->entry == XT_EC_ENTRY_RETURN &&
           t->env->regs[R_ESP] == t->co_rsp + 8 && ec_dispatch_ready(t, f);
}

static G_NORETURN void ec_enter(XtThread *t, XtEcFrame *f);

/* After a discard: the entry again, from the emulator stack's base. */
static G_NORETURN void ec_enter_based(void)
{
    XtCpuArea *area = xt_cpu_area(NtCurrentTeb());

    ec_enter(area->EmulatorData[0], area->EmulatorData[1]);
    __builtin_unreachable();
}

static G_NORETURN __attribute__((noinline))
void ec_rebase(XtThread *t, XtEcFrame *f)
{
    ec_discard(t, f);
    xt_ec_jump_set_stack((uintptr_t)ec_enter_based,
                         xt_cpu_area(NtCurrentTeb())->EmulatorStackBase);
}

/*
 * The resume: ec_dispatch's acquisition, cpu_exec_start then RCU, the
 * checks under ownership (a failure gives back exactly what was taken,
 * then the entry goes on as any other, discarding the frame), then the
 * import into the engine's format and the code for the return address:
 * the call's landing, if the return stack's top is its push, else the
 * jump cache's TB (a miss: the epilogue, which returns zero to the
 * frame's owner).  It returns that for entry_tail.
 */
/* The resume's checks failed under ownership: all of it given back. */
static G_NORETURN void ec_resume_decline(XtThread *t, XtEcFrame *f)
{
    rcu_read_unlock_reader(t->rcu_reader);
    cpu_exec_end(t->cpu);
    t->active = XT_ACT_NONE;
    t->state = XT_WINDOWS;
    ec_rebase(t, f);
}

static uintptr_t ec_resume_owned(XtThread *t, XtEcFrame *f);

static __attribute__((noinline)) uintptr_t ec_resume(XtThread *t,
                                                     XtEcFrame *f)
{
    CPUState *cs = t->cpu;
    /*
     * x-ecfast's kept frame: FPSR is the guest's, held, and what C does
     * here (cpu_exec_start's tail) mustn't reach it.
     */
    bool fast = f->resume_kind == XT_EC_KEPT_FAST;
    uint64_t fpsr = fast ? host_fp_status_read() : 0;
    uintptr_t code;

    t->ec_suspended = false;
    t->state = XT_ACQUIRING;
    xt_inject(t, XT_INJ_ACQUIRE);
    t->active = XT_ACT_EXEC;
    cpu_exec_start(cs);
    if (!tcg_cpu_bound) {
        current_cpu = cs;
    }
    rcu_read_lock_reader(t->rcu_reader);
    if (unlikely(!ec_resume_clear(t, cs))) {
        ec_frame_normalize(t, f, fpsr);
        ec_resume_decline(t, f);
    }
    code = ec_resume_owned(t, f);
    if (fast) {
        host_fp_status_write(fpsr);
    }
    return code;
}

/*
 * x-ecfast's resume in assembly where it can't finish, the entry's state
 * captured as entry_tail captures it (all but FPSR, the guest's, kept
 * here), on the emulator stack below the kept frame, ownership taken so
 * far (the activation counted, the state XT_ACQUIRING, cpu->running
 * set): with an exclusive section pending at cpu_exec_start
 * (XT_EC_FAST_START), its tail, then the rest of ec_resume; with a
 * request or a flush found under ownership (XT_EC_FAST_CLEAR, the RCU
 * read section taken too), the frame normalized with the guest's FPSR,
 * ownership given back, and the entry goes on as any other.  It returns
 * what ec_resume returns, for entry_tail.
 */
uintptr_t xt_ec_fast_slow(XtEcFrame *f, int why)
{
    /* The guest's, held: what C does here mustn't reach it. */
    uint64_t fpsr = host_fp_status_read();
    XtThread *t = f->fr_t;
    uintptr_t code;

    qatomic_inc(&ec_fast_slows[why]);
    if (why == XT_EC_FAST_START) {
        cpu_exec_start_finish(t->cpu);
        rcu_read_lock_reader(t->rcu_reader);
        if (likely(ec_resume_clear(t, t->cpu))) {
            code = ec_resume_owned(t, f);
            host_fp_status_write(fpsr);
            return code;
        }
    }
    ec_frame_normalize(t, f, fpsr);
    ec_resume_decline(t, f);
}

/*
 * The resume under ownership: the frame consumed, the import, and the
 * code for the return address.
 */
static uintptr_t ec_resume_owned(XtThread *t, XtEcFrame *f)
{
    CPUState *cs = t->cpu;
    CPUX86State *env = t->env;
    uintptr_t code = 0;
    TranslationBlock *tb;
    bool fast = f->resume_kind == XT_EC_KEPT_FAST;

    f->resume_go = f->resume_sp;
    f->resume_sp = 0;
    f->resume_kind = XT_EC_KEPT_C;
    f->fr_key = 0;
    if (fast) {
        xt_ec_import_fast(t, f->pc, f->nzcv);
    } else {
        xt_ec_import_engine(t, f->pc, f->nzcv);
    }
    t->state = XT_ENGINE;
    if (tcg_retalign) {
        /* The call's own landing, the return it predicts. */
        code = tcg_retstack_take_landing(cs, f->pc);
        if (code) {
            code |= 1;
        }
    }
    t->after_suspend = false;
    t->gfault.code = 0;
    /* x-ecfast's departure kept the host FP state (ec_enter_kept). */
    if (!fast) {
        x86_host_fp_enter(env);
    }
    if (!code) {
        tb = cpu_exec_tb_cached(cs, cpu_exec_tb_state(cs));
        code = tb ? (uintptr_t)tb->tc.ptr : 0;
    }
    qemu_thread_jit_execute();
    return code;
}

/*
 * An entry with a kept frame: the resume, which returns where entry_tail
 * goes on (tcg_ec_resume_entry), so that the calls on the way are
 * returned from; else a discard first.
 */
/*
 * x-ecfast's kept frame, resumable as it was left: the call's own return
 * (a return, RSP past the return address), no single step coming in, the
 * host FP state still the guest's default (native code may have changed
 * the control), and none of what can change while native code runs: the
 * remote requests, a flush, single stepping or a breakpoint set, the
 * one-shot cflags or a pending exception.  The selectors were as an
 * entry loads them at the departure (ec_callout's x-ecfast branch); what
 * else ec_dispatch_ready asks of a fresh entry (RF, bp_hit, the reader,
 * diagnostics, the log) only C paths change, and those enter by
 * discarding the frame.  ec_resume checks the
 * requests again under ownership.
 */
static inline QEMU_ALWAYS_INLINE bool ec_fast_resume_ready(XtThread *t,
                                                           const XtEcFrame *f)
{
    CPUState *cs = t->cpu;

    return f->entry == XT_EC_ENTRY_RETURN && !(f->nzcv & (1u << 21)) &&
           t->env->regs[R_ESP] == t->co_rsp + 8 && ec_fpcr_default() &&
           !qatomic_read(&t->suspend_req) && !qatomic_read(&t->terminating) &&
           !qatomic_read(&cs->exit_request) &&
           !qatomic_read(&cs->neg.icount_decr.u16.high) &&
           cs->cflags_next_tb == -1 && cs->exception_index < 0 &&
           !cpu_single_stepping(cs) && QTAILQ_EMPTY(&cs->breakpoints) &&
           qatomic_read(&tb_ctx.tb_flush_count) == t->co_flush;
}

static __attribute__((noinline)) uintptr_t ec_enter_kept(XtThread *t,
                                                         XtEcFrame *f)
{
    /*
     * x-ecfast's kept frame resumes as it was left (ec_fast_resume_ready);
     * else it is normalized first, so the resume or the discard finds it
     * as ec_callout leaves it.
     */
    if (f->resume_kind == XT_EC_KEPT_FAST) {
        if (likely(ec_fast_resume_ready(t, f))) {
            return ec_resume(t, f);
        }
        ec_frame_normalize(t, f, host_fp_status_read());
    }
    if (ec_resume_ready(t, f)) {
        return ec_resume(t, f);
    }
    ec_rebase(t, f);
}

/*
 * Testing (cacheselftest): the cache's guarded routines, once, on the
 * first thread to finish an acquisition, in the engine's state.  A
 * thread's first entry is never dispatched (ec_dispatch_ready: its reader
 * isn't registered yet), so the first acquisition comes through here.
 */
static void __attribute__((noinline)) ec_cache_selftest_once(void)
{
    if (qatomic_xchg(&cache_selftest, false)) {
        xt_cache_selftest();
    }
}

static inline QEMU_ALWAYS_INLINE void ec_cache_selftest(void)
{
    if (unlikely(qatomic_read(&cache_selftest))) {
        ec_cache_selftest_once();
    }
}

/*
 * A call, jump or return into x64 code (ExitToX64, DispatchJump,
 * RetToEntryThunk in arm64ec.S), with F's record of it: the x64 registers
 * are in the CPU state already, or, where the frame had none to name (a
 * thread's first entry, whose record ec_thread creates), in their ARM64EC
 * places in F; the return address on the stack already.  The record says
 * which, whatever exists by now.
 */
static G_NORETURN void ec_enter(XtThread *t, XtEcFrame *f)
{
    if (ec_dispatch_ready(t, f)) {
        ec_dispatch(t, f);
    }
    t->ec_suspended = false;
    xt_acquire_begin(t);
    if (likely(f->saved_to_env)) {
        xt_ec_import_entry(t, f->pc, f->nzcv);
    } else {
        xt_ec_import_call(t, &f->ctx, f->pc, f->nzcv);
    }
    xt_acquire_end(t);
    ec_cache_selftest();
    if (tcg_retalign) {
        ec_retstack_entry(t, f);
    }
    ec_run(t, f);
}

uintptr_t xt_ec_enter(XtEcFrame *f)
{
    XtThread *t = ec_thread();

    if (unlikely(f->resume_sp)) {
        return ec_enter_kept(t, f);
    }
    ec_enter(t, f);
}

/*
 * Windows treats a thread as consistent from KiUserEmulationDispatcher's
 * entry until CpuDispatchEmulation sets InSimulation: on the guest stack,
 * the x64 state still in the native context there, from which the AMD64
 * context is converted.  A suspension in that window reads and writes the
 * native registers, so an edit made then reaches BeginSimulation only in
 * the registers the dispatcher keeps (saved in the frame by
 * BeginSimulation): R12-R15, RBX, RSI and RDI.  A suspension's
 * continuation loads them from its context (xt_ec_continue_kept), and
 * native code keeps them up to BeginSimulation, so they differ from the
 * AMD64 context only by such an edit, and are taken from there.  An edit
 * to any other register in the window is lost (under Prism too).
 */
static void ec_window_edits(const ARM64_NT_CONTEXT *kept, CONTEXT *c)
{
    c->R12 = kept->X19;
    c->R13 = kept->X20;
    c->R14 = kept->X21;
    c->R15 = kept->X22;
    c->Rsi = kept->X25;
    c->Rdi = kept->X26;
    c->Rbx = kept->X27;
}

/*
 * KiUserEmulationDispatcher's entry, after a continuation at x64 code:
 * the CPU area's AMD64 context is authoritative, with what the packed
 * form couldn't carry from the exit it continues (the one at the same
 * RSP; a handler may move RIP past a faulting instruction): EFLAGS but
 * NZCV and TF.  The YMM upper halves come from its extended part, which
 * Windows fills from the continued context; v16-v31 hold nothing here
 * after a system call.  ST0-ST7 (MM0-MM7) come from its FltSave, which
 * Windows fills from the packed form's places for them; their control,
 * status and tag words stay the engine's, as Windows carries none.
 */
#define MXCSR_CARRIED 0xe03f
void xt_ec_begin(void)
{
    XtCpuArea *area = xt_cpu_area(NtCurrentTeb());
    XtThread *t = ec_thread();
    const CONTEXT *w = (const CONTEXT *)area->ContextAmd64;
    const uint32_t nzcv = CC_S | CC_Z | CC_C | CC_O | TF_MASK;
    uint32_t kept;
    CONTEXT c;

    if (unlikely(((XtEcFrame *)area->EmulatorData[1])->resume_sp)) {
        XtEcFrame *f = area->EmulatorData[1];

        /*
         * The dispatcher's FPSR isn't the guest's: the departure's is (an
         * MXCSR the context carries is imported after, as an edit).
         */
        ec_frame_normalize(t, f, f->dep_fpsr);
        ec_discard(t, f);
    }
    if (cross_process_work) {
        cross_process_work();
    }

    memset(&c, 0, sizeof(c));
    xt_export(t, &c);
    if ((w->ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER) {
        memcpy(&c.Rax, &w->Rax, 16 * sizeof(c.Rax));
        if (t->ec_suspended) {
            ec_window_edits(&((XtEcFrame *)area->EmulatorData[1])->ctx, &c);
        }
    }
    t->ec_suspended = false;
    if ((w->ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL) {
        c.Rip = w->Rip;
        c.Rsp = w->Rsp;
        c.Rbp = w->Rbp;
        c.SegCs = w->SegCs;
        c.SegSs = w->SegSs;
        c.EFlags = w->EFlags;
        if (aux_take(t, w->Rsp, &kept)) {
            c.EFlags = (kept & ~nzcv) | (w->EFlags & nzcv);
        }
    }
    if ((w->ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS) {
        c.SegDs = w->SegDs;
        c.SegEs = w->SegEs;
        c.SegFs = w->SegFs;
        c.SegGs = w->SegGs;
    }
    if ((w->ContextFlags & CONTEXT_FLOATING_POINT) ==
        CONTEXT_FLOATING_POINT) {
        /*
         * MXCSR's rounding, flush-to-zero and flags travel (as FPCR and
         * FPSR); changed there, they are an edit.  Its exception masks
         * and DAZ don't, and stay the engine's.
         */
        uint32_t edited = MXCSR_CARRIED & (w->MxCsr ^ c.MxCsr);

        memcpy(c.FltSave.FloatRegisters, w->FltSave.FloatRegisters,
               sizeof(c.FltSave.FloatRegisters));
        memcpy(c.FltSave.XmmRegisters, w->FltSave.XmmRegisters,
               sizeof(c.FltSave.XmmRegisters));
        if (edited) {
            c.MxCsr = (c.MxCsr & ~MXCSR_CARRIED) |
                      (w->MxCsr & MXCSR_CARRIED);
            c.FltSave.MxCsr = c.MxCsr;
        }
    }
    c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS |
                     CONTEXT_FLOATING_POINT;
    if ((w->ContextFlags & CONTEXT_DEBUG_REGISTERS) ==
        CONTEXT_DEBUG_REGISTERS) {
        c.ContextFlags |= CONTEXT_DEBUG_REGISTERS;
        c.Dr0 = w->Dr0;
        c.Dr1 = w->Dr1;
        c.Dr2 = w->Dr2;
        c.Dr3 = w->Dr3;
        c.Dr7 = w->Dr7;
    }
    area->InSimulation = 1;
    xt_acquire_begin(t);
    xt_import(t, &c);
    if (xt_ec_ymm(t)) {
        xt_ec_import_ymm(t, w);
    }
    xt_acquire_end(t);
    ec_cache_selftest();
    ec_run(t, (XtEcFrame *)area->EmulatorData[1]);
}

/*
 * The test harness: an ARM64EC process loads the module and drives one
 * engine thread per calling thread with contexts it passes, as P1's
 * native harness does.  Faults reach a vectored handler with the x64 view
 * of the native context (ARM64EC_NT_CONTEXT), which has no x13, x14, x23,
 * x24, x28 or v16-v31.  That is enough for a fault in a helper, which is
 * ARM64EC code, below generated code that keeps nothing in those across
 * the call; a retried fault in generated code needs the module's own
 * entry (ResetToConsistentState), which sees the full native context.
 */
struct XtEcTestExit {
    int kind;
    int trapnr;
    uint32_t code;
    uint64_t addr, info0, info1;
};

static void from_ec_view(const ARM64EC_NT_CONTEXT *ec, ARM64_NT_CONTEXT *n)
{
    uint32_t f = ec->AMD64_EFlags;

    memset(n, 0, sizeof(*n));
    n->ContextFlags = CONTEXT_ARM64_FULL;
    n->X0 = ec->X0;
    n->X1 = ec->X1;
    n->X2 = ec->X2;
    n->X3 = ec->X3;
    n->X4 = ec->X4;
    n->X5 = ec->X5;
    n->X6 = ec->X6;
    n->X7 = ec->X7;
    n->X8 = ec->X8;
    n->X9 = ec->X9;
    n->X10 = ec->X10;
    n->X11 = ec->X11;
    n->X12 = ec->X12;
    n->X15 = ec->X15;
    n->X16 = (uint64_t)ec->X16_3 << 48 | (uint64_t)ec->X16_2 << 32 |
             (uint64_t)ec->X16_1 << 16 | ec->X16_0;
    n->X17 = (uint64_t)ec->X17_3 << 48 | (uint64_t)ec->X17_2 << 32 |
             (uint64_t)ec->X17_1 << 16 | ec->X17_0;
    n->X19 = ec->X19;
    n->X20 = ec->X20;
    n->X21 = ec->X21;
    n->X22 = ec->X22;
    n->X25 = ec->X25;
    n->X26 = ec->X26;
    n->X27 = ec->X27;
    n->Fp = ec->Fp;
    n->Lr = ec->Lr;
    n->Sp = ec->Sp;
    n->Pc = ec->Pc;
    /* NZCV from SF, ZF, CF and OF, as Windows maps them. */
    n->Cpsr = (f & 0x80 ? 1u << 31 : 0) | (f & 0x40 ? 1u << 30 : 0) |
              (f & 0x01 ? 1u << 29 : 0) | (f & 0x800 ? 1u << 28 : 0);
    memcpy(n->V, ec->V, sizeof(ec->V));
{
        uint64_t fpcr, fpsr;

        asm volatile("mrs %0, fpcr" : "=r"(fpcr));
        asm volatile("mrs %0, fpsr" : "=r"(fpsr));
        n->Fpcr = fpcr;
        n->Fpsr = fpsr;
    }
}

static LONG CALLBACK xt_ec_veh(EXCEPTION_POINTERS *p)
{
    ARM64EC_NT_CONTEXT *ec = (ARM64EC_NT_CONTEXT *)p->ContextRecord;
    ARM64_NT_CONTEXT n;

    from_ec_view(ec, &n);
    if (!xt_fault_redirect(p->ExceptionRecord, &n)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    /* The continuation's entry: what xt_fault_redirect changed. */
    ec->X0 = n.X0;
    ec->X1 = n.X1;
    ec->Lr = n.Lr;
    ec->Sp = n.Sp;
    ec->Pc = n.Pc;
    NtContinue(p->ContextRecord, FALSE);
    return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * The native harness: its vectored handler sees faults through the x64
 * view (from_ec_view), and its threads run generated code without the
 * cooperative suspension, so pinning stays off (xt_fault_context_partial)
 * unless XTAJIT_HARNESS_PIN is set, for runs that neither fault nor meet
 * an asynchronous context operation (timing the generated code).
 */
static bool harness_pin(void)
{
    WCHAR w[8];
    SIZE_T n = 0;

    return RtlQueryEnvironmentVariable(NULL, L"XTAJIT_HARNESS_PIN", 18, w,
                                       ARRAY_SIZE(w) - 1, &n) >= 0 && n;
}

XTEXPORT int xt_ec_test_init(int *rejected)
{
    /* Its contexts have no place for the YMM upper halves. */
    if (xt_cpu_avx()) {
        return -1;
    }
    xt_fault_context_partial = !harness_pin();
    xt_native_harness = true;
    xt_diag = true;
    if (!init_syscalls() || process_init() < 0) {
        return -1;
    }
    qatomic_set(&engine_state, 2);
    RtlAddVectoredExceptionHandler(1, xt_ec_veh);
    *rejected = init_rejected;
    return init_applied;
}

XTEXPORT void *xt_ec_test_thread(void)
{
    XtThread *t = xt_self ? xt_self : xt_thread_new(false);

    t->stop_at_int3 = true;
    t->cpu->opaque = t;
    return t;
}

XTEXPORT int xt_ec_test_run(CONTEXT *ctx, XtEcTestExit *out)
{
    XtThread *t = xt_self;
    XtExit x;

    t->activation++;
    xt_acquire(t, ctx);
    xt_run(t, &x);
    xt_publish(t, ctx);
    memset(out, 0, sizeof(*out));
    out->kind = x.kind;
    out->trapnr = x.trapnr;
    if (x.kind == XT_EXIT_EXCEPTION) {
        out->code = x.rec.ExceptionCode;
        out->addr = (uintptr_t)x.rec.ExceptionAddress;
        out->info0 = x.rec.ExceptionInformation[0];
        out->info1 = x.rec.ExceptionInformation[1];
    }
    return x.kind;
}

/* TCG's code buffer: Windows must count it as EC code. */
XTEXPORT void *xt_ec_test_code_buffer(void)
{
    return tcg_ctx->code_gen_buffer;
}

/*
 * Write code for the harness: QEMU's write protection of translated pages
 * comes off first (page_unprotect, as for a guest write, which also drops
 * their translations).
 */
XTEXPORT void xt_ec_test_load(void *dst, const void *src, size_t len)
{
    uintptr_t p = (uintptr_t)dst & TARGET_PAGE_MASK;

    mmap_lock();
    for (; p < (uintptr_t)dst + len; p += TARGET_PAGE_SIZE) {
        if (page_get_flags(p) & PAGE_WRITE_ORG) {
            page_unprotect(NULL, p, 0);
        }
    }
    memcpy(dst, src, len);
    mmap_unlock();
    xt_invalidate((uintptr_t)dst, len);
}

/*
 * A thread-local variable larger than a root's storage, page-aligned and
 * with an initial value, for the harness to check from many threads at
 * once (emutls.c): 1 if this thread's copy is aligned, holds the initial
 * value at its first use and stays the thread's own.  With REAP 1: the
 * roots left after a sweep of the ended threads' instead; 2: the sweep
 * alone (the count is safe only while nothing else sweeps).
 */
static __thread uint8_t test_tls[80 * KiB] __attribute__((aligned(4096))) = {
    0x5a, 0xa5,
};

XTEXPORT int xt_ec_test_tls(int reap)
{
    /* The TEB's own address tells threads apart. */
    uintptr_t tid = (uintptr_t)NtCurrentTeb();
    uint8_t *p;

    if (reap) {
        xt_emutls_reap();
        return reap == 1 ? xt_emutls_roots() : 0;
    }
    /* The variable's first use, by the harness's threads at once. */
    p = test_tls;
    if ((uintptr_t)p & 4095) {
        return -1;
    }
    if (p[0] != 0x5a || p[1] != 0xa5 || p[2] || p[sizeof(test_tls) - 1]) {
        return -2;
    }
    memcpy(p + 2, &tid, sizeof(tid));
    NtYieldExecution();
    if (test_tls != p || memcmp(p + 2, &tid, sizeof(tid))) {
        return -3;
    }
    return 1;
}

/* The emulated TLS's test hooks (xt_emutls_test). */
XTEXPORT long xt_ec_test_tls_hook(int what, long arg)
{
    return xt_emutls_test(what, arg);
}

/* A thread-local variable's access, ARG times, for its cost. */
static __thread long test_tls_count;

static __attribute__((noinline)) void test_tls_touch(void)
{
    test_tls_count++;
}

static long test_global_count;

static __attribute__((noinline)) void test_global_touch(void)
{
    qatomic_set(&test_global_count, test_global_count + 1);
}

XTEXPORT long xt_ec_test_tls_cost(int tls, long n)
{
    for (long i = 0; i < n; i++) {
        if (tls) {
            test_tls_touch();
        } else {
            test_global_touch();
        }
    }
    return tls ? test_tls_count : test_global_count;
}

/* Drop translations of a range the harness rewrote. */
XTEXPORT void xt_ec_test_invalidate(void *addr, size_t len)
{
    xt_invalidate((uintptr_t)addr, len);
}

/* Process-wide counts: faults continued, translations flushed. */
XTEXPORT void xt_ec_test_counts(uint32_t *faults, uint32_t *flushes)
{
    *faults = xt_fault_count();
    *flushes = qatomic_read(&tb_ctx.tb_flush_count);
}

/* What init found: the direct system calls' numbers, the checker's table. */
XTEXPORT void xt_ec_test_syscalls(int64_t nr[4], uint32_t *lut_size)
{
    nr[0] = nr_continue;
    nr[1] = nr_raise;
    nr[2] = nr_alloc;
    nr[3] = nr_protect;
    *lut_size = xt_ntdll_lut_size;
}

/* The entries ntdll made: bits 6-8 as xt_ec_entry_stub reports them. */
XTEXPORT uint32_t xt_ec_test_reached(void)
{
    return reached;
}

/*
 * A notification's halves (arm64ec-gate.c): the first, entered as an
 * attempt (not as a callback of the engine's own work), leaves its
 * operation on the gate for the second, which claims it as it enters, and
 * releases it once its work is done.
 */
static uint32_t ec_half_enter(XtGate *g, BOOL after, uint32_t kind,
                              const void *addr, SIZE_T len, int *claimed)
{
    if (after) {
        *claimed = xt_adm_enter_claim(g, kind, (uintptr_t)addr, len);
        return 0;
    }
    *claimed = -1;
    return xt_adm_enter(g);
}

static void ec_half_exit(XtGate *g, uint32_t level, int claimed,
                         uint32_t kind, const void *addr, SIZE_T len)
{
    if (level & XT_ADM_ATTEMPT) {
        xt_root_push(g, kind, (uintptr_t)addr, len);
    }
    if (claimed >= 0) {
        xt_root_release(g, claimed);
    }
    xt_adm_exit(g);
    if (level & XT_ADM_ATTEMPT) {
        XT_TP(XT_TP_HALF_EXITED, g, kind);
    }
}

/*
 * Windows' calls into the module during a native call (the notifications,
 * the flush notices, termination): with x-ecfast's kept frame
 * (XT_EC_KEPT_FAST) the guest's host FP state is still held, and the
 * module's own exception flags mustn't join the guest's, so each gives
 * FPSR back as it found it.
 */
static inline void ec_fpsr_restore(uint64_t *fpsr)
{
    host_fp_status_write(*fpsr);
}

#define EC_FPSR_GUARD()                                                      \
    uint64_t ec_fpsr_saved __attribute__((cleanup(ec_fpsr_restore))) =      \
        host_fp_status_read()

/*
 * Windows' calls into the module: each runs inside a level of its own on
 * the thread's admission word (arm64ec-gate.c), entered before anything
 * else and left on its way out, so that a thread inside one is never
 * taken as idle, and one entered once the process's end has closed the
 * gate parks before it does anything.
 */

XTEXPORT NTSTATUS ProcessInit(void)
{
    XtGate *g = xt_gate_self();
    NTSTATUS r;

    xt_adm_enter(g);
    r = ec_process_init();
    xt_adm_exit(g);
    return r;
}

XTEXPORT NTSTATUS ThreadInit(void)
{
    XtGate *g = xt_gate_self();
    NTSTATUS r;

    xt_adm_enter(g);
    r = ec_thread_init();
    xt_adm_exit(g);
    return r;
}

/*
 * The end of a thread's own ThreadTerm.  ntdll's NtTerminateThread sets
 * InSyscallCallback, calls ThreadTerm and then terminates the thread
 * with the flag still set: its clearing, which answers the doorbell,
 * comes after the system call, so never for the thread's own end.  A
 * suspension or context request that arrives in between finds the thread
 * inconsistent, so Windows holds it and rings the doorbell, and the
 * request fails once the thread has ended (STATUS_UNSUCCESSFUL).  So,
 * nothing of the engine's held any more, the thread clears the flag
 * itself, which makes the rest of its way to the system call consistent,
 * and answers a rung doorbell as ntdll does where it clears the flag: a
 * continuation with no context, CONTEXT_ARM64 alone, which returns here.
 * A context set there takes the thread elsewhere, as it would a native
 * thread on its way out; its next entry makes it a new record
 * (enter_engine).
 */
static void ec_term_answer(void)
{
    XtCpuArea *area = xt_cpu_area(NtCurrentTeb());
    uintptr_t sp = (uintptr_t)__builtin_frame_address(0);
    ARM64_NT_CONTEXT none = { .ContextFlags = CONTEXT_ARM64 };

    if (!area || area->InSimulation ||
        (sp >= area->EmulatorStackLimit && sp < area->EmulatorStackBase)) {
        return;
    }
    area->InSyscallCallback = 0;
    /* The flag's clearing before the doorbell's read, as Windows rings it. */
    smp_mb();
    if (area->SuspendDoorbell && (qatomic_read(area->SuspendDoorbell) & 1)) {
        xt_continue_native(&none);
    }
}

XTEXPORT NTSTATUS ThreadTerm(HANDLE thread, LONG code)
{
    EC_FPSR_GUARD();
    XtGate *g = xt_gate_self();
    uint32_t level = xt_adm_enter(g);
    bool popped = false, own_end = false;
    NTSTATUS r;

    /* Its level popped already if it waited for another thread outside. */
    r = ec_thread_term(thread, code, g, level, &popped, &own_end);
    if (!popped) {
        xt_adm_exit(g);
    }
    if (own_end) {
        ec_term_answer();
    }
    return r;
}

XTEXPORT void ProcessTerm(HANDLE h, BOOL after, NTSTATUS status)
{
    EC_FPSR_GUARD();
    XtGate *g = xt_gate_self();

    xt_adm_enter(g);
    ec_process_term(h, after, status);
    xt_adm_exit(g);
}

XTEXPORT void NotifyMemoryAlloc(void *addr, SIZE_T len, ULONG type, ULONG prot,
                                BOOL after, NTSTATUS status)
{
    EC_FPSR_GUARD();
    XtGate *g = xt_gate_self();
    uint32_t level;
    int claimed;

    level = ec_half_enter(g, after, XT_MEMOP_ALLOC, addr, len, &claimed);
    ec_notify_memory_alloc(addr, len, type, prot, after, status);
    ec_half_exit(g, level, claimed, XT_MEMOP_ALLOC, addr, len);
}

XTEXPORT void NotifyMemoryFree(void *addr, SIZE_T len, ULONG type, BOOL after,
                               NTSTATUS status)
{
    EC_FPSR_GUARD();
    XtGate *g = xt_gate_self();
    uint32_t level;
    int claimed;

    level = ec_half_enter(g, after, XT_MEMOP_FREE, addr, len, &claimed);
    ec_notify_memory_free(addr, len, type, after, status);
    ec_half_exit(g, level, claimed, XT_MEMOP_FREE, addr, len);
}

XTEXPORT void NotifyMemoryProtect(void *addr, SIZE_T len, ULONG prot,
                                  BOOL after, NTSTATUS status)
{
    EC_FPSR_GUARD();
    XtGate *g = xt_gate_self();
    uint32_t level;
    int claimed;

    level = ec_half_enter(g, after, XT_MEMOP_PROTECT, addr, len, &claimed);
    ec_notify_memory_protect(addr, len, prot, after, status);
    ec_half_exit(g, level, claimed, XT_MEMOP_PROTECT, addr, len);
}

XTEXPORT NTSTATUS NotifyMapViewOfSection(void *unk1, void *addr, void *unk2,
                                         SIZE_T len, ULONG type, ULONG prot)
{
    EC_FPSR_GUARD();
    XtGate *g = xt_gate_self();
    NTSTATUS r;

    xt_adm_enter(g);
    r = ec_notify_map_view_of_section(unk1, addr, unk2, len, type, prot);
    xt_adm_exit(g);
    return r;
}

XTEXPORT void NotifyUnmapViewOfSection(void *addr, BOOL after, NTSTATUS status)
{
    EC_FPSR_GUARD();
    XtGate *g = xt_gate_self();
    uint32_t level;
    int claimed;

    level = ec_half_enter(g, after, XT_MEMOP_UNMAP, addr, 0, &claimed);
    ec_notify_unmap_view_of_section(addr, after, status);
    ec_half_exit(g, level, claimed, XT_MEMOP_UNMAP, addr, 0);
}

XTEXPORT void FlushInstructionCacheHeavy(const void *addr, SIZE_T len)
{
    EC_FPSR_GUARD();
    XtGate *g = xt_gate_self();

    xt_adm_enter(g);
    ec_flush_instruction_cache_heavy(addr, len);
    xt_adm_exit(g);
}

XTEXPORT void BTCpu64FlushInstructionCache(const void *addr, SIZE_T len)
{
    EC_FPSR_GUARD();
    XtGate *g = xt_gate_self();

    xt_adm_enter(g);
    ec_btcpu64_flush_instruction_cache(addr, len);
    xt_adm_exit(g);
}

XTEXPORT void BTCpu64NotifyMemoryDirty(void *addr, SIZE_T len)
{
    EC_FPSR_GUARD();
    XtGate *g = xt_gate_self();

    xt_adm_enter(g);
    ec_btcpu64_notify_memory_dirty(addr, len);
    xt_adm_exit(g);
}

XTEXPORT void BTCpu64NotifyReadFile(HANDLE h, void *addr, SIZE_T len,
                                    BOOL after, NTSTATUS status)
{
    EC_FPSR_GUARD();
    XtGate *g = xt_gate_self();
    uint32_t level;
    int claimed;

    level = ec_half_enter(g, after, XT_MEMOP_READ, addr, len, &claimed);
    ec_btcpu64_notify_read_file(h, addr, len, after, status);
    ec_half_exit(g, level, claimed, XT_MEMOP_READ, addr, len);
}

XTEXPORT BOOLEAN BTCpu64IsProcessorFeaturePresent(UINT feature)
{
    EC_FPSR_GUARD();
    XtGate *g = xt_gate_self();
    BOOLEAN r;

    xt_adm_enter(g);
    r = ec_btcpu64_is_processor_feature_present(feature);
    xt_adm_exit(g);
    return r;
}

XTEXPORT void UpdateProcessorInformation(void *info)
{
    EC_FPSR_GUARD();
    XtGate *g = xt_gate_self();

    xt_adm_enter(g);
    ec_update_processor_information(info);
    xt_adm_exit(g);
}
