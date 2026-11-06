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
 * The page below a thread's emulator stack (ThreadInit): its doorbell, and
 * the native registers of an entry (arm64ec.S stores them) or of an exit
 * to native code (xt_ec_exit_native loads them).
 */
typedef struct XtEcFrame {
    ULONG doorbell;
    uint32_t pad[3];
    ARM64_NT_CONTEXT ctx;
} XtEcFrame;

/* arm64ec.c: the entries' C halves, on the emulator stack */
void xt_ec_enter(XtEcFrame *f);
void xt_ec_begin(void);

/* arm64ec.S: transfers out of the engine; neither returns */
G_NORETURN void xt_ec_exit_native(ARM64_NT_CONTEXT *n);
/* The same, and v16-v31 from N (the YMM upper halves) */
G_NORETURN void xt_ec_exit_native_ymm(ARM64_NT_CONTEXT *n);
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

#endif
