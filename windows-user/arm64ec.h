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

/* Whether ADDR is EC code (native), by the PEB's bitmap. */
static inline bool xt_is_ec_code(uint64_t addr)
{
    const uint64_t *bitmap;

    if (addr >= XT_EC_BITMAP_LIMIT) {
        return false;
    }
    bitmap = *(const uint64_t **)
        ((char *)NtCurrentTeb()->ProcessEnvironmentBlock + XT_PEB_EC_BITMAP);
    return (bitmap[addr >> 18] >> ((addr >> 12) & 63)) & 1;
}

/* arm64ec.S */
void xt_check_call(void);
/* arm64ec.c: an entry not built yet, WHICH 1-4, on the emulator stack. */
void xt_ec_entry_stub(int which, uint64_t target);

#endif
