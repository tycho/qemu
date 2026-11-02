/*
 * The module's own C runtime, over ntdll alone.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef WINDOWS_USER_RUNTIME_H
#define WINDOWS_USER_RUNTIME_H

#include <winternl.h>

/*
 * The runtime defines functions that Windows' headers declare dllimport
 * (the C runtime's, kernel32's): its definitions are the ones linked.
 */
#ifdef __clang__
#pragma clang diagnostic ignored "-Winconsistent-dllimport"
#endif

/*
 * The import slot of a function the runtime defines and Windows' headers
 * declare dllimport, so that callers compiled against those headers
 * reach it.  lld would make the slot itself ("locally defined symbol
 * imported"), but with --gc-sections it may drop the function and leave
 * the slot pointing at the image base.
 */
#define XT_IMPORT_SLOT(f) void *__imp_##f = (void *)f

/* ntdll's, which winternl.h leaves out. */
NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID *, ULONG_PTR, PSIZE_T,
                                       ULONG, ULONG);
NTSTATUS NTAPI NtAllocateVirtualMemoryEx(HANDLE, PVOID *, PSIZE_T, ULONG,
                                         ULONG, MEM_EXTENDED_PARAMETER *,
                                         ULONG);
NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE, PVOID *, PSIZE_T, ULONG);
NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE, PVOID *, PSIZE_T, ULONG,
                                      PULONG);
NTSTATUS NTAPI NtWriteFile(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK,
                           PVOID, ULONG, PLARGE_INTEGER, PULONG);
NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
NTSTATUS NTAPI NtDelayExecution(BOOLEAN, PLARGE_INTEGER);
NTSTATUS NTAPI NtYieldExecution(void);
NTSTATUS NTAPI NtFlushInstructionCache(HANDLE, PVOID, SIZE_T);
NTSTATUS NTAPI NtQueryPerformanceCounter(PLARGE_INTEGER, PLARGE_INTEGER);
NTSTATUS NTAPI RtlCreateUserThread(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN,
                                   ULONG, SIZE_T, SIZE_T, PVOID, PVOID,
                                   PHANDLE, CLIENT_ID *);
void NTAPI RtlExitUserThread(NTSTATUS);
NTSTATUS NTAPI RtlQueryEnvironmentVariable(PVOID, PCWSTR, SIZE_T, PWSTR,
                                           SIZE_T, PSIZE_T);
NTSTATUS NTAPI LdrDisableThreadCalloutsForDll(PVOID);
NTSTATUS NTAPI LdrGetDllHandle(PWSTR, PULONG, PUNICODE_STRING, PVOID *);
NTSTATUS NTAPI LdrGetProcedureAddress(PVOID, PANSI_STRING, ULONG, PVOID *);
void NTAPI RtlAcquireSRWLockExclusive(PSRWLOCK);
void NTAPI RtlReleaseSRWLockExclusive(PSRWLOCK);
void NTAPI RtlAcquireSRWLockShared(PSRWLOCK);
void NTAPI RtlReleaseSRWLockShared(PSRWLOCK);
BOOLEAN NTAPI RtlTryAcquireSRWLockExclusive(PSRWLOCK);
BOOLEAN NTAPI RtlTryAcquireSRWLockShared(PSRWLOCK);
NTSTATUS NTAPI RtlWaitOnAddress(const void *, const void *, SIZE_T,
                                const LARGE_INTEGER *);
void NTAPI RtlWakeAddressSingle(const void *);
void NTAPI RtlWakeAddressAll(const void *);
NTSTATUS NTAPI RtlSleepConditionVariableSRW(PCONDITION_VARIABLE, PSRWLOCK,
                                            const LARGE_INTEGER *, ULONG);
void NTAPI RtlWakeConditionVariable(PCONDITION_VARIABLE);
void NTAPI RtlWakeAllConditionVariable(PCONDITION_VARIABLE);
NTSTATUS NTAPI RtlInitializeCriticalSection(PRTL_CRITICAL_SECTION);
NTSTATUS NTAPI RtlEnterCriticalSection(PRTL_CRITICAL_SECTION);
NTSTATUS NTAPI RtlLeaveCriticalSection(PRTL_CRITICAL_SECTION);
BOOLEAN NTAPI RtlTryEnterCriticalSection(PRTL_CRITICAL_SECTION);
NTSTATUS NTAPI RtlDeleteCriticalSection(PRTL_CRITICAL_SECTION);

extern IMAGE_DOS_HEADER __ImageBase;

/* The linker's list of GCC-style constructors. */
typedef void (*CrtFn)(void);
extern CrtFn __CTOR_LIST__[];

/* Status codes winnt.h leaves to ntstatus.h. */
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#endif

/*
 * SYSTEM_BASIC_INFORMATION as Windows has it (winternl.h's leaves its
 * fields reserved).
 */
typedef struct XtBasicInfo {
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} XtBasicInfo;

/* crt.c: start-up, per thread and per process */
BOOL WINAPI DllMainCRTStartup(HINSTANCE inst, DWORD reason, LPVOID reserved);
void xt_crt_process_init(void);
void xt_crt_thread_init(void);
void xt_crt_thread_fini(void);

/* heap.c */
void xt_heap_init(void);
void xt_heap_thread_init(void);
void xt_heap_thread_fini(void);
void *xt_heap_aligned(size_t size, size_t align);

/* stdio.c: the process's standard error, and a fatal error */
void xt_stderr_write(const void *p, size_t n);
G_NORETURN void xt_fatal(const char *what);

#endif
