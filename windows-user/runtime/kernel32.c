/*
 * The Win32 calls QEMU's Windows code (util/qemu-thread-win32.c,
 * util/oslib-win32.c, util/cacheflush.c) and the allocator make, on ntdll:
 * a WOW64 process's native side has no kernel32.  Each is what its
 * callers here need, not the whole Win32 contract; where a caller handles
 * failure and the module has no use for the service (sockets, libraries,
 * the crypto provider), the call fails.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <winternl.h>
#include <wincrypt.h>
#include "runtime.h"

/* Synchronization: slim reader/writer locks, condition variables, futexes. */

void WINAPI InitializeSRWLock(PSRWLOCK l)
{
    l->Ptr = NULL;
}

void WINAPI AcquireSRWLockExclusive(PSRWLOCK l)
{
    RtlAcquireSRWLockExclusive(l);
}

void WINAPI ReleaseSRWLockExclusive(PSRWLOCK l)
{
    RtlReleaseSRWLockExclusive(l);
}

void WINAPI AcquireSRWLockShared(PSRWLOCK l)
{
    RtlAcquireSRWLockShared(l);
}

void WINAPI ReleaseSRWLockShared(PSRWLOCK l)
{
    RtlReleaseSRWLockShared(l);
}

BOOLEAN WINAPI TryAcquireSRWLockExclusive(PSRWLOCK l)
{
    return RtlTryAcquireSRWLockExclusive(l);
}

BOOLEAN WINAPI TryAcquireSRWLockShared(PSRWLOCK l)
{
    return RtlTryAcquireSRWLockShared(l);
}

void WINAPI InitializeConditionVariable(PCONDITION_VARIABLE c)
{
    c->Ptr = NULL;
}

/* A timeout in milliseconds as NT's relative LARGE_INTEGER (100 ns units). */
static LARGE_INTEGER *nt_timeout(LARGE_INTEGER *t, DWORD ms)
{
    if (ms == INFINITE) {
        return NULL;
    }
    t->QuadPart = -(LONGLONG)ms * 10000;
    return t;
}

WINBOOL WINAPI SleepConditionVariableSRW(PCONDITION_VARIABLE c, PSRWLOCK l,
                                         DWORD ms, ULONG flags)
{
    LARGE_INTEGER t;
    NTSTATUS st = RtlSleepConditionVariableSRW(c, l, nt_timeout(&t, ms),
                                               flags);

    if (st != STATUS_SUCCESS) {
        SetLastError(st == STATUS_TIMEOUT ? ERROR_TIMEOUT
                                          : ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return TRUE;
}

void WINAPI WakeConditionVariable(PCONDITION_VARIABLE c)
{
    RtlWakeConditionVariable(c);
}

void WINAPI WakeAllConditionVariable(PCONDITION_VARIABLE c)
{
    RtlWakeAllConditionVariable(c);
}

/* addr is volatile in the Win32 interface. */
WINBOOL WINAPI WaitOnAddress(volatile void *addr, PVOID cmp, SIZE_T size,
                             DWORD ms)
{
    LARGE_INTEGER t;
    NTSTATUS st = RtlWaitOnAddress((const void *)addr, cmp, size,
                                   nt_timeout(&t, ms));

    if (st != STATUS_SUCCESS) {
        SetLastError(st == STATUS_TIMEOUT ? ERROR_TIMEOUT
                                          : ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return TRUE;
}

void WINAPI WakeByAddressSingle(PVOID addr)
{
    RtlWakeAddressSingle(addr);
}

void WINAPI WakeByAddressAll(PVOID addr)
{
    RtlWakeAddressAll(addr);
}

/*
 * Critical sections (util/qemu-thread-win32.c's recursive mutexes), and
 * the performance counter (QEMU's clock on Windows).
 */

void WINAPI InitializeCriticalSection(LPCRITICAL_SECTION cs)
{
    RtlInitializeCriticalSection(cs);
}

void WINAPI EnterCriticalSection(LPCRITICAL_SECTION cs)
{
    RtlEnterCriticalSection(cs);
}

void WINAPI LeaveCriticalSection(LPCRITICAL_SECTION cs)
{
    RtlLeaveCriticalSection(cs);
}

WINBOOL WINAPI TryEnterCriticalSection(LPCRITICAL_SECTION cs)
{
    return RtlTryEnterCriticalSection(cs);
}

void WINAPI DeleteCriticalSection(LPCRITICAL_SECTION cs)
{
    RtlDeleteCriticalSection(cs);
}

WINBOOL WINAPI QueryPerformanceCounter(LARGE_INTEGER *c)
{
    return NtQueryPerformanceCounter(c, NULL) >= 0;
}

WINBOOL WINAPI QueryPerformanceFrequency(LARGE_INTEGER *f)
{
    LARGE_INTEGER c;

    return NtQueryPerformanceCounter(&c, f) >= 0;
}

/* Processes and threads */

HANDLE WINAPI GetCurrentProcess(void)
{
    return (HANDLE)-1;
}

HANDLE WINAPI GetCurrentThread(void)
{
    return (HANDLE)-2;
}

/* A 64-bit TEB's ClientId (process, thread) and LastErrorValue. */
#define TEB_CLIENT_ID 0x40
#define TEB_LAST_ERROR 0x68

DWORD WINAPI GetCurrentProcessId(void)
{
    return *(DWORD *)((char *)NtCurrentTeb() + TEB_CLIENT_ID);
}

DWORD WINAPI GetCurrentThreadId(void)
{
    return *(DWORD *)((char *)NtCurrentTeb() + TEB_CLIENT_ID + 8);
}

DWORD WINAPI GetLastError(void)
{
    return *(DWORD *)((char *)NtCurrentTeb() + TEB_LAST_ERROR);
}

void WINAPI SetLastError(DWORD e)
{
    *(DWORD *)((char *)NtCurrentTeb() + TEB_LAST_ERROR) = e;
}

void WINAPI Sleep(DWORD ms)
{
    LARGE_INTEGER t;

    if (ms == 0) {
        NtYieldExecution();
    } else {
        NtDelayExecution(FALSE, nt_timeout(&t, ms));
    }
}

WINBOOL WINAPI CloseHandle(HANDLE h)
{
    return NtClose(h) >= 0;
}

WINBOOL WINAPI FlushInstructionCache(HANDLE proc, LPCVOID addr, SIZE_T len)
{
    return NtFlushInstructionCache(proc, (PVOID)addr, len) >= 0;
}

/*
 * Fiber-local storage, for the allocator's thread-exit destructor: the
 * module ends a thread's heap itself (xt_crt_thread_fini), so the slot
 * holds nothing and runs nothing.
 */
DWORD WINAPI FlsAlloc(PFLS_CALLBACK_FUNCTION fn)
{
    return 0;
}

WINBOOL WINAPI FlsFree(DWORD index)
{
    return TRUE;
}

WINBOOL WINAPI FlsSetValue(DWORD index, PVOID value)
{
    return TRUE;
}

/* Memory */

static ULONG nt_alloc_type(DWORD type)
{
    return type & (MEM_COMMIT | MEM_RESERVE | MEM_RESET | MEM_TOP_DOWN |
                   MEM_LARGE_PAGES);
}

LPVOID WINAPI VirtualAlloc(LPVOID addr, SIZE_T len, DWORD type, DWORD prot)
{
    PVOID base = addr;
    SIZE_T size = len;

#ifdef __arm64ec__
    /*
     * In an ARM64EC process, the module's executable memory (TCG's code
     * buffer) holds native code: Windows must see it as EC code, not x64.
     */
    if (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                PAGE_EXECUTE_WRITECOPY)) {
        MEM_EXTENDED_PARAMETER ec = {
            .Type = MemExtendedParameterAttributeFlags,
            .ULong64 = MEM_EXTENDED_PARAMETER_EC_CODE,
        };

        if (NtAllocateVirtualMemoryEx(GetCurrentProcess(), &base, &size,
                                      nt_alloc_type(type), prot, &ec, 1) < 0) {
            return NULL;
        }
        return base;
    }
#else
    /*
     * The module's own memory (TCG's code buffer, the runtime's) lies
     * outside the 32-bit guest's address space, and far enough above it
     * that generated code reaches neither guest addresses by ADRP nor the
     * module's image, which Windows maps below 4 GiB, by BL: each takes
     * the same form in every process, wherever Windows put the module.
     */
    if (!addr) {
        XtBasicInfo sbi;
        MEM_ADDRESS_REQUIREMENTS req = { 0 };
        MEM_EXTENDED_PARAMETER ext = { 0 };

        if (NtQuerySystemInformation(SystemBasicInformation, &sbi,
                                     sizeof(sbi), NULL) < 0) {
            return NULL;
        }
        req.LowestStartingAddress = (void *)XT_HIGH_ALLOC_BASE;
        req.HighestEndingAddress = (void *)sbi.MaximumUserModeAddress;
        ext.Type = MemExtendedParameterAddressRequirements;
        ext.Pointer = &req;
        if (NtAllocateVirtualMemoryEx(GetCurrentProcess(), &base, &size,
                                      nt_alloc_type(type), prot, &ext,
                                      1) < 0) {
            return NULL;
        }
        return base;
    }
#endif
    if (NtAllocateVirtualMemory(GetCurrentProcess(), &base, 0, &size,
                                nt_alloc_type(type), prot) < 0) {
        return NULL;
    }
    return base;
}

/* qemu_mprotect_*(): TCG's guard pages and code buffer permissions. */
WINBOOL WINAPI VirtualProtect(LPVOID addr, SIZE_T len, DWORD prot,
                              PDWORD old)
{
    PVOID base = addr;
    SIZE_T size = len;
    ULONG o;

    if (NtProtectVirtualMemory(GetCurrentProcess(), &base, &size, prot,
                               &o) < 0) {
        return FALSE;
    }
    if (old) {
        *old = o;
    }
    return TRUE;
}

WINBOOL WINAPI VirtualFree(LPVOID addr, SIZE_T len, DWORD type)
{
    PVOID base = addr;
    SIZE_T size = len;

    return NtFreeVirtualMemory(GetCurrentProcess(), &base, &size, type) >= 0;
}

void WINAPI GetSystemInfo(LPSYSTEM_INFO si)
{
    XtBasicInfo sbi;

    memset(si, 0, sizeof(*si));
    if (NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi),
                                 NULL) < 0) {
        return;
    }
    si->wProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM64;
    si->dwPageSize = sbi.PageSize;
    si->lpMinimumApplicationAddress = (void *)sbi.MinimumUserModeAddress;
    si->lpMaximumApplicationAddress = (void *)sbi.MaximumUserModeAddress;
    si->dwActiveProcessorMask = sbi.ActiveProcessorsAffinityMask;
    si->dwNumberOfProcessors = sbi.NumberOfProcessors;
    si->dwAllocationGranularity = sbi.AllocationGranularity;
}

/* util/cacheflush.c: the host's cache line sizes. */
WINBOOL WINAPI GetLogicalProcessorInformation(
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION buf, PDWORD len)
{
    ULONG ret = 0;
    NTSTATUS st = NtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)73 /* SystemLogicalProcessorInformation */,
        buf, *len, &ret);

    *len = ret;
    if (st < 0) {
        SetLastError(st == STATUS_INFO_LENGTH_MISMATCH ?
                     ERROR_INSUFFICIENT_BUFFER : ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return TRUE;
}

/* qemu_get_host_physmem: the default code buffer size. */
WINBOOL WINAPI GlobalMemoryStatusEx(LPMEMORYSTATUSEX m)
{
    XtBasicInfo sbi;

    if (NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi),
                                 NULL) < 0) {
        return FALSE;
    }
    memset(m, 0, sizeof(*m));
    m->dwLength = sizeof(*m);
    m->ullTotalPhys = sbi.PageSize * (uint64_t)sbi.NumberOfPhysicalPages;
    return TRUE;
}

/* Services the module doesn't use: callers handle the failure. */

/* util/oslib-win32.c's socket-aware close(): the module has no sockets. */
int WINAPI closesocket(UINT_PTR s)
{
    return -1;
}

int WINAPI WSAGetLastError(void)
{
    return 0;
}

WINBOOL WINAPI GetHandleInformation(HANDLE h, LPDWORD flags)
{
    return FALSE;
}

WINBOOL WINAPI SetHandleInformation(HANDLE h, DWORD mask, DWORD flags)
{
    return FALSE;
}

/* util/qemu-thread-win32.c's SetThreadDescription lookup: no names. */
HMODULE WINAPI LoadLibraryA(LPCSTR name)
{
    return NULL;
}

WINBOOL WINAPI FreeLibrary(HMODULE m)
{
    return TRUE;
}

/*
 * Modules already loaded, and their exports, through ntdll's loader:
 * wow64.dll's functions, ntdll's own.  No module is loaded here.
 */
HMODULE WINAPI GetModuleHandleW(LPCWSTR name)
{
    UNICODE_STRING u;
    PVOID h = NULL;

    if (!name) {
        return (HMODULE)NtCurrentTeb()->ProcessEnvironmentBlock->Reserved3[1];
    }
    RtlInitUnicodeString(&u, name);
    if (LdrGetDllHandle(NULL, NULL, &u, &h) < 0) {
        SetLastError(ERROR_MOD_NOT_FOUND);
        return NULL;
    }
    return h;
}

HMODULE WINAPI GetModuleHandleA(LPCSTR name)
{
    WCHAR w[MAX_PATH];
    size_t i;

    if (!name) {
        return GetModuleHandleW(NULL);
    }
    for (i = 0; name[i] && i < MAX_PATH - 1; i++) {
        w[i] = (unsigned char)name[i];
    }
    w[i] = 0;
    return GetModuleHandleW(w);
}

FARPROC WINAPI GetProcAddress(HMODULE m, LPCSTR name)
{
    ANSI_STRING a;
    PVOID p = NULL;
    NTSTATUS st;

    if (!m) {
        return NULL;
    }
    if ((uintptr_t)name >> 16) {
        RtlInitAnsiString(&a, name);
        st = LdrGetProcedureAddress(m, &a, 0, &p);
    } else {
        st = LdrGetProcedureAddress(m, NULL, (ULONG)(uintptr_t)name, &p);
    }
    if (st < 0) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return NULL;
    }
    return (FARPROC)p;
}

/* Error messages (g_win32_error_message): none, the caller prints codes. */
DWORD WINAPI FormatMessageA(DWORD flags, LPCVOID src, DWORD id, DWORD lang,
                            LPSTR buf, DWORD size, va_list *args)
{
    return 0;
}

HLOCAL WINAPI LocalFree(HLOCAL p)
{
    return NULL;
}

/* crypto/random-platform.c: no provider, as on a host without one. */
WINBOOL WINAPI CryptGenRandom(ULONG_PTR prov, DWORD len, uint8_t *buf)
{
    return FALSE;
}

XT_IMPORT_SLOT(InitializeSRWLock);
XT_IMPORT_SLOT(AcquireSRWLockExclusive);
XT_IMPORT_SLOT(ReleaseSRWLockExclusive);
XT_IMPORT_SLOT(AcquireSRWLockShared);
XT_IMPORT_SLOT(ReleaseSRWLockShared);
XT_IMPORT_SLOT(TryAcquireSRWLockExclusive);
XT_IMPORT_SLOT(TryAcquireSRWLockShared);
XT_IMPORT_SLOT(InitializeConditionVariable);
XT_IMPORT_SLOT(SleepConditionVariableSRW);
XT_IMPORT_SLOT(WakeConditionVariable);
XT_IMPORT_SLOT(WakeAllConditionVariable);
XT_IMPORT_SLOT(WaitOnAddress);
XT_IMPORT_SLOT(WakeByAddressSingle);
XT_IMPORT_SLOT(WakeByAddressAll);
XT_IMPORT_SLOT(InitializeCriticalSection);
XT_IMPORT_SLOT(EnterCriticalSection);
XT_IMPORT_SLOT(LeaveCriticalSection);
XT_IMPORT_SLOT(TryEnterCriticalSection);
XT_IMPORT_SLOT(DeleteCriticalSection);
XT_IMPORT_SLOT(QueryPerformanceCounter);
XT_IMPORT_SLOT(QueryPerformanceFrequency);
XT_IMPORT_SLOT(CloseHandle);
XT_IMPORT_SLOT(VirtualProtect);
XT_IMPORT_SLOT(GetModuleHandleA);
XT_IMPORT_SLOT(GetModuleHandleW);
XT_IMPORT_SLOT(GetProcAddress);
XT_IMPORT_SLOT(FormatMessageA);
XT_IMPORT_SLOT(LocalFree);
XT_IMPORT_SLOT(GetCurrentProcess);
XT_IMPORT_SLOT(GetCurrentThread);
XT_IMPORT_SLOT(GetCurrentProcessId);
XT_IMPORT_SLOT(GetCurrentThreadId);
XT_IMPORT_SLOT(GetLastError);
XT_IMPORT_SLOT(SetLastError);
XT_IMPORT_SLOT(Sleep);
XT_IMPORT_SLOT(FlushInstructionCache);
XT_IMPORT_SLOT(FlsAlloc);
XT_IMPORT_SLOT(FlsFree);
XT_IMPORT_SLOT(FlsSetValue);
XT_IMPORT_SLOT(VirtualAlloc);
XT_IMPORT_SLOT(VirtualFree);
XT_IMPORT_SLOT(GetSystemInfo);
XT_IMPORT_SLOT(GetLogicalProcessorInformation);
XT_IMPORT_SLOT(GlobalMemoryStatusEx);
XT_IMPORT_SLOT(closesocket);
XT_IMPORT_SLOT(WSAGetLastError);
XT_IMPORT_SLOT(GetHandleInformation);
XT_IMPORT_SLOT(SetHandleInformation);
XT_IMPORT_SLOT(LoadLibraryA);
XT_IMPORT_SLOT(FreeLibrary);
XT_IMPORT_SLOT(CryptGenRandom);
