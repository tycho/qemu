/*
 * The module's C runtime start-up.
 *
 * The native side of a WOW64 process has ntdll alone: no kernel32 and no
 * C runtime DLL, so the module brings its own.  This part does what a
 * DLL's C runtime start-up does: the PE TLS directory, constructors, TLS
 * callbacks and the allocator's per-thread state, plus errno and the ways
 * out (abort, exit, assert).
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <winternl.h>
#include "runtime.h"

/*
 * The TLS callbacks, run by the runtime itself; and the PE TLS directory
 * of the WOW64 module.  The loader gives that module a TLS index from it;
 * in a WOW64 process it sets up no blocks for the CPU module, so
 * xt_tls_attach installs them (thread.c).  The x64 module has no PE TLS:
 * its thread-local variables are emulated (emutls.c).
 */
__attribute__((section(".CRT$XLA"))) PIMAGE_TLS_CALLBACK __xl_a;
__attribute__((section(".CRT$XLZ"))) PIMAGE_TLS_CALLBACK __xl_z;
#ifndef TARGET_X86_64
uint64_t _tls_index;
__attribute__((section(".tls"))) char _tls_start;
__attribute__((section(".tls$ZZZ"))) char _tls_end;
const IMAGE_TLS_DIRECTORY64 _tls_used = {
    (uintptr_t)&_tls_start,
    (uintptr_t)&_tls_end,
    (uintptr_t)&_tls_index,
    (uintptr_t)(&__xl_a + 1),
    0,
    0,
};
#endif

/*
 * Initializers: the C ones the compiler puts in .CRT$XI* and .CRT$XC*,
 * and GCC-style constructors (QEMU's module and type registration) in
 * the list the linker builds.  The list's first entry is a count or -1,
 * and it ends at a null entry; they run last to first.
 */
__attribute__((section(".CRT$XIA"))) CrtFn __xi_a;
__attribute__((section(".CRT$XIZ"))) CrtFn __xi_z;
__attribute__((section(".CRT$XCA"))) CrtFn __xc_a;
__attribute__((section(".CRT$XCZ"))) CrtFn __xc_z;

static void run_fns(CrtFn *begin, CrtFn *end)
{
    for (CrtFn *f = begin; f < end; f++) {
        if (*f) {
            (*f)();
        }
    }
}

static void run_tls_callbacks(DWORD reason)
{
    PIMAGE_TLS_CALLBACK *f;

    for (f = &__xl_a + 1; f < &__xl_z; f++) {
        if (*f) {
            (*f)(NULL, reason, NULL);
        }
    }
}

/*
 * The loader's entry point.  It runs before the module's TLS exists, so
 * it does nothing: wow64.dll calls BTCpuProcessInit next, which starts
 * the runtime (xt_crt_process_init).
 */
BOOL WINAPI DllMainCRTStartup(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) {
        LdrDisableThreadCalloutsForDll(inst);
    }
    return TRUE;
}

void xt_crt_process_init(void)
{
    CrtFn *ctor = &__CTOR_LIST__[1];
    CrtFn *end = ctor;

    xt_heap_init();
    while (*end) {
        end++;
    }
    while (end > ctor) {
        (*--end)();
    }
    run_fns(&__xi_a + 1, &__xi_z);
    run_fns(&__xc_a + 1, &__xc_z);
    run_tls_callbacks(DLL_PROCESS_ATTACH);
}

void xt_crt_thread_init(void)
{
    xt_heap_thread_init();
    run_tls_callbacks(DLL_THREAD_ATTACH);
}

void xt_crt_thread_fini(void)
{
    run_tls_callbacks(DLL_THREAD_DETACH);
    xt_heap_thread_fini();
}

/*
 * atexit: the module is never unloaded, and a process's end gives back
 * everything it holds, so the handlers are accepted and not run.
 */
int __cdecl atexit(void (*fn)(void))
{
    return 0;
}

static __thread int thread_errno;

int *__cdecl _errno(void)
{
    return &thread_errno;
}

/*
 * abort, exit and assertion failures write to the process's standard
 * error and end the process with 0xE1000000 | a code, naming the caller's
 * offset in the module for symbolizing against the link map.
 */
static G_NORETURN void die(const char *what, void *ra, unsigned code)
{
    char buf[512];

    snprintf(buf, sizeof(buf), "libwow64xtcg: %s (from +0x%llx)\n", what,
             (unsigned long long)((char *)ra - (char *)&__ImageBase));
    xt_stderr_write(buf, strlen(buf));
    NtTerminateProcess(GetCurrentProcess(), 0xE1000000 | code);
    __builtin_trap();
}

void __cdecl abort(void)
{
    die("abort", __builtin_return_address(0), 1);
}

void __cdecl exit(int code)
{
    char what[32];

    snprintf(what, sizeof(what), "exit(%d)", code);
    die(what, __builtin_return_address(0), 2);
}

void __cdecl _exit(int code)
{
    exit(code);
}

void __cdecl _assert(const char *msg, const char *file, unsigned line)
{
    char what[400];

    snprintf(what, sizeof(what), "%s:%u: assertion failed: %s", file, line,
             msg);
    die(what, __builtin_return_address(0), 3);
}

XT_IMPORT_SLOT(_assert);
XT_IMPORT_SLOT(_errno);
