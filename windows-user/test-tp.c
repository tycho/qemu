/*
 * xtajit: the x64 module's test points for the thread gates (test only).
 * A controller process shares a page with this one (XtTpBlock), its
 * section's handle inherited and named by XTAJIT_TP (hexadecimal).  The
 * page is mapped at process init, before the first gate (no notification
 * of the module's follows a view's mapping); after that nothing here
 * allocates.  The controller arms a
 * point of the entries' admission (arm64ec.S's tp_point, in the inject
 * copies, which XTAJIT_TP selects), and the thread that reaches it is held
 * there while the controller acts on it.
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
QEMU_BUILD_BUG_ON(sizeof(XtTpBlock) > 0x1000);

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
    b->apc_routine = (uint64_t)(uintptr_t)tp_apc;
    b->module_base = (uint64_t)(uintptr_t)&__ImageBase;
    b->live_layout = 2;
    qatomic_store_release(&xt_tp_block, b);
    qatomic_or(&xt_cap_entry_mode, XT_EC_ENTRY_INJECT);
    qatomic_store_release(&b->ready, 1);
}
