/*
 * xtajit: engine bring-up and what linux-user provides elsewhere.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "qemu/accel.h"
#include "qapi/error.h"
#include "qom/object.h"
#include "hw/core/cpu.h"
#include "cpu.h"
#include "exec/page-vary.h"
#include "exec/cpu-common.h"
#include "user/guest-base.h"
#include "user/page-protection.h"
#include "tcg/startup.h"
#include "tcg/tcg.h"
#include "accel/accel-ops.h"
#include "accel/tcg/cpu-loop.h"
#include "exec/mmap-lock.h"
#include "exec/page-protection.h"
#include "exec/translation-block.h"
#include "tcg/helper-tcg.h"
#include "qemu/thread.h"
#include "qemu/timer.h"
#include "user/cpu_loop.h"
#include "gdbstub/user.h"
#include "exec/gdbstub.h"
#include "disas/disas.h"
#include "xtajit.h"

extern IMAGE_DOS_HEADER __ImageBase;

uintptr_t guest_base;
bool have_guest_base;
uintptr_t reserved_va;
uintptr_t guest_addr_max;

NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID *, ULONG_PTR, PSIZE_T,
                                       ULONG, ULONG);
NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE, PVOID, int, PVOID, SIZE_T,
                                    PSIZE_T);

/*
 * The mmap lock: recursive per thread, as in linux-user/mmap.c.  It
 * serializes translation and page flag changes.
 */
static QemuMutex mmap_mutex;
static __thread int mmap_lock_count;

void mmap_lock(void)
{
    if (mmap_lock_count++ == 0) {
        qemu_mutex_lock(&mmap_mutex);
    }
}

void mmap_unlock(void)
{
    assert(mmap_lock_count > 0);
    if (--mmap_lock_count == 0) {
        qemu_mutex_unlock(&mmap_mutex);
    }
}

bool have_mmap_lock(void)
{
    return mmap_lock_count > 0;
}

/* Zeroed memory below 4 GiB (guest-visible to the i386 engine). */
void *xt_alloc_low(size_t len)
{
    PVOID base = NULL;
    SIZE_T size = len;

    if (NtAllocateVirtualMemory(GetCurrentProcess(), &base, 0x7fffffff, &size,
                                MEM_RESERVE | MEM_COMMIT,
                                PAGE_READWRITE) < 0) {
        return NULL;
    }
    return base;
}

/* QEMU page flags for a Windows protection. */
static int prot_flags(ULONG prot)
{
    switch (prot & 0xff) {
    case PAGE_READONLY:
        return PAGE_READ;
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
        return PAGE_READ | PAGE_WRITE;
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
        return PAGE_READ | PAGE_EXEC;
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return PAGE_READ | PAGE_WRITE | PAGE_EXEC;
    default:
        return 0;
    }
}

/*
 * Bring QEMU's page flags for ADDR's page up to date with Windows; true if
 * that changed them and the access is allowed now.  QEMU's flags are
 * filled lazily: a page gets them when a probe first misses
 * (cpu_loop_exit_sigsegv below), and a refused access refreshes them
 * before it faults, so mappings and protections made without a
 * notification (the loader's, natively; another thread's) are seen.  A
 * page QEMU write-protects for its translations keeps PAGE_WRITE_ORG.
 * An unchanged answer means the fault is real: no retry loops.
 */
bool xt_mem_refresh(vaddr addr, MMUAccessType access)
{
    MEMORY_BASIC_INFORMATION mbi;
    vaddr start, last;
    int flags, old, want;
    bool changed = false;

    if (addr > guest_addr_max ||
        NtQueryVirtualMemory(GetCurrentProcess(), (void *)(uintptr_t)addr,
                             0, &mbi, sizeof(mbi), NULL) < 0) {
        return false;
    }
    start = (uintptr_t)mbi.BaseAddress;
    last = MIN(start + mbi.RegionSize - 1, (vaddr)guest_addr_max);
    flags = 0;
    /*
     * In a WOW64 process Windows maps this module below 4 GiB, whatever
     * its preferred base: its pages are not the guest's.
     */
    if (mbi.AllocationBase == (void *)&__ImageBase) {
        mbi.State = MEM_RESERVE;
    }
    if (mbi.State == MEM_COMMIT) {
        flags = PAGE_VALID | prot_flags(mbi.Protect);
        if (flags & PAGE_WRITE) {
            flags |= PAGE_WRITE_ORG;
        }
    }

    mmap_lock();
    old = page_get_flags(addr) & (PAGE_VALID | PAGE_RWX | PAGE_WRITE_ORG);
    if ((old & PAGE_WRITE_ORG) && !(old & PAGE_WRITE) &&
        flags == (old & (PAGE_VALID | PAGE_READ | PAGE_EXEC))) {
        /* Write-protected by tb_lock_page0, not by the guest. */
        flags = old;
    } else if (flags != old) {
        changed = true;
        if (xt_self) {
            xt_event(xt_self, XT_EV_REFRESH, old << 16 | flags, addr);
        }
        if (flags) {
            page_set_flags(start, last, flags, PAGE_RWX | PAGE_WRITE_ORG);
        } else {
            page_set_flags(start, last, 0, PAGE_VALID);
        }
    }
    mmap_unlock();

    want = access == MMU_INST_FETCH ? PAGE_EXEC
         : access == MMU_DATA_STORE ? PAGE_WRITE_ORG : PAGE_READ;
    return changed && (flags & want);
}

/*
 * A guest fault: #PF (x86_cpu_record_sigsegv), the access refused by
 * QEMU's page flags or faulting natively.  Before it is raised the page's
 * flags are refreshed from Windows (xt_mem_refresh); if that allows the
 * access, it is retried.
 */
void cpu_loop_exit_sigsegv(CPUState *cs, vaddr addr,
                           MMUAccessType access_type, bool maperr,
                           uintptr_t ra)
{
    XtThread *t = xt_self;

    /* A fault while translating abandons the translation. */
    if (have_mmap_lock() && tcg_ctx->gen_tb) {
        tcg_ctx->gen_tb = NULL;
    }
    /*
     * Windows removes a guard page's protection as it raises the fault:
     * the refreshed flags then allow the access, but the guest must see
     * the fault.  An in-page error isn't a protection either.
     */
    if (xt_mem_refresh(addr, access_type) &&
        !(t && (t->gfault.code == STATUS_GUARD_PAGE_VIOLATION ||
                t->gfault.code == STATUS_IN_PAGE_ERROR))) {
        if (t) {
            xt_event(t, XT_EV_RETRY, addr, access_type);
            t->gfault.code = 0;
        }
        cpu_loop_exit_restore(cs, ra);
    }
    if (t && !t->gfault.code) {
        t->gfault.code = STATUS_ACCESS_VIOLATION;
    }
    cs->cc->tcg_ops->record_sigsegv(cs, addr, access_type, maperr, ra);
    g_assert_not_reached();
}

void cpu_loop_exit_sigbus(CPUState *cs, vaddr addr,
                          MMUAccessType access_type, uintptr_t ra)
{
    cs->cc->tcg_ops->record_sigbus(cs, addr, access_type, ra);
    g_assert_not_reached();
}

uint64_t cpu_get_tsc(CPUX86State *env)
{
    return cpu_get_host_ticks();
}

bool qemu_cpu_is_self(CPUState *cs)
{
    return current_cpu == cs;
}

/* Cut: the gdbstub and the disassemblers (logging only). */
void gdb_init_cpu(CPUState *cs)
{
}

bool gdb_may_set_breakpoints(void)
{
    return false;
}

void x86_cpu_gdb_init(CPUState *cs)
{
}

int x86_cpu_gdb_read_register(CPUState *cs, GByteArray *buf, int reg)
{
    return 0;
}

int x86_cpu_gdb_write_register(CPUState *cs, uint8_t *buf, int reg)
{
    return 0;
}

void disas(FILE *out, const void *code, size_t size)
{
}

void target_disas(FILE *out, CPUState *cs, const DisasContextBase *db)
{
}

const char *lookup_symbol(uint64_t orig_addr)
{
    return "";
}

/*
 * The descriptor tables, below 4 GiB, shared by every CPU.  The GDT has
 * the selectors 32-bit code sees on Windows on Arm, x86 Windows' own: flat
 * 32-bit code (0x1b) and data (0x23), and the TEB segment (0x3b, based per
 * thread when loaded); and, for contexts made on x64 hosts, data 0x2b and
 * the TEB at 0x53.  The IDT is read by
 * do_interrupt_user for a gate's DPL: exceptions at DPL 0, and at DPL 3
 * the vectors 32-bit Windows code may raise with int: 3, 4, 0x29 (fast
 * fail), 0x2c (assertion), 0x2d (debug service), 0x2e (the system-call
 * stub) and 0x81 (the host counter).
 */
#define GDT_ENTRIES 16
static uint64_t *gdt;
static uint32_t *idt;

static uint64_t make_desc(uint32_t base, uint32_t limit, uint32_t flags)
{
    uint32_t e1 = (limit & 0xffff) | ((base & 0xffff) << 16);
    uint32_t e2 = ((base >> 16) & 0xff) | (base & 0xff000000) |
                  (limit & 0xf0000) | flags;

    return e1 | ((uint64_t)e2 << 32);
}

static const uint32_t code32_flags =
    DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
    (3 << DESC_DPL_SHIFT) | (0xb << DESC_TYPE_SHIFT);
static const uint32_t data32_flags =
    DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
    (3 << DESC_DPL_SHIFT) | (0x3 << DESC_TYPE_SHIFT);

static void setup_tables(void)
{
    gdt = xt_alloc_low(4096);
    gdt[0x1b >> 3] = make_desc(0, 0xfffff, code32_flags);
    gdt[0x23 >> 3] = make_desc(0, 0xfffff, data32_flags);
    gdt[0x2b >> 3] = make_desc(0, 0xfffff, data32_flags);
    gdt[0x3b >> 3] = make_desc(0, 0xfff, data32_flags & ~DESC_G_MASK);
    gdt[0x53 >> 3] = make_desc(0, 0xfff, data32_flags & ~DESC_G_MASK);

    idt = xt_alloc_low(256 * 8);
    for (int n = 0; n < 256; n++) {
        int dpl = n == 3 || n == 4 || n == 0x29 || n == 0x2c || n == 0x2d ||
                  n == 0x2e || n == 0x81 ? 3 : 0;

        if (n >= 20 && !dpl) {
            continue;
        }
        idt[n * 2] = 0;
        idt[n * 2 + 1] = 0x8000 | (dpl << 13);
    }
}

/*
 * Protected mode at CPL 3 with WOW64's segments, as linux-user's
 * init_main_thread sets up the mode; the selectors are loaded from the
 * contexts (xt_import).
 */
static void setup_mode(CPUX86State *env)
{
    env->cr[0] = CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK | CR0_ET_MASK |
                 CR0_NE_MASK;
    env->hflags |= HF_PE_MASK | HF_CPL_MASK;
    env->cr[4] |= CR4_OSFXSR_MASK | CR4_OSXMMEXCPT_MASK;
    env->hflags |= HF_OSFXSR_MASK;
    env->eflags |= IF_MASK;
    env->gdt.base = (uintptr_t)gdt;
    env->gdt.limit = GDT_ENTRIES * 8 - 1;
    env->idt.base = (uintptr_t)idt;
    env->idt.limit = 256 * 8 - 1;
}

static QemuMutex cpu_create_mutex;

/*
 * The guest's CPU: QEMU's qemu32 with the features Windows on Arm's own
 * x86 emulator offers 32-bit code, all of which TCG implements.  No XSAVE
 * or AVX: the WOW64 context has no place for the YMM state.
 */
const char *xt_cpu_model =
    "qemu32,ssse3=on,sse4.1=on,sse4.2=on,popcnt=on,aes=on,pclmulqdq=on,"
    "cx16=on,rdtscp=on,lahf-lm=on,3dnowprefetch=on,nx=on";
static const char *cpu_type;

/* A CPU for the calling thread, in parallel mode from the start. */
CPUState *xt_cpu_new(void)
{
    CPUState *cs;

    qemu_mutex_lock(&cpu_create_mutex);
    cs = cpu_create(cpu_type);
    qemu_mutex_unlock(&cpu_create_mutex);
    cpu_reset(cs);
    setup_mode(cpu_env(cs));
    cs->tcg_cflags |= CF_PARALLEL;
    return cs;
}

/* Drop translations of [start, start + len), as for a host write. */
void xt_invalidate(vaddr start, vaddr len)
{
    vaddr last;

    if (!len || start > guest_addr_max) {
        return;
    }
    last = MIN(start + len - 1, (vaddr)guest_addr_max);
    mmap_lock();
    tb_invalidate_phys_range(NULL, start, last);
    mmap_unlock();
}

CPUState *xt_spare_cpu;
static int applied, rejected;

static void set_settings(Object *accel, const char *settings)
{
    char **kv = g_strsplit(settings, ",", 0);

    for (int i = 0; kv[i]; i++) {
        char *eq = strchr(kv[i], '=');
        g_autofree char *name = NULL;

        if (!eq) {
            continue;
        }
        /* QEMU's own accelerator properties go as they are, the rest as x-. */
        name = g_strndup(kv[i], eq - kv[i]);
        if (strcmp(name, "one-insn-per-tb") && strcmp(name, "tb-size") &&
            strcmp(name, "split-wx")) {
            g_free(name);
            name = g_strdup_printf("x-%.*s", (int)(eq - kv[i]), kv[i]);
        }
        if (object_property_find(accel, name) &&
            object_property_parse(accel, name, eq + 1, NULL)) {
            applied++;
        } else {
            rejected++;
        }
    }
    g_strfreev(kv);
}

/*
 * The process-wide bring-up, as linux-user's main() without a loader:
 * QOM, the TCG accelerator with SETTINGS (comma-separated
 * accelerator properties, x- ones without the prefix), page size, the
 * descriptor tables, a first CPU and the prologue.
 */
int xt_engine_init(const char *settings, int *n_applied, int *n_rejected)
{
    AccelState *accel;
    AccelClass *ac;
    CPUState *first;

    qemu_mutex_init(&mmap_mutex);
    qemu_mutex_init(&cpu_create_mutex);
    guest_addr_max = UINT32_MAX;

    module_call_init(MODULE_INIT_TRACE);
    qemu_init_cpu_list();
    module_call_init(MODULE_INIT_QOM);

    accel = current_accel();
    ac = ACCEL_GET_CLASS(accel);
    accel_init_interfaces(ac);
    if (settings) {
        set_settings(OBJECT(accel), settings);
    }
    ac->init_machine(accel, NULL);
    if (n_applied) {
        *n_applied = applied;
        *n_rejected = rejected;
    }

    cpu_type = parse_cpu_option(xt_cpu_model);

    set_preferred_target_page_bits(ctz32(qemu_real_host_page_size()));
    finalize_target_page_bits();
    setup_tables();

    /* The prologue needs a CPU; it becomes the first thread's. */
    first = xt_cpu_new();
    tcg_prologue_init();
    xt_spare_cpu = first;
    return 0;
}
