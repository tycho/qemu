/*
 * Thread-local variables in an x64 process.
 *
 * The x64 module is built with -femulated-tls: each access asks
 * __emutls_get_address for this thread's copy of a variable.  The copies
 * live in storage of the module's own, a root per thread reached through
 * a TEB TLS slot the module allocates.  The module has no PE TLS: the
 * loader counts the threads it gives TLS vectors, and gives each one a
 * new block when a module with TLS loads.  The module's code runs on
 * threads the loader doesn't count (its internal ones, ones past the
 * loader's thread shutdown, ones it hasn't initialized yet), and a vector
 * on one of those takes a block meant for another thread.
 *
 * A root is made at a thread's first access, and goes once the thread has
 * ended (xt_emutls_reap), whether or not the thread ever had a guest
 * record.  Making one, or a variable's copy, calls no code that can come
 * back into the module: not the allocator (whose own state is
 * thread-local) or ntdll, only system calls (xt_alloc_direct), and the
 * root is in the thread's slot before anything else is done.  A
 * variable's index is claimed without a lock, so no thread's suspension
 * or end can hold up another's.  The slot is taken in ProcessInit.
 * Before it (the native test harness only), storage comes through ntdll.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/units.h"
#include <winternl.h>
#include "runtime.h"
#include "xtajit.h"

/* The compiler's descriptor of a thread-local variable (GCC's layout). */
typedef struct EmutlsObject {
    size_t size;
    size_t align;
    uintptr_t index;        /* 0 until first accessed, then 1-based */
    const void *templ;      /* the initial value; NULL: zeros */
} EmutlsObject;

#define ROOT_SIZE (64 * KiB)
#define ROOT_SLOTS 1024

typedef struct TlsChunk {
    struct TlsChunk *next;
} TlsChunk;

typedef struct TlsRoot {
    struct TlsRoot *next;   /* every thread's, for the reaper */
    HANDLE thread;          /* signalled once the thread has ended */
    TlsChunk *chunks;       /* further storage, when the root's is used up */
    char *free, *end;       /* the rest of the current storage */
    void *slot[ROOT_SLOTS]; /* each variable's copy, by index - 1 */
} TlsRoot;

/* The PEB's TLS slot bitmap, and the TEB's slots (64-bit layouts). */
#define PEB_TLS_BITMAP 0x78
#define TEB_PEB 0x60
#define TEB_TLS_SLOTS 0x1480
#define TLS_MINIMUM_SLOTS 64
#define ThreadZeroTlsCell 10

static LONG slot_state;     /* 0 none, 1 being allocated, 2 slot_index */
static ULONG slot_index;
static EmutlsObject *registered[ROOT_SLOTS]; /* by index - 1 */
static TlsRoot *roots;

static G_NORETURN void emutls_fail(const char *why)
{
    xt_stderr_write(why, strlen(why));
    NtTerminateProcess(GetCurrentProcess(), 0xE1000000 | 0x71);
    __builtin_trap();
}

/*
 * A TEB TLS slot for the roots, as kernelbase's TlsAlloc takes one: a bit
 * in the PEB's bitmap under the PEB lock, then the cell cleared in every
 * thread.  One of the first 64, which every TEB has.
 */
void xt_emutls_init(void)
{
    char *peb = *(char **)((char *)NtCurrentTeb() + TEB_PEB);
    ULONG i;

    if (qatomic_load_acquire(&slot_state) == 2) {
        return;
    }
    if (qatomic_cmpxchg(&slot_state, 0, 1) != 0) {
        while (qatomic_load_acquire(&slot_state) != 2) {
            NtYieldExecution();
        }
        return;
    }
    RtlAcquirePebLock();
    i = RtlFindClearBitsAndSet(*(void **)(peb + PEB_TLS_BITMAP), 1, 0);
    RtlReleasePebLock();
    if (i >= TLS_MINIMUM_SLOTS) {
        emutls_fail("libarm64ecxtcg: no TEB TLS slot\n");
    }
    /* A cell left set by an earlier owner of the slot would be a root. */
    if (NtSetInformationThread(GetCurrentThread(),
                               (THREADINFOCLASS)ThreadZeroTlsCell, &i,
                               sizeof(i)) < 0) {
        emutls_fail("libarm64ecxtcg: TEB TLS slot not cleared\n");
    }
    slot_index = i;
    qatomic_store_release(&slot_state, 2);
}

static TlsRoot **root_cell(void)
{
    return (TlsRoot **)((char *)NtCurrentTeb() + TEB_TLS_SLOTS +
                        slot_index * sizeof(void *));
}

/* Storage, through the system call once ProcessInit has made that possible. */
static void *alloc_storage(size_t len)
{
    void *p = xt_syscalls_ready() ? xt_alloc_direct(len) : xt_alloc_high(len);

    if (!p) {
        emutls_fail("libarm64ecxtcg: no memory for thread-local storage\n");
    }
    return p;
}

/* memcpy without a call (the module's comes from ntdll). */
static void copy_bytes(uint8_t *d, const uint8_t *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
        barrier();
    }
}

/* Onto the list of roots; R is the reaper's once there. */
static void push_root(TlsRoot *r)
{
    TlsRoot *head;

    do {
        head = qatomic_read(&roots);
        r->next = head;
    } while (qatomic_cmpxchg(&roots, head, r) != head);
}

static TlsRoot *new_root(void)
{
    TlsRoot *r = alloc_storage(ROOT_SIZE);

    r->free = (char *)(r + 1);
    r->end = (char *)r + ROOT_SIZE;
    *root_cell() = r;
    /* A root the reaper can't see end would never go. */
    if (NtDuplicateObject(GetCurrentProcess(), GetCurrentThread(),
                          GetCurrentProcess(), &r->thread, SYNCHRONIZE, 0,
                          0) < 0) {
        emutls_fail("libarm64ecxtcg: no handle for thread-local storage\n");
    }
    push_root(r);
    return r;
}

static void *new_copy(TlsRoot *r, const EmutlsObject *o)
{
    size_t align = MAX(o->align, sizeof(void *));
    uintptr_t p = ROUND_UP((uintptr_t)r->free, align);

    if (p + o->size > (uintptr_t)r->end) {
        size_t len = ROUND_UP(sizeof(TlsChunk) + align + o->size, ROOT_SIZE);
        TlsChunk *c = alloc_storage(len);

        c->next = r->chunks;
        r->chunks = c;
        r->end = (char *)c + len;
        p = ROUND_UP((uintptr_t)(c + 1), align);
    }
    r->free = (char *)(p + o->size);
    if (o->templ) {
        copy_bytes((uint8_t *)p, o->templ, o->size);
    }
    return (void *)p;
}

/*
 * A variable's first access, on any thread: its entry in the table, the
 * first free one if it has none, gives its index.  An entry never changes
 * once claimed, so threads racing on the same variable find the same one.
 */
static uintptr_t register_object(EmutlsObject *o)
{
    for (size_t j = 0; j < ROOT_SLOTS; j++) {
        EmutlsObject *e = qatomic_read(&registered[j]);

        if (!e) {
            e = qatomic_cmpxchg(&registered[j], NULL, o);
            e = e ? e : o;
        }
        if (e == o) {
            qatomic_store_release(&o->index, j + 1);
            return j + 1;
        }
    }
    emutls_fail("libarm64ecxtcg: too many thread-local variables\n");
}

/* The compiler's call, at every access to a thread-local variable. */
void *__emutls_get_address(EmutlsObject *o);
void *__emutls_get_address(EmutlsObject *o)
{
    uintptr_t i = qatomic_load_acquire(&o->index);
    TlsRoot *r;
    void *p;

    if (!i) {
        i = register_object(o);
    }
    if (qatomic_load_acquire(&slot_state) != 2) {
        xt_emutls_init();
    }
    r = *root_cell();
    if (!r) {
        r = new_root();
    }
    p = r->slot[i - 1];
    if (!p) {
        p = r->slot[i - 1] = new_copy(r, o);
    }
    return p;
}

static void free_region(void *p)
{
    SIZE_T size = 0;

    NtFreeVirtualMemory(GetCurrentProcess(), &p, &size, MEM_RELEASE);
}

/* The roots of threads that have ended go, with their storage. */
void xt_emutls_reap(void)
{
    LARGE_INTEGER zero = { .QuadPart = 0 };
    TlsRoot *r = qatomic_xchg(&roots, NULL), *next;

    for (; r; r = next) {
        next = r->next;
        if (NtWaitForSingleObject(r->thread, FALSE, &zero) == STATUS_SUCCESS) {
            NtClose(r->thread);
            while (r->chunks) {
                TlsChunk *c = r->chunks;

                r->chunks = c->next;
                free_region(c);
            }
            free_region(r);
            continue;
        }
        push_root(r);
    }
}
