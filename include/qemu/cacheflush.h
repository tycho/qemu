/*
 * Flush the host cpu caches.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef QEMU_CACHEFLUSH_H
#define QEMU_CACHEFLUSH_H

/**
 * flush_idcache_range:
 * @rx: instruction address
 * @rw: data address
 * @len: length to flush
 *
 * Flush @len bytes of the data cache at @rw and the icache at @rx
 * to bring them in sync.  The two addresses may be different virtual
 * mappings of the same physical page(s).
 */

#if defined(HOST_X86_64) || defined(__s390x__)

static inline void flush_idcache_range(uintptr_t rx, uintptr_t rw, size_t len)
{
    /* icache is coherent and does not require flushing. */
}

#elif defined(EMSCRIPTEN)

static inline void flush_idcache_range(uintptr_t rx, uintptr_t rw, size_t len)
{
    /* Wasm doesn't have executable region of memory. */
}

#else

void flush_idcache_range(uintptr_t rx, uintptr_t rw, size_t len);

#endif

/**
 * flush_idcache_range2:
 * @rx0, @rw0, @len0: the first range, as for flush_idcache_range
 * @rx1, @rw1, @len1: the second range; @len1 may be 0
 *
 * As flush_idcache_range for both ranges, synchronizing once where the
 * host allows it.
 */
#if defined(HOST_AARCH64) && !defined(CONFIG_DARWIN)

#ifdef CONFIG_WIN32
/* Testing: take FlushInstructionCache even when IDC and DIC are set. */
extern bool qemu_icache_test_fallback;
#endif

void flush_idcache_range2(uintptr_t rx0, uintptr_t rw0, size_t len0,
                          uintptr_t rx1, uintptr_t rw1, size_t len1);

#else

static inline void flush_idcache_range2(uintptr_t rx0, uintptr_t rw0,
                                        size_t len0, uintptr_t rx1,
                                        uintptr_t rw1, size_t len1)
{
    if (len0) {
        flush_idcache_range(rx0, rw0, len0);
    }
    if (len1) {
        flush_idcache_range(rx1, rw1, len1);
    }
}

#endif

#endif /* QEMU_CACHEFLUSH_H */
