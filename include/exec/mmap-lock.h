/*
 * QEMU user-only mmap lock, with stubs for system mode
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef EXEC_MMAP_LOCK_H
#define EXEC_MMAP_LOCK_H

#ifdef CONFIG_USER_ONLY

void TSA_NO_TSA mmap_lock(void);
void TSA_NO_TSA mmap_unlock(void);
bool have_mmap_lock(void);

/*
 * A translation's hold (tb_gen_code).  Where the port lets threads
 * translate in parallel, one that excludes every mmap_lock holder but not
 * other translations, whose own mmap_lock calls then serialize only with
 * each other; elsewhere the mmap lock itself.
 */
void TSA_NO_TSA mmap_lock_translation(void);
void TSA_NO_TSA mmap_unlock_translation(void);
bool have_mmap_lock_translation(void);

/*
 * After a longjmp out of translation or a locked section: release every
 * level of the mmap lock and the translation's hold this thread has.
 */
void mmap_lock_reset(void);

static inline void mmap_unlock_guard(void *unused)
{
    mmap_unlock();
}

#define WITH_MMAP_LOCK_GUARD() \
    for (int _mmap_lock_iter __attribute__((cleanup(mmap_unlock_guard))) \
         = (mmap_lock(), 0); _mmap_lock_iter == 0; _mmap_lock_iter = 1)

#else

static inline void mmap_lock(void) {}
static inline void mmap_unlock(void) {}
static inline void mmap_lock_translation(void) {}
static inline void mmap_unlock_translation(void) {}
#define WITH_MMAP_LOCK_GUARD()

#endif /* CONFIG_USER_ONLY */
#endif /* EXEC_MMAP_LOCK_H */
