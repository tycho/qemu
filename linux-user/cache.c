/*
 * linux-user: the translation cache's files (tcg-cache.h), for testing
 * the format, publication and refresh on a host where processes come and
 * go cheaply.  x-cache=files (QEMU_XTCG=cache=files) with
 * XTCG_CACHE_DIR=dir turns it on.
 *
 * The directory is dir/<fingerprint>: a hash of everything that changes
 * the code a translation gives (QEMU's build, its resolved settings, the
 * guest base and CPU, the host's features), so another build or setting
 * never reads it.  It and every file in it must be the user's and not
 * writable by anyone else, or the cache is off (the directory) or the file
 * skipped.
 *
 * Publication, snapshots and the writer thread are the directory back
 * end's (tcg/tcg-cache-dir.c.inc); this is its POSIX side.  Files are
 * read with pread, published by temporary file and rename.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include <dirent.h>
#include <link.h>
#include <sys/file.h>
#include <sys/mman.h>
#include "qemu/thread.h"
#include "qemu/rcu.h"
#include "qemu/timer.h"
#include "qemu/log.h"
#include "qom/object.h"
#include "qemu/accel.h"
#include "user/guest-base.h"
#include "user/guest-host.h"
#include "host/cpuinfo.h"
#include "tcg/startup.h"
#include "tcg/tcg-cache.h"
#include "exec/translation-block.h"
#include "qemu/cutils.h"
#include "qemu.h"
#include "user-internals.h"

static int cache_dirfd = -1;

/* QEMU's own build ID, from its GNU build-id note. */
typedef struct BuildId {
    uint8_t id[64];
    size_t len;
} BuildId;

static int build_id_cb(struct dl_phdr_info *info, size_t size, void *data)
{
    BuildId *b = data;

    /* The first object is the executable itself. */
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        const uint8_t *p, *end;

        if (ph->p_type != PT_NOTE) {
            continue;
        }
        p = (const uint8_t *)(info->dlpi_addr + ph->p_vaddr);
        end = p + ph->p_memsz;
        while (p + 12 <= end) {
            uint32_t namesz = ldl_he_p(p), descsz = ldl_he_p(p + 4);
            uint32_t type = ldl_he_p(p + 8);
            const uint8_t *name = p + 12;
            const uint8_t *desc = name + ROUND_UP(namesz, 4);

            if (desc + ROUND_UP(descsz, 4) > end) {
                break;
            }
            if (type == 3 && namesz == 4 && !memcmp(name, "GNU", 4)
                && descsz && descsz <= sizeof(b->id)) {
                memcpy(b->id, desc, descsz);
                b->len = descsz;
                return 1;
            }
            p = desc + ROUND_UP(descsz, 4);
        }
    }
    return 1;
}

/* g_ptr_array_sort passes pointers to the elements. */
static gint prop_cmp(gconstpointer a, gconstpointer b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/*
 * The fingerprint: everything that changes what a translation emits, in
 * a fixed order, hashed.  After tcg_prologue_init, which decides the
 * return stack's register.  False if QEMU has no build ID.
 */
static bool cache_fingerprint(const char *cpu_model, char *hex)
{
    g_autoptr(GString) g = g_string_new("xtcg-cache 1\n");
    Object *accel = OBJECT(current_accel());
    ObjectPropertyIterator iter;
    ObjectProperty *prop;
    g_autoptr(GPtrArray) props = g_ptr_array_new_with_free_func(g_free);
    BuildId b = { };
    uint64_t h0, h1;

    dl_iterate_phdr(build_id_cb, &b);
    if (!b.len) {
        return false;
    }
    g_string_append(g, "build ");
    for (size_t i = 0; i < b.len; i++) {
        g_string_append_printf(g, "%02x", b.id[i]);
    }
    g_string_append_printf(g, "\ntarget %s\ncpu %s\n", TARGET_NAME,
                           cpu_model ? cpu_model : "");
    g_string_append_printf(g, "guest_base %" PRIxPTR " reserved_va %"
                           PRIxPTR "\n", guest_base, reserved_va);
    g_string_append_printf(g, "page_bits %d host_page %zu\n",
                           TARGET_PAGE_BITS, qemu_real_host_page_size());
    g_string_append_printf(g, "cpuinfo %" PRIx64 " lazysync %d pin %d\n",
                           (uint64_t)cpuinfo, tcg_lazysync_user,
                           tcg_pin_user);
    g_string_append_printf(g, "loglevel %x\n", qemu_loglevel);
    g_string_append_printf(g, "sizes env %zu tb %zu slots %d\n",
                           sizeof(CPUArchState), sizeof(TranslationBlock),
                           TB_JMP_SLOTS);
    object_property_iter_init(&iter, accel);
    while ((prop = object_property_iter_next(&iter))) {
        if (prop->get) {
            g_autofree char *v = object_property_print(accel, prop->name,
                                                       true, NULL);

            g_ptr_array_add(props, g_strdup_printf("%s=%s\n", prop->name,
                                                   v ? v : "?"));
        }
    }
    g_ptr_array_sort(props, prop_cmp);
    for (guint i = 0; i < props->len; i++) {
        g_string_append(g, g_ptr_array_index(props, i));
    }
    h0 = tcg_cache_hash64(0, g->str, g->len);
    h1 = tcg_cache_hash64(1, g->str, g->len);
    stq_le_p(tcg_cache_fingerprint, h0);
    stq_le_p(tcg_cache_fingerprint + 8, h1);
    snprintf(hex, 33, "%016" PRIx64 "%016" PRIx64, h0, h1);
    if (getenv("XTCG_CACHE_FPSHOW")) {
        fprintf(stderr, "xtcg-cache fingerprint %s:\n%s", hex, g->str);
    }
    return true;
}

/* @fd's file: a regular file or directory of ours nobody else writes. */
static bool cache_owned(int fd, bool dir)
{
    struct stat st;

    return !fstat(fd, &st) && st.st_uid == getuid()
           && !(st.st_mode & (S_IWGRP | S_IWOTH))
           && (dir ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode));
}

static int cache_open_dir(int at, const char *name)
{
    int fd;

    if (mkdirat(at, name, 0700) && errno != EEXIST) {
        return -1;
    }
    fd = openat(at, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0 && !cache_owned(fd, true)) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    return fd;
}

/* The POSIX side of the directory back end (TCGCacheDirOps). */

static int posix_list(TCGCacheDirEntryFn *fn, void *opaque, int max)
{
    /* Its own open file description: a dup would share the offset. */
    int dfd = openat(cache_dirfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *d = dfd >= 0 ? fdopendir(dfd) : NULL;
    struct dirent *de;
    bool failed = false;
    int seen = 0;

    if (!d) {
        if (dfd >= 0) {
            close(dfd);
        }
        return -1;
    }
    while (seen < max) {
        char name[64] = "";
        struct stat st;

        errno = 0;
        de = readdir(d);
        if (!de) {
            if (errno) {
                seen = -1;
            }
            break;
        }

        seen++;
        /* As a coverage list holds it: a 64-byte field, zero after it. */
        if (strlen(de->d_name) >= 64) {
            continue;
        }
        /* Gone since: absent.  Any other failure: the listing is unsure. */
        if (fstatat(cache_dirfd, de->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
            if (errno != ENOENT) {
                failed = true;
            }
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            continue;
        }
        /* Zero-padded, as a coverage list holds a name. */
        memcpy(name, de->d_name, strlen(de->d_name));
        fn(opaque, name, st.st_size, st.st_mtime);
    }
    closedir(d);
    return failed ? -1 : seen;
}

static void *posix_open(const char *name, size_t *sizep)
{
    struct stat st;
    /* Not blocking: a FIFO by that name must not hold the scan. */
    int fd = openat(cache_dirfd, name,
                    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);

    if (fd < 0) {
        return NULL;
    }
    if (!cache_owned(fd, false) || fstat(fd, &st)) {
        close(fd);
        return NULL;
    }
    *sizep = st.st_size;
    return (void *)(intptr_t)(fd + 1);
}

static int posix_fd(void *fh)
{
    return (int)(intptr_t)fh - 1;
}

static int64_t posix_read(void *fh, void *dst, uint64_t off, size_t len)
{
    size_t done = 0;

    while (done < len) {
        ssize_t n = pread(posix_fd(fh), (uint8_t *)dst + done, len - done,
                          off + done);

        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return TCG_CACHE_GFAULT;
        }
        done += n;
    }
    return 0;
}

static const void *posix_map(void *fh, size_t size)
{
    void *map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, posix_fd(fh), 0);

    return map == MAP_FAILED ? NULL : map;
}

static void posix_close(void *fh)
{
    close(posix_fd(fh));
}

static void posix_unmap(const void *map, size_t size)
{
    munmap((void *)map, size);
}

/* A temporary file, exclusively created: a name taken, the next. */
static int posix_tmp(char *tmp, size_t size)
{
    static uint64_t counter;
    int fd = -1;

    for (int i = 0; i < 4 && fd < 0; i++) {
        snprintf(tmp, size, "tmp-%x-%" PRIx64, getpid(),
                 qatomic_fetch_inc(&counter));
        fd = openat(cache_dirfd, tmp,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
        if (fd < 0 && errno != EEXIST) {
            break;
        }
    }
    return fd;
}

static bool posix_publish(const void *data, size_t len, const char *name,
                          unsigned pause_ms)
{
    char tmp[64];
    size_t done = 0;
    int fd = posix_tmp(tmp, sizeof(tmp));

    if (fd < 0) {
        return false;
    }
    while (done < len) {
        ssize_t n = write(fd, (const uint8_t *)data + done, len - done);

        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            break;
        }
        done += n;
    }
    if (pause_ms) {
        g_usleep(pause_ms * 1000);
    }
    close(fd);
    if (done != len
        || (renameat2(cache_dirfd, tmp, cache_dirfd, name, RENAME_NOREPLACE)
            && (errno != EINVAL && errno != ENOSYS
                ? true
                : linkat(cache_dirfd, tmp, cache_dirfd, name, 0)))) {
        unlinkat(cache_dirfd, tmp, 0);
        return false;
    }
    /* linkat's fallback leaves the temporary name too. */
    unlinkat(cache_dirfd, tmp, 0);
    return true;
}

typedef struct PosixTmp {
    int fd;
    char name[64];
} PosixTmp;

static void *posix_create(void)
{
    PosixTmp *t = g_new0(PosixTmp, 1);

    t->fd = posix_tmp(t->name, sizeof(t->name));
    if (t->fd < 0) {
        g_free(t);
        return NULL;
    }
    return t;
}

static bool posix_write(void *wh, const void *data, size_t len, uint64_t off)
{
    PosixTmp *t = wh;
    size_t done = 0;

    while (done < len) {
        ssize_t n = pwrite(t->fd, (const uint8_t *)data + done, len - done,
                           off + done);

        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            return false;
        }
        done += n;
    }
    return true;
}

static void posix_drop(void *wh)
{
    PosixTmp *t = wh;

    close(t->fd);
    unlinkat(cache_dirfd, t->name, 0);
    g_free(t);
}

static bool posix_commit(void *wh, const char *name)
{
    PosixTmp *t = wh;
    bool ok;

    close(t->fd);
    ok = !renameat2(cache_dirfd, t->name, cache_dirfd, name, RENAME_NOREPLACE)
         || ((errno == EINVAL || errno == ENOSYS)
             && !linkat(cache_dirfd, t->name, cache_dirfd, name, 0));
    /* linkat's fallback leaves the temporary name too. */
    unlinkat(cache_dirfd, t->name, 0);
    g_free(t);
    return ok;
}

static bool posix_remove(const char *name)
{
    return !unlinkat(cache_dirfd, name, 0);
}

static void *posix_trylock(void)
{
    int fd = openat(cache_dirfd, "lock",
                    O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);

    if (fd < 0) {
        return NULL;
    }
    if (!cache_owned(fd, false) || flock(fd, LOCK_EX | LOCK_NB)) {
        close(fd);
        return NULL;
    }
    return (void *)(intptr_t)(fd + 1);
}

static void posix_unlock(void *lh)
{
    close((int)(intptr_t)lh - 1);
}

static TCGCacheDirOps posix_ops = {
    .list = posix_list,
    .open = posix_open,
    .read = posix_read,
    .map = posix_map,
    .close = posix_close,
    .unmap = posix_unmap,
    .publish = posix_publish,
    .create = posix_create,
    .write = posix_write,
    .commit = posix_commit,
    .drop = posix_drop,
    .remove = posix_remove,
    .trylock = posix_trylock,
    .unlock = posix_unlock,
};

/*
 * After tcg_prologue_init: the fingerprint, the directory, then the
 * first snapshot (here, so that a short process's first TBs can hit)
 * and the writer.
 */
void tcg_cache_dir_init(const char *cpu_model)
{
    const char *base = getenv("XTCG_CACHE_DIR");
    char hex[33];
    int64_t t0 = get_clock();
    int bfd;

    if (tcg_cache_mode != TCG_CACHE_ON || !tcg_cache_files) {
        return;
    }
    if (!base) {
        fprintf(stderr, "xtcg-cache: x-cache=files without XTCG_CACHE_DIR: "
                "files off\n");
        return;
    }
    if (!cache_fingerprint(cpu_model, hex)) {
        fprintf(stderr, "xtcg-cache: no build ID: files off\n");
        return;
    }
    bfd = cache_open_dir(AT_FDCWD, base);
    if (bfd < 0) {
        fprintf(stderr, "xtcg-cache: %s: %s: files off\n", base,
                strerror(errno));
        return;
    }
    cache_dirfd = cache_open_dir(bfd, hex);
    close(bfd);
    if (cache_dirfd < 0) {
        fprintf(stderr, "xtcg-cache: %s/%s: %s: files off\n", base, hex,
                strerror(errno));
        return;
    }
    tcg_cache_born = time(NULL) / 86400;
    posix_ops.pid = getpid();
    tcg_cache_dir_start(&posix_ops, t0);
}
