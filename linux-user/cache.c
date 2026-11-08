/*
 * linux-user: the translation cache's files (tcg-cache.h), for testing
 * the format, publication and refresh on a host where processes come and
 * go cheaply.  XTCG_CACHE=on XTCG_CACHE_DIR=dir turns it on.
 *
 * The directory is dir/<fingerprint>: a hash of everything that changes
 * the code a translation gives (QEMU's build, its resolved settings, the
 * guest base and CPU, the host's features), so another build or setting
 * never reads it.  It and every file in it must be the user's and not
 * writable by anyone else, or the cache is off (the directory) or the file
 * skipped.
 *
 * Each process publishes its captures as segments, by temporary file and
 * rename, and maps the newest segments (and a pack, if one covers older
 * ones) into a snapshot the lookups read.  A writer thread publishes and
 * refreshes the snapshot; it reads files with pread only, never through a
 * mapping, so that a file truncated under it can't fault it.  The
 * translating threads read the mappings through the guarded copy.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include <dirent.h>
#include <link.h>
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
static bool cache_child;            /* a fork's child: read only */
static QemuThread writer;
static QemuMutex wlock;
static QemuCond wcond;
static bool writer_on;
static uint64_t seg_counter, tmp_counter;
static int64_t last_refresh;
static unsigned hold_ms;

#define CACHE_ENUM_MAX      256
#define CACHE_LOOSE_MAX     (TCG_CACHE_SNAP_FILES - 1)
#define CACHE_AGE_NS        (2 * NANOSECONDS_PER_SECOND)
#define CACHE_REFRESH_NS    NANOSECONDS_PER_SECOND

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

/*
 * Checked reads for the writer thread: tcg_cache_file_open's reads of a
 * file not mapped, by pread from its descriptor.  @src is an offset from
 * a base that is never dereferenced.
 */
static __thread int pread_fd = -1;
#define PREAD_BASE ((const uint8_t *)(uintptr_t)4096)

static int64_t pread_copy(void *dst, const void *src, size_t len)
{
    off_t off = (const uint8_t *)src - PREAD_BASE;

    return pread(pread_fd, dst, len, off) == (ssize_t)len ? 0
           : TCG_CACHE_GFAULT;
}

/* A file to read: opened, owned, its header read and checked by pread. */
typedef struct CacheCand {
    char name[64];
    uint64_t tick;
    uint64_t hdr_check;
    size_t size;
    bool pack;
} CacheCand;

static int cache_open_file(const char *name, TCGCacheFile *f, size_t *sizep)
{
    struct stat st;
    /* Not blocking: a FIFO by that name must not hold the scan. */
    int fd = openat(cache_dirfd, name,
                    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    int r;

    if (fd < 0) {
        tcg_cache_stats.snap_refused++;
        return -1;
    }
    if (!cache_owned(fd, false) || fstat(fd, &st)
        || st.st_size < sizeof(TCGCacheFileHdr)
        || st.st_size > TCG_CACHE_FILE_MAX) {
        close(fd);
        tcg_cache_stats.snap_refused++;
        return -1;
    }
    pread_fd = fd;
    r = tcg_cache_file_open(f, PREAD_BASE, st.st_size, pread_copy,
                            tcg_cache_nofault);
    pread_fd = -1;
    if (r && tcg_cache_debug) {
        fprintf(stderr, "xtcg-cache dir: %s: %s\n", name, tcg_cache_v_name(r));
    }
    if (r) {
        tcg_cache_file_close(f);
        close(fd);
        tcg_cache_stats.snap_refused++;
        return -1;
    }
    *sizep = st.st_size;
    return fd;
}

/* "pack-" then hexadecimal then ".xtp". */
static bool cache_pack_name_ok(const char *name)
{
    size_t n = strnlen(name, 64);

    if (n == 64 || n < 10 || strncmp(name, "pack-", 5)
        || strcmp(name + n - 4, ".xtp")) {
        return false;
    }
    for (size_t i = 5; i < n - 4; i++) {
        if (!g_ascii_isxdigit(name[i]) || g_ascii_isupper(name[i])) {
            return false;
        }
    }
    return true;
}

static int cand_cmp(const void *a, const void *b)
{
    const CacheCand *x = a, *y = b;

    return x->tick > y->tick ? -1 : x->tick < y->tick;
}

static void snap_release(TCGCacheSnap *s)
{
    for (int i = 0; i < s->n; i++) {
        munmap((void *)s->f[i].map, s->f[i].size);
    }
}

/* Covered by @pack: the same name and the same header. */
static bool covered_by(const TCGCacheFile *pack, const CacheCand *c)
{
    for (uint32_t i = 0; pack && i < pack->hdr.n_cover; i++) {
        if (!strncmp(pack->cover[i].name, c->name, 64)
            && pack->cover[i].hdr_check == c->hdr_check) {
            return true;
        }
    }
    return false;
}

/* Testing: XTCG_CACHE_PAUSE_<where>_MS, a pause at a point of the work. */
static unsigned pause_publish_ms, pause_snap_ms, pause_mapped_ms;
static unsigned pause_exit_ms;
/* Testing (XTCG_CACHE_REFRESH_ALWAYS): refresh every second regardless. */
static bool refresh_always;

static void cache_pause(unsigned ms)
{
    if (ms) {
        g_usleep(ms * 1000);
    }
}

/* Map @name for lookups, into @f; false if it can't be. */
static bool cache_map_file(const char *name, TCGCacheFile *f)
{
    size_t size;
    void *map;
    int fd = cache_open_file(name, f, &size);

    if (fd < 0) {
        return false;
    }
    map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) {
        tcg_cache_file_close(f);
        return false;
    }
    /* From here on read by translating threads, through the guard. */
    f->map = map;
    f->copy = tcg_cache_gcopy;
    f->fault = tcg_cache_nofault;
    return true;
}

/*
 * A snapshot of the directory: the newest valid pack, and the newest
 * CACHE_LOOSE_MAX segments it doesn't cover.  Only checked reads; files
 * are mapped, never read through the mapping here.
 */
static TCGCacheSnap *snap_build(void)
{
    TCGCacheSnap *snap = g_new0(TCGCacheSnap, 1);
    CacheCand cand[CACHE_ENUM_MAX];
    TCGCacheFile pack = { }, *packp = NULL;
    char pack_name[64] = "";
    int ncand = 0, seen = 0, dfd;
    int64_t t0 = get_clock();
    struct dirent *de;
    DIR *d;

    /* Its own open file description: a dup would share the offset. */
    dfd = openat(cache_dirfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    d = dfd >= 0 ? fdopendir(dfd) : NULL;
    if (!d) {
        if (dfd >= 0) {
            close(dfd);
        }
        return snap;
    }
    while ((de = readdir(d)) && seen++ < CACHE_ENUM_MAX) {
        TCGCacheFile f;
        size_t size;
        bool is_pack = cache_pack_name_ok(de->d_name);
        char field[64] = { };
        int fd;

        /* As a coverage list holds it: a 64-byte field, zero after it. */
        if (strlen(de->d_name) >= sizeof(field)) {
            continue;
        }
        memcpy(field, de->d_name, strlen(de->d_name));
        if (!is_pack && !tcg_cache_segment_name_ok(field)) {
            continue;
        }
        fd = cache_open_file(de->d_name, &f, &size);
        if (tcg_cache_debug) {
            fprintf(stderr, "xtcg-cache dir: %s: %s\n", de->d_name,
                    fd < 0 ? "refused" : "ok");
        }
        if (fd < 0) {
            continue;
        }
        close(fd);
        if (is_pack != (f.hdr.magic == TCG_CACHE_PACK_MAGIC)) {
            tcg_cache_file_close(&f);
            continue;
        }
        if (is_pack) {
            if (!packp || f.hdr.tick > pack.hdr.tick) {
                if (packp) {
                    tcg_cache_file_close(&pack);
                }
                pack = f;
                packp = &pack;
                pstrcpy(pack_name, sizeof(pack_name), de->d_name);
            } else {
                tcg_cache_file_close(&f);
            }
            continue;
        }
        cand[ncand] = (CacheCand){ .tick = f.hdr.tick,
                                   .hdr_check = f.hdr.check, .size = size };
        pstrcpy(cand[ncand].name, sizeof(cand[ncand].name), de->d_name);
        ncand++;
        tcg_cache_file_close(&f);
    }
    closedir(d);
    qsort(cand, ncand, sizeof(*cand), cand_cmp);
    cache_pause(pause_snap_ms);

    /*
     * The pack first, mapped: only the pack actually acquired covers
     * anything.  Then the newest loose segments it doesn't cover.
     */
    if (packp) {
        tcg_cache_file_close(&pack);
        packp = NULL;
        if (cache_map_file(pack_name, &pack)) {
            packp = &pack;
        }
    }
    for (int i = 0; i < ncand && snap->n < CACHE_LOOSE_MAX; i++) {
        if (!covered_by(packp, &cand[i])
            && cache_map_file(cand[i].name, &snap->f[snap->n])) {
            snap->n++;
        }
    }
    if (packp) {
        snap->f[snap->n++] = pack;
    }
    snap->release = snap_release;
    tcg_cache_stats.snaps++;
    tcg_cache_stats.snap_files += snap->n;
    tcg_cache_stats.refresh_ns += get_clock() - t0;
    return snap;
}

/*
 * Write @len bytes as a new segment: a temporary file, then a rename.
 * Testing: @pause_ms with the temporary file open.
 */
static bool cache_publish(const void *data, size_t len, unsigned pause_ms)
{
    int64_t t0 = get_clock();
    char tmp[64], name[64];
    size_t flen, done = 0;
    void *file;
    int fd;

    if (tcg_cache_debug) {
        fprintf(stderr, "xtcg-cache publish: %zu bytes, thread %d\n", len,
                qemu_get_thread_id());
    }
    file = tcg_cache_write_file(false, t0, data, len, NULL, 0, &flen);
    if (!file) {
        tcg_cache_stats.publish_fail++;
        return false;
    }
    snprintf(tmp, sizeof(tmp), "tmp-%x-%" PRIx64, getpid(),
             qatomic_fetch_inc(&tmp_counter));
    fd = openat(cache_dirfd, tmp,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        g_free(file);
        tcg_cache_stats.publish_fail++;
        return false;
    }
    while (done < flen) {
        ssize_t n = write(fd, (uint8_t *)file + done, flen - done);

        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            break;
        }
        done += n;
    }
    cache_pause(pause_ms);
    close(fd);
    g_free(file);
    snprintf(name, sizeof(name), "seg-%x-%" PRIx64 "-%" PRIx64 ".xtc",
             getpid(), (uint64_t)t0,
             qatomic_fetch_inc(&seg_counter) ^ ((uint64_t)t0 << 16));
    if (done != flen
        || (renameat2(cache_dirfd, tmp, cache_dirfd, name, RENAME_NOREPLACE)
            && (errno != EINVAL && errno != ENOSYS
                ? true
                : linkat(cache_dirfd, tmp, cache_dirfd, name, 0)))) {
        unlinkat(cache_dirfd, tmp, 0);
        tcg_cache_stats.publish_fail++;
        return false;
    }
    /* linkat's fallback leaves the temporary name too. */
    unlinkat(cache_dirfd, tmp, 0);
    tcg_cache_stats.published++;
    tcg_cache_stats.publish_ns += get_clock() - t0;
    return true;
}

/* At most one round of the buffers, so that refresh isn't put off. */
static void cache_drain(void)
{
    size_t len;
    void *d;

    for (int i = 0; i < TCG_CACHE_BUFS
         && (d = tcg_cache_sink_take(get_clock(), CACHE_AGE_NS, false, false,
                                     &len)); i++) {
        cache_publish(d, len, pause_publish_ms);
        tcg_cache_sink_give(d);
    }
}

static void cache_refresh(void)
{
    TCGCacheSnap *snap;

    if (tcg_cache_snap_waiting()) {
        tcg_cache_stats.snap_skipped++;
        return;
    }
    snap = snap_build();
    if (!tcg_cache_snap_publish(snap)) {
        snap_release(snap);
        for (int i = 0; i < snap->n; i++) {
            tcg_cache_file_close(&snap->f[i]);
        }
        g_free(snap);
        tcg_cache_stats.snap_skipped++;
    }
}

static void writer_wake(void)
{
    qemu_cond_signal(&wcond);
}

/*
 * The writer's work (publishing, building and publishing snapshots) is
 * done holding wwork, which fork takes: a fork never happens in the
 * middle of it, with descriptors open, a snapshot half built or a
 * call_rcu half queued.
 */
static QemuMutex wwork;

static void *writer_main(void *arg)
{
    qemu_mutex_lock(&wlock);
    while (writer_on) {
        int64_t now;

        qemu_cond_timedwait(&wcond, &wlock, 100);
        if (!writer_on) {
            break;
        }
        qemu_mutex_unlock(&wlock);
        qemu_mutex_lock(&wwork);
        cache_drain();
        /* Testing (XTCG_CACHE_HOLD_MS): each of the writer's locks, held. */
        if (hold_ms) {
            tcg_cache_sink_hold(hold_ms);
            qemu_mutex_lock(&wlock);
            g_usleep(hold_ms * 1000);
            qemu_mutex_unlock(&wlock);
        }
        now = get_clock();
        if ((qatomic_read(&tcg_cache_file_missed) || refresh_always)
            && now - last_refresh >= CACHE_REFRESH_NS) {
            qatomic_set(&tcg_cache_file_missed, false);
            last_refresh = now;
            cache_refresh();
        }
        qemu_mutex_unlock(&wwork);
        qemu_mutex_lock(&wlock);
    }
    qemu_mutex_unlock(&wlock);
    return NULL;
}

/*
 * Testing (XTCG_CACHE_MKPACK=good|badcheck): pack every loose segment in
 * the directory into pack-<gen>.xtp, read by pread only, covering them
 * (with "badcheck", each coverage entry's header checksum wrong).  A
 * stand-in for compaction, which deletes nothing.
 */
static void cache_test_pack(bool badcheck)
{
    g_autoptr(GByteArray) data = g_byte_array_new();
    g_autofree TCGCacheCover *cover = g_new0(TCGCacheCover,
                                             TCG_CACHE_COVER_MAX);
    uint32_t n_cover = 0;
    char tmp[64], name[64];
    size_t flen;
    void *file;
    struct dirent *de;
    int dfd = openat(cache_dirfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *d = dfd >= 0 ? fdopendir(dfd) : NULL;
    int fd;

    while (d && (de = readdir(d)) && n_cover < TCG_CACHE_COVER_MAX) {
        char field[64] = { };
        TCGCacheFile f;
        size_t size;
        uint8_t *buf;

        if (strlen(de->d_name) >= sizeof(field)) {
            continue;
        }
        memcpy(field, de->d_name, strlen(de->d_name));
        if (!tcg_cache_segment_name_ok(field)) {
            continue;
        }
        fd = cache_open_file(field, &f, &size);
        if (fd < 0) {
            continue;
        }
        buf = g_malloc(f.hdr.data_len);
        if (pread(fd, buf, f.hdr.data_len, f.hdr.data_off)
            == f.hdr.data_len) {
            g_byte_array_append(data, buf, f.hdr.data_len);
            memcpy(cover[n_cover].name, field, sizeof(field));
            cover[n_cover].hdr_check = f.hdr.check ^ (badcheck ? 1 : 0);
            n_cover++;
        }
        g_free(buf);
        tcg_cache_file_close(&f);
        close(fd);
    }
    if (d) {
        closedir(d);
    }
    file = tcg_cache_write_file(true, 1, data->data, data->len, cover,
                                n_cover, &flen);
    if (!file) {
        fprintf(stderr, "xtcg-cache: test pack: nothing written\n");
        return;
    }
    snprintf(tmp, sizeof(tmp), "tmp-pack-%x", getpid());
    snprintf(name, sizeof(name), "pack-%x.xtp", 1);
    fd = openat(cache_dirfd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                0600);
    if (fd < 0 || write(fd, file, flen) != (ssize_t)flen) {
        fprintf(stderr, "xtcg-cache: test pack: %s\n", strerror(errno));
    } else {
        renameat(cache_dirfd, tmp, cache_dirfd, name);
        fprintf(stderr, "xtcg-cache: test pack: %u segments, %zu bytes\n",
                n_cover, flen);
    }
    if (fd >= 0) {
        close(fd);
    }
    g_free(file);
}

/*
 * After tcg_prologue_init: the fingerprint, the directory, the first
 * snapshot (here, so that a short process's first TBs can hit), the
 * writer.
 */
void tcg_cache_dir_init(const char *cpu_model)
{
    const char *base = getenv("XTCG_CACHE_DIR");
    char hex[33];
    int64_t t0 = get_clock();
    int bfd;

    if (!base || tcg_cache_mode != TCG_CACHE_ON) {
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
    if (getenv("XTCG_CACHE_HOLD_MS")) {
        hold_ms = atoi(getenv("XTCG_CACHE_HOLD_MS"));
    }
    if (getenv("XTCG_CACHE_PAUSE_PUBLISH_MS")) {
        pause_publish_ms = atoi(getenv("XTCG_CACHE_PAUSE_PUBLISH_MS"));
    }
    if (getenv("XTCG_CACHE_PAUSE_SNAP_MS")) {
        pause_snap_ms = atoi(getenv("XTCG_CACHE_PAUSE_SNAP_MS"));
    }
    if (getenv("XTCG_CACHE_PAUSE_EXIT_MS")) {
        pause_exit_ms = atoi(getenv("XTCG_CACHE_PAUSE_EXIT_MS"));
    }
    if (getenv("XTCG_CACHE_PAUSE_MAPPED_MS")) {
        pause_mapped_ms = atoi(getenv("XTCG_CACHE_PAUSE_MAPPED_MS"));
    }
    if (getenv("XTCG_CACHE_PAUSE_RETIRE_MS")) {
        tcg_cache_retire_pause_ms = atoi(getenv("XTCG_CACHE_PAUSE_RETIRE_MS"));
    }
    refresh_always = getenv("XTCG_CACHE_REFRESH_ALWAYS");
    if (getenv("XTCG_CACHE_PAUSE_PUT_MS")) {
        tcg_cache_sink_pause_ms = atoi(getenv("XTCG_CACHE_PAUSE_PUT_MS"));
    }
    if (getenv("XTCG_CACHE_MKPACK")) {
        cache_test_pack(!strcmp(getenv("XTCG_CACHE_MKPACK"), "badcheck"));
    }
    tcg_cache_snap_publish(snap_build());
    tcg_cache_stats.startup_ns = get_clock() - t0;
    /* Testing: the files are mapped; a test may change them now. */
    cache_pause(pause_mapped_ms);
    qemu_mutex_init(&wlock);
    qemu_mutex_init(&wwork);
    qemu_cond_init(&wcond);
    tcg_cache_sink_wake = writer_wake;
    tcg_cache_sink_init();
    writer_on = true;
    last_refresh = get_clock();
    qemu_thread_create(&writer, "xtcg-cache", writer_main, NULL,
                       QEMU_THREAD_DETACHED);
}

/* A clean exit: whatever was captured, published from this thread. */
void tcg_cache_dir_exit(void)
{
    void *data[TCG_CACHE_BUFS];
    size_t lens[TCG_CACHE_BUFS];
    int n;

    if (cache_dirfd < 0 || cache_child) {
        return;
    }
    /* Captures stop here; what is already there, at most the buffers. */
    n = tcg_cache_sink_close(data, lens);
    if (tcg_cache_debug) {
        fprintf(stderr, "xtcg-cache exit: %d buffers claimed\n", n);
    }
    /*
     * Published as the writer's work is, under wwork, so that another
     * thread's fork doesn't inherit it half done; if the writer has it,
     * best effort gives up.
     */
    /* Testing (XTCG_CACHE_EXIT_NOLOCK): without it, the hazard shows. */
    if (n && getenv("XTCG_CACHE_EXIT_NOLOCK")) {
        for (int i = 0; i < n; i++) {
            cache_publish(data[i], lens[i], pause_exit_ms);
        }
    } else if (n && !qemu_mutex_trylock(&wwork)) {
        for (int i = 0; i < n; i++) {
            cache_publish(data[i], lens[i], pause_exit_ms);
        }
        qemu_mutex_unlock(&wwork);
    }
}

/*
 * fork: the sink's lock and the writer's held across it.  The child has
 * no writer; it keeps its snapshot's mappings for lookups, publishes
 * nothing, and its locks are made afresh, so that it may fork again.
 */
void tcg_cache_dir_fork_start(void)
{
    if (cache_dirfd < 0) {
        return;
    }
    qemu_mutex_lock(&wwork);
    qemu_mutex_lock(&wlock);
    tcg_cache_sink_fork_start();
}

void tcg_cache_dir_fork_end(bool child)
{
    if (cache_dirfd < 0) {
        return;
    }
    tcg_cache_sink_fork_end(child);
    if (child) {
        tcg_cache_snap_fork_child();
        tcg_cache_sink_wake = NULL;
        qemu_mutex_init(&wlock);
        qemu_mutex_init(&wwork);
        qemu_cond_init(&wcond);
        writer_on = false;
        cache_child = true;
    } else {
        qemu_mutex_unlock(&wlock);
        qemu_mutex_unlock(&wwork);
    }
}
