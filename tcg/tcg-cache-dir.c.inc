/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The translation cache's directory (tcg-cache.h), on any OS: a writer
 * thread that publishes the sink's buffers as segments and keeps the
 * lookups' snapshot fresh, the snapshot's choice of files, the exit's
 * publication, and fork.  The OS's part (TCGCacheDirOps) lists, opens,
 * reads, maps and publishes the files of a directory it has checked.
 * Included in tcg.c after tcg-cache-file.c.inc.
 *
 * Each process publishes its captures as segments, and maps the newest
 * segments (and a pack, if one covers older ones) into a snapshot the
 * lookups read.  The writer reads files with ops->read only, never
 * through a mapping, so that a file changed under it can't fault it; the
 * translating threads read the mappings through the guarded copy.
 */

static const TCGCacheDirOps *dir_ops;
static bool dir_child;              /* a fork's child: read only */
/*
 * Who ends the back end: one terminating thread takes it, by
 * compare-and-exchange from DIR_RUNNING, to quiesce it (DIR_QUIESCED) or
 * to publish at exit (DIR_EXITING).  Once it is taken the writer starts no
 * refresh; one already started is waited for by the quiesce.  The OS runs
 * these calls where a terminating thread can't be suspended inside them,
 * so none is left holding a lock.
 */
enum { DIR_RUNNING, DIR_QUIESCED, DIR_EXITING };
static int dir_shutdown;
static int dir_shutdown_tid;        /* DIR_QUIESCED's thread, holding wwork */
static bool dir_quiescing;          /* a quiesce has begun */
static bool dir_quiet;              /* and is complete */
static QemuThread dir_writer;
static QemuMutex dir_wlock;
static QemuCond dir_wcond;
static bool dir_writer_on;
static uint64_t dir_seg_counter;
static int64_t dir_last_refresh;
/* The exit's segment, written without allocating. */
static void *dir_exit_buf;
static size_t dir_exit_cap;

/*
 * The writer's work (publishing, building and publishing snapshots) is
 * done holding dir_wwork, which fork and the exit's publication take: a
 * fork never happens in the middle of it, with files open, a snapshot
 * half built or a call_rcu half queued, and the exit never publishes
 * beside it.
 */
static QemuMutex dir_wwork;

#define DIR_ENUM_MAX        256
#define DIR_LOOSE_MAX       (TCG_CACHE_SNAP_FILES - 1)
#define DIR_AGE_NS          (2 * NANOSECONDS_PER_SECOND)
#define DIR_REFRESH_NS      NANOSECONDS_PER_SECOND

/*
 * Testing: XTCG_CACHE_HOLD_MS, each of the writer's locks held;
 * XTCG_CACHE_PAUSE_<where>_MS, a pause at a point of the work (CLAIM:
 * the exit's, once it has taken the shutdown);
 * XTCG_CACHE_REFRESH_ALWAYS, a refresh every second regardless;
 * XTCG_CACHE_EXIT_NOLOCK, the exit's publication without dir_wwork.
 * Read at start, so that the writer never reads the environment.
 */
static unsigned dir_hold_ms, dir_pause_publish_ms, dir_pause_snap_ms;
static unsigned dir_pause_mapped_ms, dir_pause_exit_ms, dir_pause_claim_ms;
static bool dir_refresh_always, dir_exit_nolock;
/* Testing (XTCG_CACHE_TEST_LOSE): quiesce as if an exit had the shutdown. */
static bool dir_test_lose;

static unsigned dir_env_ms(const char *name)
{
    const char *v = getenv(name);

    return v ? atoi(v) : 0;
}

static void dir_pause(unsigned ms)
{
    if (ms) {
        g_usleep(ms * 1000);
    }
}

/*
 * Checked reads for the writer thread: tcg_cache_file_open's reads of a
 * file not mapped, by ops->read.  @src is an offset from a base that is
 * never dereferenced.
 */
static __thread void *dir_read_fh;
#define DIR_READ_BASE ((const uint8_t *)(uintptr_t)4096)

static int64_t dir_read_copy(void *dst, const void *src, size_t len)
{
    return dir_ops->read(dir_read_fh, dst,
                         (const uint8_t *)src - DIR_READ_BASE, len);
}

/* A file to read: opened, owned, its header read and checked. */
typedef struct DirCand {
    char name[64];
    uint64_t tick;
    uint64_t hdr_check;
} DirCand;

static void *dir_open_file(const char *name, TCGCacheFile *f, size_t *sizep)
{
    size_t size;
    void *fh = dir_ops->open(name, &size);
    int r;

    if (!fh) {
        tcg_cache_stats.snap_refused++;
        return NULL;
    }
    if (size < sizeof(TCGCacheFileHdr) || size > TCG_CACHE_FILE_MAX) {
        dir_ops->close(fh);
        tcg_cache_stats.snap_refused++;
        return NULL;
    }
    dir_read_fh = fh;
    r = tcg_cache_file_open(f, DIR_READ_BASE, size, dir_read_copy,
                            tcg_cache_nofault);
    dir_read_fh = NULL;
    if (r && tcg_cache_debug) {
        fprintf(stderr, "xtcg-cache dir: %s: %s\n", name, tcg_cache_v_name(r));
    }
    if (r) {
        tcg_cache_file_close(f);
        dir_ops->close(fh);
        tcg_cache_stats.snap_refused++;
        return NULL;
    }
    *sizep = size;
    return fh;
}

/* "pack-" then lower-case hexadecimal then ".xtp". */
static bool dir_pack_name_ok(const char *name)
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

static int dir_cand_cmp(const void *a, const void *b)
{
    const DirCand *x = a, *y = b;

    return x->tick > y->tick ? -1 : x->tick < y->tick;
}

static void dir_snap_release(TCGCacheSnap *s)
{
    for (int i = 0; i < s->n; i++) {
        dir_ops->unmap(s->f[i].map, s->f[i].size);
    }
}

/* Covered by @pack: the same name and the same header. */
static bool dir_covered_by(const TCGCacheFile *pack, const DirCand *c)
{
    for (uint32_t i = 0; pack && i < pack->hdr.n_cover; i++) {
        if (!strncmp(pack->cover[i].name, c->name, 64)
            && pack->cover[i].hdr_check == c->hdr_check) {
            return true;
        }
    }
    return false;
}

/* Map @name for lookups, into @f; false if it can't be. */
static bool dir_map_file(const char *name, TCGCacheFile *f)
{
    size_t size;
    const void *map;
    void *fh = dir_open_file(name, f, &size);

    if (!fh) {
        return false;
    }
    map = dir_ops->map(fh, size);
    dir_ops->close(fh);
    if (!map) {
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
 * DIR_LOOSE_MAX segments it doesn't cover.  Only checked reads; files
 * are mapped, never read through the mapping here.
 */
static TCGCacheSnap *dir_snap_build(void)
{
    TCGCacheSnap *snap = g_new0(TCGCacheSnap, 1);
    g_autofree char (*names)[64] = g_malloc0(DIR_ENUM_MAX * 64);
    g_autofree DirCand *cand = g_new0(DirCand, DIR_ENUM_MAX);
    TCGCacheFile pack = { }, *packp = NULL;
    char pack_name[64] = "";
    int ncand = 0, nnames;
    int64_t t0 = get_clock();

    nnames = dir_ops->list(names, DIR_ENUM_MAX);
    for (int i = 0; i < nnames; i++) {
        const char *name = names[i];
        bool is_pack = dir_pack_name_ok(name);
        TCGCacheFile f;
        size_t size;
        void *fh;

        if (!is_pack && !tcg_cache_segment_name_ok(name)) {
            continue;
        }
        fh = dir_open_file(name, &f, &size);
        if (tcg_cache_debug) {
            fprintf(stderr, "xtcg-cache dir: %s: %s\n", name,
                    fh ? "ok" : "refused");
        }
        if (!fh) {
            continue;
        }
        dir_ops->close(fh);
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
                memcpy(pack_name, name, sizeof(pack_name));
            } else {
                tcg_cache_file_close(&f);
            }
            continue;
        }
        cand[ncand] = (DirCand){ .tick = f.hdr.tick,
                                 .hdr_check = f.hdr.check };
        memcpy(cand[ncand].name, name, sizeof(cand[ncand].name));
        ncand++;
        tcg_cache_file_close(&f);
    }
    qsort(cand, ncand, sizeof(*cand), dir_cand_cmp);
    if (tcg_cache_debug) {
        fprintf(stderr, "xtcg-cache dir: %d entries, %d segments, pack %s\n",
                nnames, ncand, packp ? pack_name : "none");
    }
    dir_pause(dir_pause_snap_ms);

    /*
     * The pack first, mapped: only the pack actually acquired covers
     * anything.  Then the newest loose segments it doesn't cover.
     */
    if (packp) {
        tcg_cache_file_close(&pack);
        packp = NULL;
        if (dir_map_file(pack_name, &pack)) {
            packp = &pack;
        }
    }
    for (int i = 0; i < ncand && snap->n < DIR_LOOSE_MAX; i++) {
        if (!dir_covered_by(packp, &cand[i])
            && dir_map_file(cand[i].name, &snap->f[snap->n])) {
            snap->n++;
        }
    }
    if (packp) {
        snap->f[snap->n++] = pack;
    }
    snap->release = dir_snap_release;
    tcg_cache_stats.snaps++;
    tcg_cache_stats.snap_files += snap->n;
    tcg_cache_stats.refresh_ns += get_clock() - t0;
    return snap;
}

/* A new segment's name: this process, the time, a counter. */
static void dir_seg_name(char *name, size_t size, int64_t t0)
{
    snprintf(name, size, "seg-%x-%" PRIx64 "-%" PRIx64 ".xtc", dir_ops->pid,
             (uint64_t)t0,
             qatomic_fetch_inc(&dir_seg_counter) ^ ((uint64_t)t0 << 16));
}

/* Publish @len bytes of envelopes as a new segment. */
static bool dir_publish(const void *data, size_t len, unsigned pause_ms)
{
    int64_t t0 = get_clock();
    char name[64];
    size_t flen;
    void *file;
    bool ok;

    if (tcg_cache_debug) {
        fprintf(stderr, "xtcg-cache publish: %zu bytes\n", len);
    }
    file = tcg_cache_write_file(false, t0, data, len, NULL, 0, &flen);
    if (!file) {
        tcg_cache_stats.publish_fail++;
        return false;
    }
    dir_seg_name(name, sizeof(name), t0);
    ok = dir_ops->publish(file, flen, name, pause_ms);
    g_free(file);
    if (!ok) {
        tcg_cache_stats.publish_fail++;
        return false;
    }
    tcg_cache_stats.published++;
    tcg_cache_stats.publish_ns += get_clock() - t0;
    return true;
}

/* At most one round of the buffers, so that refresh isn't put off. */
static void dir_drain(bool force)
{
    size_t len;
    void *d;

    for (int i = 0; i < TCG_CACHE_BUFS
         && (d = tcg_cache_sink_take(get_clock(), DIR_AGE_NS, force, false,
                                     &len)); i++) {
        dir_publish(d, len, dir_pause_publish_ms);
        tcg_cache_sink_give(d);
    }
}

static void dir_refresh(void)
{
    TCGCacheSnap *snap;

    if (tcg_cache_snap_waiting()) {
        tcg_cache_stats.snap_skipped++;
        return;
    }
    snap = dir_snap_build();
    if (!tcg_cache_snap_publish(snap)) {
        dir_snap_release(snap);
        for (int i = 0; i < snap->n; i++) {
            tcg_cache_file_close(&snap->f[i]);
        }
        g_free(snap);
        tcg_cache_stats.snap_skipped++;
    }
}

static void dir_writer_wake(void)
{
    qemu_cond_signal(&dir_wcond);
}

static void *dir_writer_main(void *arg)
{
    qemu_mutex_lock(&dir_wlock);
    while (dir_writer_on) {
        int64_t now;

        qemu_cond_timedwait(&dir_wcond, &dir_wlock, 100);
        if (!dir_writer_on) {
            break;
        }
        qemu_mutex_unlock(&dir_wlock);
        qemu_mutex_lock(&dir_wwork);
        dir_drain(false);
        if (dir_hold_ms) {
            tcg_cache_sink_hold(dir_hold_ms);
            qemu_mutex_lock(&dir_wlock);
            g_usleep(dir_hold_ms * 1000);
            qemu_mutex_unlock(&dir_wlock);
        }
        now = get_clock();
        if ((qatomic_read(&tcg_cache_file_missed) || dir_refresh_always)
            && now - dir_last_refresh >= DIR_REFRESH_NS
            && !qatomic_read(&dir_shutdown)) {
            qatomic_set(&tcg_cache_file_missed, false);
            dir_last_refresh = now;
            dir_refresh();
        }
        qemu_mutex_unlock(&dir_wwork);
        qemu_mutex_lock(&dir_wlock);
    }
    qemu_mutex_unlock(&dir_wlock);
    return NULL;
}

/*
 * Testing (XTCG_CACHE_MKPACK=good|badcheck): pack every loose segment in
 * the directory into pack-1.xtp, read by checked reads only, covering
 * them (with "badcheck", each coverage entry's header checksum wrong).
 * A stand-in for compaction, which deletes nothing.
 */
static void dir_test_pack(bool badcheck)
{
    GByteArray *data = g_byte_array_new();
    g_autofree TCGCacheCover *cover = g_new0(TCGCacheCover,
                                             TCG_CACHE_COVER_MAX);
    g_autofree char (*names)[64] = g_malloc0(DIR_ENUM_MAX * 64);
    uint32_t n_cover = 0;
    int nnames = dir_ops->list(names, DIR_ENUM_MAX);
    size_t flen;
    void *file;

    for (int i = 0; i < nnames && n_cover < TCG_CACHE_COVER_MAX; i++) {
        TCGCacheFile f;
        size_t size;
        uint8_t *buf;
        void *fh;

        if (!tcg_cache_segment_name_ok(names[i])) {
            continue;
        }
        fh = dir_open_file(names[i], &f, &size);
        if (!fh) {
            continue;
        }
        buf = g_malloc(f.hdr.data_len);
        if (!dir_ops->read(fh, buf, f.hdr.data_off, f.hdr.data_len)) {
            g_byte_array_append(data, buf, f.hdr.data_len);
            memcpy(cover[n_cover].name, names[i], 64);
            cover[n_cover].hdr_check = f.hdr.check ^ (badcheck ? 1 : 0);
            n_cover++;
        }
        g_free(buf);
        tcg_cache_file_close(&f);
        dir_ops->close(fh);
    }
    file = tcg_cache_write_file(true, 1, data->data, data->len, cover,
                                n_cover, &flen);
    g_byte_array_free(data, TRUE);
    if (!file) {
        fprintf(stderr, "xtcg-cache: test pack: nothing written\n");
        return;
    }
    if (dir_ops->publish(file, flen, "pack-1.xtp", 0)) {
        fprintf(stderr, "xtcg-cache: test pack: %u segments, %zu bytes\n",
                n_cover, flen);
    } else {
        fprintf(stderr, "xtcg-cache: test pack: not published\n");
    }
    g_free(file);
}

/*
 * Testing (XTCG_CACHE_CHECKALL): every segment and pack in the directory,
 * up to 4096 entries, each artifact validated as a lookup would; one
 * line of totals on stderr.
 */
static void dir_test_check(void)
{
    enum { MAX = 4096 };
    g_autofree char (*names)[64] = g_malloc0(MAX * 64);
    uint64_t counts[TCG_CACHE_V_MAX] = { };
    int nnames = dir_ops->list(names, MAX), files = 0, refused = 0, bad = 0;

    for (int i = 0; i < nnames; i++) {
        TCGCacheFile f;

        if (!dir_pack_name_ok(names[i])
            && !tcg_cache_segment_name_ok(names[i])) {
            continue;
        }
        if (!dir_map_file(names[i], &f)) {
            refused++;
            continue;
        }
        files++;
        bad += tcg_cache_check_file(f.map, f.size, true, counts);
        dir_ops->unmap(f.map, f.size);
        tcg_cache_file_close(&f);
    }
    fprintf(stderr, "xtcg-cache: check: %d entries, %d files, %d refused, "
            "%d with damage; artifacts:", nnames, files, refused, bad);
    for (int v = 0; v < TCG_CACHE_V_MAX; v++) {
        if (counts[v]) {
            fprintf(stderr, " %s=%" PRIu64, tcg_cache_v_name(v), counts[v]);
        }
    }
    fprintf(stderr, "\n");
}

void tcg_cache_dir_start(const TCGCacheDirOps *ops, int64_t t0)
{
    const char *mkpack = getenv("XTCG_CACHE_MKPACK");

    dir_ops = ops;
    dir_hold_ms = dir_env_ms("XTCG_CACHE_HOLD_MS");
    dir_pause_publish_ms = dir_env_ms("XTCG_CACHE_PAUSE_PUBLISH_MS");
    dir_pause_snap_ms = dir_env_ms("XTCG_CACHE_PAUSE_SNAP_MS");
    dir_pause_exit_ms = dir_env_ms("XTCG_CACHE_PAUSE_EXIT_MS");
    dir_pause_mapped_ms = dir_env_ms("XTCG_CACHE_PAUSE_MAPPED_MS");
    dir_pause_claim_ms = dir_env_ms("XTCG_CACHE_PAUSE_CLAIM_MS");
    tcg_cache_retire_pause_ms = dir_env_ms("XTCG_CACHE_PAUSE_RETIRE_MS");
    tcg_cache_sink_pause_ms = dir_env_ms("XTCG_CACHE_PAUSE_PUT_MS");
    dir_refresh_always = getenv("XTCG_CACHE_REFRESH_ALWAYS");
    dir_exit_nolock = getenv("XTCG_CACHE_EXIT_NOLOCK");
    dir_test_lose = getenv("XTCG_CACHE_TEST_LOSE");
    dir_exit_cap = tcg_cache_segment_bound(TCG_CACHE_BUF_SIZE);
    dir_exit_buf = g_malloc(dir_exit_cap);
    if (getenv("XTCG_CACHE_CHECKALL")) {
        dir_test_check();
    }
    if (mkpack) {
        dir_test_pack(!strcmp(mkpack, "badcheck"));
    }
    tcg_cache_snap_publish(dir_snap_build());
    tcg_cache_stats.startup_ns = get_clock() - t0;
    /* Testing: the files are mapped; a test may change them now. */
    dir_pause(dir_pause_mapped_ms);
    qemu_mutex_init(&dir_wlock);
    qemu_mutex_init(&dir_wwork);
    qemu_cond_init(&dir_wcond);
    tcg_cache_sink_wake = dir_writer_wake;
    tcg_cache_sink_init();
    dir_writer_on = true;
    dir_last_refresh = get_clock();
    qemu_thread_create(&dir_writer, "xtcg-cache", dir_writer_main, NULL,
                       QEMU_THREAD_DETACHED);
}

/*
 * The writer finishes its round, if it is in one, and never starts
 * another: from here this thread holds dir_wwork, so that the writer
 * holds none of the back end's locks when the process kills it.  Then
 * what the sink holds is published, and the snapshots already retired are
 * reclaimed, so that QEMU's RCU thread, which reclaims them, holds none of
 * its locks either (a thread that enters the engine later registers with
 * it); nothing retires another.  Only while the process's other threads
 * are alive, and none of them in the engine; not inside an RCU read-side
 * section.
 *
 * If a thread is publishing at exit (DIR_EXITING), this one still stops
 * the writer, after that publication, but publishes nothing.  Once done,
 * a quiesce returns at once.  Two never overlap: a process ends by
 * ExitProcess on one thread at a time.  A call that finds one in progress
 * nonetheless only stops captures, and submits no work to the RCU thread.
 */
void tcg_cache_dir_quiesce(void)
{
    int64_t t0;
    int was;

    if (!dir_ops || dir_child) {
        return;
    }
    if (qatomic_read(&dir_quiet)) {
        return;
    }
    if (qatomic_xchg(&dir_quiescing, true)) {
        qatomic_set(&tcg_cache_sink_on, false);
        return;
    }
    if (dir_test_lose) {
        qatomic_cmpxchg(&dir_shutdown, DIR_RUNNING, DIR_EXITING);
    }
    was = qatomic_cmpxchg(&dir_shutdown, DIR_RUNNING, DIR_QUIESCED);
    t0 = get_clock();
    qemu_mutex_lock(&dir_wwork);
    if (was == DIR_RUNNING) {
        qatomic_set(&dir_shutdown_tid, qemu_get_thread_id());
    } else {
        qatomic_set(&tcg_cache_sink_on, false);
    }
    qemu_mutex_lock(&dir_wlock);
    dir_writer_on = false;
    qemu_cond_signal(&dir_wcond);
    qemu_mutex_unlock(&dir_wlock);
    if (tcg_cache_debug) {
        fprintf(stderr, "xtcg-cache: quiesce (%s): the writer stopped after "
                "%.3f ms\n", was == DIR_RUNNING ? "owner" : "after an exit",
                (get_clock() - t0) / 1e6);
    }
    for (int i = 0; was == DIR_RUNNING && i < TCG_CACHE_BUFS; i++) {
        dir_drain(true);
    }
    t0 = get_clock();
    drain_call_rcu();
    qatomic_set(&dir_quiet, true);
    if (tcg_cache_debug) {
        fprintf(stderr, "xtcg-cache: quiesced, reclamation %.3f ms\n",
                (get_clock() - t0) / 1e6);
    }
}

/*
 * A clean exit: captures stop here, and what the buffers hold is
 * published from this thread, allocating nothing and waiting for no lock:
 * by the thread that quiesced the back end, or else by the first to end
 * it, if the sink's lock and the writer's work are free.
 */
void tcg_cache_dir_exit(void)
{
    void *data[TCG_CACHE_BUFS];
    size_t lens[TCG_CACHE_BUFS];
    bool locked = false;
    int n;

    if (!dir_ops || dir_child) {
        return;
    }
    if (qatomic_read(&dir_shutdown) == DIR_QUIESCED) {
        if (qatomic_read(&dir_shutdown_tid) != qemu_get_thread_id()) {
            qatomic_set(&tcg_cache_sink_on, false);
            return;
        }
    } else if (qatomic_cmpxchg(&dir_shutdown, DIR_RUNNING, DIR_EXITING)
               != DIR_RUNNING) {
        qatomic_set(&tcg_cache_sink_on, false);
        return;
    }
    dir_pause(dir_pause_claim_ms);
    n = tcg_cache_sink_close(data, lens);
    if (!n) {
        return;
    }
    /* Testing (XTCG_CACHE_EXIT_NOLOCK): without dir_wwork, as a hazard. */
    if (qatomic_read(&dir_shutdown) == DIR_EXITING && !dir_exit_nolock) {
        if (qemu_mutex_trylock(&dir_wwork)) {
            if (tcg_cache_debug) {
                fprintf(stderr, "xtcg-cache: exit: the writer is busy, "
                        "nothing published\n");
            }
            return;
        }
        locked = true;
    }
    for (int i = 0; i < n; i++) {
        int64_t t0 = get_clock();
        size_t flen = tcg_cache_write_segment_to(dir_exit_buf, dir_exit_cap,
                                                 t0, data[i], lens[i]);
        char name[64];

        dir_seg_name(name, sizeof(name), t0);
        if (flen && dir_ops->publish(dir_exit_buf, flen, name,
                                     dir_pause_exit_ms)) {
            tcg_cache_stats.published++;
        } else {
            tcg_cache_stats.publish_fail++;
        }
    }
    if (locked) {
        qemu_mutex_unlock(&dir_wwork);
    }
}

/*
 * fork: the writer's work, its lock and the sink's held across it.  The
 * child has no writer; it keeps its snapshot's mappings for lookups,
 * publishes nothing, and its locks are made afresh, so that it may fork
 * again.
 */
void tcg_cache_dir_fork_start(void)
{
    if (!dir_ops || qatomic_read(&dir_shutdown) == DIR_QUIESCED) {
        return;
    }
    qemu_mutex_lock(&dir_wwork);
    qemu_mutex_lock(&dir_wlock);
    tcg_cache_sink_fork_start();
}

void tcg_cache_dir_fork_end(bool child)
{
    if (!dir_ops || qatomic_read(&dir_shutdown) == DIR_QUIESCED) {
        return;
    }
    tcg_cache_sink_fork_end(child);
    if (child) {
        tcg_cache_snap_fork_child();
        tcg_cache_sink_wake = NULL;
        qemu_mutex_init(&dir_wlock);
        qemu_mutex_init(&dir_wwork);
        qemu_cond_init(&dir_wcond);
        dir_writer_on = false;
        dir_child = true;
    } else {
        qemu_mutex_unlock(&dir_wlock);
        qemu_mutex_unlock(&dir_wwork);
    }
}
