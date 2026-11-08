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

#define DIR_SCAN_MAX        65536   /* entries a scan looks at */
#define DIR_SIZE_CLAMP      (1ull << 40)
#define DIR_PACKS_MAX       8       /* pack names a scan keeps */
#define DIR_TMPS_MAX        64      /* old temporaries a scan keeps */
#define DIR_LOOSE_MAX       (TCG_CACHE_SNAP_FILES - 1)
#define DIR_AGE_NS          (2 * NANOSECONDS_PER_SECOND)
#define DIR_REFRESH_NS      NANOSECONDS_PER_SECOND
/* Compaction: when, its inputs, what it keeps. */
#define DIR_COMPACT_LOOSE   16
#define DIR_COMPACT_BYTES   (8u << 20)
#define DIR_COMPACT_NS      (60 * NANOSECONDS_PER_SECOND)
#define DIR_COMPACT_URGENT  (2 * DIR_LOOSE_MAX)
#define DIR_COMPACT_IN      64
#define DIR_KEEP_PER_KEY    4
#define DIR_TMP_AGE_S       600
/* Budgets: the directory's bytes; the bytes a process maps. */
#define DIR_DISK_MAX        (1ull << 30)
#define DIR_MAP_MAX         (768ull << 20)

/*
 * What the last scan saw, and what this process published since: the
 * compaction trigger and the disk budget.  The writer's, under dir_wwork.
 */
static uint64_t dir_seen_loose, dir_seen_loose_bytes, dir_seen_bytes;
static uint64_t dir_pub_since, dir_pub_bytes_since;
static int64_t dir_last_compact;
/* The last maintenance made no progress: the next waits its interval. */
static bool dir_compact_stuck;

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
/*
 * Testing: XTCG_CACHE_COMPACT_LOOSE (the trigger's count of loose
 * segments), XTCG_CACHE_COMPACT_MS (its interval), XTCG_CACHE_DISK_MAX
 * and XTCG_CACHE_MAP_MAX (the budgets, bytes), XTCG_CACHE_TMP_AGE_S (a
 * temporary's age before compaction deletes it), XTCG_CACHE_PAUSE_COMPACT_MS
 * (after the selection, and before the rename), XTCG_CACHE_PAUSE_COMMITTED_MS
 * (after the rename, before the deletions).
 */
static uint64_t dir_compact_loose = DIR_COMPACT_LOOSE;
static int64_t dir_compact_ns = DIR_COMPACT_NS;
static uint64_t dir_disk_max = DIR_DISK_MAX, dir_map_max = DIR_MAP_MAX;
static int64_t dir_tmp_age_s = DIR_TMP_AGE_S;
static unsigned dir_pause_compact_ms, dir_pause_committed_ms;
/*
 * Testing: XTCG_CACHE_TEST_NODELETE, a substring: deletions of files
 * whose names contain it fail; XTCG_CACHE_TEST_READFAIL, hdr:S or data:S:
 * reads of their headers (opening them) or of their data (compaction's)
 * fail; XTCG_CACHE_TEST_LISTFAIL, every listing fails;
 * XTCG_CACHE_TEST_MUTATE, a substring: compaction's read of a whole
 * envelope of such a file refills its window and finds the length in the
 * envelope's header changed (as if the file changed between the reads);
 * XTCG_CACHE_TEST_ONEGROUP, compaction's duplicate search takes every
 * artifact for one key and content identity.
 */
static const char *dir_test_nodelete, *dir_test_hdrfail, *dir_test_datafail;
static const char *dir_test_mutate;
static bool dir_test_listfail, dir_test_onegroup;
/* Testing (XTCG_CACHE_TEST_SLACK): compaction's room past the budget. */
static uint64_t dir_budget_slack = 512ull << 20;

static bool dir_test_match(const char *pat, const char *name)
{
    return pat && *pat && strstr(name, pat);
}
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

typedef struct DirCand {
    char name[64];
    uint64_t size;
} DirCand;

/*
 * A file to read: opened, owned, its header read and checked.  *@invalid
 * is set if it opened but isn't a file a reader would take (not if it
 * couldn't be opened or read: that proves nothing about it).
 */
static void *dir_open_file(const char *name, TCGCacheFile *f, size_t *sizep,
                           bool *invalid)
{
    size_t size;
    void *fh = dir_ops->open(name, &size);
    int r;

    memset(f, 0, sizeof(*f));
    *invalid = false;
    if (!fh) {
        tcg_cache_stats.snap_refused++;
        return NULL;
    }
    if (size < sizeof(TCGCacheFileHdr) || size > TCG_CACHE_FILE_MAX) {
        dir_ops->close(fh);
        tcg_cache_stats.snap_refused++;
        *invalid = true;
        return NULL;
    }
    dir_read_fh = fh;
    r = dir_test_match(dir_test_hdrfail, name)
        ? TCG_CACHE_V_FAULT
        : tcg_cache_file_open(f, DIR_READ_BASE, size, dir_read_copy,
                              tcg_cache_nofault);
    dir_read_fh = NULL;
    if (r && tcg_cache_debug) {
        fprintf(stderr, "xtcg-cache dir: %s: %s\n", name, tcg_cache_v_name(r));
    }
    if (r) {
        tcg_cache_file_close(f);
        dir_ops->close(fh);
        tcg_cache_stats.snap_refused++;
        /* A read that failed says nothing about the file. */
        *invalid = r != TCG_CACHE_V_FAULT;
        return NULL;
    }
    *sizep = size;
    return fh;
}

/* "pack-", the generation in 16 lower-case hexadecimal digits, ".xtp". */
static bool dir_pack_name_ok(const char *name)
{
    if (strnlen(name, 64) != 25 || strncmp(name, "pack-", 5)
        || strcmp(name + 21, ".xtp")) {
        return false;
    }
    for (int i = 5; i < 21; i++) {
        if (!g_ascii_isxdigit(name[i]) || g_ascii_isupper(name[i])) {
            return false;
        }
    }
    return true;
}

static uint64_t dir_pack_gen(const char *name)
{
    uint64_t gen = 0;

    qemu_strtou64(name + 5, NULL, 16, &gen);
    return gen;
}

static uint64_t dir_env_u64(const char *name, uint64_t dflt)
{
    const char *v = getenv(name);
    uint64_t n;

    return v && !qemu_strtou64(v, NULL, 0, &n) ? n : dflt;
}

/*
 * "seg-", the publication's wall-clock time in microseconds in 14
 * lower-case hexadecimal digits (so that name order is age order), then
 * "-" and the rest as tcg_cache_segment_name_ok takes it.
 */
static bool dir_seg_name_ok(const char *name)
{
    if (!tcg_cache_segment_name_ok(name) || name[18] != '-') {
        return false;
    }
    for (int i = 4; i < 18; i++) {
        if (!g_ascii_isxdigit(name[i]) || g_ascii_isupper(name[i])) {
            return false;
        }
    }
    return true;
}

/*
 * Keep @name in @a, at most @max of them, highest names first (@high)
 * or lowest first.
 */
static void dir_keep(DirCand *a, int *n, int max, const char *name,
                     uint64_t size, bool high)
{
    int i = *n;

    while (i > 0 && (strcmp(name, a[i - 1].name) > 0) == high) {
        i--;
    }
    if (i >= max) {
        return;
    }
    memmove(&a[i + 1], &a[i], (MIN(*n, max - 1) - i) * sizeof(*a));
    memset(a[i].name, 0, sizeof(a[i].name));
    memcpy(a[i].name, name, strnlen(name, 63));
    a[i].size = size;
    *n = MIN(*n + 1, max);
}

/* @name's place in @pack's cover list, or -1. */
static int dir_cover_find(const TCGCacheFile *pack, const char *name)
{
    for (uint32_t i = 0; pack && i < pack->hdr.n_cover; i++) {
        if (!strncmp(pack->cover[i].name, name, 64)) {
            return i;
        }
    }
    return -1;
}

/*
 * A scan of the directory, in two passes over its entries.  The first
 * keeps the highest pack names, which are then opened: the newest valid
 * one is P (its header validates and its generation is its name's).  The
 * second, against P's cover list: the loose segments (the newest, the
 * oldest), the newest of those P covers by name, which of P's covered
 * segments are listed, the old temporaries, and the totals.  Only a
 * complete scan (both listings whole) establishes that a file is absent.
 */
enum { DIR_PACK_UNREAD, DIR_PACK_VALID, DIR_PACK_INVALID };

typedef struct DirScan {
    int pass;
    bool complete;
    DirCand packs[DIR_PACKS_MAX];   /* highest generations first */
    int npacks, packs_seen;
    int pack_state[DIR_PACKS_MAX];
    int p;                          /* packs[p] is P, or -1 */
    TCGCacheFile pack;              /* P's header and cover list */
    bool *present;                  /* per P cover entry: listed */
    uint32_t n_present;
    DirCand newest[DIR_LOOSE_MAX];  /* not in P's cover list */
    int nnewest;
    DirCand newest_cov[DIR_LOOSE_MAX];
    int nnewest_cov;
    DirCand oldest[DIR_COMPACT_IN];
    int noldest;
    DirCand oldest_cov[DIR_COMPACT_IN];
    int noldest_cov;
    DirCand tmps[DIR_TMPS_MAX];
    int ntmps;
    int64_t tmp_before;
    uint64_t loose, loose_bytes, bytes;
} DirScan;

/*
 * Leftovers cleanup would delete, by the last scan; whether that scan was
 * complete (only a complete one authorizes publication and maintenance).
 */
static uint64_t dir_seen_leftovers;
static bool dir_seen_complete;
static int64_t dir_last_scan;

static void dir_scan_entry(void *opaque, const char *name, uint64_t size,
                           int64_t mtime)
{
    DirScan *sc = opaque;
    int c;

    /* Clamped, so that no sum of a scan's sizes can wrap. */
    size = MIN(size, DIR_SIZE_CLAMP);
    if (sc->pass == 1) {
        sc->bytes += size;
        if (dir_pack_name_ok(name)) {
            sc->packs_seen++;
            dir_keep(sc->packs, &sc->npacks, DIR_PACKS_MAX, name, size, true);
        }
        return;
    }
    if (!strncmp(name, "tmp-", 4)) {
        if (mtime < sc->tmp_before) {
            dir_keep(sc->tmps, &sc->ntmps, DIR_TMPS_MAX, name, size, false);
        }
        return;
    }
    if (!dir_seg_name_ok(name)) {
        return;
    }
    c = sc->p >= 0 ? dir_cover_find(&sc->pack, name) : -1;
    if (c >= 0) {
        if (!sc->present[c]) {
            sc->present[c] = true;
            sc->n_present++;
        }
        dir_keep(sc->newest_cov, &sc->nnewest_cov, DIR_LOOSE_MAX, name, size,
                 true);
        dir_keep(sc->oldest_cov, &sc->noldest_cov, DIR_COMPACT_IN, name, size,
                 false);
        return;
    }
    sc->loose++;
    sc->loose_bytes += size;
    dir_keep(sc->newest, &sc->nnewest, DIR_LOOSE_MAX, name, size, true);
    dir_keep(sc->oldest, &sc->noldest, DIR_COMPACT_IN, name, size, false);
}

/* One listing; whether it saw every entry. */
static bool dir_scan_list(DirScan *sc)
{
    int r = dir_ops->list(dir_scan_entry, sc, DIR_SCAN_MAX);

    if (dir_test_listfail) {
        r = -1;
    }
    if (r >= DIR_SCAN_MAX) {
        tcg_cache_stats.scan_trunc++;
    }
    return r >= 0 && r < DIR_SCAN_MAX;
}

static bool dir_ending(void)
{
    return qatomic_read(&dir_shutdown) != DIR_RUNNING;
}

/* The scan; dir_scan_done releases what it holds. */
static void dir_scan(DirScan *sc)
{
    bool whole;
    uint64_t leftovers = 0;

    sc->p = -1;
    sc->pass = 1;
    whole = dir_scan_list(sc);
    for (int i = 0; i < sc->npacks; i++) {
        TCGCacheFile f;
        size_t size;
        bool invalid;
        void *fh = dir_open_file(sc->packs[i].name, &f, &size, &invalid);

        sc->pack_state[i] = invalid ? DIR_PACK_INVALID : DIR_PACK_UNREAD;
        if (!fh) {
            continue;
        }
        dir_ops->close(fh);
        if (f.hdr.magic != TCG_CACHE_PACK_MAGIC
            || f.hdr.tick != dir_pack_gen(sc->packs[i].name)) {
            sc->pack_state[i] = DIR_PACK_INVALID;
            tcg_cache_file_close(&f);
            continue;
        }
        sc->pack_state[i] = DIR_PACK_VALID;
        if (sc->p < 0) {
            sc->p = i;
            sc->pack = f;
            sc->present = g_new0(bool, f.hdr.n_cover);
        } else {
            tcg_cache_file_close(&f);
        }
        leftovers += sc->p != i;
    }
    for (int i = 0; i < sc->npacks; i++) {
        leftovers += sc->pack_state[i] == DIR_PACK_INVALID;
    }
    sc->tmp_before = g_get_real_time() / G_USEC_PER_SEC - dir_tmp_age_s;
    sc->pass = 2;
    whole &= dir_scan_list(sc);
    sc->complete = whole;
    leftovers += sc->n_present + sc->ntmps;
    dir_seen_loose = sc->loose;
    dir_seen_loose_bytes = sc->loose_bytes;
    /* A partial scan never lowers the count. */
    dir_seen_bytes = whole ? sc->bytes
                           : MAX(dir_seen_bytes + dir_pub_bytes_since,
                                 sc->bytes);
    dir_seen_leftovers = leftovers;
    dir_seen_complete = whole;
    dir_last_scan = get_clock();
    dir_pub_since = dir_pub_bytes_since = 0;
    if (tcg_cache_debug) {
        fprintf(stderr, "xtcg-cache dir: %s scan: %" PRIu64 " bytes, %"
                PRIu64 " loose segments (%" PRIu64 " bytes), pack %s, %"
                PRIu64 " leftovers\n", whole ? "complete" : "partial",
                sc->bytes, sc->loose, sc->loose_bytes,
                sc->p >= 0 ? sc->packs[sc->p].name : "none", leftovers);
    }
}

static void dir_scan_done(DirScan *sc)
{
    if (sc->p >= 0) {
        tcg_cache_file_close(&sc->pack);
    }
    g_free(sc->present);
}

static void dir_snap_release(TCGCacheSnap *s)
{
    for (int i = 0; i < s->n; i++) {
        dir_ops->unmap(s->f[i].map, s->f[i].size);
    }
}

/*
 * Map @name for lookups, into @f, if the file opened is at most @room
 * bytes (the mapping budget's headroom); false if it can't be.
 */
static bool dir_map_file(const char *name, TCGCacheFile *f, uint64_t room)
{
    size_t size;
    const void *map;
    bool invalid;
    void *fh = dir_open_file(name, f, &size, &invalid);

    if (!fh) {
        return false;
    }
    if (size > room) {
        tcg_cache_stats.map_budget++;
        tcg_cache_file_close(f);
        dir_ops->close(fh);
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

static void dir_unmap_file(TCGCacheFile *f)
{
    dir_ops->unmap(f->map, f->size);
    tcg_cache_file_close(f);
}

/* The bytes a snapshot maps. */
static uint64_t dir_snap_bytes(const TCGCacheSnap *s)
{
    uint64_t n = 0;

    for (int i = 0; s && i < s->n; i++) {
        n += s->f[i].size;
    }
    return n;
}

/*
 * The pack didn't fit the mapping budget beside the current snapshot: an
 * empty snapshot replaced it, and once that one's retirement is reclaimed
 * the writer builds again at once.
 */
static bool dir_pack_owed;

/*
 * A snapshot of the directory: P, and the newest DIR_LOOSE_MAX segments
 * it doesn't cover.  Only checked reads; files are mapped, never read
 * through the mapping here.  A segment is suppressed only by the pack
 * actually mapped, by name and header checksum.  Within the mapping
 * budget, counted with the current snapshot (which this one retires; no
 * build runs while a retired one is pending, and a fork's child builds
 * none): the pack first, then segments newest first, until one doesn't
 * fit.
 */
static TCGCacheSnap *dir_snap_build(void)
{
    TCGCacheSnap *snap = g_new0(TCGCacheSnap, 1);
    g_autofree DirScan *sc = g_new0(DirScan, 1);
    uint64_t mapped = dir_snap_bytes(qatomic_read(&tcg_cache_snap));
    TCGCacheFile pack = { };
    bool have_pack = false;
    int64_t t0 = get_clock();
    int i = 0, j = 0;

    dir_scan(sc);
    dir_pause(dir_pause_snap_ms);
    snap->release = dir_snap_release;
    dir_pack_owed = false;
    if (sc->p >= 0) {
        uint64_t size = sc->packs[sc->p].size;

        if (mapped + size > dir_map_max) {
            tcg_cache_stats.map_budget++;
            /* Empty, so that the next build has room, if any can. */
            dir_pack_owed = size <= dir_map_max;
            if (dir_pack_owed) {
                goto done;
            }
        } else if (dir_map_file(sc->packs[sc->p].name, &pack,
                                dir_map_max - mapped)) {
            if (pack.hdr.check == sc->pack.hdr.check) {
                have_pack = true;
                mapped += pack.size;
            } else {
                dir_unmap_file(&pack);
            }
        }
    }
    while (snap->n < DIR_LOOSE_MAX
           && (i < sc->nnewest || j < sc->nnewest_cov)) {
        bool cov = i == sc->nnewest
                   || (j < sc->nnewest_cov
                       && strcmp(sc->newest_cov[j].name,
                                 sc->newest[i].name) > 0);
        const DirCand *d = cov ? &sc->newest_cov[j++] : &sc->newest[i++];
        TCGCacheFile *f = &snap->f[snap->n];
        int c;

        if (mapped + d->size > dir_map_max) {
            tcg_cache_stats.map_budget++;
            break;
        }
        if (!dir_map_file(d->name, f, dir_map_max - mapped)) {
            continue;
        }
        c = cov && have_pack ? dir_cover_find(&pack, d->name) : -1;
        if (c >= 0 && pack.cover[c].hdr_check == f->hdr.check) {
            dir_unmap_file(f);
            continue;
        }
        mapped += f->size;
        snap->n++;
    }
    if (have_pack) {
        snap->f[snap->n++] = pack;
    }
done:
    dir_scan_done(sc);
    tcg_cache_stats.snaps++;
    tcg_cache_stats.snap_files += snap->n;
    tcg_cache_stats.refresh_ns += get_clock() - t0;
    return snap;
}

/* A new segment's name: the time (dir_seg_name_ok), this process, a counter. */
static void dir_seg_name(char *name, size_t size, uint64_t us)
{
    snprintf(name, size, "seg-%014" PRIx64 "-%x-%" PRIx64 ".xtc",
             (uint64_t)(us & ((1ull << 56) - 1)), dir_ops->pid,
             qatomic_fetch_inc(&dir_seg_counter));
}

/*
 * The disk budget: what the last scan saw and what this process published
 * since.  The writer scans again once it has published DIR_PUB_RESCAN
 * since, so a process overshoots by at most that and its exit's buffers.
 */
#define DIR_PUB_RESCAN      (32u << 20)

static bool dir_over_budget(void)
{
    return dir_seen_bytes + dir_pub_bytes_since > dir_disk_max;
}

/* Publication allowed: the last scan complete, and under budget. */
static bool dir_may_publish(void)
{
    if (!dir_seen_complete) {
        tcg_cache_stats.publish_blind++;
        return false;
    }
    if (dir_over_budget()) {
        tcg_cache_stats.publish_budget++;
        return false;
    }
    return true;
}

/* Publish @len bytes of envelopes as a new segment. */
static bool dir_publish(const void *data, size_t len, unsigned pause_ms)
{
    int64_t t0 = get_clock();
    uint64_t us = g_get_real_time();
    char name[64];
    size_t flen;
    void *file;
    bool ok;

    if (tcg_cache_debug) {
        fprintf(stderr, "xtcg-cache publish: %zu bytes\n", len);
    }
    if (!dir_may_publish()) {
        return false;
    }
    file = tcg_cache_write_file(false, us, data, len, NULL, 0, &flen);
    if (!file) {
        tcg_cache_stats.publish_fail++;
        return false;
    }
    dir_seg_name(name, sizeof(name), us);
    ok = dir_ops->publish(file, flen, name, pause_ms);
    g_free(file);
    if (!ok) {
        tcg_cache_stats.publish_fail++;
        return false;
    }
    dir_pub_since++;
    dir_pub_bytes_since += flen;
    tcg_cache_stats.published++;
    tcg_cache_stats.publish_ns += get_clock() - t0;
    return true;
}

static void dir_rescan(void)
{
    g_autofree DirScan *sc = g_new0(DirScan, 1);

    dir_scan(sc);
    dir_scan_done(sc);
}

/*
 * At most one round of the buffers, so that refresh isn't put off.  Past
 * the allowance since the last scan, a scan before each publication
 * (@scan; else the round stops), so that no round overshoots it.
 */
static void dir_drain_bufs(bool force, bool scan)
{
    size_t len;
    void *d;

    for (int i = 0; i < TCG_CACHE_BUFS; i++) {
        if (!force && dir_pub_bytes_since > DIR_PUB_RESCAN) {
            if (!scan) {
                break;
            }
            dir_rescan();
        }
        d = tcg_cache_sink_take(get_clock(), DIR_AGE_NS, force, false, &len);
        if (!d) {
            break;
        }
        dir_publish(d, len, dir_pause_publish_ms);
        tcg_cache_sink_give(d);
    }
}

/*
 * The writer's round of the buffers (dir_drain_bufs).  The writer's own
 * rounds (not @force, the quiesce's) scan first once enough
 * was published since the last scan, for the disk budget, or, once a
 * second, while the last scan was incomplete (which stops publication).
 */
static void dir_drain(bool force)
{
    if (!force && !dir_seen_complete
        && get_clock() - dir_last_scan >= DIR_REFRESH_NS) {
        dir_rescan();
    }
    dir_drain_bufs(force, !force);
}

/*
 * Compaction's yield, every DIR_YIELD_NS of its work: the buffers ready
 * published, so that captures aren't dropped while it runs (a start-up
 * fills a buffer every few milliseconds).  Never a scan: compaction's
 * own is in use.
 */
#define DIR_YIELD_NS        (2 * SCALE_MS)
static int64_t dir_yield_at;

static void dir_compact_yield(void)
{
    int64_t now = get_clock();

    if (now - dir_yield_at >= DIR_YIELD_NS) {
        dir_yield_at = now;
        dir_drain_bufs(false, false);
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

/*
 * Compaction and cleanup (the design's phase 3, step 4, revision 8), on
 * the writer thread, under dir_wwork and the directory's lock, giving up
 * once the process starts ending.
 *
 * A merge: P and the oldest loose segments it doesn't cover into a new
 * pack, which covers them and whatever P covered that is still there (or
 * all of it, unless a complete scan says otherwise).  Per key it keeps at
 * most DIR_KEEP_PER_KEY distinct artifacts: the newest for each guest pc
 * first, then the newest; past the file's size the oldest go.  Nothing
 * is written into the directory until the new pack is renamed into it;
 * before that, an abort deletes only the temporary.
 *
 * Cleanup, after a merge or without one: invalid packs (their headers
 * fail), valid packs older than the newest, segments the newest covers
 * exactly (name and header), old temporaries.  A file that couldn't be
 * opened is never deleted on that account.
 */
typedef struct DirArt {
    TCGCacheEnv key;        /* the envelope's header: key, born, content */
    TCGCacheIdx idx;        /* in its input */
    uint64_t pc;            /* the artifact's guest pc */
    uint32_t src;
    uint32_t pad;
} DirArt;

typedef struct DirCompact {
    TCGCacheFile in[DIR_COMPACT_IN + 1];
    void *fh[DIR_COMPACT_IN + 1];
    char name[DIR_COMPACT_IN + 1][64];
    uint32_t nin;
    DirArt *arts;
    size_t n, cap;
    void *buf, *buf2;
    /* Reads go through one window of an input's data, in order. */
    uint8_t *win;
    uint32_t win_src;
    uint64_t win_off;
    size_t win_len;
    bool win_mutate;            /* testing: XTCG_CACHE_TEST_MUTATE */
} DirCompact;

#define DIR_WIN_SIZE        (1u << 20)

#define DIR_BUF_SIZE        (sizeof(TCGCacheEnv) + TCG_CACHE_ART_MAX)
/* The distinct contents of one key and content identity a merge takes. */
#define DIR_DUP_CMP         16
#define DIR_COMPACT_ARTS    (1u << 20)

/*
 * Testing: XTCG_CACHE_TEST_PROBES, the slot table's probe bound;
 * XTCG_CACHE_TEST_ARTS, the input entries a merge takes (a new pack
 * keeps three quarters of it at most, so that the next has room);
 * XTCG_CACHE_TEST_NODELETE and XTCG_CACHE_TEST_READFAIL, a substring:
 * deletions, or reads, of files whose names contain it fail.
 */
static unsigned dir_test_probes = TCG_CACHE_PROBES;
static uint64_t dir_compact_arts = DIR_COMPACT_ARTS;

/*
 * @len bytes at @off of input @src, within its data, through the window;
 * false if the read failed.
 */
static bool dir_win_read(DirCompact *c, uint32_t src, uint64_t off,
                         void *dst, size_t len)
{
    const TCGCacheFileHdr *h = &c->in[src].hdr;
    uint64_t end = (uint64_t)h->data_off + h->data_len;

    if (off < h->data_off || off > end || len > end - off
        || len > DIR_WIN_SIZE
        || dir_test_match(dir_test_datafail, c->name[src])) {
        return false;
    }
    if (c->win_src != src || !c->win_len || off < c->win_off
        || off + len > c->win_off + c->win_len) {
        size_t n = MIN(DIR_WIN_SIZE, end - off);

        c->win_len = 0;
        if (dir_ops->read(c->fh[src], c->win, off, n)) {
            return false;
        }
        c->win_src = src;
        c->win_off = off;
        c->win_len = n;
        if (c->win_mutate) {
            ((TCGCacheEnv *)c->win)->len += 8;
            c->win_mutate = false;
        }
    }
    memcpy(dst, c->win + (off - c->win_off), len);
    return true;
}

/*
 * Input @src's envelopes, in the order they lie: each read whole,
 * checked and validated, then noted.  One that fails is dropped, as
 * damage; where the structure breaks, the rest of the file is.  False to
 * give the merge up: a read failed (the data is unavailable, not bad), the
 * file changed between reads, the entries passed the allowance, or the
 * process is ending.
 */
static bool dir_compact_read(DirCompact *c, uint32_t src)
{
    const TCGCacheFileHdr *h = &c->in[src].hdr;
    uint64_t off = h->data_off, end = off + h->data_len;
    TCGCacheEnv *env = c->buf, hdr;

    while (end - off >= sizeof(*env)) {
        const TCGCacheArt *a = (const void *)(env + 1);
        int r;

        if (dir_ending()) {
            return false;
        }
        dir_compact_yield();
        if (!dir_win_read(c, src, off, &hdr, sizeof(hdr))) {
            return false;
        }
        if (hdr.magic != TCG_CACHE_ENV_MAGIC || hdr.len < sizeof(hdr)
            || hdr.len > DIR_BUF_SIZE || ROUND_UP(hdr.len, 8) > end - off) {
            tcg_cache_stats.compact_damaged++;
            break;
        }
        if (dir_test_match(dir_test_mutate, c->name[src])) {
            c->win_len = 0;
            c->win_mutate = true;
        }
        /*
         * The whole envelope may come from a refill of the window: what is
         * checked and advanced over is the length checked above, and the
         * header read again must be the same one.
         */
        if (!dir_win_read(c, src, off, env, hdr.len)) {
            return false;
        }
        if (memcmp(env, &hdr, sizeof(hdr))) {
            return false;
        }
        r = tcg_cache_env_verify(env, hdr.len);
        if (r) {
            tcg_cache_stats.compact_damaged++;
            tcg_cache_stats.file_reject[r]++;
        } else {
            if (c->n >= dir_compact_arts) {
                tcg_cache_stats.compact_skip++;
                return false;
            }
            if (c->n == c->cap) {
                c->cap = MAX(c->cap * 2, 1024);
                c->arts = g_renew(DirArt, c->arts, c->cap);
            }
            c->arts[c->n++] = (DirArt){
                .key = *env, .idx = tcg_cache_env_idx(env, off),
                .pc = a->pc, .src = src,
            };
        }
        off += ROUND_UP(hdr.len, 8);
    }
    return true;
}

static int dir_key_cmp(const TCGCacheEnv *x, const TCGCacheEnv *y)
{
    if (x->id != y->id) {
        return x->id < y->id ? -1 : 1;
    }
    if (x->rva != y->rva) {
        return x->rva < y->rva ? -1 : 1;
    }
    if (x->cs_base != y->cs_base) {
        return x->cs_base < y->cs_base ? -1 : 1;
    }
    if (x->flags != y->flags) {
        return x->flags < y->flags ? -1 : 1;
    }
    if (x->cflags != y->cflags) {
        return x->cflags < y->cflags ? -1 : 1;
    }
    return 0;
}

/* Ties: content, then input and offset, so that every order is total. */
static int dir_art_tie(const DirArt *x, const DirArt *y)
{
    if (x->key.content != y->key.content) {
        return x->key.content < y->key.content ? -1 : 1;
    }
    if (x->src != y->src) {
        return x->src < y->src ? -1 : 1;
    }
    return x->idx.off < y->idx.off ? -1 : x->idx.off > y->idx.off;
}

/* By key, content identity, earliest born. */
static int dir_art_content_cmp(const void *a, const void *b)
{
    const DirArt *x = a, *y = b;
    int c = dir_key_cmp(&x->key, &y->key);

    if (c) {
        return c;
    }
    if (x->key.content != y->key.content) {
        return x->key.content < y->key.content ? -1 : 1;
    }
    if (x->key.born != y->key.born) {
        return x->key.born < y->key.born ? -1 : 1;
    }
    return dir_art_tie(x, y);
}

/* By key, newest born. */
static int dir_art_born_cmp(const void *a, const void *b)
{
    const DirArt *x = a, *y = b;
    int c = dir_key_cmp(&x->key, &y->key);

    if (c) {
        return c;
    }
    if (x->key.born != y->key.born) {
        return x->key.born > y->key.born ? -1 : 1;
    }
    return dir_art_tie(x, y);
}

/* Oldest born first. */
static int dir_art_age_cmp(const void *a, const void *b)
{
    const DirArt *x = a, *y = b;

    if (x->key.born != y->key.born) {
        return x->key.born < y->key.born ? -1 : 1;
    }
    return dir_art_tie(x, y);
}

/* As the inputs lie: input, then offset. */
static int dir_art_place_cmp(const void *a, const void *b)
{
    const DirArt *x = a, *y = b;

    if (x->src != y->src) {
        return x->src < y->src ? -1 : 1;
    }
    return x->idx.off < y->idx.off ? -1 : x->idx.off > y->idx.off;
}

/* @x's envelope again, from its input, checked; NULL if it changed. */
static const TCGCacheEnv *dir_reget(DirCompact *c, const DirArt *x, void *buf)
{
    TCGCacheEnv *env = buf;

    if (!dir_win_read(c, x->src, x->idx.off, env, x->key.len)
        || tcg_cache_env_verify(env, x->key.len)
        || env->content != x->key.content || env->born != x->key.born
        || dir_key_cmp(env, &x->key)) {
        return NULL;
    }
    return env;
}

/*
 * Copies merged: artifacts of one key and content identity whose bytes
 * compare equal, into the earliest born.  Each is compared with every
 * distinct one before it in its group; a group of more than DIR_DUP_CMP
 * distinct ones (contents whose identities collide) gives the merge up,
 * since a copy left unmerged could displace one of them in the selection.
 * In place; the number left, or 0 with *@giveup if the merge is given up
 * (that, an input changed under the reads, or the process is ending).
 */
static size_t dir_compact_dedup(DirCompact *c, bool *giveup)
{
    DirArt *a = c->arts;
    size_t m = 0, g = 0;

    qsort(a, c->n, sizeof(*a), dir_art_content_cmp);
    for (size_t i = 0; i < c->n; i++) {
        bool dup = false;

        if (dir_ending()) {
            *giveup = true;
            return 0;
        }
        dir_compact_yield();
        /* Its group's distinct ones so far: a[g, m). */
        if (m && !dir_test_onegroup
            && (dir_key_cmp(&a[m - 1].key, &a[i].key)
                || a[m - 1].key.content != a[i].key.content)) {
            g = m;
        }
        for (size_t k = g; !dup && k < m; k++) {
            const DirArt *r = &a[k];
            const TCGCacheEnv *x, *y;

            if (r->key.len != a[i].key.len) {
                continue;
            }
            x = dir_reget(c, r, c->buf);
            y = dir_reget(c, &a[i], c->buf2);
            if (!x || !y) {
                *giveup = true;
                return 0;
            }
            dup = !memcmp(x + 1, y + 1, x->len - sizeof(*x));
        }
        if (dup) {
            tcg_cache_stats.compact_dups++;
        } else if (m - g >= DIR_DUP_CMP) {
            tcg_cache_stats.compact_collide++;
            *giveup = true;
            return 0;
        } else {
            a[m++] = a[i];
        }
    }
    return m;
}

/*
 * The selection, of the @n distinct artifacts in @a: per key the newest
 * for each guest pc first, then the newest, DIR_KEEP_PER_KEY in all; then
 * oldest born dropped while the envelopes pass @max_data bytes or their
 * number @max_n (so that the next merge has room for loose inputs).  In
 * place; the number kept, in input order, their bytes in *@datap.
 */
static size_t dir_compact_select(DirArt *a, size_t n, uint64_t max_data,
                                 size_t max_n, uint64_t *datap)
{
    g_autofree bool *take = g_new0(bool, n);
    size_t k = 0, g0, g1;
    uint64_t data = 0;

    qsort(a, n, sizeof(*a), dir_art_born_cmp);
    for (g0 = 0; g0 < n; g0 = g1) {
        unsigned taken = 0;

        for (g1 = g0 + 1; g1 < n && !dir_key_cmp(&a[g1].key, &a[g0].key);
             g1++) {
            continue;
        }
        uint64_t pcs[DIR_KEEP_PER_KEY];

        for (size_t i = g0; i < g1 && taken < DIR_KEEP_PER_KEY; i++) {
            bool seen = false;

            for (unsigned j = 0; j < taken && !seen; j++) {
                seen = pcs[j] == a[i].pc;
            }
            if (!seen) {
                take[i] = true;
                pcs[taken++] = a[i].pc;
            }
        }
        for (size_t i = g0; i < g1 && taken < DIR_KEEP_PER_KEY; i++) {
            if (!take[i]) {
                take[i] = true;
                taken++;
            }
        }
    }
    for (size_t i = 0; i < n; i++) {
        if (take[i]) {
            a[k++] = a[i];
            data += ROUND_UP(a[i].key.len, 8);
        }
    }
    if (data > max_data || k > max_n) {
        size_t drop = 0;

        qsort(a, k, sizeof(*a), dir_art_age_cmp);
        while (drop < k && (data > max_data || k - drop > max_n)) {
            data -= ROUND_UP(a[drop++].key.len, 8);
        }
        tcg_cache_stats.compact_aged += drop;
        memmove(a, a + drop, (k - drop) * sizeof(*a));
        k -= drop;
    }
    qsort(a, k, sizeof(*a), dir_art_place_cmp);
    *datap = data;
    return k;
}

/*
 * The slot table for @a's @n envelopes laid out in order after the
 * header, every entry within the reader's probes of its home: the table
 * doubles until they are, up to the reader's limit.  NULL if it can't.
 */
static TCGCacheIdx *dir_compact_table(DirArt *a, size_t n, uint64_t data,
                                      uint32_t n_cover, uint64_t gen,
                                      TCGCacheFileHdr *h, size_t *out_len)
{
    for (uint32_t log2 = 4; log2 <= TCG_CACHE_SLOT_LOG2_MAX; log2++) {
        TCGCacheIdx *slots;
        uint64_t at;
        size_t i;

        if (dir_ending()) {
            return NULL;
        }
        *out_len = tcg_cache_pack_layout(h, gen, n, n_cover, data, log2);
        if (!*out_len) {
            return NULL;
        }
        log2 = h->slot_log2;
        slots = g_new0(TCGCacheIdx, 1u << log2);
        at = h->data_off;
        for (i = 0; i < n; i++) {
            TCGCacheIdx x = tcg_cache_env_idx(&a[i].key, at);

            if (!tcg_cache_pack_slot(slots, log2, x, dir_test_probes)) {
                break;
            }
            at += ROUND_UP(a[i].key.len, 8);
        }
        if (i == n) {
            return slots;
        }
        g_free(slots);
        tcg_cache_stats.compact_regrow++;
    }
    return NULL;
}

static bool dir_remove(const char *name)
{
    if (dir_ending()) {
        return false;
    }
    dir_compact_yield();
    if (!dir_test_match(dir_test_nodelete, name) && dir_ops->remove(name)) {
        tcg_cache_stats.removed++;
        return true;
    }
    tcg_cache_stats.remove_fail++;
    return false;
}

/* Delete @name if it is the segment @e covers: the same header. */
static bool dir_remove_covered(const TCGCacheCover *e)
{
    TCGCacheFile f;
    size_t size;
    bool invalid, same;
    void *fh = dir_open_file(e->name, &f, &size, &invalid);

    if (!fh) {
        return false;
    }
    same = f.hdr.check == e->hdr_check;
    tcg_cache_file_close(&f);
    dir_ops->close(fh);
    return same && dir_remove(e->name);
}

/*
 * Cleanup, as the comment above says: valid packs ranked after
 * @keep_rank in the scan (-1: all of them, after a merge), what P covers
 * exactly, old temporaries.
 */
static void dir_compact_clean(DirScan *sc, int keep_rank)
{
    /* What is deleted is marked, so that a later pass doesn't try again. */
    for (int i = 0; i < sc->npacks; i++) {
        if ((sc->pack_state[i] == DIR_PACK_INVALID
             || (sc->pack_state[i] == DIR_PACK_VALID && i > keep_rank))
            && dir_remove(sc->packs[i].name)) {
            sc->pack_state[i] = DIR_PACK_UNREAD;
        }
    }
    for (uint32_t i = 0; sc->p >= 0 && i < sc->pack.hdr.n_cover; i++) {
        if (sc->present[i] && dir_remove_covered(&sc->pack.cover[i])) {
            sc->present[i] = false;
        }
    }
    for (int i = 0; i < sc->ntmps; i++) {
        if (sc->tmps[i].name[0] && dir_remove(sc->tmps[i].name)) {
            sc->tmps[i].name[0] = 0;
        }
    }
}

/*
 * Whether a new pack of @len bytes leaves the directory within the
 * budget's slack: what the scan saw, and what this process published
 * since (its yields publish while it merges).
 */
static bool dir_compact_room(const DirScan *sc, uint64_t len)
{
    return sc->bytes + dir_pub_bytes_since + len
           <= dir_disk_max + dir_budget_slack;
}

/* The merge; whether the new pack was published. */
static bool dir_compact_merge(DirScan *sc, DirCompact *c, uint64_t gen)
{
    static const uint8_t zero[8];
    g_autofree TCGCacheCover *cover = g_new0(TCGCacheCover,
                                             TCG_CACHE_COVER_MAX);
    g_autofree TCGCacheIdx *slots = NULL;
    uint32_t n_cover = 0, carried = 0, max_loose;
    uint64_t data, budget, arts, in_bytes = 0;
    TCGCacheFileHdr h;
    size_t kept, out_len;
    bool giveup = false;
    char name[64];
    void *wh;

    /* What P covered, carried unless a complete scan saw it gone. */
    for (uint32_t i = 0; sc->p >= 0 && i < sc->pack.hdr.n_cover; i++) {
        if (!sc->complete || sc->present[i]) {
            carried++;
        }
    }
    if (carried >= TCG_CACHE_COVER_MAX) {
        tcg_cache_stats.compact_skip++;
        return false;
    }
    max_loose = MIN(DIR_COMPACT_IN, TCG_CACHE_COVER_MAX - carried);

    /* The inputs, P first, within the metadata bound. */
    arts = 0;
    if (sc->p >= 0) {
        size_t size;
        bool invalid;

        c->fh[0] = dir_open_file(sc->packs[sc->p].name, &c->in[0], &size,
                                 &invalid);
        if (!c->fh[0]) {
            return false;
        }
        c->nin = 1;
        in_bytes = size;
        memcpy(c->name[0], sc->packs[sc->p].name, 64);
        /* Not the pack the scan read, or too big to merge. */
        arts = c->in[0].hdr.n_index;
        if (c->in[0].hdr.check != sc->pack.hdr.check
            || arts > dir_compact_arts) {
            tcg_cache_stats.compact_skip++;
            return false;
        }
    }
    /*
     * Then loose segments, the oldest first: those P doesn't cover, and
     * those it covers by name whose header isn't the one it covers.
     */
    for (int pass = 0; pass < 2; pass++) {
        const DirCand *list = pass ? sc->oldest_cov : sc->oldest;
        int nlist = pass ? sc->noldest_cov : sc->noldest;

        for (int i = 0; i < nlist && c->nin - (sc->p >= 0) < max_loose; i++) {
            uint32_t k = c->nin;
            int cv = pass ? dir_cover_find(&sc->pack, list[i].name) : -1;
            size_t size;
            bool invalid, bad;

            c->fh[k] = dir_open_file(list[i].name, &c->in[k], &size,
                                     &invalid);
            if (!c->fh[k]) {
                continue;
            }
            bad = c->in[k].hdr.magic != TCG_CACHE_SEG_MAGIC
                  || (cv >= 0 && c->in[k].hdr.check
                                 == sc->pack.cover[cv].hdr_check);
            if (bad || arts + c->in[k].hdr.n_index > dir_compact_arts) {
                tcg_cache_file_close(&c->in[k]);
                dir_ops->close(c->fh[k]);
                c->fh[k] = NULL;
                if (bad) {
                    continue;
                }
                break;
            }
            if (cv >= 0) {
                /* Not what P covers: an input, and P's entry not carried. */
                sc->present[cv] = false;
            }
            arts += c->in[k].hdr.n_index;
            in_bytes += size;
            memcpy(c->name[k], list[i].name, 64);
            c->nin++;
        }
    }
    if (c->nin == (sc->p >= 0)) {
        return false;
    }
    /* Its output can't take the directory past the budget's slack. */
    if (!dir_compact_room(sc, in_bytes)) {
        tcg_cache_stats.compact_skip++;
        return false;
    }
    for (uint32_t i = 0; i < c->nin; i++) {
        if (!dir_compact_read(c, i)) {
            return false;
        }
    }
    tcg_cache_stats.compact_arts += c->n;

    /* The new pack's cover list: its loose inputs, then what it carries. */
    for (uint32_t i = sc->p >= 0; i < c->nin; i++) {
        memcpy(cover[n_cover].name, c->name[i], 64);
        cover[n_cover++].hdr_check = c->in[i].hdr.check;
    }
    for (uint32_t i = 0; sc->p >= 0 && i < sc->pack.hdr.n_cover; i++) {
        if (!sc->complete || sc->present[i]) {
            cover[n_cover++] = sc->pack.cover[i];
        }
    }

    c->n = dir_compact_dedup(c, &giveup);
    if (giveup || dir_ending()) {
        return false;
    }
    /*
     * The envelopes' room: the file less its header, its padding, its
     * cover list and the largest slot table a reader allows (growth for
     * probe clusters may need more than the count suggests).
     */
    budget = TCG_CACHE_FILE_MAX - sizeof(TCGCacheFileHdr) - 8
             - (uint64_t)n_cover * sizeof(TCGCacheCover)
             - (sizeof(TCGCacheIdx) << TCG_CACHE_SLOT_LOG2_MAX);
    kept = dir_compact_select(c->arts, c->n, budget,
                              dir_compact_arts / 4 * 3, &data);
    slots = dir_compact_table(c->arts, kept, data, n_cover, gen, &h,
                              &out_len);
    if (!slots) {
        tcg_cache_stats.compact_skip++;
        return false;
    }
    /* The actual size, past what the inputs' sizes suggested. */
    if (!dir_compact_room(sc, out_len)) {
        tcg_cache_stats.compact_skip++;
        return false;
    }
    dir_pause(dir_pause_compact_ms);
    if (dir_ending()) {
        return false;
    }
    wh = dir_ops->create();
    if (!wh) {
        return false;
    }
    for (size_t i = 0, at = h.data_off; i < kept; i++) {
        const TCGCacheEnv *env;

        if (dir_ending()) {
            goto abort;
        }
        dir_compact_yield();
        /* Changed since the first pass: the whole output is abandoned. */
        env = dir_reget(c, &c->arts[i], c->buf);
        if (!env) {
            goto abort;
        }
        if (!dir_ops->write(wh, env, env->len, at)
            || !dir_ops->write(wh, zero, ROUND_UP(env->len, 8) - env->len,
                               at + env->len)) {
            goto abort;
        }
        at += ROUND_UP(env->len, 8);
    }
    tcg_cache_pack_seal(&h, cover);
    if (!dir_ops->write(wh, slots, sizeof(TCGCacheIdx) << h.slot_log2,
                        h.index_off)
        || (h.cover_len && !dir_ops->write(wh, cover, h.cover_len,
                                           h.cover_off))
        || !dir_ops->write(wh, &h, sizeof(h), 0)) {
        goto abort;
    }
    dir_pause(dir_pause_compact_ms);
    if (dir_ending()) {
        goto abort;
    }
    /* Again, with what this process published meanwhile. */
    if (!dir_compact_room(sc, out_len)) {
        tcg_cache_stats.compact_skip++;
        goto abort;
    }
    snprintf(name, sizeof(name), "pack-%016" PRIx64 ".xtp", gen);
    if (!dir_ops->commit(wh, name)) {
        return false;
    }
    /* Counted as published until a complete scan sees what is left. */
    dir_pub_bytes_since += out_len;
    tcg_cache_stats.compactions++;
    tcg_cache_stats.compact_in += c->nin;
    tcg_cache_stats.compact_kept += kept;
    tcg_cache_stats.compact_bytes += out_len;
    if (tcg_cache_debug) {
        fprintf(stderr, "xtcg-cache dir: compacted %u files, %zu of %zu "
                "artifacts, into %s (%zu bytes)\n", c->nin, kept, c->n, name,
                out_len);
    }
    return true;

abort:
    dir_ops->drop(wh);
    return false;
}

/*
 * One round of maintenance: a merge if @may_merge and there are loose
 * segments to take, then cleanup; or cleanup alone.  False if it made no
 * progress: its scan was incomplete, or a merge it was asked for didn't
 * happen (not because another process holds the lock, or this one is
 * ending).
 */
static bool dir_compact(bool may_merge)
{
    g_autofree DirScan *sc = g_new0(DirScan, 1);
    g_autofree DirCompact *c = g_new0(DirCompact, 1);
    int64_t t0 = get_clock();
    bool merged = false, progress = false, asked = may_merge;
    void *lh = dir_ops->trylock();

    if (!lh) {
        tcg_cache_stats.compact_busy++;
        return true;
    }
    dir_scan(sc);
    /* Only a complete scan establishes what is there, and what isn't. */
    if (dir_ending() || !sc->complete) {
        progress = dir_ending();
        goto out;
    }
    /*
     * A merge needs P to be the newest pack that isn't invalid, and room
     * under the budget's slack; otherwise only cleanup, of what the scan
     * established.
     */
    for (int i = 0; i < (sc->p >= 0 ? sc->p : sc->npacks); i++) {
        if (sc->pack_state[i] != DIR_PACK_INVALID) {
            may_merge = false;
        }
    }
    if (sc->p < 0 && sc->packs_seen > sc->npacks) {
        may_merge = false;
    }
    if (sc->bytes > dir_disk_max + dir_budget_slack) {
        may_merge = false;
    }
    /*
     * Cleanup first, which needs no merge and is cheap, so that a process
     * too short to finish a merge still does it: invalid packs (so that
     * none blocks the next generation), packs P supersedes, what P covers
     * exactly, old temporaries.
     */
    dir_compact_clean(sc, sc->p >= 0 ? sc->p : sc->npacks);
    if (sc->npacks && dir_pack_gen(sc->packs[0].name) == UINT64_MAX) {
        tcg_cache_stats.compact_skip++;
        may_merge = false;
    }
    if (may_merge && (sc->noldest || sc->noldest_cov)) {
        uint64_t gen = sc->npacks ? dir_pack_gen(sc->packs[0].name) + 1 : 1;

        c->buf = g_malloc(DIR_BUF_SIZE);
        c->buf2 = g_malloc(DIR_BUF_SIZE);
        c->win = g_malloc(DIR_WIN_SIZE);
        merged = dir_compact_merge(sc, c, gen);
        if (merged || dir_ending()) {
            progress = true;
        }
        if (!merged) {
            if (dir_ending()) {
                tcg_cache_stats.compact_exit++;
            } else {
                tcg_cache_stats.compact_fail++;
            }
        }
    } else {
        /* Asked for one and refused it: as little progress as a failure. */
        progress = !asked || !(sc->noldest || sc->noldest_cov);
    }
    for (uint32_t i = 0; i < c->nin; i++) {
        tcg_cache_file_close(&c->in[i]);
        dir_ops->close(c->fh[i]);
    }
    if (merged) {
        dir_pause(dir_pause_committed_ms);
        /* The inputs, P with them: the new pack has their artifacts. */
        for (uint32_t i = 0; i < c->nin; i++) {
            dir_remove(c->name[i]);
        }
        if (sc->p >= 0) {
            sc->pack_state[sc->p] = DIR_PACK_UNREAD;
        }
        /* Every valid pack is older now; what P covered, the new one does. */
        dir_compact_clean(sc, -1);
    }
out:
    dir_scan_done(sc);
    g_free(c->arts);
    g_free(c->buf);
    g_free(c->buf2);
    g_free(c->win);
    dir_ops->unlock(lh);
    tcg_cache_stats.compact_ns += get_clock() - t0;
    return progress;
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
        if ((((qatomic_read(&tcg_cache_file_missed) || dir_refresh_always)
              && now - dir_last_refresh >= DIR_REFRESH_NS)
             || (dir_pack_owed && !tcg_cache_snap_waiting()))
            && !qatomic_read(&dir_shutdown)) {
            qatomic_set(&tcg_cache_file_missed, false);
            dir_last_refresh = now;
            dir_refresh();
        }
        if (!dir_ending()) {
            uint64_t loose = dir_seen_loose + dir_pub_since;
            bool merge = loose > dir_compact_loose
                         || dir_seen_loose_bytes + dir_pub_bytes_since
                            > DIR_COMPACT_BYTES;
            /*
             * Once a minute at most, unless there are more loose segments
             * than a snapshot can read (those are lost to lookups) and the
             * last round made progress.
             */
            bool due = now - dir_last_compact >= dir_compact_ns
                       || (loose > DIR_COMPACT_URGENT && !dir_compact_stuck);

            if (due && (merge || dir_seen_leftovers || dir_over_budget())) {
                dir_last_compact = now;
                dir_compact_stuck = !dir_compact(merge);
            }
        }
        qemu_mutex_unlock(&dir_wwork);
        qemu_mutex_lock(&dir_wlock);
    }
    qemu_mutex_unlock(&dir_wlock);
    return NULL;
}

/* Testing: the first @max entries' names. */
typedef struct DirNames {
    char (*names)[64];
    int n, max;
} DirNames;

static void dir_names_entry(void *opaque, const char *name, uint64_t size,
                            int64_t mtime)
{
    DirNames *d = opaque;

    if (d->n < d->max) {
        memset(d->names[d->n], 0, 64);
        memcpy(d->names[d->n++], name, strnlen(name, 63));
    }
}

static int dir_names(char (*names)[64], int max)
{
    DirNames d = { names, 0, max };

    dir_ops->list(dir_names_entry, &d, DIR_SCAN_MAX);
    return d.n;
}

/*
 * Testing (XTCG_CACHE_MKPACK=good|badcheck): pack every loose segment in
 * the directory into pack generation 1, read by checked reads only, covering
 * them (with "badcheck", each coverage entry's header checksum wrong).
 * A stand-in for compaction, which deletes nothing.
 */
static void dir_test_pack(bool badcheck)
{
    GByteArray *data = g_byte_array_new();
    g_autofree TCGCacheCover *cover = g_new0(TCGCacheCover,
                                             TCG_CACHE_COVER_MAX);
    g_autofree char (*names)[64] = g_malloc0(TCG_CACHE_COVER_MAX * 64);
    uint32_t n_cover = 0;
    int nnames = dir_names(names, TCG_CACHE_COVER_MAX);
    size_t flen;
    void *file;

    for (int i = 0; i < nnames && n_cover < TCG_CACHE_COVER_MAX; i++) {
        TCGCacheFile f;
        size_t size;
        uint8_t *buf;
        bool invalid;
        void *fh;

        if (!dir_seg_name_ok(names[i])) {
            continue;
        }
        fh = dir_open_file(names[i], &f, &size, &invalid);
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
    if (dir_ops->publish(file, flen, "pack-0000000000000001.xtp", 0)) {
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
    int nnames = dir_names(names, MAX), files = 0, refused = 0, bad = 0;

    for (int i = 0; i < nnames; i++) {
        TCGCacheFile f;

        if (!dir_pack_name_ok(names[i]) && !dir_seg_name_ok(names[i])) {
            continue;
        }
        if (!dir_map_file(names[i], &f, UINT64_MAX)) {
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
    if (getenv("XTCG_CACHE_COMPACT_LOOSE")) {
        dir_compact_loose = atoi(getenv("XTCG_CACHE_COMPACT_LOOSE"));
    }
    if (getenv("XTCG_CACHE_COMPACT_MS")) {
        dir_compact_ns = dir_env_ms("XTCG_CACHE_COMPACT_MS") * SCALE_MS;
    }
    dir_disk_max = dir_env_u64("XTCG_CACHE_DISK_MAX", DIR_DISK_MAX);
    dir_map_max = dir_env_u64("XTCG_CACHE_MAP_MAX", DIR_MAP_MAX);
    if (getenv("XTCG_CACHE_TMP_AGE_S")) {
        dir_tmp_age_s = atoi(getenv("XTCG_CACHE_TMP_AGE_S"));
    }
    dir_pause_compact_ms = dir_env_ms("XTCG_CACHE_PAUSE_COMPACT_MS");
    dir_pause_committed_ms = dir_env_ms("XTCG_CACHE_PAUSE_COMMITTED_MS");
    dir_test_nodelete = getenv("XTCG_CACHE_TEST_NODELETE");
    if (getenv("XTCG_CACHE_TEST_READFAIL")) {
        const char *v = getenv("XTCG_CACHE_TEST_READFAIL");

        if (!strncmp(v, "hdr:", 4)) {
            dir_test_hdrfail = v + 4;
        } else if (!strncmp(v, "data:", 5)) {
            dir_test_datafail = v + 5;
        }
    }
    dir_test_listfail = getenv("XTCG_CACHE_TEST_LISTFAIL");
    dir_test_mutate = getenv("XTCG_CACHE_TEST_MUTATE");
    dir_test_onegroup = getenv("XTCG_CACHE_TEST_ONEGROUP");
    dir_budget_slack = dir_env_u64("XTCG_CACHE_TEST_SLACK", dir_budget_slack);
    dir_compact_arts = dir_env_u64("XTCG_CACHE_TEST_ARTS", DIR_COMPACT_ARTS);
    if (getenv("XTCG_CACHE_TEST_PROBES")) {
        dir_test_probes = MAX(atoi(getenv("XTCG_CACHE_TEST_PROBES")), 1);
    }
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
    /* The first maintenance may come at once: a process may be short. */
    dir_last_compact = dir_last_refresh - dir_compact_ns;
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
        uint64_t us = g_get_real_time();
        size_t flen = tcg_cache_write_segment_to(dir_exit_buf, dir_exit_cap,
                                                 us, data[i], lens[i]);
        char name[64];

        if (!dir_may_publish()) {
            continue;
        }
        dir_seg_name(name, sizeof(name), us);
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
