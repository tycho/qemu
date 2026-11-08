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
#define DIR_LOOSE_MAX       16
#define DIR_PARTS_MAX       8       /* parts a snapshot maps; minors' bound */
#define DIR_PARTS_SEEN      64      /* part names a scan keeps */
#define DIR_AGE_NS          (2 * NANOSECONDS_PER_SECOND)
#define DIR_REFRESH_NS      NANOSECONDS_PER_SECOND
/* Compaction: when, its inputs, what it keeps. */
#define DIR_COMPACT_LOOSE   16
#define DIR_COMPACT_BYTES   (8u << 20)
#define DIR_COMPACT_NS      (60 * NANOSECONDS_PER_SECOND)
#define DIR_COMPACT_URGENT  (2 * DIR_LOOSE_MAX)
#define DIR_COMPACT_IN      64
/* Merge admission: a time per entry, its floor, the least budget. */
#define DIR_MERGE_NS        4000
#define DIR_MERGE_NS_MIN    100
#define DIR_MERGE_BUDGET    (30 * SCALE_MS)
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
/*
 * Testing: XTCG_CACHE_PARTS_MAX, the bound on parts; XTCG_CACHE_TEST_MAJOR,
 * a major is due whenever P exists.
 */
static unsigned dir_parts_max = DIR_PARTS_MAX;
static bool dir_test_major;
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

/* A pack's or a part's name's generation. */
static uint64_t dir_name_gen(const char *name)
{
    uint64_t gen = 0;

    if (!tcg_cache_part_name_gen(name, &gen)) {
        gen = dir_pack_gen(name);
    }
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

/*
 * A scan of the directory, in two passes over its entries.  The first
 * keeps the highest pack names and every part name (DIR_PARTS_SEEN at
 * most; past that the scan isn't complete), which are then opened: the
 * newest valid pack is P (its header validates and its generation is its
 * name's); each part is valid, invalid (conclusively) or unresolved (it
 * couldn't be opened or read: that proves nothing).  The valid files'
 * cover entries make the claims, sorted by name: a file named by a claim
 * whose checksum is the file's header's is covered, by any of the claims
 * (a part's entries name only older parts).  The second pass, against
 * the claims: the loose segments (the newest, the oldest), the newest of
 * those named by a claim, which claimed files are listed, the old
 * temporaries, and the totals.  Only a complete scan (both listings
 * whole, no part overflow) establishes that a file is absent.
 */
enum { DIR_PACK_UNREAD, DIR_PACK_VALID, DIR_PACK_INVALID };

typedef struct DirPart {
    DirCand c;
    uint64_t gen;
    int state;
    bool covered;
    bool deleted;                   /* by cleanup: never an input */
    TCGCacheFile f;                 /* valid: header and cover list */
    bool *present;                  /* per cover entry: listed */
} DirPart;

/* A cover entry of a valid file: holder -1 is P, else a part's index. */
typedef struct DirClaim {
    const char *name;
    uint64_t check;
    int holder;
    uint32_t idx;
} DirClaim;

typedef struct DirScan {
    int pass;
    bool complete;
    DirCand packs[DIR_PACKS_MAX];   /* highest generations first */
    int npacks, packs_seen;
    int pack_state[DIR_PACKS_MAX];
    int p;                          /* packs[p] is P, or -1 */
    TCGCacheFile pack;              /* P's header and cover list */
    bool *present;                  /* per P cover entry: listed */
    DirPart *parts;                 /* highest generations first */
    int nparts, parts_seen;
    uint64_t max_gen;               /* of any pack or part name */
    DirClaim *claims;               /* by name */
    size_t nclaims;
    int live, unresolved;           /* parts */
    uint64_t live_bytes, live_entries;
    uint32_t n_present;
    DirCand newest[DIR_LOOSE_MAX];  /* named by no claim */
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
 * complete (only a complete one authorizes publication and maintenance);
 * its parts (live, and live plus unresolved: the bound's count) and
 * whether a major merge is due.
 */
static uint64_t dir_seen_leftovers;
static bool dir_seen_complete;
static int64_t dir_last_scan;
static int dir_seen_live, dir_seen_bound;
static bool dir_seen_major_due;

static int dir_claim_cmp(const void *a, const void *b)
{
    return strncmp(((const DirClaim *)a)->name, ((const DirClaim *)b)->name,
                   64);
}

/* The claims naming @name: their first index, *@n of them. */
static size_t dir_claims_of(const DirClaim *cl, size_t ncl, const char *name,
                            size_t *n)
{
    size_t lo = 0, hi = ncl;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;

        if (strncmp(cl[mid].name, name, 64) < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    for (hi = lo; hi < ncl && !strncmp(cl[hi].name, name, 64); hi++) {
        continue;
    }
    *n = hi - lo;
    return lo;
}

/* Whether a claim covers @name exactly: its checksum is @check. */
static bool dir_claimed(const DirClaim *cl, size_t ncl, const char *name,
                        uint64_t check)
{
    size_t n, i = dir_claims_of(cl, ncl, name, &n);

    for (size_t k = 0; k < n; k++) {
        if (cl[i + k].check == check) {
            return true;
        }
    }
    return false;
}

/* Append @f's cover entries, as @holder's, to the claims. */
static void dir_claims_add(DirClaim **cl, size_t *ncl, const TCGCacheFile *f,
                           int holder)
{
    *cl = g_renew(DirClaim, *cl, *ncl + f->hdr.n_cover);
    for (uint32_t i = 0; i < f->hdr.n_cover; i++) {
        (*cl)[(*ncl)++] = (DirClaim){
            .name = f->cover[i].name, .check = f->cover[i].hdr_check,
            .holder = holder, .idx = i,
        };
    }
}

/* The claims naming a listed file: each holder's entry is present. */
static void dir_scan_present(DirScan *sc, const char *name)
{
    size_t n, i = dir_claims_of(sc->claims, sc->nclaims, name, &n);

    for (size_t k = 0; k < n; k++) {
        const DirClaim *c = &sc->claims[i + k];
        bool *pr = c->holder < 0 ? sc->present : sc->parts[c->holder].present;

        if (!pr[c->idx]) {
            pr[c->idx] = true;
            sc->n_present++;
        }
    }
}

static void dir_scan_entry(void *opaque, const char *name, uint64_t size,
                           int64_t mtime)
{
    DirScan *sc = opaque;
    uint64_t gen;
    size_t n;

    /* Clamped, so that no sum of a scan's sizes can wrap. */
    size = MIN(size, DIR_SIZE_CLAMP);
    if (sc->pass == 1) {
        sc->bytes += size;
        if (dir_pack_name_ok(name)) {
            sc->packs_seen++;
            sc->max_gen = MAX(sc->max_gen, dir_pack_gen(name));
            dir_keep(sc->packs, &sc->npacks, DIR_PACKS_MAX, name, size, true);
        } else if (tcg_cache_part_name_gen(name, &gen)) {
            int i = sc->nparts;

            sc->parts_seen++;
            sc->max_gen = MAX(sc->max_gen, gen);
            if (sc->nparts < DIR_PARTS_SEEN) {
                /* Highest generations first, as dir_keep does. */
                while (i > 0 && gen > sc->parts[i - 1].gen) {
                    i--;
                }
                memmove(&sc->parts[i + 1], &sc->parts[i],
                        (sc->nparts - i) * sizeof(*sc->parts));
                memset(&sc->parts[i], 0, sizeof(sc->parts[i]));
                memcpy(sc->parts[i].c.name, name, strnlen(name, 63));
                sc->parts[i].c.size = size;
                sc->parts[i].gen = gen;
                sc->nparts++;
            }
        }
        return;
    }
    if (!strncmp(name, "tmp-", 4)) {
        if (mtime < sc->tmp_before) {
            dir_keep(sc->tmps, &sc->ntmps, DIR_TMPS_MAX, name, size, false);
        }
        return;
    }
    if (tcg_cache_part_name_gen(name, &gen)) {
        dir_scan_present(sc, name);
        return;
    }
    if (!dir_seg_name_ok(name)) {
        return;
    }
    dir_claims_of(sc->claims, sc->nclaims, name, &n);
    if (n) {
        dir_scan_present(sc, name);
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

/* @f, opened as @name: a valid pack or part (by @prefix's generation). */
static bool dir_level_ok(const TCGCacheFile *f, const char *name)
{
    return f->hdr.magic == TCG_CACHE_PACK_MAGIC
           && f->hdr.tick == dir_name_gen(name);
}

/* The scan; dir_scan_done releases what it holds. */
static void dir_scan(DirScan *sc)
{
    bool whole;
    uint64_t leftovers = 0;

    sc->p = -1;
    sc->pass = 1;
    sc->parts = g_new0(DirPart, DIR_PARTS_SEEN);
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
        if (!dir_level_ok(&f, sc->packs[i].name)) {
            sc->pack_state[i] = DIR_PACK_INVALID;
            tcg_cache_file_close(&f);
            continue;
        }
        sc->pack_state[i] = DIR_PACK_VALID;
        if (sc->p < 0) {
            sc->p = i;
            sc->pack = f;
            sc->present = g_new0(bool, f.hdr.n_cover);
            dir_claims_add(&sc->claims, &sc->nclaims, &sc->pack, -1);
        } else {
            tcg_cache_file_close(&f);
        }
        leftovers += sc->p != i;
    }
    for (int i = 0; i < sc->npacks; i++) {
        leftovers += sc->pack_state[i] == DIR_PACK_INVALID;
    }
    if (sc->parts_seen > DIR_PARTS_SEEN) {
        tcg_cache_stats.parts_overflow++;
        whole = false;
    }
    for (int i = 0; i < sc->nparts; i++) {
        DirPart *pt = &sc->parts[i];
        size_t size;
        bool invalid;
        void *fh = dir_open_file(pt->c.name, &pt->f, &size, &invalid);

        pt->state = invalid ? DIR_PACK_INVALID : DIR_PACK_UNREAD;
        if (!fh) {
            leftovers += invalid;
            continue;
        }
        dir_ops->close(fh);
        if (!dir_level_ok(&pt->f, pt->c.name)) {
            pt->state = DIR_PACK_INVALID;
            tcg_cache_file_close(&pt->f);
            leftovers++;
            continue;
        }
        pt->state = DIR_PACK_VALID;
        pt->present = g_new0(bool, pt->f.hdr.n_cover);
        dir_claims_add(&sc->claims, &sc->nclaims, &pt->f, i);
    }
    qsort(sc->claims, sc->nclaims, sizeof(*sc->claims), dir_claim_cmp);
    {
        /*
         * What the scan retains: parts, cover lists, presence, claims (not
         * its temporaries, the allocator's overhead or a snapshot's).
         */
        uint64_t mem = DIR_PARTS_SEEN * sizeof(DirPart)
                       + sc->nclaims * sizeof(DirClaim);

        for (int i = -1; i < sc->nparts; i++) {
            const TCGCacheFile *f = i < 0 ? (sc->p >= 0 ? &sc->pack : NULL)
                                    : sc->parts[i].state == DIR_PACK_VALID
                                    ? &sc->parts[i].f : NULL;

            if (f) {
                mem += (uint64_t)f->hdr.n_cover
                       * (sizeof(TCGCacheCover) + sizeof(bool));
            }
        }
        tcg_cache_stats.scan_mem_max = MAX(tcg_cache_stats.scan_mem_max,
                                           mem);
    }
    for (int i = 0; i < sc->nparts; i++) {
        DirPart *pt = &sc->parts[i];

        if (pt->state == DIR_PACK_UNREAD) {
            sc->unresolved++;
        } else if (pt->state == DIR_PACK_VALID) {
            pt->covered = dir_claimed(sc->claims, sc->nclaims, pt->c.name,
                                      pt->f.hdr.check);
            if (pt->covered) {
                leftovers++;
            } else {
                sc->live++;
                sc->live_bytes += pt->c.size;
                sc->live_entries += pt->f.hdr.n_index;
            }
        }
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
    dir_seen_live = sc->live;
    dir_seen_bound = sc->live + sc->unresolved;
    dir_seen_major_due = sc->p >= 0
                         && (dir_test_major
                             || (sc->live
                                 && sc->live_bytes
                                    >= sc->packs[sc->p].size / 2));
    tcg_cache_stats.parts_live = sc->live;
    tcg_cache_stats.parts_unresolved = sc->unresolved;
    tcg_cache_stats.parts_covered = sc->nparts - sc->live - sc->unresolved;
    tcg_cache_stats.scan_loose = sc->loose;
    dir_last_scan = get_clock();
    dir_pub_since = dir_pub_bytes_since = 0;
    if (tcg_cache_debug) {
        fprintf(stderr, "xtcg-cache dir: %s scan: %" PRIu64 " bytes, %"
                PRIu64 " loose segments (%" PRIu64 " bytes), pack %s, "
                "parts %d live %d unresolved, %" PRIu64 " leftovers\n",
                whole ? "complete" : "partial", sc->bytes, sc->loose,
                sc->loose_bytes,
                sc->p >= 0 ? sc->packs[sc->p].name : "none", sc->live,
                sc->unresolved, leftovers);
    }
}

static void dir_scan_done(DirScan *sc)
{
    if (sc->p >= 0) {
        tcg_cache_file_close(&sc->pack);
    }
    g_free(sc->present);
    for (int i = 0; sc->parts && i < sc->nparts; i++) {
        if (sc->parts[i].state == DIR_PACK_VALID) {
            tcg_cache_file_close(&sc->parts[i].f);
        }
        g_free(sc->parts[i].present);
    }
    g_free(sc->parts);
    g_free(sc->claims);
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

/* The third listing of a snapshot: segments against the mapped files. */
typedef struct DirSnapList {
    const DirClaim *mc;
    size_t nmc;
    DirCand newest[DIR_LOOSE_MAX];      /* named by no mapped file */
    int nnewest;
    DirCand newest_cov[DIR_LOOSE_MAX];  /* named by one */
    int nnewest_cov;
} DirSnapList;

static void dir_snap_entry(void *opaque, const char *name, uint64_t size,
                           int64_t mtime)
{
    DirSnapList *sl = opaque;
    size_t n;

    if (!dir_seg_name_ok(name)) {
        return;
    }
    dir_claims_of(sl->mc, sl->nmc, name, &n);
    if (n) {
        dir_keep(sl->newest_cov, &sl->nnewest_cov, DIR_LOOSE_MAX, name,
                 MIN(size, DIR_SIZE_CLAMP), true);
    } else {
        dir_keep(sl->newest, &sl->nnewest, DIR_LOOSE_MAX, name,
                 MIN(size, DIR_SIZE_CLAMP), true);
    }
}

/*
 * A snapshot of the directory: P, then parts, then the newest
 * DIR_LOOSE_MAX segments, each unless a file mapped in this snapshot
 * covers it exactly (name and header checksum).  Only checked reads;
 * files are mapped, never read through the mapping here.
 *
 * Parts are taken newest generation first, so that a coverer is
 * considered before what it covers: a part whose coverer was mapped is
 * suppressed, and one whose coverer couldn't be mapped is mapped in its
 * place, up to dir_parts_max.  Segments come from a listing of their own,
 * after the parts are mapped, against the mapped files' claims: the
 * newest DIR_LOOSE_MAX named by none, and the newest named by one (opened
 * and checked).  Older candidates behind those (exactly covered, or too
 * big for the budget) aren't considered: a bounded miss.
 *
 * Within the mapping budget, counted with the current snapshot (which
 * this one retires; no build runs while a retired one is pending, and a
 * fork's child builds none): a file that doesn't fit is skipped, counted,
 * and the next considered.  Lookups take the files in this order.
 */
static TCGCacheSnap *dir_snap_build(void)
{
    TCGCacheSnap *snap = g_new0(TCGCacheSnap, 1);
    g_autofree DirScan *sc = g_new0(DirScan, 1);
    g_autofree DirSnapList *sl = g_new0(DirSnapList, 1);
    g_autofree DirClaim *mc = NULL;
    size_t nmc = 0;
    uint64_t mapped = dir_snap_bytes(qatomic_read(&tcg_cache_snap));
    int64_t t0 = get_clock();
    int nparts = 0, nloose = 0, i = 0, j = 0;

    dir_scan(sc);
    dir_pause(dir_pause_snap_ms);
    snap->release = dir_snap_release;
    dir_pack_owed = false;
    if (sc->p >= 0) {
        uint64_t size = sc->packs[sc->p].size;
        TCGCacheFile *f = &snap->f[0];

        if (mapped + size > dir_map_max) {
            tcg_cache_stats.map_budget++;
            /* Empty, so that the next build has room, if any can. */
            dir_pack_owed = size <= dir_map_max;
            if (dir_pack_owed) {
                goto done;
            }
        } else if (dir_map_file(sc->packs[sc->p].name, f,
                                dir_map_max - mapped)) {
            if (f->hdr.check == sc->pack.hdr.check) {
                f->level = TCG_CACHE_LEVEL_PACK;
                if (tcg_cache_pages) {
                    tcg_cache_pages_track(f);
                }
                mapped += f->size;
                dir_claims_add(&mc, &nmc, f, snap->n++);
            } else {
                dir_unmap_file(f);
            }
        }
    }
    qsort(mc, nmc, sizeof(*mc), dir_claim_cmp);
    for (int k = 0; k < sc->nparts && nparts < dir_parts_max; k++) {
        const DirPart *pt = &sc->parts[k];
        TCGCacheFile *f = &snap->f[snap->n];

        if (pt->state != DIR_PACK_VALID
            || dir_claimed(mc, nmc, pt->c.name, pt->f.hdr.check)) {
            continue;
        }
        if (mapped + pt->c.size > dir_map_max) {
            tcg_cache_stats.map_budget++;
            continue;
        }
        if (!dir_map_file(pt->c.name, f, dir_map_max - mapped)) {
            continue;
        }
        if (f->hdr.check != pt->f.hdr.check || !dir_level_ok(f, pt->c.name)) {
            dir_unmap_file(f);
            continue;
        }
        f->level = TCG_CACHE_LEVEL_PART;
        if (tcg_cache_pages) {
            tcg_cache_pages_track(f);
        }
        mapped += f->size;
        nparts++;
        dir_claims_add(&mc, &nmc, f, snap->n++);
        qsort(mc, nmc, sizeof(*mc), dir_claim_cmp);
    }
    sl->mc = mc;
    sl->nmc = nmc;
    if (dir_ops->list(dir_snap_entry, sl, DIR_SCAN_MAX) < 0) {
        goto done;
    }
    while (nloose < DIR_LOOSE_MAX
           && (i < sl->nnewest || j < sl->nnewest_cov)) {
        bool cov = i == sl->nnewest
                   || (j < sl->nnewest_cov
                       && strcmp(sl->newest_cov[j].name,
                                 sl->newest[i].name) > 0);
        const DirCand *d = cov ? &sl->newest_cov[j++] : &sl->newest[i++];
        TCGCacheFile *f = &snap->f[snap->n];

        if (mapped + d->size > dir_map_max) {
            tcg_cache_stats.map_budget++;
            continue;
        }
        if (!dir_map_file(d->name, f, dir_map_max - mapped)) {
            continue;
        }
        if (cov && dir_claimed(mc, nmc, d->name, f->hdr.check)) {
            dir_unmap_file(f);
            continue;
        }
        f->level = TCG_CACHE_LEVEL_SEG;
        if (tcg_cache_pages) {
            tcg_cache_pages_track(f);
        }
        mapped += f->size;
        snap->n++;
        nloose++;
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
    tcg_cache_stats.publish_bytes += flen;
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
 * Compaction and cleanup, on
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

/* A merge's inputs: P, parts, loose segments. */
#define DIR_MERGE_IN        (1 + DIR_PARTS_SEEN + DIR_COMPACT_IN)

typedef struct DirCompact {
    TCGCacheFile in[DIR_MERGE_IN];
    void *fh[DIR_MERGE_IN];
    char name[DIR_MERGE_IN][64];
    int level[DIR_MERGE_IN];
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
 * Testing: XTCG_CACHE_TEST_IMG_MAX and XTCG_CACHE_TEST_SLOTS_MAX, a merge's
 * image records and slots (at most the readers' limits);
 * XTCG_CACHE_TEST_SAMEHASH, a merge plans its index as if every key had
 * one hash, then gives up whether or not the plan fit (counted as the
 * plan's refusal, or as probes): nothing it would write could be found;
 * XTCG_CACHE_PAUSE_PLAN_MS, a pause at the plan's first checkpoint,
 * publication served throughout.
 */
static uint32_t dir_test_img_max = TCG_CACHE_IMG_MAX;
static uint32_t dir_test_slots_max = TCG_CACHE_SLOTS_MAX;
static bool dir_test_samehash, dir_plan_paused;
static unsigned dir_pause_plan_ms;

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

/* A merge's checkpoint while it builds its index: publication served. */
static bool dir_plan_checkpoint(void)
{
    if (dir_pause_plan_ms && !dir_plan_paused) {
        dir_plan_paused = true;
        for (unsigned i = 0; i < dir_pause_plan_ms && !dir_ending(); i++) {
            g_usleep(1000);
            dir_compact_yield();
        }
    }
    dir_compact_yield();
    return !dir_ending();
}

/*
 * The index of @a's @n envelopes (@data bytes) laid out in order after the
 * header, image records, index and @n_cover cover entries: planned by
 * image, the file laid out, the index filled (every entry within the
 * reader's probes of its home).  NULL if it can't be, the reason counted;
 * @plan holds the image records.
 */
static TCGCacheIdx *dir_compact_table(DirArt *a, size_t n, uint64_t data,
                                      uint32_t n_cover, uint64_t gen,
                                      TCGCacheFileHdr *h, size_t *out_len,
                                      TCGCacheIdxPlan *plan)
{
    g_autofree uint64_t *id = g_new(uint64_t, MAX(n, 1));
    g_autofree uint64_t *kh = g_new(uint64_t, MAX(n, 1));
    g_autofree uint32_t *rel = g_new(uint32_t, MAX(n, 1));
    g_autofree uint32_t *len = g_new(uint32_t, MAX(n, 1));
    TCGCacheIdx *slots;
    uint64_t at = 0;
    int r;

    dir_plan_paused = false;
    for (size_t i = 0; i < n; i++) {
        const TCGCacheEnv *k = &a[i].key;

        if (!(i % 4096) && !dir_plan_checkpoint()) {
            tcg_cache_stats.merge_refused_index[TCG_CACHE_PLAN_CANCEL]++;
            return NULL;
        }
        id[i] = k->id;
        kh[i] = tcg_cache_key_hash(k->id, k->rva, k->flags, k->cs_base,
                                   k->cflags);
        rel[i] = at;
        len[i] = k->len;
        at += ROUND_UP(k->len, 8);
    }
    if (dir_test_samehash) {
        /* Planned with one hash for every key: never written. */
        g_autofree uint64_t *one = g_new(uint64_t, MAX(n, 1));

        for (size_t i = 0; i < n; i++) {
            one[i] = 1;
        }
        r = tcg_cache_index_plan(id, one, n, dir_test_probes, dir_test_img_max,
                                 dir_test_slots_max, dir_plan_checkpoint,
                                 plan);
        tcg_cache_index_plan_free(plan);
        tcg_cache_stats.merge_refused_index[r ? r : TCG_CACHE_PLAN_PROBES]++;
        return NULL;
    }
    r = tcg_cache_index_plan(id, kh, n, dir_test_probes, dir_test_img_max,
                             dir_test_slots_max, dir_plan_checkpoint, plan);
    if (r) {
        tcg_cache_stats.merge_refused_index[r]++;
        return NULL;
    }
    tcg_cache_stats.compact_regrow += plan->growths;
    *out_len = tcg_cache_pack_layout(h, gen, n, plan, n_cover, data);
    if (!*out_len) {
        return NULL;
    }
    slots = g_new(TCGCacheIdx, MAX(plan->n_slots, 1));
    if (!tcg_cache_index_fill(plan, kh, h->data_off, rel, len,
                              dir_plan_checkpoint, slots)) {
        g_free(slots);
        return NULL;
    }
    return slots;
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
 * @keep_rank in the scan (-1: all of them, after a major), invalid packs
 * and parts, parts a valid file covers exactly, segments a valid file's
 * listed claim covers exactly (each opened and checked), old temporaries.
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
    for (int i = 0; i < sc->nparts; i++) {
        DirPart *pt = &sc->parts[i];

        if (!pt->deleted
            && (pt->state == DIR_PACK_INVALID
                || (pt->state == DIR_PACK_VALID && pt->covered))
            && dir_remove(pt->c.name)) {
            pt->deleted = true;
        }
    }
    for (size_t i = 0; i < sc->nclaims; i++) {
        const DirClaim *c = &sc->claims[i];
        bool *pr = c->holder < 0 ? sc->present : sc->parts[c->holder].present;
        TCGCacheCover e = { .hdr_check = c->check };

        if (!pr[c->idx] || !dir_seg_name_ok(c->name)) {
            continue;
        }
        memcpy(e.name, c->name, strnlen(c->name, 63));
        if (dir_remove_covered(&e)) {
            /* Gone: no other claim on it is tried. */
            size_t n, k = dir_claims_of(sc->claims, sc->nclaims, c->name, &n);

            for (size_t m = 0; m < n; m++) {
                const DirClaim *o = &sc->claims[k + m];

                (o->holder < 0 ? sc->present
                               : sc->parts[o->holder].present)[o->idx] = false;
            }
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

/*
 * The kinds of merge.  A minor makes a part of the oldest loose segments,
 * never reading P or a part; a parts merge makes a part of parts; a major
 * makes a new pack of P, parts and loose segments; the first pack is made
 * of loose segments when there is no P.
 */
enum { DIR_MINOR, DIR_PARTS, DIR_MAJOR, DIR_FIRST, DIR_KINDS };
static const char *const dir_kind_name[DIR_KINDS] = {
    "minor", "parts", "major", "first",
};
enum { DIR_M_NONE, DIR_M_DONE, DIR_M_FAILED };

/*
 * The estimator of a merge's cost, for its admission: time per input
 * entry, this process's last measured (never under DIR_MERGE_NS_MIN), or
 * DIR_MERGE_NS before the first; testing, XTCG_CACHE_MERGE_NS, a fixed
 * value (0: admit everything).  A merge is
 * admitted while its estimate is at most the larger of DIR_MERGE_BUDGET
 * and the process's age (XTCG_CACHE_AGE_MS added, for tests): an
 * experimental heuristic, so that a short process starts small merges.
 */
static uint64_t dir_ns_per_entry = DIR_MERGE_NS;
/*
 * A round whose merges were refused only for their estimates: the least
 * estimate refused (dir_cost_need), and the clock time at which the
 * process's age reaches it (dir_cost_retry_at), when the writer tries
 * again, whatever the interval; such a refusal isn't a lack of progress.
 */
static uint64_t dir_cost_need;
static int64_t dir_cost_retry_at;
static int64_t dir_merge_t0;        /* the last attempt's start */
static bool dir_admit_all, dir_ns_fixed;
static int64_t dir_start_clock, dir_age_extra;

static uint64_t dir_merge_budget(void)
{
    int64_t age = get_clock() - dir_start_clock + dir_age_extra;

    return MAX(DIR_MERGE_BUDGET, MAX(age, 0));
}

static uint64_t dir_sat_mul(uint64_t a, uint64_t b)
{
    return b && a > UINT64_MAX / b ? UINT64_MAX : a * b;
}

static uint64_t dir_sat_add(uint64_t a, uint64_t b)
{
    return a > UINT64_MAX - b ? UINT64_MAX : a + b;
}

/*
 * The output's cover list as inputs are admitted: unique by name.  A
 * direct input's name and header replace a carried entry for that name
 * (that file is gone: a file of that name with another header is here);
 * a carried entry whose name the list holds with another checksum,
 * carried, conflicts, and its input isn't taken.
 */
typedef struct DirCover {
    TCGCacheCover *e;
    bool *direct;
    uint32_t n;
    GHashTable *by_name;        /* name -> index + 1 */
} DirCover;

/*
 * Whether input @name (a direct input's name and header @check; NULL for
 * P) and @f's present entries, carried, fit the list; added if so.
 */
static bool dir_cover_admit(DirCover *dc, const char *name, uint64_t check,
                            const TCGCacheFile *f, const bool *present,
                            bool dry)
{
    uint32_t add = 0;
    uint32_t nf = f ? f->hdr.n_cover : 0;

    /* First the checks, then the changes. */
    if (name) {
        gpointer v = g_hash_table_lookup(dc->by_name, name);

        if (!v) {
            add++;
        } else if (dc->direct[GPOINTER_TO_UINT(v) - 1]) {
            return false;
        }
    }
    for (uint32_t i = 0; i < nf; i++) {
        gpointer v;

        if (!present[i]) {
            continue;
        }
        if (name && !strncmp(f->cover[i].name, name, 64)) {
            return false;
        }
        v = g_hash_table_lookup(dc->by_name, f->cover[i].name);
        if (!v) {
            add++;
            continue;
        }
        if (dc->e[GPOINTER_TO_UINT(v) - 1].hdr_check
            != f->cover[i].hdr_check && !dc->direct[GPOINTER_TO_UINT(v) - 1]) {
            return false;
        }
    }
    if (dc->n + add > TCG_CACHE_COVER_MAX) {
        return false;
    }
    if (dry) {
        return true;
    }
    if (name) {
        gpointer v = g_hash_table_lookup(dc->by_name, name);
        uint32_t k = v ? GPOINTER_TO_UINT(v) - 1 : dc->n++;

        memset(&dc->e[k], 0, sizeof(dc->e[k]));
        memcpy(dc->e[k].name, name, strnlen(name, 63));
        dc->e[k].hdr_check = check;
        dc->direct[k] = true;
        g_hash_table_insert(dc->by_name, dc->e[k].name,
                            GUINT_TO_POINTER(k + 1));
    }
    for (uint32_t i = 0; i < nf; i++) {
        if (present[i]
            && !g_hash_table_contains(dc->by_name, f->cover[i].name)) {
            dc->e[dc->n] = f->cover[i];
            dc->direct[dc->n] = false;
            g_hash_table_insert(dc->by_name, dc->e[dc->n].name,
                                GUINT_TO_POINTER(dc->n + 1));
            dc->n++;
        }
    }
    return true;
}

/* A merge's admission so far. */
typedef struct DirAdmit {
    uint64_t arts, in_bytes, est, budget;
    uint32_t segs, parts;
} DirAdmit;

/*
 * Take input @name (level @level) into @c if it fits: entries, the
 * estimate, the cover list, the disk room.  @want_check, if nonzero, is
 * the header the scan read (a part, or P), which the file must still have.
 */
static bool dir_admit(DirScan *sc, DirCompact *c, DirAdmit *ad, DirCover *dc,
                      const char *name, int level, uint64_t want_check,
                      const TCGCacheFile *carry, const bool *present)
{
    uint32_t k = c->nin;
    size_t size;
    bool invalid, ok;
    uint64_t est;

    if (k >= DIR_MERGE_IN) {
        return false;
    }
    c->fh[k] = dir_open_file(name, &c->in[k], &size, &invalid);
    if (!c->fh[k]) {
        return false;
    }
    est = dir_sat_add(ad->est, dir_sat_mul(c->in[k].hdr.n_index,
                                           dir_ns_per_entry));
    ok = (level == TCG_CACHE_LEVEL_SEG
          ? c->in[k].hdr.magic == TCG_CACHE_SEG_MAGIC
            && !dir_claimed(sc->claims, sc->nclaims, name, c->in[k].hdr.check)
          : dir_level_ok(&c->in[k], name)
            && c->in[k].hdr.check == want_check);
    if (ad->arts + c->in[k].hdr.n_index > dir_compact_arts) {
        ok = false;
    }
    if (ok && !dir_admit_all && est > ad->budget) {
        /*
         * Not affordable yet: the age at which it would be is noted, if
         * nothing else refuses it (the disk room, the cover list).
         */
        if (dir_compact_room(sc, ad->in_bytes + size)
            && dir_cover_admit(dc, level == TCG_CACHE_LEVEL_PACK ? NULL : name,
                               c->in[k].hdr.check, carry, present, true)) {
            dir_cost_need = dir_cost_need ? MIN(dir_cost_need, est) : est;
        }
        ok = false;
    }
    ok = ok && dir_compact_room(sc, ad->in_bytes + size)
         && dir_cover_admit(dc, level == TCG_CACHE_LEVEL_PACK ? NULL : name,
                            c->in[k].hdr.check, carry, present, false);
    if (!ok) {
        tcg_cache_file_close(&c->in[k]);
        dir_ops->close(c->fh[k]);
        c->fh[k] = NULL;
        return false;
    }
    ad->arts += c->in[k].hdr.n_index;
    ad->in_bytes += size;
    ad->est = est;
    ad->segs += level == TCG_CACHE_LEVEL_SEG;
    ad->parts += level == TCG_CACHE_LEVEL_PART;
    memcpy(c->name[k], name, 64);
    c->level[k] = level;
    c->nin++;
    return true;
}

/* The oldest loose segments, as many as fit. */
static void dir_admit_loose(DirScan *sc, DirCompact *c, DirAdmit *ad,
                            DirCover *dc)
{
    for (int pass = 0; pass < 2; pass++) {
        const DirCand *list = pass ? sc->oldest_cov : sc->oldest;
        int nlist = pass ? sc->noldest_cov : sc->noldest;

        for (int i = 0; i < nlist && ad->segs < DIR_COMPACT_IN; i++) {
            dir_admit(sc, c, ad, dc, list[i].name, TCG_CACHE_LEVEL_SEG, 0,
                      NULL, NULL);
        }
    }
}

/*
 * The merge of @kind: its inputs admitted (@parts, part indices in the
 * order to try, for a parts merge or a major), read, merged and written
 * as part or pack @gen.  DIR_M_NONE if its minimum isn't admitted (a
 * minor or the first pack, a segment; a parts merge, two parts; a major,
 * P and a part or segment, a part if @need_part).
 */
static int dir_compact_merge(DirScan *sc, DirCompact *c, int kind,
                             const int *parts, int nparts, bool need_part,
                             uint64_t gen)
{
    static const uint8_t zero[8];
    g_autofree TCGCacheCover *cover = g_new0(TCGCacheCover,
                                             TCG_CACHE_COVER_MAX);
    g_autofree bool *direct = g_new0(bool, TCG_CACHE_COVER_MAX);
    g_autoptr(GHashTable) by_name = g_hash_table_new(g_str_hash,
                                                     g_str_equal);
    g_autofree TCGCacheIdx *slots = NULL;
    g_auto(TCGCacheIdxPlan) plan = { };
    DirCover dc = { .e = cover, .direct = direct, .by_name = by_name };
    DirAdmit ad = { .budget = dir_merge_budget() };
    bool pack_out = kind == DIR_MAJOR || kind == DIR_FIRST;
    uint64_t data, budget, written = 0, read = 0;
    int64_t t0 = get_clock();
    TCGCacheFileHdr h;
    size_t kept, out_len;
    bool giveup = false;
    char name[64];
    void *wh;

    if (kind == DIR_MAJOR
        && !dir_admit(sc, c, &ad, &dc, sc->packs[sc->p].name,
                      TCG_CACHE_LEVEL_PACK, sc->pack.hdr.check, &sc->pack,
                      sc->present)) {
        return DIR_M_NONE;
    }
    for (int i = 0; i < nparts; i++) {
        DirPart *pt = &sc->parts[parts[i]];

        dir_admit(sc, c, &ad, &dc, pt->c.name, TCG_CACHE_LEVEL_PART,
                  pt->f.hdr.check, &pt->f, pt->present);
    }
    if (kind != DIR_PARTS) {
        dir_admit_loose(sc, c, &ad, &dc);
    }
    if ((kind == DIR_MINOR || kind == DIR_FIRST) ? !ad.segs
        : kind == DIR_PARTS ? ad.parts < 2
        : need_part ? !ad.parts : !(ad.parts + ad.segs)) {
        return DIR_M_NONE;
    }
    tcg_cache_stats.merge_age_ns[kind] += get_clock() - dir_start_clock
                                          + dir_age_extra;
    tcg_cache_stats.merge_est_ns[kind] += ad.est;
    tcg_cache_stats.merge_in_bytes[kind] += ad.in_bytes;
    dir_merge_t0 = t0;
    if (tcg_cache_debug) {
        fprintf(stderr, "xtcg-cache dir: %s merge: %u files, %" PRIu64
                " entries, estimate %" PRIu64 " us of %" PRIu64 "\n",
                dir_kind_name[kind], c->nin, ad.arts, ad.est / 1000,
                ad.budget / 1000);
    }
    for (uint32_t i = 0; i < c->nin; i++) {
        if (!dir_compact_read(c, i)) {
            /* What was read before, counted as the time spent on it is. */
            tcg_cache_stats.merge_entries[kind] += c->n;
            return DIR_M_FAILED;
        }
    }
    tcg_cache_stats.compact_arts += c->n;
    tcg_cache_stats.merge_entries[kind] += c->n;
    read = c->n;
    c->n = dir_compact_dedup(c, &giveup);
    if (giveup || dir_ending()) {
        return DIR_M_FAILED;
    }
    /*
     * The envelopes' room: the file less its header, its padding, its
     * cover list, the most image records and the largest index a reader
     * allows (growth for probe clusters may need more than the count
     * suggests).
     */
    budget = TCG_CACHE_FILE_MAX - sizeof(TCGCacheFileHdr) - 8
             - (uint64_t)dc.n * sizeof(TCGCacheCover)
             - (uint64_t)TCG_CACHE_IMG_MAX * sizeof(TCGCacheImg)
             - (uint64_t)TCG_CACHE_SLOTS_MAX * sizeof(TCGCacheIdx);
    kept = dir_compact_select(c->arts, c->n, budget,
                              dir_compact_arts / 4 * 3, &data);
    slots = dir_compact_table(c->arts, kept, data, dc.n, gen, &h, &out_len,
                              &plan);
    if (!slots) {
        tcg_cache_stats.compact_skip++;
        return DIR_M_FAILED;
    }
    /* The actual size, past what the inputs' sizes suggested. */
    if (!dir_compact_room(sc, out_len)) {
        tcg_cache_stats.compact_skip++;
        return DIR_M_FAILED;
    }
    dir_pause(dir_pause_compact_ms);
    if (dir_ending()) {
        return DIR_M_FAILED;
    }
    wh = dir_ops->create();
    if (!wh) {
        return DIR_M_FAILED;
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
        written += ROUND_UP(env->len, 8);
        at += ROUND_UP(env->len, 8);
    }
    tcg_cache_pack_seal(&h, plan.img, cover);
    if (!dir_ops->write(wh, slots, sizeof(TCGCacheIdx) * h.n_slots,
                        h.index_off)) {
        goto abort;
    }
    if (h.n_img && !dir_ops->write(wh, plan.img,
                                   sizeof(TCGCacheImg) * h.n_img, h.img_off)) {
        goto abort;
    }
    if ((h.cover_len && !dir_ops->write(wh, cover, h.cover_len, h.cover_off))
        || !dir_ops->write(wh, &h, sizeof(h), 0)) {
        goto abort;
    }
    written = out_len;
    dir_pause(dir_pause_compact_ms);
    if (dir_ending()) {
        goto abort;
    }
    /* Again, with what this process published meanwhile. */
    if (!dir_compact_room(sc, out_len)) {
        tcg_cache_stats.compact_skip++;
        goto abort;
    }
    snprintf(name, sizeof(name), "%s-%016" PRIx64 ".xtp",
             pack_out ? "pack" : "part", gen);
    if (!dir_ops->commit(wh, name)) {
        tcg_cache_stats.merge_tmp_bytes += written;
        return DIR_M_FAILED;
    }
    tcg_cache_stats.merge_tmp_bytes += written;
    /* Counted as published until a complete scan sees what is left. */
    dir_pub_bytes_since += out_len;
    tcg_cache_stats.compactions++;
    tcg_cache_stats.merge_done[kind]++;
    tcg_cache_stats.compact_in += c->nin;
    tcg_cache_stats.compact_kept += kept;
    tcg_cache_stats.compact_bytes += out_len;
    /* Learned per entry read, as admission counts them (before dedup). */
    if (read && !dir_ns_fixed) {
        dir_ns_per_entry = MAX(DIR_MERGE_NS_MIN, (get_clock() - t0) / read);
    }
    if (tcg_cache_debug) {
        fprintf(stderr, "xtcg-cache dir: compacted %u files, %zu of %zu "
                "artifacts, into %s (%zu bytes)\n", c->nin, kept, c->n, name,
                out_len);
    }
    return DIR_M_DONE;

abort:
    tcg_cache_stats.merge_tmp_bytes += written;
    dir_ops->drop(wh);
    return DIR_M_FAILED;
}

/*
 * A parts merge's candidates, into @out: the live parts within 4x of the
 * smallest's entries, smallest first; at the bound (@emergency), if no
 * pair is within 4x, the two smallest (*@emergency stays true).  Their
 * number.
 */
static int dir_parts_choose(const DirScan *sc, int *out, bool *emergency)
{
    int n = 0, m = 0;

    for (int i = 0; i < sc->nparts; i++) {
        if (sc->parts[i].state == DIR_PACK_VALID && !sc->parts[i].covered
            && !sc->parts[i].deleted) {
            out[n++] = i;
        }
    }
    /* Fewest entries first (at most DIR_PARTS_SEEN: insertion). */
    for (int i = 1; i < n; i++) {
        int x = out[i], j = i;

        while (j > 0 && sc->parts[out[j - 1]].f.hdr.n_index
                        > sc->parts[x].f.hdr.n_index) {
            out[j] = out[j - 1];
            j--;
        }
        out[j] = x;
    }
    while (m < n && sc->parts[out[m]].f.hdr.n_index
                    <= 4ull * MAX(sc->parts[out[0]].f.hdr.n_index, 1)) {
        m++;
    }
    if (m < 2 && *emergency && n >= 2) {
        return 2;
    }
    *emergency = false;
    return m < 2 ? 0 : m;
}

/* A major's parts, oldest generation first. */
static int dir_parts_oldest(const DirScan *sc, int *out)
{
    int n = 0;

    for (int i = sc->nparts - 1; i >= 0; i--) {
        if (sc->parts[i].state == DIR_PACK_VALID && !sc->parts[i].covered
            && !sc->parts[i].deleted) {
            out[n++] = i;
        }
    }
    return n;
}

/*
 * One round of maintenance: cleanup, then at most one merge, the first
 * admissible of the kinds the directory's state calls for:
 *  - over the disk budget: a major, a parts merge, the first pack;
 *  - at the bound (live and unresolved parts): a parts merge, then a
 *    major that takes a part; never a minor;
 *  - otherwise: a major when due (the live parts' bytes at least half of
 *    P's), the first pack when there is no P, a minor (if @loose: the
 *    loose trigger holds), a tidy parts merge (more than 4 live parts).
 * Majors and the first pack need P to be the newest pack that isn't
 * invalid (revision 9); minors and parts merges don't read P.  False if
 * the round made no progress: its scan was incomplete, or a merge the
 * state called for wasn't admissible or failed (not because another
 * process holds the lock, or this one is ending).
 */
static bool dir_compact(bool loose)
{
    g_autofree DirScan *sc = g_new0(DirScan, 1);
    g_autofree DirCompact *c = g_new0(DirCompact, 1);
    int64_t t0 = get_clock();
    int kinds[4], nk = 0, r = DIR_M_NONE, kind = -1;
    bool progress = false, wanted = false, pack_ok = true, bound, over;
    int order[DIR_PARTS_SEEN], norder;
    bool emergency = false;
    void *lh = dir_ops->trylock();

    if (!lh) {
        tcg_cache_stats.compact_busy++;
        return true;
    }
    dir_cost_need = 0;
    dir_cost_retry_at = 0;
    dir_scan(sc);
    /* Only a complete scan establishes what is there, and what isn't. */
    if (dir_ending() || !sc->complete) {
        progress = dir_ending();
        goto out;
    }
    for (int i = 0; i < (sc->p >= 0 ? sc->p : sc->npacks); i++) {
        if (sc->pack_state[i] != DIR_PACK_INVALID) {
            pack_ok = false;
        }
    }
    if (sc->packs_seen > sc->npacks && sc->p < 0) {
        pack_ok = false;
    }
    /*
     * Cleanup first, which needs no merge and is cheap, so that a process
     * too short to finish a merge still does it.
     */
    dir_compact_clean(sc, sc->p >= 0 ? sc->p : sc->npacks);
    if (sc->max_gen == UINT64_MAX) {
        tcg_cache_stats.compact_skip++;
        goto out;
    }
    bound = sc->live + sc->unresolved >= (int)dir_parts_max;
    over = sc->bytes > dir_disk_max;
    if (over) {
        if (sc->p >= 0 && pack_ok) {
            kinds[nk++] = DIR_MAJOR;
        }
        kinds[nk++] = DIR_PARTS;
        if (sc->p < 0 && pack_ok) {
            kinds[nk++] = DIR_FIRST;
        }
    } else if (bound) {
        kinds[nk++] = DIR_PARTS;
        if (sc->p >= 0 && pack_ok) {
            kinds[nk++] = DIR_MAJOR;
        }
    } else {
        if (sc->p >= 0 && pack_ok
            && (dir_test_major
                || (sc->live
                    && sc->live_bytes >= sc->packs[sc->p].size / 2))) {
            kinds[nk++] = DIR_MAJOR;
        }
        if (sc->p < 0 && pack_ok && loose) {
            kinds[nk++] = DIR_FIRST;
        }
        if (loose) {
            kinds[nk++] = DIR_MINOR;
        }
        if (sc->live > 4) {
            kinds[nk++] = DIR_PARTS;
        }
    }
    wanted = nk > 0;
    c->buf = g_malloc(DIR_BUF_SIZE);
    c->buf2 = g_malloc(DIR_BUF_SIZE);
    c->win = g_malloc(DIR_WIN_SIZE);
    for (int i = 0; i < nk && r == DIR_M_NONE; i++) {
        kind = kinds[i];
        emergency = bound;
        norder = kind == DIR_PARTS ? dir_parts_choose(sc, order, &emergency)
                 : kind == DIR_MAJOR ? dir_parts_oldest(sc, order) : 0;
        if (kind == DIR_PARTS && norder < 2) {
            continue;
        }
        r = dir_compact_merge(sc, c, kind, order, norder,
                              kind == DIR_MAJOR && bound && !over,
                              sc->max_gen + 1);
        if (r == DIR_M_NONE) {
            for (uint32_t k = 0; k < c->nin; k++) {
                tcg_cache_file_close(&c->in[k]);
                dir_ops->close(c->fh[k]);
            }
            c->nin = 0;
        }
    }
    if (r != DIR_M_NONE) {
        /* Every attempt that began, whatever its outcome. */
        tcg_cache_stats.merge_act_ns[kind] += get_clock() - dir_merge_t0;
    }
    if (r == DIR_M_NONE) {
        if (wanted && (over || bound)) {
            tcg_cache_stats.merge_saturated++;
        }
        progress = !wanted;
        if (wanted && dir_cost_need) {
            /* Refused for its cost alone: again once the process is older. */
            dir_cost_retry_at = dir_start_clock - dir_age_extra
                                + (int64_t)MIN(dir_cost_need, INT64_MAX / 2);
            tcg_cache_stats.merge_deferred++;
            progress = true;
        }
    } else if (r == DIR_M_DONE) {
        progress = true;
        if (kind == DIR_PARTS && emergency) {
            tcg_cache_stats.merge_emergency++;
        }
    } else if (dir_ending()) {
        tcg_cache_stats.compact_exit++;
        tcg_cache_stats.merge_exit[kind]++;
        progress = true;
    } else {
        tcg_cache_stats.compact_fail++;
        tcg_cache_stats.merge_fail[kind]++;
    }
    for (uint32_t i = 0; i < c->nin; i++) {
        tcg_cache_file_close(&c->in[i]);
        dir_ops->close(c->fh[i]);
    }
    if (r == DIR_M_DONE) {
        dir_pause(dir_pause_committed_ms);
        /* The inputs: the new file has their artifacts and carries them. */
        for (uint32_t i = 0; i < c->nin; i++) {
            dir_remove(c->name[i]);
        }
        if (kind == DIR_MAJOR) {
            sc->pack_state[sc->p] = DIR_PACK_UNREAD;
        }
        /*
         * What the inputs covered, the new file does; after a major every
         * valid pack is older.
         */
        dir_compact_clean(sc, kind == DIR_MAJOR || kind == DIR_FIRST
                              ? -1 : sc->p);
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
    bool first = true;

    qemu_mutex_lock(&dir_wlock);
    while (dir_writer_on) {
        int64_t now;

        /*
         * The first round at once, so that a process shorter than the wait
         * still does its first maintenance (a start-up of 100 ms would
         * otherwise end before it).
         */
        if (!first) {
            qemu_cond_timedwait(&dir_wcond, &dir_wlock, 100);
        }
        first = false;
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
        if (!dir_ending() && !tcg_cache_no_write) {
            uint64_t loose = dir_seen_loose + dir_pub_since;
            bool merge = loose > dir_compact_loose
                         || dir_seen_loose_bytes + dir_pub_bytes_since
                            > DIR_COMPACT_BYTES;
            bool bound = dir_seen_bound >= (int)dir_parts_max;
            /*
             * Once a minute at most, unless the last round made progress
             * and there are more loose segments than a snapshot can read
             * (those are lost to lookups), or the parts are at the bound,
             * or a major is due.
             */
            /*
             * A merge deferred for its cost waits for the process's age to
             * reach its estimate, not the urgent rounds.
             */
            bool due = now - dir_last_compact >= dir_compact_ns
                       || (dir_cost_retry_at
                           ? now >= dir_cost_retry_at
                           : !dir_compact_stuck
                             && (loose > DIR_COMPACT_URGENT || bound
                                 || dir_seen_major_due));

            if (due && (merge || dir_seen_leftovers || dir_over_budget()
                        || bound || dir_seen_major_due
                        || dir_seen_live > 4)) {
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
 * Testing (XTCG_CACHE_CHECKALL): every segment, part and pack in the directory,
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

        uint64_t gen;

        if (!dir_pack_name_ok(names[i]) && !dir_seg_name_ok(names[i])
            && !tcg_cache_part_name_gen(names[i], &gen)) {
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
    dir_parts_max = MAX(dir_env_u64("XTCG_CACHE_PARTS_MAX", DIR_PARTS_MAX), 2);
    dir_parts_max = MIN(dir_parts_max, DIR_PARTS_MAX);
    dir_test_major = getenv("XTCG_CACHE_TEST_MAJOR");
    dir_ns_per_entry = dir_env_u64("XTCG_CACHE_MERGE_NS", DIR_MERGE_NS);
    dir_ns_fixed = getenv("XTCG_CACHE_MERGE_NS");
    dir_admit_all = !dir_ns_per_entry;
    dir_age_extra = dir_env_ms("XTCG_CACHE_AGE_MS") * SCALE_MS;
    dir_start_clock = t0;
    if (getenv("XTCG_CACHE_TEST_PROBES")) {
        dir_test_probes = MIN(MAX(atoi(getenv("XTCG_CACHE_TEST_PROBES")), 1),
                              TCG_CACHE_PROBES);
    }
    dir_test_img_max = MIN(dir_env_u64("XTCG_CACHE_TEST_IMG_MAX",
                                       TCG_CACHE_IMG_MAX), TCG_CACHE_IMG_MAX);
    dir_test_slots_max = MIN(dir_env_u64("XTCG_CACHE_TEST_SLOTS_MAX",
                                         TCG_CACHE_SLOTS_MAX),
                             TCG_CACHE_SLOTS_MAX);
    dir_test_samehash = getenv("XTCG_CACHE_TEST_SAMEHASH");
    dir_pause_plan_ms = dir_env_ms("XTCG_CACHE_PAUSE_PLAN_MS");
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
            tcg_cache_stats.publish_bytes += flen;
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
