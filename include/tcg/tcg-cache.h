/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Translation artifacts: a TB's code and metadata as a self-contained
 * record that can be installed again at another place in the code buffer.
 *
 * While a translation is captured, the back end records every site whose
 * encoding depends on where the code lies, with what the value at that
 * site means (its provenance): a helper, a stub generated at start-up, the
 * TB's own struct, the chunk's slow-path thunk, a place in the TB's own
 * code, or a value that must stay as it is.  A PC-relative reference whose
 * meaning isn't known fails the capture.  The front end records the guest
 * bytes the translation read, the sites it ordered with acquire/release,
 * and anything that makes the translation unfit to keep.
 */

#ifndef TCG_CACHE_H
#define TCG_CACHE_H

#include "exec/vaddr.h"
#include "qemu/rcu.h"

typedef struct TCGContext TCGContext;
typedef struct TranslationBlock TranslationBlock;

/* tcg_cache_mode */
enum {
    TCG_CACHE_OFF,
    TCG_CACHE_CAPTURE,      /* record and check; install nothing */
    TCG_CACHE_STRESS,       /* install every captured TB from its artifact */
    TCG_CACHE_ON,           /* keep eligible artifacts, install from them */
};

extern int tcg_cache_mode;
/* Development: move each install by up to this many 16-byte steps. */
extern unsigned tcg_cache_skew;
extern bool tcg_cache_stats_at_exit;
extern bool tcg_cache_debug;
/* XTCG_CACHE_COSTS: lookups and installs timed by part (tcg_cache_part). */
extern bool tcg_cache_costs;
/*
 * Testing: XTCG_CACHE_TEST_REJECT=n, each lookup's first n candidates
 * rejected; XTCG_CACHE_TEST_REGETFAIL, the duplicate test's second gets
 * fail (so no candidate is known to be a copy).
 */
extern unsigned tcg_cache_test_reject;
extern bool tcg_cache_test_reget_fail;
void tcg_cache_part(uint64_t *acc, int64_t *t);
/*
 * The statistics' times are read only when they are printed
 * (XTCG_CACHE_STATS, the module's cachestats, XTCG_CACHE_COSTS): reading
 * the clock costs about 80 ns on Windows on Arm, a hit's share otherwise.
 */
extern bool tcg_cache_timing;
#define TCG_CACHE_CLOCK() (tcg_cache_timing ? get_clock() : 0)
/*
 * XTCG_CACHE_NOWRITE (the module's cachenowrite), development: files are
 * read, never written: no captures published, no maintenance.
 */
extern bool tcg_cache_no_write;
/* Testing: queue a code-buffer flush every this many translations. */
extern unsigned tcg_cache_flush_every;
/* The store's bound, in bytes. */
extern size_t tcg_cache_max;
/* Testing: promote an install's first acquire/release site after its check. */
extern bool tcg_cache_inj_promote;

/*
 * Why a translation isn't captured.  Front-end reasons latch for the
 * whole translation attempt; back-end ones for an emission attempt.
 */
enum {
    TCG_CACHE_X_NONE,
    TCG_CACHE_X_SMC,        /* an SMC check in the TB */
    TCG_CACHE_X_REGION,     /* a region head, trial or probation counter */
    TCG_CACHE_X_PROMOTED,   /* a promoted TSO crossing site */
    TCG_CACHE_X_HOSTPTR,    /* a host pointer as an IR constant */
    TCG_CACHE_X_PLUGIN,
    TCG_CACHE_X_TORN,       /* a guest byte read twice, differently */
    TCG_CACHE_X_SPAN,       /* a guest read outside the TB's two pages */
    TCG_CACHE_X_FAKE,       /* bytes not read from guest memory */
    TCG_CACHE_X_FRONT_MAX,
    /* Back end */
    TCG_CACHE_X_UNKNOWN_REF = TCG_CACHE_X_FRONT_MAX, /* outward, no meaning */
    TCG_CACHE_X_RAW_ADRP,   /* an ADRP without a declared consumer */
    TCG_CACHE_X_ORR_PTR,    /* a relocatable value as a logical immediate */
    TCG_CACHE_X_POOL_MIX,   /* pool dedup merged different meanings */
    TCG_CACHE_X_UNSUPPORTED,/* an emitter that can't be relocated */
    TCG_CACHE_X_TOO_MANY,   /* the record list overflowed */
    TCG_CACHE_X_PROV,       /* a recorded meaning didn't match the code */
    TCG_CACHE_X_LAZY,       /* lazy-sync data outside the hot part */
    TCG_CACHE_X_VERIFY,     /* the verifier found an unrecorded site */
    TCG_CACHE_X_MAX
};

extern const char *const tcg_cache_x_names[TCG_CACHE_X_MAX];
/* Why the last capture returned NULL. */
extern unsigned tcg_cache_last_reason;

/* Provenance: what the value at a site is. */
enum {
    TCG_CAP_NONE,           /* not declared */
    TCG_CAP_ABS,            /* the value itself, unchanged */
    TCG_CAP_HELPER,         /* code or data in QEMU's image */
    TCG_CAP_STUB,           /* code generated at start-up (TCG_STUB_*) */
    TCG_CAP_OWN_TB,         /* the TB's struct (RX alias), plus an addend */
    TCG_CAP_THUNK,          /* the chunk's slow-path thunk */
    TCG_CAP_HOT,            /* a place in the TB's hot part */
    TCG_CAP_COLD,           /* a place in the TB's cold part */
    TCG_CAP_UNSUPPORTED,
};

enum {
    TCG_STUB_EPILOGUE0,     /* tcg_code_gen_epilogue */
    TCG_STUB_RET,           /* the epilogue's return path, tb_ret_addr */
    TCG_STUB_XPAGE,         /* tcg_xpage_stub */
    TCG_STUB_MAX
};

/* Forms: how a site encodes its value. */
enum {
    TCG_CAPF_NONE,
    TCG_CAPF_B26,           /* B, BL */
    TCG_CAPF_BCOND19,       /* B.cond, CBZ, CBNZ */
    TCG_CAPF_TBZ14,         /* TBZ, TBNZ */
    TCG_CAPF_LDRLIT19,      /* LDR (literal) */
    TCG_CAPF_ADR21,         /* ADR */
    TCG_CAPF_ADRP,          /* ADRP alone: a page-aligned value */
    TCG_CAPF_ADRP_ADD,      /* ADRP, then ADD of the low 12 bits */
    TCG_CAPF_ADRP_LDR,      /* ADRP, then LDR (unsigned offset), scaled */
    TCG_CAPF_RAW_ADRP,      /* ADRP whose consumer wasn't declared */
    TCG_CAPF_MOVW,          /* MOVZ or MOVN, then MOVKs (aux below) */
    TCG_CAPF_POOL64,        /* a 64-bit pool word */
    TCG_CAPF_REL32,         /* a 32-bit offset from the word to the target */
    TCG_CAPF_MAX
};

/* TCG_CAPF_MOVW's aux: the halfwords set, MOVN first, 64-bit. */
#define TCG_CAP_MOVW_MASK   0xf
#define TCG_CAP_MOVW_MOVN   0x10
#define TCG_CAP_MOVW_X      0x20

/* Constraints that later patching relies on. */
enum {
    TCG_CAPC_SLOT_LDRLIT = 1,   /* the slot reaches its target_addr by LDR */
};

/*
 * The serialized artifact.  Every offset is from the artifact's start;
 * every multi-byte field is in host order.
 */
#define TCG_CACHE_MAGIC     0x41435458      /* "XTCA" */
#define TCG_CACHE_VERSION   1

/* TCGCacheArt.flags */
#define TCG_CACHE_ART_SPLIT     1   /* hot and cold parts (tcg_tblayout) */
#define TCG_CACHE_ART_PAGE2     2   /* the TB uses the next page too */

/* A place in the TB: bit 31 says the cold part. */
#define TCG_CACHE_COLD_BIT      0x80000000u

typedef struct TCGCacheArt {
    uint32_t magic;
    uint32_t len;
    uint16_t version;
    uint16_t flags;
    uint16_t nb_slots;
    uint16_t n_rel;
    uint16_t n_con;
    uint16_t n_acq;
    uint16_t n_ext;
    uint16_t size;
    uint16_t icount;
    uint16_t jmp_call;
    uint8_t jmp_cold;
    uint8_t jmp_far;
    uint8_t loops;
    uint8_t edge_end;
    uint8_t chain_dead_in;
    uint8_t pad[3];
    uint32_t tb_flags;
    uint32_t cflags;
    uint32_t pad1;
    uint64_t pc;
    uint64_t cs_base;
    uint32_t hot_len;       /* code and pool */
    uint32_t pool_off;      /* where the pool starts, or hot_len */
    uint32_t cold_len;      /* cold code */
    uint32_t search_len;    /* unwind data, after the cold code */
    uint32_t ext_bytes;     /* the guest bytes of all extents */
    uint32_t pad2;
} TCGCacheArt;

typedef struct TCGCacheArtSlot {
    uint32_t reset;         /* a place, or TB_JMP_OFFSET_INVALID */
    uint32_t insn;          /* a place, or TB_JMP_OFFSET_INVALID */
    uint32_t cond;          /* 0, or 1 + a place */
    uint8_t dead;
    uint8_t pad[3];
} TCGCacheArtSlot;

typedef struct TCGCacheArtRel {
    uint32_t site;          /* a place */
    uint8_t form;
    uint8_t kind;
    uint16_t aux;
    uint64_t val;           /* by kind: offset, stub, addend, value, place */
} TCGCacheArtRel;

typedef struct TCGCacheArtCon {
    uint32_t site;          /* a place */
    uint8_t kind;
    uint8_t slot;
    uint16_t pad;
} TCGCacheArtCon;

typedef struct TCGCacheArtExt {
    uint16_t off;           /* from the page of pc */
    uint16_t len;
} TCGCacheArtExt;

/* The artifact's arrays and parts, located and bounds-checked. */
typedef struct TCGCacheArtView {
    const TCGCacheArt *h;
    const TCGCacheArtSlot *slot;
    const TCGCacheArtRel *rel;
    const TCGCacheArtCon *con;
    const uint64_t *acq;
    const TCGCacheArtExt *ext;
    const uint8_t *ext_bytes;
    const uint8_t *hot;
    const uint8_t *cold;
    const uint8_t *search;
} TCGCacheArtView;

bool tcg_cache_art_view(const void *art, size_t len, TCGCacheArtView *v);

/* Front end, during translation (with tcg_ctx->cap_on). */
void tcg_cache_tb_start(TCGContext *s, vaddr pc_first, unsigned page_bits);
void tcg_cache_exclude(TCGContext *s, unsigned reason);
void tcg_cache_read(TCGContext *s, vaddr pc, const void *p, size_t len);
void tcg_cache_acqrel(TCGContext *s, uint64_t pc);

/*
 * After translation, before the TB is published: the artifact (g_free
 * it), its length in *@lenp; or NULL, the reason counted.  @search is the
 * unwind data's RW address.
 */
void *tcg_cache_capture(TCGContext *s, TranslationBlock *tb,
                        const void *search, size_t search_len, size_t *lenp);

/*
 * Install: reserve the TB's places in the current layout (nothing moves
 * until commit), place and relocate it, then commit or abort.
 */
typedef struct TCGCacheRes {
    void *tb;               /* RW */
    void *hot;              /* RW */
    void *cold;             /* RW: cold code, then the unwind data */
    void *search;           /* RW */
    void *code_gen_ptr;     /* after commit */
    void *lay_cold;         /* after commit, split layout */
    const void *thunk;
    bool split;
} TCGCacheRes;

bool tcg_cache_reserve(TCGContext *s, const TCGCacheArtView *v,
                       TCGCacheRes *r);
TranslationBlock *tcg_cache_place(TCGContext *s, const TCGCacheArtView *v,
                                  const TCGCacheRes *r);
void tcg_cache_commit(TCGContext *s, const TCGCacheRes *r);

/*
 * What the OS layer provides for TCG_CACHE_ON.  An image is a mapped
 * executable: an identity (a hash of what names its contents) and the base
 * it is mapped at now.
 */
typedef struct TCGCacheImage {
    uint64_t id;
    uint64_t base;
} TCGCacheImage;

/* A guarded routine's fault: this bit, the guard bit, and the address. */
#define TCG_CACHE_GFAULT        (1ull << 63)
#define TCG_CACHE_GFAULT_GUARD  (1ull << 62)

typedef struct TCGCacheHost {
    /*
     * Whether the guest page @page holds code a cached translation may
     * come from, and its image.  Called with mmap_lock held.
     */
    bool (*page_image)(vaddr page, TCGCacheImage *img);
    /*
     * Copy or compare host memory that may change or go under the
     * caller: 0 when copied or equal, 1 when different, or a fault code
     * (TCG_CACHE_GFAULT), after which @fault is called with it.
     */
    int64_t (*copy)(void *dst, const void *src, size_t len);
    int64_t (*compare)(const void *a, const void *b, size_t len);
    void (*fault)(int64_t code);
    /* Testing: around the guest-byte comparison of a candidate. */
    void (*inject)(vaddr addr, bool before);
} TCGCacheHost;

extern const TCGCacheHost *tcg_cache_host;

/*
 * The guarded routines, for TCGCacheHost's copy and compare: leaf
 * functions whose source loads a fault handler recognises by PC
 * (tcg_cache_guard_pc).  The handler then resumes at the caller (the
 * routine's LR) with a fault code in the result register.  Elsewhere
 * they are plain copies and comparisons.
 */
int64_t tcg_cache_gcopy(void *dst, const void *src, size_t len);
int64_t tcg_cache_gcmp(const void *a, const void *b, size_t len);
bool tcg_cache_guard_pc(uintptr_t pc);
/* Where the guarded routines are assembly: their source loads' PCs. */
#define TCG_CACHE_GLOADS 6
extern const uintptr_t tcg_cache_gloads[TCG_CACHE_GLOADS];
/*
 * Testing: exercise the guarded routines on @p, two pages of @page bytes,
 * the first readable and writable, the second inaccessible.  The number
 * of failed checks; each is printed.
 */
int tcg_cache_selftest(uint8_t *p, size_t page);

/*
 * Testing (XTCG_CACHE_TRACE, the module's cachetrace): a line for each
 * translation with its key, outcome, guest-bytes hash and cost, through
 * tcg_cache_out (stderr unless the OS layer sets it).
 */
extern bool tcg_cache_trace;
extern void (*tcg_cache_out)(const char *line);

/*
 * The store: artifacts by image, rva, flags, cs_base and cflags, newest
 * first.  Under mmap_lock in user mode.
 */
typedef struct TCGCacheCand {
    const void *art;
    size_t len;
    uint64_t base;
} TCGCacheCand;

#define TCG_CACHE_CANDS 4

/*
 * Keep @art (g_malloc'd; the store owns it now, or frees it): "stored",
 * "dup" (an identical candidate is kept) or "full".  A fifth candidate
 * for a key replaces the oldest.
 */
const char *tcg_cache_store_put(const TCGCacheImage *img, void *art,
                                size_t len);
/* A hash of the guest bytes an artifact read: offsets, lengths, bytes. */
uint64_t tcg_cache_art_ghash(const void *art, size_t len);
int tcg_cache_store_find(uint64_t id, uint64_t rva, uint32_t flags,
                         uint64_t cs_base, uint32_t cflags,
                         TCGCacheCand *c);
/* Each stored artifact, for the dump. */
void tcg_cache_store_foreach(void (*fn)(void *opaque, uint64_t id,
                                        uint64_t rva, uint64_t base,
                                        const void *art, size_t len),
                             void *opaque);
/* A line describing a stored artifact, for the dump. */
int tcg_cache_dump_line(char *buf, size_t size, uint64_t id, uint64_t rva,
                        uint64_t base, const void *art, size_t len);

/*
 * Files (tcg-cache-file.c.inc).  An artifact is stored in an envelope: its
 * full key, the day it was first captured, a content identity (its key
 * and bytes, not the day) and a checksum of everything.  A segment holds
 * envelopes and an index sorted by key hash; a pack holds envelopes, an
 * open-addressed index and the list of segments it covers.  All offsets
 * are from the file's start, all fields host-order.
 */
#define TCG_CACHE_ENV_MAGIC     0x45435458      /* "XTCE" */
#define TCG_CACHE_SEG_MAGIC     0x53435458      /* "XTCS" */
#define TCG_CACHE_PACK_MAGIC    0x50435458      /* "XTCP" */
#define TCG_CACHE_FILE_VERSION  3

/* The readers' hard limits. */
#define TCG_CACHE_ART_MAX           (64 * 1024)
#define TCG_CACHE_MAX_EXT           64
#define TCG_CACHE_MAX_REL           1024
#define TCG_CACHE_MAX_ACQ           4096
#define TCG_CACHE_FILE_MAX          (512u << 20)
#define TCG_CACHE_SEG_ENTRIES_MAX   (1u << 20)
#define TCG_CACHE_SLOT_LOG2_MAX     22
#define TCG_CACHE_COVER_MAX         4096
#define TCG_CACHE_PROBES            64

/* The lazy-sync map's register byte for a constant. */
#define TCG_CACHE_LAZY_WB_CONST     0xff

typedef struct TCGCacheEnv {
    uint32_t magic;
    uint32_t len;           /* this envelope and its artifact */
    uint32_t born;          /* days since the epoch, at first capture */
    uint32_t pad;
    uint64_t id, rva, cs_base;
    uint32_t flags, cflags;
    /* XXH3_64 of the key and the artifact's XXH3_64, not born */
    uint64_t content;
    /* XXH3_64 of the header up to here and the artifact's XXH3_64 */
    uint64_t check;
} TCGCacheEnv;

typedef struct TCGCacheIdx {
    uint64_t khash;         /* the key's hash; 0: an empty pack slot */
    uint32_t off, len;      /* the envelope */
    uint32_t check;         /* rva ^ flags, folded */
    uint32_t pad;
} TCGCacheIdx;

typedef struct TCGCacheCover {
    char name[64];
    uint64_t hdr_check;     /* the segment's header checksum */
    uint64_t pad;
} TCGCacheCover;

typedef struct TCGCacheFileHdr {
    uint32_t magic;
    uint16_t version;
    uint16_t hdr_len;
    uint8_t fp[16];         /* tcg_cache_fingerprint */
    uint64_t tick;          /* a segment's publication; a pack's generation */
    uint32_t n_index;       /* entries, used slots in a pack */
    uint32_t index_off;
    uint32_t slot_log2;     /* a pack's slot table; 0 in a segment */
    uint32_t n_cover;
    uint32_t cover_off, cover_len;
    uint32_t data_off, data_len;
    uint64_t cover_check;
    uint64_t check;         /* this header, this field zero */
} TCGCacheFileHdr;

typedef struct TCGCacheFile {
    TCGCacheFileHdr hdr;    /* copied out, checked */
    const void *map;
    size_t size;
    uint64_t index_bytes;
    TCGCacheCover *cover;   /* copied out, checked */
    int level;              /* in a snapshot: TCG_CACHE_LEVEL_* */
    int64_t (*copy)(void *dst, const void *src, size_t len);
    void (*fault)(int64_t code);
} TCGCacheFile;

/* What a check found (tcg_cache_validate and the readers). */
enum {
    TCG_CACHE_V_OK,
    TCG_CACHE_V_HEADER,
    TCG_CACHE_V_LIMIT,
    TCG_CACHE_V_SPAN,
    TCG_CACHE_V_EXTENT,
    TCG_CACHE_V_REL_ORDER,
    TCG_CACHE_V_REL_FORM,
    TCG_CACHE_V_REL_SITE,
    TCG_CACHE_V_REL_CANON,
    TCG_CACHE_V_REL_TARGET,
    TCG_CACHE_V_SLOT,
    TCG_CACHE_V_CON,
    TCG_CACHE_V_UNWIND,
    TCG_CACHE_V_LAZY,
    TCG_CACHE_V_KEY,
    TCG_CACHE_V_CHECK,
    TCG_CACHE_V_FAULT,
    TCG_CACHE_V_INSN,
    TCG_CACHE_V_MAX
};

extern uint8_t tcg_cache_fingerprint[16];
/*
 * The target's check of one insn's unwind data, as its
 * restore_state_to_opc will read it; unset, no artifact validates.
 */
extern bool (*tcg_cache_insn_ok)(const uint64_t *data, bool pcrel);
/* Testing: values of the second word the target's check must refuse. */
extern const uint64_t *tcg_cache_insn_bad;
extern int tcg_cache_insn_nbad;

const char *tcg_cache_v_name(int v);
uint64_t tcg_cache_hash64(uint64_t seed, const void *data, size_t len);
/* An artifact as it may be installed: TCG_CACHE_V_OK, or why not. */
int tcg_cache_validate(const void *art, size_t len);
/* Write @art's envelope at @out (room for ROUND_UP(64 + len, 8)). */
size_t tcg_cache_envelope(void *out, uint64_t id, uint64_t rva,
                          uint32_t born, const void *art, size_t len);
/*
 * A file of the envelopes in @data (a pack if @pack), g_malloc'd; NULL if
 * the envelopes aren't back to back and bounded, or a reader would refuse
 * the file.
 */
void *tcg_cache_write_file(bool pack, uint64_t tick, const void *data,
                           size_t data_len, const TCGCacheCover *cover,
                           uint32_t n_cover, size_t *lenp);
/*
 * A segment of @data's envelopes written into @out, allocating nothing;
 * its length, or 0 (as tcg_cache_write_file's NULL, or more than @cap).
 * At most tcg_cache_segment_bound(@data_len) bytes.
 */
size_t tcg_cache_write_segment_to(void *out, size_t cap, uint64_t tick,
                                  const void *data, size_t data_len);
size_t tcg_cache_segment_bound(size_t data_len);
int tcg_cache_file_open(TCGCacheFile *f, const void *map, size_t size,
                        int64_t (*copy)(void *, const void *, size_t),
                        void (*fault)(int64_t));
void tcg_cache_file_close(TCGCacheFile *f);
/* Up to @max index entries for a key, or -1 if the index is damaged. */
int tcg_cache_file_find(const TCGCacheFile *f, uint64_t id, uint64_t rva,
                        uint32_t flags, uint64_t cs_base, uint32_t cflags,
                        TCGCacheIdx *out, int max);
/* An entry's envelope copied into @buf and checked against the key. */
int tcg_cache_file_get(const TCGCacheFile *f, const TCGCacheIdx *e,
                       uint64_t id, uint64_t rva, uint32_t flags,
                       uint64_t cs_base, uint32_t cflags, void *buf,
                       size_t buf_size, const TCGCacheEnv **envp);
void tcg_cache_nofault(int64_t code);
bool tcg_cache_segment_name_ok(const char name[64]);
bool tcg_cache_part_name_gen(const char name[64], uint64_t *genp);
/*
 * The files a process reads: the pack first, then parts newest first,
 * then loose segments newest first, the order lookups take them in, each
 * file's level recorded.  Immutable once published; @release unmaps them,
 * after a grace period.
 */
#define TCG_CACHE_SNAP_FILES 25
enum { TCG_CACHE_LEVEL_PACK, TCG_CACHE_LEVEL_PART, TCG_CACHE_LEVEL_SEG };

typedef struct TCGCacheSnap {
    struct rcu_head rcu;
    int n;
    TCGCacheFile f[TCG_CACHE_SNAP_FILES];
    void *os[TCG_CACHE_SNAP_FILES];     /* the back end's, per file */
    void (*release)(struct TCGCacheSnap *s);
} TCGCacheSnap;

/* Read with qatomic_rcu_read, under rcu_read_lock. */
extern TCGCacheSnap *tcg_cache_snap;
/* Replace the snapshot; false (and nothing done) while one waits. */
bool tcg_cache_snap_publish(TCGCacheSnap *s);
bool tcg_cache_snap_waiting(void);
void tcg_cache_snap_fork_child(void);
/* Testing: pauses in retiring a snapshot, and before a capture's lock. */
extern unsigned tcg_cache_retire_pause_ms, tcg_cache_sink_pause_ms;
/* A lookup in the snapshot found nothing: the back end may refresh it. */
extern bool tcg_cache_file_missed;
/* The day captures are born, set by the back end. */
extern uint32_t tcg_cache_born;

/* Capture buffers for the back end's writer (see tcg-cache-file.c.inc). */
#define TCG_CACHE_BUF_SIZE  (256 * 1024)
#define TCG_CACHE_BUFS      4

extern bool tcg_cache_sink_on;
/* Called (outside the sink's lock) when a buffer is queued. */
extern void (*tcg_cache_sink_wake)(void);
void tcg_cache_sink_init(void);
void tcg_cache_sink_put(uint64_t id, uint64_t rva, uint32_t born,
                        const void *art, size_t len, int64_t now);
void *tcg_cache_sink_take(int64_t now, int64_t age_ns, bool force,
                          bool trylock, size_t *lenp);
void tcg_cache_sink_give(void *data);
void tcg_cache_sink_hold(unsigned ms);
int tcg_cache_sink_close(void **data, size_t *lens);
void tcg_cache_sink_fork_start(void);
void tcg_cache_sink_fork_end(bool child);

/*
 * The directory back end (tcg-cache-dir.c.inc): the writer thread, the
 * snapshots, the exit's publication and fork, over the OS's files.  The
 * OS checks the directory before start, and each file as it opens it.
 */
typedef void TCGCacheDirEntryFn(void *opaque, const char *name,
                                uint64_t size, int64_t mtime);

typedef struct TCGCacheDirOps {
    /*
     * Each of the first @max entries whose name fits 64 bytes with its
     * NUL, to @fn with its size and modification time (seconds since the
     * epoch); the number of entries seen (@max: perhaps not all), or -1
     * if the listing failed part way.
     */
    int (*list)(TCGCacheDirEntryFn *fn, void *opaque, int max);
    /* @name opened to read: ours and checked, else NULL; its size. */
    void *(*open)(const char *name, size_t *sizep);
    /* A checked read at @off: 0, or TCG_CACHE_GFAULT if short. */
    int64_t (*read)(void *fh, void *dst, uint64_t off, size_t len);
    /* An open file mapped read-only, or NULL. */
    const void *(*map)(void *fh, size_t size);
    void (*close)(void *fh);
    void (*unmap)(const void *map, size_t size);
    /*
     * @len bytes published as @name, never replacing a file: written to
     * a temporary, then renamed.  It allocates nothing and takes no lock
     * (the exit's publication calls it).  Testing: @pause_ms with the
     * temporary open.
     */
    bool (*publish)(const void *data, size_t len, const char *name,
                    unsigned pause_ms);
    /*
     * The same in parts: a temporary created, written at offsets, then
     * published as @name (never replacing) or dropped; either closes it.
     */
    void *(*create)(void);
    bool (*write)(void *wh, const void *data, size_t len, uint64_t off);
    bool (*commit)(void *wh, const char *name);
    void (*drop)(void *wh);
    /* @name deleted, POSIX semantics where there is a choice. */
    bool (*remove)(const char *name);
    /* The directory's compaction lock, if free at once; released. */
    void *(*trylock)(void);
    void (*unlock)(void *lh);
    unsigned pid;
} TCGCacheDirOps;

/* Map the first snapshot and start the writer; @t0 when start-up began. */
void tcg_cache_dir_start(const TCGCacheDirOps *ops, int64_t t0);
/*
 * The process is ending and only this thread will run guest code: the
 * writer is stopped after its round, and what the sink holds published.
 */
void tcg_cache_dir_quiesce(void);
/* A clean exit: captures stop, and what is left is published, at best. */
void tcg_cache_dir_exit(void);
void tcg_cache_dir_fork_start(void);
void tcg_cache_dir_fork_end(bool child);

/*
 * The distinct, validated candidates for a key, each passed to @use until
 * it returns true; why others were refused counted in @rejects.
 */
int tcg_cache_file_select(const TCGCacheFile *f, uint64_t id, uint64_t rva,
                          uint32_t flags, uint64_t cs_base, uint32_t cflags,
                          void *buf, size_t bufsz,
                          bool (*use)(const TCGCacheEnv *env, void *opaque),
                          void *opaque, uint64_t *rejects);
int tcg_cache_snap_select(const TCGCacheSnap *snap, uint64_t id, uint64_t rva,
                          uint32_t flags, uint64_t cs_base, uint32_t cflags,
                          void *buf, size_t bufsz,
                          bool (*use)(const TCGCacheEnv *env, void *opaque),
                          void *opaque, uint64_t *rejects);
/* Testing (XTCG_CACHE_LOAD): a file lookups read before the store. */
extern TCGCacheFile tcg_cache_loaded;
extern bool tcg_cache_have_loaded;
/*
 * Testing (XTCG_CACHE_SAVE): the store's envelopes, an owned copy for
 * tcg_cache_write_file; @born the day.  Called with mmap_lock held.
 */
void *tcg_cache_store_envelopes(uint32_t born, size_t *lenp);
/* Testing: validate every artifact of a file; damage it every way. */
/* @e's index entry for envelope @e at @off. */
TCGCacheIdx tcg_cache_env_idx(const TCGCacheEnv *e, uint32_t off);
/*
 * An envelope copied out (@len bytes) checked as tcg_cache_file_get
 * checks one, and its artifact validated: 0, or why not.
 */
int tcg_cache_env_verify(const TCGCacheEnv *env, size_t len);
/*
 * A pack written in parts: @h laid out for @n envelopes of @data_len
 * bytes and @n_cover covered segments, its slot table at least
 * 2^@min_log2 (its length, or 0 past a reader's limits); each envelope's
 * entry put in the slot table within @probes of its home, as a reader
 * looks for it (false if it can't be); then the header sealed over the
 * cover list.
 */
size_t tcg_cache_pack_layout(TCGCacheFileHdr *h, uint64_t generation,
                             uint32_t n, uint32_t n_cover, size_t data_len,
                             uint32_t min_log2);
bool tcg_cache_pack_slot(TCGCacheIdx *slots, uint32_t slot_log2,
                         TCGCacheIdx x, unsigned probes);
void tcg_cache_pack_seal(TCGCacheFileHdr *h, const TCGCacheCover *cover);
int tcg_cache_check_file(const void *map, size_t size, bool quiet,
                         uint64_t *counts);
int tcg_cache_fuzz_file(const void *map, size_t size, uint64_t seed,
                        unsigned arts);

/*
 * Why an eligible lookup translated: no file candidate, or the last one
 * tried failed (tcg_cache_w_names).
 */
enum {
    TCG_CACHE_W_NONE,
    TCG_CACHE_W_HELPER,     /* a relocation to QEMU's image didn't fit */
    TCG_CACHE_W_STUB,       /* ... to a start-up stub */
    TCG_CACHE_W_THUNK,      /* ... to the chunk's slow-path thunk */
    TCG_CACHE_W_RELOC,      /* any other relocation or constraint */
    TCG_CACHE_W_KEYPC,      /* captured at another guest address */
    TCG_CACHE_W_KEY,        /* other key fields, or the page split */
    TCG_CACHE_W_OTHER,      /* guest bytes, promotion, eligibility, ... */
    TCG_CACHE_W_MAX
};

/* Why tcg_cache_place last returned NULL: the relocation's kind and form. */
extern unsigned tcg_cache_fail_kind, tcg_cache_fail_form;

/* Counters, printed at exit with XTCG_CACHE_STATS. */
typedef struct TCGCacheStats {
    uint64_t tried, captured, bytes, excluded[TCG_CACHE_X_MAX];
    uint64_t installs, inst_fail_reserve, inst_fail_reloc, inst_fail_bytes;
    uint64_t inst_fail_con, inst_fail_promoted, inst_fail_key, inst_dup;
    uint64_t rel_kind[TCG_CAP_UNSUPPORTED + 1], rel_form[TCG_CAPF_MAX];
    uint64_t hot_bytes, cold_bytes, search_bytes, ext_total;
    uint64_t capture_ns, install_ns;
    /* TCG_CACHE_ON */
    uint64_t translations, inel_capture, stored, store_dup, store_full;
    uint64_t store_bytes, lookups, look_inel, look_none, hits;
    uint64_t miss_base, miss_struct, miss_region, miss_inel, miss_fault;
    uint64_t flushes, inj_promote, copies, checks, guard_lost;
    /* XTCG_CACHE_LOAD */
    uint64_t file_lookups, file_hits, file_reject[TCG_CACHE_V_MAX];
    uint64_t sink_put, sink_dropped, published, publish_fail, publish_ns;
    uint64_t snaps, snap_skipped, snap_files, startup_ns, refresh_ns;
    uint64_t snap_refused, scan_trunc, map_budget, publish_budget;
    uint64_t publish_blind;
    uint64_t compactions, compact_fail, compact_busy, compact_ns;
    uint64_t compact_in, compact_arts, compact_kept, compact_aged;
    uint64_t compact_damaged, compact_bytes, removed, remove_fail;
    uint64_t compact_dups, compact_skip, compact_regrow;
    uint64_t compact_exit, compact_collide;
    /* Merges by kind: minor, parts, major, first (tcg-cache-dir.c.inc). */
    uint64_t merge_done[4], merge_fail[4], merge_exit[4];
    uint64_t merge_est_ns[4], merge_act_ns[4], merge_age_ns[4];
    uint64_t merge_in_bytes[4], merge_emergency, merge_saturated;
    uint64_t merge_tmp_bytes, parts_overflow;
    uint64_t parts_live, parts_unresolved, parts_covered, scan_loose;
    uint64_t merge_entries[4], scan_mem_max, merge_deferred;
    uint64_t look_ns, copy_ns, check_ns, hit_ns;
    /* A file lookup's parts, and an install's (XTCG_CACHE_COSTS). */
    uint64_t sel_finds, sel_find_ns, sel_gets, sel_get_bytes, sel_get_ns;
    uint64_t sel_dup_ns, sel_vals, sel_val_ns;
    uint64_t inst_prep_ns, inst_res_ns, inst_place_ns, inst_flush_ns;
    uint64_t inst_link_ns, publish_bytes, sel_dups;
    /* Files' candidates that didn't install: why, and what it cost. */
    uint64_t inst_fail_rk[TCG_CAP_UNSUPPORTED + 1];
    uint64_t inst_fail_rf[TCG_CAPF_MAX], inst_fail_kpc;
    uint64_t file_fail, file_fail_ns;
    uint64_t gen[TCG_CACHE_W_MAX], gen_ns[TCG_CACHE_W_MAX];
} TCGCacheStats;

extern TCGCacheStats tcg_cache_stats;
void tcg_cache_print_stats(void);

#endif
