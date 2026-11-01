/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QEMU float support: vector fast paths
 *
 * Each *_vec function computes n lanes of a softfloat scalar function with
 * host floating point, but only when every lane would take the hardfloat
 * path of the scalar function (or, for comparisons and conversions, which
 * have none, when the host operation provably gives the scalar function's
 * result and raises no flag).  The results and exception flags are then
 * exactly those of the scalar function applied lane by lane, and the
 * function returns true.  Otherwise it returns false, having written and
 * raised nothing, and the caller applies the scalar function lane by lane.
 *
 * The lanes are processed 16 bytes at a time with the compiler's generic
 * vector types.  n must be a compile-time constant that fills whole 16-byte
 * chunks, at most four, so that the functions, which are inline, keep every
 * chunk in registers.  All lanes are checked before any result is stored,
 * so the result may overlap the operands.
 */

#ifndef SOFTFLOAT_VEC_H
#define SOFTFLOAT_VEC_H

#include "fpu/softfloat.h"

/*
 * Hardfloat relies on the inexact flag being already set, and on round to
 * nearest even, which is what the host uses.  -ffast-math breaks the exact
 * IEEE behaviour it needs.
 */
static inline bool float_inexact_set(const float_status *s)
{
#if defined(__FAST_MATH__)
    return false;
#else
    return s->float_exception_flags & float_flag_inexact;
#endif
}

static inline bool float_hardfloat_ok(const float_status *s)
{
    return likely(float_inexact_set(s) &&
                  get_float_rounding_mode(s) == float_round_nearest_even);
}

/* Set at startup if the host's fma() is broken. */
extern bool float_force_soft_fma;

typedef uint32_t FloatVecU32 __attribute__((vector_size(16)));
typedef int32_t FloatVecS32 __attribute__((vector_size(16)));
typedef float FloatVecF32 __attribute__((vector_size(16)));
typedef uint64_t FloatVecU64 __attribute__((vector_size(16)));
typedef double FloatVecF64 __attribute__((vector_size(16)));

#define FLOAT_VEC_MAX_CHUNKS 4

/* Each returns all-ones lanes where the property holds. */
static inline FloatVecU32 fv32_not_zon(FloatVecU32 x)
{
    FloatVecU32 e = x & 0x7f800000;

    return (FloatVecU32)((e == 0x7f800000) |
                         ((e == 0) & ((x & 0x007fffff) != 0)));
}

static inline FloatVecU32 fv32_not_normal(FloatVecU32 x)
{
    FloatVecU32 e = x & 0x7f800000;

    return (FloatVecU32)((e == 0x7f800000) | (e == 0));
}

static inline FloatVecU32 fv32_zero(FloatVecU32 x)
{
    return (FloatVecU32)((x & 0x7fffffff) == 0);
}

static inline FloatVecU32 fv32_inf(FloatVecU32 x)
{
    return (FloatVecU32)((x & 0x7fffffff) == 0x7f800000);
}

/* fabsf(x) <= FLT_MIN */
static inline FloatVecU32 fv32_tiny(FloatVecU32 x)
{
    return (FloatVecU32)((x & 0x7fffffff) <= 0x00800000);
}

static inline FloatVecU64 fv64_not_zon(FloatVecU64 x)
{
    FloatVecU64 e = x & 0x7ff0000000000000ULL;

    return (FloatVecU64)((e == 0x7ff0000000000000ULL) |
                         ((e == 0) & ((x & 0x000fffffffffffffULL) != 0)));
}

static inline FloatVecU64 fv64_not_normal(FloatVecU64 x)
{
    FloatVecU64 e = x & 0x7ff0000000000000ULL;

    return (FloatVecU64)((e == 0x7ff0000000000000ULL) | (e == 0));
}

static inline FloatVecU64 fv64_zero(FloatVecU64 x)
{
    return (FloatVecU64)((x & 0x7fffffffffffffffULL) == 0);
}

static inline FloatVecU64 fv64_inf(FloatVecU64 x)
{
    return (FloatVecU64)((x & 0x7fffffffffffffffULL) ==
                         0x7ff0000000000000ULL);
}

/* fabs(x) <= DBL_MIN */
static inline FloatVecU64 fv64_tiny(FloatVecU64 x)
{
    return (FloatVecU64)((x & 0x7fffffffffffffffULL) <=
                         0x0010000000000000ULL);
}

static inline bool fv32_any(FloatVecU32 x)
{
    return (x[0] | x[1] | x[2] | x[3]) != 0;
}

static inline bool fv64_any(FloatVecU64 x)
{
    return (x[0] | x[1]) != 0;
}

static inline FloatVecU32 fv32_load(const void *p, unsigned i)
{
    FloatVecU32 v;

    memcpy(&v, (const char *)p + 16 * i, 16);
    return v;
}

static inline FloatVecU64 fv64_load(const void *p, unsigned i)
{
    FloatVecU64 v;

    memcpy(&v, (const char *)p + 16 * i, 16);
    return v;
}

static inline void fv_store(void *p, unsigned i, const void *v)
{
    memcpy((char *)p + 16 * i, v, 16);
}

typedef enum {
    FLOAT_VEC_ADD,
    FLOAT_VEC_SUB,
    FLOAT_VEC_MUL,
    FLOAT_VEC_DIV,
} FloatVecOp;

/*
 * Binary arithmetic, as float32_gen2: the inputs must pass the scalar
 * function's pre-check, and a tiny result stays on the fast path only where
 * its post-check would keep it there (add/sub/mul: both inputs zero; div:
 * dividend zero).  An infinite result, for which hardfloat raises overflow
 * itself, goes to the scalar path.
 */
static inline bool float32_binop_vec(float32 *r, const float32 *a,
                                     const float32 *b, unsigned n,
                                     float_status *s, FloatVecOp op)
{
    FloatVecU32 res[FLOAT_VEC_MAX_CHUNKS];
    FloatVecU32 bad = { 0 };
    unsigned i, c = n / 4;

    if (!float_hardfloat_ok(s)) {
        return false;
    }
    for (i = 0; i < c; i++) {
        FloatVecU32 ua = fv32_load(a, i), ub = fv32_load(b, i), tiny_ok;
        FloatVecF32 fa = (FloatVecF32)ua, fb = (FloatVecF32)ub, fr;

        bad |= fv32_not_zon(ua) |
               (op == FLOAT_VEC_DIV ? fv32_not_normal(ub) : fv32_not_zon(ub));
        switch (op) {
        case FLOAT_VEC_ADD:
            fr = fa + fb;
            break;
        case FLOAT_VEC_SUB:
            fr = fa - fb;
            break;
        case FLOAT_VEC_MUL:
            fr = fa * fb;
            break;
        default:
            fr = fa / fb;
            break;
        }
        res[i] = (FloatVecU32)fr;
        tiny_ok = op == FLOAT_VEC_DIV ? fv32_zero(ua)
                                      : fv32_zero(ua) & fv32_zero(ub);
        bad |= fv32_inf(res[i]) | (fv32_tiny(res[i]) & ~tiny_ok);
    }
    if (fv32_any(bad)) {
        return false;
    }
    for (i = 0; i < c; i++) {
        fv_store(r, i, &res[i]);
    }
    return true;
}

static inline bool float64_binop_vec(float64 *r, const float64 *a,
                                     const float64 *b, unsigned n,
                                     float_status *s, FloatVecOp op)
{
    FloatVecU64 res[FLOAT_VEC_MAX_CHUNKS];
    FloatVecU64 bad = { 0 };
    unsigned i, c = n / 2;

    if (!float_hardfloat_ok(s)) {
        return false;
    }
    for (i = 0; i < c; i++) {
        FloatVecU64 ua = fv64_load(a, i), ub = fv64_load(b, i), tiny_ok;
        FloatVecF64 fa = (FloatVecF64)ua, fb = (FloatVecF64)ub, fr;

        bad |= fv64_not_zon(ua) |
               (op == FLOAT_VEC_DIV ? fv64_not_normal(ub) : fv64_not_zon(ub));
        switch (op) {
        case FLOAT_VEC_ADD:
            fr = fa + fb;
            break;
        case FLOAT_VEC_SUB:
            fr = fa - fb;
            break;
        case FLOAT_VEC_MUL:
            fr = fa * fb;
            break;
        default:
            fr = fa / fb;
            break;
        }
        res[i] = (FloatVecU64)fr;
        tiny_ok = op == FLOAT_VEC_DIV ? fv64_zero(ua)
                                      : fv64_zero(ua) & fv64_zero(ub);
        bad |= fv64_inf(res[i]) | (fv64_tiny(res[i]) & ~tiny_ok);
    }
    if (fv64_any(bad)) {
        return false;
    }
    for (i = 0; i < c; i++) {
        fv_store(r, i, &res[i]);
    }
    return true;
}

/*
 * Fused multiply-add, as float32_muladd.  A lane whose product is zero is
 * exact and needs no result check; otherwise an infinite or tiny result goes
 * to the scalar path.  Negating the product (through a), the addend and the
 * result are exact.
 */
static inline bool float_muladd_vec_ok(int flags, float_status *s)
{
    return float_hardfloat_ok(s) && !float_force_soft_fma &&
           !(flags & ~(float_muladd_negate_c | float_muladd_negate_product |
                       float_muladd_negate_result));
}

static inline bool float32_muladd_vec(float32 *r, const float32 *a,
                                      const float32 *b, const float32 *c,
                                      unsigned n, int flags, float_status *s)
{
    uint32_t neg_a = flags & float_muladd_negate_product ? 0x80000000U : 0;
    uint32_t neg_c = flags & float_muladd_negate_c ? 0x80000000U : 0;
    uint32_t neg_r = flags & float_muladd_negate_result ? 0x80000000U : 0;
    FloatVecU32 res[FLOAT_VEC_MAX_CHUNKS];
    FloatVecU32 bad = { 0 };
    unsigned i, j, k = n / 4;

    if (!float_muladd_vec_ok(flags, s)) {
        return false;
    }
    for (i = 0; i < k; i++) {
        FloatVecU32 ua = fv32_load(a, i), ub = fv32_load(b, i);
        FloatVecU32 uc = fv32_load(c, i);
        FloatVecF32 fa = (FloatVecF32)(ua ^ neg_a), fb = (FloatVecF32)ub;
        FloatVecF32 fc = (FloatVecF32)(uc ^ neg_c), fr;

        bad |= fv32_not_zon(ua) | fv32_not_zon(ub) | fv32_not_zon(uc);
        for (j = 0; j < 4; j++) {
            fr[j] = fmaf(fa[j], fb[j], fc[j]);
        }
        res[i] = (FloatVecU32)fr;
        bad |= ~(fv32_zero(ua) | fv32_zero(ub)) &
               (fv32_inf(res[i]) | fv32_tiny(res[i]));
        res[i] ^= neg_r;
    }
    if (fv32_any(bad)) {
        return false;
    }
    for (i = 0; i < k; i++) {
        fv_store(r, i, &res[i]);
    }
    return true;
}

static inline bool float64_muladd_vec(float64 *r, const float64 *a,
                                      const float64 *b, const float64 *c,
                                      unsigned n, int flags, float_status *s)
{
    uint64_t neg_a = flags & float_muladd_negate_product ? INT64_MIN : 0;
    uint64_t neg_c = flags & float_muladd_negate_c ? INT64_MIN : 0;
    uint64_t neg_r = flags & float_muladd_negate_result ? INT64_MIN : 0;
    FloatVecU64 res[FLOAT_VEC_MAX_CHUNKS];
    FloatVecU64 bad = { 0 };
    unsigned i, j, k = n / 2;

    if (!float_muladd_vec_ok(flags, s)) {
        return false;
    }
    for (i = 0; i < k; i++) {
        FloatVecU64 ua = fv64_load(a, i), ub = fv64_load(b, i);
        FloatVecU64 uc = fv64_load(c, i);
        FloatVecF64 fa = (FloatVecF64)(ua ^ neg_a), fb = (FloatVecF64)ub;
        FloatVecF64 fc = (FloatVecF64)(uc ^ neg_c), fr;

        bad |= fv64_not_zon(ua) | fv64_not_zon(ub) | fv64_not_zon(uc);
        for (j = 0; j < 2; j++) {
            fr[j] = fma(fa[j], fb[j], fc[j]);
        }
        res[i] = (FloatVecU64)fr;
        bad |= ~(fv64_zero(ua) | fv64_zero(ub)) &
               (fv64_inf(res[i]) | fv64_tiny(res[i]));
        res[i] ^= neg_r;
    }
    if (fv64_any(bad)) {
        return false;
    }
    for (i = 0; i < k; i++) {
        fv_store(r, i, &res[i]);
    }
    return true;
}

/* Square root, as float32_sqrt: zero or normal, and not negative (not -0). */
static inline bool float32_sqrt_vec(float32 *r, const float32 *a, unsigned n,
                                    float_status *s)
{
    FloatVecU32 res[FLOAT_VEC_MAX_CHUNKS];
    FloatVecU32 bad = { 0 };
    unsigned i, j, c = n / 4;

    if (!float_hardfloat_ok(s)) {
        return false;
    }
    for (i = 0; i < c; i++) {
        FloatVecU32 ua = fv32_load(a, i);
        FloatVecF32 f = (FloatVecF32)ua;

        bad |= fv32_not_zon(ua) | (ua >> 31);
        for (j = 0; j < 4; j++) {
            f[j] = sqrtf(f[j]);
        }
        res[i] = (FloatVecU32)f;
    }
    if (fv32_any(bad)) {
        return false;
    }
    for (i = 0; i < c; i++) {
        fv_store(r, i, &res[i]);
    }
    return true;
}

static inline bool float64_sqrt_vec(float64 *r, const float64 *a, unsigned n,
                                    float_status *s)
{
    FloatVecU64 res[FLOAT_VEC_MAX_CHUNKS];
    FloatVecU64 bad = { 0 };
    unsigned i, j, c = n / 2;

    if (!float_hardfloat_ok(s)) {
        return false;
    }
    for (i = 0; i < c; i++) {
        FloatVecU64 ua = fv64_load(a, i);
        FloatVecF64 f = (FloatVecF64)ua;

        bad |= fv64_not_zon(ua) | (ua >> 63);
        for (j = 0; j < 2; j++) {
            f[j] = sqrt(f[j]);
        }
        res[i] = (FloatVecU64)f;
    }
    if (fv64_any(bad)) {
        return false;
    }
    for (i = 0; i < c; i++) {
        fv_store(r, i, &res[i]);
    }
    return true;
}

/*
 * Comparisons, as float32_compare and float32_compare_quiet: with no NaN
 * and no denormal input, neither raises a flag, and the host's ordering
 * (where -0 == +0) is IEEE's.
 *
 * float32_select_vec: r = a < b ? a : b (lt), or r = a > b ? a : b (!lt).
 * float32_compare_vec: all-ones masks where a < b (lt) and a == b (eq).
 */
static inline bool float32_select_vec(float32 *r, const float32 *a,
                                      const float32 *b, unsigned n, bool lt,
                                      float_status *s)
{
    FloatVecU32 res[FLOAT_VEC_MAX_CHUNKS];
    FloatVecU32 bad = { 0 };
    unsigned i, c = n / 4;

    for (i = 0; i < c; i++) {
        FloatVecU32 ua = fv32_load(a, i), ub = fv32_load(b, i), m;

        bad |= fv32_not_zon(ua) | fv32_not_zon(ub);
        m = lt ? (FloatVecU32)((FloatVecF32)ua < (FloatVecF32)ub)
               : (FloatVecU32)((FloatVecF32)ua > (FloatVecF32)ub);
        res[i] = (ua & m) | (ub & ~m);
    }
    if (fv32_any(bad)) {
        return false;
    }
    for (i = 0; i < c; i++) {
        fv_store(r, i, &res[i]);
    }
    return true;
}

static inline bool float64_select_vec(float64 *r, const float64 *a,
                                      const float64 *b, unsigned n, bool lt,
                                      float_status *s)
{
    FloatVecU64 res[FLOAT_VEC_MAX_CHUNKS];
    FloatVecU64 bad = { 0 };
    unsigned i, c = n / 2;

    for (i = 0; i < c; i++) {
        FloatVecU64 ua = fv64_load(a, i), ub = fv64_load(b, i), m;

        bad |= fv64_not_zon(ua) | fv64_not_zon(ub);
        m = lt ? (FloatVecU64)((FloatVecF64)ua < (FloatVecF64)ub)
               : (FloatVecU64)((FloatVecF64)ua > (FloatVecF64)ub);
        res[i] = (ua & m) | (ub & ~m);
    }
    if (fv64_any(bad)) {
        return false;
    }
    for (i = 0; i < c; i++) {
        fv_store(r, i, &res[i]);
    }
    return true;
}

static inline bool float32_compare_vec(uint32_t *lt, uint32_t *eq,
                                       const float32 *a, const float32 *b,
                                       unsigned n, float_status *s)
{
    FloatVecU32 rlt[FLOAT_VEC_MAX_CHUNKS], req[FLOAT_VEC_MAX_CHUNKS];
    FloatVecU32 bad = { 0 };
    unsigned i, c = n / 4;

    for (i = 0; i < c; i++) {
        FloatVecU32 ua = fv32_load(a, i), ub = fv32_load(b, i);

        bad |= fv32_not_zon(ua) | fv32_not_zon(ub);
        rlt[i] = (FloatVecU32)((FloatVecF32)ua < (FloatVecF32)ub);
        req[i] = (FloatVecU32)((FloatVecF32)ua == (FloatVecF32)ub);
    }
    if (fv32_any(bad)) {
        return false;
    }
    for (i = 0; i < c; i++) {
        fv_store(lt, i, &rlt[i]);
        fv_store(eq, i, &req[i]);
    }
    return true;
}

static inline bool float64_compare_vec(uint64_t *lt, uint64_t *eq,
                                       const float64 *a, const float64 *b,
                                       unsigned n, float_status *s)
{
    FloatVecU64 rlt[FLOAT_VEC_MAX_CHUNKS], req[FLOAT_VEC_MAX_CHUNKS];
    FloatVecU64 bad = { 0 };
    unsigned i, c = n / 2;

    for (i = 0; i < c; i++) {
        FloatVecU64 ua = fv64_load(a, i), ub = fv64_load(b, i);

        bad |= fv64_not_zon(ua) | fv64_not_zon(ub);
        rlt[i] = (FloatVecU64)((FloatVecF64)ua < (FloatVecF64)ub);
        req[i] = (FloatVecU64)((FloatVecF64)ua == (FloatVecF64)ub);
    }
    if (fv64_any(bad)) {
        return false;
    }
    for (i = 0; i < c; i++) {
        fv_store(lt, i, &rlt[i]);
        fv_store(eq, i, &req[i]);
    }
    return true;
}

/*
 * int32 to float32 is exact, raising nothing, when |a| <= 2^24; otherwise it
 * can be inexact, which needs hardfloat's conditions (inexact already set,
 * round to nearest even).
 */
static inline bool int32_to_float32_vec(float32 *r, const int32_t *a,
                                        unsigned n, float_status *s)
{
    FloatVecU32 res[FLOAT_VEC_MAX_CHUNKS];
    FloatVecU32 big = { 0 };
    unsigned i, c = n / 4;

    for (i = 0; i < c; i++) {
        FloatVecU32 ux = fv32_load(a, i);

        big |= (FloatVecU32)(ux + (1u << 24) > (2u << 24));
        res[i] = (FloatVecU32)__builtin_convertvector((FloatVecS32)ux,
                                                      FloatVecF32);
    }
    if (fv32_any(big) && !float_hardfloat_ok(s)) {
        return false;
    }
    for (i = 0; i < c; i++) {
        fv_store(r, i, &res[i]);
    }
    return true;
}

/*
 * float32 to int32, rounding as the status says (with hardfloat's
 * conditions: round to nearest even, inexact already set) or toward zero
 * (inexact already set).  A zero or normal input in [-2^31, 2^31 - 128]
 * (2^31 - 128 is the largest float32 below 2^31) can't overflow, so invalid
 * isn't raised; inexact, the only other possible flag, is already set.  The
 * host's rintf rounds to nearest even, as hardfloat assumes of the host.
 */
static inline bool float32_to_int32_vec_common(int32_t *r, const float32 *a,
                                               unsigned n, float_status *s,
                                               bool rtz)
{
    FloatVecS32 res[FLOAT_VEC_MAX_CHUNKS];
    FloatVecU32 bad = { 0 };
    unsigned i, j, c = n / 4;

    if (rtz ? !float_inexact_set(s) : !float_hardfloat_ok(s)) {
        return false;
    }
    for (i = 0; i < c; i++) {
        FloatVecU32 ua = fv32_load(a, i);
        FloatVecF32 f = (FloatVecF32)ua;

        bad |= fv32_not_zon(ua) | (FloatVecU32)(f < -2147483648.0f) |
               (FloatVecU32)(f > 2147483520.0f);
        if (!rtz) {
            for (j = 0; j < 4; j++) {
                f[j] = rintf(f[j]);
            }
        }
        res[i] = __builtin_convertvector(f, FloatVecS32);
    }
    if (fv32_any(bad)) {
        return false;
    }
    for (i = 0; i < c; i++) {
        fv_store(r, i, &res[i]);
    }
    return true;
}

static inline bool float32_to_int32_vec(int32_t *r, const float32 *a,
                                        unsigned n, float_status *s)
{
    return float32_to_int32_vec_common(r, a, n, s, false);
}

static inline bool float32_to_int32_round_to_zero_vec(int32_t *r,
                                                      const float32 *a,
                                                      unsigned n,
                                                      float_status *s)
{
    return float32_to_int32_vec_common(r, a, n, s, true);
}

#endif /* SOFTFLOAT_VEC_H */
