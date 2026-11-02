/*
 * The C library functions the engine calls that ntdll doesn't export
 * (ntdll-crt.def lists the ones it does) and mingw-w64's static library
 * doesn't provide: the standard streams, the environment, the time, and
 * the file calls, which fail (the module opens no files).
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <winternl.h>
#include <locale.h>
#include <wchar.h>
#include "qemu/atomic.h"
#include "qemu/ctype.h"
#include "user/host-mman.h"
#include "qemu/sockets.h"
#include "runtime.h"

/* The C library's close, which os-win32.h's qemu_close_wrap calls. */
#undef close

/*
 * The standard streams: three sentinels whose writes go to the process's
 * standard handles (StandardInput, StandardOutput and StandardError, at
 * 0x20, 0x28 and 0x30 of the 64-bit RTL_USER_PROCESS_PARAMETERS).  Other
 * streams don't exist.
 */
static char std_streams[3][16];

static void *std_handle(FILE *f)
{
    RTL_USER_PROCESS_PARAMETERS *pp =
        NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters;

    for (int i = 0; i < 3; i++) {
        if ((char *)f == std_streams[i]) {
            return *(HANDLE *)((char *)pp + 0x20 + 8 * i);
        }
    }
    return NULL;
}

static size_t std_write(FILE *f, const void *p, size_t n)
{
    HANDLE h = std_handle(f);
    IO_STATUS_BLOCK io;

    if (!h || NtWriteFile(h, NULL, NULL, NULL, &io, (PVOID)p, n, NULL,
                          NULL) < 0) {
        return 0;
    }
    return n;
}

void xt_stderr_write(const void *p, size_t n)
{
    std_write((FILE *)std_streams[2], p, n);
}

G_NORETURN void xt_fatal(const char *what)
{
    xt_stderr_write("libwow64xtcg: ", 14);
    xt_stderr_write(what, strlen(what));
    xt_stderr_write("\n", 1);
    NtTerminateProcess((HANDLE)-1, 0xE1000004);
    __builtin_trap();
}

FILE *__cdecl __acrt_iob_func(unsigned index)
{
    return index < 3 ? (FILE *)std_streams[index] : NULL;
}

size_t __cdecl fwrite(const void *p, size_t size, size_t count, FILE *f)
{
    return size ? std_write(f, p, size * count) / size : 0;
}

int __cdecl fputc(int c, FILE *f)
{
    unsigned char ch = c;

    return std_write(f, &ch, 1) ? ch : EOF;
}

int __cdecl putc(int c, FILE *f)
{
    return fputc(c, f);
}

int __cdecl putchar(int c)
{
    return fputc(c, stdout);
}

int __cdecl fputs(const char *s, FILE *f)
{
    size_t n = strlen(s);

    return std_write(f, s, n) == n ? 0 : EOF;
}

int __cdecl puts(const char *s)
{
    return fputs(s, stdout) == EOF || fputc('\n', stdout) == EOF ? EOF : 0;
}

int __cdecl fflush(FILE *f)
{
    return 0;
}

int __cdecl vfprintf(FILE *f, const char *fmt, va_list ap)
{
    char buf[1024];
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);

    if (n > 0) {
        std_write(f, buf, MIN(n, (int)sizeof(buf) - 1));
    }
    return n;
}

int __cdecl fprintf(FILE *f, const char *fmt, ...)
{
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vfprintf(f, fmt, ap);
    va_end(ap);
    return n;
}

int __cdecl printf(const char *fmt, ...)
{
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vfprintf(stdout, fmt, ap);
    va_end(ap);
    return n;
}

/*
 * mingw-w64's printf family locks the stream, and takes the lock again in
 * calls it makes while holding it: one recursive lock for all streams.
 */
static SRWLOCK file_lock = SRWLOCK_INIT;
static DWORD file_lock_owner;
static int file_lock_depth;

void __cdecl _lock_file(FILE *f)
{
    DWORD me = GetCurrentThreadId();

    if (qatomic_read(&file_lock_owner) != me) {
        AcquireSRWLockExclusive(&file_lock);
        qatomic_set(&file_lock_owner, me);
    }
    file_lock_depth++;
}

void __cdecl _unlock_file(FILE *f)
{
    if (--file_lock_depth == 0) {
        qatomic_set(&file_lock_owner, 0);
        ReleaseSRWLockExclusive(&file_lock);
    }
}

/* Files: the module opens none. */

FILE *__cdecl fopen(const char *path, const char *mode)
{
    errno = ENOENT;
    return NULL;
}

int __cdecl fclose(FILE *f)
{
    return EOF;
}

char *__cdecl fgets(char *s, int n, FILE *f)
{
    return NULL;
}

int __cdecl getc(FILE *f)
{
    return EOF;
}

int __cdecl ungetc(int c, FILE *f)
{
    return EOF;
}

int __cdecl ferror(FILE *f)
{
    return 1;
}

int __cdecl open(const char *path, int flags, ...)
{
    errno = ENOENT;
    return -1;
}

int __cdecl close(int fd)
{
    errno = EBADF;
    return -1;
}

int __cdecl read(int fd, void *buf, unsigned int n)
{
    errno = EBADF;
    return -1;
}

int __cdecl write(int fd, const void *buf, unsigned int n)
{
    if (fd == 1 || fd == 2) {
        return std_write((FILE *)std_streams[fd], buf, n);
    }
    errno = EBADF;
    return -1;
}

int __cdecl unlink(const char *path)
{
    errno = ENOENT;
    return -1;
}

int __cdecl access(const char *path, int mode)
{
    errno = ENOENT;
    return -1;
}

/* File descriptors and Windows handles: the standard handles only. */
intptr_t __cdecl _get_osfhandle(int fd)
{
    if (fd >= 0 && fd < 3) {
        return (intptr_t)std_handle((FILE *)std_streams[fd]);
    }
    errno = EBADF;
    return (intptr_t)INVALID_HANDLE_VALUE;
}

int __cdecl _open_osfhandle(intptr_t h, int flags)
{
    errno = EMFILE;
    return -1;
}

int __cdecl _commit(int fd)
{
    errno = EBADF;
    return -1;
}

/* cpu_memory_rw_debug's /proc/self/mem path, for debuggers: none. */
ssize_t pread(int fd, void *buf, size_t n, off_t off)
{
    errno = ENOSYS;
    return -1;
}

ssize_t pwrite(int fd, const void *buf, size_t n, off_t off)
{
    errno = ENOSYS;
    return -1;
}

/*
 * util/oslib-win32.c's close() asks this first.  The module has no
 * sockets: util/qemu-sockets.c's would bring the socket library's calls.
 */
bool fd_is_socket(int fd)
{
    return false;
}

/*
 * The environment, from the process's: each variable read once, its value
 * kept for the life of the process, as getenv's result must stay valid.
 */
static GHashTable *env_cache;
static SRWLOCK env_lock = SRWLOCK_INIT;

static char *env_read(const char *name)
{
    WCHAR wname[256], wval[1024];
    SIZE_T len = 0;
    char *val;
    size_t i;

    for (i = 0; name[i] && i < G_N_ELEMENTS(wname) - 1; i++) {
        wname[i] = (unsigned char)name[i];
    }
    wname[i] = 0;
    if (RtlQueryEnvironmentVariable(NULL, wname, i, wval,
                                    G_N_ELEMENTS(wval) - 1, &len) < 0) {
        return NULL;
    }
    val = malloc(len + 1);
    for (i = 0; i < len; i++) {
        val[i] = wval[i] < 0x80 ? (char)wval[i] : '?';
    }
    val[len] = 0;
    return val;
}

char *__cdecl getenv(const char *name)
{
    char *val;
    gpointer found;

    AcquireSRWLockExclusive(&env_lock);
    if (!env_cache) {
        env_cache = g_hash_table_new(g_str_hash, g_str_equal);
    }
    if (g_hash_table_lookup_extended(env_cache, name, NULL, &found)) {
        val = found;
    } else {
        val = env_read(name);
        g_hash_table_insert(env_cache, g_strdup(name), val);
    }
    ReleaseSRWLockExclusive(&env_lock);
    return val;
}

int __cdecl getpid(void)
{
    return GetCurrentProcessId();
}

/*
 * The time, broken down in UTC; the module has no time zone data, so
 * local time is UTC too.  Days from and to a civil date as in Howard
 * Hinnant's days_from_civil and civil_from_days.
 */
static int64_t days_from_civil(int64_t y, unsigned m, unsigned d)
{
    int64_t era, yoe, doy;

    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    return era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
}

static struct tm *broken_down(const __time64_t *t, struct tm *tm)
{
    int64_t s = *t, days = s / 86400, rem = s % 86400;
    int64_t z, era, doe, yoe, doy, mp, y;
    unsigned d, m;

    if (rem < 0) {
        rem += 86400;
        days--;
    }
    tm->tm_hour = rem / 3600;
    tm->tm_min = rem / 60 % 60;
    tm->tm_sec = rem % 60;
    tm->tm_wday = (int)((days % 7 + 11) % 7);     /* 1970-01-01: Thursday */
    z = days + 719468;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = z - era * 146097;
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y = yoe + era * 400;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp < 10 ? mp + 3 : mp - 9;
    y += m <= 2;
    tm->tm_year = y - 1900;
    tm->tm_mon = m - 1;
    tm->tm_mday = d;
    tm->tm_yday = (int)(days - days_from_civil(y, 1, 1));
    tm->tm_isdst = 0;
    return tm;
}

static __thread struct tm tls_tm;

struct tm *__cdecl _gmtime64(const __time64_t *t)
{
    return broken_down(t, &tls_tm);
}

struct tm *__cdecl _localtime64(const __time64_t *t)
{
    return broken_down(t, &tls_tm);
}

/* The "C" locale: one byte per character, wide characters Latin-1. */

struct lconv *__cdecl localeconv(void)
{
    static struct lconv c = { .decimal_point = (char *)".",
                              .thousands_sep = (char *)"",
                              .grouping = (char *)"" };

    return &c;
}

size_t __cdecl mbrtowc(wchar_t *wc, const char *s, size_t n, mbstate_t *ps)
{
    if (!s) {
        return 0;
    }
    if (n == 0) {
        return (size_t)-2;
    }
    if (wc) {
        *wc = (unsigned char)*s;
    }
    return *s != 0;
}

size_t __cdecl mbrlen(const char *s, size_t n, mbstate_t *ps)
{
    return mbrtowc(NULL, s, n, ps);
}

size_t __cdecl wcrtomb(char *s, wchar_t wc, mbstate_t *ps)
{
    if (!s) {
        return 1;
    }
    if (wc > 0xff) {
        errno = EILSEQ;
        return (size_t)-1;
    }
    *s = (char)wc;
    return 1;
}

size_t __cdecl mbsrtowcs(wchar_t *dst, const char **src, size_t n,
                         mbstate_t *ps)
{
    const unsigned char *s = (const unsigned char *)*src;
    size_t i;

    for (i = 0; !dst || i < n; i++) {
        if (dst) {
            dst[i] = s[i];
        }
        if (!s[i]) {
            if (dst) {
                *src = NULL;
            }
            return i;
        }
    }
    *src = (const char *)s + i;
    return i;
}

size_t __cdecl wcsrtombs(char *dst, const wchar_t **src, size_t n,
                         mbstate_t *ps)
{
    const wchar_t *s = *src;
    size_t i;

    for (i = 0; !dst || i < n; i++) {
        if (s[i] > 0xff) {
            errno = EILSEQ;
            return (size_t)-1;
        }
        if (dst) {
            dst[i] = (char)s[i];
        }
        if (!s[i]) {
            if (dst) {
                *src = NULL;
            }
            return i;
        }
    }
    *src = s + i;
    return i;
}

/* Functions ntdll lacks. */

char *__cdecl strerror(int e)
{
    static __thread char buf[32];

    snprintf(buf, sizeof(buf), "error %d", e);
    return buf;
}

char *__cdecl strtok(char *s, const char *delim)
{
    static __thread char *save;

    if (!s) {
        s = save;
    }
    if (!s) {
        return NULL;
    }
    s += strspn(s, delim);
    if (!*s) {
        save = NULL;
        return NULL;
    }
    save = s + strcspn(s, delim);
    if (*save) {
        *save++ = 0;
    } else {
        save = NULL;
    }
    return s;
}

/*
 * The integer conversions, with errno: QEMU's qemu_strto* check ERANGE,
 * which ntdll's versions don't set.  One unsigned core; the signed forms
 * bound its result.
 */
static unsigned long long parse_ull(const char *s, char **end, int base,
                                     bool *neg, bool *range)
{
    const char *p = s;
    unsigned long long v = 0;
    bool any = false;

    *neg = false;
    *range = false;
    while (qemu_isspace(*p)) {
        p++;
    }
    if (*p == '+' || *p == '-') {
        *neg = *p++ == '-';
    }
    if ((base == 0 || base == 16) && p[0] == '0' &&
        (p[1] == 'x' || p[1] == 'X') && qemu_isxdigit(p[2])) {
        p += 2;
        base = 16;
    } else if (base == 0) {
        base = *p == '0' ? 8 : 10;
    }
    if (base < 2 || base > 36) {
        errno = EINVAL;
        if (end) {
            *end = (char *)s;
        }
        return 0;
    }
    for (;; p++) {
        int d = qemu_isdigit(*p) ? *p - '0' :
                qemu_isalpha(*p) ? qemu_tolower(*p) - 'a' + 10 : 36;

        if (d >= base) {
            break;
        }
        any = true;
        if (v > (ULLONG_MAX - d) / base) {
            *range = true;
        }
        v = v * base + d;
    }
    if (end) {
        *end = (char *)(any ? p : s);
    }
    return *range ? ULLONG_MAX : v;
}

unsigned long long __cdecl strtoull(const char *s, char **end, int base)
{
    bool neg, range;
    unsigned long long v = parse_ull(s, end, base, &neg, &range);

    if (range) {
        errno = ERANGE;
        return ULLONG_MAX;
    }
    return neg ? -v : v;
}

long long __cdecl strtoll(const char *s, char **end, int base)
{
    bool neg, range;
    unsigned long long v = parse_ull(s, end, base, &neg, &range);
    unsigned long long max = LLONG_MAX + (unsigned long long)neg;

    if (range || v > max) {
        errno = ERANGE;
        v = max;
    }
    return neg ? (long long)-v : (long long)v;
}

/* long is 32 bits here. */
unsigned long __cdecl strtoul(const char *s, char **end, int base)
{
    bool neg, range;
    unsigned long long v = parse_ull(s, end, base, &neg, &range);

    if (range || v > ULONG_MAX) {
        errno = ERANGE;
        return ULONG_MAX;
    }
    return neg ? -(unsigned long)v : (unsigned long)v;
}

long __cdecl strtol(const char *s, char **end, int base)
{
    bool neg, range;
    unsigned long long v = parse_ull(s, end, base, &neg, &range);
    unsigned long long max = LONG_MAX + (unsigned long long)neg;

    if (range || v > max) {
        errno = ERANGE;
        v = max;
    }
    return neg ? (long)-v : (long)v;
}

int __cdecl atoi(const char *s)
{
    return (int)strtol(s, NULL, 10);
}

long __cdecl atol(const char *s)
{
    return strtol(s, NULL, 10);
}

float __cdecl sqrtf(float x)
{
    return __builtin_sqrtf(x);
}

double __cdecl frexp(double x, int *e)
{
    union { double d; uint64_t u; } v = { .d = x };
    int be = (v.u >> 52) & 0x7ff;

    if (be == 0) {
        if (x == 0) {
            *e = 0;
            return x;
        }
        x = frexp(x * 0x1p64, e);
        *e -= 64;
        return x;
    }
    if (be == 0x7ff) {
        *e = 0;
        return x;
    }
    *e = be - 1022;
    v.u = (v.u & ~(0x7ffull << 52)) | (1022ull << 52);
    return v.d;
}

XT_IMPORT_SLOT(__acrt_iob_func);
XT_IMPORT_SLOT(_lock_file);
XT_IMPORT_SLOT(_unlock_file);
XT_IMPORT_SLOT(write);
XT_IMPORT_SLOT(_get_osfhandle);
XT_IMPORT_SLOT(_open_osfhandle);
XT_IMPORT_SLOT(_commit);
XT_IMPORT_SLOT(read);
XT_IMPORT_SLOT(open);
XT_IMPORT_SLOT(close);
XT_IMPORT_SLOT(unlink);
XT_IMPORT_SLOT(access);
XT_IMPORT_SLOT(getpid);
XT_IMPORT_SLOT(_gmtime64);
XT_IMPORT_SLOT(_localtime64);
XT_IMPORT_SLOT(localeconv);
XT_IMPORT_SLOT(strtoull);
XT_IMPORT_SLOT(strtoll);
XT_IMPORT_SLOT(strtoul);
XT_IMPORT_SLOT(strtol);
XT_IMPORT_SLOT(atoi);
XT_IMPORT_SLOT(atol);
XT_IMPORT_SLOT(getenv);
XT_IMPORT_SLOT(strerror);
XT_IMPORT_SLOT(strtok);
XT_IMPORT_SLOT(frexp);
