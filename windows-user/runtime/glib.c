/*
 * The glib functions the engine reaches, on the module's own C runtime:
 * real glib needs kernel32.  Semantics follow glib's documentation for
 * what QEMU uses; nothing else is implemented.  glib's own headers give
 * the public types and macros.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#define __USE_MINGW_ANSI_STDIO 1
#include <glib.h>
#include <windows.h>
#include <winternl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runtime.h"

/*
 * glib's headers wrap some of these in inline fast paths; define the
 * functions.
 */
#undef g_strdup
#undef g_string_append_len
#undef g_string_free
#undef g_string_append_c
#undef g_str_has_suffix
#undef g_str_has_prefix
#undef g_str_equal

/* Memory */

gpointer g_malloc(gsize n)
{
    gpointer p;

    if (!n) {
        return NULL;
    }
    p = malloc(n);
    if (!p) {
        abort();
    }
    return p;
}

gpointer g_malloc0(gsize n)
{
    gpointer p;

    if (!n) {
        return NULL;
    }
    p = calloc(1, n);
    if (!p) {
        abort();
    }
    return p;
}

gpointer g_malloc0_n(gsize n, gsize size)
{
    if (size && n > G_MAXSIZE / size) {
        abort();
    }
    return g_malloc0(n * size);
}

gpointer g_malloc_n(gsize n, gsize size)
{
    if (size && n > G_MAXSIZE / size) {
        abort();
    }
    return g_malloc(n * size);
}

gpointer g_realloc_n(gpointer mem, gsize n, gsize size)
{
    gpointer p;

    if (size && n > G_MAXSIZE / size) {
        abort();
    }
    if (!n || !size) {
        free(mem);
        return NULL;
    }
    p = realloc(mem, n * size);
    if (!p) {
        abort();
    }
    return p;
}

gpointer g_realloc(gpointer mem, gsize n)
{
    return g_realloc_n(mem, n, 1);
}

void g_free(gpointer mem)
{
    free(mem);
}

gpointer g_memdup2(gconstpointer mem, gsize n)
{
    gpointer p;

    if (!mem || !n) {
        return NULL;
    }
    p = g_malloc(n);
    memcpy(p, mem, n);
    return p;
}

/* Strings */

static const guint16 ascii_table[256] = {
    0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x104, 0x104,
    0x004, 0x104, 0x104, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004,
    0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x140,
    0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0,
    0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x459, 0x459, 0x459, 0x459, 0x459, 0x459, 0x459,
    0x459, 0x459, 0x459, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x653,
    0x653, 0x653, 0x653, 0x653, 0x653, 0x253, 0x253, 0x253, 0x253, 0x253, 0x253,
    0x253, 0x253, 0x253, 0x253, 0x253, 0x253, 0x253, 0x253, 0x253, 0x253, 0x253,
    0x253, 0x253, 0x253, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x473, 0x473,
    0x473, 0x473, 0x473, 0x473, 0x073, 0x073, 0x073, 0x073, 0x073, 0x073, 0x073,
    0x073, 0x073, 0x073, 0x073, 0x073, 0x073, 0x073, 0x073, 0x073, 0x073, 0x073,
    0x073, 0x073, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x004,
};
const guint16 *const g_ascii_table = ascii_table;

gchar *g_strdup(const gchar *s)
{
    return s ? g_memdup2(s, strlen(s) + 1) : NULL;
}

gchar *g_strndup(const gchar *s, gsize n)
{
    gchar *p;

    if (!s) {
        return NULL;
    }
    p = g_malloc(n + 1);
    strncpy(p, s, n);
    p[n] = 0;
    return p;
}

gchar *g_strdup_vprintf(const gchar *fmt, va_list ap)
{
    va_list aq;
    int n;
    gchar *p;

    va_copy(aq, ap);
    n = vsnprintf(NULL, 0, fmt, aq);
    va_end(aq);
    p = g_malloc(n + 1);
    vsnprintf(p, n + 1, fmt, ap);
    return p;
}

gchar *g_strdup_printf(const gchar *fmt, ...)
{
    va_list ap;
    gchar *p;

    va_start(ap, fmt);
    p = g_strdup_vprintf(fmt, ap);
    va_end(ap);
    return p;
}

gchar *g_strconcat(const gchar *s, ...)
{
    va_list ap;
    gsize n = 1;
    const gchar *a;
    gchar *p, *q;

    if (!s) {
        return NULL;
    }
    va_start(ap, s);
    for (a = s; a; a = va_arg(ap, const gchar *)) {
        n += strlen(a);
    }
    va_end(ap);
    q = p = g_malloc(n);
    *q = 0;
    va_start(ap, s);
    for (a = s; a; a = va_arg(ap, const gchar *)) {
        gsize l = strlen(a);

        memcpy(q, a, l);
        q += l;
    }
    va_end(ap);
    *q = 0;
    return p;
}

gint g_strcmp0(const char *a, const char *b)
{
    if (!a) {
        return -(a != b);
    }
    if (!b) {
        return 1;
    }
    return strcmp(a, b);
}

gboolean g_str_has_suffix(const gchar *s, const gchar *suffix)
{
    gsize n = strlen(s), m = strlen(suffix);

    return n >= m && !strcmp(s + n - m, suffix);
}

gchar **g_strsplit(const gchar *s, const gchar *delim, gint max)
{
    gsize dl = strlen(delim);
    GPtrArray *a = g_ptr_array_new();
    const gchar *p = s, *q;

    if (max < 1) {
        max = G_MAXINT;
    }
    if (*s) {
        while (--max && (q = strstr(p, delim))) {
            g_ptr_array_add(a, g_strndup(p, q - p));
            p = q + dl;
        }
        g_ptr_array_add(a, g_strdup(p));
    }
    g_ptr_array_add(a, NULL);
    return (gchar **)g_ptr_array_free(a, FALSE);
}

void g_strfreev(gchar **v)
{
    if (v) {
        for (gchar **p = v; *p; p++) {
            g_free(*p);
        }
        g_free(v);
    }
}

guint g_strv_length(gchar **v)
{
    guint n = 0;

    while (v && v[n]) {
        n++;
    }
    return n;
}

gsize g_strlcpy(gchar *dest, const gchar *src, gsize size)
{
    gsize n = strlen(src);

    if (size) {
        gsize c = MIN(n, size - 1);

        memcpy(dest, src, c);
        dest[c] = 0;
    }
    return n;
}

gboolean g_str_has_prefix(const gchar *s, const gchar *prefix)
{
    return !strncmp(s, prefix, strlen(prefix));
}

gchar g_ascii_tolower(gchar c)
{
    return c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c;
}

gint g_ascii_strcasecmp(const gchar *a, const gchar *b)
{
    for (;; a++, b++) {
        gint ca = g_ascii_tolower(*a), cb = g_ascii_tolower(*b);

        if (ca != cb || !ca) {
            return ca - cb;
        }
    }
}

const gchar *g_getenv(const gchar *name)
{
    return getenv(name);
}

static gchar *prgname;

void g_set_prgname(const gchar *name)
{
    prgname = g_strdup(name);
}

/* The machine-wide data directory, for qemu_get_local_state_dir(). */
const gchar *const *g_win32_get_system_data_dirs_for_module(
    void (*address_of_function)(void))
{
    static const gchar *const dirs[] = { "C:\\ProgramData", NULL };

    return dirs;
}

/* The module creates no files. */
gint g_file_open_tmp(const gchar *tmpl, gchar **name_used, GError **error)
{
    if (error) {
        *error = g_malloc0(sizeof(GError));
        (*error)->message = g_strdup("no temporary files");
    }
    return -1;
}

/* UTF-16, surrogate pairs included, to UTF-8. */
gchar *g_utf16_to_utf8(const gunichar2 *w, glong len, glong *read,
                       glong *written, GError **error)
{
    GString *s = g_string_new(NULL);
    glong i;

    for (i = 0; len < 0 ? w[i] != 0 : i < len; i++) {
        gunichar c = w[i];

        if (c >= 0xd800 && c < 0xdc00 && (len < 0 || i + 1 < len) &&
            w[i + 1] >= 0xdc00 && w[i + 1] < 0xe000) {
            c = 0x10000 + ((c - 0xd800) << 10) + (w[++i] - 0xdc00);
        }
        g_string_append_unichar(s, c);
    }
    if (read) {
        *read = i;
    }
    if (written) {
        *written = s->len;
    }
    return g_string_free(s, FALSE);
}

gunichar2 *g_utf8_to_utf16(const gchar *s, glong len, glong *read,
                           glong *written, GError **error)
{
    gsize n = len < 0 ? strlen(s) : (gsize)len;
    gunichar2 *w = g_malloc((n + 1) * sizeof(gunichar2));

    /* ASCII only: the engine converts thread names. */
    for (gsize i = 0; i < n; i++) {
        w[i] = (guchar)s[i] < 0x80 ? s[i] : '?';
    }
    w[n] = 0;
    if (read) {
        *read = n;
    }
    if (written) {
        *written = n;
    }
    return w;
}

gchar *g_win32_error_message(gint error)
{
    return g_strdup_printf("Windows error %d", error);
}

const gchar *g_get_prgname(void)
{
    return NULL;
}

/* GString */

static void gs_grow(GString *s, gsize extra)
{
    if (s->len + extra + 1 > s->allocated_len) {
        gsize n = MAX(s->allocated_len * 2, s->len + extra + 1);

        s->str = g_realloc_n(s->str, n, 1);
        s->allocated_len = n;
    }
}

GString *g_string_new(const gchar *init)
{
    GString *s = g_malloc0(sizeof(*s));

    gs_grow(s, init ? strlen(init) : 0);
    s->str[0] = 0;
    if (init) {
        g_string_append_len(s, init, -1);
    }
    return s;
}

gchar *g_string_free(GString *s, gboolean free_segment)
{
    gchar *p = s->str;

    g_free(s);
    if (free_segment) {
        g_free(p);
        return NULL;
    }
    return p;
}

GString *g_string_sized_new(gsize size)
{
    GString *s = g_malloc0(sizeof(*s));

    gs_grow(s, size);
    s->str[0] = 0;
    return s;
}

GString *g_string_new_len(const gchar *init, gssize len)
{
    GString *s;

    if (len < 0) {
        return g_string_new(init);
    }
    s = g_string_sized_new(len);
    if (init) {
        memcpy(s->str, init, len);
    }
    s->len = len;
    s->str[len] = 0;
    return s;
}

GString *g_string_set_size(GString *s, gsize len)
{
    if (len > s->len) {
        gs_grow(s, len - s->len);
    }
    s->len = len;
    s->str[len] = 0;
    return s;
}

GString *g_string_assign(GString *s, const gchar *val)
{
    if (s->str != val) {
        g_string_set_size(s, 0);
        g_string_append_len(s, val, -1);
    }
    return s;
}

GString *g_string_insert_len(GString *s, gssize pos, const gchar *val,
                             gssize len)
{
    if (len < 0) {
        len = strlen(val);
    }
    if (pos < 0) {
        pos = s->len;
    }
    gs_grow(s, len);
    memmove(s->str + pos + len, s->str + pos, s->len - pos + 1);
    memcpy(s->str + pos, val, len);
    s->len += len;
    return s;
}

GString *g_string_append_len(GString *s, const gchar *val, gssize len)
{
    return g_string_insert_len(s, -1, val, len);
}

GString *g_string_insert_c(GString *s, gssize pos, gchar c)
{
    return g_string_insert_len(s, pos, &c, 1);
}

GString *g_string_prepend(GString *s, const gchar *val)
{
    return g_string_insert_len(s, 0, val, -1);
}

GString *g_string_prepend_c(GString *s, gchar c)
{
    return g_string_insert_len(s, 0, &c, 1);
}

GString *g_string_erase(GString *s, gssize pos, gssize len)
{
    if (len < 0 || pos + len > (gssize)s->len) {
        len = s->len - pos;
    }
    memmove(s->str + pos, s->str + pos + len, s->len - pos - len + 1);
    s->len -= len;
    return s;
}

GString *g_string_append_unichar(GString *s, gunichar c)
{
    gchar b[4];
    int n;

    if (c < 0x80) {
        b[0] = c;
        n = 1;
    } else if (c < 0x800) {
        b[0] = 0xc0 | (c >> 6);
        b[1] = 0x80 | (c & 0x3f);
        n = 2;
    } else if (c < 0x10000) {
        b[0] = 0xe0 | (c >> 12);
        b[1] = 0x80 | ((c >> 6) & 0x3f);
        b[2] = 0x80 | (c & 0x3f);
        n = 3;
    } else {
        b[0] = 0xf0 | (c >> 18);
        b[1] = 0x80 | ((c >> 12) & 0x3f);
        b[2] = 0x80 | ((c >> 6) & 0x3f);
        b[3] = 0x80 | (c & 0x3f);
        n = 4;
    }
    return g_string_insert_len(s, -1, b, n);
}

void g_string_append_vprintf(GString *s, const gchar *fmt, va_list ap)
{
    gchar *p = g_strdup_vprintf(fmt, ap);

    g_string_append_len(s, p, -1);
    g_free(p);
}

void g_string_vprintf(GString *s, const gchar *fmt, va_list ap)
{
    s->len = 0;
    s->str[0] = 0;
    g_string_append_vprintf(s, fmt, ap);
}

void g_string_append_printf(GString *s, const gchar *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    g_string_append_vprintf(s, fmt, ap);
    va_end(ap);
}

/* GPtrArray, GArray */

typedef struct {
    GPtrArray a;
    guint alloc;
    gint ref;
    GDestroyNotify free_func;
} XPtrArray;

GPtrArray *g_ptr_array_new(void)
{
    XPtrArray *x = g_malloc0(sizeof(*x));

    x->ref = 1;
    return &x->a;
}

void g_ptr_array_add(GPtrArray *a, gpointer p)
{
    XPtrArray *x = (XPtrArray *)a;

    if (a->len == x->alloc) {
        x->alloc = MAX(16, x->alloc * 2);
        a->pdata = g_realloc_n(a->pdata, x->alloc, sizeof(gpointer));
    }
    a->pdata[a->len++] = p;
}

gpointer g_ptr_array_remove_index_fast(GPtrArray *a, guint i)
{
    gpointer p = a->pdata[i];

    a->pdata[i] = a->pdata[--a->len];
    return p;
}

void g_ptr_array_set_free_func(GPtrArray *a, GDestroyNotify f)
{
    ((XPtrArray *)a)->free_func = f;
}

gboolean g_ptr_array_remove(GPtrArray *a, gpointer p)
{
    XPtrArray *x = (XPtrArray *)a;

    for (guint i = 0; i < a->len; i++) {
        if (a->pdata[i] == p) {
            memmove(&a->pdata[i], &a->pdata[i + 1],
                    (a->len - i - 1) * sizeof(gpointer));
            a->len--;
            if (x->free_func) {
                x->free_func(p);
            }
            return TRUE;
        }
    }
    return FALSE;
}

/* glib's comparison takes pointers to the elements, as qsort's does. */
void g_ptr_array_sort(GPtrArray *a, GCompareFunc f)
{
    if (a->len) {
        qsort(a->pdata, a->len, sizeof(gpointer),
              (int (*)(const void *, const void *))f);
    }
}

gpointer *g_ptr_array_free(GPtrArray *a, gboolean free_seg)
{
    XPtrArray *x = (XPtrArray *)a;
    gpointer *p = a->pdata;

    if (free_seg && x->free_func) {
        for (guint i = 0; i < a->len; i++) {
            x->free_func(p[i]);
        }
    }
    g_free(a);
    if (free_seg) {
        g_free(p);
        return NULL;
    }
    return p;
}

void g_ptr_array_unref(GPtrArray *a)
{
    if (__atomic_sub_fetch(&((XPtrArray *)a)->ref, 1, __ATOMIC_ACQ_REL) == 0) {
        g_ptr_array_free(a, TRUE);
    }
}

typedef struct {
    GArray a;
    guint elt;
    guint alloc;
    gboolean zero_term;
    gboolean clear;
    gint ref;
} XArray;

GArray *g_array_sized_new(gboolean zero_term, gboolean clear, guint elt,
                          guint reserved)
{
    XArray *x = g_malloc0(sizeof(*x));

    x->elt = elt;
    x->zero_term = zero_term;
    x->clear = clear;
    x->ref = 1;
    x->alloc = reserved + (zero_term ? 1 : 0);
    x->a.data = x->alloc ? g_malloc0_n(x->alloc, elt) : NULL;
    return &x->a;
}

static void ga_resize(XArray *x, guint len)
{
    guint need = len + (x->zero_term ? 1 : 0);

    if (need > x->alloc) {
        guint n = MAX(need, MAX(16, x->alloc * 2));

        x->a.data = g_realloc_n(x->a.data, n, x->elt);
        memset(x->a.data + (gsize)x->alloc * x->elt, 0,
               (gsize)(n - x->alloc) * x->elt);
        x->alloc = n;
    }
    if (len > x->a.len && x->clear) {
        memset(x->a.data + (gsize)x->a.len * x->elt, 0,
               (gsize)(len - x->a.len) * x->elt);
    }
    x->a.len = len;
    if (x->zero_term) {
        memset(x->a.data + (gsize)len * x->elt, 0, x->elt);
    }
}

GArray *g_array_append_vals(GArray *a, gconstpointer data, guint n)
{
    XArray *x = (XArray *)a;
    guint old = a->len;

    ga_resize(x, old + n);
    if (data && n) {
        memcpy(a->data + (gsize)old * x->elt, data, (gsize)n * x->elt);
    }
    return a;
}

gchar *g_array_free(GArray *a, gboolean free_seg)
{
    gchar *p = a->data;

    g_free(a);
    if (free_seg) {
        g_free(p);
        return NULL;
    }
    return p;
}

void g_array_unref(GArray *a)
{
    if (__atomic_sub_fetch(&((XArray *)a)->ref, 1, __ATOMIC_ACQ_REL) == 0) {
        g_array_free(a, TRUE);
    }
}

/* A GByteArray is a GArray of bytes, as in glib. */
GByteArray *g_byte_array_new(void)
{
    return (GByteArray *)g_array_sized_new(FALSE, FALSE, 1, 0);
}

GByteArray *g_byte_array_set_size(GByteArray *a, guint len)
{
    ga_resize((XArray *)a, len);
    return a;
}

GByteArray *g_byte_array_append(GByteArray *a, const guint8 *data, guint len)
{
    return (GByteArray *)g_array_append_vals((GArray *)a, data, len);
}

guint8 *g_byte_array_free(GByteArray *a, gboolean free_seg)
{
    return (guint8 *)g_array_free((GArray *)a, free_seg);
}

/* GList, GSList */

GList *g_list_append(GList *l, gpointer data)
{
    GList *n = g_malloc0(sizeof(*n)), *t = l;

    n->data = data;
    if (!l) {
        return n;
    }
    while (t->next) {
        t = t->next;
    }
    t->next = n;
    n->prev = t;
    return l;
}

GList *g_list_insert_before(GList *l, GList *sibling, gpointer data)
{
    GList *n;

    if (!sibling) {
        return g_list_append(l, data);
    }
    n = g_malloc0(sizeof(*n));
    n->data = data;
    n->next = sibling;
    n->prev = sibling->prev;
    sibling->prev = n;
    if (n->prev) {
        n->prev->next = n;
        return l;
    }
    return n;
}

GList *g_list_delete_link(GList *l, GList *link)
{
    if (link->prev) {
        link->prev->next = link->next;
    } else {
        l = link->next;
    }
    if (link->next) {
        link->next->prev = link->prev;
    }
    g_free(link);
    return l;
}

void g_list_foreach(GList *l, GFunc f, gpointer ud)
{
    while (l) {
        GList *n = l->next;

        f(l->data, ud);
        l = n;
    }
}

/* GQueue: a GList with its tail and length. */

GQueue *g_queue_new(void)
{
    return g_malloc0(sizeof(GQueue));
}

void g_queue_free(GQueue *q)
{
    g_list_free(q->head);
    g_free(q);
}

gboolean g_queue_is_empty(GQueue *q)
{
    return q->head == NULL;
}

void g_queue_push_tail(GQueue *q, gpointer data)
{
    GList *n = g_malloc0(sizeof(*n));

    n->data = data;
    n->prev = q->tail;
    if (q->tail) {
        q->tail->next = n;
    } else {
        q->head = n;
    }
    q->tail = n;
    q->length++;
}

gpointer g_queue_peek_tail(GQueue *q)
{
    return q->tail ? q->tail->data : NULL;
}

gpointer g_queue_pop_tail(GQueue *q)
{
    GList *n = q->tail;
    gpointer data;

    if (!n) {
        return NULL;
    }
    data = n->data;
    q->tail = n->prev;
    if (q->tail) {
        q->tail->next = NULL;
    } else {
        q->head = NULL;
    }
    q->length--;
    g_free(n);
    return data;
}

GList *g_list_find_custom(GList *l, gconstpointer data, GCompareFunc f)
{
    for (; l; l = l->next) {
        if (!f(l->data, data)) {
            return l;
        }
    }
    return NULL;
}

void g_list_free(GList *l)
{
    while (l) {
        GList *n = l->next;

        g_free(l);
        l = n;
    }
}

/* Stable merge sort of a singly linked chain through ->next. */
static gpointer list_sort(gpointer head, size_t next_off, GCompareDataFunc f,
                          gpointer ud)
{
#define NEXT(p) (*(gpointer *)((char *)(p) + next_off))
#define DATA(p) (*(gpointer *)(p))
    gpointer a = head, b, *tail, out = NULL;
    gpointer slow, fast;

    if (!head || !NEXT(head)) {
        return head;
    }
    slow = head;
    fast = NEXT(head);
    while (fast && NEXT(fast)) {
        slow = NEXT(slow);
        fast = NEXT(NEXT(fast));
    }
    b = NEXT(slow);
    NEXT(slow) = NULL;
    a = list_sort(a, next_off, f, ud);
    b = list_sort(b, next_off, f, ud);
    tail = &out;
    while (a && b) {
        if (f(DATA(a), DATA(b), ud) <= 0) {
            *tail = a;
            a = NEXT(a);
        } else {
            *tail = b;
            b = NEXT(b);
        }
        tail = &NEXT(*tail);
    }
    *tail = a ? a : b;
    return out;
#undef NEXT
#undef DATA
}

GList *g_list_sort_with_data(GList *l, GCompareDataFunc f, gpointer ud)
{
    GList *prev = NULL;

    l = list_sort(l, offsetof(GList, next), f, ud);
    for (GList *p = l; p; p = p->next) {
        p->prev = prev;
        prev = p;
    }
    return l;
}

GSList *g_slist_prepend(GSList *l, gpointer data)
{
    GSList *n = g_malloc(sizeof(*n));

    n->data = data;
    n->next = l;
    return n;
}

GSList *g_slist_append(GSList *l, gpointer data)
{
    GSList *n = g_malloc0(sizeof(*n)), *t = l;

    n->data = data;
    if (!l) {
        return n;
    }
    while (t->next) {
        t = t->next;
    }
    t->next = n;
    return l;
}

GSList *g_slist_find(GSList *l, gconstpointer data)
{
    while (l && l->data != data) {
        l = l->next;
    }
    return l;
}

GSList *g_slist_remove(GSList *l, gconstpointer data)
{
    GSList **p = &l;

    while (*p) {
        if ((*p)->data == data) {
            GSList *n = *p;

            *p = n->next;
            g_free(n);
            break;
        }
        p = &(*p)->next;
    }
    return l;
}

void g_slist_foreach(GSList *l, GFunc f, gpointer ud)
{
    while (l) {
        GSList *n = l->next;

        f(l->data, ud);
        l = n;
    }
}

void g_slist_free(GSList *l)
{
    while (l) {
        GSList *n = l->next;

        g_free(l);
        l = n;
    }
}

GSList *g_slist_sort_with_data(GSList *l, GCompareDataFunc f, gpointer ud)
{
    return list_sort(l, offsetof(GSList, next), f, ud);
}

/* GHashTable: chained, power-of-two buckets. */

typedef struct HNode {
    struct HNode *next;
    gpointer key, value;
    guint hash;
} HNode;

struct _GHashTable {
    HNode **b;
    guint nb, size, ref;
    GHashFunc hf;
    GEqualFunc ef;
    GDestroyNotify kd, vd;
};

GHashTable *g_hash_table_new_full(GHashFunc hf, GEqualFunc ef,
                                  GDestroyNotify kd, GDestroyNotify vd)
{
    GHashTable *h = g_malloc0(sizeof(*h));

    h->nb = 16;
    h->b = g_malloc0_n(h->nb, sizeof(HNode *));
    h->hf = hf ? hf : g_direct_hash;
    h->ef = ef;
    h->kd = kd;
    h->vd = vd;
    h->ref = 1;
    return h;
}

GHashTable *g_hash_table_new(GHashFunc hf, GEqualFunc ef)
{
    return g_hash_table_new_full(hf, ef, NULL, NULL);
}

static HNode **h_find(GHashTable *h, gconstpointer key, guint hash)
{
    HNode **pp = &h->b[hash & (h->nb - 1)];

    for (; *pp; pp = &(*pp)->next) {
        if ((*pp)->hash == hash &&
            (h->ef ? h->ef((*pp)->key, key) : (*pp)->key == key)) {
            break;
        }
    }
    return pp;
}

static void h_resize(GHashTable *h)
{
    guint nb = h->nb * 2;
    HNode **b = g_malloc0_n(nb, sizeof(HNode *));

    for (guint i = 0; i < h->nb; i++) {
        for (HNode *n = h->b[i], *next; n; n = next) {
            next = n->next;
            n->next = b[n->hash & (nb - 1)];
            b[n->hash & (nb - 1)] = n;
        }
    }
    g_free(h->b);
    h->b = b;
    h->nb = nb;
}

static gboolean h_insert(GHashTable *h, gpointer key, gpointer value,
                         gboolean keep_key)
{
    guint hash = h->hf(key);
    HNode **pp = h_find(h, key, hash), *n = *pp;

    if (n) {
        if (h->vd) {
            h->vd(n->value);
        }
        if (keep_key) {
            if (h->kd) {
                h->kd(key);
            }
        } else {
            if (h->kd) {
                h->kd(n->key);
            }
            n->key = key;
        }
        n->value = value;
        return FALSE;
    }
    n = g_malloc(sizeof(*n));
    n->key = key;
    n->value = value;
    n->hash = hash;
    n->next = NULL;
    *pp = n;
    if (++h->size > h->nb * 2) {
        h_resize(h);
    }
    return TRUE;
}

gboolean g_hash_table_insert(GHashTable *h, gpointer key, gpointer value)
{
    return h_insert(h, key, value, TRUE);
}

gboolean g_hash_table_replace(GHashTable *h, gpointer key, gpointer value)
{
    return h_insert(h, key, value, FALSE);
}

gboolean g_hash_table_add(GHashTable *h, gpointer key)
{
    return h_insert(h, key, key, FALSE);
}

gpointer g_hash_table_lookup(GHashTable *h, gconstpointer key)
{
    HNode *n = *h_find(h, key, h->hf(key));

    return n ? n->value : NULL;
}

gboolean g_hash_table_lookup_extended(GHashTable *h, gconstpointer key,
                                      gpointer *okey, gpointer *value)
{
    HNode *n = *h_find(h, key, h->hf(key));

    if (!n) {
        return FALSE;
    }
    if (okey) {
        *okey = n->key;
    }
    if (value) {
        *value = n->value;
    }
    return TRUE;
}

gboolean g_hash_table_contains(GHashTable *h, gconstpointer key)
{
    return *h_find(h, key, h->hf(key)) != NULL;
}

static void h_free_node(GHashTable *h, HNode *n)
{
    if (h->kd) {
        h->kd(n->key);
    }
    if (h->vd) {
        h->vd(n->value);
    }
    g_free(n);
}

gboolean g_hash_table_remove(GHashTable *h, gconstpointer key)
{
    HNode **pp = h_find(h, key, h->hf(key)), *n = *pp;

    if (!n) {
        return FALSE;
    }
    *pp = n->next;
    h->size--;
    h_free_node(h, n);
    return TRUE;
}

void g_hash_table_remove_all(GHashTable *h)
{
    for (guint i = 0; i < h->nb; i++) {
        for (HNode *n = h->b[i], *next; n; n = next) {
            next = n->next;
            h_free_node(h, n);
        }
        h->b[i] = NULL;
    }
    h->size = 0;
}

guint g_hash_table_size(GHashTable *h)
{
    return h->size;
}

void g_hash_table_foreach(GHashTable *h, GHFunc f, gpointer ud)
{
    for (guint i = 0; i < h->nb; i++) {
        for (HNode *n = h->b[i]; n; n = n->next) {
            f(n->key, n->value, ud);
        }
    }
}

void g_hash_table_unref(GHashTable *h)
{
    if (--h->ref == 0) {
        g_hash_table_remove_all(h);
        g_free(h->b);
        g_free(h);
    }
}

void g_hash_table_destroy(GHashTable *h)
{
    g_hash_table_remove_all(h);
    g_hash_table_unref(h);
}

/*
 * The iterator: dummy1 the table, dummy2 the node just returned,
 * dummy3 the next node, dummy4 the bucket of the next node.
 */
void g_hash_table_iter_init(GHashTableIter *it, GHashTable *h)
{
    it->dummy1 = h;
    it->dummy2 = NULL;
    it->dummy3 = NULL;
    it->dummy4 = -1;
    for (guint i = 0; i < h->nb; i++) {
        if (h->b[i]) {
            it->dummy3 = h->b[i];
            it->dummy4 = i;
            break;
        }
    }
}

gboolean g_hash_table_iter_next(GHashTableIter *it, gpointer *key,
                                gpointer *value)
{
    GHashTable *h = it->dummy1;
    HNode *n = it->dummy3;

    if (!n) {
        return FALSE;
    }
    it->dummy2 = n;
    if (key) {
        *key = n->key;
    }
    if (value) {
        *value = n->value;
    }
    if (n->next) {
        it->dummy3 = n->next;
    } else {
        it->dummy3 = NULL;
        for (guint i = it->dummy4 + 1; i < h->nb; i++) {
            if (h->b[i]) {
                it->dummy3 = h->b[i];
                it->dummy4 = i;
                break;
            }
        }
    }
    return TRUE;
}

void g_hash_table_iter_remove(GHashTableIter *it)
{
    GHashTable *h = it->dummy1;
    HNode *n = it->dummy2, **pp = &h->b[n->hash & (h->nb - 1)];

    while (*pp != n) {
        pp = &(*pp)->next;
    }
    *pp = n->next;
    h->size--;
    h_free_node(h, n);
    it->dummy2 = NULL;
}

void g_hash_table_iter_replace(GHashTableIter *it, gpointer value)
{
    GHashTable *h = it->dummy1;
    HNode *n = it->dummy2;

    if (h->vd) {
        h->vd(n->value);
    }
    n->value = value;
}

guint g_direct_hash(gconstpointer v)
{
    guintptr x = (guintptr)v;

    return (guint)(x ^ (x >> 32));
}

gboolean g_direct_equal(gconstpointer a, gconstpointer b)
{
    return a == b;
}

guint g_int64_hash(gconstpointer v)
{
    guint64 x = *(const guint64 *)v;

    return (guint)(x ^ (x >> 32));
}

gboolean g_int64_equal(gconstpointer a, gconstpointer b)
{
    return *(const gint64 *)a == *(const gint64 *)b;
}

guint g_str_hash(gconstpointer v)
{
    guint32 h = 5381;

    for (const signed char *p = v; *p; p++) {
        h = (h << 5) + h + *p;
    }
    return h;
}

gboolean g_str_equal(gconstpointer a, gconstpointer b)
{
    return !strcmp(a, b);
}

/* GTree: a treap ordered by the tree's comparison. */

typedef struct TNode {
    struct TNode *l, *r;
    gpointer key, value;
    guint prio;
} TNode;

struct _GTree {
    TNode *root;
    GCompareDataFunc cmp;
    gpointer cmp_data;
    GDestroyNotify kd, vd;
    gint ref;
    guint seed;
};

GTree *g_tree_new_full(GCompareDataFunc cmp, gpointer cmp_data,
                       GDestroyNotify kd, GDestroyNotify vd)
{
    GTree *t = g_malloc0(sizeof(*t));

    t->cmp = cmp;
    t->cmp_data = cmp_data;
    t->kd = kd;
    t->vd = vd;
    t->ref = 1;
    t->seed = 0x9e3779b9;
    return t;
}

GTree *g_tree_ref(GTree *t)
{
    t->ref++;
    return t;
}

static void t_free(GTree *t, TNode *n)
{
    if (n) {
        t_free(t, n->l);
        t_free(t, n->r);
        if (t->kd) {
            t->kd(n->key);
        }
        if (t->vd) {
            t->vd(n->value);
        }
        g_free(n);
    }
}

void g_tree_destroy(GTree *t)
{
    t_free(t, t->root);
    t->root = NULL;
    if (--t->ref == 0) {
        g_free(t);
    }
}

static TNode *t_insert(GTree *t, TNode *n, gpointer key, gpointer value)
{
    int c;

    if (!n) {
        n = g_malloc0(sizeof(*n));
        n->key = key;
        n->value = value;
        t->seed = t->seed * 1103515245 + 12345;
        n->prio = t->seed;
        return n;
    }
    c = t->cmp(key, n->key, t->cmp_data);
    if (c == 0) {
        if (t->vd) {
            t->vd(n->value);
        }
        if (t->kd) {
            t->kd(key);
        }
        n->value = value;
    } else if (c < 0) {
        n->l = t_insert(t, n->l, key, value);
        if (n->l->prio > n->prio) {
            TNode *l = n->l;

            n->l = l->r;
            l->r = n;
            n = l;
        }
    } else {
        n->r = t_insert(t, n->r, key, value);
        if (n->r->prio > n->prio) {
            TNode *r = n->r;

            n->r = r->l;
            r->l = n;
            n = r;
        }
    }
    return n;
}

void g_tree_insert(GTree *t, gpointer key, gpointer value)
{
    t->root = t_insert(t, t->root, key, value);
}

static TNode *t_join(TNode *a, TNode *b)
{
    if (!a) {
        return b;
    }
    if (!b) {
        return a;
    }
    if (a->prio > b->prio) {
        a->r = t_join(a->r, b);
        return a;
    }
    b->l = t_join(a, b->l);
    return b;
}

gboolean g_tree_remove(GTree *t, gconstpointer key)
{
    TNode **pp = &t->root;

    while (*pp) {
        int c = t->cmp(key, (*pp)->key, t->cmp_data);

        if (c == 0) {
            TNode *n = *pp;

            *pp = t_join(n->l, n->r);
            n->l = n->r = NULL;
            t_free(t, n);
            return TRUE;
        }
        pp = c < 0 ? &(*pp)->l : &(*pp)->r;
    }
    return FALSE;
}

gpointer g_tree_lookup(GTree *t, gconstpointer key)
{
    TNode *n = t->root;

    while (n) {
        int c = t->cmp(key, n->key, t->cmp_data);

        if (c == 0) {
            return n->value;
        }
        n = c < 0 ? n->l : n->r;
    }
    return NULL;
}

static gboolean t_foreach(TNode *n, GTraverseFunc f, gpointer ud)
{
    return n && (t_foreach(n->l, f, ud) || f(n->key, n->value, ud) ||
                 t_foreach(n->r, f, ud));
}

void g_tree_foreach(GTree *t, GTraverseFunc f, gpointer ud)
{
    t_foreach(t->root, f, ud);
}

static gint t_count(TNode *n)
{
    return n ? 1 + t_count(n->l) + t_count(n->r) : 0;
}

gint g_tree_nnodes(GTree *t)
{
    return t_count(t->root);
}

/* Threads and time */

void g_mutex_lock(GMutex *m)
{
    AcquireSRWLockExclusive((SRWLOCK *)&m->p);
}

gboolean g_mutex_trylock(GMutex *m)
{
    return TryAcquireSRWLockExclusive((SRWLOCK *)&m->p);
}

void g_mutex_unlock(GMutex *m)
{
    ReleaseSRWLockExclusive((SRWLOCK *)&m->p);
}

/*
 * One-time initialization, as glib does it: the lock isn't held while
 * the initializer runs, so an initializer may itself initialize something
 * else once; a second thread waits for the first to finish.
 */
static SRWLOCK once_lock = SRWLOCK_INIT;
static CONDITION_VARIABLE once_cond = CONDITION_VARIABLE_INIT;
static GSList *once_running;    /* g_once_init_enter's locations */

static void once_wait(void)
{
    RtlSleepConditionVariableSRW(&once_cond, &once_lock, NULL, 0);
}

static void once_done(void)
{
    RtlWakeAllConditionVariable(&once_cond);
    ReleaseSRWLockExclusive(&once_lock);
}

gpointer g_once_impl(GOnce *once, GThreadFunc func, gpointer arg)
{
    gpointer ret;

    AcquireSRWLockExclusive(&once_lock);
    while (once->status == G_ONCE_STATUS_PROGRESS) {
        once_wait();
    }
    if (once->status == G_ONCE_STATUS_READY) {
        ReleaseSRWLockExclusive(&once_lock);
        return once->retval;
    }
    once->status = G_ONCE_STATUS_PROGRESS;
    ReleaseSRWLockExclusive(&once_lock);

    ret = func(arg);

    AcquireSRWLockExclusive(&once_lock);
    once->retval = ret;
    __atomic_store_n(&once->status, G_ONCE_STATUS_READY, __ATOMIC_RELEASE);
    once_done();
    return ret;
}

/*
 * TRUE for the one caller that initializes the location, which then calls
 * g_once_init_leave; a location already set returns FALSE without locking,
 * and one being initialized waits.
 */
gboolean(g_once_init_enter)(volatile void *location)
{
    gsize *loc = (gsize *)location;     /* volatile in glib's interface */
    gboolean init = FALSE;

    if (__atomic_load_n(loc, __ATOMIC_ACQUIRE)) {
        return FALSE;
    }
    AcquireSRWLockExclusive(&once_lock);
    if (!__atomic_load_n(loc, __ATOMIC_RELAXED)) {
        while (g_slist_find(once_running, loc)) {
            once_wait();
        }
        if (!__atomic_load_n(loc, __ATOMIC_RELAXED)) {
            once_running = g_slist_prepend(once_running, loc);
            init = TRUE;
        }
    }
    ReleaseSRWLockExclusive(&once_lock);
    return init;
}

/* location is volatile in glib's interface. */
void(g_once_init_leave)(volatile void *location, gsize result)
{
    AcquireSRWLockExclusive(&once_lock);
    __atomic_store_n((gsize *)location, result, __ATOMIC_RELEASE);
    once_running = g_slist_remove(once_running, (void *)location);
    once_done();
}

/* The performance counter in microseconds. */
gint64 g_get_monotonic_time(void)
{
    LARGE_INTEGER c, f;
    gint64 secs, rest;

    NtQueryPerformanceCounter(&c, &f);
    secs = c.QuadPart / f.QuadPart;
    rest = c.QuadPart - secs * f.QuadPart;
    return secs * G_USEC_PER_SEC + rest * G_USEC_PER_SEC / f.QuadPart;
}

/*
 * In 100 ns units; the wait still ends on a timer tick (1 ms, or 15.6 ms
 * by default), so short sleeps are longer than asked.
 */
void g_usleep(gulong us)
{
    LARGE_INTEGER t;

    t.QuadPart = -(LONGLONG)us * 10;
    NtDelayExecution(FALSE, &t);
}

struct _GRand {
    guint64 s;
};

GRand *g_rand_new(void)
{
    GRand *r = g_malloc(sizeof(*r));
    LARGE_INTEGER c;

    NtQueryPerformanceCounter(&c, NULL);
    r->s = c.QuadPart | 1;
    return r;
}

GRand *g_rand_new_with_seed_array(const guint32 *seed, guint len)
{
    GRand *r = g_malloc(sizeof(*r));

    r->s = 0x9e3779b97f4a7c15ull;
    for (guint i = 0; i < len; i++) {
        r->s = (r->s ^ seed[i]) * 0x100000001b3ull;
    }
    r->s |= 1;
    return r;
}

guint32 g_rand_int(GRand *r)
{
    r->s ^= r->s << 13;
    r->s ^= r->s >> 7;
    r->s ^= r->s << 17;
    return (guint32)(r->s >> 16);
}

/* The process-wide generator, under a lock. */
static GRand *global_rand;
static SRWLOCK global_rand_lock = SRWLOCK_INIT;

gint32 g_random_int_range(gint32 begin, gint32 end)
{
    guint32 v;

    AcquireSRWLockExclusive(&global_rand_lock);
    if (!global_rand) {
        global_rand = g_rand_new();
    }
    v = g_rand_int(global_rand);
    ReleaseSRWLockExclusive(&global_rand_lock);
    return begin + (gint32)(v % (guint32)(end - begin));
}

struct _GDateTime {
    gint64 unix_us;
};

gint64 g_get_real_time(void)
{
    LARGE_INTEGER t;

    /* 100 ns units since 1601. */
    NtQuerySystemTime(&t);
    return (t.QuadPart - 116444736000000000LL) / 10;
}

GDateTime *g_date_time_new_now_utc(void)
{
    GDateTime *d = g_malloc(sizeof(*d));
    LARGE_INTEGER t;

    /* 100 ns units since 1601. */
    NtQuerySystemTime(&t);
    d->unix_us = (t.QuadPart - 116444736000000000LL) / 10;
    return d;
}

gchar *g_date_time_format_iso8601(GDateTime *d)
{
    gint64 s = d->unix_us / 1000000, days = s / 86400, rem = s % 86400;
    /* Civil date from days since 1970-01-01 (Howard Hinnant's algorithm). */
    gint64 z = days + 719468, era = z / 146097, doe = z - era * 146097;
    gint64 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    gint64 doy = doe - (365 * yoe + yoe / 4 - yoe / 100),
           mp = (5 * doy + 2) / 153;
    int day = doy - (153 * mp + 2) / 5 + 1, mon = mp < 10 ? mp + 3 : mp - 9;
    int year = yoe + era * 400 + (mon <= 2);

    return g_strdup_printf("%04d-%02d-%02dT%02d:%02d:%02d.%06dZ", year, mon,
                           day, (int)(rem / 3600), (int)(rem / 60 % 60),
                           (int)(rem % 60), (int)(d->unix_us % 1000000));
}

void g_date_time_unref(GDateTime *d)
{
    g_free(d);
}

/* Assertions and warnings */

void g_warn_message(const char *domain, const char *file, int line,
                    const char *func, const char *warnexpr)
{
    fprintf(stderr, "%s:%d:%s: runtime check failed: (%s)\n", file, line,
            func, warnexpr ? warnexpr : "code should not be reached");
}

void g_return_if_fail_warning(const char *domain, const char *func,
                              const char *expr)
{
    fprintf(stderr, "%s: assertion '%s' failed\n", func, expr);
}

/* Messages go to standard error in any case: no handler to replace. */
GLogFunc g_log_set_default_handler(GLogFunc func, gpointer data)
{
    return NULL;
}


void g_assertion_message_expr(const char *domain, const char *file, int line,
                              const char *func, const char *expr)
{
    fprintf(stderr, "%s:%d:%s: assertion failed: (%s)\n", file, line, func,
            expr ? expr : "code should not be reached");
    fflush(stderr);
    __fastfail(FAST_FAIL_FATAL_APP_EXIT);
}
