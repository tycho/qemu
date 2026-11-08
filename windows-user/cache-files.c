/*
 * xtajit: the translation cache's files (tcg-cache.h) on Windows: the
 * fingerprint, the directory and its ownership, and the NT side of the
 * directory back end (TCGCacheDirOps, tcg/tcg-cache-dir.c.inc).  The
 * setting cachefiles turns them on, with cache.
 *
 * The directory is XTCG_CACHE_DIR, or %LOCALAPPDATA%\xtcg\cache, then a
 * directory named by the fingerprint: a hash of everything that changes
 * the code a translation gives (the module's build, its resolved
 * settings, the guest CPU, the host's features), so that another build or
 * setting never reads it.
 *
 * Each of those directories is opened by handle, and refused if it is
 * itself a reparse point; the path above it (the profile, or
 * XTCG_CACHE_DIR's parents) is resolved as Windows resolves any path.
 * One that doesn't exist is created owned by the user, with a DACL
 * granting the user and SYSTEM alone; one that exists must be owned by
 * the user and grant write access to nobody else, or the files are off.
 * Each file is opened relative to the directory's handle and checked the
 * same way, else skipped.  Files are read with NtReadFile at
 * an offset, and mapped above 4 GiB, outside a WOW64 guest's address
 * space.  Publication writes a temporary file, then renames it without
 * replacing, allocating nothing and taking no lock.
 *
 * Copyright (c) 2026 Steven Noonan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "qemu/cacheinfo.h"
#include "qemu/log.h"
#include "qom/object.h"
#include "qemu/accel.h"
#include "host/cpuinfo.h"
#include "tcg/startup.h"
#include "tcg/tcg.h"
#include "tcg/tcg-cache.h"
#include "exec/translation-block.h"
#include "xtajit.h"

NTSTATUS NTAPI NtReadFile(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK,
                          PVOID, ULONG, PLARGE_INTEGER, PULONG);
NTSTATUS NTAPI NtQueryDirectoryFile(HANDLE, HANDLE, PVOID, PVOID,
                                    PIO_STATUS_BLOCK, PVOID, ULONG,
                                    FILE_INFORMATION_CLASS, BOOLEAN,
                                    PUNICODE_STRING, BOOLEAN);
NTSTATUS NTAPI NtQuerySecurityObject(HANDLE, SECURITY_INFORMATION,
                                     PSECURITY_DESCRIPTOR, ULONG, PULONG);
NTSTATUS NTAPI NtCreateSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                               PLARGE_INTEGER, ULONG, ULONG, HANDLE);
NTSTATUS NTAPI NtMapViewOfSectionEx(HANDLE, HANDLE, PVOID *, PLARGE_INTEGER,
                                    PSIZE_T, ULONG, ULONG,
                                    MEM_EXTENDED_PARAMETER *, ULONG);
NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
NTSTATUS NTAPI NtOpenProcessToken(HANDLE, ACCESS_MASK, PHANDLE);
NTSTATUS NTAPI NtQueryInformationToken(HANDLE, TOKEN_INFORMATION_CLASS,
                                       PVOID, ULONG, PULONG);
NTSTATUS NTAPI RtlCreateSecurityDescriptor(PSECURITY_DESCRIPTOR, ULONG);
NTSTATUS NTAPI RtlSetOwnerSecurityDescriptor(PSECURITY_DESCRIPTOR, PSID,
                                             BOOLEAN);
NTSTATUS NTAPI RtlSetDaclSecurityDescriptor(PSECURITY_DESCRIPTOR, BOOLEAN,
                                            PACL, BOOLEAN);
NTSTATUS NTAPI RtlGetOwnerSecurityDescriptor(PSECURITY_DESCRIPTOR, PSID *,
                                             PBOOLEAN);
NTSTATUS NTAPI RtlGetDaclSecurityDescriptor(PSECURITY_DESCRIPTOR, PBOOLEAN,
                                            PACL *, PBOOLEAN);
NTSTATUS NTAPI RtlCreateAcl(PACL, ULONG, ULONG);
NTSTATUS NTAPI RtlAddAccessAllowedAceEx(PACL, ULONG, ULONG, ACCESS_MASK,
                                        PSID);
NTSTATUS NTAPI RtlGetAce(PACL, ULONG, void **ace);
BOOLEAN NTAPI RtlEqualSid(PSID, PSID);
ULONG NTAPI RtlLengthSid(PSID);
BOOLEAN NTAPI RtlValidSid(PSID);

#define XT_STATUS_OBJECT_NAME_COLLISION ((NTSTATUS)0xC0000035)
#define XT_FILE_OPEN 1
#define XT_FILE_CREATE 2
#define XT_FILE_OPEN_IF 3
#define XT_FILE_DIRECTORY_FILE 0x01
#define XT_FILE_SYNCHRONOUS_IO_NONALERT 0x20
#define XT_FILE_NON_DIRECTORY_FILE 0x40
#define XT_FILE_OPEN_REPARSE_POINT 0x200000
#define XT_HIGH_BASE 0x100000000ull

typedef struct XtFileDisposition {
    BOOLEAN DeleteFile;
} XtFileDisposition;

/* Anything that changes a file or a directory's entries, or its rights. */
#define XT_WRITE_RIGHTS (GENERIC_WRITE | GENERIC_ALL | WRITE_DAC |      \
                         WRITE_OWNER | DELETE | FILE_WRITE_DATA |       \
                         FILE_APPEND_DATA | FILE_WRITE_EA |             \
                         FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD)

bool xt_cache_files;

static HANDLE dir_h;
static union {
    SID sid;
    uint8_t b[SECURITY_MAX_SID_SIZE];
} user_sid;
static SID system_sid = {
    SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_LOCAL_SYSTEM_RID }
};
static SECURITY_DESCRIPTOR sd_dir, sd_file;
static uint64_t acl_dir[32], acl_file[32];

/* The user and SYSTEM, full access; inherited by a directory's files. */
static bool make_sd(SECURITY_DESCRIPTOR *sd, void *acl, size_t acl_size,
                    ULONG inherit)
{
    if (RtlCreateSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION) < 0 ||
        RtlCreateAcl(acl, acl_size, ACL_REVISION) < 0 ||
        RtlAddAccessAllowedAceEx(acl, ACL_REVISION, inherit, FILE_ALL_ACCESS,
                                 &user_sid.sid) < 0 ||
        RtlAddAccessAllowedAceEx(acl, ACL_REVISION, inherit, FILE_ALL_ACCESS,
                                 &system_sid) < 0 ||
        RtlSetDaclSecurityDescriptor(sd, TRUE, acl, FALSE) < 0 ||
        RtlSetOwnerSecurityDescriptor(sd, &user_sid.sid, FALSE) < 0) {
        return false;
    }
    sd->Control |= SE_DACL_PROTECTED;
    return true;
}

static bool get_user(void)
{
    union {
        TOKEN_USER tu;
        uint8_t b[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    } u;
    HANDLE tok;
    ULONG n;
    NTSTATUS st;

    if (NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok) < 0) {
        return false;
    }
    st = NtQueryInformationToken(tok, TokenUser, &u, sizeof(u), &n);
    NtClose(tok);
    if (st < 0 || !RtlValidSid(u.tu.User.Sid) ||
        RtlLengthSid(u.tu.User.Sid) > sizeof(user_sid)) {
        return false;
    }
    memcpy(&user_sid, u.tu.User.Sid, RtlLengthSid(u.tu.User.Sid));
    return true;
}

/*
 * @h's file is the user's and nobody else may change it: not a reparse
 * point, a directory iff @dir, owned by the user, and its DACL granting
 * write access to no one but the user and SYSTEM.  Its size in @sizep.
 */
static bool nt_owned(HANDLE h, bool dir, size_t *sizep)
{
    union {
        SECURITY_DESCRIPTOR_RELATIVE sd;
        uint64_t b[512];
    } sd;
    FILE_ATTRIBUTE_TAG_INFO tag;
    FILE_STANDARD_INFORMATION std;
    IO_STATUS_BLOCK io;
    PSID owner;
    PACL dacl;
    BOOLEAN def, present;
    ULONG need;

    if (NtQueryInformationFile(h, &io, &tag, sizeof(tag),
                               FileAttributeTagInformation) < 0 ||
        (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        NtQueryInformationFile(h, &io, &std, sizeof(std),
                               FileStandardInformation) < 0 ||
        !std.Directory != !dir || std.EndOfFile.QuadPart < 0) {
        return false;
    }
    if (NtQuerySecurityObject(h, OWNER_SECURITY_INFORMATION |
                              DACL_SECURITY_INFORMATION, &sd, sizeof(sd),
                              &need) < 0 ||
        RtlGetOwnerSecurityDescriptor(&sd, &owner, &def) < 0 || !owner ||
        !RtlEqualSid(owner, &user_sid.sid) ||
        RtlGetDaclSecurityDescriptor(&sd, &present, &dacl, &def) < 0 ||
        !present || !dacl) {
        return false;
    }
    for (ULONG i = 0; i < dacl->AceCount; i++) {
        ACE_HEADER *a;
        ACCESS_ALLOWED_ACE *aa;

        if (RtlGetAce(dacl, i, (PVOID *)&a) < 0) {
            return false;
        }
        if ((a->AceFlags & INHERIT_ONLY_ACE) ||
            a->AceType == ACCESS_DENIED_ACE_TYPE) {
            continue;
        }
        if (a->AceType != ACCESS_ALLOWED_ACE_TYPE) {
            return false;
        }
        aa = (ACCESS_ALLOWED_ACE *)a;
        if ((aa->Mask & XT_WRITE_RIGHTS) &&
            !RtlEqualSid((PSID)&aa->SidStart, &user_sid.sid) &&
            !RtlEqualSid((PSID)&aa->SidStart, &system_sid)) {
            return false;
        }
    }
    if (sizep) {
        *sizep = std.EndOfFile.QuadPart;
    }
    return true;
}

static void nt_name(UNICODE_STRING *us, WCHAR *w, const char *name)
{
    int n = 0;

    while (name[n] && n < 63) {
        w[n] = (unsigned char)name[n];
        n++;
    }
    w[n] = 0;
    us->Buffer = w;
    us->Length = n * sizeof(WCHAR);
    us->MaximumLength = us->Length + sizeof(WCHAR);
}

/* Open, or create as ours, directory @name under @root; checked. */
static HANDLE nt_open_dir(HANDLE root, const WCHAR *name, size_t len)
{
    UNICODE_STRING us = {
        .Buffer = (PWSTR)name, .Length = len * sizeof(WCHAR),
        .MaximumLength = len * sizeof(WCHAR),
    };
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK io;
    HANDLE h;

    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, root, &sd_dir);
    if (NtCreateFile(&h, FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_TRAVERSE |
                     FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE, &oa,
                     &io, NULL, FILE_ATTRIBUTE_NORMAL,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                     XT_FILE_OPEN_IF, XT_FILE_DIRECTORY_FILE |
                     XT_FILE_SYNCHRONOUS_IO_NONALERT |
                     XT_FILE_OPEN_REPARSE_POINT, NULL, 0) < 0) {
        return NULL;
    }
    if (!nt_owned(h, true, NULL)) {
        NtClose(h);
        return NULL;
    }
    return h;
}

/* The NT side of the directory back end. */

static int nt_list(char (*names)[64], int max)
{
    UNICODE_STRING us = { 0 };
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK io;
    uint64_t buf[2048];
    BOOLEAN restart = TRUE;
    int n = 0, seen = 0;
    HANDLE h;

    /* Its own handle: the directory's scan position is the handle's. */
    InitializeObjectAttributes(&oa, &us, 0, dir_h, NULL);
    if (NtOpenFile(&h, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &io,
                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                   XT_FILE_DIRECTORY_FILE | XT_FILE_SYNCHRONOUS_IO_NONALERT |
                   XT_FILE_OPEN_REPARSE_POINT) < 0) {
        return 0;
    }
    while (n < max && seen < max) {
        FILE_DIRECTORY_INFORMATION *e = (void *)buf;

        if (NtQueryDirectoryFile(h, NULL, NULL, NULL, &io, buf, sizeof(buf),
                                 FileDirectoryInformation, FALSE, NULL,
                                 restart) < 0) {
            break;
        }
        restart = FALSE;
        for (;;) {
            ULONG len = e->FileNameLength / sizeof(WCHAR);
            bool ok = !(e->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                      len < 64;

            seen++;
            for (ULONG i = 0; ok && i < len; i++) {
                ok = e->FileName[i] > ' ' && e->FileName[i] < 0x7f;
            }
            if (ok) {
                memset(names[n], 0, 64);
                for (ULONG i = 0; i < len; i++) {
                    names[n][i] = e->FileName[i];
                }
                n++;
            }
            if (!e->NextEntryOffset || n >= max || seen >= max) {
                break;
            }
            e = (void *)((uint8_t *)e + e->NextEntryOffset);
        }
    }
    NtClose(h);
    return n;
}

static void *nt_open(const char *name, size_t *sizep)
{
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK io;
    WCHAR w[64];
    HANDLE h;

    nt_name(&us, w, name);
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, dir_h, NULL);
    if (NtCreateFile(&h, FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL |
                     SYNCHRONIZE, &oa, &io, NULL, 0,
                     FILE_SHARE_READ | FILE_SHARE_DELETE, XT_FILE_OPEN,
                     XT_FILE_NON_DIRECTORY_FILE |
                     XT_FILE_SYNCHRONOUS_IO_NONALERT |
                     XT_FILE_OPEN_REPARSE_POINT, NULL, 0) < 0) {
        return NULL;
    }
    if (!nt_owned(h, false, sizep)) {
        NtClose(h);
        return NULL;
    }
    return h;
}

static int64_t nt_read(void *fh, void *dst, uint64_t off, size_t len)
{
    LARGE_INTEGER at = { .QuadPart = off };
    IO_STATUS_BLOCK io;

    if (len > UINT32_MAX ||
        NtReadFile(fh, NULL, NULL, NULL, &io, dst, len, &at, NULL) < 0 ||
        io.Information != len) {
        return TCG_CACHE_GFAULT;
    }
    return 0;
}

static void *user_max;

static const void *nt_map(void *fh, size_t size)
{
    LARGE_INTEGER max = { .QuadPart = size }, off = { 0 };
    MEM_ADDRESS_REQUIREMENTS req = {
        .LowestStartingAddress = (void *)XT_HIGH_BASE,
        .HighestEndingAddress = user_max,
    };
    MEM_EXTENDED_PARAMETER ext = {
        .Type = MemExtendedParameterAddressRequirements, .Pointer = &req,
    };
    PVOID base = NULL;
    SIZE_T view = 0;
    HANDLE sec;
    NTSTATUS st;

    st = NtCreateSection(&sec, SECTION_MAP_READ | SECTION_QUERY, NULL, &max,
                         PAGE_READONLY, SEC_COMMIT, fh);
    if (st < 0) {
        if (tcg_cache_debug) {
            fprintf(stderr, "xtcg-cache map: section %lx\n", st);
        }
        return NULL;
    }
    st = NtMapViewOfSectionEx(sec, GetCurrentProcess(), &base, &off, &view, 0,
                              PAGE_READONLY, &ext, 1);
    NtClose(sec);
    if (tcg_cache_debug) {
        fprintf(stderr, "xtcg-cache map: %zu bytes at %p (%lx)\n", size, base,
                st);
    }
    return st < 0 ? NULL : base;
}

static void nt_close(void *fh)
{
    NtClose(fh);
}

static void nt_unmap(const void *map, size_t size)
{
    NtUnmapViewOfSection(GetCurrentProcess(), (PVOID)map);
}

static TCGCacheDirOps nt_ops;

static bool nt_publish(const void *data, size_t len, const char *name,
                       unsigned pause_ms)
{
    static uint64_t counter;
    union {
        FILE_RENAME_INFORMATION r;
        uint8_t b[sizeof(FILE_RENAME_INFORMATION) + 64 * sizeof(WCHAR)];
    } ri;
    XtFileDisposition del = { TRUE };
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK io;
    char tmp[64];
    WCHAR w[64];
    size_t done = 0;
    HANDLE h = NULL;
    NTSTATUS st = -1;
    int n;

    /* Created exclusively: a name taken, the next, then give up. */
    for (int i = 0; i < 4; i++) {
        snprintf(tmp, sizeof(tmp), "tmp-%x-%" PRIx64, nt_ops.pid,
                 qatomic_fetch_inc(&counter));
        nt_name(&us, w, tmp);
        InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, dir_h,
                                   &sd_file);
        st = NtCreateFile(&h, FILE_WRITE_DATA | DELETE | SYNCHRONIZE, &oa,
                          &io, NULL, FILE_ATTRIBUTE_NORMAL, 0, XT_FILE_CREATE,
                          XT_FILE_NON_DIRECTORY_FILE |
                          XT_FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (st != XT_STATUS_OBJECT_NAME_COLLISION) {
            break;
        }
    }
    if (st < 0) {
        return false;
    }
    while (done < len) {
        LARGE_INTEGER at = { .QuadPart = done };
        ULONG chunk = MIN(len - done, 1u << 20);

        if (NtWriteFile(h, NULL, NULL, NULL, &io, (uint8_t *)data + done,
                        chunk, &at, NULL) < 0 || !io.Information) {
            break;
        }
        done += io.Information;
    }
    if (pause_ms) {
        g_usleep(pause_ms * 1000);
    }
    st = -1;
    if (done == len) {
        memset(&ri, 0, sizeof(ri));
        ri.r.ReplaceIfExists = FALSE;
        ri.r.RootDirectory = dir_h;
        for (n = 0; name[n] && n < 63; n++) {
            ri.r.FileName[n] = (unsigned char)name[n];
        }
        ri.r.FileNameLength = n * sizeof(WCHAR);
        st = NtSetInformationFile(h, &io, &ri,
                                  offsetof(FILE_RENAME_INFORMATION, FileName) +
                                  ri.r.FileNameLength, FileRenameInformation);
    }
    if (st < 0) {
        NtSetInformationFile(h, &io, &del, sizeof(del),
                             FileDispositionInformation);
    }
    NtClose(h);
    return st >= 0;
}

static TCGCacheDirOps nt_ops = {
    .list = nt_list,
    .open = nt_open,
    .read = nt_read,
    .map = nt_map,
    .close = nt_close,
    .unmap = nt_unmap,
    .publish = nt_publish,
};

/* The module's own build: the 8 bytes lld's CodeView record hashes. */
static bool build_id(uint64_t *id)
{
    const uint8_t *b = (const uint8_t *)&__ImageBase;
    const IMAGE_NT_HEADERS *nt = (const void *)(b + __ImageBase.e_lfanew);
    const IMAGE_DATA_DIRECTORY *dd =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    const IMAGE_DEBUG_DIRECTORY *d = (const void *)(b + dd->VirtualAddress);

    for (size_t i = 0; dd->VirtualAddress &&
         i < dd->Size / sizeof(*d); i++) {
        const uint8_t *cv = b + d[i].AddressOfRawData;

        if (d[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW &&
            d[i].AddressOfRawData && d[i].SizeOfData >= 24 &&
            !memcmp(cv, "RSDS", 4) && !memcmp(cv + 12, "LLD PDB.", 8)) {
            memcpy(id, cv + 4, 8);
            return *id != 0;
        }
    }
    return false;
}

static gint prop_cmp(gconstpointer a, gconstpointer b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/*
 * The fingerprint: everything that changes what a translation emits, in
 * a fixed order, hashed.  After the first CPU's prologue, which decides
 * the return stack's register.  False without the module's build ID.
 */
static bool fingerprint(CPUState *first, WCHAR *hex)
{
    g_autoptr(GString) g = g_string_new("xtcg-cache 1 windows\n");
    GPtrArray *props;
    Object *accel = OBJECT(current_accel());
    CPUX86State *env = cpu_env(first);
    ObjectPropertyIterator iter;
    ObjectProperty *prop;
    uint64_t id, h0, h1;
    char s[33];

    if (!build_id(&id)) {
        return false;
    }
    props = g_ptr_array_new();
    g_string_append_printf(g, "build %016" PRIx64 "\ntarget %s\ncpu %s\n",
                           id, TARGET_NAME, xt_cpu_model);
    g_string_append(g, "features");
    for (int i = 0; i < FEATURE_WORDS; i++) {
        g_string_append_printf(g, " %" PRIx64, (uint64_t)env->features[i]);
    }
    g_string_append_printf(g, "\ncpuid %x %x %x %x %x %x\n", env->cpuid_level,
                           env->cpuid_xlevel, env->cpuid_version,
                           env->cpuid_vendor1, env->cpuid_vendor2,
                           env->cpuid_vendor3);
    g_string_append_printf(g, "guest_addr_max %" PRIx64 "\n",
                           (uint64_t)guest_addr_max);
    g_string_append_printf(g, "page_bits %d host_page %zu\n",
                           TARGET_PAGE_BITS, qemu_real_host_page_size());
    g_string_append_printf(g, "cpuinfo %" PRIx64 " icache %d dcache %d\n",
                           (uint64_t)cpuinfo, qemu_icache_linesize,
                           qemu_dcache_linesize);
    g_string_append_printf(g, "lazysync %d pin %d partial %d native %d "
                           "retstack %d cross-faults %d\n",
                           tcg_lazysync_user, tcg_pin_user,
                           xt_fault_context_partial, xt_native_harness,
                           tcg_retstack, tcg_tso_cross_faults);
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
        g_free(g_ptr_array_index(props, i));
    }
    g_ptr_array_free(props, TRUE);
    h0 = tcg_cache_hash64(0, g->str, g->len);
    h1 = tcg_cache_hash64(1, g->str, g->len);
    stq_le_p(tcg_cache_fingerprint, h0);
    stq_le_p(tcg_cache_fingerprint + 8, h1);
    snprintf(s, sizeof(s), "%016" PRIx64 "%016" PRIx64, h0, h1);
    for (int i = 0; i < 33; i++) {
        hex[i] = (unsigned char)s[i];
    }
    if (getenv("XTCG_CACHE_FPSHOW")) {
        fprintf(stderr, "xtcg-cache fingerprint %s:\n%s", s, g->str);
    }
    return true;
}

/* An environment variable's value, wide, in @buf; its length or 0. */
static size_t env_wide(const WCHAR *name, WCHAR *buf, size_t size)
{
    UNICODE_STRING us;
    SIZE_T n = 0;

    for (us.Length = 0; name[us.Length / sizeof(WCHAR)]; us.Length += 2) {
    }
    if (RtlQueryEnvironmentVariable(NULL, (PWSTR)name,
                                    us.Length / sizeof(WCHAR), buf, size - 1,
                                    &n) < 0) {
        return 0;
    }
    buf[n] = 0;
    return n;
}

/* Open the absolute (Win32) path @path as a directory: \??\ before it. */
static HANDLE open_abs(const WCHAR *path, size_t len, bool checked)
{
    WCHAR full[300];
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK io;
    size_t k = 0;
    HANDLE h;

    if (len > ARRAY_SIZE(full) - 8) {
        return NULL;
    }
    for (const char *p = "\\??\\"; *p; p++) {
        full[k++] = *p;
    }
    memcpy(full + k, path, len * sizeof(WCHAR));
    k += len;
    if (checked) {
        return nt_open_dir(NULL, full, k);
    }
    us.Buffer = full;
    us.Length = us.MaximumLength = k * sizeof(WCHAR);
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (NtOpenFile(&h, FILE_TRAVERSE | SYNCHRONIZE, &oa, &io,
                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                   XT_FILE_DIRECTORY_FILE |
                   XT_FILE_SYNCHRONOUS_IO_NONALERT) < 0) {
        return NULL;
    }
    return h;
}

/*
 * After the first CPU: the fingerprint, the directory, then the first
 * snapshot (here, so that a short process's first TBs can hit) and the
 * writer.
 */
void xt_cache_files_init(CPUState *first)
{
    WCHAR base[260], hex[33];
    XtBasicInfo sbi;
    LARGE_INTEGER now;
    int64_t t0 = get_clock();
    size_t n;
    HANDLE b = NULL, h;

    if (!xt_cache_files || tcg_cache_mode != TCG_CACHE_ON) {
        return;
    }
#ifdef TARGET_X86_64
    /*
     * Not yet: the x64 module has no termination calls to stop the writer
     * before the process kills it, and a writer killed holding the sink's
     * lock would leave a capture at exit waiting for it forever.
     */
    fprintf(stderr, "xtcg-cache: files: the WOW64 module only\n");
    return;
#endif
    if (NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi),
                                 NULL) < 0) {
        return;
    }
    user_max = (void *)sbi.MaximumUserModeAddress;
    if (!get_user() ||
        !make_sd(&sd_dir, acl_dir, sizeof(acl_dir),
                 OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) ||
        !make_sd(&sd_file, acl_file, sizeof(acl_file), 0)) {
        fprintf(stderr, "xtcg-cache: no user: files off\n");
        return;
    }
    if (!fingerprint(first, hex)) {
        fprintf(stderr, "xtcg-cache: no build ID: files off\n");
        return;
    }
    n = env_wide(L"XTCG_CACHE_DIR", base, ARRAY_SIZE(base));
    if (n) {
        b = open_abs(base, n, true);
    }
    n = n ? 0 : env_wide(L"LOCALAPPDATA", base, ARRAY_SIZE(base));
    if (n) {
        HANDLE root = open_abs(base, n, false);

        h = root ? nt_open_dir(root, L"xtcg", 4) : NULL;
        b = h ? nt_open_dir(h, L"cache", 5) : NULL;
        if (root) {
            NtClose(root);
        }
        if (h) {
            NtClose(h);
        }
    }
    if (!b) {
        fprintf(stderr, "xtcg-cache: no directory of ours: files off\n");
        return;
    }
    dir_h = nt_open_dir(b, hex, 32);
    NtClose(b);
    if (!dir_h) {
        fprintf(stderr, "xtcg-cache: the fingerprint's directory isn't "
                "ours: files off\n");
        return;
    }
    NtQuerySystemTime(&now);
    tcg_cache_born = (now.QuadPart / 10000000 - 11644473600ll) / 86400;
    nt_ops.pid = GetCurrentProcessId();
    tcg_cache_dir_start(&nt_ops, t0);
}
