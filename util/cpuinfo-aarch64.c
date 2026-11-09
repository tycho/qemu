/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Host specific cpu identification for AArch64.
 */

#include "qemu/osdep.h"
#include "host/cpuinfo.h"

#ifdef CONFIG_LINUX
# ifdef CONFIG_GETAUXVAL
#  include <sys/auxv.h>
# else
#  include <asm/hwcap.h>
#  include "elf.h"
# endif
# ifndef HWCAP2_BTI
#  define HWCAP2_BTI 0  /* added in glibc 2.32 */
# endif
# ifndef HWCAP2_CSSC
#  define HWCAP2_CSSC 0  /* added in glibc 2.38 */
# endif
# ifndef HWCAP2_LRCPC3
#  define HWCAP2_LRCPC3 (1ul << 46)  /* kernel ABI; not in glibc 2.39 */
# endif
# ifndef HWCAP_LRCPC
#  define HWCAP_LRCPC 0
# endif
# ifndef HWCAP_ILRCPC
#  define HWCAP_ILRCPC 0
# endif
# ifndef HWCAP_ASIMDDP
#  define HWCAP_ASIMDDP 0
# endif
# ifndef HWCAP2_I8MM
#  define HWCAP2_I8MM 0
# endif
# ifndef HWCAP2_AFP
#  define HWCAP2_AFP 0  /* added in glibc 2.35 */
# endif
# ifndef HWCAP2_RPRES
#  define HWCAP2_RPRES 0  /* added in glibc 2.35 */
# endif
# ifndef HWCAP2_FRINT
#  define HWCAP2_FRINT 0
# endif
#endif
#ifdef CONFIG_ELF_AUX_INFO
#include <sys/auxv.h>
#endif
#ifdef CONFIG_DARWIN
# include <sys/sysctl.h>
#endif
#ifdef _WIN32
# include <winternl.h>
#endif
#if defined(__OpenBSD__) && !defined(CONFIG_ELF_AUX_INFO)
# include <machine/armreg.h>
# include <machine/cpu.h>
# include <sys/sysctl.h>
#endif

unsigned cpuinfo;

#ifdef CONFIG_DARWIN
static bool sysctl_for_bool(const char *name)
{
    int val = 0;
    size_t len = sizeof(val);

    if (sysctlbyname(name, &val, &len, NULL, 0) == 0) {
        return val != 0;
    }

    /*
     * We might in the future ask for properties not present in older kernels,
     * but we're only asking about static properties, all of which should be
     * 'int'.  So we shouldn't see ENOMEM (val too small), or any of the other
     * more exotic errors.
     */
    assert(errno == ENOENT);
    return false;
}
#endif

#ifdef _WIN32
NTSTATUS NTAPI NtOpenKey(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSTATUS NTAPI NtQueryValueKey(HANDLE, PUNICODE_STRING, int, PVOID, ULONG,
                               PULONG);

/* An unsigned 4-bit field of an ID register. */
#define ID_FIELD(reg, lsb)  (((reg) >> (lsb)) & 0xf)

/*
 * Windows has no hwcaps or sysctl, but records each processor's ID
 * registers in the registry: REG_QWORD values named "CP " and the
 * register's MRS encoding in hex (op0 bit 0, op1, CRn, CRm, op2), so
 * ID_AA64ISAR0_EL1 is "CP 4030".  Processor 0's are read, through ntdll
 * alone, so that code loaded before kernel32 and advapi32 can run this.
 */
static HANDLE win32_cpu_key(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES oa;
    HANDLE key;

    RtlInitUnicodeString(&name, L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION"
                         L"\\System\\CentralProcessor\\0");
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtOpenKey(&key, KEY_QUERY_VALUE, &oa) < 0 ? NULL : key;
}

/* An ID register's value, or 0 (no features) if Windows doesn't list it. */
static uint64_t win32_id_reg(HANDLE key, const wchar_t *value)
{
    /* KEY_VALUE_PARTIAL_INFORMATION, with room for a REG_QWORD. */
    struct {
        ULONG title_index;
        ULONG type;
        ULONG length;
        UCHAR data[8];
    } info;
    UNICODE_STRING name;
    ULONG len;
    uint64_t reg;

    RtlInitUnicodeString(&name, value);
    if (NtQueryValueKey(key, &name, 2 /* KeyValuePartialInformation */,
                        &info, sizeof(info), &len) < 0 ||
        info.type != REG_QWORD || info.length != sizeof(reg)) {
        return 0;
    }
    memcpy(&reg, info.data, sizeof(reg));
    return reg;
}

uint64_t cpuinfo_win32_ctr_el0(void)
{
    HANDLE key = win32_cpu_key();
    uint64_t ctr = 0;

    if (key) {
        ctr = win32_id_reg(key, L"CP 5801");
        NtClose(key);
    }
    return ctr;
}
#endif

/* Called both as constructor and (possibly) via other constructors. */
unsigned __attribute__((constructor)) cpuinfo_init(void)
{
    unsigned info = cpuinfo;

    if (info) {
        return info;
    }

    info = CPUINFO_ALWAYS;

#if defined(CONFIG_LINUX) || defined(CONFIG_ELF_AUX_INFO)
    unsigned long hwcap = qemu_getauxval(AT_HWCAP);
    info |= (hwcap & HWCAP_ATOMICS ? CPUINFO_LSE : 0);
    info |= (hwcap & HWCAP_USCAT ? CPUINFO_LSE2 : 0);
    info |= (hwcap & HWCAP_AES ? CPUINFO_AES : 0);
    info |= (hwcap & HWCAP_PMULL ? CPUINFO_PMULL : 0);
    info |= (hwcap & HWCAP_LRCPC ? CPUINFO_LRCPC : 0);
    info |= (hwcap & HWCAP_ILRCPC ? CPUINFO_LRCPC2 : 0);
    info |= (hwcap & HWCAP_SHA1 ? CPUINFO_SHA1 : 0);
    info |= (hwcap & HWCAP_SHA2 ? CPUINFO_SHA2 : 0);
    info |= (hwcap & HWCAP_CRC32 ? CPUINFO_CRC32 : 0);
    info |= (hwcap & HWCAP_ASIMDDP ? CPUINFO_DOTPROD : 0);

    unsigned long hwcap2 = qemu_getauxval(AT_HWCAP2);
    info |= (hwcap2 & HWCAP2_BTI ? CPUINFO_BTI : 0);
    info |= (hwcap2 & HWCAP2_LRCPC3 ? CPUINFO_LRCPC3 : 0);
    info |= (hwcap2 & HWCAP2_CSSC ? CPUINFO_CSSC : 0);
    info |= (hwcap2 & HWCAP2_AFP ? CPUINFO_AFP : 0);
    info |= (hwcap2 & HWCAP2_RPRES ? CPUINFO_RPRES : 0);
    info |= (hwcap2 & HWCAP2_FRINT ? CPUINFO_FRINTTS : 0);
    info |= (hwcap2 & HWCAP2_I8MM ? CPUINFO_I8MM : 0);
#endif
#ifdef CONFIG_DARWIN
    info |= sysctl_for_bool("hw.optional.arm.FEAT_LSE") * CPUINFO_LSE;
    info |= sysctl_for_bool("hw.optional.arm.FEAT_LSE2") * CPUINFO_LSE2;
    info |= sysctl_for_bool("hw.optional.arm.FEAT_AES") * CPUINFO_AES;
    info |= sysctl_for_bool("hw.optional.arm.FEAT_PMULL") * CPUINFO_PMULL;
    info |= sysctl_for_bool("hw.optional.arm.FEAT_SHA1") * CPUINFO_SHA1;
    info |= sysctl_for_bool("hw.optional.arm.FEAT_SHA256") * CPUINFO_SHA2;
    info |= sysctl_for_bool("hw.optional.arm.FEAT_CRC32") * CPUINFO_CRC32;
    info |= sysctl_for_bool("hw.optional.arm.FEAT_DotProd") * CPUINFO_DOTPROD;
    info |= sysctl_for_bool("hw.optional.arm.FEAT_I8MM") * CPUINFO_I8MM;
    info |= sysctl_for_bool("hw.optional.arm.FEAT_FRINTTS") * CPUINFO_FRINTTS;
    info |= sysctl_for_bool("hw.optional.arm.FEAT_BTI") * CPUINFO_BTI;
    info |= sysctl_for_bool("hw.optional.arm.FEAT_CSSC") * CPUINFO_CSSC;
    info |= sysctl_for_bool("hw.optional.arm.FEAT_LRCPC") * CPUINFO_LRCPC;
    info |= sysctl_for_bool("hw.optional.arm.FEAT_LRCPC2") * CPUINFO_LRCPC2;
    info |= sysctl_for_bool("hw.optional.arm.FEAT_LRCPC3") * CPUINFO_LRCPC3;
    info |= sysctl_for_bool("hw.optional.arm.FEAT_AFP") * CPUINFO_AFP;
    info |= sysctl_for_bool("hw.optional.arm.FEAT_RPRES") * CPUINFO_RPRES;
#endif
#ifdef _WIN32
    {
        HANDLE key = win32_cpu_key();

        if (key) {
            uint64_t isar0 = win32_id_reg(key, L"CP 4030");
            uint64_t isar1 = win32_id_reg(key, L"CP 4031");
            uint64_t isar2 = win32_id_reg(key, L"CP 4032");
            uint64_t pfr1 = win32_id_reg(key, L"CP 4021");
            uint64_t mmfr1 = win32_id_reg(key, L"CP 4039");
            uint64_t mmfr2 = win32_id_reg(key, L"CP 403A");

            NtClose(key);
            info |= ID_FIELD(isar0, 20) >= 2 ? CPUINFO_LSE : 0;
            info |= ID_FIELD(mmfr2, 32) >= 1 ? CPUINFO_LSE2 : 0;
            info |= ID_FIELD(isar0, 4) >= 1 ? CPUINFO_AES : 0;
            info |= ID_FIELD(isar0, 4) >= 2 ? CPUINFO_PMULL : 0;
            info |= ID_FIELD(isar0, 16) >= 1 ? CPUINFO_CRC32 : 0;
            info |= ID_FIELD(pfr1, 0) >= 1 ? CPUINFO_BTI : 0;
            info |= ID_FIELD(isar2, 52) >= 1 ? CPUINFO_CSSC : 0;
            info |= ID_FIELD(isar1, 20) >= 1 ? CPUINFO_LRCPC : 0;
            info |= ID_FIELD(isar1, 20) >= 2 ? CPUINFO_LRCPC2 : 0;
            info |= ID_FIELD(isar1, 20) >= 3 ? CPUINFO_LRCPC3 : 0;
            info |= ID_FIELD(mmfr1, 44) >= 1 ? CPUINFO_AFP : 0;
            info |= ID_FIELD(isar2, 4) >= 1 ? CPUINFO_RPRES : 0;
            info |= ID_FIELD(isar1, 32) >= 1 ? CPUINFO_FRINTTS : 0;
            info |= ID_FIELD(isar0, 8) >= 1 ? CPUINFO_SHA1 : 0;
            info |= ID_FIELD(isar0, 12) >= 1 ? CPUINFO_SHA2 : 0;
            info |= ID_FIELD(isar0, 44) >= 1 ? CPUINFO_DOTPROD : 0;
            info |= ID_FIELD(isar1, 52) >= 1 ? CPUINFO_I8MM : 0;
        } else {
            /*
             * The processor features the kernel publishes in
             * KUSER_SHARED_DATA, which IsProcessorFeaturePresent returns
             * for indexes below 64.
             */
            const volatile uint8_t *pf = (const volatile uint8_t *)0x7ffe0274;

            info |= pf[PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE] ?
                    CPUINFO_LSE : 0;
            info |= pf[PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE] ?
                    CPUINFO_AES | CPUINFO_PMULL | CPUINFO_SHA1 | CPUINFO_SHA2 :
                    0;
            info |= pf[PF_ARM_V83_LRCPC_INSTRUCTIONS_AVAILABLE] ?
                    CPUINFO_LRCPC : 0;
            info |= pf[PF_ARM_V82_DP_INSTRUCTIONS_AVAILABLE] ?
                    CPUINFO_DOTPROD : 0;
            info |= pf[PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE] ?
                    CPUINFO_CRC32 : 0;
        }
    }
#endif
#if defined(__OpenBSD__) && !defined(CONFIG_ELF_AUX_INFO)
    int mib[2];
    uint64_t isar0;
    uint64_t pfr1;
    size_t len;

    mib[0] = CTL_MACHDEP;
    mib[1] = CPU_ID_AA64ISAR0;
    len = sizeof(isar0);
    if (sysctl(mib, 2, &isar0, &len, NULL, 0) != -1) {
        if (ID_AA64ISAR0_ATOMIC(isar0) >= ID_AA64ISAR0_ATOMIC_IMPL) {
            info |= CPUINFO_LSE;
        }
        if (ID_AA64ISAR0_AES(isar0) >= ID_AA64ISAR0_AES_BASE) {
            info |= CPUINFO_AES;
        }
        if (ID_AA64ISAR0_AES(isar0) >= ID_AA64ISAR0_AES_PMULL) {
            info |= CPUINFO_PMULL;
        }
    }

    mib[0] = CTL_MACHDEP;
    mib[1] = CPU_ID_AA64PFR1;
    len = sizeof(pfr1);
    if (sysctl(mib, 2, &pfr1, &len, NULL, 0) != -1) {
        if (ID_AA64PFR1_BT(pfr1) >= ID_AA64PFR1_BT_IMPL) {
            info |= CPUINFO_BTI;
        }
    }
#endif

    cpuinfo = info;
    return info;
}
