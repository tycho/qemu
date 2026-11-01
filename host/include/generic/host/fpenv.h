/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Host floating-point control and status registers: no host support.
 */

#ifndef HOST_FPENV_H
#define HOST_FPENV_H

static inline bool host_fpenv_native(void)
{
    return false;
}

#define HOST_FP_CONTROL_QEMU    0

static inline uint64_t host_fp_control_read(void)
{
    return 0;
}

static inline void host_fp_control_write(uint64_t v)
{
}

static inline uint64_t host_fp_status_read(void)
{
    return 0;
}

static inline void host_fp_status_write(uint64_t v)
{
}

#endif /* HOST_FPENV_H */
