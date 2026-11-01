/*
 * tpm-sysbus.c - Support functions for SysBus TPM devices
 *
 * Copyright (c) 2023 QEMU contributors
 *
 * Authors:
 *   Joelle van Dyne <j@getutm.app>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "system/tpm.h"
#include "hw/core/platform-bus.h"
#include "hw/core/sysbus.h"
#include "qapi/error.h"

/*
 * Called from a machine's plug handler, once the platform bus has mapped
 * the device: tell it its physical address, which a CRB device puts in its
 * registers and the TPM2 ACPI table.
 */
void tpm_sysbus_plug(TPMIf *tpmif, Object *pbus, hwaddr pbus_base)
{
    PlatformBusDevice *pbusdev = PLATFORM_BUS_DEVICE(pbus);
    SysBusDevice *sbdev = SYS_BUS_DEVICE(tpmif);
    MemoryRegion *sbdev_mr;
    hwaddr tpm_base;
    uint64_t tpm_size;

    /* only the CRB device takes its address */
    if (!TPM_IS_CRB_SYSBUS(tpmif)) {
        return;
    }

    tpm_base = platform_bus_get_mmio_addr(pbusdev, sbdev, 0);
    assert(tpm_base != -1);

    tpm_base += pbus_base;

    sbdev_mr = sysbus_mmio_get_region(sbdev, 0);
    tpm_size = memory_region_size(sbdev_mr);

    object_property_set_uint(OBJECT(sbdev), "x-baseaddr",
                             tpm_base, &error_abort);
    object_property_set_uint(OBJECT(sbdev), "x-size",
                             tpm_size, &error_abort);
}
