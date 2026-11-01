/*
 * tpm_crb_sysbus.c - QEMU's TPM CRB interface emulator, as a SysBus device
 *
 * Copyright (c) 2018 Red Hat, Inc.
 * Copyright (c) 2023 QEMU contributors
 *
 * Authors:
 *   Marc-André Lureau <marcandre.lureau@redhat.com>
 *   Joelle van Dyne <j@getutm.app>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * tpm-crb-device is a TPM 2.0 Command Response Buffer (CRB) Interface, as
 * defined in TCG PC Client Platform TPM Profile (PTP) Specification Family
 * "2.0" Level 00 Revision 01.03 v22, for machines that place it on a
 * platform bus (arm virt).
 *
 * The registers and the data buffer are one ROM device: the guest reads
 * them as memory and only its writes trap.  Hypervisors that can't emulate
 * every load the guest uses on MMIO (HVF reports no syndrome for load pairs
 * and post-indexed loads) can then run the guest's TPM driver.  The region
 * is a multiple of the host page size, so that it can be mapped into the
 * guest.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/core/qdev-properties.h"
#include "hw/core/sysbus.h"
#include "hw/pci/pci_ids.h"
#include "hw/acpi/tpm.h"
#include "migration/vmstate.h"
#include "system/tpm_backend.h"
#include "system/tpm_util.h"
#include "tpm_prop.h"
#include "trace.h"
#include "qom/object.h"

#define CRB_CTRL_CMD_SIZE (TPM_CRB_ADDR_SIZE - A_CRB_DATA_BUFFER)

#define CRB_INTF_TYPE_CRB_ACTIVE 0b1
#define CRB_INTF_VERSION_CRB 0b1
#define CRB_INTF_CAP_LOCALITY_0_ONLY 0b0
#define CRB_INTF_CAP_IDLE_FAST 0b0
#define CRB_INTF_CAP_XFER_SIZE_64 0b11
#define CRB_INTF_CAP_FIFO_NOT_SUPPORTED 0b0
#define CRB_INTF_CAP_CRB_SUPPORTED 0b1
#define CRB_INTF_IF_SELECTOR_CRB 0b1

enum crb_loc_ctrl {
    CRB_LOC_CTRL_REQUEST_ACCESS = BIT(0),
    CRB_LOC_CTRL_RELINQUISH = BIT(1),
    CRB_LOC_CTRL_SEIZE = BIT(2),
    CRB_LOC_CTRL_RESET_ESTABLISHMENT_BIT = BIT(3),
};

enum crb_ctrl_req {
    CRB_CTRL_REQ_CMD_READY = BIT(0),
    CRB_CTRL_REQ_GO_IDLE = BIT(1),
};

enum crb_start {
    CRB_START_INVOKE = BIT(0),
};

enum crb_cancel {
    CRB_CANCEL_INVOKE = BIT(0),
};

#define TPM_CRB_NO_LOCALITY 0xff

struct TPMCRBStateSysBus {
    /*< private >*/
    SysBusDevice parent_obj;

    /*< public >*/
    TPMBackend *tpmbe;
    TPMBackendCmd cmd;
    MemoryRegion mmio;
    size_t be_buffer_size;

    /* Set by the machine when it maps the device (tpm_sysbus_plug). */
    uint64_t baseaddr;
    uint64_t size;
};

OBJECT_DECLARE_SIMPLE_TYPE(TPMCRBStateSysBus, TPM_CRB_SYSBUS)

static uint8_t tpm_crb_get_active_locty(uint32_t *regs)
{
    if (!ARRAY_FIELD_EX32(regs, CRB_LOC_STATE, locAssigned)) {
        return TPM_CRB_NO_LOCALITY;
    }
    return ARRAY_FIELD_EX32(regs, CRB_LOC_STATE, activeLocality);
}

static void tpm_crb_mmio_write(void *opaque, hwaddr addr,
                               uint64_t val, unsigned size)
{
    TPMCRBStateSysBus *s = opaque;
    uint8_t locty = addr >> 12;
    uint32_t *regs = memory_region_get_ram_ptr(&s->mmio);
    void *mem = &regs[R_CRB_DATA_BUFFER];

    trace_tpm_crb_mmio_write(addr, size, val);

    /* TPM command bytes go to the data buffer */
    if (addr >= A_CRB_DATA_BUFFER) {
        if (addr + size <= TPM_CRB_ADDR_SIZE) {
            memcpy(mem + addr - A_CRB_DATA_BUFFER, &val, size);
            memory_region_set_dirty(&s->mmio, addr, size);
        }
        return;
    }

    switch (addr) {
    case A_CRB_CTRL_REQ:
        switch (val) {
        case CRB_CTRL_REQ_CMD_READY:
            ARRAY_FIELD_DP32(regs, CRB_CTRL_STS, tpmIdle, 0);
            break;
        case CRB_CTRL_REQ_GO_IDLE:
            ARRAY_FIELD_DP32(regs, CRB_CTRL_STS, tpmIdle, 1);
            break;
        }
        break;
    case A_CRB_CTRL_CANCEL:
        if (val == CRB_CANCEL_INVOKE &&
            regs[R_CRB_CTRL_START] & CRB_START_INVOKE) {
            tpm_backend_cancel_cmd(s->tpmbe);
        }
        break;
    case A_CRB_CTRL_START:
        if (val == CRB_START_INVOKE &&
            !(regs[R_CRB_CTRL_START] & CRB_START_INVOKE) &&
            tpm_crb_get_active_locty(regs) == locty) {
            regs[R_CRB_CTRL_START] |= CRB_START_INVOKE;
            s->cmd = (TPMBackendCmd) {
                .in = mem,
                .in_len = MIN(tpm_cmd_get_size(mem), s->be_buffer_size),
                .out = mem,
                .out_len = s->be_buffer_size,
            };

            tpm_backend_deliver_request(s->tpmbe, &s->cmd);
        }
        break;
    case A_CRB_LOC_CTRL:
        switch (val) {
        case CRB_LOC_CTRL_RESET_ESTABLISHMENT_BIT:
            /* not loc 3 or 4 */
            break;
        case CRB_LOC_CTRL_RELINQUISH:
            ARRAY_FIELD_DP32(regs, CRB_LOC_STATE, locAssigned, 0);
            ARRAY_FIELD_DP32(regs, CRB_LOC_STS, Granted, 0);
            break;
        case CRB_LOC_CTRL_REQUEST_ACCESS:
            ARRAY_FIELD_DP32(regs, CRB_LOC_STS, Granted, 1);
            ARRAY_FIELD_DP32(regs, CRB_LOC_STS, beenSeized, 0);
            ARRAY_FIELD_DP32(regs, CRB_LOC_STATE, locAssigned, 1);
            break;
        }
        break;
    }

    memory_region_set_dirty(&s->mmio, 0, A_CRB_DATA_BUFFER);
}

static const MemoryRegionOps tpm_crb_memory_ops = {
    .write = tpm_crb_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

static void tpm_crb_sysbus_request_completed(TPMIf *ti, int ret)
{
    TPMCRBStateSysBus *s = TPM_CRB_SYSBUS(ti);
    uint32_t *regs = memory_region_get_ram_ptr(&s->mmio);

    regs[R_CRB_CTRL_START] &= ~CRB_START_INVOKE;
    if (ret != 0) {
        ARRAY_FIELD_DP32(regs, CRB_CTRL_STS, tpmSts, 1); /* fatal error */
    }

    memory_region_set_dirty(&s->mmio, 0, TPM_CRB_ADDR_SIZE);
}

static enum TPMVersion tpm_crb_sysbus_get_tpm_version(TPMIf *ti)
{
    TPMCRBStateSysBus *s = TPM_CRB_SYSBUS(ti);

    return tpm_backend_get_tpm_version(s->tpmbe);
}

static int tpm_crb_sysbus_pre_save(void *opaque)
{
    TPMCRBStateSysBus *s = opaque;

    tpm_backend_finish_sync(s->tpmbe);
    return 0;
}

/* The registers and the data buffer migrate with the region's RAM. */
static const VMStateDescription vmstate_tpm_crb_sysbus = {
    .name = "tpm-crb-sysbus",
    .pre_save = tpm_crb_sysbus_pre_save,
    .fields = (const VMStateField[]) {
        VMSTATE_END_OF_LIST(),
    }
};

static const Property tpm_crb_sysbus_properties[] = {
    DEFINE_PROP_TPMBE("tpmdev", TPMCRBStateSysBus, tpmbe),
    DEFINE_PROP_UINT64("x-baseaddr", TPMCRBStateSysBus,
                       baseaddr, TPM_CRB_ADDR_BASE),
    DEFINE_PROP_UINT64("x-size", TPMCRBStateSysBus,
                       size, TPM_CRB_ADDR_SIZE),
};

static void tpm_crb_sysbus_reset(DeviceState *dev)
{
    TPMCRBStateSysBus *s = TPM_CRB_SYSBUS(dev);
    uint32_t *regs = memory_region_get_ram_ptr(&s->mmio);
    uint64_t buf = s->baseaddr + A_CRB_DATA_BUFFER;

    tpm_backend_reset(s->tpmbe);

    memset(regs, 0, TPM_CRB_ADDR_SIZE);

    ARRAY_FIELD_DP32(regs, CRB_LOC_STATE, tpmRegValidSts, 1);
    ARRAY_FIELD_DP32(regs, CRB_LOC_STATE, tpmEstablished, 1);
    ARRAY_FIELD_DP32(regs, CRB_CTRL_STS, tpmIdle, 1);
    ARRAY_FIELD_DP32(regs, CRB_INTF_ID,
                     InterfaceType, CRB_INTF_TYPE_CRB_ACTIVE);
    ARRAY_FIELD_DP32(regs, CRB_INTF_ID,
                     InterfaceVersion, CRB_INTF_VERSION_CRB);
    ARRAY_FIELD_DP32(regs, CRB_INTF_ID,
                     CapLocality, CRB_INTF_CAP_LOCALITY_0_ONLY);
    ARRAY_FIELD_DP32(regs, CRB_INTF_ID,
                     CapCRBIdleBypass, CRB_INTF_CAP_IDLE_FAST);
    ARRAY_FIELD_DP32(regs, CRB_INTF_ID,
                     CapDataXferSizeSupport, CRB_INTF_CAP_XFER_SIZE_64);
    ARRAY_FIELD_DP32(regs, CRB_INTF_ID,
                     CapFIFO, CRB_INTF_CAP_FIFO_NOT_SUPPORTED);
    ARRAY_FIELD_DP32(regs, CRB_INTF_ID,
                     CapCRB, CRB_INTF_CAP_CRB_SUPPORTED);
    ARRAY_FIELD_DP32(regs, CRB_INTF_ID,
                     InterfaceSelector, CRB_INTF_IF_SELECTOR_CRB);
    ARRAY_FIELD_DP32(regs, CRB_INTF_ID, RID, 0b0000);
    ARRAY_FIELD_DP32(regs, CRB_INTF_ID2, VID, PCI_VENDOR_ID_IBM);

    /* The command and response buffers: the data buffer, 64-bit address */
    regs[R_CRB_CTRL_CMD_SIZE] = CRB_CTRL_CMD_SIZE;
    regs[R_CRB_CTRL_CMD_LADDR] = (uint32_t)buf;
    regs[R_CRB_CTRL_CMD_HADDR] = (uint32_t)(buf >> 32);
    regs[R_CRB_CTRL_RSP_SIZE] = CRB_CTRL_CMD_SIZE;
    regs[R_CRB_CTRL_RSP_ADDR] = (uint32_t)buf;
    regs[R_CRB_CTRL_RSP_HADDR] = (uint32_t)(buf >> 32);

    s->be_buffer_size = MIN(tpm_backend_get_buffer_size(s->tpmbe),
                            CRB_CTRL_CMD_SIZE);

    if (tpm_backend_startup_tpm(s->tpmbe, s->be_buffer_size) < 0) {
        exit(1);
    }

    memory_region_rom_device_set_romd(&s->mmio, true);
    memory_region_set_dirty(&s->mmio, 0, TPM_CRB_ADDR_SIZE);
}

static void tpm_crb_sysbus_realizefn(DeviceState *dev, Error **errp)
{
    TPMCRBStateSysBus *s = TPM_CRB_SYSBUS(dev);

    if (!tpm_find()) {
        error_setg(errp, "at most one TPM device is permitted");
        return;
    }

    if (!s->tpmbe) {
        error_setg(errp, "'tpmdev' property is required");
        return;
    }

    if (tpm_crb_sysbus_get_tpm_version(TPM_IF(s)) != TPM_VERSION_2_0) {
        error_setg(errp, "TPM CRB only supports TPM 2.0 backends");
        return;
    }

    if (!memory_region_init_rom_device(&s->mmio, OBJECT(dev),
                                       &tpm_crb_memory_ops, s, "tpm-crb-mem",
                                       ROUND_UP(TPM_CRB_ADDR_SIZE,
                                                qemu_real_host_page_size()),
                                       errp)) {
        return;
    }
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->mmio);
}

static void tpm_crb_sysbus_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    TPMIfClass *tc = TPM_IF_CLASS(klass);

    device_class_set_props(dc, tpm_crb_sysbus_properties);
    dc->vmsd = &vmstate_tpm_crb_sysbus;
    tc->model = TPM_MODEL_TPM_CRB;
    dc->realize = tpm_crb_sysbus_realizefn;
    dc->user_creatable = true;
    device_class_set_legacy_reset(dc, tpm_crb_sysbus_reset);
    tc->request_completed = tpm_crb_sysbus_request_completed;
    tc->get_version = tpm_crb_sysbus_get_tpm_version;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo tpm_crb_sysbus_info = {
    .name = TYPE_TPM_CRB_SYSBUS,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(TPMCRBStateSysBus),
    .class_init = tpm_crb_sysbus_class_init,
    .interfaces = (const InterfaceInfo[]) {
        { TYPE_TPM_IF },
        { }
    }
};

static void tpm_crb_sysbus_register(void)
{
    type_register_static(&tpm_crb_sysbus_info);
}

type_init(tpm_crb_sysbus_register)
