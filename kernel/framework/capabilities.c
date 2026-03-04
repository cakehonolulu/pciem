// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025-2026 Joel Bueno
 *   Author(s): Joel Bueno <buenocalvachehjoel@gmail.com>
 *              Carlos López <carlos.lopezr4096@gmail.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "pciem_capabilities.h"
#include "pciem_framework.h"
#include <linux/pci_regs.h>
#include <linux/slab.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
#include <asm/unaligned.h>
#else
#include <linux/unaligned.h>
#endif

static u8 msi_cap_size(struct pciem_cap_msi_config *cfg)
{
    u8 size = 10;

    if (cfg->has_64bit)
    {
        size += 4;
    }

    size += 2;

    if (cfg->has_per_vector_masking)
    {
        size += 8;
    }

    return size;
}

void pciem_init_cap_manager(struct pciem_root_complex *v)
{
    guard(write_lock)(&v->cap_lock);

    if (v->cap_mgr)
        return;

    v->cap_mgr = kzalloc(sizeof(*v->cap_mgr), GFP_KERNEL);
    if (!v->cap_mgr)
    {
        pr_err("Failed to allocate capability manager\n");
        return;
    }
    v->cap_mgr->num_caps = 0;
    v->cap_mgr->next_offset = 0x40;
}

void pciem_cleanup_cap_manager(struct pciem_root_complex *v)
{
    struct pciem_cap_manager *mgr;
    int i;

    guard(write_lock)(&v->cap_lock);

    mgr = v->cap_mgr;
    if (!mgr)
        return;

    for (i = 0; i < v->cap_mgr->num_caps; i++)
    {
        if (mgr->caps[i].type == PCIEM_CAP_VSEC && mgr->caps[i].config.vsec.data)
        {
            kfree(mgr->caps[i].config.vsec.data);
        }
    }

    kfree(mgr);
    v->cap_mgr = NULL;
}

int pciem_add_cap_msi(struct pciem_root_complex *v, struct pciem_cap_msi_config *cfg)
{
    struct pciem_cap_manager *mgr;
    struct pciem_cap_entry *cap;

    guard(write_lock)(&v->cap_lock);

    mgr = v->cap_mgr;
    if (!mgr || mgr->num_caps >= MAX_PCI_CAPS)
        return -ENOMEM;

    cap = &mgr->caps[mgr->num_caps];
    cap->type = PCIEM_CAP_MSI;
    cap->offset = mgr->next_offset;
    cap->size = msi_cap_size(cfg);
    cap->config.msi = *cfg;

    memset(&cap->state.msi_state, 0, sizeof(cap->state.msi_state));
    cap->state.msi_state.control = 0;

    mgr->next_offset += cap->size;
    mgr->num_caps++;

    pr_info("Added MSI capability at offset 0x%02x (size %u)\n", cap->offset, cap->size);

    return 0;
}
EXPORT_SYMBOL(pciem_add_cap_msi);

int pciem_add_cap_msix(struct pciem_root_complex *v, struct pciem_cap_msix_config *cfg)
{
    struct pciem_cap_manager *mgr;
    struct pciem_cap_entry *cap;

    guard(write_lock)(&v->cap_lock);

    mgr = v->cap_mgr;
    if (!mgr || mgr->num_caps >= MAX_PCI_CAPS)
        return -ENOMEM;

    cap = &mgr->caps[mgr->num_caps];
    cap->type = PCIEM_CAP_MSIX;
    cap->offset = mgr->next_offset;
    cap->size = 12;
    cap->config.msix = *cfg;

    cap->state.msix_state.control = 0;

    mgr->next_offset += cap->size;
    mgr->num_caps++;

    pr_info("Added MSI-X capability at offset 0x%02x\n", cap->offset);

    return 0;
}

int pciem_add_cap_pm(struct pciem_root_complex *v, struct pciem_cap_pm_config *cfg)
{
    struct pciem_cap_manager *mgr;
    struct pciem_cap_entry *cap;

    guard(write_lock)(&v->cap_lock);

    mgr = v->cap_mgr;
    if (!mgr || mgr->num_caps >= MAX_PCI_CAPS)
        return -ENOMEM;

    cap = &mgr->caps[mgr->num_caps];
    cap->type = PCIEM_CAP_PM;
    cap->offset = mgr->next_offset;
    cap->size = 8;
    cap->config.pm = *cfg;

    cap->state.pm_state.control = 0;
    cap->state.pm_state.status = 0;

    mgr->next_offset += cap->size;
    mgr->num_caps++;

    pr_info("Added Power Management capability at offset 0x%02x\n", cap->offset);

    return 0;
}

int pciem_add_cap_pcie(struct pciem_root_complex *v, struct pciem_cap_pcie_config *cfg)
{
    struct pciem_cap_manager *mgr;
    struct pciem_cap_entry *cap;

    guard(write_lock)(&v->cap_lock);

    mgr = v->cap_mgr;
    if (!mgr || mgr->num_caps >= MAX_PCI_CAPS)
        return -ENOMEM;

    cap = &mgr->caps[mgr->num_caps];
    cap->type = PCIEM_CAP_PCIE;
    cap->offset = mgr->next_offset;
    cap->size = 60;
    cap->config.pcie = *cfg;

    mgr->next_offset += cap->size;
    mgr->num_caps++;

    pr_info("Added PCIe capability at offset 0x%02x\n", cap->offset);

    return 0;
}

int pciem_add_cap_vsec(struct pciem_root_complex *v, struct pciem_cap_vsec_config *cfg)
{
    struct pciem_cap_manager *mgr;
    struct pciem_cap_entry *cap;
    u8 *data_copy;

    guard(write_lock)(&v->cap_lock);

    mgr = v->cap_mgr;
    if (!mgr || mgr->num_caps >= MAX_PCI_CAPS)
        return -ENOMEM;

    data_copy = kmalloc(cfg->vsec_length, GFP_KERNEL);
    if (!data_copy)
        return -ENOMEM;

    memcpy(data_copy, cfg->data, cfg->vsec_length);

    cap = &mgr->caps[mgr->num_caps];
    cap->type = PCIEM_CAP_VSEC;
    cap->offset = mgr->next_offset;
    cap->size = 8 + cfg->vsec_length;
    cap->config.vsec = *cfg;
    cap->config.vsec.data = data_copy;

    mgr->next_offset += cap->size;
    mgr->num_caps++;

    pr_info("Added VSEC capability at offset 0x%02x (vendor 0x%04x)\n", cap->offset, cfg->vendor_id);

    return 0;
}

int pciem_add_cap_pasid(struct pciem_root_complex *v, struct pciem_cap_pasid_config *cfg)
{
    struct pciem_cap_manager *mgr;
    struct pciem_cap_entry *cap;

    guard(write_lock)(&v->cap_lock);

    mgr = v->cap_mgr;
    if (!mgr || mgr->num_caps >= MAX_PCI_CAPS)
        return -ENOMEM;

    cap = &mgr->caps[mgr->num_caps];
    cap->type = PCIEM_CAP_PASID;
    cap->offset = mgr->next_offset;
    cap->size = 8;
    cap->config.pasid = *cfg;

    cap->state.pasid_state.control = 0;
    cap->state.pasid_state.pasid = 0;

    mgr->next_offset += cap->size;
    mgr->num_caps++;

    pr_info("Added PASID capability at offset 0x%02x\n", cap->offset);

    return 0;
}

void pciem_build_config_space(struct pciem_root_complex *v)
{
    int i;
    struct pciem_cap_manager *mgr = v->cap_mgr;

    if (!mgr || mgr->num_caps == 0)
    {
        v->cfg[PCI_CAPABILITY_LIST] = 0;
        v->cfg[PCI_STATUS] &= ~(PCI_STATUS_CAP_LIST >> 8);
        return;
    }

    v->cfg[PCI_CAPABILITY_LIST] = mgr->caps[0].offset;
    v->cfg[PCI_STATUS] |= (PCI_STATUS_CAP_LIST >> 8);

    for (i = 0; i < mgr->num_caps; i++)
    {
        struct pciem_cap_entry *cap = &mgr->caps[i];
        u8 *cfg = &v->cfg[cap->offset];
        u8 next_ptr = (i + 1 < mgr->num_caps) ? mgr->caps[i + 1].offset : 0;

        switch (cap->type)
        {
        case PCIEM_CAP_MSI: {
            struct pciem_cap_msi_config *msi = &cap->config.msi;
            u16 control = 0;
            u8 pos = 0;

            cfg[pos++] = PCI_CAP_ID_MSI;
            cfg[pos++] = next_ptr;

            if (msi->has_64bit)
            {
                control |= PCI_MSI_FLAGS_64BIT;
            }

            if (msi->has_per_vector_masking)
            {
                control |= PCI_MSI_FLAGS_MASKBIT;
            }

            control |= (msi->num_vectors_log2 << 1);
            put_unaligned_le16(control, &cfg[pos]);
            pos += 2;

            put_unaligned_le32(0, &cfg[pos]);
            pos += 4;

            if (msi->has_64bit)
            {
                put_unaligned_le32(0, &cfg[pos]);
                pos += 4;
            }

            put_unaligned_le16(0, &cfg[pos]);
            pos += 2;

            if (msi->has_per_vector_masking)
            {
                put_unaligned_le32(0, &cfg[pos]);
                pos += 4;
                put_unaligned_le32(0, &cfg[pos]);
            }
            break;
        }

        case PCIEM_CAP_MSIX: {
            struct pciem_cap_msix_config *msix = &cap->config.msix;
            u8 pos = 0;

            cfg[pos++] = PCI_CAP_ID_MSIX;
            cfg[pos++] = next_ptr;

            put_unaligned_le16((msix->table_size - 1) & 0x7FF, &cfg[pos]);
            pos += 2;

            put_unaligned_le32((msix->table_offset & ~0x7) | (msix->bar_index & 0x7), &cfg[pos]);
            pos += 4;

            put_unaligned_le32((msix->pba_offset & ~0x7) | (msix->bar_index & 0x7), &cfg[pos]);
            break;
        }

        case PCIEM_CAP_PM: {
            struct pciem_cap_pm_config *pm = &cap->config.pm;
            u16 pmc = 0;
            u8 pos = 0;

            cfg[pos++] = PCI_CAP_ID_PM;
            cfg[pos++] = next_ptr;

            pmc |= (pm->version & 0x3);
            if (pm->d1_support)
            {
                pmc |= PCI_PM_CAP_D1;
            }
            if (pm->d2_support)
            {
                pmc |= PCI_PM_CAP_D2;
            }
            if (pm->pme_support)
            {
                pmc |= PCI_PM_CAP_PME_D0 | PCI_PM_CAP_PME_D3hot | PCI_PM_CAP_PME_D3cold;
            }
            put_unaligned_le16(pmc, &cfg[pos]);
            pos += 2;

            put_unaligned_le16(0, &cfg[pos]);
            pos += 2;

            cfg[pos++] = 0;
            cfg[pos++] = 0;
            break;
        }

        case PCIEM_CAP_PCIE: {
            struct pciem_cap_pcie_config *pcie = &cap->config.pcie;
            u8 pos = 0;

            cfg[pos++] = PCI_CAP_ID_EXP;
            cfg[pos++] = next_ptr;

            put_unaligned_le16((pcie->device_type << 4) | 2, &cfg[pos]);
            pos += 2;

            put_unaligned_le32(0x00008000, &cfg[pos]);
            pos += 4;

            put_unaligned_le32(0, &cfg[pos]);
            pos += 4;

            put_unaligned_le32((pcie->link_speed & 0xF) | ((pcie->link_width & 0x3F) << 4), &cfg[pos]);
            pos += 4;

            put_unaligned_le32(((pcie->link_speed & 0xF) | ((pcie->link_width & 0x3F) << 4)) << 16, &cfg[pos]);
            pos += 4;

            memset(&cfg[pos], 0, 60 - pos);
            break;
        }

        case PCIEM_CAP_VSEC: {
            struct pciem_cap_vsec_config *vsec = &cap->config.vsec;
            u8 pos = 0;

            cfg[pos++] = PCI_CAP_ID_VNDR;
            cfg[pos++] = next_ptr;

            cfg[pos++] = (8 + vsec->vsec_length) & 0xFF;

            cfg[pos++] = 0;

            put_unaligned_le16(vsec->vendor_id, &cfg[pos]);
            pos += 2;

            cfg[pos++] = vsec->vsec_id & 0xFF;
            cfg[pos++] = ((vsec->vsec_id >> 8) & 0xF) | ((vsec->vsec_rev & 0xF) << 4);

            memcpy(&cfg[pos], vsec->data, vsec->vsec_length);
            break;
        }

        case PCIEM_CAP_PASID: {
            struct pciem_cap_pasid_config *pasid = &cap->config.pasid;
            u16 caps = 0;
            u8 pos = 0;

            cfg[pos++] = 0x1B;
            cfg[pos++] = next_ptr;

            if (pasid->execute_permission)
            {
                caps |= 0x02;
            }
            if (pasid->privileged_mode)
            {
                caps |= 0x04;
            }
            caps |= ((pasid->max_pasid_width - 1) << 8);
            put_unaligned_le16(caps, &cfg[pos]);
            pos += 2;

            put_unaligned_le16(0, &cfg[pos]);
            pos += 2;

            put_unaligned_le16(0, &cfg[pos]);
            break;
        }
        }
    }
}

static bool handle_msi_read(struct pciem_cap_entry *cap, u32 offset, u32 size, u32 *value)
{
    struct pciem_msi_state *st = &cap->state.msi_state;

    if (offset == PCI_MSI_FLAGS && size == 2)
    {
        *value = st->control;
        return true;
    }
    if (offset == PCI_MSI_ADDRESS_LO)
    {
        *value = st->address_lo;
        return true;
    }

    if (cap->config.msi.has_64bit)
    {
        if (offset == PCI_MSI_ADDRESS_HI)
        {
            *value = st->address_hi;
            return true;
        }
        else if (offset == PCI_MSI_DATA_64)
        {
            *value = st->data;
            return true;
        }
    }
    else
    {
        if (offset == PCI_MSI_DATA_32)
        {
            *value = st->data;
            return true;
        }
    }

    return false;
}

static bool handle_msix_read(struct pciem_cap_entry *cap, u32 offset, u32 size, u32 *value)
{
    struct pciem_msix_state *st = &cap->state.msix_state;

    if (offset == PCI_MSIX_FLAGS && size == 2)
    {
        *value = st->control;
        return true;
    }
    return false;
}

static bool handle_pm_read(struct pciem_cap_entry *cap, u32 offset, u32 size, u32 *value)
{
    struct pciem_pm_state *st = &cap->state.pm_state;

    if (offset == PCI_PM_CTRL && size == 2)
    {
        *value = st->control;
        return true;
    }
    return false;
}

static bool handle_pasid_read(struct pciem_cap_entry *cap, u32 offset, u32 size, u32 *value)
{
    struct pciem_pasid_state *st = &cap->state.pasid_state;

    if (offset == PCI_PASID_CTRL && size == 2)
    {
        *value = st->control;
        return true;
    }

    return false;
}

bool pciem_handle_cap_read(struct pciem_root_complex *v, int where, int size, u32 *value)
{
    struct pciem_cap_manager *mgr = v->cap_mgr;
    int i;

    guard(read_lock)(&v->cap_lock);

    if (!mgr)
        return false;

    for (i = 0; i < mgr->num_caps; i++)
    {
        struct pciem_cap_entry *cap = &mgr->caps[i];

        if (where >= cap->offset && where < (cap->offset + cap->size))
        {
            int cap_offset = where - cap->offset;

            switch (cap->type)
            {
            case PCIEM_CAP_MSI:
                return handle_msi_read(cap, cap_offset, size, value);
            case PCIEM_CAP_MSIX:
                return handle_msix_read(cap, cap_offset, size, value);
            case PCIEM_CAP_PM:
                return handle_pm_read(cap, cap_offset, size, value);
            case PCIEM_CAP_PASID:
                return handle_pasid_read(cap, cap_offset, size, value);
            default:
                break;
            }

            return false;
        }
    }

    return false;
}

static bool handle_msi_write(struct pciem_cap_entry *cap, u32 offset, u32 size, u32 value)
{
    struct pciem_msi_state *st = &cap->state.msi_state;

    if (offset == PCI_MSI_FLAGS && size == 2) {
        st->control = value & 0xffff;
        pr_info("MSI Control written: 0x%04x (Enable: %d)\n", value, !!(value & PCI_MSI_FLAGS_ENABLE));
        return true;
    }
    if (offset == PCI_MSI_ADDRESS_LO && size == 4)
    {
        st->address_lo = value;
        pr_info("MSI Address Lo written: 0x%08x\n", value);
        return true;
    }
    if (cap->config.msi.has_64bit)
    {
        if (offset == PCI_MSI_ADDRESS_HI && size == 4)
        {
            st->address_hi = value;
            pr_info("MSI Address Hi written: 0x%08x\n", value);
            return true;
        }
        else if (offset == PCI_MSI_DATA_64 && size == 2)
        {
            st->data = value & 0xFFFF;
            pr_info("MSI Data written: 0x%04x\n", value);
            return true;
        }
        else if (offset == PCI_MSI_MASK_64 && size == 4)
        {
            st->mask_bits = value;
            pr_info("MSI Mask bits written: 0x%08x\n", value);
            return true;
        }
    }
    else
    {
        if (offset == PCI_MSI_DATA_32 && size == 2)
        {
            st->data = value & 0xFFFF;
            pr_info("MSI Data written: 0x%04x\n", value);
            return true;
        }
        else if (offset == PCI_MSI_MASK_32 && size == 4)
        {
            st->mask_bits = value;
            pr_info("MSI Mask bits written: 0x%08x\n", value);
            return true;
        }
    }
    return false;
}

static bool handle_msix_write(struct pciem_cap_entry *cap, u32 offset, u32 size, u32 value)
{
    struct pciem_msix_state *st = &cap->state.msix_state;

    if (offset == PCI_MSIX_FLAGS && size == 2)
    {
        st->control = value & 0xC7FF;
        pr_info("MSI-X Control written: 0x%04x (Enable: %d)\n", value, !!(value & PCI_MSIX_FLAGS_ENABLE));
        return true;
    }

    return false;
}

static bool handle_pm_write(struct pciem_cap_entry *cap, u32 offset, u32 size, u32 value)
{
    struct pciem_pm_state *st = &cap->state.pm_state;

    if (offset == PCI_PM_CTRL && size == 2)
    {
        st->control = value & (PCI_PM_CTRL_STATE_MASK | PCI_PM_CTRL_PME_ENABLE | PCI_PM_CTRL_PME_STATUS);
        pr_info("PM Control written: 0x%04x (Power State: D%d)\n", value, value & 0x3);
        return true;
    }

    return false;
}

static bool handle_pasid_write(struct pciem_cap_entry *cap, u32 offset, u32 size, u32 value)
{
    struct pciem_pasid_state *st = &cap->state.pasid_state;

    if (offset == PCI_PASID_CTRL && size == 2)
    {
        st->control = value & (PCI_PASID_CTRL_ENABLE | PCI_PASID_CTRL_EXEC | PCI_PASID_CTRL_PRIV);
        if (value & PCI_PASID_CTRL_ENABLE)
        {
            pr_info("PASID Enabled\n");
        }
        return true;
    }

    return false;
}

bool pciem_handle_cap_write(struct pciem_root_complex *v, int where, int size, u32 value)
{
    struct pciem_cap_manager *mgr = v->cap_mgr;
    int i;

    /* Take a read lock since we are not updating anything in the cap. manager itself,
     * only the actual capabilities. */
    guard(read_lock)(&v->cap_lock);

    if (!mgr)
        return false;

    for (i = 0; i < mgr->num_caps; i++)
    {
        struct pciem_cap_entry *cap = &mgr->caps[i];

        if (where >= cap->offset && where < (cap->offset + cap->size))
        {
            u32 cap_offset = where - cap->offset;

            switch (cap->type)
            {
            case PCIEM_CAP_MSI:
                return handle_msi_write(cap, cap_offset, size, value);
            case PCIEM_CAP_MSIX:
                return handle_msix_write(cap, cap_offset, size, value);
            case PCIEM_CAP_PM:
                return handle_pm_write(cap, cap_offset, size, value);
            case PCIEM_CAP_PASID:
                return handle_pasid_write(cap, cap_offset, size, value);
            default:
                break;
            }

            return true;
        }
    }

    return false;
}
