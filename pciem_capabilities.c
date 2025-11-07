#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "pciem_capabilities.h"
#include "pciem_framework.h"
#include <linux/pci_regs.h>
#include <linux/slab.h>

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

void pciem_init_cap_manager(struct pciem_host *v)
{
    if (!v->cap_mgr)
    {
        v->cap_mgr = kzalloc(sizeof(*v->cap_mgr), GFP_KERNEL);
        if (!v->cap_mgr)
        {
            pr_err("Failed to allocate capability manager\n");
            return;
        }
        v->cap_mgr->num_caps = 0;
        v->cap_mgr->next_offset = 0x40;
    }
}

void pciem_cleanup_cap_manager(struct pciem_host *v)
{
    int i;

    if (!v->cap_mgr)
    {
        return;
    }

    for (i = 0; i < v->cap_mgr->num_caps; i++)
    {
        if (v->cap_mgr->caps[i].type == PCIEM_CAP_VSEC && v->cap_mgr->caps[i].config.vsec.data)
        {
            kfree(v->cap_mgr->caps[i].config.vsec.data);
        }
    }

    kfree(v->cap_mgr);
    v->cap_mgr = NULL;
}

int pciem_add_cap_msi(struct pciem_host *v, struct pciem_cap_msi_config *cfg)
{
    struct pciem_cap_entry *cap;

    if (!v->cap_mgr || v->cap_mgr->num_caps >= MAX_PCI_CAPS)
    {
        return -ENOMEM;
    }

    cap = &v->cap_mgr->caps[v->cap_mgr->num_caps];
    cap->type = PCIEM_CAP_MSI;
    cap->offset = v->cap_mgr->next_offset;
    cap->size = msi_cap_size(cfg);
    cap->config.msi = *cfg;

    memset(&cap->state.msi_state, 0, sizeof(cap->state.msi_state));
    cap->state.msi_state.control = 0;

    v->cap_mgr->next_offset += cap->size;
    v->cap_mgr->num_caps++;

    pr_info("Added MSI capability at offset 0x%02x (size %u)\n", cap->offset, cap->size);

    return 0;
}

int pciem_add_cap_msix(struct pciem_host *v, struct pciem_cap_msix_config *cfg)
{
    struct pciem_cap_entry *cap;

    if (!v->cap_mgr || v->cap_mgr->num_caps >= MAX_PCI_CAPS)
    {
        return -ENOMEM;
    }

    cap = &v->cap_mgr->caps[v->cap_mgr->num_caps];
    cap->type = PCIEM_CAP_MSIX;
    cap->offset = v->cap_mgr->next_offset;
    cap->size = 12;
    cap->config.msix = *cfg;

    cap->state.msix_state.control = 0;

    v->cap_mgr->next_offset += cap->size;
    v->cap_mgr->num_caps++;

    pr_info("Added MSI-X capability at offset 0x%02x\n", cap->offset);

    return 0;
}

int pciem_add_cap_pm(struct pciem_host *v, struct pciem_cap_pm_config *cfg)
{
    struct pciem_cap_entry *cap;

    if (!v->cap_mgr || v->cap_mgr->num_caps >= MAX_PCI_CAPS)
    {
        return -ENOMEM;
    }

    cap = &v->cap_mgr->caps[v->cap_mgr->num_caps];
    cap->type = PCIEM_CAP_PM;
    cap->offset = v->cap_mgr->next_offset;
    cap->size = 8;
    cap->config.pm = *cfg;

    cap->state.pm_state.control = 0;
    cap->state.pm_state.status = 0;

    v->cap_mgr->next_offset += cap->size;
    v->cap_mgr->num_caps++;

    pr_info("Added Power Management capability at offset 0x%02x\n", cap->offset);

    return 0;
}

int pciem_add_cap_pcie(struct pciem_host *v, struct pciem_cap_pcie_config *cfg)
{
    struct pciem_cap_entry *cap;

    if (!v->cap_mgr || v->cap_mgr->num_caps >= MAX_PCI_CAPS)
    {
        return -ENOMEM;
    }

    cap = &v->cap_mgr->caps[v->cap_mgr->num_caps];
    cap->type = PCIEM_CAP_PCIE;
    cap->offset = v->cap_mgr->next_offset;
    cap->size = 60;
    cap->config.pcie = *cfg;

    v->cap_mgr->next_offset += cap->size;
    v->cap_mgr->num_caps++;

    pr_info("Added PCIe capability at offset 0x%02x\n", cap->offset);

    return 0;
}

int pciem_add_cap_vsec(struct pciem_host *v, struct pciem_cap_vsec_config *cfg)
{
    struct pciem_cap_entry *cap;
    u8 *data_copy;

    if (!v->cap_mgr || v->cap_mgr->num_caps >= MAX_PCI_CAPS)
    {
        return -ENOMEM;
    }

    data_copy = kmalloc(cfg->vsec_length, GFP_KERNEL);
    if (!data_copy)
    {
        return -ENOMEM;
    }

    memcpy(data_copy, cfg->data, cfg->vsec_length);

    cap = &v->cap_mgr->caps[v->cap_mgr->num_caps];
    cap->type = PCIEM_CAP_VSEC;
    cap->offset = v->cap_mgr->next_offset;
    cap->size = 8 + cfg->vsec_length;
    cap->config.vsec = *cfg;
    cap->config.vsec.data = data_copy;

    v->cap_mgr->next_offset += cap->size;
    v->cap_mgr->num_caps++;

    pr_info("Added VSEC capability at offset 0x%02x (vendor 0x%04x)\n", cap->offset, cfg->vendor_id);

    return 0;
}

int pciem_add_cap_pasid(struct pciem_host *v, struct pciem_cap_pasid_config *cfg)
{
    struct pciem_cap_entry *cap;

    if (!v->cap_mgr || v->cap_mgr->num_caps >= MAX_PCI_CAPS)
    {
        return -ENOMEM;
    }

    cap = &v->cap_mgr->caps[v->cap_mgr->num_caps];
    cap->type = PCIEM_CAP_PASID;
    cap->offset = v->cap_mgr->next_offset;
    cap->size = 8;
    cap->config.pasid = *cfg;

    cap->state.pasid_state.control = 0;
    cap->state.pasid_state.pasid = 0;

    v->cap_mgr->next_offset += cap->size;
    v->cap_mgr->num_caps++;

    pr_info("Added PASID capability at offset 0x%02x\n", cap->offset);

    return 0;
}

void pciem_build_config_space(struct pciem_host *v)
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
            *(u16 *)&cfg[pos] = control;
            pos += 2;

            *(u32 *)&cfg[pos] = 0;
            pos += 4;

            if (msi->has_64bit)
            {
                *(u32 *)&cfg[pos] = 0;
                pos += 4;
            }

            *(u16 *)&cfg[pos] = 0;
            pos += 2;

            if (msi->has_per_vector_masking)
            {
                *(u32 *)&cfg[pos] = 0;
                pos += 4;
                *(u32 *)&cfg[pos] = 0;
            }
            break;
        }

        case PCIEM_CAP_MSIX: {
            struct pciem_cap_msix_config *msix = &cap->config.msix;
            u8 pos = 0;

            cfg[pos++] = PCI_CAP_ID_MSIX;
            cfg[pos++] = next_ptr;

            *(u16 *)&cfg[pos] = (msix->table_size - 1) & 0x7FF;
            pos += 2;

            *(u32 *)&cfg[pos] = (msix->table_offset & ~0x7) | (msix->bar_index & 0x7);
            pos += 4;

            *(u32 *)&cfg[pos] = (msix->pba_offset & ~0x7) | (msix->bar_index & 0x7);
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
            *(u16 *)&cfg[pos] = pmc;
            pos += 2;

            *(u16 *)&cfg[pos] = 0;
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

            *(u16 *)&cfg[pos] = (pcie->device_type << 4) | 2;
            pos += 2;

            *(u32 *)&cfg[pos] = 0x00008000;
            pos += 4;

            *(u32 *)&cfg[pos] = 0;
            pos += 4;

            *(u32 *)&cfg[pos] = (pcie->link_speed & 0xF) | ((pcie->link_width & 0x3F) << 4);
            pos += 4;

            *(u32 *)&cfg[pos] = (pcie->link_speed & 0xF) | ((pcie->link_width & 0x3F) << 4) << 16;
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

            *(u16 *)&cfg[pos] = vsec->vendor_id;
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

            cfg[pos++] = 0x1B cfg[pos++] = next_ptr;

            if (pasid->execute_permission)
            {
                caps |= 0x02;
            }
            if (pasid->privileged_mode)
            {
                caps |= 0x04;
            }
            caps |= ((pasid->max_pasid_width - 1) << 8);
            *(u16 *)&cfg[pos] = caps;
            pos += 2;

            *(u16 *)&cfg[pos] = 0;
            pos += 2;

            *(u16 *)&cfg[pos] = 0;
            break;
        }
        }
    }
}

bool pciem_handle_cap_read(struct pciem_host *v, int where, int size, u32 *value)
{
    struct pciem_cap_manager *mgr = v->cap_mgr;
    int i;

    if (!mgr)
    {
        return false;
    }

    for (i = 0; i < mgr->num_caps; i++)
    {
        struct pciem_cap_entry *cap = &mgr->caps[i];

        if (where >= cap->offset && where < (cap->offset + cap->size))
        {
            int cap_offset = where - cap->offset;

            switch (cap->type)
            {
            case PCIEM_CAP_MSI:
                if (cap_offset == 2 && size == 2)
                {
                    *value = cap->state.msi_state.control;
                    return true;
                }
                if (cap->config.msi.has_64bit)
                {
                    if (cap_offset == 4)
                    {
                        *value = cap->state.msi_state.address_lo;
                        return true;
                    }
                    else if (cap_offset == 8)
                    {
                        *value = cap->state.msi_state.address_hi;
                        return true;
                    }
                    else if (cap_offset == 12)
                    {
                        *value = cap->state.msi_state.data;
                        return true;
                    }
                }
                else
                {
                    if (cap_offset == 4)
                    {
                        *value = cap->state.msi_state.address_lo;
                        return true;
                    }
                    else if (cap_offset == 8)
                    {
                        *value = cap->state.msi_state.data;
                        return true;
                    }
                }
                break;

            case PCIEM_CAP_MSIX:
                if (cap_offset == 2 && size == 2)
                {
                    *value = cap->state.msix_state.control;
                    return true;
                }
                break;

            case PCIEM_CAP_PM:
                if (cap_offset == 4 && size == 2)
                {
                    *value = cap->state.pm_state.control;
                    return true;
                }
                break;

            case PCIEM_CAP_PASID:
                if (cap_offset == 4 && size == 2)
                {
                    *value = cap->state.pasid_state.control;
                    return true;
                }
                break;

            default:
                break;
            }

            return false;
        }
    }

    return false;
}

bool pciem_handle_cap_write(struct pciem_host *v, int where, int size, u32 value)
{
    struct pciem_cap_manager *mgr = v->cap_mgr;
    int i;

    if (!mgr)
    {
        return false;
    }

    for (i = 0; i < mgr->num_caps; i++)
    {
        struct pciem_cap_entry *cap = &mgr->caps[i];

        if (where >= cap->offset && where < (cap->offset + cap->size))
        {
            int cap_offset = where - cap->offset;

            switch (cap->type)
            {
            case PCIEM_CAP_MSI:
                if (cap_offset == 2 && size == 2)
                {
                    cap->state.msi_state.control = value & 0xFFFF;
                    pr_info("MSI Control written: 0x%04x (Enable: %d)\n", value, !!(value & PCI_MSI_FLAGS_ENABLE));
                    return true;
                }
                if (cap->config.msi.has_64bit)
                {
                    if (cap_offset == 4 && size == 4)
                    {
                        cap->state.msi_state.address_lo = value;
                        pr_info("MSI Address Lo written: 0x%08x\n", value);
                        return true;
                    }
                    else if (cap_offset == 8 && size == 4)
                    {
                        cap->state.msi_state.address_hi = value;
                        pr_info("MSI Address Hi written: 0x%08x\n", value);
                        return true;
                    }
                    else if (cap_offset == 12 && size == 2)
                    {
                        cap->state.msi_state.data = value & 0xFFFF;
                        pr_info("MSI Data written: 0x%04x\n", value);
                        return true;
                    }
                    else if (cap_offset == 14 && size == 4)
                    {
                        cap->state.msi_state.mask_bits = value;
                        pr_info("MSI Mask bits written: 0x%08x\n", value);
                        return true;
                    }
                }
                else
                {
                    if (cap_offset == 4 && size == 4)
                    {
                        cap->state.msi_state.address_lo = value;
                        pr_info("MSI Address written: 0x%08x\n", value);
                        return true;
                    }
                    else if (cap_offset == 8 && size == 2)
                    {
                        cap->state.msi_state.data = value & 0xFFFF;
                        pr_info("MSI Data written: 0x%04x\n", value);
                        return true;
                    }
                    else if (cap_offset == 10 && size == 4)
                    {
                        cap->state.msi_state.mask_bits = value;
                        pr_info("MSI Mask bits written: 0x%08x\n", value);
                        return true;
                    }
                }
                break;

            case PCIEM_CAP_MSIX:
                if (cap_offset == 2 && size == 2)
                {
                    cap->state.msix_state.control = value & 0xC7FF;
                    pr_info("MSI-X Control written: 0x%04x (Enable: %d)\n", value, !!(value & PCI_MSIX_FLAGS_ENABLE));
                    return true;
                }
                break;

            case PCIEM_CAP_PM:
                if (cap_offset == 4 && size == 2)
                {
                    cap->state.pm_state.control = value & 0x8103;
                    pr_info("PM Control written: 0x%04x (Power State: D%d)\n", value, value & 0x3);
                    return true;
                }
                break;

            case PCIEM_CAP_PASID:
                if (cap_offset == 4 && size == 2)
                {
                    cap->state.pasid_state.control = value & 0x07;
                    if (value & 0x01)
                    {
                        pr_info("PASID Enabled\n");
                    }
                    return true;
                }
                break;

            default:
                break;
            }

            return true;
        }
    }

    return false;
}