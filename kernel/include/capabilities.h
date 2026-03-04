/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Copyright (C) 2025-2026  Joel Bueno
 *  Copyright (C) 2025-2026  Carlos López
 */

#ifndef PCIEM_CAPABILITIES_H
#define PCIEM_CAPABILITIES_H

#include <linux/pci_regs.h>
#include <linux/types.h>

#define MAX_PCI_CAPS 16

struct pciem_cap_msi_config
{
    bool has_64bit;
    bool has_per_vector_masking;
    u8 num_vectors_log2;
};

struct pciem_cap_msix_config
{
    u8 bar_index;
    u32 table_offset;
    u32 pba_offset;
    u16 table_size;
};

struct pciem_cap_pm_config
{
    bool d1_support;
    bool d2_support;
    bool pme_support;
    u8 version;
};

struct pciem_cap_pcie_config
{
    u8 device_type;
    u8 link_width;
    u8 link_speed;
};

struct pciem_cap_vsec_config
{
    u16 vendor_id;
    u16 vsec_id;
    u8 vsec_rev;
    u16 vsec_length;
    u8 *data;
};

struct pciem_cap_pasid_config
{
    u8 max_pasid_width;
    bool execute_permission;
    bool privileged_mode;
};

struct pciem_root_complex;

int pciem_add_cap_msi(struct pciem_root_complex *v, struct pciem_cap_msi_config *cfg);
int pciem_add_cap_msix(struct pciem_root_complex *v, struct pciem_cap_msix_config *cfg);
int pciem_add_cap_pm(struct pciem_root_complex *v, struct pciem_cap_pm_config *cfg);
int pciem_add_cap_pcie(struct pciem_root_complex *v, struct pciem_cap_pcie_config *cfg);
int pciem_add_cap_vsec(struct pciem_root_complex *v, struct pciem_cap_vsec_config *cfg);
int pciem_add_cap_pasid(struct pciem_root_complex *v, struct pciem_cap_pasid_config *cfg);

void pciem_init_cap_manager(struct pciem_root_complex *v);
void pciem_build_config_space(struct pciem_root_complex *v);
void pciem_cleanup_cap_manager(struct pciem_root_complex *v);

bool pciem_handle_cap_read(struct pciem_root_complex *v, int where, int size, u32 *value);
bool pciem_handle_cap_write(struct pciem_root_complex *v, int where, int size, u32 value);

#endif /* PCIEM_CAPABILITIES_H */
