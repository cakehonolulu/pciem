/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Copyright (C) 2025-2026  Joel Bueno
 *  Copyright (C) 2025-2026  Carlos López
 */

#ifndef PCIEM_P2P_H
#define PCIEM_P2P_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/mutex.h>

struct pciem_root_complex;

struct pciem_p2p_region {
    struct list_head list;
    phys_addr_t phys_start;
    resource_size_t size;
    void __iomem *kaddr;
    char name[32];
};

struct pciem_p2p_manager {
    struct list_head regions;
    struct mutex lock;
    size_t max_transfer_size;
    bool enabled;
};

#define PCIEM_P2P_MAX_TRANSFER (16 * 1024 * 1024)

int pciem_p2p_init(struct pciem_root_complex *v, const char *regions_str);
void pciem_p2p_cleanup(struct pciem_root_complex *v);
int pciem_p2p_register_region(struct pciem_root_complex *v,
                               phys_addr_t phys,
                               resource_size_t size,
                               const char *name);
int pciem_p2p_unregister_region(struct pciem_root_complex *v,
                                 phys_addr_t phys);
int pciem_p2p_read(struct pciem_root_complex *v,
                   phys_addr_t phys_addr,
                   void *dst,
                   size_t len);
int pciem_p2p_write(struct pciem_root_complex *v,
                    phys_addr_t phys_addr,
                    const void *src,
                    size_t len);
int pciem_p2p_validate_access(struct pciem_root_complex *v,
                               phys_addr_t phys_addr,
                               size_t len);
struct pciem_p2p_region *pciem_p2p_get_region(struct pciem_root_complex *v,
                                               phys_addr_t phys_addr);

#endif /* PCIEM_P2P_H */