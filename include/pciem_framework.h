/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Copyright (C) 2025-2026  Joel Bueno
 *  Copyright (C) 2025-2026  Carlos López
 */

#ifndef PCIEM_FRAMEWORK_H
#define PCIEM_FRAMEWORK_H

#include <linux/completion.h>
#include <linux/fs.h>
#include <linux/irq_work.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/msi.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#ifdef CONFIG_X86
#include <asm/pci.h>
#endif

struct pciem_host_bridge_priv {
    struct pciem_root_complex *v;

#ifdef CONFIG_X86
    struct pci_sysdata sd;
#endif
};

#include "pciem_p2p.h"

struct pciem_mempool {
    phys_addr_t         base;
    resource_size_t     total_size;
    resource_size_t     next_offset;
    spinlock_t          lock;
    struct resource     *res;
    bool                initialized;
};

extern struct pciem_mempool pciem_pool;

phys_addr_t pciem_pool_alloc(resource_size_t size);

enum pciem_bus_mode {
    PCIEM_BUS_MODE_VIRTUAL_ROOT = 0,
    PCIEM_BUS_MODE_ATTACH_TO_HOST = 1,
};

struct pciem_bar_info
{
    resource_size_t size;
    u32 flags;
    bool intercept_page_faults;

    u32 base_addr_val;

    struct resource *res;

    struct resource *allocated_res;
    struct page *pages;
    phys_addr_t phys_addr;
    unsigned int order;
    bool mem_owned_by_framework;

    resource_size_t carved_start;
    resource_size_t carved_end;

    struct list_head vma_list;
    spinlock_t vma_lock;
};

struct pciem_hijack_state {
    struct pci_bus *target_bus;
    int hijacked_slot;
    struct pci_ops *original_ops;
    struct pci_ops proxy_ops;
};

struct pciem_root_complex
{
    struct list_head list_node;

    unsigned int msi_irq;
    struct irq_work msi_irq_work;
    unsigned int pending_msi_irq;
    struct pci_dev *pciem_pdev;
    struct pci_bus *root_bus;
    u8 cfg[256];

    enum pciem_bus_mode bus_mode;

    union {
        struct {
            struct pci_host_bridge *bridge;
            int assigned_domain;
            int assigned_busnr;
        } virtual_root;

        struct pciem_hijack_state hijack;
    } mode_state;

    struct pciem_bar_info bars[PCI_STD_NUM_BARS];
    rwlock_t bars_lock;

    struct platform_device *shared_bridge_pdev;

    struct pciem_cap_manager *cap_mgr;
    rwlock_t cap_lock;

    resource_size_t total_carved_start;
    resource_size_t total_carved_end;
    resource_size_t next_carve_offset;

    struct pciem_p2p_manager *p2p_mgr;

    struct work_struct activation_work;
    bool activated;

    bool detaching;
};

void pciem_trigger_msi(struct pciem_root_complex *v, int vector);
int pciem_complete_init(struct pciem_root_complex *v);
int pciem_start_device(struct pciem_root_complex *v);
int pciem_register_bar(struct pciem_root_complex *v, uint32_t bar_num, resource_size_t size, u32 flags);
struct pciem_root_complex *pciem_alloc_root_complex(void);
void pciem_free_root_complex(struct pciem_root_complex *v);
int pciem_init_bar_tracking(void);
void pciem_cleanup_bar_tracking(void);
void pciem_disable_bar_tracking(void);
void __iomem *pciem_get_driver_bar_vaddr(struct pci_dev *pdev, u32 bar);

#endif /* PCIEM_FRAMEWORK_H */
