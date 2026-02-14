// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025-2026 Joel Bueno
 *   Author(s): Joel Bueno <buenocalvachehjoel@gmail.com>
 *              Carlos López <carlos.lopezr4096@gmail.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/pci.h>
#include <linux/pci_ids.h>

#include <asm/cacheflush.h>
#include <asm/io.h>
#include <asm/tlbflush.h>
#include <linux/atomic.h>
#include <linux/cleanup.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/pci-acpi.h>
#include <linux/pci_regs.h>
#include <linux/resource.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/idr.h>
#include <linux/workqueue.h>

#include "pciem_capabilities.h"
#include "pciem_dma.h"
#include "pciem_framework.h"
#include "pciem_p2p.h"
#include "pciem_userspace.h"

static char *pciem_phys_regions = "";
module_param(pciem_phys_regions, charp, 0444);
MODULE_PARM_DESC(pciem_phys_regions,
                 "Physical memory regions for BARs: bar0:0x1bf000000:0x10000,bar2:0x1bf010000:0x20000");

static char *p2p_regions = "";
module_param(p2p_regions, charp, 0444);
MODULE_PARM_DESC(p2p_regions,
    "P2P whitelist: 0xADDR:0xSIZE,0xADDR:0xSIZE");

static struct miscdevice pciem_dev;
static const struct file_operations pciem_fops;
static struct pci_ops vph_pci_ops;

static void pciem_fixup_bridge_domain(struct pci_host_bridge *bridge, 
                                      struct pciem_host_bridge_priv *priv, 
                                      int domain)
{
    bridge->domain_nr = domain;

#ifdef CONFIG_X86
    priv->sd.domain = domain;
    priv->sd.node = NUMA_NO_NODE;
    bridge->sysdata = &priv->sd;
#else
    bridge->sysdata = priv;
#endif
}

static int parse_phys_regions(struct pciem_root_complex *v)
{
    char *str, *token, *cur;
    u32 bar_num;
    resource_size_t start, size;

    if (!pciem_phys_regions || strlen(pciem_phys_regions) == 0)
    {
        return 0;
    }

    str = kstrdup(pciem_phys_regions, GFP_KERNEL);
    if (!str)
    {
        return -ENOMEM;
    }

    cur = str;
    while ((token = strsep(&cur, ",")) != NULL)
    {
        if (sscanf(token, "bar%u:0x%llx:0x%llx", &bar_num, &start, &size) == 3 ||
            sscanf(token, "bar%u:%llx:%llx", &bar_num, &start, &size) == 3)
        {
            if (bar_num >= PCI_STD_NUM_BARS)
            {
                pr_warn("Invalid BAR number %u in phys_regions\n", bar_num);
                continue;
            }

            v->bars[bar_num].carved_start = start;
            v->bars[bar_num].carved_end = start + size - 1;
            pr_info("Parsed BAR%u phys region: 0x%llx-0x%llx\n", bar_num, (u64)start, (u64)(start + size - 1));
        }
    }

    kfree(str);
    return 0;
}

int pciem_register_bar(struct pciem_root_complex *v, u32 bar_num, resource_size_t size, u32 flags)
{
    if (bar_num >= PCI_STD_NUM_BARS)
        return -EINVAL;

    guard(write_lock)(&v->bars_lock);

    if (size == 0)
    {
        v->bars[bar_num].size = 0;
        v->bars[bar_num].flags = 0;
        return 0;
    }

    if (size & (size - 1))
    {
        pr_err("pciem: BAR %u size 0x%llx is not a power of 2\n", bar_num, (u64)size);
        return -EINVAL;
    }

    v->bars[bar_num].size = size;
    v->bars[bar_num].flags = flags;
    v->bars[bar_num].base_addr_val = 0;

    pr_info("pciem: Registered BAR %u: size 0x%llx, flags 0x%x\n", bar_num, (u64)size, flags);

    return 0;
}
EXPORT_SYMBOL(pciem_register_bar);

void pciem_trigger_msi(struct pciem_root_complex *v, int vector)
{
    struct pci_dev *dev = v->pciem_pdev;
    int irq;

    if (!dev || (!dev->msi_enabled && !dev->msix_enabled))
    {
        pr_warn("Cannot trigger MSI/MSI-X: device not ready or interrupts not enabled (msi=%d, msix=%d)\n",
                dev ? dev->msi_enabled : 0, dev ? dev->msix_enabled : 0);
        return;
    }

    if (dev->msix_enabled) {
        irq = pci_irq_vector(dev, vector);
        if (irq < 0) {
            pr_warn("Cannot get IRQ for MSI-X vector %d: %d\n", vector, irq);
            return;
        }
        pr_info("Triggering MSI-X vector %d (IRQ %u) via irq_work\n", vector, irq);
    }
    else {
        irq = dev->irq;
        if (irq == 0) {
            pr_warn("Cannot trigger MSI: dev->irq is 0\n");
            return;
        }
        pr_info("Triggering MSI (IRQ %u) via irq_work\n", irq);
    }

    v->pending_msi_irq = irq;
    irq_work_queue(&v->msi_irq_work);
}
EXPORT_SYMBOL(pciem_trigger_msi);

static void pciem_msi_irq_work_func(struct irq_work *work)
{
    struct pciem_root_complex *v = container_of(work, struct pciem_root_complex, msi_irq_work);
    unsigned int irq = v->pending_msi_irq;
    if (irq)
    {
        generic_handle_irq(irq);
    }
}

static void pciem_bus_init_resources(struct pciem_root_complex *v)
{
    u32 i;
    struct pciem_bar_info *bar;
    struct pci_dev *dev __free(pci_dev_put) = pci_get_slot(v->root_bus, 0);

    if (!dev)
        return;

    for (i = 0; i < PCI_STD_NUM_BARS; i++)
    {
        bar = &v->bars[i];
        if (bar->size > 0 && bar->allocated_res)
        {
            dev->resource[i] = *bar->allocated_res;
            dev->resource[i].flags |= IORESOURCE_BUSY;
            bar->res = &dev->resource[i];
        }
    }

    pci_bus_assign_resources(v->root_bus);
    pr_info("init: found pci_dev vendor=%04x device=%04x", dev->vendor, dev->device);
}

static int pciem_reserve_bar_res(struct pciem_bar_info *bar, u32 i, struct list_head *resources)
{
    struct resource_entry *entry;

    if (!bar->allocated_res)
        return 0;

    entry = resource_list_create_entry(bar->allocated_res, i);
    if (!entry)
        return -ENOMEM;

    resource_list_add_tail(entry, resources);
    pr_info("init: Added BAR%u to resource list", i);
    return 0;
}

static int pciem_reserve_bars_res(struct pciem_root_complex *v, struct list_head *resources)
{
    int i, rc;
    struct pciem_bar_info *bar, *prev = NULL;

    for (i = 0; i < PCI_STD_NUM_BARS; i++)
    {
        bar = &v->bars[i];
        if (i > 0)
            prev = &v->bars[i - 1];

        if (!bar->size)
            continue;

        if (i & 1 && prev && prev->flags & PCI_BASE_ADDRESS_MEM_TYPE_64)
            continue;

        rc = pciem_reserve_bar_res(bar, i, resources);
        if (rc)
            return rc;
    }

    return 0;
}

static void pciem_cleanup_bar(struct pciem_bar_info *bar)
{
    if (bar->allocated_res && bar->mem_owned_by_framework)
    {
        if (bar->allocated_res->parent) {
            release_resource(bar->allocated_res);
        }
        kfree(bar->allocated_res->name);
        kfree(bar->allocated_res);
        bar->allocated_res = NULL;
    }
    if (bar->pages) {
        __free_pages(bar->pages, bar->order);
        bar->pages = NULL;
    }
}

static void pciem_cleanup_bars(struct pciem_root_complex *v)
{
    for (int i = 0; i < PCI_STD_NUM_BARS; i++)
        pciem_cleanup_bar(&v->bars[i]);
}

static u32 pciem_read_bar_address(const struct pciem_root_complex *v, u32 idx)
{
    u32 val;
    const struct pciem_bar_info *bar = &v->bars[idx];
    const struct pciem_bar_info *prev = idx > 0 && (idx % 2) == 1
        ? &v->bars[idx - 1]
        : NULL;

    if (bar->size != 0)
    {
        u32 probe_val = (u32)(~(bar->size - 1));

        if (bar->base_addr_val == probe_val)
            val = probe_val | (bar->flags & ~PCI_BASE_ADDRESS_MEM_MASK);
        else
            val = bar->base_addr_val | (bar->flags & ~PCI_BASE_ADDRESS_MEM_MASK);

        return val;
    }

    if (prev && (prev->flags & PCI_BASE_ADDRESS_MEM_TYPE_64))
    {
        u32 probe_val_high = 0xffffffff;

        if (prev->size >= (1ULL << 32))
            probe_val_high = (u32)(~(prev->size - 1) >> 32);

        if (bar->base_addr_val == probe_val_high)
            val = probe_val_high;
        else
            val = bar->base_addr_val;

        return val;
    }

    return 0;
}

static int pciem_conf_read_impl(struct pciem_root_complex *v, int where, int size, u32 *value)
{
    u32 val = ~0U;

    if (!v)
    {
        *value = ~0U;
        return PCIBIOS_DEVICE_NOT_FOUND;
    }
    if (unlikely(v->detaching)) {
        *value = ~0U;
        return PCIBIOS_DEVICE_NOT_FOUND;
    }
    if (where < 0 || (where + size) > (int)sizeof(v->cfg))
    {
        *value = ~0U;
        return PCIBIOS_DEVICE_NOT_FOUND;
    }
    if (pciem_handle_cap_read(v, where, size, &val))
    {
        *value = val;
        return PCIBIOS_SUCCESSFUL;
    }

    if (where >= PCI_BASE_ADDRESS_0 &&
        where < PCI_BASE_ADDRESS_0 + (4 * PCI_STD_NUM_BARS) &&
        (where % 4 == 0) &&
        size == 4)
    {
        int idx = (where - PCI_BASE_ADDRESS_0) / 4;
        *value = pciem_read_bar_address(v, idx);
        return PCIBIOS_SUCCESSFUL;
    }

    if (where == PCI_ROM_ADDRESS && size == 4)
    {
        val = 0;
    }
    else
    {
        switch (size)
        {
        case 1:
            val = v->cfg[where];
            break;
        case 2:
            val = *(u16 *)&v->cfg[where];
            break;
        case 4:
            val = *(u32 *)&v->cfg[where];
            break;
        default:
            val = ~0U;
        }
    }
    *value = val;
    return PCIBIOS_SUCCESSFUL;
}

static int pciem_write_bar_address(struct pciem_root_complex *v, u32 idx, u32 value)
{
    struct pciem_bar_info *bar = &v->bars[idx];
    struct pciem_bar_info *prev = idx > 0 && (idx % 2) == 1
        ? &v->bars[idx - 1]
        : NULL;

    if (bar->size != 0)
    {
        u32 mask = (u32)(~(bar->size - 1));
        if (bar->flags & PCI_BASE_ADDRESS_SPACE_IO)
            mask &= ~PCI_BASE_ADDRESS_IO_MASK;
        else
            mask &= ~PCI_BASE_ADDRESS_MEM_MASK;

        bar->base_addr_val = value & mask;
        return PCIBIOS_SUCCESSFUL;
    }

    if (prev && (prev->flags & PCI_BASE_ADDRESS_MEM_TYPE_64))
    {
        u32 mask_high = 0xffffffff;

        if (prev->size < (1ULL << 32))
            mask_high = 0;
        else
            mask_high = (u32)(~(prev->size - 1) >> 32);

        bar->base_addr_val = value & mask_high;
        return PCIBIOS_SUCCESSFUL;
    }

    return PCIBIOS_FUNC_NOT_SUPPORTED;
}

static int pciem_conf_write_impl(struct pciem_root_complex *v, int where, int size, u32 value)
{
    if (!v)
    {
        return PCIBIOS_DEVICE_NOT_FOUND;
    }
    if (unlikely(v->detaching)) {
        return PCIBIOS_SUCCESSFUL;
    }
    if (where < 0 || (where + size) > (int)sizeof(v->cfg))
    {
        return PCIBIOS_DEVICE_NOT_FOUND;
    }

    if (pciem_handle_cap_write(v, where, size, value))
    {
        return PCIBIOS_SUCCESSFUL;
    }

    if (where >= PCI_BASE_ADDRESS_0 &&
        where < PCI_BASE_ADDRESS_0 + (4 * PCI_STD_NUM_BARS) &&
        (where % 4 == 0) &&
        size == 4)
    {
        int idx = (where - PCI_BASE_ADDRESS_0) / 4;
        return pciem_write_bar_address(v, idx, value);
    }

    if (where == PCI_ROM_ADDRESS)
        return PCIBIOS_SUCCESSFUL;

    switch (size)
    {
    case 1:
        v->cfg[where] = (u8)value;
        break;
    case 2:
        *(u16 *)&v->cfg[where] = (u16)value;
        break;
    case 4:
        *(u32 *)&v->cfg[where] = (u32)value;
        break;
    default:
        return PCIBIOS_FUNC_NOT_SUPPORTED;
    }
    return PCIBIOS_SUCCESSFUL;
}

static int vph_read_config(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 *value)
{
    struct pciem_root_complex *v;

#ifdef CONFIG_X86
    struct pci_sysdata *sd = bus->sysdata;
    struct pciem_host_bridge_priv *priv = container_of(sd, struct pciem_host_bridge_priv, sd);
    v = priv->v;
#else
    struct pciem_host_bridge_priv *priv = bus->sysdata;
    v = priv->v;
#endif

    if (devfn != 0) {
        *value = ~0U;
        return PCIBIOS_DEVICE_NOT_FOUND;
    }

    return pciem_conf_read_impl(v, where, size, value);
}

static int vph_write_config(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 value)
{
    struct pciem_root_complex *v;

#ifdef CONFIG_X86
    struct pci_sysdata *sd = bus->sysdata;
    struct pciem_host_bridge_priv *priv = container_of(sd, struct pciem_host_bridge_priv, sd);
    v = priv->v;
#else
    struct pciem_host_bridge_priv *priv = bus->sysdata;
    v = priv->v;
#endif

    if (devfn != 0) return PCIBIOS_DEVICE_NOT_FOUND;
    return pciem_conf_write_impl(v, where, size, value);
}

static struct pci_ops vph_pci_ops = {
    .read = vph_read_config,
    .write = vph_write_config,
};

static int proxy_read_config(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 *value)
{
    if (!bus || !bus->ops)
        return PCIBIOS_DEVICE_NOT_FOUND;

    struct pciem_root_complex *v = container_of(bus->ops, struct pciem_root_complex,
                                                 mode_state.hijack.proxy_ops);

    if (unlikely(bus->ops != &v->mode_state.hijack.proxy_ops)) {
        pr_warn_once("proxy_read_config called with unexpected ops pointer\n");
        return v->mode_state.hijack.original_ops->read(bus, devfn, where, size, value);
    }

    if (bus->number == v->mode_state.hijack.target_bus->number &&
        PCI_SLOT(devfn) == v->mode_state.hijack.hijacked_slot) {

        /* FIXME: Function 0 for now */
        if (PCI_FUNC(devfn) > 0) {
            *value = ~0U;
            return PCIBIOS_DEVICE_NOT_FOUND;
        }
        return pciem_conf_read_impl(v, where, size, value);
    }

    return v->mode_state.hijack.original_ops->read(bus, devfn, where, size, value);
}

static int proxy_write_config(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 value)
{
    if (!bus || !bus->ops)
        return PCIBIOS_DEVICE_NOT_FOUND;

    struct pciem_root_complex *v = container_of(bus->ops, struct pciem_root_complex,
                                                 mode_state.hijack.proxy_ops);

    if (unlikely(bus->ops != &v->mode_state.hijack.proxy_ops)) {
        pr_warn_once("proxy_write_config called with unexpected ops pointer\n");
        return v->mode_state.hijack.original_ops->write(bus, devfn, where, size, value);
    }

    if (bus->number == v->mode_state.hijack.target_bus->number &&
        PCI_SLOT(devfn) == v->mode_state.hijack.hijacked_slot) {

        if (PCI_FUNC(devfn) > 0) return PCIBIOS_DEVICE_NOT_FOUND;
        return pciem_conf_write_impl(v, where, size, value);
    }

    return v->mode_state.hijack.original_ops->write(bus, devfn, where, size, value);
}

static struct pci_bus *pciem_find_suitable_root_bus(void)
{
    struct pci_bus *bus = NULL;
    struct pci_dev *pdev = NULL;

    bus = pci_find_bus(0, 0);
    if (bus) return bus;

    while ((pdev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, pdev)) != NULL) {
        if (pdev->bus && !pdev->bus->parent) {
            bus = pdev->bus;
            pci_dev_put(pdev);
            return bus;
        }
    }
    return NULL;
}

static int pciem_find_free_slot(struct pci_bus *bus)
{
    int slot;
    u32 vendor, class;

    if (!bus) return -ENODEV;

    for (slot = 1; slot < 32; slot++) {
        if (pci_bus_read_config_dword(bus, PCI_DEVFN(slot, 0), PCI_VENDOR_ID, &vendor))
            continue;

        if (vendor == 0xffffffff || vendor == 0x00000000) {
            if (pci_bus_read_config_dword(bus, PCI_DEVFN(slot, 0), PCI_CLASS_REVISION, &class) == 0) {
                class >>= 8;

                if ((class >> 8) == PCI_BASE_CLASS_BRIDGE)
                    continue;
            }

            pci_bus_read_config_dword(bus, PCI_DEVFN(slot, 1), PCI_VENDOR_ID, &vendor);

            if (vendor == 0xffffffff || vendor == 0x00000000)
                return slot;
        }
    }
    return -ENOSPC;
}

static struct resource *
pciem_find_iomem_region(struct resource *r, resource_size_t start,
                        resource_size_t end, struct resource **parent)
{
    struct resource *child;

    BUG_ON(start > end);

    while (r)
    {
        if (!(r->flags & IORESOURCE_MEM))
            goto next;

        /* Cannot fit in this region */
        if (start < r->start || end >= r->end)
            goto next;

        /* Return early if exact match */
        if (r->start == start && r->end == end)
            return r;

        /* Attempt to find in child node */
        *parent = r;
        child = pciem_find_iomem_region(r->child, start, end, parent);
        if (child)
            return child;

next:
        r = r->sibling;
    }

    return NULL;
}

static int pciem_init_virtual_root_mode(struct pciem_root_complex *v, struct list_head *resources)
{
    int rc, busnr = 1, domain = 0;
    struct pci_host_bridge *bridge;
    struct pciem_host_bridge_priv *priv;

    while (pci_find_bus(domain, busnr)) {
        busnr++;
        if (busnr > 255) {
            pr_err("init: No free bus number available\n");
            return -EBUSY;
        }
    }

    bridge = pci_alloc_host_bridge(sizeof(*priv));
    if (!bridge)
        return -ENOMEM;

    priv = pci_host_bridge_priv(bridge);
    priv->v = v;

    pciem_fixup_bridge_domain(bridge, priv, domain);

    bridge->dev.parent = &v->shared_bridge_pdev->dev;
    bridge->busnr = busnr;
    bridge->ops = &vph_pci_ops;
    list_splice_init(resources, &bridge->windows);

    rc = pci_host_probe(bridge);
    if (rc < 0) {
        pr_err("init: pci_host_probe failed: %d\n", rc);
        pci_free_host_bridge(bridge);
        return -ENODEV;
    }

    v->root_bus = bridge->bus;
    if (!v->root_bus) {
        pr_err("init: Failed to create root bus\n");
        return -ENODEV;
    }

    pci_bus_add_devices(v->root_bus);
    pciem_bus_init_resources(v);

    v->pciem_pdev = pci_get_domain_bus_and_slot(domain, v->root_bus->number, PCI_DEVFN(0, 0));
    if (!v->pciem_pdev) {
        pr_err("init: Failed to find emulated device\n");
        return -ENODEV;
    }

    v->mode_state.virtual_root.bridge = bridge;
    v->mode_state.virtual_root.assigned_domain = domain;
    v->mode_state.virtual_root.assigned_busnr = busnr;

    pr_info("init: Virtual root mode - domain %d, bus %d\n", domain, busnr);
    return 0;
}

static int pciem_init_attach_to_host_mode(struct pciem_root_complex *v)
{
    struct pci_bus *target_bus;
    struct pci_dev *dev;
    int slot, i;

    target_bus = pciem_find_suitable_root_bus();
    if (!target_bus) {
        pr_err("init: No suitable root bus found (paravirt environment?)\n");
        pr_err("init: Try using PCIEM_CREATE_FLAG_BUS_MODE_VIRTUAL instead\n");
        return -ENODEV;
    }

    pr_info("init: Targeting bus %04x:%02x for device injection\n",
            pci_domain_nr(target_bus), target_bus->number);

    slot = pciem_find_free_slot(target_bus);
    if (slot < 0) {
        pr_err("init: No free slots on target bus\n");
        return -ENOSPC;
    }

    pr_info("init: Injecting device at slot %02x on bus %04x:%02x\n",
            slot, pci_domain_nr(target_bus), target_bus->number);

    v->mode_state.hijack.target_bus = target_bus;
    v->mode_state.hijack.hijacked_slot = slot;
    v->mode_state.hijack.original_ops = target_bus->ops;

    v->mode_state.hijack.proxy_ops = *target_bus->ops;
    v->mode_state.hijack.proxy_ops.read = proxy_read_config;
    v->mode_state.hijack.proxy_ops.write = proxy_write_config;

    for (i = 0; i < PCI_STD_NUM_BARS; i++) {
        struct pciem_bar_info *bar = &v->bars[i];
        if (bar->size == 0) continue;
        if (i > 0 && (i % 2 == 1) && (v->bars[i - 1].flags & PCI_BASE_ADDRESS_MEM_TYPE_64))
            continue;

        bar->base_addr_val = (u32)(bar->phys_addr & 0xFFFFFFFF);
        if (bar->flags & PCI_BASE_ADDRESS_MEM_TYPE_64 && i+1 < PCI_STD_NUM_BARS) {
            v->bars[i+1].base_addr_val = (u32)(bar->phys_addr >> 32);
        }
    }

    /* FIXME: How usual would be for config space changes after system is booted? */
    pci_lock_rescan_remove();
    WRITE_ONCE(target_bus->ops, &v->mode_state.hijack.proxy_ops);
    /* FIXME: Are memory barriers needed here? */
    smp_mb();
    dev = pci_scan_single_device(target_bus, PCI_DEVFN(slot, 0));
    pci_unlock_rescan_remove();

    if (!dev) {
        pr_err("init: Scan failed to create device\n");
        WRITE_ONCE(target_bus->ops, v->mode_state.hijack.original_ops);
        return -ENODEV;
    }

    pr_info("init: Setting up device resources\n");
    for (i = 0; i < PCI_STD_NUM_BARS; i++) {
        struct pciem_bar_info *bar = &v->bars[i];

        if (bar->size == 0)
            continue;

        if (i > 0 && (i % 2 == 1) &&
            (v->bars[i - 1].flags & PCI_BASE_ADDRESS_MEM_TYPE_64))
            continue;

        if (bar->allocated_res) {
            dev->resource[i] = *bar->allocated_res;
            dev->resource[i].name = pci_name(dev);
            dev->resource[i].flags |= IORESOURCE_PCI_FIXED | IORESOURCE_BUSY;
            bar->res = &dev->resource[i];

            pr_info("init: BAR%d assigned: %pR\n", i, &dev->resource[i]);
        }
    }

    pci_bus_add_device(dev);

    v->pciem_pdev = dev;
    v->root_bus = target_bus;

    pr_info("init: Attach-to-host mode active: %s\n", pci_name(dev));
    return 0;
}

int pciem_complete_init(struct pciem_root_complex *v)
{
    int rc = 0;
    struct resource *mem_res = NULL;
    LIST_HEAD(resources);
    u32 i;

    struct platform_device_info pdevinfo = {
        .name = "pciem",
        .id = PLATFORM_DEVID_AUTO,
        .res = NULL,
        .num_res = 0,
    };
    
    v->shared_bridge_pdev = platform_device_register_full(&pdevinfo);

    if (IS_ERR(v->shared_bridge_pdev))
    {
        rc = PTR_ERR(v->shared_bridge_pdev);
        goto fail_pdev_null;
    }

    rc = pciem_p2p_init(v, p2p_regions);
    if (rc) {
        pr_warn("pciem: P2P init failed: %d (non-fatal)\n", rc);
    }

    for (i = 0; i < PCI_STD_NUM_BARS; i++)
    {
        struct pciem_bar_info *bar = &v->bars[i];
        struct pciem_bar_info *prev = i > 0 && (i % 2) == 1
            ? &v->bars[i - 1]
            : NULL;
        resource_size_t start, end;

        if (bar->size == 0)
            continue;

        if (prev && (prev->flags & PCI_BASE_ADDRESS_MEM_TYPE_64))
            continue;

        bar->order = get_order(bar->size);
        pr_info("init: preparing BAR%u physical memory (%llu KB, order %u)", i, (u64)bar->size / 1024, bar->order);

        if (!bar->carved_start || !bar->carved_end)
            continue;

        start = bar->carved_start;
        end = bar->carved_end;

        pr_info("init: BAR%u using pre-carved region [0x%llx-0x%llx]", i, (u64)start, (u64)end);

        struct resource *found = NULL;
        struct resource *parent = &iomem_resource;

        found = pciem_find_iomem_region(iomem_resource.child, start, end, &parent);

        /* Exact match */
        if (found)
        {
            pr_info("init: BAR%u found existing iomem resource: %s [0x%llx-0x%llx]", i,
                    found->name ? found->name : "<unnamed>", (u64)found->start, (u64)found->end);
            bar->allocated_res = found;
            bar->mem_owned_by_framework = false;
            bar->phys_addr = start;
            bar->pages = NULL;
        }
        else
        {
            mem_res = kzalloc(sizeof(*mem_res), GFP_KERNEL);
            if (!mem_res)
            {
                rc = -ENOMEM;
                goto fail_bars;
            }

            mem_res->name = kasprintf(GFP_KERNEL, "PCI BAR%u", i);
            if (!mem_res->name)
            {
                kfree(mem_res);
                rc = -ENOMEM;
                goto fail_bars;
            }

            mem_res->start = start;
            mem_res->end = end;
            mem_res->flags = IORESOURCE_MEM;

            pr_info("init: BAR%u inserting into parent resource: %s [0x%llx-0x%llx]", i,
                    parent->name ? parent->name : "<unnamed>", (u64)parent->start, (u64)parent->end);
            if (request_resource(parent, mem_res))
            {
                pr_err("init: BAR%u failed to insert into parent resource", i);
                kfree(mem_res->name);
                kfree(mem_res);
                rc = -EBUSY;
                goto fail_bars;
            }

            bar->allocated_res = mem_res;
            bar->mem_owned_by_framework = true;
            bar->phys_addr = start;
            bar->pages = NULL;
            pr_info("init: BAR%u successfully reserved [0x%llx-0x%llx]", i, (u64)start, (u64)end);
        }
    }

    rc = pciem_reserve_bars_res(v, &resources);
    if (rc)
        goto fail_res_list;

    switch (v->bus_mode) {
    case PCIEM_BUS_MODE_VIRTUAL_ROOT:
        pr_info("init: Initializing in VIRTUAL_ROOT mode\n");
        rc = pciem_init_virtual_root_mode(v, &resources);
        break;

    case PCIEM_BUS_MODE_ATTACH_TO_HOST:
        pr_info("init: Initializing in ATTACH_TO_HOST mode\n");
        rc = pciem_init_attach_to_host_mode(v);
        resource_list_free(&resources);
        break;

    default:
        pr_err("init: Unknown bus mode %d\n", v->bus_mode);
        rc = -EINVAL;
        goto fail_res_list;
    }

    if (rc)
        goto fail_device;

    pr_info("init: Device ready (mode: %s)\n",
            v->bus_mode == PCIEM_BUS_MODE_VIRTUAL_ROOT ? "virtual-root" : "attach-to-host");

    return 0;

fail_device:
    if (v->pciem_pdev) {
        if (v->bus_mode == PCIEM_BUS_MODE_ATTACH_TO_HOST) {
            pci_stop_and_remove_bus_device(v->pciem_pdev);
        } else {
            pci_dev_put(v->pciem_pdev);
        }
        v->pciem_pdev = NULL;
    }
    if (v->bus_mode == PCIEM_BUS_MODE_VIRTUAL_ROOT && v->root_bus) {
        pci_remove_root_bus(v->root_bus);
        v->root_bus = NULL;
    } else if (v->bus_mode == PCIEM_BUS_MODE_ATTACH_TO_HOST) {
        if (v->mode_state.hijack.target_bus && v->mode_state.hijack.original_ops) {
            pci_lock_rescan_remove();
            WRITE_ONCE(v->mode_state.hijack.target_bus->ops,
                      v->mode_state.hijack.original_ops);
            smp_mb();
            pci_unlock_rescan_remove();
        }
    }
fail_res_list:
    resource_list_free(&resources);
fail_bars:
    pciem_cleanup_bars(v);
    platform_device_unregister(v->shared_bridge_pdev);
fail_pdev_null:
    v->shared_bridge_pdev = NULL;
    return rc;
}
EXPORT_SYMBOL(pciem_complete_init);

static void pciem_teardown_device(struct pciem_root_complex *v)
{
    pr_info("exit: tearing down pciem device\n");

    irq_work_sync(&v->msi_irq_work);

    if (v->pciem_pdev) {
        struct device_driver *drv = v->pciem_pdev->dev.driver;

        if (drv) {
            pr_info("exit: Device %s bound to driver '%s' - initiating removal\n",
                    pci_name(v->pciem_pdev), drv->name);
            v->detaching = true;
        }

        pci_stop_and_remove_bus_device(v->pciem_pdev);
        v->pciem_pdev = NULL;
    }

    if (v->root_bus)
    {
        if (v->bus_mode == PCIEM_BUS_MODE_VIRTUAL_ROOT) {
            pci_remove_root_bus(v->root_bus);
        } else if (v->bus_mode == PCIEM_BUS_MODE_ATTACH_TO_HOST) {
            if (v->mode_state.hijack.original_ops) {
                pci_lock_rescan_remove();
                WRITE_ONCE(v->mode_state.hijack.target_bus->ops,
                        v->mode_state.hijack.original_ops);
                smp_mb();
                pci_unlock_rescan_remove();
                synchronize_rcu();
                pr_info("exit: Restored original bus ops\n");
            }
        }
        v->root_bus = NULL;
    }

    pciem_cleanup_bars(v);

    if (v->shared_bridge_pdev)
    {
        platform_device_unregister(v->shared_bridge_pdev);
        v->shared_bridge_pdev = NULL;
    }

    pciem_cleanup_cap_manager(v);
    pciem_p2p_cleanup(v);
}

static int __init pciem_init(void)
{
    int ret;
    pr_info("init: pciem framework loading\n");

    ret = pciem_userspace_init();
    if (ret) {
        pr_err("init: Failed to initialize userspace support: %d\n", ret);
        goto fail_userspace;
    }

    pciem_dev.minor = MISC_DYNAMIC_MINOR;
    pciem_dev.name = "pciem";
    pciem_dev.fops = &pciem_fops;
    pciem_dev.mode = 0666;

    ret = misc_register(&pciem_dev);
    if (ret) {
        pr_err("init: Failed to register main device: %d\n", ret);
        goto fail_misc;
    }

    pr_info("init: Created /dev/pciem for userspace device creation\n");
    pr_info("init: pciem framework loaded\n");
    return 0;

fail_misc:
    pciem_userspace_cleanup();
fail_userspace:
    return ret;
}

static void __exit pciem_exit(void)
{
    pr_info("exit: unloading pciem framework\n");

    misc_deregister(&pciem_dev);
    pciem_userspace_cleanup();
    pr_info("exit: Unregistered /dev/pciem\n");
    pr_info("exit: pciem framework done");
}

struct pciem_root_complex *pciem_alloc_root_complex(void)
{
    struct pciem_root_complex *v;
    int ret;

    v = kzalloc(sizeof(*v), GFP_KERNEL);
    if (!v)
        return ERR_PTR(-ENOMEM);

    rwlock_init(&v->bars_lock);
    rwlock_init(&v->cap_lock);

    /* Essential initialization that must happen */
    init_irq_work(&v->msi_irq_work, pciem_msi_irq_work_func);
    v->pending_msi_irq = 0;
    memset(v->bars, 0, sizeof(v->bars));

    ret = parse_phys_regions(v);
    if (ret) {
        kfree(v);
        return ERR_PTR(ret);
    }

    pr_info("Allocated pciem root complex\n");
    return v;
}
EXPORT_SYMBOL(pciem_alloc_root_complex);

void pciem_free_root_complex(struct pciem_root_complex *v)
{
    if (!v)
        return;

    pr_info("Freeing pciem root complex\n");
    pciem_teardown_device(v);
    kfree(v);
}
EXPORT_SYMBOL(pciem_free_root_complex);

static int pciem_open(struct inode *inode, struct file *file)
{
    struct pciem_userspace_state *us;

    us = pciem_userspace_create();
    if (IS_ERR(us))
        return PTR_ERR(us);

    file->private_data = us;
    return 0;
}

static long pciem_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    return pciem_device_fops.unlocked_ioctl(file, cmd, arg);
}

static int pciem_release(struct inode *inode, struct file *file)
{
    if (pciem_device_fops.release)
        return pciem_device_fops.release(inode, file);
    return 0;
}

static ssize_t pciem_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    if (pciem_device_fops.read)
        return pciem_device_fops.read(file, buf, count, ppos);
    return -EINVAL;
}

static ssize_t pciem_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    if (pciem_device_fops.write)
        return pciem_device_fops.write(file, buf, count, ppos);
    return -EINVAL;
}

static __poll_t pciem_poll(struct file *file, struct poll_table_struct *wait)
{
    if (pciem_device_fops.poll)
        return pciem_device_fops.poll(file, wait);
    return 0;
}

static int pciem_mmap(struct file *file, struct vm_area_struct *vma)
{
    if (pciem_device_fops.mmap)
        return pciem_device_fops.mmap(file, vma);
    return -EINVAL;
}

static const struct file_operations pciem_fops = {
    .owner = THIS_MODULE,
    .open = pciem_open,
    .release = pciem_release,
    .read = pciem_read,
    .write = pciem_write,
    .poll = pciem_poll,
    .unlocked_ioctl = pciem_ioctl,
    .compat_ioctl = pciem_ioctl,
    .mmap = pciem_mmap,
};

module_init(pciem_init);
module_exit(pciem_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("cakehonolulu (cakehonolulu@protonmail.com)");
MODULE_DESCRIPTION("Synthetic PCIe device framework");
