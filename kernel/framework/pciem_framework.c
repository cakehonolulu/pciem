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
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/idr.h>

#include "pciem_capabilities.h"
#include "pciem_dma.h"
#include "pciem_framework.h"
#include "pciem_p2p.h"

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
    int bar_num;
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
        if (sscanf(token, "bar%d:0x%llx:0x%llx", &bar_num, &start, &size) == 3 ||
            sscanf(token, "bar%d:%llx:%llx", &bar_num, &start, &size) == 3)
        {
            if (bar_num < 0 || bar_num >= PCI_STD_NUM_BARS)
            {
                pr_warn("Invalid BAR number %d in phys_regions\n", bar_num);
                continue;
            }

            v->bars[bar_num].carved_start = start;
            v->bars[bar_num].carved_end = start + size - 1;
            pr_info("Parsed BAR%d phys region: 0x%llx-0x%llx\n", bar_num, (u64)start, (u64)(start + size - 1));
        }
    }

    kfree(str);
    return 0;
}

int pciem_register_bar(struct pciem_root_complex *v, int bar_num, resource_size_t size, u32 flags)
{
    if (bar_num < 0 || bar_num >= PCI_STD_NUM_BARS)
    {
        return -EINVAL;
    }

    if (size == 0)
    {
        v->bars[bar_num].size = 0;
        v->bars[bar_num].flags = 0;
        return 0;
    }

    if (size & (size - 1))
    {
        pr_err("pciem: BAR %d size 0x%llx is not a power of 2\n", bar_num, (u64)size);
        return -EINVAL;
    }

    v->bars[bar_num].size = size;
    v->bars[bar_num].flags = flags;
    v->bars[bar_num].base_addr_val = 0;

    pr_info("pciem: Registered BAR %d: size 0x%llx, flags 0x%x\n", bar_num, (u64)size, flags);

    return 0;
}
EXPORT_SYMBOL(pciem_register_bar);

void pciem_trigger_msi(struct pciem_root_complex *v)
{
    struct pci_dev *dev = v->pciem_pdev;
    if (!dev || !dev->msi_enabled || !dev->irq)
    {
        pr_warn("Cannot trigger MSI: device not ready or MSI not enabled/irq=0\n");
        return;
    }
    pr_info("Triggering virtual MSI for IRQ %u via irq_work", dev->irq);
    v->pending_msi_irq = dev->irq;
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

static void pciem_bus_copy_resources(struct pciem_root_complex *v)
{
    int i;
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
}

static int pciem_reserve_bar_res(struct pciem_bar_info *bar, int i, struct list_head *resources)
{
    struct resource_entry *entry;

    if (!bar->allocated_res)
        return 0;

    entry = resource_list_create_entry(bar->allocated_res, i);
    if (!entry)
        return -ENOMEM;

    resource_list_add_tail(entry, resources);
    pr_info("init: Added BAR%d to resource list", i);
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

static int pciem_map_bar_userspace(struct pciem_bar_info *bar, int i)
{
    pr_info("init: BAR%d userspace mode - lightweight kernel mapping", i);

    bar->virt_addr = ioremap(bar->phys_addr, bar->size);
    if (bar->virt_addr) {
        bar->map_type = PCIEM_MAP_IOREMAP;
        return 0;
    }

    pr_warn("init: BAR%d kernel mapping failed, continuing without it (userspace will map directly)", i);
    bar->map_type = PCIEM_MAP_NONE;
    bar->virt_addr = NULL;
    return 0;
}

static int pciem_map_bars(struct pciem_root_complex *v)
{
    int rc, i;
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

        bar->map_type = PCIEM_MAP_NONE;

        rc = pciem_map_bar_userspace(bar, i);

        if (rc) {
            pr_err("init: Failed to create mapping for BAR%d", i);
            return rc;
        }

        if (bar->virt_addr) {
            pr_info("init: BAR%d mapped at %px for emulator (map_type=%d)",
                    i, bar->virt_addr, bar->map_type);
        } else {
            pr_info("init: BAR%d physical at 0x%llx (no kernel mapping)",
                    i, (u64)bar->phys_addr);
        }
    }

    return 0;
}

static void pciem_cleanup_bar(struct pciem_bar_info *bar)
{
    if (bar->virt_addr)
    {
        if (bar->map_type == PCIEM_MAP_IOREMAP_CACHE || bar->map_type == PCIEM_MAP_IOREMAP ||
            bar->map_type == PCIEM_MAP_IOREMAP_WC)
        {
            iounmap(bar->virt_addr);
        }
        bar->virt_addr = NULL;
    }
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

static int vph_read_config(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 *value)
{
    struct pciem_root_complex *v;
    u32 val = ~0U;

#ifdef CONFIG_X86
    struct pci_sysdata *sd = bus->sysdata;
    struct pciem_host_bridge_priv *priv = container_of(sd, struct pciem_host_bridge_priv, sd);
    v = priv->v;
#else
    struct pciem_host_bridge_priv *priv = bus->sysdata;
    v = priv->v;
#endif

    if (!v || devfn != 0)
    {
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

    if (where >= 0x10 && where <= 0x27 && (where % 4 == 0) && size == 4)
    {
        int idx = (where - 0x10) / 4;
        resource_size_t bsize = v->bars[idx].size;

        if (bsize != 0)
        {
            u32 probe_val = (u32)(~(bsize - 1));
            u32 flags = v->bars[idx].flags;

            if (v->bars[idx].base_addr_val == probe_val)
            {
                val = probe_val | (flags & ~PCI_BASE_ADDRESS_MEM_MASK);
            }
            else
            {
                val = v->bars[idx].base_addr_val | (flags & ~PCI_BASE_ADDRESS_MEM_MASK);
            }
        }

        else if (idx > 0 && (idx % 2 == 1) && (v->bars[idx - 1].flags & PCI_BASE_ADDRESS_MEM_TYPE_64))
        {
            resource_size_t bsize_prev = v->bars[idx - 1].size;
            u32 probe_val_high = 0xffffffff;

            if (bsize_prev >= (1ULL << 32))
            {
                probe_val_high = (u32)(~(bsize_prev - 1) >> 32);
            }

            if (v->bars[idx].base_addr_val == probe_val_high)
            {
                val = probe_val_high;
            }
            else
            {
                val = v->bars[idx].base_addr_val;
            }
        }
        else
        {
            val = 0;
        }
    }
    else if (where == 0x30 && size == 4)
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

    if (!v)
    {
        return PCIBIOS_DEVICE_NOT_FOUND;
    }
    if (where < 0 || (where + size) > (int)sizeof(v->cfg))
    {
        return PCIBIOS_DEVICE_NOT_FOUND;
    }

    if (pciem_handle_cap_write(v, where, size, value))
    {
        return PCIBIOS_SUCCESSFUL;
    }

    if (where >= 0x10 && where <= 0x27 && (where % 4 == 0) && size == 4)
    {
        int idx = (where - 0x10) / 4;
        resource_size_t bsize = v->bars[idx].size;

        if (bsize != 0)
        {
            u32 mask = (u32)(~(bsize - 1));
            if (v->bars[idx].flags & PCI_BASE_ADDRESS_SPACE_IO)
            {
                mask &= ~PCI_BASE_ADDRESS_IO_MASK;
            }
            else
            {
                mask &= ~PCI_BASE_ADDRESS_MEM_MASK;
            }

            v->bars[idx].base_addr_val = value & mask;
            return PCIBIOS_SUCCESSFUL;
        }
        else if (idx > 0 && (idx % 2 == 1) && (v->bars[idx - 1].flags & PCI_BASE_ADDRESS_MEM_TYPE_64))
        {
            resource_size_t bsize_prev = v->bars[idx - 1].size;
            u32 mask_high = 0xffffffff;
            
            if (bsize_prev < (1ULL << 32))
            {
                mask_high = 0;
            }
            else
            {
                mask_high = (u32)(~(bsize_prev - 1) >> 32);
            }
            
            v->bars[idx].base_addr_val = value & mask_high;
            return PCIBIOS_SUCCESSFUL;
        }
    }
    else if (where == 0x30)
    {
        return PCIBIOS_SUCCESSFUL;
    }
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

static struct pci_ops vph_pci_ops = {
    .read = vph_read_config,
    .write = vph_write_config,
};

int pciem_complete_init(struct pciem_root_complex *v)
{
    int rc = 0;
    struct resource *mem_res = NULL;
    LIST_HEAD(resources);
    int busnr = 1;
    int domain = 0;
    int i;

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

    rc = parse_phys_regions(v);
    if (rc)
    {
        pr_err("pciem: Failed to parse physical regions: %d\n", rc);
        goto fail_pdev;
    }

    rc = pciem_p2p_init(v, p2p_regions);
    if (rc) {
        pr_warn("pciem: P2P init failed: %d (non-fatal)\n", rc);
    }

    for (i = 0; i < PCI_STD_NUM_BARS; i++)
    {
        struct pciem_bar_info *bar = &v->bars[i];
        resource_size_t start, end;

        if (bar->size == 0)
        {
            continue;
        }

        if (i > 0 && (i % 2 == 1) && (v->bars[i - 1].flags & PCI_BASE_ADDRESS_MEM_TYPE_64))
        {
            continue;
        }

        bar->order = get_order(bar->size);
        pr_info("init: preparing BAR%d physical memory (%llu KB, order %u)", i, (u64)bar->size / 1024, bar->order);

        if (bar->carved_start != 0 && bar->carved_end != 0)
        {
            start = bar->carved_start;
            end = bar->carved_end;

            pr_info("init: BAR%d using pre-carved region [0x%llx-0x%llx]", i, (u64)start, (u64)end);

            struct resource *r = iomem_resource.child;
            struct resource *found = NULL;
            struct resource *parent = NULL;

            while (r)
            {
                if ((r->flags & IORESOURCE_MEM) && r->start <= start && r->end >= end)
                {
                    struct resource *c = r->child;
                    while (c)
                    {
                        if ((c->flags & IORESOURCE_MEM) && c->start == start && c->end == end)
                        {
                            found = c;
                            break;
                        }
                        c = c->sibling;
                    }

                    if (found)
                    {
                        break;
                    }

                    if (!parent || (r->start >= parent->start && r->end <= parent->end))
                    {
                        parent = r;
                    }
                }
                r = r->sibling;
            }

            if (found && found->start == start && found->end == end)
            {
                pr_info("init: BAR%d found existing iomem resource: %s [0x%llx-0x%llx]", i,
                        found->name ? found->name : "<unnamed>", (u64)found->start, (u64)found->end);
                bar->allocated_res = found;
                bar->mem_owned_by_framework = false;
                bar->phys_addr = start;
                bar->virt_addr = NULL;
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

                mem_res->name = kasprintf(GFP_KERNEL, "PCI BAR%d", i);
                if (!mem_res->name)
                {
                    kfree(mem_res);
                    rc = -ENOMEM;
                    goto fail_bars;
                }

                mem_res->start = start;
                mem_res->end = end;
                mem_res->flags = IORESOURCE_MEM;

                if (parent)
                {
                    pr_info("init: BAR%d inserting into parent resource: %s [0x%llx-0x%llx]", i,
                            parent->name ? parent->name : "<unnamed>", (u64)parent->start, (u64)parent->end);
                    if (request_resource(parent, mem_res))
                    {
                        pr_err("init: BAR%d failed to insert into parent resource", i);
                        kfree(mem_res->name);
                        kfree(mem_res);
                        rc = -EBUSY;
                        goto fail_bars;
                    }
                }
                else
                {
                    if (request_resource(&iomem_resource, mem_res))
                    {
                        pr_err("init: BAR%d phys region 0x%llx busy (request_resource failed).", i, (u64)start);
                        kfree(mem_res->name);
                        kfree(mem_res);
                        rc = -EBUSY;
                        goto fail_bars;
                    }
                }

                bar->allocated_res = mem_res;
                bar->mem_owned_by_framework = true;
                bar->phys_addr = start;
                bar->virt_addr = NULL;
                bar->pages = NULL;
                pr_info("init: BAR%d successfully reserved [0x%llx-0x%llx]", i, (u64)start, (u64)end);
            }
        }
    }

    rc = pciem_reserve_bars_res(v, &resources);
    if (rc)
        goto fail_res_list;

    while (pci_find_bus(domain, busnr))
    {
        busnr++;
        if (busnr > 255)
        {
            pr_err("init: No free bus number available\n");
            rc = -EBUSY;
            goto fail_res_list;
        }
    }

    struct pci_host_bridge *bridge;
    struct pciem_host_bridge_priv *priv;

    bridge = pci_alloc_host_bridge(sizeof(*priv));
    if (!bridge) {
        rc = -ENOMEM;
        goto fail_res_list;
    }

    priv = pci_host_bridge_priv(bridge);
    priv->v = v;

    pciem_fixup_bridge_domain(bridge, priv, domain);

    bridge->dev.parent = &v->shared_bridge_pdev->dev;
    bridge->busnr = busnr;
    bridge->ops = &vph_pci_ops;
    list_splice_init(&resources, &bridge->windows);

    rc = pci_host_probe(bridge);

    if (rc < 0)
    {
        pr_err("init: pci_host_probe failed: %d\n", rc);
        pci_free_host_bridge(bridge);
        rc = -ENODEV;
        goto fail_res_list;
    }

    v->root_bus = bridge->bus;

    if (!v->root_bus)
    {
        pr_err("init: pci_scan_bus failed");
        rc = -ENODEV;
        goto fail_res_list;
    }

    pci_bus_add_devices(v->root_bus);

    if (v->root_bus)
        pciem_bus_copy_resources(v);

    pci_bus_assign_resources(v->root_bus);

    if (v->root_bus)
    {
        struct pci_dev *dev;
        dev = pci_get_slot(v->root_bus, 0);
        if (dev)
        {
            pr_info("init: found pci_dev vendor=%04x device=%04x", dev->vendor, dev->device);
            pci_dev_put(dev);
        }
    }

    v->pciem_pdev = pci_get_domain_bus_and_slot(domain, v->root_bus->number, PCI_DEVFN(0, 0));
    if (!v->pciem_pdev)
    {
        pr_err("init: failed to find ProtoPCIem pci_dev");
        rc = -ENODEV;
        goto fail_map;
    }

    rc = pciem_map_bars(v);
    if (rc)
        goto fail_map;

    pr_info("init: pciem instance ready");
    return 0;

fail_map:
    if (v->pciem_pdev)
    {
        pci_dev_put(v->pciem_pdev);
        v->pciem_pdev = NULL;
    }
    if (v->root_bus)
    {
        pci_remove_root_bus(v->root_bus);
    }
fail_res_list:
    resource_list_free(&resources);
fail_bars:
    pciem_cleanup_bars(v);
fail_pdev:
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

    if (v->pciem_pdev)
    {
        pci_dev_put(v->pciem_pdev);
        v->pciem_pdev = NULL;
    }

    if (v->root_bus)
    {
        pci_remove_root_bus(v->root_bus);
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

    ret = pciem_init_bar_tracking();
    if (ret) {
        pr_info("init: BAR tracking unavailable\n");
    }

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

    pciem_cleanup_bar_tracking();
    pr_info("exit: pciem framework done");
}

struct pciem_root_complex *pciem_alloc_root_complex(void)
{
    struct pciem_root_complex *v;

    v = kzalloc(sizeof(*v), GFP_KERNEL);
    if (!v)
        return ERR_PTR(-ENOMEM);

    /* Essential initialization that must happen */
    init_irq_work(&v->msi_irq_work, pciem_msi_irq_work_func);
    v->pending_msi_irq = 0;
    memset(v->bars, 0, sizeof(v->bars));

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
    .llseek = no_llseek,
};

module_init(pciem_init);
module_exit(pciem_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("cakehonolulu (cakehonolulu@protonmail.com)");
MODULE_DESCRIPTION("Synthetic PCIe device with QEMU forwarding");
