#include "pciem_framework.h"
#include <linux/hashtable.h>
#include <linux/kprobes.h>
#include <linux/pci.h>
#include <linux/slab.h>

struct pciem_bar_mapping
{
    struct hlist_node node;
    struct pci_bus *bus;
    unsigned int devfn;
    int bar;
    void __iomem *virt_addr;
    char dev_name[32];
};

struct pci_iomap_data
{
    struct pci_dev *pdev;
    int bar;
};

#define PCIEM_MAPPING_HASH_BITS 8
static DEFINE_HASHTABLE(pciem_bar_mappings, PCIEM_MAPPING_HASH_BITS);
static DEFINE_SPINLOCK(pciem_mapping_lock);

static inline u32 pciem_hash(struct pci_bus *bus, unsigned int devfn, int bar)
{
    return hash_ptr(bus, PCIEM_MAPPING_HASH_BITS) ^ devfn ^ bar;
}

static void track_bar(struct pci_dev *pdev, int bar, void __iomem *vaddr)
{
    struct pciem_bar_mapping *m;

    if (!vaddr || !pdev || bar < 0 || bar >= PCI_STD_NUM_BARS)
        return;

    m = kmalloc(sizeof(*m), GFP_ATOMIC);
    if (!m)
        return;

    m->bus = pdev->bus;
    m->devfn = pdev->devfn;
    m->bar = bar;
    m->virt_addr = vaddr;
    snprintf(m->dev_name, sizeof(m->dev_name), "%s", pci_name(pdev));

    spin_lock(&pciem_mapping_lock);
    hash_add(pciem_bar_mappings, &m->node, pciem_hash(pdev->bus, pdev->devfn, bar));
    spin_unlock(&pciem_mapping_lock);

    pr_debug("PCIem: Tracked %s BAR%d -> %px\n", m->dev_name, bar, vaddr);
}

static int entry_pci_iomap(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct pci_iomap_data *data = (struct pci_iomap_data *)ri->data;
    data->pdev = (struct pci_dev *)regs_get_kernel_argument(regs, 0);
    data->bar = (int)regs_get_kernel_argument(regs, 1);

    return 0;
}

static int ret_pci_iomap(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct pci_iomap_data *data = (struct pci_iomap_data *)ri->data;
    void __iomem *vaddr = (void __iomem *)regs_return_value(regs);
    track_bar(data->pdev, data->bar, vaddr);
    return 0;
}

static int ret_generic(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct pci_iomap_data *data = (struct pci_iomap_data *)ri->data;
    void __iomem *vaddr = (void __iomem *)regs_return_value(regs);
    track_bar(data->pdev, data->bar, vaddr);
    return 0;
}

static int entry_generic(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct pci_iomap_data *data = (struct pci_iomap_data *)ri->data;
    data->pdev = (struct pci_dev *)regs_get_kernel_argument(regs, 0);
    data->bar = (int)regs_get_kernel_argument(regs, 1);
    return 0;
}

static int ret_pcim_iomap_regions(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct pci_iomap_data *data = (struct pci_iomap_data *)ri->data;
    int mask = data->bar;
    int ret = (int)regs_return_value(regs);
    void __iomem *const *iomap_table;
    int bar;

    if (ret != 0)
        return 0;

    iomap_table = pcim_iomap_table(data->pdev);
    if (!iomap_table)
        return 0;

    for (bar = 0; bar < PCI_STD_NUM_BARS; bar++)
    {
        if ((mask & (1 << bar)) && iomap_table[bar])
            track_bar(data->pdev, bar, iomap_table[bar]);
    }

    return 0;
}

static int entry_pcim_iomap_regions(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct pci_iomap_data *data = (struct pci_iomap_data *)ri->data;
    data->pdev = (struct pci_dev *)regs_get_kernel_argument(regs, 0);
    data->bar = (int)regs_get_kernel_argument(regs, 1);
    return 0;
}

static struct kretprobe kretprobes[] = {
    {.handler = ret_pci_iomap,
     .entry_handler = entry_pci_iomap,
     .data_size = sizeof(struct pci_iomap_data),
     .maxactive = 20},
    {.handler = ret_generic,
     .entry_handler = entry_generic,
     .data_size = sizeof(struct pci_iomap_data),
     .maxactive = 20},
    {.handler = ret_generic,
     .entry_handler = entry_generic,
     .data_size = sizeof(struct pci_iomap_data),
     .maxactive = 20},
    {.handler = ret_generic,
     .entry_handler = entry_generic,
     .data_size = sizeof(struct pci_iomap_data),
     .maxactive = 20},
    {.handler = ret_generic,
     .entry_handler = entry_generic,
     .data_size = sizeof(struct pci_iomap_data),
     .maxactive = 20},
    {.handler = ret_pcim_iomap_regions,
     .entry_handler = entry_pcim_iomap_regions,
     .data_size = sizeof(struct pci_iomap_data),
     .maxactive = 20},
};

static const char *symbols[] = {
    "pci_iomap", "pci_iomap_range", "pci_ioremap_bar", "pcim_iomap", "pci_ioremap_wc_bar", "pcim_iomap_regions",
};

#define NUM_PROBES ARRAY_SIZE(kretprobes)

int pciem_init_bar_tracking(void)
{
    int i, ret, failed = 0;

    BUILD_BUG_ON(ARRAY_SIZE(kretprobes) != ARRAY_SIZE(symbols));

    for (i = 0; i < NUM_PROBES; i++)
    {
        kretprobes[i].kp.symbol_name = symbols[i];
        ret = register_kretprobe(&kretprobes[i]);
        if (ret < 0)
        {
            pr_warn("PCIem: Failed to register %s: %d\n", symbols[i], ret);
            kretprobes[i].kp.symbol_name = NULL;
            failed++;
        }
    }

    if (failed == NUM_PROBES)
    {
        pr_err("PCIem: All kretprobes failed!\n");
        return -ENODEV;
    }

    pr_info("PCIem: BAR tracking active (%lu/%lu probes)\n", NUM_PROBES - failed, NUM_PROBES);
    return 0;
}

void pciem_disable_bar_tracking(void)
{
    int i;

    for (i = 0; i < NUM_PROBES; i++)
    {
        if (kretprobes[i].kp.symbol_name)
        {
            unregister_kretprobe(&kretprobes[i]);
            kretprobes[i].kp.symbol_name = NULL;
        }
    }

    pr_info("PCIem: BAR tracking disabled (mappings preserved)\n");
}

void pciem_cleanup_bar_tracking(void)
{
    struct pciem_bar_mapping *m;
    struct hlist_node *tmp;
    int i, bkt;

    for (i = 0; i < NUM_PROBES; i++)
    {
        if (kretprobes[i].kp.symbol_name)
            unregister_kretprobe(&kretprobes[i]);
    }

    spin_lock(&pciem_mapping_lock);
    hash_for_each_safe(pciem_bar_mappings, bkt, tmp, m, node)
    {
        hash_del(&m->node);
        kfree(m);
    }
    spin_unlock(&pciem_mapping_lock);
}

void __iomem *pciem_get_driver_bar_vaddr(struct pci_dev *pdev, int bar)
{
    struct pciem_bar_mapping *m;
    void __iomem *vaddr = NULL;

    if (!pdev || bar < 0 || bar >= PCI_STD_NUM_BARS)
        return NULL;

    spin_lock(&pciem_mapping_lock);
    hash_for_each_possible(pciem_bar_mappings, m, node, pciem_hash(pdev->bus, pdev->devfn, bar))
    {
        if (m->bus == pdev->bus && m->devfn == pdev->devfn && m->bar == bar)
        {
            vaddr = m->virt_addr;
            break;
        }
    }
    spin_unlock(&pciem_mapping_lock);

    return vaddr;
}
EXPORT_SYMBOL_GPL(pciem_get_driver_bar_vaddr);
EXPORT_SYMBOL_GPL(pciem_disable_bar_tracking);