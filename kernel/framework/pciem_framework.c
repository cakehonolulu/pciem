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
#include "pciem_ops.h"
#include "pciem_p2p.h"

static int pciem_mode = PCIEM_MODE_INTERNAL;
module_param(pciem_mode, int, 0644);
MODULE_PARM_DESC(pciem_mode, "Operation mode: 0=internal (default), 1=qemu forwarding, 2=userspace emulation");

static char *pciem_phys_regions = "";
module_param(pciem_phys_regions, charp, 0444);
MODULE_PARM_DESC(pciem_phys_regions,
                 "Physical memory regions for BARs: bar0:0x1bf000000:0x10000,bar2:0x1bf010000:0x20000");

static char *p2p_regions = "";
module_param(p2p_regions, charp, 0444);
MODULE_PARM_DESC(p2p_regions,
    "P2P whitelist: 0xADDR:0xSIZE,0xADDR:0xSIZE");

static LIST_HEAD(pciem_devices);
static DEFINE_MUTEX(pciem_devices_lock);
static DEFINE_IDA(pciem_instance_ida);
static DEFINE_MUTEX(pciem_registration_lock);

static struct miscdevice pciem_dev;
static const struct file_operations pciem_fops;

int pciem_get_mode(void)
{
    return pciem_mode;
}
EXPORT_SYMBOL(pciem_get_mode);

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

int pciem_register_bar(struct pciem_root_complex *v, int bar_num, resource_size_t size, u32 flags, bool intercept_faults)
{
    if (bar_num < 0 || bar_num >= PCI_STD_NUM_BARS)
    {
        return -EINVAL;
    }

    if (size == 0)
    {
        v->bars[bar_num].size = 0;
        v->bars[bar_num].flags = 0;
        v->bars[bar_num].intercept_page_faults = false;
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
    v->bars[bar_num].intercept_page_faults = intercept_faults;

    pr_info("pciem: Registered BAR %d: size 0x%llx, flags 0x%x, fault_intercept=%d\n", bar_num, (u64)size, flags,
            intercept_faults);

    return 0;
}
EXPORT_SYMBOL(pciem_register_bar);

void pciem_trigger_msi(struct pciem_root_complex *v)
{
    struct pci_dev *dev = v->protopciem_pdev;
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

static bool req_queue_empty(struct pciem_root_complex *v)
{
    return v->req_head == v->req_tail;
}

static bool req_queue_full(struct pciem_root_complex *v)
{
    return ((v->req_tail + 1) % MAX_PENDING_REQS) == v->req_head;
}

static void req_queue_put(struct pciem_root_complex *v, struct pciem_tlp *req)
{
    v->req_queue[v->req_tail] = *req;
    v->req_tail = (v->req_tail + 1) % MAX_PENDING_REQS;
    wake_up_interruptible(&v->req_wait);
}

static bool req_queue_get(struct pciem_root_complex *v, struct pciem_tlp *req)
{
    if (req_queue_empty(v))
    {
        return false;
    }
    *req = v->req_queue[v->req_head];
    v->req_head = (v->req_head + 1) % MAX_PENDING_REQS;
    wake_up_interruptible(&v->req_wait_full);
    return true;
}

static uint32_t alloc_req_id(struct pciem_root_complex *v)
{
    uint32_t id;
    int slot;

    id = v->next_id++;
    slot = id % MAX_PENDING_REQS;

    if (v->pending[slot].valid)
    {
        pr_err("pciem: request slot %d is busy! (id %u). Out of request slots.\n", slot, id);
        v->next_id--;
        return (uint32_t)-1;
    }

    v->pending[slot].id = id;
    v->pending[slot].valid = true;
    init_completion(&v->pending[slot].done);
    v->pending[slot].result = 0;
    return id;
}

static void complete_req(struct pciem_root_complex *v, uint32_t id, uint64_t data)
{
    int slot = id % MAX_PENDING_REQS;
    if (!v->pending[slot].valid || v->pending[slot].id != id)
    {
        pr_warn("invalid response id=%u\n", id);
        return;
    }
    v->pending[slot].result = data;
    v->pending[slot].valid = false;
    complete(&v->pending[slot].done);
}

u64 pci_shim_read(struct pciem_root_complex *v, u64 addr, u32 size)
{
    struct pciem_tlp req;
    uint32_t id;
    int slot;
    uint64_t result = 0;
    int ret;
    if (!v || atomic_read(&v->proxy_count) == 0)
    {
        return 0xFFFFFFFFFFFFFFFFULL;
    }
    mutex_lock(&v->shim_lock);
    id = alloc_req_id(v);
    if (id == (uint32_t)-1)
    {
        mutex_unlock(&v->shim_lock);
        pr_err("Read failed, no free slots\n");
        return 0xFFFFFFFFFFFFFFFFULL;
    }
    slot = id % MAX_PENDING_REQS;
    req.id = id;

    while (req_queue_full(v))
    {
        mutex_unlock(&v->shim_lock);
        pr_warn_once("pciem: shim read blocking, queue full\n");
        if (wait_event_interruptible(v->req_wait_full, !req_queue_full(v)))
        {
            return 0xFFFFFFFFFFFFFFFFULL;
        }
        mutex_lock(&v->shim_lock);
    }

    req.type = 1;
    req.size = size;
    req.addr = addr;
    req.data = 0;
    req_queue_put(v, &req);
    mutex_unlock(&v->shim_lock);
    ret = wait_for_completion_timeout(&v->pending[slot].done, HZ * 5);
    if (ret == 0)
    {
        pr_err("Read timeout id=%u\n", id);
        return 0xFFFFFFFFFFFFFFFFULL;
    }
    result = v->pending[slot].result;
    return result;
}
EXPORT_SYMBOL(pci_shim_read);

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

static int pciem_map_bar_qemu(struct pciem_bar_info *bar, int i)
{
    pr_info("init: BAR%d QEMU poller mapping as WC (ioremap_wc)", i);
    bar->virt_addr = ioremap_wc(bar->phys_addr, bar->size);
    if (!bar->virt_addr)
    {
        pr_err("init: BAR%d ioremap_wc() failed!", i);
        return -ENOMEM;
    }
    bar->map_type = PCIEM_MAP_IOREMAP_WC;
    return 0;
}

static int pciem_map_bar_regular(struct pciem_bar_info *bar, int i)
{
    bar->virt_addr = ioremap_cache(bar->phys_addr, bar->size);
    if (bar->virt_addr)
    {
        bar->map_type = PCIEM_MAP_IOREMAP_CACHE;
        return 0;
    }

    pr_warn("init: BAR%d ioremap_cache() failed; trying ioremap()", i);
    bar->virt_addr = ioremap(bar->phys_addr, bar->size);
    if (bar->virt_addr)
    {
        bar->map_type = PCIEM_MAP_IOREMAP;
        return 0;
    }

    return -ENOMEM;
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
    int mode = pciem_get_mode();
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

        switch (mode) {
        case PCIEM_MODE_QEMU:
            rc = pciem_map_bar_qemu(bar, i);
        break;
        case PCIEM_MODE_USERSPACE:
            rc = pciem_map_bar_userspace(bar, i);
            break;
        case PCIEM_MODE_INTERNAL:
        default:
            rc = pciem_map_bar_regular(bar, i);
            break;
        }

        if (rc) {
            pr_err("init: Failed to create mapping for BAR%d in mode %d", i, mode);
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

int pci_shim_write(struct pciem_root_complex *v, u64 addr, u64 data, u32 size)
{
    struct pciem_tlp req;

    if (!v || atomic_read(&v->proxy_count) == 0)
    {
        return -ENODEV;
    }

    mutex_lock(&v->shim_lock);

    req.id = alloc_req_id(v);
    if (req.id == (uint32_t)-1)
    {
        pr_err("Write failed, no free slots\n");
        mutex_unlock(&v->shim_lock);
        return -EBUSY;
    }

    while (req_queue_full(v))
    {
        mutex_unlock(&v->shim_lock);
        pr_warn_once("pciem: shim write blocking, queue full\n");
        if (wait_event_interruptible(v->req_wait_full, !req_queue_full(v)))
        {
            complete_req(v, req.id, 0);
            return -ERESTARTSYS;
        }
        mutex_lock(&v->shim_lock);
    }

    req.type = 2;
    req.size = size;
    req.addr = addr;
    req.data = data;

    req_queue_put(v, &req);

    mutex_unlock(&v->shim_lock);
    return 0;
}
EXPORT_SYMBOL(pci_shim_write);

static int shim_open(struct inode *inode, struct file *file)
{
    struct miscdevice *miscdev = file->private_data;
    struct pciem_root_complex *v = container_of(miscdev, struct pciem_root_complex, shim_miscdev);
    file->private_data = v;
    atomic_inc(&v->proxy_count);
    return 0;
}

static int shim_release(struct inode *inode, struct file *file)
{
    struct pciem_root_complex *v = file->private_data;
    atomic_dec(&v->proxy_count);
    return 0;
}

static ssize_t shim_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    struct pciem_root_complex *v = file->private_data;
    struct pciem_tlp req;
    if (wait_event_interruptible(v->req_wait, !req_queue_empty(v)))
    {
        return -ERESTARTSYS;
    }
    guard(mutex)(&v->shim_lock);
    if (req_queue_get(v, &req))
    {
        if (copy_to_user(buf, &req, sizeof(req)))
        {
            return -EFAULT;
        }
        return sizeof(req);
    }
    return 0;
}

static ssize_t shim_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    struct pciem_root_complex *v = file->private_data;
    struct shim_resp resp;
    if (count != sizeof(resp))
    {
        return -EINVAL;
    }
    if (copy_from_user(&resp, buf, sizeof(resp)))
    {
        return -EFAULT;
    }
    guard(mutex)(&v->shim_lock);
    complete_req(v, resp.id, resp.data);
    return sizeof(resp);
}

static unsigned int shim_poll(struct file *file, poll_table *wait)
{
    struct pciem_root_complex *v = file->private_data;
    unsigned int mask = 0;
    poll_wait(file, &v->req_wait, wait);
    if (!req_queue_empty(v))
    {
        mask |= POLLIN | POLLRDNORM;
    }
    return mask;
}

static long shim_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct pciem_root_complex *v = file->private_data;
    if (!v->protopciem_pdev)
    {
        return -ENODEV;
    }

    switch (cmd)
    {
    case PCIEM_SHIM_IOCTL_RAISE_IRQ:
        atomic_set(&v->proxy_irq_pending, 1);
        wake_up_interruptible(&v->write_wait);
        break;
    case PCIEM_SHIM_IOCTL_LOWER_IRQ:
        break;
    case PCIEM_SHIM_IOCTL_DMA_READ_SHARED: {
        struct shim_dma_shared_op op;

        if (copy_from_user(&op, (void __user *)arg, sizeof(op)))
            return -EFAULT;

        if (op.len > v->shared_buf_size)
        {
            pr_err("pciem: DMA read len %u > shared buf size\n", op.len);
            return -EINVAL;
        }

        int ret = pciem_dma_read_from_guest(v, op.host_phys_addr, v->shared_buf_vaddr, op.len, 0);
        if (ret < 0)
        {
            pr_err("pciem: DMA read shared failed: %d\n", ret);
            return ret;
        }
        break;
    }
    case PCIEM_SHIM_IOCTL_DMA_READ: {
        struct shim_dma_read_op op;
        void *kbuf = NULL;
        int ret;

        if (copy_from_user(&op, (void __user *)arg, sizeof(op)))
            return -EFAULT;

        if (op.len <= v->shared_buf_size) {
            kbuf = v->shared_buf_vaddr;
        } else {
            kbuf = kmalloc(op.len, GFP_KERNEL);
            if (!kbuf) {
                pr_err("pciem: kmalloc failed for %u bytes\n", op.len);
                return -ENOMEM;
            }
        }

        ret = pciem_dma_read_from_guest(v, op.host_phys_addr, kbuf, op.len, 0);
        if (ret < 0) {
            pr_err("pciem: pciem_dma_read_from_guest failed: %d\n", ret);
            if (kbuf != v->shared_buf_vaddr)
                kfree(kbuf);
            return ret;
        }

        if (copy_to_user((void __user *)op.user_buf_addr, kbuf, op.len)) {
            pr_err("pciem: DMA read copy_to_user failed\n");
            if (kbuf != v->shared_buf_vaddr)
                kfree(kbuf);
            return -EFAULT;
        }

        if (kbuf != v->shared_buf_vaddr)
            kfree(kbuf);

        break;
    }
    case PCIEM_SHIM_IOCTL_P2P_READ: {
        struct pciem_p2p_op op;
        if (copy_from_user(&op, (void __user *)arg, sizeof(op)))
            return -EFAULT;

        return pciem_p2p_read(v, op.target_phys_addr,
                            v->shared_buf_vaddr, op.len);
    }

    case PCIEM_SHIM_IOCTL_P2P_WRITE: {
        struct pciem_p2p_op op;
        if (copy_from_user(&op, (void __user *)arg, sizeof(op)))
            return -EFAULT;

        return pciem_p2p_write(v, op.target_phys_addr,
                            v->shared_buf_vaddr, op.len);
    }
    default:
        return -ENOTTY;
    }
    return 0;
}

static int shim_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct pciem_root_complex *v = file->private_data;
    unsigned long size = vma->vm_end - vma->vm_start;

    if (size > v->shared_buf_size)
    {
        pr_err("pciem: mmap size %lu too large (max %zu)\n", size, v->shared_buf_size);
        return -EINVAL;
    }

    return dma_mmap_coherent(&v->protopciem_pdev->dev, vma, v->shared_buf_vaddr, v->shared_buf_dma, size);
}

static const struct file_operations shim_fops = {
    .owner = THIS_MODULE,
    .open = shim_open,
    .release = shim_release,
    .read = shim_read,
    .write = shim_write,
    .poll = shim_poll,
    .unlocked_ioctl = shim_ioctl,
    .compat_ioctl = shim_ioctl,
    .mmap = shim_mmap,
};

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

static void vph_fill_config(struct pciem_root_complex *v)
{
    memset(v->cfg, 0, sizeof(v->cfg));

    if (v->ops && v->ops->fill_config_space)
    {
        v->ops->fill_config_space(v->cfg);
    }
    else
    {
        pr_err("pciem: no fill_config_space op provided!\n");
        *(u16 *)&v->cfg[0x00] = PCI_VENDOR_ID_REDHAT;
        *(u16 *)&v->cfg[0x02] = PCI_DEVICE_ID_RD890_IOMMU;
    }

    pciem_init_cap_manager(v);

    if (v->ops && v->ops->register_capabilities)
    {
        if (v->ops->register_capabilities(v) < 0)
        {
            pr_err("pciem: register_capabilities failed\n");
        }
    }

    pciem_build_config_space(v);
}

static int vph_emulator_thread(void *arg)
{
    struct pciem_root_complex *v = arg;
    int i;

    if (!v)
    {
        pr_err("Emulator thread started but host is NULL!");
        return -EINVAL;
    }

    for (i = 0; i < PCI_STD_NUM_BARS; i++)
    {
        if (v->bars[i].size > 0 && v->bars[i].intercept_page_faults && v->bars[i].virt_addr)
        {
            break;
        }
    }

    if (i >= PCI_STD_NUM_BARS)
    {
        pr_warn("Emulator thread: No fault-intercepted BARs with mappings found");
    }

    if (!v->ops || !v->ops->init_emulation_state || !v->ops->poll_device_state ||
        !v->ops->cleanup_emulation_state)
    {
        pr_err("Emulator thread started but device ops are not fully registered!\n");
        return -EINVAL;
    }

    if (v->ops->init_emulation_state(v))
    {
        pr_err("Failed to init device emulation state\n");
        return -ENOMEM;
    }

    pr_info("Emulation thread started");

    if (v->ops->set_command_watchpoint)
        v->ops->set_command_watchpoint(v, true);

    while (!kthread_should_stop())
    {
        bool proxy_irq, guest_mmio;

        wait_event_interruptible(v->write_wait,
                                 ((proxy_irq = atomic_xchg(&v->proxy_irq_pending, 0)) ||
                                  (guest_mmio = atomic_xchg(&v->guest_mmio_pending, 0)) || kthread_should_stop()));

        if (kthread_should_stop())
        {
            break;
        }

        if (guest_mmio || proxy_irq)
        {
            v->ops->poll_device_state(v, proxy_irq);
        }
    }

    if (v->ops->set_command_watchpoint)
        v->ops->set_command_watchpoint(v, false);

    v->ops->cleanup_emulation_state(v);
    pr_info("Emulation thread stopped");
    return 0;
}

int pciem_complete_init(struct pciem_root_complex *v)
{
    int rc = 0;
    struct resource *mem_res = NULL;
    LIST_HEAD(resources);
    int busnr = 1;
    int domain = 0;
    int i;
    int mode = pciem_get_mode();

    if (mode != PCIEM_MODE_USERSPACE) {
        WARN_ON(!v->ops);
    }

    char pdev_name[32];
    snprintf(pdev_name, sizeof(pdev_name), "%s.%d", DRIVER_NAME, v->instance_id);

    v->pdev = platform_device_register_simple(pdev_name, -1, NULL, 0);
    if (IS_ERR(v->pdev))
    {
        rc = PTR_ERR(v->pdev);
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

    if (mode != PCIEM_MODE_USERSPACE) {
        if (!v->ops->register_bars)
        {
            pr_err("pciem: plugin has no register_bars op\n");
            rc = -EINVAL;
            goto fail_pdev;
        }
        rc = v->ops->register_bars(v);
        if (rc)
        {
            pr_err("pciem: plugin register_bars failed: %d\n", rc);
            goto fail_pdev;
        }
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

    if (mode != PCIEM_MODE_USERSPACE) {
        vph_fill_config(v);
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

    bridge->dev.parent = &v->pdev->dev;
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

    v->protopciem_pdev = pci_get_domain_bus_and_slot(domain, v->root_bus->number, PCI_DEVFN(0, 0));
    if (!v->protopciem_pdev)
    {
        pr_err("init: failed to find ProtoPCIem pci_dev");
        rc = -ENODEV;
        goto fail_bus;
    }

    if (pciem_get_mode() == PCIEM_MODE_QEMU)
    {
        pr_info("init: Registering shim misc device for forwarding\n");
        v->shim_miscdev.minor = MISC_DYNAMIC_MINOR;
        v->shim_miscdev.name = v->shim_dev_name;
        v->shim_miscdev.fops = &shim_fops;
        v->shim_miscdev.groups = NULL;
        rc = misc_register(&v->shim_miscdev);
        if (rc)
        {
            pr_err("init: misc_register (shim) failed %d", rc);
            goto fail_map;
        }
    }

    rc = pciem_map_bars(v);
    if (rc)
        goto fail_map;

    v->shared_buf_size = SHARED_BUF_SIZE;
    v->shared_buf_vaddr =
        dma_alloc_coherent(&v->protopciem_pdev->dev, v->shared_buf_size, &v->shared_buf_dma, GFP_KERNEL);
    if (!v->shared_buf_vaddr)
    {
        pr_err("pciem: Failed to allocate shared bounce buffer\n");
        rc = -ENOMEM;
        goto fail_map;
    }

    memset(v->shared_buf_vaddr, 0, v->shared_buf_size);

    if (mode != PCIEM_MODE_USERSPACE) {
        v->emul_thread = kthread_run(vph_emulator_thread, v, "vph_emu/%d", v->instance_id);
        if (IS_ERR(v->emul_thread))
        {
            rc = PTR_ERR(v->emul_thread);
            pr_err("init: failed to start emulation thread: %d", rc);
            goto fail_map;
        }
    } else {
        v->emul_thread = NULL;
    }

    pr_info("init: pciem instance %d ready. ctrl: %s", v->instance_id, v->ctrl_dev_name);
    return 0;

fail_map:
    if (pciem_get_mode() == PCIEM_MODE_QEMU)
    {
        misc_deregister(&v->shim_miscdev);
    }
fail_bus:
    if (v->protopciem_pdev)
    {
        pci_dev_put(v->protopciem_pdev);
        v->protopciem_pdev = NULL;
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
    platform_device_unregister(v->pdev);
fail_pdev_null:
    v->pdev = NULL;
    return rc;
}
EXPORT_SYMBOL(pciem_complete_init);

static void pciem_teardown_device(struct pciem_root_complex *v)
{
    pr_info("exit: tearing down pciem instance %d", v->instance_id);

    if (v->emul_thread)
    {
        kthread_stop(v->emul_thread);
        v->emul_thread = NULL;
    }

    irq_work_sync(&v->msi_irq_work);

    if (v->protopciem_pdev)
    {
        pci_dev_put(v->protopciem_pdev);
        v->protopciem_pdev = NULL;
    }

    if (pciem_get_mode() == PCIEM_MODE_QEMU)
    {
        misc_deregister(&v->shim_miscdev);
    }

    if (v->root_bus)
    {
        pci_remove_root_bus(v->root_bus);
        v->root_bus = NULL;
    }

    pciem_cleanup_bars(v);

    if (v->pdev)
    {
        platform_device_unregister(v->pdev);
        v->pdev = NULL;
    }

    pciem_cleanup_cap_manager(v);
    pciem_p2p_cleanup(v);

    v->device_private_data = NULL;
}

static int __init pciem_init(void)
{
    int ret;
    int mode = pciem_get_mode();
    const char *mode_names[] = {"INTERNAL", "QEMU", "USERSPACE"};
    const char *mode_str = (mode >= 0 && mode < 3) ? mode_names[mode] : "UNKNOWN";

    pr_info("init: pciem framework loading (mode: %s)\n", mode_str);

    if (mode == PCIEM_MODE_USERSPACE) {
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

        pr_info("init: Created /dev/pciem_main for userspace device creation\n");
    }

    ida_init(&pciem_instance_ida);
    INIT_LIST_HEAD(&pciem_devices);

    pr_info("init: pciem framework loaded. Waiting for device plugins.");
    return 0;

fail_misc:
    pciem_userspace_cleanup();
fail_userspace:
    return ret;
}

static void __exit pciem_exit(void)
{
    struct pciem_root_complex *v, *tmp;
    int mode = pciem_get_mode();

    pr_info("exit: unloading pciem framework\n");

    if (mode == PCIEM_MODE_USERSPACE) {
        misc_deregister(&pciem_dev);
        pciem_userspace_cleanup();
        pr_info("exit: Unregistered /dev/pciem_main\n");
    }

    guard(mutex)(&pciem_registration_lock);

    mutex_lock(&pciem_devices_lock);
    list_for_each_entry_safe(v, tmp, &pciem_devices, list_node)
    {
        pr_warn("exit: forcibly cleaning up instance %d\n", v->instance_id);
        list_del(&v->list_node);
        pciem_teardown_device(v);
        ida_free(&pciem_instance_ida, v->instance_id);
        kfree(v->ctrl_dev_name);
        kfree(v->shim_dev_name);
        kfree(v);
    }
    mutex_unlock(&pciem_devices_lock);

    ida_destroy(&pciem_instance_ida);

    pr_info("exit: pciem framework done");
}

struct pciem_root_complex *pciem_register_ops(struct pciem_epc_ops *ops)
{
    struct pciem_root_complex *v;
    int rc = 0;
    int id;

    if (!ops)
    {
        if (pciem_get_mode() != PCIEM_MODE_USERSPACE) {
            pr_err("Invalid (NULL) pciem_device_ops provided!\n");
            return ERR_PTR(-EINVAL);
        }
    }

    guard(mutex)(&pciem_registration_lock);

    id = ida_alloc(&pciem_instance_ida, GFP_KERNEL);
    if (id < 0) return ERR_PTR(id);

    v = kzalloc(sizeof(*v), GFP_KERNEL);
    if (!v) {
        ida_free(&pciem_instance_ida, id);
        return ERR_PTR(-ENOMEM);
    }

    v->instance_id = id;
    v->ops = ops;

    init_irq_work(&v->msi_irq_work, pciem_msi_irq_work_func);
    v->pending_msi_irq = 0;
    mutex_init(&v->ctrl_lock);
    mutex_init(&v->shim_lock);
    v->next_id = 0;
    memset(v->pending, 0, sizeof(v->pending));
    init_waitqueue_head(&v->req_wait);
    init_waitqueue_head(&v->req_wait_full);
    v->req_head = v->req_tail = 0;
    atomic_set(&v->proxy_count, 0);
    atomic_set(&v->proxy_irq_pending, 0);
    init_waitqueue_head(&v->write_wait);
    v->device_private_data = NULL;
    memset(v->bars, 0, sizeof(v->bars));

    v->ctrl_dev_name = kasprintf(GFP_KERNEL, "pciem_ctrl%d", id);
    v->shim_dev_name = kasprintf(GFP_KERNEL, "pciem_shim%d", id);

    if (!v->ctrl_dev_name || !v->shim_dev_name) {
        kfree(v->ctrl_dev_name);
        kfree(v->shim_dev_name);
        kfree(v);
        ida_free(&pciem_instance_ida, id);
        return ERR_PTR(-ENOMEM);
    }

    pr_info("Registering instance %d...\n", id);

    if (pciem_get_mode() != PCIEM_MODE_USERSPACE) {
        rc = pciem_complete_init(v);
        if (rc)
        {
            pr_err("Failed to complete device initialization: %d\n", rc);
            ida_free(&pciem_instance_ida, id);
            kfree(v->ctrl_dev_name);
            kfree(v->shim_dev_name);
            kfree(v);
            return ERR_PTR(rc);
        }

        if (!try_module_get(THIS_MODULE))
        {
            pr_err("Failed to get pciem framework module reference!\n");
            pciem_teardown_device(v);
            ida_free(&pciem_instance_ida, id);
            kfree(v->ctrl_dev_name);
            kfree(v->shim_dev_name);
            kfree(v);
            return ERR_PTR(-ENODEV);
        }
    }

    mutex_lock(&pciem_devices_lock);
    list_add_tail(&v->list_node, &pciem_devices);
    mutex_unlock(&pciem_devices_lock);

    pr_info("pciem device initialization complete for instance %d.\n", id);
    return v;
}
EXPORT_SYMBOL(pciem_register_ops);

void pciem_unregister_ops(struct pciem_root_complex *v)
{
    if (!v) {
        pr_warn("pciem: null passed to unregister\n");
        return;
    }

    guard(mutex)(&pciem_registration_lock);

    pr_info("Device instance %d unregistering...\n", v->instance_id);

    mutex_lock(&pciem_devices_lock);
    list_del(&v->list_node);
    mutex_unlock(&pciem_devices_lock);

    pciem_teardown_device(v);

    ida_free(&pciem_instance_ida, v->instance_id);
    kfree(v->ctrl_dev_name);
    kfree(v->shim_dev_name);
    kfree(v);

    if (pciem_get_mode() != PCIEM_MODE_USERSPACE) {
        module_put(THIS_MODULE);
    }
    pr_info("pciem device teardown complete.\n");
}
EXPORT_SYMBOL(pciem_unregister_ops);

static int pciem_open(struct inode *inode, struct file *file)
{
    struct pciem_userspace_state *us;

    if (pciem_get_mode() != PCIEM_MODE_USERSPACE) {
        pr_err("Main device only available in userspace mode (mode=2)\n");
        return -EINVAL;
    }

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
