#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/pci.h>
#include <linux/pci_ids.h>

#include "pciem_device.h"
#include "pciem_framework.h"
#include "pciem_ops.h"
#include <asm/cacheflush.h>
#include <asm/io.h>
#include <asm/tlbflush.h>
#include <linux/atomic.h>
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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cakehonolulu (cakehonolulu@protonmail.com)");
MODULE_DESCRIPTION("Synthetic PCIe device with QEMU forwarding - Page Fault Interception Framework");

#define DRIVER_NAME "pciem"
#define CTRL_DEVICE_NAME "pciem_ctrl"
#define PCIEM_IOCTL_MAGIC 0xAF
#define PCIEM_IOCTL_GET_BAR0 _IOR(PCIEM_IOCTL_MAGIC, 1, struct virt_bar_info)

static int use_qemu_forwarding = 0;
module_param(use_qemu_forwarding, int, 0644);
MODULE_PARM_DESC(use_qemu_forwarding, "Use QEMU forwarding (1) or internal emulation (0)");
static unsigned long pciem_force_phys = 0;
module_param(pciem_force_phys, ulong, 0444);
MODULE_PARM_DESC(pciem_force_phys, "Force use of this physical base for BAR0 (hex)");

#define SHIM_DEVICE_NAME "pciem_shim"

#define PCIEM_SHIM_IOC_MAGIC 'R'
#define PCIEM_SHIM_IOCTL_RAISE_IRQ _IOW(PCIEM_SHIM_IOC_MAGIC, 3, int)
#define PCIEM_SHIM_IOCTL_LOWER_IRQ _IOW(PCIEM_SHIM_IOC_MAGIC, 4, int)

struct shim_dma_read_op
{
    __u64 host_phys_addr;
    __u64 user_buf_addr;
    __u32 len;
    __u32 padding;
};
#define PCIEM_SHIM_IOCTL_DMA_READ _IOWR(PCIEM_SHIM_IOC_MAGIC, 5, struct shim_dma_read_op)

struct virt_bar_info
{
    u64 phys_start;
    u64 size;
};

static struct pciem_host *g_vph;
static struct pciem_device_ops *g_dev_ops;

void pciem_register_ops(struct pciem_device_ops *ops)
{
    if (!ops)
    {
        pr_err("Invalid pciem_device_ops provided!\n");
        return;
    }
    g_dev_ops = ops;
}
EXPORT_SYMBOL(pciem_register_ops);

void pciem_trigger_msi(struct pciem_host *v)
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
    struct pciem_host *v = container_of(work, struct pciem_host, msi_irq_work);
    unsigned int irq = v->pending_msi_irq;
    if (irq)
    {
        generic_handle_irq(irq);
    }
}

static bool req_queue_empty(struct pciem_host *v)
{
    return v->req_head == v->req_tail;
}

static bool req_queue_full(struct pciem_host *v)
{
    return ((v->req_tail + 1) % MAX_PENDING_REQS) == v->req_head;
}

static void req_queue_put(struct pciem_host *v, struct shim_req *req)
{
    v->req_queue[v->req_tail] = *req;
    v->req_tail = (v->req_tail + 1) % MAX_PENDING_REQS;
    wake_up_interruptible(&v->req_wait);
}

static bool req_queue_get(struct pciem_host *v, struct shim_req *req)
{
    if (req_queue_empty(v))
        return false;
    *req = v->req_queue[v->req_head];
    v->req_head = (v->req_head + 1) % MAX_PENDING_REQS;
    wake_up_interruptible(&v->req_wait_full);
    return true;
}

static uint32_t alloc_req_id(struct pciem_host *v)
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

static void complete_req(struct pciem_host *v, uint32_t id, uint64_t data)
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

u64 pci_shim_read(u64 addr, u32 size)
{
    struct pciem_host *v = g_vph;
    struct shim_req req;
    uint32_t id;
    int slot;
    uint64_t result = 0;
    int ret;
    if (!v || atomic_read(&v->proxy_count) == 0)
        return 0xFFFFFFFFFFFFFFFFULL;
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
            return 0xFFFFFFFFFFFFFFFFULL;
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

int pci_shim_write(u64 addr, u64 data, u32 size)
{
    struct pciem_host *v = g_vph;
    struct shim_req req;

    if (!v || atomic_read(&v->proxy_count) == 0)
        return -ENODEV;

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
    struct pciem_host *v = container_of(miscdev, struct pciem_host, shim_miscdev);
    file->private_data = v;
    atomic_inc(&v->proxy_count);
    return 0;
}

static int shim_release(struct inode *inode, struct file *file)
{
    struct pciem_host *v = file->private_data;
    atomic_dec(&v->proxy_count);
    return 0;
}

static ssize_t shim_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    struct pciem_host *v = file->private_data;
    struct shim_req req;
    if (wait_event_interruptible(v->req_wait, !req_queue_empty(v)))
        return -ERESTARTSYS;
    mutex_lock(&v->shim_lock);
    if (req_queue_get(v, &req))
    {
        mutex_unlock(&v->shim_lock);
        if (copy_to_user(buf, &req, sizeof(req)))
            return -EFAULT;
        return sizeof(req);
    }
    mutex_unlock(&v->shim_lock);
    return 0;
}

static ssize_t shim_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    struct pciem_host *v = file->private_data;
    struct shim_resp resp;
    if (count != sizeof(resp))
        return -EINVAL;
    if (copy_from_user(&resp, buf, sizeof(resp)))
        return -EFAULT;
    mutex_lock(&v->shim_lock);
    complete_req(v, resp.id, resp.data);
    mutex_unlock(&v->shim_lock);
    return sizeof(resp);
}

static unsigned int shim_poll(struct file *file, poll_table *wait)
{
    struct pciem_host *v = file->private_data;
    unsigned int mask = 0;
    poll_wait(file, &v->req_wait, wait);
    if (!req_queue_empty(v))
        mask |= POLLIN | POLLRDNORM;
    return mask;
}

static long shim_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct pciem_host *v = file->private_data;
    if (!v->protopciem_pdev)
        return -ENODEV;

    switch (cmd)
    {
    case PCIEM_SHIM_IOCTL_RAISE_IRQ:
        atomic_set(&v->proxy_irq_pending, 1);
        wake_up_interruptible(&v->write_wait);
        break;
    case PCIEM_SHIM_IOCTL_LOWER_IRQ:
        break;
    case PCIEM_SHIM_IOCTL_DMA_READ: {
        struct shim_dma_read_op op;
        struct iommu_domain *domain;
        if (copy_from_user(&op, (void __user *)arg, sizeof(op)))
            return -EFAULT;
        domain = iommu_get_domain_for_dev(&v->protopciem_pdev->dev);
        if (!domain)
        {
            phys_addr_t real_phys_addr = op.host_phys_addr;
            void *kernel_va = phys_to_virt(real_phys_addr);
            if (!kernel_va)
            {
                pr_err("pciem: phys_to_virt failed (no-iommu path) for phys %llx\n", (u64)real_phys_addr);
                return -EFAULT;
            }
            clflush_cache_range(kernel_va, op.len);
            if (copy_to_user((void __user *)op.user_buf_addr, kernel_va, op.len))
            {
                pr_err("pciem: DMA read copy_to_user failed (no-iommu path)\n");
                return -EFAULT;
            }
        }
        else
        {
            size_t remaining = op.len;
            __u64 user_buf_addr = op.user_buf_addr;
            unsigned long iova = op.host_phys_addr;
            pr_info("pciem: Using IOMMU path for %u bytes from IOVA 0x%lx\n", op.len, iova);
            while (remaining > 0)
            {
                phys_addr_t hpa;
                void *kva;
                size_t chunk_len;
                hpa = iommu_iova_to_phys(domain, iova);
                if (!hpa)
                {
                    pr_err("pciem: iommu_iova_to_phys failed for IOVA 0x%lx\n", iova);
                    return -EFAULT;
                }
                chunk_len = min_t(size_t, remaining, PAGE_SIZE - (iova & ~PAGE_MASK));
                kva = memremap(hpa, chunk_len, MEMREMAP_WB);
                if (!kva)
                {
                    pr_err("pciem: memremap failed for HPA %pa\n", &hpa);
                    return -ENOMEM;
                }
                clflush_cache_range(kva, chunk_len);
                if (copy_to_user((void __user *)user_buf_addr, kva, chunk_len))
                {
                    memunmap(kva);
                    pr_err("pciem: copy_to_user failed (IOMMU path)\n");
                    return -EFAULT;
                }
                memunmap(kva);
                remaining -= chunk_len;
                user_buf_addr += chunk_len;
                iova += chunk_len;
            }
        }
        break;
    }
    default:
        return -ENOTTY;
    }
    return 0;
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
};

static const resource_size_t bar_sizes[6] = {PCIEM_BAR0_SIZE, 0, 0, 0, 0, 0};

static int vph_read_config(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 *value)
{
    struct pciem_host *v = g_vph;
    u32 val = ~0U;
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
    if (where >= 0x10 && where <= 0x27 && (where % 4 == 0) && size == 4)
    {
        int idx = (where - 0x10) / 4;
        resource_size_t bsize = bar_sizes[idx];
        if (bsize != 0)
        {
            u32 probe_val = (u32)(~(bsize - 1));
            u32 flags = PCI_BASE_ADDRESS_SPACE_MEMORY;
            if (idx == 0)
                flags |= PCI_BASE_ADDRESS_MEM_TYPE_64;
            if (v->bar_base[idx] == probe_val)
                val = probe_val | flags;
            else
                val = v->bar_base[idx] | flags;
        }
        else if (idx % 2 == 1 && bar_sizes[idx - 1] != 0)
        {
            int prev_idx = idx - 1;
            resource_size_t bsize_prev = bar_sizes[prev_idx];
            u32 probe_val_high = 0xffffffff;
            if (bsize_prev >= (1ULL << 32))
                probe_val_high = (u32)(~(bsize_prev - 1) >> 32);
            if (v->bar_base[idx] == probe_val_high)
                val = probe_val_high;
            else
                val = v->bar_base[idx];
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
    struct pciem_host *v = g_vph;
    if (!v)
        return PCIBIOS_DEVICE_NOT_FOUND;
    if (where < 0 || (where + size) > (int)sizeof(v->cfg))
        return PCIBIOS_DEVICE_NOT_FOUND;
    if (where >= 0x10 && where <= 0x27 && (where % 4 == 0) && size == 4)
    {
        int idx = (where - 0x10) / 4;
        resource_size_t bsize = bar_sizes[idx];
        if (bsize != 0)
        {
            u32 mask = (u32)(~(bsize - 1));
            v->bar_base[idx] = value & mask;
            return PCIBIOS_SUCCESSFUL;
        }
        else if (idx % 2 == 1 && bar_sizes[idx - 1] != 0)
        {
            v->bar_base[idx] = value;
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

static void vph_fill_config(struct pciem_host *v)
{
    memset(v->cfg, 0, sizeof(v->cfg));
    if (g_dev_ops && g_dev_ops->fill_config_space)
    {
        g_dev_ops->fill_config_space(v->cfg);
    }
    else
    {
        pr_err("pciem: no fill_config_space op provided!\n");
        *(u16 *)&v->cfg[0x00] = PCI_VENDOR_ID_REDHAT;
        *(u16 *)&v->cfg[0x02] = PCI_DEVICE_ID_RD890_IOMMU;
    }
}

static vm_fault_t pciem_bar_fault(struct vm_fault *vmf)
{
    struct vm_area_struct *vma = vmf->vma;
    struct pciem_host *v = vma->vm_private_data;
    unsigned long offset = vmf->address - vma->vm_start;
    pgoff_t pgoff = offset >> PAGE_SHIFT;
    unsigned long flags;

    pr_info("Page fault at offset 0x%lx (page %lu)", offset, pgoff);

    spin_lock_irqsave(&v->fault_lock, flags);

    vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);

    if (remap_pfn_range(vma, vmf->address & PAGE_MASK, (v->bar0_phys + (pgoff << PAGE_SHIFT)) >> PAGE_SHIFT, PAGE_SIZE,
                        vma->vm_page_prot))
    {
        spin_unlock_irqrestore(&v->fault_lock, flags);
        return VM_FAULT_SIGBUS;
    }

    atomic_set(&v->write_pending, 1);
    wake_up_interruptible(&v->write_wait);

    spin_unlock_irqrestore(&v->fault_lock, flags);

    return VM_FAULT_NOPAGE;
}

static void pciem_bar_vm_open(struct vm_area_struct *vma)
{
    struct pciem_host *v = vma->vm_private_data;
    unsigned long flags;

    pr_info("pciem: VMA opened: %p\n", vma);

    spin_lock_irqsave(&v->fault_lock, flags);
    if (!v->tracked_vma)
    {
        v->tracked_vma = vma;
        v->tracked_mm = vma->vm_mm;
    }
    spin_unlock_irqrestore(&v->fault_lock, flags);
}

static void pciem_bar_vm_close(struct vm_area_struct *vma)
{
    struct pciem_host *v = vma->vm_private_data;
    unsigned long flags;

    pr_info("pciem: VMA closing: %p\n", vma);

    spin_lock_irqsave(&v->fault_lock, flags);
    if (v->tracked_vma == vma)
    {
        v->tracked_vma = NULL;
        v->tracked_mm = NULL;
    }
    spin_unlock_irqrestore(&v->fault_lock, flags);
}

static const struct vm_operations_struct pciem_bar_vm_ops = {
    .fault = pciem_bar_fault,
    .open = pciem_bar_vm_open,
    .close = pciem_bar_vm_close,
};

static int vph_ctrl_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct pciem_host *v = g_vph;
    unsigned long size = vma->vm_end - vma->vm_start;

    if (!v || size > PCIEM_BAR0_SIZE)
        return -EINVAL;

    vma->vm_page_prot = vm_get_page_prot(vma->vm_flags & ~VM_WRITE);
    vma->vm_private_data = v;
    vma->vm_ops = &pciem_bar_vm_ops;

    if (remap_pfn_range(vma, vma->vm_start, v->bar0_phys >> PAGE_SHIFT, size, vma->vm_page_prot))
        return -EAGAIN;

    return 0;
}

static long vph_ctrl_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct pciem_host *v = g_vph;
    struct virt_bar_info info;
    int ret = 0;
    if (!v)
        return -ENODEV;
    mutex_lock(&v->ctrl_lock);
    switch (cmd)
    {
    case PCIEM_IOCTL_GET_BAR0:
        if (!v->bar0_res)
        {
            ret = -ENODEV;
            break;
        }
        info.phys_start = (u64)v->bar0_res->start;
        info.size = (u64)resource_size(v->bar0_res);
        if (copy_to_user((void __user *)arg, &info, sizeof(info)))
            ret = -EFAULT;
        else
            ret = 0;
        break;
    default:
        ret = -EINVAL;
    }
    mutex_unlock(&v->ctrl_lock);
    return ret;
}

static const struct file_operations vph_ctrl_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = vph_ctrl_ioctl,
    .mmap = vph_ctrl_mmap,
    .compat_ioctl = vph_ctrl_ioctl,
};

static int vph_emulator_thread(void *arg)
{
    struct pciem_host *v = arg;
    bool driver_wrote, proxy_irq;

    if (!v || !v->bar0_virt)
    {
        pr_err("Emulator thread started but BAR0 is not mapped!");
        return -EINVAL;
    }

    if (!g_dev_ops || !g_dev_ops->init_emulation_state || !g_dev_ops->poll_device_state ||
        !g_dev_ops->cleanup_emulation_state)
    {
        pr_err("Emulator thread started but device ops are not fully registered!\n");
        return -EINVAL;
    }

    if (g_dev_ops->init_emulation_state(v))
    {
        pr_err("Failed to init device emulation state\n");
        return -ENOMEM;
    }

    pr_info("Emulation thread started (Generic Framework)");

    while (!kthread_should_stop())
    {
        wait_event_interruptible_timeout(v->write_wait, (driver_wrote = atomic_xchg(&v->write_pending, 0)) ||
                                                            (proxy_irq = atomic_xchg(&v->proxy_irq_pending, 0)) ||
                                                            kthread_should_stop());

        if (kthread_should_stop())
            break;

        if (driver_wrote)
        {
            struct mm_struct *mm;
            struct vm_area_struct *vma;
            unsigned long flags;

            spin_lock_irqsave(&v->fault_lock, flags);
            mm = v->tracked_mm;
            spin_unlock_irqrestore(&v->fault_lock, flags);

            if (mm)
            {
                if (mmap_read_trylock(mm))
                {
                    spin_lock_irqsave(&v->fault_lock, flags);
                    vma = v->tracked_vma;
                    if (vma && vma->vm_mm == mm)
                    {
                        vma->vm_page_prot = vm_get_page_prot(vma->vm_flags & ~VM_WRITE);
                        zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);
                    }
                    spin_unlock_irqrestore(&v->fault_lock, flags);
                    mmap_read_unlock(mm);
                }
                else
                {
                    atomic_set(&v->write_pending, 1);
                }
            }
        }

        g_dev_ops->poll_device_state(v, proxy_irq);
    }

    g_dev_ops->cleanup_emulation_state(v);
    pr_info("Emulation (framework) thread stopped");
    return 0;
}

static int __init pciem_init(void)
{
    struct pciem_host *v;
    int rc = 0;
    struct resource *mem_res = NULL;
    LIST_HEAD(resources);
    int busnr = 1;
    int domain = 0;

    pciem_device_plugin_init();

    if (!g_dev_ops)
    {
        pr_err("pciem: No device logic plugin was registered!\n");
        return -ENODEV;
    }

    pr_info("init: pciem_hostbridge init (forwarding: %s)", use_qemu_forwarding ? "YES" : "NO");
    v = kzalloc(sizeof(*v), GFP_KERNEL);
    if (!v)
        return -ENOMEM;
    g_vph = v;
    init_irq_work(&v->msi_irq_work, pciem_msi_irq_work_func);
    v->pending_msi_irq = 0;
    mutex_init(&v->ctrl_lock);
    v->pci_mem_res = NULL;
    v->bar0_map_type = PCIEM_MAP_NONE;
    mutex_init(&v->shim_lock);
    v->next_id = 0;
    memset(v->pending, 0, sizeof(v->pending));
    init_waitqueue_head(&v->req_wait);
    init_waitqueue_head(&v->req_wait_full);
    v->req_head = v->req_tail = 0;
    atomic_set(&v->proxy_count, 0);
    spin_lock_init(&v->fault_lock);
    atomic_set(&v->write_pending, 0);
    atomic_set(&v->proxy_irq_pending, 0);
    init_waitqueue_head(&v->write_wait);
    v->device_private_data = NULL;

    v->pdev = platform_device_register_simple(DRIVER_NAME, -1, NULL, 0);
    if (IS_ERR(v->pdev))
    {
        rc = PTR_ERR(v->pdev);
        goto fail_free;
    }

#define PCIEM_MAX_TRIES 16
    v->bar0_order = get_order(PCIEM_BAR0_SIZE);
    pr_info("init: preparing BAR0 physical memory (%u KB, order %u)", PCIEM_BAR0_SIZE / 1024, v->bar0_order);
    if (pciem_force_phys)
    {
        resource_size_t start = (resource_size_t)pciem_force_phys;
        resource_size_t end = start + PCIEM_BAR0_SIZE - 1;
        struct resource *r, *found = NULL;
        pr_info("init: forced phys requested: 0x%llx -> candidate [0x%llx-0x%llx]", (unsigned long long)start,
                (unsigned long long)start, (unsigned long long)end);
        r = iomem_resource.child;
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
                    break;
                if (!found)
                    found = r;
            }
            r = r->sibling;
        }
        if (found && found->start == start && found->end == end)
        {
            pr_info("init: found existing iomem resource matching forced range: %s "
                    "[0x%llx-0x%llx]",
                    found->name ? found->name : "<unnamed>", (unsigned long long)found->start,
                    (unsigned long long)found->end);
            v->pci_mem_res = found;
            v->pci_mem_res_owned = false;
        }
        else
        {
            mem_res = kzalloc(sizeof(*mem_res), GFP_KERNEL);
            if (!mem_res)
            {
                rc = -ENOMEM;
                goto fail_pdev;
            }
            mem_res->name = kstrdup("PCI mem", GFP_KERNEL);
            if (!mem_res->name)
            {
                kfree(mem_res);
                mem_res = NULL;
                rc = -ENOMEM;
                goto fail_pdev;
            }
            mem_res->start = start;
            mem_res->end = end;
            mem_res->flags = IORESOURCE_MEM;
            if (request_resource(&iomem_resource, mem_res))
            {
                pr_err("init: forced phys 0x%llx busy (request_resource failed).", (unsigned long long)start);
                kfree(mem_res->name);
                kfree(mem_res);
                mem_res = NULL;
                rc = -EBUSY;
                goto fail_pdev;
            }
            v->pci_mem_res = mem_res;
            v->pci_mem_res_owned = true;
            pr_info("init: successfully reserved PCI MEM [0x%llx-0x%llx] (owned by "
                    "module)",
                    (unsigned long long)start, (unsigned long long)end);
        }
        v->bar0_pages = NULL;
        v->bar0_phys = start;
        v->bar0_virt = NULL;
        v->carved_start = start;
        v->carved_end = end;
    }
    else
    {
        int tries;
        for (tries = 0; tries < PCIEM_MAX_TRIES; tries++)
        {
            v->bar0_pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, v->bar0_order);
            if (!v->bar0_pages)
            {
                pr_err("init: alloc_pages() failed on try %d", tries);
                rc = -ENOMEM;
                goto fail_pdev;
            }
            v->bar0_virt = page_address(v->bar0_pages);
            v->bar0_phys = page_to_phys(v->bar0_pages);
            v->carved_start = v->bar0_phys;
            v->carved_end = v->bar0_phys + PCIEM_BAR0_SIZE - 1;
            mem_res = kzalloc(sizeof(*mem_res), GFP_KERNEL);
            if (!mem_res)
            {
                __free_pages(v->bar0_pages, v->bar0_order);
                v->bar0_pages = NULL;
                v->bar0_virt = NULL;
                rc = -ENOMEM;
                goto fail_pdev;
            }
            mem_res->name = kstrdup("PCI mem", GFP_KERNEL);
            if (!mem_res->name)
            {
                kfree(mem_res);
                __free_pages(v->bar0_pages, v->bar0_order);
                v->bar0_pages = NULL;
                v->bar0_virt = NULL;
                rc = -ENOMEM;
                goto fail_pdev;
            }
            mem_res->start = v->carved_start;
            mem_res->end = v->carved_end;
            mem_res->flags = IORESOURCE_MEM;
            if (request_resource(&iomem_resource, mem_res) == 0)
            {
                v->pci_mem_res = mem_res;
                pr_info("init: reserved PCI MEM [0x%llx-0x%llx] on try %d", (unsigned long long)v->pci_mem_res->start,
                        (unsigned long long)v->pci_mem_res->end, tries);
                mem_res = NULL;
                break;
            }
            kfree(mem_res->name);
            kfree(mem_res);
            mem_res = NULL;
            __free_pages(v->bar0_pages, v->bar0_order);
            v->bar0_pages = NULL;
            v->bar0_virt = NULL;
            v->bar0_phys = 0;
        }
        if (!v->pci_mem_res)
        {
            pr_err("init: failed to reserve PCI MEM after %d tries", PCIEM_MAX_TRIES);
            rc = -EBUSY;
            goto fail_pdev;
        }
        v->bar0_virt = NULL;
    }

    vph_fill_config(v);

    if (!g_dev_ops->setup_bars)
    {
        pr_err("pciem: no setup_bars op provided!\n");
        rc = -EINVAL;
        goto fail_res;
    }
    rc = g_dev_ops->setup_bars(v, &resources);
    if (rc)
    {
        pr_err("pciem: plugin setup_bars failed: %d\n", rc);
        goto fail_res_list;
    }

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
    v->root_bus = pci_scan_root_bus(&v->pdev->dev, busnr, &vph_pci_ops, v, &resources);
    if (!v->root_bus)
    {
        pr_err("init: pci_scan_bus failed");
        rc = -ENODEV;
        goto fail_res_list;
    }
    pci_bus_add_devices(v->root_bus);
    if (v->root_bus)
    {
        struct pci_dev *dev = pci_get_slot(v->root_bus, 0);
        if (dev)
        {
            dev->resource[0] = *v->pci_mem_res;
            dev->resource[0].flags |= IORESOURCE_BUSY;
            pci_dev_put(dev);
        }
    }
    pci_bus_assign_resources(v->root_bus);
    if (v->root_bus)
    {
        struct pci_dev *dev;
        dev = pci_get_slot(v->root_bus, 0);
        if (dev)
        {
            v->bar0_res = &dev->resource[0];
            pr_info("init: found pci_dev vendor=%04x device=%04x", dev->vendor, dev->device);
            pci_dev_put(dev);
        }
    }
    v->protopciem_pdev = pci_get_domain_bus_and_slot(domain, v->root_bus->number, PCI_DEVFN(0, 0));
    if (!v->protopciem_pdev)
    {
        pr_err("init: failed to find ProtoPCIem pci_dev");
        rc = -ENODEV;
        goto fail_misc_shim;
    }
    v->vph_miscdev.minor = MISC_DYNAMIC_MINOR;
    v->vph_miscdev.name = CTRL_DEVICE_NAME;
    v->vph_miscdev.fops = &vph_ctrl_fops;
    rc = misc_register(&v->vph_miscdev);
    if (rc)
    {
        pr_err("init: misc_register (ctrl) failed %d", rc);
        goto fail_bus;
    }
    if (use_qemu_forwarding)
    {
        pr_info("init: Registering shim misc device for forwarding\n");
        v->shim_miscdev.minor = MISC_DYNAMIC_MINOR;
        v->shim_miscdev.name = SHIM_DEVICE_NAME;
        v->shim_miscdev.fops = &shim_fops;
        v->shim_miscdev.groups = NULL;
        rc = misc_register(&v->shim_miscdev);
        if (rc)
        {
            pr_err("init: misc_register (shim) failed %d", rc);
            goto fail_misc_ctrl;
        }
    }
    v->bar0_virt = NULL;
    v->bar0_map_type = PCIEM_MAP_NONE;
    if (use_qemu_forwarding)
    {
        pr_info("init: QEMU poller mapping BAR0 as WC (ioremap_wc)");
        v->bar0_virt = ioremap_wc(v->bar0_phys, PCIEM_BAR0_SIZE);
        if (v->bar0_virt)
        {
            v->bar0_map_type = PCIEM_MAP_IOREMAP_WC;
        }
        else
        {
            pr_err("init: ioremap_wc() failed!");
            rc = -ENOMEM;
            goto fail_misc_shim;
        }
    }
    else
    {
        v->bar0_virt = ioremap_cache(v->bar0_phys, PCIEM_BAR0_SIZE);
        if (v->bar0_virt)
        {
            v->bar0_map_type = PCIEM_MAP_IOREMAP_CACHE;
        }
        else
        {
            pr_warn("init: ioremap_cache() failed; trying ioremap()");
            v->bar0_virt = ioremap(v->bar0_phys, PCIEM_BAR0_SIZE);
            if (v->bar0_virt)
                v->bar0_map_type = PCIEM_MAP_IOREMAP;
        }
    }
    if (!v->bar0_virt)
    {
        pr_err("init: Failed to create any mapping for BAR0");
        rc = -ENOMEM;
        goto fail_misc_shim;
    }
    pr_info("init: BAR0 mapped at %px for emulator (map_type=%d)", v->bar0_virt, v->bar0_map_type);
    v->emul_thread = kthread_run(vph_emulator_thread, v, "vph_emulator");
    if (IS_ERR(v->emul_thread))
    {
        rc = PTR_ERR(v->emul_thread);
        pr_err("init: failed to start emulation thread: %d", rc);
        goto fail_map;
    }
    pr_info("init: pciem_hostbridge ready. ctrl device: /dev/%s", CTRL_DEVICE_NAME);
    return 0;
fail_map:
    if (v->bar0_virt)
    {
        if (v->bar0_map_type == PCIEM_MAP_IOREMAP_CACHE || v->bar0_map_type == PCIEM_MAP_IOREMAP ||
            v->bar0_map_type == PCIEM_MAP_IOREMAP_WC)
            iounmap(v->bar0_virt);
        v->bar0_virt = NULL;
    }
fail_misc_shim:
    if (use_qemu_forwarding)
        misc_deregister(&v->shim_miscdev);
fail_misc_ctrl:
    misc_deregister(&v->vph_miscdev);
fail_bus:
    if (v->root_bus)
        pci_remove_root_bus(v->root_bus);
fail_res_list:
    resource_list_free(&resources);
fail_res:
    if (mem_res)
    {
        kfree(mem_res->name);
        kfree(mem_res);
    }
    if (v->bar0_pages)
        __free_pages(v->bar0_pages, v->bar0_order);
fail_pdev:
    platform_device_unregister(v->pdev);
fail_free:
    kfree(v);
    g_vph = NULL;
    return rc;
}

static void __exit pciem_exit(void)
{
    pr_info("exit: unloading pciem_hostbridge");
    if (!g_vph)
    {
        pr_info("exit: nothing to do");
        return;
    }
    if (g_vph->emul_thread)
        kthread_stop(g_vph->emul_thread);
    irq_work_sync(&g_vph->msi_irq_work);
    if (g_vph->protopciem_pdev)
    {
        pci_dev_put(g_vph->protopciem_pdev);
        g_vph->protopciem_pdev = NULL;
    }
    if (use_qemu_forwarding)
        misc_deregister(&g_vph->shim_miscdev);
    misc_deregister(&g_vph->vph_miscdev);
    if (g_vph->root_bus)
        pci_remove_root_bus(g_vph->root_bus);
    if (g_vph->bar0_virt)
    {
        if (g_vph->bar0_map_type == PCIEM_MAP_IOREMAP_CACHE || g_vph->bar0_map_type == PCIEM_MAP_IOREMAP ||
            g_vph->bar0_map_type == PCIEM_MAP_IOREMAP_WC)
            iounmap(g_vph->bar0_virt);
        g_vph->bar0_virt = NULL;
    }
    if (g_vph->pci_mem_res)
    {
        if (g_vph->pci_mem_res_owned)
        {
            release_resource(g_vph->pci_mem_res);
            kfree(g_vph->pci_mem_res->name);
            kfree(g_vph->pci_mem_res);
        }
        g_vph->pci_mem_res = NULL;
    }
    if (g_vph->bar0_pages)
    {
        __free_pages(g_vph->bar0_pages, g_vph->bar0_order);
        g_vph->bar0_pages = NULL;
    }
    if (g_vph->pdev)
        platform_device_unregister(g_vph->pdev);

    kfree(g_vph);
    g_vph = NULL;
    pr_info("exit: done");
}

module_init(pciem_init);
module_exit(pciem_exit);