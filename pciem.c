#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <asm/cacheflush.h>
#include <asm/io.h>
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/ioport.h>
#include <linux/irq_work.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/pci-acpi.h>
#include <linux/pci_regs.h>
#include <linux/platform_device.h>
#include <linux/poll.h>
#include <linux/resource.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cakehonolulu (cakehonolulu@protonmail.com)");
MODULE_DESCRIPTION("Synthethic PCIe device with QEMU forwarding");

#define PCIEM_PCI_VENDOR_ID 0x1F0C
#define PCIEM_PCI_DEVICE_ID 0x0001
#define PCIEM_BAR0_SIZE (64 * 1024)
#define DRIVER_NAME "pciem"
#define CTRL_DEVICE_NAME "pciem_ctrl"
#define PCIEM_IOCTL_MAGIC 0xAF
#define PCIEM_IOCTL_GET_BAR0 _IOR(PCIEM_IOCTL_MAGIC, 1, struct virt_bar_info)

#define REG_CONTROL 0x00
#define REG_STATUS 0x04
#define REG_CMD 0x08
#define REG_DATA 0x0C
#define REG_RESULT_LO 0x10
#define REG_RESULT_HI 0x14
#define REG_DMA_SRC_LO 0x20
#define REG_DMA_SRC_HI 0x24
#define REG_DMA_DST_LO 0x28
#define REG_DMA_DST_HI 0x2C
#define REG_DMA_LEN 0x30

#define CTRL_ENABLE BIT(0)
#define CTRL_RESET BIT(1)
#define CTRL_START BIT(2)
#define STATUS_BUSY BIT(0)
#define STATUS_DONE BIT(1)
#define STATUS_ERROR BIT(2)

#define CMD_ADD 0x01
#define CMD_MULTIPLY 0x02
#define CMD_CHECKSUM 0x03
#define CMD_PROCESS_BUFFER 0x04
#define CMD_EXECUTE_CMDBUF 0x05
#define CMD_DMA_FRAME 0x06

static int use_qemu_forwarding = 0;
module_param(use_qemu_forwarding, int, 0644);
MODULE_PARM_DESC(use_qemu_forwarding, "Use QEMU forwarding (1) or internal emulation (0)");
static unsigned long pciem_force_phys = 0;
module_param(pciem_force_phys, ulong, 0444);
MODULE_PARM_DESC(pciem_force_phys, "Force use of this physical base for BAR0 (hex). Example: "
                                   "pciem_force_phys=0x1bf4c0000");

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

struct shim_req
{
    uint32_t id;
    uint32_t type;
    uint32_t size;
    uint64_t addr;
    uint64_t data;
} __attribute__((packed));

struct shim_resp
{
    uint32_t id;
    uint64_t data;
} __attribute__((packed));

#define MAX_PENDING_REQS 32
struct pending_req
{
    uint32_t id;
    bool valid;
    struct completion done;
    uint64_t result;
};

struct virt_bar_info
{
    u64 phys_start;
    u64 size;
};

enum pciem_map_type
{
    PCIEM_MAP_NONE = 0,
    PCIEM_MAP_MEMREMAP,
    PCIEM_MAP_IOREMAP_CACHE,
    PCIEM_MAP_IOREMAP,
    PCIEM_MAP_IOREMAP_WC,
};

struct pciem_host
{
    unsigned int msi_irq;
    struct irq_work msi_irq_work;
    unsigned int pending_msi_irq;
    irqreturn_t (*drv_irq_handler)(int, void *);
    struct pci_dev *protopciem_pdev;
    struct pci_bus *root_bus;
    u8 cfg[256];
    struct resource *bar0_res;
    struct mutex ctrl_lock;
    bool pci_mem_res_owned;
    u32 bar_base[6];
    void __iomem *bar0_virt;
    struct page *bar0_pages;
    enum pciem_map_type bar0_map_type;
    unsigned int bar0_order;
    phys_addr_t bar0_phys;
    struct resource *pci_mem_res;
    resource_size_t carved_start, carved_end;
    struct task_struct *emul_thread;
    struct platform_device *pdev;
    struct miscdevice vph_miscdev;

    struct miscdevice shim_miscdev;
    struct mutex shim_lock;
    uint32_t next_id;
    struct pending_req pending[MAX_PENDING_REQS];
    wait_queue_head_t req_wait;
    struct shim_req req_queue[MAX_PENDING_REQS];
    int req_head, req_tail;
    atomic_t proxy_count;
    struct page *bar0_page;

    u32 shadow_control;
    u32 shadow_status;
    u32 shadow_cmd;
    u32 shadow_data;
    u32 shadow_result_lo;
    u32 shadow_result_hi;
    u32 shadow_dma_src_lo;
    u32 shadow_dma_src_hi;
    u32 shadow_dma_dst_lo;
    u32 shadow_dma_dst_hi;
    u32 shadow_dma_len;

    wait_queue_head_t cmd_done_wait;
    atomic_t cmd_pending;
};

static struct pciem_host *g_vph;

static void pciem_trigger_msi(struct pciem_host *v)
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
    if (req_queue_full(v))
    {
        pr_warn("request queue full, dropping\n");
        return;
    }
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
    return true;
}

static uint32_t alloc_req_id(struct pciem_host *v)
{
    uint32_t id = v->next_id++;
    int slot = id % MAX_PENDING_REQS;
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

static u64 pci_shim_read(u64 addr, u32 size)
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
    slot = id % MAX_PENDING_REQS;
    req.id = id;
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

static void pci_shim_write(u64 addr, u64 data, u32 size)
{
    struct pciem_host *v = g_vph;
    struct shim_req req;
    if (!v || atomic_read(&v->proxy_count) == 0)
        return;
    mutex_lock(&v->shim_lock);
    req.id = alloc_req_id(v);
    req.type = 2;
    req.size = size;
    req.addr = addr;
    req.data = data;
    req_queue_put(v, &req);
    mutex_unlock(&v->shim_lock);
}

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
        atomic_set(&v->cmd_pending, 0);
        wake_up_interruptible(&v->cmd_done_wait);
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
            u64 iova = op.host_phys_addr;
            u64 user_vadd = op.user_buf_addr;
            pr_info("pciem: Using IOMMU page-by-page copy for %zu bytes from IOVA "
                    "0x%llx\n",
                    remaining, iova);
            while (remaining > 0)
            {
                phys_addr_t pa_of_page;
                void *page_va;
                size_t page_offset = iova & ~PAGE_MASK;
                size_t bytes_to_copy = min_t(size_t, PAGE_SIZE - page_offset, remaining);
                pa_of_page = iommu_iova_to_phys(domain, iova & PAGE_MASK);
                if (!pa_of_page)
                {
                    pr_err("pciem: iommu_iova_to_phys failed for IOVA %llx\n", (iova & PAGE_MASK));
                    return -EFAULT;
                }
                page_va = phys_to_virt(pa_of_page);
                clflush_cache_range(page_va + page_offset, bytes_to_copy);
                if (copy_to_user((void __user *)user_vadd, page_va + page_offset, bytes_to_copy))
                {
                    pr_err("pciem: copy_to_user failed (iommu path) at IOVA %llx\n", iova);
                    return -EFAULT;
                }
                remaining -= bytes_to_copy;
                iova += bytes_to_copy;
                user_vadd += bytes_to_copy;
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
    *(u16 *)&v->cfg[0x00] = PCIEM_PCI_VENDOR_ID;
    *(u16 *)&v->cfg[0x02] = PCIEM_PCI_DEVICE_ID;
    *(u16 *)&v->cfg[0x04] = PCI_COMMAND_MEMORY;
    *(u16 *)&v->cfg[0x06] = PCI_STATUS_CAP_LIST;
    v->cfg[0x08] = 0x00;
    v->cfg[0x09] = 0x00;
    v->cfg[0x0a] = 0x40;
    v->cfg[0x0b] = 0x0b;
    v->cfg[0x0e] = 0x00;
    v->cfg[PCI_CAPABILITY_LIST] = 0x50;
    *(u32 *)&v->cfg[0x30] = 0x00000000;
    v->cfg[0x3c] = 0x00;
    v->cfg[0x3d] = 0x01;
    v->cfg[0x50] = PCI_CAP_ID_MSI;
    v->cfg[0x51] = 0x00;
    *(u16 *)&v->cfg[0x52] = PCI_MSI_FLAGS_64BIT | PCI_MSI_FLAGS_MASKBIT | (1 << 7);
    *(u32 *)&v->cfg[0x54] = 0x00000000;
    *(u32 *)&v->cfg[0x58] = 0x00000000;
    *(u16 *)&v->cfg[0x5C] = 0x0000;
    *(u32 *)&v->cfg[0x60] = 0x00000000;
}

static int vph_ctrl_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct pciem_host *v = g_vph;
    unsigned long size = vma->vm_end - vma->vm_start;
    if (!v || size > PCIEM_BAR0_SIZE)
        return -EINVAL;
    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
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
    if (!v || !v->bar0_virt)
    {
        pr_err("Emulator thread started but BAR0 is not mapped!");
        return -EINVAL;
    }

    if (!use_qemu_forwarding)
    {
        pr_info("Emulation thread started (internal emulator)");
        while (!kthread_should_stop())
        {
            u32 control;
            memcpy(&control, v->bar0_virt + REG_CONTROL, sizeof(control));
            if (control & CTRL_RESET)
            {
                memset_io(v->bar0_virt, 0, PCIEM_BAR0_SIZE);
                msleep(1);
                continue;
            }
            if (control & CTRL_START)
            {
                u32 cmd, data;
                u64 result = 0;
                bool error = false;
                memcpy(&cmd, v->bar0_virt + REG_CMD, sizeof(cmd));
                memcpy(&data, v->bar0_virt + REG_DATA, sizeof(data));
                u32 bsy = STATUS_BUSY;
                memcpy(v->bar0_virt + REG_STATUS, &bsy, sizeof(bsy));
                msleep(1);
                switch (cmd)
                {
                case CMD_ADD:
                    result = data + 42;
                    break;
                case CMD_MULTIPLY:
                    result = (u64)data * 3ULL;
                    break;
                case CMD_CHECKSUM:
                    result = (u64)data ^ 0xABCD1234ULL;
                    break;
                case CMD_PROCESS_BUFFER:
                    result = 0;
                    break;
                default:
                    error = true;
                    break;
                }
                u32 lo = (u32)(result & 0xFFFFFFFF);
                u32 hi = (u32)(result >> 32);
                memcpy(v->bar0_virt + REG_RESULT_LO, &lo, sizeof(lo));
                memcpy(v->bar0_virt + REG_RESULT_HI, &hi, sizeof(hi));
                u32 status;
                memcpy(&status, v->bar0_virt + REG_STATUS, sizeof(status));
                status &= ~STATUS_BUSY;
                status |= STATUS_DONE;
                if (error)
                    status |= STATUS_ERROR;
                memcpy(v->bar0_virt + REG_STATUS, &status, sizeof(status));
                control &= ~CTRL_START;
                memcpy(v->bar0_virt + REG_CONTROL, &control, sizeof(control));
            }
            msleep(1);
        }
        pr_info("Emulation thread (internal) stopped");
        return 0;
    }

    pr_info("Emulation thread started (QEMU forwarding mode)");
    memset_io(v->bar0_virt, 0, PCIEM_BAR0_SIZE);
    v->shadow_control = 0;
    v->shadow_cmd = 0;
    v->shadow_data = 0;
    v->shadow_status = 0;
    v->shadow_result_lo = 0;
    v->shadow_result_hi = 0;
    v->shadow_dma_src_lo = 0;
    v->shadow_dma_src_hi = 0;
    v->shadow_dma_dst_lo = 0;
    v->shadow_dma_dst_hi = 0;
    v->shadow_dma_len = 0;

    while (!kthread_should_stop())
    {
        u32 mem_val;
        int ret = wait_event_interruptible_timeout(
            v->cmd_done_wait, atomic_read(&v->cmd_pending) == 0 || kthread_should_stop(), msecs_to_jiffies(100));
        if (kthread_should_stop())
            break;
        if (ret < 0)
            continue;

        memcpy(&mem_val, v->bar0_virt + REG_CONTROL, sizeof(mem_val));
        if (mem_val != v->shadow_control)
        {
            if (mem_val & CTRL_RESET)
            {
                pr_info("fwd: RESET detected");
                memset_io(v->bar0_virt, 0, PCIEM_BAR0_SIZE);
                v->shadow_control = 0;
                v->shadow_cmd = 0;
                v->shadow_data = 0;
                v->shadow_status = 0;
                v->shadow_result_lo = 0;
                v->shadow_result_hi = 0;
                v->shadow_dma_src_lo = 0;
                v->shadow_dma_src_hi = 0;
                v->shadow_dma_dst_lo = 0;
                v->shadow_dma_dst_hi = 0;
                v->shadow_dma_len = 0;
                atomic_set(&v->cmd_pending, 0);
                continue;
            }
            pci_shim_write(REG_CONTROL, mem_val, 4);
            v->shadow_control = mem_val;
        }

        memcpy(&mem_val, v->bar0_virt + REG_CMD, sizeof(mem_val));
        if (mem_val != v->shadow_cmd && mem_val != 0 && atomic_read(&v->cmd_pending) == 0)
        {
            u32 params[8];
            pr_info("fwd: NEW CMD detected: 0x%x", mem_val);
            atomic_set(&v->cmd_pending, 1);

            memcpy(&params[0], v->bar0_virt + REG_CONTROL, sizeof(u32));
            memcpy(&params[1], v->bar0_virt + REG_DATA, sizeof(u32));
            memcpy(&params[2], v->bar0_virt + REG_DMA_SRC_LO, sizeof(u32));
            memcpy(&params[3], v->bar0_virt + REG_DMA_SRC_HI, sizeof(u32));
            memcpy(&params[4], v->bar0_virt + REG_DMA_DST_LO, sizeof(u32));
            memcpy(&params[5], v->bar0_virt + REG_DMA_DST_HI, sizeof(u32));
            memcpy(&params[6], v->bar0_virt + REG_DMA_LEN, sizeof(u32));

            if (params[0] != v->shadow_control)
            {
                pci_shim_write(REG_CONTROL, params[0], 4);
                v->shadow_control = params[0];
            }
            if (params[1] != v->shadow_data)
            {
                pci_shim_write(REG_DATA, params[1], 4);
                v->shadow_data = params[1];
            }
            if (params[2] != v->shadow_dma_src_lo)
            {
                pci_shim_write(REG_DMA_SRC_LO, params[2], 4);
                v->shadow_dma_src_lo = params[2];
            }
            if (params[3] != v->shadow_dma_src_hi)
            {
                pci_shim_write(REG_DMA_SRC_HI, params[3], 4);
                v->shadow_dma_src_hi = params[3];
            }
            if (params[4] != v->shadow_dma_dst_lo)
            {
                pci_shim_write(REG_DMA_DST_LO, params[4], 4);
                v->shadow_dma_dst_lo = params[4];
            }
            if (params[5] != v->shadow_dma_dst_hi)
            {
                pci_shim_write(REG_DMA_DST_HI, params[5], 4);
                v->shadow_dma_dst_hi = params[5];
            }
            if (params[6] != v->shadow_dma_len)
            {
                pci_shim_write(REG_DMA_LEN, params[6], 4);
                v->shadow_dma_len = params[6];
            }

            pci_shim_write(REG_CMD, mem_val, 4);
            v->shadow_cmd = mem_val;
            u32 bsy = STATUS_BUSY;
            memcpy(v->bar0_virt + REG_STATUS, &bsy, sizeof(bsy));
            v->shadow_status = STATUS_BUSY;

            pr_info("fwd: Waiting for command completion...");
            ret = wait_event_interruptible_timeout(
                v->cmd_done_wait, atomic_read(&v->cmd_pending) == 0 || kthread_should_stop(), msecs_to_jiffies(5000));

            if (kthread_should_stop())
                break;
            if (ret == 0)
            {
                pr_err("fwd: Command timeout!");
                v->shadow_status = STATUS_ERROR | STATUS_DONE;
                u32 err = STATUS_ERROR | STATUS_DONE;
                memcpy(v->bar0_virt + REG_STATUS, &err, sizeof(err));
                v->shadow_cmd = 0;
                atomic_set(&v->cmd_pending, 0);
                continue;
            }
            if (ret < 0)
                continue;

            pr_info("fwd: Command completed via IRQ");
            u32 final_status, final_res_lo, final_res_hi;
            final_status = (u32)pci_shim_read(REG_STATUS, 4);
            final_res_lo = (u32)pci_shim_read(REG_RESULT_LO, 4);
            final_res_hi = (u32)pci_shim_read(REG_RESULT_HI, 4);
            pr_info("fwd: Got status=0x%x, res_lo=0x%x, res_hi=0x%x from QEMU", final_status, final_res_lo,
                    final_res_hi);
            memcpy(v->bar0_virt + REG_RESULT_LO, &final_res_lo, sizeof(final_res_lo));
            memcpy(v->bar0_virt + REG_RESULT_HI, &final_res_hi, sizeof(final_res_hi));
            wmb();
            memcpy(v->bar0_virt + REG_STATUS, &final_status, sizeof(final_status));
            v->shadow_result_lo = final_res_lo;
            v->shadow_result_hi = final_res_hi;
            v->shadow_status = final_status;
            v->shadow_cmd = 0;
            pciem_trigger_msi(v);
        }
    }
    pr_info("Emulation (forwarding) thread stopped");
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
    v->drv_irq_handler = NULL;
    mutex_init(&v->shim_lock);
    v->next_id = 0;
    memset(v->pending, 0, sizeof(v->pending));
    init_waitqueue_head(&v->req_wait);
    v->req_head = v->req_tail = 0;
    atomic_set(&v->proxy_count, 0);
    init_waitqueue_head(&v->cmd_done_wait);
    atomic_set(&v->cmd_pending, 0);
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
    {
        struct resource_entry *entry;
        if (!v->pci_mem_res)
        {
            pr_err("init: internal error: pci_mem_res is NULL\n");
            rc = -EINVAL;
            goto fail_res;
        }
        entry = resource_list_create_entry(v->pci_mem_res, 0);
        if (!entry)
        {
            rc = -ENOMEM;
            goto fail_res;
        }
        resource_list_add_tail(entry, &resources);
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
    pr_info("init: BAR0 mapped at %p for emulator (map_type=%d)", v->bar0_virt, v->bar0_map_type);
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