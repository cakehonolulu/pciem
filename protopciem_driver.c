#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("cakehonolulu (cakehonolulu@protonmail.com)");
MODULE_DESCRIPTION("ProtoPCIem Driver");

#define PCIEM_PCI_VENDOR_ID 0x1F0C
#define PCIEM_PCI_DEVICE_ID 0x0001

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

#define STATUS_BUSY BIT(0)
#define STATUS_DONE BIT(1)
#define STATUS_ERROR BIT(2)

#define CMD_ADD 0x01
#define CMD_MULTIPLY 0x02
#define CMD_XOR 0x03
#define CMD_PROCESS_BUFFER 0x04
#define CMD_EXECUTE_CMDBUF 0x05
#define CMD_DMA_FRAME 0x06

#define FB_WIDTH 640
#define FB_HEIGHT 480
#define FB_BPP 3
#define FB_PITCH (FB_WIDTH * FB_BPP)
#define FB_SIZE (FB_PITCH * FB_HEIGHT)
#define MMAP_SIZE (FB_SIZE * 2)

#define PROTOPCIEM_IOC_MAGIC 'a'
#define PROTOPCIEM_IOCTL_SUBMIT_FRAME _IOW(PROTOPCIEM_IOC_MAGIC, 1, __u32)

struct pci_device
{
    struct pci_dev *pdev;
    void __iomem *bar0;
    int irq;
    bool msi_enabled;
    struct workqueue_struct *wq;
    struct work_struct work;
    struct completion op_completion;
    spinlock_t lock;
    bool operation_pending;
    u32 last_command;
    u64 last_result;
    u64 operations_completed;
    u64 interrupts_received;
    u64 errors;
    struct miscdevice protopciem_miscdev;
    void *cmdbuf_virt;
    dma_addr_t cmdbuf_phys;
    size_t cmdbuf_size;
    void *framebuf_virt;
    dma_addr_t framebuf_phys;
    size_t framebuf_size;
};

static inline u32 pci_read_reg(struct pci_device *adev, u32 offset)
{
    return ioread32(adev->bar0 + offset);
}

static inline void pci_write_reg(struct pci_device *adev, u32 offset, u32 value)
{
    iowrite32(value, adev->bar0 + offset);
}

static inline void pci_write_reg64(struct pci_device *adev, u32 offset_lo, u64 value)
{
    pci_write_reg(adev, offset_lo, (u32)(value & 0xFFFFFFFF));
    pci_write_reg(adev, offset_lo + 4, (u32)(value >> 32));
}

static inline u64 pci_read_result(struct pci_device *adev)
{
    u32 lo = pci_read_reg(adev, REG_RESULT_LO);
    u32 hi = pci_read_reg(adev, REG_RESULT_HI);
    return ((u64)hi << 32) | lo;
}

static int pci_reset(struct pci_device *adev)
{
    u32 status;
    int timeout = 1000;
    pr_info("Resetting PCI card\n");
    pci_write_reg(adev, REG_CONTROL, CTRL_RESET);
    msleep(10);
    pci_write_reg(adev, REG_CONTROL, 0);
    while (timeout-- > 0)
    {
        status = pci_read_reg(adev, REG_STATUS);
        if (!(status & STATUS_BUSY))
            break;
        udelay(10);
    }
    if (timeout <= 0)
    {
        pr_err("Reset timeout\n");
        return -ETIMEDOUT;
    }
    pr_info("Reset complete\n");
    return 0;
}

static int pci_execute_command(struct pci_device *adev, u32 cmd, u32 data, u64 *result)
{
    unsigned long flags;
    u32 status;
    int ret = 0;
    long timeout_jiffies;
    spin_lock_irqsave(&adev->lock, flags);
    if (adev->operation_pending)
    {
        spin_unlock_irqrestore(&adev->lock, flags);
        return -EBUSY;
    }
    adev->operation_pending = true;
    adev->last_command = cmd;
    if (adev->irq)
    {
        reinit_completion(&adev->op_completion);
    }
    spin_unlock_irqrestore(&adev->lock, flags);
    pr_info("Executing command 0x%02x (IRQ: %s)\n", cmd, adev->irq ? "yes" : "no");
    pci_write_reg(adev, REG_STATUS, 0);
    if (cmd != CMD_EXECUTE_CMDBUF && cmd != CMD_DMA_FRAME)
    {
        pci_write_reg(adev, REG_DATA, data);
    }
    pci_write_reg(adev, REG_CONTROL, CTRL_ENABLE);
    wmb();
    pci_write_reg(adev, REG_CMD, cmd);
    if (adev->irq)
    {
        timeout_jiffies = msecs_to_jiffies(2000);
        if (!wait_for_completion_timeout(&adev->op_completion, timeout_jiffies))
        {
            pr_err("Operation timeout (IRQ mode)\n");
            ret = -ETIMEDOUT;
            spin_lock_irqsave(&adev->lock, flags);
            adev->operation_pending = false;
            spin_unlock_irqrestore(&adev->lock, flags);
        }
        else
        {
            pr_info("Command complete (IRQ mode)\n");
        }
        status = pci_read_reg(adev, REG_STATUS);
        if (status & STATUS_ERROR)
        {
            pr_err("Operation failed (IRQ mode), reported by device\n");
            ret = -EIO;
        }
    }
    else
    {
        int timeout_poll = 1000;
        pr_info("No IRQ, using polling mode\n");
        while (timeout_poll-- > 0)
        {
            status = pci_read_reg(adev, REG_STATUS);
            if (status & STATUS_DONE)
            {
                adev->last_result = pci_read_result(adev);
                if (status & STATUS_ERROR)
                {
                    pr_warn("Error in operation (Poll mode)\n");
                    adev->errors++;
                    ret = -EIO;
                }
                adev->operations_completed++;
                break;
            }
            udelay(100);
        }
        if (timeout_poll <= 0)
        {
            pr_err("Operation timeout (Poll mode)\n");
            ret = -ETIMEDOUT;
        }
        spin_lock_irqsave(&adev->lock, flags);
        adev->operation_pending = false;
        spin_unlock_irqrestore(&adev->lock, flags);
    }
    pci_write_reg(adev, REG_CONTROL, CTRL_ENABLE);
    if (ret == 0)
    {
        *result = adev->last_result;
    }
    return ret;
}

static irqreturn_t pci_irq_handler(int irq, void *data)
{
    struct pci_device *adev = data;
    u32 status = pci_read_reg(adev, REG_STATUS);
    if (!(status & (STATUS_DONE | STATUS_ERROR)))
    {
        return IRQ_NONE;
    }
    adev->interrupts_received++;
    pci_write_reg(adev, REG_STATUS, 0);
    queue_work(adev->wq, &adev->work);
    return IRQ_HANDLED;
}

static void pci_work_handler(struct work_struct *work)
{
    struct pci_device *adev = container_of(work, struct pci_device, work);
    unsigned long flags;
    u32 status;
    spin_lock_irqsave(&adev->lock, flags);
    if (adev->operation_pending)
    {
        status = pci_read_reg(adev, REG_STATUS);
        adev->last_result = pci_read_result(adev);
        pr_info("Work: result=0x%016llx\n", adev->last_result);
        if (status & STATUS_ERROR)
        {
            pr_warn("Work: Operation completed with error\n");
            adev->errors++;
        }
        pci_write_reg(adev, REG_CMD, 0);
        adev->operations_completed++;
        adev->operation_pending = false;
        complete(&adev->op_completion);
    }
    spin_unlock_irqrestore(&adev->lock, flags);
}

static ssize_t protopciem_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    struct pci_device *adev = container_of(file->private_data, struct pci_device, protopciem_miscdev);
    u64 result;
    int ret;
    if (count == 0)
        return 0;
    if (count > adev->cmdbuf_size)
    {
        pr_warn("Command buffer too large: %zu > %zu\n", count, adev->cmdbuf_size);
        return -EINVAL;
    }
    if (copy_from_user(adev->cmdbuf_virt, buf, count))
        return -EFAULT;
    pr_info("Submitting command buffer: host_phys=0x%llx, len=%zu\n", (u64)adev->cmdbuf_phys, count);
    pci_write_reg64(adev, REG_DMA_SRC_LO, adev->cmdbuf_phys);
    pci_write_reg64(adev, REG_DMA_DST_LO, 0);
    pci_write_reg(adev, REG_DMA_LEN, (u32)count);
    wmb();
    ret = pci_execute_command(adev, CMD_EXECUTE_CMDBUF, 0, &result);
    if (ret)
    {
        pr_err("CMD_EXECUTE_CMDBUF command failed: %d\n", ret);
        return ret;
    }
    pr_info("Command buffer processed, result=0x%llx\n", result);
    return count;
}

static long protopciem_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct pci_device *adev = container_of(file->private_data, struct pci_device, protopciem_miscdev);
    u64 result;
    int ret;
    u32 buffer_id;
    dma_addr_t frame_phys_addr;

    switch (cmd)
    {
    case PROTOPCIEM_IOCTL_SUBMIT_FRAME: {
        if (copy_from_user(&buffer_id, (void __user *)arg, sizeof(buffer_id)))
            return -EFAULT;

        if (buffer_id > 1)
        {
            pr_warn("DMA_FRAME: Invalid buffer_id %u\n", buffer_id);
            return -EINVAL;
        }

        frame_phys_addr = adev->framebuf_phys + (buffer_id * FB_SIZE);

        pr_info("DMA_FRAME: Submitting frame %u: host_phys=0x%llx, len=%u\n", buffer_id, (u64)frame_phys_addr,
                (u32)FB_SIZE);

        pci_write_reg64(adev, REG_DMA_SRC_LO, frame_phys_addr);
        pci_write_reg64(adev, REG_DMA_DST_LO, 0);
        pci_write_reg(adev, REG_DMA_LEN, (u32)FB_SIZE);

        wmb();

        ret = pci_execute_command(adev, CMD_DMA_FRAME, 0, &result);
        if (ret)
        {
            pr_err("CMD_DMA_FRAME command failed: %d\n", ret);
            return ret;
        }

        pr_info("Frame DMA processed, result=0x%llx\n", result);
        break;
    }
    default:
        return -ENOTTY;
    }
    return 0;
}

static int protopciem_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct pci_device *adev = container_of(file->private_data, struct pci_device, protopciem_miscdev);
    unsigned long size = vma->vm_end - vma->vm_start;
    unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;

    if (offset != 0 || size > adev->framebuf_size)
    {
        pr_warn("mmap invalid, offset %lu or size %lu > %zu\n", offset, size, adev->framebuf_size);
        return -EINVAL;
    }

    if (size != MMAP_SIZE)
    {
        pr_warn("mmap: Warning: App mapping %lu bytes, but driver allocated %zu "
                "(for double buffering)\n",
                size, adev->framebuf_size);
    }

    return dma_mmap_coherent(&adev->pdev->dev, vma, adev->framebuf_virt, adev->framebuf_phys, size);
}

static int protopciem_open(struct inode *inode, struct file *file)
{
    pr_info("Device opened\n");
    return 0;
}

static int protopciem_release(struct inode *inode, struct file *file)
{
    pr_info("Device released\n");
    return 0;
}

static const struct file_operations protopciem_fops = {
    .owner = THIS_MODULE,
    .open = protopciem_open,
    .release = protopciem_release,
    .write = protopciem_write,
    .unlocked_ioctl = protopciem_ioctl,
    .compat_ioctl = protopciem_ioctl,
    .mmap = protopciem_mmap,
};

static ssize_t stats_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct pci_device *adev = dev_get_drvdata(dev);
    return scnprintf(buf, PAGE_SIZE, "Operations: %llu\nInterrupts: %llu\nErrors: %llu\n", adev->operations_completed,
                     adev->interrupts_received, adev->errors);
}

static DEVICE_ATTR_RO(stats);
static struct attribute *pci_attrs[] = {
    &dev_attr_stats.attr,
    NULL,
};
static const struct attribute_group pci_attr_group = {
    .attrs = pci_attrs,
};
static const struct attribute_group *pci_groups[] = {
    &pci_attr_group,
    NULL,
};

static int pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    struct pci_device *adev;
    int ret = 0;
    pr_info("==== Probing PCI Card ====\n");
    pr_info("Vendor: 0x%04x Device: 0x%04x\n", pdev->vendor, pdev->device);
    adev = kzalloc(sizeof(*adev), GFP_KERNEL);
    if (!adev)
        return -ENOMEM;
    adev->pdev = pdev;
    spin_lock_init(&adev->lock);
    init_completion(&adev->op_completion);
    pci_set_drvdata(pdev, adev);
    ret = pci_enable_device(pdev);
    if (ret)
        goto err_free;
    ret = pci_request_regions(pdev, "protopciem_pci");
    if (ret)
        goto err_disable;
    adev->bar0 = pci_iomap(pdev, 0, 0);
    if (!adev->bar0)
    {
        ret = -ENOMEM;
        goto err_regions;
    }
    pr_info("BAR0 mapped at %px (size: %llu bytes)\n", adev->bar0, (u64)pci_resource_len(pdev, 0));

    ret = pci_enable_msi(pdev);
    if (ret == 0)
    {
        adev->msi_enabled = true;
        adev->irq = pdev->irq;
        pr_info("MSI enabled, IRQ: %d\n", adev->irq);
        ret = request_irq(adev->irq, pci_irq_handler, 0, "protopciem_pci", adev);
        if (ret)
        {
            pci_disable_msi(pdev);
            adev->msi_enabled = false;
            adev->irq = 0;
        }
    }
    if (!adev->msi_enabled && pdev->irq > 0)
    {
        adev->irq = pdev->irq;
        ret = request_irq(adev->irq, pci_irq_handler, IRQF_SHARED, "protopciem_pci", adev);
        if (ret)
            adev->irq = 0;
        else
            pr_info("Legacy interrupt enabled, IRQ: %d\n", adev->irq);
    }
    if (adev->irq == 0)
        pr_warn("No interrupt available. Driver will use polling.");

    pci_set_master(pdev);
    adev->wq = create_singlethread_workqueue("pci_wq");
    if (!adev->wq)
    {
        ret = -ENOMEM;
        goto err_irq;
    }
    INIT_WORK(&adev->work, pci_work_handler);
    pci_reset(adev);

    adev->cmdbuf_size = 64 * 1024;
    adev->cmdbuf_virt = dma_alloc_coherent(&pdev->dev, adev->cmdbuf_size, &adev->cmdbuf_phys, GFP_KERNEL);
    if (!adev->cmdbuf_virt)
    {
        dev_err(&pdev->dev, "Failed to allocate DMA command buffer\n");
        ret = -ENOMEM;
        goto err_wq;
    }
    dev_info(&pdev->dev, "DMA command buffer: virt=%px phys=%pad size=%zu\n", adev->cmdbuf_virt, &adev->cmdbuf_phys,
             adev->cmdbuf_size);

    adev->framebuf_size = MMAP_SIZE;
    adev->framebuf_virt = dma_alloc_coherent(&pdev->dev, adev->framebuf_size, &adev->framebuf_phys, GFP_KERNEL);
    if (!adev->framebuf_virt)
    {
        dev_err(&pdev->dev, "Failed to allocate DMA frame buffer\n");
        ret = -ENOMEM;
        goto err_dma_cmdbuf;
    }
    dev_info(&pdev->dev, "DMA frame buffer (double): virt=%px phys=%pad size=%zu\n", adev->framebuf_virt,
             &adev->framebuf_phys, adev->framebuf_size);

    adev->protopciem_miscdev.minor = MISC_DYNAMIC_MINOR;
    adev->protopciem_miscdev.name = "protopciem";
    adev->protopciem_miscdev.fops = &protopciem_fops;
    adev->protopciem_miscdev.parent = &pdev->dev;
    ret = misc_register(&adev->protopciem_miscdev);
    if (ret)
    {
        pr_err("Failed to register misc device: %d\n", ret);
        goto err_dma_framebuf;
    }

    pci_write_reg(adev, REG_CONTROL, CTRL_ENABLE);
    pr_info("Device enabled, ready for userspace on /dev/%s\n", adev->protopciem_miscdev.name);
    pr_info("==== Probe Complete ====\n");
    return 0;

err_dma_framebuf:
    dma_free_coherent(&pdev->dev, adev->framebuf_size, adev->framebuf_virt, adev->framebuf_phys);
err_dma_cmdbuf:
    dma_free_coherent(&pdev->dev, adev->cmdbuf_size, adev->cmdbuf_virt, adev->cmdbuf_phys);
err_wq:
    destroy_workqueue(adev->wq);
err_irq:
    if (adev->irq)
        free_irq(adev->irq, adev);
    if (adev->msi_enabled)
        pci_disable_msi(pdev);
    if (adev->bar0)
        pci_iounmap(pdev, adev->bar0);
err_regions:
    pci_release_regions(pdev);
err_disable:
    pci_disable_device(pdev);
err_free:
    kfree(adev);
    return ret;
}

static void pci_remove(struct pci_dev *pdev)
{
    struct pci_device *adev = pci_get_drvdata(pdev);
    pr_info("Removing PCI device\n");
    if (!adev)
        return;
    misc_deregister(&adev->protopciem_miscdev);
    if (adev->cmdbuf_virt)
    {
        dma_free_coherent(&pdev->dev, adev->cmdbuf_size, adev->cmdbuf_virt, adev->cmdbuf_phys);
    }
    if (adev->framebuf_virt)
    {
        dma_free_coherent(&pdev->dev, adev->framebuf_size, adev->framebuf_virt, adev->framebuf_phys);
    }
    pci_write_reg(adev, REG_CONTROL, 0);
    if (adev->wq)
    {
        cancel_work_sync(&adev->work);
        destroy_workqueue(adev->wq);
    }
    if (adev->irq)
        free_irq(adev->irq, adev);
    if (adev->msi_enabled)
        pci_disable_msi(pdev);
    if (adev->bar0)
        pci_iounmap(pdev, adev->bar0);
    pci_release_regions(pdev);
    pci_disable_device(pdev);
    kfree(adev);
    pr_info("Device removed\n");
}

static const struct pci_device_id pci_ids[] = {{PCI_DEVICE(PCIEM_PCI_VENDOR_ID, PCIEM_PCI_DEVICE_ID)},
                                               {
                                                   0,
                                               }};

MODULE_DEVICE_TABLE(pci, pci_ids);

static struct pci_driver pci_driver = {
    .name = "protopciem_pci",
    .id_table = pci_ids,
    .probe = pci_probe,
    .remove = pci_remove,
    .dev_groups = pci_groups,
};

module_pci_driver(pci_driver);