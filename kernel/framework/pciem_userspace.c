#define pr_fmt(fmt) "pciem_userspace: " fmt

#include <linux/anon_inodes.h>
#include <linux/capability.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hw_breakpoint.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pci_regs.h>
#include <linux/perf_event.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#include "pciem_capabilities.h"
#include "pciem_dma.h"
#include "pciem_framework.h"
#include "pciem_p2p.h"
#include "pciem_userspace.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0)

#define IS_ERR_PCPU(ptr) (IS_ERR((const void *)(__force const unsigned long)(ptr)))
#define PTR_ERR_PCPU(ptr) (PTR_ERR((const void *)(__force const unsigned long)(ptr)))

#define EMPTY_FD (struct fd){0}

static struct file *fd_file(struct fd fd)
{
    return fd.file;
}

static bool fd_empty(struct fd fd)
{
    return unlikely(!fd.file);
}

#endif

static int pciem_device_release(struct inode *inode, struct file *file);
static ssize_t pciem_device_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos);
static long pciem_device_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static int pciem_device_mmap(struct file *file, struct vm_area_struct *vma);

const struct file_operations pciem_device_fops = {
    .owner = THIS_MODULE,
    .release = pciem_device_release,
    .write = pciem_device_write,
    .unlocked_ioctl = pciem_device_ioctl,
    .compat_ioctl = pciem_device_ioctl,
    .mmap = pciem_device_mmap,
};
EXPORT_SYMBOL(pciem_device_fops);

static int pciem_instance_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct pciem_userspace_state *us = file->private_data;
    struct pciem_bar_info *bar;
    unsigned long size = vma->vm_end - vma->vm_start;

    unsigned long bar_index = vma->vm_pgoff;

    if (!us || !us->rc)
        return -ENODEV;

    if (bar_index >= PCI_STD_NUM_BARS)
    {
        pr_err("pciem_instance: Invalid BAR index %lu via mmap offset\n", bar_index);
        return -EINVAL;
    }

    guard(read_lock)(&us->rc->bars_lock);
    bar = &us->rc->bars[bar_index];

    if (bar->size == 0 || bar->phys_addr == 0)
    {
        pr_err("pciem_instance: BAR%lu is not active or has no physical address\n", bar_index);
        return -EINVAL;
    }

    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

    if (remap_pfn_range(vma, vma->vm_start,
                        bar->phys_addr >> PAGE_SHIFT,
                        size, vma->vm_page_prot))
    {
        return -EAGAIN;
    }

    pr_debug("pciem_instance: Mapped BAR%lu (phys: 0x%llx) to userspace via instance FD\n",
            bar_index, (u64)bar->phys_addr);

    return 0;
}

static const struct file_operations pciem_instance_fops = {
    .owner = THIS_MODULE,
    .mmap = pciem_instance_mmap,
};

static void free_pending_request(struct pciem_userspace_state *us, struct pciem_pending_request *req)
{
    unsigned long flags;

    spin_lock_irqsave(&us->pending_lock, flags);
    hlist_del(&req->node);
    spin_unlock_irqrestore(&us->pending_lock, flags);

    kfree(req);
}

static struct pciem_pending_request *find_pending_request(struct pciem_userspace_state *us, uint64_t seq)
{
    struct pciem_pending_request *req;
    int hash = (int)(seq % ARRAY_SIZE(us->pending_requests));

    hlist_for_each_entry(req, &us->pending_requests[hash], node)
    {
        if (req->seq == seq)
            return req;
    }

    return NULL;
}

static void pciem_irqfd_shutdown(struct pciem_irqfd *irqfd)
{
    u64 cnt;

    list_del_init(&irqfd->list);

    eventfd_ctx_remove_wait_queue(irqfd->trigger, &irqfd->wait, &cnt);

    flush_work(&irqfd->inject_work);

    eventfd_ctx_put(irqfd->trigger);
    kfree(irqfd);
}

static void pciem_irqfds_init(struct pciem_irqfds *irqfds)
{
    spin_lock_init(&irqfds->lock);
    INIT_LIST_HEAD(&irqfds->items);
}

static void pciem_irqfds_shutdown(struct pciem_irqfds *irqfds)
{
    struct pciem_irqfd *irqfd, *tmp;

    guard(spinlock_irqsave)(&irqfds->lock);

    list_for_each_entry_safe(irqfd, tmp, &irqfds->items, list) {
        pciem_irqfd_shutdown(irqfd);
    }
}

static int pciem_shared_ring_alloc(struct pciem_userspace_state *us)
{
    struct page *page;
    int order = get_order(sizeof(struct pciem_shared_ring));

    page = alloc_pages(GFP_KERNEL_ACCOUNT | __GFP_ZERO | __GFP_COMP, order);
    if (!page)
        return -ENOMEM;

    us->shared_ring = page_address(page);
    atomic_set(&us->shared_ring->head, 0);
    atomic_set(&us->shared_ring->tail, 0);
    spin_lock_init(&us->shared_ring_lock);

    return 0;
}

struct pciem_userspace_state *pciem_userspace_create(void)
{
    struct pciem_userspace_state *us;
    int i, ret;

    us = kzalloc(sizeof(*us), GFP_KERNEL);
    if (!us)
        return ERR_PTR(-ENOMEM);

    ret = pciem_shared_ring_alloc(us);
    if (ret) {
        kfree(us);
        return ERR_PTR(ret);
    }

    for (i = 0; i < ARRAY_SIZE(us->pending_requests); i++)
        INIT_HLIST_HEAD(&us->pending_requests[i]);
    spin_lock_init(&us->pending_lock);
    us->next_seq = 1;

    atomic_set(&us->registered, PCIEM_UNREGISTERED);
    atomic_set(&us->event_pending, 0);

    spin_lock_init(&us->watchpoint_lock);
    for (i = 0; i < MAX_WATCHPOINTS; i++)
    {
        us->watchpoints[i].active = false;
        us->watchpoints[i].perf_bp = NULL;
    }

    us->eventfd = NULL;
    spin_lock_init(&us->eventfd_lock);

    pciem_irqfds_init(&us->irqfds);

    return us;
}

void pciem_userspace_destroy(struct pciem_userspace_state *us)
{
    struct pciem_pending_request *req;
    struct hlist_node *tmp;
    int i;

    if (!us)
        return;

    for (i = 0; i < MAX_WATCHPOINTS; i++)
    {
        if (us->watchpoints[i].active && us->watchpoints[i].perf_bp)
        {
            unregister_wide_hw_breakpoint(us->watchpoints[i].perf_bp);
            us->watchpoints[i].perf_bp = NULL;
            us->watchpoints[i].active = false;
        }
    }

    pciem_irqfds_shutdown(&us->irqfds);

    for (i = 0; i < ARRAY_SIZE(us->pending_requests); i++)
    {
        hlist_for_each_entry_safe(req, tmp, &us->pending_requests[i], node)
        {
            req->response_status = -ENODEV;
            complete(&req->done);
            hlist_del(&req->node);
            kfree(req);
        }
    }

    __free_pages(virt_to_page(us->shared_ring), get_order(sizeof(struct pciem_shared_ring)));

    kfree(us);
}

static bool pciem_shared_ring_push(struct pciem_userspace_state *us,
                                   struct pciem_event *event)
{
    int tail, next_tail, head;

    guard(spinlock_irqsave)(&us->shared_ring_lock);

    tail = atomic_read(&us->shared_ring->tail);
    next_tail = (tail + 1) % PCIEM_RING_SIZE;
    head = atomic_read(&us->shared_ring->head);

    if (next_tail == head)
        return false;

    memcpy(&us->shared_ring->events[tail], event, sizeof(*event));
    atomic_set_release(&us->shared_ring->tail, next_tail);

    return true;
}

static void pciem_eventfd_signal(struct pciem_userspace_state *us)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,7,0)
        eventfd_signal(us->eventfd, 1);
#else
        eventfd_signal(us->eventfd);
#endif
}

void pciem_userspace_queue_event(struct pciem_userspace_state *us, struct pciem_event *event)
{
    unsigned long flags;

    if (!us || !event)
        return;

    event->timestamp = ktime_get_ns();

    if (!pciem_shared_ring_push(us, event))
        pr_warn_ratelimited("Shared ring buffer full, dropping event for userspace (seq=%llu)\n",
                            event->seq);

    spin_lock_irqsave(&us->eventfd_lock, flags);
    if (us->eventfd)
        pciem_eventfd_signal(us);
    else
        atomic_set(&us->event_pending, 1);
    spin_unlock_irqrestore(&us->eventfd_lock, flags);
}

int pciem_userspace_wait_response(struct pciem_userspace_state *us, uint64_t seq, uint64_t *data_out,
                                  unsigned long timeout_ms)
{
    struct pciem_pending_request *req;
    unsigned long timeout_jiffies;
    int ret;

    req = find_pending_request(us, seq);
    if (!req)
        return -EINVAL;

    timeout_jiffies = msecs_to_jiffies(timeout_ms);
    ret = wait_for_completion_timeout(&req->done, timeout_jiffies);

    if (ret == 0)
    {
        pr_warn("Request seq=%llu timed out\n", seq);
        free_pending_request(us, req);
        return -ETIMEDOUT;
    }

    if (data_out)
        *data_out = req->response_data;

    ret = req->response_status;
    free_pending_request(us, req);

    return ret;
}

static int pciem_check_unregistered(struct pciem_userspace_state *us)
{
    int registered;

    if (!us->rc)
        return -EINVAL;

    registered = atomic_read_acquire(&us->registered);
    if (registered == PCIEM_REGISTERING)
        return -EBUSY;
    if (registered == PCIEM_REGISTERED)
        return -EINVAL;

    return 0;
}

static int pciem_check_registered(struct pciem_userspace_state *us)
{
    int registered;

    if (!us->rc)
        return -EINVAL;

    registered = atomic_read_acquire(&us->registered);
    if (registered == PCIEM_REGISTERING)
        return -EBUSY;
    if (registered == PCIEM_UNREGISTERED)
        return -EINVAL;

    return 0;
}

static int pciem_start_registration(struct pciem_userspace_state *us)
{
    int val = PCIEM_UNREGISTERED;

    if (!us->rc)
        return -EINVAL;

    if (atomic_try_cmpxchg_release(&us->registered, &val, PCIEM_REGISTERING))
        return 0;

    if (val == PCIEM_REGISTERING)
        return -EBUSY;

    /* If the cmpxchg() failed the state can only be REGISTERING
     * (checked above) or REGISTERED (this case), so return EINVAL */
    return -EINVAL;
}

static void pciem_cancel_registration(struct pciem_userspace_state *us)
{
    atomic_set_release(&us->registered, PCIEM_UNREGISTERED);
}

static void pciem_complete_registration(struct pciem_userspace_state *us)
{
    atomic_set_release(&us->registered, PCIEM_REGISTERED);
}

static int pciem_device_release(struct inode *inode, struct file *file)
{
    struct pciem_userspace_state *us = file->private_data;

    pr_info("Userspace device fd closed\n");

    if (us)
    {
        if (!pciem_check_registered(us))
        {
            pr_info("Cleaning up registered device instance\n");
            pciem_free_root_complex(us->rc);
            us->rc = NULL;
        }

        pciem_userspace_destroy(us);
    }

    return 0;
}

static ssize_t pciem_device_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    struct pciem_userspace_state *us = file->private_data;
    struct pciem_response response;
    struct pciem_pending_request *req;
    unsigned long flags;

    if (count < sizeof(response))
        return -EINVAL;

    if (copy_from_user(&response, buf, sizeof(response)))
        return -EFAULT;

    spin_lock_irqsave(&us->pending_lock, flags);
    req = find_pending_request(us, response.seq);
    if (req)
    {
        req->response_data = response.data;
        req->response_status = response.status;
        complete(&req->done);
    }
    spin_unlock_irqrestore(&us->pending_lock, flags);

    if (!req)
        return -EINVAL;

    return sizeof(response);
}

static int pciem_device_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct pciem_userspace_state *us = file->private_data;
    unsigned long pfn;
    int ret;

    pfn = page_to_pfn(virt_to_page(us->shared_ring));
    ret = remap_pfn_range(vma, vma->vm_start, pfn, vma->vm_end - vma->vm_start, vma->vm_page_prot);

    if (ret == 0)
        pr_info("Shared ring mmap successful\n");

    return ret;
}

static long pciem_ioctl_create_device(struct pciem_userspace_state *us, struct pciem_create_device __user *arg)
{
    if (us->rc)
        return -EBUSY;

    us->rc = pciem_alloc_root_complex();
    if (IS_ERR(us->rc))
    {
        int ret = PTR_ERR(us->rc);
        us->rc = NULL;
        return ret;
    }

    pciem_init_cap_manager(us->rc);

    pr_info("Created userspace device instance\n");

    return 0;
}

static long pciem_ioctl_add_bar(struct pciem_userspace_state *us, struct pciem_bar_config __user *arg)
{
    struct pciem_bar_config cfg;
    int ret;

    ret = pciem_check_unregistered(us);
    if (ret)
        return ret;

    if (copy_from_user(&cfg, arg, sizeof(cfg)))
        return -EFAULT;

    if (cfg.bar_index >= PCI_STD_NUM_BARS)
        return -EINVAL;

    if (cfg.size && (cfg.size & (cfg.size - 1)))
    {
        pr_err("BAR%u size 0x%llx is not a power of 2\n", cfg.bar_index, cfg.size);
        return -EINVAL;
    }

    ret = pciem_register_bar(us->rc, cfg.bar_index, cfg.size, cfg.flags);

    if (ret == 0)
    {
        pr_info("Registered BAR%u: size=0x%llx, flags=0x%x\n", cfg.bar_index, cfg.size, cfg.flags);
    }

    return ret;
}

static long pciem_ioctl_add_capability(struct pciem_userspace_state *us, struct pciem_cap_config __user *arg)
{
    struct pciem_cap_config cfg;
    int ret;

    ret = pciem_check_unregistered(us);
    if (ret)
        return ret;

    if (copy_from_user(&cfg, arg, sizeof(cfg)))
        return -EFAULT;

    switch (cfg.cap_type)
    {
    case PCIEM_CAP_MSI: {
        struct pciem_cap_msi_userspace *msi_cfg;
        struct pciem_cap_msi_config msi;

        msi_cfg = &cfg.msi;
        msi.num_vectors_log2 = msi_cfg->num_vectors_log2;
        msi.has_64bit = msi_cfg->has_64bit;
        msi.has_per_vector_masking = msi_cfg->has_masking;

        ret = pciem_add_cap_msi(us->rc, &msi);
        break;
    }

    case PCIEM_CAP_MSIX: {
        struct pciem_cap_msix_userspace *msix_cfg;
        struct pciem_cap_msix_config msix;

        msix_cfg = &cfg.msix;
        msix.bar_index = msix_cfg->bar_index;
        msix.table_offset = msix_cfg->table_offset;
        msix.pba_offset = msix_cfg->pba_offset;
        msix.table_size = msix_cfg->table_size;

        ret = pciem_add_cap_msix(us->rc, &msix);
        break;
    }

    default:
        pr_warn("Unsupported capability type: %d\n", cfg.cap_type);
        ret = -ENOTSUPP;
    }

    return ret;
}

static long pciem_ioctl_set_config(struct pciem_userspace_state *us, struct pciem_config_space __user *arg)
{
    struct pciem_config_space cfg;
    u8 *config;
    int ret;

    ret = pciem_check_unregistered(us);
    if (ret)
        return ret;

    if (copy_from_user(&cfg, arg, sizeof(cfg)))
        return -EFAULT;

    config = us->rc->cfg;

    *(u16 *)(config + PCI_VENDOR_ID) = cfg.vendor_id;
    *(u16 *)(config + PCI_DEVICE_ID) = cfg.device_id;
    *(u16 *)(config + PCI_SUBSYSTEM_VENDOR_ID) = cfg.subsys_vendor_id;
    *(u16 *)(config + PCI_SUBSYSTEM_ID) = cfg.subsys_device_id;
    *(u8 *)(config + PCI_REVISION_ID) = cfg.revision;
    *(u8 *)(config + PCI_CLASS_PROG) = cfg.class_code[0];
    *(u8 *)(config + PCI_CLASS_DEVICE) = cfg.class_code[1];
    *(u8 *)(config + PCI_CLASS_DEVICE + 1) = cfg.class_code[2];
    *(u8 *)(config + PCI_HEADER_TYPE) = cfg.header_type;
    *(u16 *)(config + PCI_COMMAND) = PCI_COMMAND_MEMORY;
    *(u16 *)(config + PCI_STATUS) = PCI_STATUS_CAP_LIST;

    pr_info("Config space set: vendor=0x%04x, device=0x%04x, class=0x%02x%02x%02x\n", cfg.vendor_id, cfg.device_id,
            cfg.class_code[2], cfg.class_code[1], cfg.class_code[0]);

    return 0;
}

static long pciem_ioctl_register(struct pciem_userspace_state *us)
{
    int ret;
    int fd;

    ret = pciem_start_registration(us);
    if (ret)
        return ret;

    pr_info("Registering userspace-defined device on PCI bus\n");

    pciem_build_config_space(us->rc);

    ret = pciem_complete_init(us->rc);
    if (ret)
    {
        pciem_cancel_registration(us);
        pr_err("Failed to complete device initialization: %d\n", ret);
        return ret;
    }

    pciem_complete_registration(us);

    fd = anon_inode_getfd("pciem_instance", &pciem_instance_fops, us, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        pr_err("Failed to create instance fd\n");
        return fd;
    }

    pr_info("Userspace device registered successfully, returning FD %d\n",
            fd);

    return fd;
}

static long pciem_ioctl_inject_irq(struct pciem_userspace_state *us, struct pciem_irq_inject __user *arg)
{
    struct pciem_irq_inject inject;
    int ret;

    ret = pciem_check_registered(us);
    if (ret)
        return ret;

    if (copy_from_user(&inject, arg, sizeof(inject)))
        return -EFAULT;

    pr_debug("Injecting MSI vector %d\n", inject.vector);

    pciem_trigger_msi(us->rc, inject.vector);

    return 0;
}

static long pciem_ioctl_dma(struct pciem_userspace_state *us, struct pciem_dma_op __user *arg)
{
    struct pciem_dma_op op;
    void *kernel_buf;
    int ret;

    ret = pciem_check_registered(us);
    if (ret)
        return ret;

    if (copy_from_user(&op, arg, sizeof(op)))
        return -EFAULT;

    if (op.length == 0)
        return -EINVAL;

    kernel_buf = kmalloc(op.length, GFP_KERNEL);
    if (!kernel_buf)
        return -ENOMEM;

    if (op.flags & PCIEM_DMA_FLAG_WRITE)
    {
        if (copy_from_user(kernel_buf, (void __user *)op.user_addr, op.length))
        {
            kfree(kernel_buf);
            return -EFAULT;
        }

        ret = pciem_dma_write_to_guest(us->rc, op.guest_iova, kernel_buf, op.length, op.pasid);
    }
    else
    {
        ret = pciem_dma_read_from_guest(us->rc, op.guest_iova, kernel_buf, op.length, op.pasid);

        if (ret == 0 && copy_to_user((void __user *)op.user_addr, kernel_buf, op.length))
            ret = -EFAULT;
    }

    kfree(kernel_buf);
    return ret;
}

static long pciem_ioctl_dma_atomic(struct pciem_userspace_state *us, struct pciem_dma_atomic __user *arg)
{
    struct pciem_dma_atomic atomic;
    u64 result;
    int ret;

    ret = pciem_check_registered(us);
    if (ret)
        return ret;

    if (copy_from_user(&atomic, arg, sizeof(atomic)))
        return -EFAULT;

    switch (atomic.op_type)
    {
    case PCIEM_ATOMIC_FETCH_ADD:
        result = pciem_dma_atomic_fetch_add(us->rc, atomic.guest_iova, atomic.operand, atomic.pasid);
        break;
    case PCIEM_ATOMIC_FETCH_SUB:
        result = pciem_dma_atomic_fetch_sub(us->rc, atomic.guest_iova, atomic.operand, atomic.pasid);
        break;
    case PCIEM_ATOMIC_SWAP:
        result = pciem_dma_atomic_swap(us->rc, atomic.guest_iova, atomic.operand, atomic.pasid);
        break;
    case PCIEM_ATOMIC_CAS:
        result = pciem_dma_atomic_cas(us->rc, atomic.guest_iova, atomic.compare, atomic.operand, atomic.pasid);
        break;
    case PCIEM_ATOMIC_FETCH_AND:
        result = pciem_dma_atomic_fetch_and(us->rc, atomic.guest_iova, atomic.operand, atomic.pasid);
        break;
    case PCIEM_ATOMIC_FETCH_OR:
        result = pciem_dma_atomic_fetch_or(us->rc, atomic.guest_iova, atomic.operand, atomic.pasid);
        break;
    case PCIEM_ATOMIC_FETCH_XOR:
        result = pciem_dma_atomic_fetch_xor(us->rc, atomic.guest_iova, atomic.operand, atomic.pasid);
        break;
    default:
        return -EINVAL;
    }

    atomic.result = result;

    if (copy_to_user(arg, &atomic, sizeof(atomic)))
        return -EFAULT;

    return ret;
}

static long pciem_ioctl_p2p(struct pciem_userspace_state *us, struct pciem_p2p_op_user __user *arg)
{
    struct pciem_p2p_op_user op;
    void *kernel_buf;
    int ret;

    ret = pciem_check_registered(us);
    if (ret)
        return ret;

    if (copy_from_user(&op, arg, sizeof(op)))
        return -EFAULT;

    if (op.length == 0)
        return -EINVAL;

    kernel_buf = kmalloc(op.length, GFP_KERNEL);
    if (!kernel_buf)
        return -ENOMEM;

    if (op.flags & PCIEM_DMA_FLAG_WRITE)
    {
        if (copy_from_user(kernel_buf, (void __user *)op.user_addr, op.length))
        {
            kfree(kernel_buf);
            return -EFAULT;
        }

        ret = pciem_p2p_write(us->rc, op.target_phys_addr, kernel_buf, op.length);
    }
    else
    {
        ret = pciem_p2p_read(us->rc, op.target_phys_addr, kernel_buf, op.length);

        if (ret == 0 && copy_to_user((void __user *)op.user_addr, kernel_buf, op.length))
            ret = -EFAULT;
    }

    kfree(kernel_buf);
    return ret;
}

static long pciem_ioctl_get_bar_info(struct pciem_userspace_state *us, struct pciem_bar_info_query __user *arg)
{
    struct pciem_bar_info_query query;
    struct pciem_bar_info *bar;
    int ret;

    ret = pciem_check_registered(us);
    if (ret)
        return ret;

    if (copy_from_user(&query, arg, sizeof(query)))
        return -EFAULT;

    if (query.bar_index >= PCI_STD_NUM_BARS)
        return -EINVAL;

    guard(read_lock)(&us->rc->bars_lock);
    bar = &us->rc->bars[query.bar_index];

    if (bar->size == 0)
        return -ENOENT;

    query.phys_addr = bar->phys_addr;
    query.size = bar->size;
    query.flags = bar->flags;

    if (copy_to_user(arg, &query, sizeof(query)))
        return -EFAULT;

    pr_debug("BAR%u info: phys=0x%llx size=0x%llx flags=0x%x\n", query.bar_index, query.phys_addr, query.size,
             query.flags);

    return 0;
}

static void pciem_userspace_bp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs)
{
    unsigned long context = (unsigned long)bp->overflow_handler_context;
    struct pciem_userspace_state *us = (struct pciem_userspace_state *)(context & ~0xFFUL);
    int wp_index = (int)(context & 0xFF);

    if (!us || wp_index >= MAX_WATCHPOINTS)
        return;

    struct pciem_watchpoint_info *wp = &us->watchpoints[wp_index];
    if (!wp->active)
        return;

    struct pciem_event event = {
        .type = PCIEM_EVENT_MMIO_WRITE, .bar = wp->bar_index, .offset = wp->offset, .size = wp->width, .data = 0};

    pciem_userspace_queue_event(us, &event);
}

static void __iomem *pciem_resolve_bar_address(struct pci_dev *pdev, u32 bar, uint32_t flags)
{
    void __iomem *bar_base = NULL;
    bool try_kprobes = true;
    bool try_manual = true;

    if (flags & PCIEM_WP_FLAG_BAR_KPROBES) {
        try_manual = false;
    } else if (flags & PCIEM_WP_FLAG_BAR_MANUAL) {
        try_kprobes = false;
    }

    if (try_kprobes) {
        bar_base = pciem_get_driver_bar_vaddr(pdev, bar);
        if (bar_base) {
            pr_debug("pciem_userspace: BAR%u resolved via kprobes\n", bar);
            return bar_base;
        }
        if (!try_manual) {
            pr_warn("pciem_userspace: BAR%u not found via kprobes (kprobes-only mode)\n", bar);
            return NULL;
        }
    }

    if (try_manual) {
        void *drvdata = pci_get_drvdata(pdev);
        if (drvdata) {
            /*
                FIXME?:

                This assumes that the driver's private data structure is as follows:

                struct drvdata {
                    struct pci_dev *pdev;
                    void __iomem *bars[x];
                    ...
                };
            */
            void __iomem **bar_array = (void __iomem **)((char *)drvdata + sizeof(struct pci_dev *));
            bar_base = bar_array[bar];
            if (bar_base) {
                pr_debug("pciem_userspace: BAR%u resolved via manual method\n", bar);
                return bar_base;
            }
        }
        if (!try_kprobes) {
            pr_warn("pciem_userspace: BAR%u not found via manual method (manual-only mode)\n", bar);
            return NULL;
        }
    }
    
    return NULL;
}

static long pciem_ioctl_set_watchpoint(struct pciem_userspace_state *us, struct pciem_watchpoint_config __user *arg)
{
    struct pciem_watchpoint_config cfg;
    struct pci_dev *pdev;
    void __iomem *bar_base;
    void __iomem *target_va;
    struct perf_event_attr attr;
    unsigned long flags;
    int wp_slot = -1;
    int i, ret;

    ret = pciem_check_registered(us);
    if (ret)
        return ret;

    if (copy_from_user(&cfg, arg, sizeof(cfg)))
        return -EFAULT;

    if (cfg.bar_index >= PCI_STD_NUM_BARS)
        return -EINVAL;

    spin_lock_irqsave(&us->watchpoint_lock, flags);

    for (i = 0; i < MAX_WATCHPOINTS; i++)
    {
        if (us->watchpoints[i].active && us->watchpoints[i].bar_index == cfg.bar_index &&
            us->watchpoints[i].offset == cfg.offset)
        {
            wp_slot = i;
            break;
        }
    }

    if (wp_slot == -1 && cfg.flags != 0)
    {
        for (i = 0; i < MAX_WATCHPOINTS; i++)
        {
            if (!us->watchpoints[i].active)
            {
                wp_slot = i;
                break;
            }
        }
    }

    spin_unlock_irqrestore(&us->watchpoint_lock, flags);

    if (wp_slot == -1)
    {
        if (cfg.flags != 0)
        {
            pr_err("pciem_userspace: No free watchpoint slots (max %d)\n", MAX_WATCHPOINTS);
            return -ENOSPC;
        }
        return 0;
    }

    if (us->watchpoints[wp_slot].active)
    {
        if (us->watchpoints[wp_slot].perf_bp)
        {
            unregister_wide_hw_breakpoint(us->watchpoints[wp_slot].perf_bp);
            us->watchpoints[wp_slot].perf_bp = NULL;
        }
        us->watchpoints[wp_slot].active = false;

        pr_info("pciem_userspace: Watchpoint[%d] disabled (BAR%u+0x%x)\n", wp_slot, us->watchpoints[wp_slot].bar_index,
                us->watchpoints[wp_slot].offset);
    }

    if (cfg.flags == 0)
    {
        return 0;
    }

    pdev = us->rc->pciem_pdev;
    if (!pdev)
    {
        pr_err("pciem_userspace: No pdev available\n");
        return -ENODEV;
    }

    bar_base = pciem_resolve_bar_address(pdev, cfg.bar_index, cfg.flags);

    if (!bar_base)
    {
        const char *method_str = 
            (cfg.flags & PCIEM_WP_FLAG_BAR_KPROBES) ? " (kprobes-only)" :
            (cfg.flags & PCIEM_WP_FLAG_BAR_MANUAL) ? " (manual-only)" : "";
        pr_err("pciem_userspace: Could not locate BAR%u mapping%s\n",
               cfg.bar_index, method_str);
        return -EAGAIN;
    }

    target_va = bar_base + cfg.offset;

    hw_breakpoint_init(&attr);
    attr.bp_addr = (unsigned long)target_va;

    switch (cfg.width)
    {
    case 1:
        attr.bp_len = HW_BREAKPOINT_LEN_1;
        break;
    case 2:
        attr.bp_len = HW_BREAKPOINT_LEN_2;
        break;
    case 4:
        attr.bp_len = HW_BREAKPOINT_LEN_4;
        break;
    case 8:
        attr.bp_len = HW_BREAKPOINT_LEN_8;
        break;
    default:
        pr_err("pciem_userspace: Invalid watchpoint width %d\n", cfg.width);
        return -EINVAL;
    }

    attr.bp_type = HW_BREAKPOINT_W;
    attr.disabled = false;

    unsigned long context = ((unsigned long)us & ~0xFFUL) | (wp_slot & 0xFF);

    us->watchpoints[wp_slot].perf_bp = register_wide_hw_breakpoint(&attr, pciem_userspace_bp_handler, (void *)context);

    if (IS_ERR_PCPU(us->watchpoints[wp_slot].perf_bp))
    {
        int err = PTR_ERR_PCPU(us->watchpoints[wp_slot].perf_bp);
        us->watchpoints[wp_slot].perf_bp = NULL;
        pr_err("pciem_userspace: Failed to register watchpoint: %d\n", err);
        return err;
    }

    us->watchpoints[wp_slot].active = true;
    us->watchpoints[wp_slot].bar_index = cfg.bar_index;
    us->watchpoints[wp_slot].offset = cfg.offset;
    us->watchpoints[wp_slot].width = cfg.width;

    pr_info("pciem_userspace: Watchpoint[%d] enabled on BAR%u+0x%x (VA %px, width %d)\n", wp_slot, cfg.bar_index,
            cfg.offset, target_va, cfg.width);

    if (!us->bar_tracking_disabled) {
        pciem_disable_bar_tracking();
        us->bar_tracking_disabled = true;
    }

    return 0;
}

static long pciem_ioctl_set_eventfd(struct pciem_userspace_state *us, struct pciem_eventfd_config __user *arg)
{
    struct pciem_eventfd_config cfg;
    struct eventfd_ctx *eventfd = NULL;
    struct eventfd_ctx *old_eventfd = NULL;
    unsigned long flags;
    int fd, ret;

    ret = pciem_check_registered(us);
    if (ret)
        return ret;

    if (copy_from_user(&cfg, arg, sizeof(cfg)))
        return -EFAULT;

    fd = cfg.eventfd;

    if (fd >= 0)
    {
        eventfd = eventfd_ctx_fdget(fd);
        if (IS_ERR(eventfd))
        {
            pr_err("Failed to get eventfd context for fd %d: %ld\n", fd, PTR_ERR(eventfd));
            return PTR_ERR(eventfd);
        }
        pr_info("Registered eventfd %d for ring buffer notifications\n", fd);
    }

    spin_lock_irqsave(&us->eventfd_lock, flags);
    old_eventfd = us->eventfd;
    us->eventfd = eventfd;
    spin_unlock_irqrestore(&us->eventfd_lock, flags);

    /* If there was no previous eventfd, there may be pending events
     * from before userspace registered this eventfd */
    if (!old_eventfd) {
        if (atomic_xchg(&us->event_pending, 0))
            pciem_eventfd_signal(us);
        return 0;
    }

    /* Free the previous eventfd */
    eventfd_ctx_put(old_eventfd);
    pr_info("Unregistered previous eventfd\n");

    return 0;
}

static void pciem_irqfd_work(struct work_struct *work)
{
    struct pciem_irqfd *irqfd = container_of(work, struct pciem_irqfd, inject_work);
    struct pciem_userspace_state *us = irqfd->us;

    if (us && us->rc) {
        pciem_trigger_msi(us->rc, irqfd->vector);
    }
}

static int pciem_irqfd_wakeup(wait_queue_entry_t *wait, unsigned mode, int sync, void *key)
{
    struct pciem_irqfd *irqfd = container_of(wait, struct pciem_irqfd, wait);
    struct pciem_irqfds *irqfds = &irqfd->us->irqfds;
    __poll_t flags = key_to_poll(key);
    u64 count;

    if (flags & EPOLLIN) {
        eventfd_ctx_do_read(irqfd->trigger, &count);
        schedule_work(&irqfd->inject_work);
    }

    if (flags & EPOLLHUP) {
        guard(spinlock_irqsave)(&irqfds->lock);
        if (!list_empty(&irqfd->list)) {
            pr_info("Unregistering IRQ eventfd for vector %u\n", irqfd->vector);
            pciem_irqfd_shutdown(irqfd);
        }
    }

    return 0;
}

struct pciem_poll_helper {
    struct poll_table_struct pt;
    struct pciem_irqfd *irqfd;
};

static void pciem_irqfd_ptable_queue_proc(struct file *file, wait_queue_head_t *wqh, poll_table *pt)
{
    struct pciem_poll_helper *helper = container_of(pt, struct pciem_poll_helper, pt);
    struct pciem_irqfd *irqfd = helper->irqfd;
    struct pciem_irqfds *irqfds = &irqfd->us->irqfds;

    guard(spinlock_irqsave)(&irqfds->lock);

    add_wait_queue(wqh, &irqfd->wait);
    list_add_tail(&irqfd->list, &irqfds->items);
}

static long pciem_ioctl_set_irqfd(struct pciem_userspace_state *us,
                                        struct pciem_irqfd_config __user *arg)
{
    struct pciem_irqfd_config cfg;
    struct eventfd_ctx *eventfd = NULL;
    struct pciem_irqfd *irqfd = NULL;
    struct fd f = EMPTY_FD;
    struct pciem_poll_helper pt_helper;
    __poll_t events;
    int ret;

    ret = pciem_check_registered(us);
    if (ret)
        return ret;

    if (copy_from_user(&cfg, arg, sizeof(cfg)))
        return -EFAULT;

    irqfd = kzalloc(sizeof(*irqfd), GFP_KERNEL_ACCOUNT);
    if (!irqfd)
        return -ENOMEM;

    eventfd = eventfd_ctx_fdget(cfg.eventfd);
    if (IS_ERR(eventfd)) {
        ret = PTR_ERR(eventfd);
        goto fail;
    }

    f = fdget(cfg.eventfd);
    if (fd_empty(f)) {
        ret = -EBADF;
        goto fail;
    }

    irqfd->trigger = eventfd;
    irqfd->vector = cfg.vector;
    irqfd->flags = cfg.flags;
    irqfd->us = us;
    INIT_LIST_HEAD(&irqfd->list);
    INIT_WORK(&irqfd->inject_work, pciem_irqfd_work);
    init_waitqueue_func_entry(&irqfd->wait, pciem_irqfd_wakeup);

    init_poll_funcptr(&pt_helper.pt, pciem_irqfd_ptable_queue_proc);
    pt_helper.irqfd = irqfd;

    events = vfs_poll(fd_file(f), &pt_helper.pt);
    if (events & EPOLLIN)
        schedule_work(&irqfd->inject_work);

    fdput(f);

    pr_info("Registered IRQ eventfd %d for vector %u (Direct Wakeup)\n", cfg.eventfd, cfg.vector);

    return 0;

fail:
    if (!fd_empty(f))
        fdput(f);
    if (eventfd && !IS_ERR(eventfd))
        eventfd_ctx_put(eventfd);
    if (irqfd)
        kfree(irqfd);
    return ret;
}

static long pciem_ioctl_dma_indirect(struct pciem_userspace_state *us, struct pciem_dma_indirect __user *arg)
{
    struct pciem_dma_indirect req;
    void *data_buf = NULL;
    uint64_t *list_buf = NULL;
    uint64_t cur_prp_list;
    uint32_t page_size;
    uint32_t offset;
    uint32_t chunk;
    uint64_t user_ptr;
    uint32_t remaining;
    int list_idx = 0;
    int ret;

    ret = pciem_check_registered(us);
    if (ret)
        return ret;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    if (req.length == 0)
        return 0;

    page_size = req.page_size;

    if (page_size < 4096 || page_size > 65536 || (page_size & (page_size - 1)))
        return -EINVAL;

    remaining = req.length;
    user_ptr = req.user_addr;

    list_buf = kmalloc(page_size, GFP_KERNEL);
    data_buf = kmalloc(page_size, GFP_KERNEL);

    if (!list_buf || !data_buf) {
        ret = -ENOMEM;
        goto out;
    }

    offset = req.prp1 & (page_size - 1);
    chunk = page_size - offset;
    if (chunk > remaining) chunk = remaining;

    if (req.flags & PCIEM_DMA_FLAG_WRITE) {
        if (copy_from_user(data_buf, (void __user *)user_ptr, chunk)) {
            ret = -EFAULT;
            goto out;
        }
        ret = pciem_dma_write_to_guest(us->rc, req.prp1, data_buf, chunk, req.pasid);
    } else {
        ret = pciem_dma_read_from_guest(us->rc, req.prp1, data_buf, chunk, req.pasid);
        if (ret == 0) {
            if (copy_to_user((void __user *)user_ptr, data_buf, chunk))
                ret = -EFAULT;
        }
    }

    if (ret) goto out;

    remaining -= chunk;
    user_ptr += chunk;

    if (remaining == 0) goto out;

    if (remaining <= page_size) {
        if (req.flags & PCIEM_DMA_FLAG_WRITE) {
            if (copy_from_user(data_buf, (void __user *)user_ptr, remaining)) {
                ret = -EFAULT;
                goto out;
            }
            ret = pciem_dma_write_to_guest(us->rc, req.prp2, data_buf, remaining, req.pasid);
        } else {
            ret = pciem_dma_read_from_guest(us->rc, req.prp2, data_buf, remaining, req.pasid);
            if (ret == 0 && copy_to_user((void __user *)user_ptr, data_buf, remaining)) {
                ret = -EFAULT;
            }
        }
        goto out;
    }

    cur_prp_list = req.prp2;
    list_idx = 0;

    uint32_t list_offset = cur_prp_list & (page_size - 1);
    uint32_t list_bytes = page_size - list_offset;
    
    ret = pciem_dma_read_from_guest(us->rc, cur_prp_list, list_buf, list_bytes, req.pasid);
    if (ret) goto out;

    uint64_t *prps = (uint64_t *)list_buf;
    uint32_t max_entries = list_bytes / 8;

    while (remaining > 0) {
        if (list_idx == max_entries - 1 && remaining > page_size) {
            cur_prp_list = prps[list_idx];
            
            list_offset = cur_prp_list & (page_size - 1);
            list_bytes = page_size - list_offset;
            max_entries = list_bytes / 8;

            ret = pciem_dma_read_from_guest(us->rc, cur_prp_list, list_buf, list_bytes, req.pasid);
            if (ret) goto out;
            
            prps = (uint64_t *)list_buf;
            list_idx = 0;
            continue;
        }

        uint64_t data_phys = prps[list_idx++];
        chunk = (remaining < page_size) ? remaining : page_size;

        if (req.flags & PCIEM_DMA_FLAG_WRITE) {
            if (copy_from_user(data_buf, (void __user *)user_ptr, chunk)) {
                ret = -EFAULT;
                goto out;
            }
            ret = pciem_dma_write_to_guest(us->rc, data_phys, data_buf, chunk, req.pasid);
        } else {
            ret = pciem_dma_read_from_guest(us->rc, data_phys, data_buf, chunk, req.pasid);
            if (ret == 0 && copy_to_user((void __user *)user_ptr, data_buf, chunk)) {
                ret = -EFAULT;
            }
        }

        if (ret) goto out;

        remaining -= chunk;
        user_ptr += chunk;
    }

out:
    kfree(list_buf);
    kfree(data_buf);
    return ret;
}

static long pciem_device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct pciem_userspace_state *us = file->private_data;

    switch (cmd)
    {
    case PCIEM_IOCTL_CREATE_DEVICE:
        return pciem_ioctl_create_device(us, (struct pciem_create_device __user *)arg);

    case PCIEM_IOCTL_ADD_BAR:
        return pciem_ioctl_add_bar(us, (struct pciem_bar_config __user *)arg);

    case PCIEM_IOCTL_ADD_CAPABILITY:
        return pciem_ioctl_add_capability(us, (struct pciem_cap_config __user *)arg);

    case PCIEM_IOCTL_SET_CONFIG:
        return pciem_ioctl_set_config(us, (struct pciem_config_space __user *)arg);

    case PCIEM_IOCTL_REGISTER:
        return pciem_ioctl_register(us);

    case PCIEM_IOCTL_INJECT_IRQ:
        return pciem_ioctl_inject_irq(us, (struct pciem_irq_inject __user *)arg);

    case PCIEM_IOCTL_DMA:
        return pciem_ioctl_dma(us, (struct pciem_dma_op __user *)arg);

    case PCIEM_IOCTL_DMA_ATOMIC:
        return pciem_ioctl_dma_atomic(us, (struct pciem_dma_atomic __user *)arg);

    case PCIEM_IOCTL_P2P:
        return pciem_ioctl_p2p(us, (struct pciem_p2p_op_user __user *)arg);

    case PCIEM_IOCTL_GET_BAR_INFO:
        return pciem_ioctl_get_bar_info(us, (struct pciem_bar_info_query __user *)arg);

    case PCIEM_IOCTL_SET_WATCHPOINT:
        return pciem_ioctl_set_watchpoint(us, (struct pciem_watchpoint_config __user *)arg);

    case PCIEM_IOCTL_SET_EVENTFD:
        return pciem_ioctl_set_eventfd(us, (struct pciem_eventfd_config __user *)arg);

    case PCIEM_IOCTL_SET_IRQFD:
        return pciem_ioctl_set_irqfd(us, (struct pciem_irqfd_config __user *)arg);

    case PCIEM_IOCTL_DMA_INDIRECT:
        return pciem_ioctl_dma_indirect(us, (struct pciem_dma_indirect __user *)arg);

    default:
        return -ENOTTY;
    }
}

int pciem_userspace_init(void)
{
    pr_info("Userspace device support initialized\n");
    return 0;
}

void pciem_userspace_cleanup(void)
{
    pr_info("Userspace device support cleanup\n");
}

EXPORT_SYMBOL(pciem_userspace_create);
EXPORT_SYMBOL(pciem_userspace_destroy);
EXPORT_SYMBOL(pciem_userspace_queue_event);
EXPORT_SYMBOL(pciem_userspace_wait_response);
