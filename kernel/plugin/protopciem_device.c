#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/cpumask.h>
#include <linux/hw_breakpoint.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pci_regs.h>
#include <linux/percpu.h>
#include <linux/perf_event.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "pciem_capabilities.h"
#include "pciem_ops.h"
#include "protopciem_device.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cakehonolulu (cakehonolulu@protonmail.com)");
MODULE_DESCRIPTION("ProtoPCIem Device Plugin for PCIem Framework");

static void proto_fill_config(u8 *cfg);
static int proto_register_capabilities(struct pciem_root_complex *v);
static int proto_register_bars(struct pciem_root_complex *v);
static int proto_init_state(struct pciem_root_complex *v);
static void proto_cleanup_state(struct pciem_root_complex *v);
static void proto_poll_state(struct pciem_root_complex *v, bool proxy_irq_fired);
static void proto_set_command_watchpoint(struct pciem_root_complex *v, bool enable);

struct proto_device_state
{
    u32 shadow_control;
    u32 shadow_status;
    u32 shadow_cmd;
    u32 shadow_data;
    u32 shadow_result_lo;
    u32 shadow_result_hi;
    u32 shadow_dma_src_lo;
    u32 shadow_dma_src_hi;
    u32 shadow_dma_dst_lo;
    u32 shadow_dst_hi;
    u32 shadow_dma_len;
    struct pciem_root_complex *host;
    struct delayed_work watchpoint_work;
    int retries;
};

static struct pciem_epc_ops my_device_ops = {
    .fill_config_space = proto_fill_config,
    .register_capabilities = proto_register_capabilities,
    .register_bars = proto_register_bars,
    .init_emulation_state = proto_init_state,
    .cleanup_emulation_state = proto_cleanup_state,
    .poll_device_state = proto_poll_state,
    .set_command_watchpoint = proto_set_command_watchpoint,
};

static void proto_watchpoint_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs)
{
    struct pciem_root_complex *v = (struct pciem_root_complex *)bp->overflow_handler_context;

    if (!v)
        return;

    pr_info("fwd: watchpoint hit on REG_CMD!\n");

    atomic_set(&v->guest_mmio_pending, 1);

    wake_up_interruptible(&v->write_wait);
}

static void proto_set_command_watchpoint(struct pciem_root_complex *v, bool enable)
{
    struct proto_device_state *s = v->device_private_data;
    if (!s)
    {
        pr_err("fwd: No private data for watchpoint\n");
        return;
    }

    if (enable)
    {
        if (v->cmd_watchpoint)
        {
            int cpu;
            pr_info("fwd: watchpoint re-enabling\n");
            for_each_online_cpu(cpu)
            {
                struct perf_event *bp = *per_cpu_ptr(v->cmd_watchpoint, cpu);
                if (bp)
                    perf_event_enable(bp);
            }
            return;
        }

        struct pci_dev *pdev = v->protopciem_pdev;
        if (!pdev)
        {
            pr_err("fwd: No pdev available for watchpoint\n");
            return;
        }

        void *drvdata = pci_get_drvdata(pdev);
        if (!drvdata)
        {
            if (s->retries == 0)
                s->retries = 20;
            if (s->retries-- > 0)
            {
                pr_info("fwd: Driver not probed yet, scheduling retry (%d left)\n", s->retries);
                schedule_delayed_work(&s->watchpoint_work, msecs_to_jiffies(500));
            }
            else
            {
                pr_err("fwd: Timed out waiting for driver probe\n");
            }
            return;
        }

        // TODO: Something less hacky?
        void __iomem **bar0_ptr = (void __iomem **)((char *)drvdata + sizeof(struct pci_dev *));
        void __iomem *driver_bar0 = *bar0_ptr;
        if (!driver_bar0)
        {
            return;
        }

        unsigned long va_reg_cmd = (unsigned long)(driver_bar0 + REG_CMD);

        struct perf_event_attr attr;
        hw_breakpoint_init(&attr);
        attr.bp_addr = va_reg_cmd;
        attr.bp_len = HW_BREAKPOINT_LEN_4;
        attr.bp_type = HW_BREAKPOINT_W;
        attr.disabled = false;

        v->cmd_watchpoint = register_wide_hw_breakpoint(&attr, proto_watchpoint_handler, v);

        uintptr_t wp_val = (uintptr_t __force)v->cmd_watchpoint;

        if (IS_ERR((void *)wp_val))
        {
            pr_err("... %ld\n", PTR_ERR((void *)wp_val));
            v->cmd_watchpoint = NULL;
        }
        else
        {
            pr_info("fwd: watchpoint registered for driver's VA 0x%lx (BAR0+0x08)\n", va_reg_cmd);
        }
    }
    else if (v->cmd_watchpoint)
    {
        if (v->cmd_watchpoint)
        {
            int cpu;
            pr_info("fwd: watchpoint disabling\n");
            for_each_online_cpu(cpu)
            {
                struct perf_event *bp = *per_cpu_ptr(v->cmd_watchpoint, cpu);
                if (bp)
                    perf_event_disable(bp);
            }
        }
    }
}

static void proto_watchpoint_retry(struct work_struct *work)
{
    struct delayed_work *dwork = to_delayed_work(work);
    struct proto_device_state *s = container_of(dwork, struct proto_device_state, watchpoint_work);
    proto_set_command_watchpoint(s->host, true);
}

static int proto_init_state(struct pciem_root_complex *v)
{
    struct proto_device_state *s;

    s = kzalloc(sizeof(*s), GFP_KERNEL);

    if (!s)
    {
        return -ENOMEM;
    }

    s->host = v;
    s->retries = 0;
    INIT_DELAYED_WORK(&s->watchpoint_work, proto_watchpoint_retry);

    v->device_private_data = s;

    if (v->bars[0].virt_addr)
    {
        memset_io(v->bars[0].virt_addr, 0, v->bars[0].size);
    }

    if (v->bars[2].virt_addr)
    {
        void __iomem *bar2_base = v->bars[2].virt_addr;
        resource_size_t bar2_size = v->bars[2].size;
        int i;

        pr_info("Initializing BAR2 data buffer with test pattern\n");

        if (!IS_ALIGNED((unsigned long)bar2_base, 4))
        {
            pr_warn("BAR2 base not 4-byte aligned, skipping initialization\n");
        }
        else
        {
            for (i = 0; i < bar2_size / 4; i++)
            {
                iowrite32(i * 4, bar2_base + (i * 4));
            }

            iowrite32(0xDEADBEEF, bar2_base);
            iowrite32(0xCAFEBABE, bar2_base + 4);
            if (v->bars[2].size <= 0xFFFFFFFFUL)
            {
                iowrite32((u32)v->bars[2].size, bar2_base + 8);
            }
            else
            {
                iowrite32((u32)(v->bars[2].size & 0xFFFFFFFF), bar2_base + 8);
                iowrite32((u32)(v->bars[2].size >> 32), bar2_base + 12);
                pr_info("BAR2 size is 64-bit: 0x%llx\n", (u64)v->bars[2].size);
            }
        }
    }

    pr_info("ProtoPCIem device state initialized\n");
    return 0;
}

static void proto_cleanup_state(struct pciem_root_complex *v)
{
    struct proto_device_state *s = v->device_private_data;
    cancel_delayed_work_sync(&s->watchpoint_work);
    if (v->cmd_watchpoint)
    {
        unregister_wide_hw_breakpoint(v->cmd_watchpoint);
        v->cmd_watchpoint = NULL;
    }
    pr_info("ProtoPCIem device state cleaning up\n");
    kfree(v->device_private_data);
    v->device_private_data = NULL;
}

static void proto_poll_state(struct pciem_root_complex *v, bool proxy_irq_fired)
{
    struct proto_device_state *s = v->device_private_data;
    if (!s)
        return;

    u32 mem_val = ioread32(v->bars[0].virt_addr + REG_CMD);

    if (atomic_read(&v->guest_mmio_pending))
    {
        atomic_set(&v->guest_mmio_pending, 0);

        if (my_device_ops.set_command_watchpoint)
            my_device_ops.set_command_watchpoint(v, false);
    }

    if (mem_val != 0 && s->shadow_cmd == 0)
    {
        pr_info("fwd: New command issued: 0x%x\n", mem_val);

        s->shadow_control = ioread32(v->bars[0].virt_addr + REG_CONTROL);
        if (pci_shim_write(REG_CONTROL, s->shadow_control, 4))
            goto cmd_error;

        s->shadow_data = ioread32(v->bars[0].virt_addr + REG_DATA);
        if (pci_shim_write(REG_DATA, s->shadow_data, 4))
            goto cmd_error;

        s->shadow_dma_src_lo = ioread32(v->bars[0].virt_addr + REG_DMA_SRC_LO);
        if (pci_shim_write(REG_DMA_SRC_LO, s->shadow_dma_src_lo, 4))
            goto cmd_error;

        s->shadow_dma_src_hi = ioread32(v->bars[0].virt_addr + REG_DMA_SRC_HI);
        if (pci_shim_write(REG_DMA_SRC_HI, s->shadow_dma_src_hi, 4))
            goto cmd_error;

        s->shadow_dma_dst_lo = ioread32(v->bars[0].virt_addr + REG_DMA_DST_LO);
        if (pci_shim_write(REG_DMA_DST_LO, s->shadow_dma_dst_lo, 4))
            goto cmd_error;

        s->shadow_dst_hi = ioread32(v->bars[0].virt_addr + REG_DMA_DST_HI);
        if (pci_shim_write(REG_DMA_DST_HI, s->shadow_dst_hi, 4))
            goto cmd_error;

        s->shadow_dma_len = ioread32(v->bars[0].virt_addr + REG_DMA_LEN);
        if (pci_shim_write(REG_DMA_LEN, s->shadow_dma_len, 4))
            goto cmd_error;

        if (pci_shim_write(REG_CMD, mem_val, 4))
            goto cmd_error;

        s->shadow_cmd = mem_val;
        s->shadow_status = STATUS_BUSY;

        iowrite32(STATUS_BUSY, v->bars[0].virt_addr + REG_STATUS);
        return;
    }
    else if (proxy_irq_fired && s->shadow_cmd != 0)
    {
        pr_info("fwd: Command completed via IRQ\n");

        s->shadow_status = (u32)pci_shim_read(REG_STATUS, 4);
        s->shadow_result_lo = (u32)pci_shim_read(REG_RESULT_LO, 4);
        s->shadow_result_hi = (u32)pci_shim_read(REG_RESULT_HI, 4);

        s->shadow_cmd = 0;

        iowrite32(s->shadow_result_lo, v->bars[0].virt_addr + REG_RESULT_LO);
        iowrite32(s->shadow_result_hi, v->bars[0].virt_addr + REG_RESULT_HI);
        iowrite32(s->shadow_status, v->bars[0].virt_addr + REG_STATUS);

        pciem_trigger_msi(v);
        if (my_device_ops.set_command_watchpoint)
            my_device_ops.set_command_watchpoint(v, true);
        return;
    }

    // TODO: Just in case?
    if (atomic_read(&v->guest_mmio_pending) || mem_val == 0)
    {
        if (my_device_ops.set_command_watchpoint)
            my_device_ops.set_command_watchpoint(v, true);
    }

    return;

cmd_error:
    pr_err("fwd: shim write failed, aborting command\n");
    s->shadow_status = STATUS_ERROR | STATUS_DONE;
    iowrite32(s->shadow_status, v->bars[0].virt_addr + REG_STATUS);
    s->shadow_cmd = 0;
    if (my_device_ops.set_command_watchpoint)
        my_device_ops.set_command_watchpoint(v, true);
}

static int proto_register_capabilities(struct pciem_root_complex *v)
{
    struct pciem_cap_msi_config msi_cfg = {.has_64bit = true, .has_per_vector_masking = true, .num_vectors_log2 = 0};

    if (pciem_add_cap_msi(v, &msi_cfg) < 0)
    {
        pr_err("Failed to add MSI capability\n");
        return -ENOMEM;
    }

    return 0;
}

static void proto_fill_config(u8 *cfg)
{
    *(u16 *)&cfg[0x00] = PCIEM_PCI_VENDOR_ID;
    *(u16 *)&cfg[0x02] = PCIEM_PCI_DEVICE_ID;
    *(u16 *)&cfg[0x04] = PCI_COMMAND_MEMORY;
    *(u16 *)&cfg[0x06] = PCI_STATUS_CAP_LIST;
    cfg[0x08] = 0x00;
    cfg[0x09] = 0x00;
    cfg[0x0a] = 0x40;
    cfg[0x0b] = 0x0b;
    cfg[0x0e] = 0x00;
}

static int proto_register_bars(struct pciem_root_complex *v)
{
    int ret;
    int i;

    ret = pciem_register_bar(
        v, 0, PCIEM_BAR0_SIZE,
        PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64 | PCI_BASE_ADDRESS_MEM_PREFETCH, true);
    if (ret < 0)
    {
        return ret;
    }

    ret = pciem_register_bar(v, 1, 0, 0, false);
    if (ret < 0)
    {
        return ret;
    }

    ret = pciem_register_bar(
        v, 2, PCIEM_BAR2_SIZE,
        PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64 | PCI_BASE_ADDRESS_MEM_PREFETCH, false);
    if (ret < 0)
    {
        return ret;
    }

    for (i = 3; i < PCI_STD_NUM_BARS; i++)
    {
        ret = pciem_register_bar(v, i, 0, 0, false);
        if (ret < 0)
        {
            return ret;
        }
    }

    return 0;
}

static int __init proto_plugin_init(void)
{
    int rc;
    pr_info("Registering ProtoPCIem device logic in pciem...\n");

    rc = pciem_register_ops(&my_device_ops);
    if (rc)
    {
        pr_err("Failed to register with pciem: %d\n", rc);
        pr_err("Please ensure the 'pciem' module is loaded first.\n");
    }
    return rc;
}

static void __exit proto_plugin_exit(void)
{
    pr_info("Unregistering ProtoPCIem device logic from pciem...\n");
    pciem_unregister_ops(&my_device_ops);
    pr_info("ProtoPCIem device logic unregistered.\n");
}

module_init(proto_plugin_init);
module_exit(proto_plugin_exit);
