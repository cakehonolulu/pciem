#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/pci_regs.h>
#include <linux/slab.h>

#include "pciem_device.h"
#include "pciem_ops.h"

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
};

/**
 * @brief Allocate and init private state
 */
static int proto_init_state(struct pciem_host *v)
{
    struct proto_device_state *s;

    s = kzalloc(sizeof(*s), GFP_KERNEL);

    if (!s)
        return -ENOMEM;

    v->device_private_data = s;

    // Set BAR to default state
    memset_io(v->bar0_virt, 0, PCIEM_BAR0_SIZE);

    pr_info("ProtoPCIem device state initialized\n");
    return 0;
}

/**
 * @brief Free private state
 */
static void proto_cleanup_state(struct pciem_host *v)
{
    pr_info("ProtoPCIem device state cleaning up\n");
    kfree(v->device_private_data);
    v->device_private_data = NULL;
}

/**
 * @brief The main state machine for the device.
 * @param v The pciem host.
 * @param proxy_irq_fired True if this poll was triggered by
 * an event from the proxy, false if by timeout or page fault.
 */
static void proto_poll_state(struct pciem_host *v, bool proxy_irq_fired)
{
    struct proto_device_state *s = v->device_private_data;
    u32 mem_val;

    if (!s)
    {
        pr_err("proto_poll_state: no private state!\n");
        return;
    }

    mem_val = ioread32(v->bar0_virt + REG_CONTROL);
    if (mem_val != s->shadow_control)
    {
        if (mem_val & CTRL_RESET)
        {
            pr_info("fwd: RESET detected");
            memset_io(v->bar0_virt, 0, PCIEM_BAR0_SIZE);
            memset(s, 0, sizeof(*s));
            return;
        }

        if (pci_shim_write(REG_CONTROL, mem_val, 4))
            goto cmd_error;

        s->shadow_control = mem_val;
    }

    mem_val = ioread32(v->bar0_virt + REG_CMD);
    if (mem_val != s->shadow_cmd && mem_val != 0 && s->shadow_cmd == 0)
    {
        pr_info("fwd: NEW CMD detected: 0x%x", mem_val);

        s->shadow_data = ioread32(v->bar0_virt + REG_DATA);
        if (pci_shim_write(REG_DATA, s->shadow_data, 4))
            goto cmd_error;

        s->shadow_dma_src_lo = ioread32(v->bar0_virt + REG_DMA_SRC_LO);
        if (pci_shim_write(REG_DMA_SRC_LO, s->shadow_dma_src_lo, 4))
            goto cmd_error;

        s->shadow_dma_src_hi = ioread32(v->bar0_virt + REG_DMA_SRC_HI);
        if (pci_shim_write(REG_DMA_SRC_HI, s->shadow_dma_src_hi, 4))
            goto cmd_error;

        s->shadow_dma_dst_lo = ioread32(v->bar0_virt + REG_DMA_DST_LO);
        if (pci_shim_write(REG_DMA_DST_LO, s->shadow_dma_dst_lo, 4))
            goto cmd_error;

        s->shadow_dst_hi = ioread32(v->bar0_virt + REG_DMA_DST_HI);
        if (pci_shim_write(REG_DMA_DST_HI, s->shadow_dst_hi, 4))
            goto cmd_error;

        s->shadow_dma_len = ioread32(v->bar0_virt + REG_DMA_LEN);
        if (pci_shim_write(REG_DMA_LEN, s->shadow_dma_len, 4))
            goto cmd_error;

        if (pci_shim_write(REG_CMD, mem_val, 4))
            goto cmd_error;

        s->shadow_cmd = mem_val;
        s->shadow_status = STATUS_BUSY;

        iowrite32(STATUS_BUSY, v->bar0_virt + REG_STATUS);
    }
    else if (proxy_irq_fired && s->shadow_cmd != 0)
    {
        pr_info("fwd: Command completed via IRQ");

        s->shadow_status = (u32)pci_shim_read(REG_STATUS, 4);
        s->shadow_result_lo = (u32)pci_shim_read(REG_RESULT_LO, 4);
        s->shadow_result_hi = (u32)pci_shim_read(REG_RESULT_HI, 4);

        s->shadow_cmd = 0;

        iowrite32(s->shadow_result_lo, v->bar0_virt + REG_RESULT_LO);
        iowrite32(s->shadow_result_hi, v->bar0_virt + REG_RESULT_HI);
        wmb();
        iowrite32(s->shadow_status, v->bar0_virt + REG_STATUS);

        pciem_trigger_msi(v);
    }
    return;

cmd_error:
    pr_err("fwd: shim write failed, aborting command\n");
    s->shadow_status = STATUS_ERROR | STATUS_DONE;
    iowrite32(s->shadow_status, v->bar0_virt + REG_STATUS);
    s->shadow_cmd = 0;
}

/**
 * @brief Fill PCI Config Space
 */
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
    cfg[PCI_CAPABILITY_LIST] = 0x50;
    *(u32 *)&cfg[0x30] = 0x00000000;
    cfg[0x3c] = 0x00;
    cfg[0x3d] = 0x01;
    cfg[0x50] = PCI_CAP_ID_MSI;
    cfg[0x51] = 0x00;
    *(u16 *)&cfg[0x52] = PCI_MSI_FLAGS_64BIT | PCI_MSI_FLAGS_MASKBIT | (1 << 7);
    *(u32 *)&cfg[0x54] = 0x00000000;
    *(u32 *)&cfg[0x58] = 0x00000000;
    *(u16 *)&cfg[0x5C] = 0x0000;
    *(u32 *)&cfg[0x60] = 0x00000000;
}

/**
 * @brief Set up BARs
 */
static int proto_setup_bars(struct pciem_host *v, struct list_head *resources)
{
    struct resource_entry *entry;

    if (!v->pci_mem_res)
    {
        pr_err("init: internal error: pci_mem_res is NULL\n");
        return -EINVAL;
    }

    entry = resource_list_create_entry(v->pci_mem_res, 0);

    if (!entry)
        return -ENOMEM;

    resource_list_add_tail(entry, resources);
    return 0;
}

/**
 * @brief The struct of callbacks that we provide to the framework.
 */
static struct pciem_device_ops my_device_ops = {
    .fill_config_space = proto_fill_config,
    .setup_bars = proto_setup_bars,
    .init_emulation_state = proto_init_state,
    .cleanup_emulation_state = proto_cleanup_state,
    .poll_device_state = proto_poll_state,
};

void __init pciem_device_plugin_init(void)
{
    pr_info("Registering ProtoPCIem device logic...\n");
    pciem_register_ops(&my_device_ops);
}