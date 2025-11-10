#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/pci_regs.h>
#include <linux/slab.h>
#include <linux/module.h>

#include "pciem_capabilities.h"
#include "pciem_ops.h"
#include "protopciem_device.h"

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("cakehonolulu (cakehonolulu@protonmail.com)");
MODULE_DESCRIPTION("ProtoPCIem Device Plugin for PCIem Framework");

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

static int proto_init_state(struct pciem_host *v)
{
    struct proto_device_state *s;

    s = kzalloc(sizeof(*s), GFP_KERNEL);

    if (!s)
    {
        return -ENOMEM;
    }

    v->device_private_data = s;

    if (v->bars[0].virt_addr)
    {
        memset_io(v->bars[0].virt_addr, 0, v->bars[0].size);
    }

    if (v->bars[2].virt_addr)
    {
        u32 *ptr = (u32 *)v->bars[2].virt_addr;
        int i;

        pr_info("Initializing BAR2 data buffer with test pattern\n");

        for (i = 0; i < v->bars[2].size / 4; i++)
        {
            iowrite32(i * 4, &ptr[i]);
        }

        iowrite32(0xDEADBEEF, v->bars[2].virt_addr);
        iowrite32(0xCAFEBABE, v->bars[2].virt_addr + 4);
        iowrite32((u32)v->bars[2].size, v->bars[2].virt_addr + 8);
    }

    pr_info("ProtoPCIem device state initialized\n");
    return 0;
}

static void proto_cleanup_state(struct pciem_host *v)
{
    pr_info("ProtoPCIem device state cleaning up\n");
    kfree(v->device_private_data);
    v->device_private_data = NULL;
}

static void proto_poll_state(struct pciem_host *v, bool proxy_irq_fired)
{
    struct proto_device_state *s = v->device_private_data;
    u32 mem_val;

    if (!s)
    {
        pr_err("proto_poll_state: no private state!\n");
        return;
    }

    if (atomic_read(&v->proxy_count) == 0)
    {
        return;
    }

    if (!v->bars[0].virt_addr)
    {
        pr_err_once("proto_poll_state: BAR0 not mapped!\n");
        return;
    }

    mem_val = ioread32(v->bars[0].virt_addr + REG_CONTROL);
    if (mem_val != s->shadow_control)
    {
        if (mem_val & CTRL_RESET)
        {
            pr_info("fwd: RESET detected");
            memset_io(v->bars[0].virt_addr, 0, v->bars[0].size);
            memset(s, 0, sizeof(*s));
            return;
        }

        if (pci_shim_write(REG_CONTROL, mem_val, 4))
            goto cmd_error;

        s->shadow_control = mem_val;
    }

    mem_val = ioread32(v->bars[0].virt_addr + REG_CMD);
    if (mem_val != s->shadow_cmd && mem_val != 0 && s->shadow_cmd == 0)
    {
        pr_info("fwd: NEW CMD detected: 0x%x", mem_val);

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
    }
    else if (proxy_irq_fired && s->shadow_cmd != 0)
    {
        pr_info("fwd: Command completed via IRQ");

        s->shadow_status = (u32)pci_shim_read(REG_STATUS, 4);
        s->shadow_result_lo = (u32)pci_shim_read(REG_RESULT_LO, 4);
        s->shadow_result_hi = (u32)pci_shim_read(REG_RESULT_HI, 4);

        s->shadow_cmd = 0;

        iowrite32(s->shadow_result_lo, v->bars[0].virt_addr + REG_RESULT_LO);
        iowrite32(s->shadow_result_hi, v->bars[0].virt_addr + REG_RESULT_HI);
        wmb();
        iowrite32(s->shadow_status, v->bars[0].virt_addr + REG_STATUS);

        pciem_trigger_msi(v);
    }
    return;

cmd_error:
    pr_err("fwd: shim write failed, aborting command\n");
    s->shadow_status = STATUS_ERROR | STATUS_DONE;
    iowrite32(s->shadow_status, v->bars[0].virt_addr + REG_STATUS);
    s->shadow_cmd = 0;
}

static int proto_register_capabilities(struct pciem_host *v)
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

static int proto_register_bars(struct pciem_host *v)
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

static struct pciem_device_ops my_device_ops = {
    .fill_config_space = proto_fill_config,
    .register_capabilities = proto_register_capabilities,
    .register_bars = proto_register_bars,
    .init_emulation_state = proto_init_state,
    .cleanup_emulation_state = proto_cleanup_state,
    .poll_device_state = proto_poll_state,
};

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
