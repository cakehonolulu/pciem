#ifndef PCIEM_FRAMEWORK_H
#define PCIEM_FRAMEWORK_H

#include <linux/completion.h>
#include <linux/fs.h>
#include <linux/irq_work.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/msi.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/poll.h>
#include <linux/wait.h>

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

#define MAX_PENDING_REQS 256
struct pending_req
{
    uint32_t id;
    bool valid;
    struct completion done;
    uint64_t result;
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
    wait_queue_head_t req_wait_full;
    struct shim_req req_queue[MAX_PENDING_REQS];
    int req_head, req_tail;
    atomic_t proxy_count;

    struct vm_area_struct *tracked_vma;
    struct mm_struct *tracked_mm;
    spinlock_t fault_lock;
    atomic_t write_pending;

    atomic_t proxy_irq_pending;
    wait_queue_head_t write_wait;

    void *device_private_data;
};

/**
 * @brief Triggers a virtual MSI interrupt for the guest driver.
 * To be called by the plugin from its handle_proxy_irq callback.
 */
void pciem_trigger_msi(struct pciem_host *v);

/**
 * @brief Sends a synchronous read request to the QEMU proxy.
 * To be called by the plugin.
 * @return The 64-bit value read from QEMU.
 */
u64 pci_shim_read(u64 addr, u32 size);

/**
 * @brief Sends a synchronous write request to the QEMU proxy.
 * To be called by the plugin.
 * @return 0 on success, < 0 on error.
 */
int pci_shim_write(u64 addr, u64 data, u32 size);

/**
 * @brief Called by the framework during init.
 * The plugin (pciem_device_logic.c) MUST define this function
 * and call pciem_register_ops() inside it.
 */
void __init pciem_device_plugin_init(void);

#endif /* PCIEM_FRAMEWORK_H */