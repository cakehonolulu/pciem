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

struct pciem_tlp
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

struct pciem_vma_tracking
{
    struct vm_area_struct *vma;
    struct mm_struct *mm;
    int bar_index;
    struct list_head list;
};

struct pciem_bar_info
{
    resource_size_t size;
    u32 flags;
    bool intercept_page_faults;

    u32 base_addr_val;

    struct resource *res;

    struct resource *allocated_res;
    void __iomem *virt_addr;
    struct page *pages;
    phys_addr_t phys_addr;
    enum pciem_map_type map_type;
    unsigned int order;
    bool mem_owned_by_framework;

    resource_size_t carved_start;
    resource_size_t carved_end;

    struct list_head vma_list;
    spinlock_t vma_lock;
};

struct pciem_root_complex
{
    unsigned int msi_irq;
    struct irq_work msi_irq_work;
    unsigned int pending_msi_irq;
    struct pci_dev *protopciem_pdev;
    struct pci_bus *root_bus;
    u8 cfg[256];
    struct mutex ctrl_lock;

    struct pciem_bar_info bars[PCI_STD_NUM_BARS];

    struct task_struct *emul_thread;
    struct platform_device *pdev;
    struct miscdevice vph_miscdev;

    struct miscdevice shim_miscdev;
    struct mutex shim_lock;
    uint32_t next_id;
    struct pending_req pending[MAX_PENDING_REQS];
    wait_queue_head_t req_wait;
    wait_queue_head_t req_wait_full;
    struct pciem_tlp req_queue[MAX_PENDING_REQS];
    int req_head, req_tail;
    atomic_t proxy_count;

    atomic_t proxy_irq_pending;
    wait_queue_head_t write_wait;

    void *device_private_data;

    struct pciem_cap_manager *cap_mgr;

    resource_size_t total_carved_start;
    resource_size_t total_carved_end;
    resource_size_t next_carve_offset;

    atomic_t guest_mmio_pending;
    struct perf_event * __percpu * cmd_watchpoint;

    void *shared_buf_vaddr;
    dma_addr_t shared_buf_dma;
    size_t shared_buf_size;
};

struct pciem_epc_ops;

void pciem_trigger_msi(struct pciem_root_complex *v);
u64 pci_shim_read(u64 addr, u32 size);
int pci_shim_write(u64 addr, u64 data, u32 size);
int pciem_register_bar(struct pciem_root_complex *v, int bar_num, resource_size_t size, u32 flags, bool intercept_faults);
int pciem_register_ops(struct pciem_epc_ops *ops);
void pciem_unregister_ops(struct pciem_epc_ops *ops);

#endif /* PCIEM_FRAMEWORK_H */