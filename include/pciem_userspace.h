#ifndef PCIEM_USERSPACE_H
#define PCIEM_USERSPACE_H

#ifdef __KERNEL__
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/poll.h>
#else
#include <stdatomic.h>
#include <stdint.h>
typedef atomic_int atomic_t;
#endif

struct pciem_create_device
{
    uint32_t flags;
};

struct pciem_bar_config
{
    uint32_t bar_index;
    uint32_t flags;
    uint64_t size;
    uint32_t reserved;
};

struct pciem_cap_msi_userspace
{
    uint8_t num_vectors_log2;
    uint8_t has_64bit;
    uint8_t has_masking;
    uint8_t reserved;
};

struct pciem_cap_msix_userspace
{
    uint8_t bar_index;
    uint8_t reserved[3];
    uint32_t table_offset;
    uint32_t pba_offset;
    uint16_t table_size;
    uint16_t reserved2;
};

struct pciem_cap_config
{
    uint32_t cap_type;
    union {
        struct pciem_cap_msi_userspace msi;
        struct pciem_cap_msix_userspace msix;
    };
};

struct pciem_config_space
{
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t subsys_vendor_id;
    uint16_t subsys_device_id;
    uint8_t revision;
    uint8_t class_code[3];
    uint8_t header_type;
    uint8_t reserved[7];
};

struct pciem_event
{
    uint64_t seq;
    uint32_t type;
    uint32_t bar;
    uint64_t offset;
    uint32_t size;
    uint32_t reserved;
    uint64_t data;
    uint64_t timestamp;
};

#define PCIEM_EVENT_MMIO_READ 1
#define PCIEM_EVENT_MMIO_WRITE 2
#define PCIEM_EVENT_CONFIG_READ 3
#define PCIEM_EVENT_CONFIG_WRITE 4
#define PCIEM_EVENT_MSI_ACK 5
#define PCIEM_EVENT_RESET 6

struct pciem_response
{
    uint64_t seq;
    uint64_t data;
    int32_t status;
    uint32_t reserved;
};

struct pciem_irq_inject
{
    uint32_t vector;
    uint32_t reserved;
};

struct pciem_dma_op
{
    uint64_t guest_iova;
    uint64_t user_addr;
    uint32_t length;
    uint32_t pasid;
    uint32_t flags;
    uint32_t reserved;
};

#define PCIEM_DMA_FLAG_READ 0x1
#define PCIEM_DMA_FLAG_WRITE 0x2

struct pciem_dma_atomic
{
    uint64_t guest_iova;
    uint64_t operand;
    uint64_t compare;
    uint32_t op_type;
    uint32_t pasid;
    uint64_t result;
};

#define PCIEM_ATOMIC_FETCH_ADD 1
#define PCIEM_ATOMIC_FETCH_SUB 2
#define PCIEM_ATOMIC_SWAP 3
#define PCIEM_ATOMIC_CAS 4
#define PCIEM_ATOMIC_FETCH_AND 5
#define PCIEM_ATOMIC_FETCH_OR 6
#define PCIEM_ATOMIC_FETCH_XOR 7

struct pciem_p2p_op_user
{
    uint64_t target_phys_addr;
    uint64_t user_addr;
    uint32_t length;
    uint32_t flags;
};

struct pciem_bar_info_query
{
    uint32_t bar_index;
    uint64_t phys_addr;
    uint64_t size;
    uint32_t flags;
};

struct pciem_watchpoint_config
{
    uint32_t bar_index;
    uint32_t offset;
    uint32_t width;
    uint32_t flags;
};

#define PCIEM_WP_FLAG_BAR_KPROBES  (1 << 0)
#define PCIEM_WP_FLAG_BAR_MANUAL   (1 << 1)

struct pciem_eventfd_config
{
    int32_t eventfd;
    uint32_t reserved;
};

struct pciem_irqfd_config
{
    int32_t eventfd;
    uint32_t vector;
    uint32_t flags;
    uint32_t reserved;
};

#define PCIEM_IRQFD_FLAG_LEVEL    (1 << 0)
#define PCIEM_IRQFD_FLAG_DEASSERT (1 << 1)

struct pciem_dma_indirect
{
    uint64_t prp1;
    uint64_t prp2;
    uint64_t user_addr;
    uint32_t length;
    uint32_t page_size;
    uint32_t pasid;
    uint32_t flags;
    uint32_t reserved;
};

#define PCIEM_IOCTL_MAGIC 0xAF

#define PCIEM_IOCTL_CREATE_DEVICE _IOWR(PCIEM_IOCTL_MAGIC, 10, struct pciem_create_device)
#define PCIEM_IOCTL_ADD_BAR _IOW(PCIEM_IOCTL_MAGIC, 11, struct pciem_bar_config)
#define PCIEM_IOCTL_ADD_CAPABILITY _IOW(PCIEM_IOCTL_MAGIC, 12, struct pciem_cap_config)
#define PCIEM_IOCTL_SET_CONFIG _IOW(PCIEM_IOCTL_MAGIC, 13, struct pciem_config_space)
#define PCIEM_IOCTL_REGISTER _IO(PCIEM_IOCTL_MAGIC, 14)
#define PCIEM_IOCTL_INJECT_IRQ _IOW(PCIEM_IOCTL_MAGIC, 15, struct pciem_irq_inject)
#define PCIEM_IOCTL_DMA _IOWR(PCIEM_IOCTL_MAGIC, 16, struct pciem_dma_op)
#define PCIEM_IOCTL_DMA_ATOMIC _IOWR(PCIEM_IOCTL_MAGIC, 17, struct pciem_dma_atomic)
#define PCIEM_IOCTL_P2P _IOWR(PCIEM_IOCTL_MAGIC, 18, struct pciem_p2p_op_user)
#define PCIEM_IOCTL_GET_BAR_INFO _IOWR(PCIEM_IOCTL_MAGIC, 19, struct pciem_bar_info_query)
#define PCIEM_IOCTL_SET_WATCHPOINT _IOW(PCIEM_IOCTL_MAGIC, 20, struct pciem_watchpoint_config)
#define PCIEM_IOCTL_SET_EVENTFD _IOW(PCIEM_IOCTL_MAGIC, 21, struct pciem_eventfd_config)
#define PCIEM_IOCTL_SET_IRQFD _IOW(PCIEM_IOCTL_MAGIC, 22, struct pciem_irqfd_config)
#define PCIEM_IOCTL_DMA_INDIRECT _IOWR(PCIEM_IOCTL_MAGIC, 24, struct pciem_dma_indirect)

#define PCIEM_RING_SIZE 256
#define PCIEM_MAX_IRQFDS 32

struct pciem_shared_ring
{
    atomic_t head;
    char _pad1[60];
    atomic_t tail;
    char _pad2[60];
    struct pciem_event events[PCIEM_RING_SIZE];
};

#ifdef __KERNEL__

#define MAX_WATCHPOINTS 8

struct pciem_watchpoint_info
{
    bool active;
    uint32_t bar_index;
    uint32_t offset;
    uint32_t width;
    struct perf_event * __percpu * perf_bp;
};

struct pciem_irqfd
{
    struct eventfd_ctx *trigger;
    wait_queue_entry_t wait;
    struct work_struct inject_work;
    struct pciem_userspace_state *us;
    uint32_t vector;
    uint32_t flags;
    bool active;
};

#define PCIEM_UNREGISTERED 0
#define PCIEM_REGISTERING  1
#define PCIEM_REGISTERED   2

struct pciem_irqfds {
    spinlock_t lock;
    struct pciem_irqfd entries[PCIEM_MAX_IRQFDS];
};

struct pciem_userspace_state
{
    struct pciem_root_complex *rc;

    struct hlist_head pending_requests[256];
    spinlock_t pending_lock;
    uint64_t next_seq;

    atomic_t registered;
    atomic_t event_pending;

    struct pciem_shared_ring *shared_ring;
    spinlock_t shared_ring_lock;

    struct pciem_watchpoint_info watchpoints[MAX_WATCHPOINTS];
    spinlock_t watchpoint_lock;

    struct eventfd_ctx *eventfd;
    spinlock_t eventfd_lock;

    struct pciem_irqfds irqfds;

    bool bar_tracking_disabled;
};

struct pciem_pending_request
{
    struct hlist_node node;
    uint64_t seq;
    struct completion done;
    uint64_t response_data;
    int response_status;
};

int pciem_userspace_init(void);
void pciem_userspace_cleanup(void);
struct pciem_userspace_state *pciem_userspace_create(void);
void pciem_userspace_destroy(struct pciem_userspace_state *us);
int pciem_userspace_register_device(struct pciem_userspace_state *us);
void pciem_userspace_queue_event(struct pciem_userspace_state *us, struct pciem_event *event);
int pciem_userspace_wait_response(struct pciem_userspace_state *us, uint64_t seq, uint64_t *data_out,
                                  unsigned long timeout_ms);

extern const struct file_operations pciem_device_fops;

#else
#define PCIEM_CAP_MSI 0
#define PCIEM_CAP_MSIX 1
#define PCIEM_CAP_PM 2
#define PCIEM_CAP_PCIE 3
#define PCIEM_CAP_VSEC 4
#define PCIEM_CAP_PASID 5
#endif

#endif /* PCIEM_USERSPACE_H */
