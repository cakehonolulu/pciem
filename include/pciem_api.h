/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Copyright (C) 2025-2026  Joel Bueno
 *  Copyright (C) 2025-2026  Carlos López
 */

#ifndef PCIEM_API_H
#define PCIEM_API_H

#ifdef __KERNEL__
#include <linux/atomic.h>
#else
#include <stdatomic.h>
#include <stdint.h>
typedef atomic_int atomic_t;
#endif

/** Mask to extract the bus mode bits from the flags field. */
#define PCIEM_CREATE_FLAG_BUS_MODE_MASK     0x00000003

/** Create a virtual PCIe bus owned entirely by PCIem. */
#define PCIEM_CREATE_FLAG_BUS_MODE_VIRTUAL  0x00000000

/** Attach to an existing physical PCIe bus. */
#define PCIEM_CREATE_FLAG_BUS_MODE_ATTACH   0x00000001


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

#define PCIEM_CAP_MSI 0
#define PCIEM_CAP_MSIX 1
#define PCIEM_CAP_PM 2
#define PCIEM_CAP_PCIE 3
#define PCIEM_CAP_VSEC 4
#define PCIEM_CAP_PASID 5

struct pciem_cap_pasid_userspace
{
    uint8_t  max_pasid_width;
    uint8_t  execute_permission;
    uint8_t  privileged_mode;
    uint8_t  reserved;
};

struct pciem_cap_config
{
    uint32_t cap_type;
    union {
        struct pciem_cap_msi_userspace msi;
        struct pciem_cap_msix_userspace msix;
        struct pciem_cap_pasid_userspace pasid;
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

/**
 * Parameters for PCIEM_IOCTL_INJECT_IRQ.
 *
 * @param vector    MSI/MSI-X vector number to inject into the guest.
 * @param reserved  Must be zero.
 */
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

/* Notify userspace on BAR reads */
#define PCIEM_TRACE_READS         (1 << 0)

/* Notify userspace on BAR writes */
#define PCIEM_TRACE_WRITES        (1 << 1)
/*
 * Normally, when PCIem detects a write to a BAR, it emulates that
 * write on its shadow mapping of the BAR, allowing future reads to
 * observe that write. If this flag is set, writes will still be
 * notified (if requested), but PCIem will not write to the BAR.
 * Userspace must update the BAR through its own mapping if it wants
 * the device driver to see updates to the BAR.
 */
#define PCIEM_TRACE_STOP_WRITES   (1 << 2)

/* For PCIEM_IOCTL_TRACE_BAR */
struct pciem_trace_bar
{
    uint32_t bar_index;
    uint32_t flags;
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
#define PCIEM_IOCTL_SET_EVENTFD _IOW(PCIEM_IOCTL_MAGIC, 21, struct pciem_eventfd_config)
#define PCIEM_IOCTL_SET_IRQFD _IOW(PCIEM_IOCTL_MAGIC, 22, struct pciem_irqfd_config)
#define PCIEM_IOCTL_DMA_INDIRECT _IOWR(PCIEM_IOCTL_MAGIC, 24, struct pciem_dma_indirect)
#define PCIEM_IOCTL_TRACE_BAR _IOWR(PCIEM_IOCTL_MAGIC, 25, struct pciem_trace_bar)
#define PCIEM_IOCTL_START _IO(PCIEM_IOCTL_MAGIC, 26)

#define PCIEM_RING_SIZE 256
#define PCIEM_MAX_IRQFDS 32

/**
 * Lock-free single-producer/single-consumer event ring shared between the
 * kernel and userspace.
 *
 * The kernel writes events by advancing @head; userspace consumes them by
 * advancing @tail. Each counter is cache-line padded.
 * The ring is mapped read-only into userspace via mmap on the PCIem fd.
 *
 * @param head    Write index, owned by the kernel. Incremented atomically
 *                after each event is committed.
 * @param _pad1   Cache-line padding to isolate @head from @tail.
 * @param tail    Read index, owned by userspace. Incremented after each event
 *                is consumed.
 * @param _pad2   Cache-line padding to isolate @tail from the event array.
 * @param events  Circular buffer of PCIEM_RING_SIZE events.
 */
struct pciem_shared_ring
{
    atomic_t head;
    char _pad1[60];
    atomic_t tail;
    char _pad2[60];
    struct pciem_event events[PCIEM_RING_SIZE];
};

#endif /* PCIEM_API_H */
