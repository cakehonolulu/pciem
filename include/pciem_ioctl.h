
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define SHARED_BUF_SIZE (4 * 1024 * 1024)

#define DRIVER_NAME "pciem"

#define SHIM_DEVICE_NAME "pciem_shim"

struct shim_req {
    uint32_t id;
    uint32_t type;
    uint32_t size;
    uint64_t addr;
    uint64_t data;
} __attribute__((packed));

struct shim_resp {
    uint32_t id;
    uint64_t data;
} __attribute__((packed));

struct virt_bar_info
{
    uint64_t phys_start;
    uint64_t size;
};

struct pciem_get_bar_args
{
    uint32_t bar_index;
    uint32_t padding;
    struct virt_bar_info info;
};

struct shim_dma_shared_op
{
    uint64_t host_phys_addr;
    uint32_t len;
    uint32_t padding;
};

struct shim_dma_read_op
{
    uint64_t host_phys_addr;
    uint64_t user_buf_addr;
    uint32_t len;
    uint32_t padding;
};

struct pciem_p2p_op {
    uint64_t target_phys_addr;
    uint32_t len;
    uint32_t flags;
};

#define PCIEM_SHIM_IOC_MAGIC 'R'
#define PCIEM_SHIM_IOCTL_RAISE_IRQ _IOW(PCIEM_SHIM_IOC_MAGIC, 3, int)
#define PCIEM_SHIM_IOCTL_LOWER_IRQ _IOW(PCIEM_SHIM_IOC_MAGIC, 4, int)
#define PCIEM_SHIM_IOCTL_DMA_READ _IOWR(PCIEM_SHIM_IOC_MAGIC, 5, struct shim_dma_read_op)
#define PCIEM_SHIM_IOCTL_DMA_READ_SHARED _IOW(PCIEM_SHIM_IOC_MAGIC, 6, struct shim_dma_shared_op)
#define PCIEM_SHIM_IOCTL_P2P_READ  _IOW(PCIEM_SHIM_IOC_MAGIC, 7, struct pciem_p2p_op)
#define PCIEM_SHIM_IOCTL_P2P_WRITE _IOW(PCIEM_SHIM_IOC_MAGIC, 8, struct pciem_p2p_op)
