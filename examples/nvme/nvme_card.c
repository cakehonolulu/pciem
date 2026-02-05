// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 *  Copyright (C) 2026  Joel Bueno <buenocalvachejoel@gmail.com>
 *  Copyright (C) 2026  Carlos López <carlos.lopezr4096@gmail.com>
 */
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <time.h>
#include <unistd.h>

#include "pciem_userspace.h"

#define NVME_REG_CAP                0x00
#define NVME_REG_VS                 0x08
#define NVME_REG_INTMS              0x0c
#define NVME_REG_INTMC              0x10
#define NVME_REG_CC                 0x14
#define NVME_REG_CSTS               0x1c
#define NVME_REG_AQA                0x24
#define NVME_REG_ASQ_LO             0x28
#define NVME_REG_ASQ_HI             0x2c
#define NVME_REG_ACQ_LO             0x30
#define NVME_REG_ACQ_HI             0x34
#define NVME_REG_SQ0TDBL            0x1000
#define NVME_REG_CQ0HDBL            0x1004

#define NVME_CC_ENABLE              (1 << 0)
#define NVME_CC_CSS_NVM             (0 << 4)
#define NVME_CC_IOSQES              (6 << 16)
#define NVME_CC_IOCQES              (4 << 20)

#define NVME_CSTS_RDY               (1 << 0)
#define NVME_CSTS_CFS               (1 << 1)

#define NVME_ADMIN_DELETE_SQ        0x00
#define NVME_ADMIN_CREATE_SQ        0x01
#define NVME_ADMIN_DELETE_CQ        0x04
#define NVME_ADMIN_CREATE_CQ        0x05
#define NVME_ADMIN_IDENTIFY         0x06
#define NVME_ADMIN_SET_FEATURES     0x09
#define NVME_ADMIN_GET_FEATURES     0x0a

#define NVME_CMD_FLUSH              0x00
#define NVME_CMD_WRITE              0x01
#define NVME_CMD_READ               0x02

#define NVME_SCT_GENERIC            0x0
#define NVME_SCT_COMMAND_SPEC       0x1
#define NVME_SCT_MEDIA_ERROR        0x2
#define NVME_SCT_PATH_ERROR         0x3

#define NVME_SC_SUCCESS                  0x00
#define NVME_SC_INVALID_FIELD            0x02
#define NVME_SC_INTERNAL                 0x06
#define NVME_SC_INVALID_NS               0x0b
#define NVME_SC_OPERATION_DENIED         0x15

#define NVME_SC_INVALID_QUEUE            0x00
#define NVME_SC_INVALID_QUEUE_SIZE       0x01
#define NVME_SC_INVALID_INTERRUPT_VECTOR 0x02
#define NVME_SC_INVALID_QUEUE_DELETE     0x03
#define NVME_SC_INVALID_QUEUE_CREATE     0x04

#define NVME_STATUS(sct, sc)       (((sct) << 8 | (sc)) << 1)
#define NVME_SUCCESS                NVME_STATUS(NVME_SCT_GENERIC, NVME_SC_SUCCESS)
#define NVME_INVALID_FIELD          NVME_STATUS(NVME_SCT_GENERIC, NVME_SC_INVALID_FIELD)
#define NVME_INTERNAL               NVME_STATUS(NVME_SCT_GENERIC, NVME_SC_INTERNAL)
#define NVME_INVALID_NS             NVME_STATUS(NVME_SCT_GENERIC, NVME_SC_INVALID_NS)
#define NVME_OPERATION_DENIED       NVME_STATUS(NVME_SCT_GENERIC, NVME_SC_OPERATION_DENIED)

#define NVME_INVALID_QUEUE          NVME_STATUS(NVME_SCT_COMMAND_SPEC, NVME_SC_INVALID_QUEUE)
#define NVME_INVALID_QUEUE_CREATE   NVME_STATUS(NVME_SCT_COMMAND_SPEC, NVME_SC_INVALID_QUEUE_CREATE)
#define NVME_INVALID_QUEUE_DELETE   NVME_STATUS(NVME_SCT_COMMAND_SPEC, NVME_SC_INVALID_QUEUE_DELETE)

#define NVME_SECTOR_SIZE            4096
#define GB                          (1024UL * 1024UL * 1024UL)
#define NVME_DISK_SIZE_GB           1
#define NVME_DISK_SIZE              NVME_DISK_SIZE_GB * GB
#define NVME_TOTAL_SECTORS          ((NVME_DISK_SIZE_GB * 1024UL * 1024 * 1024) / NVME_SECTOR_SIZE)
#define MAX_QUEUES                  16

#define NVME_SHN_NONE     0
#define NVME_SHN_NORMAL   1
#define NVME_SHN_ABRUPT   2

#define NVME_SHST_NORMAL   0
#define NVME_SHST_PROGRESS 1
#define NVME_SHST_COMPLETE 2

enum nvme_feature_id {
    NVME_FEAT_ARBITRATION           = 0x01,
    NVME_FEAT_POWER_MGMT            = 0x02,
    NVME_FEAT_LBA_RANGE             = 0x03,
    NVME_FEAT_TEMP_THRESHOLD        = 0x04,
    NVME_FEAT_ERROR_RECOVERY        = 0x05,
    NVME_FEAT_VOLATILE_WC           = 0x06,
    NVME_FEAT_NUM_QUEUES            = 0x07,
    NVME_FEAT_IRQ_COALESCE          = 0x08,
    NVME_FEAT_IRQ_CONFIG            = 0x09,
    NVME_FEAT_WRITE_ATOMIC          = 0x0A,
    NVME_FEAT_ASYNC_EVENT           = 0x0B,
    NVME_FEAT_AUTO_PST              = 0x0C,
    NVME_FEAT_HOST_MEM_BUF          = 0x0D,
    NVME_FEAT_TIMESTAMP             = 0x0E,
    NVME_FEAT_KATO                  = 0x0F,
    NVME_FEAT_HCTM                  = 0x10,
    NVME_FEAT_NOPSC                 = 0x11,
    NVME_FEAT_RRL                   = 0x12,
    NVME_FEAT_PLM_CONFIG            = 0x13,
    NVME_FEAT_PLM_WINDOW            = 0x14,
    NVME_FEAT_HOST_BEHAVIOR         = 0x16,
};

struct nvme_cc {
    uint32_t en     : 1;  /* bit 0 */
    uint32_t rsvd1  : 13;
    uint8_t  shn    : 2;  /* bits 15:14 */
    uint32_t rsvd2  : 16;
} __attribute__((packed));

struct nvme_csts {
    uint32_t rdy    : 1;  /* bit 0 */
    uint32_t rsvd1  : 1;
    uint32_t shst   : 2;  /* bits 3:2 */
    uint32_t rsvd2  : 28;
} __attribute__((packed));

struct nvme_version {
    uint32_t major : 8;   /* bits 7:0 */
    uint32_t minor : 8;   /* bits 15:8 */
    uint32_t rsvd  : 16;  /* bits 31:16 */
} __attribute__((packed));

struct nvme_cap {
    uint64_t mqes    : 16; /* Max Queue Entries Supported (0-based) */
    uint64_t to      : 8;  /* Timeout in 500ms units */
    uint64_t dstrd   : 4;  /* Doorbell stride */
    uint64_t nssrs   : 1;  /* NVM Subsystem Reset Supported */
    uint64_t css     : 8;  /* Command Sets Supported */
    uint64_t rsvd1   : 3;
    uint64_t mpsmin  : 4;  /* Minimum page size */
    uint64_t mpsmax  : 4;  /* Maximum page size */
    uint64_t rsvd2   : 16;
} __attribute__((packed));

struct nvme_lbaf {
	uint16_t ms;
	uint8_t ds;
	uint8_t rp;
};

struct nvme_id_ns {
	uint64_t nsze;
	uint64_t ncap;
	uint64_t nuse;
	uint8_t nsfeat;
	uint8_t nlbaf;
	uint8_t flbas;
	uint8_t mc;
	uint8_t dpc;
	uint8_t dps;
	uint8_t nmic;
	uint8_t rescap;
	uint8_t fpi;
	uint8_t dlfeat;
	uint16_t nawun;
	uint16_t nawupf;
	uint16_t nacwu;
	uint16_t nabsn;
	uint16_t nabo;
	uint16_t nabspf;
	uint16_t noiob;
	uint8_t nvmcap[16];
	uint16_t npwg;
	uint16_t npwa;
	uint16_t npdg;
	uint16_t npda;
	uint16_t nows;
	uint8_t rsvd74[18];
	uint32_t anagrpid;
	uint8_t rsvd96[3];
	uint8_t nsattr;
	uint16_t nvmsetid;
	uint16_t endgid;
	uint8_t nguid[16];
	uint8_t eui64[8];
	struct nvme_lbaf lbaf[64];
	uint8_t vs[3712];
};

_Static_assert(sizeof(struct nvme_id_ns) == 4096, "nvme_id_ns");

struct nvme_id_power_state {
	uint16_t max_power;
	uint8_t rsvd2;
	uint8_t flags;
	uint32_t entry_lat;
	uint32_t exit_lat;
	uint8_t read_tput;
	uint8_t read_lat;
	uint8_t write_tput;
	uint8_t write_lat;
	uint16_t idle_power;
	uint8_t idle_scale;
	uint8_t rsvd19;
	uint16_t active_power;
	uint8_t active_work_scale;
	uint8_t rsvd23[9];
};

struct nvme_ctrl_id {
	uint16_t vid;
	uint16_t ssvid;
	char sn[20];
	char mn[40];
	char fr[8];
	uint8_t rab;
	uint8_t ieee[3];
	uint8_t cmic;
	uint8_t mdts;
	uint16_t cntlid;
	uint32_t ver;
	uint32_t rtd3r;
	uint32_t rtd3e;
	uint32_t oaes;
	uint32_t ctratt;
	uint8_t rsvd100[11];
	uint8_t cntrltype;
	uint8_t fguid[16];
	uint16_t crdt1;
	uint16_t crdt2;
	uint16_t crdt3;
	uint8_t rsvd134[122];
	uint16_t oacs;
	uint8_t acl;
	uint8_t aerl;
	uint8_t frmw;
	uint8_t lpa;
	uint8_t elpe;
	uint8_t npss;
	uint8_t avscc;
	uint8_t apsta;
	uint16_t wctemp;
	uint16_t cctemp;
	uint16_t mtfa;
	uint32_t hmpre;
	uint32_t hmmin;
	uint8_t tnvmcap[16];
	uint8_t unvmcap[16];
	uint32_t rpmbs;
	uint16_t edstt;
	uint8_t dsto;
	uint8_t fwug;
	uint16_t kas;
	uint16_t hctma;
	uint16_t mntmt;
	uint16_t mxtmt;
	uint32_t sanicap;
	uint32_t hmminds;
	uint16_t hmmaxd;
	uint16_t nvmsetidmax;
	uint16_t endgidmax;
	uint8_t anatt;
	uint8_t anacap;
	uint32_t anagrpmax;
	uint32_t nanagrpid;
	uint8_t rsvd352[160];
	uint8_t sqes;
	uint8_t cqes;
	uint16_t maxcmd;
	uint32_t nn;
	uint16_t oncs;
	uint16_t fuses;
	uint8_t fna;
	uint8_t vwc;
	uint16_t awun;
	uint16_t awupf;
	uint8_t nvscc;
	uint8_t nwpc;
	uint16_t acwu;
	uint8_t rsvd534[2];
	uint32_t sgls;
	uint32_t mnan;
	uint8_t rsvd544[224];
	char subnqn[256];
	uint8_t rsvd1024[768];
	uint32_t ioccsz;
	uint32_t iorcsz;
	uint16_t icdoff;
	uint8_t ctrattr;
	uint8_t msdbd;
	uint8_t rsvd1804[2];
	uint8_t dctype;
	uint8_t rsvd1807[241];
	struct nvme_id_power_state psd[32];
	uint8_t vs[1024];
};

_Static_assert(sizeof(struct nvme_ctrl_id) == 4096, "nvme_ctrl_id");

union cdw10_t {
    uint32_t raw;

    struct {
        uint8_t cns;
        uint8_t rsvd;
        uint16_t nsid;
    } identify;

    struct {
        uint16_t qid;
        uint16_t qsize;
    } create_io_cq;

    struct {
        uint16_t qid;
        uint16_t qsize;
    } create_io_sq;

    struct {
        uint16_t qid;
        uint16_t rsvd;
    } delete_io_cq;

    struct {
        uint16_t qid;
        uint16_t rsvd;
    } delete_io_sq;

    struct {
        uint8_t fid;
        uint8_t sel : 3;
        uint8_t rsvd : 5;
        uint16_t rsvd2;
    } features;
};

union cdw11_t {
    uint32_t raw;

    struct {
        uint16_t vector;
        uint8_t ien : 1;
        uint8_t reserved : 7;
        uint8_t phys_cont : 1;
        uint8_t rsvd : 7;
    } create_io_cq;

    struct {
        uint16_t prp1;
        uint16_t rsvd;
    } create_io_sq;

    struct {
        uint16_t nsqa;
        uint16_t ncqa;
    } feat_num_queues;
};

union cdw12_t {
    uint32_t raw;

    struct {
        uint16_t nlb;
        uint8_t  rsvd;
        uint8_t  flags;
    } rw;
};

struct nvme_command {
    uint8_t  opcode;
    uint8_t  flags;
    uint16_t command_id;
    uint32_t nsid;
    uint64_t rsvd2;
    uint64_t metadata;
    uint64_t prp1;
    uint64_t prp2;
    union cdw10_t cdw10;
    union cdw11_t cdw11;
    union cdw12_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} __attribute__((packed));

struct nvme_completion {
    uint32_t result;
    uint32_t rsvd;
    uint16_t sq_head;
    uint16_t sq_id;
    uint16_t command_id;
    uint16_t status;
} __attribute__((packed));

struct nvme_queue {
    bool created;
    uint16_t sq_size;
    uint16_t cq_size;
    uint64_t sq_addr;
    uint64_t cq_addr;
    uint16_t sq_tail;
    uint16_t sq_head;
    uint16_t cq_tail;
    uint16_t cq_head;
    uint8_t cq_phase;
    uint16_t vector;
    uint16_t id;
};

#define NVME_VS(major, minor, tertiary) \
	(((major) << 16) | ((minor) << 8) | (tertiary))

struct nvme_device {
    int fd;
    int instance_fd;
    void *bar0;
    size_t bar0_size;

    struct pciem_shared_ring *ring;
    int event_fd;

    bool running;
    bool enabled;
    uint32_t csts;

    struct nvme_queue queues[MAX_QUEUES];
    struct nvme_ctrl_id ctrl_id;

    uint8_t *disk_data;
};

#define logx(fmt, ...)                                                \
    do {                                                              \
        struct timespec __ts;                                         \
        clock_gettime(CLOCK_BOOTTIME, &__ts);                          \
        warnx("[%5ld.%06ld] " fmt,                           \
              __ts.tv_sec, __ts.tv_nsec / 1000,                     \
              ##__VA_ARGS__);                                        \
    } while (0)

#define log(fmt, ...)                                                \
    do {                                                              \
        struct timespec __ts;                                         \
        clock_gettime(CLOCK_BOOTTIME, &__ts);                          \
        warn("[%5ld.%06ld] " fmt,                           \
              __ts.tv_sec, __ts.tv_nsec / 1000,                     \
              ##__VA_ARGS__);                                        \
    } while (0)

static uint64_t size2mask(uint64_t size)
{
    return size >= 8
        ? 0xffffffffffffffff
        : (1ULL << (size << 3)) - 1;
}

static const char *reg2str(uint64_t off)
{
    switch (off) {
        case NVME_REG_CAP: return "REG_CAP";
        case NVME_REG_VS: return "REG_VS";
        case NVME_REG_CC: return "REG_CC";
        case NVME_REG_CSTS: return "REG_CSTS";
        case NVME_REG_AQA: return "REG_AQA";
        case NVME_REG_ASQ_LO: return "REG_ASQ_LO";
        case NVME_REG_ASQ_HI: return "REG_ASQ_HI";
        case NVME_REG_ACQ_LO: return "REG_ACQ_LO";
        case NVME_REG_ACQ_HI: return "REG_ACQ_HI";
        default: return "??";
    }
}

static uint64_t nvme_read_reg(struct nvme_device *dev, uint32_t offset, uint32_t size)
{
    volatile uint8_t *base = (volatile uint8_t *)dev->bar0;

    switch (size) {
    case 4:
        return *(volatile uint32_t *)(base + offset);
    case 8:
        return *(volatile uint64_t *)(base + offset);
    default:
        return 0;
    }
}

static void __nvme_write_reg(struct nvme_device *dev, uint32_t offset,
                             uint64_t value, uint32_t size, bool log)
{
    volatile uint8_t *addr = (volatile uint8_t *)dev->bar0 + offset;

    if (log)
        logx("> DEV: write @ 0x%x:%x (%s) = 0x%lx",
                offset, size, reg2str(offset), value);

    switch (size) {
    case 2:
        *(volatile uint16_t*)(addr) = (uint16_t)value;
        break;
    case 4:
        *(volatile uint32_t *)(addr) = (uint32_t)value;
        break;
    case 8:
        *(volatile uint64_t *)(addr) = value;
        break;
    }
    asm volatile("": : :"memory");
}

static void nvme_write_reg(struct nvme_device *dev, uint32_t offset, uint64_t value, uint32_t size)
{
     __nvme_write_reg(dev, offset, value, size, true);
}

static const char* adminopcode2str(uint8_t op)
{
    switch (op) {
        case NVME_ADMIN_DELETE_SQ: return "NVME_ADMIN_DELETE_SQ";
        case NVME_ADMIN_CREATE_SQ: return "NVME_ADMIN_CREATE_SQ";
        case NVME_ADMIN_DELETE_CQ: return "NVME_ADMIN_DELETE_CQ";
        case NVME_ADMIN_CREATE_CQ: return "NVME_ADMIN_CREATE_CQ";
        case NVME_ADMIN_IDENTIFY: return "NVME_ADMIN_IDENTIFY";
        case NVME_ADMIN_SET_FEATURES: return "NVME_ADMIN_SET_FEATURES";
        case NVME_ADMIN_GET_FEATURES: return "NVME_ADMIN_GET_FEATURES";
        default: return "??";
    }
}

static const char *ioopcode2str(uint8_t op)
{
    switch (op) {
        case NVME_CMD_FLUSH: return "NVME_CMD_FLUSH";
        case NVME_CMD_WRITE: return "NVME_CMD_WRITE";
        case NVME_CMD_READ: return "NVME_CMD_READ";
        default: return "??";
    }
}

static const char *shn2str(uint8_t shn)
{
    switch (shn) {
        case NVME_SHN_NONE: return "NVME_SHN_NONE";
        case NVME_SHN_NORMAL: return "NVME_SHN_NORMAL";
        case NVME_SHN_ABRUPT: return "NVME_SHN_ABRUPT";
        default: return "??";
    }
}

static int nvme_dma_rw(struct nvme_device *dev, uint64_t prp1, uint64_t prp2,
                       uint8_t *ram_ptr, uint32_t length, bool write_to_host,
                       const char *aux)
{
    uint32_t page_size = 4096;
    int ret;
    struct pciem_dma_indirect indirect = {
        .prp1 = prp1,
        .prp2 = prp2,
        .user_addr = (uint64_t)ram_ptr,
        .length = length,
        .page_size = page_size,
        .pasid = 0,
        .flags = write_to_host ? PCIEM_DMA_FLAG_WRITE : PCIEM_DMA_FLAG_READ
    };

    ret = ioctl(dev->fd, PCIEM_IOCTL_DMA_INDIRECT, &indirect);
    if (ret)
        log("x failed DMA %s (%s)", write_to_host ? "write" : "read",
            aux ? aux : "N/A");

    return ret;
}

static struct nvme_queue *nvme_get_queue(struct nvme_device *dev, uint16_t idx)
{
    if (idx >= MAX_QUEUES) {
        logx("- invalid queue index: %u", idx);
        return NULL;
    }

    return &dev->queues[idx];
}

static void set_lo32(uint64_t *dst, uint32_t val)
{
    *dst= (*dst & 0xFFFFFFFF00000000ULL) | (uint64_t)val;
}

static void set_hi32(uint64_t *dst, uint32_t val)
{
    *dst = (*dst & 0x00000000FFFFFFFFULL) | ((uint64_t)val << 32);
}

static int nvme_dma_write(struct nvme_device *dev, struct pciem_dma_op *op,
                           const char *aux)
{
    int ret;

    op->flags = PCIEM_DMA_FLAG_WRITE;
    logx("* DMA: DEV:0x%012lx -> DRV:0x%012lx (size = 0x%04x) (%s)",
         op->user_addr, op->guest_iova, op->length, aux ? aux : "N/A");
    ret = ioctl(dev->fd, PCIEM_IOCTL_DMA, op);
    if (ret)
        log("x failed DMA write (%s)", aux ? aux : "N/A");
    return ret;
}

static int nvme_dma_read(struct nvme_device *dev, struct pciem_dma_op *op,
                          const char *aux)
{
    int ret;

    op->flags = PCIEM_DMA_FLAG_READ;
    logx("* DMA: DEV:0x%012lx <- DRV:0x%012lx (size = 0x%04x) (%s)",
         op->user_addr, op->guest_iova, op->length, aux ? aux : "N/A");
    ret = ioctl(dev->fd, PCIEM_IOCTL_DMA, op);
    if (ret)
        log("x failed DMA read (%s)", aux ? aux : "N/A");
    return ret;
}

static void nvme_reset_queue(struct nvme_queue *q)
{
    uint16_t id = q->id;

    memset(q, 0, sizeof(*q));
    q->id = id;
    q->cq_phase = 1;
}

static void nvme_reset_queues(struct nvme_device *dev)
{
    for (int i = 0; i < MAX_QUEUES; ++i) {
        dev->queues[i].id = i;
        nvme_reset_queue(&dev->queues[i]);
    }
}

static uint32_t nvme_identify_cns0(struct nvme_device *dev,
                                   struct nvme_command *cmd)
{
    struct nvme_id_ns ns = {
        .nsze = NVME_TOTAL_SECTORS,
        .ncap = NVME_TOTAL_SECTORS,
        .nuse = NVME_TOTAL_SECTORS,
        .nlbaf = 1,
        .lbaf = { { .ds = 12 } },
    };
    struct pciem_dma_op op = {
        .guest_iova = cmd->prp1,
        .user_addr = (uint64_t)&ns,
        .length = sizeof(ns),
    };
    int ret;

    /* We support only one namespace */
    if (cmd->nsid != 1)
        return NVME_INVALID_NS;

    ret = nvme_dma_write(dev, &op, "identify cns=0 nsid=1");
    if (ret)
        return NVME_INTERNAL;

    return NVME_SUCCESS;
}

static uint32_t nvme_identify_cns1(struct nvme_device *dev,
                                   struct nvme_command *cmd)
{
    struct pciem_dma_op op = {
        .guest_iova = cmd->prp1,
        .user_addr = (uint64_t)&dev->ctrl_id,
        .length = sizeof(dev->ctrl_id),
    };
    int ret;

    if (cmd->nsid != 0)
        return NVME_INVALID_NS;

    ret = nvme_dma_write(dev, &op, "identify cns=1 nsid=0 (ctrl)");
    if (ret)
        return NVME_INTERNAL;

    return NVME_SUCCESS;
}

static uint32_t nvme_identify_cns2(struct nvme_device *dev,
                                   struct nvme_command *cmd)
{
    uint32_t *nslist;
    struct pciem_dma_op op = {
        .guest_iova = cmd->prp1,
        .length = 0x1000,
    };
    int ret;

    if (cmd->nsid != 0)
        return NVME_INVALID_NS;

    nslist = calloc(1, 0x1000);
    if (!nslist)
        return NVME_INTERNAL;

    nslist[0] = 1;
    op.user_addr = (uint64_t)nslist;

    ret = nvme_dma_write(dev, &op, "identify cns=2 nsid=0 (ns list)");
    free(nslist);

    return ret ? NVME_INTERNAL : NVME_SUCCESS;
}

static uint32_t nvme_identify_cns3(struct nvme_device *dev,
                                   struct nvme_command *cmd)
{
    uint8_t *dslist;
    struct pciem_dma_op op = {
        .guest_iova = cmd->prp1,
        .length = 0x1000,
    };
    int ret;

    if (cmd->nsid > 1)
        return NVME_INVALID_NS;

    dslist = calloc(1, 0x1000);
    if (!dslist)
        return NVME_INTERNAL;

    op.user_addr = (uint64_t)dslist;

    ret = nvme_dma_write(dev, &op, "identify cns=3 nsid=X (ds list)");
    free(dslist);

    return ret ? NVME_INTERNAL : NVME_SUCCESS;
}

/*
 * CNS  NSID  Meaning
 * ---  ----  ------------------------------------------------------------
 * 0    0     Invalid
 * 0    1     Identify Namespace 1 (nvme_id_ns)
 * 0    2–4   Identify Namespace N (only valid if namespace exists)
 *
 * 1    0     Identify Controller (nvme_id_ctrl)
 * 1    1–4   Invalid. NSID must be 0 for CNS=1
 *
 * 2    0     Identify Active Namespace ID List (uint32_t array, terminated by 0)
 * 2    1–4   Invalid. NSID must be 0
 *
 * 3    0     Identify Namespace Descriptor List for all namespaces (NVMe ≥1.3)
 * 3    1     Identify Namespace Descriptor List for Namespace 1
 * 3    2–4   Identify Namespace Descriptor List for Namespace N (if it exists)
 *
 * 4    0     Identify Namespace Attribute (NVMe ≥2.0)
 * 4    1–4   Identify Namespace Attribute for Namespace N (if supported)
 */
 static uint32_t nvme_identify(struct nvme_device *dev,
                               struct nvme_command *cmd)
{
    uint8_t cns = cmd->cdw10.identify.cns;

    logx("  identify cns=%u nsid=%u", cns, cmd->nsid);

    switch (cns) {
        case 0: return nvme_identify_cns0(dev, cmd);
        case 1: return nvme_identify_cns1(dev, cmd);
        case 2: return nvme_identify_cns2(dev, cmd);
        case 3: return nvme_identify_cns3(dev, cmd);
    }

    return NVME_INVALID_FIELD;
}

static uint32_t nvme_create_cq(struct nvme_device *dev,
                               struct nvme_command *cmd)
{
    uint16_t qidx = cmd->cdw10.create_io_cq.qid;
    uint16_t qsize = cmd->cdw10.create_io_cq.qsize;
    uint16_t vector = cmd->cdw11.create_io_cq.vector;
    struct nvme_queue *q = nvme_get_queue(dev, qidx);

    if (!q)
        return NVME_INVALID_QUEUE_CREATE;

    q->cq_addr = cmd->prp1;
    q->cq_size = qsize + 1;
    q->vector = vector;
    q->created = true;
    logx("+ created CQ queue %u 0x%lx:0x%x (vector=%d)",
         qidx, q->cq_addr, q->cq_size, q->vector);

    return NVME_SUCCESS;
}

static uint32_t nvme_create_sq(struct nvme_device *dev,
                               struct nvme_command *cmd)
{
    uint16_t qidx = cmd->cdw10.create_io_sq.qid;
    uint16_t qsize = cmd->cdw10.create_io_sq.qsize;
    struct nvme_queue *q = nvme_get_queue(dev, qidx);

    if (!q)
        return NVME_INVALID_QUEUE_CREATE;

    q->sq_addr = cmd->prp1;
    q->sq_size = qsize + 1;
    q->created = true;
    logx("+ created SQ queue %u 0x%lx:0x%x", qidx, q->sq_addr, q->sq_size);

    return NVME_SUCCESS;
}

static uint32_t nvme_delete_queue(struct nvme_device *dev,
                                  struct nvme_command *cmd)
{
    uint16_t qidx = cmd->cdw10.delete_io_cq.qid;

    if (qidx >= MAX_QUEUES) {
        logx("Attempted to delete invalid queue %u\n", qidx);
        return NVME_INVALID_QUEUE_DELETE;
    }

    nvme_reset_queue(&dev->queues[qidx]);
    logx("+ deleted queue %u", qidx);
    return NVME_SUCCESS;
}

static uint32_t nvme_set_features(struct nvme_device *dev,
                                  const struct nvme_command *cmd,
                                  uint32_t *result)
{
    uint8_t fid = cmd->cdw10.features.fid;

    (void)dev;

    switch (fid) {
        case NVME_FEAT_NUM_QUEUES: {
            uint16_t nsq = cmd->cdw11.feat_num_queues.nsqa;
            uint16_t ncq = cmd->cdw11.feat_num_queues.ncqa;
            logx("  FEAT: nsq=%u/%u ncq=%u/%u",
                 nsq, MAX_QUEUES, ncq, MAX_QUEUES);
            nsq = nsq < MAX_QUEUES ? nsq : MAX_QUEUES;
            ncq = ncq < MAX_QUEUES ? ncq : MAX_QUEUES;
            *result = (ncq << 16) | nsq;
            return NVME_SUCCESS;
        }
        case NVME_FEAT_ARBITRATION:
        case NVME_FEAT_POWER_MGMT:
        case NVME_FEAT_ERROR_RECOVERY:
        case NVME_FEAT_VOLATILE_WC:
        case NVME_FEAT_IRQ_COALESCE:
        case NVME_FEAT_IRQ_CONFIG:
        case NVME_FEAT_ASYNC_EVENT:
        case NVME_FEAT_TEMP_THRESHOLD:
        case NVME_FEAT_WRITE_ATOMIC:
        case NVME_FEAT_NOPSC:
        case NVME_FEAT_RRL:
        case NVME_FEAT_PLM_CONFIG:
        case NVME_FEAT_PLM_WINDOW:
            logx("  FEAT: allow 0x%x", fid);
            return NVME_SUCCESS;
        case NVME_FEAT_LBA_RANGE:        // Requires tracking LBA ranges
        case NVME_FEAT_AUTO_PST:         // Autonomous power state transitions
        case NVME_FEAT_HOST_MEM_BUF:     // Host memory buffer
        case NVME_FEAT_TIMESTAMP:        // Timestamp feature
        case NVME_FEAT_KATO:             // Keep alive timeout
        case NVME_FEAT_HCTM:             // Host controlled thermal management
        case NVME_FEAT_HOST_BEHAVIOR:    // Host behavior support
            logx("- FEAT: disallow 0x%x", fid);
            return NVME_INVALID_FIELD;
        default:
            logx("- FEAT: unknown feature 0x%x", fid);
            return NVME_INVALID_FIELD;
    }
}

static uint32_t nvme_execute_admin_command(struct nvme_device *dev,
                                           struct nvme_command *cmd,
                                           uint32_t *result)
{
    logx("  CMD: admin::%s nsid=%u", adminopcode2str(cmd->opcode), cmd->nsid);

    switch (cmd->opcode) {
        case NVME_ADMIN_IDENTIFY:
            return nvme_identify(dev, cmd);
        case NVME_ADMIN_CREATE_CQ:
            return nvme_create_cq(dev, cmd);
        case NVME_ADMIN_CREATE_SQ:
            return nvme_create_sq(dev, cmd);
        case NVME_ADMIN_DELETE_CQ:
        case NVME_ADMIN_DELETE_SQ:
            return nvme_delete_queue(dev, cmd);
        case NVME_ADMIN_SET_FEATURES:
            return nvme_set_features(dev, cmd, result);
        default: {
            logx("? unhandled admin command: 0x%x", cmd->opcode);
            return NVME_INVALID_FIELD;
        }
    }
}

static uint32_t nvme_io_write(struct nvme_device *dev, struct nvme_command *cmd)
{
    uint64_t slba = cmd->cdw10.raw | ((uint64_t)cmd->cdw11.raw << 32);
    uint64_t offset = slba << 12;
    uint32_t nlb = cmd->cdw12.rw.nlb + 1;
    uint64_t len = (uint64_t)nlb << 12;
    int ret;

    if (offset >= NVME_DISK_SIZE) {
        logx("Attempted to write offset %lx/%lx", offset, NVME_DISK_SIZE);
        return NVME_INVALID_FIELD;
    }

    ret = nvme_dma_rw(dev, cmd->prp1, cmd->prp2, dev->disk_data + offset,
                      len, false, "host write");
    return ret ? NVME_INTERNAL : NVME_SUCCESS;
}

static uint32_t nvme_io_read(struct nvme_device *dev, struct nvme_command *cmd)
{
    uint64_t slba = cmd->cdw10.raw | ((uint64_t)cmd->cdw11.raw << 32);
    uint64_t offset = slba << 12;
    uint32_t nlb = cmd->cdw12.rw.nlb + 1;
    uint64_t len = (uint64_t)nlb << 12;
    int ret;

    if (offset >= NVME_DISK_SIZE) {
        logx("Attempted to read offset %lx/%lx", offset, NVME_DISK_SIZE);
        return NVME_INVALID_FIELD;
    }

    ret = nvme_dma_rw(dev, cmd->prp1, cmd->prp2, dev->disk_data + offset,
                      len, true, "host read");
    return ret ? NVME_INTERNAL : NVME_SUCCESS;
}

static uint32_t nvme_execute_io_command(struct nvme_device *dev,
                                        struct nvme_command *cmd)
{
    logx("  CMD: io::%s nsid=%u", ioopcode2str(cmd->opcode), cmd->nsid);
    switch (cmd->opcode) {
        case NVME_CMD_FLUSH:
            return NVME_SUCCESS;
        case NVME_CMD_READ:
            return nvme_io_read(dev, cmd);
        case NVME_CMD_WRITE:
            return nvme_io_write(dev, cmd);
        default: {
            logx("? unhandled I/O command: 0x%x", cmd->opcode);
            return NVME_INVALID_FIELD;
        }
    }
}

static void nvme_execute_command(struct nvme_device *dev,
                                 struct nvme_command *cmd,
                                 struct nvme_queue *q)
{
    struct nvme_completion cpl = {0};
    struct pciem_dma_op op = {0};
    uint32_t status = NVME_OPERATION_DENIED;
    struct pciem_irq_inject irq;

    if (q->id == 0) {
        uint32_t result = 0;
        status = nvme_execute_admin_command(dev, cmd, &result);
        cpl.result = result;
    } else {
        status = nvme_execute_io_command(dev, cmd);
    }
    logx("       ret = %d", status);

    cpl.command_id = cmd->command_id;
    cpl.sq_head = q->sq_head;
    cpl.sq_id = q->id;
    cpl.status = status | (q->cq_phase & 1);

    op.guest_iova = q->cq_addr + q->cq_tail * sizeof(cpl);
    op.user_addr  = (uint64_t)&cpl;
    op.length = sizeof(cpl);
    nvme_dma_write(dev, &op, "completion");

    q->cq_tail++;
    if (q->cq_tail == q->cq_size) {
        q->cq_tail = 0;
        q->cq_phase ^= 1;
    }

    logx(". IRQ: injecting vector=%u on qid=%u", q->vector, q->id);
    // FIXME: this does not work, it's probably an issue in the kernel
    // irq.vector = q->vector;
    irq.vector = 0;
    if (ioctl(dev->fd, PCIEM_IOCTL_INJECT_IRQ, &irq))
        log("x failed IRQ=%d injection", q->vector);
}

static int nvme_read_sq_entry(struct nvme_device *dev, struct nvme_queue *q,
                              struct nvme_command *cmd)
{
    struct pciem_dma_op op = {
        .guest_iova = q->sq_addr + (q->sq_head * sizeof(*cmd)),
        .user_addr = (uint64_t)cmd,
        .length = sizeof(*cmd),
    };

    return nvme_dma_read(dev, &op, "read SQ entry");
}

static void nvme_handle_doorbell_write(struct nvme_device *dev,
                                       struct pciem_event *ev)
{
    uint16_t qidx = (ev->offset - NVME_REG_SQ0TDBL) / 8;
    bool is_cq = ((ev->offset - NVME_REG_SQ0TDBL) % 8) >= 4;
    struct nvme_queue *q;
    struct nvme_command cmd;

    if (is_cq)
        logx("  driver ACK on queue %u", qidx);
    else
        logx("  driver submission on queue %u", qidx);

    q = nvme_get_queue(dev, qidx);
    if (!q)
        return;

    if (is_cq) {
        q->cq_head = ev->data & 0xffff;
        nvme_write_reg(dev, NVME_REG_CQ0HDBL + qidx * 8, ev->data, 4);
        return;
    }

    q->sq_tail = ev->data & 0xffff;

     while (q->sq_head != q->sq_tail) {
        if (!nvme_read_sq_entry(dev, q, &cmd)) {
            q->sq_head = (q->sq_head + 1) % q->sq_size;
            nvme_execute_command(dev, &cmd, q);
        }
    }

    nvme_write_reg(dev, NVME_REG_SQ0TDBL + qidx * 8, ev->data, 4);
}

static void nvme_enable(struct nvme_device *dev)
{
    struct nvme_queue *q = &dev->queues[0];
    uint32_t aqa;

    /* On reset, the configuration is logically purged from device state,
     * but remains valid in memory. The driver expects us to reload these
     * values */
    aqa  = nvme_read_reg(dev, NVME_REG_AQA, 4);
    q->sq_size = (aqa & 0xffff) + 1;
    q->cq_size = ((aqa >> 16) & 0xffff) + 1;
    set_lo32(&q->sq_addr, nvme_read_reg(dev, NVME_REG_ASQ_LO, 4));
    set_hi32(&q->sq_addr, nvme_read_reg(dev, NVME_REG_ASQ_HI, 4));
    set_lo32(&q->cq_addr, nvme_read_reg(dev, NVME_REG_ACQ_LO, 4));
    set_hi32(&q->cq_addr, nvme_read_reg(dev, NVME_REG_ACQ_HI, 4));
    dev->enabled = true;
}

static void nvme_handle_cc_write(struct nvme_device *dev,
                                 struct pciem_event *ev)
{
    union cc {
        uint32_t raw;
        struct nvme_cc reg;
    } cc = { .raw = ev->data };
    union {
        uint32_t raw;
        struct nvme_csts reg;
    } csts = { .raw = dev->csts };

    logx("       CC = 0x%x (en=%d shn=%s)",
         cc.raw, cc.reg.en, shn2str(cc.reg.shn));

    /* Shutdown */
    if (cc.reg.shn != NVME_SHN_NONE) {
        csts.reg.shst = NVME_SHST_PROGRESS;
        csts.reg.rdy = 0;
        dev->csts = csts.raw;
        nvme_write_reg(dev, NVME_REG_CSTS, dev->csts, 4);

        dev->enabled = false;
        nvme_reset_queues(dev);

        csts.reg.shst = NVME_SHST_COMPLETE;
        csts.reg.rdy = 0;
        dev->csts = csts.raw;
        nvme_write_reg(dev, NVME_REG_CSTS, dev->csts, 4);

        dev->running = false;
        logx("  STATUS: device shut down by driver");
        return;
    }

    if (cc.reg.en) {
        nvme_enable(dev);
        csts.reg.rdy = 1;
        csts.reg.shst = NVME_SHST_NORMAL;
        logx("  STATUS: device initialized by driver");
    } else {
        dev->enabled = false;
        csts.raw = 0;
        nvme_reset_queues(dev);
        logx("  STATUS: device disabled by driver");
    }

    dev->csts = csts.raw;
    nvme_write_reg(dev, NVME_REG_CSTS, dev->csts, 4);
}

static void nvme_handle_write(struct nvme_device *dev, struct pciem_event *ev)
{
    if (ev->bar != 0)
        return;

    logx("------");
    logx("< DRV: write @ 0x%lx:%x (%s) = 0x%lx",
          ev->offset, ev->size, reg2str(ev->offset), ev->data);

    struct nvme_queue *q = &dev->queues[0];

    switch (ev->offset) {
        case NVME_REG_CC: {
            nvme_handle_cc_write(dev, ev);
            return;
        }
        case NVME_REG_AQA: {
            if (dev->enabled)
                return;
            q->sq_size = (ev->data & 0xffff) + 1;
            q->cq_size = ((ev->data >> 16) & 0xffff) + 1;
            nvme_write_reg(dev, NVME_REG_AQA, ev->data, 4);
            logx("  admin: sq_size = 0x%x", q->sq_size);
            logx("  admin: cq_size = 0x%x", q->cq_size);
            return;
        }
        case NVME_REG_ASQ_LO: {
            if (dev->enabled)
                return;
            set_lo32(&q->sq_addr, ev->data);
            nvme_write_reg(dev, NVME_REG_ASQ_LO, ev->data, 4);
            logx("  admin: sq_addr = 0x%lx", q->sq_addr);
            return;
        }
        case NVME_REG_ASQ_HI:
            if (dev->enabled)
                return;
            set_hi32(&q->sq_addr, ev->data);
            nvme_write_reg(dev, NVME_REG_ASQ_HI, ev->data, 4);
            logx("  admin: sq_addr = 0x%lx", q->sq_addr);
            return;
        case NVME_REG_ACQ_LO: {
            if (dev->enabled)
                return;
            set_lo32(&q->cq_addr, ev->data);
            nvme_write_reg(dev, NVME_REG_ACQ_LO, ev->data, 4);
            logx("  admin: cq_addr = %lx", q->cq_addr);
            return;
        }
        case NVME_REG_ACQ_HI: {
            if (dev->enabled)
                return;
            set_hi32(&q->cq_addr, ev->data);
            nvme_write_reg(dev, NVME_REG_ACQ_HI, ev->data, 4);
            logx("  admin: cq_addr = %lx", q->cq_addr);
            return;
        }
    }

    if (ev->offset < NVME_REG_SQ0TDBL) {
        logx("- ignoring write @ 0x%lx (unknown register)", ev->offset);
        return;
    }

    if (!dev->enabled) {
        logx("- ignoring write @ 0x%lx (device disabled)", ev->offset);
        return;
    }

    nvme_handle_doorbell_write(dev, ev);
}

static void dev_event_loop(void *arg)
{
    struct nvme_device *dev = arg;
    struct pciem_shared_ring *ring = dev->ring;
    struct pciem_event *ev;
    struct pollfd pollfd;
    int ret, head, tail;

    pollfd.fd = dev->event_fd;
    pollfd.events = POLLIN;

    dev->running = true;

    while (dev->running) {
        int tmp;

        ret = poll(&pollfd, 1, -1);
        if (ret  < 0)
            err(EXIT_FAILURE, "poll");
        if (ret == 0)
            continue;

        read(dev->event_fd, &tmp, sizeof(tmp));

        while (1) {
            head = atomic_load(&ring->head);
            tail = atomic_load(&ring->tail);
            if (head == tail)
                break;

            ev = &ring->events[head];
            ev->data &= size2mask(ev->size);

            if (ev->type & PCIEM_EVENT_MMIO_WRITE)
                nvme_handle_write(dev, ev);

            atomic_store(&ring->head, (head + 1) % PCIEM_RING_SIZE);
        }
    }

    logx("exiting");
}

static void dev_reset(struct nvme_device *dev)
{
    memset(dev, 0, sizeof(*dev));
    dev->fd = -1;
    dev->event_fd = -1;
    dev->instance_fd = -1;
}

static void dev_destroy(struct nvme_device *dev)
{
    if (dev->instance_fd >= 0)
        close(dev->instance_fd);
    if (dev->event_fd)
        close(dev->event_fd >= 0);
    if (dev->ring && dev->ring != MAP_FAILED)
        munmap(dev->ring, sizeof(struct pciem_shared_ring));
    if (dev->bar0 && dev->bar0 != MAP_FAILED)
        munmap(dev->bar0, dev->bar0_size);
    if (dev->fd >= 0)
        close(dev->fd);
    dev_reset(dev);
}

static int dev_register(struct nvme_device *dev)
{
    int ret;
    struct pciem_create_device create = { .flags = 0 };
    struct pciem_config_space cfg = {
        .vendor_id = 0x1234,
        .device_id = 0x5678,
        .subsys_vendor_id = 0x1234,
        .subsys_device_id = 0x0001,
        .revision = 0x01,
        .class_code = {0x02, 0x08, 0x01},
        .header_type = 0x00
    };
    struct pciem_bar_config bars[2] = {
        {
            .bar_index = 0,
            .size = 8192,
            .flags = 0
        },
        {
            .bar_index = 2,
            .size = 8192,
            .flags = 0
        }
    };
    struct pciem_cap_config cap_msix = {
        .cap_type = PCIEM_CAP_MSIX,
        .msix = {
            .bar_index = 2,
            .table_offset = 0,
            .pba_offset = 4096,
            .table_size = 16
        }
    };
    struct pciem_eventfd_config efd_cfg = {0};
    struct pciem_trace_bar trace_cfg = {
        .bar_index = 0,
        .flags = PCIEM_TRACE_WRITES,
    };

    dev_reset(dev);

    dev->ctrl_id = (struct nvme_ctrl_id) {
        .vid = 0x1234,
        .ssvid = 0x5678,
        .sn = "PCIEM-NVME-001     ",
        .mn = "PCIem Virtual NVMe SSD                 ",
        .fr = "1.0    ",
        .nn = 1,
        .sqes = 0x66,
        .cqes = 0x44,
        .ver = NVME_VS(1, 0, 0),
    };

    ret = 1;
    dev->fd = open("/dev/pciem", O_RDWR);
    if (dev->fd < 0)
        goto fail;

    ret = ioctl(dev->fd, PCIEM_IOCTL_CREATE_DEVICE, &create);
    if (ret)
        goto fail;

    ret = ioctl(dev->fd, PCIEM_IOCTL_SET_CONFIG, &cfg);
    if (ret)
        goto fail;

    for (size_t i = 0; i < (sizeof(bars) / sizeof(bars[0])); ++i) {
        ret = ioctl(dev->fd, PCIEM_IOCTL_ADD_BAR, &bars[i]);
        if (ret)
            goto fail;
    }

    ret = ioctl(dev->fd, PCIEM_IOCTL_ADD_CAPABILITY, &cap_msix);
    if (ret)
        goto fail;

    ret = ioctl(dev->fd, PCIEM_IOCTL_TRACE_BAR, &trace_cfg);
    if (ret)
        goto fail;

    dev->event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (dev->event_fd < 0)
        goto fail;

    efd_cfg.eventfd = dev->event_fd;
    ret = ioctl(dev->fd, PCIEM_IOCTL_SET_EVENTFD, &efd_cfg);
    if (ret)
        goto fail;

    logx("Eventfd configured successfully");

    ret = 1;
    dev->instance_fd = ioctl(dev->fd, PCIEM_IOCTL_REGISTER);
    if (dev->instance_fd < 0)
        goto fail;

    logx("Device registered successfully");
    return 0;

fail:
    warn("Failed to initialize device");
    dev_destroy(dev);
    return ret;
}

static void dev_prepare_ro_regs(struct nvme_device *dev)
{
    union {
        struct nvme_cap cap;
        uint64_t raw;
    } c = {
        .cap = {
            .mqes = 64 - 1,
            .to = 10,
            .dstrd = 1,
            .nssrs = 0,
            .css = 1,
            .mpsmin = 0,
            .mpsmax = 0,
        }
    };

    nvme_write_reg(dev, NVME_REG_VS, NVME_VS(1, 0, 0), 4);
    nvme_write_reg(dev, NVME_REG_CAP, c.raw, 8);
}

static int dev_alloc_resources(struct nvme_device *dev)
{
    int ret = 1;

    dev->bar0_size = 8192;
    dev->bar0 = mmap(NULL, dev->bar0_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                     dev->instance_fd, 0);
    if (dev->bar0 == MAP_FAILED)
        goto fail;

    dev_prepare_ro_regs(dev);

    dev->ring = mmap(NULL, sizeof(struct pciem_shared_ring),
                     PROT_READ | PROT_WRITE, MAP_SHARED, dev->fd, 0);
    if (dev->ring == MAP_FAILED)
        goto fail;
    logx("Shared ring buffer mapped at %p", dev->ring);

    dev->disk_data = calloc(1, NVME_DISK_SIZE);
    if (!dev->disk_data)
        goto fail;

    logx("Device resources allocated successfully");
    return 0;

fail:
    warn("Failed to allocate device resources");
    dev_destroy(dev);
    return ret;
}

int main(void)
{
    struct nvme_device dev = {0};

    if (dev_register(&dev))
        err(EXIT_FAILURE,  "dev_register");

    if (dev_alloc_resources(&dev))
        err(EXIT_FAILURE, "dev_alloc_resources");

    dev.disk_data = calloc(1, NVME_DISK_SIZE);
    if (!dev.disk_data) {
        log("x failed to allocate disk storage (0x%lx bytes)", NVME_DISK_SIZE);
        dev_destroy(&dev);
        exit(EXIT_FAILURE);
    }

    dev_event_loop(&dev);
    dev_destroy(&dev);

    return 0;
}
