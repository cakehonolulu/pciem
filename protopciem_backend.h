#ifndef HW_MISC_PROTOPCIEM_BACKEND_H
#define HW_MISC_PROTOPCIEM_BACKEND_H

#include "chardev/char-fe.h"
#include "hw/sysbus.h"
#include "protopciem_cmds.h"
#include "qemu/bitops.h"
#include "qom/object.h"
#include "ui/console.h"

#include "protopciem_device.h"

#define TYPE_PROTOPCIEM_BACKEND "protopciem-backend"
OBJECT_DECLARE_SIMPLE_TYPE(ProtoPCIemState, PROTOPCIEM_BACKEND)

enum
{
    MSG_MMIO_READ = 1,
    MSG_MMIO_WRITE = 2,
    MSG_MMIO_READ_REPLY = 3,
    MSG_DMA_READ = 4,
    MSG_DMA_WRITE = 5,
    MSG_IRQ_RAISE = 6,
    MSG_IRQ_LOWER = 7,
    MSG_RESET = 8,
    MSG_DMA_WRITE_CHUNK = 9,
    MSG_CMD_DONE = 10,
};

enum ProtoPciemRecvState
{
    RECV_STATE_HEADER,
    RECV_STATE_PAYLOAD
};

typedef struct ProtoPciemMessage
{
    uint8_t type;
    uint8_t size;
    uint16_t reserved;
    uint64_t addr;
    uint64_t data;
} __attribute__((packed)) ProtoPciemMessage;

#define FB_WIDTH 640
#define FB_HEIGHT 480
#define FB_SIZE (FB_WIDTH * FB_HEIGHT * 3)

#define CMD_BUFFER_SIZE (64 * 1024)

typedef struct ProtoPCIemState
{
    SysBusDevice parent_obj;

    MemoryRegion iomem;
    CharFrontend chr;
    QEMUTimer *poll_timer;

    uint8_t recv_buf[sizeof(ProtoPciemMessage)];
    size_t recv_pos;

    QemuConsole *con;
    uint8_t *framebuffer;

    uint32_t control;
    uint32_t status;
    uint32_t cmd;
    uint32_t data;
    uint32_t result_lo;
    uint32_t result_hi;
    uint32_t dma_src_lo;
    uint32_t dma_src_hi;
    uint32_t dma_dst_lo;
    uint32_t dma_dst_hi;
    uint32_t dma_len;

    enum ProtoPciemRecvState recv_state;
    size_t expected_payload_len;
    uint64_t payload_dst_addr;

    uint8_t *cmd_buffer;
    size_t cmd_buffer_size;

    qemu_irq irq;

    QEMUTimer *process_timer;

} ProtoPCIemState;

#endif