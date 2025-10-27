#ifndef HW_MISC_PROTOPCIEM_BACKEND_H
#define HW_MISC_PROTOPCIEM_BACKEND_H

#include "chardev/char-fe.h"
#include "hw/sysbus.h"
#include "protopciem_cmds.h"
#include "qemu/bitops.h"
#include "qom/object.h"
#include "ui/console.h"

#define TYPE_PROTOPCIEM_BACKEND "protopciem-backend"
OBJECT_DECLARE_SIMPLE_TYPE(ProtoPCIemState, PROTOPCIEM_BACKEND)

#define REG_CONTROL 0x00
#define REG_STATUS 0x04
#define REG_CMD 0x08
#define REG_DATA 0x0C
#define REG_RESULT_LO 0x10
#define REG_RESULT_HI 0x14
#define REG_DMA_SRC_LO 0x20
#define REG_DMA_SRC_HI 0x24
#define REG_DMA_DST_LO 0x28
#define REG_DMA_DST_HI 0x2C
#define REG_DMA_LEN 0x30

#define STATUS_BUSY BIT(0)
#define STATUS_DONE BIT(1)
#define STATUS_ERROR BIT(2)

#define CMD_ADD 0x01
#define CMD_MULTIPLY 0x02
#define CMD_XOR 0x03
#define CMD_PROCESS_BUFFER 0x04
#define CMD_EXECUTE_CMDBUF 0x05
#define CMD_DMA_FRAME 0x06

#define CTRL_RESET BIT(1)

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
} QEMU_PACKED ProtoPciemMessage;

#define FB_WIDTH 640
#define FB_HEIGHT 480
#define FB_SIZE (FB_WIDTH * FB_HEIGHT * 3)

#define CMD_BUFFER_SIZE (64 * 1024)

typedef struct ProtoPCIemState
{
    SysBusDevice parent_obj;

    MemoryRegion iomem;
    CharBackend chr;
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