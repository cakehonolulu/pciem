#ifndef HW_MISC_PROTOPCIEM_BACKEND_H
#define HW_MISC_PROTOPCIEM_BACKEND_H

#include "hw/sysbus.h"
#include "protopciem_cmds.h"
#include "qemu/bitops.h"
#include "qom/object.h"
#include "ui/console.h"
#include <sys/ioctl.h>

#include "pciem_ioctl.h"
#include "protopciem_device.h"

#define TYPE_PROTOPCIEM_BACKEND "protopciem-backend"
OBJECT_DECLARE_SIMPLE_TYPE(ProtoPCIemState, PROTOPCIEM_BACKEND)

#define FB_WIDTH 640
#define FB_HEIGHT 480
#define FB_SIZE (FB_WIDTH * FB_HEIGHT * 3)

#define CMD_BUFFER_SIZE (4 * 1024 * 1024)

typedef struct ProtoPCIemState
{
    SysBusDevice parent_obj;

    MemoryRegion iomem;

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

    uint8_t *cmd_buffer;
    size_t cmd_buffer_size;

    qemu_irq irq;

    int shim_fd;
    int socket_fd;
} ProtoPCIemState;

#endif