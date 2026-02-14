#include "qemu/osdep.h"
#include "hw/misc/protopciem_backend.h"
#include "hw/irq.h"
#include "hw/qdev-properties-system.h"
#include "hw/qdev-properties.h"
#include "hw/sysbus.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "ui/console.h"
#include "ui/pixel_ops.h"
#include <sys/socket.h>
#include <sys/un.h>

#define QEMU_SOCKET_PATH "/tmp/pciem_qemu.sock"

#define FATAL_ERROR(...)                                                       \
    do {                                                                       \
        printf("ProtoPCIem FATAL: " __VA_ARGS__);                             \
        printf("\n");                                                          \
        exit(1);                                                               \
    } while (0)

#define MSG_REGISTER_WRITE 1
#define MSG_REGISTER_READ  2
#define MSG_RAISE_IRQ      3
#define MSG_DMA_READ       4
#define MSG_DMA_WRITE      5

struct qemu_msg {
    uint32_t type;
    uint32_t offset;
    uint64_t value;
    uint64_t addr;
    uint32_t len;
} __attribute__((packed));

struct qemu_resp {
    uint32_t status;
    uint64_t value;
} __attribute__((packed));

static void gpu_draw_pixel(ProtoPCIemState *s, int x, int y, uint8_t r, uint8_t g, uint8_t b)
{
    if (x < 0 || x >= FB_WIDTH || y < 0 || y >= FB_HEIGHT)
    {
        return;
    }
    int idx = (y * FB_WIDTH + x) * 3;
    s->framebuffer[idx + 0] = r;
    s->framebuffer[idx + 1] = g;
    s->framebuffer[idx + 2] = b;
}

static void gpu_draw_line(ProtoPCIemState *s, int x0, int y0, int x1, int y1, uint8_t r, uint8_t g, uint8_t b)
{
    int dx = abs(x1 - x0), sx = x0 < x1 ? 1 : -1;
    int dy = -abs(y1 - y0), sy = y0 < y1 ? 1 : -1;
    int err = dx + dy, e2;
    for (;;)
    {
        gpu_draw_pixel(s, x0, y0, r, g, b);
        if (x0 == x1 && y0 == y1)
            break;
        e2 = 2 * err;
        if (e2 >= dy)
        {
            err += dy;
            x0 += sx;
        }
        if (e2 <= dx)
        {
            err += dx;
            y0 += sy;
        }
    }
}

static void gpu_clear(ProtoPCIemState *s, uint8_t r, uint8_t g, uint8_t b)
{
    if (r == g && g == b)
    {
        memset(s->framebuffer, r, FB_SIZE);
    }
    else
    {
        for (int i = 0; i < FB_WIDTH * FB_HEIGHT; i++)
        {
            s->framebuffer[i * 3 + 0] = r;
            s->framebuffer[i * 3 + 1] = g;
            s->framebuffer[i * 3 + 2] = b;
        }
    }
}

static void gpu_blit_rect(ProtoPCIemState *s, uint16_t x, uint16_t y, uint16_t width, uint16_t height,
                          const uint8_t *data)
{
    for (int j = 0; j < height; j++)
    {
        for (int i = 0; i < width; i++)
        {
            int src_idx = (j * width + i) * 3;
            gpu_draw_pixel(s, x + i, y + j, data[src_idx + 0], data[src_idx + 1], data[src_idx + 2]);
        }
    }
}

static void backend_update_display(void *opaque)
{
    ProtoPCIemState *s = opaque;
    DisplaySurface *surface = qemu_console_surface(s->con);
    if (!surface)
        return;

    uint8_t *d = surface_data(surface);
    int stride = surface_stride(surface);
    uint8_t *src = s->framebuffer;

    for (int y = 0; y < FB_HEIGHT; y++)
    {
        uint32_t *dst_row = (uint32_t *)(d + y * stride);
        uint8_t *src_row = src + y * FB_WIDTH * 3;
        for (int x = 0; x < FB_WIDTH; x++)
        {
            uint8_t r = src_row[x * 3 + 0];
            uint8_t g = src_row[x * 3 + 1];
            uint8_t b = src_row[x * 3 + 2];
            dst_row[x] = rgb_to_pixel32(r, g, b);
        }
    }
    dpy_gfx_update(s->con, 0, 0, FB_WIDTH, FB_HEIGHT);
}

static void backend_execute_command_buffer(ProtoPCIemState *s)
{
    uint8_t *p = s->cmd_buffer;
    uint8_t *end = p + s->dma_len;

    while (p < end && (p + sizeof(struct cmd_header)) <= end)
    {
        if ((uintptr_t)p % _Alignof(struct cmd_header) != 0)
        {
            FATAL_ERROR("Misaligned command");
        }

        struct cmd_header *hdr = (struct cmd_header *)p;

        if (hdr->length == 0 || (p + hdr->length) > end)
        {
            FATAL_ERROR("Corrupt command buffer");
        }

        switch (hdr->opcode)
        {
        case CMD_OP_NOP:
            break;
        case CMD_OP_CLEAR: {
            struct cmd_clear *cmd = (struct cmd_clear *)p;
            gpu_clear(s, cmd->r, cmd->g, cmd->b);
            break;
        }
        case CMD_OP_DRAW_LINE: {
            struct cmd_draw_line *cmd = (struct cmd_draw_line *)p;
            gpu_draw_line(s, cmd->x0, cmd->y0, cmd->x1, cmd->y1, cmd->r, cmd->g, cmd->b);
            break;
        }
        case CMD_OP_BLIT_RECT: {
            struct cmd_blit_rect *cmd = (struct cmd_blit_rect *)p;
            const uint8_t *data = (const uint8_t *)(cmd + 1);
            gpu_blit_rect(s, cmd->x, cmd->y, cmd->width, cmd->height, data);
            break;
        }
        default:
            printf("Unknown opcode 0x%x\n", hdr->opcode);
            exit(1);
            break;
        }

        p += hdr->length;
    }
}

static int dma_read_from_guest(ProtoPCIemState *s, uint64_t guest_addr,
                                void *dst, uint32_t len)
{
    struct qemu_msg msg;
    struct qemu_resp resp;

    msg.type = MSG_DMA_READ;
    msg.addr = guest_addr;
    msg.len = len;

    if (write(s->socket_fd, &msg, sizeof(msg)) != sizeof(msg)) {
        perror("[QEMU] Failed to send DMA read request");
        return -1;
    }

    if (read(s->socket_fd, &resp, sizeof(resp)) != sizeof(resp)) {
        perror("[QEMU] Failed to receive DMA response");
        return -1;
    }

    if (resp.status != 0) {
        fprintf(stderr, "[QEMU] DMA read failed with status %d\n", resp.status);
        return -1;
    }

    ssize_t total = 0;
    while (total < len) {
        ssize_t n = read(s->socket_fd, (uint8_t *)dst + total, len - total);
        if (n <= 0) {
            perror("[QEMU] Failed to read DMA data");
            return -1;
        }
        total += n;
    }

    return 0;
}

static void backend_process_complete(void *opaque)
{
    ProtoPCIemState *s = opaque;

    switch (s->cmd)
    {
    case CMD_DMA_FRAME:
    case CMD_EXECUTE_CMDBUF: {
        uint64_t src_addr = ((uint64_t)s->dma_src_hi << 32) | s->dma_src_lo;
        uint32_t len = s->dma_len;

        if (s->cmd == CMD_EXECUTE_CMDBUF)
        {
            if (len > s->cmd_buffer_size)
                len = s->cmd_buffer_size;

            if (dma_read_from_guest(s, src_addr, s->cmd_buffer, len) == 0)
            {
                backend_execute_command_buffer(s);
            }
        }
        else if (s->cmd == CMD_DMA_FRAME)
        {
            if (len != FB_SIZE)
            {
                FATAL_ERROR("DMA Frame size mismatch");
            }

            if (dma_read_from_guest(s, src_addr, s->framebuffer, len) == 0)
            {
                backend_update_display(s);
            }
        }

        s->status |= STATUS_DONE;
        s->status &= ~STATUS_BUSY;

        struct qemu_msg msg;
        msg.type = MSG_RAISE_IRQ;
        msg.offset = s->status;
        uint64_t result = ((uint64_t)s->result_hi << 32) | s->result_lo;
        msg.value = result;

        if (write(s->socket_fd, &msg, sizeof(msg)) != sizeof(msg))
        {
            perror("[QEMU] Failed to send IRQ notification");
        }
        return;
    }
    default:
        FATAL_ERROR("Unknown command");
    }
}

static void backend_handle_socket_event(void *opaque)
{
    ProtoPCIemState *s = PROTOPCIEM_BACKEND(opaque);
    struct qemu_msg msg;
    struct qemu_resp resp;

    ssize_t n = read(s->socket_fd, &msg, sizeof(msg));
    if (n != sizeof(msg))
    {
        if (n <= 0)
        {
            printf("[QEMU] Connection closed\n");
            qemu_set_fd_handler(s->socket_fd, NULL, NULL, NULL);
            close(s->socket_fd);
            s->socket_fd = -1;
        }
        return;
    }

    resp.status = 0;
    resp.value = 0;

    switch (msg.type) {
    case MSG_REGISTER_READ: {
        switch (msg.offset) {
        case REG_CONTROL:  resp.value = s->control; break;
        case REG_STATUS:   resp.value = s->status; break;
        case REG_CMD:      resp.value = s->cmd; break;
        case REG_DATA:     resp.value = s->data; break;
        case REG_RESULT_LO: resp.value = s->result_lo; break;
        case REG_RESULT_HI: resp.value = s->result_hi; break;
        case REG_DMA_SRC_LO: resp.value = s->dma_src_lo; break;
        case REG_DMA_SRC_HI: resp.value = s->dma_src_hi; break;
        case REG_DMA_DST_LO: resp.value = s->dma_dst_lo; break;
        case REG_DMA_DST_HI: resp.value = s->dma_dst_hi; break;
        case REG_DMA_LEN:  resp.value = s->dma_len; break;
        default: resp.status = -1; break;
        }
        if (write(s->socket_fd, &resp, sizeof(resp)) != sizeof(resp)) {
            perror("[QEMU] Failed to send register read response");
            return;
        }

        break;
    }

    case MSG_REGISTER_WRITE: {
        switch (msg.offset) {
        case REG_CONTROL:
            s->control = msg.value;
            if (msg.value & 2) {
                s->status = 0;
                s->cmd = 0;
                s->data = 0;
                gpu_clear(s, 0, 0, 0);
                backend_update_display(s);
            }
            break;
        case REG_STATUS:   s->status = msg.value; break;
        case REG_DATA:     s->data = msg.value; break;
        case REG_RESULT_LO: s->result_lo = msg.value; break;
        case REG_RESULT_HI: s->result_hi = msg.value; break;
        case REG_DMA_SRC_LO: s->dma_src_lo = msg.value; break;
        case REG_DMA_SRC_HI: s->dma_src_hi = msg.value; break;
        case REG_DMA_DST_LO: s->dma_dst_lo = msg.value; break;
        case REG_DMA_DST_HI: s->dma_dst_hi = msg.value; break;
        case REG_DMA_LEN:  s->dma_len = msg.value; break;
        case REG_CMD:
            s->cmd = msg.value;
            s->status &= ~STATUS_DONE;
            s->status |= STATUS_BUSY;
            backend_process_complete(s);
            break;
        default:
            resp.status = -1;
            break;
        }
        if (write(s->socket_fd, &resp, sizeof(resp)) != sizeof(resp)) {
            perror("[QEMU] Failed to send register write response");
            return;
        }
        break;
    }

    default:
        printf("[QEMU] Unknown message type: %d\n", msg.type);
        resp.status = -1;
        if (write(s->socket_fd, &resp, sizeof(resp)) != sizeof(resp)) {
            perror("[QEMU] Failed to send error response");
            return;
        }
        break;
    }
}

static uint64_t backend_read(void *opaque, hwaddr offset, unsigned size)
{
    return 0;
}
static void backend_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
}
static const MemoryRegionOps backend_ops = {
    .read = backend_read,
    .write = backend_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid =
        {
            .min_access_size = 4,
            .max_access_size = 8,
        },
};

static void backend_invalidate_display(void *opaque)
{
    backend_update_display(opaque);
}
static const GraphicHwOps backend_gfx_ops = {
    .invalidate = backend_invalidate_display,
    .gfx_update = backend_update_display,
};

static void protopciem_backend_realize(DeviceState *dev, Error **errp)
{
    ProtoPCIemState *s = PROTOPCIEM_BACKEND(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    struct sockaddr_un addr;

    memory_region_init_io(&s->iomem, OBJECT(s), &backend_ops, s,
                         "protopciem-backend", 0x1000);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);

    printf("[QEMU] Connecting to userspace emulator at %s\n", QEMU_SOCKET_PATH);

    s->socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s->socket_fd < 0) {
        perror("[QEMU] Failed to create socket");
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, QEMU_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    int retries = 5;
    while (retries-- > 0) {
        if (connect(s->socket_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            printf("[QEMU] Connected to userspace emulator!\n");
            break;
        }
        printf("[QEMU] Connection failed, retrying... (%d left)\n", retries);
        sleep(1);
    }

    if (retries < 0) {
        perror("[QEMU] Failed to connect to userspace emulator");
        close(s->socket_fd);
        return;
    }

    qemu_set_fd_handler(s->socket_fd, backend_handle_socket_event, NULL, s);

    s->cmd_buffer_size = CMD_BUFFER_SIZE;
    s->cmd_buffer = g_malloc0(s->cmd_buffer_size);
    s->framebuffer = g_malloc0(FB_SIZE);

    s->con = graphic_console_init(dev, 0, &backend_gfx_ops, s);
    qemu_console_resize(s->con, FB_WIDTH, FB_HEIGHT);

    printf("[QEMU] Backend initialized\n");
}

static void protopciem_backend_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = protopciem_backend_realize;
    dc->desc = "ProtoPCIem Accelerator Backend";
}

static const TypeInfo protopciem_backend_info = {
    .name = TYPE_PROTOPCIEM_BACKEND,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(ProtoPCIemState),
    .class_init = protopciem_backend_class_init,
};

static void protopciem_backend_register_types(void)
{
    type_register_static(&protopciem_backend_info);
}

type_init(protopciem_backend_register_types)