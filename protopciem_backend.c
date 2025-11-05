#include "hw/misc/protopciem_backend.h"
#include "hw/irq.h"
#include "hw/qdev-properties-system.h"
#include "hw/qdev-properties.h"
#include "hw/sysbus.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "ui/console.h"
#include "ui/pixel_ops.h"

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
    printf("[QEMU ProtoPCIem] Parsing command buffer (len=%u)\n", s->dma_len);
    uint8_t *p = s->cmd_buffer;
    uint8_t *end = p + s->dma_len;
    int count = 0;
    while (p < end && (p + sizeof(struct cmd_header)) <= end)
    {
        struct cmd_header *hdr = (struct cmd_header *)p;
        if (hdr->length == 0 || (p + hdr->length) > end)
        {
            printf("[QEMU ProtoPCIem] Corrupt command buffer! opcode=0x%x len=%u p=%p end=%p\n", hdr->opcode,
                   hdr->length, p, end);
            s->status |= STATUS_ERROR;
            break;
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
            printf("[QEMU ProtoPCIem] Unknown opcode 0x%x\n", hdr->opcode);
            s->status |= STATUS_ERROR;
            break;
        }
        p += hdr->length;
        count++;
    }
    backend_update_display(s);
    dpy_gfx_update_full(s->con);
    printf("[QEMU ProtoPCIem] Processed %d commands\n", count);
}

static void backend_send_message(ProtoPCIemState *s, ProtoPciemMessage *msg)
{
    if (qemu_chr_fe_backend_connected(&s->chr))
    {
        qemu_chr_fe_write_all(&s->chr, (uint8_t *)msg, sizeof(*msg));
    }
}

static void backend_process_complete(void *opaque)
{
    ProtoPCIemState *s = opaque;
    uint64_t result = 0;

    switch (s->cmd)
    {
    case CMD_ADD:
        printf("[QEMU ProtoPCIem] CMD_ADD: %u + 42\n", s->data);
        result = s->data + 42;
        break;
    case CMD_MULTIPLY:
        printf("[QEMU ProtoPCIem] CMD_MULTIPLY: %u * 3\n", s->data);
        result = s->data * 3;
        break;
    case CMD_XOR:
        printf("[QEMU ProtoPCIem] CMD_XOR: %u ^ 0xABCD1234\n", s->data);
        result = s->data ^ 0xABCD1234;
        break;

    case CMD_DMA_FRAME:
    case CMD_EXECUTE_CMDBUF: {
        uint64_t src_addr = ((uint64_t)s->dma_src_hi << 32) | s->dma_src_lo;
        uint64_t dst_addr = ((uint64_t)s->dma_dst_hi << 32) | s->dma_dst_lo;
        uint32_t len = s->dma_len;

        printf("[QEMU ProtoPCIem] %s: src=0x%lx dst=0x%lx len=%u\n",
               (s->cmd == CMD_DMA_FRAME) ? "CMD_DMA_FRAME" : "CMD_EXECUTE_CMDBUF", src_addr, dst_addr, len);

        size_t target_size;
        if (s->cmd == CMD_EXECUTE_CMDBUF)
        {
            target_size = s->cmd_buffer_size;
        }
        else
        {
            target_size = FB_SIZE;
        }

        if (len == 0 || (dst_addr + len) > target_size)
        {
            printf("[QEMU ProtoPCIem] Invalid DMA: dst=0x%lx len=%u (target_size=%zu)\n", dst_addr, len, target_size);
            s->status |= STATUS_ERROR | STATUS_DONE;
            s->status &= ~STATUS_BUSY;
            ProtoPciemMessage done = {.type = MSG_CMD_DONE};
            backend_send_message(s, &done);
            return;
        }

        ProtoPciemMessage dma_req = {.type = MSG_DMA_READ,
                                     .addr = src_addr,
                                     .data = dst_addr,
                                     .size = (uint8_t)(len & 0xFF),
                                     .reserved = (uint16_t)((len >> 8) & 0xFFFF)};
        backend_send_message(s, &dma_req);
        return;
    }

    default:
        printf("[QEMU ProtoPCIem] Unknown command 0x%x\n", s->cmd);
        s->status |= STATUS_ERROR;
        break;
    }

    if (s->cmd != CMD_EXECUTE_CMDBUF && s->cmd != CMD_DMA_FRAME)
    {
        s->result_lo = result & 0xFFFFFFFF;
        s->result_hi = result >> 32;
        s->status |= STATUS_DONE;
        s->status &= ~STATUS_BUSY;
        ProtoPciemMessage done_msg = {.type = MSG_CMD_DONE};
        backend_send_message(s, &done_msg);
        printf("[QEMU ProtoPCIem] Command complete, sent MSG_CMD_DONE\n");
    }
}

static void backend_handle_message(ProtoPCIemState *s, ProtoPciemMessage *msg)
{
    switch (msg->type)
    {
    case MSG_MMIO_READ: {
        uint64_t val = 0;
        switch (msg->addr)
        {
        case REG_CONTROL:
            val = s->control;
            break;
        case REG_STATUS:
            val = s->status;
            break;
        case REG_CMD:
            val = s->cmd;
            break;
        case REG_DATA:
            val = s->data;
            break;
        case REG_RESULT_LO:
            val = s->result_lo;
            break;
        case REG_RESULT_HI:
            val = s->result_hi;
            break;
        case REG_DMA_SRC_LO:
            val = s->dma_src_lo;
            break;
        case REG_DMA_SRC_HI:
            val = s->dma_src_hi;
            break;
        case REG_DMA_DST_LO:
            val = s->dma_dst_lo;
            break;
        case REG_DMA_DST_HI:
            val = s->dma_dst_hi;
            break;
        case REG_DMA_LEN:
            val = s->dma_len;
            break;
        default:
            val = 0;
            break;
        }
        ProtoPciemMessage reply = {.type = MSG_MMIO_READ_REPLY, .size = msg->size, .addr = msg->addr, .data = val};
        backend_send_message(s, &reply);
        break;
    }

    case MSG_MMIO_WRITE:
        switch (msg->addr)
        {
        case REG_CONTROL:
            s->control = msg->data;
            if (msg->data & CTRL_RESET)
            {
                s->status = 0;
                s->cmd = 0;
                s->data = 0;
                gpu_clear(s, 0, 0, 0);
                backend_update_display(s);
            }
            break;
        case REG_STATUS:
            s->status = msg->data;
            break;
        case REG_CMD:
            s->cmd = msg->data;
            if (s->cmd == CMD_DMA_FRAME || s->cmd == CMD_EXECUTE_CMDBUF)
            {
                backend_process_complete(s);
            }
            else
            {
                timer_mod(s->process_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 5000000);
            }
            break;
        case REG_DATA:
            s->data = msg->data;
            break;
        case REG_RESULT_LO:
            s->result_lo = msg->data;
            break;
        case REG_RESULT_HI:
            s->result_hi = msg->data;
            break;
        case REG_DMA_SRC_LO:
            s->dma_src_lo = msg->data;
            break;
        case REG_DMA_SRC_HI:
            s->dma_src_hi = msg->data;
            break;
        case REG_DMA_DST_LO:
            s->dma_dst_lo = msg->data;
            break;
        case REG_DMA_DST_HI:
            s->dma_dst_hi = msg->data;
            break;
        case REG_DMA_LEN:
            s->dma_len = msg->data;
            break;
        default:
            break;
        }
        break;

    case MSG_DMA_WRITE: {
        if (msg->size == 0)
        {
            printf("[QEMU ProtoPCIem] DMA transfer complete\n");

            if (s->cmd == CMD_EXECUTE_CMDBUF)
            {
                backend_execute_command_buffer(s);
            }
            else if (s->cmd == CMD_DMA_FRAME)
            {
                backend_update_display(s);
                dpy_gfx_update_full(s->con);
            }

            s->status |= STATUS_DONE;
            s->status &= ~STATUS_BUSY;
            ProtoPciemMessage done_msg = {.type = MSG_CMD_DONE};
            backend_send_message(s, &done_msg);
        }
        break;
    }

    case MSG_RESET:
        s->control = 0;
        s->status = 0;
        s->cmd = 0;
        s->data = 0;
        gpu_clear(s, 0, 0, 0);
        backend_update_display(s);
        break;

    default:
        break;
    }
}

static int backend_chr_can_receive(void *opaque)
{
    ProtoPCIemState *s = opaque;
    if (s->recv_state == RECV_STATE_PAYLOAD)
    {
        return s->expected_payload_len - s->recv_pos;
    }
    return sizeof(ProtoPciemMessage) * 16;
}

static void backend_chr_receive(void *opaque, const uint8_t *buf, int size)
{
    ProtoPCIemState *s = opaque;
    int consumed = 0;

    while (consumed < size)
    {
        if (s->recv_state == RECV_STATE_HEADER)
        {
            int remaining = sizeof(ProtoPciemMessage) - s->recv_pos;
            int to_copy = (size - consumed < remaining) ? (size - consumed) : remaining;
            memcpy(s->recv_buf + s->recv_pos, buf + consumed, to_copy);
            s->recv_pos += to_copy;
            consumed += to_copy;

            if (s->recv_pos == sizeof(ProtoPciemMessage))
            {
                ProtoPciemMessage *msg = (ProtoPciemMessage *)s->recv_buf;
                s->recv_pos = 0;
                if (msg->type == MSG_DMA_WRITE_CHUNK)
                {
                    s->expected_payload_len = ((uint32_t)msg->reserved << 8) | msg->size;
                    s->payload_dst_addr = msg->addr;

                    size_t target_size;
                    if (s->cmd == CMD_EXECUTE_CMDBUF)
                    {
                        target_size = s->cmd_buffer_size;
                    }
                    else
                    {
                        target_size = FB_SIZE;
                    }

                    if (s->expected_payload_len == 0 || s->payload_dst_addr + s->expected_payload_len > target_size)
                    {
                        printf("[QEMU ProtoPCIem] Invalid chunk: dst=0x%lx len=%zu (target_size=%zu)\n",
                               s->payload_dst_addr, s->expected_payload_len, target_size);
                        s->recv_state = RECV_STATE_HEADER;
                        s->status |= STATUS_ERROR;
                    }
                    else
                    {
                        s->recv_state = RECV_STATE_PAYLOAD;
                    }
                }
                else
                {
                    backend_handle_message(s, msg);
                    s->recv_state = RECV_STATE_HEADER;
                }
            }
        }
        else
        {
            int remaining = s->expected_payload_len - s->recv_pos;
            int to_copy = (size - consumed < remaining) ? (size - consumed) : remaining;

            if (s->cmd == CMD_EXECUTE_CMDBUF)
            {
                memcpy(s->cmd_buffer + s->payload_dst_addr + s->recv_pos, buf + consumed, to_copy);
            }
            else
            {
                memcpy(s->framebuffer + s->payload_dst_addr + s->recv_pos, buf + consumed, to_copy);
            }
            s->recv_pos += to_copy;
            consumed += to_copy;

            if (s->recv_pos == s->expected_payload_len)
            {
                s->recv_state = RECV_STATE_HEADER;
                s->recv_pos = 0;
            }
        }
    }
}

static uint64_t backend_read(void *opaque, hwaddr offset, unsigned size)
{
    qemu_log("[QEMU ProtoPCIem]: sysbus_read offset 0x%lx, size %u\n", offset, size);
    return 0;
}
static void backend_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    qemu_log("[QEMU ProtoPCIem]: sysbus_write offset 0x%lx, size %u, value 0x%lx\n", offset, size, value);
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

static void backend_poll_timer(void *opaque)
{
    ProtoPCIemState *s = opaque;
    if (qemu_chr_fe_backend_connected(&s->chr))
    {
        qemu_chr_fe_accept_input(&s->chr);
    }
    timer_mod(s->poll_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 1);
}

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

    memory_region_init_io(&s->iomem, OBJECT(s), &backend_ops, s, "protopciem-backend", 0x1000);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);

    s->process_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, backend_process_complete, s);

    qemu_chr_fe_set_handlers(&s->chr, backend_chr_can_receive, backend_chr_receive, NULL, NULL, s, NULL, true);

    s->poll_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, backend_poll_timer, s);
    timer_mod(s->poll_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 1);

    s->recv_state = RECV_STATE_HEADER;
    s->recv_pos = 0;
    s->expected_payload_len = 0;
    s->payload_dst_addr = 0;

    s->framebuffer = g_malloc0(FB_SIZE);

    s->cmd_buffer_size = CMD_BUFFER_SIZE;
    s->cmd_buffer = g_malloc0(s->cmd_buffer_size);

    s->con = graphic_console_init(dev, 0, &backend_gfx_ops, s);
    qemu_console_resize(s->con, FB_WIDTH, FB_HEIGHT);
}

static const Property protopciem_backend_properties[] = {
    DEFINE_PROP_CHR("chardev", ProtoPCIemState, chr),
};

static void protopciem_backend_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = protopciem_backend_realize;
    dc->desc = "ProtoPCIem Accelerator Backend";
    device_class_set_props(dc, protopciem_backend_properties);
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