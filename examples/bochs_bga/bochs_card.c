/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Copyright (C) 2026  Joel Bueno  <buenocalvachejoel@gmail.com>
 *
 * Bochs BGA emulated via PCIem
 *
 * Pre-requisites:
 *
 * Install the udev rule found on this directory when trying bochs_card,
 * else you'll most surely loose the host's compositor/wm and world will burn.
 *
 * What to render:
 *
 * There's a myriad of things you can run here, from kmscube to weston for instance.
 * Be sure to correctly point to the appropiate /dev/dri/card#
 * Eg:
 * weston --backend=drm --drm-device=card# --no-config
 * kmscube -D /dev/dri/card#
 *
 * You can attain the card number by issuing an "$ ls /dev/dri/"" before loading the
 * bochs card and one afterwards (And basically check which one was added).
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <SDL3/SDL.h>

#include "pciem_api.h"

#define BOCHS_VGA_VENDOR 0x1234u
#define BOCHS_VGA_DEVICE 0x1111u

#define BOCHS_CLASS_PROG 0x00u
#define BOCHS_CLASS_SUB 0x80u
#define BOCHS_CLASS_BASE 0x03u

#define VBE_IDX_ID 0u
#define VBE_IDX_XRES 1u
#define VBE_IDX_YRES 2u
#define VBE_IDX_BPP 3u
#define VBE_IDX_ENABLE 4u
#define VBE_IDX_BANK 5u
#define VBE_IDX_VIRT_WIDTH 6u
#define VBE_IDX_VIRT_HEIGHT 7u
#define VBE_IDX_X_OFFSET 8u
#define VBE_IDX_Y_OFFSET 9u
#define VBE_IDX_VIDEO_MEMORY_64K 10u
#define VBE_IDX_COUNT 11u

#define VBE_DISPI_ID5 0xB0C5u

#define VBE_DISPI_DISABLED 0x00u
#define VBE_DISPI_ENABLED 0x01u
#define VBE_DISPI_GETCAPS 0x02u
#define VBE_DISPI_LFB_ENABLED 0x40u
#define VBE_DISPI_NOCLEARMEM 0x80u

#define BGA_MMIO_VBE_OFFSET 0x500u

#define BAR0_FB_SIZE (16u * 1024u * 1024u)
#define BAR2_MMIO_SIZE (64u * 1024u)

#define BGA_MAX_WIDTH 4096u
#define BGA_MAX_HEIGHT 2160u
#define BGA_MAX_BPP 32u

#define BGA_INIT_WIDTH 1024u
#define BGA_INIT_HEIGHT 768u

#define TARGET_FPS 60u
#define FRAME_MS (1000u / TARGET_FPS)

struct bga_state
{
    uint16_t regs[VBE_IDX_COUNT];
    bool display_on;
    bool lfb_mode;
    bool mode_changed;
};

struct bochs_dev
{
    int fd;
    int instance_fd;
    int event_fd;

    struct pciem_shared_ring *ring;
    uint8_t *bar0_fb;
    uint16_t *bar2_vbe;

    pthread_mutex_t bga_mutex;
    struct bga_state bga;

    SDL_Window *window;
    SDL_Renderer *renderer;
    SDL_Texture *texture;
    uint32_t tex_w;
    uint32_t tex_h;

    pthread_t event_thread;
    volatile bool quit;
};

#define logx(fmt, ...) fprintf(stdout, "[bochs_card] " fmt "\n", ##__VA_ARGS__)
#define loge(fmt, ...) fprintf(stderr, "[bochs_card] ERROR: " fmt "\n", ##__VA_ARGS__)

static inline uint32_t bga_fb_stride(const struct bga_state *s)
{
    uint32_t vw = s->regs[VBE_IDX_VIRT_WIDTH];
    if (!vw)
        vw = s->regs[VBE_IDX_XRES];
    return vw * (s->regs[VBE_IDX_BPP] / 8u);
}

static inline uint32_t bga_scanout_offset(const struct bga_state *s)
{
    return s->regs[VBE_IDX_Y_OFFSET] * bga_fb_stride(s) + s->regs[VBE_IDX_X_OFFSET] * (s->regs[VBE_IDX_BPP] / 8u);
}

static void init_bar2_shadow(struct bochs_dev *dev)
{
    uint16_t *vbe = dev->bar2_vbe;

    vbe[VBE_IDX_ID] = VBE_DISPI_ID5;
    vbe[VBE_IDX_XRES] = BGA_MAX_WIDTH;
    vbe[VBE_IDX_YRES] = BGA_MAX_HEIGHT;
    vbe[VBE_IDX_BPP] = BGA_MAX_BPP;
    vbe[VBE_IDX_ENABLE] = VBE_DISPI_DISABLED;
    vbe[VBE_IDX_BANK] = 0;
    vbe[VBE_IDX_VIRT_WIDTH] = BGA_MAX_WIDTH;
    vbe[VBE_IDX_VIRT_HEIGHT] = BGA_MAX_HEIGHT * 2; // ???: I'm doubling it just to be double-buffer safe
    vbe[VBE_IDX_X_OFFSET] = 0;
    vbe[VBE_IDX_Y_OFFSET] = 0;
    vbe[VBE_IDX_VIDEO_MEMORY_64K] = BAR0_FB_SIZE / (64u * 1024u);

    logx("BAR2 shadow initialised (ID=0x%04x, max=%ux%u@%ubpp)", VBE_DISPI_ID5, BGA_MAX_WIDTH, BGA_MAX_HEIGHT,
         BGA_MAX_BPP);
}

static void handle_bar2_write(struct bochs_dev *dev, const struct pciem_event *ev)
{
    if (ev->offset < BGA_MMIO_VBE_OFFSET)
        return;
    if (ev->size != 2u)
        return;

    uint32_t byte_off = (uint32_t)(ev->offset - BGA_MMIO_VBE_OFFSET);
    if (byte_off >= VBE_IDX_COUNT * 2u)
        return;

    uint32_t idx = byte_off / 2u;
    uint16_t val = (uint16_t)ev->data;

    pthread_mutex_lock(&dev->bga_mutex);

    dev->bga.regs[idx] = val;

    if (idx == VBE_IDX_ENABLE)
    {
        bool was_on = dev->bga.display_on;
        dev->bga.display_on = !!(val & VBE_DISPI_ENABLED);
        dev->bga.lfb_mode = !!(val & VBE_DISPI_LFB_ENABLED);

        if (dev->bga.display_on != was_on || dev->bga.lfb_mode)
            dev->bga.mode_changed = true;

        logx("VBE ENABLE write: 0x%04x  (enabled=%d lfb=%d)", val, dev->bga.display_on, dev->bga.lfb_mode);
    }

    if (idx == VBE_IDX_XRES || idx == VBE_IDX_YRES || idx == VBE_IDX_BPP)
    {
        dev->bga.mode_changed = true;
        logx("VBE mode reg[%u] = %u", idx, val);
    }

    pthread_mutex_unlock(&dev->bga_mutex);
}

static void *event_thread_fn(void *arg)
{
    struct bochs_dev *dev = arg;
    struct pciem_shared_ring *ring = dev->ring;
    struct pollfd pfd = {.fd = dev->event_fd, .events = POLLIN};

    logx("event thread started");

    while (!dev->quit)
    {
        int ret = poll(&pfd, 1, 200);
        if (ret < 0)
        {
            if (errno == EINTR)
                continue;
            loge("poll: %s", strerror(errno));
            break;
        }
        if (!(pfd.revents & POLLIN))
            continue;

        uint64_t count;
        ssize_t __attribute__((unused)) _r = read(dev->event_fd, &count, sizeof(count));

        uint32_t tail = (uint32_t)atomic_load_explicit(&ring->tail, memory_order_acquire);
        uint32_t head = (uint32_t)atomic_load_explicit(&ring->head, memory_order_relaxed);

        while (head != tail)
        {
            const struct pciem_event *ev = &ring->events[head % PCIEM_RING_SIZE];

            switch (ev->type)
            {
            case PCIEM_EVENT_MMIO_WRITE:
                if (ev->bar == 2)
                    handle_bar2_write(dev, ev);
                break;
            case PCIEM_EVENT_RESET:
                logx("device reset");
                pthread_mutex_lock(&dev->bga_mutex);
                memset(&dev->bga, 0, sizeof(dev->bga));
                dev->bga.mode_changed = true;
                pthread_mutex_unlock(&dev->bga_mutex);
                break;
            default:
                break;
            }

            head++;
            atomic_store_explicit(&ring->head, (int)head, memory_order_release);
        }
    }

    logx("event thread exiting");
    return NULL;
}

static bool sdl_resize(struct bochs_dev *dev, uint32_t w, uint32_t h)
{
    if (dev->texture && dev->tex_w == w && dev->tex_h == h)
        return true;

    if (dev->texture)
    {
        SDL_DestroyTexture(dev->texture);
        dev->texture = NULL;
    }

    dev->texture =
        SDL_CreateTexture(dev->renderer, SDL_PIXELFORMAT_XRGB8888, SDL_TEXTUREACCESS_STREAMING, (int)w, (int)h);
    if (!dev->texture)
    {
        loge("SDL_CreateTexture: %s", SDL_GetError());
        return false;
    }

    dev->tex_w = w;
    dev->tex_h = h;

    SDL_SetWindowSize(dev->window, (int)w, (int)h);
    logx("SDL texture resized to %ux%u", w, h);
    return true;
}

static void sdl_present_frame(struct bochs_dev *dev)
{
    struct bga_state snap;

    pthread_mutex_lock(&dev->bga_mutex);
    snap = dev->bga;
    pthread_mutex_unlock(&dev->bga_mutex);

    uint32_t w = snap.regs[VBE_IDX_XRES];
    uint32_t h = snap.regs[VBE_IDX_YRES];
    uint32_t bpp = snap.regs[VBE_IDX_BPP];

    if (!w || !h || bpp != 32)
        return;
    if (!snap.display_on)
        return;

    if (!sdl_resize(dev, w, h))
        return;

    uint32_t stride = bga_fb_stride(&snap);
    uint32_t fb_off = bga_scanout_offset(&snap);

    if ((uint64_t)fb_off + (uint64_t)h * stride > BAR0_FB_SIZE)
        return;

    void *tex_pixels;
    int tex_pitch;
    if (!SDL_LockTexture(dev->texture, NULL, &tex_pixels, &tex_pitch))
    {
        loge("SDL_LockTexture: %s", SDL_GetError());
        return;
    }

    const uint8_t *src = dev->bar0_fb + fb_off;
    uint8_t *dst = tex_pixels;

    for (uint32_t row = 0; row < h; row++)
    {
        memcpy(dst, src, w * 4u);
        src += stride;
        dst += tex_pitch;
    }

    SDL_UnlockTexture(dev->texture);
    SDL_RenderTexture(dev->renderer, dev->texture, NULL, NULL);
    SDL_RenderPresent(dev->renderer);
}

static int dev_setup(struct bochs_dev *dev)
{
    int ret;

    dev->fd = open("/dev/pciem", O_RDWR | O_CLOEXEC);
    if (dev->fd < 0)
    {
        loge("open /dev/pciem: %s  (is pciem.ko loaded?)", strerror(errno));
        return -1;
    }

    struct pciem_create_device create = {
        .flags = PCIEM_CREATE_FLAG_BUS_MODE_VIRTUAL,
    };
    ret = ioctl(dev->fd, PCIEM_IOCTL_CREATE_DEVICE, &create);
    if (ret)
    {
        loge("CREATE_DEVICE: %s", strerror(errno));
        return -1;
    }

    struct pciem_config_space cfg = {
        .vendor_id = BOCHS_VGA_VENDOR,
        .device_id = BOCHS_VGA_DEVICE,
        .subsys_vendor_id = BOCHS_VGA_VENDOR,
        .subsys_device_id = 0x0000u,
        .revision = 0x02u,
        .class_code = {BOCHS_CLASS_PROG, BOCHS_CLASS_SUB, BOCHS_CLASS_BASE},
    };
    ret = ioctl(dev->fd, PCIEM_IOCTL_SET_CONFIG, &cfg);
    if (ret)
    {
        loge("SET_CONFIG: %s", strerror(errno));
        return -1;
    }

    struct pciem_bar_config bar0 = {
        .bar_index = 0,
        .flags = 0,
        .size = BAR0_FB_SIZE,
    };
    ret = ioctl(dev->fd, PCIEM_IOCTL_ADD_BAR, &bar0);
    if (ret)
    {
        loge("ADD_BAR(0): %s", strerror(errno));
        return -1;
    }

    struct pciem_bar_config bar2 = {
        .bar_index = 2,
        .flags = 0,
        .size = BAR2_MMIO_SIZE,
    };
    ret = ioctl(dev->fd, PCIEM_IOCTL_ADD_BAR, &bar2);
    if (ret)
    {
        loge("ADD_BAR(2): %s", strerror(errno));
        return -1;
    }

    struct pciem_trace_bar trace = {
        .bar_index = 2,
        .flags = PCIEM_TRACE_WRITES,
    };
    ret = ioctl(dev->fd, PCIEM_IOCTL_TRACE_BAR, &trace);
    if (ret)
    {
        loge("TRACE_BAR(2): %s", strerror(errno));
        return -1;
    }

    dev->event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (dev->event_fd < 0)
    {
        loge("eventfd: %s", strerror(errno));
        return -1;
    }

    struct pciem_eventfd_config efd_cfg = {.eventfd = dev->event_fd};
    ret = ioctl(dev->fd, PCIEM_IOCTL_SET_EVENTFD, &efd_cfg);
    if (ret)
    {
        loge("SET_EVENTFD: %s", strerror(errno));
        return -1;
    }

    dev->instance_fd = ioctl(dev->fd, PCIEM_IOCTL_REGISTER);
    if (dev->instance_fd < 0)
    {
        loge("PCIEM_IOCTL_REGISTER: %s", strerror(errno));
        return -1;
    }
    logx("device registered, instance_fd=%d", dev->instance_fd);

    dev->ring = mmap(NULL, sizeof(struct pciem_shared_ring), PROT_READ | PROT_WRITE, MAP_SHARED, dev->fd, 0);
    if (dev->ring == MAP_FAILED)
    {
        loge("mmap ring: %s", strerror(errno));
        return -1;
    }

    dev->bar0_fb = mmap(NULL, BAR0_FB_SIZE, PROT_READ, MAP_SHARED, dev->instance_fd, 0);
    if (dev->bar0_fb == MAP_FAILED)
    {
        loge("mmap bar0: %s", strerror(errno));
        return -1;
    }
    logx("BAR0 (framebuffer) mmap'd at %p", (void *)dev->bar0_fb);

    void *bar2_base =
        mmap(NULL, BAR2_MMIO_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, dev->instance_fd, 2 * sysconf(_SC_PAGESIZE));
    if (bar2_base == MAP_FAILED)
    {
        loge("mmap bar2: %s", strerror(errno));
        return -1;
    }
    dev->bar2_vbe = (uint16_t *)((uint8_t *)bar2_base + BGA_MMIO_VBE_OFFSET);
    logx("BAR2 (MMIO) mmap'd at %p", bar2_base);

    init_bar2_shadow(dev);

    pthread_mutex_lock(&dev->bga_mutex);
    dev->bga.regs[VBE_IDX_ID] = VBE_DISPI_ID5;
    dev->bga.regs[VBE_IDX_XRES] = BGA_INIT_WIDTH;
    dev->bga.regs[VBE_IDX_YRES] = BGA_INIT_HEIGHT;
    dev->bga.regs[VBE_IDX_BPP] = 32u;
    dev->bga.regs[VBE_IDX_VIRT_WIDTH] = BGA_INIT_WIDTH;
    dev->bga.regs[VBE_IDX_VIRT_HEIGHT] = BGA_INIT_HEIGHT * 2u;
    pthread_mutex_unlock(&dev->bga_mutex);

    logx("device setup complete");
    return 0;
}

static void dev_teardown(struct bochs_dev *dev)
{
    dev->quit = true;

    if (dev->event_thread)
        pthread_join(dev->event_thread, NULL);

    if (dev->bar2_vbe)
    {
        void *bar2_base = (uint8_t *)dev->bar2_vbe - BGA_MMIO_VBE_OFFSET;
        munmap(bar2_base, BAR2_MMIO_SIZE);
    }
    if (dev->bar0_fb && dev->bar0_fb != MAP_FAILED)
        munmap(dev->bar0_fb, BAR0_FB_SIZE);
    if (dev->ring && dev->ring != MAP_FAILED)
        munmap(dev->ring, sizeof(struct pciem_shared_ring));

    if (dev->instance_fd >= 0)
        close(dev->instance_fd);
    if (dev->event_fd >= 0)
        close(dev->event_fd);
    if (dev->fd >= 0)
        close(dev->fd);
}

static int sdl_setup(struct bochs_dev *dev)
{
    if (!SDL_Init(SDL_INIT_VIDEO))
    {
        loge("SDL_Init: %s", SDL_GetError());
        return -1;
    }

    dev->window = SDL_CreateWindow("PCIem nochs-drm Display", BGA_INIT_WIDTH, BGA_INIT_HEIGHT,
                                   SDL_WINDOW_RESIZABLE);
    if (!dev->window)
    {
        loge("SDL_CreateWindow: %s", SDL_GetError());
        return -1;
    }

    // ???: Let SDL3 choose the renderer, don't really see much problems w/this
    dev->renderer = SDL_CreateRenderer(dev->window, NULL);

    if (!dev->renderer)
    {
        loge("SDL_CreateRenderer: %s", SDL_GetError());
        return -1;
    }

    SDL_SetRenderDrawColor(dev->renderer, 0x18, 0x18, 0x18, 0xff);
    SDL_RenderClear(dev->renderer);
    SDL_RenderPresent(dev->renderer);

    logx("SDL3 window created (%ux%u)", BGA_INIT_WIDTH, BGA_INIT_HEIGHT);
    return 0;
}

static void sdl_teardown(struct bochs_dev *dev)
{
    if (dev->texture)
        SDL_DestroyTexture(dev->texture);
    if (dev->renderer)
        SDL_DestroyRenderer(dev->renderer);
    if (dev->window)
        SDL_DestroyWindow(dev->window);
    SDL_Quit();
}

static void main_loop(struct bochs_dev *dev)
{
    Uint64 last_frame = SDL_GetTicks();

    logx("entering render loop (target %u fps)", TARGET_FPS);

    while (!dev->quit)
    {
        SDL_Event event;
        while (SDL_PollEvent(&event))
        {
            if (event.type == SDL_EVENT_QUIT)
            {
                logx("SDL quit event");
                dev->quit = true;
            }
            if (event.type == SDL_EVENT_KEY_DOWN && event.key.key == SDLK_ESCAPE)
            {
                logx("ESC pressed, exiting");
                dev->quit = true;
            }
            if (event.type == SDL_EVENT_WINDOW_CLOSE_REQUESTED)
            {
                logx("window close requested");
                dev->quit = true;
            }
        }

        bool mode_changed = false;
        pthread_mutex_lock(&dev->bga_mutex);
        mode_changed = dev->bga.mode_changed;
        dev->bga.mode_changed = false;
        pthread_mutex_unlock(&dev->bga_mutex);

        if (mode_changed)
        {
            struct bga_state snap;
            pthread_mutex_lock(&dev->bga_mutex);
            snap = dev->bga;
            pthread_mutex_unlock(&dev->bga_mutex);

            uint32_t w = snap.regs[VBE_IDX_XRES];
            uint32_t h = snap.regs[VBE_IDX_YRES];

            if (w && h && snap.display_on)
            {
                logx("mode change: %ux%u@%ubpp (y_off=%u)", w, h, snap.regs[VBE_IDX_BPP], snap.regs[VBE_IDX_Y_OFFSET]);
                sdl_resize(dev, w, h);
            }
            else if (!snap.display_on)
            {
                SDL_SetRenderDrawColor(dev->renderer, 0x18, 0x18, 0x18, 0xff);
                SDL_RenderClear(dev->renderer);
                SDL_RenderPresent(dev->renderer);
            }
        }

        Uint64 now = SDL_GetTicks();
        if (now - last_frame >= FRAME_MS)
        {
            sdl_present_frame(dev);
            last_frame = now;
        }
        else
        {
            SDL_Delay(1);
        }
    }
}

int main(void)
{
    struct bochs_dev dev = {
        .fd = -1,
        .instance_fd = -1,
        .event_fd = -1,
    };
    int ret = EXIT_FAILURE;

    pthread_mutex_init(&dev.bga_mutex, NULL);

    if (sdl_setup(&dev))
        goto out_sdl;

    if (dev_setup(&dev))
        goto out_dev;

    if (ioctl(dev.fd, PCIEM_IOCTL_START, 0))
    {
        loge("PCIEM_IOCTL_START: %s", strerror(errno));
        goto out_dev;
    }

    logx("Bochs card installed");

    if (pthread_create(&dev.event_thread, NULL, event_thread_fn, &dev))
    {
        loge("pthread_create: %s", strerror(errno));
        goto out_dev;
    }

    main_loop(&dev);

    ret = EXIT_SUCCESS;

out_dev:
    dev_teardown(&dev);
out_sdl:
    sdl_teardown(&dev);
    pthread_mutex_destroy(&dev.bga_mutex);

    return ret;
}
