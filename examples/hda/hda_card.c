/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Copyright (C) 2026  Joel Bueno <buenocalvachejoel@gmail.com>
 *
 * Intel HDA (ICH6-compatible) synthetic sound card for PCIem
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pipewire/pipewire.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spa/param/audio/format-utils.h>
#include <spa/utils/ringbuffer.h>
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

#include "pciem_api.h"

#define HDA_GCAP 0x00
#define HDA_VMIN 0x02
#define HDA_VMAJ 0x03
#define HDA_OUTPAY 0x04
#define HDA_INPAY 0x06
#define HDA_GCTL 0x08
#define HDA_WAKEEN 0x0C
#define HDA_STATESTS 0x0E
#define HDA_GSTS 0x10
#define HDA_INTCTL 0x20
#define HDA_INTSTS 0x24
#define HDA_WALCLK 0x30
#define HDA_CORBLBASE 0x40
#define HDA_CORBUBASE 0x44
#define HDA_CORBWP 0x48
#define HDA_CORBRP 0x4A
#define HDA_CORBCTL 0x4C
#define HDA_CORBSTS 0x4D
#define HDA_CORBSIZE 0x4E
#define HDA_RIRBLBASE 0x50
#define HDA_RIRBUBASE 0x54
#define HDA_RIRBWP 0x58
#define HDA_RINTCNT 0x5A
#define HDA_RIRBCTL 0x5C
#define HDA_RIRBSTS 0x5D
#define HDA_RIRBSIZE 0x5E
#define HDA_DPLBASE 0x70
#define HDA_DPUBASE 0x74

#define HDA_SDBASE(n) (0x80 + (n) * 0x20)
#define SD_CTL0 0x00
#define SD_CTL1 0x01
#define SD_CTL2 0x02
#define SD_STS 0x03
#define SD_LPIB 0x04
#define SD_CBL 0x08
#define SD_LVI 0x0C
#define SD_FIFOW 0x0E
#define SD_FIFOS 0x10
#define SD_FMT 0x12
#define SD_BDPL 0x18
#define SD_BDPU 0x1C

#define GCTL_CRST (1U << 0)
#define GCTL_UNSOL (1U << 8)

#define INTCTL_GIE (1U << 31)
#define INTCTL_CIE (1U << 30)
#define INTSTS_GIS (1U << 31)
#define INTSTS_CIS (1U << 30)

#define CORBCTL_RUN (1U << 1)

#define CORBRP_RST (1U << 15)

#define RIRBCTL_RINTCTL (1U << 0)
#define RIRBCTL_DMA (1U << 1)

#define RIRBWP_RST (1U << 15)

#define RIRBSTS_INTFL (1U << 0)

#define SD_CTL_SRST (1U << 0)
#define SD_CTL_RUN (1U << 1)
#define SD_CTL_IOCE (1U << 2)

#define SD_STS_BCIS (1U << 2)
#define SD_STS_FIFORDY (1U << 5)

#define HDA_GCAP_VAL ((2U << 12) | (0U << 8) | (0U << 3) | (1U << 0))

#define VB_GET_PARAM 0xF00
#define VB_GET_CONN_SEL 0xF01
#define VB_GET_CONN_LIST 0xF02
#define VB_GET_PIN_CTRL 0xF07
#define VB_GET_UNSOL 0xF08
#define VB_GET_PIN_SENSE 0xF09
#define VB_GET_EAPD_BTL 0xF0C
#define VB_GET_DIGI_CONV 0xF0D
#define VB_GET_PWR_STATE 0xF0E
#define VB_GET_CONV_SCH 0xF0F
#define VB_GET_SUBSYS_ID 0xF12
#define VB_GET_CONF_DEF 0xF1C

#define AC_VENDOR_ID 0x00
#define AC_REV_ID 0x02
#define AC_NODE_COUNT 0x04
#define AC_FUNC_TYPE 0x05
#define AC_AFG_CAP 0x08
#define AC_WIDGET_CAP 0x09
#define AC_PCM 0x0A
#define AC_STREAM 0x0B
#define AC_PIN_CAP 0x0C
#define AC_IN_AMP 0x0D
#define AC_CONN_LEN 0x0E
#define AC_PWR_STATES 0x0F
#define AC_GPIO_COUNT 0x11
#define AC_OUT_AMP 0x12

#define NID_ROOT 0
#define NID_AFG 1
#define NID_DAC 2
#define NID_PIN 3

struct hda_bdl_entry
{
    uint64_t addr;
    uint32_t length;
    uint32_t flags;
} __attribute__((packed));

#define HDA_MAX_BDL 256
#define HDA_NUM_OSS 2
#define HDA_BAR_SIZE 0x4000
#define HDA_MAX_BUF (256 * 1024)

struct hda_stream
{
    bool running;
    uint32_t cbl;
    uint16_t lvi;
    uint16_t fmt;
    uint64_t bdl_addr;
    struct hda_bdl_entry bdl[HDA_MAX_BDL];
    uint32_t lpib;
    uint8_t cur_idx;
    uint32_t bytes_since_irq;
    uint32_t period_bytes;
    uint64_t walclk;
    struct timespec deadline;
};

struct hda_state
{
    int fd;
    int instance_fd;
    void *bar0;
    size_t bar0_size;

    struct pciem_shared_ring *ring;
    int event_fd;
    bool running;

    uint64_t corb_addr;
    uint16_t corb_rp;
    uint16_t corb_size;

    uint64_t rirb_addr;
    uint16_t rirb_wp;
    uint16_t rirb_size;
    uint8_t rirb_count;

    uint64_t dpl_addr;

    struct hda_stream out[HDA_NUM_OSS];

    struct pw_thread_loop *pw_loop;
    struct pw_stream *pw_stream;
    struct spa_ringbuffer pw_ring;
    uint8_t pw_ring_buf[1u << 18];
    uint32_t pw_stride;
    const char *pw_target;

    pthread_t stream_thr;
    pthread_mutex_t lock;
    pthread_cond_t cond;
};

#define br8(h, o) (*(volatile uint8_t *)((uint8_t *)(h)->bar0 + (o)))
#define br16(h, o) (*(volatile uint16_t *)((uint8_t *)(h)->bar0 + (o)))
#define br32(h, o) (*(volatile uint32_t *)((uint8_t *)(h)->bar0 + (o)))
#define bw8(h, o, v) (*(volatile uint8_t *)((uint8_t *)(h)->bar0 + (o)) = (uint8_t)(v))
#define bw16(h, o, v) (*(volatile uint16_t *)((uint8_t *)(h)->bar0 + (o)) = (uint16_t)(v))
#define bw32(h, o, v) (*(volatile uint32_t *)((uint8_t *)(h)->bar0 + (o)) = (uint32_t)(v))

static void bwn(struct hda_state *h, uint32_t off, uint64_t val, uint32_t sz)
{
    switch (sz)
    {
    case 1:
        bw8(h, off, val);
        break;
    case 2:
        bw16(h, off, val);
        break;
    case 4:
        bw32(h, off, val);
        break;
    }
}

static int dma_rw(struct hda_state *h, uint64_t iova, void *buf, uint32_t len, bool write)
{
    struct pciem_dma_op op = {
        .guest_iova = iova,
        .user_addr = (uint64_t)(uintptr_t)buf,
        .length = len,
        .flags = write ? PCIEM_DMA_FLAG_WRITE : PCIEM_DMA_FLAG_READ,
    };
    return ioctl(h->fd, PCIEM_IOCTL_DMA, &op);
}

static void inject_irq(struct hda_state *h)
{
    struct pciem_irq_inject irq = {.vector = 0};
    ioctl(h->fd, PCIEM_IOCTL_INJECT_IRQ, &irq);
}

static uint32_t codec_get_param(uint8_t nid, uint8_t param)
{
    switch (nid)
    {

    case NID_ROOT:
        switch (param)
        {
        case AC_VENDOR_ID:
            return 0x80860000;
        case AC_REV_ID:
            return 0x00100000;
        case AC_NODE_COUNT:
            return 0x00010001;
        default:
            return 0;
        }

    case NID_AFG:
        switch (param)
        {
        case AC_VENDOR_ID:
            return 0x80860000;
        case AC_NODE_COUNT:
            return 0x00020002;
        case AC_FUNC_TYPE:
            return 0x00000001;
        case AC_AFG_CAP:
            return 0x00000000;
        case AC_PCM:
            return 0x000A0060;
        case AC_STREAM:
            return 0x00000001;
        case AC_IN_AMP:
            return 0x00000000;
        case AC_OUT_AMP:
            return 0x00000000;
        case AC_PWR_STATES:
            return 0x0000000F;
        case AC_GPIO_COUNT:
            return 0x00000000;
        default:
            return 0;
        }

    case NID_DAC:
        switch (param)
        {
        case AC_WIDGET_CAP:
            return (0x0U << 20) | (1U << 4) | (1U << 2) | 0x1U;
        case AC_PCM:
            return 0x000A0060;
        case AC_STREAM:
            return 0x00000001;
        case AC_CONN_LEN:
            return 0x00000000;
        case AC_OUT_AMP:
            return (1U << 31);
        case AC_PWR_STATES:
            return 0x0000000F;
        default:
            return 0;
        }

    case NID_PIN:
        switch (param)
        {
        case AC_WIDGET_CAP:
            return (0x4U << 20) | (1U << 8) | 0x1U;
        case AC_PIN_CAP:
            return 0x00000018;
        case AC_CONN_LEN:
            return 0x00000001;
        case AC_IN_AMP:
            return 0x00000000;
        case AC_OUT_AMP:
            return 0x00000000;
        case AC_PWR_STATES:
            return 0x0000000F;
        default:
            return 0;
        }
    }
    return 0;
}

static uint32_t hda_codec_verb(uint8_t nid, uint16_t verb, uint8_t payload)
{
    uint8_t hi4 = (verb >> 8) & 0xF;
    if (hi4 == 0x2 || hi4 == 0x3)
    {
        return 0;
    }

    switch (verb)
    {
    case VB_GET_PARAM:
        return codec_get_param(nid, payload);

    case VB_GET_CONN_SEL:
        return 0;
    case VB_GET_CONN_LIST:
        return (nid == NID_PIN && payload == 0) ? NID_DAC : 0;

    case VB_GET_PIN_CTRL:
        return (nid == NID_PIN) ? 0x40 : 0;

    case VB_GET_UNSOL:
    case VB_GET_DIGI_CONV:
    case VB_GET_PWR_STATE:
    case VB_GET_CONV_SCH:
        return 0;

    case VB_GET_PIN_SENSE:
        return (nid == NID_PIN) ? 0x80000000U : 0;

    case VB_GET_EAPD_BTL:
        return (nid == NID_PIN) ? 0x02 : 0;

    case VB_GET_CONF_DEF:
        return (nid == NID_PIN) ? 0x0221401fU : 0;

    case VB_GET_SUBSYS_ID:
        return 0x80860000U;

    case 0x700 ... 0x7FF:

    case 0x500 ... 0x5FF:
        return 0;

    case 0xB00:
        return 0x00;

    default:
        return 0;
    }
}

static void hda_fire_rirb_irq(struct hda_state *h)
{
    uint32_t intctl = br32(h, HDA_INTCTL);
    if (!(intctl & INTCTL_GIE) || !(intctl & INTCTL_CIE))
        return;
    bw8(h, HDA_RIRBSTS, br8(h, HDA_RIRBSTS) | RIRBSTS_INTFL);
    bw32(h, HDA_INTSTS, br32(h, HDA_INTSTS) | INTSTS_CIS | INTSTS_GIS);
    inject_irq(h);
}

static void hda_process_corb(struct hda_state *h)
{
    uint8_t corbwp = br16(h, HDA_CORBWP) & 0xFF;
    uint16_t corb_sz = h->corb_size ? h->corb_size : 256;
    uint16_t rirb_sz = h->rirb_size ? h->rirb_size : 256;
    uint16_t prev_wp = h->rirb_wp;

    while (h->corb_rp != corbwp)
    {
        uint16_t next_rp = (h->corb_rp + 1) % corb_sz;
        uint32_t raw = 0;

        if (dma_rw(h, h->corb_addr + (uint64_t)next_rp * 4, &raw, 4, false))
        {
            fprintf(stderr, "hda: CORB DMA read failed at idx %u\n", next_rp);
            break;
        }

        uint8_t codec = (raw >> 28) & 0x0F;
        uint8_t nid = (raw >> 20) & 0x7F;
        uint16_t verb = (raw >> 8) & 0xFFF;
        uint8_t payload = (raw >> 0) & 0xFF;

        uint32_t resp = (codec == 0) ? hda_codec_verb(nid, verb, payload) : 0;

        uint16_t next_wp = (h->rirb_wp + 1) % rirb_sz;
        uint64_t rirb_e = ((uint64_t)codec << 32) | resp;

        if (dma_rw(h, h->rirb_addr + (uint64_t)next_wp * 8, &rirb_e, 8, true))
        {
            fprintf(stderr, "hda: RIRB DMA write failed at idx %u\n", next_wp);
            break;
        }

        h->rirb_wp = next_wp;
        bw16(h, HDA_RIRBWP, h->rirb_wp);

        h->corb_rp = next_rp;
        bw16(h, HDA_CORBRP, h->corb_rp);

        h->rirb_count++;
        uint8_t rintcnt = br16(h, HDA_RINTCNT) & 0xFF;
        if (h->rirb_count > rintcnt)
        {
            h->rirb_count = 0;
            if (br8(h, HDA_RIRBCTL) & RIRBCTL_RINTCTL)
                hda_fire_rirb_irq(h);
        }
    }

    if (h->rirb_wp != prev_wp && (br8(h, HDA_RIRBCTL) & RIRBCTL_RINTCTL))
        hda_fire_rirb_irq(h);
}

#define HDA_PW_RING_SIZE (1u << 18)

static void on_pw_process(void *userdata)
{
    struct hda_state *h = userdata;
    struct pw_buffer *pwb = pw_stream_dequeue_buffer(h->pw_stream);
    if (!pwb)
        return;

    struct spa_buffer *sb = pwb->buffer;
    uint8_t *dst = sb->datas[0].data;
    if (!dst)
        goto done;

    uint32_t maxsize = sb->datas[0].maxsize;
    uint32_t requested = pwb->requested ? (uint32_t)(pwb->requested * h->pw_stride) : maxsize;
    requested = SPA_MIN(requested, maxsize);

    uint32_t read_idx;
    int32_t avail = spa_ringbuffer_get_read_index(&h->pw_ring, &read_idx);
    uint32_t to_copy = (avail > 0) ? SPA_MIN((uint32_t)avail, requested) : 0;

    if (to_copy > 0)
    {
        spa_ringbuffer_read_data(&h->pw_ring, h->pw_ring_buf, HDA_PW_RING_SIZE, read_idx & (HDA_PW_RING_SIZE - 1), dst,
                                 to_copy);
        spa_ringbuffer_read_update(&h->pw_ring, read_idx + to_copy);
    }
    if (to_copy < requested)
        memset(dst + to_copy, 0, requested - to_copy);

    sb->datas[0].chunk->offset = 0;
    sb->datas[0].chunk->stride = (int32_t)h->pw_stride;
    sb->datas[0].chunk->size = requested;

done:
    pw_stream_queue_buffer(h->pw_stream, pwb);
}

static const struct pw_stream_events hda_pw_stream_events = {
    PW_VERSION_STREAM_EVENTS,
    .process = on_pw_process,
};

static void hda_pw_setup(struct hda_state *h, uint16_t fmt)
{
    unsigned int channels = (fmt & 0xF) + 1;
    unsigned int bits_f = (fmt >> 4) & 0x7;
    unsigned int div = ((fmt >> 8) & 0x7) + 1;
    unsigned int mult = ((fmt >> 11) & 0x7) + 1;
    unsigned int base_hz = (fmt & (1U << 14)) ? 44100 : 48000;
    unsigned int rate = base_hz * mult / div;

    uint32_t spa_fmt;
    uint32_t sample_bytes;
    switch (bits_f)
    {
    case 0:
        spa_fmt = SPA_AUDIO_FORMAT_U8;
        sample_bytes = 1;
        break;
    case 1:
        spa_fmt = SPA_AUDIO_FORMAT_S16_LE;
        sample_bytes = 2;
        break;
    case 2:
    case 3:
        spa_fmt = SPA_AUDIO_FORMAT_S24_LE;
        sample_bytes = 3;
        break;
    case 4:
        spa_fmt = SPA_AUDIO_FORMAT_S32_LE;
        sample_bytes = 4;
        break;
    default:
        spa_fmt = SPA_AUDIO_FORMAT_S16_LE;
        sample_bytes = 2;
        break;
    }

    fprintf(stderr, "hda: stream format: %u Hz, %u ch, bits_f=%u\n", rate, channels, bits_f);
    h->pw_stride = sample_bytes * channels;

    if (h->pw_stream)
    {
        pw_thread_loop_lock(h->pw_loop);
        pw_stream_destroy(h->pw_stream);
        h->pw_stream = NULL;
        pw_thread_loop_unlock(h->pw_loop);
    }

    if (!h->pw_loop)
    {
        pw_init(NULL, NULL);
        h->pw_loop = pw_thread_loop_new("hda-pw", NULL);
        if (!h->pw_loop)
        {
            fprintf(stderr, "hda: pw_thread_loop_new failed\n");
            return;
        }
        pw_thread_loop_start(h->pw_loop);
    }

    spa_ringbuffer_init(&h->pw_ring);
    memset(h->pw_ring_buf, 0, sizeof(h->pw_ring_buf));

    struct pw_properties *props =
        pw_properties_new(PW_KEY_MEDIA_TYPE, "Audio", PW_KEY_MEDIA_CATEGORY, "Playback", PW_KEY_MEDIA_ROLE, "Music",
                          PW_KEY_APP_NAME, "hda_card", PW_KEY_NODE_NAME, "PCIem HDA", NULL);
    if (h->pw_target)
        pw_properties_set(props, PW_KEY_TARGET_OBJECT, h->pw_target);

    pw_thread_loop_lock(h->pw_loop);

    h->pw_stream =
        pw_stream_new_simple(pw_thread_loop_get_loop(h->pw_loop), "PCIem HDA", props, &hda_pw_stream_events, h);

    if (!h->pw_stream)
    {
        pw_thread_loop_unlock(h->pw_loop);
        fprintf(stderr, "hda: pw_stream_new_simple failed\n");
        return;
    }

    uint8_t pod_buf[1024];
    struct spa_pod_builder pod_builder = SPA_POD_BUILDER_INIT(pod_buf, sizeof(pod_buf));
    struct spa_audio_info_raw info = {
        .format = spa_fmt,
        .rate = rate,
        .channels = channels,
    };
    if (channels == 1)
    {
        info.position[0] = SPA_AUDIO_CHANNEL_MONO;
    }
    else if (channels >= 2)
    {
        info.position[0] = SPA_AUDIO_CHANNEL_FL;
        info.position[1] = SPA_AUDIO_CHANNEL_FR;
    }

    const struct spa_pod *params[1];
    params[0] = spa_format_audio_raw_build(&pod_builder, SPA_PARAM_EnumFormat, &info);

    pw_stream_connect(h->pw_stream, PW_DIRECTION_OUTPUT, PW_ID_ANY,
                      PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS | PW_STREAM_FLAG_RT_PROCESS, params, 1);

    pw_thread_loop_unlock(h->pw_loop);
}

static void hda_pw_write(struct hda_state *h, const void *buf, size_t bytes)
{
    if (!h->pw_stream)
        return;

    uint32_t write_idx;
    int32_t filled = spa_ringbuffer_get_write_index(&h->pw_ring, &write_idx);
    uint32_t free = HDA_PW_RING_SIZE - (uint32_t)filled;
    uint32_t to_write = SPA_MIN((uint32_t)bytes, free);

    if (to_write == 0)
        return;

    spa_ringbuffer_write_data(&h->pw_ring, h->pw_ring_buf, HDA_PW_RING_SIZE, write_idx & (HDA_PW_RING_SIZE - 1), buf,
                              to_write);
    spa_ringbuffer_write_update(&h->pw_ring, write_idx + to_write);
}

static void hda_stream_stop(struct hda_state *h, int idx)
{
    pthread_mutex_lock(&h->lock);
    h->out[idx].running = false;
    pthread_mutex_unlock(&h->lock);
    fprintf(stderr, "hda: output stream %d stopped\n", idx);
}

static void hda_stream_start(struct hda_state *h, int idx)
{
    struct hda_stream *s = &h->out[idx];
    uint32_t base = HDA_SDBASE(idx);

    s->cbl = br32(h, base + SD_CBL);
    s->lvi = br16(h, base + SD_LVI);
    s->fmt = br16(h, base + SD_FMT);
    uint32_t lo = br32(h, base + SD_BDPL);
    uint32_t hi = br32(h, base + SD_BDPU);
    s->bdl_addr = lo | ((uint64_t)hi << 32);

    if (!s->bdl_addr || !s->cbl || s->lvi >= HDA_MAX_BDL)
    {
        fprintf(stderr, "hda: stream %d: bad params bdl=%llx cbl=%u lvi=%u\n", idx, (unsigned long long)s->bdl_addr,
                s->cbl, s->lvi);
        return;
    }

    uint32_t bdl_bytes = (uint32_t)(s->lvi + 1) * sizeof(struct hda_bdl_entry);
    if (dma_rw(h, s->bdl_addr, s->bdl, bdl_bytes, false))
    {
        fprintf(stderr, "hda: stream %d: BDL DMA read failed\n", idx);
        return;
    }

    fprintf(stderr, "hda: output stream %d start: cbl=%u lvi=%u fmt=0x%04x\n", idx, s->cbl, s->lvi, s->fmt);
    for (int i = 0; i <= s->lvi; i++)
        fprintf(stderr, "  BDL[%d]: addr=%llx len=%u ioc=%d\n", i, (unsigned long long)s->bdl[i].addr, s->bdl[i].length,
                s->bdl[i].flags & 1);

    hda_pw_setup(h, s->fmt);

    pthread_mutex_lock(&h->lock);
    s->lpib = 0;
    s->cur_idx = 0;
    s->bytes_since_irq = 0;
    s->walclk = 0;
    s->period_bytes = (s->lvi > 0) ? (s->cbl / (s->lvi + 1)) : s->cbl;
    clock_gettime(CLOCK_MONOTONIC, &s->deadline);
    s->running = true;
    pthread_cond_signal(&h->cond);
    pthread_mutex_unlock(&h->lock);
}

static uint32_t hda_fmt_bytes_per_sec(uint16_t fmt)
{
    static const unsigned int bits_tab[] = {8, 16, 20, 24, 32, 16, 16, 16};
    unsigned int channels = (fmt & 0xf) + 1;
    unsigned int bits = bits_tab[(fmt >> 4) & 0x7];
    unsigned int div = ((fmt >> 8) & 0x7) + 1;
    unsigned int mult = ((fmt >> 11) & 0x7) + 1;
    unsigned int base_hz = (fmt & (1u << 14)) ? 44100u : 48000u;
    return base_hz * mult / div * channels * (bits / 8);
}

static void hda_write_lpib(struct hda_state *h, int idx, uint32_t pos)
{
    bw32(h, HDA_SDBASE(idx) + SD_LPIB, pos);

    if (h->dpl_addr & 1)
    {
        uint64_t slot = (h->dpl_addr & ~1ULL) + (uint64_t)idx * 8;
        dma_rw(h, slot, &pos, sizeof(pos), true);
    }
}

static void *stream_thread(void *arg)
{
    struct hda_state *h = arg;
    uint8_t *audiobuf = malloc(HDA_MAX_BUF);
    if (!audiobuf)
        err(1, "stream_thread malloc");

    while (h->running)
    {

        pthread_mutex_lock(&h->lock);
        while (h->running && !h->out[0].running && !h->out[1].running)
            pthread_cond_wait(&h->cond, &h->lock);
        if (!h->running)
        {
            pthread_mutex_unlock(&h->lock);
            break;
        }

        int idx = -1;
        for (int i = 0; i < HDA_NUM_OSS; i++)
        {
            if (h->out[i].running)
            {
                idx = i;
                break;
            }
        }
        if (idx < 0)
        {
            pthread_mutex_unlock(&h->lock);
            continue;
        }

        struct hda_stream *s = &h->out[idx];
        struct hda_bdl_entry e = s->bdl[s->cur_idx];

        pthread_mutex_unlock(&h->lock);

        uint32_t len = e.length;
        if (len > HDA_MAX_BUF)
            len = HDA_MAX_BUF;

        bool dma_ok = false;
        pthread_mutex_lock(&h->lock);
        if (!s->running)
        {
            pthread_mutex_unlock(&h->lock);
            continue;
        }
        pthread_mutex_unlock(&h->lock);

        if (!dma_rw(h, e.addr, audiobuf, len, false))
            dma_ok = true;
        else
            fprintf(stderr, "hda: stream %d BDL[%u] DMA read failed\n", idx, s->cur_idx);

        pthread_mutex_lock(&h->lock);
        if (!s->running)
        {
            pthread_mutex_unlock(&h->lock);
            continue;
        }
        s->lpib += e.length;
        if (s->lpib >= s->cbl)
            s->lpib -= s->cbl;
        hda_write_lpib(h, idx, s->lpib);

        uint32_t bps = hda_fmt_bytes_per_sec(s->fmt);
        if (bps)
        {
            s->walclk += (uint64_t)e.length * 24000000ULL / bps;
            bw32(h, HDA_WALCLK, (uint32_t)s->walclk);
        }
        pthread_mutex_unlock(&h->lock);

        if (dma_ok)
            hda_pw_write(h, audiobuf, len);

        pthread_mutex_lock(&h->lock);
        uint32_t pace_bps = hda_fmt_bytes_per_sec(s->fmt);
        struct timespec entry_deadline = s->deadline;
        if (pace_bps && s->running)
        {
            uint64_t ns = (uint64_t)e.length * 1000000000ULL / pace_bps;
            entry_deadline.tv_nsec += (long)ns;
            entry_deadline.tv_sec += entry_deadline.tv_nsec / 1000000000L;
            entry_deadline.tv_nsec %= 1000000000L;
            s->deadline = entry_deadline;
        }
        pthread_mutex_unlock(&h->lock);
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &entry_deadline, NULL);

        pthread_mutex_lock(&h->lock);
        if (!s->running)
        {
            pthread_mutex_unlock(&h->lock);
            continue;
        }

        s->bytes_since_irq += e.length;

        bool fire_irq = (e.flags & 1) && (br8(h, HDA_SDBASE(idx) + SD_CTL0) & SD_CTL_IOCE) &&
                        (s->bytes_since_irq >= s->period_bytes);
        if (fire_irq)
            s->bytes_since_irq = 0;

        s->cur_idx = (s->cur_idx >= s->lvi) ? 0 : s->cur_idx + 1;
        pthread_mutex_unlock(&h->lock);

        if (fire_irq)
        {
            uint8_t sts = br8(h, HDA_SDBASE(idx) + SD_STS);
            uint32_t intsts = br32(h, HDA_INTSTS);
            uint32_t intctl = br32(h, HDA_INTCTL);

            bw8(h, HDA_SDBASE(idx) + SD_STS, sts | SD_STS_BCIS);

            if ((intctl & INTCTL_GIE) && (intctl & (1U << idx)))
            {
                bw32(h, HDA_INTSTS, intsts | INTSTS_GIS | (1U << idx));
                inject_irq(h);
            }
        }
    }

    free(audiobuf);
    return NULL;
}

static void hda_handle_write(struct hda_state *h, struct pciem_event *ev)
{
    if (ev->bar != 0)
        return;

    uint32_t off = (uint32_t)ev->offset;
    uint32_t val = (uint32_t)(ev->data & ((1ULL << (ev->size * 8)) - 1));
    uint32_t sz = ev->size;

    if (off == HDA_GCTL)
    {
        if (val & GCTL_CRST)
        {
            bw32(h, HDA_GCTL, val);
            bw16(h, HDA_STATESTS, 0x0001);
        }
        else
        {
            bw32(h, HDA_GCTL, 0);
            bw16(h, HDA_STATESTS, 0);
            for (int i = 0; i < HDA_NUM_OSS; i++)
            {
                pthread_mutex_lock(&h->lock);
                h->out[i].running = false;
                pthread_mutex_unlock(&h->lock);
            }
            h->corb_rp = 0;
            h->rirb_wp = 0;
            h->rirb_count = 0;
            bw16(h, HDA_CORBRP, 0);
            bw16(h, HDA_RIRBWP, 0);
        }
        return;
    }

    if (off == HDA_STATESTS)
    {
        bw16(h, HDA_STATESTS, br16(h, HDA_STATESTS) & ~val);
        return;
    }

    if (off == HDA_INTCTL)
    {
        bw32(h, HDA_INTCTL, val);
        return;
    }

    if (off == HDA_INTSTS)
    {
        bw32(h, HDA_INTSTS, br32(h, HDA_INTSTS) & ~val);
        return;
    }

    if (off == HDA_CORBLBASE)
    {
        h->corb_addr = (h->corb_addr & 0xFFFFFFFF00000000ULL) | val;
        bw32(h, off, val);
        return;
    }
    if (off == HDA_CORBUBASE)
    {
        h->corb_addr = (h->corb_addr & 0x00000000FFFFFFFFULL) | ((uint64_t)val << 32);
        bw32(h, off, val);
        return;
    }
    if (off == HDA_CORBSIZE)
    {
        uint8_t szcap = br8(h, HDA_CORBSIZE) & 0xF0;
        uint8_t size_code = val & 0x3;
        static const uint8_t sz_map[] = {2, 16, 0, 0};
        h->corb_size = (size_code == 2) ? 256 : sz_map[size_code];
        bw8(h, HDA_CORBSIZE, szcap | size_code);
        return;
    }
    if (off == HDA_CORBRP)
    {
        if (val & CORBRP_RST)
        {
            h->corb_rp = 0;
            bw16(h, HDA_CORBRP, CORBRP_RST);
        }
        else
        {
            bw16(h, HDA_CORBRP, 0);
        }
        return;
    }
    if (off == HDA_CORBCTL)
    {
        bw8(h, HDA_CORBCTL, val);
        if (val & CORBCTL_RUN)
            hda_process_corb(h);
        return;
    }
    if (off == HDA_CORBWP)
    {
        bw16(h, HDA_CORBWP, val & 0xFF);
        if (br8(h, HDA_CORBCTL) & CORBCTL_RUN)
            hda_process_corb(h);
        return;
    }

    if (off == HDA_RIRBLBASE)
    {
        h->rirb_addr = (h->rirb_addr & 0xFFFFFFFF00000000ULL) | val;
        bw32(h, off, val);
        return;
    }
    if (off == HDA_RIRBUBASE)
    {
        h->rirb_addr = (h->rirb_addr & 0x00000000FFFFFFFFULL) | ((uint64_t)val << 32);
        bw32(h, off, val);
        return;
    }
    if (off == HDA_RIRBSIZE)
    {
        uint8_t szcap = br8(h, HDA_RIRBSIZE) & 0xF0;
        uint8_t size_code = val & 0x3;
        static const uint8_t sz_map[] = {2, 16, 0, 0};
        h->rirb_size = (size_code == 2) ? 256 : sz_map[size_code];
        bw8(h, HDA_RIRBSIZE, szcap | size_code);
        return;
    }
    if (off == HDA_RIRBWP)
    {
        if (val & RIRBWP_RST)
        {
            h->rirb_wp = 0;
            bw16(h, HDA_RIRBWP, 0);
        }
        return;
    }
    if (off == HDA_RIRBCTL)
    {
        bw8(h, HDA_RIRBCTL, val);
        return;
    }
    if (off == HDA_RIRBSTS)
    {
        bw8(h, HDA_RIRBSTS, br8(h, HDA_RIRBSTS) & ~val);
        return;
    }
    if (off == HDA_RINTCNT)
    {
        bw16(h, HDA_RINTCNT, val & 0xFF);
        return;
    }

    if (off == HDA_DPLBASE)
    {
        h->dpl_addr = (h->dpl_addr & 0xFFFFFFFF00000000ULL) | val;
        bw32(h, off, val);
        return;
    }
    if (off == HDA_DPUBASE)
    {
        h->dpl_addr = (h->dpl_addr & 0x00000000FFFFFFFFULL) | ((uint64_t)val << 32);
        bw32(h, off, val);
        return;
    }

    if (off >= 0x80 && off < (uint32_t)(0x80 + HDA_NUM_OSS * 0x20))
    {
        int sd_idx = (off - 0x80) / 0x20;
        uint32_t sd_off = (off - 0x80) % 0x20;
        uint32_t sd_base = HDA_SDBASE(sd_idx);

        if (sd_off == SD_STS)
        {
            bw8(h, sd_base + SD_STS, br8(h, sd_base + SD_STS) & ~val);
            return;
        }

        if (sd_off == SD_CTL0)
        {
            uint8_t old_ctl = br8(h, sd_base + SD_CTL0);
            uint8_t new_ctl = (uint8_t)val;

            bool old_run = !!(old_ctl & SD_CTL_RUN);
            bool new_run = !!(new_ctl & SD_CTL_RUN);
            bool srst = !!(new_ctl & SD_CTL_SRST);

            if (srst)
            {
                hda_stream_stop(h, sd_idx);
                hda_write_lpib(h, sd_idx, 0);
                bw8(h, sd_base + SD_CTL0, new_ctl & ~SD_CTL_SRST);
                bw8(h, sd_base + SD_STS, SD_STS_FIFORDY);
            }
            else
            {
                bw8(h, sd_base + SD_CTL0, new_ctl);
                if (sz >= 2)
                    bw8(h, sd_base + SD_CTL1, (val >> 8) & 0xff);
                if (sz >= 3)
                    bw8(h, sd_base + SD_CTL2, (val >> 16) & 0xff);
                if (sz >= 4)
                {
                    uint8_t sts_clr = (val >> 24) & 0xff;
                    bw8(h, sd_base + SD_STS, br8(h, sd_base + SD_STS) & ~sts_clr);
                }

                if (new_run && !old_run)
                    hda_stream_start(h, sd_idx);
                else if (!new_run && old_run)
                    hda_stream_stop(h, sd_idx);
            }
            return;
        }

        bwn(h, off, val, sz);
        return;
    }

    bwn(h, off, val, sz);
}

static void *event_loop(void *arg)
{
    struct hda_state *h = arg;
    struct pciem_shared_ring *ring = h->ring;
    struct pollfd pfd = {.fd = h->event_fd, .events = POLLIN};

    while (h->running)
    {
        if (poll(&pfd, 1, -1) <= 0)
            continue;

        uint64_t tmp;
        ssize_t _r = read(h->event_fd, &tmp, sizeof(tmp));
        (void)_r;

        int head = atomic_load(&ring->head);
        int tail = atomic_load(&ring->tail);

        while (head != tail)
        {
            struct pciem_event *ev = &ring->events[head];

            if (ev->type == PCIEM_EVENT_MMIO_WRITE)
                hda_handle_write(h, ev);

            head = (head + 1) % PCIEM_RING_SIZE;
            atomic_store(&ring->head, head);
            tail = atomic_load(&ring->tail);
        }
    }
    return NULL;
}

static int hda_register(struct hda_state *h)
{
    int ret;

    struct pciem_create_device create = {.flags = 0};

    struct pciem_config_space cfg = {
        .vendor_id = 0x8086,
        .device_id = 0x2668,
        .subsys_vendor_id = 0x8086,
        .subsys_device_id = 0x2668,
        .revision = 0x01,
        .class_code = {0x00, 0x03, 0x04},
        .header_type = 0x00,
    };

    struct pciem_bar_config bar = {
        .bar_index = 0,
        .size = HDA_BAR_SIZE,
        .flags = 0,
    };

    struct pciem_cap_config cap = {
        .cap_type = PCIEM_CAP_MSI,
        .msi = {.num_vectors_log2 = 0, .has_64bit = true},
    };

    struct pciem_trace_bar trace = {
        .bar_index = 0,
        .flags = PCIEM_TRACE_WRITES | PCIEM_TRACE_STOP_WRITES,
    };

    h->fd = open("/dev/pciem", O_RDWR);
    if (h->fd < 0)
        return -errno;

    ret = ioctl(h->fd, PCIEM_IOCTL_CREATE_DEVICE, &create);
    if (ret)
        goto fail;

    ret = ioctl(h->fd, PCIEM_IOCTL_SET_CONFIG, &cfg);
    if (ret)
        goto fail;

    ret = ioctl(h->fd, PCIEM_IOCTL_ADD_BAR, &bar);
    if (ret)
        goto fail;

    ret = ioctl(h->fd, PCIEM_IOCTL_ADD_CAPABILITY, &cap);
    if (ret)
        goto fail;

    ret = ioctl(h->fd, PCIEM_IOCTL_TRACE_BAR, &trace);
    if (ret)
        goto fail;

    h->event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (h->event_fd < 0)
    {
        ret = -errno;
        goto fail;
    }

    struct pciem_eventfd_config efd = {.eventfd = h->event_fd};
    ret = ioctl(h->fd, PCIEM_IOCTL_SET_EVENTFD, &efd);
    if (ret)
        goto fail;

    h->instance_fd = ioctl(h->fd, PCIEM_IOCTL_REGISTER);
    if (h->instance_fd < 0)
    {
        ret = -1;
        goto fail;
    }

    return 0;
fail:
    if (h->event_fd >= 0)
    {
        close(h->event_fd);
        h->event_fd = -1;
    }
    close(h->fd);
    h->fd = -1;
    return ret;
}

static void hda_setup_shadow_regs(struct hda_state *h)
{
    bw16(h, HDA_GCAP, HDA_GCAP_VAL);
    bw8(h, HDA_VMAJ, 0x01);
    bw8(h, HDA_VMIN, 0x00);

    bw16(h, HDA_OUTPAY, 0x003C);
    bw16(h, HDA_INPAY, 0x001A);

    bw8(h, HDA_CORBSIZE, 0x40);
    bw8(h, HDA_RIRBSIZE, 0x40);

    for (int i = 0; i < HDA_NUM_OSS; i++)
    {
        bw16(h, HDA_SDBASE(i) + SD_FIFOS, 0x0100);
        bw8(h, HDA_SDBASE(i) + SD_STS, SD_STS_FIFORDY);
    }
}

int main(int argc, char **argv)
{
    struct hda_state h = {.fd = -1, .event_fd = -1, .instance_fd = -1};

    h.pw_target = (argc > 1) ? argv[1] : NULL;

    pthread_mutex_init(&h.lock, NULL);
    pthread_cond_init(&h.cond, NULL);

    fprintf(stderr, "hda: registering with PCIem ...\n");
    if (hda_register(&h))
        err(1, "hda_register");

    h.bar0_size = HDA_BAR_SIZE;
    h.bar0 = mmap(NULL, h.bar0_size, PROT_READ | PROT_WRITE, MAP_SHARED, h.instance_fd, 0);
    if (h.bar0 == MAP_FAILED)
        err(1, "mmap bar0");

    h.ring = mmap(NULL, sizeof(struct pciem_shared_ring), PROT_READ | PROT_WRITE, MAP_SHARED, h.fd, 0);
    if (h.ring == MAP_FAILED)
        err(1, "mmap ring");

    hda_setup_shadow_regs(&h);

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigprocmask(SIG_BLOCK, &mask, NULL);

    h.running = true;
    if (pthread_create(&h.stream_thr, NULL, stream_thread, &h))
        err(1, "pthread_create stream_thr");

    if (ioctl(h.fd, PCIEM_IOCTL_START, 0))
        err(1, "PCIEM_IOCTL_START");

    pthread_t ev_thr;
    if (pthread_create(&ev_thr, NULL, event_loop, &h))
        err(1, "pthread_create event_loop");

    int sig;
    sigwait(&mask, &sig);
    fprintf(stderr, "\nhda: shutting down\n");

    h.running = false;

    pthread_mutex_lock(&h.lock);
    pthread_cond_signal(&h.cond);
    pthread_mutex_unlock(&h.lock);

    uint64_t wakeup = 1;
    (void)write(h.event_fd, &wakeup, sizeof(wakeup));

    pthread_join(h.stream_thr, NULL);
    pthread_join(ev_thr, NULL);

    if (h.pw_stream)
    {
        pw_thread_loop_lock(h.pw_loop);
        pw_stream_destroy(h.pw_stream);
        pw_thread_loop_unlock(h.pw_loop);
    }
    if (h.pw_loop)
    {
        pw_thread_loop_stop(h.pw_loop);
        pw_thread_loop_destroy(h.pw_loop);
        pw_deinit();
    }

    munmap(h.bar0, h.bar0_size);
    munmap(h.ring, sizeof(*h.ring));
    close(h.instance_fd);
    close(h.event_fd);
    close(h.fd);

    pthread_mutex_destroy(&h.lock);
    pthread_cond_destroy(&h.cond);
    return 0;
}
