/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Copyright (C) 2026  Joel Bueno <buenocalvachejoel@gmail.com>
 * 
 * Intel 82540EM (E1000) userspace card for PCIem
 */

#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
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

#define E1000_CTRL 0x00000
#define E1000_STATUS 0x00008
#define E1000_EECD 0x00010
#define E1000_EERD 0x00014
#define E1000_MDIC 0x00020
#define E1000_ICR 0x000C0
#define E1000_ICS 0x000C8
#define E1000_IMS 0x000D0
#define E1000_TDBAL 0x03800
#define E1000_TDBAH 0x03804
#define E1000_TDLEN 0x03808
#define E1000_TDH 0x03810
#define E1000_TDT 0x03818
#define E1000_RDBAL 0x02800
#define E1000_RDBAH 0x02804
#define E1000_RDLEN 0x02808
#define E1000_RDH 0x02810
#define E1000_RDT 0x02818
#define E1000_RAL0 0x05400
#define E1000_RAH0 0x05404

#define E1000_CTRL_SLU (1U << 6)
#define E1000_CTRL_RST (1U << 26)

#define E1000_STATUS_LU (1U << 2)
#define E1000_STATUS_FD (1U << 0)
#define E1000_STATUS_SPEED_1000 (2U << 6)
#define E1000_STATUS_1000FD (E1000_STATUS_LU | E1000_STATUS_FD | E1000_STATUS_SPEED_1000)

#define E1000_TXD_CMD_EOP (1 << 0)
#define E1000_TXD_CMD_RS (1 << 3)
#define E1000_TXD_STAT_DD (1 << 0)

#define E1000_EECD_SK (1U << 0)
#define E1000_EECD_CS (1U << 1)
#define E1000_EECD_DI (1U << 2)
#define E1000_EECD_DO (1U << 3)
#define E1000_EECD_REQ (1U << 6)
#define E1000_EECD_GNT (1U << 7)

#define E1000_EERD_START (1U << 0)
#define E1000_EERD_DONE (1U << 4)

#define E1000_MDIC_READY (1U << 28)
#define E1000_MDIC_OP_READ (2U << 26)
#define E1000_MDIC_OP_MASK (3U << 26)

#define E1000_ICR_RXT0 (1U << 7)

#define EEPROM_SIZE 64
#define EEPROM_CHECKSUM_MAGIC 0xBABA

#define E1000_RXD_STAT_DD (1 << 0)
#define E1000_RXD_STAT_EOP (1 << 1)
#define RX_DESC_BUF_SIZE 2048

#define PHY_BMCR 0
#define PHY_BMSR 1
#define PHY_ID1 2
#define PHY_ID2 3
#define PHY_ADVERTISE 4
#define PHY_LPA 5
#define PHY_M88_SPEC 17

#define M88_PHY_ID1 0x0141
#define M88_PHY_ID2 0x0C50
#define PHY_BMSR_VAL 0x786D
#define PHY_BMCR_VAL 0x1140
#define PHY_ADVERTISE_VAL 0x01E1
#define PHY_M88_SPEC_VAL 0xAC08

#define PHY_BMSR_LINK_UP 0x0004

struct e1000_tx_desc
{
    uint64_t buffer_addr;
    uint16_t length;
    uint8_t cso, cmd, status, css;
    uint16_t special;
} __attribute__((packed));

struct e1000_rx_desc
{
    uint64_t buffer_addr;
    uint16_t length, csum;
    uint8_t status, errors;
    uint16_t special;
} __attribute__((packed));

struct e1000_device
{
    int fd, instance_fd, raw_sock, ifindex;
    void *bar0;
    size_t bar0_size;
    struct pciem_shared_ring *ring;
    int event_fd;
    bool running, link_up;
    uint8_t my_mac[6];

    uint64_t tx_ring_addr, rx_ring_addr;
    uint32_t tx_ring_len, rx_ring_len;
    uint16_t tx_head, tx_tail;
    uint16_t rx_head, rx_tail;

    uint16_t eeprom[EEPROM_SIZE];

    struct
    {
        bool last_sk;
        bool in_data;
        int bit_count;
        int data_bit;
        uint32_t shift_reg;
        uint16_t data_out;
    } eecd_sm;

    uint32_t icr_shadow;
    pthread_mutex_t icr_lock;

    pthread_t rx_thread;
    pthread_t event_thread;
};

static void e1000_eeprom_init(struct e1000_device *dev, const uint8_t *mac)
{
    memset(dev->eeprom, 0, sizeof(dev->eeprom));
    dev->eeprom[0] = (uint16_t)mac[0] | ((uint16_t)mac[1] << 8);
    dev->eeprom[1] = (uint16_t)mac[2] | ((uint16_t)mac[3] << 8);
    dev->eeprom[2] = (uint16_t)mac[4] | ((uint16_t)mac[5] << 8);
    dev->eeprom[0x0A] = 0x8000;

    uint16_t sum = 0;
    for (int i = 0; i < EEPROM_SIZE - 1; i++)
        sum += dev->eeprom[i];
    dev->eeprom[EEPROM_SIZE - 1] = EEPROM_CHECKSUM_MAGIC - sum;
}

static int dma_rw(struct e1000_device *dev, uint64_t guest_iova, void *buf, size_t len, bool to_guest)
{
    struct pciem_dma_op op = {
        .guest_iova = guest_iova,
        .user_addr = (uint64_t)buf,
        .length = len,
        .flags = to_guest ? PCIEM_DMA_FLAG_WRITE : PCIEM_DMA_FLAG_READ,
    };
    return ioctl(dev->fd, PCIEM_IOCTL_DMA, &op);
}

#define E1000_ICR_TXDW (1U << 0)

static void process_tx(struct e1000_device *dev)
{
    struct e1000_tx_desc desc;
    struct sockaddr_ll sll = {
        .sll_family = AF_PACKET,
        .sll_ifindex = dev->ifindex,
    };

    // ???: Being overly pessimistic here
    static uint8_t pkt_buf[16384];
    static uint32_t pkt_len = 0;
    bool trigger_irq = false;

    while (dev->tx_head != (uint16_t)__atomic_load_n(&dev->tx_tail, __ATOMIC_ACQUIRE))
    {
        uint64_t daddr = dev->tx_ring_addr + dev->tx_head * sizeof(desc);
        if (dma_rw(dev, daddr, &desc, sizeof(desc), false) != 0)
            break;

        bool is_ext = (desc.cmd & (1 << 5)) != 0;
        bool is_ctx = is_ext && ((desc.cso & 0xF0) == 0);

        if (!is_ctx && desc.length && desc.buffer_addr)
        {
            if (pkt_len + desc.length <= sizeof(pkt_buf))
            {
                dma_rw(dev, desc.buffer_addr, pkt_buf + pkt_len, desc.length, false);
                pkt_len += desc.length;
            }
        }

        if ((desc.cmd & E1000_TXD_CMD_EOP) && !is_ctx)
        {
            if (pkt_len > 0)
            {
                (void)sendto(dev->raw_sock, pkt_buf, pkt_len, 0, (struct sockaddr *)&sll, sizeof(sll));
            }
            pkt_len = 0;
        }

        desc.status |= E1000_TXD_STAT_DD;
        dma_rw(dev, daddr, &desc, sizeof(desc), true);

        if (desc.cmd & E1000_TXD_CMD_RS)
        {
            trigger_irq = true;
        }

        dev->tx_head = (dev->tx_head + 1) % (dev->tx_ring_len / sizeof(desc));
        *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_TDH) = dev->tx_head;
    }

    if (trigger_irq)
    {
        pthread_mutex_lock(&dev->icr_lock);
        dev->icr_shadow |= E1000_ICR_TXDW;
        *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_ICR) = dev->icr_shadow;
        pthread_mutex_unlock(&dev->icr_lock);

        struct pciem_irq_inject irq = {.vector = 0};
        ioctl(dev->fd, PCIEM_IOCTL_INJECT_IRQ, &irq);
    }
}

static bool e1000_rx_filter(struct e1000_device *dev, const uint8_t *pkt)
{
    if (memcmp(pkt, dev->my_mac, 6) == 0)
        return true;
    if (pkt[0] == 0xff && pkt[1] == 0xff && pkt[2] == 0xff && pkt[3] == 0xff && pkt[4] == 0xff && pkt[5] == 0xff)
        return true;
    if (pkt[0] & 0x01)
        return true;
    return false;
}

static void *rx_thread_func(void *arg)
{
    struct e1000_device *dev = arg;
    uint8_t pkt[65536];

    while (dev->running)
    {
        int n = recv(dev->raw_sock, pkt, sizeof(pkt), 0);
        if (n < 14)
            continue;
        if (!e1000_rx_filter(dev, pkt))
            continue;

        uint32_t ring_size = dev->rx_ring_len / sizeof(struct e1000_rx_desc);
        if (ring_size == 0)
            continue;

        int bytes_left = n;
        int offset = 0;

        while (bytes_left > 0)
        {
            uint16_t next_head = (dev->rx_head + 1) % ring_size;
            if (next_head == dev->rx_tail)
            {
                break;
            }

            uint64_t daddr = dev->rx_ring_addr + dev->rx_head * sizeof(struct e1000_rx_desc);
            struct e1000_rx_desc rxd;
            if (dma_rw(dev, daddr, &rxd, sizeof(rxd), false) != 0 || !rxd.buffer_addr)
                break;

            int chunk = (bytes_left > RX_DESC_BUF_SIZE) ? RX_DESC_BUF_SIZE : bytes_left;

            dma_rw(dev, rxd.buffer_addr, pkt + offset, chunk, true);

            rxd.length = chunk;
            rxd.status = E1000_RXD_STAT_DD;
            rxd.errors = 0;

            bytes_left -= chunk;
            offset += chunk;

            if (bytes_left == 0)
            {
                rxd.status |= E1000_RXD_STAT_EOP;
            }

            dma_rw(dev, daddr, &rxd, sizeof(rxd), true);

            dev->rx_head = next_head;
            *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_RDH) = dev->rx_head;
        }

        pthread_mutex_lock(&dev->icr_lock);
        dev->icr_shadow |= E1000_ICR_RXT0;
        *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_ICR) = dev->icr_shadow;
        pthread_mutex_unlock(&dev->icr_lock);

        struct pciem_irq_inject irq = {.vector = 0};
        ioctl(dev->fd, PCIEM_IOCTL_INJECT_IRQ, &irq);
    }
    return NULL;
}

static void e1000_handle_read(struct e1000_device *dev, struct pciem_event *ev)
{
    if (ev->bar != 0)
        return;
    if (ev->offset == E1000_ICR)
    {
        pthread_mutex_lock(&dev->icr_lock);
        dev->icr_shadow = 0;
        *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_ICR) = 0;
        pthread_mutex_unlock(&dev->icr_lock);
    }
}

static void e1000_handle_write(struct e1000_device *dev, struct pciem_event *ev)
{
    if (ev->bar != 0)
        return;

    uint32_t val = (uint32_t)(ev->data & ((1ULL << (ev->size * 8)) - 1));

    switch (ev->offset)
    {

    case E1000_CTRL:
        if (val & E1000_CTRL_RST)
        {
            val &= ~E1000_CTRL_RST;
            *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_CTRL) = val;
            *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_STATUS) = E1000_STATUS_1000FD;
            *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_RAL0) =
                (uint32_t)dev->my_mac[0] | ((uint32_t)dev->my_mac[1] << 8) | ((uint32_t)dev->my_mac[2] << 16) |
                ((uint32_t)dev->my_mac[3] << 24);
            *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_RAH0) =
                (uint32_t)dev->my_mac[4] | ((uint32_t)dev->my_mac[5] << 8) | (1U << 31);
            dev->tx_ring_addr = dev->rx_ring_addr = 0;
            dev->tx_ring_len = dev->rx_ring_len = 0;
            dev->tx_head = 0;
            __atomic_store_n(&dev->tx_tail, 0, __ATOMIC_RELEASE);
            *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_STATUS) = E1000_STATUS_1000FD;
            dev->rx_head = dev->rx_tail = 0;
            *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_TDH) = 0;
            *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_STATUS) &= ~E1000_STATUS_LU;
            dev->link_up = false;
            return;
        }
        if (val & E1000_CTRL_SLU)
        {
            dev->link_up = true;
            uint32_t status = *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_STATUS);
            *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_STATUS) = status | E1000_STATUS_1000FD;
        }
        break;

    case E1000_EECD: {
        bool new_sk = !!(val & E1000_EECD_SK);
        bool new_cs = !!(val & E1000_EECD_CS);

        if (val & E1000_EECD_REQ)
            val |= E1000_EECD_GNT;

        if (!new_cs)
        {
            dev->eecd_sm.last_sk = false;
            dev->eecd_sm.in_data = false;
            dev->eecd_sm.bit_count = 0;
            dev->eecd_sm.shift_reg = 0;
            dev->eecd_sm.data_out = 0;
            dev->eecd_sm.data_bit = 0;
        }
        else if (new_sk && !dev->eecd_sm.last_sk)
        {
            if (!dev->eecd_sm.in_data)
            {
                dev->eecd_sm.shift_reg = (dev->eecd_sm.shift_reg << 1) | (!!(val & E1000_EECD_DI));
                dev->eecd_sm.bit_count++;
                if (dev->eecd_sm.bit_count == 9)
                {
                    uint8_t opcode = (dev->eecd_sm.shift_reg >> 6) & 0x7;
                    uint8_t addr = dev->eecd_sm.shift_reg & 0x3F;
                    if (opcode == 0x6 && addr < EEPROM_SIZE)
                    {
                        dev->eecd_sm.data_out = dev->eeprom[addr];
                        dev->eecd_sm.data_bit = 15;
                        dev->eecd_sm.in_data = true;
                    }
                }
            }
            else
            {
                if ((dev->eecd_sm.data_out >> dev->eecd_sm.data_bit) & 1)
                    val |= E1000_EECD_DO;
                else
                    val &= ~E1000_EECD_DO;
                if (dev->eecd_sm.data_bit > 0)
                    dev->eecd_sm.data_bit--;
            }
        }
        dev->eecd_sm.last_sk = new_sk;
        *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_EECD) = val;
        return;
    }

    case E1000_ICS:
        pthread_mutex_lock(&dev->icr_lock);
        dev->icr_shadow |= val;
        *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_ICR) = dev->icr_shadow;
        pthread_mutex_unlock(&dev->icr_lock);
        {
            struct pciem_irq_inject irq = {.vector = 0};
            ioctl(dev->fd, PCIEM_IOCTL_INJECT_IRQ, &irq);
        }
        return;

    case E1000_EERD:
        if (val & E1000_EERD_START)
        {
            uint8_t addr = (val >> 8) & 0x7F;
            uint16_t data = (addr < EEPROM_SIZE) ? dev->eeprom[addr] : 0;
            uint32_t result = E1000_EERD_DONE | ((uint32_t)data << 16);
            *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_EERD) = result;
            return;
        }
        break;

    case E1000_MDIC: {
        uint8_t reg = (val >> 16) & 0x1F;
        uint32_t op = val & E1000_MDIC_OP_MASK;
        uint16_t data = 0;

        if (op == E1000_MDIC_OP_READ)
        {
            switch (reg)
            {
            case PHY_BMCR:
                data = PHY_BMCR_VAL;
                break;
            case PHY_BMSR:
                data = PHY_BMSR_VAL | PHY_BMSR_LINK_UP;
                break;
            case PHY_ID1:
                data = M88_PHY_ID1;
                break;
            case PHY_ID2:
                data = M88_PHY_ID2;
                break;
            case PHY_ADVERTISE:
                data = PHY_ADVERTISE_VAL;
                break;
            case PHY_LPA:
                data = 0x45E1;
                break;
            case PHY_M88_SPEC:
                data = PHY_M88_SPEC_VAL;
                break;
            }
            *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_MDIC) =
                E1000_MDIC_READY | (uint32_t)data | (val & 0x03FF0000U);
        }
        else
        {
            *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_MDIC) = E1000_MDIC_READY | (val & ~E1000_MDIC_OP_MASK);
        }
        return;
    }

    case E1000_TDBAL:
        dev->tx_ring_addr = (dev->tx_ring_addr & 0xffffffff00000000ULL) | val;
        break;
    case E1000_TDBAH:
        dev->tx_ring_addr = (dev->tx_ring_addr & 0x00000000ffffffffULL) | ((uint64_t)val << 32);
        break;
    case E1000_TDLEN:
        dev->tx_ring_len = val;
        break;
    case E1000_TDT:
        __atomic_store_n(&dev->tx_tail, (uint16_t)(val & 0xffff), __ATOMIC_RELEASE);
        process_tx(dev);
        break;

    case E1000_RDBAL:
        dev->rx_ring_addr = (dev->rx_ring_addr & 0xffffffff00000000ULL) | val;
        break;
    case E1000_RDBAH:
        dev->rx_ring_addr = (dev->rx_ring_addr & 0x00000000ffffffffULL) | ((uint64_t)val << 32);
        break;
    case E1000_RDLEN:
        dev->rx_ring_len = val;
        break;
    case E1000_RDT:
        dev->rx_tail = val & 0xffff;
        dev->rx_head = dev->rx_tail;
        *(volatile uint32_t *)((uint8_t *)dev->bar0 + E1000_RDH) = dev->rx_tail;
        break;

    case E1000_RAL0:
        dev->my_mac[0] = val & 0xFF;
        dev->my_mac[1] = (val >> 8) & 0xFF;
        dev->my_mac[2] = (val >> 16) & 0xFF;
        dev->my_mac[3] = (val >> 24) & 0xFF;
        break;
    case E1000_RAH0:
        dev->my_mac[4] = val & 0xFF;
        dev->my_mac[5] = (val >> 8) & 0xFF;
        break;

    default:
        break;
    }

    if (ev->size == 4 && ev->offset != E1000_STATUS)
        *(volatile uint32_t *)((uint8_t *)dev->bar0 + ev->offset) = val;
}

static void *e1000_mmio_event_thread(void *arg)
{
    struct e1000_device *dev = arg;
    struct pollfd pfd = {.fd = dev->event_fd, .events = POLLIN};
    int tmp;

    dev->running = true;

    while (dev->running)
    {
        if (poll(&pfd, 1, -1) <= 0)
            continue;
        read(dev->event_fd, &tmp, sizeof(tmp));

        int head = atomic_load(&dev->ring->head);
        int tail = atomic_load(&dev->ring->tail);

        while (head != tail)
        {
            struct pciem_event *ev = &dev->ring->events[head];

            if (ev->type == PCIEM_EVENT_MMIO_WRITE)
                e1000_handle_write(dev, ev);
            else if (ev->type == PCIEM_EVENT_MMIO_READ)
                e1000_handle_read(dev, ev);

            head = (head + 1) % PCIEM_RING_SIZE;
            atomic_store(&dev->ring->head, head);
            tail = atomic_load(&dev->ring->tail);
        }
    }
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <real_physical_interface>\n", argv[0]);
        return 1;
    }

    struct e1000_device dev = {0};
    pthread_mutex_init(&dev.icr_lock, NULL);

    const uint8_t mac[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
    memcpy(dev.my_mac, mac, 6);
    e1000_eeprom_init(&dev, mac);

    struct pciem_create_device create = {0};
    struct pciem_config_space cfg = {
        .vendor_id = 0x8086,
        .device_id = 0x100E,
        .subsys_vendor_id = 0x8086,
        .subsys_device_id = 0x100E,
        .revision = 0x03,
        .class_code = {0x00, 0x00, 0x02},
    };
    struct pciem_bar_config bar = {.bar_index = 0, .size = 128 * 1024};
    struct pciem_cap_config cap = {.cap_type = PCIEM_CAP_MSI, .msi = {.num_vectors_log2 = 0, .has_64bit = true}};
    struct pciem_trace_bar trace = {.bar_index = 0, .flags = PCIEM_TRACE_WRITES | PCIEM_TRACE_READS};

    dev.fd = open("/dev/pciem", O_RDWR);
    if (dev.fd < 0)
        err(1, "open /dev/pciem");

    ioctl(dev.fd, PCIEM_IOCTL_CREATE_DEVICE, &create);
    ioctl(dev.fd, PCIEM_IOCTL_SET_CONFIG, &cfg);
    ioctl(dev.fd, PCIEM_IOCTL_ADD_BAR, &bar);
    ioctl(dev.fd, PCIEM_IOCTL_ADD_CAPABILITY, &cap);
    ioctl(dev.fd, PCIEM_IOCTL_TRACE_BAR, &trace);

    dev.event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    struct pciem_eventfd_config efd = {.eventfd = dev.event_fd};
    ioctl(dev.fd, PCIEM_IOCTL_SET_EVENTFD, &efd);

    dev.instance_fd = ioctl(dev.fd, PCIEM_IOCTL_REGISTER);
    dev.bar0_size = 128 * 1024;
    dev.bar0 = mmap(NULL, dev.bar0_size, PROT_READ | PROT_WRITE, MAP_SHARED, dev.instance_fd, 0);
    if (dev.bar0 == MAP_FAILED)
        err(1, "mmap bar0");

    dev.ring = mmap(NULL, sizeof(struct pciem_shared_ring), PROT_READ | PROT_WRITE, MAP_SHARED, dev.fd, 0);
    if (dev.ring == MAP_FAILED)
        err(1, "mmap ring");

    *(volatile uint32_t *)((uint8_t *)dev.bar0 + E1000_STATUS) = E1000_STATUS_1000FD;
    *(volatile uint32_t *)((uint8_t *)dev.bar0 + E1000_RAL0) =
        (uint32_t)mac[0] | ((uint32_t)mac[1] << 8) | ((uint32_t)mac[2] << 16) | ((uint32_t)mac[3] << 24);
    *(volatile uint32_t *)((uint8_t *)dev.bar0 + E1000_RAH0) = (uint32_t)mac[4] | ((uint32_t)mac[5] << 8) | (1U << 31);
    *(volatile uint32_t *)((uint8_t *)dev.bar0 + E1000_EECD) = 0;

    dev.raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (dev.raw_sock < 0)
        err(1, "socket");

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);
    if (ioctl(dev.raw_sock, SIOCGIFINDEX, &ifr) < 0)
        err(1, "SIOCGIFINDEX");
    dev.ifindex = ifr.ifr_ifindex;

    struct sockaddr_ll sll = {.sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL), .sll_ifindex = dev.ifindex};
    bind(dev.raw_sock, (struct sockaddr *)&sll, sizeof(sll));

    struct packet_mreq mr = {.mr_ifindex = dev.ifindex, .mr_type = PACKET_MR_PROMISC};
    setsockopt(dev.raw_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));

    pthread_create(&dev.rx_thread, NULL, rx_thread_func, &dev);
    pthread_create(&dev.event_thread, NULL, e1000_mmio_event_thread, &dev);

    ioctl(dev.fd, PCIEM_IOCTL_START, 0);

    printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigprocmask(SIG_BLOCK, &mask, NULL);

    int sig;
    sigwait(&mask, &sig);

    dev.running = false;

    pthread_join(dev.event_thread, NULL);
    pthread_join(dev.rx_thread, NULL);

    pthread_mutex_destroy(&dev.icr_lock);
    close(dev.raw_sock);
    munmap(dev.bar0, dev.bar0_size);
    munmap(dev.ring, sizeof(*dev.ring));
    close(dev.instance_fd);
    close(dev.event_fd);
    close(dev.fd);
    return 0;
}
