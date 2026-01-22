#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/pci_regs.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "pciem_userspace.h"
#include "protopciem_device.h"

#define QEMU_SOCKET_PATH "/tmp/pciem_qemu.sock"

#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif

#define MSG_REGISTER_WRITE 1
#define MSG_REGISTER_READ 2
#define MSG_RAISE_IRQ 3
#define MSG_DMA_READ 4
#define MSG_DMA_WRITE 5

struct qemu_msg
{
    uint32_t type;
    uint32_t offset;
    uint64_t value;
    uint64_t addr;
    uint32_t len;
} __attribute__((packed));

struct qemu_resp
{
    uint32_t status;
    uint64_t value;
} __attribute__((packed));

struct device_state
{
    volatile uint32_t *bar0;
    volatile uint32_t *bar2;
    size_t bar0_size;
    size_t bar2_size;
    int pciem_fd;
    int instance_fd;
    int qemu_sock;
    int event_fd;
    int irq_fd;
    atomic_t running;
    int qemu_connected;
    pthread_t qemu_thread;
    uint8_t *dma_bounce_buf;

    pthread_mutex_t sock_lock;
    pthread_cond_t ack_cond;
    volatile int waiting_for_ack;
    struct qemu_resp last_resp;

    struct pciem_shared_ring *event_ring;
};

static struct device_state dev_state;

static int dev_running(struct device_state *st)
{
    return atomic_load(&st->running);
}

static void dev_stop(struct device_state *st)
{
    atomic_store(&st->running, 0);
}

static void signal_handler(int signum)
{
    printf("\n[\x1b[31m*\x1b[0m] %d received, trying to exit...\n", signum);
    dev_stop(&dev_state);
}

static int create_qemu_socket(void)
{
    int sock;
    struct sockaddr_un addr;

    unlink(QEMU_SOCKET_PATH);

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("Failed to create socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, QEMU_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Failed to bind socket");
        close(sock);
        return -1;
    }

    if (listen(sock, 1) < 0)
    {
        perror("Failed to listen on socket");
        close(sock);
        return -1;
    }

    printf("[\x1b[32m*\x1b[0m] Socket at: %s\n", QEMU_SOCKET_PATH);
    printf("[\x1b[33m*\x1b[0m] Waiting for QEMU to connect...\n");

    return sock;
}

static int wait_for_qemu_connection(int listen_sock)
{
    int client_sock;
    struct sockaddr_un client_addr;
    socklen_t client_len = sizeof(client_addr);

    client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &client_len);
    if (client_sock < 0)
    {
        perror("Failed to accept connection");
        return -1;
    }

    printf("[\x1b[32m*\x1b[0m] QEMU connected!\n");
    return client_sock;
}

static int writen(int fd, const void *buf, size_t n)
{
    size_t written = 0;
    while (written < n)
    {
        ssize_t r = write(fd, (const char *)buf + written, n - written);
        if (r <= 0)
        {
            if (r < 0 && errno == EINTR) continue;
            return -1;
        }
        written += r;
    }
    return 0;
}

static int send_register_write_sync(uint32_t offset, uint32_t value)
{
    struct qemu_msg msg;
    struct timespec timeout;
    int ret;

    msg.type = MSG_REGISTER_WRITE;
    msg.offset = offset;
    msg.value = value;

    pthread_mutex_lock(&dev_state.sock_lock);

    if (write(dev_state.qemu_sock, &msg, sizeof(msg)) != sizeof(msg))
    {
        perror("Socket write failed");
        pthread_mutex_unlock(&dev_state.sock_lock);
        return -1;
    }

    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += 10;
    
    dev_state.waiting_for_ack = 1;
    while (dev_state.waiting_for_ack)
    {
        ret = pthread_cond_timedwait(&dev_state.ack_cond, &dev_state.sock_lock, &timeout);
        if (ret == ETIMEDOUT) {
            printf("[!] QEMU timeout on reg 0x%x, disconnecting\n", offset);
            dev_state.waiting_for_ack = 0;
            dev_state.qemu_connected = 0;
            pthread_mutex_unlock(&dev_state.sock_lock);
            return -1;
        }
    }
    
    pthread_mutex_unlock(&dev_state.sock_lock);
    return 0;
}

static int forward_command_to_qemu(void)
{
    if (send_register_write_sync(REG_CONTROL, dev_state.bar0[REG_CONTROL / 4]) < 0) return -1;
    if (send_register_write_sync(REG_DATA, dev_state.bar0[REG_DATA / 4]) < 0) return -1;
    if (send_register_write_sync(REG_DMA_SRC_LO, dev_state.bar0[REG_DMA_SRC_LO / 4]) < 0) return -1;
    if (send_register_write_sync(REG_DMA_SRC_HI, dev_state.bar0[REG_DMA_SRC_HI / 4]) < 0) return -1;
    if (send_register_write_sync(REG_DMA_DST_LO, dev_state.bar0[REG_DMA_DST_LO / 4]) < 0) return -1;
    if (send_register_write_sync(REG_DMA_DST_HI, dev_state.bar0[REG_DMA_DST_HI / 4]) < 0) return -1;
    if (send_register_write_sync(REG_DMA_LEN, dev_state.bar0[REG_DMA_LEN / 4]) < 0) return -1;
    if (send_register_write_sync(REG_CMD, dev_state.bar0[REG_CMD / 4]) < 0) return -1;
    return 0;
}

static void inject_irq(uint32_t vector)
{
    if (dev_state.irq_fd >= 0)
    {
        uint64_t val = 1;
        ssize_t ret = write(dev_state.irq_fd, &val, sizeof(val));
        if (ret != sizeof(val))
        {
            struct pciem_irq_inject irq = {.vector = vector};
            ioctl(dev_state.pciem_fd, PCIEM_IOCTL_INJECT_IRQ, &irq);
        }
    }
    else
    {
        struct pciem_irq_inject irq = {.vector = vector};
        ioctl(dev_state.pciem_fd, PCIEM_IOCTL_INJECT_IRQ, &irq);
    }
}

static void *qemu_handler_thread(void *arg)
{
    struct qemu_msg msg;
    struct qemu_resp resp;
    uint32_t header;
    (void) arg;

    while (dev_running(&dev_state) && dev_state.qemu_connected)
    {
        ssize_t n = read(dev_state.qemu_sock, &header, sizeof(header));
        if (n != sizeof(header))
        {
            if (n == 0)
                printf("[\x1b[31m!\x1b[0m] QEMU connection closed!\n");
            else
                perror("Socket read failed");
            dev_state.qemu_connected = 0;
            break;
        }

        if (header == MSG_DMA_READ || header == MSG_RAISE_IRQ)
        {
            msg.type = header;
            n = read(dev_state.qemu_sock, ((char *)&msg) + 4, sizeof(msg) - 4);
            if (n != sizeof(msg) - 4)
                break;

            if (msg.type == MSG_DMA_READ)
            {
                struct pciem_dma_op dma_op = {.guest_iova = msg.addr,
                                              .user_addr = (uint64_t)dev_state.dma_bounce_buf,
                                              .length = msg.len,
                                              .flags = PCIEM_DMA_FLAG_READ,
                                              .pasid = 0};

                if (ioctl(dev_state.pciem_fd, PCIEM_IOCTL_DMA, &dma_op) < 0)
                {
                    perror("[X] DMA read failed");
                    resp.status = -1;
                }
                else
                {
                    resp.status = 0;
                }

                pthread_mutex_lock(&dev_state.sock_lock);
                if (write(dev_state.qemu_sock, &resp, sizeof(resp)) != sizeof(resp))
                {
                    perror("Socket write failed");
                    pthread_mutex_unlock(&dev_state.sock_lock);
                    break;
                }

                if (resp.status == 0)
                {
                    if (writen(dev_state.qemu_sock, dev_state.dma_bounce_buf, msg.len) < 0) {
                        perror("Failed to write DMA data to QEMU");
                        pthread_mutex_unlock(&dev_state.sock_lock);
                        break;
                    }
                }
                pthread_mutex_unlock(&dev_state.sock_lock);
            }
            else if (msg.type == MSG_RAISE_IRQ)
            {
                uint32_t status = msg.offset;
                uint64_t result = msg.value;

                dev_state.bar0[REG_STATUS / 4] = status;
                dev_state.bar0[REG_RESULT_LO / 4] = (uint32_t)(result & 0xFFFFFFFF);
                dev_state.bar0[REG_RESULT_HI / 4] = (uint32_t)(result >> 32);
                dev_state.bar0[REG_CMD / 4] = 0;

                inject_irq(0);
            }
        }
        else
        {
            resp.status = header;
            n = read(dev_state.qemu_sock, ((char *)&resp) + 4, sizeof(resp) - 4);
            if (n != sizeof(resp) - 4)
                break;

            pthread_mutex_lock(&dev_state.sock_lock);
            if (dev_state.waiting_for_ack)
            {
                dev_state.last_resp = resp;
                dev_state.waiting_for_ack = 0;
                pthread_cond_signal(&dev_state.ack_cond);
            }
            pthread_mutex_unlock(&dev_state.sock_lock);
        }
    }

    printf("[\x1b[31m!\x1b[0m] QEMU forwarding stopped\n");
    return NULL;
}

static void process_command_local(void)
{
    uint32_t cmd = dev_state.bar0[REG_CMD / 4];
    uint32_t data = dev_state.bar0[REG_DATA / 4];
    uint64_t result = 0;
    uint32_t status = STATUS_DONE;

    switch (cmd)
    {
    case CMD_ADD:
        result = (uint64_t)data + data;
        break;
    case CMD_MULTIPLY:
        result = (uint64_t)data * data;
        break;
    case CMD_XOR:
        result = data ^ 0xFFFFFFFF;
        break;
    default:
        status |= STATUS_ERROR;
        break;
    }

    dev_state.bar0[REG_RESULT_LO / 4] = (uint32_t)(result & 0xFFFFFFFF);
    dev_state.bar0[REG_RESULT_HI / 4] = (uint32_t)(result >> 32);
    dev_state.bar0[REG_STATUS / 4] = status;
    dev_state.bar0[REG_CMD / 4] = 0;

    inject_irq(0);
}

static int setup_watchpoints(void)
{
    struct pciem_watchpoint_config wp;
    wp.bar_index = 0;
    wp.offset = REG_CMD;
    wp.width = 4;
    wp.flags = 1;
    int ret = ioctl(dev_state.pciem_fd, PCIEM_IOCTL_SET_WATCHPOINT, &wp);
    if (ret < 0 && errno == EAGAIN)
        return -EAGAIN;
    return ret;
}

static int setup_eventfd(void)
{
    struct pciem_eventfd_config efd_cfg;
    
    dev_state.event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (dev_state.event_fd < 0)
    {
        perror("Failed to create eventfd");
        return -1;
    }

    efd_cfg.eventfd = dev_state.event_fd;
    efd_cfg.reserved = 0;

    if (ioctl(dev_state.pciem_fd, PCIEM_IOCTL_SET_EVENTFD, &efd_cfg) < 0)
    {
        perror("Failed to set eventfd");
        close(dev_state.event_fd);
        dev_state.event_fd = -1;
        return -1;
    }

    printf("[\x1b[32m*\x1b[0m] Eventfd configured: fd=%d\n", dev_state.event_fd);
    return 0;
}

static int setup_irq_fd(void)
{
    struct pciem_irqfd_config irq_cfg;

    dev_state.irq_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (dev_state.irq_fd < 0)
    {
        perror("Failed to create IRQ eventfd");
        return -1;
    }

    irq_cfg.eventfd = dev_state.irq_fd;
    irq_cfg.vector = 0;
    irq_cfg.flags = 0;
    irq_cfg.reserved = 0;

    if (ioctl(dev_state.pciem_fd, PCIEM_IOCTL_SET_IRQFD, &irq_cfg) < 0)
    {
        perror("Failed to set IRQ eventfd");
        close(dev_state.irq_fd);
        dev_state.irq_fd = -1;
        return -1;
    }

    printf("[\x1b[32m*\x1b[0m] IRQ eventfd configured: fd=%d\n", dev_state.irq_fd);
    return 0;
}

static void handle_bar0_write(struct device_state *st, struct pciem_event *event)
{
    volatile uint32_t *bar0 = st->bar0;

    switch (event->offset)
    {
    case REG_CMD: {
        uint32_t cmd = bar0[REG_CMD / 4];

        if (!cmd)
            return;

        bar0[REG_STATUS / 4] = STATUS_BUSY;
        if (st->qemu_connected &&
            (cmd == CMD_EXECUTE_CMDBUF || cmd == CMD_DMA_FRAME))
        {
            if (forward_command_to_qemu() < 0)
                printf("[!] Failed to forward command to QEMU!\n");
        } else {
            process_command_local();
        }
        break;
    }
    default:
        return;
    }
}

static void handle_event(struct device_state *st, struct pciem_event *event)
{
    if (event->type == PCIEM_EVENT_MMIO_WRITE && event->bar == 0)
        handle_bar0_write(st, event);
}

static int register_device(struct device_state *st)
{
    struct pciem_create_device create = {0};
    struct pciem_bar_config bar0 = {
        .bar_index = 0,
        .size = PCIEM_BAR0_SIZE,
        .flags = PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64,
    };
    struct pciem_bar_config bar2 = {
        .bar_index = 2,
        .size = PCIEM_BAR2_SIZE,
        .flags = PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64 |
                 PCI_BASE_ADDRESS_MEM_PREFETCH,
    };
    struct pciem_config_space cfg = {
        .vendor_id = PCIEM_PCI_VENDOR_ID,
        .device_id = PCIEM_PCI_DEVICE_ID,
        .class_code = {0x00, 0x00, 0x0b}
    };
    struct pciem_cap_config cap = {
        .cap_type = PCIEM_CAP_MSI,
        .msi = {
            .has_64bit = 1,
            .has_masking = 1,
        },
    };

    st->pciem_fd = open("/dev/pciem", O_RDWR);
    if (st->pciem_fd < 0) {
        warn("open(/dev/pciem)");
        return -1;
    }

    ioctl(st->pciem_fd, PCIEM_IOCTL_CREATE_DEVICE, &create);
    ioctl(st->pciem_fd, PCIEM_IOCTL_ADD_BAR, &bar0);
    ioctl(st->pciem_fd, PCIEM_IOCTL_ADD_BAR, &bar2);
    ioctl(st->pciem_fd, PCIEM_IOCTL_ADD_CAPABILITY, &cap);
    ioctl(st->pciem_fd, PCIEM_IOCTL_SET_CONFIG, &cfg);

    st->instance_fd = ioctl(st->pciem_fd, PCIEM_IOCTL_REGISTER, 0);
    if (st->instance_fd < 0) {
        warn("PCIEM_IOCTL_REGISTER");
        return -1;
    }

    return 0;
}

static int map_device(struct device_state *st)
{
    st->bar0_size = PCIEM_BAR0_SIZE;
    st->bar0 = mmap(NULL, dev_state.bar0_size, PROT_READ | PROT_WRITE,
                    MAP_SHARED, st->instance_fd, 0 * 4096);
    if (st->bar0 == MAP_FAILED) {
        warn("mmap BAR0 failed");
        return -1;
    }

    st->bar2_size = PCIEM_BAR2_SIZE;
    st->bar2 = mmap(NULL, dev_state.bar2_size, PROT_READ | PROT_WRITE,
                    MAP_SHARED, st->instance_fd, 2 * 4096);
    if (st->bar2 == MAP_FAILED) {
        warn("mmap BAR2 failed");
        return -1;
    }

    printf("[\x1b[32m*\x1b[0m] BARs mapped successfully via Instance FD\n");

    st->event_ring = mmap(NULL, sizeof(struct pciem_shared_ring),
                          PROT_READ | PROT_WRITE, MAP_SHARED,
                          st->pciem_fd, 0);
    if (st->event_ring == MAP_FAILED) {
        warn("mmap shared event ring failed");
        return -1;
    }

    return 0;
}

static void init_device(struct device_state *st)
{
    st->pciem_fd = -1;

    pthread_mutex_init(&st->sock_lock, NULL);
    pthread_cond_init(&st->ack_cond, NULL);

    st->instance_fd = -1;
    atomic_store(&st->running, 0);
    st->qemu_connected = 0;

    st->event_ring = MAP_FAILED;
    st->bar0 = MAP_FAILED;
    st->bar2 = MAP_FAILED;

    st->qemu_sock = -1;
    st->dma_bounce_buf = NULL;
    st->event_fd = -1;
    st->irq_fd = -1;
}

static void destroy_device(struct device_state *st)
{
    if (st->event_fd >= 0)
        close(st->event_fd);

    if (st->irq_fd >= 0)
    {
        close(st->irq_fd);
        st->irq_fd = -1;
    }

    if (st->dma_bounce_buf)
        free(st->dma_bounce_buf);

    if (st->qemu_sock >= 0)
        close(st->qemu_sock);

    if (st->event_ring != MAP_FAILED)
        munmap(st->event_ring, sizeof(struct pciem_shared_ring));
    if (st->bar2 != MAP_FAILED)
        munmap((void *)st->bar2, st->bar2_size);
    if (st->bar0 != MAP_FAILED)
        munmap((void *)st->bar0, st->bar0_size);

    if (st->instance_fd >= 0)
        close(st->instance_fd);

    pthread_mutex_destroy(&st->sock_lock);
    pthread_cond_destroy(&st->ack_cond);

    if (st->pciem_fd >= 0)
        close(st->pciem_fd);
}

int main(void)
{
    int listen_sock = -1;
    struct sigaction sa;

    if (geteuid() != 0)
    {
        fprintf(stderr, "ERROR: Must run as root\n");
        return 1;
    }

    init_device(&dev_state);
    atomic_store(&dev_state.running, 1);
    if (register_device(&dev_state) < 0)
        goto cleanup;

    printf("[\x1b[32m*\x1b[0m] Device registered, got instance FD: %d\n",
       dev_state.instance_fd);

    if (map_device(&dev_state) < 0)
        goto cleanup;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    listen_sock = create_qemu_socket();
    if (listen_sock < 0)
        goto cleanup;

    fd_set readfds;
    struct timeval timeout = {10, 0};
    FD_ZERO(&readfds);
    FD_SET(listen_sock, &readfds);

    if (select(listen_sock + 1, &readfds, NULL, NULL, &timeout) > 0)
    {
        dev_state.qemu_sock = wait_for_qemu_connection(listen_sock);
        if (dev_state.qemu_sock >= 0)
        {
            dev_state.qemu_connected = 1;
            dev_state.dma_bounce_buf = malloc(4 * 1024 * 1024);
            pthread_create(&dev_state.qemu_thread, NULL, qemu_handler_thread, NULL);
            printf("[\x1b[32m*\x1b[0m] QEMU forwarding mode\n");
        }
    }
    else
    {
        printf("[X] QEMU socket not found, running internal emulation...\n");
    }

    {
        int retry_count = 0;
        while (dev_running(&dev_state) && retry_count < 2000)
        {
            int ret = setup_watchpoints();
            if (ret == 0)
            {
                printf("[\x1b[32m*\x1b[0m] Watchpoints enabled successfully\n");
                break;
            }
            if (errno != EAGAIN)
            {
                printf("[!] Watchpoint setup failed: %s (continuing without watchpoints)\n", strerror(errno));
                break;
            }
            retry_count++;
            usleep(100000);
        }
    }

    if (setup_eventfd() < 0)
    {
        printf("[!] Failed to setup eventfd, falling back to busy polling\n");
    }

    if (setup_irq_fd() < 0)
    {
        printf("[!] Failed to setup IRQ eventfd, falling back to ioctl\n");
    }

    printf("[\x1b[32m*\x1b[0m] Starting event consumer...\n");
    while (dev_running(&dev_state))
    {
        if (dev_state.event_fd >= 0)
        {
            fd_set rfds;
            struct timeval tv;
            int ret;

            FD_ZERO(&rfds);
            FD_SET(dev_state.event_fd, &rfds);

            tv.tv_sec = 1;
            tv.tv_usec = 0;

            ret = select(dev_state.event_fd + 1, &rfds, NULL, NULL, &tv);
            if (ret < 0)
            {
                if (errno == EINTR)
                    continue;
                perror("select() failed");
                break;
            }
            else if (ret > 0)
            {
                uint64_t efd_count;
                if (read(dev_state.event_fd, &efd_count, sizeof(efd_count)) < 0)
                {
                    if (errno != EAGAIN)
                        perror("eventfd read failed");
                }
            }
        }

        int head = atomic_load(&dev_state.event_ring->head);
        int tail = atomic_load(&dev_state.event_ring->tail);
        
        if (head == tail) {
            // TODO: Maybe yield?
            continue;
        }

        struct pciem_event *event = &dev_state.event_ring->events[head];

        atomic_thread_fence(memory_order_acquire);
        handle_event(&dev_state, event);
        atomic_store(&dev_state.event_ring->head, (head + 1) % PCIEM_RING_SIZE);
    }

cleanup:
    printf("\n[\x1b[31m*\x1b[0m] Exit\n");

    if (dev_state.qemu_connected)
    {
        dev_stop(&dev_state);
        pthread_join(dev_state.qemu_thread, NULL);
        if (dev_state.dma_bounce_buf)
        {
            free(dev_state.dma_bounce_buf);
            dev_state.dma_bounce_buf = NULL;
        }
    }

    if (listen_sock >= 0)
        close(listen_sock);

    destroy_device(&dev_state);

    unlink(QEMU_SOCKET_PATH);
    return 0;
}
