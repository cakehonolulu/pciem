#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

struct ProtoPCIemMessage
{
    uint8_t type;
    uint8_t size;
    uint16_t reserved;
    uint64_t addr;
    uint64_t data;
} __attribute__((packed));

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

#define DMA_CHUNK_SIZE (64 * 1024)

struct shim_req
{
    uint32_t id;
    uint32_t type;
    uint32_t size;
    uint64_t addr;
    uint64_t data;
} __attribute__((packed));

struct shim_resp
{
    uint32_t id;
    uint64_t data;
} __attribute__((packed));

#define PCIEM_SHIM_IOC_MAGIC 'R'
#define PCIEM_SHIM_IOCTL_RAISE_IRQ _IOW(PCIEM_SHIM_IOC_MAGIC, 3, int)
#define PCIEM_SHIM_IOCTL_LOWER_IRQ _IOW(PCIEM_SHIM_IOC_MAGIC, 4, int)

struct shim_dma_read_op
{
    uint64_t host_phys_addr;
    uint64_t user_buf_addr;
    uint32_t len;
    uint32_t padding;
};
#define PCIEM_SHIM_IOCTL_DMA_READ _IOWR(PCIEM_SHIM_IOC_MAGIC, 5, struct shim_dma_read_op)

static int connect_socket(const char *path)
{
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0)
    {
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(s);
        return -1;
    }
    return s;
}

static int readn(int fd, void *buf, size_t n)
{
    size_t r = 0;
    while (r < n)
    {
        ssize_t m = read(fd, ((char *)buf) + r, n - r);
        if (m == 0)
        {
            return 0;
        }
        if (m < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        r += m;
    }
    return (int)r;
}

static int writen(int fd, const void *buf, size_t n)
{
    size_t w = 0;
    while (w < n)
    {
        ssize_t m = write(fd, ((const char *)buf) + w, n - w);
        if (m <= 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        w += m;
    }
    return (int)w;
}

static int handle_dma_read(int sock, int shim, struct ProtoPCIemMessage *inc)
{
    uint64_t src_addr = inc->addr;
    uint64_t dst_addr = inc->data;
    uint32_t len = ((uint32_t)inc->reserved << 8) | inc->size;

    printf("[PROXY] DMA_READ: src=0x%llx dst=0x%llx len=%u\n", (unsigned long long)src_addr,
           (unsigned long long)dst_addr, len);

    uint32_t aligned_len = (len + 7) & ~7;
    if (aligned_len == 0)
    {
        return 0;
    }

    char *buf = malloc(aligned_len);
    if (!buf)
    {
        perror("[PROXY] malloc DMA buf");
        return -1;
    }

    struct shim_dma_read_op op;
    op.host_phys_addr = src_addr;
    op.user_buf_addr = (uint64_t)buf;
    op.len = aligned_len;

    if (ioctl(shim, PCIEM_SHIM_IOCTL_DMA_READ, &op) < 0)
    {
        perror("[PROXY] ioctl(DMA_READ) failed");
        free(buf);
        return -1;
    }

    size_t bytes_sent = 0;
    while (bytes_sent < aligned_len)
    {
        size_t chunk_len = DMA_CHUNK_SIZE;
        if (bytes_sent + chunk_len > aligned_len)
        {
            chunk_len = aligned_len - bytes_sent;
        }

        struct ProtoPCIemMessage chunk_header;
        chunk_header.type = MSG_DMA_WRITE_CHUNK;
        chunk_header.addr = dst_addr + bytes_sent;
        chunk_header.data = 0;
        chunk_header.size = (uint8_t)(chunk_len & 0xFF);
        chunk_header.reserved = (uint16_t)((chunk_len >> 8) & 0xFFFF);

        if (writen(sock, &chunk_header, sizeof(chunk_header)) != sizeof(chunk_header))
        {
            perror("[PROXY] write DMA_WRITE_CHUNK header");
            free(buf);
            return -1;
        }

        if (writen(sock, buf + bytes_sent, chunk_len) != (int)chunk_len)
        {
            perror("[PROXY] write DMA_WRITE_CHUNK data");
            free(buf);
            return -1;
        }

        bytes_sent += chunk_len;
    }
    free(buf);

    struct ProtoPCIemMessage dma_done;
    memset(&dma_done, 0, sizeof(dma_done));
    dma_done.type = MSG_DMA_WRITE;
    dma_done.size = 0;

    if (writen(sock, &dma_done, sizeof(dma_done)) != sizeof(dma_done))
    {
        perror("[PROXY] write DMA_WRITE complete");
        return -1;
    }

    printf("[PROXY] DMA transfer complete (%u bytes)\n", aligned_len);

    return 0;
}

static int handle_async_message(int sock, int shim, struct ProtoPCIemMessage *msg)
{
    switch (msg->type)
    {
    case MSG_IRQ_RAISE: {
        printf("[PROXY] IRQ_RAISE\n");
        int zero = 0;
        if (ioctl(shim, PCIEM_SHIM_IOCTL_RAISE_IRQ, &zero) < 0)
        {
            perror("[PROXY] ioctl(RAISE_IRQ)");
            return -1;
        }
        break;
    }

    case MSG_IRQ_LOWER: {
        int zero = 0;
        if (ioctl(shim, PCIEM_SHIM_IOCTL_LOWER_IRQ, &zero) < 0)
        {
            perror("[PROXY] ioctl(LOWER_IRQ)");
            return -1;
        }
        break;
    }

    case MSG_DMA_READ:
        return handle_dma_read(sock, shim, msg);

    case MSG_CMD_DONE:
        printf("[PROXY] Received CMD_DONE, raising IRQ\n");
        int zero = 0;
        if (ioctl(shim, PCIEM_SHIM_IOCTL_RAISE_IRQ, &zero) < 0)
        {
            perror("[PROXY] ioctl(RAISE_IRQ)");
            return -1;
        }
        break;

    default:
        printf("[PROXY] Unknown async message type %u\n", msg->type);
        break;
    }

    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s /tmp/pciem.sock /dev/pciem_shim\n", argv[0]);
        return 1;
    }

    const char *sockpath = argv[1];
    const char *shimdev = argv[2];

    int sock = connect_socket(sockpath);
    if (sock < 0)
    {
        perror("connect socket");
        return 2;
    }

    int shim = open(shimdev, O_RDWR);
    if (shim < 0)
    {
        perror("open shim");
        close(sock);
        return 3;
    }

    printf("[PROXY] Connected to %s and %s\n", sockpath, shimdev);

    struct pollfd pfd[2];
    pfd[0].fd = shim;
    pfd[0].events = POLLIN;
    pfd[1].fd = sock;
    pfd[1].events = POLLIN;

    while (1)
    {
        int rc = poll(pfd, 2, 1);
        if (rc < 0)
        {
            if (errno == EINTR)
                continue;
            perror("poll");
            break;
        }

        if (pfd[0].revents & POLLIN)
        {
            struct shim_req req;
            int r = readn(shim, &req, sizeof(req));
            if (r <= 0)
            {
                perror("read shim");
                break;
            }

            printf("[PROXY] MMIO %s: addr=0x%llx size=%u data=0x%llx\n", req.type == 1 ? "READ" : "WRITE",
                   (unsigned long long)req.addr, req.size, (unsigned long long)req.data);

            struct ProtoPCIemMessage am;
            memset(&am, 0, sizeof(am));
            am.type = (req.type == 1) ? MSG_MMIO_READ : MSG_MMIO_WRITE;
            am.size = (uint8_t)req.size;
            am.reserved = 0;
            am.addr = req.addr;
            am.data = req.data;

            if (writen(sock, &am, sizeof(am)) != sizeof(am))
            {
                perror("[PROXY] write socket");
                break;
            }

            if (am.type == MSG_MMIO_READ)
            {
                while (1)
                {
                    struct ProtoPCIemMessage inc;
                    int rr = readn(sock, &inc, sizeof(inc));
                    if (rr <= 0)
                    {
                        perror("[PROXY] read socket (waiting for read reply)");
                        goto out;
                    }

                    if (inc.type == MSG_MMIO_READ_REPLY && inc.addr == am.addr && inc.size == am.size)
                    {

                        struct shim_resp resp;
                        resp.id = req.id;
                        resp.data = inc.data;

                        if (writen(shim, &resp, sizeof(resp)) != sizeof(resp))
                        {
                            perror("[PROXY] write shim resp");
                            goto out;
                        }

                        printf("[PROXY] READ reply: data=0x%llx\n", (unsigned long long)inc.data);
                        break;
                    }

                    if (handle_async_message(sock, shim, &inc) < 0)
                    {
                        goto out;
                    }
                }
            }
            else
            {
                struct shim_resp resp;
                resp.id = req.id;
                resp.data = 0;

                if (writen(shim, &resp, sizeof(resp)) != sizeof(resp))
                {
                    perror("[PROXY] write shim resp (for write ack)");
                    goto out;
                }
                printf("[PROXY] WRITE ack: id=%u\n", req.id);
            }
        }

        if (pfd[1].revents & POLLIN)
        {
            struct ProtoPCIemMessage inc;
            int rr = readn(sock, &inc, sizeof(inc));
            if (rr <= 0)
            {
                perror("[PROXY] read socket (async)");
                goto out;
            }

            if (handle_async_message(sock, shim, &inc) < 0)
            {
                goto out;
            }
        }
    }

out:
    close(shim);
    close(sock);
    return 0;
}