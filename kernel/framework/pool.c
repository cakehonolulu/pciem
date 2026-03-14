// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025-2026 Joel Bueno
 *   Author(s): Joel Bueno <buenocalvachejoel@gmail.com>
 *              Carlos López <carlos.lopezr4096@gmail.com>
 */
 #include "pool.h"

#include <linux/slab.h>

struct pciem_mempool {
    phys_addr_t         base;
    resource_size_t     total_size;
    resource_size_t     next_offset;
    spinlock_t          lock;
    struct resource     res;
};

static struct pciem_mempool pciem_pool = {
    .lock = __SPIN_LOCK_UNLOCKED(pciem_pool.lock),
    .res = {
        .name = "PCIem BAR pool",
        .flags = IORESOURCE_MEM,
    },
};

phys_addr_t pciem_pool_alloc(resource_size_t size)
{
    phys_addr_t addr;
    resource_size_t aligned_offset;
    unsigned long flags;

    if (!pciem_pool.total_size) {
        pr_err("pool: No physical memory pool configured.\n");
        pr_err("pool: Pass pciem_phys_region=0xADDR:0xSIZE at insmod.\n");
        return 0;
    }

    if (!size || (size & (size - 1))) {
        pr_err("pool: Allocation size 0x%llx is not a power of 2\n", (u64)size);
        return 0;
    }

    spin_lock_irqsave(&pciem_pool.lock, flags);

    aligned_offset = ALIGN(pciem_pool.next_offset, size);

    if (aligned_offset + size > pciem_pool.total_size) {
        spin_unlock_irqrestore(&pciem_pool.lock, flags);
        pr_err("pool: Out of pool memory.\n");
        return 0;
    }

    addr = pciem_pool.base + aligned_offset;
    pciem_pool.next_offset = aligned_offset + size;

    spin_unlock_irqrestore(&pciem_pool.lock, flags);

    pr_info("pool: Allocated 0x%llx bytes at phys 0x%llx (pool offset 0x%llx)\n",
            (u64)size, (u64)addr, (u64)aligned_offset);
    return addr;
}

int pciem_pool_init(const char *phys_region)
{
    phys_addr_t base;
    resource_size_t size;
    struct resource *res = &pciem_pool.res;

    if (!phys_region || !*phys_region) {
        pr_info("pool: No phys_region specified\n");
        return 0;
    }

    if (sscanf(phys_region, "0x%llx:0x%llx",
               (unsigned long long *)&base,
               (unsigned long long *)&size) != 2 &&
        sscanf(phys_region, "%llx:%llx",
               (unsigned long long *)&base,
               (unsigned long long *)&size) != 2) {
        pr_err("pool: Cannot parse phys_region=\"%s\"\n", phys_region);
        return -EINVAL;
    }

    if (!size || (size & (size - 1))) {
        pr_err("pool: Region size 0x%llx must be a power of 2\n", (u64)size);
        return -EINVAL;
    }

    res->start = base;
    res->end = base + size - 1;

    if (insert_resource(&iomem_resource, res)) {
        pr_err("pool: Failed to claim [0x%llx-0x%llx] in iomem\n",
               (u64)base, (u64)(base + size - 1));
        kfree(res);
        return -EBUSY;
    }

    pciem_pool.base = base;
    pciem_pool.total_size = size;
    pciem_pool.next_offset = 0;

    pr_info("pool: BAR pool ready [0x%llx – 0x%llx]\n",
            (u64)base, (u64)(base + size - 1));
    return 0;
}

void pciem_pool_exit(void)
{
    if (!pciem_pool.total_size)
        return;

    release_resource(&pciem_pool.res);

    pciem_pool.total_size = 0;
    pr_info("pool: BAR pool released\n");
}

int pciem_pool_insert(struct resource *res)
{
    return insert_resource(&pciem_pool.res, res);
}
