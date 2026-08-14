// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025-2026 Joel Bueno
 *   Author(s): Joel Bueno <buenocalvachejoel@gmail.com>
 *              Carlos López <carlos.lopezr4096@gmail.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": pool: " fmt

#include "pool.h"

#include <linux/bitmap.h>
#include <linux/genalloc.h>
#include <linux/mm.h>

struct pciem_mempool {
    phys_addr_t         base;
    resource_size_t     total_size;
    struct gen_pool     *pool;
    struct resource     res;
};

static struct pciem_mempool pciem_pool = {
    .res = {
        .name = "PCIem BAR pool",
        .flags = IORESOURCE_MEM,
    },
};

struct pciem_data_align {
    resource_size_t align;
};

/*
 * Almost identical copy of gen_pool_first_fit_align in linux/lib/genalloc.c
 * The only difference is pciem_data_align which takes a resource_size_t rather than an int.
 */
static unsigned long pciem_first_fit_align(unsigned long *map, unsigned long size,
                                           unsigned long start, unsigned int nr, void *data,
                                           struct gen_pool *pool, unsigned long start_addr)
{
    struct pciem_data_align *alignment;
    unsigned long align_mask, align_off;
    int order;

    alignment = data;
    order = pool->min_alloc_order;
    align_mask = ((alignment->align + (1UL << order) - 1) >> order) - 1;
    align_off = (start_addr & (alignment->align - 1)) >> order;

    return bitmap_find_next_zero_area_off(map, size, start, nr, align_mask, align_off);
}

phys_addr_t pciem_pool_alloc(resource_size_t size)
{
    struct pciem_data_align align_data;
    unsigned long addr;

    if (!pciem_pool.pool) {
        pr_err("No physical memory pool configured.\n");
        pr_err("Pass pciem_phys_region=0xADDR:0xSIZE at insmod.\n");
        return 0;
    }

    if (!size || (size & (size - 1))) {
        pr_err("Allocation size 0x%llx is not a power of 2\n", (u64)size);
        return 0;
    }

    align_data.align = size;

    addr = gen_pool_alloc_algo(pciem_pool.pool, size, pciem_first_fit_align, &align_data);
    if (!addr) {
        pr_err("Out of pool memory.\n");
        return 0;
    }

    pr_info("Allocated 0x%llx bytes at phys 0x%llx (pool offset 0x%llx)\n",
            (u64)size, (u64)addr, (u64)(addr - pciem_pool.base));
    return addr;
}

void pciem_pool_free(phys_addr_t addr, resource_size_t size)
{
    if (!pciem_pool.pool)
        return;

    if (!addr || addr < pciem_pool.base || addr + size > pciem_pool.base + pciem_pool.total_size) {
        pr_warn("Cannot free phys 0x%llx: outside of pool\n", (u64)addr);
        return;
    }

    gen_pool_free(pciem_pool.pool, addr, size);

    pr_info("Freed 0x%llx bytes at phys 0x%llx, 0x%llx bytes available\n",
            (u64)size, (u64)addr, (u64)gen_pool_avail(pciem_pool.pool));
}

int pciem_pool_init(const char *phys_region)
{
    phys_addr_t base;
    resource_size_t size;
    struct resource *res = &pciem_pool.res;
    struct gen_pool *pool;
    int ret;

    if (!phys_region || !*phys_region) {
        pr_info("No phys_region specified\n");
        return 0;
    }

    if (sscanf(phys_region, "0x%llx:0x%llx",
               (unsigned long long *)&base,
               (unsigned long long *)&size) != 2 &&
        sscanf(phys_region, "%llx:%llx",
               (unsigned long long *)&base,
               (unsigned long long *)&size) != 2) {
        pr_err("Cannot parse phys_region=\"%s\"\n", phys_region);
        return -EINVAL;
    }

    if (!size || (size & (size - 1))) {
        pr_err("Region size 0x%llx must be a power of 2\n", (u64)size);
        return -EINVAL;
    }

    res->start = base;
    res->end = base + size - 1;

    if (insert_resource(&iomem_resource, res)) {
        pr_err("Failed to claim [0x%llx-0x%llx] in iomem\n",
               (u64)base, (u64)(base + size - 1));
        return -EBUSY;
    }

    pool = gen_pool_create(PAGE_SHIFT, -1);
    if (!pool) {
        ret = -ENOMEM;
        goto err_release;
    }

    ret = gen_pool_add(pool, base, size, -1);
    if (ret)
        goto err_destroy;

    pciem_pool.base = base;
    pciem_pool.total_size = size;
    pciem_pool.pool = pool;

    pr_info("BAR pool ready [0x%llx – 0x%llx]\n",
            (u64)base, (u64)(base + size - 1));
    return 0;

err_destroy:
    gen_pool_destroy(pool);
err_release:
    release_resource(res);
    return ret;
}

void pciem_pool_exit(void)
{
    struct gen_pool *pool = pciem_pool.pool;

    if (!pool)
        return;

    pciem_pool.pool = NULL;
    pciem_pool.total_size = 0;

    gen_pool_destroy(pool);
    release_resource(&pciem_pool.res);
    pr_info("BAR pool released\n");
}

int pciem_pool_insert(struct resource *res)
{
    return insert_resource(&pciem_pool.res, res);
}
