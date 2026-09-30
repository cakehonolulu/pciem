// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025-2026 Joel Bueno
 *   Author(s): Joel Bueno <buenocalvachejoel@gmail.com>
 *              Carlos López <carlos.lopezr4096@gmail.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": dma: " fmt

#include "pciem.h"
#include "dma.h"

#include <asm/cacheflush.h>
#include <linux/atomic.h>
#include <linux/cleanup.h>
#include <linux/dma-mapping.h>
#include <linux/iommu.h>
#include <linux/mm.h>
#include <linux/slab.h>

struct pciem_dma_mapping {
    void *addr;
    bool is_ram;
};

static int pciem_map_phys(struct pciem_dma_mapping *m, phys_addr_t paddr, size_t len)
{
    m->is_ram = !!pfn_valid(PHYS_PFN(paddr));
    if (m->is_ram)
        m->addr = phys_to_virt(paddr);
    else
        m->addr = memremap(paddr, len, MEMREMAP_WB);

    return m->addr ? 0 : -EFAULT;
}

static void pciem_unmap_phys(struct pciem_dma_mapping *m)
{
    if (m->addr && !m->is_ram)
        memunmap(m->addr);
}

DEFINE_FREE(pciem_unmap_phys, struct pciem_dma_mapping, pciem_unmap_phys(&_T))

static inline phys_addr_t translate_iova_once(struct iommu_domain *domain,
                                              dma_addr_t iova)
{
    return domain ? iommu_iova_to_phys(domain, iova) : iova;
}

static phys_addr_t *translate_iova(struct pciem_root_complex *v, dma_addr_t guest_iova,
                                   size_t len, unsigned int *num_pages)
{
    struct iommu_domain *domain = iommu_get_domain_for_dev(&v->pciem_pdev->dev);
    phys_addr_t *pages __free(kfree) = NULL;
    dma_addr_t iova, iova_start, iova_end;
    size_t max_pages, page_count = 0;
    int ret;

    iova_start = PAGE_ALIGN_DOWN(guest_iova);
    iova_end = PAGE_ALIGN(guest_iova + len);
    max_pages = (iova_end - iova_start) >> PAGE_SHIFT;

    pr_debug_ratelimited("translate: 0x%llx (0x%llx - 0x%llx) (%lu pages)",
            guest_iova, iova_start, iova_end, max_pages);

    pages = kmalloc_array(max_pages, sizeof(phys_addr_t), GFP_KERNEL);
    if (!pages) {
        ret = -ENOMEM;
        goto fail;
    }

    ret = -EFAULT;
    for (iova = iova_start; iova < iova_end; iova += PAGE_SIZE, ++page_count) {
        pages[page_count] = translate_iova_once(domain, iova);
        if (!pages[page_count])
            goto fail;
    }

    *num_pages = page_count;
    return no_free_ptr(pages);

    return 0;

fail:
    pr_err("failed to translate IOVA=%llx (%d)", guest_iova, ret);
    return ERR_PTR(ret);
}

int pciem_dma_read_from_guest(struct pciem_root_complex *v, u64 guest_iova,
                              void *dst, size_t len, u32 pasid)
{
    phys_addr_t *pages = NULL;
    unsigned int i, num_pages;
    size_t dst_offset = 0;
    int ret;

    if (!v || !dst || !len)
        return -EINVAL;

    pages = translate_iova(v, guest_iova, len, &num_pages);
    if (IS_ERR(pages))
        return PTR_ERR(pages);

    pr_debug_ratelimited("read:  src=0x%llx dst=0x%lx len=0x%lx (%u pages) PASID %u\n",
            guest_iova, (size_t)dst, len, num_pages, pasid);

    for (i = 0; i < num_pages; ++i) {
        size_t src_offset = (i == 0) ? offset_in_page(guest_iova) : 0;
        size_t chunk_len = min_t(size_t, PAGE_SIZE - src_offset, len - dst_offset);
        struct pciem_dma_mapping src __free(pciem_unmap_phys) = {};

        ret = pciem_map_phys(&src, pages[i], PAGE_SIZE);
        if (ret) {
            kfree(pages);
            return ret;
        }

        dma_sync_single_for_cpu(&v->pciem_pdev->dev,
                                (dma_addr_t)(pages[i] + src_offset),
                                chunk_len, DMA_FROM_DEVICE);

        pr_debug_ratelimited("read%u: src=0x%lx dst=0x%lx len=0x%lx (pa=%llx)",
                i, (size_t)src.addr + src_offset, (size_t)dst + dst_offset,
                chunk_len, pages[i] + src_offset);

        memcpy(dst + dst_offset, src.addr + src_offset, chunk_len);

        dst_offset += chunk_len;
    }

    kfree(pages);
    return 0;
}
EXPORT_SYMBOL(pciem_dma_read_from_guest);

int pciem_dma_write_to_guest(struct pciem_root_complex *v, u64 guest_iova,
                             const void *src, size_t len, u32 pasid)
{
    phys_addr_t *pages;
    unsigned int i, num_pages;
    size_t src_offset = 0;
    int ret;

    if (!v || !src || !len)
        return -EINVAL;

    pages = translate_iova(v, guest_iova, len, &num_pages);
    if (IS_ERR(pages))
        return PTR_ERR(pages);

    pr_debug_ratelimited("write:  src=0x%lx dst=0x%llx len=0x%lx (%u pages) PASID %u\n",
            (size_t)src, guest_iova, len, num_pages, pasid);

    for (i = 0; i < num_pages; ++i) {
        unsigned int dst_offset = (i == 0) ? offset_in_page(guest_iova) : 0;
        size_t chunk_len = min_t(size_t, PAGE_SIZE - dst_offset, len - src_offset);
        struct pciem_dma_mapping dst __free(pciem_unmap_phys) = {};

        ret = pciem_map_phys(&dst, pages[i], PAGE_SIZE);
        if (ret) {
            kfree(pages);
            return -ENOMEM;
        }

       pr_debug_ratelimited("write%u: src=0x%lx dst=0x%lx len=0x%lx (pa=%llx)",
                i, (size_t)src + src_offset, (size_t)dst.addr + dst_offset,
                chunk_len, pages[i] + dst_offset);

        memcpy(dst.addr + dst_offset, src + src_offset, chunk_len);

        dma_sync_single_for_device(&v->pciem_pdev->dev,
                                   (dma_addr_t)(pages[i] + dst_offset),
                                   chunk_len, DMA_TO_DEVICE);

        src_offset += chunk_len;
    }

    kfree(pages);
    return 0;
}
EXPORT_SYMBOL(pciem_dma_write_to_guest);

static u64 do_atomic_op(struct pciem_root_complex *v, u64 guest_iova, u8 op_type, u64 operand, u64 compare, u32 pasid)
{
    struct iommu_domain *domain = iommu_get_domain_for_dev(&v->pciem_pdev->dev);
    struct pciem_dma_mapping m __free(pciem_unmap_phys) = {};
    phys_addr_t phys_addr;
    u64 old_val = 0;
    int ret;

    if (!IS_ALIGNED(guest_iova, 8)) {
        pr_err("Atomic operation on unaligned address 0x%llx\n", guest_iova);
        return 0;
    }

    phys_addr = translate_iova_once(domain, PAGE_ALIGN_DOWN(guest_iova));
    if (!phys_addr) {
        pr_err("Failed to translate IOVA for atomic op\n");
        return 0;
    }

    ret = pciem_map_phys(&m, phys_addr + offset_in_page(guest_iova), 8);
    if (ret) {
        pr_err("Failed to map page for atomic op\n");
        return 0;
    }

    if (!IS_ALIGNED((unsigned long)m.addr, 8)) {
        pr_err("Mapped address not 8-byte aligned: %px\n", m.addr);
        return 0;
    }

    switch (op_type)
    {
    case PCIEM_ATOMIC_FETCH_ADD:
        old_val = atomic64_fetch_add(operand, m.addr);
        pr_info("Atomic FETCH_ADD: IOVA 0x%llx, old=0x%llx, add=0x%llx, PASID %u\n", guest_iova, old_val, operand,
                pasid);
        break;

    case PCIEM_ATOMIC_FETCH_SUB:
        old_val = atomic64_fetch_sub(operand, m.addr);
        pr_info("Atomic FETCH_SUB: IOVA 0x%llx, old=0x%llx, sub=0x%llx, PASID %u\n", guest_iova, old_val, operand,
                pasid);
        break;

    case PCIEM_ATOMIC_SWAP:
        old_val = atomic64_xchg(m.addr, operand);
        pr_info("Atomic SWAP: IOVA 0x%llx, old=0x%llx, new=0x%llx, PASID %u\n", guest_iova, old_val, operand, pasid);
        break;

    case PCIEM_ATOMIC_CAS:
        old_val = atomic64_cmpxchg(m.addr, compare, operand);
        pr_info("Atomic CAS: IOVA 0x%llx, old=0x%llx, expected=0x%llx, new=0x%llx, PASID %u\n", guest_iova, old_val,
                compare, operand, pasid);
        break;

    case PCIEM_ATOMIC_FETCH_AND:
        old_val = atomic64_fetch_and(operand, m.addr);
        pr_info("Atomic FETCH_AND: IOVA 0x%llx, old=0x%llx, mask=0x%llx, PASID %u\n", guest_iova, old_val, operand,
                pasid);
        break;

    case PCIEM_ATOMIC_FETCH_OR:
        old_val = atomic64_fetch_or(operand, m.addr);
        pr_info("Atomic FETCH_OR: IOVA 0x%llx, old=0x%llx, bits=0x%llx, PASID %u\n", guest_iova, old_val, operand,
                pasid);
        break;

    case PCIEM_ATOMIC_FETCH_XOR:
        old_val = atomic64_fetch_xor(operand, m.addr);
        pr_info("Atomic FETCH_XOR: IOVA 0x%llx, old=0x%llx, bits=0x%llx, PASID %u\n", guest_iova, old_val, operand,
                pasid);
        break;

    default:
        pr_err("Unknown atomic operation type %u\n", op_type);
        break;
    }

    return old_val;
}

u64 pciem_dma_atomic_fetch_add(struct pciem_root_complex *v, u64 guest_iova, u64 val, u32 pasid)
{
    return do_atomic_op(v, guest_iova, PCIEM_ATOMIC_FETCH_ADD, val, 0, pasid);
}
EXPORT_SYMBOL(pciem_dma_atomic_fetch_add);

u64 pciem_dma_atomic_fetch_sub(struct pciem_root_complex *v, u64 guest_iova, u64 val, u32 pasid)
{
    return do_atomic_op(v, guest_iova, PCIEM_ATOMIC_FETCH_SUB, val, 0, pasid);
}
EXPORT_SYMBOL(pciem_dma_atomic_fetch_sub);

u64 pciem_dma_atomic_swap(struct pciem_root_complex *v, u64 guest_iova, u64 val, u32 pasid)
{
    return do_atomic_op(v, guest_iova, PCIEM_ATOMIC_SWAP, val, 0, pasid);
}
EXPORT_SYMBOL(pciem_dma_atomic_swap);

u64 pciem_dma_atomic_cas(struct pciem_root_complex *v, u64 guest_iova, u64 expected, u64 new_val, u32 pasid)
{
    return do_atomic_op(v, guest_iova, PCIEM_ATOMIC_CAS, new_val, expected, pasid);
}
EXPORT_SYMBOL(pciem_dma_atomic_cas);

u64 pciem_dma_atomic_fetch_and(struct pciem_root_complex *v, u64 guest_iova, u64 val, u32 pasid)
{
    return do_atomic_op(v, guest_iova, PCIEM_ATOMIC_FETCH_AND, val, 0, pasid);
}
EXPORT_SYMBOL(pciem_dma_atomic_fetch_and);

u64 pciem_dma_atomic_fetch_or(struct pciem_root_complex *v, u64 guest_iova, u64 val, u32 pasid)
{
    return do_atomic_op(v, guest_iova, PCIEM_ATOMIC_FETCH_OR, val, 0, pasid);
}
EXPORT_SYMBOL(pciem_dma_atomic_fetch_or);

u64 pciem_dma_atomic_fetch_xor(struct pciem_root_complex *v, u64 guest_iova, u64 val, u32 pasid)
{
    return do_atomic_op(v, guest_iova, PCIEM_ATOMIC_FETCH_XOR, val, 0, pasid);
}
EXPORT_SYMBOL(pciem_dma_atomic_fetch_xor);
