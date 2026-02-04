// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025-2026 Joel Bueno
 *   Author(s): Joel Bueno <buenocalvachehjoel@gmail.com>
 *              Carlos López <carlos.lopezr4096@gmail.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "pciem_dma.h"
#include "pciem_framework.h"
#include <asm/cacheflush.h>
#include <linux/atomic.h>
#include <linux/iommu.h>
#include <linux/mm.h>
#include <linux/slab.h>

static int translate_iova(struct pciem_root_complex *v, dma_addr_t guest_iova,
                          size_t len, phys_addr_t **phys_pages_out,
                          unsigned int *num_pages)
{
    struct iommu_domain *domain = iommu_get_domain_for_dev(&v->pciem_pdev->dev);
    dma_addr_t iova, iova_start, iova_end;
    size_t max_pages, page_count = 0;
    phys_addr_t *pages = NULL;
    int ret;

    iova_start = PAGE_ALIGN_DOWN(guest_iova);
    iova_end = PAGE_ALIGN(guest_iova + len);
    max_pages = (iova_end - iova_start) >> PAGE_SHIFT;

    pr_info("DMA: translate: 0x%llx (0x%llx - 0x%llx) (%lu pages)",
            guest_iova, iova_start, iova_end, max_pages);

    pages = kmalloc_array(max_pages, sizeof(phys_addr_t), GFP_KERNEL);
    if (!pages) {
        ret = -ENOMEM;
        goto fail;
    }

    for (iova = iova_start; iova < iova_end; iova += PAGE_SIZE) {
        phys_addr_t hpa;

        if (domain) {
            hpa = iommu_iova_to_phys(domain, iova);
            if (!hpa) {
                ret = -EFAULT;
                goto fail;
            }
        } else {
            hpa = iova;
        }

        pages[page_count++] = hpa;
    }

    *num_pages = page_count;
    *phys_pages_out = pages;

    return 0;

fail:
    pr_err("failed to translate IOVA=%llx (%d)", guest_iova, ret);
    if (pages)
        kfree(pages);
    return ret;
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

    ret = translate_iova(v, guest_iova, len, &pages, &num_pages);
    if (ret)
        return ret;

    pr_info("DMA: read:  src=0x%llx dst=0x%lx len=0x%lx (%u pages) PASID %u\n",
            guest_iova, (size_t)dst, len, num_pages, pasid);

    for (i = 0; i < num_pages; ++i) {
        void *src;
        size_t src_offset = (i == 0) ? offset_in_page(guest_iova) : 0;
        size_t chunk_len = min_t(size_t, PAGE_SIZE - src_offset, len - dst_offset);

        src = memremap(pages[i], PAGE_SIZE, MEMREMAP_WB);
        if (!src) {
            kfree(pages);
            return -ENOMEM;
        }

        pr_info("DMA: read%u: src=0x%lx dst=0x%lx len=0x%lx (pa=%llx)",
                i, (size_t)src + src_offset, (size_t)dst + dst_offset,
                chunk_len, pages[i] + src_offset);

        memcpy(dst + dst_offset, src + src_offset, chunk_len);
        memunmap(src);

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

    ret = translate_iova(v, guest_iova, len, &pages, &num_pages);
    if (ret)
        return ret;

    pr_info("DMA: write:  src=0x%lx dst=0x%llx len=0x%lx (%u pages) PASID %u\n",
            (size_t)src, guest_iova, len, num_pages, pasid);

    for (i = 0; i < num_pages; ++i) {
        void *dst;
        unsigned int dst_offset = (i == 0) ? offset_in_page(guest_iova) : 0;
        size_t chunk_len = min_t(size_t, PAGE_SIZE - dst_offset, len - src_offset);

        dst = memremap(pages[i], PAGE_SIZE, MEMREMAP_WB);
        if (!dst) {
            kfree(pages);
            return -ENOMEM;
        }

        pr_info("DMA: write%u: src=0x%lx dst=0x%lx len=0x%lx (pa=%llx)",
                i, (size_t)src + src_offset, (size_t)dst + dst_offset,
                chunk_len, pages[i] + dst_offset);

        memcpy(dst + dst_offset, src + src_offset, chunk_len);
        memunmap(dst);
        src_offset += chunk_len;
    }

    kfree(pages);
    return 0;
}
EXPORT_SYMBOL(pciem_dma_write_to_guest);

static u64 do_atomic_op(struct pciem_root_complex *v, u64 guest_iova, u8 op_type, u64 operand, u64 compare, u32 pasid)
{
    phys_addr_t phys_addr;
    void *kva;
    u64 old_val = 0;
    phys_addr_t *phys_pages = NULL;
    int num_pages;
    atomic64_t *atomic_ptr;
    int ret;

    if (guest_iova & 0x7)
    {
        pr_err("Atomic operation on unaligned address 0x%llx\n", guest_iova);
        return 0;
    }

    ret = translate_iova(v, guest_iova, 8, &phys_pages, &num_pages);
    if (ret < 0)
    {
        pr_err("Failed to translate IOVA for atomic op\n");
        return 0;
    }

    phys_addr = phys_pages[0];
    kfree(phys_pages);

    kva = memremap(phys_addr, 8, MEMREMAP_WB);
    if (!kva)
    {
        pr_err("Failed to map page for atomic op\n");
        return 0;
    }

    if (!IS_ALIGNED((unsigned long)kva, 8))
    {
        pr_err("Mapped address not 8-byte aligned: %px\n", kva);
        memunmap(kva);
        return 0;
    }

    atomic_ptr = (atomic64_t *)kva;

    switch (op_type)
    {
    case PCIEM_ATOMIC_FETCH_ADD:
        old_val = atomic64_fetch_add(operand, atomic_ptr);
        pr_info("Atomic FETCH_ADD: IOVA 0x%llx, old=0x%llx, add=0x%llx, PASID %u\n", guest_iova, old_val, operand,
                pasid);
        break;

    case PCIEM_ATOMIC_FETCH_SUB:
        old_val = atomic64_fetch_sub(operand, atomic_ptr);
        pr_info("Atomic FETCH_SUB: IOVA 0x%llx, old=0x%llx, sub=0x%llx, PASID %u\n", guest_iova, old_val, operand,
                pasid);
        break;

    case PCIEM_ATOMIC_SWAP:
        old_val = atomic64_xchg(atomic_ptr, operand);
        pr_info("Atomic SWAP: IOVA 0x%llx, old=0x%llx, new=0x%llx, PASID %u\n", guest_iova, old_val, operand, pasid);
        break;

    case PCIEM_ATOMIC_CAS:
        old_val = atomic64_cmpxchg(atomic_ptr, compare, operand);
        pr_info("Atomic CAS: IOVA 0x%llx, old=0x%llx, expected=0x%llx, new=0x%llx, PASID %u\n", guest_iova, old_val,
                compare, operand, pasid);
        break;

    case PCIEM_ATOMIC_FETCH_AND:
        old_val = atomic64_fetch_and(operand, atomic_ptr);
        pr_info("Atomic FETCH_AND: IOVA 0x%llx, old=0x%llx, mask=0x%llx, PASID %u\n", guest_iova, old_val, operand,
                pasid);
        break;

    case PCIEM_ATOMIC_FETCH_OR:
        old_val = atomic64_fetch_or(operand, atomic_ptr);
        pr_info("Atomic FETCH_OR: IOVA 0x%llx, old=0x%llx, bits=0x%llx, PASID %u\n", guest_iova, old_val, operand,
                pasid);
        break;

    case PCIEM_ATOMIC_FETCH_XOR:
        old_val = atomic64_fetch_xor(operand, atomic_ptr);
        pr_info("Atomic FETCH_XOR: IOVA 0x%llx, old=0x%llx, bits=0x%llx, PASID %u\n", guest_iova, old_val, operand,
                pasid);
        break;

    default:
        pr_err("Unknown atomic operation type %u\n", op_type);
        break;
    }

    memunmap(kva);

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
