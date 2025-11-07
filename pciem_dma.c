#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "pciem_dma.h"
#include "pciem_framework.h"
#include <asm/cacheflush.h>
#include <linux/atomic.h>
#include <linux/iommu.h>
#include <linux/mm.h>
#include <linux/slab.h>

static int translate_iova(struct pciem_host *v, u64 guest_iova, size_t len, phys_addr_t *phys_pages, int *num_pages)
{
    struct iommu_domain *domain;
    size_t remaining = len;
    u64 iova = guest_iova;
    int page_count = 0;

    domain = iommu_get_domain_for_dev(&v->protopciem_pdev->dev);

    if (!domain)
    {
        phys_pages[0] = (phys_addr_t)guest_iova;
        *num_pages = 1;
        return 0;
    }

    while (remaining > 0)
    {
        phys_addr_t hpa;
        size_t chunk_len;

        hpa = iommu_iova_to_phys(domain, iova);
        if (!hpa)
        {
            pr_err("Failed to translate IOVA 0x%llx\n", iova);
            return -EFAULT;
        }

        phys_pages[page_count++] = hpa;

        chunk_len = min_t(size_t, remaining, PAGE_SIZE - (iova & ~PAGE_MASK));
        remaining -= chunk_len;
        iova += chunk_len;
    }

    *num_pages = page_count;
    return 0;
}

int pciem_dma_read_from_guest(struct pciem_host *v, u64 guest_iova, void *dst, size_t len, u32 pasid)
{
    phys_addr_t phys_pages[32];
    int num_pages = 0;
    size_t offset = 0;
    int i;

    if (!v || !dst || len == 0)
    {
        return -EINVAL;
    }

    if (len > sizeof(phys_pages) / sizeof(phys_pages[0]) * PAGE_SIZE)
    {
        pr_err("DMA read too large: %zu bytes\n", len);
        return -EINVAL;
    }

    if (translate_iova(v, guest_iova, len, phys_pages, &num_pages) < 0)
    {
        return -EFAULT;
    }

    pr_info("DMA read: IOVA 0x%llx -> %d pages, len %zu, PASID %u\n", guest_iova, num_pages, len, pasid);

    for (i = 0; i < num_pages && offset < len; i++)
    {
        void *kva;
        size_t chunk_len;
        size_t page_offset = (i == 0) ? (guest_iova & ~PAGE_MASK) : 0;

        chunk_len = min_t(size_t, len - offset, PAGE_SIZE - page_offset);

        kva = memremap(phys_pages[i] + page_offset, chunk_len, MEMREMAP_WB);
        if (!kva)
        {
            pr_err("Failed to map physical page %pa\n", &phys_pages[i]);
            return -ENOMEM;
        }

        clflush_cache_range(kva, chunk_len);
        memcpy((u8 *)dst + offset, kva, chunk_len);
        memunmap(kva);

        offset += chunk_len;
    }

    return 0;
}
EXPORT_SYMBOL(pciem_dma_read_from_guest);

int pciem_dma_write_to_guest(struct pciem_host *v, u64 guest_iova, const void *src, size_t len, u32 pasid)
{
    phys_addr_t phys_pages[32];
    int num_pages = 0;
    size_t offset = 0;
    int i;

    if (!v || !src || len == 0)
    {
        return -EINVAL;
    }

    if (len > sizeof(phys_pages) / sizeof(phys_pages[0]) * PAGE_SIZE)
    {
        pr_err("DMA write too large: %zu bytes\n", len);
        return -EINVAL;
    }

    if (translate_iova(v, guest_iova, len, phys_pages, &num_pages) < 0)
    {
        return -EFAULT;
    }

    pr_info("DMA write: IOVA 0x%llx -> %d pages, len %zu, PASID %u\n", guest_iova, num_pages, len, pasid);

    for (i = 0; i < num_pages && offset < len; i++)
    {
        void *kva;
        size_t chunk_len;
        size_t page_offset = (i == 0) ? (guest_iova & ~PAGE_MASK) : 0;

        chunk_len = min_t(size_t, len - offset, PAGE_SIZE - page_offset);

        kva = memremap(phys_pages[i] + page_offset, chunk_len, MEMREMAP_WB);
        if (!kva)
        {
            pr_err("Failed to map physical page %pa\n", &phys_pages[i]);
            return -ENOMEM;
        }

        memcpy(kva, (u8 *)src + offset, chunk_len);
        clflush_cache_range(kva, chunk_len);
        memunmap(kva);

        offset += chunk_len;
    }

    return 0;
}
EXPORT_SYMBOL(pciem_dma_write_to_guest);

static u64 do_atomic_op(struct pciem_host *v, u64 guest_iova, u8 op_type, u64 operand, u64 compare, u32 pasid)
{
    phys_addr_t phys_addr;
    void *kva;
    u64 old_val = 0;
    phys_addr_t phys_pages[1];
    int num_pages;

    if (guest_iova & 0x7)
    {
        pr_err("Atomic operation on unaligned address 0x%llx\n", guest_iova);
        return 0;
    }

    if (translate_iova(v, guest_iova, 8, phys_pages, &num_pages) < 0)
    {
        pr_err("Failed to translate IOVA for atomic op\n");
        return 0;
    }

    phys_addr = phys_pages[0];

    kva = memremap(phys_addr, 8, MEMREMAP_WB);
    if (!kva)
    {
        pr_err("Failed to map page for atomic op\n");
        return 0;
    }

    switch (op_type)
    {
    case PCIEM_ATOMIC_FETCH_ADD:
        old_val = atomic64_fetch_add(operand, (atomic64_t *)kva);
        pr_info("Atomic FETCH_ADD: IOVA 0x%llx, old=0x%llx, add=0x%llx, PASID %u\n", guest_iova, old_val, operand,
                pasid);
        break;

    case PCIEM_ATOMIC_FETCH_SUB:
        old_val = atomic64_fetch_sub(operand, (atomic64_t *)kva);
        pr_info("Atomic FETCH_SUB: IOVA 0x%llx, old=0x%llx, sub=0x%llx, PASID %u\n", guest_iova, old_val, operand,
                pasid);
        break;

    case PCIEM_ATOMIC_SWAP:
        old_val = atomic64_xchg((atomic64_t *)kva, operand);
        pr_info("Atomic SWAP: IOVA 0x%llx, old=0x%llx, new=0x%llx, PASID %u\n", guest_iova, old_val, operand, pasid);
        break;

    case PCIEM_ATOMIC_CAS:
        old_val = atomic64_cmpxchg((atomic64_t *)kva, compare, operand);
        pr_info("Atomic CAS: IOVA 0x%llx, old=0x%llx, expected=0x%llx, new=0x%llx, PASID %u\n", guest_iova, old_val,
                compare, operand, pasid);
        break;

    case PCIEM_ATOMIC_FETCH_AND:
        old_val = atomic64_fetch_and(operand, (atomic64_t *)kva);
        pr_info("Atomic FETCH_AND: IOVA 0x%llx, old=0x%llx, mask=0x%llx, PASID %u\n", guest_iova, old_val, operand,
                pasid);
        break;

    case PCIEM_ATOMIC_FETCH_OR:
        old_val = atomic64_fetch_or(operand, (atomic64_t *)kva);
        pr_info("Atomic FETCH_OR: IOVA 0x%llx, old=0x%llx, bits=0x%llx, PASID %u\n", guest_iova, old_val, operand,
                pasid);
        break;

    case PCIEM_ATOMIC_FETCH_XOR:
        old_val = atomic64_fetch_xor(operand, (atomic64_t *)kva);
        pr_info("Atomic FETCH_XOR: IOVA 0x%llx, old=0x%llx, bits=0x%llx, PASID %u\n", guest_iova, old_val, operand,
                pasid);
        break;

    default:
        pr_err("Unknown atomic operation type %u\n", op_type);
        break;
    }

    clflush_cache_range(kva, 8);
    memunmap(kva);

    return old_val;
}

u64 pciem_dma_atomic_fetch_add(struct pciem_host *v, u64 guest_iova, u64 val, u32 pasid)
{
    return do_atomic_op(v, guest_iova, PCIEM_ATOMIC_FETCH_ADD, val, 0, pasid);
}
EXPORT_SYMBOL(pciem_dma_atomic_fetch_add);

u64 pciem_dma_atomic_fetch_sub(struct pciem_host *v, u64 guest_iova, u64 val, u32 pasid)
{
    return do_atomic_op(v, guest_iova, PCIEM_ATOMIC_FETCH_SUB, val, 0, pasid);
}
EXPORT_SYMBOL(pciem_dma_atomic_fetch_sub);

u64 pciem_dma_atomic_swap(struct pciem_host *v, u64 guest_iova, u64 val, u32 pasid)
{
    return do_atomic_op(v, guest_iova, PCIEM_ATOMIC_SWAP, val, 0, pasid);
}
EXPORT_SYMBOL(pciem_dma_atomic_swap);

u64 pciem_dma_atomic_cas(struct pciem_host *v, u64 guest_iova, u64 expected, u64 new_val, u32 pasid)
{
    return do_atomic_op(v, guest_iova, PCIEM_ATOMIC_CAS, new_val, expected, pasid);
}
EXPORT_SYMBOL(pciem_dma_atomic_cas);

u64 pciem_dma_atomic_fetch_and(struct pciem_host *v, u64 guest_iova, u64 val, u32 pasid)
{
    return do_atomic_op(v, guest_iova, PCIEM_ATOMIC_FETCH_AND, val, 0, pasid);
}
EXPORT_SYMBOL(pciem_dma_atomic_fetch_and);

u64 pciem_dma_atomic_fetch_or(struct pciem_host *v, u64 guest_iova, u64 val, u32 pasid)
{
    return do_atomic_op(v, guest_iova, PCIEM_ATOMIC_FETCH_OR, val, 0, pasid);
}
EXPORT_SYMBOL(pciem_dma_atomic_fetch_or);

u64 pciem_dma_atomic_fetch_xor(struct pciem_host *v, u64 guest_iova, u64 val, u32 pasid)
{
    return do_atomic_op(v, guest_iova, PCIEM_ATOMIC_FETCH_XOR, val, 0, pasid);
}
EXPORT_SYMBOL(pciem_dma_atomic_fetch_xor);