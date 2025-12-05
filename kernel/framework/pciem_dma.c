#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "pciem_dma.h"
#include "pciem_framework.h"
#include <asm/cacheflush.h>
#include <linux/atomic.h>
#include <linux/iommu.h>
#include <linux/mm.h>
#include <linux/slab.h>

static int translate_iova(struct pciem_root_complex *v, u64 guest_iova, size_t len,
                          phys_addr_t **phys_pages_out, int *num_pages)
{
    struct iommu_domain *domain;
    size_t remaining = len;
    u64 iova = guest_iova;
    int page_count = 0;
    int max_pages;
    phys_addr_t *phys_pages;

    domain = iommu_get_domain_for_dev(&v->protopciem_pdev->dev);

    max_pages = (PAGE_ALIGN(guest_iova + len) - (guest_iova & PAGE_MASK)) >> PAGE_SHIFT;

    phys_pages = kmalloc_array(max_pages, sizeof(phys_addr_t), GFP_KERNEL);
    if (!phys_pages) {
        pr_err("translate_iova: failed to allocate page array for %d pages\n", max_pages);
        return -ENOMEM;
    }

    while (remaining > 0)
    {
        phys_addr_t hpa;
        size_t chunk_len;

        if (page_count >= max_pages)
        {
            pr_err("translate_iova: page buffer overflow (calculated %d pages, but need more)\n", max_pages);
            kfree(phys_pages);
            return -EOVERFLOW;
        }

        if (domain) {
            hpa = iommu_iova_to_phys(domain, iova);
            if (!hpa)
            {
                pr_err("Failed to translate IOVA 0x%llx\n", iova);
                kfree(phys_pages);
                return -EFAULT;
            }
        } else {
            hpa = (phys_addr_t)iova;
        }

        phys_pages[page_count++] = hpa;

        chunk_len = min_t(size_t, remaining, PAGE_SIZE - (iova & ~PAGE_MASK));
        remaining -= chunk_len;
        iova += chunk_len;
    }

    *num_pages = page_count;
    *phys_pages_out = phys_pages;
    return 0;
}

int pciem_dma_read_from_guest(struct pciem_root_complex *v, u64 guest_iova, void *dst, size_t len, u32 pasid)
{
    phys_addr_t *phys_pages = NULL;
    int num_pages = 0;
    size_t offset = 0;
    int i;
    u8 *dst_buf = (u8 *)dst;
    int ret;

    if (!v || !dst || len == 0)
    {
        return -EINVAL;
    }

    ret = translate_iova(v, guest_iova, len, &phys_pages, &num_pages);
    if (ret < 0)
    {
        return ret;
    }

    pr_info("pciem: DMA read: IOVA 0x%llx -> %d pages, len %zu, PASID %u\n", 
            guest_iova, num_pages, len, pasid);

    for (i = 0; i < num_pages && offset < len; i++)
    {
        void *kva;
        size_t chunk_len;
        size_t page_offset = (i == 0) ? (guest_iova & ~PAGE_MASK) : 0;

        chunk_len = min_t(size_t, len - offset, PAGE_SIZE - page_offset);

        kva = memremap(phys_pages[i] + page_offset, chunk_len, MEMREMAP_WB);
        if (!kva)
        {
            pr_err("pciem: memremap failed for physical page %pa\n", &phys_pages[i]);
            kfree(phys_pages);
            return -ENOMEM;
        }

        memcpy(dst_buf + offset, kva, chunk_len);
        memunmap(kva);

        offset += chunk_len;
    }

    kfree(phys_pages);
    return 0;
}
EXPORT_SYMBOL(pciem_dma_read_from_guest);

int pciem_dma_write_to_guest(struct pciem_root_complex *v, u64 guest_iova, const void *src, size_t len, u32 pasid)
{
    phys_addr_t *phys_pages = NULL;
    int num_pages = 0;
    size_t offset = 0;
    int i;
    int ret;

    if (!v || !src || len == 0)
    {
        return -EINVAL;
    }

    ret = translate_iova(v, guest_iova, len, &phys_pages, &num_pages);
    if (ret < 0)
    {
        return ret;
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
            kfree(phys_pages);
            return -ENOMEM;
        }

        memcpy(kva, (u8 *)src + offset, chunk_len);
        memunmap(kva);

        offset += chunk_len;
    }

    kfree(phys_pages);
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