/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Copyright (C) 2025-2026  Joel Bueno
 *  Copyright (C) 2025-2026  Carlos López
 */

#ifndef PCIEM_DMA_H
#define PCIEM_DMA_H

#include <linux/types.h>

struct pciem_root_complex;

int pciem_dma_read_from_guest(struct pciem_root_complex *v, u64 guest_iova, void *dst, size_t len, u32 pasid);
int pciem_dma_write_to_guest(struct pciem_root_complex *v, u64 guest_iova, const void *src, size_t len, u32 pasid);

u64 pciem_dma_atomic_fetch_add(struct pciem_root_complex *v, u64 guest_iova, u64 val, u32 pasid);
u64 pciem_dma_atomic_fetch_sub(struct pciem_root_complex *v, u64 guest_iova, u64 val, u32 pasid);
u64 pciem_dma_atomic_swap(struct pciem_root_complex *v, u64 guest_iova, u64 val, u32 pasid);
u64 pciem_dma_atomic_cas(struct pciem_root_complex *v, u64 guest_iova, u64 expected, u64 new_val, u32 pasid);
u64 pciem_dma_atomic_fetch_and(struct pciem_root_complex *v, u64 guest_iova, u64 val, u32 pasid);
u64 pciem_dma_atomic_fetch_or(struct pciem_root_complex *v, u64 guest_iova, u64 val, u32 pasid);
u64 pciem_dma_atomic_fetch_xor(struct pciem_root_complex *v, u64 guest_iova, u64 val, u32 pasid);

#define pciem_dma_read(v, iova, dst, len) pciem_dma_read_from_guest(v, iova, dst, len, 0)
#define pciem_dma_write(v, iova, src, len) pciem_dma_write_to_guest(v, iova, src, len, 0)

struct pciem_dma_req
{
    u64 guest_iova;
    u64 host_buf_addr;
    u32 length;
    u32 pasid;
    u8 op_type;
    u8 atomic_op;
    u16 reserved;
    u64 atomic_operand;
    u64 atomic_compare;
} __attribute__((packed));

#define PCIEM_ATOMIC_FETCH_ADD 1
#define PCIEM_ATOMIC_FETCH_SUB 2
#define PCIEM_ATOMIC_SWAP 3
#define PCIEM_ATOMIC_CAS 4
#define PCIEM_ATOMIC_FETCH_AND 5
#define PCIEM_ATOMIC_FETCH_OR 6
#define PCIEM_ATOMIC_FETCH_XOR 7

#endif /* PCIEM_DMA_H */