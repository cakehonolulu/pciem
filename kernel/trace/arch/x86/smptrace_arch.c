/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Copyright (C) 2026  Carlos López <carlos.lopezr4096@gmail.com>
 *  Copyright (C) 2026  Joel Bueno <buenocalvachejoel@gmail.com>
 */

#include <asm/debugreg.h>
#include <asm/traps.h>
#include <asm/pgtable.h>
#include "insn.h"
#include "insn-eval.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
static inline pud_t pud_mkinvalid(pud_t pud)
{
	return pfn_pud(pud_pfn(pud),
	               __pgprot(pud_flags(pud) & ~(_PAGE_PRESENT | _PAGE_PROTNONE)));
}
#endif

static void ____write_cr4(unsigned long val)
{
	asm volatile("mov %0,%%cr4" : "+r"(val) :: "memory");
}

static void __flush_tlb(void)
{
	unsigned long cr4 = __read_cr4();
	____write_cr4(cr4 ^ X86_CR4_PGE);
	____write_cr4(cr4);
}

static u64 level2size(unsigned int level)
{
	switch (level) {
	case PG_LEVEL_4K: return PAGE_SIZE;
	case PG_LEVEL_2M: return HPAGE_PMD_SIZE;
	case PG_LEVEL_1G: return HPAGE_PUD_SIZE;
	default: BUG();
	}
}

static int poison_pte(struct smptrace_ctx *ctx, unsigned long va,
                      unsigned int len)
{
	int64_t remain = len;
	unsigned int level;
	struct smptrace_pte *orig, *tmp;
	struct list_head local_ptes;
	unsigned long flags;
	int ret;

	INIT_LIST_HEAD(&local_ptes);

	while (remain > 0) {
		pte_t *ptep = lookup_address(va, &level);

		if (!ptep) {
			ret = -ENOENT;
			goto fail;
		}

		orig = kzalloc(sizeof(*orig), GFP_ATOMIC);
		if (!orig) {
			ret = -ENOMEM;
			goto fail;
		}

		INIT_LIST_HEAD(&orig->list);
		orig->va    = va;
		orig->level = level;

        /* Swap out PTE */
		switch (level) {
		case PG_LEVEL_4K: {
			pte_t pte = native_local_ptep_get_and_clear(ptep);
			orig->pte = pte_val(pte);
			break;
		}
		case PG_LEVEL_2M: {
			pmd_t *pmdp = (pmd_t *)ptep;
			pmd_t  pmd  = pmdp_get(pmdp);
			orig->pte = pmd_val(pmd);
			set_pmd(pmdp, pmd_mkinvalid(pmd));
			break;
		}
		case PG_LEVEL_1G: {
			pud_t *pudp = (pud_t *)ptep;
			pud_t  pud  = pudp_get(pudp);
			orig->pte = pud_val(pud);
			set_pud(pudp, pud_mkinvalid(pud));
			break;
		}
		default:
			pr_err("unexpected page level 0x%x for VA 0x%llx\n",
			       level, (u64)va);
			kfree(orig);
			ret = -EINVAL;
			goto fail;
		}

		pr_info("poisoned PTE for VA=%lx (level=%u)", va, level);

		remain -= level2size(level);
		va     += level2size(level);
		list_add_tail(&orig->list, &local_ptes);
	}

	spin_lock_irqsave(&ctx->lock, flags);
	list_splice_tail(&local_ptes, &ctx->ptes);
	spin_unlock_irqrestore(&ctx->lock, flags);

	__flush_tlb();
	return 0;

fail:
	/* Free items, but do not bother to unpoison the PTEs. Let our
	 * caller detect the error, and simply return NULL to the caller
	 * of ioremap() */
	list_for_each_entry_safe(orig, tmp, &local_ptes, list) {
		list_del(&orig->list);
		kfree(orig);
	}
	__flush_tlb();
	return ret;
}

static void restore_pte(struct smptrace_ctx *ctx, unsigned long va,
                        unsigned int len)
{
	int64_t remain = len;
	unsigned long flags;

	while (remain > 0) {
		unsigned int level;
		pte_t *ptep = lookup_address(va, &level);
		struct smptrace_pte *orig;

		if (!ptep) {
			remain -= PAGE_SIZE;
			va     += PAGE_SIZE;
			continue;
		}

		spin_lock_irqsave(&ctx->lock, flags);
		orig = __find_pte(ctx, va);
		if (orig)
			list_del(&orig->list);
		spin_unlock_irqrestore(&ctx->lock, flags);

		if (!orig) {
			pr_err("could not find saved PTE for va=0x%lx\n", va);
			remain -= level2size(level);
			va     += level2size(level);
			continue;
		}

		if (orig->level != level)
			pr_warn("PTE level mismatch for va=0x%lx (saved=%u walk=%u)",
			        va, orig->level, level);

		switch (level) {
		case PG_LEVEL_4K:
			set_pte_atomic(ptep, __pte(orig->pte));
			break;
		case PG_LEVEL_2M:
			set_pmd((pmd_t *)ptep, __pmd(orig->pte));
			break;
		case PG_LEVEL_1G:
			set_pud((pud_t *)ptep, __pud(orig->pte));
			break;
		default:
			pr_err("unexpected page level %u for VA 0x%lx\n", level, va);
			kfree(orig);
			return;
		}

		pr_info("restored PTE for VA=%lx (level=%u)", va, level);

		remain -= level2size(orig->level);
		va     += level2size(orig->level);
		kfree(orig);
	}

	__flush_tlb();
}

static int decode_pf_instr(struct pt_regs *regs, struct insn *insn)
{
	u8 buf[MAX_INSN_SIZE];

	if (copy_from_kernel_nofault(buf, (void *)regs->ip, MAX_INSN_SIZE))
		return -EINVAL;

	return insn_decode_kernel(insn, buf);
}

static int emulate_pf_instruction(struct smptrace_ctx *ctx,
                                  struct smptrace_map *map,
                                  struct pt_regs *regs)
{
	struct insn insn;
	enum insn_mmio_type mmio;
	long *data = NULL;
	u64 addr;
	unsigned int len;
	int ret;
	u8 sign_byte;

	if (user_mode(regs))
		return -EACCES;

	ret = decode_pf_instr(regs, &insn);
	if (ret) {
		pr_warn("failed to decode #PF instr ip=0x%lx", regs->ip);
		return ret;
	}

	mmio = insn_decode_mmio(&insn, &len);
	if (mmio == INSN_MMIO_DECODE_FAILED) {
		pr_warn("failed to decode MMIO instr ip=0x%lx", regs->ip);
		return -EINVAL;
	}

    /* Get a pointer to the data if not writing an immediate, or if
	 * not doing MOVS (which we do not handle yet) */
	if (mmio != INSN_MMIO_WRITE_IMM && mmio != INSN_MMIO_MOVS) {
		data = insn_get_modrm_reg_ptr(&insn, regs);
		if (!data) {
			pr_warn("failed to get modrm reg ptr");
			return -EINVAL;
		}
	}

    /* Get the MMIO source/destination address */
	addr = (u64)insn_get_addr_ref(&insn, regs);

	switch (mmio) {
	case INSN_MMIO_WRITE:
		emulate_write(ctx, map, addr, len, (u8 *)data);
		break;
	case INSN_MMIO_WRITE_IMM:
		BUG_ON(len > 4);
		emulate_write(ctx, map, addr, len, (u8 *)insn.immediate1.bytes);
		break;
	case INSN_MMIO_READ:
		if (len == 4)
			*data = 0;
		emulate_read(ctx, map, addr, len, (u8 *)data);
		break;
	case INSN_MMIO_READ_ZERO_EXTEND:
		memset(data, 0, insn.opnd_bytes);
		emulate_read(ctx, map, addr, len, (u8 *)data);
		break;
	case INSN_MMIO_READ_SIGN_EXTEND:
        /* Sign extend based on operand size */
		if (len == 1) {
			u8 val;
			emulate_read(ctx, map, addr, len, &val);
			sign_byte = (val & 0x80) ? 0xff : 0x00;
		} else {
			u16 val;
			emulate_read(ctx, map, addr, len, (u8 *)&val);
			sign_byte = (val & 0x8000) ? 0xff : 0x00;
		}
		memset(data, sign_byte, insn.opnd_bytes);
		emulate_read(ctx, map, addr, len, (u8 *)data);
		break;
	case INSN_MMIO_MOVS:
		pr_warn_ratelimited("unhandled MOVS instruction ip=0x%lx", regs->ip);
		return -ENOTSUPP;
	default:
		pr_warn_ratelimited("unhandled MMIO instruction ip=0x%lx (%d)",
		                    regs->ip, mmio);
		return -ENOTSUPP;
	}

	regs->ip += insn.length;
	return 0;
}

static int __enter_badarea(struct kprobe *kp, struct pt_regs *regs)
{
	struct smptrace_ctx *ctx = container_of(kp, struct smptrace_ctx, badarea_kp);
	struct pt_regs *pf_regs  = (struct pt_regs *)regs_get_kernel_argument(regs, 0);
	unsigned long pf_va      = regs_get_kernel_argument(regs, 2);
	struct smptrace_map *tmp_map, map_copy = {0};
	unsigned long flags;
	bool found = false;
	int ret;

	/* Find the matching memory mapping. We copy it by value so we don't hold the spinlock 
	   during the entire emulate_pf_instruction sequence (which triggers user callbacks). */
	spin_lock_irqsave(&ctx->lock, flags);
	list_for_each_entry(tmp_map, &ctx->maps, list) {
		if (pf_va >= tmp_map->va && pf_va < tmp_map->va + tmp_map->len) {
			map_copy = *tmp_map;
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&ctx->lock, flags);

	if (!found)
		return 0;

	if (this_cpu_xchg(*ctx->in_pf, true)) {
		pr_warn("reentrant #PF on 0x%lx, ignoring", pf_va);
		return 0;
	}

	ret = emulate_pf_instruction(ctx, &map_copy, pf_regs);
	this_cpu_write(*ctx->in_pf, false);

    /* Update return address to skip the whole function we hooked */
	if (!ret) {
		instruction_pointer_set(regs, (unsigned long)smptrace_ret_gadget);
		return 1;
	}

	return 0;
}

static int smptrace_activate(struct smptrace_ctx *ctx)
{
	ctx->shadow_va = ioremap(ctx->pa, ctx->len);
	if (!ctx->shadow_va) {
		pr_err("Failed to map shadow VA\n");
		return -ENOMEM;
	}
	/* Force the kernel to set the page as present to avoid a #PF */
	readl(ctx->shadow_va);

	ctx->badarea_kp = (struct kprobe){
		.pre_handler = __enter_badarea,
		.symbol_name = "bad_area_nosemaphore",
	};
	ctx->iounmap_kp = (struct kprobe){
		.pre_handler = __enter_iounmap,
		.symbol_name = "iounmap",
	};
	ctx->ioremap_krp = (struct kretprobe){
		.entry_handler  = __enter_ioremap,
		.handler        = __exit_ioremap,
		.maxactive      = 32,
		.data_size      = sizeof(struct ioremap_args),
		.kp.symbol_name = "ioremap",
	};

	return smptrace_register_probes(ctx);
}
