/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Copyright (C) 2026  Carlos López <carlos.lopezr4096@gmail.com>
 *  Copyright (C) 2026  Joel Bueno <buenocalvachejoel@gmail.com>
 */

#include <asm/traps.h>
#include <asm/pgtable-hwdef.h>
#include <asm/sysreg.h>
#include <asm/esr.h>

#define SMPTRACE_ARM64_LEVEL_PTE  0
#define SMPTRACE_ARM64_LEVEL_PMD  1
#define SMPTRACE_ARM64_LEVEL_PUD  2

/*
 * In order to walk the kernel page tables we need to get a pointer to the PGD, which is
 * pointed to by ttbr1_el1. phys_to_ttbr() encodes the physical address in a somewhat
 * unusual way so we to basically "inverse" (There's some juggling we have to do with certain
 * ASID bits) the process so we can get the PA.
 */
static inline phys_addr_t ttbr_to_phys(u64 ttbr)
{
	phys_addr_t pa;

	pa  = ttbr & GENMASK_ULL(47, PAGE_SHIFT);
	pa |= (phys_addr_t)(ttbr & GENMASK_ULL(5, 2)) << 46;
	return pa;
}

/*
 * We basically roll our own kernel_pgd to avoid the dependency on
 * wapper_pg_dir, which is not exported to modules.
 */
static inline pgd_t *arm64_kernel_pgd(void)
{
	return (pgd_t *)phys_to_virt(ttbr_to_phys(read_sysreg(ttbr1_el1)));
}

/*
 * Walk the kernel page tables to find the PTE corresponding to the given VA.
 *
 * Pretty similar in spirit to the x86 counterpart (At least in terms of structure).
 */
static pte_t *arm64_walk_pte(unsigned long va, unsigned int *level_out)
{
	pgd_t *pgdp, pgd;
	p4d_t *p4dp, p4d;
	pud_t *pudp, pud;
	pmd_t *pmdp, pmd;

	pgdp = pgd_offset_pgd(arm64_kernel_pgd(), va);
	pgd  = READ_ONCE(*pgdp);
	if (pgd_none(pgd) || pgd_bad(pgd))
		return NULL;

	p4dp = p4d_offset(pgdp, va);
	p4d  = READ_ONCE(*p4dp);
	if (p4d_none(p4d) || p4d_bad(p4d))
		return NULL;

	pudp = pud_offset(p4dp, va);
	pud  = READ_ONCE(*pudp);
	if (pud_none(pud))
		return NULL;
	if (pud_sect(pud)) {
		*level_out = SMPTRACE_ARM64_LEVEL_PUD;
		return (pte_t *)pudp;
	}
	if (pud_bad(pud))
		return NULL;

	pmdp = pmd_offset(pudp, va);
	pmd  = READ_ONCE(*pmdp);
	if (pmd_none(pmd))
		return NULL;
	if (pmd_sect(pmd)) {
		*level_out = SMPTRACE_ARM64_LEVEL_PMD;
		return (pte_t *)pmdp;
	}
	if (pmd_bad(pmd))
		return NULL;

	*level_out = SMPTRACE_ARM64_LEVEL_PTE;
	return pte_offset_kernel(pmdp, va);
}

static unsigned long arm64_level2size(unsigned int level)
{
	switch (level) {
	case SMPTRACE_ARM64_LEVEL_PTE: return PAGE_SIZE;
	case SMPTRACE_ARM64_LEVEL_PMD: return PMD_SIZE;
	case SMPTRACE_ARM64_LEVEL_PUD: return PUD_SIZE;
	default: BUG();
	}
}

/*
 * Poison the PTEs corresponding to the given VA range, saving the original
 * PTE values in the context struct so we can restore them later.
 * 
 * This also overcomes the limitation of certain unexported functions (That
 * would probably make this much more cleaner...) erroring out on modpost.
 */
static int poison_pte(struct smptrace_ctx *ctx, unsigned long va,
                      unsigned int len)
{
	int64_t remain = len;
	struct smptrace_pte *orig, *tmp;
	struct list_head local_ptes;
	unsigned long flags;
	int ret;

	INIT_LIST_HEAD(&local_ptes);

	while (remain > 0) {
		unsigned int level;
		pte_t *ptep = arm64_walk_pte(va, &level);

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

		switch (level) {
		case SMPTRACE_ARM64_LEVEL_PTE:
			orig->pte = pte_val(READ_ONCE(*ptep));
			WRITE_ONCE(*ptep, __pte(0));
			break;
		case SMPTRACE_ARM64_LEVEL_PMD:
			orig->pte = pmd_val(READ_ONCE(*(pmd_t *)ptep));
			WRITE_ONCE(*(pmd_t *)ptep, __pmd(0));
			break;
		case SMPTRACE_ARM64_LEVEL_PUD:
			orig->pte = pud_val(READ_ONCE(*(pud_t *)ptep));
			WRITE_ONCE(*(pud_t *)ptep, __pud(0));
			break;
		}

		pr_info("poisoned PTE for VA=%lx (level=%u)", va, level);

		remain -= arm64_level2size(level);
		va     += arm64_level2size(level);
		list_add_tail(&orig->list, &local_ptes);
	}

	spin_lock_irqsave(&ctx->lock, flags);
	list_splice_tail(&local_ptes, &ctx->ptes);
	spin_unlock_irqrestore(&ctx->lock, flags);

	flush_tlb_kernel_range(va - len, va);
	return 0;

fail:
	list_for_each_entry_safe(orig, tmp, &local_ptes, list) {
		list_del(&orig->list);
		kfree(orig);
	}
	flush_tlb_kernel_range(va - (len - remain), va);
	return ret;
}

/*
 * Restore the PTEs corresponding to the given VA range.
 */
static void restore_pte(struct smptrace_ctx *ctx, unsigned long va,
                        unsigned int len)
{
	int64_t remain = len;
	unsigned long va_start = va;
	unsigned long flags;

	while (remain > 0) {
		unsigned int level;
		pte_t *ptep = arm64_walk_pte(va, &level);
		struct smptrace_pte *orig;
		unsigned long step;

		if (!ptep) {
			remain -= PAGE_SIZE;
			va     += PAGE_SIZE;
			continue;
		}

		step = arm64_level2size(level);

		spin_lock_irqsave(&ctx->lock, flags);
		orig = __find_pte(ctx, va);
		if (orig)
			list_del(&orig->list);
		spin_unlock_irqrestore(&ctx->lock, flags);

		if (!orig) {
			pr_err("could not find saved PTE for va=0x%lx\n", va);
			remain -= step;
			va     += step;
			continue;
		}

		if (orig->level != level)
			pr_warn("PTE level mismatch for va=0x%lx (saved=%u walk=%u)",
			        va, orig->level, level);

		switch (level) {
		case SMPTRACE_ARM64_LEVEL_PTE:
			WRITE_ONCE(*ptep, __pte(orig->pte));
			break;
		case SMPTRACE_ARM64_LEVEL_PMD:
			WRITE_ONCE(*(pmd_t *)ptep, __pmd(orig->pte));
			break;
		case SMPTRACE_ARM64_LEVEL_PUD:
			WRITE_ONCE(*(pud_t *)ptep, __pud(orig->pte));
			break;
		}

		pr_info("restored PTE for VA=%lx (level=%u)", va, level);

		remain -= step;
		va     += step;
		kfree(orig);
	}

	flush_tlb_kernel_range(va_start, va_start + len);
}

struct arm64_ls_insn {
	u32  rt;
	u32  rn;
	u32  size;
	bool is_store;
	bool sign_extend;
	bool sf;
	bool post_index;
	bool pre_index;
	s64  wb_delta;
};

/*
 * Basically implemented by looking at the relevant Armv8-A manual sections.
 *
 * There could be issues here but... seems to work just fine. If only we could
 * use the ISV-based decoding...
 */
static int arm64_decode_ls_insn(u32 insn, struct arm64_ls_insn *out)
{
	u32 group = (insn >> 24) & 0x3F;
	u32 size_field, opc, rt, rn;
	bool is_fp = (insn >> 26) & 1;

	if (is_fp)
		return -EINVAL;

	size_field = (insn >> 30) & 3;
	opc        = (insn >> 22) & 3;
	rn         = (insn >>  5) & 0x1F;
	rt         = insn & 0x1F;

	out->rt         = rt;
	out->rn         = rn;
	out->post_index = false;
	out->pre_index  = false;
	out->wb_delta   = 0;

	if (group == 0x39) {
		// LDUR/STUR (not handling those here...)
	} else if ((group == 0x38) && !((insn >> 21) & 1)) {
		u32 idx = (insn >> 10) & 3;

		if (idx == 0) {
			// LDUR/STUR - No need to handle for now
		} else if (idx == 1 || idx == 3) {
			// Post/pre index?
			s32 imm9 = (s32)((insn >> 12) & 0x1FF);
			// SEXT the immediate
			imm9 = (imm9 << 23) >> 23;
			out->wb_delta   = imm9;
			out->post_index = (idx == 1);
			out->pre_index  = (idx == 3);
		} else {
			return -EINVAL;
		}
	} else {
		return -EINVAL;
	}

	out->size     = 1u << size_field;
	out->is_store = (opc == 0);
	out->sf       = true;

	switch ((size_field << 2) | opc) {
	// STRB
	case 0x00: out->is_store = true;  out->sign_extend = false; break;
	// LDRB
	case 0x01: out->is_store = false; out->sign_extend = false; break;
	// LDRSB
	case 0x02: out->is_store = false; out->sign_extend = true;  break;
	// LDRSB 32
	case 0x03: out->is_store = false; out->sign_extend = true;  out->sf = false; break;
	// STRH
	case 0x04: out->is_store = true;  out->sign_extend = false; break;
	// LDRH
	case 0x05: out->is_store = false; out->sign_extend = false; break;
	// LDRSH
	case 0x06: out->is_store = false; out->sign_extend = true;  break;
	// LDRSH 32
	case 0x07: out->is_store = false; out->sign_extend = true;  out->sf = false; break;
	// STR
	case 0x08: out->is_store = true;  out->sign_extend = false; break;
	// LDR
	case 0x09: out->is_store = false; out->sign_extend = false; out->sf = false; break;
	// LDRSW
	case 0x0A: out->is_store = false; out->sign_extend = true;  break;
	// STR (no scale?)
	case 0x0C: out->is_store = true;  out->sign_extend = false; break;
	// LDR (no scale?)
	case 0x0D: out->is_store = false; out->sign_extend = false; break;
	default:
		return -EINVAL;
	}

	return 0;
}


/*
 * ESR_ELx_ISV is godsent for this, but not everyone has it for our specific
 * use case (Looking at you BCM2711) so we also have the expected fallbacl.
 */
static int emulate_arm64_fault(struct smptrace_ctx *ctx,
                               struct smptrace_map *map,
                               unsigned long fault_va,
                               unsigned long esr,
                               struct pt_regs *regs)
{
	u32 srt, size;
	bool is_store, sse, sf;
	u64 addr = fault_va;
	u64 val;

	if (user_mode(regs))
		return -EACCES;

	if (esr & ESR_ELx_ISV) {
		u32 sas = (esr & ESR_ELx_SAS) >> ESR_ELx_SAS_SHIFT;

		is_store = !!(esr & ESR_ELx_WNR);
		sse      = !!(esr & ESR_ELx_SSE);
		srt      = (esr & ESR_ELx_SRT_MASK) >> ESR_ELx_SRT_SHIFT;
		sf       = !!(esr & ESR_ELx_SF);
		size     = 1u << sas;
	} else {
		struct arm64_ls_insn ls;
		u32 insn;

		if (copy_from_kernel_nofault(&insn, (void *)regs->pc,
		                             sizeof(insn))) {
			pr_warn_ratelimited(
				"ISV=0: failed to read insn at pc=0x%llx",
				regs->pc);
			return -EFAULT;
		}

		if (arm64_decode_ls_insn(insn, &ls)) {
			pr_warn_ratelimited(
				"ISV=0: unrecognised load/store at pc=0x%llx insn=0x%08x",
				regs->pc, insn);
			return -EINVAL;
		}

		srt      = ls.rt;
		size     = ls.size;
		is_store = ls.is_store;
		sse      = ls.sign_extend;
		sf       = ls.sf;

		if ((ls.pre_index || ls.post_index) && ls.rn != 31)
			regs->regs[ls.rn] += ls.wb_delta;
	}

	if (is_store) {
		val = (srt == 31) ? 0ULL : regs->regs[srt];
		emulate_write(ctx, map, addr, size, (u8 *)&val);
	} else {
		val = 0;
		emulate_read(ctx, map, addr, size, (u8 *)&val);

		if (srt != 31) {
			if (sse) {
				unsigned int sbits = size * 8;
				s64 sval = (s64)(val << (64 - sbits)) >> (64 - sbits);
				regs->regs[srt] = sf ? (u64)sval
				                     : (u64)(u32)(s32)sval;
			} else {
				regs->regs[srt] = sf ? val : (u64)(u32)val;
			}
		}
	}

	regs->pc += 4;
	return 0;
}


/*
 * Similar to the x86 badarea handler... but hooking __do_kernel_fault instead
 * since badarea_nosemaphore doesn't exist for aarch64 and __do_kernel_fault
 * provides us with the required context to handle the fault (And even
 * richer than i386/amd64...).
 */
static int __enter_do_kernel_fault(struct kprobe *kp, struct pt_regs *regs)
{
	struct smptrace_ctx *ctx = container_of(kp, struct smptrace_ctx, badarea_kp);
	unsigned long fault_va   = regs_get_kernel_argument(regs, 0);
	unsigned long esr        = regs_get_kernel_argument(regs, 1);
	struct pt_regs *fault_regs =
		(struct pt_regs *)regs_get_kernel_argument(regs, 2);
	struct smptrace_map *tmp_map, map_copy = {0};
	unsigned long flags;
	bool found = false;
	int ret;

	// Only data aborts (There should not be any instruction aborts but...)
	if (ESR_ELx_EC(esr) != ESR_ELx_EC_DABT_CUR)
		return 0;

	spin_lock_irqsave(&ctx->lock, flags);
	list_for_each_entry(tmp_map, &ctx->maps, list) {
		if (fault_va >= tmp_map->va &&
		    fault_va <  tmp_map->va + tmp_map->len) {
			map_copy = *tmp_map;
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&ctx->lock, flags);

	if (!found)
		return 0;

	if (this_cpu_xchg(*ctx->in_pf, true)) {
		pr_warn("reentrant fault on 0x%lx, ignoring", fault_va);
		return 0;
	}

	// God bless fixed-width opcode ISAs
	ret = emulate_arm64_fault(ctx, &map_copy, fault_va, esr, fault_regs);
	this_cpu_write(*ctx->in_pf, false);

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
	readl(ctx->shadow_va);

	ctx->badarea_kp = (struct kprobe){
		.pre_handler = __enter_do_kernel_fault,
		.symbol_name = "__do_kernel_fault",
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
		.kp.symbol_name = "ioremap_prot",
	};

	return smptrace_register_probes(ctx);
}
