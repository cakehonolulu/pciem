// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 2026  Carlos López <carlos.lopezr4096@gmail.com>
 *  Copyright (C) 2026  Joel Bueno <buenocalvachejoel@gmail.com>
 *
 * smptrace: SMP MMIO read/write tracing
 *
 * This module implements something similar to mmiotrace in the Linux kernel,
 * (see Documentation/trace/mmiotrace.rst), with some differences. The main
 * change is that smptrace works with multiple CPUs concurrently, and has first
 * class software APIs for other in-kernel users (instead of just exposing a
 * debugfs interface).
 *
 * The reason why this implementation works in SMP configurations is that
 * single-stepping is not used, avoiding the potential races with that approach.
 * Instead, we hook #PF to emulate faulting MMIO instructions, allowing a
 * strictly per-CPU approach, with little inter-CPU synchronization.
 *
 * mmiotrace also has first-class support in the kernel, while smptrace uses
 * kprobes to hook the relevant pieces. While this works, it may be more
 * brittle to future changes in the  kernel. Do not use this in a production
 * system.
 *
 * smptrace uses as little kernel APIs as possible, since it is built out of
 * tree. This also implies vendoring some kernel code, namely the x86
 * isntruction decoder, which is not exported to kernel modules.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": trace: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/mm.h>
#include <linux/notifier.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <asm/io.h>
#include <asm/tlbflush.h>
#include "trace/smptrace.h"

static void __fill_io_notif(struct smptrace_io *io, const u8 *data, u32 size,
                            u64 off)
{
	io->offset = off;
	io->size = size;
	switch (size) {
	case 1:
		io->data.byte = *(u8 *)data;
		break;
	case 2:
		io->data.word = *(u16 *)data;
		break;
	case 4:
		io->data.dword = *(u32 *)data;
		break;
	case 8:
		io->data.qword = *(u64 *)data;
		break;
	default:
		BUG();
	}
}

static void emulate_read(struct smptrace_ctx *ctx, struct smptrace_map *map,
                         u64 addr, u32 size, u8 *dst)
{
	u64 off;
	struct smptrace_io io;

	off = (map->pa - ctx->pa) + (addr - map->va);
	BUG_ON(off >= ctx->len || off + size > ctx->len);
	memcpy_fromio(dst, ctx->shadow_va + off, size);

	if (ctx->notif.read) {
		__fill_io_notif(&io, dst, size, off);
		ctx->notif.read(ctx, &io);
	}
}

static void emulate_write(struct smptrace_ctx *ctx, struct smptrace_map *map,
                          u64 addr, u32 size, const u8 *src)
{
	u64 off;
	struct smptrace_io io = {0};

	off = (map->pa - ctx->pa) + (addr - map->va);
	BUG_ON(off >= ctx->len || off + size > ctx->len);

	if (!ctx->stop_writes)
		memcpy_toio(ctx->shadow_va + off, src, size);

	pr_debug("Write @ 0x%llx:%x", off, size);

	if (ctx->notif.write) {
		__fill_io_notif(&io, src, size, off);
		ctx->notif.write(ctx, &io);
	}
}

struct ioremap_args {
	resource_size_t pa;
	unsigned long len;
};

static int __enter_ioremap(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct ioremap_args *args = (struct ioremap_args *)ri->data;

	args->pa  = regs_get_kernel_argument(regs, 0);
	args->len = regs_get_kernel_argument(regs, 1);
	return 0;
}

static int poison_pte(struct smptrace_ctx *ctx, unsigned long va,
                      unsigned int len);
static void restore_pte(struct smptrace_ctx *ctx, unsigned long va,
                        unsigned int len);

static int __exit_ioremap(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kretprobe *rp = get_kretprobe(ri);
	struct smptrace_ctx *ctx = container_of(rp, struct smptrace_ctx,
	                                        ioremap_krp);
	struct ioremap_args *args = (struct ioremap_args *)ri->data;
	unsigned long va = regs_return_value(regs);
	struct smptrace_map *map;
	unsigned long flags;

	if (args->pa < ctx->pa || args->pa >= ctx->pa + ctx->len)
		return 0;

	map = kzalloc(sizeof(*map), GFP_ATOMIC);
	if (!map)
		return 0;

	map->va  = va;
	map->len = args->len;
	map->pa  = args->pa;

	pr_info("poisoning VA=0x%lx:%lx (PA=0x%llx:%lx)",
	        va, args->len, (unsigned long long)ctx->pa, ctx->len);

	spin_lock_irqsave(&ctx->lock, flags);
	list_add_tail(&map->list, &ctx->maps);
	spin_unlock_irqrestore(&ctx->lock, flags);

	if (poison_pte(ctx, va, args->len)) {
		spin_lock_irqsave(&ctx->lock, flags);
		list_del(&map->list);
		spin_unlock_irqrestore(&ctx->lock, flags);
		kfree(map);

		regs_set_return_value(regs, 0);
		iounmap((void __iomem *)va);

		pr_warn("failed to poison VA=0x%lx:%lx (PA=0x%llx:%lx)",
		        va, args->len, args->pa, args->len);
	}

	return 0;
}

static int __enter_iounmap(struct kprobe *kp, struct pt_regs *regs)
{
	struct smptrace_ctx *ctx = container_of(kp, struct smptrace_ctx,
	                                        iounmap_kp);
	unsigned long va = regs_get_kernel_argument(regs, 0);
	struct smptrace_map *map, *found = NULL;
	unsigned long flags;

	spin_lock_irqsave(&ctx->lock, flags);
	list_for_each_entry(map, &ctx->maps, list) {
		if (map->va == va) {
			found = map;
			list_del(&map->list);
			break;
		}
	}
	spin_unlock_irqrestore(&ctx->lock, flags);

	if (!found)
		return 0;

	pr_info("restoring VA=0x%lx (PA=0x%llx)", found->va,
	        (unsigned long long)found->pa);
	restore_pte(ctx, found->va, found->len);
	kfree(found);
	return 0;
}

#ifdef CONFIG_X86

#include <asm/debugreg.h>
#include <asm/traps.h>
#include <asm/pgtable.h>

#include "insn.h"
#include "insn-eval.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
static inline pud_t pud_mkinvalid(pud_t pud)
{
       return pfn_pud(pud_pfn(pud),
                      __pgprot(pud_flags(pud) & ~(_PAGE_PRESENT|_PAGE_PROTNONE)));
}
#endif

static void ____write_cr4(unsigned long val)
{
	asm volatile("mov %0,%%cr4": "+r" (val) : : "memory");
}

static void __flush_tlb(void)
{
	unsigned long cr4 = __read_cr4();
	____write_cr4(cr4 ^ X86_CR4_PGE);
	____write_cr4(cr4);
}

static uint64_t level2size(unsigned int level)
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
	pte_t *ptep, pte;
	pmd_t *pmdp, pmd;
	pud_t *pudp, pud;
	int64_t remain = len;
	unsigned int level;
	struct smptrace_pte *orig, *tmp;
	int ret;
	unsigned long flags;
	struct list_head local_ptes;

	INIT_LIST_HEAD(&local_ptes);

	while (remain > 0) {
		ptep = lookup_address(va, &level);
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
		orig->va = va;
		orig->level = level;

		/* Swap out PTE */
		switch (orig->level) {
		case PG_LEVEL_4K:
			pte = native_local_ptep_get_and_clear(ptep);
			orig->pte = pte_val(pte);
			break;
		case PG_LEVEL_2M:
			pmdp = (pmd_t *)ptep;
			pmd = pmdp_get(pmdp);
			orig->pte = pmd_val(pmd);
			set_pmd(pmdp, pmd_mkinvalid(pmd));
			break;
		case PG_LEVEL_1G:
			pudp = (pud_t *)ptep;
			pud = pudp_get(pudp);
			orig->pte = pud_val(pud);
			set_pud(pudp, pud_mkinvalid(pud));
			break;
		default:
			pr_err("unexpected page level 0x%x for VA 0x%llx\n",
			       orig->level, (u64)va);
			kfree(orig);
			ret = -EINVAL;
			goto fail;
		}

		pr_info("poisoned PTE for VA=%lx", va);

		remain -= level2size(orig->level);
		va += level2size(orig->level);
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

static struct smptrace_pte *__find_pte(struct smptrace_ctx *ctx, unsigned long va)
{
	struct smptrace_pte *tmp;

	list_for_each_entry(tmp, &ctx->ptes, list) {
		if (tmp->va == va)
			return tmp;
	}
	return NULL;
}

static void restore_pte(struct smptrace_ctx *ctx, unsigned long va,
                        unsigned int len)
{
	unsigned int level;
	pte_t *ptep;
	pmd_t *pmdp;
	pud_t *pudp;
	int64_t remain = len;
	struct smptrace_pte *orig;
	unsigned long flags;

	while (remain > 0) {
		ptep = lookup_address(va, &level);
		if (!ptep) {
			remain -= PAGE_SIZE;
			va += PAGE_SIZE;
			continue;
		}

		spin_lock_irqsave(&ctx->lock, flags);
		orig = __find_pte(ctx, va);
		if (orig)
			list_del(&orig->list);
		spin_unlock_irqrestore(&ctx->lock, flags);

		if (!orig) {
			pr_err("could not find PTE for va=0x%lx\n", va);
			remain -= level2size(level);
			va += level2size(level);
			continue;
		}
		if (orig->level != level)
			pr_warn("PTE level mismatch (prev=%u found=%u)", orig->level, level);

		switch(level) {
		case PG_LEVEL_4K:
			set_pte_atomic(ptep, __pte(orig->pte));
			break;
		case PG_LEVEL_2M:
			pmdp = (pmd_t *)ptep;
			set_pmd(pmdp, __pmd(orig->pte));
			break;
		case PG_LEVEL_1G:
			pudp = (pud_t *)ptep;
			set_pud(pudp, __pud(orig->pte));
			break;
		default:
			pr_err("unexpected page level %u for VA 0x%lx\n", level, va);
			kfree(orig);
			return;
		}

		pr_info("restored PTE for VA=%lx", va);

		remain -= level2size(orig->level);
		va += level2size(orig->level);
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

static int emulate_pf_instruction(struct smptrace_ctx *ctx, struct smptrace_map *map,
                                  struct pt_regs *regs)
{
	struct insn insn;
	enum insn_mmio_type mmio;
	long *data;
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
		/* Zero-extend for 32-bit operation */
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

/* Gadget to force a `ret` and skip bad_area_nosemaphore() completely */
static void __used smptrace_ret_gadget(void) {}

static int __enter_badarea(struct kprobe *kp, struct pt_regs *regs)
{
	struct smptrace_ctx *ctx = container_of(kp, struct smptrace_ctx, badarea_kp);
	struct pt_regs *pf_regs = (struct pt_regs *)regs_get_kernel_argument(regs, 0);
	unsigned long pf_va = regs_get_kernel_argument(regs, 2);
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
	int ret;

	ctx->shadow_va = ioremap(ctx->pa, ctx->len);
	if (!ctx->shadow_va)
		return -ENOMEM;
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
		.entry_handler = __enter_ioremap,
		.handler       = __exit_ioremap,
		.maxactive     = 32,
		.data_size     = sizeof(struct ioremap_args),
		.kp.symbol_name = "ioremap",
	};

	ret = register_kprobe(&ctx->badarea_kp);
	if (ret)
		goto fail_kprobe1;

	ret = register_kprobe(&ctx->iounmap_kp);
	if (ret)
		goto fail_kprobe2;

	ret = register_kretprobe(&ctx->ioremap_krp);
	if (ret)
		goto fail_kprobe3;

	return 0;

fail_kprobe3:
	unregister_kprobe(&ctx->iounmap_kp);
fail_kprobe2:
	unregister_kprobe(&ctx->badarea_kp);
fail_kprobe1:
	iounmap(ctx->shadow_va);
	ctx->shadow_va = NULL;
	ctx->pa = 0;
	return ret;
}

#endif /* CONFIG_X86 */

#ifdef CONFIG_ARM64

#include <asm/traps.h>
#include <asm/pgtable-hwdef.h>
#include <asm/sysreg.h>
#include <asm/esr.h>

// Eh...
#define SMPTRACE_ARM64_LEVEL_PTE	0
#define SMPTRACE_ARM64_LEVEL_PMD	1
#define SMPTRACE_ARM64_LEVEL_PUD	2

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
	unsigned long flags;
	struct list_head local_ptes;
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

static struct smptrace_pte *__find_pte(struct smptrace_ctx *ctx,
                                       unsigned long va)
{
	struct smptrace_pte *tmp;

	list_for_each_entry(tmp, &ctx->ptes, list) {
		if (tmp->va == va)
			return tmp;
	}
	return NULL;
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
	u32 rt;
	u32 rn;
	u32 size;
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

/* Gadget to force a `ret` and skip __do_kernel_fault() completely */
static void __used smptrace_ret_gadget(void) {}

/*
 * Similar to the x86 badarea handler... but hooking __do_kernel_fault instead
 * since badarea_nosemaphore doesn't exist for aarch64 and __do_kernel_fault
 * provides us with the required context to handle the fault (And even
 * richer than i386/amd64...).
 */
static int __enter_do_kernel_fault(struct kprobe *kp, struct pt_regs *regs)
{
	struct smptrace_ctx *ctx = container_of(kp, struct smptrace_ctx,
	                                        badarea_kp);
	unsigned long fault_va = regs_get_kernel_argument(regs, 0);
	unsigned long esr      = regs_get_kernel_argument(regs, 1);
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
		instruction_pointer_set(regs,
		                        (unsigned long)smptrace_ret_gadget);
		return 1;
	}

	return 0;
}

static int smptrace_activate(struct smptrace_ctx *ctx)
{
	int ret;

	ctx->shadow_va = ioremap(ctx->pa, ctx->len);
	if (!ctx->shadow_va)
		{ pr_err("Failed to map shadow VA\n"); return -ENOMEM; }
	readl(ctx->shadow_va);

	ctx->badarea_kp = (struct kprobe){
		.pre_handler = __enter_do_kernel_fault,
		.symbol_name = "__do_kernel_fault",
	};
	ctx->iounmap_kp = (struct kprobe){
		.pre_handler = __enter_iounmap,
		.symbol_name = "iounmap",
	};
	// Must use ioremap_prot for aarch64?
	ctx->ioremap_krp = (struct kretprobe){
		.entry_handler  = __enter_ioremap,
		.handler        = __exit_ioremap,
		.maxactive      = 32,
		.data_size      = sizeof(struct ioremap_args),
		.kp.symbol_name = "ioremap_prot",
	};

	ret = register_kprobe(&ctx->badarea_kp);
	if (ret)
		{ pr_err("Failed to register badarea kprobe\n"); goto fail_kprobe1; }

	ret = register_kprobe(&ctx->iounmap_kp);
	if (ret)
		{ pr_err("Failed to register iounmap kprobe\n"); goto fail_kprobe2; }

	ret = register_kretprobe(&ctx->ioremap_krp);
	if (ret)
		{ pr_err("Failed to register ioremap kretprobe\n"); goto fail_kprobe3; }

	return 0;

fail_kprobe3:
	unregister_kprobe(&ctx->iounmap_kp);
fail_kprobe2:
	unregister_kprobe(&ctx->badarea_kp);
fail_kprobe1:
	iounmap(ctx->shadow_va);
	ctx->shadow_va = NULL;
	ctx->pa = 0;
	return ret;
}

#endif /* CONFIG_ARM64 */

#ifdef CONFIG_RISCV

#include <asm/csr.h>
#include <asm/pgtable.h>

#define SMPTRACE_RISCV_LEVEL_PTE	0
#define SMPTRACE_RISCV_LEVEL_PMD	1
#define SMPTRACE_RISCV_LEVEL_PUD	2

// Would love not to re-invent the wheel
#define RISCV_PTE_V		BIT_ULL(0)
#define RISCV_PTE_R		BIT_ULL(1)
#define RISCV_PTE_X		BIT_ULL(3)
#define RISCV_PTE_LEAF		(RISCV_PTE_R | RISCV_PTE_X)
#define RISCV_PTE_PPN_MASK	GENMASK_ULL(53, 10)
#define RISCV_PTE_PPN_SHIFT	10
#define RISCV_SATP_PPN_MASK	GENMASK_ULL(43, 0)
#define RISCV_SATP_MODE_SHIFT	60
#define RISCV_SATP_MODE_SV48	9UL
#define RISCV_SATP_MODE_SV57	10UL

static inline phys_addr_t riscv_pte_pa(u64 pte)
{
	return (phys_addr_t)((pte & RISCV_PTE_PPN_MASK) >> RISCV_PTE_PPN_SHIFT)
	       << PAGE_SHIFT;
}

static inline void riscv_smptrace_sfence(void* unused)
{
	asm volatile("sfence.vma" ::: "memory");
}

// Both 3-level and 4-level page walking
static pte_t *riscv_walk_pte(unsigned long va, unsigned int *level_out,
                              unsigned long kernel_satp)
{
    unsigned long mode  = kernel_satp >> RISCV_SATP_MODE_SHIFT;
    u64 *table = (u64 *)phys_to_virt(
        (phys_addr_t)(kernel_satp & RISCV_SATP_PPN_MASK) << PAGE_SHIFT);
	unsigned long idx;
	u64 pte;

	if (mode >= RISCV_SATP_MODE_SV57) {
        idx = (va >> 48) & 0x1FF;
        pte = READ_ONCE(table[idx]);
        if (!(pte & RISCV_PTE_V)) return NULL;
        if (pte & RISCV_PTE_LEAF) {
            *level_out = SMPTRACE_RISCV_LEVEL_PUD;
            return (pte_t *)&table[idx];
        }
        table = (u64 *)phys_to_virt(riscv_pte_pa(pte));
    } else if (mode == RISCV_SATP_MODE_SV48) {
		idx = (va >> 39) & 0x1FF;
		pte = READ_ONCE(table[idx]);
		if (!(pte & RISCV_PTE_V))
			return NULL;
		if (pte & RISCV_PTE_LEAF) {
			*level_out = SMPTRACE_RISCV_LEVEL_PUD;
			return (pte_t *)&table[idx];
		}
		table = (u64 *)phys_to_virt(riscv_pte_pa(pte));
	}

	idx = (va >> 30) & 0x1FF;
	pte = READ_ONCE(table[idx]);
	if (!(pte & RISCV_PTE_V))
		return NULL;
	if (pte & RISCV_PTE_LEAF) {
		*level_out = SMPTRACE_RISCV_LEVEL_PUD;
		return (pte_t *)&table[idx];
	}
	table = (u64 *)phys_to_virt(riscv_pte_pa(pte));

	idx = (va >> 21) & 0x1FF;
	pte = READ_ONCE(table[idx]);
	if (!(pte & RISCV_PTE_V))
		return NULL;
	if (pte & RISCV_PTE_LEAF) {
		*level_out = SMPTRACE_RISCV_LEVEL_PMD;
		return (pte_t *)&table[idx];
	}
	table = (u64 *)phys_to_virt(riscv_pte_pa(pte));

	idx = (va >> PAGE_SHIFT) & 0x1FF;
	*level_out = SMPTRACE_RISCV_LEVEL_PTE;
	return (pte_t *)&table[idx];
}

static unsigned long riscv_level2size(unsigned int level)
{
	switch (level) {
	case SMPTRACE_RISCV_LEVEL_PTE: return PAGE_SIZE;
	case SMPTRACE_RISCV_LEVEL_PMD: return PMD_SIZE;
	case SMPTRACE_RISCV_LEVEL_PUD: return PUD_SIZE;
	default: BUG();
	}
}

static int poison_pte(struct smptrace_ctx *ctx, unsigned long va,
                      unsigned int len)
{
	int64_t remain = len;
	struct smptrace_pte *orig, *tmp;
	unsigned long flags;
	struct list_head local_ptes;
	int ret;

	INIT_LIST_HEAD(&local_ptes);

	while (remain > 0) {
		unsigned int level;
		pte_t *ptep = riscv_walk_pte(va, &level, ctx->riscv_kernel_satp);

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
		case SMPTRACE_RISCV_LEVEL_PTE:
			orig->pte = pte_val(READ_ONCE(*ptep));
			WRITE_ONCE(*ptep, __pte(0));
			break;
		case SMPTRACE_RISCV_LEVEL_PMD:
			orig->pte = pmd_val(READ_ONCE(*(pmd_t *)ptep));
			WRITE_ONCE(*(pmd_t *)ptep, __pmd(0));
			break;
		case SMPTRACE_RISCV_LEVEL_PUD:
			orig->pte = pud_val(READ_ONCE(*(pud_t *)ptep));
			WRITE_ONCE(*(pud_t *)ptep, __pud(0));
			break;
		}

		pr_info("poisoned PTE for VA=%lx (level=%u)", va, level);

		remain -= riscv_level2size(level);
		va     += riscv_level2size(level);
		list_add_tail(&orig->list, &local_ptes);
	}

	spin_lock_irqsave(&ctx->lock, flags);
	list_splice_tail(&local_ptes, &ctx->ptes);
	spin_unlock_irqrestore(&ctx->lock, flags);

	on_each_cpu(riscv_smptrace_sfence, NULL, 1);
	return 0;

fail:
	list_for_each_entry_safe(orig, tmp, &local_ptes, list) {
		list_del(&orig->list);
		kfree(orig);
	}
	on_each_cpu(riscv_smptrace_sfence, NULL, 1);
	return ret;
}

static struct smptrace_pte *__find_pte(struct smptrace_ctx *ctx,
                                       unsigned long va)
{
	struct smptrace_pte *tmp;

	list_for_each_entry(tmp, &ctx->ptes, list) {
		if (tmp->va == va)
			return tmp;
	}
	return NULL;
}

static void restore_pte(struct smptrace_ctx *ctx, unsigned long va,
                        unsigned int len)
{
	int64_t remain = len;

	unsigned long flags;

	while (remain > 0) {
		unsigned int level;
		pte_t *ptep = riscv_walk_pte(va, &level, ctx->riscv_kernel_satp);
		struct smptrace_pte *orig;
		unsigned long step;

		if (!ptep) {
			remain -= PAGE_SIZE;
			va     += PAGE_SIZE;
			continue;
		}

		step = riscv_level2size(level);

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
		case SMPTRACE_RISCV_LEVEL_PTE:
			WRITE_ONCE(*ptep, __pte(orig->pte));
			break;
		case SMPTRACE_RISCV_LEVEL_PMD:
			WRITE_ONCE(*(pmd_t *)ptep, __pmd(orig->pte));
			break;
		case SMPTRACE_RISCV_LEVEL_PUD:
			WRITE_ONCE(*(pud_t *)ptep, __pud(orig->pte));
			break;
		}

		pr_info("restored PTE for VA=%lx (level=%u)", va, level);

		remain -= step;
		va     += step;
		kfree(orig);
	}

	// No need to fully flush the TLB since the restored mapping should be valid
	if (irqs_disabled())
		asm volatile("sfence.vma" ::: "memory");
	else
		on_each_cpu(riscv_smptrace_sfence, NULL, 1);
}

static const unsigned short riscv_gpr_offsets[32] = {
	[0]  = 0, // Could do w/o this probably
	[1]  = offsetof(struct pt_regs, ra),
	[2]  = offsetof(struct pt_regs, sp),
	[3]  = offsetof(struct pt_regs, gp),
	[4]  = offsetof(struct pt_regs, tp),
	[5]  = offsetof(struct pt_regs, t0),
	[6]  = offsetof(struct pt_regs, t1),
	[7]  = offsetof(struct pt_regs, t2),
	[8]  = offsetof(struct pt_regs, s0),
	[9]  = offsetof(struct pt_regs, s1),
	[10] = offsetof(struct pt_regs, a0),
	[11] = offsetof(struct pt_regs, a1),
	[12] = offsetof(struct pt_regs, a2),
	[13] = offsetof(struct pt_regs, a3),
	[14] = offsetof(struct pt_regs, a4),
	[15] = offsetof(struct pt_regs, a5),
	[16] = offsetof(struct pt_regs, a6),
	[17] = offsetof(struct pt_regs, a7),
	[18] = offsetof(struct pt_regs, s2),
	[19] = offsetof(struct pt_regs, s3),
	[20] = offsetof(struct pt_regs, s4),
	[21] = offsetof(struct pt_regs, s5),
	[22] = offsetof(struct pt_regs, s6),
	[23] = offsetof(struct pt_regs, s7),
	[24] = offsetof(struct pt_regs, s8),
	[25] = offsetof(struct pt_regs, s9),
	[26] = offsetof(struct pt_regs, s10),
	[27] = offsetof(struct pt_regs, s11),
	[28] = offsetof(struct pt_regs, t3),
	[29] = offsetof(struct pt_regs, t4),
	[30] = offsetof(struct pt_regs, t5),
	[31] = offsetof(struct pt_regs, t6),
};

static unsigned long riscv_get_reg(struct pt_regs *regs, unsigned int reg)
{
	if (reg == 0)
		return 0UL;
	return *(unsigned long *)((char *)regs + riscv_gpr_offsets[reg]);
}

static void riscv_set_reg(struct pt_regs *regs, unsigned int reg,
                          unsigned long val)
{
	if (reg == 0)
		return;
	*(unsigned long *)((char *)regs + riscv_gpr_offsets[reg]) = val;
}

struct riscv_ls_insn {
	unsigned int rd;
	unsigned int rs2;
	unsigned int size;
	bool         is_store;
	bool         sign_extend;
};

static int riscv_decode_rvc_ls_insn(u16 insn16, struct riscv_ls_insn *out)
{
	u32 op     = insn16 & 0x3;
	u32 funct3 = (insn16 >> 13) & 0x7;

	out->sign_extend = false;

	// Compressed load/store(s)
	if (op == 0x0) {
		u32 rp = (insn16 >> 2) & 0x7;

		switch (funct3) {
		// C.LW
		case 0x2:
			out->rd = 8 + rp; out->rs2 = 0;
			out->size = 4;    out->is_store = false; break;
		// C.LD
		case 0x3:
			out->rd = 8 + rp; out->rs2 = 0;
			out->size = 8;    out->is_store = false; break;
		// C.SW
		case 0x6:
			out->rs2 = 8 + rp; out->rd = 0;
			out->size = 4;     out->is_store = true;  break;
		// C.SD
		case 0x7:
			out->rs2 = 8 + rp; out->rd = 0;
			out->size = 8;     out->is_store = true;  break;
		default:
			return -EINVAL;
		}

	} else if (op == 0x2) {
		switch (funct3) {
		// C.LWSP
		case 0x2:
			out->rd = (insn16 >> 7) & 0x1F; out->rs2 = 0;
			out->size = 4;                   out->is_store = false; break;
		// C.LDSP
		case 0x3:
			out->rd = (insn16 >> 7) & 0x1F; out->rs2 = 0;
			out->size = 8;                   out->is_store = false; break;
		// C.SWSP
		case 0x6:
			out->rs2 = (insn16 >> 2) & 0x1F; out->rd = 0;
			out->size = 4;                    out->is_store = true;  break;
		// C.SDSP
		case 0x7:
			out->rs2 = (insn16 >> 2) & 0x1F; out->rd = 0;
			out->size = 8;                    out->is_store = true;  break;
		default:
			return -EINVAL;
		}

	} else {
		return -EINVAL;
	}

	return 0;
}

static int riscv_decode_ls_insn(u32 insn, struct riscv_ls_insn *out)
{
	u32 opcode = insn & 0x7F;
	u32 funct3 = (insn >> 12) & 0x7;

	// Immediate group
	if (opcode == 0x03) {
		out->rd       = (insn >> 7)  & 0x1F;
		out->rs2      = 0;
		out->is_store = false;

		switch (funct3) {
		// LB
		case 0x0: out->size = 1; out->sign_extend = true;  break;
		// LH
		case 0x1: out->size = 2; out->sign_extend = true;  break;
		// LW
		case 0x2: out->size = 4; out->sign_extend = true;  break;
		// LD
		case 0x3: out->size = 8; out->sign_extend = false; break;
		// LBU
		case 0x4: out->size = 1; out->sign_extend = false; break;
		// LHU
		case 0x5: out->size = 2; out->sign_extend = false; break;
		// LWU
		case 0x6: out->size = 4; out->sign_extend = false; break;
		default:  return -EINVAL;
		}

	} else if (opcode == 0x23) {
		out->rs2         = (insn >> 20) & 0x1F;
		out->rd          = 0;
		out->is_store    = true;
		out->sign_extend = false;

		switch (funct3) {
		// SB
		case 0x0: out->size = 1; break;
		// SH
		case 0x1: out->size = 2; break;
		// SW
		case 0x2: out->size = 4; break;
		// SD
		case 0x3: out->size = 8; break;
		default:  return -EINVAL;
		}

	} else {
		return -EINVAL;
	}

	return 0;
}

static int emulate_riscv_fault(struct smptrace_ctx *ctx,
                               struct smptrace_map *map,
                               unsigned long fault_va,
                               struct pt_regs *regs)
{
	struct riscv_ls_insn ls;
	u32 insn;
	u64 val;
	bool is_rvc;

	if (user_mode(regs))
		return -EACCES;

	if (copy_from_kernel_nofault(&insn, (void *)regs->epc, sizeof(insn))) {
		pr_warn_ratelimited("failed to read insn at epc=0x%lx", regs->epc);
		return -EFAULT;
	}

	is_rvc = (insn & 0x3) != 0x3;
	if (is_rvc) {
		if (riscv_decode_rvc_ls_insn((u16)insn, &ls)) {
			pr_warn_ratelimited(
				"unhandled RVC instruction at epc=0x%lx (insn=0x%04x)",
				regs->epc, insn & 0xFFFF);
			return -EINVAL;
		}
	} else {
		if (riscv_decode_ls_insn(insn, &ls)) {
			pr_warn_ratelimited(
				"unrecognised load/store at epc=0x%lx insn=0x%08x",
				regs->epc, insn);
			return -EINVAL;
		}
	}

	if (ls.is_store) {
		unsigned long src = riscv_get_reg(regs, ls.rs2);
		emulate_write(ctx, map, fault_va, ls.size, (u8 *)&src);
	} else {
		val = 0;
		emulate_read(ctx, map, fault_va, ls.size, (u8 *)&val);

		if (ls.rd != 0) {
			if (ls.sign_extend) {
				unsigned int sbits = ls.size * 8;
				s64 sval = (s64)(val << (64 - sbits)) >> (64 - sbits);
				riscv_set_reg(regs, ls.rd, (unsigned long)sval);
			} else {
				riscv_set_reg(regs, ls.rd, (unsigned long)val);
			}
		}
	}

	// Compressed opcodes are 2 bytes, let's take that into account or fun stuff awaits us
	regs->epc += is_rvc ? 2 : 4;
	return 0;
}

/* Gadget to force a `ret` and skip handle_page_fault completely */
static void __used smptrace_ret_gadget(void) {}

// do_trap_load_page_fault and do_trap_store_page are NOKPROBE, let's do handle_page_fault
static int __enter_riscv_handle_page_fault(struct kprobe *kp,
                                           struct pt_regs *regs)
{
	struct smptrace_ctx *ctx = container_of(kp, struct smptrace_ctx,
	                                        badarea_kp);

	struct pt_regs *fault_regs =
		(struct pt_regs *)regs_get_kernel_argument(regs, 0);
	unsigned long fault_va = fault_regs->badaddr;
	unsigned long cause    = fault_regs->cause;
	struct smptrace_map *tmp_map, map_copy = {0};
	unsigned long flags;
	bool found = false;
	int ret;

	if (cause != EXC_LOAD_PAGE_FAULT && cause != EXC_STORE_PAGE_FAULT)
		return 0;

	if (user_mode(fault_regs))
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

	ret = emulate_riscv_fault(ctx, &map_copy, fault_va, fault_regs);
	this_cpu_write(*ctx->in_pf, false);

	if (!ret) {
		instruction_pointer_set(regs,
		                        (unsigned long)smptrace_ret_gadget);
		return 1;
	}

	return 0;
}

static int smptrace_activate(struct smptrace_ctx *ctx)
{
	int ret;

    // Maybe we could do w/o SATP but it should point to kernel page tables on this context
    ctx->riscv_kernel_satp = csr_read(CSR_SATP);
    if (!ctx->riscv_kernel_satp) {
        pr_err("SATP is zero... MMU not enabled (how)?\n");
        return -EINVAL;
    }

	ctx->shadow_va = ioremap(ctx->pa, ctx->len);
	if (!ctx->shadow_va)
		{ pr_err("Failed to map shadow VA\n"); return -ENOMEM; }
	readl(ctx->shadow_va);

	ctx->badarea_kp = (struct kprobe){
		.pre_handler = __enter_riscv_handle_page_fault,
		.symbol_name = "handle_page_fault",
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

	ret = register_kprobe(&ctx->badarea_kp);
	if (ret)
		{ pr_err("Failed to register handle_page_fault kprobe\n"); goto fail_kprobe1; }

	ret = register_kprobe(&ctx->iounmap_kp);
	if (ret)
		{ pr_err("Failed to register iounmap kprobe\n"); goto fail_kprobe2; }

	ret = register_kretprobe(&ctx->ioremap_krp);
	if (ret)
		{ pr_err("Failed to register ioremap kretprobe\n"); goto fail_kprobe3; }

	return 0;

fail_kprobe3:
	unregister_kprobe(&ctx->iounmap_kp);
fail_kprobe2:
	unregister_kprobe(&ctx->badarea_kp);
fail_kprobe1:
	iounmap(ctx->shadow_va);
	ctx->shadow_va = NULL;
	ctx->pa = 0;
	return ret;
}

#endif /* CONFIG_RISCV */

int smptrace_init(struct smptrace_ctx *ctx)
{
	int ret;

	INIT_LIST_HEAD(&ctx->ptes);
	INIT_LIST_HEAD(&ctx->maps);
	spin_lock_init(&ctx->lock);

	ctx->in_pf = alloc_percpu_gfp(bool, GFP_KERNEL_ACCOUNT);
	if (!ctx->in_pf)
		return -ENOMEM;

	ret = smptrace_activate(ctx);
	if (ret) {
		free_percpu(ctx->in_pf);
		return ret;
	}

	return 0;
}

static void smptrace_deactivate(struct smptrace_ctx *ctx)
{
	struct smptrace_map *map, *tmp;
	unsigned long flags;

	/* First, stop hooks on ioremap and iounmap so everyone stops updating
	 * ctx->traced_va */
	unregister_kretprobe(&ctx->ioremap_krp);
	unregister_kprobe(&ctx->iounmap_kp);

	/* Stop #PF hook now that we shouldn't be hitting #PF */
	unregister_kprobe(&ctx->badarea_kp);

	spin_lock_irqsave(&ctx->lock, flags);
	list_for_each_entry_safe(map, tmp, &ctx->maps, list) {
		list_del(&map->list);
		spin_unlock_irqrestore(&ctx->lock, flags);

		restore_pte(ctx, map->va, map->len);
		kfree(map);

		spin_lock_irqsave(&ctx->lock, flags);
	}
	spin_unlock_irqrestore(&ctx->lock, flags);

	if (ctx->shadow_va) {
		iounmap(ctx->shadow_va);
		ctx->shadow_va = NULL;
	}
}

void smptrace_destroy(struct smptrace_ctx *ctx)
{
	smptrace_deactivate(ctx);
	free_percpu(ctx->in_pf);
}
