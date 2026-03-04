// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 2026  Carlos López <carlos.lopezr4096@gmail.com>
 *  Copyright (C) 2026  Joel Bueno <buenocalvachehjoel@gmail.com>
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
#define pr_fmt(fmt) "%s:smptrace: " fmt, KBUILD_MODNAME
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
#include <asm/debugreg.h>
#include <asm/io.h>
#include <asm/tlbflush.h>
#include <asm/traps.h>

#include "insn.h"
#include "insn-eval.h"
#include "trace/smptrace.h"

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
			return -EINVAL;
		}

		pr_info("poisoned PTE for VA=%lx", va);

		remain -= level2size(orig->level);
		va += level2size(orig->level);
		list_add_tail(&orig->list, &ctx->ptes);
	}

	__flush_tlb();
	return 0;

fail:
	/* Free items, but do not bother to unpoison the PTEs. Let our
	 * caller detect the error, and simply return NULL to the caller
	 * of ioremap() */
	list_for_each_entry_safe(orig, tmp, &ctx->ptes, list) {
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

	while (remain > 0) {
		ptep = lookup_address(va, &level);
		if (!ptep)
			return;

		orig = __find_pte(ctx, va);
		if (!orig) {
			pr_err("could not find PTE for va=0x%lx", va);
			return;
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
			return;
		}

		pr_info("restored PTE for VA=%lx", va);

		remain -= level2size(orig->level);
		va += level2size(orig->level);

		list_del(&orig->list);
		kfree(orig);
	}

	__flush_tlb();
}

struct ioremap_args {
	resource_size_t pa;
	unsigned long len;
};

static int __enter_ioremap(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct ioremap_args *args = (struct ioremap_args *)ri->data;

	args->pa = regs_get_kernel_argument(regs, 0);
	args->len = regs_get_kernel_argument(regs, 1);
	return 0;
}

static int __exit_ioremap(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kretprobe *rp = get_kretprobe(ri);
	struct smptrace_ctx *ctx = container_of(rp, struct smptrace_ctx, ioremap_krp);
	struct ioremap_args *args = (struct ioremap_args *)ri->data;
	unsigned long va = regs_return_value(regs);

	if (args->pa < ctx->pa || args->pa >= ctx->pa + ctx->len)
		return 0;

	if (atomic_long_cmpxchg(&ctx->traced_va, 0, va)) {
		pr_warn_ratelimited("duplicate ioremap(0x%llx), skipping", args->pa);
		return 0;
	}

	pr_info("poisoning VA=0x%lx:%lx (PA = 0x%llx:%lx)",
	        va, args->len, ctx->pa, ctx->len);

	/*
	 * Before the PTE is poisoned, traced_len will only be read by
	 * __enter_badarea(), which will not intercept anything until this
	 * kretprobe is done (since nobody will fault on ctx->traced_va, as it is
	 * not visible yet), so we can set it safely now.
	 */
	WRITE_ONCE(ctx->traced_len, args->len);

	/*
	 * Now poison the PTE(s). If we fail, return NULL to the caller of ioremap().
	 * To avoid leaking memory, iounmap() the address. Do the iounmap() *after*
	 * setting traced_va to 0, so that our own iounmap() kprobe does not
	 * interfere.
	 */
	if (poison_pte(ctx, va, args->len)) {
		regs_set_return_value(regs, 0);
		atomic_long_set_release(&ctx->traced_va, 0);
		iounmap((void __iomem *)va);

		pr_warn("failed to poison VA=0x%lx:%lx (PA = 0x%llx:%lx)",
		        va, args->len, ctx->pa, ctx->len);
	}

	return 0;
}

static int __enter_iounmap(struct kprobe *kp, struct pt_regs *regs)
{
	struct smptrace_ctx *ctx = container_of(kp, struct smptrace_ctx, iounmap_kp);
	unsigned long va = regs_get_kernel_argument(regs, 0);
	unsigned long to_clear = va;

	/* If cmpxchg fails it means we are not tracking this VA, so ignore */
	if (!atomic_long_try_cmpxchg(&ctx->traced_va, &va, 0))
		return 0;

	pr_info("restoring VA=0x%lx (PA = 0x%llx)", to_clear, ctx->pa);
	restore_pte(ctx, to_clear, ctx->traced_len);
	WRITE_ONCE(ctx->traced_len, 0);
	return 0;
}

static void __fill_io_notif(struct smptrace_io *io, const u8 *data, u32 size,
                            u64 off)
{
	io->offset = off;
	io->size = size;
	switch(size) {
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

static void emulate_read(struct smptrace_ctx *ctx, u64 addr, u32 size, u8 *dst)
{
	u64 off;
	unsigned long traced_len = READ_ONCE(ctx->traced_len);
	struct smptrace_io io;

	/*
	 * ctx->traced_va is only set to NULL in two situations:
	 *
	 *  - Someone iounmap()s it, at which point that is a bug in the
	 *    driver, as there is a pending access (which we hooked via #PF).
	 *  - Our driver is close()d, which waits until all kprobes (including
	 *    this one) stop running.
	 *
	 * So ctx->traced_va is always safe to read.
	 */
	off  = addr - atomic_long_read(&ctx->traced_va);
	BUG_ON(off >= traced_len || off + size > traced_len);
	memcpy_fromio(dst, ctx->shadow_va + off, size);

	if (ctx->notif.read) {
		__fill_io_notif(&io, dst, size, off);
		ctx->notif.read(ctx, &io);
	}
}

static void emulate_write(struct smptrace_ctx *ctx, u64 addr, u32 size,
                          const u8 *src)
{
	u64 off;
	unsigned long traced_len = READ_ONCE(ctx->traced_len);
	struct smptrace_io io = {0};

	off  = addr - atomic_long_read(&ctx->traced_va);
	BUG_ON(off >= traced_len || off + size > traced_len);
	if (!ctx->stop_writes)
		memcpy_toio(ctx->shadow_va + off, src, size);

	pr_debug("Write @ 0x%llx:%x", off, size);

	if (ctx->notif.write) {
		__fill_io_notif(&io, src, size, off);
		ctx->notif.write(ctx, &io);
	}
}

static int decode_pf_instr(struct pt_regs *regs, struct insn *insn)
{
	u8 buf[MAX_INSN_SIZE];

	if (copy_from_kernel_nofault(buf, (void *)regs->ip, MAX_INSN_SIZE))
		return -EINVAL;

	return insn_decode_kernel(insn, buf);
}

static int emulate_pf_instruction(struct smptrace_ctx *ctx, struct pt_regs *regs)
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
		emulate_write(ctx, addr, len, (u8 *)data);
		break;
	case INSN_MMIO_WRITE_IMM:
		BUG_ON(len > 4);
		emulate_write(ctx, addr, len, (u8 *)insn.immediate1.bytes);
		break;
	case INSN_MMIO_READ:
		/* Zero-extend for 32-bit operation */
		if (len == 4)
			*data = 0;
		emulate_read(ctx, addr, len, (u8 *)data);
		break;
	case INSN_MMIO_READ_ZERO_EXTEND:
		memset(data, 0, insn.opnd_bytes);
		emulate_read(ctx, addr, len, (u8 *)data);
		break;
	case INSN_MMIO_READ_SIGN_EXTEND:
		/* Sign extend based on operand size */
		if (len == 1) {
			u8 val;
			emulate_read(ctx, addr, len, &val);
			sign_byte = (val & 0x80) ? 0xff : 0x00;
		} else {
			u16 val;
			emulate_read(ctx, addr, len, (u8 *)&val);
			sign_byte = (val & 0x8000) ? 0xff : 0x00;
		}
		memset(data, sign_byte, insn.opnd_bytes);
		emulate_read(ctx, addr, len, (u8 *)data);
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
	unsigned long traced_va = atomic_long_read(&ctx->traced_va);
	unsigned long traced_len = READ_ONCE(ctx->traced_len);
	int ret;

	if (!traced_va || pf_va < traced_va || pf_va >= traced_va + traced_len)
		return 0;

	if (this_cpu_xchg(*ctx->in_pf, true)) {
		pr_warn("reentrant #PF on 0x%lx, ignoring", traced_va);
		return 0;
	}

	ret = emulate_pf_instruction(ctx, pf_regs);
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

int smptrace_init(struct smptrace_ctx *ctx)
{
	int ret;

	INIT_LIST_HEAD(&ctx->ptes);

	ctx->in_pf = alloc_percpu_gfp(bool, GFP_KERNEL_ACCOUNT);
	if (!ctx->in_pf)
		return -ENOMEM;

	ctx->badarea_kp = (struct kprobe) {
		.pre_handler = __enter_badarea,
		.symbol_name = "bad_area_nosemaphore",
	};

	ctx->iounmap_kp = (struct kprobe) {
		.pre_handler = __enter_iounmap,
		.symbol_name = "iounmap",
	};

	ctx->ioremap_krp = (struct kretprobe) {
		.entry_handler = __enter_ioremap,
		.handler = __exit_ioremap,
		.maxactive = 32,
		.data_size = sizeof(struct ioremap_args),
		.kp = {
			.symbol_name = "ioremap",
		},
	};

	ret = smptrace_activate(ctx);
	if (ret) {
		free_percpu(ctx->in_pf);
		return ret;
	}

	return 0;
}

static void smptrace_deactivate(struct smptrace_ctx *ctx)
{
	unsigned long va;

	/* First, stop hooks on ioremap and iounmap so everyone stops updating
	 * ctx->traced_va */
	unregister_kretprobe(&ctx->ioremap_krp);
	unregister_kprobe(&ctx->iounmap_kp);

	/* Restore the VA, if we had captured any, so we stop getting #PFs */
	va = atomic_long_xchg(&ctx->traced_va, 0);
	if (va) {
		restore_pte(ctx, va, ctx->traced_len);
		WRITE_ONCE(ctx->traced_len, 0);
	}

	/* Stop #PF hook now that we shouldn't be hitting #PF */
	unregister_kprobe(&ctx->badarea_kp);

	iounmap(ctx->shadow_va);
	ctx->shadow_va = 0;
}

void smptrace_destroy(struct smptrace_ctx *ctx)
{
	smptrace_deactivate(ctx);
	free_percpu(ctx->in_pf);
}
