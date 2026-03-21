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

static struct smptrace_pte *__find_pte(struct smptrace_ctx *ctx, unsigned long va)
{
	struct smptrace_pte *tmp;

	list_for_each_entry(tmp, &ctx->ptes, list) {
		if (tmp->va == va)
			return tmp;
	}
	return NULL;
}

static void __used smptrace_ret_gadget(void) {}

static int smptrace_register_probes(struct smptrace_ctx *ctx)
{
	int ret;

	ret = register_kprobe(&ctx->badarea_kp);
	if (ret) {
		pr_err("Failed to register fault kprobe (%s): %d\n",
		       ctx->badarea_kp.symbol_name, ret);
		goto fail_badarea;
	}

	ret = register_kprobe(&ctx->iounmap_kp);
	if (ret) {
		pr_err("Failed to register iounmap kprobe: %d\n", ret);
		goto fail_iounmap;
	}

	ret = register_kretprobe(&ctx->ioremap_krp);
	if (ret) {
		pr_err("Failed to register ioremap kretprobe (%s): %d\n",
		       ctx->ioremap_krp.kp.symbol_name, ret);
		goto fail_ioremap;
	}

	return 0;

fail_ioremap:
	unregister_kprobe(&ctx->iounmap_kp);
fail_iounmap:
	unregister_kprobe(&ctx->badarea_kp);
fail_badarea:
	iounmap(ctx->shadow_va);
	ctx->shadow_va = NULL;
	ctx->pa = 0;
	return ret;
}

/*
 * Each backend must provide:
 *   static int  poison_pte(struct smptrace_ctx *, unsigned long va, unsigned int len);
 *   static void restore_pte(struct smptrace_ctx *, unsigned long va, unsigned int len);
 *   static int  smptrace_activate(struct smptrace_ctx *);
 *
 * Backends may freely call emulate_read(), emulate_write(), __find_pte(),
 * smptrace_ret_gadget(), smptrace_register_probes(), __enter_ioremap(),
 * __exit_ioremap(), and __enter_iounmap().
 */

#if defined(CONFIG_X86)
#include "arch/x86/smptrace_arch.c"
#elif defined(CONFIG_ARM64)
#include "arch/arm64/smptrace_arch.c"
#elif defined(CONFIG_RISCV)
#include "arch/riscv/smptrace_arch.c"
#else
#error "smptrace: unsupported architecture"
#endif

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
