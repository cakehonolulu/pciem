/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Copyright (C) 2026  Carlos López <carlos.lopezr4096@gmail.com>
 *  Copyright (C) 2026  Joel Bueno <buenocalvachejoel@gmail.com>
 */
#ifndef _PCIEM_SMPTRACE_H
#define _PCIEM_SMPTRACE_H
#include <asm/pgtable.h>
#include <linux/kprobes.h>
#include <linux/compiler.h>

union smptrace_data {
	u8 raw[8];
	u8 byte;
	u16 word;
	u32 dword;
	u64 qword;
};

struct smptrace_io {
	u64 offset;
	union smptrace_data data;
	u32 size;
};

struct smptrace_ctx;

typedef void (*smptrace_handler_t)(struct smptrace_ctx *ctx, struct smptrace_io *);

/* User defined hooks */
struct smptrace_notifier {
	smptrace_handler_t read;
	smptrace_handler_t write;
};

/* An un-poisoned PTE */
struct smptrace_pte {
	struct list_head list;
	unsigned long va;
	pteval_t pte;
	unsigned int level;
};

/* An active traced ioremap region */
struct smptrace_map {
	struct list_head list;
	unsigned long va;
	unsigned long len;
	resource_size_t pa;
};

struct smptrace_ctx {
	/* User hooks */
	struct smptrace_notifier notif;
	/* User-defined data for this tracer */
	uint64_t opaque;
	/* PA to be tracked */
	resource_size_t pa;
	/* Size of PA to be tracked */
	unsigned long len;
	/* Whether to emulate writes into the BAR */
	bool stop_writes;

#ifdef CONFIG_RISCV
    /*
     * Snapshotted SATP value within kernel context.
	 *
	 * Helps us avoid pulling certain symbols that would
	 * make modpost complain.
     */
    unsigned long riscv_kernel_satp;
#endif

	/*** Do not touch below here ***/

	/* Protects structural modifications to the lists */
	spinlock_t lock;

	/* Un-poisoned PTEs */
	struct list_head ptes;
	/* Active mapped VA regions */
	struct list_head maps;

	/* Tracing hooks */
	struct kretprobe ioremap_krp;
	struct kprobe iounmap_kp;
	struct kprobe badarea_kp;

	/* Address of the shadow memory we maintain. Size is ctx->len */
	void __iomem *shadow_va;

	/* Whether this CPU is handling #PF or not */
	bool __percpu *in_pf;
};


int smptrace_init(struct smptrace_ctx *ctx);
void smptrace_destroy(struct smptrace_ctx *ctx);

#endif
