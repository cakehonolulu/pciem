/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Copyright (C) 2026  Carlos López <carlos.lopezr4096@gmail.com>
 *  Copyright (C) 2026  Joel Bueno <buenocalvachejoel@gmail.com>
 */
#ifndef _PCIEM_SMPTRACE_INTERNAL
#define _PCIEM_SMPTRACE_INTERNAL
#include "trace/smptrace.h"

struct ioremap_args {
	resource_size_t pa;
	unsigned long len;
};

static void __used smptrace_ret_gadget(void) {}

static inline struct smptrace_pte *
smptrace_find_pte(struct smptrace_map *map, unsigned long va)
{
	struct smptrace_pte *tmp;

	list_for_each_entry(tmp, &map->ptes, list) {
		if (tmp->va == va)
			return tmp;
	}
	return NULL;
}

static inline bool smptrace_find_map_rcu(struct smptrace_ctx *ctx,
					  unsigned long va, struct smptrace_map *dst)
{
	struct smptrace_map *tmp_map;

	guard(rcu)();

	list_for_each_entry_rcu(tmp_map, &ctx->maps, list) {
		if (va >= tmp_map->va && va < tmp_map->va + tmp_map->len) {
			*dst = *tmp_map;
			return true;
		}
	}

	return false;
}


int smptrace_register_probes(struct smptrace_ctx *ctx);
int smptrace_enter_ioremap(struct kretprobe_instance *ri, struct pt_regs *regs);
int smptrace_exit_ioremap(struct kretprobe_instance *ri, struct pt_regs *regs);
int smptrace_enter_iounmap(struct kprobe *rp, struct pt_regs *regs);
void smptrace_emulate_write(struct smptrace_ctx *ctx, struct smptrace_map *map,
                            u64 addr, u32 size, const u8 *src);
void smptrace_emulate_read(struct smptrace_ctx *ctx, struct smptrace_map *map,
                           u64 addr, u32 size, u8 *dst);

/* Arch-specific functionality. Architectures must implement these in order
 * to be supported by smptrace */

int smptrace_arch_activate(struct smptrace_ctx *ctx);
int smptrace_arch_poison_pte(struct smptrace_map *map);
void smptrace_arch_restore_pte(struct smptrace_map *map);

#endif
