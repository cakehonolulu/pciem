/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Copyright (C) 2025-2026  Joel Bueno
 *  Copyright (C) 2025-2026  Carlos López
 */

#ifndef PCIEM_POOL_H
#define PCIEM_POOL_H

#include <linux/ioport.h>

int pciem_pool_init(const char *phys_region);
int pciem_pool_insert(struct resource *res);
phys_addr_t pciem_pool_alloc(resource_size_t size);
void pciem_pool_exit(void);

#endif /* PCIEM_POOL_H */
