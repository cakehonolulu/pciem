/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Copyright (C) 2025-2026  Joel Bueno
 *  Copyright (C) 2025-2026  Carlos López
 */

#ifndef PCIEM_USERSPACE_H
#define PCIEM_USERSPACE_H

#include "pciem_api.h"
#include "trace/smptrace.h"

#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/poll.h>
#include <linux/pci_regs.h>

int pciem_userspace_init(void);
void pciem_userspace_cleanup(void);
struct pciem_userspace_state *pciem_userspace_create(void);

extern const struct file_operations pciem_device_fops;

#endif
