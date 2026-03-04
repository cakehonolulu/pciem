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

struct pciem_irqfd
{
    struct list_head list;
    struct eventfd_ctx *trigger;
    wait_queue_entry_t wait;
    struct work_struct inject_work;
    struct pciem_userspace_state *us;
    uint32_t vector;
    uint32_t flags;
};

#define PCIEM_UNREGISTERED 0
#define PCIEM_REGISTERING  1
#define PCIEM_REGISTERED   2

struct pciem_irqfds {
    spinlock_t lock;
    struct list_head items;
};

struct pciem_tracer {
    struct pciem_userspace_state *us;
    struct smptrace_ctx ctx;
};

struct pciem_userspace_state
{
    struct pciem_root_complex *rc;

    struct hlist_head pending_requests[256];
    spinlock_t pending_lock;
    uint64_t next_seq;

    atomic_t registered;
    atomic_t event_pending;

    struct pciem_shared_ring *shared_ring;
    spinlock_t shared_ring_lock;

    struct eventfd_ctx *eventfd;
    spinlock_t eventfd_lock;

    struct pciem_irqfds irqfds;

    /* BAR read/write trackers */
    struct pciem_tracer tracers[PCI_STD_NUM_BARS];
};

struct pciem_pending_request
{
    struct hlist_node node;
    uint64_t seq;
    struct completion done;
    uint64_t response_data;
    int response_status;
};

int pciem_userspace_init(void);
void pciem_userspace_cleanup(void);
struct pciem_userspace_state *pciem_userspace_create(void);
void pciem_userspace_destroy(struct pciem_userspace_state *us);
int pciem_userspace_register_device(struct pciem_userspace_state *us);
void pciem_userspace_queue_event(struct pciem_userspace_state *us, struct pciem_event *event);
int pciem_userspace_wait_response(struct pciem_userspace_state *us, uint64_t seq, uint64_t *data_out,
                                  unsigned long timeout_ms);

extern const struct file_operations pciem_device_fops;

#endif
