#ifndef PCIEM_OPS_H
#define PCIEM_OPS_H

#include "pciem_framework.h"

struct pciem_device_ops
{
    /**
     * @brief Fills the PCI config space.
     * Called once during init.
     * @param cfg A 256-byte buffer to write config data to.
     */
    void (*fill_config_space)(u8 *cfg);

    /**
     * @brief Sets up BAR resources.
     * Called once during init. The framework allocates
     * v->pci_mem_res for BAR0, but this op lets the
     * plugin add more BARs.
     * @param v The pciem host.
     * @param resources The list of resources to add to.
     * @return 0 on success.
     */
    int (*setup_bars)(struct pciem_host *v, struct list_head *resources);

    /**
     * @brief Allocate and initialize device-specific state.
     * The plugin should kzalloc its state struct and
     * assign it to v->device_private_data.
     * @return 0 on success.
     */
    int (*init_emulation_state)(struct pciem_host *v);

    /**
     * @brief Free device-specific state.
     * The plugin should kfree(v->device_private_data).
     */
    void (*cleanup_emulation_state)(struct pciem_host *v);

    /**
     * @brief Called periodically (on timeout) or on an event.
     * This function is the device's entire state machine.
     * It MUST check for new commands by polling the BAR.
     * It MUST check for command completions if proxy_irq_fired is true.
     *
     * @param v The pciem host.
     * @param proxy_irq_fired True if this poll was triggered by
     * a proxy IRQ, false otherwise (timeout or page fault).
     */
    void (*poll_device_state)(struct pciem_host *v, bool proxy_irq_fired);
};

/**
 * @brief Registration function exported by the framework.
 * The plugin MUST call this from pciem_device_plugin_init().
 */
void pciem_register_ops(struct pciem_device_ops *ops);

#endif /* PCIEM_OPS_H */