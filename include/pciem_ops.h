#ifndef PCIEM_OPS_H
#define PCIEM_OPS_H

#include "pciem_framework.h"

struct pciem_epc_ops
{
    /**
     * @brief Fills the PCI config space base fields (vendor/device ID, etc).
     * Called once during init, BEFORE capability registration.
     * PCIem handles capability list building dynamically.
     * @param cfg A 256-byte buffer to write config data to.
     */
    void (*fill_config_space)(u8 *cfg);

    /**
     * @brief Registers PCI capabilities for this device.
     * Called once during init, AFTER fill_config_space.
     * The plugin should call pciem_add_cap_* functions here.
     * @param v The pciem host.
     * @return 0 on success.
     */
    int (*register_capabilities)(struct pciem_root_complex *v);

    /**
     * @brief Registers all BARs for this device.
     * Called once during init, BEFORE memory allocation.
     * The plugin MUST call pciem_register_bar() here for each
     * BAR it needs. BAR0 is required for the control interface.
     * @param v The pciem host.
     * @return 0 on success.
     */
    int (*register_bars)(struct pciem_root_complex *v);

    /**
     * @brief Allocate and initialize device-specific state.
     * The plugin should kzalloc its state struct and
     * assign it to v->device_private_data.
     * @return 0 on success.
     */
    int (*init_emulation_state)(struct pciem_root_complex *v);

    /**
     * @brief Free device-specific state.
     * The plugin should kfree(v->device_private_data).
     */
    void (*cleanup_emulation_state)(struct pciem_root_complex *v);

    /**
     * @brief Called periodically (on timeout) or on an event.
     * This function is the device's entire state machine.
     *
     * @param v The pciem host.
     * @param proxy_irq_fired True if this poll was triggered by
     * a proxy IRQ, false otherwise (timeout or page fault).
     */
    void (*poll_device_state)(struct pciem_root_complex *v, bool proxy_irq_fired);

    void (*set_command_watchpoint)(struct pciem_root_complex *v, bool enable);
};

#endif /* PCIEM_OPS_H */