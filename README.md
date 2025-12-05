<div align="center">
  <img src="resources/icon.png">
</div>

<div align="center">
  A Linux kernel framework for synthetic PCIe device emulation with QEMU forwarding support.
</div>

<div align="center">
  https://cakehonolulu.github.io/introducing-pciem/
</div>


## What is PCIem?

PCIem is a framework that creates virtual PCIe devices in the Linux kernel by leveraging a few novel techniques to populate synthetic cards as legitimate PCI devices to the host OS.

To brief what PCIem is: a framework for developing and testing PCIe device drivers without requiring actual hardware.

## Architecture

```
┌──────────────────────────────────────────┐                                   ┌──────────────────────────────────────────────────┐
│                                          │                                   │                                                  │
│ ┌─────────►Host Linux Kernel             │                                   │                  Linux Userspace                 │
│ │                                        │                                   │                                                  │
│ │                                        │                                   │                                                  │
│ │    ┌────────────────────────────┐      │                                   │    ┌────────────────────────────────────────┐    │
│ │    │      PCIem Framework       ◄───Exposes──────┐               ┌─Communicates─►          PCIem Userspace Proxy         │    │
│ │    │                            │      │         │               │         │    │                                        │    │
│ │    │ - PCI Config Space         │      │       ┌─▼───────────────▼─┐       │    │ - Bridge between user and kernel space │    │
│ │    │                            │      │       │    "Shim" Layer   │       │    │                                        │    │
│ │    │ - BAR Mappings             │      │       │                   │       │    │ - Safely handles duplex communication  │    │
│ │◄───┤                            │      │       │ - /dev/pciem_shim │       │    │                                        │    │
│ │    │ - INT/MSI/MSI-X Interrupts │      │       │                   │       │    │ - From/to QEMU forwarding              │    │
│ │    │                            │      │       └───────────────────┘       │    │                                        │    │
│ │    │ - DMA (With/without IOMMU) │      │                                   │    └────────────────────▲───────────────────┘    │
│ │    │                            │      │                                   │                         │                        │
│ │    └────────────────────────────┘      │                                   │                         │                        │
│ │                                        │                                   │                     Interacts                    │
│ │    PCIe driver is unaware of PCIem     │                                   │                         │                        │
│ │                                        │                                   │                         │                        │
│ │ ┌──────────────────────────────────┐   │                                   │           ┌─────────────▼─────────────┐          │
│ │ │          Real PCIe Driver        │   │                                   │           │        QEMU Backend       │          │
│ │ │                                  │   │                                   │           │                           │          │
│ └─┤ - Unouched logic from production │   │                                   │           │ - Emulating PCIe instance │          │
│   │                                  │   │                                   │           │                           │          │
│   └──────────────────────────────────┘   │                                   │           └───────────────────────────┘          │
│                                          │                                   │                                                  │
└──────────────────────────────────────────┘                                   └──────────────────────────────────────────────────┘
               Kernel Space                                                                          Userspace                                  
```

## Current Features

- **BAR Support**: Register and manage up to 6 Base Address Registers
- **Page Fault Interception**: No polling! Purely event-based (At the cost of trapping accesses; no race conditions!)
- **Legacy IRQ/MSI/MSI-X Support**: Full interrupt support!
- **PCI Capability Framework**: Modular capabilities system (Linked-list underneath)
- **DMA System**: IOMMU-aware DMA operations (Preliminary atomic memory operations support!)

## Building

The framework consists of kernel modules and userspace components:

```bash
# Clone the repo
git clone https://github.com/cakehonolulu/pciem

cd pciem

# Build kernel modules
make

# Load the framework
insmod pciem_framework.ko use_qemu_forwarding=1 pciem_phys_regions="bar0:0x1bf000000:0x10000,bar2:0x1bf010000:0x100000
```

## Memory Carving

PCIem requires physical memory regions to be reserved at boot time using the kernel command line:

```
memmap=2M$0x1bf000000
```

This "carves out" 2MB starting at physical address 0x1bf000000, basically marking them as ```Type 12 (0xC)``` on the E820 memory map (On x86_64 at least).

## Device Plugin System

Device-specific logic is implemented via the `pciem_device_ops` interface:

```c
struct pciem_epc_ops {
    void (*fill_config_space)(u8 *cfg);
    int (*register_capabilities)(struct pciem_root_complex *v);
    int (*register_bars)(struct pciem_root_complex *v);
    int (*init_emulation_state)(struct pciem_root_complex *v);
    void (*cleanup_emulation_state)(struct pciem_root_complex *v);
    void (*poll_device_state)(struct pciem_root_complex *v, bool proxy_irq);
};
```

See `protopciem_device.c` for a reference implementation of a simple GPU-like dumb-framebuffer accelerator device.

## QEMU Integration

When running in forwarding mode:

1. Start QEMU with the backend device:
```bash
qemu-system-x86_64 ... -device protopciem-backend,chardev=pciem \
  -chardev socket,id=pciem,path=/tmp/pciem.sock,server=on,wait=off
```

2. Run the userspace proxy (You may need `sudo`):
```bash
./pciem_uproxy /tmp/pciem.sock /dev/pciem_shim
```

The proxy should run in the background doing the communication between QEMU and the PCIe stack.

## Components

- `kernel/framework/pciem_framework.c`: Core framework implementing "virtual PCI host bridge"
- `kernel/framework/pciem_capabilities.c`: PCI capability management (MSI, MSI-X, PM, etc.)
- `kernel/framework/pciem_dma.c`: IOMMU-aware DMA engine
- `userspace/pciem_uproxy.c`: Userspace proxy for QEMU forwarding
- `qemu/protopciem_backend.c`: QEMU device backend implementation
- `kernel/plugin/protopciem_device.c`: Example dumb-framebuffer description for PCIem

## Current Limitations

- Requires pre-carved physical memory regions
- Single device per framework instance
- Limited to x86_64 architecture?

## License

Dual MIT/GPLv2 (pciem_framework.c and protopciem_driver.c)

MIT (Rest)

## References

- Blog post: https://cakehonolulu.github.io/introducing-pciem/
- PCI Express specification: https://pcisig.com/specifications
