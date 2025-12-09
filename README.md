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
│ │    │      PCIem Framework       ◄───Exposes──────┐             ┌─Communicates───►          QEMU Backend                  │    │
│ │    │                            │      │         │             │           │    │                                        │    │
│ │    │ - PCI Config Space         │      │       ┌─▼─────────────▼─┐         │    │ - Emulates PCIe device logic           │    │
│ │    │                            │      │       │  "Shim" Layer   │         │    │                                        │    │
│ │    │ - BAR Mappings             │      │       │                 │         │    │ - Directly accesses /dev/pciem_shim    │    │
│ │    │                            │      │       │ /dev/pciem_shim │         │    │                                        │    │
│ │◄───┤ - INT/MSI/MSI-X Interrupts │      │       │                 │         │    └────────────────────────────────────────┘    │
│ │    │                            │      │       └─────────────────┘         │                                                  │
│ │    │ - DMA (With/without IOMMU) │      │                                   │                                                  │
│ │    │                            │      │                                   └──────────────────────────────────────────────────┘
│ │    │ - P2P DMA                  │      │                                                         Userspace                     
│ │    │                            │      │                                                                                       
│ │    └────────────────────────────┘      │                                                                                       
│ │                                        │                                                                                       
│ │                                        │                                                                                       
│ │    PCIe driver is unaware of PCIem     │                                                                                       
│ │                                        │                                                                                       
│ │                                        │                                                                                       
│ │ ┌──────────────────────────────────┐   │                                                                                       
│ │ │          Real PCIe Driver        │   │                                                                                       
│ │ │                                  │   │                                                                                       
│ └─┤ - Untouched logic from production│   │                                                                                       
│   │                                  │   │                                                                                       
│   └──────────────────────────────────┘   │                                                                                       
│                                          │                                                                                       
└──────────────────────────────────────────┘                                                                                       
               Kernel Space                                                                                                         
```

## Current Features

- **BAR Support**: Register and manage up to 6 Base Address Registers
- **Hardware Watchpoints**: Event-driven architecture using CPU watchpoints for MMIO detection
- **Legacy IRQ/MSI/MSI-X Support**: Full interrupt support with dynamic triggering
- **PCI Capability Framework**: Modular PCI capabilities system (Linked-list underneath)
- **DMA System**: IOMMU-aware DMA operations with atomic memory operations support
- **P2P DMA**: Peer-to-peer DMA between devices with whitelist-based access control
- **QEMU Integration**: Direct forwarding to QEMU device backends via shim layer

## Building

The framework consists of kernel modules and userspace components:

```bash
# Clone the repo
git clone https://github.com/cakehonolulu/pciem

cd pciem

# Build kernel modules
make

# Load the framework
insmod pciem_framework.ko use_qemu_forwarding=1 pciem_phys_regions="bar0:0x1bf000000:0x10000,bar2:0x1bf010000:0x100000"
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
    void (*poll_device_state)(struct pciem_root_complex *v, bool proxy_irq_fired);
    void (*set_command_watchpoint)(struct pciem_root_complex *v, bool enable);
};
```

See `protopciem_device.c` for a reference implementation of a simple GPU-like dumb-framebuffer accelerator device.

## QEMU Integration

When running in forwarding mode:

1. Start QEMU:
```bash
qemu-system-x86_64 ...
```

This assumes you instantiate your backend within the board, but you could probably also try and instantiate it as a ```SysBusDevice```.

The QEMU backend directly opens and communicates with `/dev/pciem_shim` - no separate userspace proxy is needed (But you can alter the architecture as per your needs to improve upon the original design).

## P2P DMA

PCIem supports peer-to-peer DMA operations between the guest and host devices on the physical bus. Configure whitelisted P2P regions at module load time:

```bash
sudo insmod kernel/pciem.ko p2p_regions="0x9ffe00000:0x1000,0x9ffe01000:0x1000"
```

## Components

- `kernel/framework/pciem_framework.c`: Core framework implementing "virtual PCI host bridge"
- `kernel/framework/pciem_capabilities.c`: PCI capability management (MSI, MSI-X, PM, PCIe, etc.)
- `kernel/framework/pciem_dma.c`: IOMMU-aware DMA engine with atomic operations
- `kernel/framework/pciem_p2p.c`: Peer-to-peer DMA management with whitelist support
- `kernel/plugin/protopciem_device.c`: Example dumb-framebuffer device plugin
- `kernel/driver/protopciem_driver.c`: Reference PCIe device driver
- `qemu/protopciem_backend.c`: QEMU device backend implementation

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
