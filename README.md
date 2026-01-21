<div align="center">
  <img src="resources/icon.png">
</div>

<div align="center">
  A Linux kernel framework for synthetic PCIe device emulation entirely in userspace.
</div>

<div align="center">
  https://cakehonolulu.github.io/introducing-pciem/

  https://cakehonolulu.github.io/docs/pciem/
</div>

[![CI](https://github.com/cakehonolulu/pciem/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/cakehonolulu/pciem/actions/workflows/ci.yml)

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
│ │    │      PCIem Framework       ◄──────┼────────────►/dev/pciem◄───────────┼────►          Userspace PCI shim            │    │
│ │    │                            │      │                                   │    │                                        │    │
│ │    │ - PCI Config Space         │      │                                   │    │ - Emulates PCIe device logic           │    │
│ │    │                            │      │                                   │    │                                        │    │
│ │    │ - BAR Mappings             │      │                                   │    └────────────────────────────────────────┘    │
│ │    │                            │      │                                   │                                                  │
│ │◄───┤ - INT/MSI/MSI-X Interrupts │      │                                   │                                                  │
│ │    │                            │      │                                   └──────────────────────────────────────────────────┘
│ │    │ - DMA (With/without IOMMU) │      │                                                         Userspace                     
│ │    │                            │      │                                                                                       
│ │    │ - P2P DMA                  │      │                                                                                       
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

- **BAR Support**: Register and manage BARs programmatically
- **Watchpoints**: Event-driven architecture using CPU watchpoints for access detection
- **Legacy IRQ/MSI/MSI-X Support**: Full interrupt support with dynamic triggering
- **PCI Capability Framework**: Modular PCI capabilities system (Linked-list underneath)
- **DMA System**: IOMMU-aware DMA operations with atomic memory operations support
- **P2P DMA**: Peer-to-peer DMA between devices with whitelist-based access control
- **Userspace-defined**: Implement your PCIe prototypes anywhere

# Examples

## ProtoPCIem card

The card is programmed entirely in QEMU, who does all the userspace initialization and command handling from the real driver running in the host. Can run software-rendered DOOM (Submits finished frames with DMA to the card which QEMU displays) and also simple OpenGL 1.X games (On the screenshots, tyr-glquake and xash3d; thanks to a custom OpenGL state machine implemented entirely in QEMU that software-renders the command lists and updates the internal state accordingly).

<p align="center">
  <img width="1903" height="1029" alt="imagen" src="https://github.com/user-attachments/assets/16f64475-ee51-4f79-ae17-b06363f0b12a" />
</p>

<p align="center">
  <img width="1757" height="893" alt="imagen" src="https://github.com/user-attachments/assets/4ad00e14-83e5-4e1f-b374-fbaa92def4e3" />
</p>

<p align="center">
  <img width="1227" height="846" alt="imagen" src="https://github.com/user-attachments/assets/d21a7d84-f857-4790-bdc6-7bf2714e9eda" />
</p>

## License

Dual MIT/GPLv2 (pciem_framework.c and protopciem_driver.c)

MIT (Rest)

## References

- Blog post: https://cakehonolulu.github.io/introducing-pciem/
- Documentation: https://cakehonolulu.github.io/docs/pciem/
- PCI Express specification: https://pcisig.com/specifications
