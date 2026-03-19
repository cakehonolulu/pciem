<div align="center">
  <img src="resources/icon.svg" width="300" height="300">
  <br>
  <h2>PCIem</h2>
</div>

<div align="center">
  A Linux kernel framework enabling synthetic userspace PCIe device emulation. | <a href="https://cakehonolulu.github.io/docs/pciem">Documentation</a>
</div>

## What is PCIem?

PCIem is a framework that creates virtual PCIe devices in the Linux kernel by leveraging a few novel techniques to populate synthetic cards as legitimate PCI devices to the host OS.

To brief what PCIem is: a framework for (Albeit not limited to) developing and testing PCIe device drivers without requiring actual hardware on the host.

## Comparison with libfvio-user

`PCIem` and `libfvio-user` are two different solutions for different needs, there may be confusion when comparing both so herein the differences (See [figure 1](#figure1) for more).

The main one is that `libvfio-user` usually relies on a client (That implements the `vfio-user` protocol), usually QEMU (Through KVM, using VM exits) to expose the emulated PCIe device to the guest. You write your `vfio` server (With a callback mechanism usually) which then interacts with the client.

What `PCIem` does instead is, expose the device *directly* on the host; no KVM, no guests, no virtual machines, nothing. The device appears on the host's PCIe bus as if it was physically connected.

<div align="center" id="figure1">

| Feature | PCIem | libfvio-user |
| :--- | :--- | :--- |
| **Connection** | Device file (`/dev/pciem`) | UNIX Sockets (`vfio-user` protocol) |
| **Target driver runs on** | Host | Guest OS |
| **Emulated device runs on** | Userspace | Userspace |
| **Device accesses** | Direct (Within host) | Virtualized (Guest to Host) |

_Figure 1: Comparison between frameworks_

</div>

## Architecture

```mermaid
graph LR
    subgraph Kernel ["Host Linux Kernel"]
        direction TB

        RealDriver["Real PCIe Driver"]

        subgraph Framework ["PCIem Framework"]
            direction TB
            Config["PCI Config Space"]
            BARs["BARs"]
            IRQ["Interrupts"]
            DMA["DMA / IOMMU"]
        end

    end

    Interface(("/dev/pciem"))

    subgraph User ["Linux Userspace"]
        direction TB
        Shim["Device Emulation"]
    end

    Framework <==> Interface
    Interface <==> Shim
```

## Current Features

- **BAR creation**: Programmatically create and monitor BAR regions.
- **BAR MMIO tracing**: MMIO read/write detection and notification to avoid polling for accesses.
- **Interrupts support**: Legacy/MSI/MSI-X interrupt injection.
- **PCI capability framework**: PCI capabilities system (Linked-list underneath).
- **DMA system**: IOMMU-aware DMA accesses from/to userspace device.
  - **P2P support (Preliminar!)**: Peer-to-peer DMA between devices with whitelist-based access control.
- **Userspace**: Implement your PCIe devices _entirely_ in userspace.

## Minimum supported environment

- Linux Kernel Version: `6.6`
- C Compiler: `gcc-12`
- Ubuntu Version: `24.04 LTS`


---------

### CI Status

#### amd64

| Distribution | Build | QEMU Test |
|:---|:---:|:---:|
| Ubuntu Latest | [![](https://img.shields.io/github/actions/workflow/status/cakehonolulu/pciem/ci.yml?job=amd64%20build%20(Ubuntu%20latest)&style=for-the-badge&logo=ubuntu&logoColor=white&label=build&labelColor=E95420)](https://github.com/cakehonolulu/pciem/actions/workflows/ci.yml) | [![](https://img.shields.io/github/actions/workflow/status/cakehonolulu/pciem/ci.yml?job=amd64%20QEMU%20Test%20(Ubuntu%20Latest)&style=for-the-badge&logo=qemu&logoColor=white&label=qemu&labelColor=E95420)](https://github.com/cakehonolulu/pciem/actions/workflows/ci.yml) |
| Ubuntu 24.04 LTS | [![](https://img.shields.io/github/actions/workflow/status/cakehonolulu/pciem/ci.yml?job=amd64%20build%20(Ubuntu%20LTS)&style=for-the-badge&logo=ubuntu&logoColor=white&label=build&labelColor=E95420)](https://github.com/cakehonolulu/pciem/actions/workflows/ci.yml) | [![](https://img.shields.io/github/actions/workflow/status/cakehonolulu/pciem/ci.yml?job=amd64%20QEMU%20Test%20(Ubuntu%2024.04%20LTS)&style=for-the-badge&logo=qemu&logoColor=white&label=qemu&labelColor=E95420)](https://github.com/cakehonolulu/pciem/actions/workflows/ci.yml) |
| Debian Stable | [![](https://img.shields.io/github/actions/workflow/status/cakehonolulu/pciem/ci.yml?job=amd64%20build%20(Debian%20stable)&style=for-the-badge&logo=debian&logoColor=white&label=build&labelColor=A81D33)](https://github.com/cakehonolulu/pciem/actions/workflows/ci.yml) | [![](https://img.shields.io/github/actions/workflow/status/cakehonolulu/pciem/ci.yml?job=amd64%20QEMU%20Test%20(Debian%20Stable)&style=for-the-badge&logo=qemu&logoColor=white&label=qemu&labelColor=A81D33)](https://github.com/cakehonolulu/pciem/actions/workflows/ci.yml) |
| Fedora Latest | [![](https://img.shields.io/github/actions/workflow/status/cakehonolulu/pciem/ci.yml?job=amd64%20build%20(Fedora%20Latest)&style=for-the-badge&logo=fedora&logoColor=white&label=build&labelColor=294172)](https://github.com/cakehonolulu/pciem/actions/workflows/ci.yml) | [![](https://img.shields.io/github/actions/workflow/status/cakehonolulu/pciem/ci.yml?job=amd64%20QEMU%20Test%20(Fedora%20Latest)&style=for-the-badge&logo=qemu&logoColor=white&label=qemu&labelColor=294172)](https://github.com/cakehonolulu/pciem/actions/workflows/ci.yml) |
| openSUSE Tumbleweed | [![](https://img.shields.io/github/actions/workflow/status/cakehonolulu/pciem/ci.yml?job=amd64%20build%20(openSUSE%20Tumbleweed)&style=for-the-badge&logo=opensuse&logoColor=white&label=build&labelColor=2D5F0F)](https://github.com/cakehonolulu/pciem/actions/workflows/ci.yml) | [![](https://img.shields.io/github/actions/workflow/status/cakehonolulu/pciem/ci.yml?job=amd64%20QEMU%20Test%20(openSUSE%20Tumbleweed)&style=for-the-badge&logo=qemu&logoColor=white&label=qemu&labelColor=2D5F0F)](https://github.com/cakehonolulu/pciem/actions/workflows/ci.yml) |

#### aarch64

| Distribution | Build | QEMU Test |
|:---|:---:|:---:|
| Ubuntu 24.04 LTS | [![](https://img.shields.io/github/actions/workflow/status/cakehonolulu/pciem/ci.yml?job=aarch64%20build%20(Ubuntu%20latest)&style=for-the-badge&logo=ubuntu&logoColor=white&label=build&labelColor=E95420)](https://github.com/cakehonolulu/pciem/actions/workflows/ci.yml) | [![](https://img.shields.io/github/actions/workflow/status/cakehonolulu/pciem/ci.yml?job=aarch64%20QEMU%20Test%20(Ubuntu%20LTS)&style=for-the-badge&logo=qemu&logoColor=white&label=qemu&labelColor=E95420)](https://github.com/cakehonolulu/pciem/actions/workflows/ci.yml) |

# Examples

## Bochs BGA (drm) Card

A Bochs BGA-compatible (bochs-drm) card that can be driven by userspace utilities such as Weston; uses SDL3.

https://github.com/user-attachments/assets/d2f7abe4-aef4-4d3a-a30b-ab7ec793faed

## NVME Controller

NVME controller with 1GB of storage attached to. User can freely format, mount, create and remove files from the memory.

https://github.com/user-attachments/assets/29ce370a-7317-4fd4-9d1d-c3e868e1083d

## Intel HDA Card

ICH6-compatible emulation model that can play samples in conjunction with pipewire.

_NOTE: Slight audio crackling only heard on recording, works fine otherwise_

https://github.com/user-attachments/assets/7264a18c-6fcb-46c4-acde-9531b0be7ff6

## Intel E1000 Card

A pretty naive implementation of the E1000 card. Supports communications redirection to/from your real NIC. Can also use Wi-Fi but it's less stable.

https://github.com/user-attachments/assets/b6b9862c-349c-49da-8a79-4769dfa31915

<details>
  <summary>Legacy example(s)</summary>
<h2>ProtoPCIem card</h2>

The card is programmed entirely in QEMU (State machine for the card, basically), which does all the userspace initialization and command handling from the real driver running in the host.

Can run software-rendered DOOM (Submits finished frames with DMA to the card which QEMU displays) and also simple OpenGL 1.X games (On the screenshots, tyr-glquake and xash3d; thanks to a custom OpenGL state machine implemented entirely in QEMU that software-renders the command lists and updates the internal state accordingly).

<details>
  <summary>Screenshots</summary>
<p align="center">
  <img width="1903" height="1029" alt="imagen" src="https://github.com/user-attachments/assets/16f64475-ee51-4f79-ae17-b06363f0b12a" />
</p>

<p align="center">
  <img width="1757" height="893" alt="imagen" src="https://github.com/user-attachments/assets/4ad00e14-83e5-4e1f-b374-fbaa92def4e3" />
</p>

<p align="center">
  <img width="1227" height="846" alt="imagen" src="https://github.com/user-attachments/assets/d21a7d84-f857-4790-bdc6-7bf2714e9eda" />
</p>

</details>

</p>
  
</details>


## License

* PCIem kernel components: GPLv2
* Examples: dual MIT/GPLv2.

## References

- Blog post: https://cakehonolulu.github.io/introducing-pciem/
- Hackernews post: https://news.ycombinator.com/item?id=46689065
- PCI Express specification: https://pcisig.com/specifications
