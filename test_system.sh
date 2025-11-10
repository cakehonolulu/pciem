#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
log_info() {
echo -e "${GREEN}[INFO]${NC} $1"
}
log_warn() {
echo -e "${YELLOW}[WARN]${NC} $1"
}
log_error() {
echo -e "${RED}[ERROR]${NC} $1"
}
check_module() {
if lsmod | grep -q "$1"; then
log_info "Module $1 is loaded"
return 0
else
log_warn "Module $1 is not loaded"
return 1
fi
}

log_info "Building kernel modules and proxy..."
make clean
make modules
make proxy

log_info "Unloading all related modules..."
sudo rmmod protopciem_driver 2>/dev/null || true
sudo rmmod protopciem_device 2>/dev/null || true
sudo rmmod pciem 2>/dev/null || true
sleep 1

if [[ "$1" == "forwarding" ]]; then
    log_info "Loading pciem in QEMU Forwarding mode"
    /usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 ~/signing_key.priv ~/signing_key.x509 pciem.ko
    sudo insmod pciem.ko use_qemu_forwarding=1 pciem_phys_regions="bar0:0x1bf000000:0x10000,bar2:0x1bf100000:0x100000"
else
    log_info "Loading pciem in default (internal emulation) mode"
    /usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 ~/signing_key.priv ~/signing_key.x509 pciem.ko
    sudo insmod pciem.ko
fi
sleep 1

log_info "Loading ProtoPCIem device plugin..."
sudo insmod protopciem_device.ko
sleep 1

if ! check_module pciem; then
    log_error "Failed to load pciem framework"
    exit 1
fi
if ! check_module protopciem_device; then
    log_error "Failed to load protopciem_device plugin"
    exit 1
fi

if ! lspci -d 1f0c:0001 &>/dev/null; then
log_error "Virtual PCI device not found!"
exit 1
fi

log_info "Checking device files..."
if [[ "$1" == "forwarding" ]]; then
    if [ ! -c /dev/pciem_shim ]; then
        log_error "/dev/pciem_shim not found (needed for forwarding)"
        exit 1
    fi
    log_info "/dev/pciem_shim exists"
fi

if [ ! -c /dev/pciem_ctrl ]; then
log_error "/dev/pciem_ctrl not found"
exit 1
fi
log_info "/dev/pciem_ctrl exists"

if [[ "$1" == "forwarding" ]]; then
    log_warn "Waiting for QEMU socket to be created..."
    timeout=60
    while [ $timeout -gt 0 ]; do
    if [ -S /tmp/pciem.sock ]; then
        log_info "QEMU socket detected!"
        break
    fi
    sleep 1
    timeout=$((timeout - 1))
    done
    
    if [ ! -S /tmp/pciem.sock ]; then
        log_warn "QEMU socket not found, continuing anyway..."
    else
        log_info "Starting proxy daemon..."
        sudo ./pciem_uproxy /tmp/pciem.sock /dev/pciem_shim &
        PROXY_PID=$!
        sleep 2
        if ps -p $PROXY_PID > /dev/null; then
            log_info "Proxy running with PID $PROXY_PID"
        else
            log_error "Proxy failed to start"
            exit 1
        fi
    fi
fi

log_info "Loading ProtoPCIem driver..."
sudo rmmod protopciem_driver 2>/dev/null || true
/usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 ~/signing_key.priv ~/signing_key.x509 protopciem_driver.ko
sudo insmod protopciem_driver.ko
sleep 1
if ! check_module protopciem_driver; then
    log_error "Failed to load ProtoPCIem driver"
    exit 1
fi

log_info "Test complete! Check dmesg for results."
