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

log_info "Building kernel modules..."
make clean
make all

log_info "Unloading all related modules..."
sudo rmmod protopciem_driver 2>/dev/null || true
sudo rmmod pciem 2>/dev/null || true
sleep 1

log_info "Loading pciem"
/usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 ~/signing_key.priv ~/signing_key.x509 kernel/pciem.ko
sudo insmod kernel/pciem.ko pciem_phys_regions="bar0:0x1bf000000:0x10000,bar2:0x1bf100000:0x100000"
sleep 1

sudo ./userspace/protopciem_card &

sleep 1

if ! lspci -d 1f0c:0001 &>/dev/null; then
log_error "Virtual PCI device not found!"
exit 1
fi

log_info "Loading ProtoPCIem driver..."
sudo rmmod protopciem_driver 2>/dev/null || true
/usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 ~/signing_key.priv ~/signing_key.x509 kernel/driver/protopciem_driver.ko
sudo insmod kernel/driver/protopciem_driver.ko
sleep 1
if ! check_module protopciem_driver; then
    log_error "Failed to load ProtoPCIem driver"
    exit 1
fi

log_info "Test complete! Check dmesg for results."
