#!/bin/sh
# SPDX-License-Identifier: MIT

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PCIEM_KO="${PCIEM_KO:-$SCRIPT_DIR/../../kernel/pciem.ko}"
HELPER="${HELPER:-$SCRIPT_DIR/pciem_vroot_smoke}"
VENDOR=0x1ab8
DEV0=0xd120
DEV1=0xd121
HELPER_PID=

die() {
	echo "FATAL: $*" >&2
	exit 1
}

cleanup() {
	if [ -n "$HELPER_PID" ]; then
		kill "$HELPER_PID" 2>/dev/null || true
		wait "$HELPER_PID" 2>/dev/null || true
	fi
	rmmod pciem 2>/dev/null || true
}

count_matches() {
	want_vendor=$1
	want_device=$2
	count=0

	for dir in /sys/bus/pci/devices/*; do
		[ -f "$dir/vendor" ] || continue
		[ -f "$dir/device" ] || continue
		vendor=$(cat "$dir/vendor")
		device=$(cat "$dir/device")
		if [ "$vendor" = "$want_vendor" ] && [ "$device" = "$want_device" ]; then
			count=$((count + 1))
		fi
	done

	echo "$count"
}

[ "$(id -u)" -eq 0 ] || die "this script must be run as root"
[ -f "$PCIEM_KO" ] || die "pciem.ko not found: $PCIEM_KO"
[ -x "$HELPER" ] || die "helper not found: $HELPER"

trap cleanup EXIT INT TERM

rmmod pciem 2>/dev/null || true
insmod "$PCIEM_KO"
"$HELPER" &
HELPER_PID=$!

sleep 2

count0=$(count_matches "$VENDOR" "$DEV0")
count1=$(count_matches "$VENDOR" "$DEV1")

echo "virtual-root device count for $VENDOR:$DEV0 -> $count0"
echo "virtual-root device count for $VENDOR:$DEV1 -> $count1"

[ "$count0" -eq 1 ] || die "expected exactly one $VENDOR:$DEV0 device"
[ "$count1" -eq 1 ] || die "expected exactly one $VENDOR:$DEV1 device"

echo "RESULT: PASS"
