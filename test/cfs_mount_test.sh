#!/bin/bash
# Real-kernel acceptance: build each cfs disk, export it the way a user would,
# and mount/fsck/swap it on the actual machine.  Needs root and loop devices,
# so it runs on real hardware, not inside PRoot.
set -u
cd "$(dirname "$0")/.." || exit 1
CT=./cfs-tool
# Work on a real filesystem: /tmp is often a small tmpfs, and these disks are
# gigabyte-sized.  CFS_MOUNT_WORK overrides.
W=${CFS_MOUNT_WORK:-./.mountwork}
rm -rf "$W"; mkdir -p "$W"
OFF=$((2048*512))          # partition start (MBR, 1MB aligned)
M=/mnt/cfs_mount_test
fail=0
ok()  { echo "OK   $*"; }
bad() { echo "FAIL $*"; fail=$((fail+1)); }
SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO=sudo

mnt_test() {   # label img opts
    local label=$1 img=$2 opts=$3
    $SUDO mkdir -p $M
    if ! $SUDO mount -o "loop,offset=$OFF,$opts" "$img" "$M"; then bad "$label: mount"; return; fi
    ok "$label: mount"
    if ! $SUDO sh -c "echo probe > $M/.cfs_probe"; then bad "$label: write"; fi
    $SUDO sync; $SUDO umount "$M" || bad "$label: umount"
    if $SUDO mount -o "loop,offset=$OFF,$opts" "$img" "$M"; then
        local v; v=$($SUDO cat "$M/.cfs_probe" 2>/dev/null)
        [ "$v" = probe ] && ok "$label: write+remount read-back" || bad "$label: read-back [$v]"
        $SUDO rm -f "$M/.cfs_probe"; $SUDO umount "$M"
    else bad "$label: remount"; fi
}

for sz in 64M 256M 1G; do
    $CT mkfs ext4 $sz $W/e.cfs -p 1 >/dev/null 2>&1 || { bad "mkfs ext4 $sz"; continue; }
    $CT cat $W/e.cfs @block > $W/e.img
    mnt_test "ext4 $sz" $W/e.img rw
    dd if=$W/e.img of=$W/part bs=512 skip=2048 2>/dev/null
    if $SUDO e2fsck -fn $W/part >/dev/null 2>&1; then ok "ext4 $sz: e2fsck clean"; else bad "ext4 $sz: e2fsck"; fi
    rm -f $W/e.cfs $W/e.img $W/part
done

$CT mkfs fat32 64M $W/f.cfs -p 1 >/dev/null 2>&1 || bad "mkfs fat32"
$CT cat $W/f.cfs @block > $W/f.img
mnt_test "fat32 64M" $W/f.img rw
dd if=$W/f.img of=$W/fpart bs=512 skip=2048 2>/dev/null
if [ -x /sbin/fsck.vfat ]; then
    if $SUDO /sbin/fsck.vfat -n $W/fpart >/dev/null 2>&1; then ok "fat32: fsck.vfat clean"; else bad "fat32: fsck.vfat"; fi
else echo "SKIP fat32: fsck.vfat not installed"; fi

$CT mkfs swap 64M $W/s.cfs -p 1 >/dev/null 2>&1 || bad "mkfs swap"
$CT cat $W/s.cfs @block > $W/s.img
# swap is exercised as a block device (loop), which is how a real partition is used
LOOP=$($SUDO losetup -f --show -o $OFF $W/s.img 2>/dev/null)
if [ -n "$LOOP" ] && $SUDO swapon "$LOOP" 2>/dev/null; then
    ok "swap: swapon accepted ($LOOP)"
    grep -q "$LOOP" /proc/swaps && ok "swap: active in /proc/swaps" || bad "swap: not in /proc/swaps"
    $SUDO swapoff "$LOOP"
    $SUDO losetup -d "$LOOP" 2>/dev/null
else bad "swap: swapon rejected"; fi

rm -rf "$W"
echo "=== mount acceptance: $fail failures ==="
exit $((fail>0))
