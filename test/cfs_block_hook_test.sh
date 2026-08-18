#!/bin/sh
# cfs_block_hook_test.sh — virtual block device + partition device semantics
set -u
cd "$(dirname "$0")/.." || exit 1
T=/tmp/cfs_hook_test
rm -rf "$T"; mkdir -p "$T"
PASS=0; FAIL=0
ck() { if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  OK $3"; else FAIL=$((FAIL+1)); echo "  FAIL $3 (got '$1' want '$2')"; fi; }

echo "[h1] partitioned disk via block hook"
./cfs-tool mkfs ext4 64M "$T/d.cfs" -p 1 >/dev/null 2>&1 || { echo "FAIL mkfs -p"; exit 1; }
# mkfs -p fills 1MB..disk; rebuild a two-partition table
./cfs-tool partdel "$T/d.cfs" 1 >/dev/null 2>&1 || { echo "FAIL partdel"; exit 1; }
# sector mode keeps sizes 512-aligned (byte mode end-inclusive adds 1)
./cfs-tool partadd "$T/d.cfs" linux 2048 65535 --boot >/dev/null 2>&1 || { echo "FAIL partadd 1"; exit 1; }
./cfs-tool partadd "$T/d.cfs" linux 65536 98303 >/dev/null 2>&1 || { echo "FAIL partadd 2"; exit 1; }

export LD_PRELOAD="$PWD/cfs_block_hook.so"
export CFS_BLOCK_DEV=/dev/vda
export CFS_BLOCK_FILE="$T/d.cfs"
export CFS_BLOCK_PARTS=1

ck "$(./test/vblk_probe /dev/vda size64)" "67108864" "whole disk BLKGETSIZE64"
ck "$(./test/vblk_probe /dev/vda1 size64)" "32505856" "part1 size (32M-1M)"
ck "$(./test/vblk_probe /dev/vda2 size64)" "16777216" "part2 size (32M..48M)"
ck "$(./test/vblk_probe /dev/vda1 rdev)" "252:1" "part1 rdev"
ck "$(./test/vblk_probe /dev/vda2 rdev)" "252:2" "part2 rdev"
ck "$(./test/vblk_probe /dev/vda ssz)" "512" "ssz 512"

ck "$(./test/vblk_probe /dev/vda read 510 2)" "55aa" "MBR signature"
ck "$(./test/vblk_probe /dev/vda1 read 1080 2)" "53ef" "ext4 magic @ part1+1024+56"
P1=$(./test/vblk_probe /dev/vda1 read 2048 16)
DISK=$(./test/vblk_probe /dev/vda read 1050624 16)
ck "$P1" "$DISK" "part1 data == disk bytes at 1MB+2048"

echo "[h2] stale cache + BLKRRPART re-read"
( sleep 0.3; env -u LD_PRELOAD ./cfs-tool partadd "$T/d.cfs" linux 98304 114687 >/dev/null 2>&1 ) &
ck "$(./test/vblk_probe /dev/vda stalecheck 3 /dev/vda3)" "stale:8388608" "stale cache invisible, BLKRRPART reveals vda3"
wait

echo "[h3] sector size"
ck "$(CFS_SECTOR_SIZE=4096 ./test/vblk_probe /dev/vda ssz)" "4096" "ssz 4096"
ck "$(CFS_SECTOR_SIZE=4096 ./test/vblk_probe /dev/vda getsize)" "16384" "BLKGETSIZE halved"

echo "[h4] aliases off by default"
ck "$(env -u CFS_BLOCK_PARTS ./test/vblk_probe /dev/vda1 size64)" "open-fail" "no alias without CFS_BLOCK_PARTS"

unset LD_PRELOAD
echo ""
echo "=== hook test: $PASS ok, $FAIL failed ==="
[ "$FAIL" -eq 0 ] || exit 1
