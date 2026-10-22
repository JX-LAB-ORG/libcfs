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

echo "[h2] the container takes one writer at a time"
# This used to have a background cfs-tool partadd change the container while
# the device was open, and check that the hook's cached partition table went
# stale until BLKRRPART.  That scenario is now impossible by design: a
# container takes an advisory lock, so a second writer is refused outright
# rather than allowed to corrupt a table another handle is mid-way through.
# The guarantee is the refusal, so that is what gets checked.
rm -f "$T/ready"
# The hook is exported, so every child this subshell starts would load it too
# — and its constructor opens the container exclusively.  A `sleep` polling
# for the probe's ready file therefore takes the very lock the probe is
# trying to acquire, and the probe reports open-fail.  Drop the hook for the
# whole subshell (this is where `env -u LD_PRELOAD sleep 0.3` used to break).
( unset LD_PRELOAD
  n=0
  while [ ! -e "$T/ready" ] && [ "$n" -lt 200 ]; do sleep 0.05; n=$((n+1)); done
  ./cfs-tool partadd "$T/d.cfs" linux 98304 114687 >/dev/null 2>&1; \
  echo $? > "$T/ext.rc" ) &
ck "$(CFS_PROBE_READY="$T/ready" ./test/vblk_probe /dev/vda stalecheck 3 /dev/vda3)" "still-fail" "external writer refused while the device is open"
wait
ck "$([ "$(cat "$T/ext.rc" 2>/dev/null)" != "0" ] && echo refused || echo allowed)" \
   "refused" "cfs-tool partadd exits non-zero against an open container"

echo "[h3] sector size"
ck "$(CFS_SECTOR_SIZE=4096 ./test/vblk_probe /dev/vda ssz)" "4096" "ssz 4096"
ck "$(CFS_SECTOR_SIZE=4096 ./test/vblk_probe /dev/vda getsize)" "16384" "BLKGETSIZE halved"

echo "[h4] aliases off by default"
ck "$(env -u CFS_BLOCK_PARTS ./test/vblk_probe /dev/vda1 size64)" "open-fail" "no alias without CFS_BLOCK_PARTS"

echo "[h5] disk metadata ioctls"
GEO=$(./test/vblk_probe /dev/vda geo)
ck "$(echo "$GEO" | cut -d: -f1-3)" "255:63:8" "HDIO_GETGEO heads/sectors/cylinders (64MB)"
ck "$(echo "$GEO" | cut -d: -f4)" "0" "whole disk geo start"
GEO1=$(./test/vblk_probe /dev/vda1 geo)
ck "$(echo "$GEO1" | cut -d: -f4)" "2048" "partition geo start = 2048"
ck "$(./test/vblk_probe /dev/vda ident)" "CFS SSD" "HDIO_GET_IDENTITY model (default ssd)"
ck "$(./test/vblk_probe /dev/vda iomin)" "512" "BLKIOMIN"
ck "$(./test/vblk_probe /dev/vda ioopt)" "4096" "BLKIOOPT"
ck "$(./test/vblk_probe /dev/vda alignoff)" "0" "BLKALIGNOFF"

echo "[h6] BLKDISCARD zeroes the range"
BEFORE=$(./test/vblk_probe /dev/vda1 read 32768 8)
ck "$BEFORE" "0000000000000000" "region empty before (ext4 meta sits at 1MB+)"
./test/vblk_probe /dev/vda1 discard 65536 4096 >/dev/null
AFTER=$(./test/vblk_probe /dev/vda1 read 65536 8)
ck "$AFTER" "0000000000000000" "discarded range reads zero"
# discard must also work on the whole disk (cross-partition range)
./test/vblk_probe /dev/vda discard 1048576 4096 >/dev/null
ck "$(./test/vblk_probe /dev/vda read 1048576 4)" "00000000" "whole-disk discard zeroes"

echo "[h3] the declared size is a hard capacity"
# A guest must not be able to push the container past the size it was created
# with, and a full container has to look like a full disk (ENOSPC), not like
# an I/O error.  Writes land past both partitions, so the table is untouched.
ck "$(./test/vblk_probe /dev/vda write 67108352 512)" "ok" "write the last sector"
ck "$(./test/vblk_probe /dev/vda write 67108864 512)" "fail:ENOSPC:28" "write at the end -> ENOSPC"
ck "$(./test/vblk_probe /dev/vda write 67108608 512)" "fail:ENOSPC:28" "write straddling the end -> ENOSPC"
ck "$(./test/vblk_probe /dev/vda write 100663296 512)" "fail:ENOSPC:28" "write far past the end -> ENOSPC"
ck "$(./test/vblk_probe /dev/vda size64)" "67108864" "capacity unchanged by refused writes"
ck "$(./test/vblk_probe /dev/vda read 67108352 2)" "a5a5" "the last sector survived"

echo "[h4] the physical quota bounds the host file"
# The declared size says how big the container looks from the inside; the
# quota says how much host space it may take.  The quota is set through the
# environment (the hook only ever calls cfs_open), so this also covers that
# path.  The writes are incompressible on purpose: compressible bytes would
# never make the file grow, and the test would pass without testing anything.
Q="$T/q.cfs"
./cfs-tool mkfs ext4 64M "$Q" -p 1 >/dev/null 2>&1 || { echo "FAIL mkfs q"; exit 1; }
base=$(stat -c %s "$Q")
LIMIT=$((base + 2097152))
export LD_PRELOAD="$PWD/cfs_block_hook.so"
export CFS_BLOCK_DEV=/dev/vda CFS_BLOCK_FILE="$Q" CFS_BLOCK_PARTS=1
export CFS_MAX_PHYSICAL=$LIMIT
ok=0; i=0
while [ $i -lt 200 ]; do
    if ./test/vblk_probe /dev/vda writerand $((i * 262144)) 262144 | grep -q '^ok$'; then
        ok=$((ok + 1)); i=$((i + 1))
    else
        break
    fi
done
after=$(stat -c %s "$Q")
ck "$([ "$ok" -gt 0 ] && echo yes || echo no)" "yes" "the quota still lets writes through"
ck "$([ $((ok * 262144)) -lt 67108864 ] && echo quota-first || echo capacity-first)" \
   "quota-first" "the quota refused before the 64MB capacity"
ck "$([ "$after" -le "$LIMIT" ] && echo within || echo over)" "within" \
   "host file stayed within the quota ($after <= $LIMIT)"
unset CFS_MAX_PHYSICAL

unset LD_PRELOAD
echo ""
echo "=== hook test: $PASS ok, $FAIL failed ==="
[ "$FAIL" -eq 0 ] || exit 1
