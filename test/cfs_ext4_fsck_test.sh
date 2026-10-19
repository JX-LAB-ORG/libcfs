#!/bin/sh
# External-tool acceptance for the self-contained ext4 formatter and installer:
# build disks, export them exactly as a user would, and let e2fsck judge them.
# A filesystem is only "valid" if fsck(8) says so — our own verifier would
# happily agree with our own bug.
set -u
cd "$(dirname "$0")/.." || exit 1
CT=./cfs-tool
T=$(mktemp -d /tmp/cfs_fsck_XXXXXX) || exit 1
fail=0

# e2fsck lives in /sbin, which is often not on a non-root PATH
E2FSCK=$(command -v e2fsck 2>/dev/null || echo /sbin/e2fsck)
[ -x "$E2FSCK" ] || { echo "SKIP: e2fsck not installed"; rm -rf "$T"; exit 0; }

check_disk() {          # check_disk <label> <cfs> <partition_offset_sectors>
    $CT cat "$2" @block > "$T/img" 2>/dev/null || { echo "FAIL $1: export"; fail=$((fail+1)); return; }
    dd if="$T/img" of="$T/part" bs=512 skip="$3" 2>/dev/null
    if $E2FSCK -fn "$T/part" > "$T/fsck.log" 2>&1; then
        echo "OK   $1: $(tail -1 "$T/fsck.log")"
    else
        echo "FAIL $1: e2fsck reported problems"
        sed -n '1,12p' "$T/fsck.log"
        fail=$((fail+1))
    fi
}

# 1. Formatter across group counts: 1 group, 2 groups, 8 groups.
for sz in 64M 256M 1G; do
    rm -f "$T/d.cfs"
    $CT mkfs ext4 "$sz" "$T/d.cfs" -p 1 >/dev/null 2>&1 || { echo "FAIL mkfs $sz"; fail=$((fail+1)); continue; }
    check_disk "mkfs ext4 $sz" "$T/d.cfs" 2048
done

# 2. Installer onto a multi-group disk (the path that used to be refused).
if [ -x ./test/iso_gen ]; then
    ./test/iso_gen "$T/small.iso" || { echo "FAIL iso_gen"; fail=$((fail+1)); }
    for sz in 256M 1G; do
        rm -f "$T/i.cfs"
        $CT install "$T/small.iso" "$sz" "$T/i.cfs" -p 1 >/dev/null 2>&1 || { echo "FAIL install $sz"; fail=$((fail+1)); continue; }
        check_disk "install $sz" "$T/i.cfs" 2048
    done
else
    echo "SKIP: test/iso_gen not built"
fi

rm -rf "$T"
[ "$fail" -eq 0 ] && echo "=== ext4 fsck acceptance: 0 failures ===" || echo "=== ext4 fsck acceptance: $fail failures ==="
[ "$fail" -eq 0 ]
