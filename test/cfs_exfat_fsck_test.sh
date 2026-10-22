#!/bin/sh
# External-tool acceptance for the self-contained exFAT formatter: build
# disks, export them exactly as a user would, and let exfatprogs and the
# kernel judge them.  The formatter checks its own checksums; that only proves
# it agrees with itself, and a filesystem nobody else can read is not a
# filesystem.  Needs fsck.exfat (/usr/sbin, often not on PATH); the mount step
# additionally needs root and loop devices, so it runs on real hardware.
set -u
cd "$(dirname "$0")/.." || exit 1
CT=./cfs-tool
TMPROOT=${CFS_FSCK_WORK:-${TMPDIR:-/tmp}}
T=$(mktemp -d "$TMPROOT/cfs_exfat_XXXXXX") || exit 1
fail=0

FSCK=$(command -v fsck.exfat 2>/dev/null || echo /usr/sbin/fsck.exfat)
[ -x "$FSCK" ] || { echo "SKIP: fsck.exfat not installed"; rm -rf "$T"; exit 0; }

have_k=$(df -Pk "$TMPROOT" 2>/dev/null | awk 'NR==2{print $4}')
case ${have_k:-x} in ''|*[!0-9]*) have_k=0 ;; esac
if [ "$have_k" -lt 1150000 ]; then
    echo "SKIP: ${TMPROOT} has ${have_k}K free, the 1G case needs ~1.1G of scratch"
    echo "      set TMPDIR (or CFS_FSCK_WORK) to a larger filesystem"
    rm -rf "$T"; exit 0
fi

# export <cfs> <partition_offset_sectors> -> $T/part, streamed (see the ext4
# script: a temp copy plus the slice is 2G, and /tmp is a tmpfs on some boxes)
export_part() {
    rm -f "$T/part" "$T/fifo"
    mkfifo "$T/fifo" || return 1
    $CT cat "$1" @block > "$T/fifo" 2>/dev/null &
    cpid=$!
    dd if="$T/fifo" of="$T/part" bs=512 skip="$2" 2>/dev/null
    wait "$cpid" || { rm -f "$T/fifo"; return 1; }
    rm -f "$T/fifo"
    [ -s "$T/part" ]
}

check_disk() {          # check_disk <label> <cfs> <offset>
    export_part "$2" "$3" || { echo "FAIL $1: export"; fail=$((fail+1)); return; }
    if $FSCK -n "$T/part" > "$T/fsck.log" 2>&1; then
        echo "OK   $1: $(tail -1 "$T/fsck.log")"
    else
        echo "FAIL $1: fsck.exfat reported problems"
        sed -n '1,12p' "$T/fsck.log"
        fail=$((fail+1))
    fi
}

# 1. Formatter across the cluster-size thresholds, both partition schemes.
for sz in 64M 256M 1G; do
    rm -f "$T/d.cfs"
    $CT mkfs exfat "$sz" "$T/d.cfs" -p 1 >/dev/null 2>&1 \
        || { echo "FAIL mkfs exfat $sz -p 1"; fail=$((fail+1)); continue; }
    check_disk "mkfs exfat $sz (mbr)" "$T/d.cfs" 2048

    rm -f "$T/d.cfs"
    $CT mkfs exfat "$sz" "$T/d.cfs" -p 1 -g >/dev/null 2>&1 \
        || { echo "FAIL mkfs exfat $sz -g"; fail=$((fail+1)); continue; }
    check_disk "mkfs exfat $sz (gpt)" "$T/d.cfs" 2048
done

# 2. The filesystem has to survive a real mount: the kernel's exFAT driver
#    (or fuse) is a second independent reader, and it exercises the FAT chain
#    walk that fsck only inspects.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    # only if it will not stop for a password in the middle of a test run;
    # otherwise run this script under sudo instead
    command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null && SUDO=sudo
fi
MNT=$(mktemp -d "$TMPROOT/cfs_exfat_mnt_XXXXXX")
if [ "$(id -u)" -eq 0 ] || [ -n "$SUDO" ]; then
    rm -f "$T/d.cfs"
    if $CT mkfs exfat 64M "$T/d.cfs" -p 1 >/dev/null 2>&1; then
        if export_part "$T/d.cfs" 2048; then
            if $SUDO mount -t exfat -o loop,ro "$T/part" "$MNT" > "$T/mnt.log" 2>&1; then
                echo "OK   mount exfat: $( $SUDO ls "$MNT" | tr '\n' ' ' )"
                $SUDO umount "$MNT" 2>/dev/null
            else
                # No kernel exFAT driver is not our bug; say which it was.
                if grep -qi "unknown filesystem\|not supported\|no such file" "$T/mnt.log"; then
                    echo "SKIP: no kernel exFAT driver on this machine"
                else
                    echo "FAIL mount exfat"; sed -n '1,6p' "$T/mnt.log"; fail=$((fail+1))
                fi
            fi
        else
            echo "FAIL mount exfat: export"; fail=$((fail+1))
        fi
    else
        echo "FAIL mkfs exfat 64M for mount"; fail=$((fail+1))
    fi
else
    echo "SKIP: mount needs root and a FUSE/kernel exFAT driver"
fi
$SUDO rmdir "$MNT" 2>/dev/null || rmdir "$MNT" 2>/dev/null

rm -rf "$T"
[ "$fail" -eq 0 ] && echo "=== exfat acceptance: 0 failures ===" || echo "=== exfat acceptance: $fail failures ==="
[ "$fail" -eq 0 ]
