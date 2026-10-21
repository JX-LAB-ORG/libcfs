#!/bin/bash
# bench_image.sh — cpenc against the general compressors on a REAL disk image.
#
# Everything measured so far used data classes (text, JSON, ELF, synthetic
# tables).  The product scenario is different: a container holding a guest
# disk, and what cfs actually stores is the image.  An ext4 image is mostly
# zeros (free space) with ELF and text packed into the used clusters, so its
# ratio is not the ratio of any single data class.
#
#   usage: bench_image.sh [work_dir] [image_mb] [populate_mb]
set -u
cd "$(dirname "$0")/.." || exit 1
W=${1:-/root/bench/img}
IMG_MB=${2:-400}
POP_MB=${3:-250}
CT=./cfs-tool
CPENC=/root/libcpool/test/bench_cpenc
mkdir -p "$W" || exit 1

now_us() { local t=${EPOCHREALTIME}; echo $(( ${t%.*}*1000000 + 10#${t#*.} )); }
mb() { awk -v v="$1" 'BEGIN{printf "%.2f", v/1048576}'; }
x() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.2f", (b>0)? a/b : 0}'; }
best() { local best=99999999999 i s e; for ((i=0;i<${2:-1};i++)); do s=$(now_us); eval "$1" >/dev/null 2>&1; e=$(now_us); (( e-s < best )) && best=$((e-s)); done; echo "$best"; }

# ── a representative rootfs tree: ELF binaries, shared objects, headers,
#    docs.  Capped so the image size stays manageable. ──
TREE="$W/tree"
if [ ! -d "$TREE" ]; then
    mkdir -p "$TREE"
    cp -a /usr/include "$TREE/" 2>/dev/null
    cp -a /usr/share/cmake "$TREE/" 2>/dev/null
    mkdir -p "$TREE/lib" "$TREE/bin"
    # Budget the two big directories against what is left after the text
    # ones, and skip any single file that would blow past its budget — the
    # largest-first order otherwise lets one 176MB libLLVM eat the whole
    # allowance and leaves the image too small for the tree.
    want=$(( (POP_MB - 60) * 1048576 / 2 ))
    maxf=$((32 * 1048576))
    got=0
    for f in $(ls -S /usr/lib/*.so* 2>/dev/null); do
        [ -f "$f" ] || continue
        sz=$(stat -c %s "$f")
        [ "$sz" -gt "$maxf" ] && continue
        [ $((got + sz)) -gt $want ] && break
        cp "$f" "$TREE/lib/" 2>/dev/null && got=$((got + sz))
    done
    got=0
    for f in $(ls -S /usr/bin/* 2>/dev/null); do
        [ -f "$f" ] || continue
        sz=$(stat -c %s "$f")
        [ "$sz" -gt "$maxf" ] && continue
        [ $((got + sz)) -gt $want ] && break
        cp "$f" "$TREE/bin/" 2>/dev/null && got=$((got + sz))
    done
fi
POP=$(du -sb "$TREE" | cut -f1)
printf 'populated tree : %s MB in %s files\n' "$(mb $POP)" "$(find "$TREE" -type f | wc -l)"
# The image has to be able to hold the tree and still have free space, which
# is what makes it an image rather than a tarball.
NEED_MB=$(( POP / 1048576 + 150 ))
[ "$IMG_MB" -lt "$NEED_MB" ] && IMG_MB=$NEED_MB && printf 'image grown    : %s MB (tree + 150 MB free)\n' "$IMG_MB"

# ── the image itself: real ext4, no mount, e2fsck-clean ──
IMG="$W/img.ext4"
if [ ! -s "$IMG" ]; then
    rm -f "$IMG"
    mke2fs -q -t ext4 -d "$TREE" -F "$IMG" "${IMG_MB}M" || { echo "mke2fs failed"; exit 1; }
fi
ISZ=$(stat -c %s "$IMG")
printf 'image          : %s MB\n' "$(mb $ISZ)"
if command -v e2fsck >/dev/null 2>&1 || [ -x /sbin/e2fsck ]; then
    E=$(command -v e2fsck 2>/dev/null || echo /sbin/e2fsck)
    $E -fn "$IMG" >/dev/null 2>&1 && echo "e2fsck         : clean" || echo "e2fsck         : DIRTY"
fi
echo

printf '%-10s %10s %8s %10s %10s\n' TOOL SIZE_MB RATIO C_MBps D_MBps
# ── cpenc, at the block size the device layer uses ──
line=$("$CPENC" "$IMG" 8192 2 2 2>/dev/null | tail -1)
c=$(echo "$line" | sed -n 's/.*-> *\([0-9.]*\) MB.*/\1/p')
cs=$(echo "$line" | sed -n 's/.*C *\([0-9.]*\) MB\/s.*/\1/p')
ds=$(echo "$line" | sed -n 's/.*D *\([0-9.]*\) MB\/s.*/\1/p')
printf '%-10s %10s %8.2f %10s %10s\n' cpenc "$c" "$(awk -v a="$ISZ" -v b="$c" 'BEGIN{print a/(b*1048576)}')" "$cs" "$ds"

# ── the general-purpose compressors, same bytes ──
for name in zstd-19 xz-9 gzip-9 lz4-12; do
    case "$name" in
    zstd-19) ccmd="zstd -19 -q -f -o $W/o $IMG";                    dcmd="zstd -d -q -f -o /dev/null $W/o" ;;
    xz-9)    ccmd="xz -9 -T1 -c $IMG > $W/o";                       dcmd="xz -d -c $W/o > /dev/null" ;;
    gzip-9)  ccmd="gzip -9 -c $IMG > $W/o";                         dcmd="gzip -d -c $W/o > /dev/null" ;;
    lz4-12)  ccmd="lz4 -12 -c $IMG > $W/o";                         dcmd="lz4 -d -c $W/o > /dev/null" ;;
    esac
    rm -f "$W/o"
    tc=$(best "$ccmd"); sz=$(stat -c %s "$W/o" 2>/dev/null || echo 0)
    [ "${sz:-0}" -gt 0 ] || continue
    td=$(best "$dcmd")
    printf '%-10s %10s %8.2f %10.2f %10.2f\n' "$name" "$(mb $sz)" "$(x $ISZ $sz)" \
        "$(awk -v s=$ISZ -v t=$tc 'BEGIN{print s/1048576*1000000/t}')" \
        "$(awk -v s=$ISZ -v t=$td 'BEGIN{print s/1048576*1000000/t}')"
done
echo
echo "the image is ${IMG_MB} MB of which $(mb $POP) MB is populated — the rest is"
echo "free space, i.e. zeros, which every compressor here eats almost for free."
