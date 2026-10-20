#!/bin/bash
# bench_tools.sh — cpenc against the general-purpose compressors, same bytes.
#
# Each tool runs on the same 16MB slice of each corpus with its own strong
# setting, best of REPS.  Ratio alone is not the story: cfs reads are
# decompress-bound, so decompress MB/s matters as much as size, and the
# table prints both.
#
#   usage: bench_tools.sh [corpus_dir] [slice_mb]
set -u
C=${1:-/root/bench/corpus}
SLICE_MB=${2:-16}
REPS=${REPS:-2}
W=${TMPDIR:-/tmp}/benchtools.$$
mkdir -p "$W" || exit 1

CPENC=${CPENC:-/root/libcpool/test/bench_cpenc}
have() { command -v "$1" >/dev/null 2>&1; }

now_us() { local t=${EPOCHREALTIME}; echo $(( ${t%.*}*1000000 + 10#${t#*.} )); }

# best-of-REPS wall time (us) for a command string; output discarded
best() {
    local best=99999999999 i s e
    for ((i=0;i<REPS;i++)); do
        s=$(now_us); eval "$1" >/dev/null 2>&1; e=$(now_us)
        (( e-s < best )) && best=$((e-s))
    done
    echo "$best"
}

# row CORPUS TOOL SIZE_BYTES ORIG_BYTES C_US D_US   (times empty = no decompress)
row() {
    awk -v c="$1" -v t="$2" -v sz="$3" -v o="$4" -v tc="${5:-0}" -v td="${6:-0}" 'BEGIN{
        printf "%-12s %-10s %8.2f %8.2f", c, t, sz/1048576, o/(sz?sz:1);
        if (tc > 0) printf " %9.2f", o/1048576*1000000/tc; else printf " %9s", "-";
        if (td > 0) printf " %9.2f", o/1048576*1000000/td; else printf " %9s", "-";
        print "";
    }'
}

corpora="code.tar text.tar bin.elf json.dat records.dat logs.dat rand.bin zeros.bin"

printf '%-12s %-10s %8s %8s %9s %9s\n' CORPUS TOOL SIZE_MB RATIO C_MBps D_MBps
for f in $corpora; do
    [ -s "$C/$f" ] || continue
    head -c $((SLICE_MB*1024*1024)) "$C/$f" > "$W/in"
    o=$(stat -c %s "$W/in")

    # ── cpenc, at the block size cfs actually uses (8MB) ──
    line=$("$CPENC" "$W/in" 8192 2 2 2>/dev/null | tail -1)
    c=$(echo "$line" | sed -n 's/.*-> *\([0-9.]*\) MB.*/\1/p')
    cs=$(echo "$line" | sed -n 's/.*C *\([0-9.]*\) MB\/s.*/\1/p')
    ds=$(echo "$line" | sed -n 's/.*D *\([0-9.]*\) MB\/s.*/\1/p')
    if [ -n "$c" ]; then
        # the codec already reports MB/s; convert back to us for a common row()
        row "$f" cpenc "$(awk -v m="$c" 'BEGIN{printf "%d", m*1048576}')" "$o" \
            "$(awk -v v="$cs" -v o="$o" 'BEGIN{printf "%d", (v>0)? o/1048576/v*1000000 : 0}')" \
            "$(awk -v v="$ds" -v o="$o" 'BEGIN{printf "%d", (v>0)? o/1048576/v*1000000 : 0}')"
    fi

    # ── the general-purpose tools ──
    for name in zstd-19 xz-9 brotli-11 gzip-9 lz4-12 bzip2-9; do
        case "$name" in
        zstd-19)   have zstd   || continue; ccmd="zstd -19 -q -f -o $W/out $W/in"; dcmd="zstd -d -q -f -o /dev/null $W/out" ;;
        xz-9)      have xz     || continue; ccmd="xz -9 -c $W/in > $W/out";        dcmd="xz -d -c $W/out > /dev/null" ;;
        brotli-11) have brotli || continue; ccmd="brotli -q 11 -c $W/in > $W/out"; dcmd="brotli -d -c $W/out > /dev/null" ;;
        gzip-9)    have gzip   || continue; ccmd="gzip -9 -c $W/in > $W/out";      dcmd="gzip -d -c $W/out > /dev/null" ;;
        lz4-12)    have lz4    || continue; ccmd="lz4 -12 -c $W/in > $W/out";      dcmd="lz4 -d -c $W/out > /dev/null" ;;
        bzip2-9)   have bzip2  || continue; ccmd="bzip2 -9 -c $W/in > $W/out";     dcmd="bzip2 -d -c $W/out > /dev/null" ;;
        esac
        rm -f "$W/out"
        tc=$(best "$ccmd"); sz=$(stat -c %s "$W/out" 2>/dev/null || echo 0)
        [ "${sz:-0}" -gt 0 ] || continue
        td=$(best "$dcmd")
        row "$f" "$name" "$sz" "$o" "$tc" "$td"
    done
done
rm -rf "$W"
