#!/bin/sh
# fuzz.sh — libFuzzer target for the container parser.
#
#   usage: fuzz.sh [seconds] [corpus_dir]
#
# The block decoder has its own target, in ../libcpool.  This one writes the
# input to a file and drives the public API: cfs_open, cfs_ls, cfs_stat,
# cfs_read, then cfs_verify over the same bytes.
#
# AddressSanitizer cannot run in this environment (PRoot's address-space
# emulation rejects its shadow map), so buffers the library fills sit against
# PROT_NONE guard pages and UBSan covers undefined arithmetic.  Needs the
# sanitizer runtime: `apk add compiler-rt`.
set -u
cd "$(dirname "$0")/.." || exit 1
SECS=${1:-60}
CORPUS=${2:-/tmp/fz_cfs}
mkdir -p "$CORPUS" || exit 1

if [ -z "$(ls -A "$CORPUS" 2>/dev/null)" ]; then
    W=$(mktemp -d) || exit 1
    mkdir -p "$W/d/sub"
    echo hello > "$W/d/a.txt"
    head -c 5000 /dev/urandom > "$W/d/sub/b.bin"
    ./cfs-tool pack "$W/d" "$CORPUS/seed_pack" >/dev/null 2>&1
    cp "$CORPUS/seed_pack" "$W/x.cfs" && ./cfs-tool dedup "$W/x.cfs" >/dev/null 2>&1 \
        && cp "$W/x.cfs" "$CORPUS/seed_dedup"
    ./cfs-tool mkfs ext4 64M "$CORPUS/seed_ext4" -p 1 >/dev/null 2>&1
    ./cfs-tool mkfs fat32 64M "$CORPUS/seed_fat" >/dev/null 2>&1
    ./cfs-tool mkfs swap 32M "$CORPUS/seed_swap" >/dev/null 2>&1
    ./cfs-tool pack "$W/d" "$CORPUS/seed_raw" --raw >/dev/null 2>&1
    rm -rf "$W"
fi

clang -fsanitize=fuzzer,undefined -fno-sanitize-recover=all -O1 -g -I. -I.. \
      test/fuzz_cfs.c cfs.c cfs_dedup.c cfs_part.c cfs_verify.c \
      ../libcpool/cpenc.c ../libcpool/bwt.c -lm -o test/fuzz_cfs || exit 1

echo "fuzzing for ${SECS}s, corpus $CORPUS"
./test/fuzz_cfs "$CORPUS" -max_total_time="$SECS" -max_len=1048576 -print_final_stats=1
