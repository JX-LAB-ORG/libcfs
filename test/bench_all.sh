#!/bin/bash
# bench_all.sh — one run of the whole performance survey.
#
#   ./test/bench_all.sh [container_mb] [out_file]
#
# Sections: codec ratio/throughput by corpus, block-size and order sweeps,
# the general-purpose compressors on the same bytes, the container's I/O
# behaviour, and the merge layer's benefit and cost.
set -u
cd "$(dirname "$0")/.." || exit 1
CONTAINER_MB=${1:-256}
OUT=${2:-/root/bench/report.txt}
C=/root/bench/corpus
mkdir -p "$C" /root/bench

{
echo "==================== machine ===================="
echo "arch     $(uname -m)   cores $(nproc)"
grep -m1 -E "model name|Processor" /proc/cpuinfo
free -m | head -2
echo

echo "==================== corpora ===================="
sh ./test/bench_corpus.sh 2>&1 | tail -12
echo

echo "==================== codec: by corpus (8MB blocks, order 2) ===================="
for f in code.tar text.tar bin.elf json.dat records.dat logs.dat rand.bin zeros.bin; do
    [ -s "$C/$f" ] && ./../libcpool/test/bench_cpenc "$C/$f" 8192 2 3
done
echo

echo "==================== codec: block size sweep (code.tar) ===================="
for b in 64 256 1024 4096 8192 65536; do
    ./../libcpool/test/bench_cpenc "$C/code.tar" "$b" 2 2
done
echo

echo "==================== codec: order sweep (code.tar, 8MB) ===================="
for o in 0 1 2 3 4; do
    ./../libcpool/test/bench_cpenc "$C/code.tar" 8192 "$o" 2
done
echo

echo "==================== codec: binary, block size sweep ===================="
for b in 256 1024 8192; do
    ./../libcpool/test/bench_cpenc "$C/bin.elf" "$b" 2 2
done
echo

echo "==================== vs general-purpose (16MB slices) ===================="
bash ./test/bench_tools.sh "$C" 16
echo

echo "==================== container I/O (${CONTAINER_MB}MB, code.tar data) ===================="
echo "--- reference: plain file on the same filesystem ---"
dd if=/dev/zero of=/root/bench/plain.bin bs=1M count=$CONTAINER_MB conv=fsync 2>&1 | tail -1
dd if=/root/bench/plain.bin of=/dev/null bs=1M 2>&1 | tail -1
rm -f /root/bench/plain.bin
echo "--- cfs ---"
./test/bench_cfs /root/bench/bench.cfs "$CONTAINER_MB" "$C/code.tar"
ls -la /root/bench/bench.cfs | awk '{print "container file on disk:", $5, "bytes"}'
rm -f /root/bench/bench.cfs
echo

echo "==================== merge layer ===================="
bash ./test/bench_dedup.sh "$C/code.tar" 4 "$C"
} 2>&1 | tee "$OUT"

echo
echo "report written to $OUT"
