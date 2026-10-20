#!/bin/sh
# Build the benchmark corpora.  Real data wherever the machine has it; the
# generated classes (json/records/logs) are shaped like the real thing rather
# than being random bytes, because ratio on random bytes says nothing.
#
#   CORPUS_DIR=/root/bench/corpus ./test/bench_corpus.sh
set -u
C=${CORPUS_DIR:-/root/bench/corpus}
mkdir -p "$C" || exit 1
MB=$((1024 * 1024))

say() { printf '%-12s %s\n' "$1" "$2"; }

# ── code: C headers + our own sources, as a tar (a real archive shape) ──
if [ ! -s "$C/code.tar" ]; then
    tar cf "$C/code.tar" -C / usr/include 2>/dev/null
    tar rf "$C/code.tar" -C / root/libcfs root/libcpool 2>/dev/null
fi
say code.tar "$(du -h "$C/code.tar" | cut -f1)"

# ── text: cmake's reStructuredText manual (English prose) ──
if [ ! -s "$C/text.tar" ]; then
    tar cf "$C/text.tar" -C /usr/share cmake 2>/dev/null
fi
say text.tar "$(du -h "$C/text.tar" | cut -f1)"

# ── binary: an ELF shared object (code + reloc tables + zero padding) ──
if [ ! -s "$C/bin.elf" ]; then
    head -c $((64 * MB)) /usr/lib/libLLVM.so.22.1 > "$C/bin.elf" 2>/dev/null
fi
say bin.elf "$(du -h "$C/bin.elf" | cut -f1)"

# ── shaped classes: json / records / logs (built by the C generator, so the
#    benchmark has no interpreter dependency) ──
GEN=$(dirname "$0")/bench_gen
[ -x "$GEN" ] || { echo "build test/bench_gen first (make bench)"; exit 1; }
"$GEN" "$C" 32 >/dev/null
for f in json.dat records.dat logs.dat; do say "$f" "$(du -h "$C/$f" | cut -f1)"; done

# ── random (incompressible control) and zeros (sparse control) ──
[ -s "$C/rand.bin" ] || head -c $((16 * MB)) /dev/urandom > "$C/rand.bin"
[ -s "$C/zeros.bin" ] || dd if=/dev/zero of="$C/zeros.bin" bs=$MB count=64 2>/dev/null
say rand.bin "$(du -h "$C/rand.bin" | cut -f1)"
say zeros.bin "$(du -h "$C/zeros.bin" | cut -f1)"

echo "corpora in $C"
