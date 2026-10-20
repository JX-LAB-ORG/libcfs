#!/bin/bash
# bench_dedup.sh — the store-level feature: what merging buys and what it costs.
#
# Corpus: N near-copies of one base file (the "same image, small delta" shape
# that made this layer worth building).  Measures pack size, merge size and
# time, read speed through a reference table, the cost of a runtime write into
# a merged file, and GC.
#
#   usage: bench_dedup.sh [base_file] [copies] [corpus_dir]
set -u
BASE=${1:-/root/bench/corpus/code.tar}
COPIES=${2:-4}
C=${3:-/root/bench/corpus}
CT=${CT:-/root/libcfs/cfs-tool}
W=${TMPDIR:-/tmp}/benchdedup.$$
mkdir -p "$W/tree" || exit 1

now_us() { local t=${EPOCHREALTIME}; echo $(( ${t%.*}*1000000 + 10#${t#*.} )); }
sz_of() { stat -c %s "$1" 2>/dev/null || echo 0; }
mb() { awk -v v="$1" 'BEGIN{printf "%.2f", v/1048576}'; }
sec() { awk -v v="$1" 'BEGIN{printf "%.2f", v/1000000}'; }
ratio() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.2f", (b>0)? a/b : 0}'; }

[ -s "$BASE" ] || { echo "missing base $BASE"; exit 1; }

# ── build the corpus: base + copies, each with a few percent of bytes changed ──
python3 -I - "$BASE" "$W/tree" "$COPIES" <<'PY'
import os, sys
base, tree, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
data = open(base, "rb").read()
for i in range(n):
    b = bytearray(data)
    step = (97 + i * 13) * 1024
    for p in range(i * 37, len(b), step):          # touch one window per step
        for k in range(0, min(512, len(b) - p)):
            b[p + k] = (b[p + k] ^ (i + 1)) & 0xFF
    open(os.path.join(tree, "img%d.tar" % i), "wb").write(bytes(b))
PY
tot=0
for f in "$W/tree"/*; do tot=$((tot + $(sz_of "$f"))); done
echo "corpus: $COPIES files, $(mb $tot) MB logical (near-copies of $(basename "$BASE"))"
echo

# ── baseline: what a general-purpose archiver does with the same tree ──
t=$(now_us); tar cf - -C "$W" tree | zstd -19 -q -o "$W/base.zst"; tz=$(( $(now_us) - t )); zz=$(sz_of "$W/base.zst")
t=$(now_us); tar cf - -C "$W" tree | xz -9 -q -c > "$W/base.xz"; tx=$(( $(now_us) - t )); zx=$(sz_of "$W/base.xz")
printf '%-22s %10s MB  %8s  %6.1fs\n' "tar+zstd -19" "$(mb $zz)" "$(ratio $tot $zz)x" "$(sec $tz)"
printf '%-22s %10s MB  %8s  %6.1fs\n' "tar+xz -9"    "$(mb $zx)" "$(ratio $tot $zx)x" "$(sec $tx)"
echo

# ── pack into cfs (no merge) ──
rm -f "$W/d.cfs"
t=$(now_us); "$CT" pack "$W/tree" "$W/d.cfs" >/dev/null 2>&1; tp=$(( $(now_us) - t )); sp=$(sz_of "$W/d.cfs")
printf '%-22s %10s MB  %8s  %6.1fs\n' "cfs pack" "$(mb $sp)" "$(ratio $tot $sp)x" "$(sec $tp)"

# ── merge (content-addressed) ──
t=$(now_us); "$CT" dedup "$W/d.cfs" --stats 2>&1 | sed 's/^/    /'; tm=$(( $(now_us) - t )); sm=$(sz_of "$W/d.cfs")
printf '%-22s %10s MB  %8s  %6.1fs\n' "cfs dedup merge" "$(mb $sm)" "$(ratio $tot $sm)x" "$(sec $tm)"
echo

# ── read through the reference tables ──
t=$(now_us); "$CT" cat "$W/d.cfs" /img2.tar > "$W/out" 2>/dev/null; tr=$(( $(now_us) - t ))
printf '%-22s %10s MB in %6.2fs = %7.2f MB/s\n' "read merged file" "$(mb $(sz_of "$W/out"))" "$(sec $tr)" \
    "$(awk -v b="$(sz_of "$W/out")" -v t="$tr" 'BEGIN{printf "%.2f", (t>0)? b/1048576*1000000/t : 0}')"

# ── runtime write into a merged file ──
head -c 1048576 "$BASE" > "$W/patch.bin"
t=$(now_us); "$CT" write "$W/d.cfs" /img2.tar "$W/patch.bin" >/dev/null 2>&1; tw=$(( $(now_us) - t ))
printf '%-22s %6.2fs for 1 MB write\n' "runtime write" "$(sec $tw)"

# ── GC ──
t=$(now_us); "$CT" dedup "$W/d.cfs" --gc 2>&1 | sed 's/^/    /'; tg=$(( $(now_us) - t )); sg=$(sz_of "$W/d.cfs")
printf '%-22s %10s MB  %6.2fs\n' "dedup --gc" "$(mb $sg)" "$(sec $tg)"
echo
rm -rf "$W"
