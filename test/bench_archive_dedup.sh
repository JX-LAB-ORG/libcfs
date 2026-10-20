#!/bin/bash
# bench_archive_dedup.sh — what does the merge layer already get on compressed
# near-copies, and how much is left on the table?
#
# Two questions, one corpus:
#   1. Do independently gzipped near-copies still share bytes?  (deflate has a
#      32KB window and resyncs after a difference, so they probably do —
#      the "compressed copies share nothing" claim was never measured.)
#   2. If they do, does the merge layer find it?  The oracle for "how much
#      cross-stream redundancy exists at all" is a strong compressor run over
#      all the copies at once, which can see everything.
#
# Everything here works on the compressed bytes: nothing is decompressed, so
# whatever is found is found without touching the hash.
#
#   usage: bench_archive_dedup.sh [base_file] [copies] [gz_level]
set -u
cd "$(dirname "$0")/.." || exit 1
BASE=${1:-/root/bench/corpus/code.tar}
COPIES=${2:-4}
LVL=${3:-9}
CT=./cfs-tool
W=${TMPDIR:-/tmp}/bencharch.$$
mkdir -p "$W/raw" "$W/gz" || exit 1

sz_of() { stat -c %s "$1" 2>/dev/null || echo 0; }
mb() { awk -v v="$1" 'BEGIN{printf "%.2f", v/1048576}'; }
x() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.2f", (b>0)? a/b : 0}'; }

[ -s "$BASE" ] || { echo "missing base $BASE"; exit 1; }

# ── near-copies, the corpus the merge layer was measured on ──
python3 -I - "$BASE" "$W/raw" "$COPIES" <<'PY'
import os, sys
base, out, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
data = open(base, "rb").read()
for i in range(n):
    b = bytearray(data)
    step = (97 + i * 13) * 1024
    for p in range(i * 37, len(b), step):
        for k in range(0, min(512, len(b) - p)):
            b[p + k] = (b[p + k] ^ (i + 1)) & 0xFF
    open(os.path.join(out, "img%d.tar" % i), "wb").write(bytes(b))
PY

raw=0
for f in "$W/raw"/*; do raw=$((raw + $(sz_of "$f"))); done
for f in "$W/raw"/*; do gzip -$LVL -c "$f" > "$W/gz/$(basename "$f").gz"; done
gz=0
for f in "$W/gz"/*; do gz=$((gz + $(sz_of "$f"))); done
echo "corpus: $COPIES near-copies — $(mb $raw) MB of content, $(mb $gz) MB once gzipped"
echo

# ── oracle: how much redundancy is in the gz corpus at all, when one
#    compressor can see all of it at once ──
cat "$W"/gz/* > "$W/all.gz"
xz -9 -c "$W/all.gz" > "$W/all.gz.xz"
echo "  gz corpus, one xz -9 over the whole thing : $(mb $(sz_of "$W/all.gz.xz")) MB  ($(x $gz $(sz_of "$W/all.gz.xz"))x)"
echo "  → anything the merge layer does not reach, but this does, is the gap"
echo

run() {   # run <label> <dir> <content_bytes>
    rm -f "$W/t.cfs"
    "$CT" pack "$2" "$W/t.cfs" >/dev/null 2>&1
    local p; p=$(sz_of "$W/t.cfs")
    "$CT" dedup "$W/t.cfs" --stats >/dev/null 2>&1
    local m; m=$(sz_of "$W/t.cfs")
    printf '%-18s pack %8s MB (%5.2fx)   merge %8s MB (%6.2fx)\n' \
        "$1" "$(mb $p)" "$(x $3 $p)" "$(mb $m)" "$(x $3 $m)"
}

echo "--- merged as stored ---"
run "plain files" "$W/raw" "$raw"
run "gz near-copies" "$W/gz" "$gz"
echo
echo "--- the same gz corpus measured against the content it came from ---"
printf '%-18s %8s MB of content stored as %s MB  (%.2fx)\n' \
    "gz, merged" "$(mb $raw)" "$(sz_of "$W/t.cfs")" "$(x $raw $(sz_of "$W/t.cfs"))"

rm -rf "$W"
