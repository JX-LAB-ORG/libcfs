#define _GNU_SOURCE
#include "../cfs.h"
#include "../cfs_format.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

static int failures = 0;
#define T(c, msg) do { if (!(c)) { fprintf(stderr, "FAIL: %s (errno=%d)\n", msg, errno); failures++; } \
                       else { fprintf(stderr, "  OK: %s\n", msg); } } while(0)

#define PATH     "/tmp/test_dedup.cfs"

#define TEXT_SZ  317
#define BIG_SZ   (8ULL * 1024 * 1024 + 100 * 1024)   /* > 8MB, straddles the 8MB unit */
#define RAND_SZ  (300 * 1024)
#define POST_SZ  4096

/* ── read helpers ───────────────────────────────────────────────
 * check_read issues cfs_read(name, len, off) and compares against the
 * pre-merge snapshot.  The expected return is the CLAMPED byte count:
 * a read that runs past EOF returns fsize-off (never an error), and a
 * read starting at/after EOF returns 0. */
static void check_read(CFS *c, const char *name, const uint8_t *snap, size_t fsize,
                       off_t off, size_t len, const char *msg) {
    size_t exp = 0;
    if (off >= 0 && (uint64_t)off < fsize) {
        exp = len;
        if ((uint64_t)off + len > fsize) exp = (size_t)(fsize - (uint64_t)off);
    }
    uint8_t *rb = malloc(len ? len : 1);
    if (!rb) { failures++; fprintf(stderr, "FAIL: %s (oom)\n", msg); return; }
    ssize_t n = cfs_read(c, name, rb, len, off);
    int ok = (n == (ssize_t)exp) && (exp == 0 || memcmp(rb, snap + off, exp) == 0);
    if (!ok) {
        failures++;
        fprintf(stderr, "FAIL: %s (off=%lld len=%zu got=%zd exp=%zu)\n",
                msg, (long long)off, len, n, exp);
    } else {
        fprintf(stderr, "  OK: %s\n", msg);
    }
    free(rb);
}

/* Full battery for one file: whole read, mid-file partials, a read
 * crossing EOF (clamped), and a read entirely past EOF (returns 0). */
static void battery(CFS *c, const char *name, const uint8_t *snap, size_t fsize) {
    char m[160];

    /* full read from offset 0 */
    {
        uint8_t *rb = malloc(fsize ? fsize : 1);
        if (!rb) { failures++; fprintf(stderr, "FAIL: %s (oom)\n", name); return; }
        ssize_t n = cfs_read(c, name, rb, fsize, 0);
        int ok = (n == (ssize_t)fsize) && (fsize == 0 || !memcmp(rb, snap, fsize));
        snprintf(m, sizeof m, "%s: full read @0 (%zu bytes)", name, fsize);
        T(ok, m);
        free(rb);
    }

    /* several mid-file partial reads */
    if (fsize > 0) {
        size_t offs[3];
        offs[0] = 0;
        offs[1] = fsize / 2;
        offs[2] = fsize > 100 ? fsize - 100 : 0;
        for (int i = 0; i < 3; i++) {
            size_t len = 100;
            if (offs[i] + len > fsize) len = fsize - offs[i];
            if (len == 0) continue;
            snprintf(m, sizeof m, "%s: partial read @%zu len %zu", name, offs[i], len);
            check_read(c, name, snap, fsize, (off_t)offs[i], len, m);
        }
    }

    /* read crossing EOF: must clamp to fsize-off, not error */
    if (fsize > 16) {
        snprintf(m, sizeof m, "%s: read crossing EOF clamps", name);
        check_read(c, name, snap, fsize, (off_t)(fsize - 16), 4096, m);
    }

    /* read entirely past EOF: returns 0 */
    snprintf(m, sizeof m, "%s: read past EOF returns 0", name);
    check_read(c, name, snap, fsize, (off_t)(fsize + 1000), 64, m);
}

static int has_name(CfsDirEntry *ents, int n, const char *name) {
    for (int i = 0; i < n; i++) if (!strcmp(ents[i].name, name)) return 1;
    return 0;
}

int main(void) {
    setvbuf(stderr, NULL, _IONBF, 0);

    /* ── build the source buffers ─────────────────────────────── */
    uint8_t *text = malloc(TEXT_SZ);
    uint8_t *big  = malloc(BIG_SZ);
    uint8_t *dup  = malloc(BIG_SZ);
    uint8_t *rnd  = malloc(RAND_SZ);
    uint8_t *post = malloc(POST_SZ);
    if (!text || !big || !dup || !rnd || !post) { fprintf(stderr, "oom\n"); return 1; }

    const char *phrase = "The quick brown fox jumps over the lazy dog. ";
    for (size_t i = 0; i < TEXT_SZ; i++) text[i] = (uint8_t)phrase[i % 44];

    for (size_t i = 0; i < BIG_SZ; i++) big[i] = (uint8_t)(i % 251);   /* repeating pattern */
    memcpy(dup, big, BIG_SZ);   /* an exact second copy — the dedup fixture */

    {   uint64_t s = 0x123456789ABCDEFULL;                             /* deterministic LCG */
        for (size_t i = 0; i < RAND_SZ; i++) {
            s = s * 6364136223846793005ULL + 1442695040888963407ULL;
            rnd[i] = (uint8_t)(s >> 33);
        }
    }
    for (size_t i = 0; i < POST_SZ; i++) post[i] = (uint8_t)(i * 131 + 7);

    /* ── create container ─────────────────────────────────────── */
    fprintf(stderr, "=== Build ===\n");
    unlink(PATH);
    CFS *c = cfs_create(PATH);
    T(c != NULL, "create");
    if (!c) return 1;

    /* cfs_add_file rejects size==0, so the empty file is made with cfs_write. */
    T(cfs_write(c, "empty.txt", NULL, 0) == 0, "add empty.txt (size 0)");
    T(cfs_add_file(c, "text.txt", text, TEXT_SZ) == 0, "add text.txt");
    T(cfs_add_file(c, "big.bin", big, BIG_SZ) == 0, "add big.bin (>8MB)");
    T(cfs_add_file(c, "dup.bin", dup, BIG_SZ) == 0, "add dup.bin (copy of big.bin)");
    T(cfs_add_file(c, "rand.bin", rnd, RAND_SZ) == 0, "add rand.bin");
    T(cfs_finalise(c) == 0, "finalise");
    cfs_close(c);

    /* ── snapshot expected bytes before merging ───────────────── */
    fprintf(stderr, "\n=== Snapshot (pre-merge) ===\n");
    c = cfs_open(PATH, CFS_RDWR);
    T(c != NULL, "reopen RDWR");
    if (!c) return 1;

    uint8_t *s_text = malloc(TEXT_SZ), *s_big = malloc(BIG_SZ), *s_dup = malloc(BIG_SZ),
            *s_rnd = malloc(RAND_SZ);
    if (!s_text || !s_big || !s_dup || !s_rnd) { fprintf(stderr, "oom\n"); return 1; }
    T(cfs_read(c, "text.txt", s_text, TEXT_SZ, 0) == TEXT_SZ && !memcmp(s_text, text, TEXT_SZ),
      "snapshot text.txt");
    T(cfs_read(c, "big.bin", s_big, BIG_SZ, 0) == (ssize_t)BIG_SZ && !memcmp(s_big, big, BIG_SZ),
      "snapshot big.bin");
    T(cfs_read(c, "dup.bin", s_dup, BIG_SZ, 0) == (ssize_t)BIG_SZ && !memcmp(s_dup, dup, BIG_SZ),
      "snapshot dup.bin");
    T(cfs_read(c, "rand.bin", s_rnd, RAND_SZ, 0) == RAND_SZ && !memcmp(s_rnd, rnd, RAND_SZ),
      "snapshot rand.bin");

    /* ── merge ────────────────────────────────────────────────── */
    fprintf(stderr, "\n=== Merge ===\n");
    T(cfs_dedup_merge(c) == 0, "cfs_dedup_merge");

    CfsDedupStats ds;
    T(cfs_dedup_stats(c, &ds) == 0, "cfs_dedup_stats");
    T(ds.merged_files > 0, "stats: merged_files > 0");
    fprintf(stderr, "  stats: merged=%u skipped=%u logical=%llu store=%llu table=%llu\n",
            ds.merged_files, ds.skipped,
            (unsigned long long)ds.logical_bytes,
            (unsigned long long)ds.store_bytes,
            (unsigned long long)ds.table_bytes);
    {
        uint64_t merged_sum = (uint64_t)TEXT_SZ + 2 * (uint64_t)BIG_SZ + (uint64_t)RAND_SZ;
        /* dup.bin is byte-identical to big.bin, so its whole content must be
         * served by references: the store may hold at most one copy of it. */
        T(ds.store_bytes + (uint64_t)BIG_SZ <= merged_sum,
          "stats: the duplicate file was deduped away");
        T(ds.store_bytes > 0 && ds.store_bytes < merged_sum,
          "stats: store smaller than merged input");
    }
    cfs_close(c);

    /* ── reopen and verify byte-identical reads ───────────────── */
    fprintf(stderr, "\n=== Verify after reopen ===\n");
    c = cfs_open(PATH, CFS_RDWR);
    T(c != NULL, "reopen RDWR after merge");
    if (!c) return 1;

    battery(c, "empty.txt", s_text, 0);
    battery(c, "text.txt", s_text, TEXT_SZ);
    battery(c, "rand.bin", s_rnd, RAND_SZ);
    battery(c, "big.bin", s_big, (size_t)BIG_SZ);
    battery(c, "dup.bin", s_dup, (size_t)BIG_SZ);

    /* read straddling the 8MB reference-table unit boundary */
    fprintf(stderr, "  -- 8MB boundary --\n");
    check_read(c, "big.bin", s_big, (size_t)BIG_SZ,
               (off_t)(8ULL * 1024 * 1024 - 128), 256,
               "big.bin: read straddles 8MB boundary");

    /* ── a file written after the merge goes through write-path dedup ── */
    fprintf(stderr, "\n=== Post-merge written file ===\n");
    T(cfs_write(c, "after.bin", post, POST_SZ) == 0, "write after.bin post-merge");
    {
        CfsStat st;
        T(cfs_stat(c, "after.bin", &st) == 0, "stat after.bin");
        /* cfs_write() now dedups on the write path itself: a regular file is
         * a reference table over @store, not a plain block list. */
        T(st.mode == CFS_MODE_DEDUP, "after.bin is written dedup-mode");
        uint8_t *rb = malloc(POST_SZ);
        ssize_t n = cfs_read(c, "after.bin", rb, POST_SZ, 0);
        T(n == POST_SZ && !memcmp(rb, post, POST_SZ), "after.bin reads back correctly");
        free(rb);
    }

    /* ── cfs_ls still lists everything ────────────────────────── */
    fprintf(stderr, "\n=== cfs_ls ===\n");
    {
        CfsDirEntry ents[64];
        int n = cfs_ls(c, "", ents, 64);
        T(n >= 5, "cfs_ls returns entries");
        T(has_name(ents, n, "empty.txt"), "ls: empty.txt");
        T(has_name(ents, n, "text.txt"),  "ls: text.txt");
        T(has_name(ents, n, "big.bin"),   "ls: big.bin");
        T(has_name(ents, n, "dup.bin"),   "ls: dup.bin");
        T(has_name(ents, n, "rand.bin"),  "ls: rand.bin");
        T(has_name(ents, n, "after.bin"), "ls: after.bin");
    }

    cfs_close(c);

    free(text); free(big); free(dup); free(rnd); free(post);
    free(s_text); free(s_big); free(s_dup); free(s_rnd);
    unlink(PATH);

    fprintf(stderr, "\n=== %d failures ===\n", failures);
    return failures ? 1 : 0;
}
