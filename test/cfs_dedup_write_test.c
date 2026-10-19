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

#define PATH  "/tmp/test_dedup_write.cfs"
#define SZ    (300 * 1024)
#define ASZ   (2 * 1024 * 1024)      /* @block size */

static void fill(uint8_t *b, size_t n, uint32_t seed) {
    uint64_t s = seed * 6364136223846793005ULL + 1442695040888963407ULL;
    for (size_t i = 0; i < n; i++) { s = s * 6364136223846793005ULL + 1442695040888963407ULL; b[i] = (uint8_t)(s >> 33); }
}

static int same(CFS *c, const char *path, const uint8_t *want, size_t n) {
    uint8_t *got = malloc(n ? n : 1);
    if (!got) return 0;
    ssize_t r = cfs_read(c, path, got, n, 0);
    int ok = (r == (ssize_t)n) && !memcmp(got, want, n);
    if (!ok) {
        if (r != (ssize_t)n) fprintf(stderr, "    short read %zd of %zu\n", r, n);
        else for (size_t i = 0; i < n; i++)
            if (got[i] != want[i]) {
                fprintf(stderr, "    first mismatch @%zu got=%02x want=%02x\n", i, got[i], want[i]);
                break;
            }
    }
    free(got);
    return ok;
}

int main(void) {
    setvbuf(stderr, NULL, _IONBF, 0);
    unlink(PATH);

    uint8_t *a = malloc(SZ), *b = malloc(SZ), *patch = malloc(SZ);
    if (!a || !b || !patch) { fprintf(stderr, "oom\n"); return 1; }
    fill(a, SZ, 1);
    fill(b, SZ, 2);
    memset(patch, 0xAB, SZ);

    /* ── build a container with two files (b duplicates a's first half) ── */
    fprintf(stderr, "=== Build ===\n");
    memcpy(b, a, SZ / 2);
    CFS *c = cfs_create(PATH);
    T(c != NULL, "create");
    if (!c) return 1;
    T(cfs_add_file(c, "a.bin", a, SZ) == 0, "add a.bin");
    T(cfs_add_file(c, "b.bin", b, SZ) == 0, "add b.bin (half duplicate)");
    T(cfs_finalise(c) == 0, "finalise");

    /* ── merge ────────────────────────────────────────────────── */
    fprintf(stderr, "\n=== Merge ===\n");
    T(cfs_dedup_merge(c) == 0, "cfs_dedup_merge");
    CfsDedupStats d0;
    cfs_dedup_stats(c, &d0);
    fprintf(stderr, "  store=%llu logical=%llu\n",
            (unsigned long long)d0.store_bytes, (unsigned long long)d0.logical_bytes);
    T(d0.store_bytes < d0.logical_bytes, "merge deduplicated the shared half");

    /* ── a write of identical bytes must change nothing ───────── */
    fprintf(stderr, "\n=== No-op write ===\n");
    {
        CfsDedupStats before, after;
        cfs_dedup_stats(c, &before);
        T(cfs_dedup_write(c, "a.bin", a + 4096, 8192, 4096) == 8192, "rewrite identical range");
        cfs_dedup_stats(c, &after);
        T(after.store_bytes == before.store_bytes, "identical write appended nothing");
        T(same(c, "a.bin", a, SZ), "a.bin unchanged after no-op write");
    }

    /* ── a real write lands, and only there ───────────────────── */
    fprintf(stderr, "\n=== Overwrite ===\n");
    {
        uint8_t *want = malloc(SZ);
        memcpy(want, a, SZ);
        memcpy(want + 100000, patch, 20000);
        T(cfs_dedup_write(c, "a.bin", patch, 20000, 100000) == 20000, "overwrite 20KB in the middle");
        T(same(c, "a.bin", want, SZ), "a.bin reads back patched");
        T(same(c, "b.bin", b, SZ), "b.bin untouched by a's write");

        /* straddling an entry boundary: 300KB in, 8KB wide */
        memcpy(want + 250000, patch, 8192);
        T(cfs_dedup_write(c, "a.bin", patch, 8192, 250000) == 8192, "overwrite across an entry boundary");
        T(same(c, "a.bin", want, SZ), "a.bin reads back patched (2)");

        /* write the SAME bytes again → no-op path must still be correct */
        T(cfs_dedup_write(c, "a.bin", patch, 8192, 250000) == 8192, "repeat of the same write");
        T(same(c, "a.bin", want, SZ), "a.bin unchanged by the repeat");

        /* extend past the end */
        uint8_t *want2 = malloc(SZ + 4096);
        memcpy(want2, want, SZ);
        memcpy(want2 + SZ, patch, 4096);
        T(cfs_dedup_write(c, "a.bin", patch, 4096, SZ) == 4096, "extend past the end");
        CfsStat st;
        T(cfs_stat(c, "a.bin", &st) == 0 && st.size == SZ + 4096, "size grew");
        T(same(c, "a.bin", want2, SZ + 4096), "extended content reads back");
        free(want); free(want2);
    }

    /* ── @block: merge the device, then a random write ────────── */
    fprintf(stderr, "\n=== @block ===\n");
    {
        T(cfs_block_resize(c, ASZ) == 0, "block_resize");
        uint8_t *disk = calloc(1, ASZ);
        fill(disk, ASZ, 7);
        T(cfs_block_write(c, disk, ASZ, 0) == 0, "fill @block");
        T(cfs_dedup_merge(c) == 0, "merge (includes @block)");
        CfsStat st;
        T(cfs_stat(c, "@block", &st) == 0 && st.mode == CFS_MODE_DEDUP, "@block became a merged device");

        uint8_t blk[4096];
        fill(blk, sizeof blk, 9);
        T(cfs_block_write(c, blk, sizeof blk, 1u << 20) == 0, "random write into merged @block");
        memcpy(disk + (1u << 20), blk, sizeof blk);
        uint8_t *got = malloc(ASZ);
        T(cfs_block_read(c, got, ASZ, 0) == (ssize_t)ASZ && !memcmp(got, disk, ASZ),
          "@block reads back with the write applied");
        free(got); free(disk);
    }

    /* ── maintenance, on its own container so @store starts small ── */
    fprintf(stderr, "\n=== GC ===\n");
    {
        const char *p2 = "/tmp/test_dedup_gc.cfs";
        unlink(p2);
        CFS *g = cfs_create(p2);
        T(g != NULL, "gc container");
        if (!g) return 1;
        uint8_t *orig = malloc(SZ), *p = malloc(4096);
        if (!orig || !p) { fprintf(stderr, "oom\n"); return 1; }
        fill(orig, SZ, 3);
        T(cfs_add_file(g, "x.bin", orig, SZ) == 0, "add x.bin");
        T(cfs_finalise(g) == 0, "finalise x");
        T(cfs_dedup_merge(g) == 0, "merge x");
        /* rewriting one range over and over strands everything it replaced */
        for (int i = 0; i < 200; i++) {
            fill(p, 4096, 2000u + (uint32_t)i);
            if (cfs_dedup_write(g, "x.bin", p, 4096, 8192) != 4096) { T(0, "rewrite burst"); break; }
        }
        CfsDedupGcStats gs;
        T(cfs_dedup_gc(g, &gs) == 0, "cfs_dedup_gc");
        fprintf(stderr, "  refrag=%u dead=%llu store %llu -> %llu\n", gs.refrag_files,
                (unsigned long long)gs.dead_bytes,
                (unsigned long long)gs.store_before, (unsigned long long)gs.store_after);
        T(gs.dead_bytes > 0, "dead bytes were found");
        T(gs.store_after > 0 && gs.store_after < gs.store_before, "@store shrank");

        uint8_t *want = malloc(SZ);
        memcpy(want, orig, SZ);
        fill(p, 4096, 2000u + 199u);
        memcpy(want + 8192, p, 4096);
        T(same(g, "x.bin", want, SZ), "x.bin reads back after GC");
        CfsDedupGcStats g2;
        T(cfs_dedup_gc(g, &g2) == 0 && g2.store_after == 0,
          "second pass finds nothing worth reclaiming");
        cfs_close(g);

        g = cfs_open(p2, CFS_RDWR);           /* the remap has to persist */
        T(g != NULL, "reopen after GC");
        if (g) { T(same(g, "x.bin", want, SZ), "x.bin after GC + reopen"); cfs_close(g); }
        free(orig); free(p); free(want);
        unlink(p2);
    }

    cfs_close(c);

    /* ── everything survives a reopen ─────────────────────────── */
    fprintf(stderr, "\n=== Reopen ===\n");
    c = cfs_open(PATH, CFS_RDWR);
    T(c != NULL, "reopen");
    if (c) {
        uint8_t *want = malloc(SZ + 4096);
        memcpy(want, a, SZ);
        memcpy(want + 100000, patch, 20000);
        memcpy(want + 250000, patch, 8192);
        memcpy(want + SZ, patch, 4096);
        T(same(c, "a.bin", want, SZ + 4096), "a.bin after reopen");
        T(same(c, "b.bin", b, SZ), "b.bin after reopen");
        free(want);
        cfs_close(c);
    }

    free(a); free(b); free(patch);
    unlink(PATH);
    fprintf(stderr, "\n=== %d failures ===\n", failures);
    return failures ? 1 : 0;
}
