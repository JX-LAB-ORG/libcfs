#define _GNU_SOURCE
#include "../cfs.h"
#include "../cfs_format.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

/* Write-path content-addressed dedup (v7 G3).
 *
 * The point of the feature is that no maintenance step is needed: after the
 * writes below the container already holds one copy of the shared content,
 * and every file still reads back byte-exact.  The corpus is deliberately
 * incompressible (xorshift noise) so the size assertions measure dedup, not
 * the entropy coder. */

static int failures = 0;
#define T(c, msg) do { if (!(c)) { fprintf(stderr, "FAIL: %s (errno=%d)\n", msg, errno); failures++; } \
                       else { fprintf(stderr, "  OK: %s\n", msg); } } while(0)

#define PATH "/tmp/test_dedup_writepath.cfs"
#define SZ   (256 * 1024)
#define N    12
#define PATCH 32

static void fill(uint8_t *b, size_t n, uint32_t seed) {
    uint64_t s = seed * 6364136223846793005ULL + 1442695040888963407ULL;
    for (size_t i = 0; i < n; i++) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        b[i] = (uint8_t)(s >> 32);
    }
}

/* The i-th near copy: the base with one PATCH-byte run changed. */
static void make_near(uint8_t *dst, const uint8_t *base, int i) {
    memcpy(dst, base, SZ);
    size_t off = (size_t)((i * 7919u) % (SZ - PATCH));
    memset(dst + off, (uint8_t)(0xA5 + i), PATCH);
}

static char names[N][16], names2[N][16];

static int same(CFS *c, const char *path, const uint8_t *want, size_t n) {
    uint8_t *got = malloc(n ? n : 1);
    if (!got) return 0;
    ssize_t r = cfs_read(c, path, got, n, 0);
    int ok = (r == (ssize_t)n) && !memcmp(got, want, n);
    if (!ok) fprintf(stderr, "    %s: read %zd of %zu%s\n", path, r, n,
                     (r == (ssize_t)n) ? " (content differs)" : "");
    free(got);
    return ok;
}

int main(void) {
    setvbuf(stderr, NULL, _IONBF, 0);
    unlink(PATH);

    uint8_t *base = malloc(SZ), *near = malloc(SZ);
    if (!base || !near) { fprintf(stderr, "oom\n"); return 1; }
    fill(base, SZ, 1);

    CFS *c = cfs_create(PATH);
    T(c != NULL, "create");
    if (!c) return 1;

    fprintf(stderr, "\n=== %d identical %dKB files, one write each ===\n", N, SZ / 1024);
    for (int i = 0; i < N; i++) {
        snprintf(names[i], sizeof names[i], "/f%02d.bin", i);
        T(cfs_write(c, names[i], base, SZ) == 0, names[i]);
        CfsStat st;
        T(cfs_stat(c, names[i], &st) == 0 && st.mode == CFS_MODE_DEDUP,
          "written as a reference table");
    }
    {
        CfsDedupStats ds;
        T(cfs_dedup_stats(c, &ds) == 0, "stats");
        fprintf(stderr, "  store=%llu logical=%llu tables=%llu\n",
                (unsigned long long)ds.store_bytes, (unsigned long long)ds.logical_bytes,
                (unsigned long long)ds.table_bytes);
        T(ds.store_bytes > 0 && ds.store_bytes < 2 * SZ,
          "store holds one copy, not N (no merge command ran)");
        T(ds.merged_files == (uint32_t)N, "all N files are dedup-mode");
    }
    T(cfs_physical_used(c) < 2 * (uint64_t)SZ + 65536,
      "container is about one copy, not N");
    {
        int all = 1;
        for (int i = 0; i < N; i++) all &= same(c, names[i], base, SZ);
        T(all, "every identical file reads back byte-exact");
    }

    fprintf(stderr, "\n=== %d near-identical files (one %dB patch each) ===\n", N, PATCH);
    for (int i = 0; i < N; i++) {
        snprintf(names2[i], sizeof names2[i], "/n%02d.bin", i);
        make_near(near, base, i);
        T(cfs_write(c, names2[i], near, SZ) == 0, names2[i]);
        T(same(c, names2[i], near, SZ), "near copy reads back");
    }
    {
        CfsDedupStats ds;
        T(cfs_dedup_stats(c, &ds) == 0, "stats (near)");
        fprintf(stderr, "  store=%llu logical=%llu\n",
                (unsigned long long)ds.store_bytes, (unsigned long long)ds.logical_bytes);
        T(ds.store_bytes < 4 * SZ, "near-identical store stays near one copy");
        T(cfs_physical_used(c) < 4 * (uint64_t)SZ + 131072,
          "near-identical container stays near one copy");
    }

    /* A fresh handle must rebuild the index from @store, or a write of bytes
     * the store already holds would duplicate them. */
    fprintf(stderr, "\n=== reopen: incremental write matches earlier content ===\n");
    CfsDedupStats before, after;
    cfs_dedup_stats(c, &before);
    cfs_close(c);

    c = cfs_open(PATH, CFS_RDWR);
    T(c != NULL, "reopen RDWR");
    if (!c) return 1;
    uint64_t p0 = cfs_physical_used(c);
    T(cfs_write(c, "/copy.bin", base, SZ) == 0, "write a copy in a new session");
    uint64_t p1 = cfs_physical_used(c);
    cfs_dedup_stats(c, &after);
    fprintf(stderr, "  container %llu -> %llu, store %llu -> %llu\n",
            (unsigned long long)p0, (unsigned long long)p1,
            (unsigned long long)before.store_bytes, (unsigned long long)after.store_bytes);
    /* The rebuild re-chunks @store as one stream, so chunks whose cut was
     * forced by a file's EOF can look different there; those few chunks are
     * stored again.  The point is that it is a few chunks, not a copy. */
    T(after.store_bytes - before.store_bytes < SZ / 4,
      "identical content added only resync chunks, not a copy");
    T(p1 - p0 < 65536, "growth is the table, not a second copy");
    T(same(c, "/copy.bin", base, SZ), "cross-session copy reads back");

    fprintf(stderr, "\n=== truncate / extend / rm / ls on a dedup file ===\n");
    T(cfs_truncate(c, "/f00.bin", SZ / 2) == 0, "truncate to half");
    T(same(c, "/f00.bin", base, SZ / 2), "truncated prefix reads back");
    {
        CfsStat st;
        T(cfs_stat(c, "/f00.bin", &st) == 0 && st.size == SZ / 2, "size is SZ/2");
        T(cfs_truncate(c, "/f00.bin", SZ + 4096) == 0, "extend past the old end");
        uint8_t *tail = malloc(4096);
        T(tail && cfs_read(c, "/f00.bin", tail, 4096, SZ) == 4096, "read the extended tail");
        int zero = 1;
        for (int i = 0; tail && i < 4096; i++) zero &= (tail[i] == 0);
        T(zero, "extended tail is zeros");
        free(tail);
    }
    T(cfs_unlink(c, "/n00.bin") == 0, "unlink a dedup file");
    {
        CfsDirEntry ents[64];
        int n = cfs_ls(c, "", ents, 64);
        T(n == N + N + 1 - 1, "listing counts every file, @store hidden");
    }
    {
        int all = 1;
        for (int i = 1; i < N; i++) {
            make_near(near, base, i);
            all &= same(c, names2[i], near, SZ);
        }
        T(all, "surviving near files still read back");
    }
    cfs_close(c);
    c = cfs_open(PATH, CFS_RDONLY);
    T(c != NULL, "reopen after truncate/rm");
    if (c) {
        T(same(c, "/copy.bin", base, SZ), "persisted copy reads back");
        cfs_close(c);
    }

    fprintf(stderr, "\n=== independent self-check ===\n");
    {
        FILE *o = tmpfile();
        int rc = cfs_verify(PATH, CFS_VERIFY_DEEP, o ? o : stderr);
        if (o) fclose(o);
        T(rc == 0, "cfs_verify --deep finds no problems");
    }

    free(base); free(near);
    unlink(PATH);
    fprintf(stderr, "\n=== %d failures ===\n", failures);
    return failures ? 1 : 0;
}
