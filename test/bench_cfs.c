/* bench_cfs.c — container-level benchmark.
 *
 * The codec benchmark says what cpenc does to bytes; this says what the
 * container does to a workload.  The interesting numbers are the ones that
 * are not the codec's: a 4K random write costs a whole 8MB slab
 * decompress + patch + recompress, a small-file create costs an inode-table
 * rewrite, and compact rewrites everything.
 *
 *   usage: bench_cfs <container.cfs> <size_mb> [data_file]
 *
 * A data file (a real corpus) is used as the write source so the ratio and
 * the CPU cost are the realistic ones; without it a repeating pattern is
 * generated.
 */
#include "../cfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MB (1024 * 1024)
#define CHUNK (1 * MB)
#define RAND_OPS 400
#define SMALL_FILES 1000
#define SMALL_SZ 4096

static double now_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static uint64_t rng = 0x243F6A8885A308D3ull;
static uint64_t xr(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <container.cfs> <size_mb> [data_file]\n", argv[0]);
        return 2;
    }
    const char *cpath = argv[1];
    uint64_t sz = (uint64_t)atoi(argv[2]) * MB;
    const char *dataf = argc > 3 ? argv[3] : NULL;

    /* source data: real corpus if given, else a compressible pattern */
    uint8_t *chunk = malloc(CHUNK);
    if (!chunk) return 1;
    uint8_t *reald = NULL;
    size_t realn = 0;
    if (dataf) {
        FILE *f = fopen(dataf, "rb");
        if (f) {
            fseek(f, 0, SEEK_END); realn = (size_t)ftell(f); fseek(f, 0, SEEK_SET);
            reald = malloc(realn);
            if (reald) { if (fread(reald, 1, realn, f) != realn) realn = 0; }
            fclose(f);
        }
    }
    if (realn < CHUNK) {
        for (size_t i = 0; i < CHUNK; i++) chunk[i] = (uint8_t)((i * 2654435761u) >> 24);
    }

    unlink(cpath);
    CFS *c = cfs_create(cpath);
    if (!c) { fprintf(stderr, "create failed\n"); return 1; }
    if (cfs_block_resize(c, sz) != 0) { fprintf(stderr, "resize failed\n"); return 1; }

    /* ── sequential write ── */
    double t0 = now_s();
    for (uint64_t off = 0; off < sz; off += CHUNK) {
        if (realn >= CHUNK) {
            size_t o = (size_t)(off % (realn - CHUNK));
            memcpy(chunk, reald + o, CHUNK);
        }
        if (cfs_block_write(c, chunk, CHUNK, (off_t)off) != 0) { fprintf(stderr, "w fail @%llu\n", (unsigned long long)off); return 1; }
    }
    double tw = now_s() - t0;
    printf("seq write      %6.1f MB in %6.2fs = %7.2f MB/s\n", (double)sz / MB, tw, (double)sz / MB / tw);

    /* ── sequential read ── */
    uint8_t *rb = malloc(CHUNK);
    t0 = now_s();
    for (uint64_t off = 0; off < sz; off += CHUNK) {
        if (cfs_block_read(c, rb, CHUNK, (off_t)off) != (ssize_t)CHUNK) { fprintf(stderr, "r fail\n"); return 1; }
    }
    double tr = now_s() - t0;
    printf("seq read       %6.1f MB in %6.2fs = %7.2f MB/s\n", (double)sz / MB, tr, (double)sz / MB / tr);
    free(rb);

    /* ── random 4K patch writes (the expensive path) ── */
    uint8_t p[SMALL_SZ];
    for (int i = 0; i < SMALL_SZ; i++) p[i] = (uint8_t)(i * 31 + 7);
    t0 = now_s();
    for (int i = 0; i < RAND_OPS; i++) {
        uint64_t off = (xr() % (sz / SMALL_SZ)) * SMALL_SZ;
        if (cfs_block_write(c, p, SMALL_SZ, (off_t)off) != 0) { fprintf(stderr, "patch fail\n"); return 1; }
    }
    double tp = now_s() - t0;
    printf("rand 4K write  %6d ops in %6.2fs = %7.1f ops/s (%6.2f MB/s)\n",
           RAND_OPS, tp, RAND_OPS / tp, (double)RAND_OPS * SMALL_SZ / MB / tp);

    /* ── random 4K reads ── */
    uint8_t rb2[SMALL_SZ];
    t0 = now_s();
    for (int i = 0; i < RAND_OPS * 4; i++) {
        uint64_t off = (xr() % (sz / SMALL_SZ)) * SMALL_SZ;
        if (cfs_block_read(c, rb2, SMALL_SZ, (off_t)off) != SMALL_SZ) { fprintf(stderr, "rr fail\n"); return 1; }
    }
    double trr = now_s() - t0;
    printf("rand 4K read   %6d ops in %6.2fs = %7.1f ops/s (%6.2f MB/s)\n",
           RAND_OPS * 4, trr, RAND_OPS * 4 / trr, (double)RAND_OPS * 4 * SMALL_SZ / MB / trr);

    /* ── many small files: create + stat + read ── */
    uint8_t sb[SMALL_SZ];
    for (int i = 0; i < SMALL_SZ; i++) sb[i] = (uint8_t)(i ^ 0x5A);
    t0 = now_s();
    for (int i = 0; i < SMALL_FILES; i++) {
        char nm[64];
        snprintf(nm, sizeof(nm), "/bench/s%04d", i);
        if (cfs_write(c, nm, sb, SMALL_SZ) != 0) { fprintf(stderr, "small create fail %d\n", i); return 1; }
    }
    double tc = now_s() - t0;
    printf("small create   %6d files in %6.2fs = %7.1f files/s\n", SMALL_FILES, tc, SMALL_FILES / tc);

    t0 = now_s();
    for (int i = 0; i < SMALL_FILES; i++) {
        char nm[64];
        snprintf(nm, sizeof(nm), "/bench/s%04d", i);
        CfsStat st;
        if (cfs_stat(c, nm, &st) != 0) { fprintf(stderr, "stat fail\n"); return 1; }
        if (cfs_read(c, nm, sb, SMALL_SZ, 0) != SMALL_SZ) { fprintf(stderr, "small read fail\n"); return 1; }
    }
    double tsr = now_s() - t0;
    printf("small read     %6d files in %6.2fs = %7.1f files/s\n", SMALL_FILES, tsr, SMALL_FILES / tsr);

    cfs_close(c);

    /* ── reopen cost ── */
    t0 = now_s();
    c = cfs_open(cpath, CFS_RDWR);
    double to = now_s() - t0;
    if (!c) { fprintf(stderr, "reopen failed\n"); return 1; }
    printf("open           %6.2fs\n", to);

    /* ── compact ── */
    t0 = now_s();
    cfs_compact(c);
    double tcm = now_s() - t0;
    printf("compact        %6.2fs\n", tcm);

    CfsStats st;
    cfs_stats(c, &st);
    printf("container      %.1f MB logical, %.1f MB stored, ratio %.2fx\n",
           (double)st.total_orig_size / MB, (double)st.total_compressed_size / MB,
           (double)st.compress_ratio);
    cfs_close(c);
    free(chunk); free(reald);
    return 0;
}
