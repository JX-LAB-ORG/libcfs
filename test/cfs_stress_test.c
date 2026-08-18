#include "../cfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

static int failed = 0;
#define CHK(c,m) do{if(!(c)){failed++;fprintf(stderr,"  FAIL: %s\n",m);}else{fprintf(stderr,"  OK %s\n",m);}}while(0)

#define DISK_SZ (64ULL * 1024 * 1024)
#define PATH     "/tmp/test_stress.cfs"

/* deterministic PRNG (xorshift32) */
static uint32_t rng_state = 0x12345678;
static uint32_t rnd(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

static uint8_t *model;   /* 256MB in-memory model */

static void wm(CFS *c, uint64_t off, const uint8_t *d, size_t n) {
    if (cfs_block_write(c, d, n, (off_t)off) != 0) {
        failed++;
        fprintf(stderr, "  FAIL: write @%llu n=%zu\n", (unsigned long long)off, n);
        return;
    }
    memcpy(model + off, d, n);
}

static int vm(CFS *c, uint64_t off, size_t n) {
    uint8_t *rd = malloc(n);
    ssize_t got = cfs_block_read(c, rd, n, (off_t)off);
    int ok = (got == (ssize_t)n) && memcmp(rd, model + off, n) == 0;
    free(rd);
    return ok;
}

/* verify a random sample of the model */
static void sample_check(CFS *c, int rounds) {
    for (int i = 0; i < rounds; i++) {
        uint64_t off = ((uint64_t)rnd() % DISK_SZ) & ~(uint64_t)511;
        size_t n = (size_t)(rnd() % 4096) + 1;
        if (off + n > DISK_SZ) n = (size_t)(DISK_SZ - off);
        if (!vm(c, off, n)) {
            failed++;
            fprintf(stderr, "  FAIL: sample @%llu n=%zu\n", (unsigned long long)off, n);
            return;
        }
    }
}

static void test_random_stress(void) {
    printf("[s1] 500 random writes + reopen consistency\n");
    unlink(PATH);
    model = calloc(1, DISK_SZ);
    CFS *c = cfs_create(PATH);
    CHK(c != NULL, "create");
    if (!c) return;
    cfs_block_resize(c, DISK_SZ);

    uint8_t buf[8192];
    for (int i = 0; i < 20; i++) {
        uint64_t off = ((uint64_t)rnd() % DISK_SZ) & ~(uint64_t)511;
        size_t n = (size_t)(rnd() % 8192) + 1;
        if (off + n > DISK_SZ) n = (size_t)(DISK_SZ - off);
        for (size_t j = 0; j < n; j++) buf[j] = (uint8_t)(rnd() & 0xFF);
        wm(c, off, buf, n);
        /* occasionally reopen mid-stream to exercise persistence */
        if (i % 10 == 9) {
            cfs_close(c);
            c = cfs_open(PATH, CFS_RDWR);
            CHK(c != NULL, "mid-stream reopen");
            if (!c) return;
        }
    }
    CHK(vm(c, 0, DISK_SZ), "full-disk model match");
    sample_check(c, 30);

    /* reopen and re-verify */
    cfs_close(c);
    c = cfs_open(PATH, CFS_RDONLY);
    CHK(c != NULL, "final reopen");
    if (c) {
        sample_check(c, 30);
        cfs_close(c);
    }
    free(model);
    unlink(PATH);
}

static void test_block_cap_fallback(void) {
    printf("[s2] 16-block cap -> RMW fallback\n");
    unlink(PATH);
    model = calloc(1, DISK_SZ);
    CFS *c = cfs_create(PATH);
    CHK(c != NULL, "create");
    if (!c) return;
    cfs_block_resize(c, DISK_SZ);

    /* 17 scattered writes: first 16 create blocks, the 17th must exceed
     * the cap and fall back to whole-file RMW */
    uint8_t buf[512];
    for (int i = 0; i < 17; i++) {
        uint64_t off = (uint64_t)i * (DISK_SZ / 20) + 10;   /* scattered, gap-growing */
        for (size_t j = 0; j < 512; j++) buf[j] = (uint8_t)(i * 31 + j);
        wm(c, off, buf, 512);
    }
    CHK(vm(c, 0, DISK_SZ), "full model match after fallback");
    sample_check(c, 40);

    /* fallback must also handle overlapping writes afterwards */
    for (int i = 0; i < 5; i++) {
        uint64_t off = ((uint64_t)rnd() % DISK_SZ) & ~(uint64_t)511;
        size_t n = 1024;
        if (off + n > DISK_SZ) off = DISK_SZ - n;
        for (size_t j = 0; j < n; j++) buf[j] = (uint8_t)(rnd() & 0xFF);
        wm(c, off, buf, n);
    }
    CHK(vm(c, 0, DISK_SZ), "full model match after post-fallback writes");
    cfs_close(c);
    free(model);
    unlink(PATH);
}

static void test_part_loop(void) {
    printf("[s3] 100 part label/add/del/reopen cycles\n");
    int ok = 1;
    for (int iter = 0; iter < 100; iter++) {
        unlink(PATH);
        CFS *c = cfs_create(PATH);
        if (!c) { ok = 0; break; }
        cfs_block_resize(c, 64ULL * 1024 * 1024);
        if (cfs_part_label(c, CFS_PART_MBR) != 0) { ok = 0; cfs_close(c); break; }
        int a1 = cfs_part_add(c, 1ULL << 20, 1ULL << 20, 0x83, NULL, 1);
        int a2 = cfs_part_add(c, 2ULL << 20, 1ULL << 20, 0x0C, NULL, 0);
        if (a1 != 1 || a2 != 2) { ok = 0; cfs_close(c); break; }
        if (cfs_part_del(c, 1) != 0) { ok = 0; cfs_close(c); break; }
        cfs_close(c);
        c = cfs_open(PATH, CFS_RDONLY);
        if (!c) { ok = 0; break; }
        CfsPartition p;
        if (cfs_part_count(c) != 1 || cfs_part_get(c, 1, &p) != 0 ||
            p.start != (2ULL << 20) || p.mbr_type != 0x0C) { ok = 0; cfs_close(c); break; }
        cfs_close(c);
    }
    CHK(ok, "100 cycles of label/add/del/reopen");
    unlink(PATH);
}

int main(void) {
    test_random_stress();
    test_block_cap_fallback();
    test_part_loop();
    printf("\n=== %d failures ===\n", failed);
    return failed ? 1 : 0;
}
