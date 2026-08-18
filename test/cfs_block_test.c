#include "../cfs.h"
#include "../cfs_format.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failed = 0;
#define CHK(c,m) do{if(!(c)){failed++;fprintf(stderr,"  FAIL: %s\n",m);}else{fprintf(stderr,"  OK %s\n",m);}}while(0)

#define DISK_SZ  (128ULL * 1024 * 1024)
#define PATH     "/tmp/test_block.cfs"

/* ── Test 1: shrink regression — writing at offset 0 must not shrink the disk ── */
static void test_shrink_regression(void) {
    printf("[t1] shrink regression\n");
    unlink(PATH);
    CFS *c = cfs_create(PATH);
    CHK(c != NULL, "create");
    if (!c) return;
    CHK(cfs_block_resize(c, DISK_SZ) == 0, "resize 128MB");
    CHK(cfs_block_size(c) == DISK_SZ, "size = 128MB before write");

    const char *data = "X";
    CHK(cfs_block_write(c, data, 1, 0) == 0, "write 1B @0");
    CHK(cfs_block_size(c) == DISK_SZ, "size still 128MB after 1B@0 write");

    uint8_t r[16];
    CHK(cfs_block_read(c, r, 16, 0) == 16, "read 16B @0");
    CHK(r[0] == 'X' && r[1] == 0 && r[15] == 0, "data + zero pad");
    CHK(cfs_block_read(c, r, 8, DISK_SZ - 8) == 8, "read @end");
    for (int i = 0; i < 8; i++) CHK(r[i] == 0, "trailing sparse zero");
    cfs_close(c);
    unlink(PATH);
}

/* ── Tests 2-5: in-memory model for full verification ── */
static uint8_t model[DISK_SZ];

static CFS *mk_disk(void) {
    memset(model, 0, sizeof(model));
    unlink(PATH);
    CFS *c = cfs_create(PATH);
    if (!c) return NULL;
    if (cfs_block_resize(c, DISK_SZ) != 0) { cfs_close(c); return NULL; }
    return c;
}

static void wm(CFS *c, uint64_t off, const uint8_t *d, size_t n) {
    if (cfs_block_write(c, d, n, (off_t)off) != 0) {
        failed++;
        fprintf(stderr, "  FAIL: write @%llu n=%zu\n", (unsigned long long)off, n);
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

static void test_sparse_writes(void) {
    printf("[t2] sparse writes across 64MB boundary\n");
    CFS *c = mk_disk();
    CHK(c != NULL, "create");
    if (!c) return;

    uint8_t a[512], b[8], c5[5];
    for (int i = 0; i < 512; i++) a[i] = (uint8_t)(i * 7 + 1);
    for (int i = 0; i < 8; i++)  b[i] = (uint8_t)(0xA0 + i);
    for (int i = 0; i < 5; i++)  c5[i] = (uint8_t)(i * 31);

    wm(c, 0, a, 512);
    wm(c, 1000, b, 8);
    wm(c, 64ULL*1024*1024 - 4, a, 4);   /* straddles the 64MB boundary */
    wm(c, 64ULL*1024*1024 + 5, c5, 5);

    CHK(vm(c, 0, 512), "r @0");
    CHK(vm(c, 512, 488), "hole [512,1000) zero");
    CHK(vm(c, 1000, 8), "r @1000");
    CHK(vm(c, 1008, 64ULL*1024*1024 - 4 - 1008), "hole [1008,64MB-4) zero");
    CHK(vm(c, 64ULL*1024*1024 - 4, 4), "boundary straddle");
    CHK(vm(c, 64ULL*1024*1024, 5), "zero @64MB");
    CHK(vm(c, 64ULL*1024*1024 + 5, 5), "r @64MB+5");
    CHK(vm(c, 64ULL*1024*1024 + 10, DISK_SZ - (64ULL*1024*1024 + 10)), "tail hole zero");

    cfs_close(c);
    unlink(PATH);
}

static void test_patch_and_cross(void) {
    printf("[t3] in-place patch, new blocks, cross-block write\n");
    CFS *c = mk_disk();
    CHK(c != NULL, "create");
    if (!c) return;

    uint8_t patA[64 * 1024], patB[512], patC[1024];
    for (int i = 0; i < 64 * 1024; i++) patA[i] = (uint8_t)(i ^ 0x55);
    for (int i = 0; i < 512; i++)     patB[i] = (uint8_t)(i * 3);
    for (int i = 0; i < 1024; i++)    patC[i] = (uint8_t)(i * 11);

    wm(c, 0, patA, sizeof(patA));            /* block 0: [0, 64K) */
    wm(c, 100, patB, sizeof(patB));          /* patch block 0 in place */
    CHK(vm(c, 0, 64 * 1024), "block0 patched readback");

    wm(c, 64ULL*1024*1024, patB, 512);       /* new hole block at 64MB */
    CHK(vm(c, 64ULL*1024*1024, 512), "block @64MB readback");

    wm(c, 64ULL*1024*1024 - 100, patC, 1024); /* cross: hole + block1 patch + tail hole */
    CHK(vm(c, 64ULL*1024*1024 - 100, 1024), "cross-block write readback");
    CHK(vm(c, 64ULL*1024*1024 + 924, 512), "block1 tail after cross");

    cfs_close(c);
    unlink(PATH);
}

static void test_hole_does_not_touch(void) {
    printf("[t4] hole write leaves old blocks untouched\n");
    CFS *c = mk_disk();
    CHK(c != NULL, "create");
    if (!c) return;

    uint8_t a[1024], b[64];
    for (int i = 0; i < 1024; i++) a[i] = (uint8_t)(i * 13);
    for (int i = 0; i < 64; i++)   b[i] = (uint8_t)(0xF0 + i);

    wm(c, 0, a, sizeof(a));
    wm(c, 64ULL*1024*1024 + 10, b, sizeof(b));
    CHK(vm(c, 0, 1024), "block0 unchanged");
    CHK(vm(c, 64ULL*1024*1024 + 10, 64), "block1 written");

    cfs_close(c);
    unlink(PATH);
}

static void test_out_of_order_holes(void) {
    printf("[t5] out-of-order hole blocks (sorting)\n");
    CFS *c = mk_disk();
    CHK(c != NULL, "create");
    if (!c) return;

    uint8_t hi[1024], lo[1024];
    for (int i = 0; i < 1024; i++) hi[i] = (uint8_t)(0x10 + i);
    for (int i = 0; i < 1024; i++) lo[i] = (uint8_t)(0x80 + i);

    wm(c, 100ULL*1024*1024, hi, sizeof(hi));   /* first block at 100MB */
    wm(c, 50ULL*1024*1024,  lo, sizeof(lo));   /* hole block at 50MB — must be sorted first */
    CHK(vm(c, 50ULL*1024*1024, 1024), "50MB readback");
    CHK(vm(c, 50ULL*1024*1024 + 1024, 50ULL*1024*1024 - 1024), "hole [50MB+1K,100MB) zero");
    CHK(vm(c, 100ULL*1024*1024, 1024), "100MB readback");

    /* middle-of-file hole: two blocks at 0 and 100MB, write into [64MB, 64MB+1K) */
    wm(c, 64ULL*1024*1024, lo, 512);
    CHK(vm(c, 64ULL*1024*1024, 512), "middle hole block readback");
    CHK(vm(c, 64ULL*1024*1024 + 512, 100ULL*1024*1024 - (64ULL*1024*1024 + 512)), "gap after middle block zero");

    /* persistence: reopen and re-verify a few regions */
    cfs_close(c);
    c = cfs_open(PATH, CFS_RDONLY);
    CHK(c != NULL, "reopen");
    if (c) {
        CHK(vm(c, 0, 1024), "persist: block0");
        CHK(vm(c, 50ULL*1024*1024, 1024), "persist: 50MB");
        CHK(vm(c, 64ULL*1024*1024, 512), "persist: 64MB");
        CHK(vm(c, 100ULL*1024*1024, 1024), "persist: 100MB");
        cfs_close(c);
    }
    unlink(PATH);
}

/* ── Test 6: RAW mode ── */
static void test_raw_mode(void) {
    printf("[t6] RAW mode block writes\n");
    unlink(PATH);
    CFS *c = cfs_create(PATH);
    CHK(c != NULL, "create");
    if (!c) return;
    CHK(cfs_block_resize(c, DISK_SZ) == 0, "resize");
    cfs_close(c);

    c = cfs_open(PATH, CFS_RDWR | CFS_RAW);
    CHK(c != NULL, "open RAW");
    if (!c) return;
    uint8_t d[4096];
    for (int i = 0; i < 4096; i++) d[i] = (uint8_t)(i * 3);
    CHK(cfs_block_write(c, d, 4096, 0) == 0, "write 4K @0");
    CHK(cfs_block_write(c, d, 512, 64ULL*1024*1024 + 8) == 0, "write @64MB+8");
    uint8_t r[512];
    CHK(cfs_block_read(c, r, 512, 64ULL*1024*1024 + 8) == 512 && !memcmp(r, d, 512), "RAW readback");
    CHK(cfs_block_read(c, r, 16, 0) == 16 && !memcmp(r, d, 16), "RAW readback @0");
    cfs_close(c);
    unlink(PATH);
}

#include "../libcpool/cpenc.h"

/* CPEnc regression guards for the three bugs found during block-layer work:
 * LUT batch-decode bit drift, freq256 tail clobber (n%4 != 0), and
 * length-limited huffman on highly skewed distributions. */
static void test_cpenc_diag(void) {
    printf("[t0] cpenc regression\n");
    uint8_t a[64 * 1024], ap[64 * 1024], b[512];
    for (int i = 0; i < 64 * 1024; i++) a[i] = (uint8_t)(i ^ 0x55);
    memcpy(ap, a, sizeof(a));
    for (int i = 0; i < 512; i++) b[i] = (uint8_t)(i * 3);
    memcpy(ap + 100, b, 512);   /* patched variant */
    size_t mc = cpenc_max_compressed_size(sizeof(a));
    uint8_t *c = malloc(mc), *out = malloc(sizeof(a));
    size_t cl = mc, dl = sizeof(a);
    int rc = cpenc_compress(a, sizeof(a), c, &cl, 2);
    int rc2 = rc ? -9 : cpenc_decompress(c, cl, out, &dl);
    CHK(rc == 0 && rc2 == 0 && dl == sizeof(a) && !memcmp(out, a, sizeof(a)),
        "cpenc 64K raw roundtrip (stride-8 LUT groups)");
    cl = mc; dl = sizeof(a);
    rc = cpenc_compress(ap, sizeof(ap), c, &cl, 2);
    rc2 = rc ? -9 : cpenc_decompress(c, cl, out, &dl);
    CHK(rc == 0 && rc2 == 0 && dl == sizeof(a) && !memcmp(out, ap, sizeof(ap)),
        "cpenc 64K patched roundtrip");
    free(c); free(out);

    /* 64MB zero-pad + 64B tail: freq256 tail (n%4 == 2) + huffman skew */
    {
        size_t plen = 67107850, sz = plen + 64;
        uint8_t *big = malloc(sz), *bigout = malloc(sz);
        memset(big, 0, plen);
        for (int i = 0; i < 64; i++) big[plen + i] = (uint8_t)(0xF0 + i);
        size_t mc2 = cpenc_max_compressed_size(sz);
        uint8_t *c2 = malloc(mc2);
        size_t cl2 = mc2, dl2 = sz;
        rc = cpenc_compress(big, sz, c2, &cl2, 2);
        rc2 = rc ? -9 : cpenc_decompress(c2, cl2, bigout, &dl2);
        CHK(rc == 0 && rc2 == 0 && dl2 == sz && !memcmp(bigout, big, sz),
            "cpenc 64MB pad+tail roundtrip");
        free(big); free(bigout); free(c2);
    }
}

int main(void) {
    test_cpenc_diag();
    test_shrink_regression();
    test_sparse_writes();
    test_patch_and_cross();
    test_hole_does_not_touch();
    test_out_of_order_holes();
    test_raw_mode();
    printf("\n=== %d failures ===\n", failed);
    return failed ? 1 : 0;
}
