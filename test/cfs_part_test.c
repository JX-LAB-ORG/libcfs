#include "../cfs.h"
#include "../cfs_part.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failed = 0;
#define CHK(c,m) do{if(!(c)){failed++;fprintf(stderr,"  FAIL: %s\n",m);}else{fprintf(stderr,"  OK %s\n",m);}}while(0)

#define PATH "/tmp/test_parts.cfs"
#define DISK_SZ (64ULL * 1024 * 1024)

static CFS *mk_disk(void) {
    unlink(PATH);
    CFS *c = cfs_create(PATH);
    if (!c) return NULL;
    if (cfs_block_resize(c, DISK_SZ) != 0) { cfs_close(c); return NULL; }
    return c;
}

/* raw byte helpers to inspect the table on disk */
static uint8_t *raw_lba0(CFS *c) {
    static uint8_t buf[512];
    ssize_t n = cfs_block_read(c, buf, 512, 0);
    return n == 512 ? buf : NULL;
}

static void test_mbr_roundtrip(void) {
    printf("[p1] MBR label/add/get/raw bytes\n");
    CFS *c = mk_disk();
    CHK(c != NULL, "create");
    if (!c) return;

    CHK(cfs_part_count(c) == 0, "bare disk: count 0");
    CHK(cfs_part_label(c, CFS_PART_MBR) == 0, "label mbr");
    CHK(cfs_part_count(c) == 0, "empty mbr: count 0");

    int rc = cfs_part_add(c, 1ULL << 20, 1ULL << 20, 0x83, NULL, 1);  /* 1MB..2MB, linux, boot */
    CHK(rc == 1, "partadd -> index 1");
    CHK(cfs_part_count(c) == 1, "count 1");

    CfsPartition p;
    CHK(cfs_part_get(c, 1, &p) == 0, "get 1");
    CHK(p.start == (1ULL << 20) && p.size == (1ULL << 20), "start/size");
    CHK(p.mbr_type == 0x83 && p.bootable == 1, "type/boot");

    uint8_t *l0 = raw_lba0(c);
    CHK(l0 != NULL, "raw read");
    if (l0) {
        CHK(l0[510] == 0x55 && l0[511] == 0xAA, "MBR signature");
        const uint8_t *e = l0 + 446;
        CHK(e[0] == 0x80, "boot flag byte");
        CHK(e[4] == 0x83, "type byte");
        CHK(e[8] == 0x00 && e[9] == 0x08 && e[10] == 0x00 && e[11] == 0x00, "start_lba=2048");
        CHK(e[12] == 0x00 && e[13] == 0x08 && e[14] == 0x00 && e[15] == 0x00, "sectors=2048");
    }
    cfs_close(c);
    unlink(PATH);
}

static void test_rejections(void) {
    printf("[p2] validation rejections\n");
    CFS *c = mk_disk();
    CHK(c != NULL, "create");
    if (!c) return;
    cfs_part_label(c, CFS_PART_MBR);

    CHK(cfs_part_add(c, 1000, 4096, 0x83, NULL, 0) < 0, "misaligned start");
    CHK(cfs_part_add(c, 4096, 1000, 0x83, NULL, 0) < 0, "misaligned size");
    CHK(cfs_part_add(c, DISK_SZ, 4096, 0x83, NULL, 0) < 0, "out of disk");
    CHK(cfs_part_add(c, 0, 4096, 0x83, NULL, 0) == 1, "first at 0");
    CHK(cfs_part_add(c, 2048, 4096, 0x83, NULL, 0) < 0, "overlap");
    CHK(cfs_part_add(c, 8192, 4096, 0x83, NULL, 0) == 2, "second ok");
    CHK(cfs_part_add(c, 12288, 4096, 0x83, NULL, 0) == 3, "third ok");
    CHK(cfs_part_add(c, 16384, 4096, 0x83, NULL, 0) == 4, "fourth ok");
    CHK(cfs_part_add(c, 20480, 4096, 0x83, NULL, 0) < 0, "fifth rejected (MBR 4 max)");
    cfs_close(c);
    unlink(PATH);
}

static void test_del_shift(void) {
    printf("[p3] MBR partdel shifts numbers\n");
    CFS *c = mk_disk();
    CHK(c != NULL, "create");
    if (!c) return;
    cfs_part_label(c, CFS_PART_MBR);
    cfs_part_add(c, 4096, 4096, 0x83, NULL, 0);
    cfs_part_add(c, 8192, 4096, 0x0C, NULL, 0);
    cfs_part_add(c, 12288, 4096, 0x83, NULL, 0);

    CHK(cfs_part_del(c, 2) == 0, "del 2");
    CfsPartition p;
    CHK(cfs_part_get(c, 2, &p) == 0 && p.mbr_type == 0x83 && p.start == 12288, "old 3 shifted to 2");
    CHK(cfs_part_get(c, 3, &p) != 0, "no 3 anymore");
    CHK(cfs_part_count(c) == 2, "count 2");
    cfs_close(c);
    unlink(PATH);
}

static void test_gpt_roundtrip(void) {
    printf("[p4] GPT label/add/5 parts/roundtrip\n");
    CFS *c = mk_disk();
    CHK(c != NULL, "create");
    if (!c) return;

    CHK(cfs_part_label(c, CFS_PART_GPT) == 0, "label gpt");
    CHK(cfs_part_count(c) == 0, "empty gpt");

    uint8_t *l0 = raw_lba0(c);
    CHK(l0 != NULL, "raw read");
    if (l0) {
        CHK(l0[510] == 0x55 && l0[511] == 0xAA, "protective MBR signature");
        CHK(l0[446 + 4] == 0xEE, "protective MBR type 0xEE");
    }
    /* LBA1 header needs a 1024B read */
    uint8_t hdr[1024];
    CHK(cfs_block_read(c, hdr, 1024, 0) == 1024, "read LBA0-1");
    CHK(!memcmp(hdr + 512, "EFI PART", 8), "GPT header sig");
    CHK(hdr[512 + 8] == 0x00 && hdr[512 + 9] == 0x00 && hdr[512 + 10] == 0x01 && hdr[512 + 11] == 0x00, "rev 1.0");
    CHK(hdr[512 + 24] == 1, "cur_lba=1");

    int ok5 = 1;
    for (int i = 1; i <= 5; i++) {
        uint64_t start = (uint64_t)i * (1ULL << 20);
        if (cfs_part_add(c, start, 1ULL << 20, 0x83, NULL, 0) != i) ok5 = 0;
    }
    CHK(ok5, "gpt partadd 1..5");
    CHK(cfs_part_count(c) == 5, "count 5");
    cfs_close(c);

    /* reopen: reparse from disk */
    c = cfs_open(PATH, CFS_RDONLY);
    CHK(c != NULL, "reopen");
    if (c) {
        CHK(cfs_part_count(c) == 5, "reparse count 5");
        CfsPartition p;
        CHK(cfs_part_get(c, 3, &p) == 0 && p.start == (3ULL << 20), "reopen part 3");
        CHK(p.is_gpt == 1, "is_gpt");
        CHK(!strcmp(p.type_str, "linux"), "type linux");
        CHK(strlen(p.guid) == 36, "guid text");
        cfs_close(c);
    }
    unlink(PATH);
}

static void test_gpt_del_stable(void) {
    printf("[p5] GPT partdel keeps numbering\n");
    CFS *c = mk_disk();
    CHK(c != NULL, "create");
    if (!c) return;
    cfs_part_label(c, CFS_PART_GPT);
    for (int i = 1; i <= 4; i++)
        cfs_part_add(c, (uint64_t)i * (1ULL << 20), 1ULL << 20, 0x83, NULL, 0);

    CHK(cfs_part_del(c, 2) == 0, "del 2");
    CfsPartition p;
    CHK(cfs_part_get(c, 3, &p) == 0 && p.start == (3ULL << 20), "part 3 still numbered 3");
    CHK(cfs_part_get(c, 2, &p) != 0, "no 2");
    CHK(cfs_part_count(c) == 3, "count 3");
    cfs_close(c);
    unlink(PATH);
}

static void test_cache_invalidation(void) {
    printf("[p6] raw block write into table region invalidates cache\n");
    CFS *c = mk_disk();
    CHK(c != NULL, "create");
    if (!c) return;
    cfs_part_label(c, CFS_PART_MBR);
    cfs_part_add(c, 4096, 4096, 0x83, NULL, 0);
    CHK(cfs_part_count(c) == 1, "cached count 1");

    /* scribble zeros over the MBR */
    uint8_t z[512]; memset(z, 0, sizeof(z));
    CHK(cfs_block_write(c, z, 512, 0) == 0, "raw write LBA0");
    CHK(cfs_part_count(c) == 0, "count 0 after table destroyed");
    cfs_close(c);
    unlink(PATH);
}

static void test_part_io(void) {
    printf("[p7] partition-relative read/write\n");
    CFS *c = mk_disk();
    CHK(c != NULL, "create");
    if (!c) return;
    cfs_part_label(c, CFS_PART_MBR);
    cfs_part_add(c, 1ULL << 20, 1ULL << 20, 0x83, NULL, 0);

    uint8_t d[4096];
    for (int i = 0; i < 4096; i++) d[i] = (uint8_t)(i * 7);
    CHK(cfs_part_write(c, 1, d, 4096, 0) == 0, "part write @0");
    CHK(cfs_part_write(c, 1, d, 100, 4096 - 100) == 0, "part write tail");
    CHK(cfs_part_write(c, 1, d, 512, (1 << 20) - 511) < 0, "past partition end rejected");

    /* direct: verify absolute offsets in @block */
    uint8_t ab[4096];
    CHK(cfs_block_read(c, ab, 4096, 1ULL << 20) == 4096 && !memcmp(ab, d, 100), "abs offset == part data");
    CHK(cfs_block_read(c, ab, 8, 1ULL << 20) == 8 && !memcmp(ab, d, 8), "abs read head");
    cfs_close(c);
    unlink(PATH);
}

static void test_no_table(void) {
    printf("[p8] bare disk behavior\n");
    CFS *c = mk_disk();
    CHK(c != NULL, "create");
    if (!c) return;
    CHK(cfs_part_add(c, 4096, 4096, 0x83, NULL, 0) == -2, "partadd without table -> -2");
    CHK(cfs_part_del(c, 1) == -2, "partdel without table -> -2");
    CHK(cfs_part_read(c, 1, NULL, 0, 0) == -1, "partread without table -> -1");
    cfs_close(c);
    unlink(PATH);
}

static void test_mkfs_partitioned(void) {
    printf("[p9] mkfs ext4/fat32 into partition 1\n");
    CFS *c = mk_disk();
    CHK(c != NULL, "create");
    if (!c) return;
    cfs_part_label(c, CFS_PART_MBR);
    CHK(cfs_part_add(c, 1ULL << 20, DISK_SZ - (1ULL << 20), 0x83, NULL, 0) == 1, "partadd");
    CHK(cfs_mkfs_ext4_at(c, 1ULL << 20, DISK_SZ - (1ULL << 20)) == 0, "mkfs ext4 in part");

    uint8_t sb[2];
    /* ext4 superblock lives at partition+1024, s_magic at offset 56 within it */
    CHK(cfs_block_read(c, sb, 2, (1ULL << 20) + 1024 + 56) == 2 && sb[0] == 0x53 && sb[1] == 0xEF, "ext4 magic @part+1024+56");
    cfs_close(c);
    unlink(PATH);

    c = mk_disk();
    CHK(c != NULL, "create 2");
    if (c) {
        cfs_part_label(c, CFS_PART_MBR);
        cfs_part_add(c, 1ULL << 20, DISK_SZ - (1ULL << 20), 0x0C, NULL, 0);
        CHK(cfs_mkfs_fat32_at(c, 1ULL << 20, DISK_SZ - (1ULL << 20)) == 0, "mkfs fat32 in part");
        uint8_t b[2];
        CHK(cfs_block_read(c, b, 2, (1ULL << 20) + 510) == 2 && b[0] == 0x55 && b[1] == 0xAA, "FAT32 boot sig @part+510");
        cfs_close(c);
    }
    unlink(PATH);
}

static void test_crc32(void) {
    printf("[p10] crc32 known vector\n");
    /* exercised through GPT: a bad crc must yield NONE, a good one parses */
    CFS *c = mk_disk();
    CHK(c != NULL, "create");
    if (!c) return;
    cfs_part_label(c, CFS_PART_GPT);
    cfs_part_add(c, 1ULL << 20, 1ULL << 20, 0x83, NULL, 0);
    CHK(cfs_part_count(c) == 1, "valid gpt parses");

    /* corrupt the header CRC */
    uint8_t h[1024];
    cfs_block_read(c, h, 1024, 0);
    h[512 + 16] ^= 0xFF;   /* hdr_crc byte */
    CHK(cfs_block_write(c, h, 1024, 0) == 0, "corrupt header crc");
    CHK(cfs_part_count(c) == 0, "corrupt gpt -> none");
    cfs_close(c);
    unlink(PATH);
}

int main(void) {
    test_mbr_roundtrip();
    test_rejections();
    test_del_shift();
    test_gpt_roundtrip();
    test_gpt_del_stable();
    test_cache_invalidation();
    test_part_io();
    test_no_table();
    test_mkfs_partitioned();
    test_crc32();
    printf("\n=== %d failures ===\n", failed);
    return failed ? 1 : 0;
}
