/* cfs_part_fix_test.c — regressions for the partition-layer defects.
 *
 * One test per independently verified fix:
 *   f1 block hook clamps every I/O to the partition size
 *   f2 a partition may not cover the partition table (MBR LBA0, GPT both ends)
 *   f3 MBR start/size must fit the 32-bit sector fields
 *   f4 GPT parser rejects an entry array larger than the bytes it read
 *   f5 GPT part_save keeps one complete table at every step and rolls back
 *   f6 parttype by name works on GPT
 *   f7 mkfs/install -p N honours N and caps GPT at the last usable LBA
 *   f8 EOF/zero-length part reads, 1MiB alignment warning, add overflow
 *
 * The block-hook test re-executes this binary with LD_PRELOAD set: the child
 * only opens /dev/vda1 and prints the syscall results, the parent checks that
 * the neighbouring partition was not touched.
 */
#define _GNU_SOURCE
#include "../cfs.h"
#include "../cfs_part.h"
#include "iso_mk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/fs.h>
#include <sys/ioctl.h>

/* Also compiled against the pre-fix header when checking that these tests
 * fail on a pristine tree. */
#ifndef MBR_FIRST_USABLE
#define MBR_FIRST_USABLE 2048
#endif
#ifndef GPT_LAST_USABLE_RESERVE
#define GPT_LAST_USABLE_RESERVE 34
#endif

static int failed = 0;
#define CHECK(cond, ...) do { if (!(cond)) { failed++; \
    fprintf(stderr, "  FAIL: " __VA_ARGS__); fputc('\n', stderr); } \
    else fprintf(stderr, "  OK\n"); } while (0)

#define DISK_SZ (64ULL * 1024 * 1024)
static char path[512];
static char tool[1024];

static void set_paths(const char *argv0) {
    const char *tmp = getenv("TMPDIR");
    snprintf(path, sizeof(path), "%s/cfs_part_fix.cfs", tmp && *tmp ? tmp : "/tmp");
    const char *s = strrchr(argv0, '/');
    if (!s) snprintf(tool, sizeof(tool), "./cfs-tool");
    else snprintf(tool, sizeof(tool), "%.*s/../cfs-tool", (int)(s - argv0), argv0);
}

static CFS *mk_disk(uint64_t sz) {
    unlink(path);
    CFS *c = cfs_create(path);
    if (!c) return NULL;
    if (cfs_block_resize(c, sz) != 0) { cfs_close(c); return NULL; }
    return c;
}

/* ── CRC32 (same polynomial the GPT code uses) ─────────────────── */
static uint32_t crc32_calc(const void *data, size_t n) {
    uint32_t tab[256];
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t v = i;
        for (int b = 0; b < 8; b++) v = (v & 1) ? (v >> 1) ^ 0xEDB88320u : v >> 1;
        tab[i] = v;
    }
    const uint8_t *p = data;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) crc = (crc >> 8) ^ tab[(crc ^ p[i]) & 0xFF];
    return crc ^ 0xFFFFFFFFu;
}

static uint32_t le32r(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ── child mode for the block-hook test ────────────────────────── */
static int hook_child(void) {
    int fd = open("/dev/vda1", O_RDWR);
    if (fd < 0) { printf("open-fail\n"); return 0; }
    struct stat st;
    if (fstat(fd, &st) != 0) { printf("stat-fail\n"); return 0; }
    uint64_t psize = (uint64_t)st.st_size;

    uint8_t a[512], b[512];
    memset(a, 0xAA, sizeof(a));
    memset(b, 0xBB, sizeof(b));

    ssize_t w_end = pwrite(fd, a, sizeof(a), (off_t)psize);          /* at EOF */
    uint8_t r1[512];
    memset(r1, 0x11, sizeof(r1));
    ssize_t r_end = pread(fd, r1, sizeof(r1), (off_t)psize);         /* at EOF */
    uint8_t r2[1024];
    memset(r2, 0x22, sizeof(r2));
    ssize_t r_cross = pread(fd, r2, sizeof(r2), (off_t)(psize - 512));
    ssize_t w_cross = pwrite(fd, b, sizeof(b), (off_t)(psize - 256));

    printf("w_end=%zd r_end=%zd r_cross=%zd w_cross=%zd r1=%02x r2a=%02x r2b=%02x\n",
           w_end, r_end, r_cross, w_cross, r1[0], r2[0], r2[512]);
    close(fd);
    return 0;
}

/* ── f1: block-hook partition boundary ─────────────────────────── */
static void test_hook_clamp(const char *argv0) {
    printf("[f1] block hook clamps I/O to the partition size\n");
    CFS *c = mk_disk(DISK_SZ);
    CHECK(c != NULL, "create");
    if (!c) return;

    CHECK(cfs_part_label(c, CFS_PART_MBR) == 0, "label mbr");
    CHECK(cfs_part_add(c, 1ULL << 20, 8ULL << 20, MBR_TYPE_LINUX, NULL, 0) == 1, "add p1 (1MiB..9MiB)");
    CHECK(cfs_part_add(c, 9ULL << 20, 8ULL << 20, MBR_TYPE_LINUX, NULL, 0) == 2, "add p2 (9MiB..17MiB)");

    uint8_t marker = 0xA7;
    CHECK(cfs_block_write(c, &marker, 1, (off_t)(9ULL << 20)) == 0, "p2 marker");
    cfs_close(c);   /* the hook must be able to take the container lock */

    int pipefd[2];
    if (pipe(pipefd) != 0) { CHECK(0, "pipe"); return; }
    pid_t pid = fork();
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], 1);
        close(pipefd[1]);
        char hook[1024];
        snprintf(hook, sizeof(hook), "%s", tool);
        char *slash = strrchr(hook, '/');
        if (slash) strcpy(slash + 1, "cfs_block_hook.so");
        else strcpy(hook, "./cfs_block_hook.so");
        setenv("LD_PRELOAD", hook, 1);
        /* Under ASan the executable links libasan, but LD_PRELOAD would put
         * the hook first in the library list and the runtime refuses to run.
         * The hook is instrumented with the same runtime, so this is safe. */
        const char *ao = getenv("ASAN_OPTIONS");
        char aobuf[1024];
        snprintf(aobuf, sizeof(aobuf), "%s%sverify_asan_link_order=0",
                 ao && *ao ? ao : "", ao && *ao ? ":" : "");
        setenv("ASAN_OPTIONS", aobuf, 1);
        setenv("CFS_BLOCK_DEV", "/dev/vda", 1);
        setenv("CFS_BLOCK_FILE", path, 1);
        setenv("CFS_BLOCK_PARTS", "1", 1);
        execl("/proc/self/exe", argv0, "--hook-child", (char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);
    char out[512] = {0};
    ssize_t n = read(pipefd[0], out, sizeof(out) - 1);
    close(pipefd[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    if (n <= 0) out[0] = 0;

    long w_end = -99, r_end = -99, r_cross = -99, w_cross = -99;
    unsigned r1 = 0, r2a = 0, r2b = 0;
    sscanf(out, "w_end=%ld r_end=%ld r_cross=%ld w_cross=%ld r1=%x r2a=%x r2b=%x",
           &w_end, &r_end, &r_cross, &w_cross, &r1, &r2a, &r2b);
    fprintf(stderr, "  child: %s", out[0] ? out : "(no output)\n");

    CHECK(w_end == 0, "pwrite at psize: short write of 0 (got %ld)", w_end);
    CHECK(r_end == 0, "pread at psize: 0 bytes (got %ld)", r_end);
    CHECK(r_cross == 512, "pread crossing the end is short: 512 (got %ld)", r_cross);
    CHECK(w_cross == 256, "pwrite crossing the end is short: 256 (got %ld)", w_cross);
    CHECK(r1 == 0x11, "the EOF read wrote nothing (got 0x%02x)", r1);
    CHECK(r2a == 0x00, "the crossing read returned the in-partition tail (0x%02x)", r2a);
    CHECK(r2b == 0x22, "the crossing read did not leave the partition");

    /* The neighbouring partition must be untouched. */
    c = cfs_open(path, CFS_RDONLY);
    CHECK(c != NULL, "reopen");
    if (c) {
        uint8_t b[16];
        CHECK(cfs_block_read(c, b, sizeof(b), (off_t)(9ULL << 20)) == 16, "read p2 head");
        int intact = b[0] == 0xA7;
        for (int i = 1; i < 16; i++) if (b[i] != 0) intact = 0;
        CHECK(intact, "p2 head intact (marker 0x%02x)", b[0]);
        cfs_close(c);
    }
    unlink(path);
}

/* ── f2: a partition must not cover the partition table ────────── */
static void test_table_coverage(void) {
    printf("[f2] partitions cannot cover the partition table\n");

    /* MBR: LBA0 is the table; the first usable LBA is 2048. */
    CFS *c = mk_disk(DISK_SZ);
    CHECK(c != NULL, "create");
    if (!c) return;
    CHECK(cfs_part_label(c, CFS_PART_MBR) == 0, "label mbr");
    CHECK(cfs_part_add(c, 0, 1ULL << 20, MBR_TYPE_LINUX, NULL, 0) < 0, "MBR at LBA0 rejected");
    CHECK(cfs_part_add(c, 512, 1ULL << 20, MBR_TYPE_LINUX, NULL, 0) < 0, "MBR at LBA1 rejected");
    CHECK(cfs_part_add(c, (1ULL << 20) - 512, 1ULL << 20, MBR_TYPE_LINUX, NULL, 0) < 0,
          "MBR straddling LBA0..2047 rejected");
    CHECK(cfs_part_add(c, 1ULL << 20, 1ULL << 20, MBR_TYPE_LINUX, NULL, 0) == 1, "MBR at 1MiB ok");
    uint8_t sig[2];
    CHECK(cfs_block_read(c, sig, 2, 510) == 2 && sig[0] == 0x55 && sig[1] == 0xAA,
          "MBR signature still there");
    cfs_close(c);
    unlink(path);

    /* GPT: LBA0-33 at the front, backup entries/header in the last 33. */
    c = mk_disk(DISK_SZ);
    CHECK(c != NULL, "create");
    if (!c) return;
    CHECK(cfs_part_label(c, CFS_PART_GPT) == 0, "label gpt");
    CHECK(cfs_part_add(c, 0, 1ULL << 20, MBR_TYPE_LINUX, NULL, 0) < 0, "GPT at LBA0 rejected");
    CHECK(cfs_part_add(c, 33 * 512, 1ULL << 20, MBR_TYPE_LINUX, NULL, 0) < 0, "GPT before LBA34 rejected");

    uint64_t disk_sectors = DISK_SZ / 512;
    uint64_t last_usable = disk_sectors - GPT_LAST_USABLE_RESERVE;
    CHECK(cfs_part_add(c, (last_usable + 1) * 512, 512, MBR_TYPE_LINUX, NULL, 0) < 0,
          "GPT starting past the last usable LBA rejected");
    CHECK(cfs_part_add(c, 1ULL << 20, (last_usable - 2048 + 2) * 512, MBR_TYPE_LINUX, NULL, 0) < 0,
          "GPT ending in the backup table rejected");
    CHECK(cfs_part_add(c, 1ULL << 20, (last_usable - 2048 + 1) * 512, MBR_TYPE_LINUX, NULL, 0) == 1,
          "GPT through the last usable LBA ok");

    /* Writing to a valid partition must not erase the table. */
    uint8_t z[512];
    memset(z, 0x5A, sizeof(z));
    CHECK(cfs_part_write(c, 1, z, sizeof(z), 0) == 0, "write into the valid partition");
    CHECK(cfs_part_count(c) == 1, "table still parses after a partition write");
    cfs_close(c);
    unlink(path);
}

/* ── f3: MBR 32-bit sector fields are not silently truncated ───── */
static void test_mbr_32bit(void) {
    printf("[f3] MBR rejects values outside the 32-bit sector fields\n");
    const uint64_t BIG = 4ULL * 1024 * 1024 * 1024 * 1024;   /* 4TiB sparse */
    CFS *c = mk_disk(BIG);
    CHECK(c != NULL, "create 4TiB sparse disk");
    if (!c) return;
    CHECK(cfs_block_size(c) == BIG, "size is 4TiB");
    CHECK(cfs_part_label(c, CFS_PART_MBR) == 0, "label mbr");

    /* start LBA 2^32 used to truncate to LBA 0 on the way back in */
    uint64_t start = (1ULL << 32) * 512;
    CHECK(cfs_part_add(c, start, 1ULL << 20, MBR_TYPE_LINUX, NULL, 0) < 0, "start LBA 2^32 rejected");
    /* 2^32 sectors used to truncate to a zero-length partition */
    CHECK(cfs_part_add(c, 1ULL << 20, (1ULL << 32) * 512, MBR_TYPE_LINUX, NULL, 0) < 0,
          "size of 2^32 sectors rejected");
    /* a partition that fits is still accepted and reads back exactly */
    CHECK(cfs_part_add(c, 1ULL << 20, 1ULL << 20, MBR_TYPE_LINUX, NULL, 0) == 1, "32-bit-range partition ok");
    CfsPartition p;
    CHECK(cfs_part_get(c, 1, &p) == 0 && p.start == (1ULL << 20) && p.size == (1ULL << 20),
          "round-trip start/size");
    CHECK(cfs_part_count(c) == 1, "count 1");
    cfs_close(c);
    unlink(path);
}

/* ── f4: GPT entry array bound ─────────────────────────────────── */
static void test_gpt_entry_size(void) {
    printf("[f4] GPT parser rejects an oversized entry array\n");
    CFS *c = mk_disk(DISK_SZ);
    CHECK(c != NULL, "create");
    if (!c) return;
    CHECK(cfs_part_label(c, CFS_PART_GPT) == 0, "label gpt");
    CHECK(cfs_part_add(c, 1ULL << 20, 1ULL << 20, MBR_TYPE_LINUX, NULL, 0) == 1, "add part");
    CHECK(cfs_part_count(c) == 1, "valid gpt parses");

    uint8_t tbl[GPT_TABLE_BYTES];
    CHECK(cfs_block_read(c, tbl, sizeof(tbl), 0) == (ssize_t)sizeof(tbl), "read LBA0-33");
    /* entry_size 256 with the full 128 entries claims 32KiB from a 16KiB
     * buffer.  The entry CRC is (and was) over the 16KiB that is present, so
     * the header still validates and the old parser walked off the heap. */
    uint8_t *hdr = tbl + 512;
    hdr[84] = 0x00; hdr[85] = 0x01; hdr[86] = 0; hdr[87] = 0;   /* entry_size = 256 */
    hdr[16] = hdr[17] = hdr[18] = hdr[19] = 0;                  /* zero hdr_crc */
    uint32_t crc = crc32_calc(hdr, 92);
    hdr[16] = (uint8_t)crc; hdr[17] = (uint8_t)(crc >> 8);
    hdr[18] = (uint8_t)(crc >> 16); hdr[19] = (uint8_t)(crc >> 24);
    CHECK(cfs_block_write(c, tbl, sizeof(tbl), 0) == 0, "write patched table");

    CHECK(cfs_part_count(c) == 0, "oversized entry array rejected (count 0)");
    cfs_close(c);
    unlink(path);
}

/* ── helpers for the backup GPT ────────────────────────────────── */
static int gpt_backup_valid(CFS *c) {
    uint64_t disk = cfs_block_size(c);
    uint64_t sectors = disk / 512;
    if (sectors < GPT_MIN_DISK_SECT) return 0;
    uint64_t blba = sectors - 1;
    uint8_t h[512];
    if (cfs_block_read(c, h, sizeof(h), (off_t)(blba * 512)) != (ssize_t)sizeof(h)) return 0;
    if (memcmp(h, GPT_HEADER_SIG, 8) != 0) return 0;
    uint32_t hsz = le32r(h + 12);
    if (hsz < 92 || hsz > 512) return 0;
    uint32_t stored = le32r(h + 16);
    h[16] = h[17] = h[18] = h[19] = 0;
    if (crc32_calc(h, hsz) != stored) return 0;
    uint64_t elba = le32r(h + 72) | ((uint64_t)le32r(h + 76) << 32);
    uint32_t num = le32r(h + 80), esz = le32r(h + 84);
    if (esz < GPT_ENTRY_SIZE || esz % GPT_ENTRY_SIZE) return 0;
    if (num > GPT_ENTRIES_MAX || (uint64_t)num * esz > GPT_ENTRIES_BYTES) return 0;
    if (elba != blba - GPT_ENTRIES_BYTES / 512) return 0;
    uint8_t *e = malloc((size_t)num * esz);
    if (!e) return 0;
    int ok = cfs_block_read(c, e, (size_t)num * esz, (off_t)(elba * 512)) == (ssize_t)((size_t)num * esz);
    if (ok && crc32_calc(e, (size_t)num * esz) != le32r(h + 88)) ok = 0;
    free(e);
    return ok;
}

/* ── f5: GPT part_save atomicity under a physical quota ────────── */
static CFS *mk_gpt_one(void) {
    CFS *c = mk_disk(8ULL << 20);
    if (!c) return NULL;
    if (cfs_part_label(c, CFS_PART_GPT) != 0) { cfs_close(c); return NULL; }
    if (cfs_part_add(c, 1ULL << 20, 1ULL << 20, MBR_TYPE_LINUX, NULL, 0) != 1) {
        cfs_close(c); return NULL;
    }
    return c;
}

static void test_gpt_quota_atomicity(void) {
    printf("[f5] failed GPT partadd leaves the old table whole\n");
    int saw_failure = 0;
    static const uint64_t deltas[] = {
        0, 256, 512, 1024, 2048, 4096, 8192, 12288, 16384, 24576,
        32768, 49152, 65536, 98304, 131072, 196608, 262144, 524288
    };
    for (size_t i = 0; i < sizeof(deltas) / sizeof(deltas[0]); i++) {
        CFS *c = mk_gpt_one();
        if (!c) { CHECK(0, "quota case %zu: setup", i); return; }
        uint64_t used = cfs_physical_used(c);
        cfs_set_physical_limit(c, used + deltas[i]);
        int rc = cfs_part_add(c, 3ULL << 20, 1ULL << 20, MBR_TYPE_LINUX, NULL, 0);
        cfs_close(c);

        c = cfs_open(path, CFS_RDONLY);
        if (!c) { CHECK(0, "quota case %zu: reopen", i); continue; }
        int n = cfs_part_count(c);
        CfsPartition p;
        int p1_ok = cfs_part_get(c, 1, &p) == 0 && p.start == (1ULL << 20) && p.size == (1ULL << 20);
        int primary_ok = (n == 1 && p1_ok) ||
                         (n == 2 && p1_ok && cfs_part_get(c, 2, &p) == 0 && p.start == (3ULL << 20));
        int backup_ok = gpt_backup_valid(c);
        if (rc < 0) saw_failure = 1;
        if (!(primary_ok && (rc >= 0 ? n == 2 : n == 1) && backup_ok))
            fprintf(stderr, "  case %zu delta=%llu rc=%d n=%d backup=%d\n",
                    i, (unsigned long long)deltas[i], rc, n, backup_ok);
        CHECK(primary_ok, "quota case %zu: primary table is old-or-new (rc=%d n=%d)", i, rc, n);
        CHECK(rc >= 0 ? n == 2 : n == 1, "quota case %zu: count matches the result (rc=%d n=%d)", i, rc, n);
        CHECK(backup_ok, "quota case %zu: backup GPT self-consistent", i);
        cfs_close(c);
        unlink(path);
    }
    CHECK(saw_failure, "the sweep actually hit the quota at least once");
}

/* ── f6: parttype by name on GPT ───────────────────────────────── */
static void test_parttype_gpt_name(void) {
    printf("[f6] parttype by name changes a GPT partition\n");
    CFS *c = mk_disk(DISK_SZ);
    CHECK(c != NULL, "create");
    if (!c) return;
    CHECK(cfs_part_label(c, CFS_PART_GPT) == 0, "label gpt");
    CHECK(cfs_part_add(c, 1ULL << 20, 1ULL << 20, MBR_TYPE_LINUX, NULL, 0) == 1, "add linux part");

    CfsPartition p;
    CHECK(cfs_part_get(c, 1, &p) == 0 && !strcmp(p.type_str, "linux"), "starts linux");

    CHECK(cfs_part_type(c, 1, MBR_TYPE_EFI, NULL, -1) == 0, "parttype efi by name");
    CHECK(cfs_part_get(c, 1, &p) == 0 && !strcmp(p.type_str, "efi"), "type_str is efi");
    char efi_guid[37];
    {   /* the EFI system partition GUID, in text form */
        static const uint8_t g[16] = {0x28,0x73,0x2A,0xC1,0x1F,0xF8,0xD2,0x11,
                                      0xBA,0x4B,0x00,0xA0,0xC9,0x3E,0xC9,0x3B};
        snprintf(efi_guid, sizeof(efi_guid),
                 "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                 g[3],g[2],g[1],g[0],g[5],g[4],g[7],g[6],
                 g[8],g[9],g[10],g[11],g[12],g[13],g[14],g[15]);
    }
    CHECK(!strcmp(p.guid, efi_guid), "guid is the EFI system GUID (%s)", p.guid);
    cfs_close(c);

    /* the change must survive a reparse */
    c = cfs_open(path, CFS_RDONLY);
    CHECK(c != NULL && cfs_part_get(c, 1, &p) == 0 && !strcmp(p.type_str, "efi"),
          "reparsed type is efi");
    if (c) cfs_close(c);
    unlink(path);
}

/* ── subprocess helper for cfs-tool ────────────────────────────── */
static int run_tool(char *const argv[]) {
    pid_t pid = fork();
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); dup2(devnull, 2); close(devnull); }
        execv(tool, argv);
        _exit(127);
    }
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) != pid) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* ── f7: mkfs/install -p N ─────────────────────────────────────── */
static void test_mkfs_install_pn(void) {
    printf("[f7] mkfs/install -p N honours N and the GPT usable end\n");
    static char out[600];
    snprintf(out, sizeof(out), "%s.cfs", path);

    /* -p 2 creates two partitions and formats the second */
    char *mk[] = { tool, "mkfs", "ext4", "64M", out, "-p", "2", NULL };
    CHECK(run_tool(mk) == 0, "mkfs -p 2 succeeds");
    CFS *c = cfs_open(out, CFS_RDONLY);
    CHECK(c != NULL, "open mkfs -p 2 image");
    if (c) {
        CfsPartition p1, p2;
        CHECK(cfs_part_count(c) == 2, "two partitions exist (got %d)", cfs_part_count(c));
        CHECK(cfs_part_get(c, 1, &p1) == 0 && cfs_part_get(c, 2, &p2) == 0, "partitions 1 and 2");
        uint8_t sb[2];
        CHECK(cfs_block_read(c, sb, 2, (off_t)(p2.start + 1024 + 56)) == 2 &&
              sb[0] == 0x53 && sb[1] == 0xEF, "ext4 magic lives in partition 2");
        cfs_close(c);
    }
    unlink(out);

    /* -p 1 -g must stop at the last usable LBA, leaving the backup GPT. */
    char *mkg[] = { tool, "mkfs", "ext4", "64M", out, "-p", "1", "-g", NULL };
    CHECK(run_tool(mkg) == 0, "mkfs -p 1 -g succeeds");
    c = cfs_open(out, CFS_RDONLY);
    CHECK(c != NULL, "open mkfs -g image");
    if (c) {
        CfsPartition p;
        uint64_t sectors = cfs_block_size(c) / 512;
        CHECK(cfs_part_get(c, 1, &p) == 0, "gpt partition 1");
        CHECK(p.start + p.size <= (sectors - GPT_LAST_USABLE_RESERVE + 1) * 512,
              "gpt partition ends at or before the last usable LBA");
        CHECK(gpt_backup_valid(c), "backup GPT survived mkfs -g");
        cfs_close(c);
    }
    unlink(out);

    /* a partition number of zero is refused, not silently treated as "none" */
    char *mk0[] = { tool, "mkfs", "ext4", "64M", out, "-p", "0", NULL };
    CHECK(run_tool(mk0) != 0, "mkfs -p 0 refused");

    /* install -p 2 must install into partition 2 */
    uint8_t data[4096];
    for (size_t i = 0; i < sizeof(data); i++) data[i] = (uint8_t)(i * 13 + 7);
    IsoMkEntry ent[] = { { "FW.BIN", data, sizeof(data), 0 } };
    size_t isz = 0;
    uint8_t *iso = iso_mk_build(ent, 1, "CFSTEST", &isz);
    CHECK(iso != NULL && isz > 0, "build ISO");
    char isopath[600];
    snprintf(isopath, sizeof(isopath), "%s.iso", path);
    FILE *f = iso ? fopen(isopath, "wb") : NULL;
    if (f) { fwrite(iso, 1, isz, f); fclose(f); }
    free(iso);
    if (f) {
        char *inst[] = { tool, "install", isopath, "64M", out, "-p", "2", NULL };
        CHECK(run_tool(inst) == 0, "install -p 2 succeeds");
        c = cfs_open(out, CFS_RDONLY);
        CHECK(c != NULL, "open install -p 2 image");
        if (c) {
            CfsPartition p2;
            CHECK(cfs_part_count(c) == 2, "install created two partitions");
            CHECK(cfs_part_get(c, 2, &p2) == 0, "install partition 2 exists");
            uint8_t sb[2];
            CHECK(cfs_block_read(c, sb, 2, (off_t)(p2.start + 1024 + 56)) == 2 &&
                  sb[0] == 0x53 && sb[1] == 0xEF, "ext4 magic in partition 2");
            cfs_close(c);
        }
        unlink(out);
        unlink(isopath);
    }
}

/* ── f8: smaller partition-layer defects ───────────────────────── */
static int alignment_warning(CFS *c, uint64_t start, uint64_t size) {
    fflush(stderr);
    int saved = dup(2);
    FILE *tmp = tmpfile();
    if (saved < 0 || !tmp) { if (saved >= 0) close(saved); if (tmp) fclose(tmp); return -1; }
    dup2(fileno(tmp), 2);
    cfs_part_add(c, start, size, MBR_TYPE_LINUX, NULL, 0);
    fflush(stderr);
    dup2(saved, 2);
    close(saved);
    rewind(tmp);
    char line[256];
    int seen = 0;
    while (fgets(line, sizeof(line), tmp))
        if (strstr(line, "1MB-aligned")) seen = 1;
    fclose(tmp);
    return seen;
}

static void test_smaller(void) {
    printf("[f8] EOF reads, alignment warning, overflow in partadd\n");

    /* EOF / zero-length read */
    CFS *c = mk_disk(DISK_SZ);
    CHECK(c != NULL, "create");
    if (!c) return;
    CHECK(cfs_part_label(c, CFS_PART_MBR) == 0, "label mbr");
    CHECK(cfs_part_add(c, 1ULL << 20, 1ULL << 20, MBR_TYPE_LINUX, NULL, 0) == 1, "add part");
    CfsPartition p;
    CHECK(cfs_part_get(c, 1, &p) == 0, "get part");
    uint8_t b[512];
    CHECK(cfs_part_read(c, 1, b, 0, 0) == 0, "zero-length read returns 0");
    CHECK(cfs_part_read(c, 1, b, 16, (off_t)p.size) == 0, "read exactly at EOF returns 0");
    CHECK(cfs_part_read(c, 1, b, 16, (off_t)(p.size + 512)) == 0, "read past EOF returns 0");
    CHECK(cfs_part_read(c, 1, b, 512, (off_t)(p.size - 100)) == 100, "short read at the tail");
    cfs_close(c);
    unlink(path);

    /* 1MiB alignment: a start that is 2KiB-aligned but not 1MiB-aligned.
     * The old check multiplied by 512 first, so it only caught 2KiB. */
    c = mk_disk(DISK_SZ);
    CHECK(c != NULL, "create");
    if (!c) return;
    CHECK(cfs_part_label(c, CFS_PART_MBR) == 0, "label mbr");
    CHECK(alignment_warning(c, (1ULL << 20) + 2048, 4096) == 1, "warning for a 2KiB-aligned start");
    CHECK(alignment_warning(c, 2ULL << 20, 4096) == 0, "no warning for a 1MiB-aligned start");
    cfs_close(c);
    unlink(path);

    /* start + size that wraps 64 bits must not look in-bounds */
    c = mk_disk(DISK_SZ);
    CHECK(c != NULL, "create");
    if (!c) return;
    CHECK(cfs_part_label(c, CFS_PART_GPT) == 0, "label gpt");
    CHECK(cfs_part_add(c, UINT64_MAX - 511, 4096, MBR_TYPE_LINUX, NULL, 0) < 0,
          "wrapped start+size rejected");
    CHECK(cfs_part_count(c) == 0, "no partition was created");
    cfs_close(c);
    unlink(path);
}

static const char *only = NULL;
static int want(const char *id) { return !only || !strcmp(only, id); }

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--hook-child")) return hook_child();
    if (argc > 2 && !strcmp(argv[1], "--only")) only = argv[2];
    set_paths(argv[0]);

    if (want("f1")) test_hook_clamp(argv[0]);
    if (want("f2")) test_table_coverage();
    if (want("f3")) test_mbr_32bit();
    if (want("f4")) test_gpt_entry_size();
    if (want("f5")) test_gpt_quota_atomicity();
    if (want("f6")) test_parttype_gpt_name();
    if (want("f7")) test_mkfs_install_pn();
    if (want("f8")) test_smaller();

    printf("\n=== %d failures ===\n", failed);
    return failed ? 1 : 0;
}
