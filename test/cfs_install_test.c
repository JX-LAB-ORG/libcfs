/* cfs_install_test.c — ISO install into ext4 partition, verified by the
 * read-only ext2 walker.  Covers: bare-disk install, partitioned install,
 * deep trees, multi-extent ISO files, empty files, directory growth. */

#define _POSIX_C_SOURCE 200809L
#include "iso_mk.h"
#include "ext2_read.h"
#include "../cfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;
#define CHECK(cond, ...) do { if (!(cond)) { failures++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

static uint8_t *mk_content(size_t len, uint32_t seed) {
    uint8_t *p = malloc(len ? len : 1);
    uint64_t s = 0x9E3779B97F4A7C15ull ^ seed;
    for (size_t i = 0; i < len; i++) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; p[i] = (uint8_t)(s >> 33); }
    return p;
}

/* verification callback: compare against expected tree */
typedef struct {
    int nfiles;
    const char **paths;
    size_t *sizes;
    const uint8_t **data;
    int found;
} ExpectCtx;

static int verify_cb(const E2Entry *e, const uint8_t *data, void *ctx) {
    ExpectCtx *x = ctx;
    if (e->is_dir) return 0;
    for (int i = 0; i < x->nfiles; i++) {
        if (!strcmp(e->path, x->paths[i])) {
            CHECK(e->size == x->sizes[i],
                  "%s size %llu != %zu", e->path, (unsigned long long)e->size, x->sizes[i]);
            if (x->sizes[i]) {
                CHECK(memcmp(data, x->data[i], x->sizes[i]) == 0,
                      "%s content mismatch", e->path);
            }
            x->found++;
            return 0;
        }
    }
    printf("FAIL: unexpected entry %s\n", e->path);
    failures++;
    return 0;
}

/* read partition region into memory */
static uint8_t *read_part(CFS *c, uint64_t off, uint64_t len) {
    uint8_t *buf = malloc(len ? len : 1);
    if (!buf) return NULL;
    if (cfs_block_read(c, buf, len, (off_t)off) != (ssize_t)len) { free(buf); return NULL; }
    return buf;
}

static void run_case(const char *tag, CFS *c, uint64_t base, uint64_t psize,
                     const IsoMkEntry *files, int nfiles,
                     const char **paths, size_t *sizes, const uint8_t **datas) {
    size_t isz = 0;
    uint8_t *iso = iso_mk_build(files, nfiles, "FW", &isz);
    CHECK(iso != NULL, "%s: iso_mk_build failed", tag);
    if (!iso) return;

    int rc = cfs_mkfs_ext4_install(c, base, psize, iso, isz);
    CHECK(rc == 0, "%s: install rc=%d", tag, rc);

    if (rc == 0) {
        uint8_t *img = read_part(c, base, psize);
        CHECK(img != NULL, "%s: read partition", tag);
        if (img) {
            ExpectCtx x;
            memset(&x, 0, sizeof(x));
            x.nfiles = nfiles; x.paths = paths; x.sizes = sizes; x.data = datas;
            int wrc = ext2_walk(img, psize, verify_cb, &x);
            CHECK(wrc == 0, "%s: ext2_walk rc=%d", tag, wrc);
            CHECK(x.found == nfiles, "%s: found %d/%d files", tag, x.found, nfiles);
            free(img);
        }
    }
    free(iso);
}

int main(void) {
    /* case A: bare-disk install (no partition table) */
    {
        unlink("/tmp/inst_a.cfs");
        CFS *c = cfs_create("/tmp/inst_a.cfs");
        CHECK(c != NULL, "open A");
        if (!c) return 1;

        uint8_t *bl2 = mk_content(100, 1);
        uint8_t *fip = mk_content(300000, 2);       /* multi-extent ISO */
        uint8_t *empty = mk_content(0, 3);
        uint8_t *app = mk_content(5000, 4);
        uint8_t *deep = mk_content(100, 5);
        IsoMkEntry files[] = {
            {"BL2.BIN", bl2, 100, 0},
            {"FIP.BIN", fip, 300000, 1},
            {"NVRAM.IMG", empty, 0, 0},
            {"fw/APP.BIN", app, 5000, 0},
            {"a/b/c/d/e/x.bin", deep, 100, 0},
        };
        const char *paths[] = {"/BL2.BIN", "/FIP.BIN", "/NVRAM.IMG", "/FW/APP.BIN", "/A/B/C/D/E/X.BIN"};
        size_t sizes[] = {100, 300000, 0, 5000, 100};
        const uint8_t *datas[] = {bl2, fip, empty, app, deep};
        run_case("A", c, 0, 32 * 1024 * 1024, files, 5, paths, sizes, datas);

        /* reopen: install must be persistent */
        cfs_close(c);
        c = cfs_open("/tmp/inst_a.cfs", CFS_RDWR);
        CHECK(c != NULL, "reopen A");
        if (c) {
            uint8_t *img = read_part(c, 0, 32 * 1024 * 1024);
            ExpectCtx x;
            memset(&x, 0, sizeof(x));
            x.nfiles = 5; x.paths = paths; x.sizes = sizes; x.data = datas;
            int wrc = ext2_walk(img, 32 * 1024 * 1024, verify_cb, &x);
            CHECK(wrc == 0 && x.found == 5, "A reopen verify (rc=%d found=%d)", wrc, x.found);
            free(img);
            cfs_close(c);
        }
        free(bl2); free(fip); free(empty); free(app); free(deep);
        unlink("/tmp/inst_a.cfs");
    }

    /* case B: partitioned install (MBR, partition 1 at 1MB) */
    {
        unlink("/tmp/inst_b.cfs");
        CFS *c = cfs_create("/tmp/inst_b.cfs");
        CHECK(c != NULL, "open B");
        if (!c) return 1;
        cfs_block_resize(c, 33 * 1024 * 1024);
        CHECK(cfs_part_label(c, CFS_PART_MBR) == 0, "B partlabel");
        int ar = cfs_part_add(c, 1 * 1024 * 1024, 32 * 1024 * 1024, 0x83, NULL, 0);
        printf("B partadd rc=%d disk=%llu\n", ar, (unsigned long long)cfs_block_size(c));
        CHECK(ar >= 1, "B partadd (rc=%d)", ar);

        uint8_t *boot = mk_content(777, 6);
        uint8_t *cfg = mk_content(12345, 7);
        IsoMkEntry files[] = {
            {"BOOT.BIN", boot, 777, 0},
            {"cfg/setup.ini", cfg, 12345, 0},
        };
        const char *paths[] = {"/BOOT.BIN", "/CFG/SETUP.INI"};
        size_t sizes[] = {777, 12345};
        const uint8_t *datas[] = {boot, cfg};
        run_case("B", c, 1024 * 1024, 32 * 1024 * 1024, files, 2, paths, sizes, datas);
        cfs_close(c);
        free(boot); free(cfg);
        unlink("/tmp/inst_b.cfs");
    }

    /* case C: large directory (directory growth, multi-block dirs) */
    {
        unlink("/tmp/inst_c.cfs");
        CFS *c = cfs_create("/tmp/inst_c.cfs");
        CHECK(c != NULL, "open C");
        if (!c) return 1;

        enum { NF = 320 };
        static IsoMkEntry files[NF];
        static char pbuf[NF][32];
        static const char *paths[NF];
        static size_t sizes[NF];
        static const uint8_t *datas[NF];
        for (int i = 0; i < NF; i++) {
            snprintf(pbuf[i], sizeof(pbuf[i]), "fw/mod_%03d.bin", i);
            files[i].path = pbuf[i];
            datas[i] = mk_content(64, (uint32_t)(1000 + i));
            files[i].data = (uint8_t *)datas[i];
            files[i].len = sizes[i] = 64;
            files[i].multiextent = 0;
            paths[i] = pbuf[i];
            /* path in the fs is uppercase 8.3: "FW/MOD_003.BIN" */
            snprintf(pbuf[i], sizeof(pbuf[i]), "/FW/MOD_%03d.BIN", i);
        }
        run_case("C", c, 0, 32 * 1024 * 1024, files, NF, paths, sizes, datas);
        cfs_close(c);
        for (int i = 0; i < NF; i++) free(datas[i]);
        unlink("/tmp/inst_c.cfs");
    }

    /* case D: a disk whose block table reaches past the old sentinel.
     *
     * The write path marks a pending entry as "this is a new block" with a
     * sentinel stored in the same array as block indices, and that sentinel
     * was PEND_MAX == 128 — an ordinary block index.  A container with more
     * than 128 blocks (1GB at the 8MB block chunk) therefore misread a patch
     * of block 128 as an append and wrote one entry past the table, which
     * `cfs-tool mkfs ext4 1200M` turned into a segfault.  Nothing here is a
     * large amount of data: the container is written sparse, the blocks are
     * zero runs, and the check is that the disk is still a disk afterwards. */
    {
        unlink("/tmp/inst_d.cfs");
        CFS *c = cfs_create("/tmp/inst_d.cfs");
        CHECK(c != NULL, "open D");
        if (c) {
            int rc = cfs_mkfs_ext4(c, 1200ULL * 1024 * 1024);
            CHECK(rc == 0, "D: mkfs ext4 1200M (rc=%d)", rc);
            cfs_close(c);

            c = cfs_open("/tmp/inst_d.cfs", CFS_RDONLY);
            CHECK(c != NULL, "D: reopen");
            if (c) {
                uint8_t sb[64];
                ssize_t n = cfs_block_read(c, sb, sizeof sb, 1024 + 56);
                CHECK(n == (ssize_t)sizeof sb, "D: read superblock (n=%zd)", n);
                CHECK(n == (ssize_t)sizeof sb && sb[0] == 0x53 && sb[1] == 0xEF,
                      "D: ext4 magic (got %02x%02x)", sb[0], sb[1]);
                cfs_close(c);
            }
            unlink("/tmp/inst_d.cfs");
        }
    }

    printf(failures ? "=== %d FAILURES ===\n" : "=== 0 failures ===\n", failures);
    return failures ? 1 : 0;
}
