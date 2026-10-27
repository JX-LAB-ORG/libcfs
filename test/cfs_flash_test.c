/* cfs_flash_test — regression suite for "@flash.<tag>" media.
 *
 * A flash medium is a raw, 4 KiB-aligned, uncompressed extent inside the
 * container (see cfs_format.h), so it does not behave like a file: it has an
 * erase model, page-scoped programming, and can be mapped straight out of the
 * container for XIP.  This suite covers
 *
 *   A. creation/layout and the cfs_open() append_off validation
 *   B. the raw-media program rules (erased-only, no 0->1, one page at a time)
 *   C. persistence across close/reopen and MAP_SHARED write visibility
 *   D. container-level guards (XIP vs compact, write/truncate/rename, verify)
 *   E. bad blocks, erase-count persistence and the descriptor A/B copies
 *   F. creation error matrix and verify's rejection of damaged descriptors
 *
 * The first half of A is the important one historically: the extent is the
 * container's high-water mark even though its comp_size is 0, and a reopen
 * without that left the next write landing on guest byte 0.
 *
 * House style: CHK macro, "=== N failures ===" banner, non-zero exit.  The
 * suite builds on any host but is executed by the maintainer on the test box;
 * `make test-flash` only builds it.
 */
#define _GNU_SOURCE
#include "../cfs.h"
#include "../cfs_format.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

static int failed = 0;
#define CHK(c,m) do{if(!(c)){failed++;fprintf(stderr,"  FAIL: %s\n",m);}else{fprintf(stderr,"  OK %s\n",m);}}while(0)

#define MEDIUM_SIZE (4ULL * 1024 * 1024)
#define PAGE_SZ     (256u)
#define ERASE_SZ    (4096u)

static char scratch[512];
static char cont_path[600];
static char compact_path[600];
static char err_path[600];
static char err2_path[600];
static char verify_path[600];
static char verify_crc_path[600];
static char verify_geom_path[600];

/* Deterministic, poorly compressible bytes (an LCG). */
static void fill_pat(uint8_t *buf, size_t n, uint32_t seed) {
    uint32_t x = seed * 2654435761u + 1;
    for (size_t i = 0; i < n; i++) {
        x = x * 1664525u + 1013904223u;
        buf[i] = (uint8_t)(x >> 16);
    }
}

static int all_val(const uint8_t *p, size_t n, uint8_t v) {
    for (size_t i = 0; i < n; i++)
        if (p[i] != v) return 0;
    return 1;
}
static int all_ff(const uint8_t *p, size_t n) { return all_val(p, n, 0xFF); }

/* Host-side I/O on a raw descriptor: the descriptor area is edited with a
 * plain fd, not through the flash API (which owns only the medium). */
static int pread_full(int fd, void *buf, size_t n, off_t off) {
    uint8_t *p = buf;
    while (n) {
        ssize_t r = pread(fd, p, n, off);
        if (r < 0) return -1;
        if (r == 0) { errno = EIO; return -1; }
        p += r; off += r; n -= (size_t)r;
    }
    return 0;
}

static int pwrite_full(int fd, const void *buf, size_t n, off_t off) {
    const uint8_t *p = buf;
    while (n) {
        ssize_t w = pwrite(fd, p, n, off);
        if (w < 0) return -1;
        if (w == 0) { errno = ENOSPC; return -1; }
        p += w; off += w; n -= (size_t)w;
    }
    return 0;
}

static int copy_file(const char *src, const char *dst) {
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { close(in); return -1; }
    uint8_t b[65536];
    off_t off = 0;
    int rc = 0;
    for (;;) {
        ssize_t r = pread(in, b, sizeof b, off);
        if (r < 0) { rc = -1; break; }
        if (r == 0) break;
        if (pwrite_full(out, b, (size_t)r, off) != 0) { rc = -1; break; }
        off += r;
    }
    close(in);
    close(out);
    return rc;
}

/* The two descriptor copies live at the end of the extent, after the medium.
 * These helpers read the whole 4 KiB area and identify a copy the same way
 * cfs_flash.c's desc_read() does: highest sequence number wins. */
static int desc_newer(const uint8_t *area) {
    uint32_t s0 = cfs_rd32(area + CFS_FLASH_D_SEQ);
    uint32_t s1 = cfs_rd32(area + CFS_FLASH_COPY_SIZE + CFS_FLASH_D_SEQ);
    return s0 >= s1 ? 0 : 1;
}
static uint32_t desc_seq(const uint8_t *area, int copy) {
    return cfs_rd32(area + (size_t)copy * CFS_FLASH_COPY_SIZE + CFS_FLASH_D_SEQ);
}
static uint64_t desc_erase_count(const uint8_t *area, int copy) {
    return cfs_rd64(area + (size_t)copy * CFS_FLASH_COPY_SIZE +
                    CFS_FLASH_D_ECOUNT);
}

/* Descriptor file offset for a container holding the "nor0" medium.  Uses the
 * public API so the test does not hardcode create's placement rule. */
static int flash_desc_off(const char *path, const char *tag, off_t *out) {
    CFS *c = cfs_open(path, CFS_RDONLY);
    if (!c) return -1;
    CfsFlash *f = cfs_flash_open(c, tag, 0);
    int rc = -1;
    if (f) {
        int fd = -1;
        off_t off = 0;
        uint64_t len = 0;
        if (cfs_flash_extent(f, &fd, &off, &len) == 0) {
            *out = (off_t)((uint64_t)off + len);
            rc = 0;
        }
        cfs_flash_close(f);
    }
    cfs_close(c);
    return rc;
}

static int read_flash_desc(const char *path, const char *tag,
                           uint8_t area[CFS_FLASH_DESC_SIZE]) {
    off_t off = 0;
    if (flash_desc_off(path, tag, &off) != 0) return -1;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int rc = pread_full(fd, area, CFS_FLASH_DESC_SIZE, off);
    close(fd);
    return rc;
}

static int write_flash_desc(const char *path, const char *tag,
                            const uint8_t area[CFS_FLASH_DESC_SIZE]) {
    off_t off = 0;
    if (flash_desc_off(path, tag, &off) != 0) return -1;
    int fd = open(path, O_RDWR);
    if (fd < 0) return -1;
    int rc = pwrite_full(fd, area, CFS_FLASH_DESC_SIZE, off);
    close(fd);
    return rc;
}

/* Overwrite every page of [first, first+count) erase blocks with a non-0xFF
 * pattern.  A full erase that skipped any of them then has to fail. */
static int pollute_blocks(CfsFlash *f, uint32_t first, uint32_t count) {
    uint8_t page[PAGE_SZ];
    for (uint32_t b = 0; b < count; b++) {
        uint64_t base = (uint64_t)(first + b) * ERASE_SZ;
        if (cfs_flash_erase(f, base, ERASE_SZ) != 0) return -1;
        for (uint64_t o = 0; o < ERASE_SZ; o += PAGE_SZ) {
            memset(page, (b & 1) ? 0xA5 : 0x5A, sizeof page);
            if (cfs_flash_write(f, base + o, page, sizeof page) !=
                (ssize_t)sizeof page)
                return -1;
        }
    }
    return 0;
}

/* ═══ A–E: one 4 MB NOR medium with XIP ═══════════════════════════ */
static void test_medium(void) {
    uint8_t *buf = malloc(MEDIUM_SIZE);      /* 4 MB read scratch */
    CHK(buf != NULL, "allocate a 4 MB scratch buffer");
    if (!buf) return;

    /* ── A1. create, close, reopen ─────────────────────────────── */
    unlink(cont_path);
    CFS *c = cfs_create(cont_path);
    CHK(c != NULL, "A1: create the container");
    if (!c) { free(buf); return; }

    CfsFlashGeom g;
    unsigned flags = 0;
    CHK(cfs_flash_profile("nor", &g, &flags) == 0, "A1: cfs_flash_profile(\"nor\")");
    g.size = MEDIUM_SIZE;                    /* the profile leaves this to us */
    errno = 0;
    CHK(cfs_flash_create(c, "nor0", &g, flags | CFS_FLASH_F_XIP) == 0,
        "A1: create a 4 MB nor medium with CFS_FLASH_F_XIP");
    cfs_close(c);

    errno = 0;
    c = cfs_open(cont_path, CFS_RDWR);
    CHK(c != NULL,
        "A1: the container reopens (append_off folded the flash extent)");
    if (!c) { free(buf); return; }

    /* ── A2. geometry ──────────────────────────────────────────── */
    CfsFlash *f = cfs_flash_open(c, "nor0", 1);
    CHK(f != NULL, "A2: cfs_flash_open succeeds");
    if (!f) { cfs_close(c); free(buf); return; }

    uint64_t gsz = 0;
    uint32_t gsec = 0, gerase = 0, ggran = 0;
    CHK(cfs_flash_geometry(f, &gsz, &gsec, &gerase, &ggran) == 0,
        "A2: cfs_flash_geometry succeeds");
    CHK(gsz == MEDIUM_SIZE, "A2: geometry reports a 4 MB medium");
    CHK(gsec == 512, "A2: geometry reports a 512-byte sector");
    CHK(gerase == ERASE_SZ, "A2: geometry reports a 4096-byte erase block");
    CHK(ggran == PAGE_SZ, "A2: geometry reports a 256-byte page (write granule)");

    /* ── A3. the medium starts erased ──────────────────────────── */
    CHK(cfs_flash_read(f, 0, buf, MEDIUM_SIZE) == (ssize_t)MEDIUM_SIZE,
        "A3: read every byte of the freshly created medium");
    CHK(all_ff(buf, MEDIUM_SIZE),
        "A3: the whole 4 MB medium reads as all 0xFF after create");

    /* A1b: the reopen above must have left append_off past the medium; a
     * normal file write afterwards has to land beyond it, not on guest byte
     * 0.  This is the regression the reopen case exists for. */
    uint8_t seed[512];
    fill_pat(seed, sizeof seed, 17);
    CHK(cfs_write(c, "seed.bin", seed, sizeof seed) == 0,
        "A1b: a file write after reopen succeeds");
    CHK(cfs_flash_read(f, 0, buf, MEDIUM_SIZE) == (ssize_t)MEDIUM_SIZE &&
        all_ff(buf, MEDIUM_SIZE),
        "A1b: the post-open write did not land anywhere on the medium");

    /* ── A4. extent ────────────────────────────────────────────── */
    int efd = -1;
    off_t eoff = 0;
    uint64_t elen = 0;
    CHK(cfs_flash_extent(f, &efd, &eoff, &elen) == 0,
        "A4: cfs_flash_extent succeeds");
    CHK(efd >= 0, "A4: the extent reports a container descriptor");
    CHK((eoff % ERASE_SZ) == 0, "A4: the extent's file offset is a multiple of 4096");
    CHK(elen == MEDIUM_SIZE, "A4: the extent length is the medium size");

    /* ── A5. XIP truth: the mapping and the API agree ──────────── */
    void *map = MAP_FAILED;
    if (efd >= 0 && elen == MEDIUM_SIZE)
        map = mmap(NULL, (size_t)elen, PROT_READ, MAP_SHARED, efd, eoff);
    CHK(map != MAP_FAILED, "A5: mmap(MAP_SHARED) of the extent succeeds");
    if (map != MAP_FAILED) {
        uint8_t *rd = malloc(64u << 10);
        CHK(rd && cfs_flash_read(f, 0, rd, 64u << 10) == (ssize_t)(64u << 10),
            "A5: cfs_flash_read of 64 KiB");
        CHK(rd && memcmp(rd, map, 64u << 10) == 0,
            "A5: the mapping and cfs_flash_read agree for 64 KiB");
        free(rd);
        munmap(map, (size_t)elen);
    }

    /* ── B6/B7. program once, then refuse a second program ─────── */
    uint8_t pat[PAGE_SZ];
    fill_pat(pat, sizeof pat, 31);
    errno = 0;
    CHK(cfs_flash_write(f, 0, pat, sizeof pat) == (ssize_t)sizeof pat,
        "B6: program 256 B at 0 onto an erased page");
    errno = 0;
    CHK(cfs_flash_write(f, 0, pat, sizeof pat) == -1 && errno == EIO,
        "B7: programming a non-erased page again fails with EIO");

    /* ── B8. erased-only programming, and a 0->1 transition ────── */
    CHK(cfs_flash_erase(f, 0, ERASE_SZ) == 0, "B8: erase block 0");
    uint8_t low[PAGE_SZ], high[PAGE_SZ];
    memset(low, 0x0F, sizeof low);
    memset(high, 0xF0, sizeof high);
    CHK(cfs_flash_write(f, 0, low, sizeof low) == (ssize_t)sizeof low,
        "B8: program 0x0F after the erase");
    errno = 0;
    CHK(cfs_flash_write(f, 0, high, sizeof high) == -1 && errno == EIO,
        "B8: a 0->1 transition on a programmed, unerased byte fails with EIO");
    CHK(cfs_flash_erase(f, 0, ERASE_SZ) == 0, "B8: erase block 0 again");
    CHK(cfs_flash_write(f, 0, high, sizeof high) == (ssize_t)sizeof high,
        "B8: programming the same bytes succeeds once the block is erased");

    /* ── B8b. a rejected write is all-or-nothing ───────────────── */
    CHK(cfs_flash_erase(f, ERASE_SZ, ERASE_SZ) == 0,
        "B8b: erase block 1");
    uint8_t f0[PAGE_SZ];
    memset(f0, 0xF0, sizeof f0);
    CHK(cfs_flash_write(f, ERASE_SZ, f0, sizeof f0) == (ssize_t)sizeof f0,
        "B8b: program a whole page with 0xF0");
    uint8_t mix[PAGE_SZ], back[PAGE_SZ];
    memset(mix, 0x00, sizeof mix / 2);                 /* clears bits: legal */
    memset(mix + sizeof mix / 2, 0xFF, sizeof mix / 2); /* 0->1: illegal */
    errno = 0;
    CHK(cfs_flash_write(f, ERASE_SZ, mix, sizeof mix) == -1 && errno == EIO,
        "B8b: a legal first half does not save a page whose second half sets bits");
    CHK(cfs_flash_read(f, ERASE_SZ, back, sizeof back) == (ssize_t)sizeof back &&
        all_val(back, sizeof back, 0xF0),
        "B8b: the rejected write changed nothing: the whole page still reads 0xF0");

    /* ── B9. no write may cross a program page ─────────────────── */
    errno = 0;
    CHK(cfs_flash_write(f, 128, pat, PAGE_SZ) == -1 && errno == EINVAL,
        "B9: a write crossing a 256-byte page boundary fails with EINVAL");

    /* ── B10. bounds ───────────────────────────────────────────── */
    errno = 0;
    CHK(cfs_flash_write(f, MEDIUM_SIZE, pat, 1) == -1 && errno == EINVAL,
        "B10: a write at the end of the medium fails with EINVAL");
    errno = 0;
    CHK(cfs_flash_write(f, MEDIUM_SIZE - 128, pat, PAGE_SZ) == -1 &&
        errno == EINVAL,
        "B10: a write straddling the end of the medium fails with EINVAL");

    /* ── B11. erase granularity ────────────────────────────────── */
    errno = 0;
    CHK(cfs_flash_erase(f, 0, 2048) == -1 && errno == EINVAL,
        "B11: an erase length that is not a multiple of 4096 fails with EINVAL");

    /* ── B12. erase the whole medium ───────────────────────────── */
    /* Make blocks 0..3 non-0xFF first: an erase that only touched the first
     * or the last block would leave this pattern behind. */
    CHK(pollute_blocks(f, 0, 4) == 0,
        "B12: pollute erase blocks 0..3 with a non-0xFF pattern");
    CHK(cfs_flash_read(f, 0, buf, 4 * ERASE_SZ) == (ssize_t)(4 * ERASE_SZ) &&
        !all_ff(buf, 4 * ERASE_SZ),
        "B12: blocks 0..3 really are non-0xFF before the full erase");
    CHK(cfs_flash_erase(f, 0, (size_t)MEDIUM_SIZE) == 0,
        "B12: erasing the whole medium succeeds");
    CHK(cfs_flash_read(f, 0, buf, MEDIUM_SIZE) == (ssize_t)MEDIUM_SIZE,
        "B12: read every byte back after the full erase");
    CHK(all_ff(buf, MEDIUM_SIZE),
        "B12: the whole 4 MB medium reads 0xFF after the full erase");

    /* ── B13. a read-only handle, and the map/read bounds ──────── */
    CfsFlash *ro = cfs_flash_open(c, "nor0", 0);
    CHK(ro != NULL, "B13: a read-only flash handle opens");
    if (ro) {
        errno = 0;
        CHK(cfs_flash_write(ro, 0, pat, sizeof pat) == -1 && errno == EROFS,
            "B13: write on a read-only handle fails with EROFS");
        errno = 0;
        CHK(cfs_flash_erase(ro, 0, ERASE_SZ) == -1 && errno == EROFS,
            "B13: erase on a read-only handle fails with EROFS");
        CHK(cfs_flash_read(ro, 0, buf, sizeof pat) == (ssize_t)sizeof pat &&
            all_ff(buf, sizeof pat),
            "B13: reads still work on the read-only handle");

        int mw = -1;
        void *m = cfs_flash_map(ro, 0, PAGE_SZ, &mw);
        CHK(m != NULL && mw == 0,
            "B13: cfs_flash_map on a read-only handle reports *writable == 0");
        errno = 0;
        CHK(cfs_flash_map(ro, MEDIUM_SIZE, 1, &mw) == NULL && errno == EINVAL,
            "B13: map(off=size, len=1) is refused with EINVAL");
        errno = 0;
        CHK(cfs_flash_map(ro, MEDIUM_SIZE + 1, 1, &mw) == NULL && errno == EINVAL,
            "B13: map(off=size+1, len=1) is refused with EINVAL");
        errno = 0;
        CHK(cfs_flash_read(ro, MEDIUM_SIZE - 1, buf, 2) == -1 && errno == EINVAL,
            "B13: read(off=size-1, len=2) is refused with EINVAL");
        cfs_flash_close(ro);
    }

    /* ── C14. persistence across close and reopen ──────────────── */
    uint8_t pat2[PAGE_SZ];
    fill_pat(pat2, sizeof pat2, 43);
    CHK(cfs_flash_write(f, 8192, pat2, sizeof pat2) == (ssize_t)sizeof pat2,
        "C14: program a known pattern at 8192");
    CHK(cfs_flash_flush(f) == 0, "C14: cfs_flash_flush succeeds");
    cfs_flash_close(f);
    f = NULL;
    cfs_close(c);
    c = NULL;

    c = cfs_open(cont_path, CFS_RDONLY);
    CHK(c != NULL, "C14: the container reopens read-only");
    if (c) {
        f = cfs_flash_open(c, "nor0", 0);
        CHK(f != NULL, "C14: the medium reopens");
        if (f) {
            uint8_t got[PAGE_SZ];
            CHK(cfs_flash_read(f, 8192, got, sizeof got) == (ssize_t)sizeof got &&
                memcmp(got, pat2, sizeof pat2) == 0,
                "C14: the pattern reads back byte-exact after the reopen");
            cfs_flash_close(f);
            f = NULL;
        }
        cfs_close(c);
        c = NULL;
    }

    /* ── C15. MAP_SHARED write is immediately visible ──────────── */
    c = cfs_open(cont_path, CFS_RDWR);
    CHK(c != NULL, "C15: the container reopens read-write");
    if (!c) { free(buf); return; }
    f = cfs_flash_open(c, "nor0", 1);
    CHK(f != NULL, "C15: the writable medium reopens");
    if (f) {
        CHK(cfs_flash_erase(f, 3 * ERASE_SZ, ERASE_SZ) == 0,
            "C15: erase the block that is about to be mapped");
        int mw = 0;
        void *m = cfs_flash_map(f, 3 * ERASE_SZ, ERASE_SZ, &mw);
        CHK(m != NULL && mw == 1,
            "C15: cfs_flash_map returns a writable mapping");
        if (m) {
            uint8_t xp[ERASE_SZ];
            fill_pat(xp, sizeof xp, 57);
            memcpy(m, xp, sizeof xp);
            uint8_t *rd = malloc(sizeof xp);
            CHK(rd && cfs_flash_read(f, 3 * ERASE_SZ, rd, sizeof xp) ==
                (ssize_t)sizeof xp && memcmp(rd, xp, sizeof xp) == 0,
                "C15: a write through the mapping is visible to cfs_flash_read immediately");
            free(rd);
        }
        CHK(cfs_flash_flush(f) == 0, "C15: flush after the mapped write");

        /* ── D16. compact refuses an XIP container ─────────────── */
        struct stat stb;
        CHK(stat(cont_path, &stb) == 0, "D16: stat the container before compact");
        off_t size_before = stb.st_size;
        uint8_t *snap = malloc(MEDIUM_SIZE);
        CHK(snap && cfs_flash_read(f, 0, snap, MEDIUM_SIZE) ==
            (ssize_t)MEDIUM_SIZE,
            "D16: snapshot every medium byte before compact");
        errno = 0;
        CHK(cfs_compact(c) == -1 && errno == EOPNOTSUPP,
            "D16: cfs_compact on an XIP medium fails with EOPNOTSUPP");
        CHK(stat(cont_path, &stb) == 0 && stb.st_size == size_before,
            "D16: the refused compact left the container file size unchanged");
        CHK(cfs_flash_read(f, 0, buf, MEDIUM_SIZE) == (ssize_t)MEDIUM_SIZE &&
            snap && memcmp(snap, buf, MEDIUM_SIZE) == 0,
            "D16: the refused compact left every medium byte unchanged");
        free(snap);

        /* ── D18. the medium is not a file ─────────────────────── */
        uint8_t *snap_after = malloc(MEDIUM_SIZE);
        CHK(snap_after != NULL, "D18: allocate the after-refusals snapshot");
        uint8_t tmpw[512];
        fill_pat(tmpw, sizeof tmpw, 61);
        CHK(cfs_flash_read(f, 0, buf, MEDIUM_SIZE) == (ssize_t)MEDIUM_SIZE,
            "D18: snapshot every medium byte before the refusals");

        errno = 0;
        CHK(cfs_write(c, "@flash.nor0", tmpw, sizeof tmpw) == -1 &&
            errno == EINVAL,
            "D18: cfs_write on the medium fails with EINVAL");
        errno = 0;
        CHK(cfs_truncate(c, "@flash.nor0", 0) == -1 && errno == EINVAL,
            "D18: cfs_truncate(0) on the medium fails with EINVAL");
        CfsStat fst;
        errno = 0;
        CHK(cfs_stat(c, "@flash.nor0", &fst) == 0 &&
            fst.mode == CFS_MODE_FLASH,
            "D18: cfs_stat reports the flash mode");
        errno = 0;
        CHK(cfs_truncate(c, "@flash.nor0", fst.size) == -1 && errno == EINVAL,
            "D18: cfs_truncate to the entry's own span fails with EINVAL (not the equal-size early return)");
        errno = 0;
        CHK(cfs_rename(c, "@flash.nor0", "@flash.moved") == -1 &&
            errno == EINVAL,
            "D18: cfs_rename of the medium fails with EINVAL");
        errno = 0;
        CHK(cfs_unlink(c, "@flash.nor0") == -1 && errno == EINVAL,
            "D18: cfs_unlink of the medium fails with EINVAL");
        errno = 0;
        CHK(cfs_write(c, "@flash.nor0", tmpw, 0) == -1 && errno == EINVAL,
            "D18: the empty-write touch path refuses the medium with EINVAL");
        CHK(cfs_read(c, "@flash.nor0", tmpw, sizeof tmpw, 0) == -1,
            "D18: cfs_read refuses the medium");

        CHK(snap_after &&
            cfs_flash_read(f, 0, snap_after, MEDIUM_SIZE) ==
                (ssize_t)MEDIUM_SIZE &&
            memcmp(snap_after, buf, MEDIUM_SIZE) == 0,
            "D18: the refusals left every medium byte unchanged");
        free(snap_after);

        CHK(cfs_flash_geometry(f, &gsz, &gsec, &gerase, &ggran) == 0 &&
            gsz == MEDIUM_SIZE && gsec == 512 && gerase == ERASE_SZ &&
            ggran == PAGE_SZ,
            "D18: the medium still answers to its tag after the refusals");

        cfs_flash_close(f);
        f = NULL;
        f = cfs_flash_open(c, "nor0", 1);
        CHK(f != NULL, "D18: the medium reopens by its tag");
        if (f) {
            uint64_t s2 = 0, s3 = 0;
            uint32_t sec2 = 0, er2 = 0, wg2 = 0;
            CHK(cfs_flash_geometry(f, &s2, &sec2, &er2, &wg2) == 0 &&
                s2 == MEDIUM_SIZE && sec2 == 512 && er2 == ERASE_SZ &&
                wg2 == PAGE_SZ,
                "D18: geometry still matches after reopening by tag");
            /* A second geometry call proving the handle is live, not a copy
             * of the pre-reopen values. */
            CHK(cfs_flash_geometry(f, &s3, NULL, NULL, NULL) == 0 &&
                s3 == MEDIUM_SIZE,
                "D18: the reopened handle reports a live geometry");
        }
    }

    /* ── E. bad-block lookup and enforcement ───────────────────── */
    if (f) {
        errno = 0;
        CHK(cfs_flash_is_bad(f, 0) == 0,
            "E: a block with no bad-block record is good");
        errno = 0;
        CHK(cfs_flash_is_bad(f, ERASE_SZ) == 0,
            "E: the next erase block is good too");
        errno = 0;
        CHK(cfs_flash_is_bad(f, MEDIUM_SIZE) == -1 && errno == EINVAL,
            "E: an out-of-range offset is refused with EINVAL");

        CHK(cfs_flash_bad_set(f, 3, 1) == 0,
            "E: mark erase block 3 bad");
        cfs_flash_close(f);
        f = NULL;
        f = cfs_flash_open(c, "nor0", 1);
        CHK(f != NULL, "E: the medium reopens after the bad-block update");
        if (f) {
            uint64_t ec = 0;
            uint32_t bc = 0;
            CHK(cfs_flash_is_bad(f, 3 * ERASE_SZ) == 1,
                "E: cfs_flash_is_bad reports block 3 after the reopen");
            CHK(cfs_flash_info(f, NULL, NULL, NULL, &ec, &bc) == 0 && bc == 1,
                "E: cfs_flash_info reports bad_count == 1");
            errno = 0;
            CHK(cfs_flash_write(f, 3 * ERASE_SZ, pat, sizeof pat) == -1 &&
                errno == EIO,
                "E: a write touching a bad block fails with EIO");
            errno = 0;
            CHK(cfs_flash_erase(f, 3 * ERASE_SZ, ERASE_SZ) == -1 && errno == EIO,
                "E: an erase touching a bad block fails with EIO");
            CHK(cfs_flash_write(f, 4 * ERASE_SZ, pat, sizeof pat) ==
                (ssize_t)sizeof pat,
                "E: the neighbouring good block is still writable");
            CHK(cfs_flash_bad_set(f, 3, 0) == 0,
                "E: clear the bad-block record");
            CHK(cfs_flash_is_bad(f, 3 * ERASE_SZ) == 0,
                "E: block 3 is good again after the clear");
            CHK(cfs_flash_info(f, NULL, NULL, NULL, NULL, &bc) == 0 && bc == 0,
                "E: cfs_flash_info reports bad_count == 0 after the clear");
            CHK(cfs_flash_erase(f, 3 * ERASE_SZ, ERASE_SZ) == 0,
                "E: block 3 erases again once the record is cleared");
        }
    }

    /* ── E-count. the erase count survives close/reopen ────────── */
    if (f) {
        uint64_t ec_before = 0;
        CHK(cfs_flash_info(f, NULL, NULL, NULL, &ec_before, NULL) == 0,
            "E-count: read the erase count before the two erases");
        CHK(cfs_flash_erase(f, ERASE_SZ, ERASE_SZ) == 0,
            "E-count: erase block 1");
        CHK(cfs_flash_erase(f, 2 * ERASE_SZ, ERASE_SZ) == 0,
            "E-count: erase block 2");
        uint64_t ec_now = 0;
        CHK(cfs_flash_info(f, NULL, NULL, NULL, &ec_now, NULL) == 0 &&
            ec_now == ec_before + 2,
            "E-count: cfs_flash_info adds one per erased block");
        cfs_flash_close(f);
        f = NULL;
        cfs_close(c);
        c = NULL;
        c = cfs_open(cont_path, CFS_RDWR);
        CHK(c != NULL, "E-count: the container reopens after the erases");
        if (c) {
            f = cfs_flash_open(c, "nor0", 1);
            CHK(f != NULL, "E-count: the medium reopens after the erases");
            if (f) {
                uint64_t ec_re = 0;
                CHK(cfs_flash_info(f, NULL, NULL, NULL, &ec_re, NULL) == 0 &&
                    ec_re == ec_before + 2,
                    "E-count: close/reopen preserves the descriptor's erase count");
            }
        }
    }

    /* ── D-copy. the descriptor A/B copies ─────────────────────── */
    if (c && f) {
        int efd2 = -1;
        off_t eoff2 = 0;
        uint64_t elen2 = 0;
        CHK(cfs_flash_extent(f, &efd2, &eoff2, &elen2) == 0,
            "D-copy: locate the extent");
        /* One more erase: the newest descriptor copy must have a higher
         * sequence and erase count than the one it fell back to. */
        CHK(cfs_flash_erase(f, ERASE_SZ, ERASE_SZ) == 0,
            "D-copy: one more erase advances the descriptor sequence");
        off_t doff = (off_t)((uint64_t)eoff2 + elen2);
        int dfd = open(cont_path, O_RDWR);
        CHK(dfd >= 0, "D-copy: open the container to edit the descriptor area");
        if (dfd >= 0) {
            uint8_t area[CFS_FLASH_DESC_SIZE];
            uint8_t saved[CFS_FLASH_DESC_SIZE];
            CHK(pread_full(dfd, area, sizeof area, doff) == 0,
                "D-copy: read the 4 KiB descriptor area");
            memcpy(saved, area, sizeof saved);
            int ni = desc_newer(area);
            int oi = 1 - ni;
            uint32_t nseq = desc_seq(area, ni), oseq = desc_seq(area, oi);
            uint64_t nec = desc_erase_count(area, ni);
            uint64_t oec = desc_erase_count(area, oi);
            CHK(nseq > oseq,
                "D-copy: the two copies carry different sequence numbers");
            CHK(nec > oec,
                "D-copy: the newer copy is the one with the higher erase count");

            /* Break only the newer copy's CRC: open must fall back. */
            area[(size_t)ni * CFS_FLASH_COPY_SIZE + CFS_FLASH_D_CRC] ^= 0xFF;
            CHK(pwrite_full(dfd, area, sizeof area, doff) == 0,
                "D-copy: corrupt one byte of the newer copy's CRC field");
            cfs_flash_close(f);
            f = NULL;
            f = cfs_flash_open(c, "nor0", 0);
            CHK(f != NULL,
                "D-copy: cfs_flash_open falls back to the older descriptor copy");
            if (f) {
                uint64_t ec_fb = 0;
                CHK(cfs_flash_info(f, NULL, NULL, NULL, &ec_fb, NULL) == 0 &&
                    ec_fb == oec,
                    "D-copy: the fallback copy reports the older erase count");
                cfs_flash_close(f);
                f = NULL;
            }

            /* Both CRCs corrupt: neither copy is usable. */
            memcpy(area, saved, sizeof area);
            area[CFS_FLASH_D_CRC] ^= 0xFF;
            area[CFS_FLASH_COPY_SIZE + CFS_FLASH_D_CRC] ^= 0xFF;
            CHK(pwrite_full(dfd, area, sizeof area, doff) == 0,
                "D-copy: corrupt both copies' CRC fields");
            errno = 0;
            f = cfs_flash_open(c, "nor0", 0);
            CHK(f == NULL && errno == EIO,
                "D-copy: with both CRCs broken cfs_flash_open fails with EIO");
            if (f) { cfs_flash_close(f); f = NULL; }

            /* The container's own metadata is untouched: it still opens. */
            cfs_close(c);
            c = NULL;
            CFS *c2 = cfs_open(cont_path, CFS_RDONLY);
            CHK(c2 != NULL,
                "D-copy: the container itself still opens with both descriptor copies broken");
            if (c2) {
                errno = 0;
                CfsFlash *f2 = cfs_flash_open(c2, "nor0", 0);
                CHK(f2 == NULL && errno == EIO,
                    "D-copy: the medium is still rejected on the fresh container handle");
                if (f2) cfs_flash_close(f2);
                cfs_close(c2);
            }

            /* Put both copies back and prove the medium recovers. */
            CHK(pwrite_full(dfd, saved, sizeof saved, doff) == 0,
                "D-copy: restore the original descriptor area");
            close(dfd);
            c = cfs_open(cont_path, CFS_RDONLY);
            CHK(c != NULL, "D-copy: the container reopens after the restore");
            if (c) {
                f = cfs_flash_open(c, "nor0", 0);
                CHK(f != NULL, "D-copy: the restored descriptor opens again");
                if (f) {
                    uint64_t ec_restored = 0;
                    CHK(cfs_flash_info(f, NULL, NULL, NULL, &ec_restored,
                                       NULL) == 0 && ec_restored == nec,
                        "D-copy: the restored descriptor reports the newer erase count");
                    cfs_flash_close(f);
                    f = NULL;
                }
                cfs_close(c);
                c = NULL;
            }
        }
    }

    if (f) cfs_flash_close(f);
    if (c) cfs_close(c);
    free(buf);
}

/* ═══ D17: compact follows a medium without F_XIP ════════════════
 * A medium without the flag is an ordinary extent and compact copies it
 * verbatim.  The layout below is deliberate: big.bin is written and then
 * overwritten with a different size, so its first block is orphaned in front
 * of the medium.  Compact drops the orphan and packs only the small live
 * block before the extent, which forces the extent into an earlier alignment
 * bucket.  The orphan spans two host-alignment units (4 KiB, or 64 KiB on a
 * large-page kernel) and the live block stays inside the first one, so the
 * move is guaranteed either way. */
static void test_compact_nonxip(void) {
    fprintf(stderr, "[D17] compact with a non-XIP medium\n");
    unlink(compact_path);

    CFS *c = cfs_create(compact_path);
    CHK(c != NULL, "D17: create the container");
    if (!c) return;
    CHK(cfs_set_raw(c) == 0, "D17: RAW container (keeps the plain write path)");

    uint64_t al = cfs_flash_align();
    size_t big_sz = (size_t)(al * 2);   /* orphan: at least one alignment unit */
    size_t big2_sz = 1024;              /* live block: inside the first unit */
    uint8_t *big = malloc(big_sz);
    CHK(big != NULL, "D17: allocate the block that creates the orphan");
    if (!big) { cfs_close(c); return; }
    fill_pat(big, big_sz, 5);
    CHK(cfs_write(c, "big.bin", big, big_sz) == 0, "D17: write big.bin");
    free(big);
    big = malloc(big2_sz);
    CHK(big != NULL, "D17: allocate the replacement block");
    if (!big) { cfs_close(c); return; }
    fill_pat(big, big2_sz, 6);
    CHK(cfs_write(c, "big.bin", big, big2_sz) == 0,
        "D17: overwrite big.bin with a different size (orphans the first block)");
    free(big);

    CfsFlashGeom g;
    unsigned flags = 0;
    CHK(cfs_flash_profile("nor", &g, &flags) == 0, "D17: nor profile");
    g.size = MEDIUM_SIZE;
    errno = 0;
    CHK(cfs_flash_create(c, "imgn", &g, 0) == 0,
        "D17: create a medium without CFS_FLASH_F_XIP");

    CfsFlash *f = cfs_flash_open(c, "imgn", 1);
    CHK(f != NULL, "D17: open the medium");
    if (!f) { cfs_close(c); return; }

    int efd = -1;
    off_t old_off = 0;
    uint64_t elen = 0;
    CHK(cfs_flash_extent(f, &efd, &old_off, &elen) == 0,
        "D17: read the extent before compact");
    uint8_t pat[PAGE_SZ];
    fill_pat(pat, sizeof pat, 99);
    CHK(cfs_flash_write(f, 0, pat, sizeof pat) == (ssize_t)sizeof pat,
        "D17: program the medium");
    /* Two erases, so the descriptor's erase counter is non-zero and its
     * survival through compact is meaningful. */
    CHK(cfs_flash_erase(f, ERASE_SZ, ERASE_SZ) == 0,
        "D17: erase block 1 before compact");
    CHK(cfs_flash_erase(f, 2 * ERASE_SZ, ERASE_SZ) == 0,
        "D17: erase block 2 before compact");
    uint64_t ec_before = 0;
    CHK(cfs_flash_info(f, NULL, NULL, NULL, &ec_before, NULL) == 0 &&
        ec_before == 2,
        "D17: two erases are counted in the descriptor");
    CHK(cfs_flash_flush(f) == 0, "D17: flush the medium");

    /* Full snapshots: every medium byte and all 4 KiB of descriptor. */
    uint8_t *msnap = malloc(MEDIUM_SIZE);
    uint8_t dsnap[CFS_FLASH_DESC_SIZE];
    CHK(msnap && cfs_flash_read(f, 0, msnap, MEDIUM_SIZE) ==
        (ssize_t)MEDIUM_SIZE,
        "D17: snapshot every medium byte before compact");
    CHK(pread_full(efd, dsnap, sizeof dsnap,
                   (off_t)((uint64_t)old_off + elen)) == 0,
        "D17: snapshot the 4 KiB descriptor before compact");

    /* A live handle pins the extent's offset (and a dup of the file): compact
     * must refuse rather than strand it on the unlinked inode. */
    errno = 0;
    CHK(cfs_compact(c) == -1 && errno == EBUSY,
        "D17a: compact refuses while a flash handle is open (EBUSY)");
    uint8_t probe[PAGE_SZ];
    CHK(cfs_flash_read(f, 0, probe, sizeof probe) == (ssize_t)sizeof probe &&
        memcmp(probe, pat, sizeof pat) == 0,
        "D17a: the medium still works after the refusal");

    cfs_flash_close(f);   /* compact replaces the file the handle was dup'ed from */

    CHK(cfs_compact(c) == 0, "D17: cfs_compact on a non-XIP medium returns 0");
    cfs_close(c);

    c = cfs_open(compact_path, CFS_RDWR);
    CHK(c != NULL, "D17: the compacted container reopens");
    if (!c) { free(msnap); return; }
    f = cfs_flash_open(c, "imgn", 0);
    CHK(f != NULL, "D17: cfs_flash_open works after compact");
    if (f) {
        off_t new_off = 0;
        uint64_t nlen = 0;
        CHK(cfs_flash_extent(f, &efd, &new_off, &nlen) == 0 &&
            nlen == MEDIUM_SIZE,
            "D17: the extent is still the medium's size after compact");
        CHK((new_off % ERASE_SZ) == 0,
            "D17: the moved extent is still 4096-byte aligned");
        CHK(new_off != old_off,
            "D17: the orphan forced the extent to move");
        uint8_t got[PAGE_SZ];
        CHK(cfs_flash_read(f, 0, got, sizeof got) == (ssize_t)sizeof got &&
            memcmp(got, pat, sizeof pat) == 0,
            "D17: the pattern reads back byte-exact after compact");

        uint8_t *mbuf = malloc(MEDIUM_SIZE);
        CHK(mbuf && msnap &&
            cfs_flash_read(f, 0, mbuf, MEDIUM_SIZE) == (ssize_t)MEDIUM_SIZE &&
            memcmp(mbuf, msnap, MEDIUM_SIZE) == 0,
            "D17: every one of the 4 MiB of medium survived compact byte-for-byte");
        free(mbuf);

        uint8_t dafter[CFS_FLASH_DESC_SIZE];
        CHK(pread_full(efd, dafter, sizeof dafter,
                       (off_t)((uint64_t)new_off + nlen)) == 0 &&
            memcmp(dafter, dsnap, sizeof dsnap) == 0,
            "D17: the 4 KiB descriptor survived compact byte-for-byte");

        uint64_t ec_after = 0;
        CHK(cfs_flash_info(f, NULL, NULL, NULL, &ec_after, NULL) == 0 &&
            ec_after == ec_before,
            "D17: the erase count survives compact and the reopen");

        /* A normal file written after compact must land past the medium, not
         * on it: the reopened append_off has to include the moved extent. */
        uint8_t tail[512];
        fill_pat(tail, sizeof tail, 77);
        CHK(cfs_write(c, "after.bin", tail, sizeof tail) == 0,
            "D17: a normal file write after compact succeeds");
        uint8_t *mafter = malloc(MEDIUM_SIZE);
        CHK(mafter && msnap &&
            cfs_flash_read(f, 0, mafter, MEDIUM_SIZE) == (ssize_t)MEDIUM_SIZE &&
            memcmp(mafter, msnap, MEDIUM_SIZE) == 0,
            "D17: the post-compact file write did not touch the medium");
        free(mafter);

        cfs_flash_close(f);
    }
    free(msnap);
    cfs_close(c);
    unlink(compact_path);
}

/* ═══ F: creation error matrix ═══════════════════════════════════ */
static void test_create_errors(void) {
    fprintf(stderr, "[create] error matrix\n");
    unlink(err_path);

    CFS *c = cfs_create(err_path);
    CHK(c != NULL, "create: create a fresh container");
    if (c) {
        CfsFlashGeom g;
        unsigned flags = 0;
        CHK(cfs_flash_profile("nor", &g, &flags) == 0,
            "create: nor profile");
        g.size = MEDIUM_SIZE;
        errno = 0;
        CHK(cfs_flash_create(c, "dup0", &g, flags) == 0,
            "create: the first creation succeeds");
        errno = 0;
        CHK(cfs_flash_create(c, "dup0", &g, flags) == -1 && errno == EEXIST,
            "create: the same tag twice is refused with EEXIST");

        g.size = MEDIUM_SIZE - 1;   /* not a multiple of the 4096 erase */
        errno = 0;
        CHK(cfs_flash_create(c, "badsize", &g, flags) == -1 && errno == EINVAL,
            "create: a size that is not a multiple of the erase block is EINVAL");

        CfsFlashGeom eg;
        unsigned eflags = 0;
        CHK(cfs_flash_profile("emmc", &eg, &eflags) == 0 &&
            (eflags & CFS_FLASH_F_MANAGED),
            "create: the emmc profile carries CFS_FLASH_F_MANAGED");
        eg.size = MEDIUM_SIZE;
        errno = 0;
        CHK(cfs_flash_create(c, "emmc0", &eg, eflags) == -1 &&
            errno == EOPNOTSUPP,
            "create: a managed (emmc) medium is refused with EOPNOTSUPP");
        cfs_close(c);
    }

    /* A fresh container whose physical quota is below the medium size. */
    unlink(err2_path);
    c = cfs_create(err2_path);
    CHK(c != NULL, "create: create the quota-limited container");
    if (c) {
        CHK(cfs_set_physical_limit(c, MEDIUM_SIZE / 2) == 0,
            "create: set a physical quota below the medium size");
        CfsFlashGeom g;
        unsigned flags = 0;
        CHK(cfs_flash_profile("nor", &g, &flags) == 0,
            "create: nor profile for the quota case");
        g.size = MEDIUM_SIZE;
        errno = 0;
        int rc = cfs_flash_create(c, "nor0", &g, flags);
        CHK(rc == CFS_ENOSPC && errno == ENOSPC,
            "create: a quota below the medium returns CFS_ENOSPC");
        errno = 0;
        CfsFlash *f = cfs_flash_open(c, "nor0", 0);
        CHK(f == NULL && errno == ENOENT,
            "create: the refused medium was not recorded in the table");
        if (f) cfs_flash_close(f);
        cfs_close(c);
    }
    unlink(err_path);
    unlink(err2_path);
}

/* ═══ D19 + F: verify accepts a fresh flash container, and rejects
 *     damaged descriptors. ═════════════════════════════════════ */
static void test_verify_flash(void) {
    fprintf(stderr, "[D19] verify on a fresh flash container\n");
    unlink(verify_path);

    CFS *c = cfs_create(verify_path);
    CHK(c != NULL, "D19: create a fresh flash container");
    if (!c) return;
    CfsFlashGeom g;
    unsigned flags = 0;
    CHK(cfs_flash_profile("nor", &g, &flags) == 0, "D19: nor profile");
    g.size = MEDIUM_SIZE;
    errno = 0;
    CHK(cfs_flash_create(c, "nor0", &g, flags) == 0,
        "D19: create a fresh 4 MB medium");
    cfs_close(c);

    /* The report goes to a real temporary file, not tmpfile(): the suite
     * has to be able to read it back. */
    char rp[700];
    snprintf(rp, sizeof rp, "%s/verify.XXXXXX", scratch);
    int rfd = mkstemp(rp);
    CHK(rfd >= 0, "D19: create a real temp file for the verify report");
    FILE *rep = rfd >= 0 ? fdopen(rfd, "w+") : NULL;
    CHK(rep != NULL, "D19: open the report stream");
    if (rep) {
        errno = 0;
        int rc = cfs_verify(verify_path, CFS_VERIFY_DEEP, rep);
        CHK(rc == 0, "D19: cfs_verify(CFS_VERIFY_DEEP) accepts a fresh flash container");
        fflush(rep);
        CHK(fseek(rep, 0, SEEK_SET) == 0, "D19: rewind the report stream");
        char rb[16384];
        size_t rn = fread(rb, 1, sizeof rb - 1, rep);
        rb[rn] = 0;
        CHK(strstr(rb, "@flash") != NULL,
            "D19: the report names the @flash entry");
        char needle[64];
        snprintf(needle, sizeof needle, "%llu B",
                 (unsigned long long)MEDIUM_SIZE);
        CHK(strstr(rb, needle) != NULL,
            "D19: the report carries the medium's size");
        CHK(strstr(rb, "result: OK") != NULL,
            "D19: the report's result line says OK");
        fclose(rep);
    } else if (rfd >= 0) {
        close(rfd);
    }
    unlink(rp);

    /* ── F: verify rejects damaged descriptor copies ───────────── */
    unlink(verify_crc_path);
    unlink(verify_geom_path);
    CHK(copy_file(verify_path, verify_crc_path) == 0,
        "F: copy the container for the CRC corruption");
    CHK(copy_file(verify_path, verify_geom_path) == 0,
        "F: copy the container for the geometry corruption");

    uint8_t area[CFS_FLASH_DESC_SIZE];
    CHK(read_flash_desc(verify_crc_path, "nor0", area) == 0,
        "F: read the descriptor area of the CRC copy");
    area[CFS_FLASH_D_CRC] ^= 0xFF;
    area[CFS_FLASH_COPY_SIZE + CFS_FLASH_D_CRC] ^= 0xFF;
    CHK(write_flash_desc(verify_crc_path, "nor0", area) == 0,
        "F: corrupt both descriptor CRC fields");
    FILE *r1 = tmpfile();
    CHK(r1 != NULL, "F: a report stream for the CRC-corrupt verify");
    if (r1) {
        int n = cfs_verify(verify_crc_path, 0, r1);
        CHK(n > 0,
            "F: cfs_verify (non-deep) reports errors when both descriptor CRCs are broken");
        fclose(r1);
    }
    CFS *cc = cfs_open(verify_crc_path, CFS_RDONLY);
    CHK(cc != NULL,
        "F: the container still opens when both descriptor CRCs are broken");
    if (cc) {
        errno = 0;
        CfsFlash *bf = cfs_flash_open(cc, "nor0", 0);
        CHK(bf == NULL && errno == EIO,
            "F: cfs_flash_open rejects the CRC-broken medium with EIO");
        if (bf) cfs_flash_close(bf);
        cfs_close(cc);
    }

    /* A self-consistent copy whose geometry disagrees with the block span:
     * the CRC is recomputed, so only the cross-check can catch it. */
    CHK(read_flash_desc(verify_geom_path, "nor0", area) == 0,
        "F: read the descriptor area of the geometry copy");
    int ni = desc_newer(area);
    uint8_t *d = area + (size_t)ni * CFS_FLASH_COPY_SIZE;
    cfs_wr64(d + CFS_FLASH_D_SIZE, MEDIUM_SIZE - ERASE_SZ);
    cfs_wr32(d + CFS_FLASH_D_CRC, cfs_sb_crc32(d, CFS_FLASH_D_CRC));
    CHK(write_flash_desc(verify_geom_path, "nor0", area) == 0,
        "F: corrupt a geometry field and recompute the CRC");
    FILE *r2 = tmpfile();
    CHK(r2 != NULL, "F: a report stream for the geometry-corrupt verify");
    if (r2) {
        int n = cfs_verify(verify_geom_path, 0, r2);
        CHK(n > 0,
            "F: cfs_verify (non-deep) reports a geometry that disagrees with the span");
        fclose(r2);
    }
    CFS *cg = cfs_open(verify_geom_path, CFS_RDONLY);
    CHK(cg != NULL, "F: the container still opens with a bad geometry copy");
    if (cg) {
        errno = 0;
        CfsFlash *gf = cfs_flash_open(cg, "nor0", 0);
        CHK(gf == NULL && errno == EIO,
            "F: cfs_flash_open rejects the bad geometry with EIO");
        if (gf) cfs_flash_close(gf);
        cfs_close(cg);
    }

    unlink(verify_crc_path);
    unlink(verify_geom_path);
    unlink(verify_path);
}

/* Closing the container before its flash handles must be memory-safe (the
 * open-handle count is shared, not owned by the CFS struct) and the handle
 * must keep working through its own dup'd descriptor. */
static void test_handle_lifetime(void) {
    char p[600];
    snprintf(p, sizeof p, "%s/lifetime.cfs", scratch);
    unlink(p);
    fprintf(stderr, "[D20] handle lifetime across cfs_close\n");

    CFS *c = cfs_create(p);
    CHK(c != NULL, "D20: create a container");
    if (!c) return;
    CfsFlashGeom g;
    unsigned fl = 0;
    CHK(cfs_flash_profile("nor", &g, &fl) == 0, "D20: nor profile");
    g.size = MEDIUM_SIZE;
    CHK(cfs_flash_create(c, "life", &g, 0) == 0, "D20: create a medium");
    CfsFlash *f = cfs_flash_open(c, "life", 1);
    CHK(f != NULL, "D20: open a writable handle");
    cfs_close(c);
    uint8_t got[PAGE_SZ];
    memset(got, 0x00, sizeof got);
    errno = 0;
    CHK(f && cfs_flash_write(f, 0, got, sizeof got) == -1 && errno == EROFS,
        "D20: a writable handle refuses writes once its container is closed");
    errno = 0;
    CHK(f && cfs_flash_erase(f, 0, ERASE_SZ) == -1 && errno == EROFS,
        "D20: ... and refuses erase");
    CHK(f && cfs_flash_read(f, 0, got, sizeof got) == (ssize_t)sizeof got &&
        all_ff(got, sizeof got),
        "D20: the handle still reads after cfs_close");
    cfs_flash_close(f);
    unlink(p);
}

/* A descriptor whose sequence is about to wrap must be rewritten with fresh
 * low numbers; otherwise the stale copy stays numerically larger and wins on
 * every reopen, so updates stop persisting. */
static void test_seq_wrap(void) {
    char p[600];
    snprintf(p, sizeof p, "%s/wrap.cfs", scratch);
    unlink(p);
    fprintf(stderr, "[D21] descriptor sequence wraparound\n");

    CFS *c = cfs_create(p);
    CHK(c != NULL, "D21: create a container");
    if (!c) return;
    CfsFlashGeom g;
    unsigned fl = 0;
    CHK(cfs_flash_profile("nor", &g, &fl) == 0, "D21: nor profile");
    g.size = MEDIUM_SIZE;
    CHK(cfs_flash_create(c, "wrap", &g, 0) == 0, "D21: create a medium");
    CfsFlash *f = cfs_flash_open(c, "wrap", 1);
    CHK(f != NULL, "D21: open the medium");
    if (f) {
        CHK(cfs_flash_erase(f, 0, ERASE_SZ) == 0, "D21: one erase");
        cfs_flash_close(f);
    }
    cfs_close(c);

    /* Push both copies to the edge with valid CRCs. */
    uint8_t area[CFS_FLASH_DESC_SIZE];
    CHK(read_flash_desc(p, "wrap", area) == 0, "D21: read the descriptor");
    for (int copy = 0; copy < 2; copy++) {
        uint8_t *cp = area + (size_t)copy * CFS_FLASH_COPY_SIZE;
        cfs_wr32(cp + CFS_FLASH_D_SEQ,
                 copy == 0 ? 0xFFFFFFFDu : 0xFFFFFFFEu);
        /* The erase wrote only the other copy, so both must carry the count
         * the test expects the reader to see. */
        cfs_wr64(cp + CFS_FLASH_D_ECOUNT, 1);
        cfs_wr32(cp + CFS_FLASH_D_CRC, cfs_sb_crc32(cp, CFS_FLASH_D_CRC));
    }
    CHK(write_flash_desc(p, "wrap", area) == 0, "D21: install the near-wrap sequence");

    c = cfs_open(p, CFS_RDWR);
    CHK(c != NULL, "D21: reopen the container");
    if (!c) { unlink(p); return; }
    f = cfs_flash_open(c, "wrap", 1);
    CHK(f != NULL, "D21: reopen the medium");
    if (f) {
        uint64_t ec = 0;
        CHK(cfs_flash_info(f, NULL, NULL, NULL, &ec, NULL) == 0 && ec == 1,
            "D21: the near-wrap descriptor is read back");
        CHK(cfs_flash_erase(f, ERASE_SZ, ERASE_SZ) == 0,
            "D21: an erase crosses the wrap");
        cfs_flash_close(f);
    }
    cfs_close(c);

    CHK(read_flash_desc(p, "wrap", area) == 0, "D21: read the descriptor after the wrap");
    uint32_t s0 = desc_seq(area, 0), s1 = desc_seq(area, 1);
    CHK((s0 == 1 && s1 == 2) || (s0 == 2 && s1 == 1),
        "D21: both copies were reset to low sequence numbers");

    c = cfs_open(p, CFS_RDWR);
    CHK(c != NULL, "D21: reopen after the wrap");
    if (!c) { unlink(p); return; }
    f = cfs_flash_open(c, "wrap", 0);
    if (f) {
        uint64_t ec = 0;
        CHK(cfs_flash_info(f, NULL, NULL, NULL, &ec, NULL) == 0 && ec == 2,
            "D21: the erase count persisted through the reset");
        cfs_flash_close(f);
    }
    cfs_close(c);
    unlink(p);
}

int main(void) {
    setvbuf(stderr, NULL, _IONBF, 0);

    const char *tmp = getenv("TMPDIR");
    if (!tmp || !*tmp) tmp = "/tmp";
    snprintf(scratch, sizeof scratch, "%s/cfs_flash.XXXXXX", tmp);
    if (!mkdtemp(scratch)) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(cont_path, sizeof cont_path, "%s/flash.cfs", scratch);
    snprintf(compact_path, sizeof compact_path, "%s/compact.cfs", scratch);
    snprintf(err_path, sizeof err_path, "%s/errors.cfs", scratch);
    snprintf(err2_path, sizeof err2_path, "%s/quota.cfs", scratch);
    snprintf(verify_path, sizeof verify_path, "%s/verify.cfs", scratch);
    snprintf(verify_crc_path, sizeof verify_crc_path, "%s/verify-crc.cfs", scratch);
    snprintf(verify_geom_path, sizeof verify_geom_path, "%s/verify-geom.cfs", scratch);

    fprintf(stderr, "=== cfs_flash_test ===\n");
    test_medium();
    test_compact_nonxip();
    test_handle_lifetime();
    test_seq_wrap();
    test_create_errors();
    test_verify_flash();

    /* The suite leaves nothing behind. */
    unlink(cont_path);
    unlink(compact_path);
    unlink(err_path);
    unlink(err2_path);
    unlink(verify_path);
    unlink(verify_crc_path);
    unlink(verify_geom_path);
    if (rmdir(scratch) != 0)
        fprintf(stderr, "  (could not remove %s: %s)\n", scratch, strerror(errno));

    printf("\n=== %d failures ===\n", failed);
    return failed ? 1 : 0;
}
