/* cfs_fixA_test — regression tests for the write-path, merge-layer and
 * verifier defects found by the second independent review (2026-10-24).
 *
 * Each case fails on the code as it was and passes after its fix:
 *
 *   1. cfs_write()/cfs_block_write_impl() left the append cursor at the old
 *      inode-table position after appending a block; the @store flush inside
 *      cfs_sync() then wrote the pending slab over that block, and the
 *      container no longer opened.
 *   2. cfs_dedup_gc() swapped in the compacted @store but left pend_off at
 *      the old (larger) store size, so later writes referenced bytes past the
 *      new end: success returned, reads failed.
 *   3. dedup_pend_flush() cleared pend_n before store_append(); a refused
 *      append lost the bytes while the table already pointed at them.
 *   4. unlink()/rename() left the reference-table cache keyed by the old
 *      path, so a new entry under that name was read through the deleted
 *      file's table.
 *   5. cfs_dedup_write() kept using an inode pointer across a flush that
 *      reallocs c->inodes (heap-use-after-free).
 *   6. dedup_read() (and verify's deep cross-check) spun forever when a
 *      reference table stopped short of the inode's orig_size.
 *   7. rename() discarded unflushed reference-table edits (the flush looks
 *      the entry up by the path rename had just replaced).
 *   8. unlink() reported failure for a change that had already been applied
 *      (a nested sync committed it before the quota refusal).
 *   9. cfs_block_resize() silently ignored a shrink and returned 0.
 *  10. cfs_block_write() promised all-or-nothing but wrote the first 8MB
 *      segment of a request that ran past the end of the device.
 *  11. verify --deep reported an untouched sparse @block as corrupt.
 *  12. a zero pad of exactly BLOCK_CHUNK was packed with the write, producing
 *      a block larger than BLOCK_CHUNK.
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
#include <signal.h>
#include <sys/wait.h>

static int failures = 0;
#define CHECK(cond, ...) do { if (!(cond)) { failures++; \
    printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

#define DEV_CHUNK (8u << 20)

static void fill(uint8_t *b, size_t n, unsigned seed) {
    uint64_t s = (uint64_t)seed * 6364136223846793005ULL + 1442695040888963407ULL;
    for (size_t i = 0; i < n; i++) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        b[i] = (uint8_t)(s >> 32);
    }
}

static int read_matches(CFS *c, const char *path, const uint8_t *want, size_t n) {
    uint8_t *got = malloc(n ? n : 1);
    if (!got) return 0;
    ssize_t r = cfs_read(c, path, got, n, 0);
    int ok = r == (ssize_t)n && !memcmp(got, want, n);
    free(got);
    return ok;
}

/* ── minimal on-disk inode-table reader ───────────────────────
 * Independent of cfs.c (the same shape cfs_verify parses): a test that asked
 * the library to confirm what the library wrote would not catch a table the
 * library wrote wrong. */
static uint16_t rd16(const uint8_t *p) { return (uint16_t)p[0] | ((uint16_t)p[1] << 8); }
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }
static void wr64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

typedef struct {
    uint64_t orig_off;      /* absolute offset of this entry's orig_size field */
    uint64_t orig;
    uint32_t nblk;
    uint32_t max_blk_orig;
} TEntry;

static int find_inode(int fd, const char *want, TEntry *out) {
    uint8_t sb[CFS_SB_SIZE];
    if (pread(fd, sb, sizeof sb, 0) != (ssize_t)sizeof sb) return 0;
    if (memcmp(sb, "LIBCFS02", 8)) return 0;
    uint64_t io  = rd64(sb + 10);
    uint32_t isz = rd32(sb + 18);
    uint32_t nent = rd32(sb + 22);
    if (isz > (64u << 20)) return 0;
    uint8_t *t = malloc(isz ? isz : 1);
    if (!t) return 0;
    if (isz && pread(fd, t, isz, (off_t)io) != (ssize_t)isz) { free(t); return 0; }
    const uint8_t *p = t, *end = t + isz;
    int found = 0;
    for (uint32_t i = 0; i < nent && p + 24 <= end && !found; i++) {
        const uint8_t *start = p;
        uint64_t orig = rd64(p); p += 8;
        p += 8;                         /* mtime */
        p += 2;                         /* mode */
        uint16_t plen = rd16(p); p += 2;
        uint32_t nblk = rd32(p); p += 4;
        if ((size_t)(end - p) < (size_t)nblk * 16) break;
        uint32_t mx = 0;
        for (uint32_t b = 0; b < nblk; b++) {
            p += 8;                     /* offset */
            p += 4;                     /* comp_size */
            uint32_t o = rd32(p); p += 4;
            if (o > mx) mx = o;
        }
        if ((size_t)(end - p) < plen) break;
        if (plen == strlen(want) && !memcmp(p, want, plen)) {
            out->orig_off = io + (uint64_t)(size_t)(start - t);
            out->orig = orig;
            out->nblk = nblk;
            out->max_blk_orig = mx;
            found = 1;
        }
        p += plen;
    }
    free(t);
    return found;
}

/* Run fn() in a child under an alarm and report whether it returned 0.
 * A defect that spins (the read-loop hang) then shows up as a failed check
 * instead of wedging the whole suite. */
static int run_with_timeout(int (*fn)(void), int secs) {
    pid_t pid = fork();
    if (pid < 0) return 0;
    if (pid == 0) { alarm((unsigned)secs); _exit(fn()); }
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) return 0;
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

/* ═══ 1. append cursor collision ═══════════════════════════════ */
static void case_cursor_collision(void) {
    const char *path = "/tmp/fixa_cursor.cfs";
    unlink(path);
    CFS *c = cfs_create(path);
    CHECK(c != NULL, "cursor: create");
    if (!c) return;

    uint8_t a[1024], b[1024];
    uint8_t one = 'Z';
    fill(a, sizeof a, 11);
    fill(b, sizeof b, 12);

    CHECK(cfs_set_batch(c, 1) == 0, "cursor: batch on");
    CHECK(cfs_write(c, "/A", a, sizeof a) == 0, "cursor: write the 1KB file");
    /* Stages 1KB of @store bytes and leaves them pending. */
    CHECK(cfs_dedup_write(c, "/A", b, sizeof b, 0) == (ssize_t)sizeof b,
          "cursor: 1KB dedup write");
    /* A 1-byte plain write appends at the cursor; the sync that follows
     * flushes the pending slab through the same cursor. */
    CHECK(cfs_write(c, "/B", &one, 1) == 0, "cursor: write the 1B file");
    CHECK(cfs_set_batch(c, 0) == 0, "cursor: flush");
    cfs_close(c);

    c = cfs_open(path, CFS_RDONLY);
    CHECK(c != NULL, "cursor: the container still opens");
    if (c) {
        uint8_t got[sizeof a];
        memset(got, 0, sizeof got);
        CHECK(cfs_read(c, "/B", got, 1, 0) == 1 && got[0] == 'Z',
              "cursor: the 1-byte file reads back");
        CHECK(read_matches(c, "/A", b, sizeof b),
              "cursor: the dedup file reads back");
        cfs_close(c);
    }
    unlink(path);
}

/* The same defect on the device path: cfs_block_write()'s append pass writes
 * the new block at the cursor and used to leave the cursor there, so the
 * @store slab flushed by the following sync landed on top of it. */
static void case_cursor_collision_block(void) {
    const char *path = "/tmp/fixa_cursor_blk.cfs";
    unlink(path);
    CFS *c = cfs_create(path);
    CHECK(c != NULL, "cursor-blk: create");
    if (!c) return;

    uint8_t seed[16], tail[16], dfile[1024], efile[1024];
    fill(seed, sizeof seed, 13);
    fill(tail, sizeof tail, 14);
    fill(dfile, sizeof dfile, 15);
    fill(efile, sizeof efile, 16);

    CHECK(cfs_block_resize(c, 1u << 20) == 0, "cursor-blk: declare the device");
    CHECK(cfs_block_write(c, seed, sizeof seed, 0) == 0, "cursor-blk: seed block 0");
    /* Create @store first: with it already on disk, the flush below takes the
     * plain append path instead of going through store_ensure's sync (which
     * would recompute the cursor and hide the defect). */
    CHECK(cfs_write(c, "/E", efile, sizeof efile) == 0, "cursor-blk: create @store");
    CHECK(cfs_set_batch(c, 1) == 0, "cursor-blk: batch on");
    CHECK(cfs_write(c, "/D", dfile, sizeof dfile) == 0, "cursor-blk: stage 1KB of @store");
    /* Non-zero offset on a non-empty device: the append pass, not the
     * whole-file shortcut. */
    CHECK(cfs_block_write(c, tail, sizeof tail, 4096) == 0, "cursor-blk: append a block");
    CHECK(cfs_set_batch(c, 0) == 0, "cursor-blk: flush");
    cfs_close(c);

    c = cfs_open(path, CFS_RDONLY);
    CHECK(c != NULL, "cursor-blk: the container still opens");
    if (c) {
        uint8_t got[16];
        memset(got, 0, sizeof got);
        CHECK(cfs_block_read(c, got, sizeof got, 4096) == (ssize_t)sizeof got &&
              !memcmp(got, tail, sizeof got),
              "cursor-blk: the appended block reads back");
        CHECK(read_matches(c, "/D", dfile, sizeof dfile),
              "cursor-blk: the dedup file reads back");
        cfs_close(c);
    }
    unlink(path);
}

/* ═══ 2. gc leaves pend_off stale ═════════════════════════════ */
static void case_gc_cursor(void) {
    const char *path = "/tmp/fixa_gc.cfs";
    unlink(path);
    CFS *c = cfs_create(path);
    CHECK(c != NULL, "gc: create");
    if (!c) return;

    uint8_t big[8192], small[2048], patch[1024];
    fill(big, sizeof big, 21);
    fill(small, sizeof small, 22);
    fill(patch, sizeof patch, 23);

    CHECK(cfs_write(c, "/big", big, sizeof big) == 0, "gc: write 8K");
    CHECK(cfs_write(c, "/small", small, sizeof small) == 0, "gc: write 2K");
    CHECK(cfs_unlink(c, "/big") == 0, "gc: unlink the 8K file");

    CfsDedupGcStats gs;
    memset(&gs, 0, sizeof gs);
    CHECK(cfs_dedup_gc(c, &gs) == 0, "gc: compaction runs");
    CHECK(gs.store_after == sizeof small, "gc: the store shrank to the live 2K");

    /* The store just got shorter; the pending cursor has to follow it. */
    CHECK(cfs_dedup_write(c, "/small", patch, sizeof patch, 0) == (ssize_t)sizeof patch,
          "gc: the post-compaction write reports success");
    cfs_close(c);

    c = cfs_open(path, CFS_RDONLY);
    CHECK(c != NULL, "gc: reopen");
    if (c) {
        uint8_t got[2048];
        memset(got, 0, sizeof got);
        CHECK(cfs_read(c, "/small", got, sizeof got, 0) == (ssize_t)sizeof got,
              "gc: the file reads back after the post-compaction write");
        CHECK(!memcmp(got, patch, sizeof patch),
              "gc: the post-compaction write landed");
        CHECK(!memcmp(got + sizeof patch, small + sizeof patch,
                      sizeof small - sizeof patch),
              "gc: the rest of the file survived");
        cfs_close(c);
    }
    unlink(path);
}

/* ═══ 3. pending flush drops data on failure ══════════════════ */
static void case_pend_failure(void) {
    const char *path = "/tmp/fixa_pend.cfs";
    uint8_t buf[2048];
    fill(buf, sizeof buf, 31);

    /* (a) A refused flush must not throw the bytes away: once the quota
     *     allows it, the next sync has to land them. */
    unlink(path);
    CFS *c = cfs_create(path);
    CHECK(c != NULL, "pend: create");
    if (!c) return;
    CHECK(cfs_set_batch(c, 1) == 0, "pend: batch on");
    CHECK(cfs_write(c, "/F", buf, sizeof buf) == 0, "pend: batch write 2K");
    CHECK(cfs_set_physical_limit(c, cfs_physical_used(c)) == 0, "pend: tighten the quota");
    CHECK(cfs_finalise(c) != 0, "pend: the flush is refused");
    CHECK(cfs_set_physical_limit(c, 0) == 0, "pend: lift the quota");
    CHECK(cfs_set_batch(c, 0) == 0, "pend: the retry succeeds");
    CHECK(read_matches(c, "/F", buf, sizeof buf),
          "pend: the retry lands the bytes the refused flush kept");
    {
        CfsStat st;
        CHECK(cfs_stat(c, "/F", &st) == 0 && st.size == sizeof buf,
              "pend: the inode describes the file");
    }
    cfs_close(c);

    /* (b) Closing after a refused flush must not leave the container
     *     pointing at @store bytes that were never written. */
    unlink(path);
    c = cfs_create(path);
    CHECK(c != NULL, "pend: recreate");
    if (!c) return;
    CHECK(cfs_set_batch(c, 1) == 0, "pend: batch on (2)");
    CHECK(cfs_write(c, "/G", buf, sizeof buf) == 0, "pend: batch write 2K (2)");
    CHECK(cfs_set_physical_limit(c, cfs_physical_used(c)) == 0, "pend: tighten the quota (2)");
    cfs_close(c);          /* the only sync attempt fails; it must not commit */
    {
        FILE *nul = fopen("/dev/null", "w");
        int errs = cfs_verify(path, 0, nul ? nul : stderr);
        if (nul) fclose(nul);
        CHECK(errs == 0, "pend: the failed close left no dangling references (verify: %d)", errs);
    }
    unlink(path);
}

/* ═══ 4. unlink/rename leaves the table cache stale ═══════════ */
static void case_rename_cache(void) {
    const char *path = "/tmp/fixa_cache.cfs";
    unlink(path);
    CFS *c = cfs_create(path);
    CHECK(c != NULL, "cache: create");
    if (!c) return;

    uint8_t a[2048], b[1024];
    fill(a, sizeof a, 41);
    fill(b, sizeof b, 42);

    CHECK(cfs_write(c, "/A", a, sizeof a) == 0, "cache: write A (2K)");
    /* The cache has to be populated *after* the second write: writing a new
     * file drops it.  Reading A is what leaves the handle caching A's table
     * under the name "A". */
    CHECK(cfs_write(c, "/B", b, sizeof b) == 0, "cache: write B (1K)");
    CHECK(read_matches(c, "/A", a, sizeof a), "cache: read A (loads its table)");
    CHECK(cfs_unlink(c, "/A") == 0, "cache: unlink A");
    CHECK(cfs_rename(c, "/B", "/A") == 0, "cache: rename B to A");

    CHECK(read_matches(c, "/A", b, sizeof b),
          "cache: reading the new A returns B's content, not the deleted file's");
    {
        CfsStat st;
        CHECK(cfs_stat(c, "/A", &st) == 0 && st.size == sizeof b,
              "cache: the new A has B's size");
    }
    cfs_close(c);
    unlink(path);
}

/* ═══ 5. cfs_dedup_write use-after-free ═══════════════════════ */
static void case_dedup_uaf(void) {
    const char *path = "/tmp/fixa_uaf.cfs";
    unlink(path);
    CFS *c = cfs_create(path);
    CHECK(c != NULL, "uaf: create");
    if (!c) return;

    uint8_t a[2048], b[4096];
    fill(a, sizeof a, 51);
    fill(b, sizeof b, 52);

    CHECK(cfs_set_batch(c, 1) == 0, "uaf: batch on");
    CHECK(cfs_write(c, "/A", a, sizeof a) == 0, "uaf: write the 2K file");

    /* One call does all three: the range-match check flushes the pending
     * store bytes (creating @store and reallocating c->inodes), the emit loop
     * stages the replacement, and then the entry's size is extended.  On the
     * old code the extent was written through the pre-realloc pointer. */
    CHECK(cfs_dedup_write(c, "/A", b, sizeof b, 0) == (ssize_t)sizeof b,
          "uaf: the 4K overwrite reports success");
    {
        CfsStat st;
        memset(&st, 0, sizeof st);
        CHECK(cfs_stat(c, "/A", &st) == 0 && st.size == sizeof b,
              "uaf: the live inode has the extended size (%llu)",
              (unsigned long long)st.size);
    }
    CHECK(cfs_set_batch(c, 0) == 0, "uaf: sync");
    CHECK(read_matches(c, "/A", b, sizeof b), "uaf: the extended file reads back");
    cfs_close(c);
    unlink(path);
}

/* ═══ 6. a short reference table must not spin ════════════════ */
static CFS *spin_cfs;         /* for the forked child */
static int spin_read_rc(void) {
    uint8_t buf[64];
    ssize_t r = cfs_read(spin_cfs, "/A", buf, sizeof buf, 4096);
    return r < 0 ? 0 : 1;     /* fixed: -1 at once; old: never returns */
}
static const char *spin_verify_path;
static int spin_verify_rc(void) {
    FILE *nul = fopen("/dev/null", "w");
    if (!nul) return 1;
    (void)cfs_verify(spin_verify_path, CFS_VERIFY_DEEP, nul);
    fclose(nul);
    return 0;                 /* fixed: returns; old: never returns */
}

static void case_short_table(void) {
    const char *path = "/tmp/fixa_short.cfs";
    unlink(path);
    CFS *c = cfs_create(path);
    CHECK(c != NULL, "short: create");
    if (!c) return;

    uint8_t a[4096];
    fill(a, sizeof a, 61);
    CHECK(cfs_write(c, "/A", a, sizeof a) == 0, "short: write a 4K dedup file");
    cfs_close(c);

    /* Craft the defect: the inode says 8K, the reference table 4K.  A read
     * that reaches the end of the table lands in the hole branch at exactly
     * logical_size, where the old next-tuple search returned the current
     * offset and the loop never advanced. */
    int fd = open(path, O_RDWR);
    CHECK(fd >= 0, "short: reopen the container file");
    if (fd < 0) { unlink(path); return; }
    TEntry te;
    int ok = find_inode(fd, "/A", &te);
    CHECK(ok && te.orig == sizeof a, "short: found the inode in the table");
    if (ok) {
        uint8_t v[8];
        wr64(v, 2 * sizeof a);
        CHECK(pwrite(fd, v, sizeof v, (off_t)te.orig_off) == (ssize_t)sizeof v,
              "short: patched orig_size");
    }
    close(fd);

    c = cfs_open(path, CFS_RDONLY);
    CHECK(c != NULL, "short: the crafted container opens");
    if (c) {
        spin_cfs = c;
        CHECK(run_with_timeout(spin_read_rc, 5),
              "short: a read past the table's end returns instead of spinning");
        cfs_close(c);
    }
    spin_verify_path = path;
    CHECK(run_with_timeout(spin_verify_rc, 10),
          "short: verify --deep returns instead of spinning");
    unlink(path);
}

/* ═══ 7. rename loses unflushed table edits ═══════════════════ */
static void case_rename_dirty(void) {
    const char *path = "/tmp/fixa_rendirty.cfs";
    unlink(path);
    CFS *c = cfs_create(path);
    CHECK(c != NULL, "ren-dirty: create");
    if (!c) return;

    uint8_t a[4096], patch[1024];
    fill(a, sizeof a, 71);
    fill(patch, sizeof patch, 72);

    CHECK(cfs_write(c, "/A", a, sizeof a) == 0, "ren-dirty: write 4K");
    CHECK(cfs_dedup_write(c, "/A", patch, sizeof patch, 100) == (ssize_t)sizeof patch,
          "ren-dirty: in-place 1K write (no sync)");
    CHECK(cfs_rename(c, "/A", "/B") == 0, "ren-dirty: rename to B");

    {
        uint8_t got[1024];
        memset(got, 0, sizeof got);
        CHECK(cfs_read(c, "/B", got, sizeof got, 100) == (ssize_t)sizeof got,
              "ren-dirty: read the renamed file");
        CHECK(!memcmp(got, patch, sizeof patch),
              "ren-dirty: the unflushed edit survived the rename");
    }
    cfs_close(c);
    unlink(path);
}

/* ═══ 8. unlink reports failure but applies the change ═══════ */
static void case_unlink_failure(void) {
    const char *path = "/tmp/fixa_unlink.cfs";
    unlink(path);
    CFS *c = cfs_create(path);
    CHECK(c != NULL, "unlink: create");
    if (!c) return;

    uint8_t buf[1024];
    fill(buf, sizeof buf, 81);

    CHECK(cfs_set_batch(c, 1) == 0, "unlink: batch on");
    CHECK(cfs_write(c, "/U", buf, sizeof buf) == 0, "unlink: write 1K");
    CHECK(cfs_set_physical_limit(c, cfs_physical_used(c)) == 0, "unlink: tighten the quota");
    CHECK(cfs_unlink(c, "/U") != 0, "unlink: the refusal is reported");

    /* Whatever the return value said, the change must not have been applied. */
    CHECK(cfs_set_physical_limit(c, 0) == 0, "unlink: lift the quota");
    CHECK(cfs_set_batch(c, 0) == 0, "unlink: flush");
    cfs_close(c);

    c = cfs_open(path, CFS_RDONLY);
    CHECK(c != NULL, "unlink: reopen");
    if (c) {
        CfsStat st;
        CHECK(cfs_stat(c, "/U", &st) == 0,
              "unlink: a refused unlink did not delete the file");
        cfs_close(c);
    }
    unlink(path);
}

/* ═══ 9. resize is grow-only and says so ═════════════════════ */
static void case_resize_shrink(void) {
    const char *path = "/tmp/fixa_resize.cfs";
    unlink(path);
    CFS *c = cfs_create(path);
    CHECK(c != NULL, "resize: create");
    if (!c) return;

    CHECK(cfs_block_resize(c, 1u << 20) == 0, "resize: grow to 1MiB");
    CHECK(cfs_block_resize(c, 1u << 21) == 0, "resize: grow to 2MiB");
    CHECK(cfs_block_resize(c, 1u << 20) != 0, "resize: a shrink is refused");
    CHECK(cfs_block_size(c) == (1u << 21), "resize: the capacity is unchanged");
    cfs_close(c);
    unlink(path);
}

/* ═══ 10. cfs_block_write is all-or-nothing ══════════════════ */
static void case_block_write_atomic(void) {
    const char *path = "/tmp/fixa_bwrite.cfs";
    unlink(path);
    CFS *c = cfs_create(path);
    CHECK(c != NULL, "bwrite: create");
    if (!c) return;

    const uint64_t cap = 10u << 20;
    CHECK(cfs_block_resize(c, cap) == 0, "bwrite: declare 10MiB");

    /* Starts inside the device and ends past it, and straddles an 8MB split
     * boundary: the old short-write wrapper landed the first 2MiB. */
    size_t n = 6u << 20;
    uint8_t *buf = malloc(n);
    if (!buf) { cfs_close(c); unlink(path); return; }
    fill(buf, n, 91);
    CHECK(cfs_block_write(c, buf, n, 6u << 20) != 0,
          "bwrite: a request past the end of the device is refused");
    {
        uint8_t probe[4096];
        memset(probe, 0xAA, sizeof probe);
        CHECK(cfs_block_read(c, probe, sizeof probe, 6u << 20) == (ssize_t)sizeof probe,
              "bwrite: read back after the refused write");
        int zero = 1;
        for (size_t i = 0; i < sizeof probe; i++) if (probe[i]) zero = 0;
        CHECK(zero, "bwrite: the refused write landed nothing");
    }
    free(buf);
    cfs_close(c);
    unlink(path);
}

/* ═══ 11. untouched sparse device verifies clean ═════════════ */
static void case_sparse_verify(void) {
    const char *path = "/tmp/fixa_sparse.cfs";
    unlink(path);
    CFS *c = cfs_create(path);
    CHECK(c != NULL, "sparse: create");
    if (!c) return;
    /* Legal: a device of declared capacity with no writes.  Reads return
     * zeros; there is nothing wrong with the container. */
    CHECK(cfs_block_resize(c, 16u << 20) == 0, "sparse: declare 16MiB");
    cfs_close(c);

    {
        FILE *nul = fopen("/dev/null", "w");
        int errs = cfs_verify(path, CFS_VERIFY_DEEP, nul ? nul : stderr);
        if (nul) fclose(nul);
        CHECK(errs == 0, "sparse: verify --deep reports no errors (%d)", errs);
    }
    unlink(path);
}

/* ═══ 12. a block never exceeds BLOCK_CHUNK ══════════════════ */
static void case_block_chunk(void) {
    const char *path = "/tmp/fixa_chunk.cfs";
    unlink(path);
    CFS *c = cfs_create(path);
    CHECK(c != NULL, "chunk: create");
    if (!c) return;
    CHECK(cfs_block_resize(c, 32u << 20) == 0, "chunk: declare 32MiB");

    uint8_t one = 0x42;
    CHECK(cfs_block_write(c, &one, 1, 0) == 0, "chunk: 1 byte at 0");
    /* The gap to this byte is exactly BLOCK_CHUNK: the old `pad > CHUNK`
     * test packed the pad and the byte into one 8MiB+1 block. */
    CHECK(cfs_block_write(c, &one, 1, 1 + DEV_CHUNK) == 0,
          "chunk: 1 byte just past an 8MiB gap");
    cfs_close(c);

    int fd = open(path, O_RDONLY);
    CHECK(fd >= 0, "chunk: open the container file");
    if (fd >= 0) {
        TEntry te;
        int ok = find_inode(fd, "@block", &te);
        CHECK(ok, "chunk: found @block");
        CHECK(ok && te.max_blk_orig <= DEV_CHUNK,
              "chunk: no block exceeds the 8MiB chunk (largest %u)",
              ok ? te.max_blk_orig : 0u);
        CHECK(ok && te.nblk >= 2, "chunk: the full pad became its own block");
        close(fd);
    }
    unlink(path);
}

int main(void) {
    printf("[1] an append leaves the cursor for the pending store flush\n");
    case_cursor_collision();
    case_cursor_collision_block();
    printf("[2] gc compaction moves the pending store cursor\n");
    case_gc_cursor();
    printf("[3] a refused pending flush keeps its bytes\n");
    case_pend_failure();
    printf("[4] unlink/rename drop the reference-table cache\n");
    case_rename_cache();
    printf("[5] cfs_dedup_write across an inode-array realloc\n");
    case_dedup_uaf();
    printf("[6] a reference table shorter than the inode\n");
    case_short_table();
    printf("[7] rename keeps unflushed table edits\n");
    case_rename_dirty();
    printf("[8] a failed unlink applies nothing\n");
    case_unlink_failure();
    printf("[9] resize is grow-only\n");
    case_resize_shrink();
    printf("[10] cfs_block_write is all-or-nothing\n");
    case_block_write_atomic();
    printf("[11] an untouched sparse device verifies clean\n");
    case_sparse_verify();
    printf("[12] a zero pad of BLOCK_CHUNK stays out of the block\n");
    case_block_chunk();
    printf(failures ? "=== %d FAILURES ===\n" : "=== 0 failures ===\n", failures);
    return failures ? 1 : 0;
}
