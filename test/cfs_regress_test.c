/* cfs_regress_test — the four write-path defects found on 2026-10-24, each
 * as a case that fails on the code as it was and passes now.
 *
 *   1. truncate recompressed the last kept block and wrote it back at the old
 *      offset even when it had grown, running over whatever followed.  For
 *      @block the follower is another file's reference table, and the whole
 *      container stopped opening while truncate returned success.
 *   2. a write overlapping more than PEND_MAX small blocks walked off the
 *      fixed pending array (segfault at 130 blocks).
 *   3. cfs_read_all() took the file size from the inode entry *after*
 *      cfs_read(), which flushes pending merge bytes and reallocs the inode
 *      array — a use-after-free that made a just-written file "unreadable".
 *   4. truncate compressed the prefix in a RAW container, breaking the
 *      container's own invariant and making the block unwritable afterwards.
 */
#include "../cfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;
#define CHECK(cond, ...) do { if (!(cond)) { failures++; \
    printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

/* Hex-dump shaped data: 32 uppercase characters per line.  That is the shape
 * that makes a prefix compress *larger* than the block it came from. */
static void fill_hex(uint8_t *b, size_t n, int seed) {
    unsigned s = (unsigned)seed * 7919u + 12345u;
    for (size_t i = 0; i < n; i++) {
        s = s * 1103515245u + 12345u;
        b[i] = (uint8_t)"0123456789ABCDEF"[s >> 28];
        if ((i % 33) == 32) b[i] = '\n';
    }
}

static void case_truncate_growth(int raw) {
    const char *path = raw ? "/tmp/reg_trunc_raw.cfs" : "/tmp/reg_trunc.cfs";
    unlink(path);
    CFS *c = cfs_create(path);
    CHECK(c != NULL, "truncate: create");
    if (!c) return;
    if (raw && cfs_set_raw(c) != 0) CHECK(0, "truncate: set raw");

    size_t n = 4u << 20;
    CHECK(cfs_block_resize(c, n + (1u << 20)) == 0, "truncate: declare the device");
    uint8_t *dev = malloc(n), *side = malloc(4096);
    fill_hex(dev, n, 1);
    memset(side, 'S', 4096);
    CHECK(cfs_block_write(c, dev, n, 0) == 0, "truncate: write device");
    CHECK(cfs_write(c, "/side", side, 4096) == 0, "truncate: write neighbour");

    /* Cut at many points: whether the surviving prefix grows is a property
     * of the content, so sweeping is what makes this a regression test
     * rather than a test of one magic offset. */
    int bad = 0;
    for (size_t cut = n - 1; cut > n - 4096 * 64; cut -= 997) {
        if (cfs_truncate(c, "@block", cut) != 0) { bad++; break; }
        size_t got = 0;
        void *back = cfs_read_all(c, "/side", &got);
        if (!back || got != 4096 || memcmp(back, side, 4096)) { bad++; free(back); break; }
        free(back);
        /* The device must still read back what is left of it. */
        uint8_t *chk = malloc(cut ? cut : 1);
        if (!chk) { bad++; break; }
        if (cfs_block_read(c, chk, cut, 0) != (ssize_t)cut) bad++;
        else if (memcmp(chk, dev, cut)) bad++;
        free(chk);
        if (bad) break;
    }
    CHECK(bad == 0, "truncate: %s container survives cutting the device", raw ? "raw" : "compressed");

    /* RAW invariant: a block rewritten by truncate must still be writable. */
    if (raw) {
        uint8_t patch[256];
        memset(patch, 0x11, sizeof patch);
        size_t off = (n / 2) - 4096;
        int prc = cfs_block_write(c, patch, sizeof patch, (off_t)off);
        uint8_t back[256];
        memset(back, 0, sizeof back);
        cfs_block_read(c, back, sizeof back, (off_t)off);
        CHECK(prc == 0 && back[0] == 0x11, "truncate: raw block still writable after a cut");
    }
    free(dev); free(side);
    cfs_close(c);
    unlink(path);
}

static void case_pend_overflow(void) {
    unlink("/tmp/reg_pend.cfs");
    CFS *c = cfs_create("/tmp/reg_pend.cfs");
    CHECK(c != NULL, "pend: create");
    if (!c) return;
    CHECK(cfs_block_resize(c, 1u << 20) == 0, "pend: declare the device");
    /* Many small blocks: one byte written every 200 bytes, each becoming its
     * own block.  PEND_MAX is 128, so this crosses the old bound. */
    const size_t nb = 200;
    uint8_t one = 0x5A;
    int ok = 1;
    for (size_t i = 0; i < nb && ok; i++)
        if (cfs_block_write(c, &one, 1, (off_t)(i * 200)) != 0) ok = 0;
    /* Now one write over all of them, with content that will not shrink. */
    size_t span = nb * 200;
    uint8_t *big = malloc(span);
    fill_hex(big, span, 7);
    if (ok && cfs_block_write(c, big, span, 0) != 0) ok = 0;
    if (ok) {
        uint8_t *back = malloc(span);
        if (!back || cfs_block_read(c, back, span, 0) != (ssize_t)span ||
            memcmp(back, big, span)) ok = 0;
        free(back);
    }
    CHECK(ok, "pend: a write spanning %zu small blocks", nb);
    free(big);
    cfs_close(c);
    unlink("/tmp/reg_pend.cfs");
}

static void case_batch_read(void) {
    unlink("/tmp/reg_batch.cfs");
    CFS *c = cfs_create("/tmp/reg_batch.cfs");
    CHECK(c != NULL, "batch: create");
    if (!c) return;
    cfs_set_batch(c, 1);
    size_t n = 5u << 20;
    uint8_t *a = malloc(n), *b = malloc(n);
    fill_hex(a, n, 2); fill_hex(b, n, 3);
    CHECK(cfs_write(c, "/A", a, n) == 0, "batch: write A");
    CHECK(cfs_write(c, "/B", b, n) == 0, "batch: write B");
    /* Read before any sync: this is what used to return NULL or wrong bytes. */
    size_t got = 0;
    void *back = cfs_read_all(c, "/B", &got);
    CHECK(back && got == n && memcmp(back, b, n) == 0, "batch: first read sees the write");
    free(back);
    cfs_set_batch(c, 0);
    cfs_close(c);
    /* And it survives the close. */
    c = cfs_open("/tmp/reg_batch.cfs", CFS_RDONLY);
    got = 0;
    back = c ? cfs_read_all(c, "/B", &got) : NULL;
    CHECK(back && got == n && memcmp(back, b, n) == 0, "batch: reopen sees the write");
    free(back);
    if (c) cfs_close(c);
    free(a); free(b);
    unlink("/tmp/reg_batch.cfs");
}

int main(void) {
    printf("[r1] truncate recompressing a prefix that grew\n");
    case_truncate_growth(0);
    printf("[r2] truncate in a RAW container\n");
    case_truncate_growth(1);
    printf("[r3] a write spanning more blocks than the pending table had slots\n");
    case_pend_overflow();
    printf("[r4] reading a batch-written file before it is flushed\n");
    case_batch_read();
    printf(failures ? "=== %d FAILURES ===\n" : "=== 0 failures ===\n", failures);
    return failures ? 1 : 0;
}
