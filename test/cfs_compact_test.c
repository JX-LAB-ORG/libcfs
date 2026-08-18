#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../cfs.h"

static int failures = 0;
#define T(c, msg) do { if (!(c)) { fprintf(stderr, "FAIL: %s (errno=%d)\n", msg, errno); failures++; } \
                       else { fprintf(stderr, "  OK: %s\n", msg); } } while(0)

int main(void) {
    setvbuf(stderr, NULL, _IONBF, 0);

    /* ──────────── compact basic ─────────────────────────────── */
    fprintf(stderr, "=== Compact Basic ===\n");
    unlink("/tmp/test_compact.cfs");

    /* Create container with files, overwrite some to create orphans */
    CFS *c = cfs_create("/tmp/test_compact.cfs");
    T(c != NULL, "create");

    uint8_t d1[512]; for (int i = 0; i < 512; i++) d1[i] = (uint8_t)(i & 0xFF);
    T(cfs_add_file(c, "file1.bin", d1, 512) == 0, "add file1");
    T(cfs_add_file(c, "file2.bin", "hello world", 11) == 0, "add file2");
    T(cfs_add_file(c, "file3.bin", "goodbye", 7) == 0, "add file3");
    T(cfs_finalise(c) == 0, "finalise");

    /* Overwrite file2 to create orphan */
    T(cfs_write(c, "file2.bin", "NEW CONTENT HERE", 17) == 0, "overwrite file2");

    /* Get file sizes before compact */
    struct stat st;
    stat("/tmp/test_compact.cfs", &st);
    off_t before = st.st_size;
    fprintf(stderr, "  before compact: %lld bytes\n", (long long)before);

    /* Compact */
    T(cfs_compact(c) == 0, "compact");

    stat("/tmp/test_compact.cfs", &st);
    off_t after = st.st_size;
    fprintf(stderr, "  after compact: %lld bytes\n", (long long)after);
    T(after <= before, "compact reduced size");

    /* Verify all files intact */
    size_t sz;
    void *b1 = cfs_read_all(c, "file1.bin", &sz);
    T(b1 && sz == 512 && !memcmp(b1, d1, 512), "file1 intact");
    free(b1);

    void *b2 = cfs_read_all(c, "file2.bin", &sz);
    T(b2 && sz == 17 && !memcmp(b2, "NEW CONTENT HERE", 17), "file2 (new) intact");
    free(b2);

    void *b3 = cfs_read_all(c, "file3.bin", &sz);
    T(b3 && sz == 7 && !memcmp(b3, "goodbye", 7), "file3 intact");
    free(b3);

    /* Verify directory listing */
    CfsDirEntry ents[8];
    int n = cfs_ls(c, "", ents, 8);
    T(n == 3, "ls count=3 after compact");
    cfs_close(c);

    /* Reopen — verify persistent */
    c = cfs_open("/tmp/test_compact.cfs", CFS_RDONLY);
    T(c != NULL, "reopen after compact");
    b1 = cfs_read_all(c, "file1.bin", &sz);
    T(b1 && sz == 512, "reopen file1 size ok");
    free(b1);
    cfs_close(c);
    unlink("/tmp/test_compact.cfs");

    /* ──────────── unpack test ────────────────────────────────── */
    fprintf(stderr, "\n=== Unpack ===\n");
    c = cfs_create("/tmp/test_unpack.cfs");
    T(c != NULL, "create for unpack");

    uint8_t ud[2048];
    for (int i = 0; i < 2048; i++) ud[i] = (uint8_t)((i * 13 + 7) & 0xFF);
    T(cfs_add_file(c, "docs/deep/readme.txt", "Hello docs\n", 11) == 0, "add deep file");
    T(cfs_add_file(c, "data.bin", ud, 2048) == 0, "add data.bin");
    T(cfs_finalise(c) == 0, "finalise unpack");
    cfs_close(c);

    c = cfs_open("/tmp/test_unpack.cfs", CFS_RDONLY);
    T(c != NULL, "reopen for unpack");

    /* Unpack to /tmp */
    system("rm -rf /tmp/cfs_unpack_test");
    T(cfs_unpack(c, "docs/deep/readme.txt", "/tmp/cfs_unpack_test/docs/deep/readme.txt") == 0, "unpack deep file");
    T(cfs_unpack(c, "data.bin", "/tmp/cfs_unpack_test/data.bin") == 0, "unpack data.bin");

    /* Verify unpacked files */
    FILE *f = fopen("/tmp/cfs_unpack_test/docs/deep/readme.txt", "r");
    T(f != NULL, "unpacked file exists");
    if (f) {
        char buf[64];
        size_t nr = fread(buf, 1, 64, f);
        T(nr == 11 && !memcmp(buf, "Hello docs\n", 11), "unpacked content match");
        fclose(f);
    }
    f = fopen("/tmp/cfs_unpack_test/data.bin", "rb");
    T(f != NULL, "unpacked data.bin exists");
    if (f) {
        uint8_t buf2[2048];
        size_t nr = fread(buf2, 1, 2048, f);
        T(nr == 2048 && !memcmp(buf2, ud, 2048), "unpacked 2KB match");
        fclose(f);
    }
    system("rm -rf /tmp/cfs_unpack_test");
    cfs_close(c);
    unlink("/tmp/test_unpack.cfs");

    fprintf(stderr, "\n=== %d failures ===\n", failures);
    return failures ? 1 : 0;
}
