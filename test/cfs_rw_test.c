#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "../cfs.h"

static int failures = 0;
#define T(c, msg) do { if (!(c)) { fprintf(stderr, "FAIL: %s\n", msg); failures++; } \
                       else { fprintf(stderr, "  OK: %s\n", msg); } } while(0)

int main(void) {
    setvbuf(stderr, NULL, _IONBF, 0);
    fprintf(stderr, "=== cfs_write ===\n");

    /* Build a .cfs from scratch, then reopen and write into it */

    /* Phase 1: create + add_file + finalise */
    CFS *c = cfs_create("/tmp/test_rw.cfs");
    T(c != NULL, "cfs_create");
    T(cfs_add_file(c, "README", "Hello CFS!\n", 11) == 0, "add_file README");
    T(cfs_add_file(c, "data/numbers.bin", "\x00\x01\x02\x03\x04\x05\x06\x07", 8) == 0, "add_file data/numbers.bin");
    T(cfs_finalise(c) == 0, "finalise");
    cfs_close(c);

    /* Phase 2: reopen RDWR, write more files */
    c = cfs_open("/tmp/test_rw.cfs", CFS_RDWR);
    T(c != NULL, "reopen RDWR");

    T(cfs_write(c, "hello.txt", "Hello World!\n", 13) == 0, "write hello.txt");
    T(cfs_write(c, "lorem.txt", "Lorem ipsum dolor sit amet.", 26) == 0, "write lorem.txt");

    /* Overwrite an existing file */
    T(cfs_write(c, "README", "Updated readme!\n", 16) == 0, "overwrite README");

    cfs_close(c);

    /* Phase 3: reopen RO, verify all files */
    c = cfs_open("/tmp/test_rw.cfs", CFS_RDONLY);
    T(c != NULL, "reopen RO");

    /* Check file counts via ls — data/numbers.bin won't appear at root */
    CfsDirEntry ents[16];
    int n = cfs_ls(c, "", ents, 16);
    fprintf(stderr, "  ls root: %d entries\n", n);
    T(n == 3, "root has 3 entries (README, hello, lorem)");

    /* ls data/ */
    n = cfs_ls(c, "data", ents, 16);
    T(n == 1, "data/ has 1 entry");
    if (n > 0) T(!strcmp(ents[0].name, "numbers.bin"), "data/numbers.bin");

    /* Read back files */
    char buf[256];
    ssize_t r;

    r = cfs_read(c, "README", buf, 256, 0);
    T(r == 16, "README size 16");
    if (r == 16) T(!memcmp(buf, "Updated readme!\n", 16), "README content");

    r = cfs_read(c, "hello.txt", buf, 256, 0);
    T(r == 13, "hello.txt size 13");
    if (r == 13) T(!memcmp(buf, "Hello World!\n", 13), "hello.txt content");

    r = cfs_read(c, "lorem.txt", buf, 256, 0);
    T(r == 26, "lorem.txt size 26");
    if (r == 26) T(!memcmp(buf, "Lorem ipsum dolor sit amet.", 26), "lorem.txt content");

    r = cfs_read(c, "data/numbers.bin", buf, 256, 0);
    T(r == 8, "data/numbers.bin size 8");

    /* Partial reads */
    r = cfs_read(c, "lorem.txt", buf, 5, 6);
    T(r == 5, "lorem.txt offset 6: 5 bytes");
    if (r == 5) T(!memcmp(buf, "ipsum", 5), "lorem.txt offset 6 content");

    /* cfs_stat */
    CfsStat st;
    T(cfs_stat(c, "README", &st) == 0, "stat README");
    T(st.size == 16, "stat README size");

    /* cfs_stats */
    CfsStats gst;
    cfs_stats(c, &gst);
    fprintf(stderr, "  orig=%llu comp=%llu ratio=%.2fx files=%u\n",
            (unsigned long long)gst.total_orig_size,
            (unsigned long long)gst.total_compressed_size,
            (double)gst.compress_ratio, (unsigned int)gst.file_count);

    cfs_close(c);

    /* Phase 4: cfs_pack test */
    c = cfs_create("/tmp/test_pack.cfs");
    T(c != NULL, "cfs_create for pack");
    T(cfs_pack(c, "notes.txt", "/tmp/test_rw.cfs") == 0, "pack test_rw.cfs as notes.txt");
    T(cfs_finalise(c) == 0, "finalise pack");
    cfs_close(c);

    c = cfs_open("/tmp/test_pack.cfs", CFS_RDONLY);
    T(c != NULL, "open pack result");
    n = cfs_ls(c, "", ents, 16);
    T(n == 1, "pack: 1 entry");
    if (n > 0) {
        T(!strcmp(ents[0].name, "notes.txt"), "pack: notes.txt");
        fprintf(stderr, "  notes.txt size=%llu\n", (unsigned long long)ents[0].size);
    }
    cfs_close(c);

    fprintf(stderr, "\n=== %d failures ===\n", failures);
    return failures ? 1 : 0;
}
