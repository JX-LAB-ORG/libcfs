#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "../cfs.h"
#include "../cfs_format.h"

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

    /* Phase 5: the block header must agree with the inode table.
     *
     * The read path sizes its buffer from the table's orig_size while the
     * decoder trusts the header's original_size; a container where the two
     * disagree is torn or hostile.  cfs_open refuses it now.  The hex case is
     * here because the exception is easy to get wrong: a hex-wrapped block
     * records the *folded* length in its header, not the text length, so a
     * naive equality check rejects every container holding hex text. */
    fprintf(stderr, "=== header/table cross-check ===\n");
    {
        size_t hn = 65536;
        char *hex = malloc(hn);
        static const char hd[] = "0123456789ABCDEF";
        for (size_t i = 0; i < hn; i++) hex[i] = (i % 33 == 32) ? '\n' : hd[i & 15];
        CFS *h = cfs_create("/tmp/test_hex.cfs");
        T(h != NULL, "create container for a hex block");
        T(cfs_add_file(h, "dump.txt", hex, hn) == 0, "add uppercase hex file");
        T(cfs_finalise(h) == 0, "finalise hex container");
        cfs_close(h);
        CFS *r = cfs_open("/tmp/test_hex.cfs", CFS_RDONLY);
        T(r != NULL, "hex block passes the open-time header check");
        if (r) {
            char *back = cfs_read_all(r, "dump.txt", NULL);
            T(back && !memcmp(back, hex, hn), "hex block reads back byte for byte");
            free(back);
            cfs_close(r);
        }
        free(hex);
        unlink("/tmp/test_hex.cfs");
    }
    {
        CFS *c3 = cfs_create("/tmp/test_hdr.cfs");
        T(c3 != NULL, "create container for the doctored header");
        T(cfs_add_file(c3, "x.txt", "0123456789", 10) == 0, "add small file");
        T(cfs_finalise(c3) == 0, "finalise doctored container");
        cfs_close(c3);

        /* Locate the first block through the on-disk layout, then lie about
         * its decompressed size. */
        FILE *f = fopen("/tmp/test_hdr.cfs", "rb");
        T(f != NULL, "open the container file directly");
        uint8_t sb[CFS_SB_SIZE] = {0};
        if (f) { fread(sb, 1, sizeof sb, f); }
        uint64_t io = 0; uint32_t isz = 0;
        for (int i = 7; i >= 0; i--) io = (io << 8) | sb[10 + i];
        for (int i = 3; i >= 0; i--) isz = (isz << 8) | sb[18 + i];
        uint8_t *tab = malloc(isz ? isz : 1);
        if (f && tab) { fseek(f, (long)io, SEEK_SET); if (fread(tab, 1, isz, f) != isz) tab[0] = 0; }
        uint64_t boff = 0;
        for (int i = 7; i >= 0; i--) boff = (boff << 8) | tab[24 + i];
        if (f) fclose(f);
        free(tab);

        T(boff >= CFS_SB_SIZE, "located the first block through the on-disk layout");
        int fd = open("/tmp/test_hdr.cfs", O_RDWR);
        T(fd >= 0, "reopen the container file to doctor it");
        uint8_t lie[4] = { 0xFF, 0xFF, 0xFF, 0x00 };   /* 16MB, table says 10 */
        T(fd >= 0 && pwrite(fd, lie, 4, (off_t)boff + 4) == 4, "overwrite the header's original_size");
        if (fd >= 0) close(fd);

        CFS *bad = cfs_open("/tmp/test_hdr.cfs", CFS_RDONLY);
        T(bad == NULL, "a header that disagrees with the table is refused at open");
        if (bad) cfs_close(bad);
        unlink("/tmp/test_hdr.cfs");
    }

    fprintf(stderr, "\n=== %d failures ===\n", failures);
    return failures ? 1 : 0;
}
