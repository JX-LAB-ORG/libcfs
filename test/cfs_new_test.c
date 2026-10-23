#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "../cfs.h"
#include "../cfs_format.h"

static int failures = 0;
#define T(c, msg) do { if (!(c)) { fprintf(stderr, "FAIL: %s (errno=%d)\n", msg, errno); failures++; } \
                       else { fprintf(stderr, "  OK: %s\n", msg); } } while(0)

int main(void) {
    setvbuf(stderr, NULL, _IONBF, 0);

    /* ──────────── symlink ──────────────────────────────────── */
    fprintf(stderr, "=== Symlink ===\n");
    CFS *c = cfs_create("/tmp/test_new.cfs");
    T(c != NULL, "create");

    T(cfs_symlink(c, "/etc/hosts", "hosts.link") == 0, "symlink hosts.link");
    T(cfs_symlink(c, "/usr/bin/python3", "bin/python") == 0, "symlink bin/python");
    /* Duplicate should fail */
    T(cfs_symlink(c, "/tmp", "hosts.link") == -1, "symlink dup fails");
    T(errno == EEXIST, "errno=EEXIST");
    T(cfs_finalise(c) == 0, "finalise");
    cfs_close(c);

    /* Read back */
    c = cfs_open("/tmp/test_new.cfs", CFS_RDONLY);
    T(c != NULL, "reopen");

    char buf[256];
    ssize_t n = cfs_readlink(c, "hosts.link", buf, sizeof(buf));
    T(n == 10, "readlink hosts.link len=10");
    if (n > 0) T(!memcmp(buf, "/etc/hosts", (size_t)n), "readlink hosts.link content");

    n = cfs_readlink(c, "bin/python", buf, sizeof(buf));
    T(n == 16, "readlink bin/python len=16");
    if (n > 0) T(!memcmp(buf, "/usr/bin/python3", (size_t)n), "readlink bin/python content");

    CfsStat st;
    T(cfs_stat(c, "hosts.link", &st) == 0, "stat symlink");
    T(st.mode == CFS_MODE_SYMLINK, "mode=SYMLINK");
    cfs_close(c);

    /* ──────────── truncate ──────────────────────────────────── */
    fprintf(stderr, "\n=== Truncate ===\n");
    c = cfs_create("/tmp/test_trunc.cfs");
    T(c != NULL, "create");

    /* Create a file with known content */
    uint8_t data[4096];
    for (int i = 0; i < 4096; i++) data[i] = (uint8_t)(i & 0xFF);
    T(cfs_add_file(c, "test.bin", data, 4096) == 0, "add_file 4K");
    T(cfs_finalise(c) == 0, "finalise");
    cfs_close(c);

    c = cfs_open("/tmp/test_trunc.cfs", CFS_RDWR);
    T(c != NULL, "reopen RDWR");

    /* Truncate to 1024 */
    T(cfs_truncate(c, "test.bin", 1024) == 0, "truncate 4K→1K");
    size_t sz;
    void *rb = cfs_read_all(c, "test.bin", &sz);
    T(rb != NULL && sz == 1024, "read trunc size=1024");
    if (rb) { T(!memcmp(rb, data, 1024), "trunc content preserved"); free(rb); }

    /* Truncate to 0 */
    T(cfs_truncate(c, "test.bin", 0) == 0, "truncate to 0");
    rb = cfs_read_all(c, "test.bin", &sz);
    T(rb != NULL && sz == 0, "read trunc size=0");
    free(rb);

    /* Extend a truncated file */
    T(cfs_write(c, "test.bin", "ABCDEFGH", 8) == 0, "write 8B after trunc");
    rb = cfs_read_all(c, "test.bin", &sz);
    T(rb != NULL && sz == 8 && !memcmp(rb, "ABCDEFGH", 8), "write after trunc ok");
    free(rb);
    cfs_close(c);

    /* ──────────── rename ────────────────────────────────────── */
    fprintf(stderr, "\n=== Rename ===\n");
    c = cfs_create("/tmp/test_ren.cfs");
    T(c != NULL, "create");

    T(cfs_add_file(c, "oldname.txt", "hello", 5) == 0, "add oldname.txt");
    T(cfs_mkdir(c, "olddir") == 0, "mkdir olddir");
    T(cfs_add_file(c, "olddir/child.txt", "child", 5) == 0, "add olddir/child.txt");
    T(cfs_finalise(c) == 0, "finalise");
    cfs_close(c);

    c = cfs_open("/tmp/test_ren.cfs", CFS_RDWR);
    T(c != NULL, "reopen RDWR");

    /* Rename file */
    T(cfs_rename(c, "oldname.txt", "newname.txt") == 0, "rename file");
    T(cfs_stat(c, "oldname.txt", &st) == -1, "old name gone");
    T(cfs_stat(c, "newname.txt", &st) == 0 && st.size == 5, "new name exists");

    /* Rename directory (cascade) */
    T(cfs_rename(c, "olddir", "newdir") == 0, "rename dir");
    T(cfs_stat(c, "olddir", &st) == -1, "old dir gone");
    T(cfs_stat(c, "newdir", &st) == 0 && st.mode == CFS_MODE_DIR, "new dir exists");
    T(cfs_stat(c, "newdir/child.txt", &st) == 0 && st.size == 5, "child renamed correctly");

    /* Rename to existing should fail */
    T(cfs_write(c, "other.txt", "world", 5) == 0, "write other.txt");
    T(cfs_rename(c, "newname.txt", "other.txt") == -1, "rename to existing fails");
    T(errno == EEXIST, "errno=EEXIST");
    cfs_close(c);

    /* ──────────── utimens / chmod / chown ──────────────────── */
    fprintf(stderr, "\n=== Utimens/Chmod/Chown ===\n");
    c = cfs_open("/tmp/test_ren.cfs", CFS_RDWR);
    T(c != NULL, "reopen");

    /* utimens should update mtime */
    T(cfs_utimens(c, "newname.txt", 1718400000, 1718490000) == 0, "utimens");
    T(cfs_stat(c, "newname.txt", &st) == 0, "stat after utimens");
    T(st.mtime == 1718490000, "mtime updated");

    /* chmod/chown are not part of the container namespace: the API does
     * not exist, and the hook refuses with ENOTSUP. */

    /* Non-existing path */
    T(cfs_utimens(c, "noexist", 0, 0) == -1, "utimens nonoexist");

    cfs_close(c);

    /* ──────────── large file ─────────────────────────────────── */
    fprintf(stderr, "\n=== Large File ===\n");
    c = cfs_create("/tmp/test_large.cfs");
    T(c != NULL, "create");

    /* Write a file with content to test block-split path (>64MB not practical in test,
       but test write path that would split) */
    uint8_t *ldata = malloc(131072); /* 128KB */
    for (int i = 0; i < 131072; i++) ldata[i] = (uint8_t)(i * 7 + 13);
    T(cfs_add_file(c, "large.bin", ldata, 131072) == 0, "add 128KB file");
    T(cfs_finalise(c) == 0, "finalise");
    cfs_close(c);

    c = cfs_open("/tmp/test_large.cfs", CFS_RDONLY);
    T(c != NULL, "reopen RO");
    void *lr = cfs_read_all(c, "large.bin", &sz);
    T(lr != NULL && sz == 131072, "read large size=128KB");
    if (lr) { T(!memcmp(lr, ldata, 131072), "large content"); free(lr); }
    cfs_close(c);
    free(ldata);

    fprintf(stderr, "\n=== %d failures ===\n", failures);
    return failures ? 1 : 0;
}
