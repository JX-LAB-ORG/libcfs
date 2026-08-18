#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "../cfs.h"

static int failures = 0;
#define T(c, msg) do { if (!(c)) { fprintf(stderr, "FAIL: %s (errno=%d)\n", msg, errno); failures++; } \
                       else { fprintf(stderr, "  OK: %s\n", msg); } } while(0)

static void ls_debug(CFS *c, const char *dir) {
    CfsDirEntry ents[32];
    int n = cfs_ls(c, dir, ents, 32);
    fprintf(stderr, "  ls '%s': %d entries\n", dir[0] ? dir : "/", n);
    for (int i = 0; i < n; i++)
        fprintf(stderr, "    %c %-30s %llu\n",
                ents[i].is_dir ? 'd' : '-',
                ents[i].name,
                (unsigned long long)ents[i].size);
}

int main(void) {
    setvbuf(stderr, NULL, _IONBF, 0);
    fprintf(stderr, "=== cfs_mkdir / cfs_unlink / cfs_ls ===\n");

    CFS *c = cfs_create("/tmp/test_dir.cfs");
    T(c != NULL, "cfs_create");

    /* Build a directory tree:
     * /README
     * /docs/
     * /docs/guide.txt
     * /docs/api/
     * /docs/api/ref.txt
     * /src/
     * /src/main.c
     */
    T(cfs_add_file(c, "README", "hello\n", 6) == 0, "add README");
    T(cfs_mkdir(c, "docs") == 0, "mkdir docs");
    T(cfs_add_file(c, "docs/guide.txt", "guide content\n", 14) == 0, "add docs/guide.txt");
    T(cfs_mkdir(c, "docs/api") == 0, "mkdir docs/api");
    T(cfs_add_file(c, "docs/api/ref.txt", "ref content\n", 12) == 0, "add docs/api/ref.txt");
    T(cfs_mkdir(c, "src") == 0, "mkdir src");
    T(cfs_add_file(c, "src/main.c", "int main(){}\n", 12) == 0, "add src/main.c");

    T(cfs_finalise(c) == 0, "finalise");
    cfs_close(c);

    /* Reopen and list */
    fprintf(stderr, "\n--- Tree listing ---\n");
    c = cfs_open("/tmp/test_dir.cfs", CFS_RDONLY);
    T(c != NULL, "reopen");

    ls_debug(c, "");
    T(cfs_ls(c, "", (CfsDirEntry[16]){0}, 16) == 3, "root has 3 entries");

    ls_debug(c, "docs");
    T(cfs_ls(c, "docs", (CfsDirEntry[16]){0}, 16) == 2, "docs has 2 entries");

    ls_debug(c, "docs/api");
    T(cfs_ls(c, "docs/api", (CfsDirEntry[16]){0}, 16) == 1, "docs/api has 1 entry");

    ls_debug(c, "src");
    T(cfs_ls(c, "src", (CfsDirEntry[16]){0}, 16) == 1, "src has 1 entry");

    /* Trailing slash */
    T(cfs_ls(c, "docs/", (CfsDirEntry[16]){0}, 16) == 2, "docs/ has 2 entries");

    /* cfs_stat on directory */
    CfsStat st;
    T(cfs_stat(c, "docs", &st) == 0, "stat docs");
    T(st.mode == 1, "docs is dir (mode=1)");
    T(st.size == 0, "docs size=0");

    cfs_close(c);

    /* Reopen RDWR to test unlink */
    fprintf(stderr, "\n--- Unlink tests ---\n");
    c = cfs_open("/tmp/test_dir.cfs", CFS_RDWR);
    T(c != NULL, "reopen RDWR");

    /* Unlink a file */
    T(cfs_unlink(c, "README") == 0, "unlink README");
    T(cfs_stat(c, "README", &st) == -1, "README gone after unlink");
    T(cfs_ls(c, "", (CfsDirEntry[16]){0}, 16) == 2, "root now 2 entries");

    /* Unlink non-existing */
    T(cfs_unlink(c, "nope") == -1, "unlink nope fails");
    T(errno == ENOENT, "errno=ENOENT");

    /* Unlink non-empty dir should fail */
    T(cfs_unlink(c, "docs") == -1, "unlink docs (non-empty) fails");
    T(errno == ENOTEMPTY, "errno=ENOTEMPTY");

    /* Unlink nested, then dir */
    T(cfs_unlink(c, "docs/api/ref.txt") == 0, "unlink docs/api/ref.txt");
    T(cfs_unlink(c, "docs/guide.txt") == 0, "unlink docs/guide.txt");
    T(cfs_unlink(c, "docs/api") == 0, "unlink docs/api (empty dir)");
    T(cfs_unlink(c, "docs") == 0, "unlink docs (empty dir)");
    T(cfs_ls(c, "", (CfsDirEntry[16]){0}, 16) == 1, "root now 1 entry (src)");

    cfs_close(c);

    /* Reopen RO, verify final state */
    c = cfs_open("/tmp/test_dir.cfs", CFS_RDONLY);
    ls_debug(c, "");
    cfs_close(c);

    fprintf(stderr, "\n=== %d failures ===\n", failures);
    return failures ? 1 : 0;
}
