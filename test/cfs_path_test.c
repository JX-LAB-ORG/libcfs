/* cfs_path_test — the LD_PRELOAD mount's path translation.
 *
 * Every path an application passes to a syscall goes through this before
 * anything else happens, so it is the preload's real input surface.  Two
 * things it has to get right:
 *
 *   - membership is a component test, not a prefix test: "/mnt/cfs2/x" is
 *     not inside "/mnt/cfs".  A prefix test put the app in the container
 *     for a sibling directory and, worse, had the preload create real
 *     directories out there.
 *   - ".." never climbs above the container root.  A path like
 *     "/mnt/cfs/../../tmp/x" reached ensure_real_dir as "mount/../../tmp/x"
 *     and created directories outside the mount point.
 */
#include "../cfs_path.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int failed, checks;

static void eq(const char *want, const char *got, const char *what) {
    checks++;
    if (strcmp(want, got)) {
        failed++;
        printf("  FAIL %s: want \"%s\" got \"%s\"\n", what, want, got);
    }
}

static void resolve_eq(const char *mount, const char *cwd, const char *p,
                       int want_rc, const char *want, const char *what) {
    char out[256];
    memset(out, 0xAA, sizeof(out));
    int rc = cfs_resolve_path(mount, cwd, p, out, sizeof(out));
    checks++;
    if (rc != want_rc) {
        failed++;
        printf("  FAIL %s: want rc=%d got %d (out \"%s\")\n", what, want_rc, rc, out);
        return;
    }
    if (rc) eq(want, out, what);
}

int main(void) {
    printf("[p1] normalisation\n");
    {
        struct { const char *in, *out; } v[] = {
            { "a/b",        "a/b"   },
            { "a//b",       "a/b"   },
            { "/a/b/",      "a/b"   },
            { "./a",        "a"     },
            { "a/./b",      "a/b"   },
            { ".",          ""      },
            { "a/../b",     "b"     },
            { "",           ""      },
            { "///",        ""      },
        };
        for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
            char buf[64];
            snprintf(buf, sizeof buf, "%s", v[i].in);
            checks++;
            if (!cfs_path_normalize(buf)) {
                failed++;
                printf("  FAIL %s: escaped the root\n", v[i].in);
                continue;
            }
            eq(v[i].out, buf, v[i].in);
        }
        /* a ".." at the root leaves the namespace, and the result says so */
        /* "a/.." is the root, not an escape: one "../" undoes "a". */
        const char *esc[] = { "..", "/..", "a/../../b", "../../x" };
        for (size_t i = 0; i < sizeof esc / sizeof esc[0]; i++) {
            char buf[64];
            snprintf(buf, sizeof buf, "%s", esc[i]);
            checks++;
            if (cfs_path_normalize(buf)) {
                failed++;
                printf("  FAIL %s: should have escaped (got \"%s\")\n", esc[i], buf);
            }
        }
    }

    printf("[p2] absolute paths\n");
    resolve_eq("/mnt/cfs", NULL, "/mnt/cfs/a/b", 1, "a/b", "inside");
    resolve_eq("/mnt/cfs", NULL, "/mnt/cfs",     1, "",    "mount root");
    resolve_eq("/mnt/cfs", NULL, "/mnt/cfs/",    1, "",    "mount root, slash");
    resolve_eq("/mnt/cfs", NULL, "/mnt/cfs//a",  1, "a",   "double slash");
    resolve_eq("/mnt/cfs", NULL, "/mnt/cfs2/x",  0, NULL,  "sibling prefix is not ours");
    resolve_eq("/mnt/cfs", NULL, "/mnt/cfs-1/x", 0, NULL,  "sibling with -");
    resolve_eq("/mnt/cfs", NULL, "/etc/passwd",  0, NULL,  "outside");
    resolve_eq("/mnt/cfs", NULL, "/mnt/cf",      0, NULL,  "shorter than mount");
    resolve_eq("/mnt/cfs", NULL, "/mnt",         0, NULL,  "parent of mount");
    resolve_eq("/mnt/cfs", NULL, "/mnt/cfs/../etc/passwd", 0, NULL,
               ".. out of the mount is the host's file");
    resolve_eq("/mnt/cfs", NULL, "/mnt/cfs/a/../../b", 0, NULL, "no climb via ..");
    resolve_eq("/mnt/cfs", NULL, "/mnt/cfs/a/../b", 1, "b", ".. inside the mount");
    resolve_eq("/mnt/cfs/", NULL, "/mnt/cfs/a",  1, "a",   "mount with trailing slash");

    printf("[p3] relative paths\n");
    resolve_eq("/mnt/cfs", "/mnt/cfs",     "a",      1, "a",   "simple");
    resolve_eq("/mnt/cfs", "/mnt/cfs",     "./a",    1, "a",   "dot-slash");
    resolve_eq("/mnt/cfs", "/mnt/cfs",     ".",      1, "",    "dot");
    resolve_eq("/mnt/cfs", "/mnt/cfs",     "..",     0, NULL,  "dotdot at root leaves");
    resolve_eq("/mnt/cfs", "/mnt/cfs/d",   "..",     1, "",    "dotdot out of d");
    resolve_eq("/mnt/cfs", "/mnt/cfs/d",   "../x",   1, "x",   "dotdot then name");
    resolve_eq("/mnt/cfs", "/mnt/cfs/d",   "../../../x", 0, NULL, "climbing past the root leaves");
    resolve_eq("/mnt/cfs", "/mnt/cfs/d",   "e/f",    1, "d/e/f", "join");
    resolve_eq("/mnt/cfs", "/mnt/cfs/d",   "e/../f",  1, "d/f", "join then up");
    resolve_eq("/mnt/cfs", "/mnt/cfs/d",   "e/../../f", 1, "f", "join then up twice");
    resolve_eq("/mnt/cfs", "/mnt/cfs2",    "a",      0, NULL,  "cwd sibling");
    resolve_eq("/mnt/cfs", "/mnt/cfs",     "/etc",   0, NULL,  "absolute stays absolute");
    resolve_eq("/mnt/cfs", "/home/u",      "a",      0, NULL,  "cwd outside");
    resolve_eq("/mnt/cfs", NULL,           "a",      0, NULL,  "relative without cwd");

    printf("[p4] truncation and odd input\n");
    {
        char out[8];
        const char *longp = "/mnt/cfs/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        int rc = cfs_resolve_path("/mnt/cfs", NULL, longp, out, sizeof(out));
        checks++;
        if (rc != 1 || strlen(out) != sizeof(out) - 1) {
            failed++;
            printf("  FAIL truncation: rc=%d len=%zu\n", rc, strlen(out));
        }
        /* a zero-size buffer must not be written */
        rc = cfs_resolve_path("/mnt/cfs", NULL, "/mnt/cfs/a", NULL, 0);
        checks++;
        if (rc != 0) { failed++; printf("  FAIL null out accepted\n"); }
        rc = cfs_resolve_path(NULL, NULL, "/mnt/cfs/a", out, sizeof(out));
        checks++;
        if (rc != 0) { failed++; printf("  FAIL null mount accepted\n"); }
    }

    printf("  %d checks\n\n=== %d failures ===\n", checks, failed);
    return failed != 0;
}
