#define _GNU_SOURCE
#include "cfs_path.h"
#include <string.h>
#include <stdio.h>

int cfs_path_normalize(char *s) {
    char *w = s;            /* write cursor; always <= read cursor */
    const char *r = s;
    int inside = 1;
    while (*r) {
        while (*r == '/') r++;
        if (!*r) break;
        const char *e = r;
        while (*e && *e != '/') e++;
        size_t len = (size_t)(e - r);
        if (len == 1 && r[0] == '.') { r = e; continue; }
        if (len == 2 && r[0] == '.' && r[1] == '.') {
            if (w == s) inside = 0;              /* climbs above the root */
            while (w > s && w[-1] != '/') w--;   /* drop the last component */
            if (w > s) w--;                      /* and its separator */
            r = e;
            continue;
        }
        if (w > s) *w++ = '/';
        memmove(w, r, len);                      /* regions may overlap */
        w += len;
        r = e;
    }
    *w = 0;
    return inside;
}

int cfs_resolve_path(const char *mount, const char *cwd, const char *p,
                     char *out, size_t n) {
    if (!mount || !p || !out || n == 0) return 0;
    size_t ml = strlen(mount);
    while (ml > 1 && mount[ml - 1] == '/') ml--;   /* "/mnt/cfs/" ≡ "/mnt/cfs" */

    /* Inside the mount?  The next byte has to be a separator or the end:
     * a plain prefix test made "/mnt/cfs2" a path inside "/mnt/cfs", so an
     * application could read its "2" subtree from the container and, worse,
     * have the preload create real directories under that sibling. */
    if (!strncmp(p, mount, ml) && (p[ml] == 0 || p[ml] == '/')) {
        const char *r = p + ml;
        while (*r == '/') r++;
        snprintf(out, n, "%s", r);
        /* A ".." that leaves the mount leaves the container namespace:
         * "/mnt/cfs/../etc/passwd" is the host's file, not the container's
         * "etc/passwd", which is what clamping it would have produced. */
        return cfs_path_normalize(out);
    }
    if (p[0] == '/') return 0;                     /* absolute, elsewhere */

    /* Relative: only meaningful when the process is inside the mount. */
    if (!cwd) return 0;
    if (strncmp(cwd, mount, ml) || (cwd[ml] != 0 && cwd[ml] != '/')) return 0;
    const char *base = cwd + ml;
    while (*base == '/') base++;
    const char *clean = p;
    while (!strncmp(clean, "./", 2)) clean += 2;
    if (base[0]) snprintf(out, n, "%s/%s", base, clean);
    else         snprintf(out, n, "%s", clean);
    /* Same rule as above: ".." used to travel through untouched, and
     * ensure_real_dir built "mount/../../x" outside the mount point. */
    return cfs_path_normalize(out);
}
