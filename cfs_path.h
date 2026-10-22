#ifndef CFS_PATH_H
#define CFS_PATH_H
#include <stddef.h>

/*
 * The LD_PRELOAD mount maps a host path space onto the container's flat
 * namespace: a path under the mount point is a container path, everything
 * else belongs to the host.  That decision is pure string work, and it is
 * the part an application controls — every syscall argument that looks like
 * a path lands here first.  It lives in its own unit so it can be tested
 * and fuzzed without the interposed symbols the rest of the preload defines.
 */

/* Normalise a container-relative path in place: collapse runs of '/', drop
 * "." components, apply ".." against the components already seen.  Returns
 * 1 when the path stays inside the container, 0 when a ".." climbed above
 * the root — the caller then treats the path as outside (POSIX: ".." at the
 * mount root leaves the mount, so the answer is "not ours", not "clamped").
 * The result never begins or ends with '/'. */
int cfs_path_normalize(char *s);

/* Translate an application path into a container path.
 *
 *   mount  mount point, e.g. "/mnt/cfs" (a trailing '/' is ignored)
 *   cwd    the process's current directory, or NULL for absolute paths
 *   p      the path argument as the application passed it
 *   out    receives the container-relative path ("" = container root)
 *
 * Returns 1 if the path belongs to the container (out is set), 0 if it
 * belongs to the host filesystem.  The mount test is on a component
 * boundary: "/mnt/cfs2/x" is not inside "/mnt/cfs".  A ".." that would
 * leave the mount makes the whole path a host path. */
int cfs_resolve_path(const char *mount, const char *cwd, const char *p,
                     char *out, size_t n);

#endif
