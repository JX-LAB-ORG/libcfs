/* ext2_read.h — read-only ext2/4 filesystem walker for tests.
 * Validates installed partitions against the source ISO without any
 * external tooling.  Supports the single-block-group layout produced by
 * cfs_mkfs_ext4_at / cfs_mkfs_ext4_install (4KB blocks, 256B inodes,
 * extent-mapped files and directories). */

#ifndef EXT2_READ_H
#define EXT2_READ_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    char     path[512];
    uint64_t size;
    uint8_t  is_dir;
} E2Entry;

/* Walk the filesystem image read-only.  For regular files `data` points
 * to the full content (malloc'd when multi-extent, otherwise in-place).
 * cb returns 0 to continue, nonzero to stop the walk.  Returns 0 on
 * success, -1 on structural corruption. */
int ext2_walk(const uint8_t *img, size_t sz,
              int (*cb)(const E2Entry *e, const uint8_t *data, void *ctx),
              void *ctx);

#endif
