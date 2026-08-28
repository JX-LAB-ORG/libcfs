/* iso_mk.h — build a complete, spec-valid ISO9660 image in memory.
 * Used by tests to exercise the ISO9660 reader (cfs_iso9660.c) and the
 * ext4 installer without external mkisofs tooling. */
#ifndef ISO_MK_H
#define ISO_MK_H

#include <stdint.h>
#include <stddef.h>

/* One file to place in the ISO.  Directories are implied by path. */
typedef struct {
    const char  *path;         /* "dir/sub/file.txt" (no leading /) */
    const uint8_t *data;
    size_t      len;
    int         multiextent;   /* 1 = split into 2 extents (flags 0x80) */
} IsoMkEntry;

/* Build a full ISO9660 image: Boot Record + PVD + L/M path tables +
 * root + sub directories + files (2048B sectors).  Returns malloc'd
 * buffer (caller frees) and sets *out_sz, or NULL on error. */
uint8_t *iso_mk_build(const IsoMkEntry *entries, int n,
                      const char *vol_id, size_t *out_sz);

#endif
