/* cfs_iso9660.h — minimal ISO9660 reader (used by cfs-tool install).
 * Parses the primary volume descriptor, walks directory extents
 * recursively, merges multi-extent files, strips ";N" version suffixes.
 * Rock Ridge (RR/AA) is not parsed — names/modes come from the ISO base
 * fields only. */

#ifndef CFS_ISO9660_H
#define CFS_ISO9660_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    char     path[512];    /* "/dir/sub/file.txt" */
    uint64_t offset;       /* byte offset in the ISO image */
    uint64_t size;
    uint8_t  is_dir;
    uint32_t mtime;        /* POSIX seconds, UTC (tz offset applied) */
    uint16_t mode;         /* 0755 dir / 0644 file if no RR */
} IsoEntry;

typedef struct IsoFs IsoFs;

/* Parse img[0..sz).  Returns NULL if the image is not a valid ISO9660
 * volume (bad PVD, out-of-range extents, broken directory chain). */
IsoFs *iso9660_open(const uint8_t *img, size_t sz);

int   iso9660_nfiles(const IsoFs *fs);
/* Fill *out with entry i (0 <= i < iso9660_nfiles).  Returns 0 or -1. */
int   iso9660_get(const IsoFs *fs, int i, IsoEntry *out);
void  iso9660_close(IsoFs *fs);

#endif
