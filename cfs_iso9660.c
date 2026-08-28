/* cfs_iso9660.c — ISO9660 reader for cfs-tool install. */

#include "cfs_iso9660.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ISO_SECT 2048
#define PVD_OFF  16 * ISO_SECT

struct IsoFs {
    const uint8_t *img;
    size_t        sz;
    IsoEntry     *entries;
    int           n, cap;
};

/* little-endian u32 at p */
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
/* both-endian u16 at p: LE half at p, BE half at p+2 */
static uint16_t rd_both16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/* days from 1970-01-01 (Howard Hinnant civil algorithm) */
static long days_from_civil(int y, int m, int d) {
    y -= m <= 2;
    long era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (long)doe - 719468;
}

/* ISO 7-byte date (with tz) -> POSIX seconds, UTC */
static uint32_t iso_date_to_time(const uint8_t *p) {
    if (p[0] == 0) return 0; /* zeroed = no date */
    int y = 1900 + p[0], mo = p[1], d = p[2];
    int h = p[3], mi = p[4], s = p[5];
    int8_t tz = (int8_t)p[6];          /* quarter-hours from GMT */
    long secs = days_from_civil(y, mo, d) * 86400L + h * 3600L + mi * 60L + s;
    secs -= (long)tz * 900L;           /* local -> UTC */
    if (secs < 0) secs = 0;
    return (uint32_t)secs;
}

static int entry_add(IsoFs *fs, const char *path, uint64_t off,
                     uint64_t size, uint8_t is_dir, uint32_t mtime) {
    if (fs->n == fs->cap) {
        int nc = fs->cap ? fs->cap * 2 : 64;
        IsoEntry *ne = realloc(fs->entries, (size_t)nc * sizeof(*ne));
        if (!ne) return -1;
        fs->entries = ne; fs->cap = nc;
    }
    IsoEntry *e = &fs->entries[fs->n++];
    memset(e, 0, sizeof(*e));
    strncpy(e->path, path, sizeof(e->path) - 1);
    e->offset = off; e->size = size; e->is_dir = is_dir; e->mtime = mtime;
    e->mode = is_dir ? 0755 : 0644;
    return 0;
}

/* strip ";N" version suffix (ISO9660 names are "NAME.EXT;1") */
static void strip_version(char *name, size_t nlen) {
    for (size_t i = 0; i < nlen; i++) {
        if (name[i] == ';') { name[i] = 0; return; }
    }
}

typedef struct {
    char     name[256];
    uint64_t extent;      /* first extent sector */
    uint64_t size;        /* first segment bytes */
    uint64_t seg_sectors; /* sectors consumed by first segment */
    uint8_t  seen_multi;
} PendingMulti;

/* Walk one directory extent; recursion depth bounded by the directory
 * chain.  `path` is the directory's own path (no trailing slash). */
static int walk_dir(IsoFs *fs, uint64_t extent, uint64_t dsize,
                    const char *path) {
    const uint8_t *img = fs->img;
    size_t sz = fs->sz;
    uint64_t doff = extent * ISO_SECT;
    if (doff >= sz || dsize > sz - doff) return -1;

    PendingMulti pend = {0};

    /* iterate records inside the directory data */
    uint64_t pos = 0;
    while (pos < dsize) {
        const uint8_t *rec = img + doff + pos;
        uint8_t len_dr = rec[0];
        if (len_dr == 0) {
            /* padding: skip to next sector boundary */
            uint64_t next = (pos / ISO_SECT + 1) * ISO_SECT;
            if (next <= pos) return -1;
            pos = next;
            continue;
        }
        if (len_dr < 33 || pos + len_dr > dsize) return -1;

        uint8_t flags = rec[25];
        uint8_t nl = rec[32];
        if (33 + nl > len_dr) return -1;

        char name[256];
        memcpy(name, rec + 33, nl);
        name[nl] = 0;
        strip_version(name, nl);
        /* Names are kept as stored by the standard (uppercase 8.3): the
         * target firmware/OS reads this disk by the standard, so what we
         * install is exactly what the ISO declares. */
        if (name[0] == 0 || (nl == 1 && name[0] == 1)) {
            pos += len_dr;
            continue; /* "." and ".." */
        }

        uint64_t fext = rd32(rec + 2);
        uint64_t fsize = rd32(rec + 10);
        uint8_t is_dir = flags & 0x02;
        uint8_t is_multi = flags & 0x80;
        uint32_t mtime = iso_date_to_time(rec + 18);
        uint64_t sect = fext * ISO_SECT;
        uint64_t seg_sectors = (fsize + ISO_SECT - 1) / ISO_SECT;

        if (sect >= sz || fsize > sz - sect) return -1;

        char full[512];
        if (!strcmp(path, "/")) snprintf(full, sizeof(full), "/%s", name);
        else snprintf(full, sizeof(full), "%s/%s", path, name);

        if (is_multi) {
            /* multi-extent: first (or continuation) segment */
            if (pend.seen_multi) {
                /* continuation must match the pending name and directly
                 * follow the previous segment */
                if (strcmp(full, pend.name)) return -1;
                if (fext != pend.extent + pend.seg_sectors)
                    return -1;
                pend.size += fsize;
                pend.seg_sectors += seg_sectors;
            } else {
                if (is_dir) return -1; /* multi-extent dir not supported */
                if (pend.seen_multi) return -1;
                strncpy(pend.name, full, sizeof(pend.name) - 1);
                pend.name[sizeof(pend.name) - 1] = 0;
                pend.extent = fext;
                pend.size = fsize;
                pend.seg_sectors = seg_sectors;
                pend.seen_multi = 1;
            }
            pos += len_dr;
            continue;
        }

        if (pend.seen_multi) {
            /* terminator record of a multi-extent file: same name,
             * no 0x80 flag, extent directly after the previous segment */
            if (strcmp(full, pend.name)) return -1;
            if (fext != pend.extent + pend.seg_sectors) return -1;
            pend.size += fsize;
            if (entry_add(fs, pend.name, pend.extent * ISO_SECT,
                          pend.size, 0, mtime)) return -1;
            pend.seen_multi = 0;
            pos += len_dr;
            continue;
        }

        if (is_dir) {
            if (entry_add(fs, full, sect, fsize, 1, mtime)) return -1;
            if (walk_dir(fs, fext, fsize, full)) return -1;
        } else {
            if (entry_add(fs, full, sect, fsize, 0, mtime)) return -1;
        }
        pos += len_dr;
    }
    return 0;
}

IsoFs *iso9660_open(const uint8_t *img, size_t sz) {
    if (!img || sz < 17 * ISO_SECT) return NULL;
    const uint8_t *pvd = img + PVD_OFF;
    if (pvd[0] != 1 || memcmp(pvd + 1, "CD001", 5) || pvd[6] != 1) return NULL;
    if (rd_both16(pvd + 128) != ISO_SECT) return NULL; /* logical block size */

    /* root directory record inside PVD (34 bytes) */
    uint64_t root_ext = rd32(pvd + 158);
    uint64_t root_sz = rd32(pvd + 166);

    IsoFs *fs = calloc(1, sizeof(*fs));
    if (!fs) return NULL;
    fs->img = img;
    fs->sz = sz;

    if (walk_dir(fs, root_ext, root_sz, "/")) {
        iso9660_close(fs);
        return NULL;
    }
    return fs;
}

int iso9660_nfiles(const IsoFs *fs) { return fs->n; }

int iso9660_get(const IsoFs *fs, int i, IsoEntry *out) {
    if (!fs || i < 0 || i >= fs->n) return -1;
    *out = fs->entries[i];
    return 0;
}

void iso9660_close(IsoFs *fs) {
    if (!fs) return;
    free(fs->entries);
    free(fs);
}
