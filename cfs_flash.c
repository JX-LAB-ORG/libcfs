#define _GNU_SOURCE
#include "cfs_internal.h"
#include "cfs_flash.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* ── A flash medium inside a container ─────────────────────────
 * The entry is "@flash.<tag>"; its data is one contiguous, page aligned,
 * uncompressed range: [medium: size bytes][descriptor: 4096 bytes].  There
 * is no compression, no dedup and no copy-on-write here on purpose — the
 * bytes a guest writes are the bytes the container holds, which is what both
 * XIP (mmap the range) and real flash semantics (erase/program) require.
 *
 * The descriptor has two independent 2 KiB copies with their own sequence
 * numbers and CRCs, because a 4 KiB pwrite is not atomic and losing the
 * geometry would lose the device.  Descriptor updates (erase counter, bad
 * blocks) are ordinary in-place writes: they are content, not metadata, so
 * they deliberately stay outside the v3 data→table→slot commit.  A torn
 * update is detected by the CRC of that copy and the other copy is used. */

#define FLASH_FILL_CHUNK (1u << 20)   /* create/erase write size */

struct CfsFlash {
    CfsFlashRef *ref;       /* open-handle count shared with the CFS handle;
                             * kept separate so closing the CFS first is safe */
    int      fd;            /* dup() of the container fd.  It keeps the
                             * file description alive past cfs_compact's
                             * close/reopen, but the flock belongs to the
                             * shared description and is released when the
                             * CFS handle closes — so the CFS handle must
                             * outlive its flash handles, and compact refuses
                             * while one is open (the shared ref count). */
    char     path[300];
    uint64_t extent_off;    /* file offset of guest byte 0 */
    uint64_t size;          /* guest-visible length */
    uint32_t sector, page, erase, write_gran;
    int      media;
    int      erased_byte;
    unsigned flags;
    uint64_t erase_count;
    uint32_t bad_n;
    uint32_t *bad;          /* erase-block indices */
    uint32_t desc_seq;      /* sequence of the copy we last read/wrote */
    int      desc_idx;      /* which copy: 0 = first 2 KiB, 1 = second */
    int      writable;

    void    *map;           /* cached MAP_SHARED view of the medium */
    size_t   map_len;
};

/* ── helpers ──────────────────────────────────────────────────── */

static InodeEntry *flash_lookup(CFS *c, const char *path) {
    for (uint32_t i = 0; i < c->inode_count; i++)
        if (c->inodes[i].path && !strcmp(c->inodes[i].path, path))
            return &c->inodes[i];
    return NULL;
}

static int resolve_path(const char *tag, char *out, size_t outsz) {
    if (!tag || !*tag) return -1;
    if (!strncmp(tag, CFS_FLASH_PREFIX, strlen(CFS_FLASH_PREFIX))) {
        if (strlen(tag) + 1 > outsz) return -1;
        snprintf(out, outsz, "%s", tag);
    } else {
        if (strlen(tag) + strlen(CFS_FLASH_PREFIX) + 1 > outsz) return -1;
        snprintf(out, outsz, "%s%s", CFS_FLASH_PREFIX, tag);
    }
    return 0;
}

int cfs_flash_entry_tag_ok(const char *tag) {
    char p[300];
    if (resolve_path(tag, p, sizeof p) != 0) return 0;
    const char *s = p + strlen(CFS_FLASH_PREFIX);
    if (!*s || *s == '-') return 0;   /* a leading '-' would parse as an option */
    for (; *s; s++)
        if (*s == '/' || *s == '@' || (unsigned char)*s < 0x20 || *s == 0x7F)
            return 0;
    return 1;
}

static int pw_full(int fd, const void *buf, size_t n, off_t off) {
    const uint8_t *p = buf;
    while (n) {
        ssize_t w = pwrite(fd, p, n, off);
        if (w < 0) return -1;
        if (w == 0) { errno = ENOSPC; return -1; }
        p += w; off += w; n -= (size_t)w;
    }
    return 0;
}

static int pr_full(int fd, void *buf, size_t n, off_t off) {
    uint8_t *p = buf;
    while (n) {
        ssize_t r = pread(fd, p, n, off);
        if (r < 0) return -1;
        if (r == 0) { errno = EIO; return -1; }
        p += r; off += r; n -= (size_t)r;
    }
    return 0;
}

static int is_pow2(uint32_t v) { return v && !(v & (v - 1)); }
static int sync_each(void);

/* A handle whose container was closed is a reader: the flock is gone, so a
 * second process may be writing the file.  Refuse writes rather than race. */
static int flash_writable(CfsFlash *f) {
    if (!f->writable || (f->ref && f->ref->orphan)) { errno = EROFS; return 0; }
    return 1;
}

/* The host's page size is what mmap() actually requires; the format states
 * 4 KiB, so the stricter of the two wins. */
static uint64_t host_align(void) {
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0 || (ps & (ps - 1))) ps = 4096;
    return (uint64_t)ps < CFS_FLASH_DESC_SIZE ? CFS_FLASH_DESC_SIZE : (uint64_t)ps;
}

/* Same value, for cfs.c's compact pass. */
uint64_t cfs_flash_align(void) { return host_align(); }

/* Geometry the medium can actually honour.  Checked at create and again when
 * a descriptor is read, so a hand-edited container cannot describe a device
 * the arithmetic below would divide by zero on. */
static int geom_check(const CfsFlashGeom *g, unsigned flags) {
    if (!g || g->size == 0 || g->size > CFS_FLASH_MAX) return -1;
    if (!is_pow2(g->sector) || !is_pow2(g->page) || !is_pow2(g->erase)) return -1;
    /* No page-vs-sector ordering: a NOR device reads in 512-byte sectors but
     * programs in 256-byte pages, so the write granule is legitimately
     * smaller than the sector. */
    if (g->erase < g->page) return -1;
    if (g->erase < g->sector) return -1;
    if (g->erase % g->page) return -1;
    if (g->size % g->erase) return -1;
    /* write_gran is not free-form: it is the program page on raw media
     * and the sector on managed ones.  The CLI and consumers treat it
     * as the page, so a descriptor where it disagrees is not one this
     * code wrote. */
    if (g->write_gran != ((flags & CFS_FLASH_F_MANAGED) ? g->sector : g->page))
        return -1;
    /* The programming rule is "only clear bits", i.e. the all-ones erased
     * state every NOR/NAND part uses.  A 0x00-erased device would need the
     * inverse rule; v1 does not implement it, so refuse it instead of
     * accepting a medium that can never be programmed. */
    if (g->erased_byte != 0xFF) return -1;
    if (g->media < CFS_FLASH_NOR || g->media > CFS_FLASH_MCU) return -1;
    return 0;
}

int cfs_flash_profile(const char *type, CfsFlashGeom *g, unsigned *flags) {
    if (!type || !g) return -1;
    memset(g, 0, sizeof *g);
    unsigned f = 0;
    if (!strcmp(type, "nor")) {
        g->media = CFS_FLASH_NOR; g->sector = 512; g->page = 256;
        g->erase = 4096; g->write_gran = g->page; g->erased_byte = 0xFF;
    } else if (!strcmp(type, "nand")) {
        g->media = CFS_FLASH_NAND; g->sector = 512; g->page = 2048;
        g->erase = 131072; g->write_gran = g->page; g->erased_byte = 0xFF;
    } else if (!strcmp(type, "emmc")) {
        g->media = CFS_FLASH_EMMC; g->sector = 512; g->page = 512;
        g->erase = 524288; g->write_gran = g->sector; g->erased_byte = 0xFF;
        f |= CFS_FLASH_F_MANAGED;
    } else if (!strcmp(type, "mcu")) {
        g->media = CFS_FLASH_MCU; g->sector = 512; g->page = 1024;
        g->erase = 4096; g->write_gran = g->page; g->erased_byte = 0xFF;
    } else {
        errno = EINVAL;
        return -1;
    }
    if (flags) *flags = f;
    return 0;
}

/* ── descriptor (two 2 KiB copies) ────────────────────────────── */

static void desc_encode_copy(uint8_t d[CFS_FLASH_COPY_SIZE], const CfsFlashGeom *g,
                             unsigned flags, uint64_t erase_count,
                             const uint32_t *bad, uint32_t bad_n, uint32_t seq) {
    memset(d, 0, CFS_FLASH_COPY_SIZE);
    memcpy(d + CFS_FLASH_D_MAGIC, CFS_FLASH_MAGIC, 4);
    cfs_wr16(d + CFS_FLASH_D_VERSION, CFS_FLASH_VERSION);
    cfs_wr16(d + CFS_FLASH_D_MEDIA, (uint16_t)g->media);
    cfs_wr32(d + CFS_FLASH_D_FLAGS, flags);
    cfs_wr64(d + CFS_FLASH_D_SIZE, g->size);
    cfs_wr32(d + CFS_FLASH_D_SECTOR, g->sector);
    cfs_wr32(d + CFS_FLASH_D_PAGE, g->page);
    cfs_wr32(d + CFS_FLASH_D_ERASE, g->erase);
    cfs_wr32(d + CFS_FLASH_D_WGRAN, g->write_gran);
    cfs_wr32(d + CFS_FLASH_D_ERASED, (uint32_t)g->erased_byte);
    cfs_wr64(d + CFS_FLASH_D_ECOUNT, erase_count);
    cfs_wr32(d + CFS_FLASH_D_BADN, bad_n);
    cfs_wr32(d + CFS_FLASH_D_BADOFF, CFS_FLASH_D_BAD_ENTRY);
    for (uint32_t i = 0; i < bad_n; i++)
        cfs_wr32(d + CFS_FLASH_D_BAD_ENTRY + i * 4, bad[i]);
    cfs_wr32(d + CFS_FLASH_D_SEQ, seq);
    cfs_wr32(d + CFS_FLASH_D_CRC, cfs_sb_crc32(d, CFS_FLASH_D_CRC));
}

/* Parse one copy.  Does not touch bad[]; only the validity and geometry. */
typedef struct {
    CfsFlashGeom g;
    unsigned flags;
    uint64_t erase_count;
    uint32_t bad_n, seq;
} FlashDesc;

static int desc_decode_copy(const uint8_t d[CFS_FLASH_COPY_SIZE], FlashDesc *o) {
    if (memcmp(d + CFS_FLASH_D_MAGIC, CFS_FLASH_MAGIC, 4) != 0) return -1;
    if (cfs_rd16(d + CFS_FLASH_D_VERSION) != CFS_FLASH_VERSION) return -1;
    if (cfs_rd32(d + CFS_FLASH_D_CRC) != cfs_sb_crc32(d, CFS_FLASH_D_CRC))
        return -1;
    memset(o, 0, sizeof *o);
    o->g.media       = (int)cfs_rd16(d + CFS_FLASH_D_MEDIA);
    o->g.size        = cfs_rd64(d + CFS_FLASH_D_SIZE);
    o->g.sector      = cfs_rd32(d + CFS_FLASH_D_SECTOR);
    o->g.page        = cfs_rd32(d + CFS_FLASH_D_PAGE);
    o->g.erase       = cfs_rd32(d + CFS_FLASH_D_ERASE);
    o->g.write_gran  = cfs_rd32(d + CFS_FLASH_D_WGRAN);
    o->g.erased_byte = (int)cfs_rd32(d + CFS_FLASH_D_ERASED);
    /* Flags first: geom_check() needs them to know whether write_gran is the
     * page (raw) or the sector (managed). */
    o->flags         = cfs_rd32(d + CFS_FLASH_D_FLAGS);
    if (geom_check(&o->g, o->flags) != 0) return -1;
    o->erase_count = cfs_rd64(d + CFS_FLASH_D_ECOUNT);
    o->bad_n       = cfs_rd32(d + CFS_FLASH_D_BADN);
    o->seq         = cfs_rd32(d + CFS_FLASH_D_SEQ);
    if (o->bad_n > CFS_FLASH_D_BAD_MAX) return -1;
    /* The list's offset is part of the record, not an implication: a copy
     * that points it elsewhere is not one this reader wrote. */
    if (cfs_rd32(d + CFS_FLASH_D_BADOFF) != CFS_FLASH_D_BAD_ENTRY) return -1;
    for (uint32_t i = 0; i < o->bad_n; i++) {
        uint32_t idx = cfs_rd32(d + CFS_FLASH_D_BAD_ENTRY + i * 4);
        if ((uint64_t)idx * o->g.erase >= o->g.size) return -1;
    }
    return 0;
}

/* Read the descriptor area and pick the newest valid copy.  Returns 0 and
 * fills @o and @copy_idx; -1 when neither copy is usable. */
static int desc_read(int fd, uint64_t desc_off, uint64_t span, FlashDesc *o,
                     int *copy_idx) {
    uint8_t area[CFS_FLASH_DESC_SIZE];
    if (span < CFS_FLASH_DESC_SIZE) return -1;
    if (pr_full(fd, area, sizeof area, (off_t)desc_off) != 0) return -1;
    FlashDesc a, b;
    int va = desc_decode_copy(area, &a) == 0;
    int vb = desc_decode_copy(area + CFS_FLASH_COPY_SIZE, &b) == 0;
    if (!va && !vb) return -1;
    if (va && (!vb || a.seq >= b.seq)) { *o = a; *copy_idx = 0; }
    else { *o = b; *copy_idx = 1; }
    return 0;
}

static int desc_load_bad(int fd, uint64_t desc_off, int copy_idx, CfsFlash *f,
                         uint32_t bad_n) {
    uint8_t area[CFS_FLASH_DESC_SIZE];
    if (pr_full(fd, area, sizeof area, (off_t)desc_off) != 0) return -1;
    const uint8_t *d = area + (size_t)copy_idx * CFS_FLASH_COPY_SIZE;
    free(f->bad);
    f->bad = NULL;
    f->bad_n = bad_n;
    if (!bad_n) return 0;
    f->bad = malloc(bad_n * sizeof(uint32_t));
    if (!f->bad) return -1;
    for (uint32_t i = 0; i < bad_n; i++) {
        uint32_t idx = cfs_rd32(d + CFS_FLASH_D_BAD_ENTRY + i * 4);
        /* This second read is not the one desc_read validated (another handle
         * may have rewritten the area in between), so re-check the range. */
        if ((uint64_t)idx * f->erase >= f->size) {
            free(f->bad);
            f->bad = NULL;
            f->bad_n = 0;
            return -1;
        }
        f->bad[i] = idx;
    }
    return 0;
}

/* Write the copy that was not last read, with seq+1.  Both copies stay valid
 * until the next update; a torn write leaves the current one intact. */
static int desc_store(CfsFlash *f) {
    CfsFlashGeom g = {
        .size = f->size, .sector = f->sector, .page = f->page,
        .erase = f->erase, .write_gran = f->write_gran,
        .erased_byte = f->erased_byte, .media = f->media,
    };
    /* Sequence numbers are 32 bits; letting one wrap makes the stale copy
     * numerically larger and it wins forever, so an update would stop
     * persisting.  On the last value before the wrap, rewrite both copies
     * with fresh low numbers instead. */
    if (f->desc_seq >= 0xFFFFFFFEu) {
        /* Write the copy that is NOT current first, and the current one
         * second.  A crash between the two then leaves the current copy with
         * its old (huge) sequence, which still wins over the reset copy — the
         * latest state survives.  Writing them in the other order would let
         * the stale copy win after a crash. */
        uint8_t a[CFS_FLASH_COPY_SIZE], b[CFS_FLASH_COPY_SIZE];
        int cur = f->desc_idx;
        int other = 1 - cur;
        desc_encode_copy(a, &g, f->flags, f->erase_count, f->bad, f->bad_n, 1);
        desc_encode_copy(b, &g, f->flags, f->erase_count, f->bad, f->bad_n, 2);
        if (pw_full(f->fd, a, sizeof a,
                    (off_t)(f->extent_off + f->size +
                            (uint64_t)other * CFS_FLASH_COPY_SIZE)) != 0)
            return -1;
        if (pw_full(f->fd, b, sizeof b,
                    (off_t)(f->extent_off + f->size +
                            (uint64_t)cur * CFS_FLASH_COPY_SIZE)) != 0)
            return -1;
        f->desc_idx = cur;
        f->desc_seq = 2;
        return 0;
    }
    int idx = 1 - f->desc_idx;
    uint8_t copy[CFS_FLASH_COPY_SIZE];
    uint32_t seq = f->desc_seq + 1;
    desc_encode_copy(copy, &g, f->flags, f->erase_count, f->bad, f->bad_n, seq);
    if (pw_full(f->fd, copy, sizeof copy,
                (off_t)(f->extent_off + f->size + (uint64_t)idx * CFS_FLASH_COPY_SIZE)) != 0)
        return -1;
    f->desc_idx = idx;
    f->desc_seq = seq;
    return 0;
}

/* ── open / close / create ────────────────────────────────────── */

CfsFlash *cfs_flash_open(CFS *c, const char *tag, int writable) {
    if (!c) { errno = EINVAL; return NULL; }
    char path[300];
    if (resolve_path(tag, path, sizeof path) != 0) { errno = EINVAL; return NULL; }
    InodeEntry *e = flash_lookup(c, path);
    if (!e || e->raw.mode != CFS_MODE_FLASH || e->raw.block_count != 1) {
        errno = ENOENT;
        return NULL;
    }
    if (writable && !(c->flags & CFS_RDWR)) { errno = EACCES; return NULL; }
    const CfsBlock *bl = &e->raw.blocks[0];
    if (bl->comp_size != 0 || bl->orig_size < CFS_FLASH_DESC_SIZE ||
        (bl->offset % CFS_FLASH_DESC_SIZE) != 0) {
        errno = EIO;
        return NULL;
    }

    CfsFlash *f = calloc(1, sizeof *f);
    if (!f) return NULL;
    f->ref = c->flash_ref;
    snprintf(f->path, sizeof f->path, "%s", path);
    f->extent_off = bl->offset;
    f->fd = dup(c->fd);
    if (f->fd < 0) { free(f); return NULL; }

    FlashDesc d;
    int idx;
    if (desc_read(f->fd, f->extent_off + bl->orig_size - CFS_FLASH_DESC_SIZE,
                  bl->orig_size, &d, &idx) != 0 ||
        d.g.size + CFS_FLASH_DESC_SIZE != bl->orig_size) {
        close(f->fd);
        free(f);
        errno = EIO;
        return NULL;
    }
    f->size = d.g.size;
    f->sector = d.g.sector; f->page = d.g.page;
    f->erase = d.g.erase; f->write_gran = d.g.write_gran;
    f->erased_byte = d.g.erased_byte; f->media = d.g.media;
    f->flags = d.flags; f->erase_count = d.erase_count;
    f->desc_seq = d.seq; f->desc_idx = idx;
    if (desc_load_bad(f->fd, f->extent_off + bl->orig_size - CFS_FLASH_DESC_SIZE,
                      idx, f, d.bad_n) != 0) {
        close(f->fd); free(f);
        return NULL;
    }
    f->writable = writable;
    if (f->ref) f->ref->n++;     /* compact refuses while this is non-zero */
    return f;
}

void cfs_flash_close(CfsFlash *f) {
    if (!f) return;
    if (f->writable) cfs_flash_flush(f);
    if (f->map && f->map_len) munmap(f->map, f->map_len);
    if (f->fd >= 0) close(f->fd);
    if (f->ref && --f->ref->n == 0 && f->ref->orphan) free(f->ref);
    free(f->bad);
    free(f);
}

int cfs_flash_create(CFS *c, const char *tag, const CfsFlashGeom *g,
                     unsigned flags) {
    if (!c || !g || !(c->flags & CFS_RDWR)) { errno = EINVAL; return -1; }
    if (!cfs_flash_entry_tag_ok(tag)) { errno = EINVAL; return -1; }
    if (geom_check(g, flags) != 0) { errno = EINVAL; return -1; }
    if (flags & CFS_FLASH_F_MANAGED) { errno = EOPNOTSUPP; return -1; }
    char path[300];
    if (resolve_path(tag, path, sizeof path) != 0) { errno = EINVAL; return -1; }
    if (flash_lookup(c, path)) { errno = EEXIST; return -1; }

    uint64_t align = host_align();
    if (g->size % align) { errno = EINVAL; return -1; }
    uint64_t span = g->size + CFS_FLASH_DESC_SIZE;
    uint64_t off = (c->append_off + align - 1) & ~(align - 1);
    if (span > 0xFFFFFFFFu) { errno = EFBIG; return -1; }
    if (c->phys_limit && off + span > c->phys_limit) {
        errno = ENOSPC;
        return CFS_ENOSPC;
    }

    /* The append cursor moves before anything else: cfs_sync() flushes pending
     * @store bytes through it first, and those must not land on guest byte 0.
     * It is restored on every failure path below — a refused create must not
     * leave the handle describing a medium that does not exist. */
    uint64_t old_append = c->append_off;
    int rc = -1;
    c->append_off = off + span;

    /* Medium first, inode second: a crash in between leaves an unreferenced
     * range (harmless, and compact can reclaim it), never a medium that
     * claims to exist while reading as sparse zeros.  XIP needs real bytes,
     * so this is a physical fill, not ftruncate. */
    uint8_t *buf = malloc(FLASH_FILL_CHUNK);
    if (!buf) goto fail;
    memset(buf, g->erased_byte, FLASH_FILL_CHUNK);
    uint64_t done = 0;
    while (done < g->size) {
        size_t n = g->size - done < FLASH_FILL_CHUNK
                   ? (size_t)(g->size - done) : FLASH_FILL_CHUNK;
        if (pw_full(c->fd, buf, n, (off_t)(off + done)) != 0) {
            free(buf);
            if (errno == ENOSPC) rc = CFS_ENOSPC;
            goto fail;
        }
        done += n;
    }
    free(buf);

    /* Both descriptor copies, so either one alone can restore the geometry. */
    uint8_t area[CFS_FLASH_DESC_SIZE];
    desc_encode_copy(area, g, flags, 0, NULL, 0, 1);
    desc_encode_copy(area + CFS_FLASH_COPY_SIZE, g, flags, 0, NULL, 0, 2);
    if (pw_full(c->fd, area, sizeof area, (off_t)(off + g->size)) != 0)
        goto fail;
    if (fsync(c->fd) != 0) goto fail;

    InodeEntry *na = realloc(c->inodes, (c->inode_count + 1) * sizeof(InodeEntry));
    if (!na) goto fail;
    c->inodes = na;
    InodeEntry *e = &c->inodes[c->inode_count];
    memset(e, 0, sizeof *e);
    e->path = strdup(path);
    if (!e->path) goto fail;
    e->raw.orig_size = span;
    e->raw.mtime = (uint64_t)time(NULL);
    e->raw.mode = CFS_MODE_FLASH;
    e->raw.path_len = (uint16_t)strlen(path);
    e->raw.block_count = 1;
    e->raw.blocks = calloc(1, sizeof(CfsBlock));
    if (!e->raw.blocks) { free(e->path); e->path = NULL; goto fail; }
    e->raw.blocks[0].offset = off;
    e->raw.blocks[0].comp_size = 0;
    e->raw.blocks[0].orig_size = (uint32_t)span;
    c->inode_count++;
    if (cfs_sync(c) == 0) return 0;
    if (c->last_commit_landed) {
        /* The slot was written before the failure (fsync): the container now
         * describes the medium.  Dropping the in-memory entry would make the
         * handle disagree with the file, so keep it. */
        return -1;
    }
    /* Not committed: the entry exists in memory only.  Remove it by path —
     * a nested sync may have appended @store after it, so it is not
     * necessarily the last entry in the array. */
    for (uint32_t i = 0; i < c->inode_count; i++) {
        if (!c->inodes[i].path || strcmp(c->inodes[i].path, path)) continue;
        free(c->inodes[i].path);
        free(c->inodes[i].raw.blocks);
        if (i < c->inode_count - 1)
            memmove(&c->inodes[i], &c->inodes[i + 1],
                    (c->inode_count - i - 1) * sizeof(InodeEntry));
        c->inode_count--;
        break;
    }
    /* The sticky "has flash" bit is set by cfs_sync from the table it was
     * about to write; with the entry gone there is no medium to describe. */
    {
        int any = 0;
        for (uint32_t i = 0; i < c->inode_count; i++)
            if (c->inodes[i].path && c->inodes[i].raw.mode == CFS_MODE_FLASH)
                any = 1;
        if (!any) c->sb.flags &= ~CFS_SB_FLAG_FLASH;
    }
fail:
    /* The cursor is deliberately not rewound: a nested @store flush may have
     * advanced it past this extent, and a short write can leave referenced
     * bytes between the two positions.  An unreferenced extent is reclaimed
     * by compact; overwriting live bytes is not recoverable. */
    (void)old_append;
    return rc;
}

int cfs_flash_any_xip(CFS *c) {
    if (!c) return 0;
    for (uint32_t i = 0; i < c->inode_count; i++) {
        InodeEntry *e = &c->inodes[i];
        if (!e->path || e->raw.mode != CFS_MODE_FLASH || e->raw.block_count != 1)
            continue;
        const CfsBlock *bl = &e->raw.blocks[0];
        if (bl->orig_size < CFS_FLASH_DESC_SIZE) continue;
        FlashDesc d;
        int idx;
        if (desc_read(c->fd, bl->offset + bl->orig_size - CFS_FLASH_DESC_SIZE,
                      bl->orig_size, &d, &idx) == 0 &&
            (d.flags & CFS_FLASH_F_XIP))
            return 1;
    }
    return 0;
}

/* ── geometry ─────────────────────────────────────────────────── */

int cfs_flash_geometry(CfsFlash *f, uint64_t *size, uint32_t *sector,
                       uint32_t *erase_block, uint32_t *write_gran) {
    if (!f) return -1;
    if (size) *size = f->size;
    if (sector) *sector = f->sector;
    if (erase_block) *erase_block = f->erase;
    if (write_gran) *write_gran = f->write_gran;
    return 0;
}

int cfs_flash_info(CfsFlash *f, int *media, int *erased_byte, unsigned *flags,
                   uint64_t *erase_count, uint32_t *bad_count) {
    if (!f) return -1;
    if (media) *media = f->media;
    if (erased_byte) *erased_byte = f->erased_byte;
    if (flags) *flags = f->flags;
    if (erase_count) *erase_count = f->erase_count;
    if (bad_count) *bad_count = f->bad_n;
    return 0;
}

/* ── bad blocks ───────────────────────────────────────────────── */

static int bad_index(const CfsFlash *f, uint64_t block) {
    for (uint32_t i = 0; i < f->bad_n; i++)
        if (f->bad[i] == block) return 1;
    return 0;
}

int cfs_flash_is_bad(CfsFlash *f, uint64_t off) {
    if (!f || off >= f->size) { errno = EINVAL; return -1; }
    return bad_index(f, off / f->erase);
}

int cfs_flash_bad_set(CfsFlash *f, uint32_t block, int bad) {
    if (!f) { errno = EINVAL; return -1; }
    if (!flash_writable(f)) return -1;
    if (block >= f->size / f->erase) { errno = EINVAL; return -1; }
    if (bad) {
        if (bad_index(f, block)) return 0;
        if (f->bad_n >= CFS_FLASH_D_BAD_MAX) { errno = ENOSPC; return -1; }
    } else {
        uint32_t i;
        for (i = 0; i < f->bad_n; i++)
            if (f->bad[i] == block) break;
        if (i == f->bad_n) return 0;
    }

    /* Snapshot, because a failed descriptor write must not leave the handle
     * claiming a block is bad that the container does not record: a retry
     * would then see bad_index() and return success without writing. */
    uint32_t old_n = f->bad_n;
    unsigned old_flags = f->flags;
    uint32_t *snap = NULL;
    if (old_n) {
        snap = malloc(old_n * sizeof(uint32_t));
        if (!snap) return -1;
        memcpy(snap, f->bad, old_n * sizeof(uint32_t));
    }
    if (bad) {
        uint32_t *nb = realloc(f->bad, (old_n + 1) * sizeof(uint32_t));
        if (!nb) { free(snap); return -1; }
        f->bad = nb;
        f->bad[old_n] = block;
        f->bad_n = old_n + 1;
    } else {
        uint32_t i;
        for (i = 0; i < old_n; i++)
            if (f->bad[i] == block) break;
        f->bad[i] = f->bad[old_n - 1];
        f->bad_n = old_n - 1;
    }
    if (f->bad_n) f->flags |= CFS_FLASH_F_BADTAB;
    else f->flags &= ~CFS_FLASH_F_BADTAB;
    if (desc_store(f) != 0) {
        free(f->bad);
        f->bad = snap;
        f->bad_n = old_n;
        f->flags = old_flags;
        return -1;
    }
    free(snap);
    if (sync_each() && fsync(f->fd) != 0) return -1;
    return 0;
}

/* ── I/O ──────────────────────────────────────────────────────── */

static int sync_each(void) {
    const char *s = getenv("CFS_FLASH_SYNC");
    return s && !strcmp(s, "each");
}

ssize_t cfs_flash_read(CfsFlash *f, uint64_t off, void *buf, size_t len) {
    if (!f || (!buf && len)) { errno = EINVAL; return -1; }
    if (off > f->size || len > f->size - off) { errno = EINVAL; return -1; }
    if (!len) return 0;
    if (pr_full(f->fd, buf, len, (off_t)(f->extent_off + off)) != 0)
        return -1;
    return (ssize_t)len;
}

ssize_t cfs_flash_write(CfsFlash *f, uint64_t off, const void *buf, size_t len) {
    if (!f || (!buf && len)) { errno = EINVAL; return -1; }
    if (!flash_writable(f)) return -1;
    if (off > f->size || len > f->size - off) { errno = EINVAL; return -1; }
    if (!len) return 0;
    if (f->flags & CFS_FLASH_F_MANAGED) { errno = EOPNOTSUPP; return -1; }
    /* A program operation runs inside one page; crossing a page boundary is
     * what a real controller refuses, and it is also what keeps len <= page. */
    if (off / f->page != (off + len - 1) / f->page) { errno = EINVAL; return -1; }
    for (uint64_t b = off / f->erase; b <= (off + len - 1) / f->erase; b++)
        if (bad_index(f, b)) { errno = EIO; return -1; }

    /* Validate the whole range before writing anything.  Every byte must be
     * in the erased state — programming only clears bits, and a page that has
     * already been written needs an erase first (both rules the vk side
     * asked for).  NAND additionally programs whole pages. */
    if (f->media == CFS_FLASH_NAND &&
        ((off % f->page) || (len % f->page))) { errno = EINVAL; return -1; }
    uint8_t *old = malloc(len);
    if (!old) return -1;
    if (pr_full(f->fd, old, len, (off_t)(f->extent_off + off)) != 0) {
        free(old);
        return -1;
    }
    const uint8_t *nw = buf;
    for (size_t i = 0; i < len; i++) {
        if (old[i] != (uint8_t)f->erased_byte || (old[i] & nw[i]) != nw[i]) {
            free(old);
            errno = EIO;
            return -1;
        }
    }
    free(old);
    if (pw_full(f->fd, buf, len, (off_t)(f->extent_off + off)) != 0)
        return -1;
    if (sync_each() && fsync(f->fd) != 0) return -1;
    return (ssize_t)len;
}

int cfs_flash_erase(CfsFlash *f, uint64_t off, size_t len) {
    if (!f) { errno = EINVAL; return -1; }
    if (!flash_writable(f)) return -1;
    if (!len || (off % f->erase) || (len % f->erase) ||
        off > f->size || len > f->size - off) {
        errno = EINVAL;
        return -1;
    }
    if (f->flags & CFS_FLASH_F_MANAGED) { errno = EOPNOTSUPP; return -1; }
    uint64_t first = off / f->erase, n = len / f->erase;
    for (uint64_t b = first; b < first + n; b++)
        if (bad_index(f, b)) { errno = EIO; return -1; }

    uint8_t *buf = malloc(FLASH_FILL_CHUNK);
    if (!buf) return -1;
    memset(buf, f->erased_byte, FLASH_FILL_CHUNK);
    uint64_t done = 0;
    while (done < len) {
        size_t m = len - done < FLASH_FILL_CHUNK ? len - (size_t)done : FLASH_FILL_CHUNK;
        if (pw_full(f->fd, buf, m, (off_t)(f->extent_off + off + done)) != 0) {
            free(buf);
            return -1;
        }
        done += m;
    }
    free(buf);
    uint64_t old_count = f->erase_count;
    f->erase_count += n;
    if (desc_store(f) != 0) { f->erase_count = old_count; return -1; }
    if (sync_each() && fsync(f->fd) != 0) return -1;
    return 0;
}

int cfs_flash_flush(CfsFlash *f) {
    if (!f) return -1;
    if (f->map && f->map_len && msync(f->map, f->map_len, MS_SYNC) != 0)
        return -1;
    return fsync(f->fd);
}

/* ── XIP ──────────────────────────────────────────────────────── */

void *cfs_flash_map(CfsFlash *f, uint64_t off, size_t len, int *writable) {
    if (!f) { errno = EINVAL; return NULL; }
    if (off > f->size || len > f->size - off) { errno = EINVAL; return NULL; }
    /* mmap needs the file offset to be a multiple of the host page size, which
     * is not always 4 KiB (16/64 KiB arm64 kernels exist). */
    if (f->extent_off % host_align() || f->size % host_align()) {
        errno = ENOTSUP;
        return NULL;
    }
    if (!f->map) {
        int prot = PROT_READ | (f->writable ? PROT_WRITE : 0);
        void *m = mmap(NULL, (size_t)f->size, prot, MAP_SHARED, f->fd,
                       (off_t)f->extent_off);
        if (m == MAP_FAILED) return NULL;
        f->map = m;
        f->map_len = (size_t)f->size;
    }
    if (writable) *writable = f->writable;
    return (uint8_t *)f->map + off;
}

int cfs_flash_extent(CfsFlash *f, int *fd, off_t *file_off, uint64_t *len) {
    if (!f) { errno = EINVAL; return -1; }
    if (f->extent_off % host_align() || f->size % host_align()) {
        errno = ENOTSUP;
        return -1;
    }
    if (fd) *fd = f->fd;
    if (file_off) *file_off = (off_t)f->extent_off;
    if (len) *len = f->size;
    return 0;
}
