/* cfs_ext4_install.c — install an ISO file tree into an ext4 partition.
 *
 * Flow: cfs_mkfs_ext4_at (format) -> sequential allocator (block + inode
 * bitmaps kept in memory) -> write inodes/extents/directory entries.
 *
 * Layout (single-block-group, 4KB blocks, 256B inodes — matches
 * cfs_mkfs_ext4.c):
 *   block 0        superblock (at +1024)
 *   block 1        group descriptor table (the block after the superblock)
 *   block 2        block bitmap
 *   block 3        inode bitmap
 *   block 4..4+ib-1 inode table (inode n at (n-1)*256)
 *   block db=4+ib  root directory data
 *   block db+1..   data (sequential allocation)
 *
 * Files and directories get a single extent each (sequential allocation,
 * contiguous by construction); directories grow one block at a time,
 * each block one extent entry (max 4 entries / 16KB per dir).
 *
 * Write strategy: metadata blocks and small files are staged in a dirty-
 * block cache and flushed as merged big regions at the end.  The block
 * layer's patch-write path recompresses a whole 64MB block per call, so
 * per-block tiny writes would be catastrophic; merged writes amortize it
 * to one read-modify-write per 64MB block touched. */

#include "cfs.h"
#include "cfs_ext4.h"
#include "cfs_iso9660.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#define BS 4096u
#define BPG 32768u    /* blocks per group (8 x block_size) */
#define FIRST_INO 11u /* s_first_ino: 1..10 are reserved */
#define BIG_WRITE (64u * 1024u)   /* >= this size: write directly */

typedef struct {
    char     path[512];
    uint32_t ino;
    uint8_t  is_dir;
} InstEntry;

typedef struct {
    uint32_t blk;
    uint8_t  dirty;
    uint8_t  data[BS];
} DirtyBlock;

typedef struct {
    CFS    *c;
    uint64_t base;
    uint32_t bc;              /* blocks in fs */
    uint32_t ic;              /* inodes in fs */
    uint32_t groups;          /* block groups */
    uint32_t spg;             /* blocks per group */
    uint32_t ipg;             /* inodes per group */
    uint32_t itab_b;          /* inode-table blocks per group */
    uint32_t gdt_b;           /* descriptor blocks */
    uint32_t *bmp, *ibmp, *itab;   /* per-group locations, read from the GDT */
    uint8_t *bbm;             /* flat block bitmap, bc bits */
    uint8_t *ibm;             /* flat inode bitmap, ic bits */
    uint32_t next_block;
    uint32_t next_ino;
    uint32_t free_blocks, free_inodes;
    InstEntry *ents;
    int nents, ents_cap;
    DirtyBlock *dirty;
    int ndirty, dirty_cap;
} InstCtx;

static uint32_t rd32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void wr16le(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }

/* First block after the metadata of the group `blk` belongs to.  Metadata sits
 * at the start of every group, so anything below this is mkfs-owned and has to
 * be read before it is modified. */
static uint32_t meta_end(const InstCtx *x, uint32_t blk) {
    uint32_t g = blk / BPG;
    if (g >= x->groups) g = x->groups - 1;
    return x->itab[g] + x->itab_b;
}

/* ── dirty-block cache ──────────────────────────────────────── */
static DirtyBlock *cache_find(InstCtx *x, uint32_t blk) {
    for (int i = 0; i < x->ndirty; i++)
        if (x->dirty[i].blk == blk) return &x->dirty[i];
    return NULL;
}

static int cache_get(InstCtx *x, uint32_t blk, size_t off, void *buf, size_t n) {
    DirtyBlock *d = cache_find(x, blk);
    if (d) { memcpy(buf, d->data + off, n); return 0; }
    return cfs_block_read(x->c, buf, n, (off_t)(x->base + (uint64_t)blk * BS + off)) == (ssize_t)n ? 0 : -1;
}

/* write into a block; absent blocks start as zeros (mkfs just ran) */
static int cache_set(InstCtx *x, uint32_t blk, size_t off, const void *buf, size_t n) {
    if (off + n > BS) return -1;
    DirtyBlock *d = cache_find(x, blk);
    if (!d) {
        if (x->ndirty == x->dirty_cap) {
            int nc = x->dirty_cap ? x->dirty_cap * 2 : 64;
            DirtyBlock *nd = realloc(x->dirty, (size_t)nc * sizeof(*nd));
            if (!nd) return -1;
            x->dirty = nd; x->dirty_cap = nc;
        }
        d = &x->dirty[x->ndirty++];
        d->blk = blk;
        d->dirty = 0;
        if (blk < meta_end(x, blk)) {
            /* metadata region (sb/bitmaps/inode table) was written by mkfs —
             * read it before modifying, or we clobber e.g. inodes 1-2 */
            if (cfs_block_read(x->c, d->data, BS,
                               (off_t)(x->base + (uint64_t)blk * BS)) != (ssize_t)BS)
                return -1;
        } else {
            /* data region: mkfs left it unwritten (holes read as zero) */
            memset(d->data, 0, BS);
        }
    }
    memcpy(d->data + off, buf, n);
    d->dirty = 1;
    return 0;
}

static int cmp_blk(const void *a, const void *b) {
    uint32_t x = ((const DirtyBlock *)a)->blk, y = ((const DirtyBlock *)b)->blk;
    return x < y ? -1 : x > y ? 1 : 0;
}

static int cache_flush(InstCtx *x) {
    if (!x->ndirty) return 0;
    qsort(x->dirty, (size_t)x->ndirty, sizeof(*x->dirty), cmp_blk);
    int i = 0;
    while (i < x->ndirty) {
        uint32_t start = x->dirty[i].blk, end = start;
        uint64_t total = BS;
        int j = i;
        while (j + 1 < x->ndirty && x->dirty[j + 1].blk == end + 1) {
            end++; j++; total += BS;
        }
        /* gather into one buffer */
        uint8_t *buf = malloc((size_t)total);
        if (!buf) return -1;
        for (int k = i; k <= j; k++)
            memcpy(buf + (uint64_t)(x->dirty[k].blk - start) * BS,
                   x->dirty[k].data, BS);
        int rc = cfs_block_write(x->c, buf, total,
                                 (off_t)(x->base + (uint64_t)start * BS));
        free(buf);
        if (rc) return -1;
        i = j + 1;
    }
    return 0;
}

/* ── low-level IO (byte offsets via block layer) ────────────── */
static int pr(InstCtx *x, uint64_t off, void *buf, size_t n) {
    uint32_t blk = (uint32_t)(off / BS);
    size_t boff = (size_t)(off % BS);
    if (boff + n > BS) return -1;
    return cache_get(x, blk, boff, buf, n);
}

static int pw(InstCtx *x, uint64_t off, const void *buf, size_t n) {
    uint32_t blk = (uint32_t)(off / BS);
    size_t boff = (size_t)(off % BS);
    if (boff + n > BS) return -1;
    return cache_set(x, blk, boff, buf, n);
}

/* direct big write: block-aligned region, bypasses the cache */
static int pw_big(InstCtx *x, uint64_t off, const void *buf, size_t n) {
    if (off % BS) return -1;
    return cfs_block_write(x->c, buf, n, (off_t)(x->base + off)) == 0 ? 0 : -1;
}

/* ── bitmaps ────────────────────────────────────────────────── */
static void bm_set(uint8_t *bm, uint32_t bit) { bm[bit >> 3] |= (uint8_t)(1u << (bit & 7)); }

static uint32_t alloc_blocks(InstCtx *x, uint32_t n, uint32_t *first) {
    if (!n) { *first = 0; return 0; }
    /* First run of n free blocks from the cursor.  Used blocks (metadata of
     * any group, already-allocated data) are simply skipped, so this works
     * for any group layout. */
    uint32_t start = x->next_block, run = 0;
    for (uint32_t b = x->next_block; b < x->bc; b++) {
        if (x->bbm[b >> 3] & (uint8_t)(1u << (b & 7))) { run = 0; start = b + 1; continue; }
        if (++run == n) {
            *first = start;
            for (uint32_t i = 0; i < n; i++) bm_set(x->bbm, start + i);
            x->next_block = start + n;
            x->free_blocks -= n;
            return n;
        }
    }
    return 0;
}

static uint32_t alloc_inode(InstCtx *x) {
    if (x->next_ino >= x->ic) return 0;
    uint32_t ino = x->next_ino++;
    bm_set(x->ibm, ino - 1);      /* bit 0 is inode 1, not inode 0 */
    x->free_inodes--;
    return ino;
}

/* ── inode IO ───────────────────────────────────────────────── */
static uint64_t ino_off(InstCtx *x, uint32_t ino) {
    uint32_t g = (ino - 1) / x->ipg;          /* which group's inode table */
    uint32_t idx = (ino - 1) % x->ipg;        /* index inside it */
    if (g >= x->groups) return 0;
    return (uint64_t)x->itab[g] * BS + (uint64_t)idx * 256;
}

static int read_inode(InstCtx *x, uint32_t ino, Ext4Inode *out) {
    uint8_t raw[256];
    if (pr(x, ino_off(x, ino), raw, 256)) return -1;
    memcpy(out, raw, sizeof(*out));
    return 0;
}

static int write_inode(InstCtx *x, uint32_t ino, const Ext4Inode *in) {
    uint8_t raw[256];
    memset(raw, 0, sizeof(raw));
    memcpy(raw, in, sizeof(*in));
    return pw(x, ino_off(x, ino), raw, 256);
}

/* Fresh inode with one extent {ee_block=0, ee_len, ee_start} */
static void make_inode(Ext4Inode *in, uint16_t mode, uint32_t size,
                       uint32_t ee_len, uint32_t ee_start, uint16_t links,
                       uint32_t mtime) {
    memset(in, 0, sizeof(*in));
    in->i_mode = mode;
    in->i_size_lo = size;
    in->i_links_count = links;
    in->i_flags = 0x00080000;              /* EXT4_EXTENTS_FL */
    in->i_extra_isize = 28;
    uint32_t now = mtime ? mtime : (uint32_t)time(NULL);
    in->i_atime = now; in->i_ctime = now; in->i_mtime = now; in->i_crtime = now;
    in->i_blocks_lo = ee_len * (BS / 512);
    if (ee_len == 0 && size == 0) return;  /* empty file: no extent */
    in->i_block[0] = 0xF30A | (1u << 16);  /* header: magic, entries=1 */
    in->i_block[1] = 4;                    /* max entries */
    in->i_block[2] = 0;
    in->i_block[3] = 0;                    /* ee_block */
    in->i_block[4] = ee_len;               /* ee_len, ee_start_hi=0 */
    in->i_block[5] = ee_start;
}

/* grow a directory by one block: append extent entry, return new block */
static int dir_grow(InstCtx *x, uint32_t ino, uint32_t *new_block) {
    Ext4Inode in;
    if (read_inode(x, ino, &in)) return -1;
    uint16_t entries = (uint16_t)(in.i_block[0] >> 16);
    if (entries >= 4) return -1;           /* extent array full (16KB dirs) */
    uint32_t blk;
    if (!alloc_blocks(x, 1, &blk)) return -1;
    uint32_t total = in.i_size_lo / BS;
    in.i_block[0] = 0xF30A | ((uint32_t)(entries + 1) << 16);
    in.i_block[3 + 3 * entries] = total;   /* logical block index */
    in.i_block[4 + 3 * entries] = 1;
    in.i_block[5 + 3 * entries] = blk;
    in.i_size_lo += BS;
    in.i_blocks_lo += BS / 512;
    if (write_inode(x, ino, &in)) return -1;
    *new_block = blk;
    return 0;
}

/* add a directory entry to dir ino; grow if full */
static int dir_add(InstCtx *x, uint32_t dir_ino, const char *name,
                   uint32_t child_ino, uint8_t ft) {
    Ext4Inode in;
    if (read_inode(x, dir_ino, &in)) { fprintf(stderr, "DBG: diradd rino\n"); return -1; }
    uint16_t entries = (uint16_t)(in.i_block[0] >> 16);
    if (entries == 0 || in.i_size_lo == 0) { fprintf(stderr, "DBG: diradd empty ent=%u sz=%u\n", entries, in.i_size_lo); return -1; }
    uint32_t nblk = in.i_size_lo / BS;
    if (nblk > 4) { fprintf(stderr, "DBG: diradd nblk>4\n"); return -1; }

    size_t nl = strlen(name);
    if (nl > 255) return -1;
    uint32_t need = (uint32_t)((8 + nl + 3) & ~3u);

    uint8_t blk[BS];
    for (uint32_t b = 0; b < nblk; b++) {
        uint32_t phys = 0; int found = 0;
        for (uint16_t e = 0; e < entries; e++) {
            uint32_t eblock = in.i_block[3 + 3 * e];
            uint32_t elen = in.i_block[4 + 3 * e] & 0xFFFF;
            uint32_t estart = in.i_block[5 + 3 * e];
            if (b >= eblock && b < eblock + elen) {
                phys = estart + (b - eblock);
                found = 1;
                break;
            }
        }
        if (!found) { fprintf(stderr, "DBG: diradd noext\n"); return -1; }
        if (pr(x, (uint64_t)phys * BS, blk, BS)) { fprintf(stderr, "DBG: diradd prblk\n"); return -1; }

        /* walk to the last entry (its rec_len extends to block end) */
        uint32_t pos = 0, last_pos = 0, last_need = 0;
        while (pos < BS) {
            Ext4DirEntry *de = (Ext4DirEntry *)(blk + pos);
            if (de->rec_len == 0) { fprintf(stderr, "DBG: diradd rec0 pos=%u\n", pos); return -1; }
            uint32_t rl = de->rec_len;
            last_pos = pos;
            last_need = (8u + de->name_len + 3u) & ~3u;
            if (pos + rl >= BS) break;
            pos += rl;
        }
        if (last_need + need <= BS - last_pos) {
            Ext4DirEntry *last = (Ext4DirEntry *)(blk + last_pos);
            last->rec_len = (uint16_t)last_need;
            Ext4DirEntry *ne = (Ext4DirEntry *)(blk + last_pos + last_need);
            ne->inode = child_ino;
            ne->rec_len = (uint16_t)(BS - last_pos - last_need);
            ne->name_len = (uint8_t)nl;
            ne->file_type = ft;
            memcpy(ne->name, name, nl);
            if (pw(x, (uint64_t)phys * BS, blk, BS)) return -1;
            goto added;
        }
    }
    /* no space: grow directory and put the entry in the fresh block */
    uint32_t nblk2;
    if (dir_grow(x, dir_ino, &nblk2)) return -1;
    memset(blk, 0, BS);
    Ext4DirEntry *ne = (Ext4DirEntry *)blk;
    ne->inode = child_ino;
    ne->rec_len = BS;
    ne->name_len = (uint8_t)nl;
    ne->file_type = ft;
    memcpy(ne->name, name, nl);
    if (pw(x, (uint64_t)nblk2 * BS, blk, BS)) return -1;
added:
    /* a new subdirectory is itself linked from the parent: nlink += 1 */
    if (ft == EXT4_FT_DIR) {
        if (read_inode(x, dir_ino, &in)) return -1;
        in.i_links_count++;
        if (write_inode(x, dir_ino, &in)) return -1;
    }
    return 0;
}

/* ── context ────────────────────────────────────────────────── */
static int ctx_init(InstCtx *x, CFS *c, uint64_t base) {
    memset(x, 0, sizeof(*x));
    x->c = c; x->base = base;

    uint8_t sbbuf[1024];
    if (pr(x, 1024, sbbuf, 1024)) return -1;
    Ext4Super *s = (Ext4Super *)sbbuf;
    if (s->s_magic != 0xEF53) return -1;

    x->bc = s->s_blocks_count_lo;
    x->ic = s->s_inodes_count;
    x->spg = s->s_blocks_per_group;
    x->ipg = s->s_inodes_per_group;
    if (!x->spg || !x->ipg) { errno = EINVAL; return -1; }
    x->groups = (x->bc + x->spg - 1) / x->spg;
    x->itab_b = ((uint64_t)x->ipg * 256 + BS - 1) / BS;
    x->gdt_b  = ((uint64_t)x->groups * 32 + BS - 1) / BS;   /* 32-byte descriptors */

    x->bmp  = calloc(x->groups, sizeof(uint32_t));
    x->ibmp = calloc(x->groups, sizeof(uint32_t));
    x->itab = calloc(x->groups, sizeof(uint32_t));
    x->bbm  = calloc(1, (x->bc + 7) / 8);
    x->ibm  = calloc(1, (x->ic + 7) / 8);
    if (!x->bmp || !x->ibmp || !x->itab || !x->bbm || !x->ibm) return -1;

    /* Per-group locations come from the descriptor table, so whatever layout
     * mkfs chose is honoured. */
    uint8_t *gdt = malloc((size_t)x->gdt_b * BS);
    if (!gdt || pr(x, (uint64_t)BS, gdt, (size_t)x->gdt_b * BS)) { free(gdt); return -1; }
    for (uint32_t g = 0; g < x->groups; g++) {
        const uint8_t *d = gdt + (size_t)g * 32;
        x->bmp[g]  = rd32le(d + 0);
        x->ibmp[g] = rd32le(d + 4);
        x->itab[g] = rd32le(d + 8);
    }
    free(gdt);

    /* Flatten the per-group bitmaps; group g's bitmap block is exactly the
     * g-th slice of the flat array (same bit order). */
    for (uint32_t g = 0; g < x->groups; g++) {
        uint32_t bstart = g * x->spg;
        uint32_t bn = x->bc - bstart < x->spg ? x->bc - bstart : x->spg;
        if (pr(x, (uint64_t)x->bmp[g] * BS, x->bbm + bstart / 8, (bn + 7) / 8)) return -1;
        if (pr(x, (uint64_t)x->ibmp[g] * BS, x->ibm + (size_t)g * x->ipg / 8,
               (x->ipg + 7) / 8)) return -1;
    }

    /* Free counts and the cursor come from the bitmaps, not the superblock. */
    x->free_blocks = 0;
    for (uint32_t b = 0; b < x->bc; b++)
        if (!(x->bbm[b >> 3] & (uint8_t)(1u << (b & 7)))) x->free_blocks++;
    x->free_inodes = 0;
    for (uint32_t i = 0; i < x->ic; i++)
        if (!(x->ibm[i >> 3] & (uint8_t)(1u << (i & 7)))) x->free_inodes++;
    x->next_block = 0;
    while (x->next_block < x->bc &&
           (x->bbm[x->next_block >> 3] & (uint8_t)(1u << (x->next_block & 7))))
        x->next_block++;
    x->next_ino = FIRST_INO;      /* 1..10 are reserved */

    x->ents_cap = 64;
    x->ents = calloc((size_t)x->ents_cap, sizeof(*x->ents));
    if (!x->ents) return -1;
    strcpy(x->ents[0].path, "/");
    x->ents[0].ino = 2;
    x->ents[0].is_dir = 1;
    x->nents = 1;
    return 0;
}

static int ctx_finish(InstCtx *x) {
    uint8_t *gdt = malloc((size_t)x->gdt_b * BS);
    if (!gdt || pr(x, (uint64_t)BS, gdt, (size_t)x->gdt_b * BS)) { free(gdt); return -1; }

    /* Write every group's bitmaps back and refresh its descriptor's counts. */
    uint32_t total_b = 0, total_i = 0;
    for (uint32_t g = 0; g < x->groups; g++) {
        uint32_t bstart = g * x->spg;
        uint32_t bn = x->bc - bstart < x->spg ? x->bc - bstart : x->spg;
        uint32_t istart = g * x->ipg;
        uint32_t in = x->ic - istart < x->ipg ? x->ic - istart : x->ipg;
        uint32_t fb = 0, fi = 0, i;
        for (i = 0; i < bn; i++)
            if (!(x->bbm[(bstart + i) >> 3] & (uint8_t)(1u << ((bstart + i) & 7)))) fb++;
        for (i = 0; i < in; i++)
            if (!(x->ibm[(istart + i) >> 3] & (uint8_t)(1u << ((istart + i) & 7)))) fi++;
        total_b += fb; total_i += fi;
        uint32_t dirs = 0;
        for (int e = 0; e < x->nents; e++)
            if (x->ents[e].is_dir && (x->ents[e].ino - 1) / x->ipg == g) dirs++;
        uint8_t *d = gdt + (size_t)g * 32;
        wr16le(d + 12, (uint16_t)(fb > 65535 ? 65535 : fb));
        wr16le(d + 14, (uint16_t)(fi > 65535 ? 65535 : fi));
        wr16le(d + 16, (uint16_t)(dirs > 65535 ? 65535 : dirs));
        if (pw(x, (uint64_t)x->bmp[g] * BS, x->bbm + bstart / 8, (bn + 7) / 8)) { free(gdt); return -1; }
        if (pw(x, (uint64_t)x->ibmp[g] * BS, x->ibm + (size_t)istart / 8, (in + 7) / 8)) { free(gdt); return -1; }
    }

    uint8_t sbraw[BS];
    if (pr(x, 0, sbraw, BS)) { free(gdt); return -1; }
    Ext4Super *s = (Ext4Super *)(sbraw + 1024);
    s->s_free_blocks_count_lo = total_b;
    s->s_free_inodes_count = total_i;
    if (pw(x, 0, sbraw, BS)) { free(gdt); return -1; }
    if (pw(x, (uint64_t)BS, gdt, (size_t)x->gdt_b * BS)) { free(gdt); return -1; }
    free(gdt);
    return cache_flush(x);
}

/* parent dir inode + child bare name by path */
static int parent_ino(InstCtx *x, const char *path, char *child_name, size_t cn_sz) {
    const char *slash = strrchr(path, '/');
    strncpy(child_name, slash ? slash + 1 : path, cn_sz - 1);
    child_name[cn_sz - 1] = 0;
    if (!slash || slash == path) return 2;   /* root */
    size_t dl = (size_t)(slash - path);
    char dir[512];
    memcpy(dir, path, dl);
    dir[dl] = 0;
    for (int i = x->nents - 1; i >= 0; i--)
        if (x->ents[i].is_dir && !strcmp(x->ents[i].path, dir))
            return (int)x->ents[i].ino;
    return -1;
}

static int reg_ent(InstCtx *x, const char *path, uint32_t ino, uint8_t is_dir) {
    if (x->nents == x->ents_cap) {
        int nc = x->ents_cap * 2;
        InstEntry *ne = realloc(x->ents, (size_t)nc * sizeof(*ne));
        if (!ne) return -1;
        x->ents = ne; x->ents_cap = nc;
    }
    strncpy(x->ents[x->nents].path, path, sizeof(x->ents[x->nents].path) - 1);
    x->ents[x->nents].path[sizeof(x->ents[x->nents].path) - 1] = 0;
    x->ents[x->nents].ino = ino;
    x->ents[x->nents].is_dir = is_dir;
    x->nents++;
    return 0;
}

/* ── install API ────────────────────────────────────────────── */
int cfs_mkfs_ext4_install(CFS *c, uint64_t base_off, uint64_t size,
                          const uint8_t *iso_img, size_t iso_sz) {
    if (!c || !iso_img || iso_sz < 17 * 2048) return -1;
    IsoFs *fs = iso9660_open(iso_img, iso_sz);
    if (!fs) { fprintf(stderr, "DBG: iso9660_open\n"); return -1; }
    int n = iso9660_nfiles(fs);

    if (cfs_mkfs_ext4_at(c, base_off, size)) { fprintf(stderr, "DBG: mkfs\n"); iso9660_close(fs); return -1; }

    InstCtx x = {0};
    if (ctx_init(&x, c, base_off)) {
        fprintf(stderr, "DBG: ctx_init\n");
        free(x.bmp); free(x.ibmp); free(x.itab); free(x.bbm); free(x.ibm);
        iso9660_close(fs); return -1;
    }

    int rc = 0;
    for (int i = 0; i < n && rc == 0; i++) {
        IsoEntry e;
        if (iso9660_get(fs, i, &e)) { rc = -1; break; }
        char child[256];
        int pino = parent_ino(&x, e.path, child, sizeof(child));
        if (pino < 0) { fprintf(stderr, "DBG: parent_ino %s\n", e.path); rc = -1; break; }
if (e.is_dir) {
            uint32_t ino = alloc_inode(&x);
            uint32_t blk;
            if (!ino || !alloc_blocks(&x, 1, &blk)) { fprintf(stderr, "DBG: alloc dir\n"); rc = -1; break; }
            uint8_t dblk[BS]; memset(dblk, 0, sizeof(dblk));
            Ext4DirEntry *d1 = (Ext4DirEntry *)dblk;
            d1->inode = ino; d1->rec_len = 12; d1->name_len = 1;
            d1->file_type = 2; d1->name[0] = '.';
            Ext4DirEntry *d2 = (Ext4DirEntry *)(dblk + 12);
            d2->inode = (uint32_t)pino; d2->rec_len = (uint16_t)(BS - 12);
            d2->name_len = 2; d2->file_type = 2;
            d2->name[0] = '.'; d2->name[1] = '.';
            if (pw(&x, (uint64_t)blk * BS, dblk, BS)) { rc = -1; break; }
            Ext4Inode in;
            make_inode(&in, 0x41ED, BS, 1, blk, 2, e.mtime);
            if (write_inode(&x, ino, &in)) { rc = -1; break; }
            if (dir_add(&x, (uint32_t)pino, child, ino, 2)) { fprintf(stderr, "DBG: diradd dir\n"); rc = -1; break; }
            if (pino != 2) {
                Ext4Inode pin;
                if (read_inode(&x, (uint32_t)pino, &pin)) { rc = -1; break; }
                pin.i_links_count++;
                if (write_inode(&x, (uint32_t)pino, &pin)) { rc = -1; break; }
            }
            if (reg_ent(&x, e.path, ino, 1)) { rc = -1; break; }
        } else {
            if (e.offset + e.size > iso_sz) { rc = -1; break; }
            uint32_t ino = alloc_inode(&x);
            uint32_t nblk = (uint32_t)((e.size + BS - 1) / BS);
            uint32_t blk = 0;
            if (!ino || (nblk && !alloc_blocks(&x, nblk, &blk))) { fprintf(stderr, "DBG: alloc file\n"); rc = -1; break; }
            if (e.size >= BS) {
                if (pw_big(&x, (uint64_t)blk * BS, iso_img + e.offset, e.size)) { fprintf(stderr, "DBG: pw_big\n"); rc = -1; break; }
            } else if (e.size) {
                if (pw(&x, (uint64_t)blk * BS, iso_img + e.offset, e.size)) { fprintf(stderr, "DBG: pw small\n"); rc = -1; break; }
            }
            Ext4Inode in;
            make_inode(&in, 0x81A4, (uint32_t)e.size, nblk, blk, 1, e.mtime);
            if (write_inode(&x, ino, &in)) { fprintf(stderr, "DBG: wino\n"); rc = -1; break; }
            if (dir_add(&x, (uint32_t)pino, child, ino, 1)) { fprintf(stderr, "DBG: diradd file\n"); rc = -1; break; }
            if (reg_ent(&x, e.path, ino, 0)) { rc = -1; break; }
        }
    }

    if (rc == 0) rc = ctx_finish(&x);
    if (rc) fprintf(stderr, "DBG: loop/finish rc=%d (n=%d)\n", rc, n);
    free(x.bbm); free(x.ibm); free(x.ents); free(x.dirty);
    free(x.bmp); free(x.ibmp); free(x.itab);
    iso9660_close(fs);
    return rc;
}
