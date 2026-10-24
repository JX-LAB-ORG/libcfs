/* cfs_verify — container self-check.
 *
 * Every other acceptance check the project has goes through an external tool
 * (e2fsck, fsck.vfat, a real mount): they validate the filesystem *inside*
 * the container and say nothing about the container's own structures.  That
 * blind spot is where the hand-found bugs lived — most recently a write path
 * that set a block's orig_size before the write landed, leaving the block
 * table describing bytes that were never written.
 *
 * So this file walks the superblock, the inode table and every block table
 * with a parser of its own, deliberately independent of cfs.c's: a
 * disagreement between the two readers is itself a finding, and cfs_verify
 * has to work on containers too broken for cfs_open() to accept.
 *
 * Read-only throughout.  cfs_open() is used for cross-checks only, and only
 * when it succeeds.
 */
#define _GNU_SOURCE
#include "cfs.h"
#include "cfs_dedup.h"          /* pulls cfs_format.h: modes, block layout */
#include "../libcpool/cpenc.h"  /* the same codec cfs.c decodes blocks with */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

/* ── Reporting categories ───────────────────────────────────────
 * One counter pair each, so the summary says *which* layer is unhappy
 * without the reader having to scan the problem list. */
enum { C_SB, C_TAB, C_BLK, C_HDR, C_DEEP, C_REF, C_STORE, C_PHYS, C_API, C_NCAT };
static const char *const vcat[C_NCAT] = {
    "superblock", "inode-table", "block-table", "block-header", "decompress",
    "dedup-refs", "@store", "footprint", "api-crosscheck"
};

#define VPRINT_MAX 20           /* individual problems listed, not just counted */
#define VMSG_MAX   640

typedef struct { uint64_t off; uint32_t comp, orig; } VBlk;

typedef struct {
    uint64_t orig, mtime, at;   /* at = byte offset of the entry in the table */
    uint16_t mode, plen;
    uint32_t nblk;
    VBlk    *blk;
    char    *path;              /* NULL when plen == 0 (cfs_open does the same) */
} VInode;

typedef struct { uint64_t s, e; uint32_t ino, blk; } VRange;   /* physical extent */
typedef struct { uint64_t s, e; }                    VSpan;    /* @store range */
typedef struct { const char *p; uint32_t i; }        VName;    /* path, for the dup scan */

typedef struct {
    FILE       *out;
    const char *path;
    int         fd;
    int         deep;
    uint64_t    fsz;                  /* physical size of the container file */

    uint64_t    err, warn, printed;
    uint64_t    cat_err[C_NCAT], cat_warn[C_NCAT];
    char        msg[VPRINT_MAX][VMSG_MAX];

    /* superblock / table */
    uint64_t    table_off, table_end;
    uint32_t    file_count, parsed;

    /* block tables */
    uint64_t    nblk, comp_bytes, orig_bytes, hdr_checked;
    uint64_t    zero_sized, oob, overlaps, unordered;
    uint64_t    sparse_files, sparse_bytes, sparse_user, sparse_user_bytes;
    uint64_t    high_water;

    /* dedup */
    uint64_t    dedup_files, refs, ref_logical;
    uint64_t    ref_past_store, ref_past_bytes;
    uint64_t    tables_bad;
    uint64_t    store_size, store_live, store_dead;
    int         have_store, have_block, device_dedup;
    uint64_t    device_size, device_used;

    /* api cross-check */
    int         api_open, api_mismatch;
    uint32_t    user_count;           /* entries cfs.c would count as files */

    VRange     *rng;  uint32_t nrng, crng;
    VSpan      *spn;  uint32_t nspn, cspn;

    uint64_t    deep_blocks, deep_bytes;
} VCtx;

static uint16_t rd16(const uint8_t *p){return (uint16_t)p[0]|((uint16_t)p[1]<<8);}
static uint32_t rd32(const uint8_t *p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static uint64_t rd64(const uint8_t *p){return (uint64_t)rd32(p)|((uint64_t)rd32(p+4)<<32);}

/* ── problem sink ───────────────────────────────────────────────
 * Counted always, printed only for the first VPRINT_MAX: a container with a
 * broken table can produce one problem per block, and a wall of identical
 * lines hides the first one that matters. */
static void vprob(VCtx *v, int cat, int err, const char *fmt, ...) {
    if (err) { v->err++; v->cat_err[cat]++; } else { v->warn++; v->cat_warn[cat]++; }
    if (v->printed >= VPRINT_MAX) return;
    char b[VMSG_MAX];
    int n = snprintf(b, sizeof b, "%s %s: ", err ? "error" : "warn ", vcat[cat]);
    if (n < 0) n = 0;
    if ((size_t)n > sizeof b - 1) n = (int)sizeof b - 1;
    va_list ap; va_start(ap, fmt);
    vsnprintf(b + n, sizeof b - (size_t)n, fmt, ap);
    va_end(ap);
    snprintf(v->msg[v->printed], VMSG_MAX, "%s", b);
    v->printed++;
}

/* ── growable arrays ────────────────────────────────────────── */
static int vpush_range(VCtx *v, uint64_t s, uint64_t e, uint32_t ino, uint32_t blk) {
    if (v->nrng == v->crng) {
        uint32_t nc = v->crng ? v->crng * 2 : 256;
        VRange *nv = realloc(v->rng, (size_t)nc * sizeof *nv);
        if (!nv) return -1;
        v->rng = nv; v->crng = nc;
    }
    v->rng[v->nrng++] = (VRange){ s, e, ino, blk };
    return 0;
}
static int vpush_span(VCtx *v, uint64_t s, uint64_t e) {
    if (e <= s) return 0;
    if (v->nspn == v->cspn) {
        uint32_t nc = v->cspn ? v->cspn * 2 : 256;
        VSpan *nv = realloc(v->spn, (size_t)nc * sizeof *nv);
        if (!nv) return -1;
        v->spn = nv; v->cspn = nc;
    }
    v->spn[v->nspn++] = (VSpan){ s, e };
    return 0;
}
static int cmp_range(const void *a, const void *b) {
    const VRange *x = a, *y = b;
    if (x->s != y->s) return x->s < y->s ? -1 : 1;
    if (x->e != y->e) return x->e < y->e ? -1 : 1;
    return 0;
}
static int cmp_span(const void *a, const void *b) {
    const VSpan *x = a, *y = b;
    if (x->s != y->s) return x->s < y->s ? -1 : 1;
    if (x->e != y->e) return x->e < y->e ? -1 : 1;
    return 0;
}
static int cmp_name(const void *a, const void *b) {
    return strcmp(((const VName *)a)->p, ((const VName *)b)->p);
}

/* ── raw block access ─────────────────────────────────────────── */
static int vpread(VCtx *v, void *buf, size_t n, uint64_t off) {
    if (n == 0) return 0;
    if (off > v->fsz || n > v->fsz - off) return -1;
    return pread(v->fd, buf, n, (off_t)off) == (ssize_t)n ? 0 : -1;
}

/* Decompress one block into dst (which must hold b->orig bytes).  The read
 * path's own contract (cfs.c: dl != orig_size → read fails), so a failure
 * here is a read failure there. */
static int vdecode(VCtx *v, const VBlk *b, uint8_t *dst, int cat, const char *what) {
    uint8_t *comp = malloc(b->comp ? b->comp : 1);
    if (!comp) return -1;
    if (vpread(v, comp, b->comp, b->off) != 0) {
        free(comp);
        vprob(v, cat, 1, "%s: block at %llu (comp_size=%u) is past the end of the file",
              what, (unsigned long long)b->off, (unsigned)b->comp);
        return -1;
    }
    size_t dl = b->orig;
    int rc = (cpenc_decompress(comp, b->comp, dst, &dl) != 0 || dl != b->orig) ? -1 : 0;
    free(comp);
    if (rc != 0)
        vprob(v, cat, 1, "%s: block at %llu does not decode to orig_size=%u (decoded %zu)",
              what, (unsigned long long)b->off, (unsigned)b->orig, dl);
    return rc;
}

/* Concatenate the decompressed blocks of one inode.  This is exactly what
 * dt_load() builds before cfs_dedup_parse(), so a failure here is a file the
 * library cannot read either. */
static uint8_t *vpayload(VCtx *v, const VInode *in, uint64_t *out_len, int cat) {
    uint64_t total = 0;
    for (uint32_t b = 0; b < in->nblk; b++) {
        if (total > (UINT64_MAX >> 1) - in->blk[b].orig) return NULL;
        total += in->blk[b].orig;
    }
    /* A reference table is a few varints per file; anything near this is a
     * corrupt orig_size, not a table. */
    if (total > (256ULL << 20)) {
        vprob(v, cat, 1, "inode \"%s\": block table claims %llu B of payload",
              in->path ? in->path : "(no path)", (unsigned long long)total);
        return NULL;
    }
    uint8_t *buf = malloc(total ? total : 1);
    if (!buf) return NULL;
    uint64_t off = 0;
    for (uint32_t b = 0; b < in->nblk; b++) {
        char what[160];
        snprintf(what, sizeof what, "inode \"%s\" block %u", in->path ? in->path : "(no path)", b);
        if (vdecode(v, &in->blk[b], buf + off, cat, what) != 0) { free(buf); return NULL; }
        off += in->blk[b].orig;
    }
    *out_len = total;
    return buf;
}

/* Read a logical range of a plain file by the prefix-sum walk the read path
 * uses; unwritten tail and holes read as zeros, like cfs_read does. */
static int vread_range(VCtx *v, const VInode *in, uint8_t *dst, size_t n, uint64_t off) {
    if (off >= in->orig) { memset(dst, 0, n); return 0; }
    if (n > in->orig - off) n = (size_t)(in->orig - off);
    size_t done = 0;
    uint64_t cur = 0;
    for (uint32_t b = 0; b < in->nblk && done < n; b++) {
        uint64_t bend = cur + in->blk[b].orig;
        if (off >= bend) { cur = bend; continue; }
        if (off < cur) {                       /* hole before this block */
            size_t nl = (size_t)(cur - off); if (nl > n - done) nl = n - done;
            memset(dst + done, 0, nl); done += nl; off = cur;
            if (done == n) break;
        }
        uint64_t ob = off - cur;
        size_t nl = (size_t)(bend - off); if (nl > n - done) nl = n - done;
        if (in->blk[b].orig > CFS_BLOCK_MAX) return -1;
        uint8_t *dec = malloc(in->blk[b].orig ? in->blk[b].orig : 1);
        if (!dec) return -1;
        char what[160];
        snprintf(what, sizeof what, "inode \"%s\" block %u", in->path ? in->path : "(no path)", b);
        if (vdecode(v, &in->blk[b], dec, C_DEEP, what) != 0) { free(dec); return -1; }
        memcpy(dst + done, dec + ob, nl);
        free(dec);
        done += nl; off = bend; cur = bend;
    }
    if (done < n) memset(dst + done, 0, n - done);   /* trailing hole */
    return 0;
}

/* ── superblock + inode table ─────────────────────────────────── */
typedef struct {
    uint8_t  magic[8];
    uint16_t version;
    uint64_t inode_off;
    uint32_t inode_size;
    uint32_t file_count;
    uint64_t created_at;
    uint16_t flags;
} VSb;

/* Parse the table the way cfs_open() does — same layout, own code — but keep
 * counting past the end of what it can read, so a file_count that disagrees
 * with the bytes on disk shows up as a finding instead of a silent
 * truncation. */
static VInode *parse_table(VCtx *v, const uint8_t *t, uint64_t tlen,
                           uint32_t fc, uint32_t *out_n) {
    const uint8_t *p = t, *end = t + tlen;
    /* An entry is at least CFS_INODE_FIXED_SIZE bytes, so that bounds the
     * allocation no matter what file_count claims. */
    uint64_t cap = tlen / CFS_INODE_FIXED_SIZE + 1;
    uint32_t alloc_n = (uint32_t)(cap < (uint64_t)fc ? cap : (uint64_t)fc);
    VInode *ins = calloc(alloc_n ? alloc_n : 1, sizeof *ins);
    if (!ins) return NULL;
    uint32_t n = 0;
    for (uint32_t i = 0; i < fc && (size_t)(end - p) >= CFS_INODE_FIXED_SIZE; i++) {
        VInode *e = &ins[n];
        e->at    = (uint64_t)(p - t);
        e->orig  = rd64(p);
        e->mtime = rd64(p + 8);
        e->mode  = rd16(p + 16);
        e->plen  = rd16(p + 18);
        e->nblk  = rd32(p + 20);
        p += CFS_INODE_FIXED_SIZE;
        if (e->nblk > CFS_BLOCK_SANITY) {
            /* cfs_open() rejects the whole container on this; nothing after
             * it can be trusted, so stop here and say so. */
            vprob(v, C_TAB, 1, "entry %u at table+%llu: block_count=%u exceeds CFS_BLOCK_SANITY",
                  i, (unsigned long long)e->at, (unsigned)e->nblk);
            break;
        }
        if ((uint64_t)(end - p) < (uint64_t)e->nblk * 16) {
            vprob(v, C_TAB, 1, "entry %u at table+%llu: block table (%u entries) runs past the inode table",
                  i, (unsigned long long)e->at, (unsigned)e->nblk);
            break;
        }
        e->blk = calloc(e->nblk ? e->nblk : 1, sizeof *e->blk);
        if (!e->blk) break;
        for (uint32_t b = 0; b < e->nblk; b++) {
            e->blk[b].off  = rd64(p);
            e->blk[b].comp = rd32(p + 8);
            e->blk[b].orig = rd32(p + 12);
            p += 16;
        }
        if (e->plen) {
            if ((uint64_t)(end - p) < e->plen) {
                vprob(v, C_TAB, 1, "entry %u at table+%llu: path_len=%u runs past the inode table",
                      i, (unsigned long long)e->at, (unsigned)e->plen);
                free(e->blk); e->blk = NULL;   /* the entry never counted, so nobody else frees it */
                break;
            }
            e->path = malloc((size_t)e->plen + 1);
            if (!e->path) break;
            memcpy(e->path, p, e->plen);
            e->path[e->plen] = 0;
            p += e->plen;
        }
        n++;
    }
    /* The writer sizes the table as exactly the sum of its entries, so bytes
     * left over inside it mean file_count is smaller than the table's
     * content: cfs_open() would stop early and the entries beyond it would be
     * unreachable.  (Trailing bytes *past* the declared table are a different
     * thing — leftover slack from a previously longer table, reported as
     * footprint slack.) */
    if ((uint64_t)(end - p) != 0 && n == fc)
        vprob(v, C_TAB, 1, "%llu trailing byte(s) inside the declared table after entry %u "
              "(file_count=%u) — more entries are present than file_count admits",
              (unsigned long long)(end - p), n, fc);
    *out_n = n;
    return ins;
}

/* ── block table checks ─────────────────────────────────────── */
static void check_blocks(VCtx *v, const VInode *in, uint32_t idx) {
    const char *nm = in->path ? in->path : "(no path)";
    uint64_t sum = 0;
    uint64_t prev_off = 0;
    for (uint32_t b = 0; b < in->nblk; b++) {
        const VBlk *bl = &in->blk[b];
        v->nblk++;
        v->comp_bytes += bl->comp;
        v->orig_bytes += bl->orig;
        sum += bl->orig;
        if (!bl->comp || !bl->orig) {
            v->zero_sized++;
            vprob(v, C_BLK, 1, "inode %u \"%s\" block %u: comp_size=%u orig_size=%u (a zero-sized block never decodes)",
                  idx, nm, b, (unsigned)bl->comp, (unsigned)bl->orig);
            continue;
        }
        if (bl->comp < CPENC_HEADER_SIZE) {
            v->zero_sized++;
            vprob(v, C_BLK, 1, "inode %u \"%s\" block %u: comp_size=%u is smaller than a CPEnc header (%u)",
                  idx, nm, b, (unsigned)bl->comp, (unsigned)CPENC_HEADER_SIZE);
            continue;
        }
        /* comp_size is bounded by the file it lives in; orig_size is not
         * bounded by anything else, and --deep allocates it straight from
         * the table.  A 4GB claim is a corrupt entry, not a large file. */
        if (bl->orig > CFS_BLOCK_MAX) {
            v->oob++;
            vprob(v, C_BLK, 1, "inode %u \"%s\" block %u: orig_size=%u exceeds the block ceiling (%u)",
                  idx, nm, b, (unsigned)bl->orig, (unsigned)CFS_BLOCK_MAX);
            continue;
        }
        if (bl->off < CFS_SB_SIZE) {
            v->oob++;
            vprob(v, C_BLK, 1, "inode %u \"%s\" block %u: offset=%llu overlaps the superblock",
                  idx, nm, b, (unsigned long long)bl->off);
        }
        if (bl->off > v->fsz || bl->comp > v->fsz - bl->off) {
            v->oob++;
            vprob(v, C_BLK, 1, "inode %u \"%s\" block %u: [%llu,%llu) lies past the end of the file (%llu B)",
                  idx, nm, b, (unsigned long long)bl->off,
                  (unsigned long long)(bl->off + bl->comp), (unsigned long long)v->fsz);
            continue;   /* don't feed an extent we cannot trust into the overlap map */
        }
        if (bl->off + bl->comp > v->high_water) v->high_water = bl->off + bl->comp;
        /* Order: what the read path depends on is *table* order — cfs_read()
         * and block_blk_start() walk blocks[] accumulating orig_size, so the
         * entry order is the file's logical order.  Physical offsets are not
         * required to ascend: an in-place patch that grows a payload is
         * appended at the container's end (cfs.c:block_patch), which can
         * leave a later table entry at a lower offset.  So this is counted
         * and reported, never an error. */
        if (b && bl->off < prev_off) v->unordered++;
        prev_off = bl->off;
        if (vpush_range(v, bl->off, bl->off + bl->comp, idx, b) != 0) return;
    }
    /* Block count vs content, per mode.  The sum(orig_size)==orig_size rule
     * is the prefix-sum invariant the read path locates bytes by — but it
     * only holds for *content* blocks.  A DEDUP entry's blocks hold the
     * serialised reference table, so their sizes sum to the table's length,
     * not to the file's logical size; that invariant is checked in
     * check_dedup() instead. */
    if (in->mode == CFS_MODE_DEDUP) {
        if (in->nblk == 0)
            vprob(v, C_REF, 1, "inode %u \"%s\": DEDUP entry with block_count=0 (no reference table)", idx, nm);
    } else if (in->mode == CFS_MODE_DIR) {
        if (in->nblk)
            vprob(v, C_BLK, 0, "inode %u \"%s\": directory with %u block(s) — unreachable bytes",
                  idx, nm, (unsigned)in->nblk);
    } else {   /* FILE / SYMLINK: blocks are content */
        /* @block is exempt from the block_count==0 check: a device created
         * and resized but never written (cfs_create + cfs_block_resize) is
         * legal — the block layer zero-fills every byte of the declared
         * capacity, so a read returns a full device of zeros.  Requiring real
         * blocks would flag an untouched sparse device as corrupt. */
        if (in->orig && !in->nblk &&
            (!in->path || strcmp(in->path, "@block") != 0))
            vprob(v, C_BLK, 1, "inode %u \"%s\": orig_size=%llu but block_count=0 (no way to read it)",
                  idx, nm, (unsigned long long)in->orig);
        if (!in->orig && in->nblk)
            vprob(v, C_BLK, 1, "inode %u \"%s\": orig_size=0 but block_count=%u (bytes no read can reach)",
                  idx, nm, (unsigned)in->nblk);
        if (sum > in->orig) {
            vprob(v, C_BLK, 1, "inode %u \"%s\": sum(block orig_size)=%llu exceeds orig_size=%llu "
                  "(%llu B unreachable by the prefix-sum walk)",
                  idx, nm, (unsigned long long)sum, (unsigned long long)in->orig,
                  (unsigned long long)(sum - in->orig));
        } else if (sum < in->orig) {
            /* Legal only where a hole is the point: @block is a sparse
             * device whose tail the block layer zero-fills, and truncate-
             * extend leaves the same shape.  The read path zero-fills it, so
             * these are bytes the container can never return — worth saying,
             * not worth failing on. */
            v->sparse_files++; v->sparse_bytes += in->orig - sum;
            if (!in->path || in->path[0] != '@') {
                v->sparse_user++; v->sparse_user_bytes += in->orig - sum;
                vprob(v, C_BLK, 0, "inode %u \"%s\": sum(block orig_size)=%llu is short of orig_size=%llu "
                      "(%llu B read back as zeros)",
                      idx, nm, (unsigned long long)sum, (unsigned long long)in->orig,
                      (unsigned long long)(in->orig - sum));
            }
        }
    }
}

/* The 12-byte CPEnc header of every block restates what the block table
 * says; a mismatch means the table describes a block that is not the one on
 * disk — the exact shape of the write-path bug that set orig_size before the
 * write landed.  Cheap enough to do without --deep. */
static void check_block_header(VCtx *v, const VInode *in, uint32_t idx) {
    const char *nm = in->path ? in->path : "(no path)";
    for (uint32_t b = 0; b < in->nblk; b++) {
        const VBlk *bl = &in->blk[b];
        if (bl->comp < CPENC_HEADER_SIZE || bl->off < CFS_SB_SIZE) continue;
        uint8_t h[CPENC_HEADER_SIZE];
        if (vpread(v, h, sizeof h, bl->off) != 0) continue;   /* bounds already reported */
        v->hdr_checked++;
        uint16_t magic = rd16(h);
        uint8_t  ver = h[2];
        uint32_t h_orig = rd32(h + 4), h_comp = rd32(h + 8);
        if (magic != CPENC_MAGIC) {
            vprob(v, C_HDR, 1, "inode %u \"%s\" block %u: CPEnc magic 0x%04x at offset %llu (expected 0x%04x)",
                  idx, nm, b, (unsigned)magic, (unsigned long long)bl->off, (unsigned)CPENC_MAGIC);
            continue;
        }
        if (ver == 0 || ver > CPENC_VERSION)
            vprob(v, C_HDR, 1, "inode %u \"%s\" block %u: CPEnc version %u (this build decodes up to %u)",
                  idx, nm, b, (unsigned)ver, (unsigned)CPENC_VERSION);
        /* A hex-wrapped block records the *folded* length in its header, not
         * the text length the table holds; comparing them flagged every
         * container that stored hex-ish text.  The payload carries the real
         * length and vdecode checks it against the table. */
        if (h[3] != CPENC_STRIDE_HEX && h_orig != bl->orig)
            vprob(v, C_HDR, 1, "inode %u \"%s\" block %u: header original_size=%u, block table says %u",
                  idx, nm, b, (unsigned)h_orig, (unsigned)bl->orig);
        if ((uint64_t)h_comp + CPENC_HEADER_SIZE != bl->comp)
            vprob(v, C_HDR, 1, "inode %u \"%s\" block %u: header compressed_size=%u, block table says %u",
                  idx, nm, b, (unsigned)h_comp, (unsigned)bl->comp);
    }
}

/* ── dedup reference tables ─────────────────────────────────── */
/* First tuple starting at or after off (logical_size when there is none).
 * cfs.c keeps this next to the read path; here it only drives the
 * independent resolution used by the --deep cross-check. */
static uint64_t vnext_start(const CfsDedupTable *t, uint64_t off) {
    uint32_t lo = 0, hi = t->n;
    uint64_t best = t->logical_size;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (t->v[mid].logical > off) { best = t->v[mid].logical; hi = mid; }
        else lo = mid + 1;
    }
    return best;
}

static void check_dedup(VCtx *v, const VInode *in, uint32_t idx,
                        const VInode *store) {
    const char *nm = in->path ? in->path : "(no path)";
    uint64_t tlen = 0;
    uint8_t *buf = vpayload(v, in, &tlen, C_REF);
    if (!buf) { v->tables_bad++; return; }
    CfsDedupTable t;
    if (cfs_dedup_parse(buf, (size_t)tlen, &t) != 0) {
        v->tables_bad++;
        vprob(v, C_REF, 1, "inode %u \"%s\": reference table (%llu B in %u block(s)) does not parse",
              idx, nm, (unsigned long long)tlen, (unsigned)in->nblk);
        free(buf);
        return;
    }
    free(buf);
    v->dedup_files++;
    v->refs += t.n;
    v->ref_logical += t.logical_size;
    if (t.logical_size != in->orig)
        vprob(v, C_REF, 1, "inode %u \"%s\": table logical_size=%llu, inode orig_size=%llu",
              idx, nm, (unsigned long long)t.logical_size, (unsigned long long)in->orig);
    /* cfs_dedup_parse() already rejects out-of-order or overlapping tuples;
     * re-checking keeps the report specific about *which* tuple, and covers
     * the writer writing a table that the parser would only accept by luck. */
    uint64_t prev_end = 0, sum = 0;
    for (uint32_t r = 0; r < t.n; r++) {
        const CfsRef *rf = &t.v[r];
        if (rf->length == 0 || rf->logical < prev_end || rf->logical + rf->length < rf->logical)
            vprob(v, C_REF, 1, "inode %u \"%s\": ref %u (logical=%llu length=%llu) is empty, out of order or overlapping",
                  idx, nm, r, (unsigned long long)rf->logical, (unsigned long long)rf->length);
        if (rf->logical + rf->length > t.logical_size)
            vprob(v, C_REF, 1, "inode %u \"%s\": ref %u ends at %llu, past the file's logical size %llu",
                  idx, nm, r, (unsigned long long)(rf->logical + rf->length),
                  (unsigned long long)t.logical_size);
        prev_end = rf->logical + rf->length;
        sum += rf->length;
        /* Every tuple must resolve inside @store *as it is now*: the read
         * path hands (store, length) straight to cfs_read(@store), which
         * returns short — silently — for bytes the store no longer has. */
        if (!store) {
            v->ref_past_store++;
        } else if (rf->store > store->orig || rf->length > store->orig - rf->store) {
            uint64_t past = rf->store > store->orig ? rf->length
                                                    : rf->store + rf->length - store->orig;
            v->ref_past_store++;
            v->ref_past_bytes += past;
            vprob(v, C_REF, 1, "inode %u \"%s\": ref %u [store %llu,+%llu) exceeds @store size %llu (%llu B missing)",
                  idx, nm, r, (unsigned long long)rf->store, (unsigned long long)rf->length,
                  (unsigned long long)(store ? store->orig : 0), (unsigned long long)past);
        }
        if (store && vpush_span(v, rf->store, rf->store + rf->length) != 0) { cfs_dedup_table_free(&t); return; }
    }
    if (sum > t.logical_size)
        vprob(v, C_REF, 1, "inode %u \"%s\": refs cover %llu B, more than the file's logical size %llu",
              idx, nm, (unsigned long long)sum, (unsigned long long)t.logical_size);
    cfs_dedup_table_free(&t);
}

/* ── --deep: the library's read path vs this file's own resolution ──
 * Both walk the same table; if they disagree, one of them is reading the
 * container wrong, and the user gets the wrong bytes back with no error. */
static void deep_crosscheck(VCtx *v, CFS *c, const VInode *in,
                            const CfsDedupTable *t, const VInode *store) {
    const char *nm = in->path;
    const size_t CH = 1u << 20;
    /* @block is a device, not a file: the library's view of it is
     * cfs_block_read(), which zero-fills the unwritten tail.  Plain cfs_read()
     * returns 0 there (the inode has no content blocks), which is why an
     * untouched sparse device used to fail this cross-check. */
    int is_dev = (nm && !strcmp(nm, "@block"));
    uint8_t *a = malloc(CH), *b = malloc(CH);
    if (!a || !b) { free(a); free(b); return; }
    for (uint64_t off = 0; off < in->orig; off += CH) {
        size_t n = (size_t)(in->orig - off < CH ? in->orig - off : CH);
        ssize_t got = is_dev ? cfs_block_read(c, a, n, (off_t)off)
                             : cfs_read(c, nm, a, n, (off_t)off);
        if (got != (ssize_t)n) {
            vprob(v, C_DEEP, 1, "\"%s\": %s(%zu @ %llu) returned %lld, expected %zu",
                  nm, is_dev ? "cfs_block_read" : "cfs_read", n,
                  (unsigned long long)off, (long long)got, n);
            break;
        }
        /* Independent resolution: table lookup in @store, holes as zeros. */
        if (t) {
            size_t done = 0; uint64_t cur = off, end = off + n;
            while (cur < end) {
                const CfsRef *rf = cfs_dedup_table_find(t, cur);
                if (!rf) {
                    uint64_t nx = vnext_start(t, cur);
                    if (nx > end) nx = end;
                    /* A table truncated below the inode's orig_size makes
                     * vnext_start() return `cur` at its end: the zero-fill
                     * below would advance by 0 and spin forever (and, before
                     * the size clamp, underflow the memset length).  Stop;
                     * check_dedup() has already reported the size mismatch. */
                    if (nx <= cur) {
                        vprob(v, C_DEEP, 1, "\"%s\": reference table has no tuple at logical %llu "
                              "(table is shorter than the file)", nm,
                              (unsigned long long)cur);
                        break;
                    }
                    memset(b + done, 0, (size_t)(nx - cur));
                    done += (size_t)(nx - cur); cur = nx;
                    continue;
                }
                uint64_t within = cur - rf->logical;
                size_t nl = (size_t)(rf->length - within);
                if (nl > end - cur) nl = (size_t)(end - cur);
                if (!store || vread_range(v, store, b + done, nl, rf->store + within) != 0) break;
                done += nl; cur += nl;
            }
            if (cur < end) break;   /* a failed store read already reported */
        } else if (vread_range(v, in, b, n, off) != 0) {
            break;
        }
        if (memcmp(a, b, n) != 0) {
            size_t d = 0; while (d < n && a[d] == b[d]) d++;
            vprob(v, C_DEEP, 1, "\"%s\": read path and reference table disagree at logical %llu",
                  nm, (unsigned long long)(off + d));
            break;
        }
    }
    free(a); free(b);
}

/* ── summary printing ───────────────────────────────────────── */
static double pct(uint64_t a, uint64_t b) { return b ? 100.0 * (double)a / (double)b : 0.0; }

static void print_summary(VCtx *v, const VSb *sb, int have_sb, int deep) {
    FILE *o = v->out;
    fprintf(o, "== cfs verify: %s ==\n", v->path);
    fprintf(o, "  container     %llu B\n", (unsigned long long)v->fsz);
    if (have_sb) {
        char mg[9]; memcpy(mg, sb->magic, 8); mg[8] = 0;
        fprintf(o, "  superblock    magic=%s version=%u flags=0x%04x created=%llu\n",
                mg, (unsigned)sb->version, (unsigned)sb->flags, (unsigned long long)sb->created_at);
        fprintf(o, "  inode table   [%llu,%llu) declared file_count=%u parsed=%u\n",
                (unsigned long long)v->table_off, (unsigned long long)v->table_end,
                v->file_count, v->parsed);
    }
    fprintf(o, "  inode entries %u parsed, %llu block(s), comp=%llu B orig=%llu B\n",
            v->parsed, (unsigned long long)v->nblk,
            (unsigned long long)v->comp_bytes, (unsigned long long)v->orig_bytes);
    fprintf(o, "  block table   %llu zero-sized, %llu out-of-file, %llu overlapping, "
               "%llu non-ascending offset(s) (allowed: only table order is)\n",
            (unsigned long long)v->zero_sized, (unsigned long long)v->oob,
            (unsigned long long)v->overlaps, (unsigned long long)v->unordered);
    fprintf(o, "  block header  %llu of %llu checked against the block table "
               "(magic/version/orig_size/comp_size)\n",
            (unsigned long long)v->hdr_checked, (unsigned long long)v->nblk);
    fprintf(o, "  sparse tails  %llu file(s), %llu B zero-filled (%llu B of it user files)\n",
            (unsigned long long)v->sparse_files, (unsigned long long)v->sparse_bytes,
            (unsigned long long)v->sparse_user_bytes);
    if (v->dedup_files || v->tables_bad)
        fprintf(o, "  dedup refs    %llu file(s), %llu ref(s), logical=%llu B, %llu table(s) unparsable, "
                   "%llu ref(s) past @store (%llu B)\n",
                (unsigned long long)v->dedup_files, (unsigned long long)v->refs,
                (unsigned long long)v->ref_logical, (unsigned long long)v->tables_bad,
                (unsigned long long)v->ref_past_store, (unsigned long long)v->ref_past_bytes);
    else
        fprintf(o, "  dedup refs    no CFS_MODE_DEDUP entries\n");
    if (v->have_store)
        fprintf(o, "  @store        %llu B, referenced=%llu B (%.2f%%), dead=%llu B (%.2f%%) "
                   "[gc threshold %u%%]\n",
                (unsigned long long)v->store_size, (unsigned long long)v->store_live,
                pct(v->store_live, v->store_size), (unsigned long long)v->store_dead,
                pct(v->store_dead, v->store_size), (unsigned)CFS_DEDUP_DEAD_MAX);
    else
        fprintf(o, "  @store        absent\n");
    fprintf(o, "  footprint     high-water=%llu B, file=%llu B, slack=%llu B\n",
            (unsigned long long)v->high_water, (unsigned long long)v->fsz,
            (unsigned long long)(v->fsz > v->high_water ? v->fsz - v->high_water : 0));
    if (v->have_block && v->device_dedup)
        fprintf(o, "  device        @block capacity=%llu B, merged: served from @store through a "
                   "%llu B reference table\n",
                (unsigned long long)v->device_size, (unsigned long long)v->device_used);
    else if (v->have_block)
        fprintf(o, "  device        @block capacity=%llu B, materialised=%llu B (%.2f%%), "
                   "sparse tail=%llu B\n",
                (unsigned long long)v->device_size, (unsigned long long)v->device_used,
                pct(v->device_used, v->device_size),
                (unsigned long long)(v->device_size > v->device_used ? v->device_size - v->device_used : 0));
    else
        fprintf(o, "  device        no @block entry\n");
    if (deep)
        fprintf(o, "  deep          %llu block(s), %llu B decoded; read path cross-checked\n",
                (unsigned long long)v->deep_blocks, (unsigned long long)v->deep_bytes);
    else
        fprintf(o, "  deep          skipped (pass --deep to decode every block)\n");
    fprintf(o, "  api           %s%s\n", v->api_open ? "cfs_open ok" : "cfs_open refused the container",
            v->api_open ? (v->api_mismatch ? " — disagrees with this parser" : ", stats agree")
                        : " (cross-checks skipped)");
    if (v->api_open && v->parsed > 8192)
        fprintf(o, "  api note      per-entry cross-check capped at 8192 of %u entries\n", v->parsed);

    for (int i = 0; i < C_NCAT; i++)
        if (v->cat_err[i] || v->cat_warn[i])
            fprintf(o, "  [%s] %llu error(s), %llu warning(s)\n", vcat[i],
                    (unsigned long long)v->cat_err[i], (unsigned long long)v->cat_warn[i]);
    if (v->printed)
        fprintf(o, "  problems      first %llu of %llu:\n",
                (unsigned long long)v->printed, (unsigned long long)(v->err + v->warn));
    else
        fprintf(o, "  problems      none\n");
    for (uint64_t i = 0; i < v->printed; i++)
        fprintf(o, "    %s\n", v->msg[i]);
    fprintf(o, "result: %s (%llu errors, %llu warnings)\n",
            v->err ? "FAIL" : "OK", (unsigned long long)v->err, (unsigned long long)v->warn);
    /* Machine-greppable: one line, stable keys, nothing else on it. */
    fprintf(o, "CFS-VERIFY: result=%s path=%s errors=%llu warnings=%llu files=%u blocks=%llu "
               "orig=%llu comp=%llu store=%llu dead=%llu dead_pct=%.2f refs_past_store=%llu\n",
            v->err ? "FAIL" : "OK", v->path,
            (unsigned long long)v->err, (unsigned long long)v->warn, v->parsed,
            (unsigned long long)v->nblk, (unsigned long long)v->orig_bytes,
            (unsigned long long)v->comp_bytes, (unsigned long long)v->store_size,
            (unsigned long long)v->store_dead, pct(v->store_dead, v->store_size),
            (unsigned long long)v->ref_past_store);
}

/* ═══ cfs_verify ══════════════════════════════════════════════ */
int cfs_verify(const char *path, unsigned flags, FILE *out) {
    if (!path || !out) return -1;
    VCtx v;
    memset(&v, 0, sizeof v);
    v.out = out; v.path = path; v.deep = (flags & CFS_VERIFY_DEEP) ? 1 : 0;
    v.high_water = CFS_SB_SIZE;   /* the superblock is the first thing in the file */
    v.fd = open(path, O_RDONLY);
    if (v.fd < 0) return -1;
    off_t end = lseek(v.fd, 0, SEEK_END);
    v.fsz = end > 0 ? (uint64_t)end : 0;

    /* ── 1. superblock slots ──────────────────────────────────
     * Two slots, each in its own sector.  The newest valid one wins; a v2
     * record (legacy layout, no CRC/seq) is only a superblock in slot 0.
     * Checking the CRC here is the point: verify has to say that a torn
     * slot exists even though the reader is able to fall back to the other. */
    VSb sb; memset(&sb, 0, sizeof sb);
    int have_sb = 0, fatal = 0;
    if (v.fsz < CFS_SB_SIZE) {
        vprob(&v, C_SB, 1, "file is %llu B, shorter than the %u-byte superblock",
              (unsigned long long)v.fsz, (unsigned)CFS_SB_SIZE);
        fatal = 1;
    } else {
        static const uint64_t slot_off[2] = { 0, CFS_SB_SLOT_SIZE };
        uint8_t raw[2][CFS_SB_REC_SIZE];
        size_t  raw_n[2];
        CfsSbSlot slot[2];
        for (int i = 0; i < 2; i++) {
            /* Partial read: an old container may end before the second slot. */
            memset(raw[i], 0, sizeof raw[i]);
            raw_n[i] = 0;
            if (slot_off[i] < v.fsz) {
                size_t avail = (size_t)(v.fsz - slot_off[i]);
                if (avail > sizeof raw[i]) avail = sizeof raw[i];
                ssize_t r = pread(v.fd, raw[i], avail, (off_t)slot_off[i]);
                raw_n[i] = r > 0 ? (size_t)r : 0;
            }
            cfs_sb_decode(raw[i], raw_n[i], &slot[i]);
        }
        /* In an old container the bytes at 512 are data, not a record. */
        if (slot[1].kind == CFS_SB_SLOT_LEGACY) slot[1].kind = CFS_SB_SLOT_INVALID;

        int pick = -1;
        if (slot[0].kind && slot[1].kind)
            pick = slot[1].seq > slot[0].seq ? 1 : 0;
        else if (slot[0].kind) pick = 0;
        else if (slot[1].kind) pick = 1;

        /* A record that has the magic and a known version but no matching
         * CRC is a torn write — say so, even though @pick saves the day. */
        for (int i = 0; i < 2; i++) {
            if (slot[i].kind != CFS_SB_SLOT_INVALID) continue;
            if (raw_n[i] < CFS_SB_SIZE ||
                memcmp(raw[i], CFS_MAGIC, CFS_MAGIC_LEN)) continue;
            uint16_t ver = cfs_rd16(raw[i] + 8);
            if (ver != CFS_VERSION && ver != CFS_VERSION_LEGACY) continue;
            vprob(&v, C_SB, 1, "slot %d: CRC does not match its fields "
                  "(torn or corrupt; the reader would %s)",
                  i, pick >= 0 ? "fall back to the other slot" : "refuse the container");
        }
        if (pick < 0) {
            vprob(&v, C_SB, 1, "no valid superblock slot in either sector");
            fatal = 1;
        } else {
            CfsSbSlot *w = &slot[pick];
            memcpy(sb.magic, w->sb.magic, 8);
            sb.version      = w->sb.version;
            sb.inode_off    = w->sb.inode_offset;
            sb.inode_size   = w->sb.inode_size;
            sb.file_count   = w->sb.file_count;
            sb.created_at   = w->sb.created_at;
            sb.flags        = w->sb.flags;
            have_sb = 1;
            if (w->kind == CFS_SB_SLOT_LEGACY) {
                /* Informational, not a problem: this is the v2 layout the
                 * reader upgrades on its first write. */
                vprob(&v, C_SB, 0, "v2 (legacy) superblock in slot 0; layout "
                      "is upgraded on the first write");
            } else if (slot[pick ^ 1].kind == CFS_SB_SLOT_INVALID) {
                vprob(&v, C_SB, 0, "using slot %d (seq %u); the other slot is "
                      "not valid yet", pick, (unsigned)w->seq);
            }
            if (memcmp(sb.magic, CFS_MAGIC, CFS_MAGIC_LEN)) {
                vprob(&v, C_SB, 1, "bad magic %02x%02x%02x%02x... (expected \"%s\")",
                      sb.magic[0], sb.magic[1], sb.magic[2], sb.magic[3], CFS_MAGIC);
                fatal = 1;   /* every offset below is derived from it */
            }
            if (sb.version != CFS_VERSION && sb.version != CFS_VERSION_LEGACY)
                vprob(&v, C_SB, 1, "version %u, this build reads %u and %u",
                      (unsigned)sb.version, (unsigned)CFS_VERSION_LEGACY,
                      (unsigned)CFS_VERSION);
            if (sb.flags & ~(CFS_SB_FLAG_RAW | CFS_SB_FLAG_REMOVABLE |
                             CFS_SB_FLAG_ROTATIONAL | CFS_SB_FLAG_SD))
                vprob(&v, C_SB, 0, "unknown flag bits 0x%04x set", (unsigned)(sb.flags & 0xFFF0));
            v.file_count = sb.file_count;
        }
    }

    /* ── 2. inode table ─────────────────────────────────────── */
    VInode *ins = NULL;
    uint32_t n = 0;
    if (!fatal) {
        uint64_t off = sb.inode_off, sz = sb.inode_size;
        if (off < CFS_SB_SIZE)
            vprob(&v, C_TAB, 1, "inode_offset=%llu overlaps the superblock (0..%u)",
                  (unsigned long long)off, (unsigned)CFS_SB_SIZE);
        if (sz == 0 && sb.file_count)
            vprob(&v, C_TAB, 1, "inode_size=0 but file_count=%u", sb.file_count);
        if (off > v.fsz || sz > v.fsz - off) {
            vprob(&v, C_TAB, 1, "inode table [%llu,%llu) lies past the end of the file (%llu B)",
                  (unsigned long long)off, (unsigned long long)(off + sz), (unsigned long long)v.fsz);
            sz = off < v.fsz ? v.fsz - off : 0;      /* parse what is really there */
        }
        v.table_off = off;
        v.table_end = off + sz;
        if (sz > (512ULL << 20)) {
            vprob(&v, C_TAB, 1, "inode_size=%llu is implausibly large; not reading it",
                  (unsigned long long)sz);
            sz = 0;
        }
        if (sz) {
            uint8_t *t = malloc((size_t)sz);
            if (!t) { vprob(&v, C_TAB, 1, "cannot allocate %llu B for the inode table", (unsigned long long)sz); }
            else {
                if (vpread(&v, t, (size_t)sz, off) != 0) {
                    vprob(&v, C_TAB, 1, "cannot read the inode table at %llu", (unsigned long long)off);
                } else {
                    ins = parse_table(&v, t, sz, sb.file_count, &n);
                }
                free(t);
            }
        }
        v.parsed = n;
        if (n != sb.file_count)
            vprob(&v, C_TAB, 1, "file_count=%u but %u entries were parsed from %llu B of table",
                  sb.file_count, n, (unsigned long long)sz);
    }

    /* ── 3. paths and modes ─────────────────────────────────── */
    if (ins) {
        for (uint32_t i = 0; i < n; i++) {
            const VInode *e = &ins[i];
            const char *nm = e->path ? e->path : "(no path)";
            if (e->plen == 0)
                vprob(&v, C_TAB, 1, "entry %u at table+%llu: empty path (path_len=0)", i,
                      (unsigned long long)e->at);
            else if (memchr(e->path, 0, e->plen))
                vprob(&v, C_TAB, 1, "entry %u: path contains a NUL byte — cfs_open() would look it up as \"%s\"",
                      i, e->path);
            if (e->mode > CFS_MODE_DEDUP)
                vprob(&v, C_TAB, 1, "entry %u \"%s\": mode=%u is not FILE/DIR/SYMLINK/DEDUP",
                      i, nm, (unsigned)e->mode);
            if (!(e->path && e->path[0] == '@')) v.user_count++;
            if (e->path && !strcmp(e->path, CFS_STORE_PATH)) {
                if (v.have_store)
                    vprob(&v, C_STORE, 1, "entry %u: duplicate \"%s\" entry", i, CFS_STORE_PATH);
                v.have_store = 1;
                v.store_size = e->orig;
            }
            if (e->path && !strcmp(e->path, "@block")) {
                if (v.have_block)
                    vprob(&v, C_PHYS, 1, "entry %u: duplicate \"@block\" entry", i);
                v.have_block = 1;
                v.device_size = e->orig;
                v.device_dedup = (e->mode == CFS_MODE_DEDUP);
                /* How much of the declared device is actually backed by
                 * bytes, vs. left as a sparse zero tail the block layer
                 * synthesises.  A merged @block has no content blocks left —
                 * its bytes live in @store — so the sum below is the size of
                 * its reference table, and the summary says so instead. */
                for (uint32_t b = 0; b < e->nblk; b++) v.device_used += e->blk[b].orig;
            }
        }
        /* Duplicate paths: lu() returns the first match, so a second entry
         * with the same name is unreachable through every lookup path.
         * Sorted by name so the check stays O(n log n) on a big table. */
        VName *vnm = malloc((size_t)n * sizeof *vnm);
        if (vnm) {
            uint32_t m = 0;
            for (uint32_t i = 0; i < n; i++)
                if (ins[i].path) vnm[m++] = (VName){ ins[i].path, i };
            qsort(vnm, m, sizeof *vnm, cmp_name);
            for (uint32_t i = 1; i < m; i++)
                if (!strcmp(vnm[i - 1].p, vnm[i].p))
                    vprob(&v, C_TAB, 1, "entries %u and %u share the path \"%s\" (only the first is reachable)",
                          vnm[i - 1].i, vnm[i].i, vnm[i].p);
            free(vnm);
        }
    }

    /* ── 4. block tables, headers, physical extents ─────────── */
    if (ins) {
        for (uint32_t i = 0; i < n; i++) {
            check_blocks(&v, &ins[i], i);
            check_block_header(&v, &ins[i], i);
        }
        /* Overlap sweep: the read path locates bytes by prefix sum, so two
         * blocks sharing physical bytes means two files claiming the same
         * content — one of them reads the other's data. */
        if (v.nrng) {
            qsort(v.rng, v.nrng, sizeof *v.rng, cmp_range);
            uint64_t max_end = 0; uint32_t mi = 0, mb = 0; int have_max = 0;
            for (uint32_t i = 0; i < v.nrng; i++) {
                VRange *r = &v.rng[i];
                if (have_max && r->s < max_end) {
                    v.overlaps++;
                    vprob(&v, C_BLK, 1,
                          "inode %u block %u [%llu,%llu) overlaps inode %u block %u ending at %llu",
                          r->ino, r->blk, (unsigned long long)r->s, (unsigned long long)r->e,
                          mi, mb, (unsigned long long)max_end);
                }
                if (!have_max || r->e > max_end) { max_end = r->e; mi = r->ino; mb = r->blk; have_max = 1; }
                if (r->s < v.table_end && r->e > v.table_off) {
                    vprob(&v, C_BLK, 1, "inode %u block %u [%llu,%llu) overlaps the inode table [%llu,%llu)",
                          r->ino, r->blk, (unsigned long long)r->s, (unsigned long long)r->e,
                          (unsigned long long)v.table_off, (unsigned long long)v.table_end);
                }
            }
        }
    }

    /* ── 5. dedup reference tables + @store accounting ──────── */
    const VInode *store = NULL;
    if (ins) {
        for (uint32_t i = 0; i < n; i++)
            if (ins[i].path && !strcmp(ins[i].path, CFS_STORE_PATH)) { store = &ins[i]; break; }
        for (uint32_t i = 0; i < n; i++) {
            if (ins[i].mode != CFS_MODE_DEDUP) continue;
            if (ins[i].path && !strcmp(ins[i].path, CFS_STORE_PATH)) {
                vprob(&v, C_STORE, 1, "entry %u: @store itself is marked DEDUP", i);
                continue;
            }
            check_dedup(&v, &ins[i], i, store);
        }
        if (v.dedup_files && !store)
            vprob(&v, C_STORE, 1, "%llu DEDUP file(s) but no \"%s\" entry to resolve them against",
                  (unsigned long long)v.dedup_files, CFS_STORE_PATH);
        /* Dead-byte accounting, by the same union rule cfs_dedup_gc() uses:
         * bytes of @store no tuple points at are what a reclamation pass
         * would drop, and CFS_DEDUP_DEAD_MAX is expressed in these terms. */
        if (store) {
            if (v.nspn > 1) qsort(v.spn, v.nspn, sizeof *v.spn, cmp_span);
            uint64_t live = 0, cur_s = 0, cur_e = 0;
            for (uint32_t i = 0; i < v.nspn; i++) {
                uint64_t s = v.spn[i].s, e = v.spn[i].e;
                if (s > v.store_size) s = v.store_size;      /* past-store refs counted separately */
                if (e > v.store_size) e = v.store_size;
                if (e <= s) continue;
                if (s > cur_e) { live += cur_e - cur_s; cur_s = s; cur_e = e; }
                else if (e > cur_e) cur_e = e;
            }
            live += cur_e - cur_s;
            v.store_live = live;
            v.store_dead = v.store_size > live ? v.store_size - live : 0;
        }
    }

    /* ── 6. --deep ──────────────────────────────────────────── */
    CFS *c = NULL;
    if (ins && v.deep) {
        for (uint32_t i = 0; i < n; i++) {
            const VInode *e = &ins[i];
            if (e->mode == CFS_MODE_DIR || e->nblk == 0) continue;
            if (e->mode == CFS_MODE_DEDUP) continue;   /* table blocks already decoded */
            for (uint32_t b = 0; b < e->nblk; b++) {
                if (e->blk[b].orig > CFS_BLOCK_MAX) continue;   /* reported above */
                uint8_t *dec = malloc(e->blk[b].orig ? e->blk[b].orig : 1);
                if (!dec) break;
                char what[160];
                snprintf(what, sizeof what, "inode %u \"%s\" block %u", i,
                         e->path ? e->path : "(no path)", b);
                if (vdecode(&v, &e->blk[b], dec, C_DEEP, what) == 0) {
                    v.deep_blocks++;
                    v.deep_bytes += e->blk[b].orig;
                }
                free(dec);
            }
        }
    }

    /* ── 7. the library's own view, where it has one ────────── */
    c = cfs_open(path, CFS_RDONLY);
    if (c) {
        v.api_open = 1;
        CfsStats st;
        cfs_stats(c, &st);
        if (st.file_count != v.user_count) {
            v.api_mismatch++;
            vprob(&v, C_API, 1, "cfs_stats().file_count=%u, this parser counts %u user entries",
                  st.file_count, v.user_count);
        }
        uint64_t pu = cfs_physical_used(c);
        if (pu != v.fsz) {
            v.api_mismatch++;
            vprob(&v, C_API, 1, "cfs_physical_used()=%llu, file size is %llu",
                  (unsigned long long)pu, (unsigned long long)v.fsz);
        }
        if (v.have_block) {
            uint64_t bs = cfs_block_size(c);
            if (bs != v.device_size) {
                v.api_mismatch++;
                vprob(&v, C_API, 1, "cfs_block_size()=%llu, @block orig_size in the table is %llu",
                      (unsigned long long)bs, (unsigned long long)v.device_size);
            }
        }
        /* lu() is a linear scan, so this per-entry comparison is O(n²); on a
         * table large enough for that to matter, the aggregate checks above
         * still cover the shape and the note in the summary says so. */
        uint32_t per_entry_cap = 8192;
        for (uint32_t i = 0; ins && i < n && i < per_entry_cap; i++) {
            if (!ins[i].path) continue;
            CfsStat fs;
            if (cfs_stat(c, ins[i].path, &fs) != 0) continue;   /* duplicate/unreachable: reported above */
            if (fs.size != ins[i].orig || fs.mode != ins[i].mode || fs.block_count != ins[i].nblk) {
                v.api_mismatch++;
                vprob(&v, C_API, 1, "\"%s\": cfs_stat says size=%llu mode=%u blocks=%u, table says "
                      "size=%llu mode=%u blocks=%u",
                      ins[i].path, (unsigned long long)fs.size, (unsigned)fs.mode,
                      (unsigned)fs.block_count, (unsigned long long)ins[i].orig,
                      (unsigned)ins[i].mode, (unsigned)ins[i].nblk);
            }
        }
        /* Both readers agree on the shape; now make them read the same bytes. */
        if (v.deep) {
            for (uint32_t i = 0; ins && i < n; i++) {
                const VInode *e = &ins[i];
                if (!e->path || e->mode == CFS_MODE_DIR || e->orig == 0) continue;
                if (e->mode != CFS_MODE_DEDUP) { deep_crosscheck(&v, c, e, NULL, NULL); continue; }
                uint64_t tl = 0;
                uint8_t *pb = vpayload(&v, e, &tl, C_REF);
                if (!pb) continue;
                CfsDedupTable t;
                if (cfs_dedup_parse(pb, (size_t)tl, &t) == 0) {
                    deep_crosscheck(&v, c, e, &t, store);
                    cfs_dedup_table_free(&t);
                }
                free(pb);
            }
        }
        cfs_close(c);
    } else {
        vprob(&v, C_API, 1, "cfs_open() refused the container (this parser got this far)");
    }

    print_summary(&v, &sb, have_sb, v.deep);

    if (ins) {
        for (uint32_t i = 0; i < n; i++) { free(ins[i].path); free(ins[i].blk); }
        free(ins);
    }
    free(v.rng); free(v.spn);
    close(v.fd);
    return (int)(v.err > 0x7FFFFFFF ? 0x7FFFFFFF : v.err);
}
