#define _GNU_SOURCE
#include "cfs_internal.h"
#include "../libcpool/cpenc.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)p[0]|((uint16_t)p[1]<<8); }
static inline uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static inline uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p)|((uint64_t)rd32(p+4)<<32); }
static void wr16(uint8_t *p, uint16_t v) { p[0]=v&0xFF;p[1]=v>>8; }
static void wr32(uint8_t *p, uint32_t v) { p[0]=v&0xFF;p[1]=(v>>8)&0xFF;p[2]=(v>>16)&0xFF;p[3]=v>>24; }
static void wr64(uint8_t *p, uint64_t v) { wr32(p,(uint32_t)(v&0xFFFFFFFFULL)); wr32(p+4,(uint32_t)(v>>32)); }
static InodeEntry *lu(CFS *c,const char *path){for(uint32_t i=0;i<c->inode_count;i++)if(c->inodes[i].path&&!strcmp(c->inodes[i].path,path))return &c->inodes[i];return NULL;}

/* dynamic block table helpers */
static void inode_clear_blocks(InodeEntry *e) {
    free(e->raw.blocks);
    e->raw.blocks = NULL;
    e->raw.block_count = 0;
}
static int inode_grow_blocks(InodeEntry *e, uint32_t n) {
    CfsBlock *nb = realloc(e->raw.blocks, (size_t)(n ? n : 1) * sizeof(CfsBlock));
    if (!nb) return -1;
    if (n > e->raw.block_count)
        memset(nb + e->raw.block_count, 0, (size_t)(n - e->raw.block_count) * sizeof(CfsBlock));
    e->raw.blocks = nb;
    e->raw.block_count = n;
    return 0;
}

/* Merge layer — defined at the end of this file. */
static ssize_t dedup_read(CFS *c, InodeEntry *e, void *buf, size_t size, off_t offset);
static void dedup_cache_drop(CFS *c);
static int dedup_fi_add(CFS *c, const uint8_t *p, size_t n, uint64_t off);
static int dedup_pend_ready(CFS *c);
static int dedup_pend_flush(CFS *c);
static int dedup_table_flush(CFS *c);
static int dedup_emit(CFS *c, const uint8_t *p, size_t n, uint64_t *out_off);
static int cfs_lock(CFS *c);

/* ── Container-file writes: two kinds, one of them quota-guarded ──
 * Data blocks grow the file and answer to the physical quota.  Metadata (the
 * inode table and the superblock) must always land: refusing those would not
 * leave a full container, it would leave a corrupt one, and the data blocks
 * they describe are already on disk by then.  Every write to the container
 * file goes through one of these two, so there is a single place to audit. */
static int cfs_phys_room(CFS *c, off_t off, size_t n) {
    if (!c->phys_limit) return 0;                     /* unlimited */
    off_t end = lseek(c->fd, 0, SEEK_END);
    uint64_t proj = (uint64_t)off + (uint64_t)n;
    /* An in-place rewrite of an existing block may not extend the file, so
     * the projection is the file's own end when that is further out. */
    if (end > 0 && (uint64_t)end > proj) proj = (uint64_t)end;
    /* The inode table and the superblock are written past the data and are
     * never refused, so keep room for them — otherwise a container sitting
     * exactly at its quota would still grow by the table on the next sync. */
    proj += (uint64_t)c->sb.inode_size + CFS_SB_SIZE;
    if (proj > c->phys_limit) { errno = ENOSPC; return CFS_ENOSPC; }
    return 0;
}

static ssize_t cfs_pw(CFS *c, const void *b, size_t n, off_t off) {
    int rc = cfs_phys_room(c, off, n);
    if (rc) { errno = ENOSPC; return -1; }
    return pwrite(c->fd, b, n, off);
}

static ssize_t cfs_pw_meta(CFS *c, const void *b, size_t n, off_t off) {
    return pwrite(c->fd, b, n, off);
}

/* ── Write superblock + inode table to disk ────────────────────── */
static int cfs_sync(CFS *c) {
    volatile uint64_t canary_a = 0xCAFEBABECAFEBABEULL;
    volatile uint64_t canary_b = 0xDEADBEEFDEADBEEFULL;
    if (!c || !(c->flags & CFS_RDWR)) return -1;

    /* Merge layer: buffered store bytes and edited reference tables have to
     * reach disk before the inode table that points at them. */
    if (dedup_pend_flush(c) != 0) return -1;
    if (dedup_table_flush(c) != 0) return -1;

    /* Serialise inode table */
    size_t ts = 0;
    for (uint32_t i = 0; i < c->inode_count; i++)
        ts += CFS_INODE_FIXED_SIZE + (size_t)c->inodes[i].raw.block_count * 16
            + c->inodes[i].raw.path_len;
    uint8_t *tab = calloc(1, ts);
    if (!tab) return -1;
    uint8_t *op = tab;
    for (uint32_t i = 0; i < c->inode_count; i++) {
        InodeEntry *e = &c->inodes[i];
        wr64(op, e->raw.orig_size); op += 8;
        wr64(op, e->raw.mtime);     op += 8;
        wr16(op, e->raw.mode);      op += 2;
        wr16(op, e->raw.path_len);  op += 2;
        wr32(op, e->raw.block_count); op += 4;
        for (uint32_t b = 0; b < e->raw.block_count; b++) {
            wr64(op, e->raw.blocks[b].offset);     op += 8;
            wr32(op, e->raw.blocks[b].comp_size);  op += 4;
            wr32(op, e->raw.blocks[b].orig_size);  op += 4;
        }
        memcpy(op, e->path, e->raw.path_len);
        op += e->raw.path_len;
    }
    c->sb.inode_size = (uint32_t)(op - tab);

    /* Find physical end of last data block */
    uint64_t data_end = CFS_SB_SIZE;
    c->st.total_compressed_size = 0;
    c->st.total_orig_size = 0;
    c->st.file_count = 0;
    for (uint32_t i = 0; i < c->inode_count; i++) {
        /* Reserved entries (@block, @store) are internal — see cfs_open. */
        int user = !(c->inodes[i].path && c->inodes[i].path[0] == '@');
        if (user) {
            c->st.total_orig_size += c->inodes[i].raw.orig_size;
            c->st.file_count++;
        }
        for (uint32_t b = 0; b < c->inodes[i].raw.block_count; b++) {
            uint64_t be = c->inodes[i].raw.blocks[b].offset + c->inodes[i].raw.blocks[b].comp_size;
            if (be > data_end) data_end = be;
            if (user) c->st.total_compressed_size += c->inodes[i].raw.blocks[b].comp_size;
        }
    }
    c->st.compress_ratio = c->st.total_compressed_size > 0
        ? (float)c->st.total_orig_size / (float)c->st.total_compressed_size : 1.0f;
    c->sb.file_count = c->inode_count;

    /* Write inode table after last data block, then superblock.
     * Table position is monotonic (high-water of previous table end):
     * in-place block shrink can pull data_end backward, and a retreating
     * table would sit inside data that a later append reuses. */
    uint64_t hi = c->sb.inode_offset + c->sb.inode_size;
    uint64_t io = data_end > hi ? data_end : hi;
    off_t io_off = (off_t)io;
    if (cfs_pw_meta(c, tab, c->sb.inode_size, io_off) != (ssize_t)c->sb.inode_size) {
        free(tab); return -1;
    }
    c->sb.inode_offset = (uint64_t)io_off;
    free(tab);

    /* Build and write superblock */
    uint8_t sb[CFS_SB_SIZE];
    memset(sb, 0, CFS_SB_SIZE);
    memcpy(sb, CFS_MAGIC, 8);
    wr16(sb + 8,  (uint16_t)c->sb.version);
    wr64(sb + 10, c->sb.inode_offset);
    wr32(sb + 18, c->sb.inode_size);
    wr32(sb + 22, c->sb.file_count);
    wr64(sb + 26, c->sb.created_at);
    wr16(sb + 34, c->sb.flags);
    if (cfs_pw_meta(c, sb, CFS_SB_SIZE, 0) != CFS_SB_SIZE) return -1;
    if (fsync(c->fd) != 0) return -1;
    if (canary_a != 0xCAFEBABECAFEBABEULL || canary_b != 0xDEADBEEFDEADBEEFULL)
        write(2, "CANARY CORRUPT in cfs_sync\n", 27);
    return 0;
}

/* ── Create new container ────────────────────────────────── */
CFS *cfs_create(const char *path) {
    CFS *c = calloc(1, sizeof(*c)); if(!c)return NULL;
    c->fd = open(path, O_RDWR|O_CREAT|O_TRUNC, 0644);
    if(c->fd < 0) { free(c); return NULL; }
    c->cpath = strdup(path);
    if (!c->cpath) { close(c->fd); free(c); return NULL; }
    c->flags = CFS_RDWR;
    /* O_TRUNC has already cut the file down, so this is the last chance to
     * notice that someone else was using it — without the lock, "create"
     * silently destroys a container another handle is writing. */
    if (cfs_lock(c) != 0) { errno = EBUSY; close(c->fd); free(c); return NULL; }
    c->part_kind = -1;   /* partition cache starts unparsed */
    memcpy(c->sb.magic, CFS_MAGIC, 8);
    c->sb.version = CFS_VERSION;
    c->sb.created_at = (uint64_t)time(NULL);
    c->sb.inode_offset = CFS_SB_SIZE;
    /* Write initial superblock */
    if (cfs_sync(c) != 0) { close(c->fd); free(c); return NULL; }
    return c;
}

int cfs_set_raw(CFS *c) {
    if (!c || !(c->flags & CFS_RDWR)) return -1;
    c->flags |= CFS_RAW;
    c->sb.flags |= CFS_SB_FLAG_RAW;
    return cfs_sync(c);
}

/* ── Add file (builder API) ───────────────────────────────── */
int cfs_add_file(CFS *c, const char *vpath, const void *buf, size_t size) {
    if(!c||!vpath||!buf||size==0) return -1;
    size_t cl=0; uint8_t *comp=NULL;

    if(c->flags & CFS_RAW){
        /* Store uncompressed: CPEnc RAW header + lag byte + raw data */
        cl = CPENC_HEADER_SIZE + 1 + size;
        comp = malloc(cl);
        if(!comp) return -1;
        CPEncHeader *rh = (CPEncHeader*)comp;
        memset(rh,0,CPENC_HEADER_SIZE);rh->magic=CPENC_MAGIC;rh->version=CPENC_VERSION;
        rh->stride=CPENC_STRIDE_RAW;rh->original_size=(uint32_t)size;rh->compressed_size=(uint32_t)(1+size);
        comp[CPENC_HEADER_SIZE]=CPENC_LAG_NONE;
        memcpy(comp+CPENC_HEADER_SIZE+1, buf, size);
    }else{
        size_t mc=cpenc_max_compressed_size(size);
        comp=malloc(mc); if(!comp)return -1;
        cl=mc;
        if(cpenc_compress(buf,size,comp,&cl,2)!=0){free(comp);return -1;}
    }

    off_t write_off = (off_t)c->sb.inode_offset;
    if(cfs_pw(c,comp,cl,write_off)!=(ssize_t)cl){free(comp);return -1;}

    InodeEntry *na=realloc(c->inodes,(c->inode_count+1)*sizeof(InodeEntry));
    if(!na){free(comp);return -1;} c->inodes=na;
    InodeEntry *e=&c->inodes[c->inode_count++];
    memset(e,0,sizeof(*e));
    e->path=strdup(vpath);
    e->raw.orig_size=size; e->raw.mtime=(uint64_t)time(NULL);
    e->raw.mode=CFS_MODE_FILE; e->raw.path_len=(uint16_t)strlen(vpath);
    if (inode_grow_blocks(e, 1) != 0) { free(e->path); c->inode_count--; free(comp); return -1; }
    e->raw.blocks[0].offset=(uint64_t)write_off;
    e->raw.blocks[0].comp_size=(uint32_t)cl;
    e->raw.blocks[0].orig_size=(uint32_t)size;
    free(comp);
    return cfs_sync(c);
}

/* ── Finalise ────────────────────────────────────────────── */
int cfs_finalise(CFS *c) {
    return cfs_sync(c);
}

/* ── Open ─────────────────────────────────────────────────── */
/* ── One writer at a time ────────────────────────────────────────
 * A sync updates the data blocks, then the inode table, then the superblock,
 * in several passes; a second writer interleaving with that, or a reader
 * walking in between two of the passes, sees a table pointing at bytes that
 * are not there yet.  Nothing in the format prevents it, so the container
 * takes an advisory lock: writers exclusive, readers shared.  flock rather
 * than fcntl because it conflicts between two file descriptors even inside
 * one process, which is where a second handle would otherwise slip through.
 *
 * CFS_NO_LOCK=1 skips it, for reading a container whose writer is known to
 * be idle (inspection, recovery).  It does not make concurrent writing
 * safe — it only removes the seatbelt. */
static int cfs_lock(CFS *c) {
    const char *off = getenv("CFS_NO_LOCK");
    if (off && *off && *off != '0') return 0;
    if (flock(c->fd, ((c->flags & CFS_RDWR) ? LOCK_EX : LOCK_SH) | LOCK_NB) != 0)
        return -1;
    c->locked = 1;
    return 0;
}

CFS *cfs_open(const char *path, int flags) {
    int oflags = (flags & CFS_RDWR) ? O_RDWR : O_RDONLY;
    CFS *c = calloc(1, sizeof(*c)); if (!c) return NULL;
    c->part_kind = -1;   /* partition cache starts unparsed (calloc would give NONE) */
    c->flags = flags & (CFS_RDONLY | CFS_RDWR);
    c->fd = open(path, oflags);
    if (c->fd < 0) { free(c); return NULL; }
    c->cpath = strdup(path);
    if (!c->cpath) { close(c->fd); free(c); return NULL; }
    /* Lock before reading anything: a table read while another handle is
     * halfway through a sync is exactly the torn state this prevents. */
    if (cfs_lock(c) != 0) { errno = EBUSY; close(c->fd); free(c); return NULL; }
    /* Host policy, not container content: the physical quota is set by
     * whoever opens the container (the hook and the CLI both honour
     * CFS_MAX_PHYSICAL), so it never has to live in the format. */
    {
        const char *lim = getenv("CFS_MAX_PHYSICAL");
        if (lim && *lim) c->phys_limit = strtoull(lim, NULL, 0);
    }

    uint8_t sb[CFS_SB_SIZE];
    if (pread(c->fd, sb, CFS_SB_SIZE, 0) != CFS_SB_SIZE) goto fail;
    if (memcmp(sb, CFS_MAGIC, 8) || rd16(sb + 8) != CFS_VERSION) {
        goto fail;
    }
    memcpy(c->sb.magic, sb, 8);
    c->sb.version      = rd16(sb + 8);
    c->sb.inode_offset = rd64(sb + 10);
    c->sb.inode_size   = rd32(sb + 18);
    c->sb.file_count   = rd32(sb + 22);
    c->sb.created_at   = rd64(sb + 26);
    c->sb.flags        = rd16(sb + 34);
    /* container self-describes: RAW flag on disk forces uncompressed mode
     * regardless of the caller's open flags */
    if (c->sb.flags & CFS_SB_FLAG_RAW) c->flags |= CFS_RAW;
    c->st.file_count   = 0;   /* counted below, user files only */
    /* The table's position and size come from the superblock, so neither is
     * trusted: inode_size is a u32 (up to 4GB) and file_count a u32 that
     * would be multiplied by sizeof(InodeEntry).  A crafted container kills
     * the process allocating them before any parser sees the contents —
     * fuzzing the container parser found exactly that, as an out-of-memory
     * far from any crash inside cfs.  The table has to fit in the file, and
     * the entry count has to fit in the table. */
    off_t fsz = lseek(c->fd, 0, SEEK_END);
    if (fsz < 0) goto fail;
    if ((uint64_t)c->sb.inode_offset + (uint64_t)c->sb.inode_size > (uint64_t)fsz)
        goto fail;
    if (c->sb.file_count > c->sb.inode_size / CFS_INODE_FIXED_SIZE)
        goto fail;
    if (c->sb.file_count == 0) return c;

    uint8_t *it = malloc(c->sb.inode_size);
    if (!it || pread(c->fd, it, c->sb.inode_size, (off_t)c->sb.inode_offset) != (ssize_t)c->sb.inode_size)
        { free(it); goto fail; }
    c->inodes = calloc(c->sb.file_count, sizeof(InodeEntry));
    if (!c->inodes) { free(it); goto fail; }

    const uint8_t *p = it, *end = it + c->sb.inode_size;
    for (uint32_t i = 0; i < c->sb.file_count && p + CFS_INODE_FIXED_SIZE <= end; i++) {
        InodeEntry *e = &c->inodes[i];
        e->raw.orig_size   = rd64(p); p += 8;
        e->raw.mtime       = rd64(p); p += 8;
        e->raw.mode        = rd16(p); p += 2;
        e->raw.path_len    = rd16(p); p += 2;
        e->raw.block_count = rd32(p); p += 4;
        if (e->raw.block_count > CFS_BLOCK_SANITY) goto fail;
        e->raw.blocks = calloc(e->raw.block_count ? e->raw.block_count : 1, sizeof(CfsBlock));
        if (!e->raw.blocks) goto fail;
        if ((size_t)(end - p) < (size_t)e->raw.block_count * 16) goto fail;
        for (uint32_t b = 0; b < e->raw.block_count; b++) {
            CfsBlock *bl = &e->raw.blocks[b];
            bl->offset    = rd64(p); p += 8;
            bl->comp_size = rd32(p); p += 4;
            bl->orig_size = rd32(p); p += 4;
            /* Every user of a block entry trusts these three fields: the read
             * path allocates the two sizes, the write path re-materialises
             * the block before patching it, and compact copies comp_size
             * bytes.  Reject a table entry the codec could not have produced
             * or that points outside the file, once, here — a 522-byte
             * container that declared comp_size = 1.7GB still made
             * block_patch malloc it, which is the fifth time fuzzing found
             * the same shape in a new place. */
            if (bl->orig_size > CFS_BLOCK_MAX || bl->comp_size == 0) goto fail;
            if (bl->comp_size > cpenc_max_compressed_size(bl->orig_size)) goto fail;
            if ((uint64_t)bl->offset + bl->comp_size > (uint64_t)fsz) goto fail;
            /* Cross-check the codec's own header against this entry.  The
             * read path sizes its output buffer from bl->orig_size while the
             * decoder trusts the header's original_size; a container where
             * the two disagree is either torn or hostile, and handing it to
             * the decoder is how a tampered block reached a heap overflow
             * (the BWT branch, fixed in cpenc, but this is the layer that
             * should never have passed the mismatch through).  HEX is exempt
             * from the size equality: its header records the folded length,
             * not the text length the table holds, and the payload carries
             * the true size for the decoder to check. */
            if (bl->comp_size < CPENC_HEADER_SIZE) goto fail;
            {
                uint8_t hb[CPENC_HEADER_SIZE];
                if (pread(c->fd, hb, sizeof hb, (off_t)bl->offset) != (ssize_t)sizeof hb) goto fail;
                if (rd16(hb) != CPENC_MAGIC) goto fail;
                if (hb[2] < 1 || hb[2] > CPENC_VERSION) goto fail;
                if (hb[3] != CPENC_STRIDE_HEX && rd32(hb + 4) != bl->orig_size) goto fail;
                if ((uint64_t)rd32(hb + 8) + CPENC_HEADER_SIZE != bl->comp_size) goto fail;
            }
        }
        /* The path has to be there.  Leaving e->path NULL with a non-zero
         * path_len used to "work" for reads — lu() checks for NULL — and
         * then crash the first write, because cfs_sync serialises path_len
         * bytes from it.  A table whose paths do not fit is malformed. */
        if (e->raw.path_len == 0 || (size_t)(end - p) < e->raw.path_len) goto fail;
        e->path = malloc(e->raw.path_len + 1);
        if (!e->path) goto fail;
        memcpy(e->path, p, e->raw.path_len);
        e->path[e->raw.path_len] = 0;
        p += e->raw.path_len;
        /* Reserved entries (@block, @store) are internal: they are not
         * user files and would double-count merged bytes. */
        if (!(e->path && e->path[0] == '@')) {
            c->st.total_orig_size += e->raw.orig_size;
            for (uint32_t b = 0; b < e->raw.block_count; b++)
                c->st.total_compressed_size += e->raw.blocks[b].comp_size;
            c->st.file_count++;
        }
        c->inode_count++;
    }
    free(it);
    c->st.compress_ratio = c->st.total_compressed_size > 0
        ? (float)c->st.total_orig_size / (float)c->st.total_compressed_size : 1.0f;
    return c;
fail:
    close(c->fd); free(c); return NULL;
}

void cfs_close(CFS *c) {
    if (!c) return;
    if ((c->flags & CFS_RDWR) && (c->pend_n || c->dt_dirty)) cfs_sync(c);
    if (c->locked) flock(c->fd, LOCK_UN);   /* close would drop it anyway */
    if (c->fd >= 0) close(c->fd);
    dedup_cache_drop(c);
    free(c->pend_buf);
    if (c->fi_ready) cfs_feat_index_free(&c->fi);
    for (uint32_t i = 0; i < c->inode_count; i++) { free(c->inodes[i].path); free(c->inodes[i].raw.blocks); }
    free(c->inodes);
    free(c->cpath);
    free(c);
}

ssize_t cfs_read(CFS *c,const char *path,void *buf,size_t size,off_t offset){
    if(!c||!buf)return -1;
    if(size==0)return 0;
    InodeEntry *e=lu(c,path);
    if(!e)return -1;
    if(e->raw.mode==CFS_MODE_DEDUP)return dedup_read(c,e,buf,size,offset);
    if(e->raw.mode!=CFS_MODE_FILE&&e->raw.mode!=CFS_MODE_SYMLINK)return -1;
    if(e->raw.block_count==0||e->raw.orig_size==0)return 0;
    if(offset<0||(uint64_t)offset>=e->raw.orig_size)return 0;
    size_t rem=size;if((uint64_t)(offset+size)>e->raw.orig_size)rem=(size_t)(e->raw.orig_size-(uint64_t)offset);
    size_t total=0; uint64_t cur_off=0; /* cur_off tracks position in file */

    for(uint32_t b=0;b<e->raw.block_count&&rem>0;b++){
        uint64_t blk_off = cur_off;
        uint64_t blk_end = cur_off + e->raw.blocks[b].orig_size;

        if((uint64_t)offset >= blk_end){cur_off=blk_end;continue;}

        /* Hole before this block? Zero-fill. */
        if((uint64_t)offset < blk_off){
            size_t nl=(size_t)(blk_off-(uint64_t)offset);if(nl>rem)nl=rem;
            memset((uint8_t*)buf+total,0,nl);total+=nl;rem-=nl;
            if(rem==0)break;
            offset=(off_t)blk_off;
        }

        /* Read overlapping portion of this block */
        uint64_t ob=(uint64_t)offset-blk_off;
        size_t nl=(size_t)(blk_end-(uint64_t)offset);if(nl>rem)nl=rem;
        /* Both sizes come from the inode table, which is as untrusted as the
         * data: cap the compressed one by the file it has to live in, and
         * the decompressed one by what the decoder itself accepts.  Without
         * this a corrupt block table asks for 4GB here, per block. */
        {
            uint64_t cs = e->raw.blocks[b].comp_size, os = e->raw.blocks[b].orig_size;
            off_t fsz = lseek(c->fd, 0, SEEK_END);
            if (cs == 0 || os > CFS_BLOCK_MAX || fsz < 0 ||
                (uint64_t)e->raw.blocks[b].offset + cs > (uint64_t)fsz)
                return (ssize_t)total > 0 ? (ssize_t)total : -1;
        }
        uint8_t *comp=malloc(e->raw.blocks[b].comp_size),*dec=malloc(e->raw.blocks[b].orig_size);
        if(!comp||!dec){free(comp);free(dec);return(ssize_t)total>0?(ssize_t)total:-1;}
        size_t dl=e->raw.blocks[b].orig_size;
        if(pread(c->fd,comp,e->raw.blocks[b].comp_size,(off_t)e->raw.blocks[b].offset)!=(ssize_t)e->raw.blocks[b].comp_size||
           cpenc_decompress(comp,e->raw.blocks[b].comp_size,dec,&dl)!=0||dl!=e->raw.blocks[b].orig_size)
           {free(comp);free(dec);return(ssize_t)total>0?(ssize_t)total:-1;}
        memcpy((uint8_t*)buf+total,dec+ob,nl);total+=nl;rem-=nl;
        offset=(off_t)blk_end; cur_off=blk_end;
        free(comp);free(dec);
    }
    /* Trailing hole after last block? Zero-fill. */
    if(rem>0){memset((uint8_t*)buf+total,0,rem);total+=rem;}
    return (ssize_t)total;
}

void *cfs_read_all(CFS *c,const char *path,size_t *out){InodeEntry *e=lu(c,path);if(!e||(e->raw.mode!=CFS_MODE_FILE&&e->raw.mode!=CFS_MODE_SYMLINK&&e->raw.mode!=CFS_MODE_DEDUP))return NULL;void *b=malloc(e->raw.orig_size?e->raw.orig_size:1);if(!b)return NULL;if(e->raw.orig_size==0){if(out)*out=0;return b;}if(cfs_read(c,path,b,e->raw.orig_size,0)!=(ssize_t)e->raw.orig_size){free(b);return NULL;}if(out)*out=e->raw.orig_size;return b;}

int cfs_ls(CFS *c,const char *dir,CfsDirEntry *ents,int max){
    if(!c||!dir||!ents||max<=0)return 0;
    size_t dl=strlen(dir);int n=0;
    /* Strip trailing slash for consistency */
    if(dl>0&&dir[dl-1]=='/')dl--;
    for(uint32_t i=0;i<c->inode_count&&n<max;i++){
        InodeEntry *e=&c->inodes[i];if(!e->path)continue;
        if(!strcmp(e->path,CFS_STORE_PATH))continue;   /* internal */
        /* Must be under dir */
        if(strncmp(e->path,dir,dl))continue;
        /* If dir is non-root, the next char must be '/' */
        if(dl>0&&e->path[dl]!='/'&&e->path[dl]!='\0')continue;
        /* Skip the directory entry itself */
        if(dl>0&&e->path[dl]=='\0')continue;
        /* Must be a direct child: no further '/' after dir prefix */
        const char *rest = e->path + dl;
        if(*rest=='/')rest++;
        if(strchr(rest,'/'))continue;
        strncpy(ents[n].name,rest,255);ents[n].name[255]=0;
        ents[n].is_dir=(e->raw.mode==CFS_MODE_DIR);ents[n].size=e->raw.orig_size;ents[n].mtime=e->raw.mtime;n++;
    }
    return n;
}

int cfs_stat(CFS *c,const char *path,CfsStat *out){if(!c||!out)return -1;InodeEntry *e=lu(c,path);if(!e)return -1;out->size=e->raw.orig_size;out->mtime=e->raw.mtime;out->mode=(uint16_t)e->raw.mode;out->block_count=e->raw.block_count;return 0;}

void cfs_stats(CFS *c,CfsStats *out){if(c&&out)*out=c->st;}

/* ═══════════════════════════════════════════════════════════════════
   cfs_write — write a file into an existing container.
   Files > CFS_BLOCK_SPLIT are split into independent compressed blocks.
   New blocks overwrite the old inode-table area; the inode table
   is rebuilt immediately after.  Old blocks of overwritten files
   are orphaned (compact not yet implemented).
   ═══════════════════════════════════════════════════════════════════ */
int cfs_write(CFS *c, const char *path, const void *buf, size_t size) {
    if (!c || !(c->flags & CFS_RDWR) || !path) return -1;
    if (size == 0) {
        /* Touch: create or clear to 0 bytes */
        InodeEntry *e = lu(c, path);
        if (!e) {
            InodeEntry *na = realloc(c->inodes, (c->inode_count + 1) * sizeof(InodeEntry));
            if (!na) return -1;
            c->inodes = na;
            e = &c->inodes[c->inode_count++];
            memset(e, 0, sizeof(*e));
            e->path = strdup(path);
            if (!e->path) { c->inode_count--; return -1; }
        } else { free(e->path); e->path = strdup(path); }
        e->raw.orig_size = 0; e->raw.block_count = 0;
        e->raw.mtime = (uint64_t)time(NULL);
        e->raw.mode = CFS_MODE_FILE;
        e->raw.path_len = (uint16_t)strlen(path);
        inode_clear_blocks(e);
        return cfs_sync(c);
    }
    if (!buf) return -1;

    InodeEntry *e = lu(c, path);
    int is_new = (e == NULL);
    uint32_t n_blocks = (uint32_t)((size + CFS_BLOCK_SPLIT - 1) / CFS_BLOCK_SPLIT);
    if (n_blocks > CFS_BLOCK_SANITY) return -2;

    /* Allocate block metadata array */
    struct { uint8_t *data; size_t cl; } *blks =
        calloc(n_blocks, sizeof(*blks));
    if (!blks) return -1;
    int ok = 1;

    /* Compress (or RAW-store) each block */
    for (uint32_t b = 0; b < n_blocks && ok; b++) {
        size_t bo = (size_t)b * CFS_BLOCK_SPLIT;
        size_t bs = bo + CFS_BLOCK_SPLIT <= size ? CFS_BLOCK_SPLIT : size - bo;

        if (c->flags & CFS_RAW) {
            blks[b].cl = CPENC_HEADER_SIZE + 1 + bs;
            blks[b].data = malloc(blks[b].cl);
            if (!blks[b].data) { ok = 0; break; }
            CPEncHeader *rh = (CPEncHeader*)blks[b].data;
            memset(rh,0,CPENC_HEADER_SIZE);rh->magic=CPENC_MAGIC;rh->version=CPENC_VERSION;
            rh->stride=CPENC_STRIDE_RAW;rh->original_size=(uint32_t)bs;rh->compressed_size=(uint32_t)(1+bs);
            blks[b].data[CPENC_HEADER_SIZE]=CPENC_LAG_NONE;
            memcpy(blks[b].data+CPENC_HEADER_SIZE+1,(const uint8_t*)buf+bo,bs);
        } else {
            size_t mc = cpenc_max_compressed_size(bs);
            blks[b].data = malloc(mc);
            if (!blks[b].data) { ok = 0; break; }
            blks[b].cl = mc;
            if (cpenc_compress((const uint8_t*)buf + bo, bs, blks[b].data, &blks[b].cl, 2)) {
                ok = 0; break;
            }
        }
    }

    if (!ok) {
        for (uint32_t b = 0; b < n_blocks; b++) free(blks[b].data);
        free(blks); return -1;
    }

    /* Physical quota, checked for the whole batch before any in-memory state
     * changes: a refusal here must leave the handle exactly as it was, or a
     * later read would walk a block table whose blocks were never written. */
    {
        uint64_t tot = 0;
        for (uint32_t b = 0; b < n_blocks; b++) tot += blks[b].cl;
        if (cfs_phys_room(c, (off_t)c->sb.inode_offset, (size_t)tot)) {
            for (uint32_t b = 0; b < n_blocks; b++) free(blks[b].data);
            free(blks); return CFS_ENOSPC;
        }
    }

    /* Allocate or reuse inode entry */
    if (is_new) {
        InodeEntry *na = realloc(c->inodes, (c->inode_count + 1) * sizeof(InodeEntry));
        if (!na) { ok = 0; }
        else { c->inodes = na; e = &c->inodes[c->inode_count]; c->inode_count++; }
    } else {
        free(e->path);
    }
    if (!ok) {
        for (uint32_t b = 0; b < n_blocks; b++) free(blks[b].data);
        free(blks); return -1;
    }
    if (!is_new) free(e->raw.blocks);   /* overwrite: release old table */
    memset(e, 0, sizeof(*e));
    if (inode_grow_blocks(e, n_blocks) != 0) {
        for (uint32_t b = 0; b < n_blocks; b++) free(blks[b].data);
        free(blks);
        if (is_new) c->inode_count--;
        return -1;
    }
    e->path = strdup(path);
    if (!e->path) {
        for (uint32_t b = 0; b < n_blocks; b++) free(blks[b].data);
        free(blks);
        if (is_new) c->inode_count--;
        return -1;
    }

    /* Write blocks sequentially */
    uint64_t cur_off = c->sb.inode_offset;
    for (uint32_t b = 0; b < n_blocks; b++) {
        if (cfs_pw(c, blks[b].data, blks[b].cl, (off_t)cur_off) != (ssize_t)blks[b].cl) {
            ok = 0; break;
        }
        e->raw.blocks[b].offset    = cur_off;
        e->raw.blocks[b].comp_size = (uint32_t)blks[b].cl;
        e->raw.blocks[b].orig_size = (uint32_t)(b < n_blocks - 1 ? CFS_BLOCK_SPLIT
                                          : size - (size_t)b * CFS_BLOCK_SPLIT);
        cur_off += blks[b].cl;
    }

    for (uint32_t b = 0; b < n_blocks; b++) free(blks[b].data);
    free(blks);

    if (!ok) {
        free(e->path);
        if (is_new) c->inode_count--;
        return -1;
    }

    e->raw.orig_size   = size;
    e->raw.mtime       = (uint64_t)time(NULL);
    e->raw.mode        = CFS_MODE_FILE;
    e->raw.path_len    = (uint16_t)strlen(path);
    e->raw.block_count = n_blocks;

    return cfs_sync(c);
}

/* ═══════════════════════════════════════════════════════════════════
   cfs_pack — import a local file into the container.
   ═══════════════════════════════════════════════════════════════════ */
int cfs_pack(CFS *c, const char *cfs_path, const char *local_path) {
    if (!c || !cfs_path || !local_path) return -1;
    int lfd = open(local_path, O_RDONLY);
    if (lfd < 0) return -1;
    off_t end = lseek(lfd, 0, SEEK_END);
    if (end < 0 || end > 0x7FFFFFFF) { close(lfd); return -1; }
    size_t sz = (size_t)end;
    if (sz == 0) { close(lfd); return -1; }
    uint8_t *buf = malloc(sz);
    if (!buf) { close(lfd); return -1; }
    if (pread(lfd, buf, sz, 0) != (ssize_t)sz) { free(buf); close(lfd); return -1; }
    close(lfd);
    int rc = cfs_write(c, cfs_path, buf, sz);
    free(buf);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════
   cfs_mkdir — create an empty directory entry.
   ═══════════════════════════════════════════════════════════════════ */
int cfs_mkdir(CFS *c, const char *path) {
    if (!c || !(c->flags & CFS_RDWR) || !path || !*path) return -1;
    /* Check for existing entry (file or dir) */
    if (lu(c, path)) { errno = EEXIST; return -1; }

    InodeEntry *na = realloc(c->inodes, (c->inode_count + 1) * sizeof(InodeEntry));
    if (!na) return -1;
    c->inodes = na;
    InodeEntry *e = &c->inodes[c->inode_count];
    memset(e, 0, sizeof(*e));
    e->path = strdup(path);
    if (!e->path) return -1;
    c->inode_count++;

    e->raw.orig_size   = 0;
    e->raw.mtime       = (uint64_t)time(NULL);
    e->raw.mode        = CFS_MODE_DIR;
    e->raw.path_len    = (uint16_t)strlen(path);
    inode_clear_blocks(e);

    return cfs_sync(c);
}

/* ═══════════════════════════════════════════════════════════════════
   cfs_unlink — remove a file or empty directory entry.
   Blocks are orphaned; a future cfs_compact can reclaim them.
   ═══════════════════════════════════════════════════════════════════ */
int cfs_unlink(CFS *c, const char *path) {
    if (!c || !(c->flags & CFS_RDWR) || !path) return -1;

    for (uint32_t i = 0; i < c->inode_count; i++) {
        if (c->inodes[i].path && !strcmp(c->inodes[i].path, path)) {
            /* Refuse to remove non-empty directory */
            if (c->inodes[i].raw.mode == CFS_MODE_DIR) {
                /* Check if any file has this dir as a prefix */
                size_t plen = strlen(path);
                for (uint32_t j = 0; j < c->inode_count; j++) {
                    if (i == j || !c->inodes[j].path) continue;
                    if (!strncmp(c->inodes[j].path, path, plen) &&
                        c->inodes[j].path[plen] == '/') {
                        errno = ENOTEMPTY;
                        return -1;
                    }
                }
            }
            /* Free and shift remaining entries */
            free(c->inodes[i].path);
            if (i < c->inode_count - 1)
                memmove(&c->inodes[i], &c->inodes[i + 1],
                        (c->inode_count - i - 1) * sizeof(InodeEntry));
            c->inode_count--;
            return cfs_sync(c);
        }
    }
    errno = ENOENT;
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════
   cfs_truncate — truncate or extend a file.
   ═══════════════════════════════════════════════════════════════════ */
int cfs_truncate(CFS *c, const char *path, uint64_t size) {
    if (!c || !(c->flags & CFS_RDWR) || !path) return -1;
    InodeEntry *e = lu(c, path);
    if (!e || e->raw.mode != CFS_MODE_FILE) return -1;

    if (size == e->raw.orig_size) return 0;

    if (size == 0) {
        e->raw.orig_size   = 0;
        e->raw.block_count = 0;
        e->raw.mtime       = (uint64_t)time(NULL);
        inode_clear_blocks(e);
        return cfs_sync(c);
    }

    /* For single-block files, decompress → truncate/extend → recompress */
    if (e->raw.block_count <= 1) {
        void *old = NULL; size_t osz = e->raw.orig_size;
        if (e->raw.block_count == 1) {
            old = malloc(osz);
            if (!old) return -1;
            if (cfs_read(c, path, old, osz, 0) != (ssize_t)osz) {
                free(old); return -1;
            }
        }
        void *nb = malloc(size);
        if (!nb) { free(old); return -1; }
        size_t cp = size < osz ? size : osz;
        if (old && cp > 0) memcpy(nb, old, cp);
        if (size > cp) memset((uint8_t*)nb + cp, 0, size - cp);
        free(old);
        int r = cfs_write(c, path, nb, size);
        free(nb);
        return r;
    }

    /* Multi-block: truncation — shrink to fit */
    uint64_t rem = size;
    uint32_t keep = 0;
    for (uint32_t b = 0; b < e->raw.block_count && rem > 0; b++) {
        keep++;
        if (rem <= e->raw.blocks[b].orig_size) break;
        rem -= e->raw.blocks[b].orig_size;
    }

    /* Recompress the last kept block if truncated mid-block */
    if (keep > 0 && rem < (uint64_t)e->raw.blocks[keep - 1].orig_size) {
        uint64_t lb_off = 0;
        for (uint32_t b = 0; b < keep - 1; b++)
            lb_off += e->raw.blocks[b].orig_size;
        uint8_t *lb = malloc(e->raw.blocks[keep - 1].orig_size);
        if (!lb) return -1;
        if (cfs_read(c, path, lb, e->raw.blocks[keep - 1].orig_size,
                     (off_t)lb_off) != (ssize_t)e->raw.blocks[keep - 1].orig_size) {
            free(lb); return -1;
        }
        size_t mc = cpenc_max_compressed_size((size_t)rem);
        uint8_t *comp = malloc(mc);
        if (!comp) { free(lb); return -1; }
        size_t cl = mc;
        int rc = cpenc_compress(lb, (size_t)rem, comp, &cl, 2);
        free(lb);
        if (rc) { free(comp); return -1; }
        off_t wo = (off_t)e->raw.blocks[keep - 1].offset;
        if (cfs_pw(c, comp, cl, wo) != (ssize_t)cl) {
            free(comp); return -1;
        }
        e->raw.blocks[keep - 1].comp_size = (uint32_t)cl;
        e->raw.blocks[keep - 1].orig_size = (uint32_t)rem;
        free(comp);
    }

    e->raw.block_count = keep;
    e->raw.orig_size   = size;
    e->raw.mtime       = (uint64_t)time(NULL);
    return cfs_sync(c);
}

/* ═══════════════════════════════════════════════════════════════════
   cfs_symlink — create a symbolic link.
   Target is stored as raw inline data.
   ═══════════════════════════════════════════════════════════════════ */
int cfs_symlink(CFS *c, const char *target, const char *linkpath) {
    if (!c || !(c->flags & CFS_RDWR) || !target || !linkpath) return -1;
    if (lu(c, linkpath)) { errno = EEXIST; return -1; }

    size_t tl = strlen(target);
    if (tl > 4095) return -1;

    InodeEntry *na = realloc(c->inodes, (c->inode_count + 1) * sizeof(InodeEntry));
    if (!na) return -1;
    c->inodes = na;
    InodeEntry *e = &c->inodes[c->inode_count];
    memset(e, 0, sizeof(*e));
    e->path = strdup(linkpath);
    if (!e->path) return -1;
    c->inode_count++;

    /* Store target string as a single uncompressed (RAW) block for simplicity */
    off_t wo = (off_t)c->sb.inode_offset;
    uint8_t hdr[CPENC_HEADER_SIZE + 1]; memset(hdr, 0, sizeof(hdr));
    CPEncHeader *h = (CPEncHeader*)hdr;
    h->magic = CPENC_MAGIC; h->version = CPENC_VERSION;
    h->stride = CPENC_STRIDE_RAW; h->original_size = (uint32_t)tl;
    h->compressed_size = (uint32_t)(1 + tl);
    hdr[CPENC_HEADER_SIZE] = CPENC_LAG_NONE;
    if (cfs_pw(c, hdr, CPENC_HEADER_SIZE + 1, wo) != CPENC_HEADER_SIZE + 1 ||
        cfs_pw(c, target, tl, wo + CPENC_HEADER_SIZE + 1) != (ssize_t)tl)
        { free(e->path); c->inode_count--; return -1; }

    e->raw.orig_size   = tl;
    e->raw.mtime       = (uint64_t)time(NULL);
    e->raw.mode        = CFS_MODE_SYMLINK;
    e->raw.path_len    = (uint16_t)strlen(linkpath);
    if (inode_grow_blocks(e, 1) != 0) { free(e->path); c->inode_count--; return -1; }
    e->raw.blocks[0].offset    = (uint64_t)wo;
    e->raw.blocks[0].comp_size = CPENC_HEADER_SIZE + 1 + (uint32_t)tl;
    e->raw.blocks[0].orig_size = (uint32_t)tl;
    return cfs_sync(c);
}

/* ── Read symlink target ────────────────────────────────────── */
ssize_t cfs_readlink(CFS *c, const char *path, char *buf, size_t bufsiz) {
    InodeEntry *e = lu(c, path);
    if (!e || e->raw.mode != CFS_MODE_SYMLINK) return -1;
    if (bufsiz == 0) return 0;
    ssize_t n = cfs_read(c, path, buf, bufsiz, 0);
    if (n > 0 && (size_t)n < bufsiz) buf[n] = 0;
    return n;
}

/* ═══════════════════════════════════════════════════════════════════
   cfs_rename — rename/move a file or directory within the container.
   ═══════════════════════════════════════════════════════════════════ */
int cfs_rename(CFS *c, const char *oldpath, const char *newpath) {
    if (!c || !(c->flags & CFS_RDWR) || !oldpath || !newpath) return -1;
    InodeEntry *e = lu(c, oldpath);
    if (!e) { errno = ENOENT; return -1; }
    if (lu(c, newpath)) { errno = EEXIST; return -1; }

    size_t opl = strlen(oldpath), npl = strlen(newpath);
    int is_dir = (e->raw.mode == CFS_MODE_DIR);

    /* Update renamed entry */
    free(e->path);
    e->path = strdup(newpath);
    if (!e->path) return -1;
    e->raw.path_len = (uint16_t)npl;
    e->raw.mtime    = (uint64_t)time(NULL);

    /* If directory, cascade rename all children */
    if (is_dir) {
        for (uint32_t i = 0; i < c->inode_count; i++) {
            if (!c->inodes[i].path) continue;
            if (!strncmp(c->inodes[i].path, oldpath, opl) &&
                c->inodes[i].path[opl] == '/') {
                size_t rest = strlen(c->inodes[i].path + opl);
                char *np = malloc(npl + rest + 1);
                if (!np) return -1;
                memcpy(np, newpath, npl);
                memcpy(np + npl, c->inodes[i].path + opl, rest + 1);
                free(c->inodes[i].path);
                c->inodes[i].path = np;
                c->inodes[i].raw.path_len = (uint16_t)(npl + rest);
            }
        }
    }
    return cfs_sync(c);
}

/* ═══════════════════════════════════════════════════════════════════
   cfs_utimens — set access and modification times.
   (atime stored only in v3+ format; here only mtime persisted)
   ═══════════════════════════════════════════════════════════════════ */
int cfs_utimens(CFS *c, const char *path, uint64_t atime, uint64_t mtime) {
    (void)atime;
    if (!c || !(c->flags & CFS_RDWR) || !path) return -1;
    InodeEntry *e = lu(c, path);
    if (!e) { errno = ENOENT; return -1; }
    e->raw.mtime = mtime;
    return cfs_sync(c);
}

/* ── chmod ──────────────────────────────────────────────────── */
int cfs_chmod(CFS *c, const char *path, uint16_t perm) {
    (void)perm;
    if (!c || !(c->flags & CFS_RDWR) || !path) return -1;
    if (!lu(c, path)) { errno = ENOENT; return -1; }
    /* v2 format: no per-inode perm field — accept and persist implicitly */
    return 0;
}

/* ── chown ──────────────────────────────────────────────────── */
int cfs_chown(CFS *c, const char *path, uint32_t uid, uint32_t gid) {
    (void)uid; (void)gid;
    if (!c || !(c->flags & CFS_RDWR) || !path) return -1;
    if (!lu(c, path)) { errno = ENOENT; return -1; }
    /* v2 format: no per-inode uid/gid — accept and persist implicitly */
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
   cfs_compact — reclaim orphaned blocks by rewriting active data
   sequentially into a temporary file, then atomically rename.
   ═══════════════════════════════════════════════════════════════════ */
int cfs_compact(CFS *c) {
    if (!c || !(c->flags & CFS_RDWR)) return -1;

    /* The rebuilt copy and the container are both on disk while this runs,
     * so compact needs transient double space.  Refuse up front rather than
     * filling the host — a container sitting at its quota has no room for
     * its own replacement. */
    if (c->phys_limit && cfs_physical_used(c) > c->phys_limit / 2) {
        errno = ENOSPC;
        return CFS_ENOSPC;
    }

    /* The scratch file has to sit NEXT TO the container: rename() is only
     * atomic within one filesystem, and /tmp is a different one on most
     * systems — where this used to either fail with EXDEV at the very end,
     * after copying everything, or try to hold the whole container in a
     * RAM-backed tmpfs. */
    char tmp[4096];
    if (strlen(c->cpath) + 12 >= sizeof(tmp)) return -1;
    snprintf(tmp, sizeof(tmp), "%s.cmpXXXXXX", c->cpath);
    int tfd = mkstemp(tmp);
    if (tfd < 0) return -1;

    /* Walk inodes, copy active blocks to temp file */
    uint64_t cur_off = CFS_SB_SIZE;
    /* Inodes will be rebuilt with new offsets */
    for (uint32_t i = 0; i < c->inode_count; i++) {
        InodeEntry *e = &c->inodes[i];
        if (!e->path) continue;
        if (e->raw.block_count == 0 || e->raw.mode == CFS_MODE_DIR) continue;

        for (uint32_t b = 0; b < e->raw.block_count; b++) {
            if (e->raw.blocks[b].comp_size == 0) continue;
            uint8_t *blk = malloc(e->raw.blocks[b].comp_size);
            if (!blk) { close(tfd); unlink(tmp); return -1; }
            if (pread(c->fd, blk, e->raw.blocks[b].comp_size,
                      (off_t)e->raw.blocks[b].offset) !=
                (ssize_t)e->raw.blocks[b].comp_size) {
                free(blk); close(tfd); unlink(tmp); return -1;
            }
            if (pwrite(tfd, blk, e->raw.blocks[b].comp_size, (off_t)cur_off) !=
                (ssize_t)e->raw.blocks[b].comp_size) {
                free(blk); close(tfd); unlink(tmp); return -1;
            }
            free(blk);
            e->raw.blocks[b].offset = cur_off;
            cur_off += e->raw.blocks[b].comp_size;
        }
    }

    /* Write inode table */
    size_t ts = 0;
    for (uint32_t i = 0; i < c->inode_count; i++)
        ts += CFS_INODE_FIXED_SIZE + (size_t)c->inodes[i].raw.block_count * 16
            + c->inodes[i].raw.path_len;
    uint8_t *tab = calloc(1, ts);
    if (!tab) { close(tfd); unlink(tmp); return -1; }
    uint8_t *op = tab;
    for (uint32_t i = 0; i < c->inode_count; i++) {
        InodeEntry *e = &c->inodes[i];
        wr64(op, e->raw.orig_size); op += 8;
        wr64(op, e->raw.mtime);     op += 8;
        wr16(op, e->raw.mode);      op += 2;
        wr16(op, e->raw.path_len);  op += 2;
        wr32(op, e->raw.block_count); op += 4;
        for (uint32_t b = 0; b < e->raw.block_count; b++) {
            wr64(op, e->raw.blocks[b].offset);     op += 8;
            wr32(op, e->raw.blocks[b].comp_size);  op += 4;
            wr32(op, e->raw.blocks[b].orig_size);  op += 4;
        }
        memcpy(op, e->path, e->raw.path_len);
        op += e->raw.path_len;
    }
    off_t inode_off = (off_t)cur_off;
    if (pwrite(tfd, tab, ts, inode_off) != (ssize_t)ts) {
        free(tab); close(tfd); unlink(tmp); return -1;
    }
    free(tab);

    /* Build and write superblock */
    uint8_t sb[CFS_SB_SIZE];
    memset(sb, 0, CFS_SB_SIZE);
    memcpy(sb, CFS_MAGIC, 8);
    wr16(sb + 8,  CFS_VERSION);
    wr64(sb + 10, (uint64_t)inode_off);
    wr32(sb + 18, (uint32_t)ts);
    wr32(sb + 22, c->inode_count);
    wr64(sb + 26, (uint64_t)time(NULL));
    wr16(sb + 34, c->sb.flags);          /* keep RAW containers self-describing */
    if (pwrite(tfd, sb, CFS_SB_SIZE, 0) != CFS_SB_SIZE) {
        close(tfd); unlink(tmp); return -1;
    }
    fsync(tfd);

    /* Atomic replace: rename temp over original */
    /* Get original path from /proc/self/fd since we only have fd */
    char proc_path[64], orig_path[1024];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", c->fd);
    ssize_t rl = readlink(proc_path, orig_path, sizeof(orig_path) - 1);
    if (rl < 0) { close(tfd); unlink(tmp); return -1; }
    orig_path[rl] = 0;

    /* Close old fd before rename */
    close(c->fd);
    close(tfd);

    if (rename(tmp, orig_path) != 0) {
        /* Try to reopen old file */
        c->fd = open(orig_path, O_RDWR);
        return -1;
    }

    /* Reopen the compacted file */
    c->fd = open(orig_path, O_RDWR);
    if (c->fd < 0) return -1;

    /* Update superblock in memory */
    memcpy(c->sb.magic, CFS_MAGIC, 8);
    c->sb.version      = CFS_VERSION;
    c->sb.inode_offset = (uint64_t)inode_off;
    c->sb.inode_size   = (uint32_t)ts;
    c->sb.file_count   = c->inode_count;
    c->sb.created_at   = (uint64_t)time(NULL);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
   cfs_unpack — extract a file from the container to the local
   filesystem.  Creates intermediate directories as needed.
   ═══════════════════════════════════════════════════════════════════ */
int cfs_unpack(CFS *c, const char *cfs_path, const char *local_path) {
    if (!c || !cfs_path || !local_path) return -1;

    /* Read the file data */
    size_t size;
    void *data = cfs_read_all(c, cfs_path, &size);
    if (!data) return -1;

    /* Create intermediate directories */
    char dir[4096];
    strncpy(dir, local_path, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = 0;
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = 0;
        /* Walk path, creating directories */
        char *p = dir;
        if (*p == '/') p++; /* skip leading / */
        while (*p) {
            char *next = strchr(p, '/');
            if (next) *next = 0;
            mkdir(dir, 0755);
            if (next) *next = '/', p = next + 1;
            else p += strlen(p);
        }
    }

    /* Write the file */
    FILE *f = fopen(local_path, "wb");
    if (!f) { free(data); return -1; }
    size_t nw = fwrite(data, 1, size, f);
    fclose(f);
    free(data);
    if (nw != size) { unlink(local_path); return -1; }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
   Block Device Layer — exposes the container as a linear byte range
   backed by CPEnc-compressed 64MB chunks.  Uses an internal "@block"
   file entry;  no separate format layer required.
   ═══════════════════════════════════════════════════════════════════ */

#define BLOCK_PATH "@block"

static void block_sizefile(CFS *c, uint64_t sz) {
    /* Directly set a file's inode to the given size with zero blocks.
     * The next write will create real data blocks on demand. */
    InodeEntry *e = lu(c, BLOCK_PATH);
    if(!e) return;
    e->raw.orig_size = sz;
    inode_clear_blocks(e);
    e->raw.mtime = (uint64_t)time(NULL);
    cfs_sync(c);
}

static int block_ensure(CFS *c, uint64_t minsz) {
    InodeEntry *e = lu(c, BLOCK_PATH);
    if(e) {
        if(minsz > e->raw.orig_size) block_sizefile(c, minsz);
        return 0;
    }
    return cfs_write(c, BLOCK_PATH, NULL, 0);
}

ssize_t cfs_block_read(CFS *c, void *buf, size_t size, off_t offset) {
    if(!c||!buf||size==0) return -1;
    /* Create the entry if it is missing, but never grow the device: a read
     * must not mutate the container.  The zero-fill below already covers
     * every unwritten byte, so the grow this used to do was pure side
     * effect — and it meant a guest probing past the end of its disk (which
     * is ordinary behaviour) silently resized it. */
    if(block_ensure(c, 0)!=0) return -1;
    if(offset<0) return -1;
    InodeEntry *e = lu(c, BLOCK_PATH);
    if(!e) return -1;
    /* Return zeros for sparse regions beyond written data */
    size_t total = 0; ssize_t nr;
    while(total < size) {
        nr = cfs_read(c, BLOCK_PATH, (uint8_t*)buf+total,
                       size-total, (off_t)((uint64_t)offset+total));
        if(nr < 0) return total > 0 ? (ssize_t)total : -1;
        if(nr == 0) break;
        total += (size_t)nr;
    }
    /* Zero-fill trailing sparse */
    if(total < size) memset((uint8_t*)buf+total, 0, size-total), total=size;
    return (ssize_t)total;
}

#define BLOCK_CHUNK (8u << 20)   /* 8MB compression unit: bounds RMW cost */
#define PEND_MAX 128              /* pending-patch slots per write (<=2 touched) */

/* ── Block-write path: block-granular patching ───────────────────
 * Random writes touch only the blocks they overlap (decompress →
 * patch → recompress → rewrite in place, or append if the recompressed
 * payload grew).  The format's read path locates blocks by prefix sum
 * of orig_size, so block layout is kept gap-free: writes beyond the
 * current data end zero-pad the gap (zeros compress to almost nothing),
 * and a write exactly at the data end extends the last block in place.
 * Falls back to whole-file RMW only when CFS_BLOCK_SANITY (65536 blocks)
 * would be exceeded. */

/* Logical (file-coordinate) start of block b, assuming ordered blocks. */
static uint64_t block_blk_start(const InodeEntry *e, uint32_t b) {
    uint64_t acc = 0;
    for (uint32_t i = 0; i < b && i < e->raw.block_count; i++)
        acc += e->raw.blocks[i].orig_size;
    return acc;
}

/* Patch block b: overlap [po,pe) from src[po-w0, pe-w0), and optionally
 * extend it by ext bytes appended past its current end (last block only —
 * growing a middle block would shift every later block's implied offset).
 * Shrinking recompression rewrites in place; growth is staged for the
 * unified append pass.  Block layout stays contiguous: the read path
 * locates blocks by prefix sum of orig_size, so holes cannot exist. */
static int block_patch(CFS *c, InodeEntry *e, uint32_t b, const uint8_t *src,
                       uint64_t w0, uint64_t po, uint64_t pe, size_t ext,
                       uint8_t *pend_data[], uint32_t pend_idx[], size_t pend_cl[], size_t pend_orig[], int *np) {
    CfsBlock *blk = &e->raw.blocks[b];
    /* The device layer never makes a block larger than BLOCK_CHUNK, and
     * orig_size comes from the inode table: a corrupt table can declare a
     * 256MB block, and patching it allocates, decompresses and recompresses
     * that much — fuzzing found an 8.5-second write from a 746-byte
     * container.  Reject anything the chunking discipline could not have
     * produced. */
    if (blk->orig_size > CFS_BLOCK_MAX) return -1;
    uint32_t olen = blk->orig_size;
    /* ext is the tail of the caller's write.  nolen is 32-bit, so an ext
     * past the ceiling wraps it and the copy below then writes past dec:
     * the write is bounded in size, not in the arithmetic. */
    if (ext > CFS_BLOCK_MAX || (uint64_t)olen + ext > CFS_BLOCK_MAX) return -1;
    uint32_t nolen = olen + (uint32_t)ext;
    uint64_t bo = block_blk_start(e, b);
    size_t clen = (size_t)(pe - po);

    uint8_t *dec = malloc(nolen);
    if (!dec) return -1;
    if (c->flags & CFS_RAW) {
        if (pread(c->fd, dec, blk->comp_size, (off_t)blk->offset) != (ssize_t)blk->comp_size ||
            blk->comp_size != CPENC_HEADER_SIZE + olen)
            { free(dec); return -1; }
        memmove(dec, dec + CPENC_HEADER_SIZE, olen);   /* strip header */
    } else {
        uint8_t *comp = malloc(blk->comp_size);
        if (!comp) { free(dec); return -1; }
        if (pread(c->fd, comp, blk->comp_size, (off_t)blk->offset) != (ssize_t)blk->comp_size)
            { free(comp); free(dec); return -1; }
        size_t dl = olen;
        if (cpenc_decompress(comp, blk->comp_size, dec, &dl) != 0 || dl != (size_t)olen)
            { free(comp); free(dec); return -1; }
        free(comp);
    }

    memcpy(dec + (size_t)(po - bo), src + (size_t)(po - w0), clen);
    if (ext)
        memcpy(dec + olen, src + (size_t)((bo + (uint64_t)olen) - w0), ext);

    /* orig_size is deliberately NOT set here.  The payload may end up in a
     * pend slot written later, and the commit can still be refused (a full
     * container) — mutating the block now would leave the handle describing
     * a block whose bytes were never written, and the read path locates
     * blocks by prefix sums of orig_size.  Each branch below applies it once
     * its write has actually landed. */
    if (c->flags & CFS_RAW) {
        /* RAW payload = header + nolen; only in-place when size unchanged */
        if (ext) {
            uint8_t *nc = malloc(CPENC_HEADER_SIZE + 1 + nolen);
            if (!nc) { free(dec); return -1; }
            CPEncHeader *h = (CPEncHeader*)nc;
            memset(h, 0, CPENC_HEADER_SIZE);
            h->magic = CPENC_MAGIC; h->version = CPENC_VERSION;
            h->stride = CPENC_STRIDE_RAW;
            h->original_size = nolen; h->compressed_size = (uint32_t)(1 + nolen);
            nc[CPENC_HEADER_SIZE] = CPENC_LAG_NONE;
            memcpy(nc + CPENC_HEADER_SIZE + 1, dec, nolen);
            free(dec);
            pend_data[*np] = nc; pend_idx[*np] = b; pend_orig[*np] = nolen;
            pend_cl[*np] = CPENC_HEADER_SIZE + 1 + nolen; (*np)++;
            return 0;
        }
        /* rewrite the payload in place (same size) */
        uint8_t *nc = malloc(CPENC_HEADER_SIZE + 1 + olen);
        if (!nc) { free(dec); return -1; }
        CPEncHeader *h = (CPEncHeader*)nc;
        memset(h, 0, CPENC_HEADER_SIZE);
        h->magic = CPENC_MAGIC; h->version = CPENC_VERSION;
        h->stride = CPENC_STRIDE_RAW;
        h->original_size = nolen; h->compressed_size = (uint32_t)(1 + nolen);
        nc[CPENC_HEADER_SIZE] = CPENC_LAG_NONE;
        memcpy(nc + CPENC_HEADER_SIZE + 1, dec, olen);
        free(dec);
        if (cfs_pw(c, nc, CPENC_HEADER_SIZE + 1 + olen, (off_t)blk->offset) != (ssize_t)(CPENC_HEADER_SIZE + 1 + olen))
            { free(nc); return -1; }
        blk->orig_size = nolen;
        free(nc);
        return 0;
    }

    size_t mc = cpenc_max_compressed_size(nolen);
    uint8_t *nc = malloc(mc);
    if (!nc) { free(dec); return -1; }
    size_t ncl = mc;
    if (cpenc_compress(dec, nolen, nc, &ncl, 2) != 0) { free(nc); free(dec); return -1; }
    free(dec);

    if (ncl <= blk->comp_size) {
        if (cfs_pw(c, nc, ncl, (off_t)blk->offset) != (ssize_t)ncl) { free(nc); return -1; }
        blk->comp_size = (uint32_t)ncl;
        blk->orig_size = nolen;
        free(nc);
    } else {
        pend_data[*np] = nc; pend_idx[*np] = b; pend_orig[*np] = nolen;
        pend_cl[*np] = ncl; (*np)++;
    }
    return 0;
}

/* Compress a hole segment into a standalone block payload. */
static int block_hole_pack(CFS *c, const uint8_t *seg, size_t len,
                           uint8_t **out, size_t *outcl) {
    if (c->flags & CFS_RAW) {
        *outcl = CPENC_HEADER_SIZE + 1 + len;
        uint8_t *d = malloc(*outcl);
        if (!d) return -1;
        CPEncHeader *h = (CPEncHeader*)d;
        memset(h, 0, CPENC_HEADER_SIZE);
        h->magic = CPENC_MAGIC; h->version = CPENC_VERSION;
        h->stride = CPENC_STRIDE_RAW;
        h->original_size = (uint32_t)len; h->compressed_size = (uint32_t)(1 + len);
        d[CPENC_HEADER_SIZE] = CPENC_LAG_NONE;
        memcpy(d + CPENC_HEADER_SIZE + 1, seg, len);
        *out = d; return 0;
    }
    size_t mc = cpenc_max_compressed_size(len);
    uint8_t *d = malloc(mc);
    if (!d) return -1;
    size_t cl = mc;
    if (cpenc_compress(seg, len, d, &cl, 2) != 0) { free(d); return -1; }
    *out = d; *outcl = cl;
    return 0;
}

/* Whole-file read-modify-write fallback (block cap exceeded). */
static int block_write_fallback(CFS *c, const uint8_t *buf, size_t size,
                                uint64_t offset, uint64_t minsz, uint64_t prev_sz) {
    uint64_t new_sz = minsz > prev_sz ? minsz : prev_sz;
    /* This path materialises the whole device, and the device's declared
     * size comes from the inode table — as untrusted as anything else.  A
     * crafted container with a full block table and a multi-gigabyte
     * declared size turns every write into a multi-gigabyte allocation
     * (fuzzing found it at 2.1GB RSS).  Real devices cannot reach this path
     * at all: it only runs when the block table would exceed
     * CFS_BLOCK_SANITY, which is 512GB of 8MB blocks. */
    if (new_sz > (uint64_t)CFS_BLOCK_MAX * 4) {
        errno = ENOSPC;
        return -1;
    }
    size_t rbsz = 0;
    void *old = cfs_read_all(c, BLOCK_PATH, &rbsz);
    uint8_t *full = calloc(1, new_sz);
    if (!full) { free(old); return -1; }
    if (old && rbsz > 0) memcpy(full, old, rbsz < new_sz ? rbsz : new_sz);
    free(old);
    memcpy(full + offset, buf, size);
    int rc = cfs_write(c, BLOCK_PATH, full, new_sz);
    free(full);
    return rc;
}


/* Short-write form: cut the request at 8MB boundaries and stop at the first
 * piece that is refused, reporting how far it got.  The pieces never
 * straddle a boundary, so the split inside the implementation never fires
 * from here — and calling it directly (rather than the public wrapper) is
 * what keeps the two from recursing through each other. */
static int cfs_block_write_impl(CFS *c, const void *buf, size_t size, off_t offset);

ssize_t cfs_block_write_some(CFS *c, const void *buf, size_t size, off_t offset) {
    if (!c || !buf || size == 0 || offset < 0) return -1;
    size_t done = 0;
    while (done < size) {
        uint64_t off = (uint64_t)offset + done;
        uint64_t ce = (off / BLOCK_CHUNK + 1) * BLOCK_CHUNK;
        size_t part = (size_t)(ce - off);
        if (part > size - done) part = size - done;
        if (cfs_block_write_impl(c, (const uint8_t *)buf + done, part, (off_t)off) != 0)
            return done ? (ssize_t)done : -1;
        done += part;
    }
    return (ssize_t)done;
}

int cfs_block_write(CFS *c, const void *buf, size_t size, off_t offset) {
    return cfs_block_write_some(c, buf, size, offset) == (ssize_t)size ? 0 : -1;
}

static int cfs_block_write_impl(CFS *c, const void *buf, size_t size, off_t offset) {
    if(!c||!buf||size==0) return -1;
    if(offset<0) return -1;
    if(!(c->flags & CFS_RDWR)) return -1;
    /* The declared size is the device capacity, not a high-water mark: a
     * write past it fails here, the way it would on a real disk.  Growing
     * the device is explicit (cfs_block_resize), so a guest cannot push the
     * container — and the host file behind it — past what it was created
     * with.  Checked before the dedup branch and the chunk split so neither
     * can route around it.  This also keeps block_ensure()'s grow path
     * unreachable from here, and that path clears the block table. */
    {
        uint64_t w1 = (uint64_t)offset + (uint64_t)size;
        if (w1 < (uint64_t)offset) { errno = ENOSPC; return CFS_ENOSPC; }   /* offset+size wrapped */
        if (w1 > cfs_block_size(c)) { errno = ENOSPC; return CFS_ENOSPC; }
    }
    /* A merged device takes the reference path: appends to @store instead of
     * decompressing and recompressing the 8MB chunk the write lands in. */
    {
        InodeEntry *be = lu(c, BLOCK_PATH);
        if (be && be->raw.mode == CFS_MODE_DEDUP)
            return cfs_dedup_write(c, BLOCK_PATH, buf, size, offset) < 0 ? -1 : 0;
    }
    /* Chunk-boundary split: a growing block would make sequential fills
     * O(n^2) (every 1MB append recompresses the whole block).  Cut every
     * write at an 8MB boundary so each block stays <= 8MB and every
     * random-write RMW is bounded at 8MB. */
    {
        uint64_t w1 = (uint64_t)offset + size;
        uint64_t chunk_end = ((uint64_t)offset / BLOCK_CHUNK + 1) * BLOCK_CHUNK;
        if (w1 > chunk_end) {
            size_t part = (size_t)(chunk_end - (uint64_t)offset);
            int rc1 = cfs_block_write(c, buf, part, offset);
            if (rc1 != 0) return rc1;
            return cfs_block_write(c, (const uint8_t*)buf + part, size - part,
                                   (off_t)chunk_end);
        }
    }

    /* A write into the partition-table region invalidates the parsed cache */
    if (c->part_kind != -1 && (uint64_t)offset < CFS_PART_TABLE_BYTES) {
        c->part_kind = -1;
        c->part_n = 0;
    }

    uint64_t minsz = (uint64_t)offset + (uint64_t)size;
    if(block_ensure(c, minsz)!=0) return -1;
    InodeEntry *e = lu(c, BLOCK_PATH);
    if(!e) return -1;
    uint64_t prev_sz = e->raw.orig_size;

    /* Fast path A: sparse empty disk, write from offset 0 — full write,
     * keep declared size (cfs_write sets orig_size = size, which would
     * shrink the disk).  Non-zero offsets on an empty disk go through the
     * regular zero-padded append path so data lands at the right place. */
    if (e->raw.block_count == 0 && offset == 0) {
        int rc = cfs_write(c, BLOCK_PATH, buf, size);
        if (rc) return rc;
        e = lu(c, BLOCK_PATH);
        if (!e) return -1;
        uint64_t want = prev_sz > minsz ? prev_sz : minsz;
        if (e->raw.orig_size != want) {
            e->raw.orig_size = want;
            return cfs_sync(c);
        }
        return 0;
    }

    const uint8_t *src = (const uint8_t *)buf;
    uint64_t w0 = (uint64_t)offset, w1 = minsz;

    uint8_t   *pend_data[PEND_MAX];
    uint32_t   pend_idx[PEND_MAX];   /* block idx, or PEND_MAX = new block */
    size_t     pend_cl[PEND_MAX];
    size_t     pend_orig[PEND_MAX];  /* orig size of new blocks */
    int        np = 0;
    int        nnew = 0;

    uint32_t nb = e->raw.block_count;
    uint64_t cur_end = 0;
    for (uint32_t b = 0; b < nb; b++) cur_end += e->raw.blocks[b].orig_size;

    if (w0 >= cur_end) {
        /* Append-only: pad the gap with zeros.  A gap-free layout is
         * required (read path locates blocks by prefix sums).  A zero pad
         * compresses to almost nothing, so this stays cheap.  Split at the
         * next 8MB boundary so no block exceeds BLOCK_CHUNK. */
        uint64_t blk_limit = ((uint64_t)w0 / BLOCK_CHUNK + 1) * BLOCK_CHUNK;
        if (w1 > blk_limit) {
            size_t part = (size_t)(blk_limit - w0);
            int rc1 = cfs_block_write(c, src, part, (off_t)w0);
            if (rc1 != 0) return rc1;
            return cfs_block_write(c, (const uint8_t*)src + part,
                                   size - part, (off_t)blk_limit);
        }
        uint64_t pad = w0 - cur_end;
        /* Fill a far gap in chunk-sized zero blocks rather than one
         * allocation of the whole thing.  The gap is materialised because
         * block layout has to stay gap-free, and w0 comes from the device
         * size the container declares: one allocation of it turned a
         * 746-byte container into a 2GB allocation and eight seconds of
         * work (fuzzing found both).  The total is still capped — that is a
         * time bound, not a memory one. */
        if (pad > BLOCK_CHUNK) {
            if (pad > (1ULL << 30)) { errno = ENOSPC; return -1; }
            uint8_t *z = calloc(1, BLOCK_CHUNK);
            if (!z) return -1;
            uint64_t left = pad, at = cur_end;
            while (left) {
                size_t zn = left > BLOCK_CHUNK ? BLOCK_CHUNK : (size_t)left;
                if (cfs_block_write(c, z, zn, (off_t)at) != 0) { free(z); return -1; }
                at += zn; left -= zn;
            }
            free(z);
            return cfs_block_write(c, src, size, (off_t)w0);
        }
        if (pad == 0) {
            if (nb > 0 && e->raw.blocks[nb-1].orig_size >= BLOCK_CHUNK) {
                /* last block full — start a fresh one */
                uint8_t *b2 = malloc(size);
                if (!b2) return -1;
                memcpy(b2, src, size);
                int rc = block_hole_pack(c, b2, size, &pend_data[np], &pend_cl[np]);
                free(b2);
                if (rc != 0) goto fail_pend;
                pend_idx[np] = PEND_MAX;
                pend_orig[np] = size;
                np++; nnew++;
            } else if (block_patch(c, e, nb - 1, src, w0, cur_end, cur_end, size,
                            pend_data, pend_idx, pend_cl, pend_orig, &np) != 0)
                goto fail_pend;
        } else {
            size_t plen = (size_t)pad;
            uint8_t *b2 = malloc(plen + size);
            if (!b2) return -1;
            memset(b2, 0, plen);
            memcpy(b2 + plen, src, size);
            int rc = block_hole_pack(c, b2, plen + size, &pend_data[np], &pend_cl[np]);
            free(b2);
            if (rc != 0) goto fail_pend;
            pend_idx[np] = PEND_MAX;
            pend_orig[np] = plen + size;
            np++; nnew++;
        }
    } else {
        /* Patch overlapping blocks; the last block may extend past its
         * current end to absorb a tail write.  A block never grows past
         * BLOCK_CHUNK: split the write at the block's 8MB boundary so the
         * remainder lands in a fresh block (keeps every RMW bounded). */
        uint64_t acc = 0;
        for (uint32_t b = 0; b < nb; b++) {
            uint64_t bo = acc, be = acc + e->raw.blocks[b].orig_size;
            uint64_t blk_limit = bo + BLOCK_CHUNK;
            if (w1 > blk_limit && w0 < blk_limit) {
                size_t part = (size_t)(blk_limit - w0);
                int rc1 = cfs_block_write(c, src, part, (off_t)w0);
                if (rc1 != 0) return rc1;
                return cfs_block_write(c, (const uint8_t*)src + part,
                                       size - part, (off_t)blk_limit);
            }
            acc = be;
            if (be <= w0) continue;
            if (bo >= w1) break;
            uint64_t po = w0 > bo ? w0 : bo;
            uint64_t pe = w1 < be ? w1 : be;
            size_t ext = 0;
            if (b == nb - 1 && w1 > be) ext = (size_t)(w1 - be);
            if (po < pe || ext) {
                if (block_patch(c, e, b, src, w0, po, pe, ext,
                                pend_data, pend_idx, pend_cl, pend_orig, &np) != 0)
                    goto fail_pend;
            }
            if (ext) break;   /* last block absorbed the tail */
        }
    }

    /* Block-cap exceeded → whole-file RMW fallback */
    if (nb + (uint32_t)nnew > CFS_BLOCK_SANITY) {
        for (int i = 0; i < np; i++) free(pend_data[i]);
        return block_write_fallback(c, src, size, w0, minsz, prev_sz);
    }
    /* Physical quota for the whole batch, before the table grows (see the
     * note in cfs_write: a refusal must not leave a half-built table). */
    {
        uint64_t tot = 0;
        for (int i = 0; i < np; i++) tot += pend_cl[i];
        if (cfs_phys_room(c, (off_t)c->sb.inode_offset, (size_t)tot)) {
            for (int i = 0; i < np; i++) free(pend_data[i]);
            return CFS_ENOSPC;
        }
    }
    if (nnew && inode_grow_blocks(e, nb + (uint32_t)nnew) != 0) {
        for (int i = 0; i < np; i++) free(pend_data[i]);
        return -1;
    }

    /* Unified append pass: grown patches + new blocks, written at the
     * old inode-table position, cursor advancing. */
    {
        uint64_t app = c->sb.inode_offset;
        int hi = 0;
        for (int i = 0; i < np; i++) {
            if (cfs_pw(c, pend_data[i], pend_cl[i], (off_t)app) != (ssize_t)pend_cl[i]) {
                for (int j = i; j < np; j++) free(pend_data[j]);
                return -1;
            }
            free(pend_data[i]);
            if (pend_idx[i] == PEND_MAX) {
                CfsBlock *blk = &e->raw.blocks[nb + hi];
                memset(blk, 0, sizeof(*blk));
                blk->offset = app; blk->comp_size = (uint32_t)pend_cl[i];
                blk->orig_size = (uint32_t)pend_orig[i];   /* written at pend slot i, not hi */
                app += pend_cl[i];
                hi++;
            } else {
                CfsBlock *blk = &e->raw.blocks[pend_idx[i]];
                blk->offset = app; blk->comp_size = (uint32_t)pend_cl[i];
                blk->orig_size = (uint32_t)pend_orig[i];
                app += pend_cl[i];
            }
        }
        nb += (uint32_t)hi;
        e->raw.block_count = nb;
    }

    uint64_t want = prev_sz > minsz ? prev_sz : minsz;
    if (e->raw.orig_size != want) e->raw.orig_size = want;
    {
        int rc2 = cfs_sync(c);
        return rc2;
    }

fail_pend:
    for (int i = 0; i < np; i++) free(pend_data[i]);
    return -1;
}

/* ── Disk identity: carried in the superblock so the image itself declares
 * what kind of drive it is (see cfs.h). ── */
int cfs_disk_set(CFS *c, int kind) {
    if (!c || !(c->flags & CFS_RDWR)) return -1;
    if (kind < CFS_DISK_SSD || kind > CFS_DISK_SD) return -1;
    c->sb.flags &= (uint16_t)~(CFS_SB_FLAG_REMOVABLE | CFS_SB_FLAG_ROTATIONAL |
                               CFS_SB_FLAG_SD);
    if (kind == CFS_DISK_HDD) c->sb.flags |= CFS_SB_FLAG_ROTATIONAL;
    if (kind == CFS_DISK_USB) c->sb.flags |= CFS_SB_FLAG_REMOVABLE;
    if (kind == CFS_DISK_SD)  c->sb.flags |= CFS_SB_FLAG_REMOVABLE | CFS_SB_FLAG_SD;
    return cfs_sync(c);
}

int cfs_disk_get(CFS *c, CfsDiskAttrs *out) {
    if (!c || !out) return -1;
    out->removable  = (c->sb.flags & CFS_SB_FLAG_REMOVABLE) != 0;
    out->rotational = (c->sb.flags & CFS_SB_FLAG_ROTATIONAL) != 0;
    if (out->removable)
        out->kind = (c->sb.flags & CFS_SB_FLAG_SD) ? CFS_DISK_SD : CFS_DISK_USB;
    else
        out->kind = out->rotational ? CFS_DISK_HDD : CFS_DISK_SSD;
    static const char *models[] = { "CFS SSD", "CFS HDD", "CFS USB Disk", "CFS SD Card" };
    snprintf(out->model, sizeof(out->model), "%s", models[out->kind]);
    return 0;
}

uint64_t cfs_block_size(CFS *c) {
    if(!c) return 0;
    if(block_ensure(c, 0)!=0) return 0;
    InodeEntry *e = lu(c, BLOCK_PATH);
    return e ? e->raw.orig_size : 0;
}

int cfs_block_resize(CFS *c, uint64_t size) {
    if(!c || !(c->flags & CFS_RDWR)) return -1;
    if(block_ensure(c, 0)!=0) return -1;
    InodeEntry *e = lu(c, BLOCK_PATH);
    if(!e) return -1;
    /* Just extend the declared size — don't clear data blocks */
    if(size > e->raw.orig_size) e->raw.orig_size = size;
    return cfs_sync(c);
}

/* ── Physical quota ────────────────────────────────────────────── */
int cfs_set_physical_limit(CFS *c, uint64_t bytes) {
    if (!c) return -1;
    c->phys_limit = bytes;
    return 0;
}

uint64_t cfs_physical_limit(CFS *c) { return c ? c->phys_limit : 0; }

uint64_t cfs_physical_used(CFS *c) {
    if (!c) return 0;
    off_t e = lseek(c->fd, 0, SEEK_END);   /* every write is a pwrite */
    return e > 0 ? (uint64_t)e : 0;
}

/* ═══════════════════════════════════════════════════════════════════
   Merge layer — content-addressed dedup.

   @store holds the append-only stream of unique bytes.  It is an ordinary
   file entry, so the existing block table and orig_size prefix-sum lookup
   locate any range of it unchanged.  A merged file's blocks[] hold a
   serialised reference table instead of content; reads resolve each
   (logical, length, store) tuple through @store.  Table layout is
   documented in cfs_format.h.
   ═══════════════════════════════════════════════════════════════════ */

#define DEDUP_IO_CHUNK (8u << 20)   /* merge-pass append unit */
#define DEDUP_WIN      (8u << 20)   /* merge-pass read window */

static void dedup_cache_drop(CFS *c) {
    cfs_dedup_table_free(&c->dt);
    free(c->dt_path);
    c->dt_path = NULL;
}

static void free_pieces(uint8_t **data, size_t *cl, size_t *ol,
                        uint32_t n, uint32_t from) {
    for (uint32_t i = from; i < n; i++) free(data[i]);
    free(data); free(cl); free(ol);
}

/* Decompress one block payload into dec, which must hold orig_size bytes. */
static int block_payload_read(CFS *c, const CfsBlock *b, uint8_t *dec) {
    uint8_t *comp = malloc(b->comp_size ? b->comp_size : 1);
    if (!comp) return -1;
    if (pread(c->fd, comp, b->comp_size, (off_t)b->offset) != (ssize_t)b->comp_size) {
        free(comp); return -1;
    }
    size_t dl = b->orig_size;
    int rc = (cpenc_decompress(comp, b->comp_size, dec, &dl) != 0 || dl != b->orig_size) ? -1 : 0;
    free(comp);
    return rc;
}

/* Load the decoded reference table of a merged file into the handle cache. */
static int dt_load(CFS *c, InodeEntry *e) {
    if (c->dt_path && !strcmp(c->dt_path, e->path)) return 0;
    /* One table is cached at a time: switching files must not throw away the
     * edits the outgoing file has not been flushed with yet. */
    if (c->dt_dirty && dedup_table_flush(c) != 0) return -1;
    dedup_cache_drop(c);
    size_t tl = 0;
    for (uint32_t b = 0; b < e->raw.block_count; b++) tl += e->raw.blocks[b].orig_size;
    uint8_t *buf = malloc(tl ? tl : 1);
    if (!buf) return -1;
    size_t off = 0;
    for (uint32_t b = 0; b < e->raw.block_count; b++) {
        if (block_payload_read(c, &e->raw.blocks[b], buf + off) != 0) { free(buf); return -1; }
        off += e->raw.blocks[b].orig_size;
    }
    int rc = cfs_dedup_parse(buf, tl, &c->dt);
    free(buf);
    if (rc != 0) return -1;
    c->dt_path = strdup(e->path);
    return c->dt_path ? 0 : -1;
}

/* First tuple starting at or after off (logical_size when there is none). */
static uint64_t dt_next_start(const CfsDedupTable *t, uint64_t off) {
    uint32_t lo = 0, hi = t->n;
    uint64_t best = t->logical_size;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (t->v[mid].logical > off) { best = t->v[mid].logical; hi = mid; }
        else lo = mid + 1;
    }
    return best;
}

/* Store bytes written this session may still sit in the pending buffer, and
 * anything reading @store would read a hole there.  Flush only when the range
 * being read actually reaches into the unwritten tail. */
static int dedup_pend_gate(CFS *c, uint64_t store_off) {
    if (c->pend_n && store_off >= c->pend_off) return dedup_pend_flush(c);
    return 0;
}

static ssize_t dedup_read(CFS *c, InodeEntry *e, void *buf, size_t size, off_t offset) {
    if (size == 0) return 0;
    if (offset < 0 || (uint64_t)offset >= e->raw.orig_size) return 0;
    if (dt_load(c, e) != 0) return -1;
    size_t rem = size;
    if ((uint64_t)offset + rem > e->raw.orig_size)
        rem = (size_t)(e->raw.orig_size - (uint64_t)offset);
    size_t total = 0;
    uint64_t cur = (uint64_t)offset;
    while (rem > 0) {
        const CfsRef *r = cfs_dedup_table_find(&c->dt, cur);
        if (!r) {                       /* hole — same semantics as a plain file */
            uint64_t next = dt_next_start(&c->dt, cur);
            size_t nl = (size_t)(next - cur);
            if (nl > rem) nl = rem;
            memset((uint8_t*)buf + total, 0, nl);
            total += nl; cur += nl; rem -= nl;
            continue;
        }
        uint64_t within = cur - r->logical;
        size_t nl = (size_t)(r->length - within);
        if (nl > rem) nl = rem;
        if (dedup_pend_gate(c, r->store + within) != 0) return -1;
        if (cfs_read(c, CFS_STORE_PATH, (uint8_t*)buf + total, nl,
                     (off_t)(r->store + within)) != (ssize_t)nl)
            return total > 0 ? (ssize_t)total : -1;
        /* A reference walked in full is one stored feature; its bytes are in
         * hand right here, so this is where the feature index comes from —
         * reconstruction feeds it, no separate scanning pass does. */
        if (within == 0 && nl == r->length)
            dedup_fi_add(c, (const uint8_t*)buf + total, nl, r->store);
        total += nl; cur += nl; rem -= nl;
    }
    return (ssize_t)total;
}

static InodeEntry *store_ensure(CFS *c) {
    InodeEntry *e = lu(c, CFS_STORE_PATH);
    if (e) return e;
    if (cfs_write(c, CFS_STORE_PATH, NULL, 0) != 0) return NULL;
    return lu(c, CFS_STORE_PATH);
}

/* Append len bytes to @store; *out_off receives where they landed. */
static int store_append(CFS *c, const uint8_t *buf, size_t len, uint64_t *out_off) {
    InodeEntry *e = store_ensure(c);
    if (!e) return -1;
    *out_off = e->raw.orig_size;
    if (len == 0) return 0;
    uint32_t nb = (uint32_t)((len + DEDUP_IO_CHUNK - 1) / DEDUP_IO_CHUNK);
    uint8_t **data = calloc(nb, sizeof(*data));
    size_t *cl = calloc(nb, sizeof(*cl));
    size_t *ol = calloc(nb, sizeof(*ol));
    if (!data || !cl || !ol) { free_pieces(data, cl, ol, nb, 0); return -1; }
    for (uint32_t i = 0; i < nb; i++) {
        size_t bo = (size_t)i * DEDUP_IO_CHUNK;
        size_t bs = bo + DEDUP_IO_CHUNK <= len ? DEDUP_IO_CHUNK : len - bo;
        if (block_hole_pack(c, buf + bo, bs, &data[i], &cl[i]) != 0) {
            free_pieces(data, cl, ol, nb, i); return -1;
        }
        ol[i] = bs;
    }
    uint32_t old = e->raw.block_count;
    {
        uint64_t tot = 0;
        for (uint32_t i = 0; i < nb; i++) tot += cl[i];
        if (cfs_phys_room(c, (off_t)c->sb.inode_offset, (size_t)tot)) {
            free_pieces(data, cl, ol, nb, 0); return CFS_ENOSPC;
        }
    }
    if (inode_grow_blocks(e, old + nb) != 0) { free_pieces(data, cl, ol, nb, 0); return -1; }
    uint64_t off = c->sb.inode_offset;
    for (uint32_t i = 0; i < nb; i++) {
        if (cfs_pw(c, data[i], cl[i], (off_t)off) != (ssize_t)cl[i]) {
            free_pieces(data, cl, ol, nb, i); return -1;
        }
        e->raw.blocks[old + i].offset    = off;
        e->raw.blocks[old + i].comp_size = (uint32_t)cl[i];
        e->raw.blocks[old + i].orig_size = (uint32_t)ol[i];
        off += cl[i];
        free(data[i]);
    }
    free_pieces(data, cl, ol, nb, nb);
    e->raw.orig_size += len;
    e->raw.mtime = (uint64_t)time(NULL);
    /* Advance the append cursor past these blocks.  cfs_sync() below flushes
     * other writers (a dirty reference table) through the same cursor, and
     * without this they would land on top of what was just written.  The
     * recorded table size is stale until that sync rewrites it. */
    c->sb.inode_offset = off;
    c->sb.inode_size = 0;
    return cfs_sync(c);
}

/* Replace a file's content blocks with a serialised reference table. */
static int dedup_write_table(CFS *c, InodeEntry *e, const CfsDedupTable *t) {
    uint8_t *ser = NULL;
    size_t sl = 0;
    if (cfs_dedup_serialize(t, &ser, &sl) != 0) return -1;
    uint32_t nb = (uint32_t)((sl + CFS_DEDUP_BLOCK - 1) / CFS_DEDUP_BLOCK);
    if (nb == 0) nb = 1;
    uint8_t **data = calloc(nb, sizeof(*data));
    size_t *cl = calloc(nb, sizeof(*cl));
    size_t *ol = calloc(nb, sizeof(*ol));
    if (!data || !cl || !ol) { free(ser); free_pieces(data, cl, ol, nb, 0); return -1; }
    for (uint32_t i = 0; i < nb; i++) {
        size_t bo = (size_t)i * CFS_DEDUP_BLOCK;
        size_t bs = bo + CFS_DEDUP_BLOCK <= sl ? CFS_DEDUP_BLOCK : sl - bo;
        if (block_hole_pack(c, ser + bo, bs, &data[i], &cl[i]) != 0) {
            free(ser); free_pieces(data, cl, ol, nb, i); return -1;
        }
        ol[i] = bs;
    }
    free(ser);
    {
        uint64_t tot = 0;
        for (uint32_t i = 0; i < nb; i++) tot += cl[i];
        if (cfs_phys_room(c, (off_t)c->sb.inode_offset, (size_t)tot)) {
            free_pieces(data, cl, ol, nb, 0); return CFS_ENOSPC;
        }
    }
    inode_clear_blocks(e);
    if (inode_grow_blocks(e, nb) != 0) { free_pieces(data, cl, ol, nb, 0); return -1; }
    uint64_t off = c->sb.inode_offset;
    for (uint32_t i = 0; i < nb; i++) {
        if (cfs_pw(c, data[i], cl[i], (off_t)off) != (ssize_t)cl[i]) {
            free_pieces(data, cl, ol, nb, i); return -1;
        }
        e->raw.blocks[i].offset    = off;
        e->raw.blocks[i].comp_size = (uint32_t)cl[i];
        e->raw.blocks[i].orig_size = (uint32_t)ol[i];
        off += cl[i];
        free(data[i]);
    }
    free_pieces(data, cl, ol, nb, nb);
    e->raw.orig_size = t->logical_size;
    e->raw.mode      = CFS_MODE_DEDUP;
    e->raw.mtime     = (uint64_t)time(NULL);
    /* Only where the table lives changed, not what it says — so a cache
     * holding THIS file's table stays valid.  Dropping it here would free the
     * table out from under a read or write that is midway through it. */
    if (c->dt_path && strcmp(c->dt_path, e->path) != 0) dedup_cache_drop(c);
    /* Reserve the bytes for the next writer (see store_append). */
    c->sb.inode_offset = off;
    c->sb.inode_size = 0;
    return 0;
}

/* Append a reference, coalescing with the previous one when both the
 * logical and the store ranges continue where it left off. */
static int ref_push(CfsDedupTable *t, uint64_t logical, uint64_t len, uint64_t store) {
    CfsRef *pv = t->n ? &t->v[t->n - 1] : NULL;
    if (pv && pv->logical + pv->length == logical && pv->store + pv->length == store) {
        pv->length += len;
        return 0;
    }
    return cfs_dedup_table_push(t, logical, len, store);
}

/* Unmatched chunks are buffered in the handle (see dedup_emit) and appended
 * in bulk: one cfs_sync per 8MB instead of one per 4KB chunk. */

/* Scan one logical stream content-defined.  With `emit` the stream is being
 * merged: matches become references and misses are appended to @store.
 * Without `emit` the stream IS @store — its chunks are only indexed, which
 * is how a later merge matches against content stored earlier. */
static int scan_stream(CFS *c, const char *path, uint64_t size, CfsDedupTable *emit) {
    uint8_t *win = malloc(DEDUP_WIN + CFS_CDC_MAX);
    if (!win) return -1;
    size_t carry = 0;          /* unprocessed bytes at the front of win */
    uint64_t base = 0;         /* stream offset of win[0] */
    int rc = 0;

    while (rc == 0 && (base + carry < size || carry > 0)) {
        size_t want = DEDUP_WIN - carry;
        if (base + carry + want > size) want = (size_t)(size - base - carry);
        if (want && cfs_read(c, path, win + carry, want,
                             (off_t)(base + carry)) != (ssize_t)want) { rc = -1; break; }
        carry += want;
        int eof = (base + carry == size);
        size_t done = 0;
        while (carry - done > 0) {
            size_t avail = carry - done;
            size_t clen;
            if (avail < CFS_CDC_MIN) {
                if (!eof) break;                     /* wait for more bytes */
                clen = avail;                        /* short tail at EOF */
            } else {
                clen = cfs_cdc_next(win + done, avail);
                if (clen == 0) break;
                if (clen == avail && clen < CFS_CDC_MAX && !eof)
                    break;                           /* cut point lies beyond the window */
            }
            uint64_t logical = base + done;
            uint64_t k[2], soff = 0;
            cfs_feature_hash(win + done, clen, k);
            if (c->fi_ready && cfs_feat_index_get(&c->fi, k, (uint32_t)clen, &soff)) {
                if (emit && ref_push(emit, logical, clen, soff) != 0) { rc = -1; break; }
            } else if (!emit) {
                /* scanning @store itself: the chunk already lives at `logical` */
                if (dedup_fi_add(c, win + done, clen, logical) != 0) { rc = -1; break; }
            } else {
                if (dedup_emit(c, win + done, clen, &soff) != 0) { rc = -1; break; }
                if (dedup_fi_add(c, win + done, clen, soff) != 0 ||
                    ref_push(emit, logical, clen, soff) != 0) { rc = -1; break; }
            }
            done += clen;
        }
        memmove(win, win + done, carry - done);
        base += done;
        carry -= done;
        if (done == 0 && eof) break;              /* no further progress possible */
    }
    free(win);
    return rc;
}

/* Merge pass: chunk every plain file content-defined, match each chunk
 * against the feature index, and either reference the earlier copy or
 * append it to @store and index it. */
int cfs_dedup_merge(CFS *c) {
    if (!c || !(c->flags & CFS_RDWR)) return -1;
    /* Snapshot the paths first: creating @store reallocs the inode array. */
    char **paths = malloc(sizeof(char*) * (c->inode_count + 1));
    if (!paths) return -1;
    uint32_t n = 0;
    for (uint32_t i = 0; i < c->inode_count; i++) {
        InodeEntry *e = &c->inodes[i];
        if (!e->path || e->raw.mode != CFS_MODE_FILE) continue;
        if (e->raw.orig_size == 0) continue;
        if (!strcmp(e->path, CFS_STORE_PATH)) continue;   /* not the store itself */
        paths[n] = strdup(e->path);      /* @block IS merged: it is the guest disk */
        if (!paths[n]) break;
        n++;
    }

    int rc = dedup_pend_ready(c);

    /* Seed the index from what @store already holds, so merging again after
     * adding files still matches against earlier content. */
    InodeEntry *se = lu(c, CFS_STORE_PATH);
    if (rc == 0 && se && se->raw.orig_size)
        rc = scan_stream(c, CFS_STORE_PATH, se->raw.orig_size, NULL);
    se = lu(c, CFS_STORE_PATH);
    c->pend_off = se ? se->raw.orig_size : 0;

    for (uint32_t i = 0; i < n && rc == 0; i++) {
        CfsStat st;
        if (cfs_stat(c, paths[i], &st) != 0) { rc = -1; break; }
        CfsDedupTable t;
        cfs_dedup_table_init(&t, st.size);
        rc = scan_stream(c, paths[i], st.size, &t);
        if (rc == 0) {
            InodeEntry *e = lu(c, paths[i]);
            if (!e || dedup_write_table(c, e, &t) != 0) rc = -1;
            /* Bound the unsynced window: until cfs_sync runs, the on-disk
             * inode table is the pre-merge one and its bytes have been
             * overwritten, so an interruption would lose the container. */
            else if ((i & 255) == 255 && cfs_sync(c) != 0) rc = -1;
        }
        cfs_dedup_table_free(&t);
    }

    /* Both run even after a failure: the bytes at the old inode-table
     * position have already been reused, so the table must be rewritten
     * either way or the container on disk no longer describes itself. */
    if (dedup_pend_flush(c) != 0 && rc == 0) rc = -1;
    if (cfs_sync(c) != 0 && rc == 0) rc = -1;
    for (uint32_t i = 0; i < n; i++) free(paths[i]);
    free(paths);
    return rc;
}

int cfs_dedup_stats(CFS *c, CfsDedupStats *out) {
    if (!c || !out) return -1;
    memset(out, 0, sizeof(*out));
    for (uint32_t i = 0; i < c->inode_count; i++) {
        InodeEntry *e = &c->inodes[i];
        if (!e->path) continue;
        if (e->raw.mode == CFS_MODE_DEDUP) {
            out->merged_files++;
            out->logical_bytes += e->raw.orig_size;
            for (uint32_t b = 0; b < e->raw.block_count; b++)
                out->table_bytes += e->raw.blocks[b].orig_size;
        } else if (e->raw.mode == CFS_MODE_FILE && e->path[0] != '@') {
            out->skipped++;
        }
    }
    InodeEntry *s = lu(c, CFS_STORE_PATH);
    if (s) out->store_bytes = s->raw.orig_size;
    return 0;
}

/* ── runtime write path ─────────────────────────────────────────
 * A write into a merged file:
 *   1. if the target range already maps to exactly these bytes, the write is
 *      a no-op — nothing is appended and no table entry changes.  A guest
 *      rewriting a block it already wrote is the common case;
 *   2. otherwise the range is chunked, each chunk matched against the feature
 *      index, and the misses appended to @store;
 *   3. the table entries covering the written range are replaced.
 * The table itself is only written back at the next cfs_sync, so a burst of
 * writes costs one table rewrite, not one per write.
 * ─────────────────────────────────────────────────────────────── */

static int dedup_pend_ready(CFS *c) {
    if (c->pend_buf) return 0;
    c->pend_cap = DEDUP_IO_CHUNK;
    c->pend_buf = malloc(c->pend_cap);
    if (!c->pend_buf) return -1;
    InodeEntry *se = lu(c, CFS_STORE_PATH);
    c->pend_off = se ? se->raw.orig_size : 0;
    return 0;
}

static int dedup_pend_flush(CFS *c) {
    if (!c->pend_n) return 0;
    /* Clear before appending: store_append() syncs, and cfs_sync() re-enters
     * here — with the count still set that would recurse forever. */
    size_t n = c->pend_n;
    uint64_t want = c->pend_off;
    c->pend_n = 0;
    uint64_t soff = 0;
    if (store_append(c, c->pend_buf, n, &soff) != 0) return -1;
    if (soff != want) return -1;        /* predicted landing offset must hold */
    c->pend_off += n;
    return 0;
}

static int dedup_emit(CFS *c, const uint8_t *p, size_t n, uint64_t *out_off) {
    if (dedup_pend_ready(c) != 0) return -1;
    /* The bytes reach @store only when the pending buffer is flushed, so the
     * quota has to be answered here rather than at the flush: by then the
     * caller has already put a reference into the table, and a refusal would
     * strand that reference on bytes that were never written — the file
     * stops resolving.  The projection is the position the whole pending
     * buffer will occupy once appended (the append cursor plus everything
     * buffered), charging raw bytes where the append will charge compressed
     * ones: conservative, which is the right direction for a safety limit. */
    if (cfs_phys_room(c, (off_t)c->sb.inode_offset, c->pend_n + n) != 0) return -1;
    if (c->pend_n + n > c->pend_cap && dedup_pend_flush(c) != 0) return -1;
    *out_off = c->pend_off + c->pend_n;
    memcpy(c->pend_buf + c->pend_n, p, n);
    c->pend_n += n;
    return 0;
}

static int dedup_fi_add(CFS *c, const uint8_t *p, size_t n, uint64_t off) {
    if (!c->fi_ready) { cfs_feat_index_init(&c->fi); c->fi_ready = 1; }
    uint64_t k[2];
    cfs_feature_hash(p, n, k);
    return cfs_feat_index_put(&c->fi, k, off, (uint32_t)n);
}

/* Put (logical, length, store) into a sorted table, replacing whatever it
 * overlaps and trimming the entries at its ends.  Extending past the current
 * end is the fast path. */
static int dedup_table_put(CfsDedupTable *t, uint64_t logical, uint64_t length,
                           uint64_t store) {
    uint64_t lo = logical, hi = logical + length;
    if (length == 0 || hi < lo) return -1;
    if (t->n == 0 || lo >= t->v[t->n - 1].logical + t->v[t->n - 1].length) {
        if (cfs_dedup_table_push(t, logical, length, store) != 0) return -1;
        if (hi > t->logical_size) t->logical_size = hi;   /* push() does not know */
        return 0;
    }
    CfsRef *nv = malloc(((size_t)t->n + 2) * sizeof *nv);
    if (!nv) return -1;
    uint32_t w = 0, i = 0;
    CfsRef tail; int has_tail = 0;
    while (i < t->n && t->v[i].logical + t->v[i].length <= lo) nv[w++] = t->v[i++];
    if (i < t->n && t->v[i].logical < lo) {
        CfsRef *r = &t->v[i];
        nv[w++] = (CfsRef){ r->logical, lo - r->logical, r->store };
        /* one entry can straddle both ends of the written range */
        if (r->logical + r->length > hi) {
            tail = (CfsRef){ hi, r->logical + r->length - hi, r->store + (hi - r->logical) };
            has_tail = 1;
        }
        i++;
    }
    nv[w++] = (CfsRef){ logical, length, store };
    while (i < t->n && t->v[i].logical < hi) {
        uint64_t a = t->v[i].logical;
        if (a + t->v[i].length > hi) {
            tail = (CfsRef){ hi, a + t->v[i].length - hi, t->v[i].store + (hi - a) };
            has_tail = 1;
        }
        i++;
    }
    if (has_tail) nv[w++] = tail;
    while (i < t->n) nv[w++] = t->v[i++];
    free(t->v);
    t->v = nv;
    t->n = w;
    t->cap = w;
    if (hi > t->logical_size) t->logical_size = hi;
    return 0;
}

/* True when [off, off+n) already maps to exactly these bytes. */
static int dedup_range_matches(CFS *c, const CfsDedupTable *t, const uint8_t *buf,
                               uint64_t off, size_t n) {
    uint8_t *tmp = malloc(n ? n : 1);
    if (!tmp) return 0;
    int same = 1;
    size_t done = 0;
    while (done < n && same) {
        const CfsRef *r = cfs_dedup_table_find(t, off + done);
        if (!r) { same = 0; break; }                 /* a hole is all zeros */
        uint64_t within = (off + done) - r->logical;
        size_t take = (size_t)(r->length - within);
        if (take > n - done) take = n - done;
        if (dedup_pend_gate(c, r->store + within) != 0) { same = 0; break; }
        if (cfs_read(c, CFS_STORE_PATH, tmp, take,
                     (off_t)(r->store + within)) != (ssize_t)take) { same = 0; break; }
        if (memcmp(tmp, buf + done, take) != 0) same = 0;
        done += take;
    }
    free(tmp);
    return same;
}

ssize_t cfs_dedup_write(CFS *c, const char *path, const void *vbuf, size_t size,
                        off_t offset) {
    if (!c || !path || !vbuf || size == 0) return -1;
    if (!(c->flags & CFS_RDWR) || offset < 0) return -1;
    InodeEntry *e = lu(c, path);
    if (!e || e->raw.mode != CFS_MODE_DEDUP) return -1;
    if (dt_load(c, e) != 0) return -1;               /* c->dt is this file's */
    const uint8_t *buf = vbuf;
    uint64_t off = (uint64_t)offset;

    if (dedup_range_matches(c, &c->dt, buf, off, size)) return (ssize_t)size;

    /* Reserve for the whole write before touching anything.  The loop below
     * emits and references one chunk at a time, so a refusal in the middle
     * would leave the earlier chunks referenced but never stored — the file
     * stops resolving.  Charging the raw size where the append will charge
     * the compressed size is conservative, which is the right direction. */
    if (cfs_phys_room(c, (off_t)c->sb.inode_offset, c->pend_n + size) != 0) return -1;

    /* And a snapshot, for everything that is not the quota: an I/O failure
     * part-way through has the same shape. */
    size_t snap_n = c->dt.n;
    uint64_t snap_ls = c->dt.logical_size;
    CfsRef *snap = NULL;
    if (snap_n) {
        snap = malloc(snap_n * sizeof *snap);
        if (!snap) return -1;
        memcpy(snap, c->dt.v, snap_n * sizeof *snap);
    }

    size_t done = 0;
    while (done < size) {
        size_t avail = size - done;
        size_t clen;
        if (avail < CFS_CDC_MIN) {
            clen = avail;
        } else {
            clen = cfs_cdc_next(buf + done, avail);
            if (clen == 0 || clen > avail) clen = avail;
        }
        uint64_t k[2] = { 0, 0 }, soff = 0;
        int hit = 0;
        if (clen >= CFS_CDC_MIN && c->fi_ready) {
            cfs_feature_hash(buf + done, clen, k);
            hit = cfs_feat_index_get(&c->fi, k, (uint32_t)clen, &soff);
        }
        if (!hit) {
            if (dedup_emit(c, buf + done, clen, &soff) != 0) goto rollback;
            if (clen >= CFS_CDC_MIN && dedup_fi_add(c, buf + done, clen, soff) != 0)
                goto rollback;
        }
        if (dedup_table_put(&c->dt, off + done, clen, soff) != 0) goto rollback;
        done += clen;
    }
    if (off + size > e->raw.orig_size) e->raw.orig_size = off + size;
    e->raw.mtime = (uint64_t)time(NULL);
    c->dt_dirty = 1;
    free(snap);
    return (ssize_t)size;

rollback:
    /* Put the reference table back exactly as it was.  Bytes already staged
     * in the pending buffer stay there and will be appended unreferenced, so
     * they cost a little space until GC reclaims them and cannot corrupt
     * anything; the feature index entries for them stay valid too, because
     * those bytes do reach the store. */
    if (snap) { memcpy(c->dt.v, snap, snap_n * sizeof *snap); free(snap); }
    c->dt.n = snap_n;
    c->dt.logical_size = snap_ls;
    return -1;
}

/* ── maintenance: threshold-driven re-merge and store reclamation ──
 * Writes only append and re-split, so a long-lived container accumulates two
 * kinds of slack: reference tables with more entries than an ideal layout
 * (fragmentation) and @store bytes nothing points at any more (dead data).
 * Both are only worth fixing once they are big enough to pay for a whole-file
 * / whole-store pass, so each has a threshold and this runs at maintenance
 * time, never on the write path.
 * ─────────────────────────────────────────────────────────────── */

typedef struct { uint64_t start, end; } Range;

typedef struct {
    Range   *v;
    uint32_t n, cap;
} Ranges;

static int ranges_add(Ranges *r, uint64_t start, uint64_t end) {
    if (start >= end) return 0;
    if (r->n == r->cap) {
        uint32_t nc = r->cap ? r->cap * 2 : 256;
        Range *nv = realloc(r->v, (size_t)nc * sizeof *nv);
        if (!nv) return -1;
        r->v = nv; r->cap = nc;
    }
    r->v[r->n].start = start;
    r->v[r->n].end = end;
    r->n++;
    return 0;
}

static int range_cmp(const void *a, const void *b) {
    const Range *x = a, *y = b;
    return x->start < y->start ? -1 : x->start > y->start ? 1 : 0;
}

/* Sort and coalesce, so the store's live bytes form disjoint runs. */
static void ranges_merge(Ranges *r) {
    if (r->n < 2) return;
    qsort(r->v, r->n, sizeof *r->v, range_cmp);
    uint32_t w = 0;
    for (uint32_t i = 1; i < r->n; i++) {
        if (r->v[i].start <= r->v[w].end) {
            if (r->v[i].end > r->v[w].end) r->v[w].end = r->v[i].end;
        } else {
            r->v[++w] = r->v[i];
        }
    }
    r->n = w + 1;
}

/* Where a live range ends up after the dead bytes are dropped. */
static uint64_t range_remap(const Ranges *r, uint64_t off) {
    uint64_t acc = 0;
    for (uint32_t i = 0; i < r->n; i++) {
        if (off < r->v[i].start) break;
        if (off < r->v[i].end) return acc + (off - r->v[i].start);
        acc += r->v[i].end - r->v[i].start;
    }
    return acc;      /* dead byte: only reachable from a stale reference */
}

static uint64_t range_total(const Ranges *r) {
    uint64_t t = 0;
    for (uint32_t i = 0; i < r->n; i++) t += r->v[i].end - r->v[i].start;
    return t;
}

/* Split a pending-byte cursor advance so the next writer does not reuse it. */
static void dedup_cursor_reserve(CFS *c, uint64_t off) {
    c->sb.inode_offset = off;
    c->sb.inode_size = 0;
}

int cfs_dedup_gc(CFS *c, CfsDedupGcStats *out) {
    if (!c || !(c->flags & CFS_RDWR)) return -1;
    CfsDedupGcStats st;
    memset(&st, 0, sizeof st);
    InodeEntry *se = lu(c, CFS_STORE_PATH);
    if (!se || se->raw.orig_size == 0) { if (out) *out = st; return 0; }
    uint64_t store_sz = se->raw.orig_size;
    st.store_before = store_sz;

    /* Which merged files are fragmented enough to be worth rebuilding. */
    char **paths = malloc(sizeof(char*) * (c->inode_count + 1));
    if (!paths) return -1;
    uint32_t nfrag = 0;
    for (uint32_t i = 0; i < c->inode_count; i++) {
        InodeEntry *e = &c->inodes[i];
        if (!e->path || e->raw.mode != CFS_MODE_DEDUP || e->raw.orig_size == 0) continue;
        if (dt_load(c, e) != 0) continue;
        uint64_t ideal = (c->dt.logical_size / CFS_DEDUP_AVG_CHUNK) + 1;
        if ((uint64_t)c->dt.n >= ideal * CFS_DEDUP_FRAG_MAX) {
            paths[nfrag] = strdup(e->path);
            if (!paths[nfrag]) break;
            nfrag++;
        }
    }

    /* Rebuild them: chunk the file against the store's content again, which
     * turns many small fragments back into few large references. */
    int rc = 0;
    if (nfrag) {
        if (dedup_pend_ready(c) != 0) rc = -1;
        if (rc == 0) rc = scan_stream(c, CFS_STORE_PATH, store_sz, NULL);   /* seed index */
        for (uint32_t i = 0; i < nfrag && rc == 0; i++) {
            CfsStat fst;
            if (cfs_stat(c, paths[i], &fst) != 0) { rc = -1; break; }
            CfsDedupTable t;
            cfs_dedup_table_init(&t, fst.size);
            rc = scan_stream(c, paths[i], fst.size, &t);
            if (rc == 0) {
                InodeEntry *e = lu(c, paths[i]);
                if (!e || dedup_write_table(c, e, &t) != 0) rc = -1;
                else {
                    st.refrag_files++;
                    /* Reading the file to rebuild it loaded its OLD table into
                     * the cache; it no longer describes the file. */
                    dedup_cache_drop(c);
                }
            }
            cfs_dedup_table_free(&t);
            if (rc == 0 && (i & 255) == 255) cfs_sync(c);
        }
        if (dedup_pend_flush(c) != 0 && rc == 0) rc = -1;
        if (cfs_sync(c) != 0 && rc == 0) rc = -1;
        se = lu(c, CFS_STORE_PATH);
        if (se) store_sz = se->raw.orig_size;
        st.store_before = store_sz;      /* rebuilding appends; measure from here */
    }
    for (uint32_t i = 0; i < nfrag; i++) free(paths[i]);
    free(paths);
    if (rc != 0) return rc;

    /* Collect every live byte of @store from the (now current) tables. */
    Ranges live;
    memset(&live, 0, sizeof live);
    for (uint32_t i = 0; i < c->inode_count; i++) {
        InodeEntry *e = &c->inodes[i];
        if (!e->path || e->raw.mode != CFS_MODE_DEDUP || e->raw.orig_size == 0) continue;
        if (dt_load(c, e) != 0) continue;
        for (uint32_t r = 0; r < c->dt.n; r++)
            if (ranges_add(&live, c->dt.v[r].store, c->dt.v[r].store + c->dt.v[r].length) != 0) {
                free(live.v); return -1;
            }
    }
    ranges_merge(&live);
    uint64_t tot = range_total(&live);
    st.dead_bytes = tot < store_sz ? store_sz - tot : 0;
    dedup_cache_drop(c);
    if (st.dead_bytes * 100 < store_sz * CFS_DEDUP_DEAD_MAX) {   /* not worth a pass */
        free(live.v);
        if (out) *out = st;
        return 0;
    }

    /* Write the live bytes into a fresh entry, then swap it in for @store. */
    const char *tmp_path = "@store.gc";
    if (cfs_write(c, tmp_path, NULL, 0) != 0) { free(live.v); return -1; }
    uint8_t *buf = malloc(DEDUP_IO_CHUNK);
    if (!buf) { free(live.v); return -1; }
    uint64_t moved = 0;
    for (uint32_t i = 0; i < live.n && rc == 0; i++) {
        uint64_t off = live.v[i].start, end = live.v[i].end;
        while (off < end && rc == 0) {
            size_t want = (size_t)(end - off < DEDUP_IO_CHUNK ? end - off : DEDUP_IO_CHUNK);
            if (cfs_read(c, CFS_STORE_PATH, buf, want, (off_t)off) != (ssize_t)want) { rc = -1; break; }
            InodeEntry *te = lu(c, tmp_path);
            if (!te) { rc = -1; break; }
            /* append through the same cursor discipline as store_append */
            uint32_t nb = 1;
            uint8_t *comp = NULL; size_t cl = 0;
            if (block_hole_pack(c, buf, want, &comp, &cl) != 0) { rc = -1; break; }
            uint32_t old = te->raw.block_count;
            if (cfs_phys_room(c, (off_t)c->sb.inode_offset, cl)) { free(comp); rc = CFS_ENOSPC; break; }
            if (inode_grow_blocks(te, old + nb) != 0) { free(comp); rc = -1; break; }
            if (cfs_pw(c, comp, cl, (off_t)c->sb.inode_offset) != (ssize_t)cl) {
                free(comp); rc = -1; break;
            }
            te->raw.blocks[old].offset = c->sb.inode_offset;
            te->raw.blocks[old].comp_size = (uint32_t)cl;
            te->raw.blocks[old].orig_size = (uint32_t)want;
            dedup_cursor_reserve(c, c->sb.inode_offset + cl);
            te->raw.orig_size += want;
            free(comp);
            off += want;
            moved += want;
        }
    }
    free(buf);
    if (rc != 0) { free(live.v); cfs_unlink(c, tmp_path); return -1; }

    /* Remap every reference to the compacted layout, then retire the old store. */
    for (uint32_t i = 0; i < c->inode_count && rc == 0; i++) {
        InodeEntry *e = &c->inodes[i];
        if (!e->path || e->raw.mode != CFS_MODE_DEDUP) continue;
        if (!strcmp(e->path, tmp_path)) continue;
        if (dt_load(c, e) != 0) { rc = -1; break; }
        for (uint32_t r = 0; r < c->dt.n; r++)
            c->dt.v[r].store = range_remap(&live, c->dt.v[r].store);
        c->dt_dirty = 1;
        if (dedup_table_flush(c) != 0) { rc = -1; break; }
    }
    st.store_after = moved;
    free(live.v);
    if (rc == 0) {
        InodeEntry *te = lu(c, tmp_path);
        InodeEntry *s2 = lu(c, CFS_STORE_PATH);
        if (!te || !s2) rc = -1;
        else {
            inode_clear_blocks(s2);
            s2->raw.blocks = te->raw.blocks;      /* take the compacted blocks */
            s2->raw.block_count = te->raw.block_count;
            s2->raw.orig_size = te->raw.orig_size;
            s2->raw.mtime = (uint64_t)time(NULL);
            te->raw.blocks = NULL;                /* old store bytes are orphaned */
            te->raw.block_count = 0;
            cfs_unlink(c, tmp_path);
        }
    }
    dedup_cache_drop(c);
    if (cfs_sync(c) != 0) rc = -1;
    if (out) *out = st;
    return rc;
}
static int dedup_table_flush(CFS *c) {
    if (!c->dt_dirty || !c->dt_path) { c->dt_dirty = 0; return 0; }
    InodeEntry *e = lu(c, c->dt_path);
    if (!e || e->raw.mode != CFS_MODE_DEDUP) { c->dt_dirty = 0; return 0; }
    c->dt_dirty = 0;
    e->raw.orig_size = c->dt.logical_size;
    return dedup_write_table(c, e, &c->dt);
}
