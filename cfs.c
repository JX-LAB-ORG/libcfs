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

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)p[0]|((uint16_t)p[1]<<8); }
static inline uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static inline uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p)|((uint64_t)rd32(p+4)<<32); }
static void wr16(uint8_t *p, uint16_t v) { p[0]=v&0xFF;p[1]=v>>8; }
static void wr32(uint8_t *p, uint32_t v) { p[0]=v&0xFF;p[1]=(v>>8)&0xFF;p[2]=(v>>16)&0xFF;p[3]=v>>24; }
static void wr64(uint8_t *p, uint64_t v) { wr32(p,(uint32_t)(v&0xFFFFFFFFULL)); wr32(p+4,(uint32_t)(v>>32)); }
static InodeEntry *lu(CFS *c,const char *path){for(uint32_t i=0;i<c->inode_count;i++)if(c->inodes[i].path&&!strcmp(c->inodes[i].path,path))return &c->inodes[i];return NULL;}

/* ── Write superblock + inode table to disk ────────────────────── */
static int cfs_sync(CFS *c) {
    volatile uint64_t canary_a = 0xCAFEBABECAFEBABEULL;
    volatile uint64_t canary_b = 0xDEADBEEFDEADBEEFULL;
    if (!c || !(c->flags & CFS_RDWR)) return -1;

    /* Serialise inode table */
    size_t ts = 0;
    for (uint32_t i = 0; i < c->inode_count; i++)
        ts += CFS_INODE_FIXED_SIZE + c->inodes[i].raw.path_len;
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
        for (int b = 0; b < CFS_BLOCK_MAX; b++) {
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
    for (uint32_t i = 0; i < c->inode_count; i++) {
        c->st.total_orig_size += c->inodes[i].raw.orig_size;
        for (uint32_t b = 0; b < c->inodes[i].raw.block_count && b < CFS_BLOCK_MAX; b++) {
            uint64_t be = c->inodes[i].raw.blocks[b].offset + c->inodes[i].raw.blocks[b].comp_size;
            if (be > data_end) data_end = be;
            c->st.total_compressed_size += c->inodes[i].raw.blocks[b].comp_size;
        }
    }
    c->st.file_count = c->inode_count;
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
    if (pwrite(c->fd, tab, c->sb.inode_size, io_off) != (ssize_t)c->sb.inode_size) {
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
    if (pwrite(c->fd, sb, CFS_SB_SIZE, 0) != CFS_SB_SIZE) return -1;
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
    c->flags = CFS_RDWR;
    memcpy(c->sb.magic, CFS_MAGIC, 8);
    c->sb.version = CFS_VERSION;
    c->sb.created_at = (uint64_t)time(NULL);
    c->sb.inode_offset = CFS_SB_SIZE;
    /* Write initial superblock */
    if (cfs_sync(c) != 0) { close(c->fd); free(c); return NULL; }
    return c;
}

/* ── Add file (builder API) ───────────────────────────────── */
int cfs_add_file(CFS *c, const char *vpath, const void *buf, size_t size) {
    if(!c||!vpath||!buf||size==0) return -1;
    size_t cl=0; uint8_t *comp=NULL;

    if(c->flags & CFS_RAW){
        /* Store uncompressed: CPEnc RAW header + raw data */
        cl = CPENC_HEADER_SIZE + size;
        comp = malloc(cl);
        if(!comp) return -1;
        CPEncHeader *rh = (CPEncHeader*)comp;
        memset(rh,0,CPENC_HEADER_SIZE);rh->magic=CPENC_MAGIC;rh->version=CPENC_VERSION;
        rh->stride=CPENC_STRIDE_RAW;rh->original_size=(uint32_t)size;rh->compressed_size=(uint32_t)size;
        memcpy(comp+CPENC_HEADER_SIZE, buf, size);
    }else{
        size_t mc=cpenc_max_compressed_size(size);
        comp=malloc(mc); if(!comp)return -1;
        cl=mc;
        if(cpenc_compress(buf,size,comp,&cl,2)!=0){free(comp);return -1;}
    }

    off_t write_off = (off_t)c->sb.inode_offset;
    if(pwrite(c->fd,comp,cl,write_off)!=(ssize_t)cl){free(comp);return -1;}

    InodeEntry *na=realloc(c->inodes,(c->inode_count+1)*sizeof(InodeEntry));
    if(!na){free(comp);return -1;} c->inodes=na;
    InodeEntry *e=&c->inodes[c->inode_count++];
    memset(e,0,sizeof(*e));
    e->path=strdup(vpath);
    e->raw.orig_size=size; e->raw.mtime=(uint64_t)time(NULL);
    e->raw.mode=CFS_MODE_FILE; e->raw.path_len=(uint16_t)strlen(vpath); e->raw.block_count=1;
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
CFS *cfs_open(const char *path, int flags) {
    int oflags = (flags & CFS_RDWR) ? O_RDWR : O_RDONLY;
    CFS *c = calloc(1, sizeof(*c)); if (!c) return NULL;
    c->part_kind = -1;   /* partition cache starts unparsed (calloc would give NONE) */
    c->flags = flags & (CFS_RDONLY | CFS_RDWR);
    c->fd = open(path, oflags);
    if (c->fd < 0) { free(c); return NULL; }

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
    c->st.file_count   = c->sb.file_count;
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
        for (int b = 0; b < CFS_BLOCK_MAX; b++) {
            e->raw.blocks[b].offset    = rd64(p); p += 8;
            e->raw.blocks[b].comp_size = rd32(p); p += 4;
            e->raw.blocks[b].orig_size = rd32(p); p += 4;
        }
        if (e->raw.path_len && (size_t)(end - p) >= e->raw.path_len) {
            e->path = malloc(e->raw.path_len + 1);
            memcpy(e->path, p, e->raw.path_len);
            e->path[e->raw.path_len] = 0;
            p += e->raw.path_len;
        }
        c->st.total_orig_size += e->raw.orig_size;
        for (uint32_t b = 0; b < e->raw.block_count && b < CFS_BLOCK_MAX; b++)
            c->st.total_compressed_size += e->raw.blocks[b].comp_size;
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
    if (c->fd >= 0) close(c->fd);
    for (uint32_t i = 0; i < c->inode_count; i++) free(c->inodes[i].path);
    free(c->inodes);
    free(c);
}

ssize_t cfs_read(CFS *c,const char *path,void *buf,size_t size,off_t offset){
    if(!c||!buf)return -1;
    if(size==0)return 0;
    InodeEntry *e=lu(c,path);
    if(!e||(e->raw.mode!=CFS_MODE_FILE&&e->raw.mode!=CFS_MODE_SYMLINK))return -1;
    if(e->raw.block_count==0||e->raw.orig_size==0)return 0;
    if(offset<0||(uint64_t)offset>=e->raw.orig_size)return 0;
    size_t rem=size;if((uint64_t)(offset+size)>e->raw.orig_size)rem=(size_t)(e->raw.orig_size-(uint64_t)offset);
    size_t total=0; uint64_t cur_off=0; /* cur_off tracks position in file */

    for(uint32_t b=0;b<e->raw.block_count&&b<CFS_BLOCK_MAX&&rem>0;b++){
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

void *cfs_read_all(CFS *c,const char *path,size_t *out){InodeEntry *e=lu(c,path);if(!e||(e->raw.mode!=CFS_MODE_FILE&&e->raw.mode!=CFS_MODE_SYMLINK))return NULL;void *b=malloc(e->raw.orig_size?e->raw.orig_size:1);if(!b)return NULL;if(e->raw.orig_size==0){if(out)*out=0;return b;}if(cfs_read(c,path,b,e->raw.orig_size,0)!=(ssize_t)e->raw.orig_size){free(b);return NULL;}if(out)*out=e->raw.orig_size;return b;}

int cfs_ls(CFS *c,const char *dir,CfsDirEntry *ents,int max){
    if(!c||!dir||!ents||max<=0)return 0;
    size_t dl=strlen(dir);int n=0;
    /* Strip trailing slash for consistency */
    if(dl>0&&dir[dl-1]=='/')dl--;
    for(uint32_t i=0;i<c->inode_count&&n<max;i++){
        InodeEntry *e=&c->inodes[i];if(!e->path)continue;
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
        memset(e->raw.blocks, 0, sizeof(e->raw.blocks));
        return cfs_sync(c);
    }
    if (!buf) return -1;

    InodeEntry *e = lu(c, path);
    int is_new = (e == NULL);
    uint32_t n_blocks = (uint32_t)((size + CFS_BLOCK_SPLIT - 1) / CFS_BLOCK_SPLIT);
    if (n_blocks > CFS_BLOCK_MAX) return -2;

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
            blks[b].cl = CPENC_HEADER_SIZE + bs;
            blks[b].data = malloc(blks[b].cl);
            if (!blks[b].data) { ok = 0; break; }
            CPEncHeader *rh = (CPEncHeader*)blks[b].data;
            memset(rh,0,CPENC_HEADER_SIZE);rh->magic=CPENC_MAGIC;rh->version=CPENC_VERSION;
            rh->stride=CPENC_STRIDE_RAW;rh->original_size=(uint32_t)bs;rh->compressed_size=(uint32_t)bs;
            memcpy(blks[b].data+CPENC_HEADER_SIZE,(const uint8_t*)buf+bo,bs);
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
    memset(e, 0, sizeof(*e));
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
        if (pwrite(c->fd, blks[b].data, blks[b].cl, (off_t)cur_off) != (ssize_t)blks[b].cl) {
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
    e->raw.block_count = 0;
    memset(e->raw.blocks, 0, sizeof(e->raw.blocks));

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
        memset(e->raw.blocks, 0, sizeof(e->raw.blocks));
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
    for (uint32_t b = 0; b < e->raw.block_count && b < CFS_BLOCK_MAX && rem > 0; b++) {
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
        if (pwrite(c->fd, comp, cl, wo) != (ssize_t)cl) {
            free(comp); return -1;
        }
        e->raw.blocks[keep - 1].comp_size = (uint32_t)cl;
        e->raw.blocks[keep - 1].orig_size = (uint32_t)rem;
        free(comp);
    }

    for (uint32_t b = keep; b < CFS_BLOCK_MAX; b++)
        memset(&e->raw.blocks[b], 0, sizeof(e->raw.blocks[b]));
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
    uint8_t hdr[CPENC_HEADER_SIZE]; memset(hdr, 0, sizeof(hdr));
    CPEncHeader *h = (CPEncHeader*)hdr;
    h->magic = CPENC_MAGIC; h->version = CPENC_VERSION;
    h->stride = CPENC_STRIDE_RAW; h->original_size = (uint32_t)tl;
    h->compressed_size = (uint32_t)tl;
    if (pwrite(c->fd, hdr, CPENC_HEADER_SIZE, wo) != CPENC_HEADER_SIZE ||
        pwrite(c->fd, target, tl, wo + CPENC_HEADER_SIZE) != (ssize_t)tl)
        { free(e->path); c->inode_count--; return -1; }

    e->raw.orig_size   = tl;
    e->raw.mtime       = (uint64_t)time(NULL);
    e->raw.mode        = CFS_MODE_SYMLINK;
    e->raw.path_len    = (uint16_t)strlen(linkpath);
    e->raw.block_count = 1;
    e->raw.blocks[0].offset    = (uint64_t)wo;
    e->raw.blocks[0].comp_size = CPENC_HEADER_SIZE + (uint32_t)tl;
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

    /* Build a temporary path */
    char tmp[1024];
    int flen = snprintf(tmp, sizeof(tmp), "/tmp/cfs_compact_XXXXXX");
    (void)flen;
    int tfd = mkstemp(tmp);
    if (tfd < 0) return -1;

    /* Walk inodes, copy active blocks to temp file */
    uint64_t cur_off = CFS_SB_SIZE;
    /* Inodes will be rebuilt with new offsets */
    for (uint32_t i = 0; i < c->inode_count; i++) {
        InodeEntry *e = &c->inodes[i];
        if (!e->path) continue;
        if (e->raw.block_count == 0 || e->raw.mode == CFS_MODE_DIR) continue;

        for (uint32_t b = 0; b < e->raw.block_count && b < CFS_BLOCK_MAX; b++) {
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
        ts += CFS_INODE_FIXED_SIZE + c->inodes[i].raw.path_len;
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
        for (int b = 0; b < CFS_BLOCK_MAX; b++) {
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
    e->raw.block_count = 0;
    memset(e->raw.blocks, 0, sizeof(e->raw.blocks));
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
    if(block_ensure(c, (uint64_t)offset+(uint64_t)size)!=0) return -1;
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

/* ── Block-write path: block-granular patching ───────────────────
 * Random writes touch only the blocks they overlap (decompress →
 * patch → recompress → rewrite in place, or append if the recompressed
 * payload grew).  The format's read path locates blocks by prefix sum
 * of orig_size, so block layout is kept gap-free: writes beyond the
 * current data end zero-pad the gap (zeros compress to almost nothing),
 * and a write exactly at the data end extends the last block in place.
 * Falls back to whole-file RMW only when the 16-block cap would be
 * exceeded. */

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
                       uint8_t *pend_data[], uint32_t pend_idx[], size_t pend_cl[], int *np) {
    CfsBlock *blk = &e->raw.blocks[b];
    uint32_t olen = blk->orig_size;
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

    blk->orig_size = nolen;
    if (c->flags & CFS_RAW) {
        /* RAW payload = header + nolen; only in-place when size unchanged */
        if (ext) {
            uint8_t *nc = malloc(CPENC_HEADER_SIZE + nolen);
            if (!nc) { free(dec); return -1; }
            CPEncHeader *h = (CPEncHeader*)nc;
            memset(h, 0, CPENC_HEADER_SIZE);
            h->magic = CPENC_MAGIC; h->version = CPENC_VERSION;
            h->stride = CPENC_STRIDE_RAW;
            h->original_size = nolen; h->compressed_size = nolen;
            memcpy(nc + CPENC_HEADER_SIZE, dec, nolen);
            free(dec);
            pend_data[*np] = nc; pend_idx[*np] = b; pend_cl[*np] = CPENC_HEADER_SIZE + nolen; (*np)++;
            return 0;
        }
        /* rewrite the payload in place (same size) */
        uint8_t *nc = malloc(CPENC_HEADER_SIZE + olen);
        if (!nc) { free(dec); return -1; }
        CPEncHeader *h = (CPEncHeader*)nc;
        memset(h, 0, CPENC_HEADER_SIZE);
        h->magic = CPENC_MAGIC; h->version = CPENC_VERSION;
        h->stride = CPENC_STRIDE_RAW;
        h->original_size = nolen; h->compressed_size = nolen;
        memcpy(nc + CPENC_HEADER_SIZE, dec, olen);
        free(dec);
        if (pwrite(c->fd, nc, CPENC_HEADER_SIZE + olen, (off_t)blk->offset) != (ssize_t)(CPENC_HEADER_SIZE + olen))
            { free(nc); return -1; }
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
        if (pwrite(c->fd, nc, ncl, (off_t)blk->offset) != (ssize_t)ncl) { free(nc); return -1; }
        blk->comp_size = (uint32_t)ncl;
        free(nc);
    } else {
        pend_data[*np] = nc; pend_idx[*np] = b; pend_cl[*np] = ncl; (*np)++;
    }
    return 0;
}

/* Compress a hole segment into a standalone block payload. */
static int block_hole_pack(CFS *c, const uint8_t *seg, size_t len,
                           uint8_t **out, size_t *outcl) {
    if (c->flags & CFS_RAW) {
        *outcl = CPENC_HEADER_SIZE + len;
        uint8_t *d = malloc(*outcl);
        if (!d) return -1;
        CPEncHeader *h = (CPEncHeader*)d;
        memset(h, 0, CPENC_HEADER_SIZE);
        h->magic = CPENC_MAGIC; h->version = CPENC_VERSION;
        h->stride = CPENC_STRIDE_RAW;
        h->original_size = (uint32_t)len; h->compressed_size = (uint32_t)len;
        memcpy(d + CPENC_HEADER_SIZE, seg, len);
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

int cfs_block_write(CFS *c, const void *buf, size_t size, off_t offset) {
    if(!c||!buf||size==0) return -1;
    if(offset<0) return -1;
    if(!(c->flags & CFS_RDWR)) return -1;

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

    uint8_t   *pend_data[CFS_BLOCK_MAX];
    uint32_t   pend_idx[CFS_BLOCK_MAX];   /* block idx, or CFS_BLOCK_MAX = new block */
    size_t     pend_cl[CFS_BLOCK_MAX];
    size_t     pend_orig[CFS_BLOCK_MAX];  /* orig size of new blocks */
    int        np = 0;
    int        nnew = 0;

    uint32_t nb = e->raw.block_count;
    uint64_t cur_end = 0;
    for (uint32_t b = 0; b < nb; b++) cur_end += e->raw.blocks[b].orig_size;

    if (w0 >= cur_end) {
        /* Append-only: pad the gap with zeros.  A gap-free layout is
         * required (read path locates blocks by prefix sums).  A zero pad
         * compresses to almost nothing, so this stays cheap. */
        uint64_t pad = w0 - cur_end;
        if (pad == 0) {
            if (block_patch(c, e, nb - 1, src, w0, cur_end, cur_end, size,
                            pend_data, pend_idx, pend_cl, &np) != 0)
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
            pend_idx[np] = CFS_BLOCK_MAX;
            pend_orig[np] = plen + size;
            np++; nnew++;
        }
    } else {
        /* Patch overlapping blocks; the last block may extend past its
         * current end to absorb a tail write. */
        uint64_t acc = 0;
        for (uint32_t b = 0; b < nb; b++) {
            uint64_t bo = acc, be = acc + e->raw.blocks[b].orig_size;
            acc = be;
            if (be <= w0) continue;
            if (bo >= w1) break;
            uint64_t po = w0 > bo ? w0 : bo;
            uint64_t pe = w1 < be ? w1 : be;
            size_t ext = 0;
            if (b == nb - 1 && w1 > be) ext = (size_t)(w1 - be);
            if (po < pe || ext) {
                if (block_patch(c, e, b, src, w0, po, pe, ext,
                                pend_data, pend_idx, pend_cl, &np) != 0)
                    goto fail_pend;
            }
            if (ext) break;   /* last block absorbed the tail */
        }
    }

    /* Block-cap exceeded → whole-file RMW fallback */
    if (nb + (uint32_t)nnew > CFS_BLOCK_MAX) {
        for (int i = 0; i < np; i++) free(pend_data[i]);
        return block_write_fallback(c, src, size, w0, minsz, prev_sz);
    }

    /* Unified append pass: grown patches + new blocks, written at the
     * old inode-table position, cursor advancing. */
    {
        uint64_t app = c->sb.inode_offset;
        int hi = 0;
        for (int i = 0; i < np; i++) {
            if (pwrite(c->fd, pend_data[i], pend_cl[i], (off_t)app) != (ssize_t)pend_cl[i]) {
                for (int j = i; j < np; j++) free(pend_data[j]);
                return -1;
            }
            free(pend_data[i]);
            if (pend_idx[i] == CFS_BLOCK_MAX) {
                CfsBlock *blk = &e->raw.blocks[nb + hi];
                memset(blk, 0, sizeof(*blk));
                blk->offset = app; blk->comp_size = (uint32_t)pend_cl[i];
                blk->orig_size = (uint32_t)pend_orig[i];   /* written at pend slot i, not hi */
                app += pend_cl[i];
                hi++;
            } else {
                CfsBlock *blk = &e->raw.blocks[pend_idx[i]];
                blk->offset = app; blk->comp_size = (uint32_t)pend_cl[i];
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
