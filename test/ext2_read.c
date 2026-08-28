/* ext2_read.c — read-only ext2/4 walker (test tool). */

#define _POSIX_C_SOURCE 200809L
#include "ext2_read.h"
#include "../cfs_ext4.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BS 4096u

typedef struct {
    const uint8_t *img;
    size_t sz;
    uint8_t *visited;         /* ic bits */
    uint32_t ic;
    int (*cb)(const E2Entry *, const uint8_t *, void *);
    void *ctx;
    int stop;
} WalkCtx;

static int extent_blocks(const Ext4Inode *in, uint32_t logblk, uint32_t *phys) {
    uint16_t entries = (uint16_t)(in->i_block[0] >> 16);
    if (entries == 0 || entries > 4) return -1;
    for (uint16_t e = 0; e < entries; e++) {
        uint32_t eblock = in->i_block[3 + 3 * e];
        uint32_t elen = in->i_block[4 + 3 * e] & 0xFFFF;
        uint32_t estart = in->i_block[5 + 3 * e];
        if (logblk >= eblock && logblk < eblock + elen) {
            *phys = estart + (logblk - eblock);
            return 0;
        }
    }
    return -1;
}

static int get_inode(const WalkCtx *w, uint32_t ino, Ext4Inode *out) {
    uint64_t off = (uint64_t)3 * BS + (uint64_t)(ino - 1) * 256;
    if (off + 256 > w->sz) return -1;
    memcpy(out, w->img + off, sizeof(*out));
    return 0;
}

static int dir_walk(WalkCtx *w, uint32_t ino, const char *path) {
    if (ino >= w->ic) return -1;
    if (w->visited[ino >> 3] & (uint8_t)(1u << (ino & 7))) return -1; /* cycle */
    w->visited[ino >> 3] |= (uint8_t)(1u << (ino & 7));

    Ext4Inode in;
    if (get_inode(w, ino, &in)) return -1;
    uint32_t nblk = in.i_size_lo / BS;
    if (nblk > 4) return -1;

    uint8_t blk[BS];
    for (uint32_t b = 0; b < nblk; b++) {
        uint32_t phys;
        if (extent_blocks(&in, b, &phys)) return -1;
        if ((uint64_t)(phys + 1) * BS > w->sz) return -1;
        memcpy(blk, w->img + (uint64_t)phys * BS, BS);

        uint32_t pos = 0;
        while (pos < BS) {
            Ext4DirEntry *de = (Ext4DirEntry *)(blk + pos);
            if (de->rec_len == 0) return -1;
            uint32_t rl = de->rec_len;
            if (rl < 8 || pos + rl > BS) return -1;
            if (de->inode) {
                char name[256];
                size_t nl = de->name_len;
                if (nl > 255) return -1;
                memcpy(name, de->name, nl);
                name[nl] = 0;
                if (!(nl == 1 && name[0] == '.') &&          /* "." */
                    !(nl == 2 && name[0] == '.' && name[1] == '.')) {   /* ".." */
                    char full[512];
                    if (!strcmp(path, "/")) snprintf(full, sizeof(full), "/%s", name);
                    else snprintf(full, sizeof(full), "%s/%s", path, name);

                    Ext4Inode cin;
                    if (get_inode(w, de->inode, &cin)) return -1;
                    E2Entry e;
                    memset(&e, 0, sizeof(e));
                    strncpy(e.path, full, sizeof(e.path) - 1);
                    e.size = cin.i_size_lo;
                    e.is_dir = (cin.i_mode & 0xF000) == 0x4000 ? 1 : 0;

                    if (e.is_dir) {
                        if (w->cb(&e, NULL, w->ctx)) { w->stop = 1; return 0; }
                        if (dir_walk(w, de->inode, full)) return -1;
                    } else {
                        /* assemble file content from its extents */
                        uint16_t entries = (uint16_t)(cin.i_block[0] >> 16);
                        uint32_t nfile_blk = (uint32_t)((e.size + BS - 1) / BS);
                        uint8_t *buf = NULL;
                        const uint8_t *data = NULL;
                        if (e.size) {
                            if (entries == 1) {
                                uint32_t phys;
                                if (extent_blocks(&cin, 0, &phys)) return -1;
                                data = w->img + (uint64_t)phys * BS;
                            } else {
                                buf = malloc((size_t)nfile_blk * BS);
                                if (!buf) return -1;
                                for (uint32_t b2 = 0; b2 < nfile_blk; b2++) {
                                    uint32_t phys;
                                    if (extent_blocks(&cin, b2, &phys)) { free(buf); return -1; }
                                    if ((uint64_t)(phys + 1) * BS > w->sz) { free(buf); return -1; }
                                    memcpy(buf + (size_t)b2 * BS, w->img + (uint64_t)phys * BS, BS);
                                }
                                data = buf;
                            }
                            if (w->cb(&e, data, w->ctx)) { free(buf); w->stop = 1; return 0; }
                            free(buf);
                        } else {
                            if (w->cb(&e, NULL, w->ctx)) { w->stop = 1; return 0; }
                        }
                    }
                }
            }
            if (pos + rl >= BS) break;
            pos += rl;
        }
        if (w->stop) return 0;
    }
    return 0;
}

int ext2_walk(const uint8_t *img, size_t sz,
              int (*cb)(const E2Entry *, const uint8_t *, void *), void *ctx) {
    if (!img || sz < 4096) return -1;
    const Ext4Super *s = (const Ext4Super *)(img + 1024);
    if (s->s_magic != 0xEF53) return -1;
    if (sz < (uint64_t)4 * BS) return -1;

    WalkCtx w;
    memset(&w, 0, sizeof(w));
    w.img = img; w.sz = sz; w.cb = cb; w.ctx = ctx;
    w.ic = s->s_inodes_count;
    w.visited = calloc(1, (w.ic + 7) / 8);
    if (!w.visited) return -1;

    int rc = dir_walk(&w, 2, "/");
    free(w.visited);
    return rc;
}
