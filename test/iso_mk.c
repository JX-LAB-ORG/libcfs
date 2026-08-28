/* iso_mk.c — spec-valid ISO9660 builder for tests.
 *
 * Layout:
 *   sector  0-15   system area (zeros)
 *   sector 16      PVD (type 1)
 *   sector 17      boot record (type 0)
 *   sector 18      volume descriptor set terminator (type 255)
 *   sector 19..    L path table, M path table (each ceil(n/2048) sectors)
 *   sector ..      directories + files in DFS order, sector-aligned extents
 *
 * Features: arbitrary directory depth, multi-extent files (flag 0x80),
 * both-endian extent/size fields, 7-byte ISO dates, 8.3;1 names, path
 * tables with correct parent ids, whole-sector directory data. */

#define _POSIX_C_SOURCE 200809L
#include "iso_mk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SECT 2048

typedef struct IsoNode {
    char      *name;        /* bare name, no ";1" */
    uint8_t    is_dir;
    uint8_t    is_multi;    /* first extent of a multi-extent file */
    uint64_t   extent;      /* sector number */
    uint64_t   size;        /* total size (files) or data bytes (dirs) */
    uint64_t   seg2_extent, seg2_size;   /* multi-extent second segment */
    const uint8_t *data;
    size_t     data_len;
    struct IsoNode *parent;
    struct IsoNode **kids; int nkids, kids_cap;
} IsoNode;

/* multi-extent first segment size: half the data, rounded up to a sector */
static size_t me_seg1(size_t len) {
    size_t s1 = (len / 2 + SECT - 1) / SECT * SECT;
    return s1 > len ? len : s1;
}

static IsoNode *node_new(const char *name, uint8_t is_dir, IsoNode *parent) {
    IsoNode *n = calloc(1, sizeof(*n));
    if (!n) return NULL;
    n->name = strdup(name);
    if (!n->name) { free(n); return NULL; }
    n->is_dir = is_dir;
    n->parent = parent;
    return n;
}

static int node_add_kid(IsoNode *n, IsoNode *kid) {
    if (n->nkids == n->kids_cap) {
        int cap = n->kids_cap ? n->kids_cap * 2 : 4;
        IsoNode **nk = realloc(n->kids, (size_t)cap * sizeof(*nk));
        if (!nk) return -1;
        n->kids = nk; n->kids_cap = cap;
    }
    n->kids[n->nkids++] = kid;
    return 0;
}

static void free_tree(IsoNode *n) {
    for (int i = 0; i < n->nkids; i++) free_tree(n->kids[i]);
    free(n->kids); free(n->name); free(n);
}

/* ISO9660 8.3 d-characters: uppercase, 0-9 A-Z _ */
static void iso_name(const char *src, char *out, size_t outsz) {
    char base[64] = {0}, ext[16] = {0};
    const char *dot = strrchr(src, '.');
    const char *end = dot ? dot : src + strlen(src);
    size_t bl = 0, el = 0;
    for (const char *p = src; p < end && bl < 8; p++) {
        char c = *p;
        if (c >= 'a' && c <= 'z') c = (char)(c - 32);
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || c == '_') base[bl++] = c;
    }
    if (dot && dot[1]) {
        for (const char *p = dot + 1; *p && el < 3; p++) {
            char c = *p;
            if (c >= 'a' && c <= 'z') c = (char)(c - 32);
            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || c == '_') ext[el++] = c;
        }
    }
    snprintf(out, outsz, "%s%s%s;1", base, el ? "." : "", ext);
}

static void put_both16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF); p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 8);   p[3] = (uint8_t)(v & 0xFF);
}
static void put_both32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF); p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF); p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 24); p[5] = (uint8_t)((v >> 16) & 0xFF);
    p[6] = (uint8_t)((v >> 8) & 0xFF); p[7] = (uint8_t)(v & 0xFF);
}

static void put_iso_date(uint8_t *p, time_t t) {
    long secs = (long)t;
    int days = (int)(secs / 86400);
    int rem = (int)(secs % 86400);
    if (rem < 0) { rem += 86400; days--; }
    int h = rem / 3600, mi = (rem % 3600) / 60, s = rem % 60;
    int z = days + 719468;
    int era = (z >= 0 ? z : z - 146096) / 146097;
    unsigned doe = (unsigned)(z - era * 146097);
    unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int y = (int)yoe + era * 400;
    unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    unsigned mp = (5 * doy + 2) / 153;
    int d = (int)(doy - (153 * mp + 2) / 5 + 1);
    int m = mp < 10 ? (int)mp + 3 : (int)mp - 9;
    y += m <= 2;
    p[0] = (uint8_t)(y - 1900); p[1] = (uint8_t)m; p[2] = (uint8_t)d;
    p[3] = (uint8_t)h; p[4] = (uint8_t)mi; p[5] = (uint8_t)s;
    p[6] = 0;
}

/* ── directory record ───────────────────────────────────────── */
static int build_dr(IsoNode *n, uint8_t *rec, int is_dot) {
    const char *name;
    char ianame[64];
    if (is_dot == 1) name = "\x00";
    else if (is_dot == 2) name = "\x01";
    else { iso_name(n->name, ianame, sizeof(ianame)); name = ianame; }

    uint8_t flags = n->is_dir ? 0x02 : 0x00;
    if (n->is_multi) flags |= 0x80;
    /* multi-extent first segment declares its own segment size */
    uint64_t dsize = (n->is_multi && !n->is_dir) ? me_seg1(n->data_len) : n->size;

    memset(rec, 0, 34);
    size_t nl = strlen(name);
    /* len_dr must be even per ISO9660; the pad byte follows the name */
    rec[0] = (uint8_t)((33 + nl + 1) & ~1u);
    rec[1] = 0;
    put_both32(rec + 2, (uint32_t)n->extent);
    put_both32(rec + 10, (uint32_t)dsize);
    put_iso_date(rec + 18, 1700000000);
    rec[25] = flags;
    rec[26] = 0; rec[27] = 0;
    put_both16(rec + 28, 1);
    rec[32] = (uint8_t)nl;
    memcpy(rec + 33, name, nl);
    return 33 + (int)nl;
}

static int build_dr_seg2(IsoNode *n, uint8_t *rec) {
    char ianame[64];
    iso_name(n->name, ianame, sizeof(ianame));
    size_t nl = strlen(ianame);
    memset(rec, 0, 34);
    rec[0] = (uint8_t)(33 + nl);
    put_both32(rec + 2, (uint32_t)n->seg2_extent);
    put_both32(rec + 10, (uint32_t)n->seg2_size);
    put_iso_date(rec + 18, 1700000000);
    rec[25] = 0;
    rec[32] = (uint8_t)nl;
    memcpy(rec + 33, ianame, nl);
    return 33 + (int)nl;
}

typedef struct { uint8_t *data; size_t len, cap; } DirBuf;

static int dir_push(DirBuf *b, const uint8_t *rec, size_t rl) {
    if (rl & 1) rl++;
    if (b->len + rl > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : SECT;
        while (nc < b->len + rl) nc *= 2;
        uint8_t *nd = realloc(b->data, nc);
        if (!nd) return -1;
        b->data = nd; b->cap = nc;
    }
    memcpy(b->data + b->len, rec, rl);
    b->len += rl;
    return 0;
}

/* one record per kid; multi-extent files get a second record */
static uint64_t dir_need(IsoNode *n) {
    uint64_t need = 34 + 34;
    for (int i = 0; i < n->nkids; i++) {
        uint8_t rec[200];
        need += build_dr(n->kids[i], rec, 0);
        if (!n->kids[i]->is_dir && n->kids[i]->is_multi)
            need += build_dr_seg2(n->kids[i], rec);
    }
    return need;
}

/* recursive size pass: n->size = whole sectors of n's directory */
static void size_pass(IsoNode *n) {
    for (int i = 0; i < n->nkids; i++)
        if (n->kids[i]->is_dir) size_pass(n->kids[i]);
    n->size = (dir_need(n) + SECT - 1) / SECT * SECT;
}

/* recursive extent assignment (DFS pre-order): dirs and files each get
 * sectors; multi-extent second segment placed directly after the first */
static uint64_t assign_extents(IsoNode *n, uint64_t cur) {
    for (int i = 0; i < n->nkids; i++) {
        IsoNode *k = n->kids[i];
        if (k->is_dir) {
            k->extent = cur;
            cur += (k->size + SECT - 1) / SECT;
            cur = assign_extents(k, cur);
        } else {
            k->extent = cur;
            if (k->is_multi) {
                /* segments are contiguous: seg1 sectors, then seg2 */
                size_t s1 = me_seg1(k->data_len);
                cur += (s1 + SECT - 1) / SECT;
                k->seg2_size = k->data_len - s1;
                k->seg2_extent = cur;
                if (k->seg2_size) cur += (k->seg2_size + SECT - 1) / SECT;
            } else {
                cur += (k->data_len + SECT - 1) / SECT;
            }
        }
    }
    return cur;
}

/* recursive record emission: write n's directory then children */
static int emit_dir(IsoNode *n, uint8_t *img) {
    uint8_t rec[200];
    DirBuf b = {0};
    if (dir_push(&b, rec, (size_t)build_dr(n, rec, 1)) ||
        dir_push(&b, rec, (size_t)build_dr(n, rec, 2))) { free(b.data); return -1; }
    for (int i = 0; i < n->nkids; i++) {
        if (dir_push(&b, rec, (size_t)build_dr(n->kids[i], rec, 0))) { free(b.data); return -1; }
        if (!n->kids[i]->is_dir && n->kids[i]->is_multi) {
            if (dir_push(&b, rec, (size_t)build_dr_seg2(n->kids[i], rec))) { free(b.data); return -1; }
        }
    }
    memcpy(img + n->extent * SECT, b.data, b.len);
    free(b.data);

    for (int i = 0; i < n->nkids; i++) {
        IsoNode *k = n->kids[i];
        if (k->is_dir) {
            if (emit_dir(k, img)) return -1;
        } else {
            memcpy(img + k->extent * SECT, k->data, k->data_len);
            if (k->is_multi && k->seg2_size) {
                size_t s1 = me_seg1(k->data_len);
                memcpy(img + k->seg2_extent * SECT, k->data + s1, k->seg2_size);
            }
        }
    }
    return 0;
}

/* recursive path-table walk with parent ids (pre-order) */
static int pt_walk(IsoNode *n, IsoNode **order, int *oi, int max) {
    if (*oi >= max) return -1;
    order[(*oi)++] = n;
    for (int i = 0; i < n->nkids; i++)
        if (n->kids[i]->is_dir)
            if (pt_walk(n->kids[i], order, oi, max)) return -1;
    return 0;
}

static int pt_record(IsoNode *n, uint8_t *rec, int big_endian, int parent_id) {
    size_t nl = strlen(n->name);
    rec[0] = (uint8_t)nl;
    rec[1] = 0;
    uint32_t ext = (uint32_t)n->extent;
    if (big_endian) {
        rec[2] = (uint8_t)(ext >> 24); rec[3] = (uint8_t)(ext >> 16);
        rec[4] = (uint8_t)(ext >> 8);  rec[5] = (uint8_t)ext;
        rec[6] = (uint8_t)(parent_id >> 8); rec[7] = (uint8_t)parent_id;
    } else {
        rec[2] = (uint8_t)ext; rec[3] = (uint8_t)(ext >> 8);
        rec[4] = (uint8_t)(ext >> 16); rec[5] = (uint8_t)(ext >> 24);
        rec[6] = (uint8_t)parent_id; rec[7] = (uint8_t)(parent_id >> 8);
    }
    memcpy(rec + 8, n->name, nl);
    return 8 + (int)((nl + 1) & ~1u);
}

uint8_t *iso_mk_build(const IsoMkEntry *entries, int n,
                      const char *vol_id, size_t *out_sz) {
    IsoNode *root = node_new("ROOT", 1, NULL);
    if (!root) return NULL;

    for (int i = 0; i < n; i++) {
        char path[512]; strncpy(path, entries[i].path, sizeof(path) - 1);
        path[sizeof(path) - 1] = 0;
        char *save = NULL, *tok = strtok_r(path, "/", &save);
        IsoNode *cur = root;
        while (tok) {
            char *next = strtok_r(NULL, "/", &save);
            if (!*tok) { tok = next; continue; }
            if (next == NULL) break;   /* last segment = the file name */
            int found = 0;
            for (int j = 0; j < cur->nkids; j++)
                if (!strcmp(cur->kids[j]->name, tok)) { cur = cur->kids[j]; found = 1; break; }
            if (!found) {
                IsoNode *k = node_new(tok, 1, cur);
                if (!k || node_add_kid(cur, k)) { free_tree(root); return NULL; }
                cur = k;
            }
            tok = next;
        }
        /* tok = file name (path is dirs + last segment) */
        if (!tok || !*tok) continue;
        IsoNode *f = node_new(tok, 0, cur);
        if (!f || node_add_kid(cur, f)) { free_tree(root); return NULL; }
        f->data = entries[i].data;
        f->data_len = entries[i].len;
        f->size = entries[i].len;
        f->is_multi = entries[i].multiextent && entries[i].len > SECT;
    }

    size_pass(root);
    root->extent = 0;
    uint64_t maxsector = assign_extents(root, 1);
    maxsector += 1;

    /* path table */
    IsoNode *order[1024]; int oi = 0;
    if (pt_walk(root, order, &oi, 1024)) { free_tree(root); return NULL; }
    uint8_t *pt[2] = {0, 0}; size_t ptlen[2] = {0, 0};
    for (int i = 0; i < oi; i++) {
        int ppid = 1;
        for (int j = 0; j < oi; j++)
            if (order[j] == order[i]->parent) { ppid = j + 1; break; }
        for (int be = 0; be < 2; be++) {
            uint8_t rec[300];
            int rl = pt_record(order[i], rec, be, ppid);
            uint8_t *np = realloc(pt[be], ptlen[be] + (size_t)rl);
            if (!np) { free_tree(root); free(pt[0]); free(pt[1]); return NULL; }
            pt[be] = np;
            memcpy(pt[be] + ptlen[be], rec, (size_t)rl);
            ptlen[be] += (size_t)rl;
        }
    }
    size_t pt_sectors = (ptlen[0] + SECT - 1) / SECT;
    if (pt_sectors == 0) pt_sectors = 1;

    /* shift data area after the path tables */
    uint64_t data_start = 19 + 2 * pt_sectors;
    {
        IsoNode *stk[1024]; int sp = 0; stk[sp++] = root;
        while (sp) {
            IsoNode *x = stk[--sp];
            x->extent += data_start;
            if (!x->is_dir && x->is_multi) x->seg2_extent += data_start;
            for (int i = 0; i < x->nkids; i++) stk[sp++] = x->kids[i];
        }
    }

    uint64_t total_sectors = data_start + maxsector;
    size_t img_sz = (size_t)total_sectors * SECT;
    uint8_t *img = calloc(1, img_sz);
    if (!img) { free_tree(root); free(pt[0]); free(pt[1]); return NULL; }

    /* ── PVD ── */
    uint8_t *pvd = img + 16 * SECT;
    pvd[0] = 1; memcpy(pvd + 1, "CD001", 5); pvd[6] = 1;
    if (vol_id) { memset(pvd + 40, ' ', 32); memcpy(pvd + 40, vol_id, strnlen(vol_id, 32)); }
    put_both32(pvd + 80, (uint32_t)total_sectors);
    put_both16(pvd + 120, 1); put_both16(pvd + 124, 1);
    put_both16(pvd + 128, SECT);
    put_both32(pvd + 132, (uint32_t)ptlen[0]);
    uint32_t lt = 19, mt = (uint32_t)(19 + pt_sectors);
    put_both32(pvd + 140, lt); put_both32(pvd + 144, lt);
    put_both32(pvd + 148, mt); put_both32(pvd + 152, mt);
    uint8_t rr[200];
    build_dr(root, rr, 0);
    memcpy(pvd + 156, rr, 34);
    if (vol_id) { memset(pvd + 190, ' ', 128); memcpy(pvd + 190, vol_id, strnlen(vol_id, 128)); }
    memset(pvd + 318, ' ', 128); memset(pvd + 446, ' ', 128);
    memset(pvd + 574, ' ', 128); memset(pvd + 702, ' ', 37);
    memset(pvd + 739, ' ', 37);  memset(pvd + 776, ' ', 37);
    put_iso_date(pvd + 813, 1700000000);
    put_iso_date(pvd + 830, 1700000000);
    memset(pvd + 847, 0, 17); memset(pvd + 864, 0, 17);
    pvd[881] = 1;

    /* ── boot record + terminator ── */
    uint8_t *boot = img + 17 * SECT;
    boot[0] = 0; memcpy(boot + 1, "CD001", 5); boot[6] = 1;
    strcpy((char *)boot + 7, "EL TORITO SPECIFICATION");
    uint8_t *term = img + 18 * SECT;
    term[0] = 255; memcpy(term + 1, "CD001", 5); term[6] = 1;

    /* ── path tables, then data ── */
    memcpy(img + lt * SECT, pt[0], ptlen[0]);
    memcpy(img + mt * SECT, pt[1], ptlen[1]);
    if (emit_dir(root, img)) { free_tree(root); free(pt[0]); free(pt[1]); free(img); return NULL; }

    free_tree(root);
    free(pt[0]); free(pt[1]);
    *out_sz = img_sz;
    return img;
}
