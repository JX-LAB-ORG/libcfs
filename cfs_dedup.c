#include "cfs_dedup.h"
#include <stdlib.h>

static inline uint32_t rd32(const uint8_t *p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static inline uint64_t rd64(const uint8_t *p){return (uint64_t)rd32(p)|((uint64_t)rd32(p+4)<<32);}
static void wr32(uint8_t *p,uint32_t v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);p[2]=(uint8_t)(v>>16);p[3]=(uint8_t)(v>>24);}
static void wr64(uint8_t *p,uint64_t v){wr32(p,(uint32_t)v);wr32(p+4,(uint32_t)(v>>32));}

/* ── varints ─────────────────────────────────────────────────── */

size_t cfs_put_uvarint(uint8_t *p, uint64_t v) {
    size_t n = 0;
    while (v >= 0x80) { p[n++] = (uint8_t)((v & 0x7F) | 0x80); v >>= 7; }
    p[n++] = (uint8_t)v;
    return n;
}

size_t cfs_get_uvarint(const uint8_t *p, size_t len, uint64_t *out) {
    uint64_t v = 0;
    for (size_t i = 0; i < len && i < 10; i++) {   /* 10 bytes is the 64-bit ceiling */
        v |= (uint64_t)(p[i] & 0x7F) << (7 * i);
        if (!(p[i] & 0x80)) { *out = v; return i + 1; }
    }
    return 0;   /* truncated or over-long */
}

size_t cfs_put_svarint(uint8_t *p, int64_t v) {
    return cfs_put_uvarint(p, ((uint64_t)v << 1) ^ (uint64_t)(v >> 63));   /* zigzag */
}

size_t cfs_get_svarint(const uint8_t *p, size_t len, int64_t *out) {
    uint64_t u;
    size_t n = cfs_get_uvarint(p, len, &u);
    if (!n) return 0;
    *out = (int64_t)(u >> 1) ^ -(int64_t)(u & 1);
    return n;
}

/* ── reference table ─────────────────────────────────────────── */

void cfs_dedup_table_init(CfsDedupTable *t, uint64_t logical_size) {
    t->v = NULL; t->n = 0; t->cap = 0; t->logical_size = logical_size;
}

void cfs_dedup_table_free(CfsDedupTable *t) {
    free(t->v);
    t->v = NULL; t->n = 0; t->cap = 0;
}

int cfs_dedup_table_push(CfsDedupTable *t, uint64_t logical, uint64_t length, uint64_t store) {
    if (length == 0 || logical + length < logical) return -1;   /* empty or end wraps */
    if (t->n) {
        const CfsRef *prev = &t->v[t->n - 1];
        if (logical < prev->logical + prev->length) return -1;  /* out of order or overlap */
    }
    if (t->n == t->cap) {
        uint32_t nc = t->cap ? t->cap * 2 : 16;
        CfsRef *nv = realloc(t->v, (size_t)nc * sizeof *nv);
        if (!nv) return -1;
        t->v = nv; t->cap = nc;
    }
    t->v[t->n++] = (CfsRef){ logical, length, store };
    return 0;
}

const CfsRef *cfs_dedup_table_find(const CfsDedupTable *t, uint64_t off) {
    uint32_t lo = 0, hi = t->n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        const CfsRef *r = &t->v[mid];
        if (off < r->logical) hi = mid;
        else if (off - r->logical >= r->length) lo = mid + 1;
        else return r;
    }
    return NULL;
}

/* ── codec ───────────────────────────────────────────────────── */

int cfs_dedup_serialize(const CfsDedupTable *t, uint8_t **out, size_t *outlen) {
    size_t need = 12 + (size_t)t->n * 30;   /* ≤10 bytes per varint, 3 per tuple */
    uint8_t *b = malloc(need);
    if (!b) return -1;
    uint8_t *p = b;
    wr32(p, t->n); wr64(p + 4, t->logical_size); p += 12;
    uint64_t prev_end = 0, prev_store_end = 0;
    for (uint32_t i = 0; i < t->n; i++) {
        const CfsRef *r = &t->v[i];
        p += cfs_put_uvarint(p, r->logical - prev_end);
        p += cfs_put_uvarint(p, r->length);
        p += cfs_put_svarint(p, (int64_t)(r->store - prev_store_end));
        prev_end = r->logical + r->length;
        prev_store_end = r->store + r->length;
    }
    *out = b; *outlen = (size_t)(p - b);
    return 0;
}

/* Trailing bytes after the n_refs tuples are tolerated (reserved for future
 * fields); any other deviation — short header, short varint, zero length,
 * overflowing or non-ascending tuple — is rejected. */
int cfs_dedup_parse(const uint8_t *buf, size_t len, CfsDedupTable *out) {
    if (len < 12) return -1;
    uint32_t n = rd32(buf);
    CfsDedupTable t;
    cfs_dedup_table_init(&t, rd64(buf + 4));
    const uint8_t *p = buf + 12;
    size_t rem = len - 12;
    if (n > rem / 3) return -1;   /* each tuple needs ≥3 bytes */
    if (n) {
        t.v = malloc((size_t)n * sizeof *t.v);
        if (!t.v) return -1;
        t.cap = n;
    }
    uint64_t prev_end = 0, prev_store_end = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint64_t gap, length; int64_t delta; size_t c;
        if (!(c = cfs_get_uvarint(p, rem, &gap))) goto bad;
        p += c; rem -= c;
        if (!(c = cfs_get_uvarint(p, rem, &length))) goto bad;
        p += c; rem -= c;
        if (!(c = cfs_get_svarint(p, rem, &delta))) goto bad;
        p += c; rem -= c;
        uint64_t logical = prev_end + gap;
        if (length == 0 || logical < prev_end || logical + length < logical) goto bad;
        uint64_t store = prev_store_end + (uint64_t)delta;
        t.v[t.n++] = (CfsRef){ logical, length, store };
        prev_end = logical + length;
        prev_store_end = store + length;
    }
    *out = t;
    return 0;
bad:
    free(t.v);
    return -1;
}

/* ── content-defined chunking ────────────────────────────────── */

static uint64_t cfs_gear_G[256];
static int cfs_gear_ready;

/* Fixed seed → the same 256 gear constants on every call and every run. */
static void cfs_gear_init(void) {
    if (cfs_gear_ready) return;
    uint64_t x = 0x9E3779B97F4A7C15ULL;
    for (int i = 0; i < 256; i++) {
        x += 0x9E3779B97F4A7C15ULL;
        uint64_t z = x;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        cfs_gear_G[i] = z ^ (z >> 31);
    }
    cfs_gear_ready = 1;
}

size_t cfs_cdc_next(const uint8_t *p, size_t n) {
    if (n < CFS_CDC_MIN) return 0;
    cfs_gear_init();
    size_t lim = n < CFS_CDC_MAX ? n : CFS_CDC_MAX;
    uint64_t h = 0;
    for (size_t i = 0; i < lim; i++) {
        h = (h << 1) + cfs_gear_G[p[i]];
        if (i + 1 >= CFS_CDC_MIN && (h & CFS_CDC_MASK) == 0) return i + 1;
    }
    return lim;
}

/* ── feature hash ────────────────────────────────────────────── */

static inline uint64_t cfs_mix64(uint64_t z) {
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

void cfs_feature_hash(const void *p, size_t n, uint64_t out[2]) {
    const uint8_t *b = p;
    uint64_t h0 = 0xCBF29CE484222325ULL, h1 = 0x9E3779B97F4A7C15ULL;
    size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        uint64_t v = rd64(b + i);
        h0 = (h0 ^ v) * 0x100000001B3ULL;
        h1 = (h1 + v) * 0x2545F4914F6CDD1DULL;
    }
    uint64_t t = 0;
    for (size_t j = 0; i + j < n; j++) t |= (uint64_t)b[i + j] << (8 * j);
    h0 = (h0 ^ t) * 0x100000001B3ULL;
    h1 = (h1 + t) * 0x2545F4914F6CDD1DULL;
    out[0] = cfs_mix64(h0);
    out[1] = cfs_mix64(h1);
}

/* ── feature index (open addressing, linear probe) ───────────── */

static inline uint64_t cfs_feat_h(uint64_t k0, uint64_t k1) {
    uint64_t h = k0 ^ (k1 * 0x9E3779B97F4A7C15ULL);
    h ^= h >> 33; h *= 0xFF51AFD7ED558CCDULL;
    return h ^ (h >> 33);
}

void cfs_feat_index_init(CfsFeatIndex *ix) { ix->v = NULL; ix->cap = 0; ix->n = 0; }
void cfs_feat_index_free(CfsFeatIndex *ix) { free(ix->v); ix->v = NULL; ix->cap = 0; ix->n = 0; }

static int cfs_feat_grow(CfsFeatIndex *ix, uint32_t nc) {
    CfsFeatEnt *nv = calloc(nc, sizeof *nv);
    if (!nv) return -1;
    uint32_t m = nc - 1;
    for (uint32_t j = 0; j < ix->cap; j++) {
        CfsFeatEnt *e = &ix->v[j];
        if (!e->used) continue;
        uint32_t i = (uint32_t)(cfs_feat_h(e->k0, e->k1) & m);
        while (nv[i].used) i = (i + 1) & m;
        nv[i] = *e;
    }
    free(ix->v);
    ix->v = nv; ix->cap = nc;
    return 0;
}

int cfs_feat_index_put(CfsFeatIndex *ix, const uint64_t k[2], uint64_t off, uint32_t len) {
    if (ix->cap == 0 && cfs_feat_grow(ix, 16) != 0) return -1;
    uint32_t m = ix->cap - 1;
    uint32_t i = (uint32_t)(cfs_feat_h(k[0], k[1]) & m);
    while (ix->v[i].used) {
        if (ix->v[i].k0 == k[0] && ix->v[i].k1 == k[1]) return 0;   /* first occurrence stays */
        i = (i + 1) & m;
    }
    if ((uint64_t)(ix->n + 1) * 10 > (uint64_t)ix->cap * 7) {       /* load > 0.7 → double */
        if (ix->cap >= (1u << 30) || cfs_feat_grow(ix, ix->cap * 2) != 0) return -1;
        m = ix->cap - 1;
        i = (uint32_t)(cfs_feat_h(k[0], k[1]) & m);
        while (ix->v[i].used) i = (i + 1) & m;
    }
    ix->v[i] = (CfsFeatEnt){ k[0], k[1], off, len, 1 };
    ix->n++;
    return 0;
}

int cfs_feat_index_get(const CfsFeatIndex *ix, const uint64_t k[2], uint32_t len, uint64_t *off) {
    if (ix->cap == 0) return 0;
    uint32_t m = ix->cap - 1;
    uint32_t i = (uint32_t)(cfs_feat_h(k[0], k[1]) & m);
    while (ix->v[i].used) {
        if (ix->v[i].k0 == k[0] && ix->v[i].k1 == k[1]) {
            if (ix->v[i].len != len) return 0;   /* length rejects most collisions */
            if (off) *off = ix->v[i].off;
            return 1;
        }
        i = (i + 1) & m;
    }
    return 0;
}
