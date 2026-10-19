#ifndef CFS_DEDUP_H
#define CFS_DEDUP_H
#include <stdint.h>
#include <stddef.h>
#include "cfs_format.h"

/* ── Merge layer: reference tables and their codec ────────────
 * Pure byte-buffer codec — no container I/O lives here.  cfs.c owns the
 * store, the block writes and the read dispatch; this file only turns a
 * tuple list into the on-disk form and back.
 */

typedef struct {
    uint64_t logical;   /* logical offset in the file */
    uint64_t length;    /* byte length of the reference */
    uint64_t store;     /* offset in @store of the referenced bytes */
} CfsRef;

typedef struct {
    CfsRef  *v;
    uint32_t n, cap;
    uint64_t logical_size;
} CfsDedupTable;

void  cfs_dedup_table_init(CfsDedupTable *t, uint64_t logical_size);
void  cfs_dedup_table_free(CfsDedupTable *t);
/* Append a tuple.  Tuples must be pushed in ascending logical order and
 * must not overlap; returns -1 on overlap/overflow. */
int   cfs_dedup_table_push(CfsDedupTable *t, uint64_t logical, uint64_t length,
                           uint64_t store);
/* Tuple covering `off`, or NULL if `off` falls in a hole. */
const CfsRef *cfs_dedup_table_find(const CfsDedupTable *t, uint64_t off);

/* Serialise into a freshly malloc'd buffer (caller frees).  0 on success. */
int   cfs_dedup_serialize(const CfsDedupTable *t, uint8_t **out, size_t *outlen);
/* Parse a serialised table.  0 on success; the table owns its own array. */
int   cfs_dedup_parse(const uint8_t *buf, size_t len, CfsDedupTable *out);

/* ── feature sampling: content-defined chunking + feature index ──
 * A "feature" is a content-defined chunk: its boundaries are decided by a
 * rolling hash over the bytes, so identical content yields identical
 * boundaries no matter where it sits — which is what makes matching
 * alignment-independent.  Only the feature hashes need to stay in memory;
 * the store bytes themselves stay on disk.
 */
#define CFS_CDC_MIN   (1u << 10)     /* 1KB  — no chunk shorter than this */
#define CFS_CDC_MAX   (64u << 10)    /* 64KB — hard cap */
#define CFS_CDC_MASK  0xFFFu         /* cut when (h & mask)==0 → ~4KB average */

/* Length of the content-defined chunk starting at p (n bytes available).
 * Returns 0 when fewer than CFS_CDC_MIN bytes remain. */
size_t cfs_cdc_next(const uint8_t *p, size_t n);

/* 128-bit feature hash of a chunk: two independent 64-bit mixes, so a
 * match needs no byte-wise verification. */
void   cfs_feature_hash(const void *p, size_t n, uint64_t out[2]);

typedef struct {
    uint64_t k0, k1;      /* feature */
    uint64_t off;         /* where the chunk lives in @store */
    uint32_t len;         /* chunk length */
    uint32_t used;
} CfsFeatEnt;

typedef struct {
    CfsFeatEnt *v;
    uint32_t    cap, n;
} CfsFeatIndex;

void cfs_feat_index_init(CfsFeatIndex *ix);
void cfs_feat_index_free(CfsFeatIndex *ix);
/* Insert; a later put of the same feature keeps the earlier offset (the
 * first occurrence stays canonical).  Returns -1 only on allocation failure. */
int  cfs_feat_index_put(CfsFeatIndex *ix, const uint64_t k[2], uint64_t off, uint32_t len);
/* Returns 1 and fills *off on a hit whose stored length equals len; 0 on miss. */
int  cfs_feat_index_get(const CfsFeatIndex *ix, const uint64_t k[2], uint32_t len,
                        uint64_t *off);

/* LEB128 varints.  Both return the number of bytes consumed/produced;
 * cfs_get_* return 0 on truncation. */
size_t cfs_put_uvarint(uint8_t *p, uint64_t v);
size_t cfs_get_uvarint(const uint8_t *p, size_t len, uint64_t *out);
size_t cfs_put_svarint(uint8_t *p, int64_t v);      /* zigzag */
size_t cfs_get_svarint(const uint8_t *p, size_t len, int64_t *out);

#endif /* CFS_DEDUP_H */
