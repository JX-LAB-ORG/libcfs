#ifndef CFS_FORMAT_H
#define CFS_FORMAT_H
#include <stdint.h>
#include <stddef.h>

/*
 * ── .cfs container layout ───────────────────────────────────
 *
 *  [SuperBlock    32B]   offset 0
 *  [InodeTable    N B]   at inode_offset
 *  [DataBlocks    M B]   at inode_offset + inode_size
 *
 * Each Inode records one file/dir/symlink entry.
 * Each DataBlock is a CPEnc-compressed slab.
 */

/* ── SuperBlock (32 bytes) ─────────────────────────────────── */
#define CFS_MAGIC       "LIBCFS02"
#define CFS_MAGIC_LEN   8
#define CFS_VERSION     2
#define CFS_BLOCK_SPLIT  (64ULL * 1024 * 1024)  /* split files at 64MB per block */

/* Hard ceiling on one block's decompressed size, matching the codec's own
 * CPENC_MAX_BLOCK.  cfs never emits anything near this (CFS_BLOCK_SPLIT is
 * 64MB); it exists so a corrupt block table cannot ask the read path for a
 * 4GB allocation. */
#define CFS_BLOCK_MAX    (256u << 20)

typedef struct {
    char     magic[8];       /* "LIBCFS02" */
    uint16_t version;        /* 2 */
    uint64_t inode_offset;   /* where InodeTable starts */
    uint32_t inode_size;     /* total byte size of InodeTable */
    uint32_t file_count;     /* number of entries */
    uint64_t created_at;     /* unix timestamp */
    uint16_t flags;          /* container attributes (RAW = uncompressed) */
} CfsSuperBlock;
/* The struct above is the in-memory form, which the compiler pads (48 bytes,
 * flags at 40).  The on-disk form is written field by field at the offsets
 * cfs.c uses: magic 0, version 8, inode_offset 10, inode_size 18,
 * file_count 22, created_at 26, flags 34 — 36 bytes, padded to 40. */
#define CFS_SB_SIZE  40   /* on-disk size; see the note above */
#define CFS_SB_FLAG_RAW 0x0001   /* whole container stored uncompressed */
#define CFS_SB_FLAG_REMOVABLE  0x0002  /* media behaves like USB/SD */
#define CFS_SB_FLAG_ROTATIONAL 0x0004  /* spinning disk (0 = SSD/flash) */
#define CFS_SB_FLAG_SD         0x0008  /* removable media is an SD card */

/* ── Inode (24-byte fixed part + 16 B per block + variable path) ─ */
#define CFS_MODE_FILE   0
#define CFS_MODE_DIR    1
#define CFS_MODE_SYMLINK 2
#define CFS_MODE_DEDUP  3   /* blocks[] hold a reference table, not content */

/* ── Merge layer (content-addressed dedup) ───────────────────
 * @store: reserved entry holding the append-only stream of unique bytes.
 *         Ordinary file semantics (blocks are CPEnc-compressed slabs), so
 *         the existing block table + orig_size prefix-sum lookup locate
 *         any byte range of it unchanged.
 *
 * A CFS_MODE_DEDUP file's orig_size is its LOGICAL size; its blocks[]
 * hold the serialised reference table instead of content:
 *
 *   [u32 n_refs][u64 logical_size]
 *   n_refs x { uvarint gap, uvarint length, svarint store_delta }
 *
 *   gap         = logical      - prev_end           (prev_end starts at 0)
 *   store_delta = store        - (prev_store+prev_length)   (starts at 0)
 *
 * Tuples are sorted by logical offset and non-overlapping.  Logical ranges
 * covered by no tuple read as zeros (same hole semantics as a plain file).
 * A reference means: logical[logical, logical+length) == store[store, +length).
 */
#define CFS_STORE_PATH      "@store"
/* Reserved; the matcher's real floor is CFS_CDC_MIN (1024 B) in cfs_dedup.c.
 * Kept so an older reader of this header still compiles. */
#define CFS_DEDUP_MIN_MATCH 64
#define CFS_DEDUP_BLOCK     (8u << 20)   /* reference-table block unit */

/* Maintenance thresholds.  Rewriting a merged file (re-chunk, re-match) and
 * reclaiming the store are both whole-file/whole-store passes, so they only
 * pay off once writes have degraded the layout enough.  Checked at
 * maintenance time (compact), never on the write path. */
#define CFS_DEDUP_AVG_CHUNK (4u << 10)   /* CFS_CDC_MASK implies ~4KB */
#define CFS_DEDUP_FRAG_MAX  4            /* refs*avg / logical_size; 1.0 = ideal */
#define CFS_DEDUP_DEAD_MAX  50           /* percent of @store that is unreferenced */

/* Block table is dynamic: the disk size (set by the CLI at create time)
 * determines the block count, no hard cap.  On-disk inode layout is
 * [orig u64][mtime u64][mode u16][path_len u16][block_count u32]
 * [blocks x block_count x 16B][path]; the struct below is the in-memory
 * form (blocks heap-allocated). */
#define CFS_BLOCK_SANITY 65536   /* validation cap only, not a limit */

typedef struct {
    uint64_t offset;     /* absolute offset in .cfs */
    uint32_t comp_size;  /* compressed size */
    uint32_t orig_size;  /* decompressed size of THIS block */
} CfsBlock;

typedef struct {
    uint64_t orig_size;      /* uncompressed byte size */
    uint64_t mtime;          /* modification timestamp */
    uint16_t mode;           /* CFS_MODE_FILE/DIR/SYMLINK/DEDUP */
    uint16_t path_len;       /* byte-length of path name */
    uint32_t block_count;    /* number of blocks (>=1 for files) */
    CfsBlock *blocks;        /* heap, block_count entries */
} CfsInode;
#define CFS_INODE_FIXED_SIZE (offsetof(CfsInode, blocks))   /* disk header: 24B */

/* ── DataBlock ───────────────────────────────────────────────
 * Each block is self-contained: [CPEncHeader 12B][compressed payload]
 * where the CPEnc header's original_size reflects this block's contribution. */

#endif /* CFS_FORMAT_H */
