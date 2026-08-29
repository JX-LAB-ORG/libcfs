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

typedef struct {
    char     magic[8];       /* "LIBCFS02" */
    uint16_t version;        /* 2 */
    uint64_t inode_offset;   /* where InodeTable starts */
    uint32_t inode_size;     /* total byte size of InodeTable */
    uint32_t file_count;     /* number of entries */
    uint64_t created_at;     /* unix timestamp */
    uint16_t flags;          /* container attributes (RAW = uncompressed) */
} CfsSuperBlock;
#define CFS_SB_SIZE  40   /* 8+2+8+4+4+8+2 = 36, padded to 40 for alignment */
#define CFS_SB_FLAG_RAW 0x0001   /* whole container stored uncompressed */

/* ── Inode (64 + variable path name) ───────────────────────── */
#define CFS_MODE_FILE   0
#define CFS_MODE_DIR    1
#define CFS_MODE_SYMLINK 2

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
    uint16_t mode;           /* CFS_MODE_FILE/DIR/SYMLINK */
    uint16_t path_len;       /* byte-length of path name */
    uint32_t block_count;    /* number of blocks (>=1 for files) */
    CfsBlock *blocks;        /* heap, block_count entries */
} CfsInode;
#define CFS_INODE_FIXED_SIZE (offsetof(CfsInode, blocks))   /* disk header: 24B */

/* ── DataBlock ───────────────────────────────────────────────
 * Each block is self-contained: [CPEncHeader 12B][compressed payload]
 * where the CPEnc header's original_size reflects this block's contribution. */

#endif /* CFS_FORMAT_H */
