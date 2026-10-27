#ifndef CFS_FORMAT_H
#define CFS_FORMAT_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * ── .cfs container layout ───────────────────────────────────
 *
 *  v3 (crash-consistent, written by this code):
 *  [Slot 0        44B]   offset 0    (inside a 512-byte sector)
 *  [Slot 1        44B]   offset 512  (the other 512-byte sector)
 *  [DataBlocks    M B]   offset >= CFS_SB_REGION (1024)
 *  [InodeTable    N B]   wherever the slot that describes it says
 *
 *  v2 (legacy, still readable and upgraded on the first write):
 *  [SuperBlock    40B]   offset 0
 *  [InodeTable    N B]   at inode_offset
 *  [DataBlocks    M B]   appended at inode_offset + inode_size
 *
 * Each Inode records one file/dir/symlink entry.
 * Each DataBlock is a CPEnc-compressed slab.
 *
 * The two slots hold the same fields; each also carries a sequence number
 * and a CRC32 over its own 40-byte prefix.  A commit writes the new data,
 * then the new table, then the slot that is NOT the live one, so one slot
 * always points at a complete table.  The live table is never overwritten:
 * its region is the one the newest valid slot points at.
 */

/* ── SuperBlock (40-byte fields, 44-byte v3 slot record) ────── */
#define CFS_MAGIC       "LIBCFS02"
#define CFS_MAGIC_LEN   8
#define CFS_VERSION        3   /* written by this code */
#define CFS_VERSION_LEGACY 2   /* still readable; upgraded on first write */
#define CFS_VERSION_MIN    CFS_VERSION_LEGACY
#define CFS_BLOCK_SPLIT  (64ULL * 1024 * 1024)  /* split files at 64MB per block */

/* Hard ceiling on one block's decompressed size, matching the codec's own
 * CPENC_MAX_BLOCK.  cfs never emits anything near this (CFS_BLOCK_SPLIT is
 * 64MB); it exists so a corrupt block table cannot ask the read path for a
 * 4GB allocation. */
#define CFS_BLOCK_MAX    (256u << 20)

typedef struct {
    char     magic[8];       /* "LIBCFS02" */
    uint16_t version;        /* 3 (2 = legacy, read-only compatible) */
    uint64_t inode_offset;   /* where InodeTable starts */
    uint32_t inode_size;     /* total byte size of InodeTable */
    uint32_t file_count;     /* number of entries */
    uint64_t created_at;     /* unix timestamp */
    uint16_t flags;          /* container attributes (RAW = uncompressed) */
} CfsSuperBlock;
/* The struct above is the in-memory form, which the compiler pads (48 bytes,
 * flags at 40).  The on-disk fields are written at fixed offsets:
 * magic 0, version 8, inode_offset 10, inode_size 18, file_count 22,
 * created_at 26, flags 34 — 36 bytes, padded to 40.  A v3 slot record adds
 * seq (u32) at 36 and a CRC32 of bytes [0,40) at 40, for 44 bytes.  Both
 * fit inside one 512-byte sector, so a torn sector cannot touch the other
 * slot. */
#define CFS_SB_SIZE       40   /* legacy record / v3 CRC-covered prefix */
#define CFS_SB_REC_SIZE   44   /* v3 slot record: 40 fields + seq + crc */
#define CFS_SB_SEQ_OFF    36
#define CFS_SB_CRC_OFF    40
#define CFS_SB_SLOT_SIZE  512  /* one sector per slot: tear isolation */
#define CFS_SB_SLOTS      2
#define CFS_SB_REGION     (CFS_SB_SLOT_SIZE * CFS_SB_SLOTS)  /* 1024 */
#define CFS_SB_FLAG_RAW 0x0001   /* whole container stored uncompressed */
#define CFS_SB_FLAG_REMOVABLE  0x0002  /* media behaves like USB/SD */
#define CFS_SB_FLAG_ROTATIONAL 0x0004  /* spinning disk (0 = SSD/flash) */
#define CFS_SB_FLAG_SD         0x0008  /* removable media is an SD card */
#define CFS_SB_FLAG_FLASH      0x0010  /* container holds a @flash.* medium */

/* ── Slot record encode/decode (shared by cfs.c and cfs_verify.c) ──
 * A slot is only trusted when its CRC matches; the CRC is what turns a torn
 * 512-byte sector write into a fallback to the other slot instead of an
 * unopenable container.  Version 2 has no CRC and is accepted only in slot 0
 * (an old container's bytes at 512 are its data, not a slot). */
static inline uint32_t cfs_sb_crc32(const void *data, size_t n) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        crc ^= p[i];
        for (int k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)-(int32_t)(crc & 1u));
    }
    return ~crc;
}
static inline uint16_t cfs_rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static inline uint32_t cfs_rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint64_t cfs_rd64(const uint8_t *p) {
    return (uint64_t)cfs_rd32(p) | ((uint64_t)cfs_rd32(p + 4) << 32);
}
static inline void cfs_wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static inline void cfs_wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static inline void cfs_wr64(uint8_t *p, uint64_t v) {
    cfs_wr32(p, (uint32_t)v); cfs_wr32(p + 4, (uint32_t)(v >> 32));
}

#define CFS_SB_SLOT_INVALID 0   /* no usable record */
#define CFS_SB_SLOT_LEGACY  1   /* v2 record: no seq, no CRC */
#define CFS_SB_SLOT_VALID   2   /* v3 record with a matching CRC */

typedef struct {
    int          kind;   /* CFS_SB_SLOT_* */
    uint32_t     seq;    /* 0 for a legacy record */
    CfsSuperBlock sb;
} CfsSbSlot;

static inline void cfs_sb_encode(uint8_t rec[CFS_SB_REC_SIZE],
                                 const CfsSuperBlock *sb, uint32_t seq) {
    for (unsigned i = 0; i < CFS_SB_REC_SIZE; i++) rec[i] = 0;
    for (unsigned i = 0; i < 8; i++) rec[i] = (uint8_t)sb->magic[i];
    cfs_wr16(rec + 8,  sb->version);
    cfs_wr64(rec + 10, sb->inode_offset);
    cfs_wr32(rec + 18, sb->inode_size);
    cfs_wr32(rec + 22, sb->file_count);
    cfs_wr64(rec + 26, sb->created_at);
    cfs_wr16(rec + 34, sb->flags);
    cfs_wr32(rec + CFS_SB_SEQ_OFF, seq);
    cfs_wr32(rec + CFS_SB_CRC_OFF, cfs_sb_crc32(rec, CFS_SB_SIZE));
}

/* Returns CFS_SB_SLOT_*; @n is how many bytes could actually be read. */
static inline int cfs_sb_decode(const uint8_t *rec, size_t n, CfsSbSlot *out) {
    out->kind = CFS_SB_SLOT_INVALID;
    out->seq = 0;
    if (n < CFS_SB_SIZE) return out->kind;
    if (memcmp(rec, CFS_MAGIC, CFS_MAGIC_LEN) != 0) return out->kind;
    uint16_t ver = cfs_rd16(rec + 8);
    out->sb.version      = ver;
    out->sb.inode_offset = cfs_rd64(rec + 10);
    out->sb.inode_size   = cfs_rd32(rec + 18);
    out->sb.file_count   = cfs_rd32(rec + 22);
    out->sb.created_at   = cfs_rd64(rec + 26);
    out->sb.flags        = cfs_rd16(rec + 34);
    for (unsigned i = 0; i < 8; i++) out->sb.magic[i] = (char)rec[i];
    if (ver == CFS_VERSION) {
        /* A v3 record without a matching CRC is a torn write, not a slot. */
        if (n < CFS_SB_REC_SIZE) return out->kind;
        uint32_t seq = cfs_rd32(rec + CFS_SB_SEQ_OFF);
        if (seq == 0) return out->kind;
        if (cfs_rd32(rec + CFS_SB_CRC_OFF) != cfs_sb_crc32(rec, CFS_SB_SIZE))
            return out->kind;
        out->kind = CFS_SB_SLOT_VALID;
        out->seq = seq;
        return out->kind;
    }
    if (ver == CFS_VERSION_LEGACY) {
        out->kind = CFS_SB_SLOT_LEGACY;
        out->seq = 0;
        return out->kind;
    }
    return out->kind;
}

/* ── Inode (24-byte fixed part + 16 B per block + variable path) ─ */
#define CFS_MODE_FILE   0
#define CFS_MODE_DIR    1
#define CFS_MODE_SYMLINK 2
#define CFS_MODE_DEDUP  3   /* blocks[] hold a reference table, not content */
#define CFS_MODE_FLASH  4   /* a raw flash medium; see CfsFlashDesc below */

/* ── Flash media ────────────────────────────────────────────────
 * A flash entry is named "@flash.<tag>" and holds one contiguous, 4 KiB
 * aligned, uncompressed byte range of the container file:
 *
 *     [ medium: desc->size bytes ][ descriptor: 4096 bytes ]
 *
 * Byte 0 of the medium sits at the start of the range, so it is page aligned
 * and a consumer can mmap() it straight out of the container file (XIP).  The
 * descriptor follows the medium and is not part of the address space the
 * guest sees.
 *
 * The block table has one entry per extent:
 *     { offset = range start, comp_size = 0 (raw marker), orig_size = span }
 * comp_size == 0 is the "not a CPEnc stream" marker; every other mode must
 * have a real compressed block there.  A medium is always one entry: the
 * span must fit orig_size (u32) and CFS_FLASH_MAX keeps media at 1 GiB.
 *
 * Unlike every other entry, a flash medium is not compressed, not deduped
 * and not rewritten by cfs_sync: guest writes go straight to the range with
 * pwrite().  A medium created with CFS_FLASH_F_XIP promises that the range
 * never moves, so cfs_compact() refuses the whole container (an XIP consumer
 * may hold a mapping, and the extent's file offset is part of the contract).
 * Without that flag the range may move on compact; it is copied verbatim.
 */
/* On-disk descriptor: two independent 2 KiB copies inside the 4 KiB area, in
 * the same spirit as the two superblock slots.  An erase or a bad-block edit
 * writes the older copy with sequence+1; a torn 2 KiB write leaves the other
 * copy valid, so the geometry cannot be lost.  Fields are little endian and
 * fixed-offset; each copy carries a CRC32 over its own first 2044 bytes. */
#define CFS_FLASH_COPY_SIZE    2048u
#define CFS_FLASH_DESC_SIZE    4096u
#define CFS_FLASH_PREFIX       "@flash."
#define CFS_FLASH_MAGIC        "CFSF"
#define CFS_FLASH_VERSION      1
#define CFS_FLASH_MAX          (1ULL << 30)   /* one block entry, honest limit */
#define CFS_FLASH_F_XIP        0x0001u  /* keep the extent's offset stable */
#define CFS_FLASH_F_MANAGED    0x0002u  /* FTL behind it: plain sector writes */
#define CFS_FLASH_F_BADTAB     0x0004u  /* bad-block list is present */

enum { CFS_FLASH_NOR = 0, CFS_FLASH_NAND = 1, CFS_FLASH_EMMC = 2, CFS_FLASH_MCU = 3 };

#define CFS_FLASH_D_MAGIC      0
#define CFS_FLASH_D_VERSION    4
#define CFS_FLASH_D_MEDIA      6
#define CFS_FLASH_D_FLAGS      8
#define CFS_FLASH_D_SIZE       12
#define CFS_FLASH_D_SECTOR     20
#define CFS_FLASH_D_PAGE       24
#define CFS_FLASH_D_ERASE      28
#define CFS_FLASH_D_WGRAN      32
#define CFS_FLASH_D_ERASED     36
#define CFS_FLASH_D_ECOUNT     40
#define CFS_FLASH_D_BADN       48
#define CFS_FLASH_D_BADOFF     52       /* byte offset of the bad-block list */
#define CFS_FLASH_D_BAD_ENTRY  56       /* u32 erase-block indices */
#define CFS_FLASH_D_BAD_MAX    ((CFS_FLASH_D_SEQ - CFS_FLASH_D_BAD_ENTRY) / 4)
#define CFS_FLASH_D_SEQ        2040
#define CFS_FLASH_D_CRC        2044



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
    uint32_t comp_size;  /* compressed size (0 = raw flash extent) */
    uint32_t orig_size;  /* decompressed size of THIS block */
} CfsBlock;

/* How many bytes a block table entry occupies in the file: the compressed
 * payload normally, the whole raw span for a flash range. */
static inline uint64_t cfs_block_span(uint16_t mode, const CfsBlock *b) {
    return mode == CFS_MODE_FLASH ? (uint64_t)b->orig_size : (uint64_t)b->comp_size;
}

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
