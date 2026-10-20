#ifndef CFS_H
#define CFS_H
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─── Flags ────────────────────────────────────────────────── */
#define CFS_RDONLY  0x01
#define CFS_RDWR    0x02
#define CFS_CREATE  0x04
#define CFS_RAW     0x08   /* store data uncompressed (RAW passthrough) */

/* ─── Error codes ──────────────────────────────────────────── */
/* cfs_block_write() returns this when the write would land past the device
 * capacity.  The declared size is a hard limit, the way a real disk's is —
 * growing the device is explicit (cfs_block_resize), so a guest cannot push
 * the container, or the host file behind it, past what it was created with.
 * Layers that surface errors to a guest map this to ENOSPC, so a full
 * container reads as a full disk rather than as an I/O error. */
#define CFS_ENOSPC  (-28)   /* same value as ENOSPC */

/* ─── Opaque container handle ──────────────────────────────── */
typedef struct CFS CFS;

/* ─── Directory entry ──────────────────────────────────────── */
typedef struct {
    char     name[256];
    uint8_t  is_dir;
    uint64_t size;
    uint64_t mtime;
} CfsDirEntry;

/* ─── Stat ─────────────────────────────────────────────────── */
typedef struct {
    uint64_t size;
    uint64_t mtime;
    uint16_t mode;     /* 0=file, 1=dir, 2=symlink */
    uint32_t block_count;
} CfsStat;

/* ─── Truncate ──────────────────────────────────────────────── */
int    cfs_truncate(CFS *cfs, const char *path, uint64_t size);

/* ─── Symlink ───────────────────────────────────────────────── */
int    cfs_symlink(CFS *cfs, const char *target, const char *linkpath);
ssize_t cfs_readlink(CFS *cfs, const char *path, char *buf, size_t bufsiz);

/* ─── Rename ────────────────────────────────────────────────── */
int    cfs_rename(CFS *cfs, const char *oldpath, const char *newpath);

/* ─── Utimens / Chmod / Chown ───────────────────────────────── */
int    cfs_utimens(CFS *cfs, const char *path, uint64_t atime, uint64_t mtime);
int    cfs_chmod(CFS *cfs, const char *path, uint16_t perm);
int    cfs_chown(CFS *cfs, const char *path, uint32_t uid, uint32_t gid);

/* ─── Compact / Unpack ─────────────────────────────────────── */
int    cfs_compact(CFS *cfs);
int    cfs_unpack(CFS *cfs, const char *cfs_path, const char *local_path);

/* ─── Merge layer (content-addressed dedup) ──────────────────
 * cfs_dedup_merge() walks every plain file, moves its bytes into the
 * shared @store stream and rewrites the inode as a reference table.
 * Step 1 stores each file as a single whole-file reference (plumbing
 * only, no matching); feature matching lands on top of the same tables. */
typedef struct {
    uint32_t merged_files;   /* files converted to reference tables */
    uint32_t skipped;        /* files left alone (empty/dirs/reserved) */
    uint64_t logical_bytes;  /* bytes now served through references */
    uint64_t store_bytes;    /* bytes appended to @store */
    uint64_t table_bytes;    /* serialised reference-table bytes */
} CfsDedupStats;

typedef struct {
    uint32_t refrag_files;   /* files rebuilt because they fragmented */
    uint64_t dead_bytes;     /* unreferenced @store bytes found */
    uint64_t store_before;   /* @store size entering the reclamation */
    uint64_t store_after;    /* @store size leaving it (0 = no pass run) */
} CfsDedupGcStats;

int    cfs_dedup_merge(CFS *cfs);
int    cfs_dedup_stats(CFS *cfs, CfsDedupStats *out);
/* Threshold-driven maintenance: rebuild the tables that fragmented past
 * CFS_DEDUP_FRAG_MAX and drop @store bytes nothing references once they pass
 * CFS_DEDUP_DEAD_MAX.  Never runs on the write path. */
int    cfs_dedup_gc(CFS *cfs, CfsDedupGcStats *out);
/* Write into a file that cfs_dedup_merge() turned into a reference table.
 * Identical bytes are a no-op; otherwise the range is chunked, matched
 * against the feature index and the misses appended to @store. */
ssize_t cfs_dedup_write(CFS *cfs, const char *path, const void *buf,
                        size_t size, off_t offset);

/* ─── Physical quota ───────────────────────────────────────────
 * The declared device size says how big the container looks from the inside;
 * this says how much host space it may occupy.  A repetitive archive can
 * expand to terabytes inside while costing almost nothing outside, so the
 * two are deliberately independent — and only this one protects the host
 * when a small archive carries a lot of *unique* data.
 *
 * Enforced where data blocks are appended; metadata always lands, so a full
 * container stays consistent instead of corrupt.  0 = unlimited.  The
 * CFS_MAX_PHYSICAL environment variable sets it at open. */
int      cfs_set_physical_limit(CFS *cfs, uint64_t bytes);
uint64_t cfs_physical_limit(CFS *cfs);
uint64_t cfs_physical_used(CFS *cfs);   /* bytes the container file occupies */

/* ─── Block Device Layer ───────────────────────────────────── */
ssize_t cfs_block_read(CFS *cfs, void *buf, size_t size, off_t offset);
int     cfs_block_write(CFS *cfs, const void *buf, size_t size, off_t offset);
uint64_t cfs_block_size(CFS *cfs);
int     cfs_block_resize(CFS *cfs, uint64_t size);

/* ─── Disk identity ────────────────────────────────────────────
 * Declared when the container is created, carried by the container itself:
 * the image says what kind of drive it is, the way a USB stick carries its
 * own identity.  The hook and virt-kernel's device models report it.  This
 * is device metadata, not disk content — no formatter can put it in a
 * filesystem, which is why it lives in the superblock. */
#define CFS_DISK_SSD 0   /* fixed, non-rotating */
#define CFS_DISK_HDD 1   /* fixed, spinning */
#define CFS_DISK_USB 2   /* removable flash drive */
#define CFS_DISK_SD  3   /* removable SD card */

typedef struct {
    int  kind;         /* CFS_DISK_* */
    int  removable;    /* USB/SD style removable media */
    int  rotational;   /* spinning disk vs SSD/flash */
    char model[24];    /* derived from the kind */
} CfsDiskAttrs;

int cfs_disk_set(CFS *cfs, int kind);
int cfs_disk_get(CFS *cfs, CfsDiskAttrs *out);

/* ─── Partition layer (standard MBR/GPT inside @block) ─────── */
typedef struct {
    int      index;      /* 1-based partition number */
    uint64_t start;      /* byte offset inside @block */
    uint64_t size;       /* byte size */
    int      is_gpt;     /* 1 = GPT partition, 0 = MBR */
    uint8_t  mbr_type;   /* MBR type byte (0 for GPT) */
    int      bootable;   /* 1 = boot flag (MBR status 0x80) */
    char     type_str[40];
    char     guid[37];   /* GPT partition GUID */
} CfsPartition;

#define CFS_PART_NONE 0
#define CFS_PART_MBR  1
#define CFS_PART_GPT  2

int     cfs_part_count(CFS *cfs);                 /* 0 = no table (bare disk) */
int     cfs_part_get(CFS *cfs, int idx, CfsPartition *out);
ssize_t cfs_part_read(CFS *cfs, int idx, void *buf, size_t size, off_t offset);
int     cfs_part_write(CFS *cfs, int idx, const void *buf, size_t size, off_t offset);
int     cfs_part_label(CFS *cfs, int kind);       /* CFS_PART_NONE/MBR/GPT */
int     cfs_part_add(CFS *cfs, uint64_t start, uint64_t size,
                     uint8_t mbr_type, const char *guid, int bootable);
int     cfs_part_del(CFS *cfs, int idx);
int     cfs_part_type(CFS *cfs, int idx, uint8_t mbr_type, const char *guid, int bootable);
void    cfs_part_invalidate(CFS *cfs);

/* ─── Self-contained mkfs ──────────────────────────────────── */
int     cfs_mkfs_ext4(CFS *cfs, uint64_t disk_sz);
int     cfs_mkfs_ext4_at(CFS *cfs, uint64_t base_off, uint64_t size);
int     cfs_mkfs_ext4_install(CFS *cfs, uint64_t base_off, uint64_t size,
                              const uint8_t *iso_img, size_t iso_sz);
int     cfs_mkfs_fat32(CFS *cfs, uint64_t disk_sz);
int     cfs_mkfs_fat32_at(CFS *cfs, uint64_t base_off, uint64_t size);
int     cfs_mkfs_swap(CFS *cfs, uint64_t disk_sz);
int     cfs_mkfs_swap_at(CFS *cfs, uint64_t base_off, uint64_t size);

/* ─── Stats ────────────────────────────────────────────────── */
typedef struct {
    uint64_t total_orig_size;
    uint64_t total_compressed_size;
    float    compress_ratio;
    uint32_t file_count;
} CfsStats;

/* ─── Lifecycle ────────────────────────────────────────────── */
CFS   *cfs_open(const char *path, int flags);
void   cfs_close(CFS *cfs);

/* ─── Read (auto-decompress) ───────────────────────────────── */
ssize_t cfs_read(CFS *cfs, const char *path,
                 void *buf, size_t size, off_t offset);
void   *cfs_read_all(CFS *cfs, const char *path, size_t *out_size);

/* ─── Directory ────────────────────────────────────────────── */
int    cfs_ls(CFS *cfs, const char *dir,
              CfsDirEntry *entries, int max_entries);
int    cfs_stat(CFS *cfs, const char *path, CfsStat *out);
int    cfs_mkdir(CFS *cfs, const char *path);
int    cfs_unlink(CFS *cfs, const char *path);

/* ─── Write (P1 — append new file) ─────────────────────────── */
int    cfs_write(CFS *cfs, const char *path,
                 const void *buf, size_t size);
int    cfs_pack(CFS *cfs, const char *cfs_path, const char *local_path);

/* ─── Batch creation (build container from scratch) ──────────── */
CFS   *cfs_create(const char *path);
/* Mark a container as RAW (uncompressed) and persist it in the
 * superblock.  Must be called on a fresh container before writing data;
 * afterwards every open() of the file enters uncompressed mode
 * automatically. */
int    cfs_set_raw(CFS *c);
int    cfs_add_file(CFS *cfs, const char *vpath,
                    const void *buf, size_t size);
int    cfs_finalise(CFS *cfs);

/* ─── Stats ────────────────────────────────────────────────── */
void   cfs_stats(CFS *cfs, CfsStats *out);

#ifdef __cplusplus
}
#endif
#endif /* CFS_H */
