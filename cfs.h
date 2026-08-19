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

/* ─── Block Device Layer ───────────────────────────────────── */
ssize_t cfs_block_read(CFS *cfs, void *buf, size_t size, off_t offset);
int     cfs_block_write(CFS *cfs, const void *buf, size_t size, off_t offset);
uint64_t cfs_block_size(CFS *cfs);
int     cfs_block_resize(CFS *cfs, uint64_t size);

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
int    cfs_add_file(CFS *cfs, const char *vpath,
                    const void *buf, size_t size);
int    cfs_finalise(CFS *cfs);

/* ─── Stats ────────────────────────────────────────────────── */
void   cfs_stats(CFS *cfs, CfsStats *out);

#ifdef __cplusplus
}
#endif
#endif /* CFS_H */
