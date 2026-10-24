/* cfs_mkfs_fat32 — Self-contained FAT32 formatter.
 * Writes BPB + FSInfo + FATs at a partition base offset via cfs_block_write. */

#include "cfs.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define FAT_SECTOR     512
#define FAT_RSVD       32            /* reserved sectors before FAT1 */
#define FAT_FSINFO     1             /* FSInfo sector */
#define FAT_BACKUP     6             /* backup boot sector */
#define FAT_ROOT_CLUST 2
#define FAT_MIN_SIZE   (33ULL * 1024 * 1024)   /* FAT32 spec minimum */
#define FAT_EOF        0x0FFFFFFF
#define FAT_MEDIA      0x0FFFFFF8

typedef struct {
    uint8_t  jmp[3];
    char     oem[8];
    uint16_t bytes_per_sector;      /* 0x0B */
    uint8_t  sectors_per_cluster;   /* 0x0D */
    uint16_t rsvd_sector_count;     /* 0x0E */
    uint8_t  num_fats;              /* 0x10 */
    uint16_t root_ent_count;        /* 0x11 */
    uint16_t total_sect16;          /* 0x13 */
    uint8_t  media;                 /* 0x15 */
    uint16_t fat_sz16;              /* 0x16 */
    uint16_t sect_per_track;        /* 0x18 */
    uint16_t num_heads;             /* 0x1A */
    uint32_t hidden_sectors;        /* 0x1C — partition start in LBA */
    uint32_t total_sect32;          /* 0x20 */
    uint32_t fat_sz32;              /* 0x24 */
    uint16_t ext_flags;             /* 0x28 */
    uint16_t fs_ver;                /* 0x2A */
    uint32_t root_cluster;          /* 0x2C */
    uint16_t fsinfo_sector;         /* 0x30 */
    uint16_t backup_boot;           /* 0x32 */
    uint8_t  reserved[12];          /* 0x34 */
    uint8_t  drive_num;             /* 0x40 */
    uint8_t  reserved1;             /* 0x41 */
    uint8_t  sig;                   /* 0x42 */
    uint32_t vol_id;                /* 0x43 */
    char     vol_label[11];         /* 0x47 */
    char     fs_type[8];            /* 0x52 */
    uint8_t  boot_code[420];        /* 0x5A */
    uint16_t boot_sig;              /* 0x1FE */
} __attribute__((packed)) FatBpb;

static void le16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

int cfs_mkfs_fat32(CFS *c, uint64_t disk_sz) {
    return cfs_mkfs_fat32_at(c, 0, disk_sz);
}

int cfs_mkfs_fat32_at(CFS *c, uint64_t base_off, uint64_t size) {
    if (!c || size < FAT_MIN_SIZE) return -1;
    if (base_off % FAT_SECTOR) return -1;
    /* Capacity first: cfs_block_write refuses anything past the declared
     * size, so the formatter must declare it before it writes. */
    /* Grow to fit, but never pass a size below the current capacity: resize
     * is grow-only (a smaller request is refused), and the caller may have
     * declared a device slightly larger than this partition — the GPT tail
     * reserves 34 sectors for the backup table. */
    if (cfs_block_size(c) < base_off + size &&
        cfs_block_resize(c, base_off + size) != 0) return -1;

    /* Sector-to-cluster sizing (mkfs.fat style table) */
    uint32_t spc;   /* sectors per cluster */
    if (size >= 32ULL * 1024 * 1024 * 1024) spc = 64;      /* 32KB */
    else if (size >= 16ULL * 1024 * 1024 * 1024) spc = 32; /* 16KB */
    else if (size >= 8ULL * 1024 * 1024 * 1024) spc = 16;  /* 8KB */
    else if (size >= 260ULL * 1024 * 1024) spc = 8;        /* 4KB */
    else spc = 4;                                          /* 2KB */

    /* FAT32 is only legal with at least 65525 clusters; below that it is
     * FAT16 territory.  Shrink the cluster until the floor is met (a 64MB
     * volume needs 512-byte clusters) and refuse if even 512B cannot. */
    uint64_t total_sects = size / FAT_SECTOR;
    uint32_t fat_sz;
    uint64_t data_start, clusters;
    for (;;) {
        fat_sz = (uint32_t)(((total_sects / spc + 2) * 4 + FAT_SECTOR - 1) / FAT_SECTOR);
        if (total_sects <= FAT_RSVD + 2ULL * fat_sz) return -1;
        data_start = FAT_RSVD + 2ULL * fat_sz;
        clusters = (total_sects - data_start) / spc;
        if (clusters >= 65525 || spc == 1) break;
        spc >>= 1;
    }
    if (clusters < 65525 || clusters > 0x0FFFFFF5) return -1;

    /* Build BPB */
    uint8_t *bs = calloc(1, FAT_SECTOR);
    if (!bs) return -1;
    FatBpb *b = (FatBpb *)bs;
    b->jmp[0] = 0xEB; b->jmp[1] = 0x58; b->jmp[2] = 0x90;
    memcpy(b->oem, "MSDOS5.0", 8);
    le16((uint8_t *)&b->bytes_per_sector, FAT_SECTOR);
    b->sectors_per_cluster = (uint8_t)spc;
    le16((uint8_t *)&b->rsvd_sector_count, FAT_RSVD);
    b->num_fats = 2;
    le16((uint8_t *)&b->root_ent_count, 0);
    le16((uint8_t *)&b->total_sect16, 0);
    b->media = 0xF8;
    le16((uint8_t *)&b->fat_sz16, 0);
    le16((uint8_t *)&b->sect_per_track, 63);
    le16((uint8_t *)&b->num_heads, 255);
    le32((uint8_t *)&b->hidden_sectors, (uint32_t)(base_off / FAT_SECTOR));
    le32((uint8_t *)&b->total_sect32, (uint32_t)total_sects);
    le32((uint8_t *)&b->fat_sz32, fat_sz);
    le16((uint8_t *)&b->ext_flags, 0);
    le16((uint8_t *)&b->fs_ver, 0);
    le32((uint8_t *)&b->root_cluster, FAT_ROOT_CLUST);
    le16((uint8_t *)&b->fsinfo_sector, FAT_FSINFO);
    le16((uint8_t *)&b->backup_boot, FAT_BACKUP);
    b->drive_num = 0x80;
    b->sig = 0x29;
    le32((uint8_t *)&b->vol_id, (uint32_t)(time(NULL) ^ (uint32_t)getpid()));
    /* 11 bytes, space padded, no NUL — a trailing NUL makes fsck declare the
     * label invalid, and the root directory must carry the same label. */
    static const char label[11] = { 'C','F','S','-','D','I','S','K',' ',' ',' ' };
    memcpy(b->vol_label, label, 11);
    memcpy(b->fs_type, "FAT32   ", 8);
    b->boot_sig = 0xAA55;

    /* FSInfo sector 1 */
    uint8_t fi[FAT_SECTOR];
    memset(fi, 0, sizeof(fi));
    le32(fi + 0, 0x41615252);
    le32(fi + 484, 0x61417272);
    le32(fi + 488, (uint32_t)(clusters - 1));          /* free clusters (root uses 1) */
    le32(fi + 492, FAT_ROOT_CLUST + 1);                /* hint: next free */
    le32(fi + 508, 0xAA550000);

    /* FATs: entry 0 media, entry 1 EOF, root cluster EOF */
    size_t fat_bytes = (size_t)fat_sz * FAT_SECTOR;
    uint8_t *fat = calloc(1, fat_bytes);
    if (!fat) { free(bs); return -1; }
    le32(fat, FAT_MEDIA);
    le32(fat + 4, FAT_EOF);
    le32(fat + 8, FAT_EOF);   /* cluster 2 = root dir */
    uint64_t free_c = clusters - 1;

    /* Root directory: the volume-label record.  The boot sector carries the
     * same label; without a matching entry fsck.fat calls it invalid. */
    uint8_t root[FAT_SECTOR];
    memset(root, 0, sizeof(root));
    memcpy(root, label, 11);
    root[11] = 0x08;                       /* ATTR_VOLUME_ID */

    int rc = 0;
    if (cfs_block_write(c, bs, FAT_SECTOR, (off_t)base_off) != 0 ||
        cfs_block_write(c, fi, sizeof(fi), (off_t)(base_off + FAT_FSINFO * FAT_SECTOR)) != 0 ||
        cfs_block_write(c, bs, FAT_SECTOR, (off_t)(base_off + FAT_BACKUP * FAT_SECTOR)) != 0 ||
        cfs_block_write(c, fi, sizeof(fi), (off_t)(base_off + (FAT_BACKUP + 1) * FAT_SECTOR)) != 0 ||
        cfs_block_write(c, fat, fat_bytes, (off_t)(base_off + FAT_RSVD * FAT_SECTOR)) != 0 ||
        cfs_block_write(c, fat, fat_bytes, (off_t)(base_off + (FAT_RSVD + fat_sz) * FAT_SECTOR)) != 0 ||
        cfs_block_write(c, root, FAT_SECTOR, (off_t)(base_off + data_start * FAT_SECTOR)) != 0)
        rc = -1;
    free(bs);
    free(fat);
    if (rc != 0) return -1;

    fprintf(stderr, "cfs: fat32: %llu clusters, %u/sector, fat=%u sectors, free=%llu\n",
            (unsigned long long)clusters, spc, fat_sz, (unsigned long long)free_c);
    return 0;
}
