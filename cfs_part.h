#ifndef CFS_PART_H
#define CFS_PART_H
#include <stdint.h>

/* ── MBR ──────────────────────────────────────────────────────── */
#define MBR_SECTOR_SIZE    512
#define MBR_PART_OFF       446
#define MBR_PART_ENTRIES   4
#define MBR_PART_ENTRY_SZ  16
#define MBR_SIG_OFF        510
#define MBR_SIG_HI         0x55
#define MBR_SIG_LO         0xAA

#define MBR_TYPE_EMPTY     0x00
#define MBR_TYPE_LINUX     0x83
#define MBR_TYPE_FAT32     0x0C
#define MBR_TYPE_FAT16     0x06
#define MBR_TYPE_EFI       0xEF    /* EFI system partition */
#define MBR_TYPE_GPT_PROT  0xEE    /* protective MBR on GPT disks */
#define MBR_TYPE_SWAP      0x82
#define MBR_TYPE_NTFS      0x07

/* LBA where the first MBR partition may start.  Everything below (the MBR
 * itself lives in LBA0) belongs to the partition table: a partition that
 * covered it would let an ordinary write erase the table. */
#define MBR_FIRST_USABLE   2048          /* 1MiB */

typedef struct {
    uint8_t  status;
    uint8_t  chs_first[3];
    uint8_t  type;
    uint8_t  chs_last[3];
    uint32_t start_lba;
    uint32_t sectors;
} __attribute__((packed)) MbrEntry;

/* ── GPT ──────────────────────────────────────────────────────── */
#define GPT_HEADER_SIG     "EFI PART"
#define GPT_ENTRIES_LBA    2
#define GPT_ENTRIES_MAX    128
#define GPT_ENTRY_SIZE     128
#define GPT_FIRST_USABLE   34
#define GPT_ENTRIES_BYTES  (GPT_ENTRIES_MAX * GPT_ENTRY_SIZE)   /* 16384 = 32 sectors */
#define GPT_TABLE_BYTES    (34 * 512)                            /* LBA0-33 */
#define GPT_BACKUP_SECTORS 33                                    /* backup entries + header */
#define GPT_MIN_DISK_SECT  67                                    /* 34 + 33 */
/* Last usable LBA is disk_sectors - GPT_LAST_USABLE_RESERVE: the backup
 * entry array (32 sectors) and backup header (1) follow it at the tail. */
#define GPT_LAST_USABLE_RESERVE 34

typedef struct {
    char     sig[8];          /* "EFI PART" */
    uint32_t rev;             /* 0x00010000 */
    uint32_t hdr_size;        /* 92 */
    uint32_t hdr_crc;         /* CRC32 over header with crc field zeroed */
    uint32_t reserved;
    uint64_t cur_lba;         /* 1 */
    uint64_t backup_lba;
    uint64_t first_usable;    /* 34 */
    uint64_t last_usable;
    uint8_t  disk_guid[16];
    uint64_t entries_lba;     /* 2 */
    uint32_t num_entries;     /* 128 */
    uint32_t entry_size;      /* 128 */
    uint32_t entries_crc;     /* CRC32 over the whole entry array */
    uint8_t  reserved2[512 - 92];
} __attribute__((packed)) GptHeader;

typedef struct {
    uint8_t  type_guid[16];
    uint8_t  unique_guid[16];
    uint64_t first_lba;
    uint64_t last_lba;
    uint64_t attrs;
    uint8_t  name[72];        /* UTF-16LE */
} __attribute__((packed)) GptEntry;

/* GPT partition type GUIDs (little-endian byte order) */
static const uint8_t GPT_GUID_LINUX[16] =
    { 0xAF,0x3D,0xC6,0x0F, 0x83,0x84, 0x72,0x47, 0x8E,0x79, 0x3D,0x69,0xD8,0x47,0x7D,0xE4 }; /* linux-data */
static const uint8_t GPT_GUID_EFI[16] =
    { 0x28,0x73,0x2A,0xC1, 0x1F,0xF8, 0xD2,0x11, 0xBA,0x4B, 0x00,0xA0,0xC9,0x3E,0xC9,0x3B }; /* EFI system */
static const uint8_t GPT_GUID_MS[16] =
    { 0xA2,0xA0,0xD0,0xEB, 0xE5,0xB9, 0x33,0x44, 0x87,0xC0, 0x68,0xB6,0xB7,0x26,0x99,0xC7 }; /* MS basic data */
static const uint8_t GPT_GUID_SWAP[16] =
    { 0x6D,0xFD,0x57,0x06, 0xAB,0xA4, 0xC4,0x43, 0x84,0xE5, 0x09,0x33,0xC8,0x4B,0x4F,0x4F }; /* linux swap */

#endif /* CFS_PART_H */
