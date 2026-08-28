#define _GNU_SOURCE
#include "cfs_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ═══════════════════════════════════════════════════════════════════
   Partition layer — standard MBR/GPT tables living in @block's byte
   space (LBA 0 onward).  The container format itself is agnostic; the
   table is parsed on demand and cached in the CFS handle.

   Layout references (UEFI spec / classic MBR):
     MBR : 512B @0, 4×16B entries @446, 0x55AA @510
     GPT : protective MBR @LBA0, header @LBA1, 128×128B entries
           @LBA2-33, backup entries @last-33..last-2, backup header @last
   ═══════════════════════════════════════════════════════════════════ */

/* ── CRC32 (IEEE 802.3, reflected poly 0xEDB88320) ─────────────── */
static uint32_t crc32_tab[256];
static void crc32_init(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t v = i;
        for (int b = 0; b < 8; b++) v = (v & 1) ? (v >> 1) ^ 0xEDB88320u : v >> 1;
        crc32_tab[i] = v;
    }
}
static uint32_t cfs_crc32(const void *data, size_t n) {
    static int inited = 0;
    if (!inited) { crc32_init(); inited = 1; }
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) crc = (crc >> 8) ^ crc32_tab[(crc ^ p[i]) & 0xFF];
    return crc ^ 0xFFFFFFFFu;
}

/* ── Little-endian helpers ─────────────────────────────────────── */
static inline uint32_t le32r(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint64_t le64r(const uint8_t *p) {
    return (uint64_t)le32r(p) | ((uint64_t)le32r(p + 4) << 32);
}
static inline void le32w(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static inline void le64w(uint8_t *p, uint64_t v) {
    le32w(p, (uint32_t)v); le32w(p + 4, (uint32_t)(v >> 32));
}

/* ── GUID text helpers ─────────────────────────────────────────── */
static void guid_to_str(const uint8_t *g, char out[37]) {
    snprintf(out, 37, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6],
             g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
}
static int guid_from_str(const char *s, uint8_t g[16]) {
    unsigned b[16];
    if (sscanf(s, "%2x%2x%2x%2x-%2x%2x-%2x%2x-%2x%2x-%2x%2x%2x%2x%2x%2x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &b[6], &b[7],
               &b[8], &b[9], &b[10], &b[11], &b[12], &b[13], &b[14], &b[15]) != 16)
        return -1;
    for (int i = 0; i < 16; i++) g[i] = (uint8_t)b[i];
    g[0] = (uint8_t)b[3]; g[1] = (uint8_t)b[2]; g[2] = (uint8_t)b[1]; g[3] = (uint8_t)b[0];
    g[4] = (uint8_t)b[5]; g[5] = (uint8_t)b[4];
    g[6] = (uint8_t)b[7]; g[7] = (uint8_t)b[6];
    return 0;
}

/* ── Type names ────────────────────────────────────────────────── */
static const char *mbr_type_name(uint8_t t) {
    switch (t) {
    case MBR_TYPE_LINUX: return "linux";
    case MBR_TYPE_FAT32: return "fat32";
    case MBR_TYPE_FAT16: return "fat16";
    case MBR_TYPE_EFI:   return "efi";
    case MBR_TYPE_SWAP:  return "swap";
    case MBR_TYPE_NTFS:  return "ntfs";
    default:             return NULL;
    }
}
static const char *gpt_type_name(const uint8_t g[16]) {
    if (!memcmp(g, GPT_GUID_LINUX, 16)) return "linux";
    if (!memcmp(g, GPT_GUID_EFI,   16)) return "efi";
    if (!memcmp(g, GPT_GUID_MS,    16)) return "ms-basic";
    if (!memcmp(g, GPT_GUID_SWAP,  16)) return "swap";
    return NULL;
}

/* ── MBR parse/build ───────────────────────────────────────────── */
static int mbr_parse(const uint8_t *sec, CfsPartition *out, int max) {
    if (sec[MBR_SIG_OFF] != MBR_SIG_HI || sec[MBR_SIG_OFF + 1] != MBR_SIG_LO) return 0;
    int n = 0;
    for (int i = 0; i < MBR_PART_ENTRIES; i++) {
        const MbrEntry *e = (const MbrEntry *)(sec + MBR_PART_OFF + i * MBR_PART_ENTRY_SZ);
        if (e->type == MBR_TYPE_EMPTY || le32r((const uint8_t *)&e->sectors) == 0) continue;
        if (n >= max) break;
        CfsPartition *p = &out[n++];
        memset(p, 0, sizeof(*p));
        p->index = n;
        p->start = (uint64_t)le32r((const uint8_t *)&e->start_lba) * MBR_SECTOR_SIZE;
        p->size  = (uint64_t)le32r((const uint8_t *)&e->sectors) * MBR_SECTOR_SIZE;
        p->is_gpt = 0;
        p->mbr_type = e->type;
        p->bootable = (e->status & 0x80) ? 1 : 0;
        const char *tn = mbr_type_name(e->type);
        snprintf(p->type_str, sizeof(p->type_str), "%s", tn ? tn : "unknown");
    }
    return n;
}

static void mbr_chs(uint32_t lba, uint8_t chs[3]) {
    uint32_t h = (lba / 63) % 255;
    uint32_t s = lba % 63 + 1;
    uint32_t c = lba / (63 * 255);
    if (c > 1023) { c = 1023; h = 254; s = 63; }
    chs[0] = (uint8_t)h;
    chs[1] = (uint8_t)(((c >> 2) & 0xC0) | (s & 0x3F));
    chs[2] = (uint8_t)(c & 0xFF);
}

static void mbr_build(uint8_t *sec, const CfsPartition *parts, int n) {
    memset(sec, 0, MBR_SECTOR_SIZE);
    for (int i = 0; i < n && i < MBR_PART_ENTRIES; i++) {
        MbrEntry *e = (MbrEntry *)(sec + MBR_PART_OFF + i * MBR_PART_ENTRY_SZ);
        memset(e, 0, sizeof(*e));
        uint64_t start = parts[i].start / MBR_SECTOR_SIZE;
        uint64_t sectors = parts[i].size / MBR_SECTOR_SIZE;
        e->status = parts[i].bootable ? 0x80 : 0x00;
        e->type = parts[i].mbr_type;
        if (start <= 0xFFFFFFFFull) mbr_chs((uint32_t)start, e->chs_first);
        else memset(e->chs_first, 0xFF, 3);
        if (start + sectors - 1 <= 0xFFFFFFFFull) mbr_chs((uint32_t)(start + sectors - 1), e->chs_last);
        else memset(e->chs_last, 0xFE, 3);
        le32w((uint8_t *)&e->start_lba, (uint32_t)start);
        le32w((uint8_t *)&e->sectors, (uint32_t)sectors);
    }
    sec[MBR_SIG_OFF] = MBR_SIG_HI;
    sec[MBR_SIG_OFF + 1] = MBR_SIG_LO;
}

/* ── GPT parse/build ───────────────────────────────────────────── */
static int gpt_parse(const uint8_t *table, size_t table_len,
                     CfsPartition *out, int max) {
    /* table must contain LBA0-33 (≥ 17408B) */
    if (table_len < 512 + 512 + GPT_ENTRIES_BYTES) return -1;
    const GptHeader *h = (const GptHeader *)(table + 512);
    if (memcmp(h->sig, GPT_HEADER_SIG, 8)) { return -1; }
    if (le32r((const uint8_t *)&h->rev) != 0x00010000) { return -1; }
    uint32_t hdr_sz = le32r((const uint8_t *)&h->hdr_size);
    if (hdr_sz < 92 || hdr_sz > 512) { return -1; }

    /* verify header CRC (crc field zeroed) */
    uint8_t hbuf[512];
    memcpy(hbuf, h, 512);
    uint32_t stored = le32r((const uint8_t *)&h->hdr_crc);
    memset(hbuf + 16, 0, 4);
    if (cfs_crc32(hbuf, hdr_sz) != stored) { return -1; }

    uint32_t num = le32r((const uint8_t *)&h->num_entries);
    uint32_t esz = le32r((const uint8_t *)&h->entry_size);
    if (num > GPT_ENTRIES_MAX || esz < 128) { return -1; }

    const uint8_t *ep = table + 512 + 512;   /* LBA2 */
    uint32_t ent_crc = cfs_crc32(ep, GPT_ENTRIES_BYTES);
    if (ent_crc != le32r((const uint8_t *)&h->entries_crc)) { return -1; }

    int n = 0;
    for (uint32_t i = 0; i < num && n < max; i++) {
        const GptEntry *ge = (const GptEntry *)(ep + (size_t)i * esz);
        static const uint8_t zero[16] = {0};
        if (!memcmp(ge->type_guid, zero, 16)) continue;
        CfsPartition *p = &out[n++];
        memset(p, 0, sizeof(*p));
        p->index = (int)i + 1;
        uint64_t fl = le64r((const uint8_t *)&ge->first_lba);
        uint64_t ll = le64r((const uint8_t *)&ge->last_lba);
        p->start = fl * MBR_SECTOR_SIZE;
        p->size = (ll >= fl) ? (ll - fl + 1) * MBR_SECTOR_SIZE : 0;
        p->is_gpt = 1;
        p->bootable = (le64r((const uint8_t *)&ge->attrs) & 4) ? 1 : 0;  /* bit2: legacy bootable */
        const char *tn = gpt_type_name(ge->type_guid);
        snprintf(p->type_str, sizeof(p->type_str), "%s", tn ? tn : "unknown");
        guid_to_str(ge->type_guid, p->guid);
    }
    return n;
}

static void gpt_build(uint8_t *lba0, uint8_t *hdr, uint8_t *entries,
                      const CfsPartition *parts, int n,
                      uint64_t disk_sectors) {
    /* Protective MBR @LBA0 (type 0xEE, NOT the 0xEF ESP type) */
    mbr_build(lba0, NULL, 0);
    MbrEntry *pe = (MbrEntry *)(lba0 + MBR_PART_OFF);
    pe->type = MBR_TYPE_GPT_PROT;
    le32w((uint8_t *)&pe->start_lba, 1);
    le32w((uint8_t *)&pe->sectors, (uint32_t)(disk_sectors < 0xFFFFFFFFull ? disk_sectors : 0xFFFFFFFFull));

    /* Entries @LBA2 — written into their numbered slot (index-1) so that
     * GPT numbering stays stable across deletions. */
    memset(entries, 0, GPT_ENTRIES_BYTES);
    for (int i = 0; i < n && i < GPT_ENTRIES_MAX; i++) {
        int slot = parts[i].index - 1;
        if (slot < 0 || slot >= GPT_ENTRIES_MAX) continue;
        GptEntry *ge = (GptEntry *)(entries + (size_t)slot * GPT_ENTRY_SIZE);
        memset(ge, 0, GPT_ENTRY_SIZE);
        if (parts[i].guid[0]) {
            if (guid_from_str(parts[i].guid, ge->type_guid) != 0) {
                memcpy(ge->type_guid, GPT_GUID_LINUX, 16);
            }
        } else {
            const uint8_t *tg = GPT_GUID_LINUX;
            if (!strcmp(parts[i].type_str, "efi"))        tg = GPT_GUID_EFI;
            else if (!strcmp(parts[i].type_str, "swap"))  tg = GPT_GUID_SWAP;
            else if (!strcmp(parts[i].type_str, "ms-basic") ||
                     !strcmp(parts[i].type_str, "fat32") ||
                     !strcmp(parts[i].type_str, "fat16") ||
                     !strcmp(parts[i].type_str, "ntfs"))  tg = GPT_GUID_MS;
            memcpy(ge->type_guid, tg, 16);
        }
        /* unique guid: derive deterministically from the slot */
        uint8_t u[16];
        memset(u, 0, 16);
        u[0] = 0xCF; u[1] = 0x53;
        u[5] = (uint8_t)(slot >> 8); u[6] = (uint8_t)slot;
        u[8] = (uint8_t)(slot * 7); u[9] = (uint8_t)(slot * 3);
        memcpy(ge->unique_guid, u, 16);
        uint64_t start = parts[i].start / MBR_SECTOR_SIZE;
        uint64_t sectors = parts[i].size / MBR_SECTOR_SIZE;
        le64w((uint8_t *)&ge->first_lba, start);
        le64w((uint8_t *)&ge->last_lba, start + sectors - 1);
        if (parts[i].bootable) le64w((uint8_t *)&ge->attrs, 4);
        /* name: "cfs-partN" UTF-16LE */
        char nm[32];
        snprintf(nm, sizeof(nm), "cfs-part%d", slot + 1);
        for (int j = 0; nm[j] && j < 32; j++) { ge->name[j * 2] = (uint8_t)nm[j]; ge->name[j * 2 + 1] = 0; }
    }

    /* Header @LBA1 */
    memset(hdr, 0, 512);
    memcpy(hdr, GPT_HEADER_SIG, 8);
    le32w((uint8_t *)(hdr + 8), 0x00010000);
    le32w((uint8_t *)(hdr + 12), 92);
    le64w((uint8_t *)(hdr + 24), 1);
    le64w((uint8_t *)(hdr + 32), disk_sectors - 1);
    le64w((uint8_t *)(hdr + 40), GPT_FIRST_USABLE);
    le64w((uint8_t *)(hdr + 48), disk_sectors - GPT_FIRST_USABLE - GPT_BACKUP_SECTORS - 1);
    memset(hdr + 56, 0, 16);   /* disk guid: zero (not user-visible in v1) */
    le64w((uint8_t *)(hdr + 72), GPT_ENTRIES_LBA);
    le32w((uint8_t *)(hdr + 80), GPT_ENTRIES_MAX);
    le32w((uint8_t *)(hdr + 84), GPT_ENTRY_SIZE);
    le32w((uint8_t *)(hdr + 88), cfs_crc32(entries, GPT_ENTRIES_BYTES));
    le32w((uint8_t *)(hdr + 16), cfs_crc32(hdr, 92));  /* header crc after fields set */
}

/* ── Cache loading ─────────────────────────────────────────────── */
static int part_load(CFS *c) {
    if (c->part_kind != -1) return 0;

    c->part_kind = CFS_PART_NONE;
    c->part_n = 0;
    uint64_t sz = cfs_block_size(c);
    if (sz == 0) return 0;

    size_t rd = (size_t)(sz < GPT_TABLE_BYTES ? sz : GPT_TABLE_BYTES);
    uint8_t *buf = malloc(rd);
    if (!buf) return -1;
    if (cfs_block_read(c, buf, rd, 0) != (ssize_t)rd) { free(buf); return -1; }

    if (rd >= 512 && buf[MBR_SIG_OFF] == MBR_SIG_HI && buf[MBR_SIG_OFF + 1] == MBR_SIG_LO) {
        if (rd >= 1024 + GPT_ENTRIES_BYTES && !memcmp(buf + 512, GPT_HEADER_SIG, 8)) {
            int n = gpt_parse(buf, rd, c->part_cache, GPT_ENTRIES_MAX);
            if (n < 0) c->part_kind = CFS_PART_NONE;      /* corrupt header/CRC */
            else { c->part_n = n; c->part_kind = CFS_PART_GPT; }  /* 0 entries = empty GPT */
        } else {
            c->part_n = mbr_parse(buf, c->part_cache, MBR_PART_ENTRIES);
            c->part_kind = CFS_PART_MBR;
        }
    }
    free(buf);
    return 0;
}

/* ── Table save ────────────────────────────────────────────────── */
static int part_save(CFS *c) {
    if (c->part_kind == CFS_PART_MBR) {
        uint8_t sec[MBR_SECTOR_SIZE];
        mbr_build(sec, c->part_cache, c->part_n);
        int rc = cfs_block_write(c, sec, sizeof(sec), 0);
        if (rc) return rc;
        c->part_kind = -1;   /* force re-parse */
        return 0;
    }
    if (c->part_kind == CFS_PART_GPT) {
        uint64_t sz = cfs_block_size(c);
        uint64_t grow = 1ULL << 20;   /* 1MB: roomy minimum (≥ 34+33 sectors) */
        if (sz < grow) {
            if (cfs_block_resize(c, grow) != 0) return -1;
            sz = grow;
        }
        uint64_t sectors = sz / MBR_SECTOR_SIZE;

        uint8_t *lba0 = malloc(MBR_SECTOR_SIZE);
        uint8_t *hdr = malloc(MBR_SECTOR_SIZE);
        uint8_t *entries = malloc(GPT_ENTRIES_BYTES);
        if (!lba0 || !hdr || !entries) { free(lba0); free(hdr); free(entries); return -1; }

        gpt_build(lba0, hdr, entries, c->part_cache, c->part_n, sectors);
        int rc = 0;
        uint64_t backup_lba = sectors - 1;
        int w1 = cfs_block_write(c, lba0, MBR_SECTOR_SIZE, 0);
        int w2 = cfs_block_write(c, hdr, MBR_SECTOR_SIZE, MBR_SECTOR_SIZE);
        int w3 = cfs_block_write(c, entries, GPT_ENTRIES_BYTES, MBR_SECTOR_SIZE * GPT_ENTRIES_LBA);
        int w4 = cfs_block_write(c, entries, GPT_ENTRIES_BYTES, backup_lba * MBR_SECTOR_SIZE - GPT_ENTRIES_BYTES);
        if (w1 != 0 || w2 != 0 || w3 != 0 || w4 != 0)
            rc = -1;
        else {
            /* backup header: cur_lba=backup, backup_lba=1, re-CRC */
            GptHeader *bh = (GptHeader *)hdr;
            le64w((uint8_t *)&bh->cur_lba, backup_lba);
            le64w((uint8_t *)&bh->backup_lba, 1);
            le32w((uint8_t *)&bh->hdr_crc, 0);
            le32w((uint8_t *)&bh->hdr_crc, cfs_crc32(hdr, 92));
            int w5 = cfs_block_write(c, hdr, MBR_SECTOR_SIZE, (off_t)(backup_lba * MBR_SECTOR_SIZE));
            if (w5 != 0)
                rc = -1;
        }
        free(lba0); free(hdr); free(entries);
        if (rc == 0) { c->part_kind = -1; return 0; }
        return rc;
    }
    return -1;
}

/* ── Public API ────────────────────────────────────────────────── */
void cfs_part_invalidate(CFS *c) {
    if (!c) return;
    c->part_kind = -1;
    c->part_n = 0;
    c->part_wr_gen++;
}

int cfs_part_count(CFS *c) {
    if (!c || part_load(c) != 0) return -1;
    return c->part_n;
}

int cfs_part_get(CFS *c, int idx, CfsPartition *out) {
    if (!c || !out || part_load(c) != 0) return -1;
    for (int i = 0; i < c->part_n; i++)
        if (c->part_cache[i].index == idx) {
            *out = c->part_cache[i];
            return 0;
        }
    return -1;
}

ssize_t cfs_part_read(CFS *c, int idx, void *buf, size_t size, off_t offset) {
    CfsPartition p;
    if (!c || !buf || part_load(c) != 0 || cfs_part_get(c, idx, &p) != 0) return -1;
    if (offset < 0 || (uint64_t)offset > p.size) return -1;
    size_t n = size;
    if ((uint64_t)offset + n > p.size) n = (size_t)(p.size - (uint64_t)offset);
    return cfs_block_read(c, buf, n, (off_t)(p.start + (uint64_t)offset));
}

int cfs_part_write(CFS *c, int idx, const void *buf, size_t size, off_t offset) {
    CfsPartition p;
    if (!c || !buf || part_load(c) != 0 || cfs_part_get(c, idx, &p) != 0) return -1;
    if (offset < 0 || (uint64_t)offset + size > p.size) return -1;
    return cfs_block_write(c, buf, size, (off_t)(p.start + (uint64_t)offset));
}

int cfs_part_label(CFS *c, int kind) {
    if (!c || !(c->flags & CFS_RDWR)) return -1;
    if (kind != CFS_PART_NONE && kind != CFS_PART_MBR && kind != CFS_PART_GPT) return -1;
    if (part_load(c) != 0) return -1;
    if (kind != CFS_PART_NONE && c->part_n > 0) return -1;   /* non-empty table: refuse */

    if (kind == CFS_PART_NONE) {
        uint8_t sec[MBR_SECTOR_SIZE];
        memset(sec, 0, sizeof(sec));
        if (cfs_block_write(c, sec, sizeof(sec), 0) != 0) return -1;
        c->part_kind = -1;
        return 0;
    }
    if (kind == CFS_PART_MBR) {
        uint8_t sec[MBR_SECTOR_SIZE];
        mbr_build(sec, NULL, 0);
        if (cfs_block_write(c, sec, sizeof(sec), 0) != 0) return -1;
        c->part_kind = -1;
        return 0;
    }
    c->part_n = 0;
    c->part_kind = kind;      /* part_save dispatches on this */
    return part_save(c);
}

int cfs_part_add(CFS *c, uint64_t start, uint64_t size,
                 uint8_t mbr_type, const char *guid, int bootable) {
    if (!c || !(c->flags & CFS_RDWR)) return -1;
    if (part_load(c) != 0) return -1;
    if (c->part_kind == CFS_PART_NONE) return -2;   /* no table: run partlabel first */

    if (start % MBR_SECTOR_SIZE || size % MBR_SECTOR_SIZE) return -3;   /* 512B alignment */
    if (size == 0) return -3;
    uint64_t disk = cfs_block_size(c);
    if (start + size > disk) return -4;             /* out of disk */
    if (c->part_kind == CFS_PART_MBR && c->part_n >= MBR_PART_ENTRIES) return -5;
    if (c->part_kind == CFS_PART_GPT && c->part_n >= GPT_ENTRIES_MAX) return -5;

    for (int i = 0; i < c->part_n; i++) {
        uint64_t a0 = c->part_cache[i].start, a1 = a0 + c->part_cache[i].size;
        if (start < a1 && a0 < start + size) return -6;   /* overlap */
    }
    if (start * MBR_SECTOR_SIZE % (1ULL << 20) != 0)
        fprintf(stderr, "cfs: warning: partition start not 1MB-aligned (%llu)\n",
                (unsigned long long)start);

    CfsPartition *p = &c->part_cache[c->part_n];
    memset(p, 0, sizeof(*p));
    p->start = start;
    p->size = size;
    p->bootable = bootable ? 1 : 0;
    if (c->part_kind == CFS_PART_MBR) {
        if (mbr_type == MBR_TYPE_EMPTY) mbr_type = MBR_TYPE_LINUX;
        p->mbr_type = mbr_type;
        p->index = c->part_n + 1;
        const char *tn = mbr_type_name(mbr_type);
        snprintf(p->type_str, sizeof(p->type_str), "%s", tn ? tn : "unknown");
    } else {
        p->is_gpt = 1;
        /* lowest free slot keeps GPT numbering stable across deletions */
        int slot = 1;
        for (;;) {
            int used = 0;
            for (int i = 0; i < c->part_n; i++)
                if (c->part_cache[i].index == slot) { used = 1; break; }
            if (!used) break;
            slot++;
        }
        p->index = slot;
        const uint8_t *tg = NULL;
        switch (mbr_type) {
        case MBR_TYPE_EFI:  tg = GPT_GUID_EFI;   snprintf(p->type_str, sizeof(p->type_str), "efi"); break;
        case MBR_TYPE_SWAP: tg = GPT_GUID_SWAP;  snprintf(p->type_str, sizeof(p->type_str), "swap"); break;
        case MBR_TYPE_FAT16:
        case MBR_TYPE_FAT32:
        case MBR_TYPE_NTFS: tg = GPT_GUID_MS;    snprintf(p->type_str, sizeof(p->type_str), "ms-basic"); break;
        default:            tg = GPT_GUID_LINUX; snprintf(p->type_str, sizeof(p->type_str), "linux"); break;
        }
        uint8_t gb[16];
        if (guid) {
            if (guid_from_str(guid, gb) != 0) return -7;
        } else {
            memcpy(gb, tg, 16);
        }
        guid_to_str(gb, p->guid);
    }
    c->part_n++;
    if (part_save(c) != 0) { c->part_n--; return -1; }
    return p->index;
}

int cfs_part_del(CFS *c, int idx) {
    if (!c || !(c->flags & CFS_RDWR)) return -1;
    if (part_load(c) != 0) return -1;
    if (c->part_kind == CFS_PART_NONE) return -2;
    int found = -1;
    for (int i = 0; i < c->part_n; i++)
        if (c->part_cache[i].index == idx) { found = i; break; }
    if (found < 0) return -3;

    if (c->part_kind == CFS_PART_MBR) {
        /* shift up and renumber (fdisk semantics: numbers change) */
        memmove(&c->part_cache[found], &c->part_cache[found + 1],
                (size_t)(c->part_n - found - 1) * sizeof(CfsPartition));
        c->part_n--;
        for (int i = 0; i < c->part_n; i++) c->part_cache[i].index = i + 1;
    } else {
        /* compact the cache array but keep each partition's slot number,
         * so GPT numbering stays stable across deletions */
        memmove(&c->part_cache[found], &c->part_cache[found + 1],
                (size_t)(c->part_n - found - 1) * sizeof(CfsPartition));
        c->part_n--;
    }
    if (part_save(c) != 0) { c->part_n++; return -1; }
    return 0;
}

int cfs_part_type(CFS *c, int idx, uint8_t mbr_type, const char *guid, int bootable) {
    if (!c || !(c->flags & CFS_RDWR)) return -1;
    if (part_load(c) != 0) return -1;
    if (c->part_kind == CFS_PART_NONE) return -2;
    for (int i = 0; i < c->part_n; i++) {
        if (c->part_cache[i].index == idx) {
            CfsPartition *p = &c->part_cache[i];
            if (c->part_kind == CFS_PART_MBR) {
                if (mbr_type != MBR_TYPE_EMPTY) {
                    p->mbr_type = mbr_type;
                    const char *tn = mbr_type_name(mbr_type);
                    snprintf(p->type_str, sizeof(p->type_str), "%s", tn ? tn : "unknown");
                }
            } else {
                uint8_t gb[16];
                if (guid && guid_from_str(guid, gb) == 0)
                    guid_to_str(gb, p->guid);
            }
            if (bootable >= 0) p->bootable = bootable ? 1 : 0;
            return part_save(c);
        }
    }
    return -3;
}
