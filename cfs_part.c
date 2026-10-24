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
/* MBR-style type byte -> the GPT type GUID the same name means.  Shared by
 * partadd and parttype so the two cannot drift apart (parttype used to be a
 * silent no-op on GPT because the CLI passes guid=NULL). */
static const uint8_t *gpt_guid_for_type(uint8_t mbr_type, const char **name) {
    switch (mbr_type) {
    case MBR_TYPE_EFI:  *name = "efi";      return GPT_GUID_EFI;
    case MBR_TYPE_SWAP: *name = "swap";     return GPT_GUID_SWAP;
    case MBR_TYPE_FAT16:
    case MBR_TYPE_FAT32:
    case MBR_TYPE_NTFS: *name = "ms-basic"; return GPT_GUID_MS;
    default:            *name = "linux";    return GPT_GUID_LINUX;
    }
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

/* MBR partition entries carry 32-bit LBA fields.  Building the sector with a
 * truncated value is worse than refusing: a 4TiB disk with a partition at
 * LBA 2^32 parses back as LBA 0, and a 2^32-sector partition parses back as
 * size 0 (it disappears from the table).  Validate the whole range first. */
static int mbr_build(uint8_t *sec, const CfsPartition *parts, int n) {
    memset(sec, 0, MBR_SECTOR_SIZE);
    for (int i = 0; i < n && i < MBR_PART_ENTRIES; i++) {
        uint64_t start = parts[i].start / MBR_SECTOR_SIZE;
        uint64_t sectors = parts[i].size / MBR_SECTOR_SIZE;
        if (start > 0xFFFFFFFFull || sectors == 0 || sectors > 0xFFFFFFFFull ||
            start + sectors - 1 > 0xFFFFFFFFull) {
            memset(sec, 0, MBR_SECTOR_SIZE);
            return -1;
        }
    }
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
    return 0;
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
    /* The entry array must fit in the 32 sectors this parser read.  Trusting
     * num/esz independently let `num * esz` walk past the heap buffer while
     * the CRC was still computed over the fixed 16KiB. */
    if (num > GPT_ENTRIES_MAX || esz < GPT_ENTRY_SIZE || esz % GPT_ENTRY_SIZE) { return -1; }
    if ((uint64_t)num * esz > GPT_ENTRIES_BYTES) { return -1; }

    const uint8_t *ep = table + 512 + 512;   /* LBA2 */
    uint32_t ent_crc = cfs_crc32(ep, (size_t)num * esz);
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
    /* Inclusive last LBA a partition may use: the backup entries (32
     * sectors) and backup header (1) occupy everything after it.  The old
     * formula reserved 34 sectors too many and disagreed with the bounds
     * cfs_part_add now enforces. */
    le64w((uint8_t *)(hdr + 48), disk_sectors - GPT_LAST_USABLE_RESERVE);
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
/* GPT is written so that a reader always finds one complete table:
 *
 *   1. backup entry array + backup header   (one write)
 *   2. primary header + entry array         (one write, at LBA1..LBA33)
 *   3. protective MBR                       (one write, at LBA0)
 *
 * The old code wrote LBA0 first and then the primary header and its entry
 * array as separate writes; a quota refusal in the middle left the primary
 * header describing an entry array that was never written (the parser then
 * finds zero partitions) with a stale backup.  Writing the primary as one
 * contiguous block means a refusal happens before anything lands, and the
 * backup-first order means that while the primary is still old it remains
 * complete.  If any step fails, the regions already written are restored to
 * the bytes read at entry, so a failed partadd leaves the previous table. */
static int part_save(CFS *c) {
    if (c->part_kind == CFS_PART_MBR) {
        uint8_t sec[MBR_SECTOR_SIZE];
        if (mbr_build(sec, c->part_cache, c->part_n) != 0) {
            c->part_kind = -1;   /* the cache cannot be written; re-read it */
            return -1;
        }
        int rc = cfs_block_write(c, sec, sizeof(sec), 0);
        c->part_kind = -1;   /* force re-parse, whether or not the write landed */
        return rc;
    }
    if (c->part_kind == CFS_PART_GPT) {
        uint64_t sz = cfs_block_size(c);
        uint64_t grow = 1ULL << 20;   /* 1MB: roomy minimum (≥ 34+33 sectors) */
        if (sz < grow) {
            if (cfs_block_resize(c, grow) != 0) { c->part_kind = -1; return -1; }
            sz = grow;
        }
        uint64_t sectors = sz / MBR_SECTOR_SIZE;
        if (sectors < GPT_MIN_DISK_SECT) { c->part_kind = -1; return -1; }

        size_t back_len = GPT_ENTRIES_BYTES + MBR_SECTOR_SIZE;   /* entries + header */
        uint8_t *lba0    = malloc(MBR_SECTOR_SIZE);
        uint8_t *hdr     = malloc(MBR_SECTOR_SIZE);              /* primary header */
        uint8_t *bhdr    = malloc(MBR_SECTOR_SIZE);              /* backup header */
        uint8_t *entries = malloc(GPT_ENTRIES_BYTES);
        uint8_t *prim    = malloc(GPT_TABLE_BYTES);              /* LBA1..LBA33 */
        uint8_t *oldprim = malloc(GPT_TABLE_BYTES);
        uint8_t *back    = malloc(back_len);
        uint8_t *oldback = malloc(back_len);
        if (!lba0 || !hdr || !bhdr || !entries || !prim || !oldprim || !back || !oldback) {
            free(lba0); free(hdr); free(bhdr); free(entries);
            free(prim); free(oldprim); free(back); free(oldback);
            c->part_kind = -1;
            return -1;
        }

        uint64_t backup_lba = sectors - 1;
        uint64_t backup_off = backup_lba * MBR_SECTOR_SIZE - GPT_ENTRIES_BYTES;

        gpt_build(lba0, hdr, entries, c->part_cache, c->part_n, sectors);

        /* Backup header: same table, located at the last LBA and pointing at
         * the backup entry array (32 sectors before it). */
        memcpy(bhdr, hdr, MBR_SECTOR_SIZE);
        GptHeader *bh = (GptHeader *)bhdr;
        le64w((uint8_t *)&bh->cur_lba, backup_lba);
        le64w((uint8_t *)&bh->backup_lba, 1);
        le64w((uint8_t *)&bh->entries_lba, backup_lba - GPT_ENTRIES_BYTES / MBR_SECTOR_SIZE);
        le32w((uint8_t *)&bh->hdr_crc, 0);
        le32w((uint8_t *)&bh->hdr_crc, cfs_crc32(bhdr, 92));

        memcpy(prim, hdr, MBR_SECTOR_SIZE);
        memcpy(prim + MBR_SECTOR_SIZE, entries, GPT_ENTRIES_BYTES);
        memcpy(back, entries, GPT_ENTRIES_BYTES);
        memcpy(back + GPT_ENTRIES_BYTES, bhdr, MBR_SECTOR_SIZE);

        /* Snapshot the current table for rollback. */
        if (cfs_block_read(c, oldprim, GPT_TABLE_BYTES, 0) != (ssize_t)GPT_TABLE_BYTES ||
            cfs_block_read(c, oldback, back_len, (off_t)backup_off) != (ssize_t)back_len) {
            free(lba0); free(hdr); free(bhdr); free(entries);
            free(prim); free(oldprim); free(back); free(oldback);
            c->part_kind = -1;
            return -1;
        }

        int rc = 0, try_back = 1, try_prim = 0, try_mbr = 0;
        if (cfs_block_write(c, back, back_len, (off_t)backup_off) != 0) rc = -1;
        else {
            try_prim = 1;
            if (cfs_block_write(c, prim, GPT_TABLE_BYTES - MBR_SECTOR_SIZE,
                                MBR_SECTOR_SIZE) != 0) rc = -1;
            else {
                try_mbr = 1;
                if (cfs_block_write(c, lba0, MBR_SECTOR_SIZE, 0) != 0) rc = -1;
            }
        }
        if (rc != 0) {
            /* Restore newest-first, primary before the protective MBR: a
             * reader that re-parses mid-rollback must still see LBA0 and the
             * header agree.  Best effort — a failed attempt left the old
             * bytes in place anyway (the quota check precedes the write). */
            if (try_prim)
                cfs_block_write(c, oldprim + MBR_SECTOR_SIZE,
                                GPT_TABLE_BYTES - MBR_SECTOR_SIZE, MBR_SECTOR_SIZE);
            if (try_back)
                cfs_block_write(c, oldback, back_len, (off_t)backup_off);
            if (try_mbr)
                cfs_block_write(c, oldprim, MBR_SECTOR_SIZE, 0);
        }
        free(lba0); free(hdr); free(bhdr); free(entries);
        free(prim); free(oldprim); free(back); free(oldback);
        c->part_kind = -1;   /* re-parse: table may be old or new, never mixed */
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
    if (offset < 0) return -1;
    /* EOF is a short read of zero bytes, not an error: pread(2) semantics,
     * and the block layer cannot express a zero-length read (it returns -1). */
    uint64_t off = (uint64_t)offset;
    if (off >= p.size) return 0;
    size_t n = size;
    if (n > p.size - off) n = (size_t)(p.size - off);   /* no offset+size overflow */
    if (n == 0) return 0;
    return cfs_block_read(c, buf, n, (off_t)(p.start + off));
}

int cfs_part_write(CFS *c, int idx, const void *buf, size_t size, off_t offset) {
    CfsPartition p;
    if (!c || !buf || part_load(c) != 0 || cfs_part_get(c, idx, &p) != 0) return -1;
    if (offset < 0) return -1;
    uint64_t off = (uint64_t)offset;
    if (off > p.size || size > p.size - off) return -1;   /* overflow-safe */
    return cfs_block_write(c, buf, size, (off_t)(p.start + off));
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

/* [a0, a0+asz) and [b0, b0+bsz) overlap?  Subtraction keeps the comparison
 * inside 64 bits even when either range reaches the top of the address
 * space; the naive `a0 + asz > b0` form wraps there. */
static int ranges_overlap(uint64_t a0, uint64_t asz, uint64_t b0, uint64_t bsz) {
    if (asz == 0 || bsz == 0) return 0;
    return a0 <= b0 ? (b0 - a0 < asz) : (a0 - b0 < bsz);
}

int cfs_part_add(CFS *c, uint64_t start, uint64_t size,
                 uint8_t mbr_type, const char *guid, int bootable) {
    if (!c || !(c->flags & CFS_RDWR)) return -1;
    if (part_load(c) != 0) return -1;
    if (c->part_kind == CFS_PART_NONE) return -2;   /* no table: run partlabel first */

    if (start % MBR_SECTOR_SIZE || size % MBR_SECTOR_SIZE) return -3;   /* 512B alignment */
    if (size == 0) return -3;
    uint64_t disk = cfs_block_size(c);
    /* Written without start+size so a wrapped sum cannot look in-bounds. */
    if (start >= disk || size > disk - start) return -4;   /* out of disk */

    /* A partition must not cover the table that describes it: LBA0 for MBR,
     * LBA0-33 and the backup copy in the last 33 sectors for GPT.  Writing
     * to such a partition would erase the table (and, for GPT, its backup). */
    if (c->part_kind == CFS_PART_MBR) {
        if (start < (uint64_t)MBR_FIRST_USABLE * MBR_SECTOR_SIZE) return -8;
        /* MBR stores both fields as 32-bit sector counts.  Refuse before
         * mbr_build truncates: a truncated start parses back as LBA 0. */
        uint64_t first_sect = start / MBR_SECTOR_SIZE;
        uint64_t n_sect     = size / MBR_SECTOR_SIZE;
        if (first_sect > 0xFFFFFFFFull || n_sect > 0xFFFFFFFFull ||
            first_sect + n_sect - 1 > 0xFFFFFFFFull) return -9;
    } else {
        uint64_t disk_sect = disk / MBR_SECTOR_SIZE;
        uint64_t first_sect = start / MBR_SECTOR_SIZE;
        uint64_t n_sect = size / MBR_SECTOR_SIZE;
        if (disk_sect < GPT_MIN_DISK_SECT) return -8;
        uint64_t last_usable = disk_sect - GPT_LAST_USABLE_RESERVE;   /* inclusive */
        if (first_sect < GPT_FIRST_USABLE ||
            first_sect + n_sect - 1 > last_usable) return -8;
    }
    if (c->part_kind == CFS_PART_MBR && c->part_n >= MBR_PART_ENTRIES) return -5;
    if (c->part_kind == CFS_PART_GPT && c->part_n >= GPT_ENTRIES_MAX) return -5;

    for (int i = 0; i < c->part_n; i++) {
        if (ranges_overlap(start, size, c->part_cache[i].start,
                           c->part_cache[i].size)) return -6;   /* overlap */
    }
    /* start is in bytes; the 1MiB alignment test is on the byte offset. */
    if (start % (1ULL << 20) != 0)
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
        const char *tn = NULL;
        const uint8_t *tg = gpt_guid_for_type(mbr_type, &tn);
        snprintf(p->type_str, sizeof(p->type_str), "%s", tn);
        uint8_t gb[16];
        if (guid) {
            if (guid_from_str(guid, gb) != 0) return -7;
        } else {
            memcpy(gb, tg, 16);
        }
        guid_to_str(gb, p->guid);
    }
    c->part_n++;
    if (part_save(c) != 0) { cfs_part_invalidate(c); return -1; }
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
    if (part_save(c) != 0) { cfs_part_invalidate(c); return -1; }
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
                if (guid) {
                    if (guid_from_str(guid, gb) == 0)
                        guid_to_str(gb, p->guid);
                } else if (mbr_type != MBR_TYPE_EMPTY) {
                    /* `parttype <cfs> <n> efi` on GPT: the CLI has only the
                     * type name, so resolve it here instead of doing nothing. */
                    const char *tn = NULL;
                    const uint8_t *tg = gpt_guid_for_type(mbr_type, &tn);
                    memcpy(gb, tg, 16);
                    guid_to_str(gb, p->guid);
                    snprintf(p->type_str, sizeof(p->type_str), "%s", tn);
                }
            }
            if (bootable >= 0) p->bootable = bootable ? 1 : 0;
            return part_save(c);
        }
    }
    return -3;
}
