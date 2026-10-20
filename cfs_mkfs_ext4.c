/* cfs_mkfs_ext4 — Self-contained ext4 formatter.
 * Builds the entire metadata in memory, writes once via cfs_block_write. */

#include "cfs.h"
#include "cfs_format.h"
#include "cfs_ext4.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

/* 8 x block_size for 4K blocks — ext4's hard cap on blocks per group */
#define EXT4_BPG 32768u
#define EXT4_IPG 2048u    /* inodes per group */

/* Sparse-super rule: group 0, group 1, and groups that are powers of 3, 5
 * or 7 carry a backup superblock and group descriptor table.  A group that
 * needs one starts with [super][GDT] before its own bitmaps. */
static int ext4_has_super(uint32_t g) {
    if (g <= 1) return 1;
    for (uint64_t b = 3; b <= g; b *= 3) if (b == g) return 1;
    for (uint64_t b = 5; b <= g; b *= 5) if (b == g) return 1;
    for (uint64_t b = 7; b <= g; b *= 7) if (b == g) return 1;
    return 0;
}

static void uuid_gen(uint8_t out[16]) {
    uint64_t t = (uint64_t)time(NULL);
    uint32_t p = (uint32_t)getpid();
    memset(out, 0, 16);
    memcpy(out, &t, 8); memcpy(out + 8, &p, 4);
    out[6] = (out[6] & 0x0F) | 0x40;
    out[8] = (out[8] & 0x3F) | 0x80;
}

int cfs_mkfs_ext4(CFS *c, uint64_t disk_sz) {
    return cfs_mkfs_ext4_at(c, 0, disk_sz);
}

int cfs_mkfs_ext4_at(CFS *c, uint64_t base_off, uint64_t size) {
    if (!c || size < 262144) return -1;

    const uint32_t bs = 4096;
    uint32_t bc = (uint32_t)(size / bs);
    if (bc < 64) return -1;
    /* Establish the capacity BEFORE the first write.  The declared size is a
     * hard limit (cfs_block_write refuses anything past it), so a formatter
     * that wrote first and resized at the end would have every write
     * refused — the CLI path only worked because cfs-tool resized for it. */
    if (cfs_block_resize(c, base_off + size) != 0) return -1;
    /* A block group holds at most 8 x block_size blocks (32768 with 4K
     * blocks).  Cramming a larger filesystem into one group is what made
     * e2fsck call the superblock corrupt, so past that we lay out real
     * groups: each carries its own bitmaps and inode table at the start of
     * the group, which is where e2fsck insists on finding them. */
    uint32_t groups  = (bc + EXT4_BPG - 1) / EXT4_BPG;
    uint32_t ipg     = EXT4_IPG;                        /* inodes per group */
    uint32_t ic      = ipg * groups;
    uint32_t itab_b  = (ipg * 256 + bs - 1) / bs;       /* inode table blocks */
    /* Without the 64bit feature the descriptors are 32 bytes each — the
     * s_desc_size field is only honoured when 64bit is set, so spacing them
     * 64 wide makes every group past the first read half of the descriptor
     * before it (which is how group 1's bitmap "became" block 0). */
    uint32_t dsz     = 32;
    uint32_t gdt_b   = (groups * dsz + bs - 1) / bs;    /* descriptor blocks */
    /* group 0: [0] superblock, [1..gdt_b] descriptors, then its own bitmaps
     * and inode table, then the root directory */
    uint32_t bmp_b   = 1 + gdt_b;
    uint32_t ibmp_b  = bmp_b + 1;
    uint32_t itab0_b = ibmp_b + 1;
    uint32_t root_b  = itab0_b + itab_b;
    uint32_t g0_used = root_b + 1;                      /* blocks 0..root_b */
    uint32_t meta_sz = g0_used * bs;

    uint8_t *img = calloc(1, meta_sz);
    if (!img) return -1;

    uint64_t free_b = 0;
    for (uint32_t g = 0; g < groups; g++) {
        uint32_t gstart  = g * EXT4_BPG;
        uint32_t gblocks = bc - gstart < EXT4_BPG ? bc - gstart : EXT4_BPG;
        uint32_t used    = (g == 0) ? g0_used
                         : (ext4_has_super(g) ? 1 + gdt_b : 0) + 2 + itab_b;
        if (used > gblocks) { free(img); return -1; }
        free_b += gblocks - used;
    }

    /* Superblock at offset 1024 */
    Ext4Super sb; memset(&sb, 0, sizeof(sb));
    sb.s_inodes_count      = ic;
    sb.s_blocks_count_lo   = bc;
    sb.s_free_blocks_count_lo = (uint32_t)free_b;
    /* inodes 1..10 are reserved (s_first_ino); 2 is the root directory */
    sb.s_free_inodes_count = ic - 10;
    sb.s_first_data_block  = 0;
    sb.s_log_block_size    = 2; /* 4KB */
    sb.s_log_cluster_size  = 2;
    sb.s_blocks_per_group  = EXT4_BPG;
    sb.s_clusters_per_group = EXT4_BPG;   /* must equal blocks_per_group; 0 makes
                                           * e2fsck call the superblock corrupt
                                           * before it looks at anything else */
    sb.s_inodes_per_group  = ipg;
    sb.s_magic       = 0xEF53;
    sb.s_state       = 1;   /* EXT4_VALID_FS — no journal, clean state */
    sb.s_errors      = 1;
    sb.s_creator_os  = 0;
    sb.s_rev_level   = 1;
    sb.s_first_ino   = 11;  /* first non-reserved inode (dynamic rev) */
    sb.s_inode_size  = 256;
    sb.s_min_extra_isize  = 32;
    sb.s_want_extra_isize = 32;
    sb.s_block_group_nr = 0;
    /* compat = EXT_ATTR only. HAS_JOURNAL was set but no journal inode
     * exists — kernels reject such a mount. No-journal (ext2-style)
     * filesystem is fully mountable by ext4. */
    sb.s_feature_compat   = 0x0008;
    sb.s_feature_incompat = 0x0002 | 0x0040;
    /* ro_compat bits must all be defined features: an undefined bit makes
     * e2fsck refuse the filesystem outright ("unsupported feature"). */
    sb.s_feature_ro_compat= 0x0001 | 0x0002 | 0x0008 | 0x0020 | 0x0040;
    uuid_gen(sb.s_uuid);
    snprintf(sb.s_volume_name, 16, "cfs-disk");
    sb.s_desc_size   = 32;
    sb.s_mkfs_time   = (uint32_t)time(NULL);
    sb.s_flags       = 0x0002;
    memcpy(img + 1024, &sb, sizeof(sb));

    /* One descriptor per group (32 bytes each — see dsz above) */
    for (uint32_t g = 0; g < groups; g++) {
        uint32_t gstart  = g * EXT4_BPG;
        uint32_t gblocks = bc - gstart < EXT4_BPG ? bc - gstart : EXT4_BPG;
        uint32_t used    = (g == 0) ? g0_used
                         : (ext4_has_super(g) ? 1 + gdt_b : 0) + 2 + itab_b;
        uint32_t meta = (g == 0) ? 1 + gdt_b : gstart + (ext4_has_super(g) ? 1 + gdt_b : 0);
        Ext4BgDesc bgd; memset(&bgd, 0, sizeof(bgd));
        bgd.bg_block_bitmap_lo = (g == 0) ? bmp_b  : meta;
        bgd.bg_inode_bitmap_lo = (g == 0) ? ibmp_b : meta + 1;
        bgd.bg_inode_table_lo  = (g == 0) ? itab0_b : meta + 2;
        bgd.bg_free_blocks_count_lo = (uint16_t)(gblocks - used);
        bgd.bg_free_inodes_count_lo = (uint16_t)(g == 0 ? ipg - 10 : ipg);
        bgd.bg_used_dirs_count = (g == 0) ? 1 : 0;
        memcpy(img + (uint64_t)bs + (uint64_t)g * dsz, &bgd, dsz);
    }

    /* Group 0 block bitmap: its metadata + the root directory, then padding */
    for (uint32_t i = 0; i < g0_used; i++)
        img[bmp_b * bs + i / 8] |= (uint8_t)(1 << (i % 8));
    for (uint32_t i = (groups == 1 ? bc : EXT4_BPG); i < bs * 8; i++)
        img[bmp_b * bs + i / 8] |= (uint8_t)(1 << (i % 8));

    /* Group 0 inode bitmap: reserved inodes 1..10, then padding */
    img[ibmp_b * bs + 0] = 0xFF;   /* inodes 1..8 */
    img[ibmp_b * bs + 1] = 0x03;   /* inodes 9,10 */
    for (uint32_t i = ipg; i < bs * 8; i++)
        img[ibmp_b * bs + i / 8] |= (uint8_t)(1 << (i % 8));

    /* Root inode (inode 2 = index 1) in group 0's inode table */
    Ext4Inode ri; memset(&ri, 0, sizeof(ri));
    ri.i_mode       = 0x41ED;
    ri.i_size_lo    = bs;
    ri.i_links_count= 2;
    ri.i_flags      = 0x00080000;
    ri.i_extra_isize= 32;
    uint64_t now = (uint64_t)time(NULL);
    ri.i_atime = (uint32_t)now; ri.i_ctime = (uint32_t)now;
    ri.i_mtime = (uint32_t)now; ri.i_crtime = (uint32_t)now;
    ri.i_blocks_lo = (bs + 511) / 512;
    /* Extent header: magic | entries=1, max=4, depth=0, gen=0 */
    ri.i_block[0] = 0xF30A | (1u << 16);
    ri.i_block[1] = 4;
    ri.i_block[2] = 0;
    /* Extent entry: ee_block=0, ee_len=1, ee_start_hi=0, ee_start_lo=root_b */
    ri.i_block[3] = 0;
    ri.i_block[4] = 1;
    ri.i_block[5] = root_b;
    memcpy(img + itab0_b * bs + 1 * 256, &ri, sizeof(ri));

    /* Root directory at root_b */
    Ext4DirEntry *d1 = (Ext4DirEntry*)(img + root_b * bs);
    d1->inode = 2; d1->rec_len = 12; d1->name_len = 1; d1->file_type = 2; d1->name[0] = '.';
    Ext4DirEntry *d2 = (Ext4DirEntry*)(img + root_b * bs + 12);
    d2->inode = 2; d2->rec_len = (uint16_t)(bs - 12); d2->name_len = 2;
    d2->file_type = 2; d2->name[0] = '.'; d2->name[1] = '.';

    /* Write group 0's metadata at the partition base.  img stays alive: the
     * descriptor block is copied into every backup GDT below. */
    int rc = cfs_block_write(c, img, meta_sz, (off_t)base_off);
    if (rc != 0) { free(img); return -1; }

    /* Every other group: optional backup superblock + GDT, then its own
     * bitmaps.  The inode table is left as a hole — the block layer reads
     * holes back as zeros, which is what a fresh inode table holds. */
    /* buffer must hold [backup super][backup GDT][block bitmap][inode bitmap] */
    uint32_t gsz = ((1 + gdt_b) + 2) * bs;
    uint8_t *gb = calloc(1, (size_t)gsz);
    if (!gb) return -1;
    for (uint32_t g = 1; g < groups; g++) {
        uint32_t gstart  = g * EXT4_BPG;
        uint32_t gblocks = bc - gstart < EXT4_BPG ? bc - gstart : EXT4_BPG;
        int sup = ext4_has_super(g);
        uint32_t meta = (uint32_t)(sup ? 1 + gdt_b : 0);
        memset(gb, 0, gsz);
        if (sup) {                      /* backup superblock + descriptor table */
            Ext4Super bsb = sb;
            bsb.s_block_group_nr = (uint16_t)g;
            memcpy(gb + 1024, &bsb, sizeof(bsb));
            memcpy(gb + bs, img + bs, (size_t)gdt_b * bs);
        }
        /* its own bitmaps sit after the backup, indexed within the group */
        for (uint32_t i = 0; i < meta + 2 + itab_b; i++)
            gb[meta * bs + i / 8] |= (uint8_t)(1 << (i % 8));
        for (uint32_t i = gblocks; i < bs * 8; i++)
            gb[meta * bs + i / 8] |= (uint8_t)(1 << (i % 8));
        for (uint32_t i = ipg; i < bs * 8; i++)
            gb[(meta + 1) * bs + i / 8] |= (uint8_t)(1 << (i % 8));
        if (cfs_block_write(c, gb, (meta + 2) * bs,
                            (off_t)(base_off + (uint64_t)gstart * bs)) != 0) {
            free(gb); return -1;
        }
    }
    free(gb);
    free(img);

    return 0;   /* the capacity was set before the first write */
}
