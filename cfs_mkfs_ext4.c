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

    uint32_t bs = 4096;
    uint32_t bc = (uint32_t)(size / bs);
    uint32_t ic = bc * bs / 16384;
    if (ic < 64) ic = 64;
    uint32_t ib = (ic * 256 + bs - 1) / bs;
    uint32_t oh = 3 + ib;
    uint32_t db = oh; /* root directory data block */
    uint32_t meta_sz = (db + 1) * bs;

    /* Build entire metadata in memory */
    uint8_t *img = calloc(1, meta_sz);
    if (!img) return -1;

    /* Superblock at offset 1024 */
    Ext4Super sb; memset(&sb, 0, sizeof(sb));
    sb.s_inodes_count      = ic;
    sb.s_blocks_count_lo   = bc;
    sb.s_free_blocks_count_lo = bc > oh ? bc - oh - 1 : 0;
    sb.s_free_inodes_count = ic - 2;
    sb.s_first_data_block  = 0;
    sb.s_log_block_size    = 2; /* 4KB */
    sb.s_log_cluster_size  = 2;
    sb.s_blocks_per_group  = bc;
    sb.s_inodes_per_group  = ic;
    sb.s_magic       = 0xEF53;
    sb.s_state       = 1;   /* EXT4_VALID_FS — no journal, clean state */
    sb.s_errors      = 1;
    sb.s_creator_os  = 0;
    sb.s_rev_level   = 1;
    sb.s_first_ino   = 2; /* EXT4_ROOT_INO */
    sb.s_inode_size  = 256;
    sb.s_block_group_nr = 0;
    /* compat = EXT_ATTR only. HAS_JOURNAL was set but no journal inode
     * exists — kernels reject such a mount. No-journal (ext2-style)
     * filesystem is fully mountable by ext4. */
    sb.s_feature_compat   = 0x0008;
    sb.s_feature_incompat = 0x0002 | 0x0040;
    sb.s_feature_ro_compat= 0x0003 | 0x0008 | 0x0040 | 0x0080 | 0x0100;
    uuid_gen(sb.s_uuid);
    snprintf(sb.s_volume_name, 16, "cfs-disk");
    sb.s_desc_size   = 64;
    sb.s_mkfs_time   = (uint32_t)time(NULL);
    sb.s_flags       = 0x0002;
    memcpy(img + 1024, &sb, sizeof(sb));

    /* Group descriptor at offset 2048 (within block 0) */
    Ext4BgDesc bgd; memset(&bgd, 0, sizeof(bgd));
    bgd.bg_block_bitmap_lo = 1;
    bgd.bg_inode_bitmap_lo = 2;
    bgd.bg_inode_table_lo  = 3;
    bgd.bg_free_blocks_count_lo = (uint16_t)(bc > oh ? bc - oh - 1 : 0);
    bgd.bg_free_inodes_count_lo = (uint16_t)(ic - 2);
    bgd.bg_used_dirs_count = 1;
    memcpy(img + 2048, &bgd, sizeof(bgd));

    /* Block bitmap at block 1 */
    for (uint32_t i = 0; i <= db; i++)
        img[1 * bs + i / 8] |= (uint8_t)(1 << (i % 8));

    /* Inode bitmap at block 2: inode 1 (bad blocks) and 2 (root) used */
    img[2 * bs + 0] = 0x06;

    /* Root inode (inode 2 = index 1) at block 3 */
    Ext4Inode ri; memset(&ri, 0, sizeof(ri));
    ri.i_mode       = 0x41ED;
    ri.i_size_lo    = bs;
    ri.i_links_count= 2;
    ri.i_flags      = 0x00080000;
    ri.i_extra_isize= 28;
    uint64_t now = (uint64_t)time(NULL);
    ri.i_atime = (uint32_t)now; ri.i_ctime = (uint32_t)now;
    ri.i_mtime = (uint32_t)now; ri.i_crtime = (uint32_t)now;
    ri.i_blocks_lo = (bs + 511) / 512;
    /* Extent header: magic | entries=1, max=4, depth=0, gen=0 */
    ri.i_block[0] = 0xF30A | (1u << 16);
    ri.i_block[1] = 4;
    ri.i_block[2] = 0;
    /* Extent entry: ee_block=0, ee_len=1, ee_start_hi=0, ee_start_lo=db */
    ri.i_block[3] = 0;
    ri.i_block[4] = 1;
    ri.i_block[5] = db;
    memcpy(img + 3 * bs + 1 * 256, &ri, sizeof(ri));

    /* Root directory at data_block */
    Ext4DirEntry *d1 = (Ext4DirEntry*)(img + db * bs);
    d1->inode = 2; d1->rec_len = 12; d1->name_len = 1; d1->file_type = 2; d1->name[0] = '.';
    Ext4DirEntry *d2 = (Ext4DirEntry*)(img + db * bs + 12);
    d2->inode = 2; d2->rec_len = (uint16_t)(bs - 12); d2->name_len = 2;
    d2->file_type = 2; d2->name[0] = '.'; d2->name[1] = '.';

    /* Write entire metadata to cfs at the partition base */
    int rc = cfs_block_write(c, img, meta_sz, (off_t)base_off);
    free(img);
    if (rc != 0) return -1;

    /* Ensure @block covers the partition end (grow-only) */
    cfs_block_resize(c, base_off + size);
    return 0;
}
