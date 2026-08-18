#ifndef CFS_INTERNAL_H
#define CFS_INTERNAL_H
#include "cfs.h"
#include "cfs_format.h"
#include "cfs_part.h"

/* Shared between cfs.c and cfs_part.c */

/* Partition-table region at the front of @block (LBA0-33 for GPT) */
#define CFS_PART_TABLE_BYTES GPT_TABLE_BYTES

typedef struct { char *path; CfsInode raw; } InodeEntry;

struct CFS {
    int           fd;
    int           flags;
    CfsSuperBlock sb;
    CfsStats      st;
    InodeEntry   *inodes;
    uint32_t      inode_count;

    /* Partition-table cache (parsed from @block bytes on demand) */
    int      part_kind;          /* -1 unparsed, CFS_PART_NONE/MBR/GPT */
    int      part_n;
    CfsPartition part_cache[128];
    uint64_t part_wr_gen;        /* bump on writes overlapping the table region */
};

#endif /* CFS_INTERNAL_H */
