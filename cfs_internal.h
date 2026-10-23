#ifndef CFS_INTERNAL_H
#define CFS_INTERNAL_H
#include "cfs.h"
#include "cfs_format.h"
#include "cfs_part.h"
#include "cfs_dedup.h"

/* Shared between cfs.c and cfs_part.c */

/* Partition-table region at the front of @block (LBA0-33 for GPT) */
#define CFS_PART_TABLE_BYTES GPT_TABLE_BYTES

typedef struct { char *path; CfsInode raw; } InodeEntry;

struct CFS {
    int           fd;
    int           flags;
    char         *cpath;      /* the container's own path, for scratch files */
    CfsSuperBlock sb;
    CfsStats      st;
    InodeEntry   *inodes;
    uint32_t      inode_count;

    /* Partition-table cache (parsed from @block bytes on demand) */
    int      part_kind;          /* -1 unparsed, CFS_PART_NONE/MBR/GPT */
    int      part_n;
    CfsPartition part_cache[128];
    uint64_t part_wr_gen;        /* bump on writes overlapping the table region */

    /* Merge-layer cache: decoded reference table of the last file touched.
     * dt_path == NULL means nothing is loaded; dt_dirty means the table has
     * in-memory edits that cfs_sync has to write back. */
    CfsDedupTable dt;
    char         *dt_path;
    int           dt_dirty;

    /* Feature index (hash -> store offset).  Not persisted and never built
     * by a separate pass: it is fed by the data that flows through anyway —
     * references walked during reconstruction, and chunks appended on write. */
    CfsFeatIndex  fi;
    int           fi_ready;

    /* Store bytes appended during this session that are not yet flushed. */
    uint8_t      *pend_buf;
    size_t        pend_n, pend_cap;
    uint64_t      pend_off;

    /* Physical quota: the most this container's file may occupy on the host,
     * in bytes (0 = unlimited).  The declared device size says how big the
     * container looks from the inside; this says how much host space the
     * host is willing to give it.  A repetitive archive can expand to
     * terabytes inside while costing almost nothing outside, so the two are
     * deliberately independent — and only the second one protects the host
     * when a small archive carries a lot of *unique* data. */
    uint64_t      phys_limit;

    /* Set when this handle holds the container's advisory lock (see
     * cfs_lock in cfs.c).  Released on close. */
    int           locked;

    /* Bulk-write mode (cfs_set_batch): hold the pending @store bytes and the
     * inode table in memory across writes, so a multi-file import compresses
     * the store in a few large blocks instead of one block per file.  This
     * lengthens (it does not create) the window in which the on-disk table
     * has been overwritten by an append but not yet rewritten; see the API
     * comment.  `dirty` records that the in-memory table has not been written
     * yet, so close() knows to. */
    int           batch;
    int           dirty;
};

#endif /* CFS_INTERNAL_H */
