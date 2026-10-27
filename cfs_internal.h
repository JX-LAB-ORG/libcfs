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

/* Shared count of open flash handles.  It lives outside the CFS struct so a
 * flash handle can be closed after cfs_close() without touching freed
 * memory: cfs_close frees it when no handle remains, otherwise the last
 * handle does.  (The container lock still ends at cfs_close, which is why a
 * handle is only a reader once its CFS handle is gone.) */
typedef struct { int n; int orphan; } CfsFlashRef;

/* Commit the in-memory inode table (data → table → non-live slot → fsync).
 * Internal, but cfs_flash.c creates its entry directly and must use the same
 * commit path as every other writer. */
int cfs_sync(CFS *c);

struct CFS {
    int           fd;
    int           flags;
    char         *cpath;      /* the container's own path, for scratch files */
    CfsSuperBlock sb;
    CfsStats      st;
    InodeEntry   *inodes;
    uint32_t      inode_count;

    /* ── Crash-consistency state ──────────────────────────────────
     * Two superblock slots, each in its own 512-byte sector: slot 0 at 0,
     * slot 1 at CFS_SB_SLOT_SIZE.  sb_slot is the slot written last (the
     * live one), sb_seq its sequence.  slot_off/slot_size describe the table
     * each valid slot points at, so a commit knows which region is live and
     * which is the older copy it may overwrite.
     *
     * append_off is the next byte a data block may occupy.  It is always at
     * or past the end of both slots' tables, so an append can overwrite
     * neither the live table nor the other slot's table (which a crash
     * fallback needs).  c->sb.inode_offset is the *live* table, not a
     * cursor: it moves only after a new table and its slot have landed. */
    uint32_t      sb_seq;
    int           sb_slot;
    int           slot_valid[CFS_SB_SLOTS];
    uint64_t      slot_off[CFS_SB_SLOTS];
    uint32_t      slot_size[CFS_SB_SLOTS];
    uint64_t      append_off;
    int           legacy;     /* opened from a v2 record: upgrade on first sync */

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
    /* Set while dedup_pend_flush() is inside store_append().  store_append()
     * ends with cfs_sync(), which re-enters the flush; the nested call must
     * not append the same buffer a second time.  The bytes stay in pend_* (
     * they are cleared only once the append has landed), so without this the
     * sync would recurse forever. */
    int           pend_flushing;

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

    /* Set by cfs_sync() once the non-live superblock slot has been written.
     * A failure after that point (fsync) means the container still describes
     * the new state; callers that would otherwise roll back in memory use
     * this to avoid making the handle disagree with the file. */
    int           last_commit_landed;

    /* Open CfsFlash handles on this container.  cfs_compact() refuses while
     * any is open: compaction replaces the file and moves every extent, and
     * a handle's dup'd fd (and any mmap) would keep pointing at the old
     * inode, so later writes would land where nothing reads them. */
    CfsFlashRef  *flash_ref;

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
