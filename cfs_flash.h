#ifndef CFS_FLASH_H
#define CFS_FLASH_H
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CFS is declared the same way in cfs.h; a repeated typedef of one struct type
 * is legal in C11 and lets either header be included first. */
typedef struct CFS CFS;

/* ── Flash media ────────────────────────────────────────────────
 * A medium lives in the container as "@flash.<tag>": one contiguous, 4 KiB
 * aligned, uncompressed range (see cfs_format.h for the on-disk shape).  It
 * is deliberately not a file: cfs_read()/cfs_write() refuse it, so nobody can
 * pretend compressed-file semantics apply.  Access is through this API only.
 *
 * Two families, distinguished by cfs_format.h's F_MANAGED flag:
 *
 *   raw (nor / nand / mcu)   erase blocks and page programming.  write()
 *                            requires the target bytes to be in the erased
 *                            state and may only clear bits (1 -> 0); it may
 *                            not cross a program page.  NAND additionally
 *                            programs whole pages.  Violations fail.
 *   managed (emmc / sd)      an FTL sits behind the controller: plain sector
 *                            writes, no erase model.  Reserved; the API
 *                            accepts the flag but v1 cannot create one.
 *
 * Nothing here is compressed, deduplicated or copy-on-write: a write lands in
 * the container's bytes at that offset, visible to every other reader, the
 * way a physical medium behaves. */

typedef struct CfsFlash CfsFlash;

typedef struct {
    uint64_t size;        /* guest-visible bytes */
    uint32_t sector;      /* controller sector (usually 512) */
    uint32_t page;        /* program page (raw) / write granule (managed) */
    uint32_t erase;       /* erase block size */
    uint32_t write_gran;  /* raw: == page; managed: sector */
    int      erased_byte; /* 0xFF for NOR/NAND/MCU */
    int      media;       /* CFS_FLASH_NOR/NAND/EMMC/MCU */
} CfsFlashGeom;

/* ── Lifecycle ───────────────────────────────────────────────────
 * `tag` is either "uefi" (resolved to "@flash.uefi") or the full entry name.
 * A writable handle is required for write/erase; reads and maps work on
 * either.  open() takes no container lock of its own: the CFS handle already
 * carries the container's lock.  Closing the CFS handle first is memory-safe
 * (the open-handle count is shared, not owned by the CFS struct), but it
 * releases that lock — after it, another process may write or compact, so
 * keep the CFS handle open for as long as the medium must be stable.
 * cfs_compact() refuses with EBUSY while any handle is open, because it
 * replaces the file and moves the extents.  Two handles on one medium are
 * safe for I/O, but concurrent descriptor updates (erase counters, bad
 * blocks) can lose one another; close one before updating through another. */
CfsFlash *cfs_flash_open (CFS *c, const char *tag, int writable);
void      cfs_flash_close(CfsFlash *f);

/* Create a medium.  `flags` takes CFS_FLASH_F_* from cfs_format.h; F_XIP
 * makes cfs_compact() refuse the container.  The extent is allocated at the
 * end of the container, page aligned, physically filled with
 * geom->erased_byte, and only then committed — a crash in between leaves an
 * unreferenced range, never a medium that reads as zeros.  Returns 0 on
 * success, CFS_ENOSPC when the physical quota has no room, or -1 with errno
 * (EEXIST, EINVAL, EOPNOTSUPP on v1 managed media).  A -1 caused by a
 * failure AFTER the superblock slot was written (fsync) still leaves the
 * medium in the container: the handle keeps it so memory matches disk, and a
 * retry reports EEXIST. */
int       cfs_flash_create(CFS *c, const char *tag, const CfsFlashGeom *g,
                           unsigned flags);

/* ── Geometry ───────────────────────────────────────────────────
 * The four values must match what the guest's controller reports.  Any
 * pointer may be NULL. */
int       cfs_flash_geometry(CfsFlash *f, uint64_t *size, uint32_t *sector,
                             uint32_t *erase_block, uint32_t *write_gran);

/* Read-only device facts the geometry call does not carry: media type, the
 * erased byte, the descriptor flags (CFS_FLASH_F_*), how many erase
 * operations this API has performed, and how many bad blocks are recorded.
 * Any pointer may be NULL. */
int       cfs_flash_info(CfsFlash *f, int *media, int *erased_byte,
                         unsigned *flags, uint64_t *erase_count,
                         uint32_t *bad_count);

/* ── I/O ────────────────────────────────────────────────────────
 * read:  arbitrary offset/length inside the medium.
 * write: real flash programming.  Returns len, or -1 with errno:
 *        EINVAL  range out of bounds, crosses a page, or unaligned in a way
 *                the medium does not allow;
 *        EIO     a target byte is not in the erased state, the write would
 *                turn a 0 back into a 1, or the range touches a bad block;
 *        EROFS   handle opened read-only.
 * erase: offset and length must be whole erase blocks; fills erased_byte.
 *        Returns 0 or -1 (EINVAL, EIO for a bad block, EROFS). */
ssize_t   cfs_flash_read (CfsFlash *f, uint64_t off, void *buf, size_t len);
ssize_t   cfs_flash_write(CfsFlash *f, uint64_t off, const void *buf, size_t len);
int       cfs_flash_erase(CfsFlash *f, uint64_t off, size_t len);

/* msync the mapping (when one exists) and fsync the container.  Writes are
 * visible to readers immediately; this is the durability barrier.  Also
 * called by cfs_flash_close(), which ignores its result. */
int       cfs_flash_flush(CfsFlash *f);

/* ── XIP ────────────────────────────────────────────────────────
 * map() returns a host pointer into a MAP_SHARED mapping of the container
 * file, at the requested offset.  The mapping is cached per handle and
 * dropped on close.  Out-of-range requests return NULL with errno=EINVAL.
 * *writable is 1 only when the handle is writable.
 *
 * extent() is the primitive underneath: the handle's own descriptor (do NOT
 * close it), the file offset of guest byte 0 (page aligned) and the medium
 * length, so a caller that must place the bytes at a specific host address
 * (a guest physical address) can mmap() the file itself.  Neither function
 * moves any data.  A caller's mapping is valid only while the handle is
 * open: closing it does not unmap the caller's mapping, but the handle (and
 * compact, which needs no live handles) is what keeps the extent's offset
 * meaningful.
 *
 * A WRITABLE mapping bypasses the programming rules: stores through it land
 * in the page cache without cfs seeing them.  Map read-only and write
 * through cfs_flash_write() when the 1->0 / erased-target rules have to
 * hold; map writable only when the consumer owns the medium's semantics. */
void     *cfs_flash_map   (CfsFlash *f, uint64_t off, size_t len, int *writable);
int       cfs_flash_extent(CfsFlash *f, int *fd, off_t *file_off, uint64_t *len);

/* ── Bad blocks ─────────────────────────────────────────────────
 * v1 records them and makes operations on them fail; it does not remap.
 * bad_set() writes the descriptor (both copies stay valid); the list is
 * capped by CFS_FLASH_D_BAD_MAX entries (496) because it lives in the
 * 4 KiB descriptor. */
int       cfs_flash_is_bad(CfsFlash *f, uint64_t off);
int       cfs_flash_bad_set(CfsFlash *f, uint32_t block, int bad);

/* ── Profiles ───────────────────────────────────────────────────
 * "nor", "nand", "emmc", "mcu" fill a CfsFlashGeom with the defaults from
 * USAGE.md and set CFS_FLASH_F_MANAGED for emmc.  Returns 0 or -1 (EINVAL
 * for an unknown name). */
int       cfs_flash_profile(const char *type, CfsFlashGeom *g, unsigned *flags);

/* Library-internal helpers shared with cfs.c/cfs_verify.c. */
int       cfs_flash_entry_tag_ok(const char *tag);
int       cfs_flash_any_xip(CFS *c);   /* 1 = some medium forbids compact */
/* The alignment a flash extent needs on this host: max(4096, page size).
 * cfs_compact() uses it so a moved extent stays mappable. */
uint64_t  cfs_flash_align(void);

#ifdef __cplusplus
}
#endif
#endif /* CFS_FLASH_H */
