/* cfs_mkfs_swap — Self-contained Linux swap v2 formatter.
 * Writes the swap header page at a partition base offset via cfs_block_write. */

#include "cfs.h"
#include <string.h>
#include <stdlib.h>

#define SWAP_PAGE_SIZE  4096
#define SWAP_MAGIC      "SWAPSPACE2"
#define SWAP_MAGIC_LEN  10
#define SWAP_MIN_SIZE   (SWAP_PAGE_SIZE * 10)

static void le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

int cfs_mkfs_swap(CFS *c, uint64_t disk_sz) {
    return cfs_mkfs_swap_at(c, 0, disk_sz);
}

int cfs_mkfs_swap_at(CFS *c, uint64_t base_off, uint64_t size) {
    if (!c || size < SWAP_MIN_SIZE || base_off % SWAP_PAGE_SIZE) return -1;
    /* Capacity first: cfs_block_write refuses anything past the declared
     * size, so the formatter must declare it before it writes. */
    /* Grow to fit, but never pass a size below the current capacity: resize
     * is grow-only (a smaller request is refused), and the caller may have
     * declared a device slightly larger than this partition — the GPT tail
     * reserves 34 sectors for the backup table. */
    if (cfs_block_size(c) < base_off + size &&
        cfs_block_resize(c, base_off + size) != 0) return -1;

    /* Linux swap_header_v1 layout inside page 0:
     *   bootbits[1024] | version(1) @1024 | last_page @1028 |
     *   nr_badpages @1032 | uuid[16] @1036 | volume[16] @1052 |
     *   padding/badpages ... | magic[10] @4086 (page tail) */
    uint8_t page[SWAP_PAGE_SIZE];
    memset(page, 0, sizeof(page));
    le32(page + 1024, 1);                        /* version */
    le32(page + 1028, (uint32_t)(size / SWAP_PAGE_SIZE) - 1);  /* last usable page */
    le32(page + 1032, 0);                        /* no bad pages */
    memcpy(page + SWAP_PAGE_SIZE - SWAP_MAGIC_LEN, SWAP_MAGIC, SWAP_MAGIC_LEN);

    if (cfs_block_write(c, page, SWAP_PAGE_SIZE, (off_t)base_off) != 0) return -1;
    return 0;
}
