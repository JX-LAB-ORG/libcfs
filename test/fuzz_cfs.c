/* fuzz_cfs.c — libFuzzer target for the container parser.
 *
 * The decoder fuzzer covers one block.  This covers everything above it: a
 * container written by anyone, opened by cfs_open(), walked, read and
 * self-checked.  The contract is the same shape — malformed input is
 * rejected, never trusted — but the attack surface is much wider: the
 * superblock, the inode table, every block table, the reference tables, the
 * partition cache and the block device.
 *
 * Buffers that the library fills are placed against PROT_NONE guard pages,
 * because AddressSanitizer cannot run here (PRoot's address-space emulation
 * rejects its shadow map).  cfs_verify() gets the same bytes and is expected
 * to survive them too: it is the tool that will be pointed at a damaged
 * container first.
 */
#define _GNU_SOURCE
#include "../cfs.h"
#include "../cfs_format.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#define PG 4096u
#define TMP "/tmp/fuzz_cfs.cfs"
#define MAX_READ (64u << 10)   /* deep decode has its own target */

static uint8_t *guard_buf(size_t len, size_t *map_len, void **map_base) {
    size_t pages = (len + PG - 1) / PG;
    if (pages == 0) pages = 1;
    size_t total = (pages + 2) * PG;
    uint8_t *base = mmap(NULL, total, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return NULL;
    mprotect(base, PG, PROT_NONE);
    mprotect(base + (pages + 1) * PG, PG, PROT_NONE);
    *map_len = total;
    *map_base = base;
    return base + PG + pages * PG - len;
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    if (n < CFS_SB_SIZE || n > (4u << 20)) return 0;

    int fd = open(TMP, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return 0;
    if (write(fd, d, n) != (ssize_t)n) { close(fd); return 0; }
    close(fd);

    /* Read-only walk: whatever opens, we list, stat and read. */
    CFS *c = cfs_open(TMP, CFS_RDONLY);
    if (c) {
        CfsDirEntry ents[64];
        int ne = cfs_ls(c, "/", ents, 64);
        for (int i = 0; i < ne && i < 64; i++) {
            char path[300];
            snprintf(path, sizeof(path), "/%s", ents[i].name);
            CfsStat st;
            if (cfs_stat(c, path, &st) != 0) continue;
            if (st.mode != CFS_MODE_FILE && st.mode != CFS_MODE_DEDUP) continue;
            size_t want = st.size < MAX_READ ? (size_t)st.size : MAX_READ;
            if (!want) continue;
            size_t ml; void *mb;
            uint8_t *buf = guard_buf(want, &ml, &mb);
            if (!buf) continue;
            cfs_read(c, path, buf, want, 0);
            munmap(mb, ml);
        }
        /* the device layer and the block hook go through these */
        (void)cfs_block_size(c);
        CfsDiskAttrs da; (void)cfs_disk_get(c, &da);
        (void)cfs_part_count(c);
        cfs_close(c);
    }

    /* The self-check has to survive the same bytes: it is what gets pointed
     * at a damaged container first, and it parses independently of cfs.c. */
    FILE *nul = fopen("/dev/null", "w");
    if (nul) { cfs_verify(TMP, 0, nul);   /* structure only: the decoder is fuzzed separately */ fclose(nul); }
    else cfs_verify(TMP, 0, stderr);

    unlink(TMP);
    return 0;
}
