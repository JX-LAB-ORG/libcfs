#define _GNU_SOURCE
#include "cfs.h"
#include "cfs_part.h"            /* table geometry: 1MiB start, GPT last usable */
#include "cfs_format.h"          /* CFS_VERSION: the on-disk container format */
#include "../libcpool/cpenc.h"   /* CPENC_VERSION, for --version */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

/* Container paths are stored without a leading slash — the FUSE layer strips
 * it on the way in — but on the command line everyone types one.  ls already
 * accepted both, which made the other commands silently not finding
 * "/a.txt" read like a missing file rather than a path form. */
static const char *cpath(const char *p) {
    while (p && *p == '/') p++;
    return p ? p : "";
}

static FILE *usage_fp = NULL;
static void usage(const char *prog) {    FILE *f = usage_fp ? usage_fp : stderr; fprintf(f,
        "Usage: %s <command> [args...]\n"
        "       %s --help | --version\n"
        "\n"
        "Commands:\n"
        "  mount  <cfs>        [mount_pt]   Mount .cfs and spawn shell\n"
        "  pack   <dir>        <out.cfs>    Pack directory into .cfs [--raw]\n"
        "  unpack <cfs>        <path> <out> Extract one file from .cfs\n"
        "  write  <cfs>        <path> <src> Write local file into .cfs\n"
        "  mkfs   <type> <size> <cfs> [-p <n>] [-g] [--disk ssd|hdd|usb|sd]\n"
        "  disktype <cfs> [ssd|hdd|usb|sd]  Query/declare the drive identity\n"
        "  install <iso> <size> <cfs> [-p <n>] [-g]\n"
        "                                  Install ISO content into ext4\n"
        "                                  (mkfs + populate, standalone disk)\n"
        "                                  Format .cfs as ext4/fat32/exfat/swap\n"
        "                                  -p <n>: create <n> partitions, format\n"
        "                                          partition <n>\n"
        "                                  -g:     GPT partition table (with -p)\n"
        "  ls     <cfs>        [dir]        List contents\n"
        "  cat    <cfs>        <path>       Print file to stdout\n"
        "  stat   <cfs>        [path]       Show stats or file info\n"
        "  verify <cfs>        [--deep]     Self-check container structures\n"
        "                                  (superblock, inode/block tables, dedup\n"
        "                                  refs, @store accounting); --deep also\n"
        "                                  decodes every block and re-reads every\n"
        "                                  file through the library\n"
        "  mkdir  <cfs>        <path>       Create directory\n"
        "  rm     <cfs>        <path>       Remove file\n"
        "  mv     <cfs>        <old> <new>  Rename file\n"
        "  symlink <cfs>       <target> <lnk> Create symlink\n"
        "  trunc  <cfs>        <path> <size> Truncate file\n"
        "  compact <cfs>                    Reclaim orphaned blocks\n"
        "  dedup  <cfs>        [--stats] [--dry] [--no-compact] [--gc]\n"
        "                                  Content-addressed merge (dedup);\n"
        "                                  compacts at the end unless --no-compact;\n"
        "                                  --gc reclaims once past the thresholds\n"
        "                                  --stats: print merge statistics\n"
        "                                  --dry:   stats only, do not merge\n"
        "  partlabel <cfs> <mbr|gpt|none> [--force]\n"
        "                                  Create/remove partition table\n"
        "  partadd  <cfs> <type> <start> <end> [--boot] [--guid <GUID>]\n"
        "                                  Add partition (start/end: sectors,\n"
        "                                  or bytes with K/M/G suffix; end incl.)\n"
        "                                  types: linux fat32 fat16 efi swap ntfs 0xNN\n"
        "  partdel  <cfs> <n>              Delete partition\n"
        "  parttype <cfs> <n> <type> [--boot|--no-boot]\n"
        "                                  Change partition type/boot flag\n"
        "  partlist <cfs>                  Print partition table\n"
        "  partwrite <cfs> <n> <src>       Write file into partition\n"
        "  flash init <cfs> <tag> --type nor|nand|mcu|emmc --size 16M\n"
        "                                  Create a flash medium\n"
        "                                  [--page N --erase N --sector N\n"
        "                                   --erased 0xFF] [--xip]\n"
        "  flash info <cfs> <tag>          Show medium geometry and state\n"
        "  flash read <cfs> <tag> <out> [--offset N] [--len N]\n"
        "                                  Extract medium bytes to <out>\n"
        "  flash write <cfs> <tag> <image> [--offset N] [--erase] [--verify]\n"
        "                                  Program <image> page by page\n"
        "  flash erase <cfs> <tag> [--offset N] [--len N]\n"
        "                                  Erase whole blocks (default: whole\n"
        "                                  medium)\n"
        "  flash bad <cfs> <tag> [--list] [--mark N|--clear N]\n"
        "                                  Count/list/mark bad erase blocks\n"
        "\n",
        prog, prog);
}

/* ── partition helpers ─────────────────────────────────────────── */
/* bare integer = 512B sectors; K/M/G suffix = bytes */
static int parse_extent(const char *s, uint64_t *out, int *sector_mode) {
    char *end;
    uint64_t v = strtoull(s, &end, 0);
    if (end == s) return -1;
    if (*end == 0) { *out = v * 512; *sector_mode = 1; }
    else if (*end == 'K' || *end == 'k') { *out = v * 1024; *sector_mode = 0; }
    else if (*end == 'M' || *end == 'm') { *out = v * 1048576; *sector_mode = 0; }
    else if (*end == 'G' || *end == 'g') { *out = v * 1073741824; *sector_mode = 0; }
    else return -1;
    return 0;
}

static int parse_type(const char *s, uint8_t *out) {
    if (!strcmp(s, "linux")) *out = 0x83;
    else if (!strcmp(s, "fat32")) *out = 0x0C;
    else if (!strcmp(s, "fat16")) *out = 0x06;
    else if (!strcmp(s, "efi"))   *out = 0xEF;
    else if (!strcmp(s, "swap"))  *out = 0x82;
    else if (!strcmp(s, "ntfs"))  *out = 0x07;
    else if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        char *end; long v = strtol(s, &end, 16);
        if (*end || v < 0 || v > 255) return -1;
        *out = (uint8_t)v;
    } else return -1;
    return 0;
}

static void fmt_size(char *buf, size_t n, uint64_t v) {
    if (v >= (1ULL << 30)) snprintf(buf, n, "%.1fG", v / 1073741824.0);
    else if (v >= (1ULL << 20)) snprintf(buf, n, "%.1fM", v / 1048576.0);
    else if (v >= 1024) snprintf(buf, n, "%.1fK", v / 1024.0);
    else snprintf(buf, n, "%llu", (unsigned long long)v);
}

/* ── flash helpers ─────────────────────────────────────────────── */
/* A bare number is BYTES for a flash medium.  parse_extent() above reads a
 * bare number as 512-byte sectors, which is the right convention for a
 * partition table and the wrong one for a device geometry: "--size 1024"
 * must mean 1 KiB, not 512 KiB. */
static int parse_flash_size(const char *s, uint64_t *out) {
    if (!s || !*s) return -1;
    char *end;
    errno = 0;
    /* Base 10 unless the literal is explicitly hexadecimal.  Base 0 would
     * turn a leading zero into octal, so "--offset 04096" would silently
     * mean 2118 bytes — and a flash offset is exactly where being wrong is
     * invisible. */
    int base = (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) ? 16 : 10;
    unsigned long long v = strtoull(s, &end, base);
    if (end == s || errno == ERANGE) return -1;
    uint64_t mul = 1;
    if (*end == 'K' || *end == 'k') { mul = 1024ULL; end++; }
    else if (*end == 'M' || *end == 'm') { mul = 1048576ULL; end++; }
    else if (*end == 'G' || *end == 'g') { mul = 1073741824ULL; end++; }
    if (*end) return -1;
    if (v > UINT64_MAX / mul) return -1;
    *out = (uint64_t)v * mul;
    return 0;
}

/* "@flash.<tag>"; a tag that already carries the prefix is left alone, so the
 * CLI and the library agree on what a name means. */
static int flash_path(const char *tag, char *buf, size_t n) {
    int r;
    if (!strncmp(tag, CFS_FLASH_PREFIX, strlen(CFS_FLASH_PREFIX)))
        r = snprintf(buf, n, "%s", tag);
    else
        r = snprintf(buf, n, "%s%s", CFS_FLASH_PREFIX, tag);
    return (r >= 0 && (size_t)r < n) ? 0 : -1;
}

/* Count bad erase blocks, optionally listing them.  cfs_flash_is_bad() takes
 * a byte offset and maps it to its block, so calling it once per block start
 * is the whole scan the v1 API allows. */
static uint64_t flash_bad_scan(CfsFlash *f, uint64_t size, uint32_t erase,
                               int list) {
    uint64_t blocks = size / erase, count = 0;
    for (uint64_t i = 0; i < blocks; i++) {
        if (cfs_flash_is_bad(f, i * erase) != 1) continue;
        count++;
        if (list)
            printf("  bad block %llu (offset %llu)\n",
                   (unsigned long long)i, (unsigned long long)(i * erase));
    }
    return count;
}

static const char *flash_media_name(int media) {
    switch (media) {
    case CFS_FLASH_NOR:  return "nor";
    case CFS_FLASH_NAND: return "nand";
    case CFS_FLASH_EMMC: return "emmc";
    case CFS_FLASH_MCU:  return "mcu";
    default:             return "unknown";
    }
}

/* Program an image one page at a time without ever crossing a page.  NOR and
 * MCU accept a partial page inside the erased region.  NAND programs whole
 * pages only, so a partial page is rewritten from its start with the bytes
 * already there for everything the image does not cover — on an erased page
 * those are the erased byte whatever it is, and on a page that is not erased
 * the library refuses the write (EIO), which is the real device's answer. */
static int flash_program(CfsFlash *f, uint64_t off, const uint8_t *buf,
                         size_t len, uint32_t page, int whole_pages,
                         uint64_t *fail_off, int *fail_err) {
    uint64_t pos = 0;
    while (pos < len) {
        uint64_t abs = off + pos;
        uint64_t head = abs % page;
        size_t room = (size_t)(page - head);
        size_t n = len - pos < room ? len - pos : room;

        if (!whole_pages || (head == 0 && n == page)) {
            ssize_t w = cfs_flash_write(f, abs, buf + pos, n);
            if (w == (ssize_t)n) { pos += n; continue; }
            *fail_off = abs; *fail_err = errno;
            return -1;
        }

        uint8_t *pb = malloc(page);
        if (!pb) { *fail_off = abs; *fail_err = ENOMEM; return -1; }
        if (cfs_flash_read(f, abs - head, pb, page) != (ssize_t)page) {
            int re = errno;
            free(pb);
            *fail_off = abs; *fail_err = re;
            return -1;
        }
        memcpy(pb + head, buf + pos, n);
        ssize_t w = cfs_flash_write(f, abs - head, pb, page);
        int e = errno;
        free(pb);
        if (w == (ssize_t)page) { pos += n; continue; }
        *fail_off = abs - head; *fail_err = e;
        return -1;
    }
    return 0;
}

/* Build a fresh table with `n` equal-sized partitions and return partition
 * `n` in *sel.  mkfs/install -p used to take the number and ignore it: the
 * table always got one partition from 1MiB to the end, and with -g that
 * partition covered the backup GPT.  Partition 1 keeps the old geometry
 * exactly; partition n only exists if n partitions were asked for. */
static int create_partitions(CFS *c, int kind, int n, uint64_t disk_sz, CfsPartition *sel) {
    if (n < 1) return -1;
    if (cfs_part_label(c, kind) != 0) return -1;

    uint64_t sectors = disk_sz / MBR_SECTOR_SIZE;
    uint64_t first = MBR_FIRST_USABLE;                 /* LBA 2048 = 1MiB */
    uint64_t last;                                     /* inclusive */
    if (sectors <= first) return -1;
    if (kind == CFS_PART_GPT) {
        /* Stop before the backup entries/header at the tail. */
        if (sectors <= GPT_FIRST_USABLE + GPT_LAST_USABLE_RESERVE) return -1;
        last = sectors - GPT_LAST_USABLE_RESERVE;
    } else {
        last = sectors - 1;
    }
    if (last < first) return -1;

    uint64_t total = last - first + 1;                 /* sectors */
    if (total < (uint64_t)n) return -1;
    uint64_t slice = total / (uint64_t)n;

    for (int i = 0; i < n; i++) {
        uint64_t s = first + (uint64_t)i * slice;
        uint64_t cnt = (i == n - 1) ? (last - s + 1) : slice;
        int rc = cfs_part_add(c, s * MBR_SECTOR_SIZE, cnt * MBR_SECTOR_SIZE,
                              MBR_TYPE_LINUX, NULL, 0);
        if (rc < 0) return rc;
    }
    return cfs_part_get(c, n, sel);
}

static void delete_all_parts(CFS *c) {
    while (cfs_part_count(c) > 0) {
        int done = 0;
        for (int i = 1; i <= 128 && !done; i++) {
            CfsPartition p;
            if (cfs_part_get(c, i, &p) == 0) { cfs_part_del(c, i); done = 1; }
        }
        if (!done) break;
    }
}

/* Recursively pack a directory */
static int pack_dir(CFS *c, const char *dir, const char *prefix) {
    char cmd[4096], line[4096];
    /* Use find to recursively list all files */
    snprintf(cmd, sizeof(cmd),
             "cd \"%s\" && find . \\( -type f -o -type d -o -type l \\) 2>/dev/null", dir);

    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    int count = 0;
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = 0;
        if (line[0] == '.' && line[1] == '/') memmove(line, line + 2, len - 1);
        if (line[0] == 0 || !strcmp(line, ".")) continue;

        char local[8192], vpath[4096];
        snprintf(local, sizeof(local), "%s/%s", dir, line);
        if (prefix[0])
            snprintf(vpath, sizeof(vpath), "%s/%s", prefix, line);
        else
            strncpy(vpath, line, sizeof(vpath) - 1);

        struct stat st;
        if (lstat(local, &st) != 0) { fprintf(stderr, "skip %s\n", local); continue; }

        if (S_ISDIR(st.st_mode)) {
            /* Create directory entry */
            int rc = cfs_mkdir(c, vpath);
            if (rc != 0) fprintf(stderr, "warn: cfs_mkdir(%s) -> %d\n", vpath, rc);
            else fprintf(stderr, "  d %s\n", vpath);
        } else if (S_ISLNK(st.st_mode)) {
            char target[4096];
            ssize_t tl = readlink(local, target, sizeof(target) - 1);
            if (tl > 0) {
                target[tl] = 0;
                int rc = cfs_symlink(c, target, vpath);
                if (rc != 0) fprintf(stderr, "warn: cfs_symlink(%s) -> %d\n", vpath, rc);
                else fprintf(stderr, "  l %s -> %s\n", vpath, target);
            }
        } else if (S_ISREG(st.st_mode)) {
            /* Pack file */
            int rc = cfs_pack(c, vpath, local);
            if (rc != 0) fprintf(stderr, "err: cfs_pack(%s) -> %d\n", vpath, rc);
            else { fprintf(stderr, "  f %s (%lld B)\n", vpath, (long long)st.st_size); count++; }
        }
    }
    pclose(fp);
    return count;
}

int main(int argc, char *argv[]) {
    if (argc < 2) { usage(argv[0]); return 1; }

    const char *cmd = argv[1];

    /* Two versions matter and they are not the same number: the tool can be
     * upgraded without the on-disk format moving, and a bug report that
     * names only one of them is ambiguous. */
    if (!strcmp(cmd, "--help") || !strcmp(cmd, "-h")) {
        usage_fp = stdout;
        usage(argv[0]);
        return 0;
    }
    if (!strcmp(cmd, "--version") || !strcmp(cmd, "-V")) {
        printf("cfs-tool %s (container format %d, block codec %d)\n",
               CFS_TOOL_VERSION, CFS_VERSION, CPENC_VERSION);
        return 0;
    }

    if (!strcmp(cmd, "pack")) {
        if (argc < 4) { usage(argv[0]); return 1; }
        const char *dir = argv[2], *out = argv[3];
        int raw = 0;
        for (int i = 4; i < argc; i++) if (!strcmp(argv[i], "--raw")) raw = 1;

        unlink(out);
        CFS *c = cfs_create(out);
        if (!c) { fprintf(stderr, "cfs_create(%s) failed\n", out); return 1; }
        /* Import the whole tree as one bulk write: @store then reaches disk in
         * a few large compressed slabs instead of one small slab per file,
         * which is what lets near-identical files share compression too. */
        if (cfs_set_batch(c, 1) != 0) { fprintf(stderr, "pack: batch mode failed\n"); cfs_close(c); unlink(out); return 1; }
        if (raw && cfs_set_raw(c) != 0) { fprintf(stderr, "pack: set raw failed\n"); cfs_close(c); unlink(out); return 1; }

        int n = pack_dir(c, dir, "");
        if (n < 0) { cfs_close(c); unlink(out); return 1; }

        cfs_finalise(c);
        CfsStats st; cfs_stats(c, &st);
        printf("Packed %u files. %llu → %llu bytes (%.2fx)\n",
               st.file_count,
               (unsigned long long)st.total_orig_size,
               (unsigned long long)st.total_compressed_size,
               st.compress_ratio);
        cfs_close(c);
        return 0;
    }

    if (!strcmp(cmd, "write")) {
        /* cfs-tool write <cfs> <path> <source_file>  — write local file into CFS */
        if (argc < 5) { usage(argv[0]); return 1; }
        /* Only a missing file justifies cfs_create(): it opens with O_TRUNC,
         * so treating any open failure as "create it" silently destroyed a
         * container that existed but could not be opened (bad format, lock,
         * permissions, corrupt superblock). */
        struct stat sb;
        int exists = stat(argv[2], &sb) == 0;
        if (!exists && errno != ENOENT) { perror(argv[2]); return 1; }
        errno = 0;
        CFS *c = cfs_open(argv[2], CFS_RDWR);
        if (!c) {
            int open_errno = errno;
            if (exists) {
                /* cfs_open() does not set errno on every rejection path, so
                 * only name the error when it did. */
                fprintf(stderr, "%s: cannot open existing container%s%s (refusing to truncate it)\n",
                        argv[2], open_errno ? ": " : "",
                        open_errno ? strerror(open_errno) : "");
                return 1;
            }
            c = cfs_create(argv[2]);
            if (!c) { fprintf(stderr, "%s: can't create: %s\n", argv[2], strerror(errno)); return 1; }
        }
        /* Read source file */
        FILE *sf = fopen(argv[4], "rb");
        if (!sf) { perror(argv[4]); cfs_close(c); return 1; }
        fseek(sf, 0, SEEK_END); size_t sz = (size_t)ftell(sf); rewind(sf);
        uint8_t *buf = malloc(sz);
        if (!buf) { fclose(sf); cfs_close(c); return 1; }
        fread(buf, 1, sz, sf); fclose(sf);

        int rc = cfs_write(c, cpath(argv[3]), buf, sz);
        free(buf);
        cfs_close(c);
        if (rc) { fprintf(stderr, "write failed: %d\n", rc); return 1; }
        printf("Wrote %s (%zu bytes) → %s\n", argv[4], sz, argv[2]);
        return 0;
    }

    if (!strcmp(cmd, "unpack")) {
        if (argc < 5) { usage(argv[0]); return 1; }
        CFS *c = cfs_open(argv[2], CFS_RDONLY);
        if (!c) { perror(argv[2]); return 1; }
        int rc = cfs_unpack(c, cpath(argv[3]), argv[4]);
        cfs_close(c);
        if (rc) { fprintf(stderr, "unpack failed\n"); return 1; }
        return 0;
    }

    if (!strcmp(cmd, "ls")) {
        if (argc < 3) { usage(argv[0]); return 1; }
        CFS *c = cfs_open(argv[2], CFS_RDONLY);
        if (!c) { perror(argv[2]); return 1; }
        const char *dir = argc > 3 ? argv[3] : "";

        CfsDirEntry ents[256];
        int n = cfs_ls(c, dir, ents, 256);
        if (n < 0) { fprintf(stderr, "ls failed\n"); cfs_close(c); return 1; }

        for (int i = 0; i < n; i++)
            printf("%c %-40s %10llu\n",
                   ents[i].is_dir ? 'd' : '-',
                   ents[i].name,
                   (unsigned long long)ents[i].size);
        cfs_close(c);
        return 0;
    }

    if (!strcmp(cmd, "cat")) {
        if (argc < 4) { usage(argv[0]); return 1; }
        CFS *c = cfs_open(argv[2], CFS_RDONLY);
        if (!c) { perror(argv[2]); return 1; }

        size_t sz;
        void *data = cfs_read_all(c, cpath(argv[3]), &sz);
        if (!data) { fprintf(stderr, "%s: not found\n", argv[3]); cfs_close(c); return 1; }

        fwrite(data, 1, sz, stdout);
        free(data);
        cfs_close(c);
        return 0;
    }

    if (!strcmp(cmd, "stat")) {
        if (argc < 3) { usage(argv[0]); return 1; }
        CFS *c = cfs_open(argv[2], CFS_RDONLY);
        if (!c) { perror(argv[2]); return 1; }

        if (argc > 3) {
            CfsStat st;
            if (cfs_stat(c, cpath(argv[3]), &st) == 0)
                printf("%s: size=%llu mtime=%llu mode=%u blocks=%u\n",
                       argv[3],
                       (unsigned long long)st.size,
                       (unsigned long long)st.mtime,
                       (unsigned)st.mode,
                       (unsigned)st.block_count);
            else
                fprintf(stderr, "%s: not found\n", argv[3]);
        } else {
            CfsStats st; cfs_stats(c, &st);
            printf("files=%u orig=%llu comp=%llu ratio=%.2fx\n",
                   st.file_count,
                   (unsigned long long)st.total_orig_size,
                   (unsigned long long)st.total_compressed_size,
                   st.compress_ratio);
        }
        cfs_close(c);
        return 0;
    }

    if (!strcmp(cmd, "verify")) {
        if (argc < 3) { usage(argv[0]); return 1; }
        unsigned vf = 0;
        for (int i = 3; i < argc; i++) if (!strcmp(argv[i], "--deep")) vf |= CFS_VERIFY_DEEP;
        /* Unlike the other commands this one does not go through cfs_open():
         * a container cfs_open() rejects is the one most worth verifying. */
        int rc = cfs_verify(argv[2], vf, stdout);
        if (rc < 0) { perror(argv[2]); return 1; }
        return rc ? 1 : 0;
    }

    if (!strcmp(cmd, "mkdir")) {
        if (argc < 4) { usage(argv[0]); return 1; }
        CFS *c = cfs_open(argv[2], CFS_RDWR);
        if (!c) { perror(argv[2]); return 1; }
        int rc = cfs_mkdir(c, cpath(argv[3]));
        if (rc) fprintf(stderr, "mkdir %s failed (errno=%d)\n", argv[3], errno);
        cfs_close(c);
        return rc ? 1 : 0;
    }

    if (!strcmp(cmd, "rm")) {
        if (argc < 4) { usage(argv[0]); return 1; }
        CFS *c = cfs_open(argv[2], CFS_RDWR);
        if (!c) { perror(argv[2]); return 1; }
        /* A medium is not a file: its extent sits in the container's byte
         * space and its inode is the only way to find it.  Decide by the
         * entry's mode, not by the name — an ordinary file may legitimately
         * be called "@flash.notes", and cfs_unlink() refuses real media
         * anyway. */
        CfsStat st;
        if (cfs_stat(c, cpath(argv[3]), &st) == 0 && st.mode == 4) {
            fprintf(stderr, "rm: %s is a flash medium, not a file; a medium cannot be removed\n",
                    argv[3]);
            cfs_close(c);
            return 1;
        }
        int rc = cfs_unlink(c, cpath(argv[3]));
        if (rc) fprintf(stderr, "rm %s failed (errno=%d)\n", argv[3], errno);
        cfs_close(c);
        return rc ? 1 : 0;
    }

    if (!strcmp(cmd, "mv")) {
        if (argc < 5) { usage(argv[0]); return 1; }
        CFS *c = cfs_open(argv[2], CFS_RDWR);
        if (!c) { perror(argv[2]); return 1; }
        int rc = cfs_rename(c, cpath(argv[3]), cpath(argv[4]));
        if (rc) fprintf(stderr, "mv %s %s failed (errno=%d)\n", argv[3], argv[4], errno);
        cfs_close(c);
        return rc ? 1 : 0;
    }

    if (!strcmp(cmd, "symlink")) {
        if (argc < 5) { usage(argv[0]); return 1; }
        CFS *c = cfs_open(argv[2], CFS_RDWR);
        if (!c) { perror(argv[2]); return 1; }
        int rc = cfs_symlink(c, argv[3], cpath(argv[4]));
        if (rc) fprintf(stderr, "symlink failed (errno=%d)\n", errno);
        cfs_close(c);
        return rc ? 1 : 0;
    }

    if (!strcmp(cmd, "trunc")) {
        if (argc < 5) { usage(argv[0]); return 1; }
        CFS *c = cfs_open(argv[2], CFS_RDWR);
        if (!c) { perror(argv[2]); return 1; }
        uint64_t sz = strtoull(argv[4], NULL, 0);
        int rc = cfs_truncate(c, cpath(argv[3]), sz);
        if (rc) fprintf(stderr, "trunc failed (errno=%d)\n", errno);
        cfs_close(c);
        return rc ? 1 : 0;
    }

    if (!strcmp(cmd, "mount")) {
        if (argc < 3) { usage(argv[0]); return 1; }
        const char *cfs_file = argv[2];
        const char *mount_pt = argc > 3 ? argv[3] : argv[2];

        /* Verify cfs file exists and is valid */
        CFS *c = cfs_open(cfs_file, CFS_RDONLY);
        if (!c) { perror(cfs_file); return 1; }
        cfs_close(c);

        /* Find preload .so next to cfs-tool binary */
        char preload[1024];
        if (argv[0][0] == '/') {
            char *slash = strrchr(argv[0], '/');
            if (slash) {
                size_t dlen = (size_t)(slash - argv[0]);
                memcpy(preload, argv[0], dlen);
                preload[dlen] = 0;
            } else strcpy(preload, ".");
        } else strcpy(preload, ".");

        /* Ensure mount point exists */
        mkdir(mount_pt, 0755);

        /* Spawn shell with LD_PRELOAD.  The environment is inherited, not
         * replaced: a shell started with only these three variables has no
         * PATH, HOME or TERM, so `cd ~`, `ls` from a profile and every
         * interactive habit break for no reason the user can see.  Only the
         * three variables this feature owns are overridden. */
        char env_preload[2048], env_mount[1024], env_file[1024];
        snprintf(env_preload, sizeof(env_preload), "LD_PRELOAD=%s/cfs_preload.so", preload);
        snprintf(env_mount, sizeof(env_mount), "CFS_MOUNT=%s", mount_pt);
        snprintf(env_file, sizeof(env_file), "CFS_FILE=%s", cfs_file);
        size_t en = 0;
        while (environ[en]) en++;
        char **envp = calloc(en + 4, sizeof(char *));
        if (!envp) { perror("calloc"); return 1; }
        size_t eo = 0;
        for (size_t i = 0; i < en; i++) {
            const char *e = environ[i];
            if (!strncmp(e, "CFS_MOUNT=", 10) || !strncmp(e, "CFS_FILE=", 9) ||
                !strncmp(e, "CFS_MOUNT_TREE=", 15) || !strncmp(e, "LD_PRELOAD=", 11))
                continue;
            envp[eo++] = environ[i];
        }
        envp[eo++] = env_preload;
        envp[eo++] = env_mount;
        envp[eo++] = env_file;
        envp[eo]   = NULL;

        printf("cfs: mounting %s at %s\n", cfs_file, mount_pt);
        printf("cfs: type 'exit' to unmount\n\n");

        const char *shell = getenv("SHELL");
        if (!shell || !shell[0]) shell = "/bin/sh";
        char *argv_shell[] = {(char*)shell, NULL};
        execve(shell, argv_shell, envp);
        perror("execve");
        return 1;
    }

    if (!strcmp(cmd, "mkfs")) {
        /* cfs-tool mkfs <fstype> <size> <out.cfs> [-p <n>] [-g]
         * Self-contained: writes fs structures directly, no external tools. */
        if (argc < 4) {
            fprintf(stderr, "Usage: %s mkfs <fstype> <size> <out.cfs> [-p <n>] [-g]\n", argv[0]);
            fprintf(stderr, "  fstype: ext4 | fat32 | exfat | swap\n");
            fprintf(stderr, "  size:   100M, 1G, 10G, etc.\n");
            fprintf(stderr, "  -p <n>: create <n> partitions, format partition <n>\n");
            fprintf(stderr, "  -g:     use GPT instead of MBR (with -p)\n");
            return 1;
        }
        const char *fstype = argv[2], *size_str = argv[3], *out = argv[4];
        int part = 0, part_req = 0, gpt = 0, raw = 0;
        const char *disk_kind = NULL;
        for (int i = 5; i < argc; i++) {
            if (!strcmp(argv[i], "-p") && i + 1 < argc) { part = atoi(argv[++i]); part_req = 1; }
            else if (!strcmp(argv[i], "-g")) gpt = 1;
            else if (!strcmp(argv[i], "--raw")) raw = 1;
            else if (!strcmp(argv[i], "--disk") && i + 1 < argc) disk_kind = argv[++i];
        }
        if (part_req && part < 1) {
            fprintf(stderr, "mkfs: -p needs a partition number >= 1\n");
            return 1;
        }

        int is_ext4 = !strcmp(fstype, "ext4");
        int is_fat32 = !strcmp(fstype, "fat32");
        int is_exfat = !strcmp(fstype, "exfat");
        int is_swap = !strcmp(fstype, "swap");
        if (!is_ext4 && !is_fat32 && !is_exfat && !is_swap) {
            fprintf(stderr, "mkfs: only ext4/fat32/exfat/swap are supported\n");
            return 1;
        }

        uint64_t disk_sz = 0;
        {   char *end; double v = strtod(size_str, &end);
            if (*end == 'G' || *end == 'g') disk_sz = (uint64_t)(v * 1073741824.0);
            else if (*end == 'M' || *end == 'm') disk_sz = (uint64_t)(v * 1048576.0);
            else if (*end == 'K' || *end == 'k') disk_sz = (uint64_t)(v * 1024.0);
            else if (*end == 0) disk_sz = (uint64_t)v;
        }
        if (disk_sz < 262144) { fprintf(stderr, "mkfs: size too small (min 256KB)\n"); return 1; }
        if (part_req && disk_sz < 2ULL * 1024 * 1024) {
            fprintf(stderr, "mkfs: -p requires at least 2MB (1MB partition start)\n");
            return 1;
        }

        unlink(out);
        CFS *c = cfs_create(out);
        if (!c) { perror(out); return 1; }
        if (raw && cfs_set_raw(c) != 0) { fprintf(stderr, "mkfs: set raw failed\n"); cfs_close(c); unlink(out); return 1; }
        if (disk_kind) {
            /* The image declares what kind of drive it is; the hook and
             * virt-kernel's device models report it to the guest. */
            int k = !strcmp(disk_kind, "ssd") ? CFS_DISK_SSD :
                    !strcmp(disk_kind, "hdd") ? CFS_DISK_HDD :
                    !strcmp(disk_kind, "usb") ? CFS_DISK_USB :
                    !strcmp(disk_kind, "sd")  ? CFS_DISK_SD : -1;
            if (k < 0 || cfs_disk_set(c, k) != 0) {
                fprintf(stderr, "mkfs: bad --disk '%s' (ssd|hdd|usb|sd)\n", disk_kind);
                cfs_close(c); unlink(out); return 1;
            }
        }

        int rc;
        cfs_block_resize(c, disk_sz);
        if (part_req) {
            int kind = gpt ? CFS_PART_GPT : CFS_PART_MBR;
            CfsPartition p;
            int ar = create_partitions(c, kind, part, disk_sz, &p);
            if (ar != 0) {
                fprintf(stderr, "mkfs: partition setup failed (%d)\n", ar);
                cfs_close(c); unlink(out); return 1;
            }
            if (is_ext4) rc = cfs_mkfs_ext4_at(c, p.start, p.size);
            else if (is_fat32) rc = cfs_mkfs_fat32_at(c, p.start, p.size);
            else if (is_exfat) rc = cfs_mkfs_exfat_at(c, p.start, p.size);
            else rc = cfs_mkfs_swap_at(c, p.start, p.size);
        } else {
            if (is_ext4) rc = cfs_mkfs_ext4(c, disk_sz);
            else if (is_fat32) rc = cfs_mkfs_fat32(c, disk_sz);
            else if (is_exfat) rc = cfs_mkfs_exfat(c, disk_sz);
            else rc = cfs_mkfs_swap(c, disk_sz);
        }
        cfs_finalise(c);
        cfs_close(c);

        if (rc != 0) { fprintf(stderr, "mkfs: %s init failed\n", fstype); unlink(out); return 1; }

        printf("cfs: %llu MB %s filesystem written to %s\n",
               (unsigned long long)(disk_sz >> 20), fstype, out);
        if (!part)
            printf("     mount with: cfs_block_hook.so + mount -t %s /dev/vda /mnt\n",
                   is_ext4 ? "ext4" : (is_fat32 ? "vfat" : (is_exfat ? "exfat" : "swap")));
        else
            printf("     partition table: %s, fs on partition %d\n", gpt ? "gpt" : "mbr", part);
        return 0;
    }

    if (!strcmp(cmd, "install")) {
        /* cfs-tool install <iso> <size> <out.cfs> [-p <n>] [-g]
         * Build a standalone disk: mkfs ext4 + populate from the ISO.
         * Without -p the filesystem goes on the bare @block; with -p on
         * partition n (MBR by default, -g for GPT). */
        if (argc < 5) {
            fprintf(stderr, "Usage: %s install <iso> <size> <out.cfs> [-p <n>] [-g]\n", argv[0]);
            fprintf(stderr, "  size:  100M, 1G, etc. (disk size; ISO must fit)\n");
            fprintf(stderr, "  -p <n>: create <n> partitions, install into partition <n>\n");
            fprintf(stderr, "  -g:     use GPT instead of MBR (with -p)\n");
            return 1;
        }
        const char *iso_path = argv[2], *size_str = argv[3], *out = argv[4];
        int part = 0, part_req = 0, gpt = 0, raw = 0;
        for (int i = 5; i < argc; i++) {
            if (!strcmp(argv[i], "-p") && i + 1 < argc) { part = atoi(argv[++i]); part_req = 1; }
            else if (!strcmp(argv[i], "-g")) gpt = 1;
            else if (!strcmp(argv[i], "--raw")) raw = 1;
        }
        if (part_req && part < 1) {
            fprintf(stderr, "install: -p needs a partition number >= 1\n");
            return 1;
        }

        uint64_t disk_sz = 0;
        {   char *end; double v = strtod(size_str, &end);
            if (*end == 'G' || *end == 'g') disk_sz = (uint64_t)(v * 1073741824.0);
            else if (*end == 'M' || *end == 'm') disk_sz = (uint64_t)(v * 1048576.0);
            else if (*end == 'K' || *end == 'k') disk_sz = (uint64_t)(v * 1024.0);
            else if (*end == 0) disk_sz = (uint64_t)v;
        }
        if (disk_sz < 2ULL * 1024 * 1024) { fprintf(stderr, "install: size too small (min 2MB)\n"); return 1; }

        /* read ISO into memory */
        FILE *f = fopen(iso_path, "rb");
        if (!f) { perror(iso_path); return 1; }
        fseek(f, 0, SEEK_END);
        long isz = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (isz < 17 * 2048) { fprintf(stderr, "install: %s too small to be an ISO\n", iso_path); fclose(f); return 1; }
        uint8_t *iso = malloc((size_t)isz);
        if (!iso) { fclose(f); return 1; }
        if (fread(iso, 1, (size_t)isz, f) != (size_t)isz) { fprintf(stderr, "install: read %s failed\n", iso_path); free(iso); fclose(f); return 1; }
        fclose(f);

        unlink(out);
        CFS *c = cfs_create(out);
        if (!c) { perror(out); free(iso); return 1; }
        if (raw && cfs_set_raw(c) != 0) { fprintf(stderr, "install: set raw failed\n"); cfs_close(c); unlink(out); free(iso); return 1; }
        cfs_block_resize(c, disk_sz);

        int rc;
        uint64_t base = 0, fsize = disk_sz;
        if (part_req) {
            int kind = gpt ? CFS_PART_GPT : CFS_PART_MBR;
            CfsPartition p;
            int ar = create_partitions(c, kind, part, disk_sz, &p);
            if (ar != 0) {
                fprintf(stderr, "install: partition setup failed (%d)\n", ar);
                cfs_close(c); unlink(out); free(iso); return 1;
            }
            base = p.start; fsize = p.size;
        }
        if ((uint64_t)isz > fsize) {
            fprintf(stderr, "install: ISO (%zu B) does not fit filesystem (%llu B)\n", isz, (unsigned long long)fsize);
            cfs_close(c); unlink(out); free(iso); return 1;
        }

        rc = cfs_mkfs_ext4_install(c, base, fsize, iso, (size_t)isz);
        cfs_finalise(c);
        cfs_close(c);
        free(iso);
        if (rc != 0) { fprintf(stderr, "install: failed (%d)\n", rc); unlink(out); return 1; }

        char where[40] = "";
        if (part_req) snprintf(where, sizeof(where), ", partition %d", part);
        printf("cfs: ISO %s installed on %s (%llu MB disk%s)\n", iso_path, out,
               (unsigned long long)(disk_sz >> 20), where);
        return 0;
    }

    if (!strcmp(cmd, "partlabel")) {
        if (argc < 4) { fprintf(stderr, "Usage: %s partlabel <cfs> <mbr|gpt|none> [--force]\n", argv[0]); return 1; }
        const char *cfs_path = argv[2], *kind_s = argv[3];
        int force = 0;
        for (int i = 4; i < argc; i++) if (!strcmp(argv[i], "--force")) force = 1;

        int kind;
        if (!strcmp(kind_s, "mbr")) kind = CFS_PART_MBR;
        else if (!strcmp(kind_s, "gpt")) kind = CFS_PART_GPT;
        else if (!strcmp(kind_s, "none")) kind = CFS_PART_NONE;
        else { fprintf(stderr, "partlabel: kind must be mbr|gpt|none\n"); return 1; }

        CFS *c = cfs_open(cfs_path, CFS_RDWR);
        if (!c) { perror(cfs_path); return 1; }
        if (force && kind != CFS_PART_NONE) delete_all_parts(c);
        int rc = cfs_part_label(c, kind);
        cfs_close(c);
        if (rc != 0) {
            fprintf(stderr, "partlabel: failed (existing non-empty table? use --force)\n");
            return 1;
        }
        printf("partlabel: %s\n", kind_s);
        return 0;
    }

    if (!strcmp(cmd, "partadd")) {
        if (argc < 6) {
            fprintf(stderr, "Usage: %s partadd <cfs> <type> <start> <end> [--boot] [--guid <GUID>]\n", argv[0]);
            return 1;
        }
        const char *cfs_path = argv[2], *type_s = argv[3];
        uint8_t t;
        if (parse_type(type_s, &t) != 0) { fprintf(stderr, "partadd: bad type '%s'\n", type_s); return 1; }
        uint64_t start, end;
        int sm0, sm1;
        if (parse_extent(argv[4], &start, &sm0) != 0 ||
            parse_extent(argv[5], &end, &sm1) != 0) {
            fprintf(stderr, "partadd: bad start/end (sectors or K/M/G bytes)\n"); return 1;
        }
        if (end < start) { fprintf(stderr, "partadd: end < start\n"); return 1; }
        uint64_t size = (end - start) + (sm0 ? 512 : 1);   /* end inclusive */

        int boot = 0;
        const char *guid = NULL;
        for (int i = 6; i < argc; i++) {
            if (!strcmp(argv[i], "--boot")) boot = 1;
            else if (!strcmp(argv[i], "--guid") && i + 1 < argc) guid = argv[++i];
        }

        CFS *c = cfs_open(cfs_path, CFS_RDWR);
        if (!c) { perror(cfs_path); return 1; }
        int rc = cfs_part_add(c, start, size, t, guid, boot);
        cfs_close(c);
        if (rc < 0) {
            const char *msg = rc == -2 ? "no partition table (run partlabel first)" :
                              rc == -3 ? "misaligned or zero size" :
                              rc == -4 ? "out of disk" :
                              rc == -5 ? "no free entries" :
                              rc == -6 ? "overlaps existing partition" :
                              rc == -7 ? "bad GUID" :
                              rc == -8 ? "covers the partition table" :
                              rc == -9 ? "outside the MBR 32-bit sector range" : "failed";
            fprintf(stderr, "partadd: %s\n", msg);
            return 1;
        }
        printf("partadd: partition %d\n", rc);
        return 0;
    }

    if (!strcmp(cmd, "partdel")) {
        if (argc < 4) { fprintf(stderr, "Usage: %s partdel <cfs> <n>\n", argv[0]); return 1; }
        CFS *c = cfs_open(argv[2], CFS_RDWR);
        if (!c) { perror(argv[2]); return 1; }
        int rc = cfs_part_del(c, atoi(argv[3]));
        cfs_close(c);
        if (rc != 0) { fprintf(stderr, "partdel: failed\n"); return 1; }
        printf("partdel: ok\n");
        return 0;
    }

    if (!strcmp(cmd, "parttype")) {
        if (argc < 5) {
            fprintf(stderr, "Usage: %s parttype <cfs> <n> <type> [--boot|--no-boot]\n", argv[0]);
            return 1;
        }
        uint8_t t;
        if (parse_type(argv[4], &t) != 0) { fprintf(stderr, "parttype: bad type\n"); return 1; }
        int boot = -1;
        for (int i = 5; i < argc; i++) {
            if (!strcmp(argv[i], "--boot")) boot = 1;
            else if (!strcmp(argv[i], "--no-boot")) boot = 0;
        }
        CFS *c = cfs_open(argv[2], CFS_RDWR);
        if (!c) { perror(argv[2]); return 1; }
        int rc = cfs_part_type(c, atoi(argv[3]), t, NULL, boot);
        cfs_close(c);
        if (rc != 0) { fprintf(stderr, "parttype: failed\n"); return 1; }
        printf("parttype: ok\n");
        return 0;
    }

    if (!strcmp(cmd, "partlist") || !strcmp(cmd, "partprint")) {
        if (argc < 3) { fprintf(stderr, "Usage: %s partlist <cfs>\n", argv[0]); return 1; }
        CFS *c = cfs_open(argv[2], CFS_RDONLY);
        if (!c) { perror(argv[2]); return 1; }
        int n = cfs_part_count(c);
        uint64_t dsz = cfs_block_size(c);
        if (n < 0) { cfs_close(c); return 1; }
        printf("Disk: %s   size=%llu  (%llu sectors x 512B)\n", argv[2],
               (unsigned long long)dsz, (unsigned long long)(dsz / 512));
        if (n == 0) {
            printf("Partition table: none\n");
            cfs_close(c);
            return 0;
        }
        CfsPartition p0;
        int has = cfs_part_get(c, 1, &p0) == 0;
        printf("Partition table: %s\n", has && p0.is_gpt ? "gpt" : "mbr");
        printf("#  Start    End     Sectors   Size  Type   Boot\n");
        for (int i = 1; i <= 128; i++) {
            CfsPartition p;
            if (cfs_part_get(c, i, &p) != 0) continue;
            uint64_t s0 = p.start / 512, s1 = (p.start + p.size) / 512 - 1;
            char sz[16]; fmt_size(sz, sizeof(sz), p.size);
            printf("%d  %-8llu %-7llu %-8llu %-5s %-7s %s\n",
                   p.index, (unsigned long long)s0, (unsigned long long)s1,
                   (unsigned long long)(p.size / 512), sz, p.type_str,
                   p.bootable ? "*" : "");
        }
        cfs_close(c);
        return 0;
    }

    if (!strcmp(cmd, "partwrite")) {
        if (argc < 5) { fprintf(stderr, "Usage: %s partwrite <cfs> <n> <src>\n", argv[0]); return 1; }
        CFS *c = cfs_open(argv[2], CFS_RDWR);
        if (!c) { perror(argv[2]); return 1; }
        int idx = atoi(argv[3]);
        CfsPartition p;
        if (cfs_part_get(c, idx, &p) != 0) {
            fprintf(stderr, "partwrite: no such partition %d\n", idx);
            cfs_close(c); return 1;
        }
        FILE *f = fopen(argv[4], "rb");
        if (!f) { perror(argv[4]); cfs_close(c); return 1; }
        uint8_t *buf = malloc(64 * 1024 * 1024);
        if (!buf) { fclose(f); cfs_close(c); return 1; }
        size_t total = 0, got;
        while ((got = fread(buf, 1, 64 * 1024 * 1024, f)) > 0) {
            if (cfs_part_write(c, idx, buf, got, (off_t)total) != 0) {
                fprintf(stderr, "partwrite: write failed at %zu (past partition end?)\n", total);
                free(buf); fclose(f); cfs_close(c); return 1;
            }
            total += got;
            if (total >= p.size) break;
        }
        free(buf); fclose(f); cfs_close(c);
        printf("partwrite: %zu bytes -> partition %d\n", total, idx);
        return 0;
    }

    if (!strcmp(cmd, "compact")) {
        if (argc < 3) { usage(argv[0]); return 1; }
        CFS *c = cfs_open(argv[2], CFS_RDWR);
        if (!c) { perror(argv[2]); return 1; }
        int rc = cfs_compact(c);
        if (rc) {
            int e = errno;
            if (e == EOPNOTSUPP)
                fprintf(stderr, "compact refused: the container holds a "
                        "@flash medium created with --xip, whose extent must "
                        "not move\n");
            else
                fprintf(stderr, "compact failed%s%s\n", e ? ": " : "",
                        e ? strerror(e) : "");
        } else printf("compact ok\n");
        cfs_close(c);
        return rc ? 1 : 0;
    }

    if (!strcmp(cmd, "dedup")) {
        /* cfs-tool dedup <cfs> [--stats] [--dry]
         * Merge plain files into the shared @store (content-addressed dedup).
         * --dry reads stats only; a real merge needs the container RDWR. */
        if (argc < 3) { usage(argv[0]); return 1; }
        const char *cfs_path = argv[2];
        int show_stats = 0, dry = 0, no_compact = 0, gc = 0;
        for (int i = 3; i < argc; i++) {
            if (!strcmp(argv[i], "--stats")) show_stats = 1;
            else if (!strcmp(argv[i], "--dry")) dry = 1;
            else if (!strcmp(argv[i], "--no-compact")) no_compact = 1;
            else if (!strcmp(argv[i], "--gc")) gc = 1;
            else { fprintf(stderr, "dedup: unknown option '%s'\n", argv[i]); return 1; }
        }

        CFS *c = cfs_open(cfs_path, dry ? CFS_RDONLY : CFS_RDWR);
        if (!c) { perror(cfs_path); return 1; }

        if (gc && !dry) {
            CfsDedupGcStats gs;
            if (cfs_dedup_gc(c, &gs) != 0) {
                fprintf(stderr, "dedup: gc failed\n");
                cfs_close(c);
                return 1;
            }
            printf("dedup --gc: refrag=%u dead=%llu store %llu -> %llu\n",
                   gs.refrag_files, (unsigned long long)gs.dead_bytes,
                   (unsigned long long)gs.store_before, (unsigned long long)gs.store_after);
            if (gs.store_after == 0)
                printf("  (below the maintenance thresholds — nothing reclaimed)\n");
            cfs_close(c);
            return 0;
        }

        if (!dry) {
            int rc = cfs_dedup_merge(c);
            if (rc) {
                fprintf(stderr, "dedup: merge failed (%d)\n", rc);
                cfs_close(c);
                return 1;
            }
        }

        CfsDedupStats ds;
        if (cfs_dedup_stats(c, &ds) != 0) {
            fprintf(stderr, "dedup: stats failed\n");
            cfs_close(c);
            return 1;
        }

        printf("%s: merged=%u skipped=%u logical=%llu store=%llu\n",
               dry ? "dedup (dry run)" : "dedup",
               ds.merged_files, ds.skipped,
               (unsigned long long)ds.logical_bytes,
               (unsigned long long)ds.store_bytes);

        if (show_stats || dry) {
            double ratio = ds.store_bytes > 0
                ? (double)ds.logical_bytes / (double)ds.store_bytes : 1.0;
            printf("  merged files:    %u\n", ds.merged_files);
            printf("  skipped:         %u\n", ds.skipped);
            printf("  logical bytes:   %llu\n", (unsigned long long)ds.logical_bytes);
            printf("  store bytes:     %llu\n", (unsigned long long)ds.store_bytes);
            printf("  table bytes:     %llu\n", (unsigned long long)ds.table_bytes);
            printf("  effective ratio: %.2fx\n", ratio);
        }

        /* A merge moves every file's bytes into @store and leaves the old
         * content blocks orphaned, so the container roughly doubles until a
         * compact reclaims them.  Do it here unless asked not to. */
        if (!dry && !no_compact) {
            struct stat sb;
            long long before = stat(cfs_path, &sb) == 0 ? (long long)sb.st_size : -1;
            if (cfs_compact(c) != 0) {
                fprintf(stderr, "dedup: compact failed — run 'cfs-tool compact' to reclaim orphans\n");
            } else if (before >= 0 && stat(cfs_path, &sb) == 0) {
                printf("  compacted:       %lld -> %lld bytes\n", before, (long long)sb.st_size);
            }
        } else if (!dry) {
            printf("  note: orphaned content blocks remain — run 'cfs-tool compact'\n");
        }
        cfs_close(c);
        return 0;
    }

    if (!strcmp(cmd, "disktype")) {
        /* cfs-tool disktype <cfs> [ssd|hdd|usb|sd] — query or declare the
         * drive identity the container carries. */
        if (argc < 3) { usage(argv[0]); return 1; }
        CFS *c = cfs_open(argv[2], argc > 3 ? CFS_RDWR : CFS_RDONLY);
        if (!c) { perror(argv[2]); return 1; }
        if (argc > 3) {
            const char *k = argv[3];
            int kind = !strcmp(k, "ssd") ? CFS_DISK_SSD :
                       !strcmp(k, "hdd") ? CFS_DISK_HDD :
                       !strcmp(k, "usb") ? CFS_DISK_USB :
                       !strcmp(k, "sd")  ? CFS_DISK_SD : -1;
            if (kind < 0 || cfs_disk_set(c, kind) != 0) {
                fprintf(stderr, "disktype: bad kind '%s' (ssd|hdd|usb|sd)\n", k);
                cfs_close(c); return 1;
            }
        }
        CfsDiskAttrs a;
        if (cfs_disk_get(c, &a) != 0) { cfs_close(c); return 1; }
        printf("%s: kind=%s removable=%d rotational=%d model=\"%s\"\n", argv[2],
               a.kind == CFS_DISK_SSD ? "ssd" : a.kind == CFS_DISK_HDD ? "hdd" :
               a.kind == CFS_DISK_USB ? "usb" : "sd",
               a.removable, a.rotational, a.model);
        cfs_close(c);
        return 0;
    }

    if (!strcmp(cmd, "flash")) {
        /* cfs-tool flash <init|info|read|write|erase|bad> <cfs> <tag> ...
         * `tag` is the short name; the library adds "@flash.". */
        if (argc < 4) { usage(argv[0]); return 1; }
        const char *sub = argv[2];
        const char *cfs_path = argv[3];
        const char *tag = argc > 4 ? argv[4] : NULL;
        char tagdisp[300];
        const char *tagname = tag ? tag : "";
        if (tag && flash_path(tag, tagdisp, sizeof tagdisp) == 0)
            tagname = tagdisp;

        if (!strcmp(sub, "init")) {
            if (argc < 5) { usage(argv[0]); return 1; }
            const char *type = NULL;
            uint64_t size = 0, page = 0, erase = 0, sector = 0, erased = 0;
            int have_size = 0, have_page = 0, have_erase = 0, have_sector = 0,
                have_erased = 0, xip = 0;
            for (int i = 5; i < argc; i++) {
                if (!strcmp(argv[i], "--type") && i + 1 < argc) type = argv[++i];
                else if (!strcmp(argv[i], "--size") && i + 1 < argc) {
                    if (parse_flash_size(argv[++i], &size) != 0) {
                        fprintf(stderr, "flash init: bad --size '%s' (bytes, or K/M/G suffix)\n", argv[i]);
                        return 1;
                    }
                    have_size = 1;
                } else if (!strcmp(argv[i], "--page") && i + 1 < argc) {
                    if (parse_flash_size(argv[++i], &page) != 0 || page > UINT32_MAX) {
                        fprintf(stderr, "flash init: bad --page '%s'\n", argv[i]);
                        return 1;
                    }
                    have_page = 1;
                } else if (!strcmp(argv[i], "--erase") && i + 1 < argc) {
                    if (parse_flash_size(argv[++i], &erase) != 0 || erase > UINT32_MAX) {
                        fprintf(stderr, "flash init: bad --erase '%s'\n", argv[i]);
                        return 1;
                    }
                    have_erase = 1;
                } else if (!strcmp(argv[i], "--sector") && i + 1 < argc) {
                    if (parse_flash_size(argv[++i], &sector) != 0 || sector > UINT32_MAX) {
                        fprintf(stderr, "flash init: bad --sector '%s'\n", argv[i]);
                        return 1;
                    }
                    have_sector = 1;
                } else if (!strcmp(argv[i], "--erased") && i + 1 < argc) {
                    if (parse_flash_size(argv[++i], &erased) != 0 || erased > 255) {
                        fprintf(stderr, "flash init: bad --erased '%s' (v1 supports 0xFF only)\n", argv[i]);
                        return 1;
                    }
                    have_erased = 1;
                } else if (!strcmp(argv[i], "--xip")) {
                    xip = 1;
                } else {
                    fprintf(stderr, "flash init: unknown option '%s'\n", argv[i]);
                    return 1;
                }
            }
            if (!type) {
                fprintf(stderr, "flash init: --type is required (nor|nand|mcu|emmc)\n");
                return 1;
            }
            if (!have_size) {
                fprintf(stderr, "flash init: --size is required\n");
                return 1;
            }

            CfsFlashGeom g;
            unsigned flags = 0;
            if (cfs_flash_profile(type, &g, &flags) != 0) {
                fprintf(stderr, "flash init: unknown type '%s' (nor|nand|mcu|emmc)\n", type);
                return 1;
            }
            g.size = size;
            if (have_page)   g.page = (uint32_t)page;
            if (have_erase)  g.erase = (uint32_t)erase;
            if (have_sector) g.sector = (uint32_t)sector;
            if (have_erased) {
                /* Programming only clears bits, which is the all-ones erased
                 * state; a 0x00 medium would need the inverse rule. */
                if (erased != 0xFF) {
                    fprintf(stderr, "flash init: --erased must be 0xFF (v1 programs by clearing bits)\n");
                    return 1;
                }
                g.erased_byte = (int)erased;
            }
            /* write_gran follows the page on raw media and the sector on a
             * managed one, also when an explicit --page/--sector overrides
             * the profile. */
            g.write_gran = (flags & CFS_FLASH_F_MANAGED) ? g.sector : g.page;
            if (xip) flags |= CFS_FLASH_F_XIP;

            /* A container that does not exist yet is created first, like
             * mkfs.  An existing one is opened; a failed open is reported,
             * never replaced (cfs_create() truncates). */
            struct stat sb;
            /* lstat, not stat: a dangling symlink exists as a path and
             * must not be replaced by a container, nor unlinked on failure. */
            int exists = lstat(cfs_path, &sb) == 0;
            if (!exists && errno != ENOENT) { perror(cfs_path); return 1; }
            CFS *c;
            if (exists) {
                errno = 0;
                c = cfs_open(cfs_path, CFS_RDWR);
                if (!c) {
                    int oe = errno;
                    fprintf(stderr, "flash init: cannot open %s%s%s\n", cfs_path,
                            oe ? ": " : "", oe ? strerror(oe) : " (invalid or corrupt container)");
                    return 1;
                }
            } else {
                c = cfs_create(cfs_path);
                if (!c) {
                    fprintf(stderr, "flash init: cannot create %s: %s\n", cfs_path, strerror(errno));
                    return 1;
                }
            }
            int rc = cfs_flash_create(c, tag, &g, flags);
            int cerr = errno;
            cfs_close(c);
            if (rc != 0) {
                /* If this command created the container, do not leave an
                 * empty file behind after the create failed.  An existing
                 * container is never touched. */
                if (!exists) unlink(cfs_path);
                if (cerr == EEXIST)
                    fprintf(stderr, "flash init: %s already exists\n", tagname);
                else if (cerr == EOPNOTSUPP)
                    fprintf(stderr, "flash init: managed media (%s) are not supported by this container version\n", type);
                else if (cerr == ENOSPC)
                    fprintf(stderr, "flash init: no room for %llu bytes (%s) in %s\n",
                            (unsigned long long)g.size, type, cfs_path);
                else if (cerr == EINVAL)
                    fprintf(stderr, "flash init: invalid geometry (page/sector/erase must be powers of two, erase >= page and a multiple of it, size a multiple of erase and of the host page size)\n");
                else
                    fprintf(stderr, "flash init: create failed: %s (errno=%d)\n", strerror(cerr), cerr);
                return 1;
            }

            char hs[32];
            fmt_size(hs, sizeof hs, g.size);
            printf("flash init: %s created\n", tagname);
            printf("  type:       %s\n", type);
            printf("  size:       %llu bytes (%s)\n", (unsigned long long)g.size, hs);
            printf("  sector:     %u\n", g.sector);
            printf("  page:       %u\n", g.page);
            printf("  erase:      %u\n", g.erase);
            printf("  write_gran: %u\n", g.write_gran);
            printf("  erased:     0x%02X\n", (unsigned)g.erased_byte);
            printf("  flags:      %s%s\n",
                   (flags & CFS_FLASH_F_MANAGED) ? "managed" : "raw",
                   (flags & CFS_FLASH_F_XIP) ? ",xip" : "");
            return 0;
        }

        if (!strcmp(sub, "info")) {
            if (argc < 5) { usage(argv[0]); return 1; }
            CFS *c = cfs_open(cfs_path, CFS_RDONLY);
            if (!c) { perror(cfs_path); return 1; }
            CfsFlash *f = cfs_flash_open(c, tag, 0);
            if (!f) {
                fprintf(stderr, "flash info: %s: %s (errno=%d)\n", tagname, strerror(errno), errno);
                cfs_close(c);
                return 1;
            }
            uint64_t size = 0;
            uint32_t sector = 0, erase = 0, wgran = 0;
            int media = -1, erased = -1;
            unsigned flags = 0;
            uint64_t ecount = 0;
            uint32_t bad_n = 0;
            if (cfs_flash_geometry(f, &size, &sector, &erase, &wgran) != 0 ||
                cfs_flash_info(f, &media, &erased, &flags, &ecount, &bad_n) != 0) {
                fprintf(stderr, "flash info: geometry unreadable\n");
                cfs_flash_close(f); cfs_close(c);
                return 1;
            }
            char hs[32];
            fmt_size(hs, sizeof hs, size);
            printf("%s\n", tagname);
            printf("  size:       %llu bytes (%s)\n", (unsigned long long)size, hs);
            printf("  media:      %s\n", flash_media_name(media));
            printf("  sector:     %u\n", sector);
            /* cfs_flash_info() has no page field; on raw media the programming
             * page is exactly write_gran (see cfs_flash.h). */
            printf("  page:       %u%s\n", wgran,
                   (flags & CFS_FLASH_F_MANAGED) ? " (not exposed; write_gran shown)"
                                                 : " (raw media: page == write_gran)");
            printf("  erase:      %u\n", erase);
            printf("  write_gran: %u\n", wgran);
            printf("  erased:     0x%02X\n", (unsigned)erased);
            printf("  flags:      %s%s%s\n",
                   (flags & CFS_FLASH_F_XIP) ? "xip" : "no-xip",
                   (flags & CFS_FLASH_F_MANAGED) ? ",managed" : ",raw",
                   (flags & CFS_FLASH_F_BADTAB) ? ",badtab" : "");
            printf("  erase count:%llu\n", (unsigned long long)ecount);
            printf("  bad blocks: %u of %llu erase blocks\n",
                   bad_n, (unsigned long long)(size / erase));
            CfsStat st;
            if (cfs_stat(c, tagname, &st) == 0)
                printf("  stat:       mode=%u size=%llu block_count=%u\n",
                       (unsigned)st.mode, (unsigned long long)st.size,
                       (unsigned)st.block_count);
            cfs_flash_close(f);
            cfs_close(c);
            return 0;
        }

        if (!strcmp(sub, "read")) {
            if (argc < 6) { usage(argv[0]); return 1; }
            const char *out = argv[5];
            uint64_t off = 0, len = 0;
            int have_len = 0;
            for (int i = 6; i < argc; i++) {
                if (!strcmp(argv[i], "--offset") && i + 1 < argc) {
                    if (parse_flash_size(argv[++i], &off) != 0) {
                        fprintf(stderr, "flash read: bad --offset '%s'\n", argv[i]);
                        return 1;
                    }
                } else if (!strcmp(argv[i], "--len") && i + 1 < argc) {
                    if (parse_flash_size(argv[++i], &len) != 0) {
                        fprintf(stderr, "flash read: bad --len '%s'\n", argv[i]);
                        return 1;
                    }
                    have_len = 1;
                } else {
                    fprintf(stderr, "flash read: unknown option '%s'\n", argv[i]);
                    return 1;
                }
            }

            CFS *c = cfs_open(cfs_path, CFS_RDONLY);
            if (!c) { perror(cfs_path); return 1; }
            CfsFlash *f = cfs_flash_open(c, tag, 0);
            if (!f) {
                fprintf(stderr, "flash read: %s: %s (errno=%d)\n", tagname, strerror(errno), errno);
                cfs_close(c);
                return 1;
            }
            uint64_t size = 0;
            uint32_t sector = 0, erase = 0, wgran = 0;
            cfs_flash_geometry(f, &size, &sector, &erase, &wgran);
            if (off > size) {
                fprintf(stderr, "flash read: offset %llu is past the end (%llu bytes)\n",
                        (unsigned long long)off, (unsigned long long)size);
                cfs_flash_close(f); cfs_close(c); return 1;
            }
            if (!have_len) len = size - off;
            else if (len > size - off) {
                fprintf(stderr, "flash read: length %llu exceeds the remaining %llu bytes\n",
                        (unsigned long long)len, (unsigned long long)(size - off));
                cfs_flash_close(f); cfs_close(c); return 1;
            }

            uint8_t *buf = malloc(len ? (size_t)len : 1);
            if (!buf) {
                fprintf(stderr, "flash read: out of memory for %llu bytes\n",
                        (unsigned long long)len);
                cfs_flash_close(f); cfs_close(c); return 1;
            }
            if (len && cfs_flash_read(f, off, buf, (size_t)len) != (ssize_t)len) {
                fprintf(stderr, "flash read: %llu bytes at %llu failed: %s (errno=%d)\n",
                        (unsigned long long)len, (unsigned long long)off,
                        strerror(errno), errno);
                free(buf); cfs_flash_close(f); cfs_close(c); return 1;
            }
            /* "wb" truncates.  If the output is the container itself, that
             * destroys the superblock and every table while the command
             * would still report success, so refuse up front. */
            {
                struct stat so, sc;
                if (stat(out, &so) == 0 && stat(cfs_path, &sc) == 0 &&
                    so.st_dev == sc.st_dev && so.st_ino == sc.st_ino) {
                    fprintf(stderr, "flash read: refusing to overwrite the container itself\n");
                    free(buf); cfs_flash_close(f); cfs_close(c); return 1;
                }
            }
            FILE *of = fopen(out, "wb");
            if (!of) {
                perror(out);
                free(buf); cfs_flash_close(f); cfs_close(c); return 1;
            }
            if (len && fwrite(buf, 1, (size_t)len, of) != (size_t)len) {
                fprintf(stderr, "flash read: writing %s failed: %s\n", out, strerror(errno));
                fclose(of); free(buf); cfs_flash_close(f); cfs_close(c); return 1;
            }
            if (fclose(of) != 0) {
                fprintf(stderr, "flash read: closing %s failed: %s\n", out, strerror(errno));
                free(buf); cfs_flash_close(f); cfs_close(c); return 1;
            }
            printf("flash read: %llu bytes from %s at %llu -> %s\n",
                   (unsigned long long)len, tagname,
                   (unsigned long long)off, out);
            free(buf);
            cfs_flash_close(f);
            cfs_close(c);
            return 0;
        }

        if (!strcmp(sub, "write")) {
            if (argc < 6) { usage(argv[0]); return 1; }
            const char *image = argv[5];
            uint64_t off = 0;
            int do_erase = 0, do_verify = 0;
            for (int i = 6; i < argc; i++) {
                if (!strcmp(argv[i], "--offset") && i + 1 < argc) {
                    if (parse_flash_size(argv[++i], &off) != 0) {
                        fprintf(stderr, "flash write: bad --offset '%s'\n", argv[i]);
                        return 1;
                    }
                } else if (!strcmp(argv[i], "--erase")) {
                    do_erase = 1;
                } else if (!strcmp(argv[i], "--verify")) {
                    do_verify = 1;
                } else {
                    fprintf(stderr, "flash write: unknown option '%s'\n", argv[i]);
                    return 1;
                }
            }

            CFS *c = cfs_open(cfs_path, CFS_RDWR);
            if (!c) { perror(cfs_path); return 1; }
            CfsFlash *f = cfs_flash_open(c, tag, 1);
            if (!f) {
                fprintf(stderr, "flash write: %s: %s (errno=%d)\n", tagname, strerror(errno), errno);
                cfs_close(c);
                return 1;
            }
            uint64_t size = 0;
            uint32_t sector = 0, erase = 0, wgran = 0;
            int media = -1;
            cfs_flash_geometry(f, &size, &sector, &erase, &wgran);
            cfs_flash_info(f, &media, NULL, NULL, NULL, NULL);
            if (off > size) {
                fprintf(stderr, "flash write: offset %llu is past the end (%llu bytes)\n",
                        (unsigned long long)off, (unsigned long long)size);
                cfs_flash_close(f); cfs_close(c); return 1;
            }

            struct stat sb;
            if (stat(image, &sb) != 0) {
                perror(image);
                cfs_flash_close(f); cfs_close(c); return 1;
            }
            if (!S_ISREG(sb.st_mode)) {
                fprintf(stderr, "flash write: %s is not a regular file\n", image);
                cfs_flash_close(f); cfs_close(c); return 1;
            }
            uint64_t want = (uint64_t)sb.st_size;
            if (want > size - off) {
                fprintf(stderr, "flash write: %s is %llu bytes; only %llu fit at offset %llu (medium %llu)\n",
                        image, (unsigned long long)want,
                        (unsigned long long)(size - off),
                        (unsigned long long)off, (unsigned long long)size);
                cfs_flash_close(f); cfs_close(c); return 1;
            }
            FILE *in = fopen(image, "rb");
            if (!in) {
                perror(image);
                cfs_flash_close(f); cfs_close(c); return 1;
            }
            uint8_t *buf = malloc(want ? (size_t)want : 1);
            if (!buf) {
                fprintf(stderr, "flash write: out of memory for %llu bytes\n",
                        (unsigned long long)want);
                fclose(in); cfs_flash_close(f); cfs_close(c); return 1;
            }
            if (want && fread(buf, 1, (size_t)want, in) != (size_t)want) {
                fprintf(stderr, "flash write: reading %s failed\n", image);
                fclose(in); free(buf); cfs_flash_close(f); cfs_close(c); return 1;
            }
            fclose(in);

            if (do_erase && want) {
                uint64_t eoff = off & ~((uint64_t)erase - 1);
                uint64_t eend = (off + want + erase - 1) & ~((uint64_t)erase - 1);
                if (eend > size) eend = size;
                if (cfs_flash_erase(f, eoff, (size_t)(eend - eoff)) != 0) {
                    fprintf(stderr, "flash write: erase of %llu bytes at %llu failed: %s (errno=%d)\n",
                            (unsigned long long)(eend - eoff), (unsigned long long)eoff,
                            strerror(errno), errno);
                    free(buf); cfs_flash_close(f); cfs_close(c); return 1;
                }
                printf("flash write: erased %llu bytes at %llu\n",
                       (unsigned long long)(eend - eoff), (unsigned long long)eoff);
            }

            if (want) {
                uint64_t fail_off = 0;
                int fail_err = 0;
                if (flash_program(f, off, buf, (size_t)want, wgran,
                                  media == CFS_FLASH_NAND,
                                  &fail_off, &fail_err) != 0) {
                    fprintf(stderr, "flash write: program failed at medium offset %llu",
                            (unsigned long long)fail_off);
                    if (fail_off >= off)
                        fprintf(stderr, " (image offset %llu)",
                                (unsigned long long)(fail_off - off));
                    fprintf(stderr, ": %s (errno=%d)\n",
                            strerror(fail_err), fail_err);
                    fprintf(stderr, "  (a target page that is not erased, or bits going 0->1, needs --erase first)\n");
                    free(buf); cfs_flash_close(f); cfs_close(c); return 1;
                }
            }
            if (cfs_flash_flush(f) != 0) {
                fprintf(stderr, "flash write: flush failed: %s (errno=%d)\n",
                        strerror(errno), errno);
                free(buf); cfs_flash_close(f); cfs_close(c); return 1;
            }
            printf("flash write: %llu bytes -> %s at %llu\n",
                   (unsigned long long)want, tagname, (unsigned long long)off);

            if (do_verify) {
                size_t chunk = 1u << 20;
                uint8_t *rb = malloc(chunk);
                if (!rb) {
                    fprintf(stderr, "flash write: out of memory for verify\n");
                    free(buf); cfs_flash_close(f); cfs_close(c); return 1;
                }
                uint64_t done = 0;
                int vrc = 0;
                while (done < want) {
                    size_t n = want - done < chunk ? (size_t)(want - done) : chunk;
                    if (cfs_flash_read(f, off + done, rb, n) != (ssize_t)n) {
                        fprintf(stderr, "flash write: verify read at %llu failed: %s (errno=%d)\n",
                                (unsigned long long)(off + done), strerror(errno), errno);
                        vrc = 1;
                        break;
                    }
                    for (size_t k = 0; k < n; k++) {
                        if (rb[k] != buf[done + k]) {
                            fprintf(stderr, "flash write: verify mismatch at medium offset %llu (image offset %llu): wrote 0x%02X, read 0x%02X\n",
                                    (unsigned long long)(off + done + k),
                                    (unsigned long long)(done + k),
                                    buf[done + k], rb[k]);
                            vrc = 1;
                            break;
                        }
                    }
                    if (vrc) break;
                    done += n;
                }
                free(rb);
                if (vrc) { free(buf); cfs_flash_close(f); cfs_close(c); return 1; }
                printf("flash write: verified %llu bytes\n", (unsigned long long)want);
            }
            free(buf);
            cfs_flash_close(f);
            cfs_close(c);
            return 0;
        }

        if (!strcmp(sub, "erase")) {
            if (argc < 5) { usage(argv[0]); return 1; }
            uint64_t off = 0, len = 0;
            int have_len = 0;
            for (int i = 5; i < argc; i++) {
                if (!strcmp(argv[i], "--offset") && i + 1 < argc) {
                    if (parse_flash_size(argv[++i], &off) != 0) {
                        fprintf(stderr, "flash erase: bad --offset '%s'\n", argv[i]);
                        return 1;
                    }
                } else if (!strcmp(argv[i], "--len") && i + 1 < argc) {
                    if (parse_flash_size(argv[++i], &len) != 0) {
                        fprintf(stderr, "flash erase: bad --len '%s'\n", argv[i]);
                        return 1;
                    }
                    have_len = 1;
                } else {
                    fprintf(stderr, "flash erase: unknown option '%s'\n", argv[i]);
                    return 1;
                }
            }

            CFS *c = cfs_open(cfs_path, CFS_RDWR);
            if (!c) { perror(cfs_path); return 1; }
            CfsFlash *f = cfs_flash_open(c, tag, 1);
            if (!f) {
                fprintf(stderr, "flash erase: %s: %s (errno=%d)\n", tagname, strerror(errno), errno);
                cfs_close(c);
                return 1;
            }
            uint64_t size = 0;
            uint32_t sector = 0, erase = 0, wgran = 0;
            cfs_flash_geometry(f, &size, &sector, &erase, &wgran);
            if (off > size) {
                fprintf(stderr, "flash erase: offset %llu is past the end (%llu bytes)\n",
                        (unsigned long long)off, (unsigned long long)size);
                cfs_flash_close(f); cfs_close(c); return 1;
            }
            if (!have_len) len = size - off;
            if (!len) {
                fprintf(stderr, "flash erase: length is zero (nothing to erase)\n");
                cfs_flash_close(f); cfs_close(c); return 1;
            }
            if (len > size - off) {
                fprintf(stderr, "flash erase: length %llu exceeds the remaining %llu bytes\n",
                        (unsigned long long)len, (unsigned long long)(size - off));
                cfs_flash_close(f); cfs_close(c); return 1;
            }
            if ((off % erase) || (len % erase)) {
                /* Suggest the range that covers what was asked: start at the
                 * containing block, end at the end of the last covered one. */
                uint64_t s_off = off - (off % erase);
                uint64_t end = off + len;
                uint64_t rem = end % erase;
                uint64_t s_end = rem ? end + (erase - rem) : end;
                if (s_end > size) s_end = size;
                uint64_t s_len = s_end - s_off;
                fprintf(stderr, "flash erase: offset %llu and length %llu must both be multiples of the erase block size %u\n",
                        (unsigned long long)off, (unsigned long long)len, erase);
                if (off % erase)
                    fprintf(stderr, "  offset is not erase-aligned; containing block starts at %llu\n",
                            (unsigned long long)s_off);
                if (len % erase)
                    fprintf(stderr, "  length is not a whole number of erase blocks\n");
                fprintf(stderr, "  suggestion: --offset %llu --len %llu\n",
                        (unsigned long long)s_off, (unsigned long long)s_len);
                cfs_flash_close(f); cfs_close(c); return 1;
            }
            if (cfs_flash_erase(f, off, (size_t)len) != 0) {
                fprintf(stderr, "flash erase: %llu bytes at %llu failed: %s (errno=%d)%s\n",
                        (unsigned long long)len, (unsigned long long)off,
                        strerror(errno), errno,
                        errno == EIO ? " [touches a bad erase block]" : "");
                cfs_flash_close(f); cfs_close(c); return 1;
            }
            if (cfs_flash_flush(f) != 0) {
                fprintf(stderr, "flash erase: flush failed: %s (errno=%d)\n",
                        strerror(errno), errno);
                cfs_flash_close(f); cfs_close(c); return 1;
            }
            printf("flash erase: %llu bytes at %llu (%llu erase blocks) on %s\n",
                   (unsigned long long)len, (unsigned long long)off,
                   (unsigned long long)(len / erase), tagname);
            cfs_flash_close(f);
            cfs_close(c);
            return 0;
        }

        if (!strcmp(sub, "bad")) {
            if (argc < 5) { usage(argv[0]); return 1; }
            int list = 0, have_mark = 0, have_clear = 0;
            uint32_t mark = 0, clear = 0;
            for (int i = 5; i < argc; i++) {
                if (!strcmp(argv[i], "--list")) { list = 1; continue; }
                if (!strcmp(argv[i], "--mark") || !strcmp(argv[i], "--clear")) {
                    int is_mark = !strcmp(argv[i], "--mark");
                    if (i + 1 >= argc) {
                        fprintf(stderr, "flash bad: %s needs an erase-block index\n", argv[i]);
                        return 1;
                    }
                    char *end = NULL;
                    errno = 0;
                    int base = (argv[i + 1][0] == '0' &&
                                (argv[i + 1][1] == 'x' || argv[i + 1][1] == 'X'))
                               ? 16 : 10;
                    unsigned long long v = strtoull(argv[++i], &end, base);
                    if (errno || !end || *end || v > 0xFFFFFFFFULL) {
                        fprintf(stderr, "flash bad: bad block index '%s'\n", argv[i]);
                        return 1;
                    }
                    if (is_mark) { mark = (uint32_t)v; have_mark = 1; }
                    else { clear = (uint32_t)v; have_clear = 1; }
                    continue;
                }
                fprintf(stderr, "flash bad: unknown option '%s'\n", argv[i]);
                return 1;
            }
            if (have_mark && have_clear) {
                fprintf(stderr, "flash bad: --mark and --clear are mutually exclusive\n");
                return 1;
            }
            int wr = have_mark || have_clear;
            CFS *c = cfs_open(cfs_path, wr ? CFS_RDWR : CFS_RDONLY);
            if (!c) { perror(cfs_path); return 1; }
            CfsFlash *f = cfs_flash_open(c, tag, wr);
            if (!f) {
                fprintf(stderr, "flash bad: %s: %s (errno=%d)\n", tagname, strerror(errno), errno);
                cfs_close(c);
                return 1;
            }
            if (wr) {
                int rc = have_mark ? cfs_flash_bad_set(f, mark, 1)
                                   : cfs_flash_bad_set(f, clear, 0);
                if (rc != 0) {
                    int e = errno;
                    fprintf(stderr, "flash bad: cannot %s block %u: %s\n",
                            have_mark ? "mark" : "clear",
                            have_mark ? mark : clear, strerror(e));
                    cfs_flash_close(f);
                    cfs_close(c);
                    return 1;
                }
                if (cfs_flash_flush(f) != 0) {
                    int e = errno;
                    fprintf(stderr, "flash bad: flush failed: %s\n", strerror(e));
                    cfs_flash_close(f);
                    cfs_close(c);
                    return 1;
                }
            }
            uint64_t size = 0;
            uint32_t sector = 0, erase = 0, wgran = 0;
            cfs_flash_geometry(f, &size, &sector, &erase, &wgran);
            uint64_t bad = flash_bad_scan(f, size, erase, list);
            printf("flash bad: %llu of %llu erase blocks are bad on %s\n",
                   (unsigned long long)bad, (unsigned long long)(size / erase), tagname);
            if (!bad) printf("  (none recorded)\n");
            cfs_flash_close(f);
            cfs_close(c);
            return 0;
        }

        fprintf(stderr, "flash: unknown command '%s' (init|info|read|write|erase|bad)\n", sub);
        usage(argv[0]);
        return 1;
    }

    usage(argv[0]);
    return 1;
}
