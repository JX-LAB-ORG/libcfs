#define _GNU_SOURCE
#include "cfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <command> [args...]\n"
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
        "                                  -p <n>: format inside partition n\n"
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
        "\n",
        prog);
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
             "cd \"%s\" && find . -type f -o -type d 2>/dev/null", dir);

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
        if (stat(local, &st) != 0) { fprintf(stderr, "skip %s\n", local); continue; }

        if (S_ISDIR(st.st_mode)) {
            /* Create directory entry */
            int rc = cfs_mkdir(c, vpath);
            if (rc != 0) fprintf(stderr, "warn: cfs_mkdir(%s) -> %d\n", vpath, rc);
            else fprintf(stderr, "  d %s\n", vpath);
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

    if (!strcmp(cmd, "pack")) {
        if (argc < 4) { usage(argv[0]); return 1; }
        const char *dir = argv[2], *out = argv[3];
        int raw = 0;
        for (int i = 4; i < argc; i++) if (!strcmp(argv[i], "--raw")) raw = 1;

        unlink(out);
        CFS *c = cfs_create(out);
        if (!c) { fprintf(stderr, "cfs_create(%s) failed\n", out); return 1; }
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
        CFS *c = cfs_open(argv[2], CFS_RDWR);
        if (!c) {
            /* Maybe it doesn't exist yet — create it */
            c = cfs_create(argv[2]);
            if (!c) { fprintf(stderr, "%s: can't open or create\n", argv[2]); return 1; }
        }
        /* Read source file */
        FILE *sf = fopen(argv[4], "rb");
        if (!sf) { perror(argv[4]); cfs_close(c); return 1; }
        fseek(sf, 0, SEEK_END); size_t sz = (size_t)ftell(sf); rewind(sf);
        uint8_t *buf = malloc(sz);
        if (!buf) { fclose(sf); cfs_close(c); return 1; }
        fread(buf, 1, sz, sf); fclose(sf);

        int rc = cfs_write(c, argv[3], buf, sz);
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
        int rc = cfs_unpack(c, argv[3], argv[4]);
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
        void *data = cfs_read_all(c, argv[3], &sz);
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
            if (cfs_stat(c, argv[3], &st) == 0)
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
        int rc = cfs_mkdir(c, argv[3]);
        if (rc) fprintf(stderr, "mkdir %s failed (errno=%d)\n", argv[3], errno);
        cfs_close(c);
        return rc ? 1 : 0;
    }

    if (!strcmp(cmd, "rm")) {
        if (argc < 4) { usage(argv[0]); return 1; }
        CFS *c = cfs_open(argv[2], CFS_RDWR);
        if (!c) { perror(argv[2]); return 1; }
        int rc = cfs_unlink(c, argv[3]);
        if (rc) fprintf(stderr, "rm %s failed (errno=%d)\n", argv[3], errno);
        cfs_close(c);
        return rc ? 1 : 0;
    }

    if (!strcmp(cmd, "mv")) {
        if (argc < 5) { usage(argv[0]); return 1; }
        CFS *c = cfs_open(argv[2], CFS_RDWR);
        if (!c) { perror(argv[2]); return 1; }
        int rc = cfs_rename(c, argv[3], argv[4]);
        if (rc) fprintf(stderr, "mv %s %s failed (errno=%d)\n", argv[3], argv[4], errno);
        cfs_close(c);
        return rc ? 1 : 0;
    }

    if (!strcmp(cmd, "symlink")) {
        if (argc < 5) { usage(argv[0]); return 1; }
        CFS *c = cfs_open(argv[2], CFS_RDWR);
        if (!c) { perror(argv[2]); return 1; }
        int rc = cfs_symlink(c, argv[3], argv[4]);
        if (rc) fprintf(stderr, "symlink failed (errno=%d)\n", errno);
        cfs_close(c);
        return rc ? 1 : 0;
    }

    if (!strcmp(cmd, "trunc")) {
        if (argc < 5) { usage(argv[0]); return 1; }
        CFS *c = cfs_open(argv[2], CFS_RDWR);
        if (!c) { perror(argv[2]); return 1; }
        uint64_t sz = strtoull(argv[4], NULL, 0);
        int rc = cfs_truncate(c, argv[3], sz);
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

        /* Spawn shell with LD_PRELOAD */
        char env_preload[2048], env_mount[1024], env_file[1024];
        snprintf(env_preload, sizeof(env_preload), "LD_PRELOAD=%s/cfs_preload.so", preload);
        snprintf(env_mount, sizeof(env_mount), "CFS_MOUNT=%s", mount_pt);
        snprintf(env_file, sizeof(env_file), "CFS_FILE=%s", cfs_file);
        char *envp[] = {env_preload, env_mount, env_file, NULL};

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
            fprintf(stderr, "  fstype: ext4 | fat32 | swap\n");
            fprintf(stderr, "  size:   100M, 1G, 10G, etc.\n");
            fprintf(stderr, "  -p <n>: format inside partition n (creates MBR + partition 1)\n");
            fprintf(stderr, "  -g:     use GPT instead of MBR (with -p)\n");
            return 1;
        }
        const char *fstype = argv[2], *size_str = argv[3], *out = argv[4];
        int part = 0, gpt = 0, raw = 0;
        const char *disk_kind = NULL;
        for (int i = 5; i < argc; i++) {
            if (!strcmp(argv[i], "-p") && i + 1 < argc) part = atoi(argv[++i]);
            else if (!strcmp(argv[i], "-g")) gpt = 1;
            else if (!strcmp(argv[i], "--raw")) raw = 1;
            else if (!strcmp(argv[i], "--disk") && i + 1 < argc) disk_kind = argv[++i];
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
        if (part && disk_sz < 2ULL * 1024 * 1024) {
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
        if (part) {
            int kind = gpt ? CFS_PART_GPT : CFS_PART_MBR;
            if (cfs_part_label(c, kind) != 0) {
                fprintf(stderr, "mkfs: partition label failed\n"); cfs_close(c); unlink(out); return 1;
            }
            uint64_t pstart = 1ULL << 20;   /* LBA 2048 */
            int ar = cfs_part_add(c, pstart, disk_sz - pstart, 0x83, NULL, 0);
            if (ar < 0) {
                fprintf(stderr, "mkfs: partadd failed (%d)\n", ar); cfs_close(c); unlink(out); return 1;
            }
            CfsPartition p;
            if (cfs_part_get(c, 1, &p) != 0) {
                fprintf(stderr, "mkfs: partition lookup failed\n"); cfs_close(c); unlink(out); return 1;
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
            printf("     partition table: %s, fs on partition 1\n", gpt ? "gpt" : "mbr");
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
            fprintf(stderr, "  -p <n>: install into partition n (creates MBR + partition 1 if missing)\n");
            fprintf(stderr, "  -g:     use GPT instead of MBR (with -p)\n");
            return 1;
        }
        const char *iso_path = argv[2], *size_str = argv[3], *out = argv[4];
        int part = 0, gpt = 0, raw = 0;
        for (int i = 5; i < argc; i++) {
            if (!strcmp(argv[i], "-p") && i + 1 < argc) part = atoi(argv[++i]);
            else if (!strcmp(argv[i], "-g")) gpt = 1;
            else if (!strcmp(argv[i], "--raw")) raw = 1;
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
        if (part) {
            int kind = gpt ? CFS_PART_GPT : CFS_PART_MBR;
            if (cfs_part_label(c, kind) != 0) {
                fprintf(stderr, "install: partition label failed\n"); cfs_close(c); unlink(out); free(iso); return 1;
            }
            uint64_t pstart = 1ULL << 20;   /* LBA 2048 */
            int ar = cfs_part_add(c, pstart, disk_sz - pstart, 0x83, NULL, 0);
            if (ar < 0) {
                fprintf(stderr, "install: partadd failed (%d)\n", ar); cfs_close(c); unlink(out); free(iso); return 1;
            }
            CfsPartition p;
            if (cfs_part_get(c, 1, &p) != 0) {
                fprintf(stderr, "install: partition lookup failed\n"); cfs_close(c); unlink(out); free(iso); return 1;
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

        printf("cfs: ISO %s installed on %s (%llu MB disk%s)\n", iso_path, out,
               (unsigned long long)(disk_sz >> 20), part ? ", partition 1" : "");
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
                              rc == -7 ? "bad GUID" : "failed";
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
        if (rc) fprintf(stderr, "compact failed\n");
        else printf("compact ok\n");
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

    usage(argv[0]);
    return 1;
}
