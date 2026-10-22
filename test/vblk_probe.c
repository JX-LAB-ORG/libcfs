/* vblk_probe — probe the virtual block device (run under cfs_block_hook.so)
 * usage: vblk_probe <dev> size64|ssz|getsize|rdev|rrpart
 *        vblk_probe <dev> read <off> <len>     (hex bytes)
 *        vblk_probe <dev> write <off> <len>    (ok | fail:<errno>) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/fs.h>
#include <linux/hdreg.h>

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    const char *dev = argv[1];
    const char *cmd = argv[2];

    if (!strcmp(cmd, "size64") || !strcmp(cmd, "ssz") || !strcmp(cmd, "getsize") ||
        !strcmp(cmd, "rrpart")) {
        int fd = open(dev, O_RDONLY);
        if (fd < 0) { printf("open-fail\n"); return 0; }
        if (!strcmp(cmd, "size64")) {
            uint64_t sz;
            if (ioctl(fd, BLKGETSIZE64, &sz)) { printf("ioctl-fail\n"); return 0; }
            printf("%llu\n", (unsigned long long)sz);
        } else if (!strcmp(cmd, "ssz")) {
            int ssz;
            if (ioctl(fd, BLKSSZGET, &ssz)) { printf("ioctl-fail\n"); return 0; }
            printf("%d\n", ssz);
        } else if (!strcmp(cmd, "getsize")) {
            unsigned long sz;
            if (ioctl(fd, BLKGETSIZE, &sz)) { printf("ioctl-fail\n"); return 0; }
            printf("%lu\n", sz);
        } else {
            printf("%s\n", ioctl(fd, BLKRRPART) ? "fail" : "ok");
        }
        return 0;
    }
    if (!strcmp(cmd, "rdev")) {
        struct stat st;
        if (stat(dev, &st)) { printf("stat-fail\n"); return 0; }
        printf("%u:%u\n", major(st.st_rdev), minor(st.st_rdev));
        return 0;
    }
    if (!strcmp(cmd, "read") && argc >= 5) {
        unsigned long off = strtoul(argv[3], 0, 0);
        unsigned long len = strtoul(argv[4], 0, 0);
        int fd = open(dev, O_RDONLY);
        if (fd < 0) { printf("open-fail\n"); return 0; }
        uint8_t *b = malloc(len);
        ssize_t n = pread(fd, b, len, (off_t)off);
        if (n != (ssize_t)len) { printf("read-fail:%zd\n", n); return 0; }
        for (size_t i = 0; i < len; i++) printf("%02x", b[i]);
        printf("\n");
        return 0;
    }
    if ((!strcmp(cmd, "write") || !strcmp(cmd, "writerand")) && argc >= 5) {
        unsigned long off = strtoul(argv[3], 0, 0);
        unsigned long len = strtoul(argv[4], 0, 0);
        int fd = open(dev, O_RDWR);
        if (fd < 0) { printf("open-fail\n"); return 0; }
        uint8_t *b = malloc(len);
        if (!b) { printf("alloc-fail\n"); return 0; }
        if (!strcmp(cmd, "write")) {
            memset(b, 0xA5, len);            /* compressible: capacity tests */
        } else {
            uint64_t s = 0x9E3779B97F4A7C15ull;   /* incompressible: quota tests */
            for (unsigned long i = 0; i < len; i++) {
                s ^= s << 13; s ^= s >> 7; s ^= s << 17;
                b[i] = (uint8_t)(s >> 33);
            }
        }
        ssize_t n = pwrite(fd, b, len, (off_t)off);
        free(b);
        if (n == (ssize_t)len) { printf("ok\n"); return 0; }
        const char *nm = errno == ENOSPC ? "ENOSPC" : errno == EIO ? "EIO"
                       : errno == EINVAL ? "EINVAL" : "other";
        printf("fail:%s:%d\n", nm, errno);
        return 0;
    }
    if (!strcmp(cmd, "geo") || !strcmp(cmd, "ident") || !strcmp(cmd, "iomin") ||
        !strcmp(cmd, "ioopt") || !strcmp(cmd, "alignoff") || !strcmp(cmd, "discard")) {
        int fd = open(dev, O_RDWR);
        if (fd < 0) { printf("open-fail\n"); return 0; }
        if (!strcmp(cmd, "geo")) {
            struct hd_geometry g;
            if (ioctl(fd, HDIO_GETGEO, &g)) { printf("ioctl-fail\n"); return 0; }
            printf("%u:%u:%u:%lu\n", g.heads, g.sectors, g.cylinders, g.start);
        } else if (!strcmp(cmd, "ident")) {
            unsigned char id[512];
            if (ioctl(fd, HDIO_GET_IDENTITY, id)) { printf("ioctl-fail\n"); return 0; }
            char model[41]; memcpy(model, id + 54, 40); model[40] = 0;
            char *e = model + 39; while (e >= model && *e == ' ') *e-- = 0;
            printf("%s\n", model);
        } else if (!strcmp(cmd, "iomin")) {
            unsigned int v;
            if (ioctl(fd, BLKIOMIN, &v)) { printf("ioctl-fail\n"); return 0; }
            printf("%u\n", v);
        } else if (!strcmp(cmd, "ioopt")) {
            unsigned int v;
            if (ioctl(fd, BLKIOOPT, &v)) { printf("ioctl-fail\n"); return 0; }
            printf("%u\n", v);
        } else if (!strcmp(cmd, "alignoff")) {
            int v;
            if (ioctl(fd, BLKALIGNOFF, &v)) { printf("ioctl-fail\n"); return 0; }
            printf("%d\n", v);
        } else {
            unsigned long off = strtoul(argv[3], 0, 0);
            unsigned long len = strtoul(argv[4], 0, 0);
            uint64_t rng[2] = { off, len };
            if (ioctl(fd, BLKDISCARD, rng)) { printf("ioctl-fail\n"); return 0; }
            printf("ok\n");
        }
        return 0;
    }
    if (!strcmp(cmd, "stalecheck") && argc >= 5) {
        /* single-process stale-cache + BLKRRPART scenario:
         * prime the partition cache, wait for an external partadd to land,
         * the new partition must be invisible, then BLKRRPART must reveal it. */
        int fd = open(dev, O_RDONLY);
        if (fd < 0) { printf("open-fail\n"); return 0; }
        /* Tell the caller the device is held, so the external writer it is
         * about to start cannot race us: a fixed sleep on the writer's side
         * guessed how long this process takes to open, and on a loaded
         * machine the guess loses — the writer grabbed the lock first and
         * this open failed, which the test could only report as "open-fail"
         * rather than the refusal it was checking for. */
        const char *ready = getenv("CFS_PROBE_READY");
        if (ready) {
            int rf = open(ready, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (rf >= 0) close(rf);
        }
        uint64_t sz;
        if (ioctl(fd, BLKGETSIZE64, &sz)) { printf("ioctl-fail\n"); return 0; }
        usleep(900 * 1000);
        int fd3 = open(argv[4], O_RDONLY);
        int stale = (fd3 < 0);
        if (fd3 >= 0) close(fd3);
        if (ioctl(fd, BLKRRPART) != 0) { printf("rrpart-fail\n"); return 0; }
        fd3 = open(argv[4], O_RDONLY);
        if (fd3 < 0) { printf("still-fail\n"); return 0; }
        uint64_t s3;
        if (ioctl(fd3, BLKGETSIZE64, &s3)) { printf("ioctl2-fail\n"); return 0; }
        close(fd3);
        printf("%s:%llu\n", stale ? "stale" : "visible", (unsigned long long)s3);
        return 0;
    }
    return 2;
}
