/* cfs-fuse — FUSE daemon that mounts a .cfs container as a real filesystem.
 *
 * Requires libfuse3:  apk add fuse3-dev
 * Build:  cc -std=gnu11 -O3 $(pkg-config --cflags fuse3) -I. -I../libcpool \
 *             cfs-fuse.c cfs.o ../libcpool/cpenc.o $(pkg-config --libs fuse3) -o cfs-fuse
 * Mount:  ./cfs-fuse -o allow_other container.cfs /mnt/cfs
 * Unmount: fusermount3 -u /mnt/cfs  */

#define FUSE_USE_VERSION 35
#include "cfs.h"
#include "cfs_format.h"
#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

static CFS *cfs_ctx;
static int cfs_flags;

/* ── Helpers ──────────────────────────────────────────────────── */
static void cfs_to_stat(const char *path, struct stat *st) {
    memset(st, 0, sizeof(*st));
    if (!path || !path[0]) {
        /* Root directory */
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
        return;
    }
    CfsStat cs;
    if (cfs_stat(cfs_ctx, path, &cs) != 0) {
        /* Check if it's a known directory via ls */
        CfsDirEntry ents[2];
        if (cfs_ls(cfs_ctx, path, ents, 2) > 0) {
            st->st_mode = S_IFDIR | 0755;
            st->st_nlink = 2;
            st->st_mtime = (time_t)cs.mtime;
            return;
        }
        return; /* not found */
    }
    if (cs.mode == CFS_MODE_DIR) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
    } else if (cs.mode == CFS_MODE_SYMLINK) {
        st->st_mode = S_IFLNK | 0777;
        st->st_size = (off_t)cs.size;
    } else {
        st->st_mode = S_IFREG | 0644;
        st->st_nlink = 1;
        st->st_size = (off_t)cs.size;
        st->st_blksize = 4096;
        st->st_blocks = (cs.size + 511) / 512;
    }
    st->st_mtime = (time_t)cs.mtime;
    st->st_atime = (time_t)cs.mtime;
    st->st_ctime = (time_t)cs.mtime;
    st->st_uid = getuid();
    st->st_gid = getgid();
}

/* ── FUSE callbacks ────────────────────────────────────────────── */

static int cfs_fuse_getattr(const char *path, struct stat *st,
                             struct fuse_file_info *fi) {
    (void)fi;
    const char *p = (*path == '/') ? path + 1 : path;
    if (!*p) { /* root */
        memset(st, 0, sizeof(*st));
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
        return 0;
    }
    cfs_to_stat(p, st);
    if (st->st_mode == 0) return -ENOENT;
    return 0;
}

static int cfs_fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                             off_t offset, struct fuse_file_info *fi,
                             enum fuse_readdir_flags flags) {
    (void)offset; (void)fi; (void)flags;
    const char *p = (*path == '/') ? path + 1 : path;

    CfsDirEntry ents[256];
    int n = cfs_ls(cfs_ctx, p, ents, 256);
    if (n < 0) return -ENOENT;

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    for (int i = 0; i < n; i++) {
        filler(buf, ents[i].name, NULL, 0, 0);
    }
    return 0;
}

static int cfs_fuse_open(const char *path, struct fuse_file_info *fi) {
    const char *p = (*path == '/') ? path + 1 : path;
    if (!*p) return -EISDIR;

    CfsStat cs;
    if (cfs_stat(cfs_ctx, p, &cs) != 0) {
        if ((fi->flags & O_CREAT)) return 0; /* will be created on write */
        return -ENOENT;
    }
    if (cs.mode == CFS_MODE_DIR) return -EISDIR;
    return 0;
}

static int cfs_fuse_read(const char *path, char *buf, size_t size, off_t offset,
                          struct fuse_file_info *fi) {
    (void)fi;
    const char *p = (*path == '/') ? path + 1 : path;
    ssize_t n = cfs_read(cfs_ctx, p, buf, size, offset);
    if (n < 0) return -EIO;
    return (int)n;
}

static int cfs_fuse_write(const char *path, const char *buf, size_t size,
                           off_t offset, struct fuse_file_info *fi) {
    (void)fi;
    const char *p = (*path == '/') ? path + 1 : path;

    if (offset == 0) {
        /* Full write — cfs_write handles it */
        if (cfs_write(cfs_ctx, p, buf, size) != 0) return -EIO;
        return (int)size;
    }

    /* Offset write: read-modify-write */
    size_t osz;
    void *old = cfs_read_all(cfs_ctx, p, &osz);
    size_t new_sz = (size_t)offset + size;
    if (new_sz < osz) new_sz = osz;
    uint8_t *new_buf = calloc(1, new_sz);
    if (!new_buf) return -ENOMEM;
    if (old && osz > 0) memcpy(new_buf, old, osz);
    memcpy(new_buf + offset, buf, size);
    free(old);
    int rc = cfs_write(cfs_ctx, p, new_buf, new_sz);
    free(new_buf);
    if (rc != 0) return -EIO;
    return (int)size;
}

static int cfs_fuse_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void)mode; (void)fi;
    const char *p = (*path == '/') ? path + 1 : path;
    cfs_write(cfs_ctx, p, NULL, 0); /* touch */
    return 0;
}

static int cfs_fuse_mkdir(const char *path, mode_t mode) {
    (void)mode;
    const char *p = (*path == '/') ? path + 1 : path;
    if (cfs_mkdir(cfs_ctx, p) != 0) return -EIO;
    return 0;
}

static int cfs_fuse_unlink(const char *path) {
    const char *p = (*path == '/') ? path + 1 : path;
    if (cfs_unlink(cfs_ctx, p) != 0) return -errno;
    return 0;
}

static int cfs_fuse_rename(const char *from, const char *to, unsigned int flags) {
    if (flags) return -EINVAL;
    const char *f = (*from == '/') ? from + 1 : from;
    const char *t = (*to == '/') ? to + 1 : to;
    if (cfs_rename(cfs_ctx, f, t) != 0) return -errno;
    return 0;
}

static int cfs_fuse_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    (void)fi;
    const char *p = (*path == '/') ? path + 1 : path;
    if (cfs_truncate(cfs_ctx, p, (uint64_t)size) != 0) return -EIO;
    return 0;
}

static int cfs_fuse_symlink(const char *target, const char *linkpath) {
    const char *l = (*linkpath == '/') ? linkpath + 1 : linkpath;
    if (cfs_symlink(cfs_ctx, target, l) != 0) return -errno;
    return 0;
}

static int cfs_fuse_readlink(const char *path, char *buf, size_t size) {
    const char *p = (*path == '/') ? path + 1 : path;
    ssize_t n = cfs_readlink(cfs_ctx, p, buf, size);
    if (n < 0) return -errno;
    if ((size_t)n >= size) n = (ssize_t)(size - 1);
    buf[n] = 0;
    return 0;
}

static int cfs_fuse_utimens(const char *path, const struct timespec tv[2],
                             struct fuse_file_info *fi) {
    (void)fi;
    const char *p = (*path == '/') ? path + 1 : path;
    uint64_t at = tv ? (uint64_t)tv[0].tv_sec : 0;
    uint64_t mt = tv ? (uint64_t)tv[1].tv_sec : 0;
    if (cfs_utimens(cfs_ctx, p, at, mt) != 0) return -errno;
    return 0;
}

static int cfs_fuse_statfs(const char *path, struct statvfs *stbuf) {
    (void)path;
    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->f_bsize = 4096;
    stbuf->f_frsize = 4096;
    stbuf->f_blocks = UINT64_MAX >> 12;
    stbuf->f_bfree = UINT64_MAX >> 12;
    stbuf->f_bavail = UINT64_MAX >> 12;
    stbuf->f_files = 1 << 20;
    stbuf->f_ffree = 1 << 20;
    stbuf->f_namemax = 255;
    return 0;
}

/* ── FUSE operations table ─────────────────────────────────────── */
static const struct fuse_operations cfs_ops = {
    .getattr  = cfs_fuse_getattr,
    .readdir  = cfs_fuse_readdir,
    .open     = cfs_fuse_open,
    .read     = cfs_fuse_read,
    .write    = cfs_fuse_write,
    .create   = cfs_fuse_create,
    .mkdir    = cfs_fuse_mkdir,
    .unlink   = cfs_fuse_unlink,
    .rename   = cfs_fuse_rename,
    .truncate = cfs_fuse_truncate,
    .symlink  = cfs_fuse_symlink,
    .readlink = cfs_fuse_readlink,
    .utimens  = cfs_fuse_utimens,
    .statfs   = cfs_fuse_statfs,
};

/* ── Main ──────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [options] <cfs_file> <mount_point>\n", argv[0]);
        fprintf(stderr, "Example: %s -o allow_other container.cfs /mnt/cfs\n", argv[0]);
        return 1;
    }

    /* Extract cfs file and mount point from args */
    const char *cfs_file = NULL, *mount_pt = NULL;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            if (!cfs_file) cfs_file = argv[i];
            else if (!mount_pt) mount_pt = argv[i];
        }
    }
    if (!cfs_file || !mount_pt) {
        fprintf(stderr, "Error: need <cfs_file> and <mount_point>\n");
        return 1;
    }

    /* Open cfs container */
    cfs_flags = CFS_RDWR;
    const char *raw_env = getenv("CFS_RAW");
    if (raw_env && raw_env[0] == '1') cfs_flags |= CFS_RAW;
    cfs_ctx = cfs_open(cfs_file, cfs_flags);
    if (!cfs_ctx) {
        /* Try creating if it doesn't exist */
        cfs_ctx = cfs_create(cfs_file);
        if (!cfs_ctx) { perror(cfs_file); return 1; }
        cfs_finalise(cfs_ctx);
        cfs_close(cfs_ctx);
        cfs_ctx = cfs_open(cfs_file, cfs_flags);
        if (!cfs_ctx) { perror(cfs_file); return 1; }
    }

    fprintf(stderr, "cfs-fuse: mounted %s on %s", cfs_file, mount_pt);
    if (cfs_flags & CFS_RAW) fprintf(stderr, " (RAW storage)");
    fprintf(stderr, "\n");

    /* Run FUSE main loop */
    int rc = fuse_main(args.argc, args.argv, &cfs_ops, NULL);
    cfs_close(cfs_ctx);
    return rc;
}
