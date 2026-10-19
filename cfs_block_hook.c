/* cfs_block_hook.c — LD_PRELOAD: virtual block device with full debug logging */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <linux/fs.h>
#include <linux/hdreg.h>
#include <limits.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define _DBG(fmt,...) fprintf(stderr,"[cfs-block] " fmt "\n",##__VA_ARGS__)

/* ── cfs types ──────────────────────────────────────────────── */
#define CFS_RDONLY 0x01
#define CFS_RDWR   0x02
#define CFS_RAW    0x08   /* store data uncompressed */
struct _cfs; typedef struct _cfs CFS;
typedef struct {
    int      index;
    uint64_t start;
    uint64_t size;
    int      is_gpt;
    uint8_t  mbr_type;
    int      bootable;
    char     type_str[40];
    char     guid[37];
} CfsPartition;
extern CFS     *cfs_open(const char *p, int f);
extern void     cfs_close(CFS *c);
extern ssize_t  cfs_block_read(CFS *c, void *b, size_t s, off_t o);
extern int      cfs_block_write(CFS *c, const void *b, size_t s, off_t o);
extern uint64_t cfs_block_size(CFS *c);
extern int      cfs_part_count(CFS *c);
extern int      cfs_part_get(CFS *c, int idx, CfsPartition *out);
extern void     cfs_part_invalidate(CFS *c);
typedef struct {              /* mirrors CfsDiskAttrs in cfs.h */
    int  kind;
    int  removable;
    int  rotational;
    char model[24];
} CfsDiskAttrs;
extern int      cfs_disk_get(CFS *c, CfsDiskAttrs *out);

/* ── State ──────────────────────────────────────────────────── */
static char blk_dev[256], blk_file[512];
static char blk_base[256];      /* CFS_BLOCK_DEV with trailing digits stripped */
static CFS *blk_cfs;
static int blk_parts = 0;       /* CFS_BLOCK_PARTS=1 exposes /dev/vdaN */
static int blk_ssz = 512;       /* CFS_SECTOR_SIZE=512|4096 */

#define MAX_BLK_FD 16
typedef struct {
    int      active;
    off_t    pos;
    int      part;              /* 0 = whole disk, N = partition */
    uint64_t pstart;            /* partition start in disk bytes */
    uint64_t psize;             /* partition size in bytes */
} BlkFd;
static BlkFd blk_fds[MAX_BLK_FD];

static int blk_fd_alloc(void) {
    for (int i = 10; i < MAX_BLK_FD; i++)
        if (!blk_fds[i].active) { blk_fds[i].active = 1; blk_fds[i].pos = 0; return i; }
    errno = EMFILE; return -1;
}
static BlkFd *blk_fd_get(int fd) {
    if (fd >= 10 && fd < MAX_BLK_FD && blk_fds[fd].active) return &blk_fds[fd];
    return NULL;
}

/* Resolve a path: 1 = ours (whole disk or partition), 0 = not ours,
 * -1 = syntactically ours but partition lookup failed (ENOENT). */
static int blk_resolve(const char *p, int *part, uint64_t *pstart, uint64_t *psize) {
    if (!blk_cfs || !blk_dev[0]) return 0;
    if (!strcmp(p, blk_dev)) {
        *part = 0; *pstart = 0; *psize = cfs_block_size(blk_cfs);
        return 1;
    }
    if (!blk_parts) return 0;
    size_t bl = strlen(blk_base);
    if (strncmp(p, blk_base, bl) != 0) return 0;
    if (!isdigit((unsigned char)p[bl])) return 0;
    int n = atoi(p + bl);
    if (n <= 0) return 0;
    CfsPartition cp;
    if (cfs_part_get(blk_cfs, n, &cp) != 0) { errno = ENOENT; return -1; }
    *part = n; *pstart = cp.start; *psize = cp.size;
    return 1;
}

/* ── Real libc pointers ─────────────────────────────────────── */
static int     (*_o)(const char*,int,...);
static int     (*_oa)(int,const char*,int,...);
static ssize_t (*_r)(int,void*,size_t);
static ssize_t (*_w)(int,const void*,size_t);
static int     (*_c)(int);
static off_t   (*_ls)(int,off_t,int);
static int     (*_io)(int,int,...);
static int     (*_fs)(int,struct stat*);
static int     (*_st)(const char*,struct stat*);
static int     (*_ac)(const char*,int);
static int     (*_fc)(int,int,...);
#define LOAD(p,fn) do{if(!(p))(p)=(__typeof__(p))dlsym(RTLD_NEXT,fn);}while(0)

__attribute__((constructor)) static void _init(void) {
    _o =  (typeof(_o)) dlsym(RTLD_NEXT, "open");
    _oa = (typeof(_oa))dlsym(RTLD_NEXT, "openat");
    _r =  (typeof(_r)) dlsym(RTLD_NEXT, "read");
    _w =  (typeof(_w)) dlsym(RTLD_NEXT, "write");
    _c =  (typeof(_c)) dlsym(RTLD_NEXT, "close");
    _ls = (typeof(_ls))dlsym(RTLD_NEXT, "lseek");
    _io = (typeof(_io))dlsym(RTLD_NEXT, "ioctl");
    _fs = (typeof(_fs))dlsym(RTLD_NEXT, "fstat");
    _st = (typeof(_st))dlsym(RTLD_NEXT, "stat");
    _ac = (typeof(_ac))dlsym(RTLD_NEXT, "access");
    _fc = (typeof(_fc))dlsym(RTLD_NEXT, "fcntl");
    const char *dev = getenv("CFS_BLOCK_DEV"), *file = getenv("CFS_BLOCK_FILE");
    if (!dev || !file) return;
    strncpy(blk_dev, dev, 255); blk_dev[255] = 0;
    strncpy(blk_file, file, 511); blk_file[511] = 0;
    const char *ps = getenv("CFS_BLOCK_PARTS");
    const char *sz = getenv("CFS_SECTOR_SIZE");
    if (ps && !strcmp(ps, "1")) blk_parts = 1;
    if (sz) { int v = atoi(sz); if (v == 4096) blk_ssz = 4096; }
    /* Partition aliases need a base name without trailing digits */
    strncpy(blk_base, blk_dev, sizeof(blk_base) - 1); blk_base[sizeof(blk_base) - 1] = 0;
    size_t bbl = strlen(blk_base);
    while (bbl > 0 && isdigit((unsigned char)blk_base[bbl - 1])) bbl--;
    if (bbl < strlen(blk_base)) { blk_base[bbl] = 0; blk_parts = 0; }  /* dev ends in digit: no aliases */
    blk_cfs = cfs_open(blk_file, CFS_RDWR | CFS_RAW);
    _DBG("init dev=%s cfs=%p sz=%llu parts=%d ssz=%d", blk_dev, (void*)blk_cfs,
         (unsigned long long)(blk_cfs ? cfs_block_size(blk_cfs) : 0), blk_parts, blk_ssz);
    memset(blk_fds, 0, sizeof(blk_fds));
}
__attribute__((destructor)) static void _fin(void) {
    if (blk_cfs) { cfs_close(blk_cfs); blk_cfs = NULL; }
}

/* ═══════════════════════════════════════════════════════════════
   open family
   ═══════════════════════════════════════════════════════════════ */
/* The drive's own sysfs attributes, served for whoever reads the exact
 * paths (lsblk-style directory enumeration belongs to a real device model,
 * not to a preload shim). */
static const char *blk_sysfs_content(const char *p) {
    static char buf[24];
    if (!blk_dev[0] || !blk_cfs) return NULL;
    const char *base = strrchr(blk_dev, '/');
    base = base ? base + 1 : blk_dev;
    CfsDiskAttrs a;
    if (cfs_disk_get(blk_cfs, &a) != 0) return NULL;
    char path[360];
    snprintf(path, sizeof(path), "/sys/block/%s/queue/rotational", base);
    if (!strcmp(p, path)) { snprintf(buf, sizeof(buf), "%d\n", a.rotational); return buf; }
    snprintf(path, sizeof(path), "/sys/block/%s/removable", base);
    if (!strcmp(p, path)) { snprintf(buf, sizeof(buf), "%d\n", a.removable); return buf; }
    snprintf(path, sizeof(path), "/sys/block/%s/size", base);
    if (!strcmp(p, path)) {
        snprintf(buf, sizeof(buf), "%llu\n",
                 (unsigned long long)(cfs_block_size(blk_cfs) / 512));
        return buf;
    }
    return NULL;
}


int open(const char *p, int flags, ...) {
    LOAD(_o, "open");
    int part = 0; uint64_t pstart = 0, psize = 0;
    int r = blk_resolve(p, &part, &pstart, &psize);
    if (r > 0) {
        int fd = blk_fd_alloc();
        _DBG("OPEN %s flags=0x%x → fd=%d part=%d", p, flags, fd, part);
        if (fd < 0) return -1;
        blk_fds[fd].part = part; blk_fds[fd].pstart = pstart; blk_fds[fd].psize = psize;
        return fd;
    }
    if (r < 0) return -1;   /* partition path, lookup failed → ENOENT */
    {
        const char *sc = blk_sysfs_content(p);
        if (sc) {
            int fd = (int)syscall(SYS_memfd_create, "cfs-sysfs", 0);
            if (fd < 0) return -1;
            size_t n = strlen(sc);
            if (write(fd, sc, n) != (ssize_t)n) { close(fd); return -1; }
            lseek(fd, 0, SEEK_SET);
            _DBG("OPEN %s -> memfd %d (%s)", p, fd, sc);
            return fd;
        }
    }
    va_list ap; va_start(ap, flags); mode_t m = va_arg(ap, mode_t); va_end(ap);
    return _o(p, flags, m);
}
int open64(const char *p, int f, ...) {
    va_list ap; va_start(ap, f); mode_t m = va_arg(ap, mode_t); va_end(ap);
    return open(p, f, m);
}
int openat(int d, const char *p, int f, ...) {
    va_list ap; va_start(ap, f); mode_t m = va_arg(ap, mode_t); va_end(ap);
    if (d == AT_FDCWD) return open(p, f, m);
    LOAD(_oa, "openat"); return _oa(d, p, f, m);
}
int openat64(int d, const char *p, int f, ...) {
    va_list ap; va_start(ap, f); mode_t m = va_arg(ap, mode_t); va_end(ap);
    if (d == AT_FDCWD) return open(p, f, m);
    LOAD(_oa, "openat"); return _oa(d, p, f, m);
}
int __open_2(const char *p, int f) { return open(p, f, 0); }
int creat(const char *p, mode_t m) { return open(p, O_CREAT|O_WRONLY|O_TRUNC, m); }

/* ═══════════════════════════════════════════════════════════════
   read / pread
   ═══════════════════════════════════════════════════════════════ */
ssize_t read(int fd, void *buf, size_t n) {
    BlkFd *bf = blk_fd_get(fd);
    if (!bf) { LOAD(_r, "read"); return _r(fd, buf, n); }
    ssize_t nr = cfs_block_read(blk_cfs, buf, n, (off_t)(bf->pstart + (uint64_t)bf->pos));
    _DBG("READ fd=%d n=%zu off=%lld → %zd", fd, n, (long long)bf->pos, nr);
    if (nr > 0) bf->pos += nr;
    return nr;
}
ssize_t pread(int fd, void *buf, size_t n, off_t off) {
    BlkFd *bf = blk_fd_get(fd);
    if (!bf) { static ssize_t (*_pr)(int,void*,size_t,off_t); LOAD(_pr, "pread"); return _pr(fd, buf, n, off); }
    ssize_t nr = cfs_block_read(blk_cfs, buf, n, (off_t)(bf->pstart + (uint64_t)off));
    _DBG("PREAD fd=%d off=%lld n=%zu → %zd", fd, (long long)off, n, nr);
    return nr;
}
ssize_t pread64(int fd, void *b, size_t n, off_t o) { return pread(fd, b, n, o); }

/* ═══════════════════════════════════════════════════════════════
   write / pwrite
   ═══════════════════════════════════════════════════════════════ */
ssize_t write(int fd, const void *buf, size_t n) {
    BlkFd *bf = blk_fd_get(fd);
    if (!bf) { LOAD(_w, "write"); return _w(fd, buf, n); }
    _DBG("WRITE fd=%d n=%zu off=%lld", fd, n, (long long)bf->pos);
    if (cfs_block_write(blk_cfs, buf, n, (off_t)(bf->pstart + (uint64_t)bf->pos)) != 0) return -1;
    bf->pos += (off_t)n;
    return (ssize_t)n;
}
ssize_t pwrite(int fd, const void *buf, size_t n, off_t off) {
    BlkFd *bf = blk_fd_get(fd);
    if (!bf) { static ssize_t (*_pw)(int,const void*,size_t,off_t); LOAD(_pw, "pwrite"); return _pw(fd, buf, n, off); }
    _DBG("PWRITE fd=%d off=%lld n=%zu", fd, (long long)off, n);
    if (cfs_block_write(blk_cfs, buf, n, (off_t)(bf->pstart + (uint64_t)off)) != 0) return -1;
    return (ssize_t)n;
}
ssize_t pwrite64(int fd, const void *b, size_t n, off_t o) { return pwrite(fd, b, n, o); }

/* ═══════════════════════════════════════════════════════════════
   close / lseek
   ═══════════════════════════════════════════════════════════════ */
int close(int fd) {
    BlkFd *bf = blk_fd_get(fd);
    if (!bf) { LOAD(_c, "close"); return _c(fd); }
    _DBG("CLOSE fd=%d", fd);
    memset(bf, 0, sizeof(*bf));
    return 0;
}
off_t lseek(int fd, off_t off, int whence) {
    BlkFd *bf = blk_fd_get(fd);
    if (!bf) { LOAD(_ls, "lseek"); return _ls(fd, off, whence); }
    uint64_t sz = bf->part ? bf->psize : cfs_block_size(blk_cfs);
    off_t np;
    switch (whence) {
    case SEEK_SET: np = off; break;
    case SEEK_CUR: np = bf->pos + off; break;
    case SEEK_END: np = (off_t)sz + off; break;
    default: errno = EINVAL; return (off_t)-1;
    }
    if (np < 0) { errno = EINVAL; return (off_t)-1; }
    bf->pos = np;
    _DBG("LSEEK fd=%d off=%lld whence=%d → %lld (sz=%llu)", fd, (long long)off, whence, (long long)np, (unsigned long long)sz);
    return np;
}
off_t lseek64(int fd, off_t o, int w) { return lseek(fd, o, w); }

/* ═══════════════════════════════════════════════════════════════
   ioctl
   ═══════════════════════════════════════════════════════════════ */
/* glibc declares the request as unsigned long, musl as int — match whichever
 * this is, or the definition conflicts with the header's prototype. */
#if defined(__GLIBC__)
int ioctl(int fd, unsigned long req, ...) {
#else
int ioctl(int fd, int req, ...) {
#endif
    BlkFd *bf = blk_fd_get(fd);
    if (!bf) {
        va_list ap; va_start(ap, req); void *a = va_arg(ap, void*); va_end(ap);
        LOAD(_io, "ioctl"); return _io(fd, req, a);
    }
    va_list ap; va_start(ap, req); void *a = va_arg(ap, void*); va_end(ap);
    _DBG("IOCTL fd=%d req=0x%x", fd, (unsigned)req);
    uint64_t sz = bf->part ? bf->psize : cfs_block_size(blk_cfs);
    switch ((unsigned)req) {
    case BLKGETSIZE64: *(uint64_t*)a = sz;
        _DBG("  BLKGETSIZE64 = %llu", (unsigned long long)sz); return 0;
    case BLKSSZGET: *(int*)a = blk_ssz; return 0;
    case BLKBSZGET: *(int*)a = 4096; return 0;
    case BLKGETSIZE: *(unsigned long*)a = (unsigned long)(sz / (uint64_t)blk_ssz); return 0;
    case BLKIOMIN: *(unsigned int*)a = blk_ssz; return 0;
    case BLKIOOPT: *(unsigned int*)a = 4096; return 0;
    case BLKALIGNOFF: *(int*)a = 0; return 0;
    case 0x125E: /*BLKROGET*/ *(int*)a = 0; return 0;
    case 0x125F: /*BLKRRPART — truly re-read the disk: the inode table may
                    have moved (external writers append new blocks), so
                    reopen the container and swap in a fresh handle */
        if (bf->part != 0) { errno = EINVAL; return -1; }
        {
            CFS *nc = cfs_open(blk_file, CFS_RDWR | CFS_RAW);
            if (!nc) { errno = EIO; return -1; }
            CFS *old = blk_cfs;
            blk_cfs = nc;
            if (old) cfs_close(old);
            _DBG("  BLKRRPART: reopened %s", blk_file);
            return 0;
        }
    case 0x1261: /*BLKFLSBUF*/ return 0;
    case 0x1277: /*BLKDISCARD — arg is uint64_t range[2] (start, len) bytes;
                    discarded data must read back as zeros */
        {
            uint64_t rng[2];
            memcpy(rng, a, sizeof(rng));
            if (bf->part) {
                if (rng[0] + rng[1] > bf->psize) { errno = EINVAL; return -1; }
                rng[0] += bf->pstart;
            }
            if (rng[0] + rng[1] > cfs_block_size(blk_cfs)) { errno = EINVAL; return -1; }
            static uint8_t zbuf[4096];
            uint64_t off = rng[0], left = rng[1];
            while (left > 0) {
                size_t n = left > sizeof(zbuf) ? sizeof(zbuf) : (size_t)left;
                if (cfs_block_write(blk_cfs, zbuf, n, (off_t)off) != 0) { errno = EIO; return -1; }
                off += n; left -= n;
            }
            return 0;
        }
    case HDIO_GETGEO: {
        struct hd_geometry *g = a;
        uint64_t sectors = sz / 512;
        g->heads = 255;
        g->sectors = 63;
        g->cylinders = (unsigned short)(sectors / (255ULL * 63ULL));
        g->start = (unsigned long)(bf->part ? bf->pstart / 512 : 0);
        return 0;
    }
    case HDIO_GET_IDENTITY: {
        /* ATA identify block: serial @20, firmware @46, model @54,
         * all space-padded to fixed widths.  The model comes from the
         * container's own disk identity, so an image declared as an SD card
         * reports itself as one. */
        unsigned char *id = a;
        CfsDiskAttrs da;
        const char *model = "CFS VIRTUAL DISK";
        if (blk_cfs && cfs_disk_get(blk_cfs, &da) == 0) model = da.model;
        memset(id, 0, 512);
        memset(id + 20, ' ', 20);
        memcpy(id + 20, "CFS0001", 7);
        memset(id + 46, ' ', 8);
        memcpy(id + 46, "v3.1", 4);
        memset(id + 54, ' ', 40);
        size_t ml = strlen(model);
        if (ml > 40) ml = 40;
        memcpy(id + 54, model, ml);
        return 0;
    }
    default: _DBG("  UNKNOWN IOCTL"); errno = ENOTTY; return -1;
    }
}

/* ═══════════════════════════════════════════════════════════════
   stat / fstat
   ═══════════════════════════════════════════════════════════════ */
int fstat(int fd, struct stat *st) {
    BlkFd *bf = blk_fd_get(fd);
    if (!bf) { LOAD(_fs, "fstat"); return _fs(fd, st); }
    memset(st, 0, sizeof(*st));
    st->st_mode   = S_IFBLK | 0660;
    st->st_rdev   = makedev(252, bf->part);
    st->st_size   = (off_t)(bf->part ? bf->psize : cfs_block_size(blk_cfs));
    st->st_blksize = 4096;
    st->st_blocks  = (st->st_size + 511) / 512;
    _DBG("FSTAT fd=%d size=%lld mode=0%o part=%d", fd, (long long)st->st_size, st->st_mode, bf->part);
    return 0;
}
int stat(const char *p, struct stat *st) {
    int part = 0; uint64_t pstart = 0, psize = 0;
    int r = blk_resolve(p, &part, &pstart, &psize);
    if (r > 0) {
        memset(st, 0, sizeof(*st));
        st->st_mode   = S_IFBLK | 0660;
        st->st_rdev   = makedev(252, part);
        st->st_size   = (off_t)psize;
        st->st_blksize = 4096;
        st->st_blocks  = (st->st_size + 511) / 512;
        _DBG("STAT %s size=%lld mode=0%o part=%d", p, (long long)st->st_size, st->st_mode, part);
        return 0;
    }
    if (r < 0) { errno = ENOENT; return -1; }
    {
        const char *sc = blk_sysfs_content(p);
        if (sc) {
            memset(st, 0, sizeof(*st));
            st->st_mode = S_IFREG | 0444;
            st->st_size = (off_t)strlen(sc);
            st->st_blksize = 4096;
            st->st_blocks = 1;
            return 0;
        }
    }
    LOAD(_st, "stat"); return _st(p, st);
}
int lstat(const char *p, struct stat *st) { return stat(p, st); }

int __xstat(int v, const char *p, struct stat *s)   { (void)v; return stat(p, s); }
int __xstat64(int v, const char *p, struct stat *s)  { (void)v; return stat(p, s); }
int __lxstat(int v, const char *p, struct stat *s)   { (void)v; return stat(p, s); }
int __lxstat64(int v, const char *p, struct stat *s) { (void)v; return stat(p, s); }
int __fxstat(int v, int fd, struct stat *s)          { (void)v; return fstat(fd, s); }
int __fxstat64(int v, int fd, struct stat *s)        { (void)v; return fstat(fd, s); }
int __fxstatat(int v, int d, const char *p, struct stat *s, int f) {
    (void)v; return d == AT_FDCWD ? stat(p, s) : fstat(d, s);
}

/* ═══════════════════════════════════════════════════════════════
   access / fcntl / readlink / realpath
   ═══════════════════════════════════════════════════════════════ */
int access(const char *p, int m) {
    int part = 0; uint64_t pstart = 0, psize = 0;
    int r = blk_resolve(p, &part, &pstart, &psize);
    if (r > 0) { _DBG("ACCESS %s mode=%d → 0", p, m); return 0; }
    if (r < 0) { errno = ENOENT; return -1; }
    LOAD(_ac, "access"); return _ac(p, m);
}
int fcntl(int fd, int cmd, ...) {
    BlkFd *bf = blk_fd_get(fd);
    if (!bf) { va_list ap; va_start(ap, cmd); long arg = va_arg(ap, long); va_end(ap);
        LOAD(_fc, "fcntl"); return _fc(fd, cmd, arg); }
    _DBG("FCNTL fd=%d cmd=%d", fd, cmd);
    switch (cmd) { case 1: case 2: return 0; case 3: return O_RDWR; case 4: return 0; default: return 0; }
}
ssize_t readlink(const char *p, char *b, size_t n) {
    int part = 0; uint64_t pstart = 0, psize = 0;
    int r = blk_resolve(p, &part, &pstart, &psize);
    if (r > 0) {
        size_t l = strlen(blk_dev); if (l >= n) l = n - 1;
        memcpy(b, blk_dev, l); b[l] = 0;
        _DBG("READLINK %s → '%s'", p, b);
        return (ssize_t)l;
    }
    if (r < 0) { errno = ENOENT; return -1; }
    static ssize_t (*_rl)(const char*, char*, size_t); LOAD(_rl, "readlink"); return _rl(p, b, n);
}
char *realpath(const char *p, char *r) {
    int part = 0; uint64_t pstart = 0, psize = 0;
    int rc = blk_resolve(p, &part, &pstart, &psize);
    if (rc > 0) {
        _DBG("REALPATH %s → '%s'", p, blk_dev);
        if (r) { strncpy(r, blk_dev, PATH_MAX - 1); r[PATH_MAX - 1] = 0; return r; }
        return strdup(blk_dev);
    }
    if (rc < 0) { errno = ENOENT; return NULL; }
    static typeof(realpath) *_rp; if (!_rp) _rp = (typeof(_rp))dlsym(RTLD_NEXT, "realpath"); return _rp(p, r);
}

/* ═══════════════════════════════════════════════════════════════
   misc
   ═══════════════════════════════════════════════════════════════ */
int dup(int oldfd) {
    BlkFd *bf = blk_fd_get(oldfd);
    if (!bf) { static int (*_du)(int); LOAD(_du, "dup"); return _du(oldfd); }
    int fd = blk_fd_alloc(); if (fd < 0) return -1;
    blk_fds[fd] = *bf; blk_fds[fd].pos = bf->pos;
    _DBG("DUP %d → %d", oldfd, fd);
    return fd;
}
int dup2(int oldfd, int newfd) {
    if (oldfd == newfd) return newfd;
    BlkFd *bf = blk_fd_get(oldfd);
    if (!bf) { static int (*_d2)(int, int); LOAD(_d2, "dup2"); return _d2(oldfd, newfd); }
    blk_fds[newfd] = *bf;
    _DBG("DUP2 %d %d", oldfd, newfd);
    return newfd;
}
int fsync(int fd) { BlkFd *bf = blk_fd_get(fd); if (bf) return 0;
    static int (*_sy)(int); LOAD(_sy, "fsync"); return _sy(fd); }
int fdatasync(int fd) { return fsync(fd); }
void sync(void) {}
int fallocate(int fd, int mode, off_t o, off_t l) {
    BlkFd *bf = blk_fd_get(fd);
    if (!bf) { static int (*_fa)(int, int, off_t, off_t); LOAD(_fa, "fallocate"); return _fa(fd, mode, o, l); }
    _DBG("FALLOCATE fd=%d off=%lld len=%lld → 0", fd, (long long)o, (long long)l);
    return 0;
}
int statfs(const char *p, struct statfs *s) {
    int part = 0; uint64_t pstart = 0, psize = 0;
    int r = blk_resolve(p, &part, &pstart, &psize);
    if (r > 0) {
        memset(s, 0, sizeof(*s)); s->f_type = 0xEF53; s->f_bsize = 4096;
        s->f_blocks = psize >> 12; s->f_bfree = s->f_blocks / 2;
        s->f_bavail = s->f_blocks / 2; s->f_files = 1 << 20; s->f_ffree = 1 << 19; s->f_namelen = 255;
        return 0;
    }
    if (r < 0) { errno = ENOENT; return -1; }
    static int (*_sfs)(const char*, struct statfs*); LOAD(_sfs, "statfs"); return _sfs(p, s);
}
int fstatfs(int fd, struct statfs *s) {
    BlkFd *bf = blk_fd_get(fd);
    if (!bf) { static int (*_fsfs)(int, struct statfs*); LOAD(_fsfs, "fstatfs"); return _fsfs(fd, s); }
    memset(s, 0, sizeof(*s)); s->f_type = 0xEF53; s->f_bsize = 4096;
    s->f_blocks = (bf->part ? bf->psize : cfs_block_size(blk_cfs)) >> 12;
    s->f_bfree = s->f_blocks / 2;
    s->f_bavail = s->f_blocks / 2; s->f_files = 1 << 20; s->f_ffree = 1 << 19; s->f_namelen = 255;
    return 0;
}
void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
    BlkFd *bf = blk_fd_get(fd);
    if (!bf) { static typeof(mmap)*_mm; if (!_mm) _mm = (typeof(_mm))dlsym(RTLD_NEXT, "mmap"); return _mm(addr, len, prot, flags, fd, off); }
    void *p = (void*)syscall(SYS_mmap, addr, len, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) return p;
    cfs_block_read(blk_cfs, p, len, (off_t)(bf->pstart + (uint64_t)off));
    if (!(prot & PROT_WRITE)) syscall(SYS_mprotect, p, len, prot);
    return p;
}
int munmap(void *addr, size_t len) { static int (*_mu)(void*, size_t); LOAD(_mu, "munmap"); return _mu(addr, len); }
