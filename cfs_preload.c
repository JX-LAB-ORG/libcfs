#define _GNU_SOURCE
#include "cfs_path.h"
#include <stdint.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <dirent.h>
/* mount/umount prototypes — declared manually to avoid sys/mount.h
 * pulling in sys/ioctl.h which conflicts with our ioctl hook */
extern int mount(const char*, const char*, const char*, unsigned long, const void*);
extern int umount(const char*);
extern int umount2(const char*, int);
/* execve from unistd, klogctl/syslog */
extern int execve(const char*, char*const*, char*const*);
extern int klogctl(int, char*, int);
extern pid_t getpid(void);
extern char **environ;
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <limits.h>
#include <time.h>

/* Inode mode constants (from cfs_format.h, replicated for standalone build).
 * CFS_MODE_DEDUP is deliberately absent: a dedup entry is not something this
 * layer serves, and it must fall through to the ordinary-file path rather
 * than be mistaken for one. */
#define CFS_MODE_FILE    0
#define CFS_MODE_DIR     1
#define CFS_MODE_SYMLINK 2

/* ─── libcfs types ──────────────────────────────────────────────── */
#define CFS_RDONLY  0x01
#define CFS_RDWR    0x02
#define CFS_RAW     0x08   /* store data uncompressed */

typedef struct {
    char     name[256];
    uint8_t  is_dir;
    uint64_t size;
    uint64_t mtime;
} CfsDirEntry;

typedef struct {
    uint64_t size;
    uint64_t mtime;
    uint16_t mode;
    uint32_t block_count;
} CfsStat;

struct _cfs; typedef struct _cfs CFS;
extern CFS     *cfs_open(const char *p, int f);
extern int      cfs_lock_now(CFS *c);
extern void    *cfs_read_all(CFS *c, const char *p, size_t *o);
extern ssize_t  cfs_read(CFS *c, const char *p, void *b, size_t s, off_t o);
extern int      cfs_write(CFS *c, const char *p, const void *b, size_t s);
extern int      cfs_ls(CFS *c, const char *d, CfsDirEntry *e, int m);
extern int      cfs_stat(CFS *c, const char *p, CfsStat *o);
extern int      cfs_mkdir(CFS *c, const char *p);
extern int      cfs_unlink(CFS *c, const char *p);
extern int      cfs_truncate(CFS *c, const char *p, uint64_t s);
extern int      cfs_symlink(CFS *c, const char *t, const char *l);
extern ssize_t  cfs_readlink(CFS *c, const char *p, char *b, size_t s);
extern int      cfs_rename(CFS *c, const char *o, const char *n);
extern int      cfs_utimens(CFS *c, const char *p, uint64_t a, uint64_t m);
extern void     cfs_close(CFS *c);

/* ─── State ─────────────────────────────────────────────────────── */
static char cfs_mount[512];
static char cfs_path[512];
static CFS *cfs;
static int  cfs_locked;   /* this process holds the exclusive lock */
static int  cfs_member;   /* this process is inside a tree that holds it */
static int  cfs_ready;    /* directories materialised, lock settled */
static int  cfs_warned;   /* the contention message is printed once */

/* ─── Virtual fd table ──────────────────────────────────────────── */
#define MAX_VFD 1024
#define VFD_DIRTY   0x01
#define VFD_WRONLY  0x02
#define VFD_RDWR    0x04
typedef struct {
    int    active;
    int    owner;     /* 1 = this slot owns buf; dups borrow it */
    int    flags;     /* VFD_DIRTY | VFD_WRONLY | VFD_RDWR */
    void  *buf;
    size_t size;
    size_t capacity;
    off_t  pos;
    char   path[256];
} VFile;
static VFile vfds[MAX_VFD];

/* ─── Real libc function pointers (explicit types, no typeof) ──── */
static int       (*_o)   (const char*, int, mode_t);
static int       (*_oat) (int, const char*, int, mode_t);
static ssize_t   (*_r)   (int, void*, size_t);
static ssize_t   (*_pr)  (int, void*, size_t, off_t);
static ssize_t   (*_w)   (int, const void*, size_t);
static int       (*_c)   (int);
static off_t     (*_ls)  (int, off_t, int);
static int       (*_st)  (const char*, struct stat*);
static int       (*_fst) (int, struct stat*);
static int       (*_acc) (const char*, int);
static int       (*_fc)  (int, int, ...);
static DIR*      (*_od)  (const char*);
static int       (*_cd)  (DIR*);
static struct dirent* (*_rd)(DIR*);
static FILE*     (*_fopen)(const char*, const char*);
static FILE*     (*_fdopen)(int, const char*);
static FILE*     (*_fmemopen)(void*, size_t, const char*);
static int       (*_fclose)(FILE*);
static int       (*_chdir)(const char*);

/* Track fmemopen buffers so we can free on fclose */
#define MAX_FMEM 64
static struct { FILE *fp; void *buf; size_t size; } fmem_tab[MAX_FMEM];
static void*     (*_mm)  (void*, size_t, int, int, int, off_t);
static int       (*_mu)  (void*, size_t);
static ssize_t   (*_rv)  (int, const struct iovec*, int);

#define LOAD(p, fn) do { if (!p) p = (__typeof__(p))dlsym(RTLD_NEXT, fn); } while(0)

/* ─── Constructor ───────────────────────────────────────────────── */
static void cfs_mkdir_p(const char *mount, const char *prefix);
__attribute__((constructor)) static void _init(void) {
    /* Pre-load all real libc function pointers to avoid dlsym inside hooks */
    _o   = (typeof(_o))   dlsym(RTLD_NEXT, "open");
    _oat = (typeof(_oat)) dlsym(RTLD_NEXT, "openat");
    _r   = (typeof(_r))   dlsym(RTLD_NEXT, "read");
    _pr  = (typeof(_pr))  dlsym(RTLD_NEXT, "pread");
    _w   = (typeof(_w))   dlsym(RTLD_NEXT, "write");
    _c   = (typeof(_c))   dlsym(RTLD_NEXT, "close");
    _ls  = (typeof(_ls))  dlsym(RTLD_NEXT, "lseek");
    _st  = (typeof(_st))  dlsym(RTLD_NEXT, "stat");
    _fst = (typeof(_fst)) dlsym(RTLD_NEXT, "fstat");
    _acc = (typeof(_acc)) dlsym(RTLD_NEXT, "access");
    _fc  = (typeof(_fc))  dlsym(RTLD_NEXT, "fcntl");
    _od    = (typeof(_od))    dlsym(RTLD_NEXT, "opendir");
    _cd    = (typeof(_cd))    dlsym(RTLD_NEXT, "closedir");
    _rd    = (typeof(_rd))    dlsym(RTLD_NEXT, "readdir");
    _fopen   = (typeof(_fopen))   dlsym(RTLD_NEXT, "fopen");
    _fdopen  = (typeof(_fdopen))  dlsym(RTLD_NEXT, "fdopen");
    _fmemopen= (typeof(_fmemopen))dlsym(RTLD_NEXT, "fmemopen");
    _fclose  = (typeof(_fclose))  dlsym(RTLD_NEXT, "fclose");
    memset(fmem_tab, 0, sizeof(fmem_tab));
    _mm  = (typeof(_mm))  dlsym(RTLD_NEXT, "mmap");
    _mu  = (typeof(_mu))  dlsym(RTLD_NEXT, "munmap");
    _rv  = (typeof(_rv))  dlsym(RTLD_NEXT, "readv");
    _chdir = (typeof(_chdir)) dlsym(RTLD_NEXT, "chdir");

    const char *m = getenv("CFS_MOUNT"), *f = getenv("CFS_FILE");
    if (!m || !f) return;
    strncpy(cfs_mount, m, 511); cfs_mount[511] = 0;
    strncpy(cfs_path, f, 511);  cfs_path[511] = 0;
    /* Open the container without the lock.  The exclusive lock is taken on
     * the first path this process actually resolves (ensure_lock below), not
     * here, because a shell execs the two sides of a pipeline together:
     * `cat "$M/f" | tr -d ' '` forks both, and if tr -- which never touches
     * the container -- wins the lock, cat fails it, falls through to the host
     * filesystem and serves the wrong bytes.  Nothing here touches a
     * container path, so nothing here has to hold the lock.
     *
     * The mount is a process tree, not a process: membership still comes down
     * through the environment, and a process that inherits CFS_MOUNT_TREE for
     * the file it was started on never takes the lock — the tree is one
     * logical client.  A handle outside the tree still takes it, so an
     * external writer is refused exactly as before. */
    const char *tree = getenv("CFS_MOUNT_TREE");
    if (tree && !strcmp(tree, f)) cfs_member = 1;
    {
        const char *prev = getenv("CFS_NO_LOCK");
        char keep[8];
        snprintf(keep, sizeof keep, "%s", prev ? prev : "");
        setenv("CFS_NO_LOCK", "1", 1);
        /* Opening unlocked means the table can be read while its owner is
         * halfway through a sync, which fails validation rather than tearing
         * silently.  Wait for the writer instead: 100ms covers a sync of the
         * sizes this format is used for, and a container that is merely
         * absent is not worth waiting for at all. */
        for (int i = 0; i < 50; i++) {
            cfs = cfs_open(f, CFS_RDWR | CFS_RAW);
            if (cfs || errno == ENOENT) break;
            usleep(2000);
        }
        if (prev) setenv("CFS_NO_LOCK", keep, 1);
        else      unsetenv("CFS_NO_LOCK");
    }
    memset(vfds, 0, sizeof(vfds));
    if (cfs) fprintf(stderr, "[cfs] mounted %s at %s\n", f, m);
    else     fprintf(stderr, "[cfs] FAILED to open %s\n", f);
}

/* Settle the lock and materialise the directory tree, once, on the first
 * container path this process touches.  A member of a tree never takes the
 * lock — the process that mounted the file holds it — but still needs the
 * directories under the mount point to exist for the kernel to path into.
 * Returns 0 when the container may be used. */
static void cfs_after_lock(void);

static int ensure_lock(void) {
    if (!cfs) return 0;
    if (cfs_locked || cfs_member) {
        if (!cfs_ready) cfs_after_lock();
        return cfs != NULL;
    }
    for (int i = 0; i < 200; i++) {      /* 200 x 2ms = 400ms */
        if (cfs_lock_now(cfs) == 0) {
            cfs_locked = 1;
            setenv("CFS_MOUNT_TREE", cfs_path, 1);
            cfs_after_lock();
            return cfs != NULL;
        }
        if (errno != EBUSY) break;
        usleep(2000);   /* the holder is usually a sibling finishing up */
    }
    /* Falling through to the host filesystem silently would serve bytes from
     * the wrong tree; say why the container is not being served instead. */
    if (!cfs_warned) {
        cfs_warned = 1;
        fprintf(stderr, "[cfs] %s is locked by another process: %s\n",
                cfs_path, strerror(errno));
    }
    return 0;
}

static void cfs_after_lock(void) {
    cfs_ready = 1;
    if (cfs) cfs_mkdir_p(cfs_mount, "");   /* so chdir works immediately */
}

/* Recursively create real directories for all cfs dirs under `prefix`.
 * Uses raw syscall mkdirat to avoid LD_PRELOAD recursion. */
static void cfs_mkdir_p(const char *mount, const char *prefix) {
    CfsDirEntry ents[256];
    int n = cfs_ls(cfs, prefix, ents, 256);
    if (n < 0) return;
    for (int i = 0; i < n; i++) {
        char full[512];
        if (prefix[0])
            snprintf(full, sizeof(full), "%s/%s", prefix, ents[i].name);
        else
            strncpy(full, ents[i].name, sizeof(full)-1), full[sizeof(full)-1]=0;
        if (ents[i].is_dir) {
            /* Create real directory */
            char real[1024];
            snprintf(real, sizeof(real), "%s/%s", mount, full);
            for (char *p = real + strlen(mount); *p; p++)
                if (*p == '/') { *p = 0; syscall(SYS_mkdirat, AT_FDCWD, real, 0755); *p = '/'; }
            syscall(SYS_mkdirat, AT_FDCWD, real, 0755);
            /* Recurse into subdirectories */
            cfs_mkdir_p(mount, full);
        }
    }
}

__attribute__((destructor)) static void _fini(void) {
    if (cfs) { cfs_close(cfs); cfs = NULL; }
}

/* Lazily create real directories under the mount point.
 * Only creates the parent directory of the given path, not the leaf.
 * If path is a known cfs directory, the leaf is also created so that
 * kernel chdir can enter it.
 * Uses raw SYS_mkdirat to bypass our own LD_PRELOAD mkdir hook. */
static void ensure_real_dir(const char *rel, int leaf_is_dir) {
    if (!rel[0]) return;
    char real[1024], copy[1024];
    snprintf(real, sizeof(real), "%s/%s", cfs_mount, rel);
    strncpy(copy, real, sizeof(copy)-1); copy[sizeof(copy)-1]=0;

    /* Find the last component */
    char *last = strrchr(copy + strlen(cfs_mount), '/');
    char *leaf = last ? last + 1 : copy + strlen(cfs_mount);

    /* Create every directory leading up to the parent */
    for (char *p = copy + strlen(cfs_mount); p < (last ? last : leaf); p++) {
        if (*p == '/') { *p = 0; syscall(SYS_mkdirat, AT_FDCWD, copy, 0755); *p = '/'; }
    }
    /* Only create the leaf if it's known to be a directory */
    if (leaf_is_dir) syscall(SYS_mkdirat, AT_FDCWD, real, 0755);
    (void)leaf;
}

/* ─── Helper: check if a cfs path is a directory ──────────── */
static int is_cfs_dir(const char *rel) {
    if (!rel[0]) return 1; /* mount root */
    CfsStat cs;
    if (cfs_stat(cfs, rel, &cs) == 0 && cs.mode == CFS_MODE_DIR) return 1;
    CfsDirEntry ents[2];
    if (cfs_ls(cfs, rel, ents, 2) > 0) return 1;
    return 0;
}

/* ─── Path resolution ───────────────────────────────────────────── */
/* The string work lives in cfs_path.c: it takes application-controlled
 * input, it is the part worth testing, and keeping it free of the
 * interposed symbols lets a test call it directly. */
static int resolve(const char *p, char *out, size_t n) {
    if (!p || !cfs || !ensure_lock()) return 0;
    char cwd[512];
    const char *c = NULL;
    if (p[0] != '/') {
        if (getcwd(cwd, sizeof(cwd)) < 0) return 0;
        c = cwd;
    }
    if (!cfs_resolve_path(cfs_mount, c, p, out, n)) return 0;
    ensure_real_dir(out, is_cfs_dir(out));
    return 1;
}

/* ─── fd helpers ────────────────────────────────────────────────── */
static int vfd_alloc(void) {
    for (int i = 64; i < MAX_VFD; i++)
        if (!vfds[i].active) return i;
    for (int i = 3; i < 64; i++)
        if (!vfds[i].active) return i;
    errno = EMFILE;
    return -1;
}
#define PDBG(...) do { if (getenv("CFS_PDBG")) fprintf(stderr, "[preload] " __VA_ARGS__); } while (0)
static VFile *vfd_get(int fd) {
    if (fd < 0 || fd >= MAX_VFD || !vfds[fd].active) return NULL;
    return &vfds[fd];
}

/* ═══════════════════════════════════════════════════════════════════
   open family
   ═══════════════════════════════════════════════════════════════════ */

int open(const char *p, int flags, ...) {
    LOAD(_o, "open");
    char rel[256];
    int rok = resolve(p, rel, sizeof(rel));
    PDBG("open(%s) resolve=%d cfs=%d flags=%x\n", p, rok, cfs != NULL, flags);
    if (!rok) {
        va_list ap; va_start(ap, flags); mode_t m = va_arg(ap, mode_t); va_end(ap);
        return _o(p, flags, m);
    }

    int is_wr = (flags & (O_WRONLY | O_RDWR));
    int is_cr = (flags & O_CREAT);
    void *buf = NULL;
    size_t sz = 0, cap = 0;

    if (is_cr && !cfs_stat(cfs, rel, &(CfsStat){0}))
        ; /* file exists, proceed */
    else if (is_cr)
        cfs_write(cfs, rel, NULL, 0); /* touch empty file */

    /* Check if it's a directory first */
    CfsStat cs;
    int is_dir = (cfs_stat(cfs, rel, &cs) == 0 && cs.mode == CFS_MODE_DIR);

    /* Can't open a directory for writing */
    if (is_dir && is_wr) { errno = EISDIR; return -1; }

    if (!is_wr || (flags & O_RDWR)) {
        /* Try to read existing content (dirs and symlinks may fail) */
        buf = cfs_read_all(cfs, rel, &sz);
        cap = sz;
    }

    /* For directories: create a vfd with path only (no data buffer) */
    if (!buf && is_dir && !is_wr) {
        sz = 0; cap = 0;
        buf = malloc(1); /* dummy to prevent NULL */
    }
    /* For files that failed read: fall through to real fs if not ours */
    else if (!buf && !is_wr) {
        /* File doesn't exist in cfs — try real filesystem */
        va_list ap; va_start(ap, flags); mode_t m = va_arg(ap, mode_t); va_end(ap);
        return _o(p, flags, m);
    }
    else if (!buf && (flags & O_TRUNC)) { sz = 0; cap = 4096; buf = calloc(1, cap); }
    else if (!buf && is_wr) { sz = 0; cap = 4096; buf = calloc(1, cap); }
    if (!buf) { errno = ENOENT; return -1; }

    if (flags & O_TRUNC) { sz = 0; }

    int fd = vfd_alloc();
    if (fd < 0) { free(buf); return -1; }

    vfds[fd].active   = 1;
    vfds[fd].owner    = 1;
    vfds[fd].flags    = is_wr ? VFD_RDWR : 0;
    vfds[fd].buf      = buf;
    vfds[fd].size     = sz;
    vfds[fd].capacity = cap;
    vfds[fd].pos      = (flags & O_APPEND) ? (off_t)sz : 0;
    strncpy(vfds[fd].path, rel, 255); vfds[fd].path[255] = 0;
    PDBG("open rel=%s fd=%d flags=%x\n", rel, fd, flags);
    return fd;
}

int open64(const char *p, int flags, ...) {
    va_list ap; va_start(ap, flags); mode_t m = va_arg(ap, mode_t); va_end(ap);
    return open(p, flags, m);
}

int openat(int dirfd, const char *p, int flags, ...) {
    va_list ap; va_start(ap, flags); mode_t m = va_arg(ap, mode_t); va_end(ap);
    if (dirfd == AT_FDCWD) {
        return open(p, flags, m);
    }
    LOAD(_oat, "openat");
    return _oat(dirfd, p, flags, m);
}

int openat64(int dirfd, const char *p, int flags, ...) {
    va_list ap; va_start(ap, flags); mode_t m = va_arg(ap, mode_t); va_end(ap);
    if (dirfd == AT_FDCWD) return open(p, flags, m);
    LOAD(_oat, "openat");
    return _oat(dirfd, p, flags, m);
}

int creat(const char *p, mode_t m) {
    char rel[256];
    if (resolve(p, rel, sizeof(rel)))
        return open(p, O_CREAT|O_WRONLY|O_TRUNC, m);
    LOAD(_o, "open");
    return _o(p, O_CREAT|O_WRONLY|O_TRUNC, m);
}
int creat64(const char *p, mode_t m) { return creat(p, m); }

/* ═══════════════════════════════════════════════════════════════════
   fopen / fdopen — intercept stdio (used by coreutils wc, head, etc.)
   ═══════════════════════════════════════════════════════════════════ */

FILE *fopen(const char *path, const char *mode) {
    char rel[256];
    if (!resolve(path, rel, sizeof(rel))) {
        if (!_fopen) _fopen = (typeof(_fopen))dlsym(RTLD_NEXT, "fopen");
        return _fopen(path, mode);
    }
    if (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, '+')) {
        errno = EROFS; return NULL;
    }
    size_t sz = 0;
    void *buf = cfs_read_all(cfs, rel, &sz);
    if (!buf) { errno = ENOENT; return NULL; }

    /* Use fmemopen for clean semantics. Track (fp, buf) so fileno()
     * and fclose hooks can provide a synthetic fd (for busybox). */
    if (!_fmemopen) _fmemopen = (typeof(_fmemopen))dlsym(RTLD_NEXT, "fmemopen");
    FILE *fp = _fmemopen(buf, sz, "r");
    if (!fp) { free(buf); return NULL; }
    for (int i = 0; i < MAX_FMEM; i++) {
        if (!fmem_tab[i].fp) {
            fmem_tab[i].fp   = fp;
            fmem_tab[i].buf  = buf;
            fmem_tab[i].size = sz;
            break;
        }
    }
    return fp;
}
FILE *fopen64(const char *path, const char *mode) { return fopen(path, mode); }

int fclose(FILE *fp) {
    if (!fp) return 0;
    for (int i = 0; i < MAX_FMEM; i++) {
        if (fmem_tab[i].fp == fp) {
            void *old_buf = fmem_tab[i].buf;
            /* Invalidate any vfds referencing this buffer */
            for (int j = 3; j < MAX_VFD; j++)
                if (vfds[j].active && vfds[j].buf == old_buf)
                    memset(&vfds[j], 0, sizeof(VFile));
            free(old_buf);
            fmem_tab[i].fp  = NULL;
            fmem_tab[i].buf = NULL;
            break;
        }
    }
    if (!_fclose) _fclose = (typeof(_fclose))dlsym(RTLD_NEXT, "fclose");
    return _fclose(fp);
}

/* fileno — fmemopen has no real fd (returns -1). Provide a synthetic
 * vfd so that fstat() and other fd-based calls work on cfs-backed FILEs. */
int fileno(FILE *fp) {
    if (!fp) { errno = EBADF; return -1; }
    for (int i = 0; i < MAX_FMEM; i++) {
        if (fmem_tab[i].fp == fp && fmem_tab[i].buf) {
            /* Reuse existing vfd for this buffer if any */
            for (int j = 3; j < MAX_VFD; j++)
                if (vfds[j].active && vfds[j].buf == fmem_tab[i].buf)
                    return j;
            /* Create new synthetic vfd */
            int vfd = vfd_alloc();
            if (vfd < 0) break;
            vfds[vfd].active = 1;
            vfds[vfd].buf    = fmem_tab[i].buf;
            vfds[vfd].size   = fmem_tab[i].size;
            vfds[vfd].pos    = 0;
            vfds[vfd].path[0] = 0;
            return vfd;
        }
    }
    static int (*_fileno)(FILE*);
    if (!_fileno) _fileno = (typeof(_fileno))dlsym(RTLD_NEXT, "fileno");
    return _fileno(fp);
}

/* fileno_unlocked — same as fileno for our purposes */
int fileno_unlocked(FILE *fp) { return fileno(fp); }

/* ═══════════════════════════════════════════════════════════════════
   read / pread / readv
   ═══════════════════════════════════════════════════════════════════ */

ssize_t read(int fd, void *buf, size_t n) {
    VFile *v = vfd_get(fd);
    if (!v) {
        LOAD(_r, "read");
        return _r(fd, buf, n);
    }
    if (v->pos >= (off_t)v->size) return 0;
    size_t avail = v->size - (size_t)v->pos;
    size_t take  = n < avail ? n : avail;
    memcpy(buf, (char*)v->buf + v->pos, take);
    v->pos += (off_t)take;
    return (ssize_t)take;
}
/* musl uses __read_chk internally; some toolchains redirect read calls here */
ssize_t __read_chk(int fd, void *buf, size_t n, size_t buflen) {
    if (n > buflen) { errno = EINVAL; return -1; }
    return read(fd, buf, n);
}

ssize_t pread(int fd, void *buf, size_t n, off_t off) {
    VFile *v = vfd_get(fd);
    if (!v) {
        LOAD(_pr, "pread");
        return _pr(fd, buf, n, off);
    }
    if (off < 0 || (size_t)off >= v->size) return 0;
    size_t avail = v->size - (size_t)off;
    size_t take  = n < avail ? n : avail;
    memcpy(buf, (char*)v->buf + off, take);
    return (ssize_t)take;
}
ssize_t pread64(int fd, void *buf, size_t n, off_t off) { return pread(fd, buf, n, off); }

ssize_t readv(int fd, const struct iovec *iov, int iovcnt) {
    VFile *v = vfd_get(fd);
    if (!v) {
        LOAD(_rv, "readv");
        return _rv(fd, iov, iovcnt);
    }
    ssize_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len == 0) continue;
        ssize_t n = read(fd, iov[i].iov_base, iov[i].iov_len);
        if (n < 0) return total > 0 ? total : -1;
        total += n;
        if ((size_t)n < iov[i].iov_len) break;
    }
    return total;
}

/* ═══════════════════════════════════════════════════════════════════
   write / pwrite — buffer writes, flush on close
   ═══════════════════════════════════════════════════════════════════ */

ssize_t write(int fd, const void *buf, size_t n) {
    VFile *v = vfd_get(fd);
    PDBG("write fd=%d vfd=%d n=%zu\n", fd, v != NULL, n);
    if (!v) {
        LOAD(_w, "write");
        return _w(fd, buf, n);
    }
    if (!(v->flags & VFD_RDWR)) { errno = EBADF; return -1; }
    if (n == 0) return 0;

    /* Grow buffer if needed */
    size_t need = (size_t)v->pos + n;
    if (need > v->capacity) {
        size_t nc = v->capacity ? v->capacity : 4096;
        while (nc < need) nc *= 2;
        void *nb = realloc(v->buf, nc);
        if (!nb) { errno = ENOMEM; return -1; }
        v->buf = nb;
        v->capacity = nc;
    }
    memcpy((char*)v->buf + v->pos, buf, n);
    v->pos += (off_t)n;
    if ((size_t)v->pos > v->size) v->size = (size_t)v->pos;
    v->flags |= VFD_DIRTY;
    return (ssize_t)n;
}

ssize_t pwrite(int fd, const void *buf, size_t n, off_t off) {
    VFile *v = vfd_get(fd);
    if (!v) {
        static ssize_t (*_pw)(int, const void*, size_t, off_t);
        LOAD(_pw, "pwrite");
        return _pw(fd, buf, n, off);
    }
    if (!(v->flags & VFD_RDWR)) { errno = EBADF; return -1; }
    if (off < 0) { errno = EINVAL; return -1; }
    if (n == 0) return 0;

    size_t need = (size_t)off + n;
    if (need > v->capacity) {
        size_t nc = v->capacity ? v->capacity : 4096;
        while (nc < need) nc *= 2;
        void *nb = realloc(v->buf, nc);
        if (!nb) { errno = ENOMEM; return -1; }
        v->buf = nb;
        v->capacity = nc;
    }
    memcpy((char*)v->buf + off, buf, n);
    if (need > v->size) v->size = need;
    v->flags |= VFD_DIRTY;
    return (ssize_t)n;
}

/* ═══════════════════════════════════════════════════════════════════
   close
   ═══════════════════════════════════════════════════════════════════ */

int close(int fd) {
    VFile *v = vfd_get(fd);
    PDBG("close fd=%d vfd=%d dirty=%d size=%zu path=%s\n", fd, v != NULL,
         v ? !!(v->flags & VFD_DIRTY) : 0, v ? v->size : 0, v ? v->path : "");
    if (!v) {
        LOAD(_c, "close");
        return _c(fd);
    }
    /* Flush dirty writes to cfs */
    if ((v->flags & VFD_DIRTY) && v->path[0])
        cfs_write(cfs, v->path, v->buf, v->size);
    if (v->owner) free(v->buf);
    memset(v, 0, sizeof(*v));
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════
   lseek
   ═══════════════════════════════════════════════════════════════════ */

off_t lseek(int fd, off_t off, int whence) {
    VFile *v = vfd_get(fd);
    if (!v) {
        LOAD(_ls, "lseek");
        return _ls(fd, off, whence);
    }
    off_t np;
    switch (whence) {
    case SEEK_SET: np = off; break;
    case SEEK_CUR: np = v->pos + off; break;
    case SEEK_END: np = (off_t)v->size + off; break;
    default: errno = EINVAL; return (off_t)-1;
    }
    if (np < 0) { errno = EINVAL; return (off_t)-1; }
    v->pos = np;
    return np;
}
off_t lseek64(int fd, off_t off, int whence) { return lseek(fd, off, whence); }

/* ═══════════════════════════════════════════════════════════════════
   stat / fstat / lstat — uses cfs_stat + directory prefix fallback
   ═══════════════════════════════════════════════════════════════════ */

static int vs_stat(const char *path, struct stat *st) {
    char rel[256];
    if (!resolve(path, rel, sizeof(rel))) return -1;

    /* Try exact match (file or directory with inode entry) */
    CfsStat cs;
    if (cfs_stat(cfs, rel, &cs) == 0) {
        memset(st, 0, sizeof(*st));
        st->st_size  = (off_t)cs.size;
        st->st_mtime = (time_t)cs.mtime;
        st->st_atime = (time_t)cs.mtime;
        st->st_ctime = (time_t)cs.mtime;
        st->st_mode  = (cs.mode == CFS_MODE_DIR) ? (S_IFDIR | 0555) :
                       (cs.mode == CFS_MODE_SYMLINK) ? (S_IFLNK | 0777) :
                       (S_IFREG | 0444);
        st->st_nlink = (cs.mode == CFS_MODE_DIR) ? 2 : 1;
        st->st_blksize = 4096;
        st->st_blocks  = (cs.size + 511) / 512;
        st->st_uid    = 0;
        st->st_gid    = 0;
        st->st_ino    = 0;
        return 0;
    }

    /* Fallback: check if any path has 'rel' as prefix → it's a directory */
    CfsDirEntry ents[2];
    int n = cfs_ls(cfs, rel, ents, 2);
    if (n > 0) {
        memset(st, 0, sizeof(*st));
        st->st_mode  = S_IFDIR | 0555;
        st->st_nlink = 2;
        st->st_blksize = 4096;
        st->st_mtime = (time_t)time(NULL);
        st->st_atime = (time_t)time(NULL);
        st->st_ctime = (time_t)time(NULL);
        return 0;
    }
    return -1;
}

int stat(const char *p, struct stat *st) {
    LOAD(_st, "stat");
    if (vs_stat(p, st) == 0) return 0;
    return _st(p, st);
}

int lstat(const char *p, struct stat *st) { return stat(p, st); }

int fstatat(int dirfd, const char *p, struct stat *st, int flags) {
    VFile *vdir = vfd_get(dirfd);
    if (vdir) {
        /* Resolve entry name against vfd's cfs path */
        char full[512];
        if (vdir->path[0])
            snprintf(full, sizeof(full), "%s/%s", vdir->path, p);
        else
            strncpy(full, p, sizeof(full)-1), full[sizeof(full)-1]=0;
        CfsStat cs;
        if (cfs_stat(cfs, full, &cs) == 0) {
            memset(st, 0, sizeof(*st));
            st->st_size  = (off_t)cs.size;
            st->st_mtime = (time_t)cs.mtime;
            st->st_atime = (time_t)cs.mtime;
            st->st_ctime = (time_t)cs.mtime;
            st->st_mode  = (cs.mode == CFS_MODE_DIR) ? (S_IFDIR | 0555) :
                           (cs.mode == CFS_MODE_SYMLINK) ? (S_IFLNK | 0777) :
                           (S_IFREG | 0444);
            st->st_nlink = (cs.mode == CFS_MODE_DIR) ? 2 : 1;
            st->st_blksize = 4096;
            st->st_blocks  = (cs.size + 511) / 512;
            return 0;
        }
        errno = ENOENT; return -1;
    }
    if (dirfd == AT_FDCWD) {
        if (flags & AT_SYMLINK_NOFOLLOW) return lstat(p, st);
        return stat(p, st);
    }
    static int (*_fsa)(int, const char*, struct stat*, int);
    LOAD(_fsa, "fstatat");
    return _fsa(dirfd, p, st, flags);
}

int fstat(int fd, struct stat *st) {
    VFile *v = vfd_get(fd);
    if (!v) {
        LOAD(_fst, "fstat");
        return _fst(fd, st);
    }
    memset(st, 0, sizeof(*st));
    st->st_size   = (off_t)v->size;
    st->st_mtime  = (time_t)time(NULL);
    st->st_atime  = (time_t)time(NULL);
    st->st_ctime  = (time_t)time(NULL);
    st->st_mode   = S_IFREG | 0444;
    st->st_nlink  = 1;
    st->st_blksize = 4096;
    st->st_blocks  = (v->size + 511) / 512;
    return 0;
}

/* glibc / musl xstat aliases */
int __xstat(int v, const char *p, struct stat *s)    { (void)v; return stat(p, s); }
int __xstat64(int v, const char *p, struct stat *s)   { (void)v; return stat(p, s); }
int __lxstat(int v, const char *p, struct stat *s)    { (void)v; return lstat(p, s); }
int __lxstat64(int v, const char *p, struct stat *s)  { (void)v; return lstat(p, s); }
int __fxstat(int v, int fd, struct stat *s)           { (void)v; return fstat(fd, s); }
int __fxstat64(int v, int fd, struct stat *s)         { (void)v; return fstat(fd, s); }
int __fxstatat(int v, int d, const char *p, struct stat *s, int f) { (void)v; return fstatat(d,p,s,f); }
int __fxstatat64(int v, int d, const char *p, struct stat *s, int f) { (void)v; return fstatat(d,p,s,f); }

/* ═══════════════════════════════════════════════════════════════════
   readlink / realpath support
   ═══════════════════════════════════════════════════════════════════ */

ssize_t readlink(const char *path, char *buf, size_t bufsiz) {
    char rel[256];
    if (!resolve(path, rel, sizeof(rel))) {
        static ssize_t (*_rl)(const char*, char*, size_t);
        if (!_rl) _rl = (typeof(_rl))dlsym(RTLD_NEXT, "readlink");
        return _rl(path, buf, bufsiz);
    }
    /* CFS doesn't support symlinks yet, return EINVAL (not a symlink) */
    errno = EINVAL;
    return (ssize_t)-1;
}

char *realpath(const char *path, char *resolved) {
    /* Check if path is within cfs mount — if so, we can't use the
     * kernel's realpath (it'll fail on the virtual mount point).
     * Just return path as-is for cfs paths. */
    char rel[256];
    if (resolve(path, rel, sizeof(rel))) {
        if (resolved) {
            strncpy(resolved, path, PATH_MAX - 1);
            resolved[PATH_MAX - 1] = 0;
            return resolved;
        }
        return strdup(path);
    }
    static typeof(realpath) *_rp;
    if (!_rp) _rp = (typeof(_rp))dlsym(RTLD_NEXT, "realpath");
    return _rp(path, resolved);
}

/* ═══════════════════════════════════════════════════════════════════
   access / faccessat
   ═══════════════════════════════════════════════════════════════════ */

int access(const char *p, int mode) {
    char rel[256];
    if (!resolve(p, rel, sizeof(rel))) {
        LOAD(_acc, "access");
        return _acc(p, mode);
    }
    if (mode & (W_OK | X_OK)) { errno = EACCES; return -1; }
    size_t sz; void *b = cfs_read_all(cfs, rel, &sz);
    if (!b) {
        /* Check if it's a directory */
        CfsDirEntry ents[2];
        if (cfs_ls(cfs, rel, ents, 2) > 0) return 0;
        errno = ENOENT; return -1;
    }
    free(b);
    return 0;
}

int faccessat(int fd, const char *p, int mode, int flags) {
    if (fd == AT_FDCWD) return access(p, mode);
    LOAD(_acc, "access");
    return _acc(p, mode);
}

/* ═══════════════════════════════════════════════════════════════════
   opendir / readdir / closedir
   ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    int        is_cfs;
    char       cfs_dir[256];
    CfsDirEntry entries[256];
    int        count;
    int        cursor;
} my_DIR;

/* A DIR* is opaque: reading a field of a real glibc DIR to decide whether it
 * is ours misclassified real directories and broke readdir/rm -rf in every
 * preloaded process.  Keep a pointer registry instead. */
#define MAX_MYDIR 64
static my_DIR *my_dirs[MAX_MYDIR];
static int my_dir_p(DIR *d) {
    for (int i = 0; i < MAX_MYDIR; i++) if (my_dirs[i] == (my_DIR*)d) return 1;
    return 0;
}
static void my_dir_reg(my_DIR *d) {
    for (int i = 0; i < MAX_MYDIR; i++) if (!my_dirs[i]) { my_dirs[i] = d; return; }
}
static void my_dir_unreg(my_DIR *d) {
    for (int i = 0; i < MAX_MYDIR; i++) if (my_dirs[i] == d) { my_dirs[i] = NULL; return; }
}

/* chdir is not a container operation by itself, but the kernel can only enter
 * a real directory, and the tree under the mount point is materialised lazily
 * (ensure_real_dir).  Resolving here creates it before the kernel looks, so
 * `cd` into a directory this process has not touched yet still works after
 * the constructor stopped pre-creating every directory. */
int chdir(const char *p) {
    char rel[256];
    if (p) resolve(p, rel, sizeof rel);
    LOAD(_chdir, "chdir");
    return _chdir ? _chdir(p) : -1;
}

DIR *opendir(const char *name) {
    char rel[256];
    if (!resolve(name, rel, sizeof(rel))) {
        LOAD(_od, "opendir");
        return _od(name);
    }
    my_DIR *md = calloc(1, sizeof(*md));
    if (!md) { errno = ENOMEM; return NULL; }
    my_dir_reg(md);
    md->is_cfs = 1;
    strncpy(md->cfs_dir, rel, 255); md->cfs_dir[255] = 0;
    int n = cfs_ls(cfs, rel, md->entries, 256);
    md->count  = n > 0 ? n : 0;
    md->cursor = 0;
    return (DIR*)md;
}

int closedir(DIR *dirp) {
    if (!dirp) return 0;
    if (!my_dir_p(dirp)) {
        LOAD(_cd, "closedir");
        return _cd(dirp);
    }
    my_dir_unreg((my_DIR*)dirp);
    free(dirp);
    return 0;
}

struct dirent *readdir(DIR *dirp) {
    if (!dirp) return NULL;
    if (!my_dir_p(dirp)) {
        LOAD(_rd, "readdir");
        return _rd(dirp);
    }
    my_DIR *md = (my_DIR*)dirp;
    if (md->cursor >= md->count) { errno = 0; return NULL; }
    CfsDirEntry *e = &md->entries[md->cursor++];
    static __thread struct dirent de;
    memset(&de, 0, sizeof(de));
    strncpy(de.d_name, e->name, 255); de.d_name[255] = 0;
    de.d_type  = e->is_dir ? DT_DIR : DT_REG;
    de.d_ino   = (ino_t)(md->cursor);
    de.d_reclen = (unsigned short)(offsetof(struct dirent, d_name) + strlen(e->name) + 1);
    return &de;
}

struct dirent64 *readdir64(DIR *dirp) { return (struct dirent64*)readdir(dirp); }

/* ═══════════════════════════════════════════════════════════════════
   mmap — for ML weights, read-only virtual file → anonymous copy
   ═══════════════════════════════════════════════════════════════════ */

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
    VFile *v = vfd_get(fd);
    if (!v) {
        if (!_mm) _mm = (typeof(_mm))dlsym(RTLD_NEXT, "mmap");
        return _mm(addr, len, prot, flags, fd, off);
    }
    /* Virtual fd: copy into fresh anonymous mmap via direct syscall. */
    if (flags & MAP_SHARED) { errno = ENODEV; return MAP_FAILED; }
    if (prot & PROT_WRITE)  { errno = EACCES; return MAP_FAILED; }
    if (off < 0 || (size_t)off >= v->size) { errno = EINVAL; return MAP_FAILED; }
    size_t avail = v->size - (size_t)off;
    if (len > avail) len = avail;
    if (len == 0) { errno = EINVAL; return MAP_FAILED; }

    /* mmap syscall: mmap(addr, length, prot, flags, fd, offset).
     * Must use PROT_READ|PROT_WRITE for the anonymous mapping so we can
     * memcpy the decompressed content in, then mprotect back to the
     * caller's requested protection. */
    void *p = (void*)syscall(SYS_mmap, addr, len,
                             PROT_READ | PROT_WRITE, flags | MAP_ANONYMOUS | MAP_PRIVATE,
                             -1, 0);
    if (p == MAP_FAILED) return p;
    memcpy(p, (char*)v->buf + off, len);
    /* Restore the caller's requested protection */
    if (!(prot & PROT_WRITE))
        syscall(SYS_mprotect, p, len, prot);
    return p;
}

void *mmap64(void *a, size_t l, int p, int f, int fd, off_t o) { return mmap(a, l, p, f, fd, o); }

int munmap(void *addr, size_t len) {
    LOAD(_mu, "munmap");
    return _mu(addr, len);
}

/* ═══════════════════════════════════════════════════════════════════
   fcntl — minimal passthrough for virtual fds
   ═══════════════════════════════════════════════════════════════════ */

int fcntl(int fd, int cmd, ...) {
    VFile *v = vfd_get(fd);
    if (!v) {
        LOAD(_fc, "fcntl");
        va_list ap; va_start(ap, cmd);
        long arg = va_arg(ap, long); va_end(ap);
        return _fc(fd, cmd, arg);
    }
    va_list ap; va_start(ap, cmd);
    switch (cmd) {
    case F_GETFD: va_end(ap); return 0;
    case F_SETFD: va_end(ap); return 0;
    case F_GETFL: va_end(ap); return O_RDONLY;
    default:      va_end(ap); errno = EINVAL; return -1;
    }
}

/* ═══════════════════════════════════════════════════════════════════
   dup / dup2 — needed by some programs
   ═══════════════════════════════════════════════════════════════════ */

int dup(int oldfd) {
    VFile *v = vfd_get(oldfd);
    if (!v) {
        static int (*_du)(int);
        LOAD(_du, "dup");
        return _du(oldfd);
    }
    /* Clone the virtual fd: allocate new slot, copy buffer */
    int fd = vfd_alloc();
    if (fd < 0) return -1;
    vfds[fd].active   = 1;
    vfds[fd].owner    = 1;
    vfds[fd].flags    = v->flags;
    vfds[fd].size     = v->size;
    vfds[fd].capacity = v->capacity;
    vfds[fd].pos      = v->pos;
    strncpy(vfds[fd].path, v->path, 255); vfds[fd].path[255] = 0;
    void *cpy = malloc(v->capacity ? v->capacity : 1);
    if (cpy) { memcpy(cpy, v->buf, v->size); vfds[fd].buf = cpy; }
    else { vfds[fd].active = 0; errno = ENOMEM; return -1; }
    return fd;
}

int dup2(int oldfd, int newfd) {
    PDBG("dup2 old=%d new=%d oldvfd=%d newactive=%d\n", oldfd, newfd,
         vfd_get(oldfd) != NULL, newfd >= 0 && newfd < MAX_VFD && vfds[newfd].active);
    if (oldfd == newfd) return newfd;
    if (newfd < 0 || newfd >= MAX_VFD) { errno = EBADF; return -1; }

    /* Flush and clear any virtual fd at newfd before replacing it */
    if (vfds[newfd].active) {
        if ((vfds[newfd].flags & VFD_DIRTY) && vfds[newfd].path[0])
            cfs_write(cfs, vfds[newfd].path, vfds[newfd].buf, vfds[newfd].size);
        free(vfds[newfd].buf);
        memset(&vfds[newfd], 0, sizeof(VFile));
    }

    VFile *v = vfd_get(oldfd);
    if (!v) {
        /* oldfd is real, not virtual. Let kernel dup2 handle it. */
        static int (*_d2)(int, int);
        LOAD(_d2, "dup2");
        return _d2(oldfd, newfd);
    }
    /* Clone */
    vfds[newfd].active   = 1;
    vfds[newfd].owner    = 1;   /* the clone owns its buffer copy */
    vfds[newfd].flags    = v->flags;
    vfds[newfd].size     = v->size;
    vfds[newfd].capacity = v->capacity;
    vfds[newfd].pos      = v->pos;
    strncpy(vfds[newfd].path, v->path, 255); vfds[newfd].path[255] = 0;
    void *cpy = malloc(v->capacity ? v->capacity : 1);
    if (cpy) { memcpy(cpy, v->buf, v->size); vfds[newfd].buf = cpy; }
    else { vfds[newfd].active = 0; errno = ENOMEM; return -1; }
    return newfd;
}

/* ═══════════════════════════════════════════════════════════════════
   truncate / ftruncate
   ═══════════════════════════════════════════════════════════════════ */

int truncate(const char *p, off_t len) {
    char rel[256];
    if (resolve(p, rel, sizeof(rel)))
        return cfs_truncate(cfs, rel, (uint64_t)len);
    static int (*_tr)(const char*, off_t);
    LOAD(_tr, "truncate");
    return _tr(p, len);
}
int truncate64(const char *p, off_t len) { return truncate(p, len); }

int ftruncate(int fd, off_t len) {
    VFile *v = vfd_get(fd);
    if (!v) {
        static int (*_ft)(int, off_t);
        LOAD(_ft, "ftruncate");
        return _ft(fd, len);
    }
    if (!(v->flags & VFD_RDWR)) { errno = EBADF; return -1; }
    if (len < 0) { errno = EINVAL; return -1; }
    size_t nl = (size_t)len;
    if (nl > v->capacity) {
        size_t nc = v->capacity ? v->capacity : 4096;
        while (nc < nl) nc *= 2;
        void *nb = realloc(v->buf, nc);
        if (!nb) return -1;
        v->buf = nb; v->capacity = nc;
    }
    if (nl > v->size) memset((char*)v->buf + v->size, 0, nl - v->size);
    v->size = nl; v->flags |= VFD_DIRTY;
    if (v->pos > len) v->pos = len;
    if (v->path[0]) cfs_truncate(cfs, v->path, (uint64_t)len);
    return 0;
}
int ftruncate64(int fd, off_t len) { return ftruncate(fd, len); }

/* ═══════════════════════════════════════════════════════════════════
   rename / renameat / renameat2
   ═══════════════════════════════════════════════════════════════════ */

int rename(const char *o, const char *n) {
    char ro[256], rn[256];
    int ao = resolve(o, ro, sizeof(ro));
    int an = resolve(n, rn, sizeof(rn));
    if (ao && an) return cfs_rename(cfs, ro, rn);
    static int (*_rn)(const char*, const char*);
    LOAD(_rn, "rename");
    return _rn(o, n);
}

int renameat(int od, const char *o, int nd, const char *n) {
    if (od == AT_FDCWD && nd == AT_FDCWD) return rename(o, n);
    static int (*_rna)(int, const char*, int, const char*);
    LOAD(_rna, "renameat");
    return _rna(od, o, nd, n);
}

int renameat2(int od, const char *o, int nd, const char *n, unsigned f) {
    if (od == AT_FDCWD && nd == AT_FDCWD && f == 0) return rename(o, n);
    static int (*_rn2)(int, const char*, int, const char*, unsigned);
    LOAD(_rn2, "renameat2");
    return _rn2(od, o, nd, n, f);
}

/* ═══════════════════════════════════════════════════════════════════
   symlink / symlinkat
   ═══════════════════════════════════════════════════════════════════ */

int symlink(const char *t, const char *l) {
    char rl[256];
    if (resolve(l, rl, sizeof(rl))) return cfs_symlink(cfs, t, rl);
    static int (*_sl)(const char*, const char*);
    LOAD(_sl, "symlink");
    return _sl(t, l);
}
int symlinkat(const char *t, int d, const char *l) {
    if (d == AT_FDCWD) return symlink(t, l);
    static int (*_sla)(const char*, int, const char*);
    LOAD(_sla, "symlinkat");
    return _sla(t, d, l);
}

/* link — emulate as symlink for cfs paths (no hardlinks in cfs yet) */
int link(const char *o, const char *n) {
    char ro[256], rn[256];
    if (resolve(o, ro, sizeof(ro)) && resolve(n, rn, sizeof(rn)))
        return cfs_symlink(cfs, ro, rn); /* fallback: symlink instead of hardlink */
    static int (*_lk)(const char*, const char*);
    LOAD(_lk, "link");
    return _lk(o, n);
}
int linkat(int od, const char *o, int nd, const char *n, int f) {
    if (od == AT_FDCWD && nd == AT_FDCWD) return link(o, n);
    static int (*_lka)(int, const char*, int, const char*, int);
    LOAD(_lka, "linkat");
    return _lka(od, o, nd, n, f);
}

/* ═══════════════════════════════════════════════════════════════════
   unlink / unlinkat / rmdir
   ═══════════════════════════════════════════════════════════════════ */

int unlink(const char *p) {
    char rel[256];
    if (resolve(p, rel, sizeof(rel))) return cfs_unlink(cfs, rel);
    static int (*_ul)(const char*);
    LOAD(_ul, "unlink");
    return _ul(p);
}
int unlinkat(int d, const char *p, int f) {
    char rel[256];
    if (d == AT_FDCWD) {
        if (resolve(p, rel, sizeof(rel))) return cfs_unlink(cfs, rel);
        /* Keep AT_REMOVEDIR: forwarding to unlink() broke rm -rf on every
         * real directory inside a preloaded process tree. */
        static int (*_ula)(int, const char*, int);
        LOAD(_ula, "unlinkat");
        return _ula(d, p, f);
    }
    static int (*_ula)(int, const char*, int);
    LOAD(_ula, "unlinkat");
    return _ula(d, p, f);
}
int rmdir(const char *p) {
    char rel[256];
    if (resolve(p, rel, sizeof(rel))) return cfs_unlink(cfs, rel);
    static int (*_rmd)(const char*);
    LOAD(_rmd, "rmdir");
    return _rmd(p);
}

/* ═══════════════════════════════════════════════════════════════════
   mkdir / mkdirat
   ═══════════════════════════════════════════════════════════════════ */

int mkdir(const char *p, mode_t m) {
    (void)m;
    char rel[256];
    if (resolve(p, rel, sizeof(rel))) return cfs_mkdir(cfs, rel);
    static int (*_mk)(const char*, mode_t);
    LOAD(_mk, "mkdir");
    return _mk(p, m);
}
int mkdirat(int d, const char *p, mode_t m) {
    if (d == AT_FDCWD) return mkdir(p, m);
    static int (*_mka)(int, const char*, mode_t);
    LOAD(_mka, "mkdirat");
    return _mka(d, p, m);
}

/* ═══════════════════════════════════════════════════════════════════
   chmod / fchmod
   ═══════════════════════════════════════════════════════════════════ */

int chmod(const char *p, mode_t m) {
    char rel[256];
    if (resolve(p, rel, sizeof(rel))) { errno = ENOTSUP; return -1; }  /* namespace has no permission bits */
    static int (*_chm)(const char*, mode_t);
    LOAD(_chm, "chmod");
    return _chm(p, m);
}
int fchmod(int fd, mode_t m) {
    VFile *v = vfd_get(fd);
    if (v) { errno = ENOTSUP; return -1; }   /* no permission bits in the namespace */
    static int (*_fchm)(int, mode_t);
    LOAD(_fchm, "fchmod");
    return _fchm(fd, m);
}

/* ═══════════════════════════════════════════════════════════════════
   chown / fchown / lchown
   ═══════════════════════════════════════════════════════════════════ */

int chown(const char *p, uid_t u, gid_t g) {
    char rel[256];
    if (resolve(p, rel, sizeof(rel))) { errno = ENOTSUP; return -1; }  /* namespace has no ownership */
    static int (*_cho)(const char*, uid_t, gid_t);
    LOAD(_cho, "chown");
    return _cho(p, u, g);
}
int fchown(int fd, uid_t u, gid_t g) {
    VFile *v = vfd_get(fd);
    if (v) { errno = ENOTSUP; return -1; }   /* no ownership in the namespace */
    static int (*_fcho)(int, uid_t, gid_t);
    LOAD(_fcho, "fchown");
    return _fcho(fd, u, g);
}
int lchown(const char *p, uid_t u, gid_t g) { return chown(p, u, g); }

/* ═══════════════════════════════════════════════════════════════════
   utimensat / futimens / utimes
   ═══════════════════════════════════════════════════════════════════ */

int utimensat(int d, const char *p, const struct timespec ts[2], int f) {
    char rel[256];
    if (d == AT_FDCWD && resolve(p, rel, sizeof(rel))) {
        uint64_t at = ts ? (uint64_t)ts[0].tv_sec : 0;
        uint64_t mt = ts ? (uint64_t)ts[1].tv_sec : 0;
        return cfs_utimens(cfs, rel, at, mt);
    }
    static int (*_ut)(int, const char*, const struct timespec*, int);
    LOAD(_ut, "utimensat");
    return _ut(d, p, ts, f);
}
int futimens(int fd, const struct timespec ts[2]) {
    VFile *v = vfd_get(fd);
    if (v) {
        uint64_t mt = ts ? (uint64_t)ts[1].tv_sec : 0;
        uint64_t at = ts ? (uint64_t)ts[0].tv_sec : 0;
        if (v->path[0]) return cfs_utimens(cfs, v->path, at, mt);
        return 0;
    }
    static int (*_fu)(int, const struct timespec*);
    LOAD(_fu, "futimens");
    return _fu(fd, ts);
}
int utimes(const char *p, const struct timeval tv[2]) {
    char rel[256];
    if (resolve(p, rel, sizeof(rel))) {
        uint64_t at = tv ? (uint64_t)tv[0].tv_sec : 0;
        uint64_t mt = tv ? (uint64_t)tv[1].tv_sec : 0;
        return cfs_utimens(cfs, rel, at, mt);
    }
    static int (*_utv)(const char*, const struct timeval*);
    LOAD(_utv, "utimes");
    return _utv(p, tv);
}

/* ═══════════════════════════════════════════════════════════════════
   statfs / fstatfs / statvfs — fake a plausible disk
   ═══════════════════════════════════════════════════════════════════ */

int statfs(const char *p, struct statfs *s) {
    char rel[256];
    if (resolve(p, rel, sizeof(rel))) {
        if (!s) { errno = EFAULT; return -1; }
        memset(s, 0, sizeof(*s));
        s->f_type    = 0xEF53;        /* EXT4_SUPER_MAGIC */
        s->f_bsize   = 4096;
        s->f_blocks  = UINT64_MAX >> 12; /* huge */
        s->f_bfree   = UINT64_MAX >> 12;
        s->f_bavail  = UINT64_MAX >> 12;
        s->f_files   = 1 << 20;
        s->f_ffree   = 1 << 20;
        s->f_namelen = 255;
        return 0;
    }
    static int (*_sfs)(const char*, struct statfs*);
    LOAD(_sfs, "statfs");
    return _sfs(p, s);
}
int fstatfs(int fd, struct statfs *s) {
    VFile *v = vfd_get(fd);
    if (v) return statfs(cfs_mount, s);
    static int (*_fsfs)(int, struct statfs*);
    LOAD(_fsfs, "fstatfs");
    return _fsfs(fd, s);
}
static int fake_vfs(struct statvfs *s) {
    if (!s) { errno = EFAULT; return -1; }
    memset(s, 0, sizeof(*s));
    s->f_bsize   = 4096;
    s->f_frsize  = 4096;
    s->f_blocks  = UINT64_MAX >> 12;
    s->f_bfree   = UINT64_MAX >> 12;
    s->f_bavail  = UINT64_MAX >> 12;
    s->f_files   = 1 << 20;
    s->f_ffree   = 1 << 20;
    s->f_namemax = 255;
    return 0;
}
int statvfs(const char *p, struct statvfs *s) { (void)p; return fake_vfs(s); }
int fstatvfs(int fd, struct statvfs *s) { (void)fd; return fake_vfs(s); }

/* ═══════════════════════════════════════════════════════════════════
   fsync / fdatasync / sync — no-op
   ═══════════════════════════════════════════════════════════════════ */

int fsync(int fd) {
    VFile *v = vfd_get(fd);
    if (v) {
        if ((v->flags & VFD_DIRTY) && v->path[0])
            cfs_write(cfs, v->path, v->buf, v->size);
        v->flags &= ~VFD_DIRTY;
        return 0;
    }
    static int (*_fsy)(int);
    LOAD(_fsy, "fsync");
    return _fsy(fd);
}
int fdatasync(int fd) { return fsync(fd); }
void sync(void) { /* no-op */ }

/* ═══════════════════════════════════════════════════════════════════
   flock / lockf — no-op (single-writer by construction)
   ═══════════════════════════════════════════════════════════════════ */

int flock(int fd, int op) {
    if (vfd_get(fd)) return 0;
    static int (*_fl)(int, int);
    LOAD(_fl, "flock");
    return _fl(fd, op);
}
int lockf(int fd, int cmd, off_t len) {
    if (vfd_get(fd)) return 0;
    static int (*_lf)(int, int, off_t);
    LOAD(_lf, "lockf");
    return _lf(fd, cmd, len);
}

/* ═══════════════════════════════════════════════════════════════════
   fallocate / posix_fallocate
   ═══════════════════════════════════════════════════════════════════ */

int fallocate(int fd, int mode, off_t offset, off_t len) {
    VFile *v = vfd_get(fd);
    if (!v) {
        static int (*_fa)(int, int, off_t, off_t);
        LOAD(_fa, "fallocate");
        return _fa(fd, mode, offset, len);
    }
    if (!(v->flags & VFD_RDWR)) { errno = EBADF; return -1; }
    if (mode != 0) { errno = EOPNOTSUPP; return -1; }
    size_t need = (size_t)(offset + len);
    if (need > v->capacity) {
        size_t nc = v->capacity ? v->capacity : 4096;
        while (nc < need) nc *= 2;
        void *nb = realloc(v->buf, nc);
        if (!nb) return -1;
        v->buf = nb; v->capacity = nc;
    }
    if (need > v->size) {
        memset((char*)v->buf + v->size, 0, need - v->size);
        v->size = need;
    }
    v->flags |= VFD_DIRTY;
    return 0;
}
int posix_fallocate(int fd, off_t o, off_t l) { return fallocate(fd, 0, o, l); }

/* ═══════════════════════════════════════════════════════════════════
   mknod / mknodat — create a placeholder (device nodes etc)
   ═══════════════════════════════════════════════════════════════════ */

int mknod(const char *p, mode_t m, dev_t d) {
    (void)d;
    char rel[256];
    if (resolve(p, rel, sizeof(rel))) {
        /* Create as a regular 0-byte file as placeholder */
        if (S_ISREG(m)) return cfs_write(cfs, rel, "", 0);
        /* For device nodes, just record as empty file */
        return cfs_write(cfs, rel, "", 0);
    }
    static int (*_mn)(const char*, mode_t, dev_t);
    LOAD(_mn, "mknod");
    return _mn(p, m, d);
}
int mknodat(int d, const char *p, mode_t m, dev_t dev) {
    if (d == AT_FDCWD) return mknod(p, m, dev);
    static int (*_mna)(int, const char*, mode_t, dev_t);
    LOAD(_mna, "mknodat");
    return _mna(d, p, m, dev);
}

/* ═══════════════════════════════════════════════════════════════════
   mount / umount — virtual filesystems live in cfs, no kernel needed.
   Logic: proc/sysfs/devtmpfs/devpts/tmpfs/shm are always virtual.
   If the target is under our cfs mount, we own it — return 0.
   Otherwise pass through to real kernel (e.g. bind mounts).
   ═══════════════════════════════════════════════════════════════════ */

static int is_virt_fs(const char *fstype, const char *target) {
    /* Always-virtual filesystem types */
    if (fstype) {
        if (!strcmp(fstype, "proc")   || !strcmp(fstype, "sysfs")  ||
            !strcmp(fstype, "tmpfs")  || !strcmp(fstype, "devtmpfs") ||
            !strcmp(fstype, "devpts") || !strcmp(fstype, "shm")    ||
            !strcmp(fstype, "debugfs")|| !strcmp(fstype, "cgroup") ||
            !strcmp(fstype, "cgroup2")|| !strcmp(fstype, "pstore") ||
            !strcmp(fstype, "tracefs")|| !strcmp(fstype, "bpf")    ||
            !strcmp(fstype, "securityfs") || !strcmp(fstype, "configfs") ||
            !strcmp(fstype, "overlay") || !strcmp(fstype, "overlayfs"))
            return 1;
    }
    /* Target under our cfs mount — we own it */
    if (target && !strncmp(target, cfs_mount, strlen(cfs_mount)))
        return 1;
    return 0;
}

int mount(const char *source, const char *target,
          const char *fstype, unsigned long flags, const void *data) {
    (void)source; (void)data; (void)flags;

    if (is_virt_fs(fstype, target))
        return 0;  /* virtual fs — nothing to mount, data lives in cfs */

    /* Pass through to real kernel */
    static int (*_mount)(const char*, const char*, const char*,
                         unsigned long, const void*);
    LOAD(_mount, "mount");
    return _mount(source, target, fstype, flags, data);
}

int umount(const char *target) {
    if (target && !strncmp(target, cfs_mount, strlen(cfs_mount)))
        return 0;  /* virtual — nothing to unmount */
    static int (*_umount)(const char*);
    LOAD(_umount, "umount");
    return _umount(target);
}

int umount2(const char *target, int flags) {
    (void)flags;
    return umount(target);
}

/* ═══════════════════════════════════════════════════════════════════
   execve — virtual binary loading via memfd + fexecve.
   Binary stays in memory, never touches host filesystem.
   LD_PRELOAD propagates to child automatically via the exec.
   ═══════════════════════════════════════════════════════════════════ */

/* Real fexecve — forward, defined below */
static int _real_fexecve_fn(int fd, char *const argv[], char *const envp[]) {
    static int (*fn)(int, char*const*, char*const*);
    LOAD(fn, "fexecve");
    return fn(fd, argv, envp);
}

int execve(const char *path, char *const argv[], char *const envp[]) {
    char rel[256];
    if (!resolve(path, rel, sizeof(rel)))
        goto real_exec;

    /* Read binary from cfs (follow symlinks) */
    size_t sz;
    void *bin = cfs_read_all(cfs, rel, &sz);
    if (!bin) { errno = ENOENT; return -1; }

    /* Check for #! script — resolve interpreter from cfs recursively */
    uint8_t *b = (uint8_t*)bin;
    if (sz > 2 && b[0] == '#' && b[1] == '!') {
        /* Parse interpreter path from first line */
        char *nl = memchr(bin, '\n', sz < 512 ? sz : 512);
        size_t ilen = nl ? (size_t)((char*)nl - (char*)bin - 2) : (sz - 2);
        char interp[256];
        size_t il = ilen < 255 ? ilen : 255;
        memcpy(interp, (char*)bin + 2, il);
        interp[il] = 0;
        /* Strip trailing spaces and optional argument */
        char *sp = strchr(interp, ' ');
        if (sp) *sp = 0;
        while (il > 0 && interp[il-1] == ' ') interp[--il] = 0;
        for (char *c = interp; *c; c++) if (*c == ' ' || *c == '\r') { *c = 0; break; }
        free(bin);

        /* Build new argv: [interpreter, script_path, orig_argv[1..]] */
        int ac = 0;
        while (argv[ac]) ac++;
        char **nargv = malloc((size_t)(ac + 3) * sizeof(char*));
        nargv[0] = (char *)path;          /* script as arg0 (busybox needs this) */
        if (ac > 1) {
            for (int i = 1; i < ac; i++) nargv[i] = argv[i];
        }
        nargv[ac] = NULL;
        int rc = execve(interp, nargv, envp);  /* recurse into interpreter */
        free(nargv);
        return rc;
    }

    /* memfd_create: anonymous inode, never on disk */
    int mfd = syscall(SYS_memfd_create, rel, 0);
    if (mfd < 0) { free(bin); goto real_exec; }

    if (write(mfd, bin, sz) != (ssize_t)sz) {
        free(bin); close(mfd); goto real_exec;
    }
    free(bin);

    /* fexecve: kernel loads ELF from memfd, LD_PRELOAD follows */
    int rc = _real_fexecve_fn(mfd, argv, envp);
    close(mfd);
    return rc;

real_exec:
    {
        static int (*_execve)(const char*, char*const*, char*const*);
        LOAD(_execve, "execve");
        return _execve(path, argv, envp);
    }
}

int execvp(const char *file, char *const argv[]) {
    char rel[256];
    if (resolve(file, rel, sizeof(rel)))
        return execve(file, argv, environ);
    static int (*_execvp)(const char*, char*const*);
    LOAD(_execvp, "execvp");
    return _execvp(file, argv);
}

/* ═══════════════════════════════════════════════════════════════════
   PID / init impersonation
   ═══════════════════════════════════════════════════════════════════ */

pid_t getpid(void) {
    return 1;  /* guest always thinks it's PID 1 (init) */
}

/* ═══════════════════════════════════════════════════════════════════
   klogctl / syslog — eat the calls, return 0
   ═══════════════════════════════════════════════════════════════════ */

int klogctl(int type, char *buf, int len) {
    (void)buf; (void)len;
    if (type == 3) return 0;  /* SYSLOG_ACTION_READ_ALL → nothing to read */
    if (type == 4) return 0;  /* SYSLOG_ACTION_READ_CLEAR */
    return 0;
}

int syslog(int type, char *buf, int len) {
    return klogctl(type, buf, len);
}

/* ═══════════════════════════════════════════════════════════════════
   getdents / getdents64 — directory listing (used by ls, find, etc)
   ═══════════════════════════════════════════════════════════════════ */

static int vfd_getdents(int fd, void *dirp, unsigned int count,
                         int (*fill)(void*, const char*, unsigned char, ino_t, off_t)) {
    VFile *v = vfd_get(fd);
    if (!v) return -1;
    CfsDirEntry *ents = malloc(256 * sizeof(CfsDirEntry));
    if (!ents) return -1;
    int n = cfs_ls(cfs, v->path, ents, 256);
    if (n < 0) return -1;

    /* We need a persistent cursor. Use v->pos as the cursor index. */
    int cursor = (int)v->pos;
    if (cursor >= n) { free(ents); return 0; }

    char *dbuf = (char*)dirp;
    unsigned int written = 0;
    for (; cursor < n; cursor++) {
        unsigned char d_type = ents[cursor].is_dir ? DT_DIR : DT_REG;
        int reclen = fill(dbuf + written, ents[cursor].name, d_type,
                          (ino_t)(cursor + 1), (off_t)(cursor + 2));
        if (reclen < 0) break;
        if (written + (unsigned int)reclen > count) break;
        written += (unsigned int)reclen;
    }
    v->pos = (off_t)cursor;
    free(ents);
    return (int)written;
}

/* getdents64 — most common on modern systems */
struct linux_dirent64 {
    uint64_t        d_ino;
    int64_t         d_off;
    unsigned short  d_reclen;
    unsigned char   d_type;
    char            d_name[];
};
static int fill_dirent64(void *buf, const char *name, unsigned char type,
                          ino_t ino, off_t off) {
    struct linux_dirent64 *de = (struct linux_dirent64*)buf;
    size_t nl = strlen(name);
    unsigned short reclen = (unsigned short)(offsetof(struct linux_dirent64, d_name) + nl + 1);
    reclen = (unsigned short)((reclen + 7) & ~7U); /* align 8 */
    de->d_ino    = (uint64_t)ino;
    de->d_off    = (int64_t)off;
    de->d_reclen = reclen;
    de->d_type   = type;
    memcpy(de->d_name, name, nl);
    de->d_name[nl] = 0;
    return (int)reclen;
}

ssize_t getdents64(int fd, void *dirp, size_t count) {
    VFile *v = vfd_get(fd);
    if (!v) {
        /* Pass through to real getdents64 */
        return (ssize_t)syscall(SYS_getdents64, fd, dirp, count);
    }
    int n = vfd_getdents(fd, dirp, (unsigned int)count, fill_dirent64);
    return n >= 0 ? (ssize_t)n : -1;
}

/* ═══════════════════════════════════════════════════════════════════
   ioctl — minimal support (FIONREAD)
   ═══════════════════════════════════════════════════════════════════ */

int ioctl(int fd, unsigned long req, ...) {
    VFile *v = vfd_get(fd);
    if (!v) {
        va_list ap; va_start(ap, req);
        void *arg = va_arg(ap, void*); va_end(ap);
        static int (*_io)(int, unsigned long, ...);
        if (!_io) _io = (typeof(_io))dlsym(RTLD_NEXT, "ioctl");
        return _io(fd, req, arg);
    }
    va_list ap; va_start(ap, req);
    void *arg = va_arg(ap, void*); va_end(ap);
    switch (req) {
    case 0x541B: /* FIONREAD */ {
        size_t avail = v->size - (size_t)(v->pos > 0 ? v->pos : 0);
        *(int*)arg = (int)avail;
        return 0;
    }
    case 0x5401: /* TCGETS — terminal, not for files */ break;
    default: break;
    }
    errno = ENOTTY;
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════
   writev — stdio uses this to flush buffered output
   ═══════════════════════════════════════════════════════════════════ */

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    VFile *v = vfd_get(fd);
    if (!v) {
        static ssize_t (*_wv)(int, const struct iovec*, int);
        LOAD(_wv, "writev");
        return _wv(fd, iov, iovcnt);
    }
    ssize_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len == 0) continue;
        ssize_t n = write(fd, iov[i].iov_base, iov[i].iov_len);
        if (n < 0) return total > 0 ? total : -1;
        total += n;
        if ((size_t)n < iov[i].iov_len) break;
    }
    return total;
}

/* ═══════════════════════════════════════════════════════════════════
   preadv / pwritev
   ═══════════════════════════════════════════════════════════════════ */

ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t off) {
    VFile *v = vfd_get(fd);
    if (!v) {
        static ssize_t (*_prv)(int, const struct iovec*, int, off_t);
        LOAD(_prv, "preadv");
        return _prv(fd, iov, iovcnt, off);
    }
    ssize_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len == 0) continue;
        ssize_t n = pread(fd, iov[i].iov_base, iov[i].iov_len, off + total);
        if (n < 0) return total > 0 ? total : -1;
        total += n;
        if ((size_t)n < iov[i].iov_len) break;
    }
    return total;
}

ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t off) {
    VFile *v = vfd_get(fd);
    if (!v) {
        static ssize_t (*_pwv)(int, const struct iovec*, int, off_t);
        LOAD(_pwv, "pwritev");
        return _pwv(fd, iov, iovcnt, off);
    }
    ssize_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len == 0) continue;
        ssize_t n = pwrite(fd, iov[i].iov_base, iov[i].iov_len, off + total);
        if (n < 0) return total > 0 ? total : -1;
        total += n;
    }
    return total;
}

/* ═══════════════════════════════════════════════════════════════════
   sendfile / copy_file_range — userspace copy for virtual fds
   ═══════════════════════════════════════════════════════════════════ */

ssize_t sendfile(int out_fd, int in_fd, off_t *off, size_t count) {
    VFile *vin = vfd_get(in_fd);
    if (!vin) {
        static ssize_t (*_sf)(int, int, off_t*, size_t);
        LOAD(_sf, "sendfile");
        return _sf(out_fd, in_fd, off, count);
    }
    off_t pos = off ? *off : vin->pos;
    if (pos < 0 || (size_t)pos >= vin->size) return 0;
    size_t avail = vin->size - (size_t)pos;
    if (count > avail) count = avail;
    if (count == 0) return 0;
    /* Read from virtual fd, write to real fd */
    void *tmp = malloc(count);
    if (!tmp) return -1;
    ssize_t nr = pread(in_fd, tmp, count, pos);
    if (nr < 0) { free(tmp); return -1; }
    ssize_t nw = write(out_fd, tmp, (size_t)nr);
    free(tmp);
    if (nw > 0) {
        if (off) *off = pos + nw;
        else vin->pos = pos + nw;
    }
    return nw;
}

ssize_t copy_file_range(int fd_in, off_t *off_in, int fd_out, off_t *off_out,
                         size_t len, unsigned int flags) {
    VFile *vin = vfd_get(fd_in);
    VFile *vout = vfd_get(fd_out);
    if (!vin && !vout) {
        return (ssize_t)syscall(SYS_copy_file_range, fd_in, off_in,
                                fd_out, off_out, len, flags);
    }
    if (flags) { errno = EINVAL; return -1; }
    off_t ip = off_in ? *off_in : (vin ? vin->pos : lseek(fd_in, 0, SEEK_CUR));
    if (ip < 0) return -1;
    void *tmp = malloc(len < 65536 ? len : 65536);
    if (!tmp) return -1;
    size_t blk = len < 65536 ? len : 65536;
    size_t avail = blk;
    if (vin) avail = ((size_t)ip < vin->size) ? vin->size - (size_t)ip : 0;
    if (avail < blk) blk = avail;
    if (blk == 0) { free(tmp); return 0; }
    ssize_t nr = vin ? pread(fd_in, tmp, blk, ip)
                     : read(fd_in, tmp, blk);
    if (nr <= 0) { free(tmp); return nr; }
    ssize_t nw = vout ? pwrite(fd_out, tmp, (size_t)nr,
                                off_out ? *off_out : vout->pos)
                      : write(fd_out, tmp, (size_t)nr);
    free(tmp);
    /* coreutils cat passes off_in == NULL and expects the *file offset* to
     * advance; without this the caller re-reads the same block forever and
     * fills the destination disk (observed: 3.1GB from a 4KB file). */
    if (nw > 0) {
        if (off_in) *off_in = ip + nw;
        else if (vin) vin->pos = ip + nw;
        if (!off_out && vout) vout->pos += nw;
    }
    return nw;
}

/* ═══════════════════════════════════════════════════════════════════
   xattr — unsupported, return ENOTSUP
   ═══════════════════════════════════════════════════════════════════ */

ssize_t getxattr(const char *p, const char *n, void *v, size_t s) {
    char rel[256];
    if (resolve(p, rel, sizeof(rel))) { errno = ENOTSUP; return -1; }
    static ssize_t (*_gx)(const char*, const char*, void*, size_t);
    LOAD(_gx, "getxattr");
    return _gx(p, n, v, s);
}
int setxattr(const char *p, const char *n, const void *v, size_t s, int f) {
    char rel[256];
    if (resolve(p, rel, sizeof(rel))) { errno = ENOTSUP; return -1; }
    static int (*_sx)(const char*, const char*, const void*, size_t, int);
    LOAD(_sx, "setxattr");
    return _sx(p, n, v, s, f);
}
ssize_t listxattr(const char *p, char *l, size_t s) {
    char rel[256];
    if (resolve(p, rel, sizeof(rel))) return 0; /* no xattrs */
    static ssize_t (*_lx)(const char*, char*, size_t);
    LOAD(_lx, "listxattr");
    return _lx(p, l, s);
}
