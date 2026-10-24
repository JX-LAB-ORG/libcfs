/* cfs_crash_test — the container must survive a killed writer.
 *
 * The old layout put the inode table exactly where the next data append
 * started, so a write that failed (or a writer killed between the data and
 * the table) overwrote the live table and the container stopped opening.
 * These cases exercise every stage of the new commit protocol:
 *
 *   (a) SIGKILL at each stage of a write: before the data, after the data but
 *       before the table, after the table but before the superblock slot.
 *   (b) a real ENOSPC on a small tmpfs (needs `unshare -Ur -m`; skipped when
 *       the machine cannot create a mount namespace).
 *   (c) a corrupted slot CRC: the reader falls back to the older slot.
 *   (d) ordinary write/read/sync round-trip, plus a hand-built v2 container
 *       (read compatibility) that the first write upgrades in place.
 *
 * The kill stages are reached deterministically through the CFS_CRASH_STAGE
 * hook in cfs.c, which makes the process SIGKILL itself at the named point.
 *
 * House style: CHECK macro, "=== N failures ===" banner, non-zero exit.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include "../cfs.h"
#include "../cfs_format.h"
#include "../cfs_dedup.h"       /* CFS_CDC_MIN */
#include "../libcpool/cpenc.h"  /* raw-block construction for the v2 fixture */

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); failures++; } \
    else { fprintf(stderr, "  OK: %s\n", msg); } } while (0)

/* ── scratch files ─────────────────────────────────────────────── */
static char scratch[512];

static void path_in(char *out, size_t n, const char *name) {
    snprintf(out, n, "%s/%s", scratch, name);
}

/* Deterministic, poorly compressible bytes: an LCG keeps the dedup layer from
 * collapsing the fill, and makes the expected content exact. */
static void fill_pattern(uint8_t *buf, size_t n, uint32_t seed) {
    uint32_t x = seed * 2654435761u + 1;
    for (size_t i = 0; i < n; i++) {
        x = x * 1664525u + 1013904223u;
        buf[i] = (uint8_t)(x >> 16);
    }
}

static int file_copy(const char *src, const char *dst) {
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { close(in); return -1; }
    uint8_t buf[65536];
    ssize_t r;
    int rc = 0;
    while ((r = read(in, buf, sizeof buf)) > 0)
        if (write(out, buf, (size_t)r) != r) { rc = -1; break; }
    if (r < 0) rc = -1;
    close(in);
    close(out);
    return rc;
}

/* Read a file through the library.  Returns 1 only when it exists and its
 * bytes match. */
static int has_content(const char *cpath, const char *name,
                       const void *want, size_t len) {
    CFS *c = cfs_open(cpath, CFS_RDONLY);
    if (!c) return 0;
    uint8_t *got = malloc(len ? len : 1);
    ssize_t r = c ? cfs_read(c, name, got, len, 0) : -1;
    int ok = (r == (ssize_t)len && !memcmp(got, want, len));
    free(got);
    cfs_close(c);
    return ok;
}

static int file_present(const char *cpath, const char *name) {
    CFS *c = cfs_open(cpath, CFS_RDONLY);
    if (!c) return -1;
    CfsStat st;
    int rc = cfs_stat(c, name, &st);
    cfs_close(c);
    return rc == 0;
}

static int verify_clean(const char *cpath) {
    FILE *sink = fopen("/dev/null", "w");
    if (!sink) return -1;
    int rc = cfs_verify(cpath, 0, sink);
    fclose(sink);
    return rc;               /* 0 = no errors, -1 = unopenable */
}

/* ── kill a writer at one commit stage ─────────────────────────── */
static pid_t spawn_write(const char *cpath, const char *name,
                         const void *data, size_t len, const char *stage) {
    pid_t pid = fork();
    if (pid == 0) {
        if (stage) setenv("CFS_CRASH_STAGE", stage, 1);
        CFS *c = cfs_open(cpath, CFS_RDWR);
        if (!c) _exit(2);
        int rc = cfs_write(c, name, data, len);
        cfs_close(c);
        _exit(rc == 0 ? 0 : 3);
    }
    return pid;
}

static int killed_by_sigkill(pid_t pid) {
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) return 0;
    return WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL;
}

/* ── (d) ordinary round-trip ───────────────────────────────────── */
static void case_roundtrip(void) {
    fprintf(stderr, "=== round-trip ===\n");
    char cp[600];
    path_in(cp, sizeof cp, "roundtrip.cfs");
    unlink(cp);

    uint8_t a[3000], b[9000];
    fill_pattern(a, sizeof a, 7);
    fill_pattern(b, sizeof b, 11);

    CFS *c = cfs_create(cp);
    CHECK(c != NULL, "create");
    if (!c) return;
    CHECK(cfs_write(c, "small.bin", a, sizeof a) == 0, "write small.bin");
    CHECK(cfs_write(c, "large.bin", b, sizeof b) == 0, "write large.bin");
    CHECK(cfs_finalise(c) == 0, "finalise");
    cfs_close(c);

    CHECK(has_content(cp, "small.bin", a, sizeof a), "small.bin reads back after reopen");
    CHECK(has_content(cp, "large.bin", b, sizeof b), "large.bin reads back after reopen");

    c = cfs_open(cp, CFS_RDWR);
    CHECK(c != NULL, "reopen RDWR");
    if (c) {
        CHECK(cfs_write(c, "small.bin", b, 4096) == 0, "overwrite small.bin");
        CHECK(cfs_write(c, "third.bin", a, 100) == 0, "write third.bin");
        cfs_close(c);
    }
    CHECK(has_content(cp, "small.bin", b, 4096), "overwrite survives reopen");
    CHECK(has_content(cp, "third.bin", a, 100), "third.bin survives reopen");
    CHECK(verify_clean(cp) == 0, "verify accepts a freshly written container");
}

/* ── (a) SIGKILL at every stage ─────────────────────────────────
 * A baseline container with two durable files is copied for each stage; the
 * child then writes one more file and is killed.  Afterwards the old state
 * must open, every durable file must read back, and the new file must not be
 * visible (no slot points at it). */
static void case_kill_stages(void) {
    fprintf(stderr, "=== kill at each commit stage ===\n");
    char base[600], work[600];
    path_in(base, sizeof base, "baseline.cfs");
    unlink(base);

    uint8_t small[2000], big[12000], fresh[600];
    fill_pattern(small, sizeof small, 21);
    fill_pattern(big, sizeof big, 22);
    fill_pattern(fresh, sizeof fresh, 23);

    CFS *c = cfs_create(base);
    if (!c) { CHECK(0, "create baseline"); return; }
    if (cfs_write(c, "alpha.bin", small, sizeof small) != 0 ||
        cfs_write(c, "beta.bin", big, sizeof big) != 0 ||
        cfs_finalise(c) != 0) {
        cfs_close(c);
        CHECK(0, "build baseline");
        return;
    }
    cfs_close(c);

    static const char *stages[] = { "before-data", "after-data", "before-slot" };
    static const char *labels[] = {
        "before-data   (no data written)",
        "after-data    (data on disk, no table)",
        "before-slot   (table on disk, no superblock)",
    };
    for (unsigned i = 0; i < sizeof stages / sizeof stages[0]; i++) {
        path_in(work, sizeof work, "killed.cfs");
        unlink(work);
        if (file_copy(base, work) != 0) { CHECK(0, labels[i]); continue; }

        pid_t pid = spawn_write(work, "killed.bin", fresh, sizeof fresh, stages[i]);
        int killed = killed_by_sigkill(pid);

        char msg[256];
        snprintf(msg, sizeof msg, "%s: writer died by SIGKILL", labels[i]);
        CHECK(killed, msg);
        snprintf(msg, sizeof msg, "%s: container still opens", labels[i]);
        CFS *r = cfs_open(work, CFS_RDONLY);
        CHECK(r != NULL, msg);
        if (r) cfs_close(r);

        snprintf(msg, sizeof msg, "%s: alpha.bin intact", labels[i]);
        CHECK(has_content(work, "alpha.bin", small, sizeof small), msg);
        snprintf(msg, sizeof msg, "%s: beta.bin intact", labels[i]);
        CHECK(has_content(work, "beta.bin", big, sizeof big), msg);
        snprintf(msg, sizeof msg, "%s: the killed write is not visible", labels[i]);
        CHECK(file_present(work, "killed.bin") == 0, msg);
        snprintf(msg, sizeof msg, "%s: verify finds no error", labels[i]);
        CHECK(verify_clean(work) == 0, msg);

        /* A survivor must accept new writes and keep the old files. */
        CFS *w = cfs_open(work, CFS_RDWR);
        snprintf(msg, sizeof msg, "%s: survives a later writer", labels[i]);
        CHECK(w != NULL &&
              cfs_write(w, "later.bin", fresh, sizeof fresh) == 0, msg);
        if (w) cfs_close(w);
        snprintf(msg, sizeof msg, "%s: post-crash write lands", labels[i]);
        CHECK(has_content(work, "later.bin", fresh, sizeof fresh) &&
              has_content(work, "beta.bin", big, sizeof big), msg);
    }
}

/* ── (c) torn slot: fall back to the older one ────────────────── */
static void case_bad_crc(void) {
    fprintf(stderr, "=== corrupted slot CRC ===\n");
    char cp[600];
    path_in(cp, sizeof cp, "crc.cfs");
    unlink(cp);

    /* Small files keep this on the plain block path: exactly one commit per
     * write, so the newest slot is the only one that knows about state B.
     * (A dedup-sized write commits several times, and the previous slot can
     * legitimately already contain it.) */
    uint8_t a[512], b[512];
    fill_pattern(a, sizeof a, 31);
    fill_pattern(b, sizeof b, 32);

    CFS *c = cfs_create(cp);
    if (!c) { CHECK(0, "create"); return; }
    CHECK(cfs_write(c, "state-a.bin", a, sizeof a) == 0, "commit state A");
    CHECK(cfs_write(c, "state-b.bin", b, sizeof b) == 0, "commit state B");
    cfs_close(c);

    /* Which slot is newest? */
    int fd = open(cp, O_RDWR);
    if (fd < 0) { CHECK(0, "open raw"); return; }
    uint8_t raw[2][CFS_SB_REC_SIZE];
    CfsSbSlot slot[2];
    for (int i = 0; i < 2; i++) {
        memset(raw[i], 0, sizeof raw[i]);
        ssize_t n = pread(fd, raw[i], sizeof raw[i],
                          (off_t)i * CFS_SB_SLOT_SIZE);
        cfs_sb_decode(raw[i], n > 0 ? (size_t)n : 0, &slot[i]);
    }
    CHECK(slot[0].kind && slot[1].kind, "both slots are valid after two commits");
    if (!(slot[0].kind && slot[1].kind)) { close(fd); return; }

    int newest = slot[1].seq > slot[0].seq ? 1 : 0;
    /* Flip a bit in the CRC field itself: the fields still parse, so only
     * the checksum can catch this. */
    uint8_t bad = raw[newest][CFS_SB_CRC_OFF] ^ 0x01;
    CHECK(pwrite(fd, &bad, 1,
                 (off_t)newest * CFS_SB_SLOT_SIZE + CFS_SB_CRC_OFF) == 1,
          "corrupt the newest slot's CRC");
    close(fd);

    /* The reader must fall back to the other slot: state A only. */
    CFS *r = cfs_open(cp, CFS_RDONLY);
    CHECK(r != NULL, "container opens after a torn slot");
    if (r) cfs_close(r);
    CHECK(has_content(cp, "state-a.bin", a, sizeof a),
          "older state's file is intact");
    CHECK(file_present(cp, "state-b.bin") == 0,
          "the newer state (only in the torn slot) is gone, not corrupt");
    CHECK(verify_clean(cp) > 0, "verify reports the torn slot's CRC");

    /* The damage must be repairable by the next commit. */
    CFS *w = cfs_open(cp, CFS_RDWR);
    CHECK(w != NULL, "reopen RDWR after recovery");
    if (w) {
        CHECK(cfs_write(w, "state-c.bin", b, sizeof b) == 0,
              "commit a new state over the torn slot");
        cfs_close(w);
    }
    CHECK(has_content(cp, "state-a.bin", a, sizeof a) &&
          has_content(cp, "state-c.bin", b, sizeof b),
          "recovered state plus the new write survive");
    CHECK(verify_clean(cp) == 0, "verify is clean after the repair");
}

/* ── write a v2 (legacy) container by hand ──────────────────────
 * This is byte-for-byte the layout the previous code emitted: 40-byte
 * superblock at 0, RAW CPEnc block at 40, table after it.  N is chosen so
 * the old table starts inside the backup slot's sector, which is the case
 * the upgrade's shield exists for. */
static int make_legacy_container(const char *path, const char *name,
                                 const uint8_t *data, uint32_t n) {
    uint32_t blk_size = CPENC_HEADER_SIZE + 1 + n;   /* header + lag + payload */
    uint32_t path_len = (uint32_t)strlen(name);
    uint32_t tab_size = 24 + 16 + path_len;          /* fixed + one block + path */
    uint64_t tab_off = CFS_SB_SIZE + blk_size;

    uint8_t *buf = calloc(1, (size_t)(tab_off + tab_size));
    if (!buf) return -1;
    /* superblock, v2 */
    memcpy(buf, CFS_MAGIC, 8);
    cfs_wr16(buf + 8, CFS_VERSION_LEGACY);
    cfs_wr64(buf + 10, tab_off);
    cfs_wr32(buf + 18, tab_size);
    cfs_wr32(buf + 22, 1);
    cfs_wr64(buf + 26, 1700000000);
    cfs_wr16(buf + 34, 0);
    /* data block: RAW passthrough */
    uint8_t *blk = buf + CFS_SB_SIZE;
    cfs_wr16(blk, CPENC_MAGIC);
    blk[2] = 7;   /* v2-era container: block format 7, no CRC trailer */
    blk[3] = CPENC_STRIDE_RAW;
    cfs_wr32(blk + 4, n);
    cfs_wr32(blk + 8, 1 + n);
    blk[CPENC_HEADER_SIZE] = CPENC_LAG_NONE;
    memcpy(blk + CPENC_HEADER_SIZE + 1, data, n);
    /* inode table, one entry */
    uint8_t *p = buf + tab_off;
    cfs_wr64(p, n); p += 8;                 /* orig_size */
    cfs_wr64(p, 1700000000); p += 8;        /* mtime */
    cfs_wr16(p, CFS_MODE_FILE); p += 2;
    cfs_wr16(p, path_len); p += 2;
    cfs_wr32(p, 1); p += 4;                 /* block_count */
    cfs_wr64(p, CFS_SB_SIZE); p += 8;       /* block offset */
    cfs_wr32(p, blk_size); p += 4;
    cfs_wr32(p, n); p += 4;
    memcpy(p, name, path_len);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { free(buf); return -1; }
    ssize_t w = write(fd, buf, tab_off + tab_size);
    close(fd);
    free(buf);
    return w == (ssize_t)(tab_off + tab_size) ? 0 : -1;
}

static void case_legacy(void) {
    fprintf(stderr, "=== v2 (legacy) container ===\n");
    char cp[600];
    path_in(cp, sizeof cp, "legacy.cfs");
    unlink(cp);

    uint8_t old[480], fresh[3000];
    fill_pattern(old, sizeof old, 41);       /* table lands at 533: inside slot 1 */
    fill_pattern(fresh, sizeof fresh, 42);

    CHECK(make_legacy_container(cp, "old.txt", old, sizeof old) == 0,
          "hand-build a v2 container");

    CFS *r = cfs_open(cp, CFS_RDONLY);
    CHECK(r != NULL, "v2 container opens read-only");
    if (r) cfs_close(r);
    CHECK(has_content(cp, "old.txt", old, sizeof old), "v2 content reads back");
    CHECK(verify_clean(cp) == 0, "verify accepts the v2 layout");

    CFS *w = cfs_open(cp, CFS_RDWR);
    CHECK(w != NULL, "v2 container opens read-write");
    if (w) {
        CHECK(cfs_write(w, "new.txt", fresh, sizeof fresh) == 0,
              "first write upgrades the layout");
        cfs_close(w);
    }
    CHECK(has_content(cp, "old.txt", old, sizeof old),
          "pre-upgrade file intact after the upgrade");
    CHECK(has_content(cp, "new.txt", fresh, sizeof fresh),
          "post-upgrade file reads back");
    CHECK(verify_clean(cp) == 0, "upgraded container verifies clean");

    /* The upgraded file must be a v3 container now. */
    uint8_t raw[CFS_SB_REC_SIZE];
    CfsSbSlot s;
    int fd = open(cp, O_RDONLY);
    if (fd >= 0) {
        ssize_t got = pread(fd, raw, sizeof raw, 0);
        close(fd);
        cfs_sb_decode(raw, got > 0 ? (size_t)got : 0, &s);
    } else {
        memset(&s, 0, sizeof s);
    }
    CHECK(s.kind == CFS_SB_SLOT_VALID && s.sb.version == CFS_VERSION,
          "primary slot is now a v3 record");
}

/* ── (b) a real ENOSPC on a small tmpfs ─────────────────────────
 * The fill child runs inside `unshare -Ur -m`, mounts a 2 MiB tmpfs and
 * writes until the host refuses the bytes.  It then reopens the container
 * and checks every file whose write returned success. */

static int tmpfs_child(const char *dir) {
    if (mount("tmpfs", dir, "tmpfs", 0, "size=1M,mode=0777") != 0) {
        fprintf(stderr, "  SKIP: cannot mount tmpfs (%s)\n", strerror(errno));
        return 77;
    }
    char cp[600];
    snprintf(cp, sizeof cp, "%s/enospc.cfs", dir);
    unlink(cp);

    enum { NSEED = 3, FILL = 800 };
    uint8_t durable[NSEED][4096], fill[4096];
    char names[NSEED][32];
    static char kept[1024][32];
    int nkept = 0;

    CFS *c = cfs_create(cp);
    if (!c) { fprintf(stderr, "  FAIL: create on tmpfs\n"); return 1; }
    for (int i = 0; i < NSEED; i++) {
        fill_pattern(durable[i], sizeof durable[i], 100 + i);
        snprintf(names[i], sizeof names[i], "durable%d.bin", i);
        if (cfs_write(c, names[i], durable[i], sizeof durable[i]) != 0) {
            fprintf(stderr, "  FAIL: durable write %d failed\n", i);
            cfs_close(c);
            return 1;
        }
    }
    cfs_close(c);

    c = cfs_open(cp, CFS_RDWR);
    if (!c) { fprintf(stderr, "  FAIL: reopen for the fill\n"); return 1; }
    int got_enospc = 0, enospc_at = -1;
    for (int i = 0; i < FILL && !got_enospc; i++) {
        char nm[32];
        snprintf(nm, sizeof nm, "fill%d.bin", i);
        fill_pattern(fill, sizeof fill, 1000 + (uint32_t)i);
        int rc = cfs_write(c, nm, fill, sizeof fill);
        if (rc != 0) {
            if (rc == CFS_ENOSPC || errno == ENOSPC) {
                got_enospc = 1;
                enospc_at = i;
            } else {
                fprintf(stderr, "  FAIL: fill %d failed with %d (errno %d)\n",
                        i, rc, errno);
                cfs_close(c);
                return 1;
            }
        } else if (nkept < (int)(sizeof kept / sizeof kept[0])) {
            snprintf(kept[nkept++], sizeof kept[0], "%s", nm);
        }
    }
    cfs_close(c);
    if (!got_enospc) {
        fprintf(stderr, "  FAIL: the %d-write fill never hit ENOSPC\n", FILL);
        return 1;
    }

    /* Every committed write, and every durable file, must survive. */
    CFS *r = cfs_open(cp, CFS_RDONLY);
    if (!r) { fprintf(stderr, "  FAIL: container unopenable after ENOSPC\n"); return 1; }
    cfs_close(r);
    for (int i = 0; i < NSEED; i++)
        if (!has_content(cp, names[i], durable[i], sizeof durable[i])) {
            fprintf(stderr, "  FAIL: %s lost after ENOSPC\n", names[i]);
            return 1;
        }
    for (int i = 0; i < nkept; i++) {
        uint32_t seed = (uint32_t)atoi(kept[i] + 4);
        fill_pattern(fill, sizeof fill, 1000 + seed);
        if (!has_content(cp, kept[i], fill, sizeof fill)) {
            fprintf(stderr, "  FAIL: committed %s lost after ENOSPC\n", kept[i]);
            return 1;
        }
    }
    FILE *sink = fopen("/dev/null", "w");
    int vr = sink ? cfs_verify(cp, 0, sink) : -1;
    if (sink) fclose(sink);
    if (vr != 0) {
        fprintf(stderr, "  FAIL: verify after ENOSPC returned %d\n", vr);
        return 1;
    }
    fprintf(stderr, "  (ENOSPC hit on fill %d; %d committed files intact)\n",
            enospc_at, nkept);
    return 0;
}

static int have_unshare(void) {
    pid_t pid = fork();
    if (pid == 0) {
        execlp("unshare", "unshare", "-Ur", "-m", "true", (char *)NULL);
        _exit(127);
    }
    int st = 0;
    if (pid < 0 || waitpid(pid, &st, 0) != pid) return 0;
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

static void case_enospc(void) {
    fprintf(stderr, "=== real ENOSPC on a tmpfs ===\n");
    if (!have_unshare()) {
        fprintf(stderr, "  SKIP: `unshare -Ur -m` is not available here\n");
        return;
    }
    char dir[] = "/tmp/cfs_crash_tmpfs.XXXXXX";
    if (!mkdtemp(dir)) { CHECK(0, "mkdtemp for the tmpfs"); return; }

    char self[4096];
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n <= 0) { CHECK(0, "locate own executable"); rmdir(dir); return; }
    self[n] = 0;

    pid_t pid = fork();
    if (pid == 0) {
        execlp("unshare", "unshare", "-Ur", "-m", self,
               "--tmpfs-child", dir, (char *)NULL);
        _exit(127);
    }
    int st = 0;
    if (pid < 0 || waitpid(pid, &st, 0) != pid) {
        CHECK(0, "run the tmpfs child");
    } else if (WIFEXITED(st) && WEXITSTATUS(st) == 77) {
        fprintf(stderr, "  SKIP: the child could not mount a tmpfs\n");
    } else if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
        CHECK(1, "real ENOSPC leaves the container openable and committed files intact");
    } else {
        CHECK(0, "real ENOSPC leaves the container openable and committed files intact");
    }
    rmdir(dir);
}

/* ── main ─────────────────────────────────────────────────────── */
int main(int argc, char **argv) {
    setvbuf(stderr, NULL, _IONBF, 0);
    if (argc == 3 && !strcmp(argv[1], "--tmpfs-child"))
        return tmpfs_child(argv[2]);

    const char *tmp = getenv("TMPDIR");
    if (!tmp || !*tmp) tmp = "/tmp";
    snprintf(scratch, sizeof scratch, "%s/cfs_crash.XXXXXX", tmp);
    if (!mkdtemp(scratch)) {
        perror("mkdtemp");
        return 1;
    }

    fprintf(stderr, "=== cfs_crash_test ===\n");
    case_roundtrip();
    case_kill_stages();
    case_bad_crc();
    case_legacy();
    case_enospc();

    /* Remove the scratch tree (the test leaves nothing behind). */
    char cmd[700];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", scratch);
    if (system(cmd) != 0) fprintf(stderr, "  (could not remove %s)\n", scratch);

    fprintf(stderr, "=== %d failures ===\n", failures);
    return failures ? 1 : 0;
}
