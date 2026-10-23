/* preload_probe — exercise the LD_PRELOAD hook through ordinary libc calls,
 * in one process.  Shell redirection cannot be used for this: bash's dup2 of
 * a virtual fd only updates the preload table, so the kernel fd a child
 * inherits is the real stdout (see the README's mount-path notes).
 *
 *   usage: preload_probe write PATH TEXT
 *          preload_probe read  PATH          (prints the byte count)
 *          preload_probe stat  PATH          (prints size and mtime)
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s write|read|stat PATH [TEXT]\n", argv[0]); return 2; }
    if (!strcmp(argv[1], "write")) {
        if (argc < 4) return 2;
        int fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) { perror("open"); return 1; }
        size_t n = strlen(argv[3]);
        if (write(fd, argv[3], n) != (ssize_t)n) { perror("write"); return 1; }
        if (close(fd) != 0) { perror("close"); return 1; }
        return 0;
    }
    if (!strcmp(argv[1], "read")) {
        int fd = open(argv[2], O_RDONLY);
        if (fd < 0) { perror("open"); return 1; }
        char b[65536]; ssize_t n; size_t total = 0;
        while ((n = read(fd, b, sizeof b)) > 0) total += (size_t)n;
        close(fd);
        printf("%zu\n", total);
        return 0;
    }
    if (!strcmp(argv[1], "stat")) {
        struct stat st;
        if (stat(argv[2], &st) != 0) { perror("stat"); return 1; }
        printf("%llu %llu\n", (unsigned long long)st.st_size, (unsigned long long)st.st_mtime);
        return 0;
    }
    return 2;
}
