/* iso_gen <out.iso> — write a small spec-valid ISO for the fsck test.
 * Reuses the same builder the install test feeds to the installer. */
#include "iso_mk.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <out.iso>\n", argv[0]); return 1; }
    static uint8_t big[300000], txt[4000];
    for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i * 7 + 3);
    for (size_t i = 0; i < sizeof txt; i++) txt[i] = (uint8_t)("hello iso world\n"[i % 16]);
    IsoMkEntry e[3] = {
        { "boot/kernel.bin", big, sizeof big, 0 },
        { "etc/hello.txt",   txt, sizeof txt, 0 },
        { "readme.md",       txt, 100, 0 },
    };
    size_t sz = 0;
    uint8_t *iso = iso_mk_build(e, 3, "FW", &sz);
    if (!iso) return 1;
    FILE *f = fopen(argv[1], "wb");
    if (!f) { free(iso); return 1; }
    size_t wr = fwrite(iso, 1, sz, f);
    fclose(f);
    free(iso);
    return wr == sz ? 0 : 1;
}
