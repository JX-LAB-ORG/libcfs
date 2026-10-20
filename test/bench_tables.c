/* bench_tables.c — row length alone, with the content held fixed and made
 * explicitly NON-periodic.
 *
 * Two earlier attempts at this were confounded and had to be thrown away:
 *   - the first varied the content along with the stride;
 *   - the second used fields like (i*37)%50000, which make the whole table
 *     exactly periodic — xz's 64MB window eats a repeating period whole, so
 *     that measured xz's long-range matcher, not cpenc's alignment.
 *
 * So here every row holds the SAME four fields, none of them periodic:
 *   f0 a monotonic clock (smooth, no repeat)
 *   f1 a microsecond field that is pure noise
 *   f2 a user id drawn from a pool, so the sequence never cycles
 *   f3 an amount that drifts with a little jitter
 * and everything past byte 16 is zero padding to reach the target stride.
 * Any ratio difference across strides is therefore alignment, nothing else.
 *
 *   usage: bench_tables <out_dir> [MB]
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define MB (1024u * 1024u)

static uint64_t s = 0xC0FFEE123456789ull;
static uint32_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return (uint32_t)(s >> 32); }

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "/root/bench/corpus";
    size_t target = (size_t)(argc > 2 ? atoi(argv[2]) : 32) * MB;
    static const int strides[] = { 16, 20, 24, 28, 32, 48, 64 };
    char path[512];

    for (unsigned k = 0; k < sizeof(strides) / sizeof(strides[0]); k++) {
        int st = strides[k];
        int nf = st / 4;
        snprintf(path, sizeof(path), "%s/rec%d.dat", dir, st);
        FILE *f = fopen(path, "wb");
        if (!f) return 1;
        for (size_t n = 0, i = 0; n < target; i++) {
            int32_t f0 = (int32_t)(1792300000u + i / 1000u);      /* monotonic clock */
            int32_t f1 = (int32_t)(rnd() % 1000000u);             /* noise           */
            int32_t f2 = (int32_t)(rnd() % 9973u);                /* id from a pool  */
            int32_t f3 = (int32_t)(100000 + (int32_t)(i % 997) * 13 + (int32_t)(rnd() % 5));
            int32_t row[4] = { f0, f1, f2, f3 };
            for (int c = 0; c < nf; c++) {
                int32_t v = c < 4 ? row[c] : 0;
                fwrite(&v, 4, 1, f);
            }
            n += (size_t)st;
        }
        fclose(f);
    }
    printf("wrote rec{16,20,24,28,32,48,64}.dat in %s (same content, non-periodic)\n", dir);
    return 0;
}
