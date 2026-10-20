/* bench_gen.c — generate the shaped corpora (json / records / logs).
 *
 * Random bytes say nothing about a compressor, so these are shaped like the
 * real thing: nested JSON records, fixed-width time-series rows, and
 * templated log lines with a few variable fields each.
 *
 *   usage: bench_gen <corpus_dir> [size_mb]
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MB (1024 * 1024)

static const char *LVL[] = {"INFO", "INFO", "INFO", "WARN", "ERROR", "DEBUG"};
static const char *MOD[] = {"http", "db", "auth", "cache", "sched", "net"};
static const char *ACT[] = {"handle", "run", "flush"};
static const char *RES[] = {"items", "users", "orders", "sessions"};
static const int   ST[]  = {200, 200, 200, 404, 500};

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "/root/bench/corpus";
    size_t target = (size_t)(argc > 2 ? atoi(argv[2]) : 32) * MB;
    char path[512];

    /* ── json: nested records, repeated keys, a few distinct shapes ── */
    snprintf(path, sizeof(path), "%s/json.dat", dir);
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return 1; }
    size_t n = 0;
    for (long i = 0; n < target; i++) {
        char buf[512];
        int len = snprintf(buf, sizeof(buf),
            "{\"id\": %ld, \"ts\": %ld, \"user\": \"u%05ld\", \"action\": \"%s\", "
            "\"items\": [", i, 1792300000L + i, i % 9973,
            (const char *[]){ "view", "click", "buy", "share" }[i % 4]);
        for (int k = 0; k <= i % 4; k++)
            len += snprintf(buf + len, sizeof(buf) - (size_t)len,
                "%s{\"sku\": \"SKU-%06ld\", \"qty\": %d, \"price\": %ld.%02ld}",
                k ? ", " : "", (i * 7 + k) % 100000, (int)((i + k) % 5 + 1),
                ((i * 13 + k) % 9000) / 100, ((i * 13 + k) % 9000) % 100);
        len += snprintf(buf + len, sizeof(buf) - (size_t)len,
            "], \"ok\": true, \"tags\": [%s]}\n",
            (const char *[]){ "\"a\"", "\"a\", \"b\"", "\"a\", \"b\", \"c\"" }[i % 3]);
        fwrite(buf, 1, (size_t)len, f);
        n += (size_t)len;
    }
    fclose(f);

    /* ── records: fixed-width columnar rows (time series) ── */
    snprintf(path, sizeof(path), "%s/records.dat", dir);
    f = fopen(path, "wb");
    if (!f) { perror(path); return 1; }
    n = 0;
    for (long i = 0; n < target; i++) {
        int64_t ts = 1792300000000LL + i * 1000;
        int32_t id = (int32_t)(i % 50000);
        double val = (double)((i * 37) % 100000) / 100.0;
        int16_t a = (int16_t)(i % 300), b = 7;
        fwrite(&ts, sizeof(ts), 1, f);
        fwrite(&id, sizeof(id), 1, f);
        fwrite(&val, sizeof(val), 1, f);
        fwrite(&a, sizeof(a), 1, f);
        fwrite(&b, sizeof(b), 1, f);
        n += sizeof(ts) + sizeof(id) + sizeof(val) + sizeof(a) + sizeof(b);
    }
    fclose(f);

    /* ── logs: templated lines, a handful of variable fields ── */
    snprintf(path, sizeof(path), "%s/logs.dat", dir);
    f = fopen(path, "w");
    if (!f) { perror(path); return 1; }
    n = 0;
    for (long i = 0; n < target; i++) {
        char buf[320];
        int len = snprintf(buf, sizeof(buf),
            "2026-10-%02ld %02ld:%02ld:%02ld.%03ld [%s] %s.%s - request id=%08lx "
            "path=/api/v1/%s/%ld status=%d dur=%ldms\n",
            i % 28 + 1, i % 24, i % 60, (i * 7) % 60, i % 1000,
            LVL[i % 6], MOD[i % 6], ACT[i % 3],
            (unsigned long)((i * 2654435761UL) & 0xFFFFFFFFUL),
            RES[i % 4], i % 10000, ST[i % 5], (i * 13) % 900);
        fwrite(buf, 1, (size_t)len, f);
        n += (size_t)len;
    }
    fclose(f);

    printf("generated json.dat records.dat logs.dat in %s\n", dir);
    return 0;
}
