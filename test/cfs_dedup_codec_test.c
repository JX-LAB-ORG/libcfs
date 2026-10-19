#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../cfs_dedup.h"

static int failures = 0, checks = 0;
#define T(c, msg) do { checks++; if (!(c)) { fprintf(stderr, "FAIL: %s\n", msg); failures++; } } while (0)

static void rt_uvarint(uint64_t v) {
    uint8_t b[16];
    size_t n = cfs_put_uvarint(b, v), m;
    uint64_t got = ~0ULL;
    m = cfs_get_uvarint(b, n, &got);
    checks++;
    if (m != n || got != v) { fprintf(stderr, "FAIL: uvarint %llu n=%zu m=%zu got=%llu\n",
                                       (unsigned long long)v, n, m, (unsigned long long)got); failures++; }
}

static void rt_svarint(int64_t v) {
    uint8_t b[16];
    size_t n = cfs_put_svarint(b, v), m;
    int64_t got = ~0LL;
    m = cfs_get_svarint(b, n, &got);
    checks++;
    if (m != n || got != v) { fprintf(stderr, "FAIL: svarint %lld n=%zu m=%zu got=%lld\n",
                                       (long long)v, n, m, (long long)got); failures++; }
}

/* deterministic LCG so the 1000-tuple case is reproducible */
static uint64_t rng = 0x243F6A8885A308D3ULL;
static uint64_t nextr(void) { rng = rng * 6364136223846793005ULL + 1442695040888963407ULL; return rng >> 11; }

static int tables_equal(const CfsDedupTable *a, const CfsDedupTable *b) {
    if (a->n != b->n || a->logical_size != b->logical_size) return 0;
    for (uint32_t i = 0; i < a->n; i++)
        if (a->v[i].logical != b->v[i].logical || a->v[i].length != b->v[i].length ||
            a->v[i].store   != b->v[i].store) return 0;
    return 1;
}

/* chunk @buf into lengths; returns the chunk count (a short tail < MIN is left) */
static size_t chunk_sizes(const uint8_t *buf, size_t n, size_t *out, size_t cap) {
    size_t off = 0, k = 0;
    while (off < n) {
        size_t c = cfs_cdc_next(buf + off, n - off);
        if (!c) break;
        if (k < cap) out[k] = c;
        k++; off += c;
    }
    return k;
}

/* same walk, recording cumulative (absolute) boundary offsets */
static size_t chunk_bounds(const uint8_t *buf, size_t n, size_t *out, size_t cap) {
    size_t off = 0, k = 0;
    while (off < n) {
        size_t c = cfs_cdc_next(buf + off, n - off);
        if (!c) break;
        off += c;
        if (k < cap) out[k] = off;
        k++;
    }
    return k;
}

static void roundtrip_n(uint32_t n, const char *label) {
    CfsDedupTable t; cfs_dedup_table_init(&t, 0);
    uint64_t logical = 0, store = 100000;
    for (uint32_t i = 0; i < n; i++) {
        logical += nextr() % 300;                 /* gaps, including 0 */
        uint64_t len = 1 + nextr() % 500;
        /* alternate forward jumps and backward jumps to force +/- store deltas */
        if (i & 1) store += nextr() % 4096;       /* positive delta */
        else       store = store > 2000 ? store - 2000 : 0;   /* negative or zero */
        if (cfs_dedup_table_push(&t, logical, len, store) != 0) { fprintf(stderr, "FAIL: push %s\n", label); failures++; cfs_dedup_table_free(&t); return; }
        logical += len;
    }
    t.logical_size = logical + 4096;

    uint8_t *buf = NULL; size_t blen = 0;
    T(cfs_dedup_serialize(&t, &buf, &blen) == 0, "serialize");
    T(buf != NULL && blen >= 12, "serialize produced header");

    CfsDedupTable p; memset(&p, 0xAA, sizeof p);
    T(cfs_dedup_parse(buf, blen, &p) == 0, "parse");
    T(tables_equal(&t, &p), label);

    /* trailing bytes tolerated (documented decision) */
    uint8_t *ext = malloc(blen + 4);
    memcpy(ext, buf, blen); memset(ext + blen, 0x7E, 4);
    CfsDedupTable p2; T(cfs_dedup_parse(ext, blen + 4, &p2) == 0, "parse trailing-tolerated");
    T(tables_equal(&t, &p2), "trailing bytes ignored");
    cfs_dedup_table_free(&p2); free(ext);
    cfs_dedup_table_free(&p); free(buf); cfs_dedup_table_free(&t);
}

int main(void) {
    /* ── varint roundtrip at boundaries ───────────────────────── */
    uint64_t uv[] = { 0, 1, 127, 128, 129, 16383, 16384, 0xFFFFFFFFULL, 1ULL << 40, ~0ULL };
    for (size_t i = 0; i < sizeof uv / sizeof uv[0]; i++) rt_uvarint(uv[i]);
    int64_t sv[] = { 0, 1, -1, 63, -64, 64, -65, 2147483647LL, -2147483648LL,
                     0x7FFFFFFFFFFFFFFFLL, (-0x7FFFFFFFFFFFFFFFLL - 1) };
    for (size_t i = 0; i < sizeof sv / sizeof sv[0]; i++) rt_svarint(sv[i]);

    /* ── getter truncation / bounds ───────────────────────────── */
    {
        uint8_t b[16]; uint64_t u; int64_t s;
        size_t n = cfs_put_uvarint(b, 300);       /* 2 bytes: 0xAC 0x02 */
        T(n == 2, "300 encodes to 2 bytes");
        T(cfs_get_uvarint(b, 1, &u) == 0, "uvarint truncated to 1 byte -> 0");
        T(cfs_get_uvarint(b, 0, &u) == 0, "uvarint len 0 -> 0");
        T(cfs_get_uvarint(b, 2, &u) == 2 && u == 300, "uvarint full read");
        T(cfs_get_svarint(b, 1, &s) == 0, "svarint truncated -> 0");
        uint8_t over[10]; memset(over, 0x80, 10);  /* 10 continuation bytes */
        T(cfs_get_uvarint(over, 10, &u) == 0, "over-long uvarint rejected");
        T(cfs_get_uvarint(over, 4, &u) == 0, "short continuation rejected");
    }

    /* ── serialize/parse roundtrip 0 / 1 / 1000 ───────────────── */
    roundtrip_n(0, "roundtrip 0 tuples");
    roundtrip_n(1, "roundtrip 1 tuple");
    roundtrip_n(1000, "roundtrip 1000 tuples");

    /* 0-tuple: exact header, logical_size preserved */
    {
        CfsDedupTable t; cfs_dedup_table_init(&t, 0xDEADBEEFCAFEULL);
        uint8_t *b = NULL; size_t bl = 0;
        T(cfs_dedup_serialize(&t, &b, &bl) == 0 && bl == 12, "empty serialize = 12 bytes");
        CfsDedupTable p; T(cfs_dedup_parse(b, bl, &p) == 0, "empty parse");
        T(p.n == 0 && p.logical_size == 0xDEADBEEFCAFEULL, "empty logical_size preserved");
        free(b); cfs_dedup_table_free(&p); cfs_dedup_table_free(&t);
    }

    /* ── malformed input rejection ────────────────────────────── */
    {
        uint8_t hdr[12]; memset(hdr, 0, sizeof hdr);   /* n=0, logical_size=0 */
        CfsDedupTable p;
        T(cfs_dedup_parse(hdr, 11, &p) == -1, "truncated header rejected");
        T(cfs_dedup_parse(hdr, 0, &p) == -1, "empty buffer rejected");

        /* n=1 but body is three continuation bytes -> truncated varint */
        uint8_t trunc[15]; memset(trunc, 0x80, sizeof trunc);
        trunc[0] = 1;   /* n_refs = 1 */
        memset(trunc + 4, 0, 8);
        T(cfs_dedup_parse(trunc, sizeof trunc, &p) == -1, "truncated varint rejected");

        /* n=2: first tuple valid, second truncated */
        uint8_t partial[18]; memset(partial, 0x80, sizeof partial);
        partial[0] = 2; memset(partial + 4, 0, 8);
        partial[12] = 0; partial[13] = 1; partial[14] = 0;   /* gap0 len1 delta0 */
        T(cfs_dedup_parse(partial, sizeof partial, &p) == -1, "second tuple truncated rejected");

        /* a tuple with length == 0 is malformed */
        uint8_t zero[15]; memset(zero, 0, sizeof zero);
        zero[0] = 1;   /* n_refs = 1; gap=0 length=0 delta=0 follow */
        T(cfs_dedup_parse(zero, sizeof zero, &p) == -1, "zero-length tuple rejected");
    }

    /* push() rejects overlaps / disorder / zero length / overflow */
    {
        CfsDedupTable t; cfs_dedup_table_init(&t, 0);
        T(cfs_dedup_table_push(&t, 10, 5, 0) == 0,  "push base");
        T(cfs_dedup_table_push(&t, 10, 0, 0) == -1, "push length 0 rejected");
        T(cfs_dedup_table_push(&t, 5, 2, 0) == -1,  "push out-of-order rejected");
        T(cfs_dedup_table_push(&t, 14, 2, 0) == -1, "push overlap rejected");
        T(cfs_dedup_table_push(&t, 15, 2, 0) == 0,  "push contiguous accepted");
        cfs_dedup_table_free(&t);

        CfsDedupTable u; cfs_dedup_table_init(&u, 0);
        T(cfs_dedup_table_push(&u, ~0ULL - 1, 5, 0) == -1, "push end-overflow rejected");
        cfs_dedup_table_free(&u);
    }

    /* ── find() holes and boundaries ──────────────────────────── */
    {
        CfsDedupTable t; cfs_dedup_table_init(&t, 100);
        T(cfs_dedup_table_push(&t, 10, 5, 100) == 0, "find setup t0");
        T(cfs_dedup_table_push(&t, 20, 3,  50) == 0, "find setup t1");
        T(cfs_dedup_table_push(&t, 30, 1, 200) == 0, "find setup t2");
        const CfsRef *r;
        T(cfs_dedup_table_find(&t, 0)  == NULL, "find before first -> NULL");
        T(cfs_dedup_table_find(&t, 9)  == NULL, "find hole before first -> NULL");
        T((r = cfs_dedup_table_find(&t, 10)) && r->logical == 10, "find start of t0");
        T((r = cfs_dedup_table_find(&t, 14)) && r->logical == 10, "find last byte of t0");
        T(cfs_dedup_table_find(&t, 15) == NULL, "find at end boundary (hole) -> NULL");
        T(cfs_dedup_table_find(&t, 19) == NULL, "find mid hole -> NULL");
        T((r = cfs_dedup_table_find(&t, 20)) && r->logical == 20, "find start of t1");
        T((r = cfs_dedup_table_find(&t, 22)) && r->logical == 20, "find last byte of t1");
        T(cfs_dedup_table_find(&t, 23) == NULL, "find hole after t1 -> NULL");
        T((r = cfs_dedup_table_find(&t, 30)) && r->logical == 30, "find t2");
        T(cfs_dedup_table_find(&t, 31) == NULL, "find at end of t2 -> NULL");
        T(cfs_dedup_table_find(&t, 1000) == NULL, "find past end -> NULL");
        cfs_dedup_table_free(&t);

        CfsDedupTable e; cfs_dedup_table_init(&e, 0);
        T(cfs_dedup_table_find(&e, 0) == NULL, "find on empty table -> NULL");
        cfs_dedup_table_free(&e);
    }

    /* ── content-defined chunking: determinism, bounds, average ── */
    {
        const size_t N = 1u << 20;
        uint8_t *buf = malloc(N);
        T(buf != NULL, "cdc buffer alloc");
        if (buf) {
            for (size_t i = 0; i < N; i++) buf[i] = (uint8_t)nextr();

            static size_t s1[4096], s2[4096];
            size_t k1 = chunk_sizes(buf, N, s1, 4096);
            size_t k2 = chunk_sizes(buf, N, s2, 4096);
            T(k1 > 0, "cdc produced chunks");
            T(k1 == k2, "cdc chunk count deterministic");
            int same = (k1 == k2);
            for (size_t i = 0; same && i < k1; i++) if (s1[i] != s2[i]) same = 0;
            T(same, "cdc repeated calls give identical boundaries");

            size_t total = 0; int inrange = 1;
            for (size_t i = 0; i < k1; i++) {
                if (s1[i] < CFS_CDC_MIN || s1[i] > CFS_CDC_MAX) inrange = 0;
                total += s1[i];
            }
            T(inrange, "cdc every chunk within [MIN,MAX]");
            T(N - total < CFS_CDC_MIN, "cdc tail is shorter than MIN");
            double avg = (double)total / (double)k1;
            fprintf(stderr, "cfs_dedup_codec_test: cdc avg chunk = %.0f bytes (%zu chunks)\n",
                    avg, k1);
            T(avg >= 2048.0 && avg <= 16384.0, "cdc average size in sane range");
        }
        free(buf);
    }

    /* ── cdc: a prefix shift changes the first chunk, then resyncs ── */
    {
        const size_t N = 1u << 20;
        uint8_t *buf = malloc(N);
        T(buf != NULL, "cdc shift buffer alloc");
        if (buf) {
            rng = 0x243F6A8885A308D3ULL;   /* fixed stream: the resync point is data-dependent */
            for (size_t i = 0; i < N; i++) buf[i] = (uint8_t)nextr();
            static size_t A[4096];
            size_t na = chunk_bounds(buf, N, A, 4096);

            size_t P = CFS_CDC_MIN;            /* long enough to disturb the first cut */
            uint8_t *sh = malloc(N + P);
            T(sh != NULL, "cdc shifted buffer alloc");
            if (sh) {
                for (size_t i = 0; i < P; i++) sh[i] = (uint8_t)nextr();
                memcpy(sh + P, buf, N);
                static size_t B[4096];
                size_t nb = chunk_bounds(sh, N + P, B, 4096);
                size_t ib = 0;                 /* drop boundaries sitting inside the prefix */
                while (ib < nb && B[ib] < P) ib++;
                size_t blen = nb - ib;
                T(blen >= na, "cdc shift reproduces every original boundary");
                size_t d = blen > na ? blen - na : 0;   /* leading chunks that changed */
                T(d == 1, "cdc shift changes only the first chunk");
                int suffix = (blen >= na);
                for (size_t i = 0; suffix && i < na; i++)
                    if (B[ib + d + i] - P != A[i]) suffix = 0;
                T(suffix, "cdc shift resynchronises to original boundaries");
            }
            free(sh);
        }
        free(buf);
    }

    /* ── feature hash ─────────────────────────────────────────── */
    {
        uint8_t hb[256];
        for (size_t i = 0; i < sizeof hb; i++) hb[i] = (uint8_t)nextr();
        uint64_t a[2], b[2];
        cfs_feature_hash(hb, sizeof hb, a);
        cfs_feature_hash(hb, sizeof hb, b);
        T(a[0] == b[0] && a[1] == b[1], "feature hash deterministic");

        uint64_t z0[2], z1[2];
        cfs_feature_hash(hb, 0, z0);
        cfs_feature_hash(hb, 0, z1);
        T(z0[0] == z1[0] && z0[1] == z1[1], "feature hash n=0 works");

        size_t pos[] = { 0, 1, 7, 8, 63, 64, 100, 127, 255 };
        int both = 1;
        for (size_t t = 0; t < sizeof pos / sizeof pos[0]; t++) {
            uint8_t cp[256]; memcpy(cp, hb, sizeof cp);
            cp[pos[t]] ^= 0x01;
            uint64_t f[2]; cfs_feature_hash(cp, sizeof cp, f);
            if (f[0] == a[0] || f[1] == a[1]) both = 0;   /* both halves must move */
        }
        T(both, "feature hash: one byte flip changes both halves");

        uint64_t l0[2], l1[2];
        cfs_feature_hash(hb, 100, l0);
        cfs_feature_hash(hb, 101, l1);
        T(l0[0] != l1[0] || l0[1] != l1[1], "feature hash length-sensitive");
    }

    /* ── feature index: first-occurrence + wrong length ───────── */
    {
        CfsFeatIndex ix; cfs_feat_index_init(&ix);
        uint64_t off;
        uint64_t miss[2] = { 0x123456789ABCDEF0ULL, 0x0FEDCBA987654321ULL };
        T(cfs_feat_index_get(&ix, miss, 10, &off) == 0, "index empty get -> 0");

        uint64_t k0[2] = { 0xAAAA000011112222ULL, 0xBBBB333344445555ULL };
        T(cfs_feat_index_put(&ix, k0, 100, 64) == 0, "index put first occurrence");
        T(cfs_feat_index_put(&ix, k0, 999, 64) == 0, "index duplicate put ok");
        T(cfs_feat_index_get(&ix, k0, 64, &off) == 1 && off == 100, "index keeps first offset");
        T(cfs_feat_index_get(&ix, k0, 65, &off) == 0, "index wrong length -> 0");
        T(cfs_feat_index_get(&ix, k0, 63, &off) == 0, "index wrong length (2) -> 0");
        cfs_feat_index_free(&ix);
    }

    /* ── feature index: 100k insert / read-back / growth ──────── */
    {
        const uint32_t N = 100000;
        static uint64_t kk[100000][2];
        static uint64_t oo[100000];
        static uint32_t ll[100000];
        CfsFeatIndex ix; cfs_feat_index_init(&ix);
        int putfail = 0;
        for (uint32_t i = 0; i < N; i++) {
            kk[i][0] = nextr();
            kk[i][1] = nextr();
            oo[i] = (uint64_t)i * 7777 + 3;
            ll[i] = 1 + (uint32_t)(nextr() % 60000);
            if (cfs_feat_index_put(&ix, kk[i], oo[i], ll[i]) != 0) putfail = 1;
        }
        T(!putfail, "index 100k puts succeed");
        T(ix.n == N, "index holds 100k entries");

        uint32_t hits = 0, offbad = 0;
        for (uint32_t i = 0; i < N; i++) {
            uint64_t got;
            if (cfs_feat_index_get(&ix, kk[i], ll[i], &got) == 1) {
                hits++;
                if (got != oo[i]) offbad++;
            }
        }
        T(hits + 2 >= N, "index reads back 100k features (rare dup keys allowed)");
        T(offbad <= 2, "index returns the stored offset");

        T(ix.cap != 0 && (ix.cap & (ix.cap - 1)) == 0, "index capacity is a power of two");
        T(ix.cap > N, "index grew past the entry count");
        T((uint64_t)ix.n * 10 <= (uint64_t)ix.cap * 7, "index load factor <= 0.7");

        uint64_t got;
        T(cfs_feat_index_get(&ix, kk[12345], ll[12345] + 1, &got) == 0, "stored key wrong length -> 0");
        T(cfs_feat_index_get(&ix, kk[12345], ll[12345] - 1, &got) == 0, "stored key wrong length (2) -> 0");
        uint64_t m2[2] = { 0xDEADBEEFCAFEBABEULL, 0x0123456789ABCDEFULL };
        T(cfs_feat_index_get(&ix, m2, 123, &got) == 0, "missing feature -> 0");

        cfs_feat_index_free(&ix);
    }

    fprintf(stderr, "cfs_dedup_codec_test: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
