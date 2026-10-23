/* test/cfs_seal_test.c — v9 sealed container core (S0 primitives + S1 format)
 *
 * Two jobs:
 *
 *   1. pin the primitives to published vectors (RFC 5869, NIST GCM, RFC 9106,
 *      RFC 8439, RFC 4231).  A wrong Argon2 parameter name or a GCM nonce
 *      length switch would still round-trip against itself, so round-trips
 *      alone prove nothing about the crypto.
 *   2. pin the format's behaviour under the attacks the plan enumerates:
 *      wrong key, missing shard, tampered header/block/ring link, swapped
 *      shard identity — each must produce zero plaintext and, for a wrong
 *      key, the same length and the same bytes on every run.
 *
 * The timing check is a report, not a gate: a busy shared server can easily
 * swamp a few hundred microseconds of difference, and the point is to see
 * the numbers, not to fail a build on a scheduler hiccup.  Plan §6's P6 is
 * about not handing out an oracle, and the traversal is written to do the
 * same work on both paths — the measurement is there to catch a regression
 * that reintroduces a shortcut.
 *
 * Build: cc -std=gnu11 -O2 -fsanitize=address,undefined -g \
 *          test/cfs_seal_test.c cfs_seal.c -lcrypto -o test/cfs_seal_test
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include "../cfs_seal.h"

static int failed = 0, checks = 0;
#define CHK(c, m) do { checks++; if (!(c)) { failed++; \
        fprintf(stderr, "  FAIL: %s\n", m); } \
    else { fprintf(stderr, "  OK %s\n", m); } } while (0)

static double now_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static uint32_t rng = 0x9E3779B9u;
static uint32_t rnd(void) {
    rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
    return rng;
}

static int hexeq(const uint8_t *got, const char *want, size_t n) {
    char buf[512];
    if (n * 2 >= sizeof buf) return 0;
    for (size_t i = 0; i < n; i++) sprintf(buf + 2 * i, "%02x", got[i]);
    buf[2 * n] = 0;
    return strcmp(buf, want) == 0;
}

static int contains(const uint8_t *hay, size_t n, const void *needle, size_t m) {
    if (m == 0 || m > n) return 0;
    for (size_t i = 0; i + m <= n; i++)
        if (memcmp(hay + i, needle, m) == 0) return 1;
    return 0;
}

/* Runs of identical bytes so the RLE codec has something to do. */
static void fill_pattern(uint8_t *p, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint32_t r = rnd();
        uint8_t v = (uint8_t)(r >> 16);
        size_t run = 1 + (r >> 24) % 200;
        if (run > n - i) run = n - i;
        memset(p + i, v, run);
        i += run;
    }
}

/* ─── tiny codec: byte RLE, count/value pairs ───────────────────────────── */
typedef struct { int encode, decode; size_t shrunk; } RleCtx;

static int rle_compress(void *ctx, const uint8_t *in, size_t n,
                        uint8_t *out, size_t cap, size_t *outlen) {
    RleCtx *c = ctx;
    size_t o = 0, i = 0;
    c->encode++;
    while (i < n) {
        size_t run = 1;
        while (i + run < n && in[i + run] == in[i] && run < 255) run++;
        if (o + 2 > cap) return -1;
        out[o++] = (uint8_t)run;
        out[o++] = in[i];
        i += run;
    }
    *outlen = o;
    if (o < n) c->shrunk++;
    return 0;
}

static int rle_decompress(void *ctx, const uint8_t *in, size_t n,
                          uint8_t *out, size_t cap, size_t *outlen) {
    RleCtx *c = ctx;
    size_t o = 0, i = 0;
    c->decode++;
    while (i < n) {
        if (i + 2 > n) return -1;
        size_t run = in[i];
        uint8_t v = in[i + 1];
        i += 2;
        if (!run || o + run > cap) return -1;
        memset(out + o, v, run);
        o += run;
    }
    *outlen = o;
    return 0;
}

/* ─── S0: published vectors ────────────────────────────────────────────── */
static void test_vectors(void) {
    fprintf(stderr, "=== S0 vectors ===\n");

    /* RFC 5869 A.1 */
    {
        uint8_t ikm[22], salt[13], info[10], okm[42];
        memset(ikm, 0x0b, sizeof ikm);
        for (int i = 0; i < 13; i++) salt[i] = (uint8_t)i;
        for (int i = 0; i < 10; i++) info[i] = (uint8_t)(0xf0 + i);
        int r = cfs_seal_hkdf(ikm, sizeof ikm, salt, sizeof salt,
                              info, sizeof info, okm, sizeof okm);
        CHK(r == 0 && hexeq(okm, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db0"
                                "2d56ecc4c5bf34007208d5b887185865", 42), "HKDF-SHA256 RFC 5869 A.1");
    }
    /* RFC 5869 A.3: zero-length salt and info */
    {
        uint8_t ikm[22], okm[42];
        memset(ikm, 0x0b, sizeof ikm);
        int r = cfs_seal_hkdf(ikm, sizeof ikm, NULL, 0, NULL, 0, okm, sizeof okm);
        CHK(r == 0 && hexeq(okm, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f"
                                "3c738d2d9d201395faa4b61a96c8", 42),
            "HKDF-SHA256 RFC 5869 A.3 (empty salt/info)");
    }
    /* NIST GCM test case 16: AES-256, all-zero key/IV, empty pt and AAD */
    {
        uint8_t key[32] = {0}, iv[12] = {0}, tag[16], ct[16];
        CHK(cfs_seal_gcm_seal(key, iv, NULL, 0, NULL, 0, ct, tag) == 0 &&
            hexeq(tag, "530f8afbc74536b9a963b4f1c4cb738b", 16),
            "AES-256-GCM empty plaintext tag");
    }
    /* NIST GCM test case 14: AES-256, 16 zero bytes */
    {
        uint8_t key[32] = {0}, iv[12] = {0}, tag[16], ct[16], pt[16] = {0}, back[16];
        CHK(cfs_seal_gcm_seal(key, iv, NULL, 0, pt, 16, ct, tag) == 0 &&
            hexeq(ct, "cea7403d4d606b6e074ec5d3baf39d18", 16) &&
            hexeq(tag, "d0d1c8a799996bf0265b98b5d48ab919", 16),
            "AES-256-GCM 16-byte ciphertext and tag");
        CHK(cfs_seal_gcm_open(key, iv, NULL, 0, ct, 16, tag, back) == 0 &&
            memcmp(back, pt, 16) == 0, "AES-256-GCM decrypt");
        tag[0] ^= 1;
        memset(back, 0xAA, 16);
        CHK(cfs_seal_gcm_open(key, iv, NULL, 0, ct, 16, tag, back) != 0,
            "AES-256-GCM rejects a bad tag");
        int zero = 1;
        for (int i = 0; i < 16; i++) if (back[i]) zero = 0;
        CHK(zero, "AES-256-GCM leaves no plaintext on tag failure");
    }
    /* RFC 9106 §5.3 Argon2id */
    {
        uint8_t pw[32], salt[16], sec[8], ad[12], out[32];
        CfsSealKdfParams p = { 32, 3, 4 };   /* 32 KiB, t=3, p=4 */
        memset(pw, 1, sizeof pw);
        memset(salt, 2, sizeof salt);
        memset(sec, 3, sizeof sec);
        memset(ad, 4, sizeof ad);
        int r = cfs_seal_argon2id_ex(pw, sizeof pw, salt, sizeof salt,
                                     sec, sizeof sec, ad, sizeof ad,
                                     &p, out, sizeof out);
        CHK(r == 0 && hexeq(out, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65e"
                                  "b52520e96b01e659", 32), "Argon2id RFC 9106 test vector");
    }
    /* RFC 8439 §2.4.2 first 16 bytes */
    {
        uint8_t key[32], nonce[12] = {0,0,0,0,0,0,0,0x4a,0,0,0,0};
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
        const char *pt = "Ladies and Gentlemen of the class of '99: If I coul";
        uint8_t ct[16];
        CHK(cfs_seal_chacha20(key, nonce, 1, pt, ct, 16) == 0 &&
            hexeq(ct, "6e2e359a2568f98041ba0728dd0d6981", 16),
            "ChaCha20 RFC 8439 keystream");
    }
    /* RFC 4231 test case 1 */
    {
        uint8_t key[20], mac[32];
        memset(key, 0x0b, sizeof key);
        CHK(cfs_seal_hmac_sha256(key, sizeof key, "Hi There", 8, mac) == 0 &&
            hexeq(mac, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                  32), "HMAC-SHA256 RFC 4231 case 1");
    }
    /* Plan §4 subkeys: one derivation each, all different, ring index mixed in */
    {
        uint8_t dek[32], salt[32], k[4][32], r1[32], mac[32], id[8];
        cfs_seal_random(dek, sizeof dek);
        cfs_seal_random(salt, sizeof salt);
        int ok = cfs_seal_subkey(dek, salt, 32, CFS_SEAL_SUB_KEK,   0, k[0]) == 0 &&
                 cfs_seal_subkey(dek, salt, 32, CFS_SEAL_SUB_AUDIT, 0, k[1]) == 0 &&
                 cfs_seal_subkey(dek, salt, 32, CFS_SEAL_SUB_DECOY, 0, k[2]) == 0 &&
                 cfs_seal_subkey(dek, salt, 32, CFS_SEAL_SUB_RING,  0, k[3]) == 0 &&
                 cfs_seal_subkey(dek, salt, 32, CFS_SEAL_SUB_RING,  1, r1) == 0;
        int distinct = 1;
        for (int i = 0; i < 4; i++)
            for (int j = i + 1; j < 4; j++)
                if (memcmp(k[i], k[j], 32) == 0) distinct = 0;
        CHK(ok && distinct, "kek/audit/decoy/ring subkeys are independent");
        CHK(memcmp(k[3], r1, 32) != 0, "ring subkey depends on the ring index");
        CHK(cfs_seal_identity(dek, id) == 0 &&
            cfs_seal_hmac_sha256(dek, 32, "cfs9:id", 7, mac) == 0 &&
            memcmp(id, mac, 8) == 0, "identity tag is HMAC(DEK,\"cfs9:id\")[0..8]");
    }
    /* getrandom: two draws differ and are not zero */
    {
        uint8_t a[32], b[32], z[32] = {0};
        CHK(cfs_seal_random(a, sizeof a) == 0 && cfs_seal_random(b, sizeof b) == 0 &&
            memcmp(a, b, 32) != 0 && memcmp(a, z, 32) != 0,
            "getrandom returns fresh bytes");
    }
}

/* ─── S0: certificate wrap ─────────────────────────────────────────────── */
static int write_ec_keypair(const char *priv_path, const char *pub_path,
                            const char *group) {
    EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "EC", group);
    if (!k) return -1;
    FILE *f = fopen(priv_path, "w");
    if (!f || !PEM_write_PrivateKey(f, k, NULL, NULL, 0, NULL, NULL)) {
        if (f) fclose(f);
        EVP_PKEY_free(k);
        return -1;
    }
    fclose(f);
    f = fopen(pub_path, "w");
    if (!f || !PEM_write_PUBKEY(f, k)) {
        if (f) fclose(f);
        EVP_PKEY_free(k);
        return -1;
    }
    fclose(f);
    EVP_PKEY_free(k);
    return 0;
}

static void test_cert(void) {
    fprintf(stderr, "=== S0 certificate wrap ===\n");
    const char *rsa_p = "/tmp/cfs_seal_rsa.pem", *rsa_u = "/tmp/cfs_seal_rsa.pub";
    const char *ec_p  = "/tmp/cfs_seal_ec.pem",  *ec_u  = "/tmp/cfs_seal_ec.pub";
    const char *bad_p = "/tmp/cfs_seal_bad.pem", *bad_u = "/tmp/cfs_seal_bad.pub";
    (void)rsa_p; (void)rsa_u;   /* RSA gets its own test below */

    CHK(write_ec_keypair(ec_p, ec_u, "P-256") == 0, "generated P-256 keypair");
    CHK(write_ec_keypair(bad_p, bad_u, "P-256") == 0, "generated a second P-256 keypair");

    uint8_t sk[32], blob[CFS_SEAL_MAX_CERT_BLOB], back[32];
    size_t blen = 0, blen2 = 0;

    CHK(cfs_seal_random(sk, sizeof sk) == 0, "random start key");

    blen = 0;
    int r = cfs_seal_cert_wrap(ec_u, sk, sizeof sk, blob, &blen);
    blen2 = sizeof back;
    CHK(r == 0 && blen > 0 && blen < CFS_SEAL_MAX_CERT_BLOB, "ECDH-ES wrap produced a blob");
    CHK(cfs_seal_cert_unwrap(ec_p, blob, blen, back, &blen2) == 0 &&
        blen2 == 32 && memcmp(back, sk, 32) == 0, "ECDH-ES unwrap round-trips");
    blen2 = sizeof back;
    CHK(cfs_seal_cert_unwrap(bad_p, blob, blen, back, &blen2) != 0,
        "ECDH-ES unwrap with the wrong private key fails");
    blob[blen / 2] ^= 0x40;
    blen2 = sizeof back;
    CHK(cfs_seal_cert_unwrap(ec_p, blob, blen, back, &blen2) != 0,
        "ECDH-ES unwrap with a corrupted blob fails");
}

/* RSA gets its own test so the bits argument is real. */
static void test_cert_rsa(void) {
    const char *priv = "/tmp/cfs_seal_rsa.pem", *pub = "/tmp/cfs_seal_rsa.pub";
    uint8_t sk[32], blob[CFS_SEAL_MAX_CERT_BLOB], back[32];
    size_t blen = 0, blen2 = 0;

    EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    CHK(k != NULL, "generated RSA-2048 key");
    if (!k) return;
    FILE *f = fopen(priv, "w");
    int ok = f && PEM_write_PrivateKey(f, k, NULL, NULL, 0, NULL, NULL);
    if (f) fclose(f);
    f = fopen(pub, "w");
    ok = ok && f && PEM_write_PUBKEY(f, k);
    if (f) fclose(f);
    EVP_PKEY_free(k);
    CHK(ok, "wrote RSA keypair as PEM");

    CHK(cfs_seal_random(sk, sizeof sk) == 0, "random start key");
    CHK(cfs_seal_cert_wrap(pub, sk, sizeof sk, blob, &blen) == 0 && blen == 4 + 256,
        "RSA-OAEP-256 wrap produced a 260-byte blob");
    blen2 = sizeof back;
    CHK(cfs_seal_cert_unwrap(priv, blob, blen, back, &blen2) == 0 &&
        blen2 == 32 && memcmp(back, sk, 32) == 0, "RSA-OAEP-256 unwrap round-trips");
}

/* ─── S1: helpers ──────────────────────────────────────────────────────── */
static CfsSealKdfParams fast_params(void) {
    CfsSealKdfParams p = { 1024, 1, 1 };   /* 1 MiB, one pass: test speed */
    return p;
}

static void free_set(CfsSealSet *s) { cfs_seal_free(s); }

/* A copy of the shard set with one byte changed at `off` of shard `idx`. */
static CfsSealSet mutate(const CfsSealSet *src, uint32_t idx, size_t off, uint8_t x) {
    CfsSealSet m;
    memset(&m, 0, sizeof m);
    m.nshards = src->nshards;
    m.shards = calloc(m.nshards, sizeof *m.shards);
    for (uint32_t i = 0; i < m.nshards; i++) {
        m.shards[i].len = src->shards[i].len;
        m.shards[i].data = malloc(src->shards[i].len);
        memcpy(m.shards[i].data, src->shards[i].data, src->shards[i].len);
    }
    m.shards[idx].data[off] ^= x;
    return m;
}

/* ─── S1: round trip ───────────────────────────────────────────────────── */
static void test_roundtrip(void) {
    fprintf(stderr, "=== S1 round trip ===\n");
    const size_t len = 300000;                 /* ~4.6 blocks */
    uint8_t *plain = malloc(len);
    fill_pattern(plain, len);
    memcpy(plain + 1000, "PLAINTEXT-MARKER-0123456789ABCDEF", 32);

    CfsSealKdfParams kdf = fast_params();
    CfsSealCreateOpts o;
    memset(&o, 0, sizeof o);
    o.nshards = 4;
    o.kdf = kdf;
    o.password = "correct horse battery staple";
    o.password_len = 28;

    RleCtx ec = {0}, dc = {0};
    CfsSealSet set;
    int r = cfs_seal_create(&o, plain, len, &set);
    CHK(r == CFS_SEAL_OK, "create 4 shards, no codec");

    /* geometry: fixed 4 KiB headers, uniform block counts */
    uint32_t nb = (uint32_t)((set.shards[0].len - CFS_SEAL_HDR_SIZE) / CFS_SEAL_BLOCK_SIZE);
    int uniform = 1;
    for (uint32_t i = 1; i < set.nshards; i++)
        if (set.shards[i].len != set.shards[0].len) uniform = 0;
    CHK(uniform && set.shards[0].len == CFS_SEAL_HDR_SIZE + (size_t)nb * CFS_SEAL_BLOCK_SIZE,
        "shards are 4 KiB header + whole 64 KiB blocks");
    CHK(nb * 4 * CFS_SEAL_BLOCK_DATA >= len, "padded capacity covers the plaintext");

    CfsSealOpenResult res;
    r = cfs_seal_open(&set, NULL, o.password, o.password_len, NULL, NULL, &res);
    CHK(r == 0 && res.status == CFS_SEAL_OK, "open with the right password");
    CHK(res.plain_len == len, "plaintext length recovered exactly");
    CHK(res.len == 4u * nb * CFS_SEAL_BLOCK_DATA, "output is the padded size");
    CHK(memcmp(res.plain, plain, len) == 0, "plaintext round-trips");

    /* no cleartext anywhere in the shards */
    int leaked = 0;
    for (uint32_t i = 0; i < set.nshards; i++)
        if (contains(set.shards[i].data, set.shards[i].len,
                     "PLAINTEXT-MARKER-0123456789ABCDEF", 32)) leaked = 1;
    CHK(!leaked, "shard bytes contain no plaintext marker");

    size_t good_len = res.len;
    cfs_seal_open_free(&res);
    free_set(&set);

    /* ── with the codec ── */
    o.codec = rle_compress;
    o.codec_ctx = &ec;
    r = cfs_seal_create(&o, plain, len, &set);
    CHK(r == CFS_SEAL_OK, "create 4 shards, RLE codec");
    CHK(ec.encode > 0 && ec.shrunk > 0, "codec compressed at least one block");

    r = cfs_seal_open(&set, NULL, o.password, o.password_len,
                      rle_decompress, &dc, &res);
    CHK(r == 0 && res.status == CFS_SEAL_OK, "open with the right codec");
    CHK(res.plain_len == len && memcmp(res.plain, plain, len) == 0,
        "compressed round-trip is byte-identical");
    CHK(dc.decode > 0, "decompression path ran");
    cfs_seal_open_free(&res);

    r = cfs_seal_open(&set, NULL, o.password, o.password_len, NULL, NULL, &res);
    CHK(r == 0 && res.status == CFS_SEAL_EAUTH && res.plain_len == 0,
        "compressed container without a codec yields no plaintext");
    cfs_seal_open_free(&res);

    /* ── argument validation ── */
    CfsSealCreateOpts bad = o;
    bad.nshards = 0;
    CfsSealSet dummy;
    CHK(cfs_seal_create(&bad, plain, len, &dummy) == CFS_SEAL_EARG,
        "create rejects zero shards");
    bad = o;
    bad.password = NULL;
    CHK(cfs_seal_create(&bad, plain, len, &dummy) == CFS_SEAL_EARG,
        "create rejects a missing key");
    free_set(&set);
    CHK(good_len > 0, "output length observed");
    free(plain);
}

/* ─── S1: wrong key and decoy ──────────────────────────────────────────── */
static void test_wrong_key(void) {
    fprintf(stderr, "=== S1 wrong key / decoy ===\n");
    const size_t len = 200000;
    uint8_t *plain = malloc(len);
    fill_pattern(plain, len);
    memcpy(plain + 777, "PLAINTEXT-MARKER-0123456789ABCDEF", 32);

    CfsSealKdfParams kdf = fast_params();
    CfsSealCreateOpts o;
    memset(&o, 0, sizeof o);
    o.nshards = 4;
    o.kdf = kdf;
    o.password = "right";
    o.password_len = 5;

    CfsSealSet set;
    CHK(cfs_seal_create(&o, plain, len, &set) == CFS_SEAL_OK, "create");

    CfsSealOpenResult good, bad1, bad2;
    CHK(cfs_seal_open(&set, NULL, "right", 5, NULL, NULL, &good) == 0 &&
        good.status == CFS_SEAL_OK, "open with the right key");
    CHK(cfs_seal_open(&set, NULL, "wrong", 5, NULL, NULL, &bad1) == 0 &&
        bad1.status == CFS_SEAL_EAUTH, "open with a wrong key returns a decoy");
    CHK(cfs_seal_open(&set, NULL, "wrong", 5, NULL, NULL, &bad2) == 0 &&
        bad2.status == CFS_SEAL_EAUTH, "re-run with the same wrong key");

    CHK(bad1.len == good.len, "decoy has the same length as a successful read");
    CHK(bad1.plain_len == 0, "decoy reports no plaintext length");
    CHK(memcmp(bad1.plain, bad2.plain, bad1.len) == 0, "decoy is reproducible");
    CHK(memcmp(bad1.plain, good.plain, bad1.len) != 0, "decoy differs from plaintext");
    CHK(!contains(bad1.plain, bad1.len, "PLAINTEXT-MARKER-0123456789ABCDEF", 32),
        "decoy contains no plaintext");
    CHK(!contains(bad1.plain, bad1.len, plain + 30000, 64),
        "decoy shares no 64-byte run with the plaintext");

    /* A password that differs in one bit must not decrypt either. */
    CfsSealOpenResult bad3;
    CHK(cfs_seal_open(&set, NULL, "righu", 5, NULL, NULL, &bad3) == 0 &&
        bad3.status == CFS_SEAL_EAUTH && memcmp(bad3.plain, bad1.plain, bad3.len) != 0,
        "a different wrong key gives a different decoy");
    cfs_seal_open_free(&bad3);

    cfs_seal_open_free(&good);
    cfs_seal_open_free(&bad1);
    cfs_seal_open_free(&bad2);
    free_set(&set);
    free(plain);
}

/* ─── S1: missing shard ────────────────────────────────────────────────── */
static void test_missing_shard(void) {
    fprintf(stderr, "=== S1 missing shard ===\n");
    const size_t len = 150000;
    uint8_t *plain = malloc(len);
    fill_pattern(plain, len);

    CfsSealKdfParams kdf = fast_params();
    CfsSealCreateOpts o;
    memset(&o, 0, sizeof o);
    o.nshards = 4;
    o.kdf = kdf;
    o.password = "pw";
    o.password_len = 2;

    CfsSealSet full;
    CHK(cfs_seal_create(&o, plain, len, &full) == CFS_SEAL_OK, "create 4 shards");

    for (uint32_t drop = 0; drop < 4; drop++) {
        CfsSealSet part;
        memset(&part, 0, sizeof part);
        part.nshards = 3;
        part.shards = calloc(3, sizeof *part.shards);
        uint32_t k = 0;
        for (uint32_t i = 0; i < 4; i++) {
            if (i == drop) continue;
            part.shards[k].data = full.shards[i].data;
            part.shards[k].len = full.shards[i].len;
            k++;
        }
        CfsSealOpenResult res;
        int r = cfs_seal_open(&part, NULL, "pw", 2, NULL, NULL, &res);
        char msg[96];
        snprintf(msg, sizeof msg, "dropping shard %u yields no plaintext", drop);
        CHK(r == 0 && res.status == CFS_SEAL_EAUTH && res.plain_len == 0, msg);
        CHK(!contains(res.plain, res.len, plain + 100, 64),
            "  and no plaintext run appears in the decoy");
        cfs_seal_open_free(&res);
        free(part.shards);   /* shard buffers belong to `full` */
    }
    free_set(&full);
    free(plain);
}

/* ─── S1: tamper ───────────────────────────────────────────────────────── */
/* Corrupt one field in every shard (a container-wide forgery attempt). */
static CfsSealSet mutate_all(const CfsSealSet *src, size_t off, uint8_t x) {
    CfsSealSet m;
    memset(&m, 0, sizeof m);
    m.nshards = src->nshards;
    m.shards = calloc(m.nshards, sizeof *m.shards);
    for (uint32_t i = 0; i < m.nshards; i++) {
        m.shards[i].len = src->shards[i].len;
        m.shards[i].data = malloc(src->shards[i].len);
        memcpy(m.shards[i].data, src->shards[i].data, src->shards[i].len);
        m.shards[i].data[off] ^= x;
    }
    return m;
}

static void test_tamper(void) {
    fprintf(stderr, "=== S1 tamper detection ===\n");
    const size_t len = 140000;
    uint8_t *plain = malloc(len);
    fill_pattern(plain, len);

    CfsSealKdfParams kdf = fast_params();
    CfsSealCreateOpts o;
    memset(&o, 0, sizeof o);
    o.nshards = 4;
    o.kdf = kdf;
    o.password = "pw";
    o.password_len = 2;

    CfsSealSet set;
    CHK(cfs_seal_create(&o, plain, len, &set) == CFS_SEAL_OK, "create");

    /* Fields replicated in every shard (plan §3.1) are tolerant of one
     * damaged copy — any key holder can start from any shard — but a
     * container-wide forgery must fail.  Fields unique to a shard fail as
     * soon as the offending shard is read. */
    struct {
        const char *what;
        size_t off;
        int replicated;   /* one bad copy still opens */
        int all_fails;    /* corrupting every copy must kill it */
    } cases[] = {
        { "salt (one shard)",           12, 0, 1 },
        { "wrapped_start (one shard)",  60, 1, 1 },
        { "keyed_check (one shard)",   124, 1, 1 },
        { "nonce_prefix (one shard)",  228, 1, 1 },
        { "ring_link (one shard)",     132, 0, 1 },
        { "shard_uuid (one shard)",     44, 0, 1 },
        /* Not authenticated by design: cert_wrap is only consulted in
         * certificate mode, and the padding carries nothing. */
        { "cert_wrap (one shard)",     240, 1, 0 },
        { "padding (one shard)",       300, 1, 0 },
    };

    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        char msg[160], msg2[160];
        CfsSealOpenResult res;

        CfsSealSet one = mutate(&set, 1, cases[i].off, 0x20);
        int r = cfs_seal_open(&one, NULL, "pw", 2, NULL, NULL, &res);
        if (cases[i].replicated) {
            snprintf(msg, sizeof msg, "%s -> container still opens", cases[i].what);
            CHK(r == 0 && res.status == CFS_SEAL_OK && res.plain_len == len &&
                memcmp(res.plain, plain, len) == 0, msg);
        } else {
            snprintf(msg, sizeof msg, "%s -> no plaintext", cases[i].what);
            CHK(r == 0 && res.status == CFS_SEAL_EAUTH && res.plain_len == 0, msg);
        }
        cfs_seal_open_free(&res);
        free_set(&one);

        if (cases[i].all_fails) {
            CfsSealSet all = mutate_all(&set, cases[i].off, 0x20);
            r = cfs_seal_open(&all, NULL, "pw", 2, NULL, NULL, &res);
            snprintf(msg2, sizeof msg2, "%s in every shard -> no plaintext",
                     cases[i].what);
            CHK(r == 0 && res.status == CFS_SEAL_EAUTH && res.plain_len == 0, msg2);
            cfs_seal_open_free(&res);
            free_set(&all);
        }
    }

    /* a data block */
    {
        CfsSealSet m = mutate(&set, 2, CFS_SEAL_HDR_SIZE + 100, 0x80);
        CfsSealOpenResult res;
        CHK(cfs_seal_open(&m, NULL, "pw", 2, NULL, NULL, &res) == 0 &&
            res.status == CFS_SEAL_EAUTH && res.plain_len == 0,
            "flip a byte in a data block -> no plaintext");
        cfs_seal_open_free(&res);
        free_set(&m);
    }

    /* swap the shard UUIDs of two shards (identity confusion) */
    {
        CfsSealSet m;
        memset(&m, 0, sizeof m);
        m.nshards = set.nshards;
        m.shards = calloc(m.nshards, sizeof *m.shards);
        for (uint32_t i = 0; i < m.nshards; i++) {
            m.shards[i].len = set.shards[i].len;
            m.shards[i].data = malloc(set.shards[i].len);
            memcpy(m.shards[i].data, set.shards[i].data, set.shards[i].len);
        }
        uint8_t tmp[16];
        memcpy(tmp, m.shards[0].data + 44, 16);
        memcpy(m.shards[0].data + 44, m.shards[2].data + 44, 16);
        memcpy(m.shards[2].data + 44, tmp, 16);
        CfsSealOpenResult res;
        CHK(cfs_seal_open(&m, NULL, "pw", 2, NULL, NULL, &res) == 0 &&
            res.status == CFS_SEAL_EAUTH && res.plain_len == 0,
            "swapped shard UUIDs -> no plaintext");
        cfs_seal_open_free(&res);
        free_set(&m);
    }

    /* duplicate one shard in place of another (ring must not close) */
    {
        CfsSealSet m;
        memset(&m, 0, sizeof m);
        m.nshards = set.nshards;
        m.shards = calloc(m.nshards, sizeof *m.shards);
        for (uint32_t i = 0; i < m.nshards; i++) {
            m.shards[i].len = set.shards[0].len;
            m.shards[i].data = malloc(m.shards[i].len);
            memcpy(m.shards[i].data, set.shards[i].data, m.shards[i].len);
        }
        memcpy(m.shards[1].data, set.shards[0].data, m.shards[1].len);
        CfsSealOpenResult res;
        CHK(cfs_seal_open(&m, NULL, "pw", 2, NULL, NULL, &res) == 0 &&
            res.status == CFS_SEAL_EAUTH && res.plain_len == 0,
            "duplicated shard -> no plaintext");
        cfs_seal_open_free(&res);
        free_set(&m);
    }

    free_set(&set);
    free(plain);
}

/* ─── S1: header indistinguishability ──────────────────────────────────── */
static void test_header(void) {
    fprintf(stderr, "=== S1 header opacity ===\n");
    const size_t len = 90000;
    uint8_t *plain = malloc(len);
    fill_pattern(plain, len);

    CfsSealKdfParams kdf = fast_params();
    CfsSealCreateOpts o;
    memset(&o, 0, sizeof o);
    o.nshards = 3;
    o.kdf = kdf;
    o.password = "same password";
    o.password_len = 13;

    CfsSealSet a, b;
    CHK(cfs_seal_create(&o, plain, len, &a) == CFS_SEAL_OK, "container A");
    CHK(cfs_seal_create(&o, plain, len, &b) == CFS_SEAL_OK, "container B (same key, same data)");

    CHK(a.shards[0].len - CFS_SEAL_HDR_SIZE > 0 &&
        (a.shards[0].len - CFS_SEAL_HDR_SIZE) % CFS_SEAL_BLOCK_SIZE == 0,
        "header size is the fixed 4 KiB prefix");

    /* no magic of any spelling */
    const char *needles[] = { "CFS", "cfs9", "LIBCFS", "SEAL", "argon" };
    int magic = 0;
    for (int i = 0; i < 5; i++)
        for (uint32_t s = 0; s < a.nshards; s++)
            if (contains(a.shards[s].data, CFS_SEAL_HDR_SIZE, needles[i],
                         strlen(needles[i]))) magic = 1;
    CHK(!magic, "no cleartext magic in any header");

    /* byte histogram of a header is flat, not mostly zeros or 0xff */
    {
        unsigned hist[256] = {0};
        for (size_t i = 0; i < CFS_SEAL_HDR_SIZE; i++)
            hist[a.shards[0].data[i]]++;
        unsigned max = 0;
        for (int i = 0; i < 256; i++) if (hist[i] > max) max = hist[i];
        /* 4096 bytes over 256 values is ~16 each; allow generous slack. */
        CHK(max < CFS_SEAL_HDR_SIZE / 8, "header bytes are uniformly distributed");
    }

    /* Same key, same plaintext, different container: no field survives. */
    {
        uint8_t *h1 = a.shards[0].data, *h2 = b.shards[0].data;
        size_t same = 0;
        for (size_t i = 0; i < CFS_SEAL_HDR_SIZE; i++) if (h1[i] == h2[i]) same++;
        CHK(same < CFS_SEAL_HDR_SIZE / 4, "two containers share almost no header bytes");

        int shared8 = 0;
        for (size_t i = 0; i + 8 <= CFS_SEAL_HDR_SIZE && !shared8; i += 8)
            if (contains(h2, CFS_SEAL_HDR_SIZE, h1 + i, 8)) shared8 = 1;
        CHK(!shared8, "no 8-byte header field repeats across containers");
    }

    /* Different shards of one container do not share header bytes either:
     * every per-shard field is independently keyed. */
    {
        int same_field = 0;
        for (uint32_t s = 1; s < a.nshards; s++)
            if (memcmp(a.shards[0].data + 60, a.shards[s].data + 60, 64) == 0 ||
                memcmp(a.shards[0].data + 132, a.shards[s].data + 132, 96) == 0)
                same_field = 1;
        CHK(!same_field, "wrapped_start and ring links differ per shard");
    }

    free_set(&a);
    free_set(&b);
    free(plain);
}

/* ─── S1: certificate mode end to end ──────────────────────────────────── */
static void test_cert_mode(void) {
    fprintf(stderr, "=== S1 certificate mode ===\n");
    const size_t len = 100000;
    uint8_t *plain = malloc(len);
    fill_pattern(plain, len);

    const char *priv = "/tmp/cfs_seal_ec.pem", *pub = "/tmp/cfs_seal_ec.pub";
    const char *other = "/tmp/cfs_seal_bad.pem";

    CfsSealKdfParams kdf = fast_params();
    CfsSealCreateOpts o;
    memset(&o, 0, sizeof o);
    o.nshards = 3;
    o.kdf = kdf;
    o.cert_pub_pem = pub;
    o.password = NULL;

    CfsSealSet set;
    CHK(cfs_seal_create(&o, plain, len, &set) == CFS_SEAL_OK, "seal to a P-256 certificate");

    CfsSealOpenResult res;
    CHK(cfs_seal_open(&set, priv, NULL, 0, NULL, NULL, &res) == 0 &&
        res.status == CFS_SEAL_OK && res.plain_len == len &&
        memcmp(res.plain, plain, len) == 0, "open with the certificate's private key");
    cfs_seal_open_free(&res);

    CHK(cfs_seal_open(&set, other, NULL, 0, NULL, NULL, &res) == 0 &&
        res.status == CFS_SEAL_EAUTH && res.plain_len == 0,
        "wrong certificate private key yields a decoy");
    cfs_seal_open_free(&res);

    CHK(cfs_seal_open(&set, NULL, "any password", 12, NULL, NULL, &res) == 0 &&
        res.status == CFS_SEAL_EAUTH && res.plain_len == 0,
        "password against a certificate container yields a decoy");
    cfs_seal_open_free(&res);

    free_set(&set);
    free(plain);
}

/* ─── default parameters, once ─────────────────────────────────────────── */
static void test_default_params(void) {
    fprintf(stderr, "=== S1 default Argon2id parameters (256 MiB, t=3, p=4) ===\n");
    const size_t len = 20000;
    uint8_t *plain = malloc(len);
    fill_pattern(plain, len);

    CfsSealKdfParams kdf;
    cfs_seal_kdf_defaults(&kdf);
    CHK(kdf.m_cost == 262144 && kdf.t_cost == 3 && kdf.lanes == 4,
        "defaults are the plan's m=256MiB t=3 p=4");

    CfsSealCreateOpts o;
    memset(&o, 0, sizeof o);
    o.nshards = 2;
    o.kdf = kdf;
    o.password = "pw";
    o.password_len = 2;

    CfsSealSet set;
    double t0 = now_s();
    int r = cfs_seal_create(&o, plain, len, &set);
    double t1 = now_s();
    CHK(r == CFS_SEAL_OK, "create with default parameters");

    CfsSealOpenResult res;
    double t2 = now_s();
    r = cfs_seal_open(&set, NULL, "pw", 2, NULL, NULL, &res);
    double t3 = now_s();
    CHK(r == 0 && res.status == CFS_SEAL_OK && res.plain_len == len &&
        memcmp(res.plain, plain, len) == 0, "open with default parameters");
    fprintf(stderr, "  argon2id 256MiB/t3/p4: seal %.2fs, open %.2fs\n",
            t1 - t0, t3 - t2);
    cfs_seal_open_free(&res);
    free_set(&set);
    free(plain);
}

/* ─── coarse timing: wrong key vs right key ────────────────────────────── */
/* Alternate the two keys so a background load spike hits both equally;
 * minimum over the pairs is the least-noisy estimator available here. */
static void time_pair(const CfsSealSet *set, const char *good, size_t goodlen,
                      const char *bad, size_t badlen,
                      double *t_right, double *t_wrong) {
    double best_r = 1e9, best_w = 1e9;
    CfsSealOpenResult res;
    for (int i = 0; i < 7; i++) {
        double t0 = now_s();
        cfs_seal_open(set, NULL, good, goodlen, NULL, NULL, &res);
        double t1 = now_s();
        if (t1 - t0 < best_r) best_r = t1 - t0;
        cfs_seal_open_free(&res);

        t0 = now_s();
        cfs_seal_open(set, NULL, bad, badlen, NULL, NULL, &res);
        t1 = now_s();
        if (t1 - t0 < best_w) best_w = t1 - t0;
        cfs_seal_open_free(&res);
    }
    *t_right = best_r;
    *t_wrong = best_w;
}

static void test_timing(void) {
    fprintf(stderr, "=== S1 timing: wrong key vs right key ===\n");
    const size_t len = 2 * 1024 * 1024;
    uint8_t *plain = malloc(len);
    fill_pattern(plain, len);

    CfsSealKdfParams kdf = fast_params();
    CfsSealCreateOpts o;
    memset(&o, 0, sizeof o);
    o.nshards = 4;
    o.kdf = kdf;
    o.password = "right";
    o.password_len = 5;

    CfsSealSet set;
    if (cfs_seal_create(&o, plain, len, &set) != CFS_SEAL_OK) {
        CHK(0, "create for the timing test");
        free(plain);
        return;
    }

    double tr = 0, tw = 0;
    time_pair(&set, "right", 5, "wrong", 5, &tr, &tw);

    double ratio = (tr > 0) ? tw / tr : 0.0;
    fprintf(stderr, "  right key: %.3f ms   wrong key: %.3f ms   ratio %.3f\n",
            tr * 1e3, tw * 1e3, ratio);
    /* Report, do not gate. */
    CHK(ratio > 0.0, "timing measured");
    if (ratio > 1.05 || ratio < 0.95)
        fprintf(stderr, "  note: ratio outside 5%% — see above for the numbers\n");

    free_set(&set);
    free(plain);
}


/* ─── corrupted-header smoke ───────────────────────────────────────────── */
/* Not a substitute for the S5 fuzzer; a cheap check that random corruption
 * never crashes the reader and never reports success over a container it
 * could not authenticate.  Padding bytes are excluded from the promise:
 * they are not authenticated and a flip there must be a no-op. */
static void test_corrupt_smoke(void) {
    fprintf(stderr, "=== S1 corrupted-header smoke ===\n");
    const size_t len = 120000;
    uint8_t *plain = malloc(len);
    fill_pattern(plain, len);

    CfsSealKdfParams kdf = fast_params();
    CfsSealCreateOpts o;
    memset(&o, 0, sizeof o);
    o.nshards = 3;
    o.kdf = kdf;
    o.password = "pw";
    o.password_len = 2;

    CfsSealSet set;
    if (cfs_seal_create(&o, plain, len, &set) != CFS_SEAL_OK) {
        CHK(0, "create for the smoke test");
        free(plain);
        return;
    }

    int bad_success = 0, crashes_avoided = 0;
    for (int round = 0; round < 120; round++) {
        CfsSealSet m;
        memset(&m, 0, sizeof m);
        m.nshards = set.nshards;
        m.shards = calloc(m.nshards, sizeof *m.shards);
        for (uint32_t i = 0; i < m.nshards; i++) {
            m.shards[i].len = set.shards[i].len;
            m.shards[i].data = malloc(m.shards[i].len);
            memcpy(m.shards[i].data, set.shards[i].data, m.shards[i].len);
        }
        uint32_t j = rnd() % m.nshards;
        int flips = 1 + (int)(rnd() % 3);
        for (int k = 0; k < flips; k++) {
            size_t off = rnd() % CFS_SEAL_HDR_SIZE;
            m.shards[j].data[off] ^= (uint8_t)(1u << (rnd() % 8));
        }
        CfsSealOpenResult res;
        if (cfs_seal_open(&m, NULL, "pw", 2, NULL, NULL, &res) != 0) {
            /* only ENOMEM could land here, and it is not corruption-driven */
            crashes_avoided++;
        } else {
            if (res.status == CFS_SEAL_OK &&
                (res.plain_len != len || memcmp(res.plain, plain, len) != 0))
                bad_success++;
            cfs_seal_open_free(&res);
        }
        free_set(&m);
    }
    CHK(bad_success == 0, "corruption never yields success with wrong plaintext");
    free_set(&set);
    free(plain);
}

int main(void) {
    setvbuf(stderr, NULL, _IONBF, 0);
    fprintf(stderr, "=== cfs_seal ===\n");

    test_vectors();
    test_cert();
    test_cert_rsa();
    test_roundtrip();
    test_wrong_key();
    test_missing_shard();
    test_tamper();
    test_header();
    test_cert_mode();
    test_corrupt_smoke();
    test_default_params();
    test_timing();

    unlink("/tmp/cfs_seal_rsa.pem");
    unlink("/tmp/cfs_seal_rsa.pub");
    unlink("/tmp/cfs_seal_ec.pem");
    unlink("/tmp/cfs_seal_ec.pub");
    unlink("/tmp/cfs_seal_bad.pem");
    unlink("/tmp/cfs_seal_bad.pub");

    fprintf(stderr, "\n=== %d failures ===\n", failed);
    (void)checks;
    return failed ? 1 : 0;
}
