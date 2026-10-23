/* cfs_seal.c — v9 sealed container, S0 (primitives) + S1 (format).
 *
 * See cfs_seal.h for the format, the key hierarchy and the reasoning behind
 * the choices.  Everything here is in-memory: cfs_seal_create() hands back
 * one buffer per shard, cfs_seal_open() takes them back.  A file backend is
 * S3's problem and does not change this layer.
 *
 * OpenSSL 3.5 supplies Argon2id, HKDF and the AEADs; the only thing that
 * needs care is that a failed ARGON2ID derive leaves the caller's output
 * buffer untouched (stale key), so every primitive here zeroes its output
 * on failure and checks EVP's return value.
 */

#define _GNU_SOURCE
#include "cfs_seal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/thread.h>
#include <openssl/x509.h>

/* ─── serialized header offsets (documented in cfs_seal.h) ─────────────── */
#define HO_VER        0u
#define HO_FLAGS      1u
#define HO_KDF        2u
#define HO_RSV        3u
#define HO_M          4u
#define HO_T          8u
#define HO_P         10u
#define HO_SALT      12u
#define HO_UUID      44u
#define HO_WRAPPED   60u
#define HO_CHECK    124u
#define HO_RING     132u
#define HO_NPREFIX  228u
#define HO_BSHIFT   236u
#define HO_RSV2     237u
#define HO_CERTWRAP 240u
#define HO_MASK_END 752u   /* [0,752) is masked; [752,4096) is random pad */

/* block frame */
#define BO_DATALEN    0u   /* u64 LE */
#define BO_STORED     8u   /* u32 LE */
#define BO_CODEC     12u
#define BO_RSV       13u

#define INFO_KEK       "cfs9:kek"
#define INFO_RING      "cfs9:ring"
#define INFO_DATA      "cfs9:data"
#define INFO_DECOY     "cfs9:decoy"
#define INFO_AUDIT     "cfs9:audit"
#define INFO_ID        "cfs9:id"
#define INFO_HDR       "cfs9:hdr"
#define INFO_HDR_MASK  "cfs9:hdr-mask"
#define INFO_NOKEY     "cfs9:nokey"
#define INFO_ECDH      "cfs9:ecdh-es+a256kw"

/* Sanity ceilings for parameters read out of an untrusted header.  A header
 * that asks for 2 TiB of Argon2 memory is a denial of service, not a key. */
#define KDF_M_MAX   (2u * 1024u * 1024u)   /* KiB = 2 GiB */
#define KDF_M_MIN   8u
#define KDF_T_MAX   16u
#define KDF_P_MAX   16u

/* ─── little helpers ───────────────────────────────────────────────────── */
static void put_u16le(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void put_u32le(uint8_t *p, uint32_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8);
                                                p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); }
static void put_u64le(uint8_t *p, uint64_t v) { for (int i=0;i<8;i++) p[i]=(uint8_t)(v>>(8*i)); }
static uint16_t get_u16le(const uint8_t *p) { return (uint16_t)(p[0] | (p[1]<<8)); }
static uint32_t get_u32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static uint64_t get_u64le(const uint8_t *p) {
    uint64_t v = 0; for (int i=7;i>=0;i--) v = (v<<8) | p[i]; return v;
}
static void put_u32be(uint8_t *p, uint32_t v) {
    p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v;
}
static void put_u64be(uint8_t *p, uint64_t v) { for (int i=0;i<8;i++) p[i]=(uint8_t)(v>>(56-8*i)); }

static int ct_eq(const void *a, const void *b, size_t n) { return CRYPTO_memcmp(a,b,n) == 0; }
static void cleanse(void *p, size_t n) { if (p && n) OPENSSL_cleanse(p, n); }

/* ─── S0: randomness ───────────────────────────────────────────────────── */
int cfs_seal_random(void *buf, size_t len) {
    uint8_t *p = buf;
    while (len) {
        ssize_t n = getrandom(p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;          /* cannot happen without a signal */
        p += (size_t)n; len -= (size_t)n;
    }
    return 0;
}

/* ─── S0: Argon2id ─────────────────────────────────────────────────────── */
void cfs_seal_kdf_defaults(CfsSealKdfParams *p) {
    if (!p) return;
    p->m_cost = 262144;   /* 256 MiB */
    p->t_cost = 3;
    p->lanes  = 4;
}

/* OpenSSL's Argon2 runs on a shared thread pool whose size defaults to 0,
 * which makes any `threads` > 1 fail outright ("invalid thread pool
 * size").  threads does not affect the derived key — only lanes does — so
 * ask for a pool once and fall back to a single thread if the process
 * refuses, exactly as the RFC's parallelism/lane split allows. */
static void seal_pool_init(void) {
    static int done;
    if (done) return;
    uint64_t want = 8;
    if (OSSL_get_max_threads(NULL) < want)
        (void)OSSL_set_max_threads(NULL, want);
    done = 1;
}

int cfs_seal_argon2id_ex(const void *password, size_t pwlen,
                         const void *salt, size_t saltlen,
                         const void *secret, size_t secretlen,
                         const void *ad, size_t adlen,
                         const CfsSealKdfParams *params,
                         uint8_t *out, size_t outlen) {
    if (!out || !outlen || !params || !password || !salt) return -1;
    if (params->lanes < 1 || params->lanes > KDF_P_MAX) return -1;
    if (params->t_cost < 1 || params->t_cost > KDF_T_MAX) return -1;
    if (params->m_cost < KDF_M_MIN || params->m_cost > KDF_M_MAX) return -1;
    if (params->m_cost < 8u * params->lanes) return -1;   /* Argon2 minimum */

    seal_pool_init();

    int rc = -1;
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
    EVP_KDF_CTX *ctx = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
    if (!ctx) goto done;

    uint32_t m = params->m_cost, t = params->t_cost, lanes = params->lanes;
    uint32_t threads = lanes;
    if (OSSL_get_max_threads(NULL) < threads) threads = 1;

    OSSL_PARAM p[10];
    int i = 0;
    p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                               (void *)password, pwlen);
    p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                               (void *)salt, saltlen);
    if (secret && secretlen)
        p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET,
                                                   (void *)secret, secretlen);
    if (ad && adlen)
        p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_ARGON2_AD,
                                                   (void *)ad, adlen);
    p[i++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &m);
    p[i++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &t);
    p[i++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads);
    p[i++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
    p[i++] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(ctx, out, outlen, p) == 1) rc = 0;

done:
    if (rc != 0) cleanse(out, outlen);   /* never leave a stale key behind */
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return rc;
}

int cfs_seal_argon2id(const void *password, size_t pwlen,
                      const uint8_t salt[CFS_SEAL_SALT_LEN],
                      const CfsSealKdfParams *params,
                      uint8_t out[CFS_SEAL_KEY_LEN]) {
    return cfs_seal_argon2id_ex(password, pwlen, salt, CFS_SEAL_SALT_LEN,
                                NULL, 0, NULL, 0, params, out, CFS_SEAL_KEY_LEN);
}

/* ─── S0: HKDF / SHA-256 / HMAC ────────────────────────────────────────── */
int cfs_seal_hkdf(const void *ikm, size_t ikmlen,
                  const void *salt, size_t saltlen,
                  const void *info, size_t infolen,
                  uint8_t *out, size_t outlen) {
    if (!ikm || !out || !outlen) return -1;
    if (outlen > 255u * 32u) return -1;

    int rc = -1;
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *ctx = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
    if (!ctx) goto done;

    OSSL_PARAM p[5];
    int i = 0;
    p[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                              (char *)"SHA256", 0);
    p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                               (void *)ikm, ikmlen);
    if (salt && saltlen)
        p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                   (void *)salt, saltlen);
    if (info && infolen)
        p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                   (void *)info, infolen);
    p[i++] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(ctx, out, outlen, p) == 1) rc = 0;

done:
    if (rc != 0) cleanse(out, outlen);
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return rc;
}

int cfs_seal_subkey(const uint8_t dek[CFS_SEAL_KEY_LEN],
                    const void *salt, size_t saltlen,
                    CfsSealSubkey which, uint32_t ring_index,
                    uint8_t out[CFS_SEAL_KEY_LEN]) {
    if (!dek || !out) return -1;
    if (which == CFS_SEAL_SUB_RING) {
        uint8_t info[sizeof INFO_RING - 1 + 4];
        memcpy(info, INFO_RING, sizeof INFO_RING - 1);
        put_u32le(info + sizeof INFO_RING - 1, ring_index);
        return cfs_seal_hkdf(dek, CFS_SEAL_KEY_LEN, salt, saltlen,
                             info, sizeof info, out, CFS_SEAL_KEY_LEN);
    }
    const char *info;
    size_t len;
    switch (which) {
    case CFS_SEAL_SUB_KEK:   info = INFO_KEK;   len = sizeof INFO_KEK - 1;   break;
    case CFS_SEAL_SUB_AUDIT: info = INFO_AUDIT; len = sizeof INFO_AUDIT - 1; break;
    case CFS_SEAL_SUB_DECOY: info = INFO_DECOY; len = sizeof INFO_DECOY - 1; break;
    default: return -1;
    }
    return cfs_seal_hkdf(dek, CFS_SEAL_KEY_LEN, salt, saltlen,
                         info, len, out, CFS_SEAL_KEY_LEN);
}

int cfs_seal_identity(const uint8_t dek[CFS_SEAL_KEY_LEN], uint8_t out[8]) {
    uint8_t mac[32];
    if (!dek || !out || cfs_seal_hmac_sha256(dek, CFS_SEAL_KEY_LEN,
                                             INFO_ID, sizeof INFO_ID - 1,
                                             mac) != 0)
        return -1;
    memcpy(out, mac, 8);
    cleanse(mac, sizeof mac);
    return 0;
}

int cfs_seal_sha256(const void *data, size_t len, uint8_t out[32]) {
    unsigned int outlen = 0;
    if (!out) return -1;
    if (!EVP_Digest(data, len, out, &outlen, EVP_sha256(), NULL)) return -1;
    return outlen == 32 ? 0 : -1;
}

int cfs_seal_hmac_sha256(const void *key, size_t keylen,
                         const void *data, size_t len, uint8_t out[32]) {
    int rc = -1;
    size_t outlen = 0;
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = mac ? EVP_MAC_CTX_new(mac) : NULL;
    if (!ctx || !key || !out) goto done;
    OSSL_PARAM p[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)"SHA256", 0),
        OSSL_PARAM_construct_end()
    };
    if (!EVP_MAC_init(ctx, key, keylen, p)) goto done;
    if (!EVP_MAC_update(ctx, data, len)) goto done;
    if (!EVP_MAC_final(ctx, out, &outlen, 32) || outlen != 32) goto done;
    rc = 0;
done:
    if (rc != 0 && out) cleanse(out, 32);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return rc;
}

/* ─── S0: AES-256-GCM ──────────────────────────────────────────────────── */
int cfs_seal_gcm_seal(const uint8_t key[CFS_SEAL_KEY_LEN],
                      const uint8_t nonce[CFS_SEAL_NONCE_LEN],
                      const void *aad, size_t aadlen,
                      const void *pt, size_t ptlen,
                      void *ct, uint8_t tag[CFS_SEAL_TAG_LEN]) {
    if (!key || !nonce || !ct || !tag) return -1;
    if (ptlen > (size_t)0x7FFFFFFF) return -1;

    int rc = -1, len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, CFS_SEAL_NONCE_LEN, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (aadlen && EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aadlen) != 1) goto done;
    if (ptlen) {
        if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)ptlen) != 1) goto done;
        if ((size_t)len != ptlen) goto done;
    }
    if (EVP_EncryptFinal_ex(ctx, (uint8_t *)ct + ptlen, &len) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, CFS_SEAL_TAG_LEN, tag) != 1) goto done;
    rc = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

int cfs_seal_gcm_open(const uint8_t key[CFS_SEAL_KEY_LEN],
                      const uint8_t nonce[CFS_SEAL_NONCE_LEN],
                      const void *aad, size_t aadlen,
                      const void *ct, size_t ctlen,
                      const uint8_t tag[CFS_SEAL_TAG_LEN],
                      void *pt) {
    if (!key || !nonce || !ct || !tag || !pt) return -1;
    if (ctlen > (size_t)0x7FFFFFFF) return -1;

    int rc = -1, len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, CFS_SEAL_NONCE_LEN, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (aadlen && EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aadlen) != 1) goto done;
    if (ctlen) {
        if (EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ctlen) != 1) goto done;
        if ((size_t)len != ctlen) goto done;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, CFS_SEAL_TAG_LEN,
                            (void *)tag) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, (uint8_t *)pt + ctlen, &len) != 1) goto done;
    rc = 0;
done:
    if (rc != 0) cleanse(pt, ctlen);   /* no unauthenticated bytes escape */
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/* ─── S0: ChaCha20 ─────────────────────────────────────────────────────── */
int cfs_seal_chacha20(const uint8_t key[CFS_SEAL_KEY_LEN],
                      const uint8_t nonce[CFS_SEAL_NONCE_LEN],
                      uint32_t counter,
                      const void *in, void *out, size_t len) {
    if (!key || !nonce || (!in && len) || (!out && len)) return -1;
    if (len > (size_t)0x7FFFFFFF) return -1;

    /* EVP_chacha20's IV is counter (4, little-endian) || nonce (12). */
    uint8_t iv[16];
    put_u32le(iv, counter);
    memcpy(iv + 4, nonce, CFS_SEAL_NONCE_LEN);

    int rc = -1, n = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, iv) != 1) goto done;
    if (len) {
        if (EVP_EncryptUpdate(ctx, out, &n, in, (int)len) != 1) goto done;
        if ((size_t)n != len) goto done;
    }
    rc = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    cleanse(iv, sizeof iv);
    return rc;
}

/* ─── S0: certificate wrap ─────────────────────────────────────────────── */
#define CERT_KIND_RSA   1u
#define CERT_KIND_ECDH  2u

static EVP_PKEY *load_pubkey(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    EVP_PKEY *k = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (k) return k;
    /* Also accept a certificate file: its subject key is the recipient. */
    f = fopen(path, "r");
    if (!f) return NULL;
    X509 *x = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    if (!x) return NULL;
    k = X509_get_pubkey(x);
    X509_free(x);
    return k;
}

static EVP_PKEY *load_privkey(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    return k;
}

int cfs_seal_cert_wrap(const char *pubkey_pem,
                       const uint8_t *in, size_t inlen,
                       uint8_t *out, size_t *outlen) {
    if (!pubkey_pem || !in || !out || !outlen) return -1;
    if (inlen != CFS_SEAL_KEY_LEN) return -1;

    int rc = -1, kind = 0;
    size_t body = 0;
    EVP_PKEY *peer = load_pubkey(pubkey_pem);
    if (!peer) return -1;

    int base = EVP_PKEY_get_base_id(peer);
    if (base == EVP_PKEY_RSA || base == EVP_PKEY_RSA_PSS) {
        kind = CERT_KIND_RSA;
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(peer, NULL);
        if (!ctx) goto done;
        if (EVP_PKEY_encrypt_init(ctx) != 1 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1 ||
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) != 1 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) != 1) {
            EVP_PKEY_CTX_free(ctx); goto done;
        }
        size_t n = 0;
        int ok = EVP_PKEY_encrypt(ctx, NULL, &n, in, inlen) == 1 &&
                 n <= CFS_SEAL_MAX_CERT_BLOB &&
                 EVP_PKEY_encrypt(ctx, out + 4, &n, in, inlen) == 1;
        EVP_PKEY_CTX_free(ctx);
        if (!ok) { rc = -2; goto done; }   /* key too large for the field */
        body = n;
    } else if (base == EVP_PKEY_EC || base == EVP_PKEY_X25519) {
        kind = CERT_KIND_ECDH;
        EVP_PKEY *eph = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
        if (!eph) goto done;

        /* Z = ECDH(eph, peer); KEK = HKDF(Z); body = SPKI(eph) || AES-KW(in) */
        EVP_PKEY_CTX *d = EVP_PKEY_CTX_new(eph, NULL);
        uint8_t *z = NULL, kek[32];
        size_t zlen = 0;
        int ok = d && EVP_PKEY_derive_init(d) == 1 &&
                 EVP_PKEY_derive_set_peer(d, peer) == 1 &&
                 EVP_PKEY_derive(d, NULL, &zlen) == 1 &&
                 (z = malloc(zlen)) != NULL &&
                 EVP_PKEY_derive(d, z, &zlen) == 1 &&
                 cfs_seal_hkdf(z, zlen, NULL, 0, INFO_ECDH, sizeof INFO_ECDH - 1,
                               kek, sizeof kek) == 0;
        if (d) EVP_PKEY_CTX_free(d);
        cleanse(z, z ? zlen : 0);
        free(z);

        uint8_t *p = out + 4 + 2;
        int spki = ok ? i2d_PUBKEY(eph, &p) : -1;
        /* 4-byte blob header + 2-byte SPKI length + SPKI + 40-byte wrap. */
        if (spki <= 0 || 4u + 2u + (size_t)spki + 40u > CFS_SEAL_MAX_CERT_BLOB) {
            cleanse(kek, sizeof kek);
            EVP_PKEY_free(eph);
            if (ok) rc = -2;
            goto done;
        }

        EVP_CIPHER_CTX *cw = EVP_CIPHER_CTX_new();
        int wlen = 0;
        if (cw) EVP_CIPHER_CTX_set_flags(cw, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        ok = cw &&
             EVP_EncryptInit_ex(cw, EVP_aes_256_wrap(), NULL, kek, NULL) == 1 &&
             EVP_EncryptUpdate(cw, out + 4 + 2 + spki, &wlen, in, (int)inlen) == 1 &&
             (size_t)wlen == inlen + 8;
        EVP_CIPHER_CTX_free(cw);
        cleanse(kek, sizeof kek);
        EVP_PKEY_free(eph);
        if (!ok) goto done;

        put_u16le(out + 4, (uint16_t)spki);
        body = 2u + (size_t)spki + inlen + 8u;
    } else {
        rc = -3;   /* unsupported certificate key type */
        goto done;
    }

    if (4u + body > CFS_SEAL_MAX_CERT_BLOB) { rc = -2; goto done; }
    out[0] = (uint8_t)kind;
    out[1] = 0;
    put_u16le(out + 2, (uint16_t)body);
    *outlen = 4u + body;
    rc = 0;
done:
    EVP_PKEY_free(peer);
    return rc;
}

int cfs_seal_cert_unwrap(const char *privkey_pem,
                         const uint8_t *in, size_t inlen,
                         uint8_t *out, size_t *outlen) {
    if (!privkey_pem || !in || !out || !outlen || inlen < 4) return -1;
    if (inlen > CFS_SEAL_CERT_WRAP_LEN) return -1;
    if (*outlen < CFS_SEAL_KEY_LEN) return -1;

    int rc = -1;
    size_t body = get_u16le(in + 2);
    if (body > inlen - 4u) return -1;
    const uint8_t *b = in + 4;
    EVP_PKEY *priv = load_privkey(privkey_pem);
    if (!priv) return -1;

    if (in[0] == CERT_KIND_RSA) {
        /* OpenSSL's provider needs a modulus-sized output buffer even
         * though OAEP-SHA256 can only ever return 32 bytes here. */
        size_t cap = (size_t)EVP_PKEY_size(priv);
        uint8_t *tmp = cap ? malloc(cap) : NULL;
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
        size_t n = cap;
        if (tmp && ctx &&
            EVP_PKEY_decrypt_init(ctx) == 1 &&
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) == 1 &&
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) == 1 &&
            EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) == 1 &&
            EVP_PKEY_decrypt(ctx, tmp, &n, b, body) == 1 &&
            n == CFS_SEAL_KEY_LEN) {
            memcpy(out, tmp, CFS_SEAL_KEY_LEN);
            *outlen = CFS_SEAL_KEY_LEN;
            rc = 0;
        }
        cleanse(tmp, cap);
        free(tmp);
        EVP_PKEY_CTX_free(ctx);
    } else if (in[0] == CERT_KIND_ECDH) {
        if (body < 2) goto done;
        size_t spki = get_u16le(b);
        if (spki + 2u > body || body - 2u - spki != CFS_SEAL_KEY_LEN + 8u) goto done;

        const uint8_t *p = b + 2;
        EVP_PKEY *eph = d2i_PUBKEY(NULL, &p, (long)spki);
        if (!eph) goto done;

        EVP_PKEY_CTX *d = EVP_PKEY_CTX_new(priv, NULL);
        uint8_t *z = NULL, kek[32];
        size_t zlen = 0;
        int ok = d && EVP_PKEY_derive_init(d) == 1 &&
                 EVP_PKEY_derive_set_peer(d, eph) == 1 &&
                 EVP_PKEY_derive(d, NULL, &zlen) == 1 &&
                 (z = malloc(zlen)) != NULL &&
                 EVP_PKEY_derive(d, z, &zlen) == 1 &&
                 cfs_seal_hkdf(z, zlen, NULL, 0, INFO_ECDH, sizeof INFO_ECDH - 1,
                               kek, sizeof kek) == 0;
        if (d) EVP_PKEY_CTX_free(d);
        cleanse(z, z ? zlen : 0);
        free(z);
        EVP_PKEY_free(eph);
        if (!ok) { cleanse(kek, sizeof kek); goto done; }

        EVP_CIPHER_CTX *cw = EVP_CIPHER_CTX_new();
        int wlen = 0;
        if (cw) EVP_CIPHER_CTX_set_flags(cw, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        ok = cw &&
             EVP_DecryptInit_ex(cw, EVP_aes_256_wrap(), NULL, kek, NULL) == 1 &&
             EVP_DecryptUpdate(cw, out, &wlen,
                               b + 2 + spki, (int)(CFS_SEAL_KEY_LEN + 8)) == 1 &&
             wlen == (int)CFS_SEAL_KEY_LEN;
        EVP_CIPHER_CTX_free(cw);
        cleanse(kek, sizeof kek);
        if (ok) { *outlen = CFS_SEAL_KEY_LEN; rc = 0; }
    }
done:
    if (rc != 0) cleanse(out, *outlen);
    EVP_PKEY_free(priv);
    return rc;
}

/* ─── parsed header ────────────────────────────────────────────────────── */
typedef struct {
    uint8_t version, flags, kdf_id;
    CfsSealKdfParams kdf;
    uint8_t salt[CFS_SEAL_SALT_LEN];
    uint8_t shard_uuid[CFS_SEAL_UUID_LEN];
    uint8_t wrapped_start[CFS_SEAL_WRAPPED_START_LEN];
    uint8_t keyed_check[CFS_SEAL_KEYED_CHECK_LEN];
    uint8_t ring_link[CFS_SEAL_RING_LINK_LEN];
    uint8_t nonce_prefix[CFS_SEAL_NONCE_PREFIX_LEN];
    uint8_t cert_wrap[CFS_SEAL_CERT_WRAP_LEN];
} SealHdr;

/* Mask key = HKDF-SHA256(salt, "cfs9:hdr-mask").  Obfuscation only; see the
 * header comment — the salt is in the clear, so this hides patterns from
 * scanners, not from anyone who has read this file. */
static int hdr_mask(const uint8_t salt[CFS_SEAL_SALT_LEN], uint8_t *mask) {
    return cfs_seal_hkdf(salt, CFS_SEAL_SALT_LEN, NULL, 0,
                         INFO_HDR_MASK, sizeof INFO_HDR_MASK - 1,
                         mask, HO_MASK_END);
}

static void hdr_apply_mask(uint8_t *h) {
    uint8_t mask[HO_MASK_END];
    if (hdr_mask(h + HO_SALT, mask) != 0) return;   /* leaves bytes as-is */
    for (size_t i = 0; i < HO_MASK_END; i++) {
        if (i >= HO_SALT && i < HO_SALT + CFS_SEAL_SALT_LEN) continue;
        h[i] ^= mask[i];
    }
    cleanse(mask, sizeof mask);
}

static int hdr_serialize(const SealHdr *f, uint8_t out[CFS_SEAL_HDR_SIZE]) {
    memset(out, 0, CFS_SEAL_HDR_SIZE);
    if (cfs_seal_random(out, CFS_SEAL_HDR_SIZE) != 0) return -1;

    out[HO_VER]   = f->version;
    out[HO_FLAGS] = f->flags;
    out[HO_KDF]   = f->kdf_id;
    /* HO_RSV stays random */
    put_u32le(out + HO_M, f->kdf.m_cost);
    put_u16le(out + HO_T, (uint16_t)f->kdf.t_cost);
    put_u16le(out + HO_P, (uint16_t)f->kdf.lanes);
    memcpy(out + HO_SALT, f->salt, CFS_SEAL_SALT_LEN);
    memcpy(out + HO_UUID, f->shard_uuid, CFS_SEAL_UUID_LEN);
    memcpy(out + HO_WRAPPED, f->wrapped_start, CFS_SEAL_WRAPPED_START_LEN);
    memcpy(out + HO_CHECK, f->keyed_check, CFS_SEAL_KEYED_CHECK_LEN);
    memcpy(out + HO_RING, f->ring_link, CFS_SEAL_RING_LINK_LEN);
    memcpy(out + HO_NPREFIX, f->nonce_prefix, CFS_SEAL_NONCE_PREFIX_LEN);
    out[HO_BSHIFT] = 16;                    /* 2^16 = CFS_SEAL_BLOCK_SIZE */
    /* HO_RSV2 stays random */
    memcpy(out + HO_CERTWRAP, f->cert_wrap, CFS_SEAL_CERT_WRAP_LEN);

    hdr_apply_mask(out);
    return 0;
}

static void hdr_parse(const uint8_t *in, SealHdr *f) {
    uint8_t h[HO_MASK_END];
    memcpy(h, in, HO_MASK_END);
    hdr_apply_mask(h);

    memset(f, 0, sizeof *f);
    f->version = h[HO_VER];
    f->flags   = h[HO_FLAGS];
    f->kdf_id  = h[HO_KDF];
    f->kdf.m_cost = get_u32le(h + HO_M);
    f->kdf.t_cost = get_u16le(h + HO_T);
    f->kdf.lanes  = get_u16le(h + HO_P);
    memcpy(f->salt,          h + HO_SALT,    CFS_SEAL_SALT_LEN);
    memcpy(f->shard_uuid,    h + HO_UUID,    CFS_SEAL_UUID_LEN);
    memcpy(f->wrapped_start, h + HO_WRAPPED, CFS_SEAL_WRAPPED_START_LEN);
    memcpy(f->keyed_check,   h + HO_CHECK,   CFS_SEAL_KEYED_CHECK_LEN);
    memcpy(f->ring_link,     h + HO_RING,    CFS_SEAL_RING_LINK_LEN);
    memcpy(f->nonce_prefix,  h + HO_NPREFIX, CFS_SEAL_NONCE_PREFIX_LEN);
    memcpy(f->cert_wrap,     h + HO_CERTWRAP, CFS_SEAL_CERT_WRAP_LEN);
    cleanse(h, sizeof h);
}

/* ─── Merkle root over a shard's plaintext blocks ──────────────────────────
 *
 * The tree commits to every plaintext block of the shard (the full 65520-byte
 * framed block, padding included), so the commitment covers even the bytes a
 * future block layout change might leave unused.  Domain separation: leaf
 * nodes are SHA256(0x00||block), internal nodes SHA256(0x01||l||r); an odd
 * node is promoted unchanged to the next level. */
static int merkle_leaf(const uint8_t *block, size_t len, uint8_t out[32]) {
    uint8_t pre = 0x00;
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    unsigned int dl = 0;
    int ok = mc && EVP_DigestInit_ex(mc, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(mc, &pre, 1) == 1 &&
             EVP_DigestUpdate(mc, block, len) == 1 &&
             EVP_DigestFinal_ex(mc, out, &dl) == 1 && dl == 32;
    EVP_MD_CTX_free(mc);
    return ok ? 0 : -1;
}

/* Reduce n leaves (destructively, into a scratch copy) to one root. */
static int merkle_reduce(uint8_t *leaves, uint32_t n, uint8_t out[32]) {
    if (n == 0) { memset(out, 0, 32); return 0; }
    uint8_t *nxt = malloc((size_t)(n / 2 + 1) * 32);
    if (!nxt) return -1;

    while (n > 1) {
        uint32_t k = 0;
        for (uint32_t i = 0; i + 1 < n; i += 2, k++) {
            uint8_t in[1 + 64], d[32];
            in[0] = 0x01;
            memcpy(in + 1, leaves + (size_t)i * 32, 32);
            memcpy(in + 33, leaves + (size_t)(i + 1) * 32, 32);
            if (cfs_seal_sha256(in, sizeof in, d) != 0) { free(nxt); return -1; }
            memcpy(leaves + (size_t)k * 32, d, 32);
        }
        if (n & 1) {                          /* promote the odd node */
            memcpy(leaves + (size_t)k * 32, leaves + (size_t)(n - 1) * 32, 32);
            k++;
        }
        n = k;
    }
    memcpy(out, leaves, 32);
    free(nxt);
    return 0;
}

/* Contiguous variant used at seal time. */
static int merkle_root(const uint8_t *base, size_t stride, uint32_t n,
                       uint8_t out[32]) {
    uint8_t *leaves = malloc((size_t)(n ? n : 1) * 32);
    if (!leaves) return -1;
    for (uint32_t i = 0; i < n; i++)
        if (merkle_leaf(base + (size_t)i * stride, stride, leaves + (size_t)i * 32) != 0) {
            free(leaves);
            return -1;
        }
    int rc = merkle_reduce(leaves, n, out);
    free(leaves);
    return rc;
}

/* ─── nonce / AAD helpers ──────────────────────────────────────────────── */
static void make_nonce(const uint8_t prefix[CFS_SEAL_NONCE_PREFIX_LEN],
                       uint32_t idx, uint8_t nonce[CFS_SEAL_NONCE_LEN]) {
    memcpy(nonce, prefix, CFS_SEAL_NONCE_PREFIX_LEN);
    put_u32be(nonce + CFS_SEAL_NONCE_PREFIX_LEN, idx);
}

/* AAD = container_uuid || shard_uuid || block_idx || offset  (44 bytes) */
static void make_block_aad(const uint8_t *cuuid, const uint8_t *suuid,
                           uint32_t idx, uint8_t aad[44]) {
    memcpy(aad, cuuid, CFS_SEAL_UUID_LEN);
    memcpy(aad + 16, suuid, CFS_SEAL_UUID_LEN);
    put_u32be(aad + 32, idx);
    put_u64be(aad + 36, (uint64_t)idx * CFS_SEAL_BLOCK_SIZE);
}

/* K_data = HKDF(DEK, salt, "cfs9:data" || SHA256(root_0 .. root_{N-1})).
 * One function for both directions: seal and open disagreeing about this
 * derivation is exactly the kind of bug that still round-trips in a
 * single-shard self-test and fails on the first real container. */
static int derive_kdata(const uint8_t dek[CFS_SEAL_KEY_LEN],
                        const uint8_t salt[CFS_SEAL_SALT_LEN],
                        const uint8_t *roots, uint32_t n,
                        uint8_t out[CFS_SEAL_KEY_LEN]) {
    uint8_t rcat[32], info[sizeof INFO_DATA - 1 + 32];
    if (!n || cfs_seal_sha256(roots, (size_t)n * 32, rcat) != 0) return -1;
    memcpy(info, INFO_DATA, sizeof INFO_DATA - 1);
    memcpy(info + sizeof INFO_DATA - 1, rcat, 32);
    return cfs_seal_hkdf(dek, CFS_SEAL_KEY_LEN, salt, CFS_SEAL_SALT_LEN,
                         info, sizeof info, out, CFS_SEAL_KEY_LEN);
}

/* ─── create ───────────────────────────────────────────────────────────── */
int cfs_seal_create(const CfsSealCreateOpts *o,
                    const void *plain, size_t len, CfsSealSet *out) {
    if (!o || !out || (!plain && len)) return CFS_SEAL_EARG;
    if (o->nshards < 1 || o->nshards > CFS_SEAL_MAX_SHARDS) return CFS_SEAL_EARG;
    if (!o->cert_pub_pem && (!o->password || o->password_len == 0)) return CFS_SEAL_EARG;

    memset(out, 0, sizeof *out);
    const uint32_t N = o->nshards;

    /* Parameters are written into every header; keep them in the range a
     * reader will accept so that a container is always self-consistent. */
    CfsSealKdfParams kdf = o->kdf;
    if (kdf.m_cost == 0) kdf.m_cost = 262144;
    if (kdf.t_cost == 0) kdf.t_cost = 3;
    if (kdf.lanes == 0)  kdf.lanes = 4;
    if (kdf.m_cost < KDF_M_MIN || kdf.m_cost > KDF_M_MAX ||
        kdf.t_cost > KDF_T_MAX || kdf.lanes > KDF_P_MAX ||
        kdf.m_cost < 8u * kdf.lanes)
        return CFS_SEAL_EARG;

    /* Uniform shard split: every shard carries the same block count. */
    const uint64_t per_shard = (uint64_t)N * CFS_SEAL_BLOCK_DATA;
    uint64_t nb64 = ((uint64_t)len + per_shard - 1) / per_shard;
    if (nb64 == 0) nb64 = 1;
    if (nb64 * N > CFS_SEAL_MAX_BLOCK_IDX) return CFS_SEAL_EARG;
    const uint32_t nblocks = (uint32_t)nb64;
    const uint64_t shard_len = CFS_SEAL_HDR_SIZE + (uint64_t)nblocks * CFS_SEAL_BLOCK_SIZE;
    if (shard_len > SIZE_MAX) return CFS_SEAL_EARG;

    int rc = CFS_SEAL_ECRYPTO;
    uint8_t salt[CFS_SEAL_SALT_LEN], npfx[CFS_SEAL_NONCE_PREFIX_LEN];
    uint8_t start_uuid[CFS_SEAL_UUID_LEN], dek[CFS_SEAL_KEY_LEN];
    uint8_t sk[CFS_SEAL_KEY_LEN], kdata[CFS_SEAL_KEY_LEN];
    uint8_t cert_wrap[CFS_SEAL_CERT_WRAP_LEN];
    size_t cert_wrap_len = 0;
    uint8_t *arena = NULL, *roots = NULL;
    memset(cert_wrap, 0, sizeof cert_wrap);

    if (cfs_seal_random(salt, sizeof salt) != 0 ||
        cfs_seal_random(npfx, sizeof npfx) != 0 ||
        cfs_seal_random(start_uuid, sizeof start_uuid) != 0 ||
        cfs_seal_random(dek, sizeof dek) != 0) {
        rc = CFS_SEAL_ECRYPTO;
        goto done;
    }

    /* Start key: password (Argon2id) or certificate (wraps a random SK). */
    uint8_t kdf_id;
    if (o->cert_pub_pem) {
        kdf_id = CFS_SEAL_KDF_CERTIFICATE;
        if (cfs_seal_random(sk, sizeof sk) != 0) { rc = CFS_SEAL_ECRYPTO; goto done; }
        if (cfs_seal_cert_wrap(o->cert_pub_pem, sk, sizeof sk,
                               cert_wrap, &cert_wrap_len) != 0) {
            rc = CFS_SEAL_EARG;   /* bad PEM, unsupported or oversized key */
            goto done;
        }
        /* cert_wrap is padded with random bytes by hdr_serialize(). */
        if (cfs_seal_random(cert_wrap + cert_wrap_len,
                            sizeof cert_wrap - cert_wrap_len) != 0) {
            rc = CFS_SEAL_ECRYPTO; goto done;
        }
    } else {
        kdf_id = CFS_SEAL_KDF_ARGON2ID;
        if (cfs_seal_argon2id(o->password, o->password_len, salt, &kdf, sk) != 0) {
            rc = CFS_SEAL_EARG;
            goto done;
        }
        /* The certificate field must look the same whether or not a
         * certificate was used, or its contents would be a mode oracle. */
        if (cfs_seal_random(cert_wrap, sizeof cert_wrap) != 0) {
            rc = CFS_SEAL_ECRYPTO;
            goto done;
        }
    }

    /* Ring keys. */
    uint8_t *ring_key = calloc(N, CFS_SEAL_KEY_LEN);
    if (!ring_key) { rc = CFS_SEAL_ENOMEM; goto done; }
    int ring_ok = 1;
    for (uint32_t i = 0; i < N; i++)
        if (cfs_seal_subkey(dek, salt, sizeof salt, CFS_SEAL_SUB_RING, i,
                            ring_key + (size_t)i * CFS_SEAL_KEY_LEN) != 0)
            ring_ok = 0;
    if (!ring_ok) { free(ring_key); rc = CFS_SEAL_ECRYPTO; goto done; }

    /* Plaintext arena: N shards x nblocks x BLOCK_PLAIN bytes, framed and
     * padded.  Roots are over these bytes (plan §5). */
    const uint64_t arena_len = (uint64_t)N * nblocks * CFS_SEAL_BLOCK_PLAIN;
    arena = malloc(arena_len ? arena_len : 1);
    roots = malloc((size_t)N * 32);
    if (!arena || !roots) { free(ring_key); rc = CFS_SEAL_ENOMEM; goto done; }

    const uint64_t chunk = (uint64_t)nblocks * CFS_SEAL_BLOCK_DATA;
    for (uint32_t s = 0; s < N; s++) {
        const uint8_t *src = (const uint8_t *)plain;
        for (uint32_t b = 0; b < nblocks; b++) {
            uint8_t *blk = arena + ((size_t)s * nblocks + b) * CFS_SEAL_BLOCK_PLAIN;
            memset(blk, 0, CFS_SEAL_BLOCK_PLAIN);

            uint64_t off = (uint64_t)s * chunk + (uint64_t)b * CFS_SEAL_BLOCK_DATA;
            size_t avail = 0;
            if (off < len) {
                uint64_t left = (uint64_t)len - off;
                avail = left > CFS_SEAL_BLOCK_DATA ? CFS_SEAL_BLOCK_DATA : (size_t)left;
            }
            /* Only form the pointer when there is data to read: `off` can
             * sit past the end for the tail shards of a short container. */
            const uint8_t *data = avail ? src + off : src;

            uint32_t stored = (uint32_t)avail;
            uint8_t codec = 0;
            uint8_t *payload = blk + CFS_SEAL_BLOCK_FRAME;
            if (o->codec && avail) {
                size_t clen = 0;
                if (o->codec(o->codec_ctx, data, avail, payload,
                             CFS_SEAL_BLOCK_DATA, &clen) == 0 &&
                    clen < avail && clen <= CFS_SEAL_BLOCK_DATA) {
                    stored = (uint32_t)clen;
                    codec = 1;
                }
            }
            if (codec == 0 && avail)
                memcpy(payload, data, avail);

            put_u64le(blk + BO_DATALEN, avail);
            put_u32le(blk + BO_STORED, stored);
            blk[BO_CODEC] = codec;
        }
        if (merkle_root(arena + (size_t)s * nblocks * CFS_SEAL_BLOCK_PLAIN,
                        CFS_SEAL_BLOCK_PLAIN, nblocks, roots + (size_t)s * 32) != 0) {
            free(ring_key); rc = CFS_SEAL_ECRYPTO; goto done;
        }
    }

    if (derive_kdata(dek, salt, roots, N, kdata) != 0) {
        free(ring_key); rc = CFS_SEAL_ECRYPTO; goto done;
    }

    /* Allocate the shards and fill header + blocks. */
    out->shards = calloc(N, sizeof *out->shards);
    if (!out->shards) { free(ring_key); rc = CFS_SEAL_ENOMEM; goto done; }
    out->nshards = N;

    uint8_t uuids[CFS_SEAL_MAX_SHARDS][CFS_SEAL_UUID_LEN];
    for (uint32_t s = 0; s < N; s++) {
        if (cfs_seal_random(uuids[s], CFS_SEAL_UUID_LEN) != 0) {
            free(ring_key); rc = CFS_SEAL_ECRYPTO; goto fail;
        }
    }
    /* The uuids are collision-free with overwhelming probability, but a
     * duplicate would break the ring walk, so check rather than assume. */
    for (uint32_t i = 0; i < N; i++)
        for (uint32_t j = i + 1; j < N; j++)
            if (memcmp(uuids[i], uuids[j], CFS_SEAL_UUID_LEN) == 0) {
                free(ring_key); rc = CFS_SEAL_ECRYPTO; goto fail;
            }

    /* The container uuid is the ring's slot-0 uuid: that is what a reader
     * looks for to know where the chain begins.  (Generating it separately
     * would leave a uuid in wrapped_start that no shard carries, and the
     * walk could never start.) */
    memcpy(start_uuid, uuids[0], CFS_SEAL_UUID_LEN);

    for (uint32_t s = 0; s < N; s++) {
        CfsSealShard *sh = &out->shards[s];
        sh->data = malloc((size_t)shard_len);
        if (!sh->data) { free(ring_key); rc = CFS_SEAL_ENOMEM; goto fail; }
        sh->len = (size_t)shard_len;

        SealHdr f;
        memset(&f, 0, sizeof f);
        f.version = CFS_SEAL_VERSION;
        f.flags   = o->codec ? CFS_SEAL_F_COMPRESSED : 0;
        f.kdf_id  = kdf_id;
        f.kdf     = kdf;
        memcpy(f.salt, salt, sizeof salt);
        memcpy(f.shard_uuid, uuids[s], CFS_SEAL_UUID_LEN);
        memcpy(f.nonce_prefix, npfx, sizeof npfx);
        memcpy(f.cert_wrap, cert_wrap, sizeof cert_wrap);

        /* wrapped_start = AEAD(SK, {start_uuid, DEK}), AAD = shard_uuid */
        uint8_t ws[CFS_SEAL_UUID_LEN + CFS_SEAL_KEY_LEN], nonce[CFS_SEAL_NONCE_LEN];
        memcpy(ws, start_uuid, CFS_SEAL_UUID_LEN);
        memcpy(ws + CFS_SEAL_UUID_LEN, dek, CFS_SEAL_KEY_LEN);
        make_nonce(npfx, CFS_SEAL_NONCE_IDX_WRAPPED, nonce);
        if (cfs_seal_gcm_seal(sk, nonce, f.shard_uuid, CFS_SEAL_UUID_LEN,
                              ws, sizeof ws, f.wrapped_start,
                              f.wrapped_start + sizeof ws) != 0) {
            cleanse(ws, sizeof ws); free(ring_key); rc = CFS_SEAL_ECRYPTO; goto fail;
        }
        cleanse(ws, sizeof ws);

        /* keyed_check = HMAC(DEK, "cfs9:hdr" || shard_uuid)[0..8] */
        uint8_t mac[32], hd[sizeof INFO_HDR - 1 + CFS_SEAL_UUID_LEN];
        memcpy(hd, INFO_HDR, sizeof INFO_HDR - 1);
        memcpy(hd + sizeof INFO_HDR - 1, uuids[s], CFS_SEAL_UUID_LEN);
        if (cfs_seal_hmac_sha256(dek, sizeof dek, hd, sizeof hd, mac) != 0) {
            free(ring_key); rc = CFS_SEAL_ECRYPTO; goto fail;
        }
        memcpy(f.keyed_check, mac, CFS_SEAL_KEYED_CHECK_LEN);

        /* ring_link = AEAD(K_s, {next_uuid, K_{s+1}, root_s}),
         *             AAD = start_uuid || shard_uuid */
        uint8_t rl[CFS_SEAL_UUID_LEN + CFS_SEAL_KEY_LEN + 32];
        memcpy(rl, uuids[(s + 1) % N], CFS_SEAL_UUID_LEN);
        memcpy(rl + CFS_SEAL_UUID_LEN, ring_key + (size_t)((s + 1) % N) * CFS_SEAL_KEY_LEN,
               CFS_SEAL_KEY_LEN);
        memcpy(rl + CFS_SEAL_UUID_LEN + CFS_SEAL_KEY_LEN, roots + (size_t)s * 32, 32);
        uint8_t raad[2 * CFS_SEAL_UUID_LEN];
        memcpy(raad, start_uuid, CFS_SEAL_UUID_LEN);
        memcpy(raad + CFS_SEAL_UUID_LEN, uuids[s], CFS_SEAL_UUID_LEN);
        make_nonce(npfx, CFS_SEAL_NONCE_IDX_RING, nonce);
        if (cfs_seal_gcm_seal(ring_key + (size_t)s * CFS_SEAL_KEY_LEN, nonce,
                              raad, sizeof raad, rl, sizeof rl, f.ring_link,
                              f.ring_link + sizeof rl) != 0) {
            cleanse(rl, sizeof rl); free(ring_key); rc = CFS_SEAL_ECRYPTO; goto fail;
        }
        cleanse(rl, sizeof rl);

        if (hdr_serialize(&f, sh->data) != 0) {
            free(ring_key); rc = CFS_SEAL_ECRYPTO; goto fail;
        }

        /* Encrypt the shard's blocks in place (header already written). */
        for (uint32_t b = 0; b < nblocks; b++) {
            uint8_t *pt = arena + ((size_t)s * nblocks + b) * CFS_SEAL_BLOCK_PLAIN;
            uint8_t *ct = sh->data + CFS_SEAL_HDR_SIZE +
                          (size_t)b * CFS_SEAL_BLOCK_SIZE;
            uint32_t idx = s * nblocks + b;
            uint8_t aad[44], n2[CFS_SEAL_NONCE_LEN];
            make_block_aad(start_uuid, uuids[s], idx, aad);
            make_nonce(npfx, idx, n2);
            if (cfs_seal_gcm_seal(kdata, n2, aad, sizeof aad, pt,
                                  CFS_SEAL_BLOCK_PLAIN, ct,
                                  ct + CFS_SEAL_BLOCK_PLAIN) != 0) {
                free(ring_key); rc = CFS_SEAL_ECRYPTO; goto fail;
            }
        }
    }

    free(ring_key);
    rc = CFS_SEAL_OK;

done:
fail:
    free(arena);
    free(roots);
    cleanse(salt, sizeof salt);
    cleanse(npfx, sizeof npfx);
    cleanse(dek, sizeof dek);
    cleanse(sk, sizeof sk);
    cleanse(kdata, sizeof kdata);
    if (rc != CFS_SEAL_OK) {
        cfs_seal_free(out);
        memset(out, 0, sizeof *out);
    }
    return rc;
}

/* ─── open ─────────────────────────────────────────────────────────────── */
typedef struct {
    int        plausible;
    uint32_t   nblocks;
    SealHdr    hdr;
} Cand;

/* Deterministic stand-in for a key we could not obtain.  Every failure path
 * uses it so the rest of the traversal runs identically and the decoy is
 * reproducible for a given wrong key. */
static int fake_key(const char *label, const uint8_t *salt, size_t saltlen,
                    uint8_t out[CFS_SEAL_KEY_LEN]) {
    uint8_t info[32 + 32];
    size_t n = strlen(label);
    if (n > 32) n = 32;
    memcpy(info, label, n);
    memcpy(info + n, salt, saltlen > 32 ? 32 : saltlen);
    return cfs_seal_hkdf(info, n + (saltlen > 32 ? 32 : saltlen), NULL, 0,
                         INFO_NOKEY, sizeof INFO_NOKEY - 1, out, CFS_SEAL_KEY_LEN);
}

int cfs_seal_open(const CfsSealSet *set,
                  const char *cert_priv_pem,
                  const void *password, size_t password_len,
                  CfsSealCodec codec, void *codec_ctx,
                  CfsSealOpenResult *out) {
    if (!set || !out) return CFS_SEAL_EARG;
    memset(out, 0, sizeof *out);
    if (!set->shards || set->nshards < 1 || set->nshards > CFS_SEAL_MAX_SHARDS)
        return CFS_SEAL_EARG;

    const uint32_t N = set->nshards;
    Cand *cand = calloc(N, sizeof *cand);
    if (!cand) return CFS_SEAL_ENOMEM;

    /* ── structural pass: which candidates look like shards at all? ───── */
    uint32_t nplaus = 0;
    uint32_t nblocks = 0;
    uint32_t plist[CFS_SEAL_MAX_SHARDS];
    for (uint32_t j = 0; j < N; j++) {
        const CfsSealShard *sh = &set->shards[j];
        if (!sh->data || sh->len < CFS_SEAL_HDR_SIZE) continue;
        size_t body = sh->len - CFS_SEAL_HDR_SIZE;
        if (body % CFS_SEAL_BLOCK_SIZE) continue;
        uint32_t nb = (uint32_t)(body / CFS_SEAL_BLOCK_SIZE);
        if (nb == 0) continue;
        /* All shards of one container have the same block count (plan
         * §3.3); a candidate that disagrees is not part of this set. */
        if (nplaus > 0 && nb != nblocks) continue;
        cand[j].plausible = 1;
        cand[j].nblocks = nb;
        hdr_parse(sh->data, &cand[j].hdr);
        if (nplaus == 0) nblocks = nb;
        plist[nplaus++] = j;
    }
    if (nplaus == 0) { free(cand); return CFS_SEAL_EFORMAT; }

    /* Output size is the structural capacity of the candidate set, so a
     * wrong key — which cannot tell members from non-members — writes the
     * same number of bytes as the right one (plan §6, P6). */
    uint64_t out_len64 = (uint64_t)nplaus * nblocks * CFS_SEAL_BLOCK_DATA;
    if (out_len64 > SIZE_MAX) { free(cand); return CFS_SEAL_EARG; }
    size_t out_len = (size_t)out_len64;

    /* The salt is per container and replicated in every shard, so take the
     * value a majority agrees on rather than the first one seen.  The salt
     * keys the header mask, so a single flipped byte there turns every
     * field of that shard into noise — including the Argon2 cost, which
     * would otherwise let one corrupted header drive the reader's memory
     * bill.  With a majority vote, one bad shard is just a non-member. */
    uint32_t first = 0, best_count = 0;
    for (uint32_t a = 0; a < nplaus; a++) {
        uint32_t j = plist[a], count = 0;
        for (uint32_t b = 0; b < nplaus; b++)
            if (memcmp(cand[j].hdr.salt, cand[plist[b]].hdr.salt,
                       CFS_SEAL_SALT_LEN) == 0) count++;
        if (count > best_count) { best_count = count; first = j; }
    }
    const uint8_t *salt = cand[first].hdr.salt;

    /* Header KDF parameters are untrusted: clamp before spending memory. */
    CfsSealKdfParams kdf = cand[first].hdr.kdf;
    if (kdf.m_cost < KDF_M_MIN) kdf.m_cost = KDF_M_MIN;
    if (kdf.m_cost > KDF_M_MAX) kdf.m_cost = KDF_M_MAX;
    if (kdf.t_cost < 1) kdf.t_cost = 1;
    if (kdf.t_cost > KDF_T_MAX) kdf.t_cost = KDF_T_MAX;
    if (kdf.lanes < 1) kdf.lanes = 1;
    if (kdf.lanes > KDF_P_MAX) kdf.lanes = KDF_P_MAX;
    if (kdf.m_cost < 8u * kdf.lanes) kdf.m_cost = 8u * kdf.lanes;

    uint8_t sk[CFS_SEAL_KEY_LEN], dek[CFS_SEAL_KEY_LEN];
    uint8_t start_uuid[CFS_SEAL_UUID_LEN], kdata[CFS_SEAL_KEY_LEN];
    uint8_t nonce_prefix[CFS_SEAL_NONCE_PREFIX_LEN];
    memset(dek, 0, sizeof dek);
    memset(start_uuid, 0, sizeof start_uuid);
    memset(kdata, 0, sizeof kdata);
    memcpy(nonce_prefix, cand[first].hdr.nonce_prefix, sizeof nonce_prefix);

    int ok = 1;

    /* ── start key ─────────────────────────────────────────────────────── */
    if (cand[first].hdr.kdf_id == CFS_SEAL_KDF_CERTIFICATE && cert_priv_pem) {
        size_t sklen = sizeof sk;
        if (cfs_seal_cert_unwrap(cert_priv_pem, cand[first].hdr.cert_wrap,
                                 sizeof cand[first].hdr.cert_wrap,
                                 sk, &sklen) != 0)
            ok = 0;
        if (sklen != sizeof sk) ok = 0;
        if (!ok) fake_key("cert", salt, CFS_SEAL_SALT_LEN, sk);
    } else if (cand[first].hdr.kdf_id == CFS_SEAL_KDF_ARGON2ID && password) {
        if (cfs_seal_argon2id(password, password_len, salt, &kdf, sk) != 0) {
            ok = 0;
            fake_key("pass", salt, CFS_SEAL_SALT_LEN, sk);
        }
    } else {
        ok = 0;                                   /* wrong mode for this key */
        fake_key("mode", salt, CFS_SEAL_SALT_LEN, sk);
    }

    /* ── unwrap the DEK from every candidate's wrapped_start ───────────── */
    int have_dek = 0;
    for (uint32_t j = 0; j < N; j++) {
        if (!cand[j].plausible) continue;
        uint8_t nonce[CFS_SEAL_NONCE_LEN];
        uint8_t ws[CFS_SEAL_UUID_LEN + CFS_SEAL_KEY_LEN];
        make_nonce(nonce_prefix, CFS_SEAL_NONCE_IDX_WRAPPED, nonce);
        if (cfs_seal_gcm_open(sk, nonce, cand[j].hdr.shard_uuid, CFS_SEAL_UUID_LEN,
                              cand[j].hdr.wrapped_start,
                              CFS_SEAL_UUID_LEN + CFS_SEAL_KEY_LEN,
                              cand[j].hdr.wrapped_start +
                                  CFS_SEAL_UUID_LEN + CFS_SEAL_KEY_LEN, ws) != 0) {
            cleanse(ws, sizeof ws);
            continue;
        }
        uint8_t mac[32], hd[sizeof INFO_HDR - 1 + CFS_SEAL_UUID_LEN];
        memcpy(hd, INFO_HDR, sizeof INFO_HDR - 1);
        memcpy(hd + sizeof INFO_HDR - 1, cand[j].hdr.shard_uuid, CFS_SEAL_UUID_LEN);
        int mac_ok = cfs_seal_hmac_sha256(ws + CFS_SEAL_UUID_LEN, CFS_SEAL_KEY_LEN,
                                          hd, sizeof hd, mac) == 0 &&
                     ct_eq(mac, cand[j].hdr.keyed_check, CFS_SEAL_KEYED_CHECK_LEN);
        cleanse(mac, sizeof mac);
        if (!mac_ok) { cleanse(ws, sizeof ws); continue; }

        if (!have_dek) {
            memcpy(start_uuid, ws, CFS_SEAL_UUID_LEN);
            memcpy(dek, ws + CFS_SEAL_UUID_LEN, CFS_SEAL_KEY_LEN);
            have_dek = 1;
        } else if (!ct_eq(dek, ws + CFS_SEAL_UUID_LEN, CFS_SEAL_KEY_LEN) ||
                   !ct_eq(start_uuid, ws, CFS_SEAL_UUID_LEN)) {
            ok = 0;                        /* shards disagree: not one set */
        }
        cleanse(ws, sizeof ws);
    }
    if (!have_dek) {
        ok = 0;
        fake_key("dek", sk, CFS_SEAL_KEY_LEN, dek);
        uint8_t tmp[CFS_SEAL_KEY_LEN];
        fake_key("uuid", sk, CFS_SEAL_KEY_LEN, tmp);
        memcpy(start_uuid, tmp, CFS_SEAL_UUID_LEN);
        cleanse(tmp, sizeof tmp);
    }

    /* ── ring keys and slot discovery ──────────────────────────────────── */
    uint8_t *ring_key = calloc(nplaus, CFS_SEAL_KEY_LEN);
    int *slot = malloc((size_t)N * sizeof *slot);
    int *is_member = calloc(N, sizeof *is_member);
    uint8_t *roots = calloc(nplaus, 32);
    if (!ring_key || !slot || !is_member || !roots) {
        free(ring_key); free(slot); free(is_member); free(roots); free(cand);
        cleanse(dek, sizeof dek); cleanse(sk, sizeof sk); cleanse(kdata, sizeof kdata);
        return CFS_SEAL_ENOMEM;
    }
    for (uint32_t i = 0; i < nplaus; i++)
        if (cfs_seal_subkey(dek, salt, CFS_SEAL_SALT_LEN, CFS_SEAL_SUB_RING, i,
                            ring_key + (size_t)i * CFS_SEAL_KEY_LEN) != 0)
            ok = 0;

    for (uint32_t j = 0; j < N; j++) {
        slot[j] = -1;
        if (!cand[j].plausible) continue;
        int found = -1;
        for (uint32_t i = 0; i < nplaus; i++) {
            uint8_t rl[CFS_SEAL_UUID_LEN + CFS_SEAL_KEY_LEN + 32];
            uint8_t nonce[CFS_SEAL_NONCE_LEN], raad[2 * CFS_SEAL_UUID_LEN];
            memcpy(raad, start_uuid, CFS_SEAL_UUID_LEN);
            memcpy(raad + CFS_SEAL_UUID_LEN, cand[j].hdr.shard_uuid, CFS_SEAL_UUID_LEN);
            make_nonce(nonce_prefix, CFS_SEAL_NONCE_IDX_RING, nonce);
            if (cfs_seal_gcm_open(ring_key + (size_t)i * CFS_SEAL_KEY_LEN, nonce,
                                  raad, sizeof raad, cand[j].hdr.ring_link,
                                  sizeof rl, cand[j].hdr.ring_link + sizeof rl,
                                  rl) != 0)
                continue;
            if (found >= 0) { found = -2; break; }   /* two slots claim it */
            found = (int)i;
            memcpy(roots + (size_t)i * 32,
                   rl + CFS_SEAL_UUID_LEN + CFS_SEAL_KEY_LEN, 32);
            cleanse(rl, sizeof rl);
        }
        if (found < 0) continue;
        slot[j] = found;
        is_member[j] = 1;
    }

    /* ── ring walk: start at start_uuid, every member exactly once ──────── */
    uint32_t members = 0;
    for (uint32_t j = 0; j < N; j++) if (is_member[j]) members++;

    int walk_ok = (members > 0);
    uint32_t *order = calloc(members ? members : 1, sizeof *order);
    if (!order) { walk_ok = 0; }
    else if (walk_ok) {
        int cur = -1;
        for (uint32_t j = 0; j < N; j++)
            if (is_member[j] && ct_eq(cand[j].hdr.shard_uuid, start_uuid, CFS_SEAL_UUID_LEN))
                cur = (int)j;
        if (cur < 0) walk_ok = 0;
        for (uint32_t step = 0; walk_ok && step < members; step++) {
            if (slot[cur] != (int)step) { walk_ok = 0; break; }
            order[step] = (uint32_t)cur;
            /* next_uuid is inside the ring link; re-open it (constant work). */
            uint8_t rl[CFS_SEAL_UUID_LEN + CFS_SEAL_KEY_LEN + 32];
            uint8_t nonce[CFS_SEAL_NONCE_LEN], raad[2 * CFS_SEAL_UUID_LEN];
            memcpy(raad, start_uuid, CFS_SEAL_UUID_LEN);
            memcpy(raad + CFS_SEAL_UUID_LEN, cand[cur].hdr.shard_uuid, CFS_SEAL_UUID_LEN);
            make_nonce(nonce_prefix, CFS_SEAL_NONCE_IDX_RING, nonce);
            if (cfs_seal_gcm_open(ring_key + (size_t)slot[cur] * CFS_SEAL_KEY_LEN,
                                  nonce, raad, sizeof raad,
                                  cand[cur].hdr.ring_link, sizeof rl,
                                  cand[cur].hdr.ring_link + sizeof rl, rl) != 0) {
                cleanse(rl, sizeof rl); walk_ok = 0; break;
            }
            /* K_{i+1} inside the link must equal the KDF's K_{i+1}. */
            uint32_t nxt_slot = ((uint32_t)slot[cur] + 1u) % members;
            if (!ct_eq(rl + CFS_SEAL_UUID_LEN,
                       ring_key + (size_t)nxt_slot * CFS_SEAL_KEY_LEN, CFS_SEAL_KEY_LEN)) {
                cleanse(rl, sizeof rl); walk_ok = 0; break;
            }
            int nxt = -1;
            for (uint32_t j = 0; j < N; j++)
                if (is_member[j] &&
                    ct_eq(cand[j].hdr.shard_uuid, rl, CFS_SEAL_UUID_LEN))
                    nxt = (int)j;
            cleanse(rl, sizeof rl);
            if (nxt < 0) { walk_ok = 0; break; }
            cur = nxt;
        }
        /* After `members` steps we must be back at the start. */
        if (walk_ok && cur >= 0 &&
            !ct_eq(cand[cur].hdr.shard_uuid, start_uuid, CFS_SEAL_UUID_LEN))
            walk_ok = 0;
    }
    if (!walk_ok) ok = 0;

    /* K_data, from the roots in walk order (which is slot order). */
    if (walk_ok && ok) {
        uint8_t *seq = malloc((size_t)members * 32);
        if (!seq) ok = 0;
        else {
            for (uint32_t i = 0; i < members; i++) {
                int j = (int)order[i];
                memcpy(seq + (size_t)i * 32, roots + (size_t)slot[j] * 32, 32);
            }
            if (derive_kdata(dek, salt, seq, members, kdata) != 0) ok = 0;
            free(seq);
        }
    }
    if (!walk_ok || !ok) fake_key("data", dek, CFS_SEAL_KEY_LEN, kdata);

    /* ── decrypt, verify, and reassemble ───────────────────────────────── */
    uint8_t *work = calloc(out_len ? out_len : 1, 1);
    uint8_t *block = malloc(CFS_SEAL_BLOCK_PLAIN);
    uint8_t *leaves = malloc((size_t)nblocks * 32);
    if (!work || !block || !leaves) {
        free(work); free(block); free(leaves);
        free(ring_key); free(slot); free(is_member);
        free(roots); free(order); free(cand);
        cleanse(dek, sizeof dek); cleanse(sk, sizeof sk); cleanse(kdata, sizeof kdata);
        return CFS_SEAL_ENOMEM;
    }
    size_t true_len = 0;
    int data_ok = ok && walk_ok;

    /* Every plausible shard is read and authenticated on both paths.  A
     * wrong key cannot close the ring, but it must still pay for the same
     * block reads and AEAD attempts — otherwise timing tells the caller
     * that the key was wrong before the decoy is ever produced (plan §6,
     * P6).  On the failure path the walk order is unavailable, so shards
     * are touched in set order; the byte count is identical. */
    {
        const uint32_t touch = walk_ok ? members : nplaus;
        for (uint32_t i = 0; i < touch; i++) {
            int j = walk_ok ? (int)order[i] : (int)plist[i];
            Cand *c = &cand[j];
            uint8_t nonce[CFS_SEAL_NONCE_LEN], aad[44];
            uint64_t shard_bytes = 0;

            for (uint32_t b = 0; b < c->nblocks; b++) {
                uint32_t idx = i * c->nblocks + b;
                const uint8_t *ct = set->shards[j].data + CFS_SEAL_HDR_SIZE +
                                    (size_t)b * CFS_SEAL_BLOCK_SIZE;
                make_block_aad(start_uuid, c->hdr.shard_uuid, idx, aad);
                make_nonce(nonce_prefix, idx, nonce);
                if (cfs_seal_gcm_open(kdata, nonce, aad, sizeof aad, ct,
                                      CFS_SEAL_BLOCK_PLAIN,
                                      ct + CFS_SEAL_BLOCK_PLAIN, block) != 0) {
                    data_ok = 0;   /* gcm_open already zeroed `block` */
                }
                /* Leaves are always computed, so a tampered block costs the
                 * same as a good one. */
                if (merkle_leaf(block, CFS_SEAL_BLOCK_PLAIN,
                                leaves + (size_t)b * 32) != 0)
                    data_ok = 0;

                uint64_t dlen = get_u64le(block + BO_DATALEN);
                uint32_t stored = get_u32le(block + BO_STORED);
                uint8_t ccodec = block[BO_CODEC];
                uint8_t *dst = work + ((size_t)i * c->nblocks + b) * CFS_SEAL_BLOCK_DATA;
                if (dlen > CFS_SEAL_BLOCK_DATA || stored > CFS_SEAL_BLOCK_DATA ||
                    stored > dlen) {
                    data_ok = 0;
                    dlen = 0;
                }
                /* Copy the whole payload slot unconditionally.  On the
                 * failure path this is zeros and gets thrown away, but it
                 * is the same memcpy the success path does — the cost of
                 * a failed decrypt must not be lower than a successful
                 * one (P6).  The slot is exactly BLOCK_DATA wide, so this
                 * never runs past `work`. */
                memcpy(dst, block + CFS_SEAL_BLOCK_FRAME, CFS_SEAL_BLOCK_DATA);
                if (data_ok && dlen) {
                    if (ccodec == 0) {
                        /* already copied */
                    } else if (ccodec == 1) {
                        size_t olen = (size_t)dlen;
                        if (!codec ||
                            codec(codec_ctx, block + CFS_SEAL_BLOCK_FRAME,
                                  stored, dst, (size_t)dlen, &olen) != 0 ||
                            olen != dlen)
                            data_ok = 0;
                    } else {
                        data_ok = 0;
                    }
                }
                if (data_ok) shard_bytes += dlen;
            }

            /* The root we just rebuilt from the recovered plaintext must be
             * the one committed in this shard's ring link. */
            uint8_t got[32];
            int mr = merkle_reduce(leaves, c->nblocks, got);
            if (walk_ok && (mr != 0 ||
                            !ct_eq(got, roots + (size_t)slot[j] * 32, 32)))
                data_ok = 0;

            if (walk_ok && data_ok) true_len += (size_t)shard_bytes;
        }
    }

    /* ── output ──────────────────────────────────────────────────────────
     *
     * The decoy is the answer to a wrong key, and it must be reproducible:
     * keyed from the start-key material that was actually available (a real
     * DEK when unwrapping worked, a deterministic stand-in when it did
     * not) and from the container's public nonce prefix.
     *
     * It is generated on *both* paths.  Skipping it on success would make
     * a correct key measurably faster than a wrong one as soon as the AEAD
     * work is balanced, which is exactly the oracle P6 forbids.  Both paths
     * also end with one full-buffer copy, for the same reason.
     */
    out->plain = malloc(out_len ? out_len : 1);
    if (!out->plain) {
        cleanse(work, out_len);
        free(work); free(block); free(leaves);
        free(ring_key); free(slot); free(is_member);
        free(roots); free(order); free(cand);
        cleanse(dek, sizeof dek); cleanse(sk, sizeof sk); cleanse(kdata, sizeof kdata);
        return CFS_SEAL_ENOMEM;
    }

    uint8_t decoy_key[CFS_SEAL_KEY_LEN], dnonce[CFS_SEAL_NONCE_LEN];
    memset(out->plain, 0, out_len);
    if (cfs_seal_subkey(dek, salt, CFS_SEAL_SALT_LEN, CFS_SEAL_SUB_DECOY, 0,
                        decoy_key) != 0) {
        memset(decoy_key, 0, sizeof decoy_key);
        data_ok = 0;
    }
    memset(dnonce, 0, sizeof dnonce);
    memcpy(dnonce, nonce_prefix, CFS_SEAL_NONCE_PREFIX_LEN);
    if (cfs_seal_chacha20(decoy_key, dnonce, 0, out->plain, out->plain,
                          out_len) != 0) {
        data_ok = 0;
        if (cfs_seal_random(out->plain, out_len) != 0)
            memset(out->plain, 0, out_len);
    }
    cleanse(decoy_key, sizeof decoy_key);

    if (data_ok) {
        memcpy(out->plain, work, out_len);
    } else {
        /* The success path just paid for a full-buffer copy; do the same
         * amount of work here so the two paths stay in step. */
        memcpy(work, out->plain, out_len);
        true_len = 0;
    }

    out->len = out_len;
    out->plain_len = data_ok ? true_len : 0;
    out->status = data_ok ? CFS_SEAL_OK : CFS_SEAL_EAUTH;

    cleanse(work, out_len);
    free(work); free(block); free(leaves);
    free(ring_key); free(slot); free(is_member);
    free(roots); free(order); free(cand);
    cleanse(sk, sizeof sk); cleanse(dek, sizeof dek); cleanse(kdata, sizeof kdata);
    return 0;
}

void cfs_seal_open_free(CfsSealOpenResult *r) {
    if (!r) return;
    if (r->plain) {
        cleanse(r->plain, r->len);
        free(r->plain);
    }
    memset(r, 0, sizeof *r);
}

void cfs_seal_free(CfsSealSet *set) {
    if (!set) return;
    if (set->shards) {
        for (uint32_t i = 0; i < set->nshards; i++) {
            if (set->shards[i].data) {
                cleanse(set->shards[i].data, set->shards[i].len);
                free(set->shards[i].data);
            }
        }
        free(set->shards);
    }
    memset(set, 0, sizeof *set);
}
