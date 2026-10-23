#ifndef CFS_SEAL_H
#define CFS_SEAL_H
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ── v9 sealed container: shard format and crypto core (S0 + S1) ──────────
 *
 * Spec: notes/v9-plan.md.  This file is the S0 (primitives) and S1 (format)
 * layer only: no FUSE/NBD, no on-disk file I/O — callers hand in shard
 * buffers and get shard buffers back, so the format can be exercised
 * entirely in memory and ported to a file backend later without touching
 * a byte of it.
 *
 * Threat model (plan §1) in one line: a shard set on untrusted storage,
 * with the key delivered out of band, must yield zero plaintext to anyone
 * who is missing a shard or has the wrong key — and must not be able to
 * tell those two cases apart from the tool's behaviour.
 *
 * ── Key hierarchy (plan §4) ──────────────────────────────────────────────
 *
 *   password --Argon2id(m,t,p)--> SK                    (kdf_id = 1)
 *   certificate --RSA-OAEP-256 / ECDH-ES+A256KW--> SK    (kdf_id = 2)
 *
 *   wrapped_start = AEAD(SK, {start_uuid, DEK})          48B + 16B tag = 64B
 *   K_i           = HKDF(DEK, salt, "cfs9:ring" || i)    one per ring slot
 *   ring_link     = AEAD(K_i, {next_uuid, K_{i+1}, root_i})  80B + 16B = 96B
 *   K_data        = HKDF(DEK, salt, "cfs9:data" || SHA256(root_0..root_{N-1}))
 *   decoy         = ChaCha20(HKDF(DEK, salt, "cfs9:decoy"), nonce_prefix)
 *   audit         = AEAD(HKDF(DEK, salt, "cfs9:audit"), ...)   (S2, derived
 *                                                                but unused)
 *   identity      = HMAC(DEK, "cfs9:id")[0..8]                 (S2/S3)
 *   keyed_check   = HMAC(DEK, "cfs9:hdr" || shard_uuid)[0..8]  (plan §3.1)
 *
 * "SK" is what plan §4 calls the password-derived KEK.  The plan also names
 * HKDF(DEK, salt, "cfs9:kek"); that subkey is derived and exported here but
 * is not on the S0/S1 data path — it is the re-wrap target for the keystore
 * layer (§4 "换口令 = 重包 DEK", which needs nothing but SK).
 *
 * Certificate mode: the 64-byte wrapped_start is still an AEAD box under a
 * per-container random SK, because 64 bytes cannot hold an RSA-OAEP or
 * ECDH-ES ciphertext of a 48-byte plaintext.  The certificate wraps SK
 * into the fixed 512-byte cert_wrap field that lives in what plan §3.1
 * leaves as header padding (offset 240).  Without a key that field is
 * pseudorandom in both modes, so it is not a mode oracle.
 *
 * ── Shard header: fixed 4 KiB, no cleartext magic (plan §3.1) ───────────
 *
 *   off  size  field
 *     0     1  version            (masked)
 *     1     1  flags              (masked)  bit0 = a codec was configured
 *     2     1  kdf_id             (masked)  1 = Argon2id, 2 = certificate
 *     3     1  rsv                (masked, random)
 *     4     4  kdf m_cost, KiB, LE(masked)
 *     8     2  kdf t_cost, LE     (masked)
 *    10     2  kdf lanes p, LE    (masked)
 *    12    32  salt                       NOT masked (must be readable to
 *                                          run Argon2id; random by nature)
 *    44    16  shard_uuid                 (masked)
 *    60    64  wrapped_start              (masked) AEAD ciphertext
 *   124     8  keyed_check                (masked) HMAC(DEK,"cfs9:hdr"||uuid)
 *   132    96  ring_link                  (masked) AEAD ciphertext
 *   228     8  nonce_prefix               (masked) per-container random
 *   236     1  block_shift = 16           (masked) 2^16 = 65536
 *   237     3  rsv                        (masked, random)
 *   240   512  cert_wrap                  (masked) cert-wrapped SK, padded
 *   752  3344  padding                    random
 *
 *  4096
 *
 * "Masked" means XOR with HKDF-SHA256(ikm = salt, info = "cfs9:hdr-mask").
 * This is obfuscation, not confidentiality: the mask key is derivable from
 * the salt in the clear, so an adversary who knows the format can recover
 * every field.  It exists so that no fixed byte pattern — not even a
 * version byte or a KDF parameter — identifies the file to a scanner, and
 * because plan §2's non-claims already concede that format-aware
 * adversaries are outside the indistinguishability claim.  Nothing in
 * P1–P7 relies on it; all authenticated fields are AEAD/MAC protected
 * under keys that are not in the header.
 *
 * ── Ring ────────────────────────────────────────────────────────────────
 *
 *   slot i (0..N-1) holds K_i = HKDF(DEK, "cfs9:ring"||u32le(i)) and a
 *   link to slot i+1 mod N.  wrapped_start carries start_uuid = slot 0's
 *   uuid, so the reader can find the start of the chain from any shard.
 *   A reader walks next_uuid through the candidate set and must visit
 *   every member exactly once and close the loop; a missing, duplicated
 *   or foreign shard breaks the walk, so the roots are incomplete and
 *   K_data is unavailable.
 *
 *   Links are per-shard and never replicated (plan §3.1): the copy of
 *   K_{i+1} in link_i is useless without shard i+1's header.
 *
 * ── AONT (plan §5) ──────────────────────────────────────────────────────
 *
 *   root_i is a Merkle root over shard i's plaintext blocks, computed at
 *   seal time and carried (encrypted) in link_i.  K_data is derived from
 *   the roots only after the whole ring has been walked.  Two consequences
 *   the caller must know:
 *
 *     - K_data cannot be derived from a partial shard set: the walk fails
 *       and cfs_seal_open() returns a decoy.  Same for a tampered header.
 *     - The roots are commitments held in the headers, so the derivation
 *       needs the ring links, not the block bytes.  A caller that writes
 *       its own reader and skips the verify-before-release rule could
 *       decrypt the shards it holds.  cfs_seal_open() never does: it
 *       decrypts everything, recomputes every root from the recovered
 *       plaintext, and only then reports success.  See the report's risk
 *       section.
 *
 * ── Blocks (plan §3.2, §3.3) ────────────────────────────────────────────
 *
 *   on disk, per shard: [4 KiB header][nblocks × 65536-byte blocks]
 *   block ciphertext : 65536 B = 16 B GCM tag + 65520 B plaintext
 *   block plaintext  : 16 B frame + up to 65504 B payload
 *   frame            : u64 data_len LE || u32 stored_len LE || u8 codec
 *                      || 3 B reserved
 *   nonce            : nonce_prefix[8] || block_idx[4]   (big-endian)
 *   AAD              : container_uuid[16] || shard_uuid[16]
 *                      || block_idx[4] BE || offset[8] BE
 *
 *   container_uuid is start_uuid (the ring's slot-0 uuid); offset is
 *   block_idx * CFS_SEAL_BLOCK_SIZE, the block's byte offset in the
 *   container's logical address space.  block_idx is global:
 *   slot * nblocks + local_block, so the same K_data never meets the same
 *   nonce twice across shards — the per-shard AAD alone would not prevent
 *   GCM nonce reuse.
 *
 *   Sizes are uniform (plan §3.3): every shard has the same block count and
 *   the same length, and plaintext is spread across slots in ring order.
 *   Compression, when configured, runs per block before encryption; a block
 *   that does not shrink is stored raw, which the frame's codec byte says.
 *
 * ── Behaviour (plan §6) ─────────────────────────────────────────────────
 *
 *   cfs_seal_open() reads every candidate header, runs the KDF once with
 *   the header's parameters, derives and walks the ring, reads and
 *   authenticates every block of every member, and always writes exactly
 *   the same number of output bytes.  On any failure it writes a
 *   deterministic ChaCha20 decoy stream keyed from the start key the
 *   caller actually supplied, so the same wrong key reproduces the same
 *   output.  The status word is for the caller's own audit log (S2) and
 *   must never reach the tool's user-visible output (plan §10).
 */

/* ─── on-disk geometry ─────────────────────────────────────────────────── */
#define CFS_SEAL_HDR_SIZE         4096u
#define CFS_SEAL_BLOCK_SIZE       65536u
#define CFS_SEAL_TAG_LEN          16u
#define CFS_SEAL_BLOCK_PLAIN      (CFS_SEAL_BLOCK_SIZE - CFS_SEAL_TAG_LEN) /* 65520 */
#define CFS_SEAL_BLOCK_FRAME      16u
#define CFS_SEAL_BLOCK_DATA       (CFS_SEAL_BLOCK_PLAIN - CFS_SEAL_BLOCK_FRAME) /* 65504 */

#define CFS_SEAL_SALT_LEN         32u
#define CFS_SEAL_UUID_LEN         16u
#define CFS_SEAL_KEY_LEN          32u
#define CFS_SEAL_NONCE_LEN        12u
#define CFS_SEAL_NONCE_PREFIX_LEN 8u
#define CFS_SEAL_WRAPPED_START_LEN 64u
#define CFS_SEAL_KEYED_CHECK_LEN  8u
#define CFS_SEAL_RING_LINK_LEN    96u
#define CFS_SEAL_CERT_WRAP_LEN    512u

/* Reserved nonce indices.  Data blocks may not use these. */
#define CFS_SEAL_NONCE_IDX_WRAPPED 0xFFFFFFFEu
#define CFS_SEAL_NONCE_IDX_RING    0xFFFFFFFFu
#define CFS_SEAL_MAX_BLOCK_IDX     (CFS_SEAL_NONCE_IDX_WRAPPED - 1u)

#define CFS_SEAL_MAX_SHARDS       64u
#define CFS_SEAL_VERSION          1u

/* flags */
#define CFS_SEAL_F_COMPRESSED     0x01u   /* a codec was configured at seal */

/* kdf_id */
#define CFS_SEAL_KDF_ARGON2ID     1u
#define CFS_SEAL_KDF_CERTIFICATE  2u

/* ─── S0: parameters ───────────────────────────────────────────────────── */
/* Argon2id cost.  m is KiB (256 MiB = 262144), the unit OpenSSL's ARGON2ID
 * and RFC 9106 both use.  `lanes` is Argon2's parallelism and changes the
 * output; `threads` is a performance hint only, so the implementation may
 * fall back to fewer threads without changing any derived key. */
typedef struct {
    uint32_t m_cost;    /* KiB */
    uint32_t t_cost;
    uint32_t lanes;     /* p */
} CfsSealKdfParams;

/* m=256 MiB, t=3, p=4 (plan §4). */
void cfs_seal_kdf_defaults(CfsSealKdfParams *p);

/* ─── S0: primitives ───────────────────────────────────────────────────── */

/* getrandom(2), retried over short reads and EINTR.  0 on success, -1 on
 * failure (never a truncated buffer). */
int cfs_seal_random(void *buf, size_t len);

/* Argon2id, 32-byte output, salt fixed at 32 bytes.  Returns 0 on success.
 * On failure the output is zeroed — OpenSSL leaves the buffer untouched
 * when the KDF refuses its parameters, and a stale key must never be used. */
int cfs_seal_argon2id(const void *password, size_t pwlen,
                      const uint8_t salt[CFS_SEAL_SALT_LEN],
                      const CfsSealKdfParams *params,
                      uint8_t out[CFS_SEAL_KEY_LEN]);

/* Same, exposing secret/ad for standard test vectors (RFC 9106). */
int cfs_seal_argon2id_ex(const void *password, size_t pwlen,
                         const void *salt, size_t saltlen,
                         const void *secret, size_t secretlen,
                         const void *ad, size_t adlen,
                         const CfsSealKdfParams *params,
                         uint8_t *out, size_t outlen);

/* HKDF-SHA256 (RFC 5869).  salt may be NULL/0 (treated as HashLen zeros),
 * info may be NULL/0.  outlen <= 255*32. */
int cfs_seal_hkdf(const void *ikm, size_t ikmlen,
                  const void *salt, size_t saltlen,
                  const void *info, size_t infolen,
                  uint8_t *out, size_t outlen);

/* The named subkeys of plan §4, all derived from the DEK.  `ring_index`
 * is used only by CFS_SEAL_SUB_RING; the others ignore it.  K_data is not
 * here because it folds in the shard roots (see cfs_seal_create/open).
 * CFS_SEAL_SUB_AUDIT is the AEAD key the S2 audit log will use; it is
 * derived and tested now so the hierarchy is fixed before that layer
 * lands. */
typedef enum {
    CFS_SEAL_SUB_KEK   = 0,   /* "cfs9:kek"    */
    CFS_SEAL_SUB_RING  = 1,   /* "cfs9:ring"||i */
    CFS_SEAL_SUB_AUDIT = 2,   /* "cfs9:audit"  */
    CFS_SEAL_SUB_DECOY = 3,   /* "cfs9:decoy"  */
} CfsSealSubkey;

int cfs_seal_subkey(const uint8_t dek[CFS_SEAL_KEY_LEN],
                    const void *salt, size_t saltlen,
                    CfsSealSubkey which, uint32_t ring_index,
                    uint8_t out[CFS_SEAL_KEY_LEN]);

/* Plan §4 identity tag: HMAC(DEK, "cfs9:id")[0..8].  Safe to show; it is
 * not a key and reveals nothing about the DEK. */
int cfs_seal_identity(const uint8_t dek[CFS_SEAL_KEY_LEN], uint8_t out[8]);

int cfs_seal_sha256(const void *data, size_t len, uint8_t out[32]);
int cfs_seal_hmac_sha256(const void *key, size_t keylen,
                         const void *data, size_t len, uint8_t out[32]);

/* AES-256-GCM.  `ct` may alias `pt`; `pt` may be NULL when ptlen is 0.
 * Seal writes ptlen bytes to ct plus a 16-byte tag.  Open returns 0 only
 * when the tag verifies (OpenSSL compares it in constant time) and never
 * leaves unauthenticated plaintext in `pt` on failure — the buffer is
 * zeroed, so a caller that ignores the return value still gets no data. */
int cfs_seal_gcm_seal(const uint8_t key[CFS_SEAL_KEY_LEN],
                      const uint8_t nonce[CFS_SEAL_NONCE_LEN],
                      const void *aad, size_t aadlen,
                      const void *pt, size_t ptlen,
                      void *ct, uint8_t tag[CFS_SEAL_TAG_LEN]);
int cfs_seal_gcm_open(const uint8_t key[CFS_SEAL_KEY_LEN],
                      const uint8_t nonce[CFS_SEAL_NONCE_LEN],
                      const void *aad, size_t aadlen,
                      const void *ct, size_t ctlen,
                      const uint8_t tag[CFS_SEAL_TAG_LEN],
                      void *pt);

/* ChaCha20 keystream XOR.  `counter` is the initial block counter; the
 * 12-byte nonce is the IETF (RFC 8439) layout.  in/out may alias. */
int cfs_seal_chacha20(const uint8_t key[CFS_SEAL_KEY_LEN],
                      const uint8_t nonce[CFS_SEAL_NONCE_LEN],
                      uint32_t counter,
                      const void *in, void *out, size_t len);

/* Certificate wrap of a 32-byte start key.  The PEM file may hold an RSA
 * public key (wrapped with RSA-OAEP-SHA256) or an EC public key (wrapped
 * with ECDH-ES + AES-256 key wrap); the kind is recorded in the blob.
 * `out` must have room for CFS_SEAL_MAX_CERT_BLOB (see below); *outlen is
 * the blob length.  RSA keys whose OAEP ciphertext exceeds the blob are
 * refused (RSA-2048/3072 fit, RSA-4096 does not). */
#define CFS_SEAL_MAX_CERT_BLOB    508u
int cfs_seal_cert_wrap(const char *pubkey_pem,
                       const uint8_t *in, size_t inlen,
                       uint8_t *out, size_t *outlen);
int cfs_seal_cert_unwrap(const char *privkey_pem,
                         const uint8_t *in, size_t inlen,
                         uint8_t *out, size_t *outlen);

/* ─── S1: format ───────────────────────────────────────────────────────── */

typedef struct {
    uint8_t *data;      /* HDR + nblocks*BLOCK bytes */
    size_t   len;
} CfsSealShard;

typedef struct {
    CfsSealShard *shards;
    uint32_t      nshards;
} CfsSealSet;

/* Optional per-block codec.  Called with outcap bytes of room; must set
 * *outlen and return 0, or return -1 to decline (the block is then stored
 * raw).  Compression happens before encryption and decompression after
 * decryption — the order is not negotiable. */
typedef int (*CfsSealCodec)(void *ctx, const uint8_t *in, size_t inlen,
                            uint8_t *out, size_t outcap, size_t *outlen);

typedef struct {
    uint32_t         nshards;
    CfsSealKdfParams kdf;
    const void      *password;      /* NULL when cert_pub_pem is set */
    size_t           password_len;
    const char      *cert_pub_pem;  /* certificate mode when non-NULL */
    CfsSealCodec     codec;         /* NULL = no compression */
    void            *codec_ctx;
} CfsSealCreateOpts;

typedef enum {
    CFS_SEAL_OK      =  0,
    CFS_SEAL_EAUTH   = -1,   /* no key / missing shard / tampered: decoy */
    CFS_SEAL_EARG    = -2,
    CFS_SEAL_ENOMEM  = -3,
    CFS_SEAL_ECRYPTO = -4,
    CFS_SEAL_EFORMAT = -5,   /* shard set is not even structurally valid */
} CfsSealStatus;

/* Seal `len` bytes into `o->nshards` shards.  Every shard is the same
 * length; the library allocates them and cfs_seal_free() releases them.
 * The caller's plaintext is split across slots in ring order. */
int cfs_seal_create(const CfsSealCreateOpts *o,
                    const void *plain, size_t len, CfsSealSet *out);

typedef struct {
    CfsSealStatus status;
    uint8_t      *plain;      /* always nblocks_total * CFS_SEAL_BLOCK_DATA
                                 bytes: real plaintext, or the decoy */
    size_t        len;        /* bytes written, same on success and decoy */
    size_t        plain_len;  /* true plaintext length; 0 unless OK */
} CfsSealOpenResult;

/* Open a candidate shard set.  Exactly one of password / cert_priv_pem is
 * used, matching the mode recorded in the header.  `set` may contain
 * non-member shards; they are read and rejected.  On anything other than
 * CFS_SEAL_OK the result holds the decoy stream and plain_len is 0.
 * Returns 0 when the call itself succeeded (including EAUTH), negative on
 * argument/allocation errors. */
int cfs_seal_open(const CfsSealSet *set,
                  const char *cert_priv_pem,
                  const void *password, size_t password_len,
                  CfsSealCodec codec, void *codec_ctx,
                  CfsSealOpenResult *out);

void cfs_seal_open_free(CfsSealOpenResult *r);
void cfs_seal_free(CfsSealSet *set);

#ifdef __cplusplus
}
#endif
#endif /* CFS_SEAL_H */
