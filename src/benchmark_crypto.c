/*
 * =============================================================================
 * Pure Cryptographic Operations Benchmark
 * =============================================================================
 *
 * Benchmarks individual cryptographic primitives WITHOUT EDHOC and WITHOUT
 * sockets.  Measures raw algorithm performance for:
 *
 *   Classical (libsodium):
 *     - X25519          : DH key exchange (Curve25519)
 *     - Ed25519         : EdDSA signature scheme
 *
 *   Post-Quantum (PQClean):
 *     - ML-KEM-768      : Key Encapsulation Mechanism (NIST Level 3)
 *     - ML-DSA-65       : Digital Signature (NIST Level 3)
 *
 *   Hybrid (libsodium + PQClean):
 *     - X25519+ML-KEM-768 : Combined classical + PQ key exchange
 *
 * Columns: X25519 | Ed25519 | ML-KEM-768 | ML-DSA-65 | X25519+ML-KEM-768
 *
 * Rows (operations):
 *   Keygen, Encap/DH, Decap/DH, Signature, Verification,
 *   HKDF-Extract, HKDF-Expand, Hash (SHA-256), AEAD Encrypt, AEAD Decrypt,
 *   Key Exchange (full), Shared Secret Derivation
 *
 * Output: CSV file at output/benchmark_crypto_ops.csv
 *
 * =============================================================================
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <sys/stat.h>

/* ── libsodium ─────────────────────────────────────────────────────────────── */
#include <sodium.h>

/* ── PQClean ML-KEM-768 ───────────────────────────────────────────────────── */
#include "crypto_kem/ml-kem-768/clean/api.h"

/* ── PQClean ML-DSA-65 ────────────────────────────────────────────────────── */
#include "crypto_sign/ml-dsa-65/clean/api.h"

/* ==========================================================================
 * Configuration
 * ========================================================================== */
#define BENCH_ITERATIONS  1000000 /* iterations per operation                  */
#define WARMUP_ITERATIONS 1000    /* warmup rounds (discarded)                 */
#define MSG_LEN           64     /* message length for sign/hash/aead         */
#define AAD_LEN           16     /* additional authenticated data length      */
#define HKDF_IKM_LEN      32    /* input keying material length              */
#define HKDF_INFO_LEN     10    /* info string length                        */
#define HKDF_OKM_LEN      32    /* output keying material length             */

#define OUTPUT_DIR        "output"
#define OUTPUT_FILE       OUTPUT_DIR "/benchmark_crypto_ops.csv"

/* ==========================================================================
 * Column identifiers
 * ========================================================================== */
enum algo_col {
    COL_X25519 = 0,
    COL_ED25519,
    COL_MLKEM768,
    COL_MLDSA65,
    COL_HYBRID,       /* X25519 + ML-KEM-768 */
    NUM_COLS
};

static const char *col_names[NUM_COLS] = {
    "X25519",
    "Ed25519",
    "ML-KEM-768",
    "ML-DSA-65",
    "X25519+ML-KEM-768"
};

/* ==========================================================================
 * Row identifiers (operations)
 * ========================================================================== */
enum op_row {
    ROW_KEYGEN = 0,
    ROW_ENCAP,          /* Encap / DH compute */
    ROW_DECAP,          /* Decap / DH compute (other side) */
    ROW_SIGNATURE,
    ROW_VERIFICATION,
    ROW_HKDF_EXTRACT,
    ROW_HKDF_EXPAND,
    ROW_HASH,
    ROW_AEAD_ENCRYPT,
    ROW_AEAD_DECRYPT,
    ROW_KEY_EXCHANGE,   /* Full key exchange (both sides) */
    ROW_SECRET_DERIVE,  /* Shared secret derivation (HKDF Extract+Expand) */
    NUM_ROWS
};

static const char *row_names[NUM_ROWS] = {
    "Keygen",
    "Encap",
    "Decap",
    "Signature",
    "Verification",
    "HKDF-Extract",
    "HKDF-Expand",
    "Hash (SHA-256)",
    "AEAD Encrypt",
    "AEAD Decrypt",
    "Key Exchange (full)",
    "Shared Secret Derivation"
};

/* ==========================================================================
 * Result table: avg_us[row][col], stddev_us[row][col]
 *  -1.0 means "N/A" (operation not applicable for that algorithm)
 * ========================================================================== */
static double avg_us[NUM_ROWS][NUM_COLS];
static double stddev_us[NUM_ROWS][NUM_COLS];
static double min_us[NUM_ROWS][NUM_COLS];
static double max_us[NUM_ROWS][NUM_COLS];
static double median_us[NUM_ROWS][NUM_COLS];

/* ==========================================================================
 * Key / artifact lengths (bytes) per [operation][algorithm].
 *   -1 means N/A (operation not applicable for that algorithm).
 *   For keygen: public key length.
 *   For encap/decap: ciphertext length.
 *   For signature: signature length.
 *   For verification: public key length.
 *   For symmetric ops: key/hash length.
 *   For key exchange: combined public key length (both sides).
 *   For secret derivation: output keying material length.
 * ========================================================================== */
static int key_length_bytes[NUM_ROWS][NUM_COLS];

static void init_key_lengths(void)
{
    /* Default: -1 = N/A (will be overwritten by valid entries) */
    for (int r = 0; r < NUM_ROWS; r++)
        for (int c = 0; c < NUM_COLS; c++)
            key_length_bytes[r][c] = -1;

    /* ── Public key sizes (Keygen) ─────────────────────────────────────── */
    key_length_bytes[ROW_KEYGEN][COL_X25519]  = crypto_scalarmult_curve25519_BYTES;           /* 32 */
    key_length_bytes[ROW_KEYGEN][COL_ED25519] = crypto_sign_ed25519_PUBLICKEYBYTES;           /* 32 */
    key_length_bytes[ROW_KEYGEN][COL_MLKEM768]= PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES; /* 1184 */
    key_length_bytes[ROW_KEYGEN][COL_MLDSA65] = PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES;  /* 1952 */
    key_length_bytes[ROW_KEYGEN][COL_HYBRID]  = crypto_scalarmult_curve25519_BYTES
                                              + PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES;  /* 32+1184=1216 */

    /* ── Encap / Shared secret compute: ciphertext or shared secret length ─ */
    key_length_bytes[ROW_ENCAP][COL_X25519]  = crypto_scalarmult_curve25519_BYTES;             /* 32 (shared secret) */
    key_length_bytes[ROW_ENCAP][COL_MLKEM768]= PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES;  /* 1088 */
    key_length_bytes[ROW_ENCAP][COL_HYBRID]  = crypto_scalarmult_curve25519_BYTES
                                             + PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES;   /* 32+1088=1120 */

    /* ── Decap: same as encap (ciphertext input) ─────────────────────── */
    key_length_bytes[ROW_DECAP][COL_X25519]  = crypto_scalarmult_curve25519_BYTES;
    key_length_bytes[ROW_DECAP][COL_MLKEM768]= PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    key_length_bytes[ROW_DECAP][COL_HYBRID]  = crypto_scalarmult_curve25519_BYTES
                                             + PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES;

    /* ── Signature: signature length ─────────────────────────────────── */
    key_length_bytes[ROW_SIGNATURE][COL_ED25519] = crypto_sign_ed25519_BYTES;                  /* 64 */
    key_length_bytes[ROW_SIGNATURE][COL_MLDSA65] = PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES;        /* 3309 */

    /* ── Verification: public key length ─────────────────────────────── */
    key_length_bytes[ROW_VERIFICATION][COL_ED25519] = crypto_sign_ed25519_PUBLICKEYBYTES;      /* 32 */
    key_length_bytes[ROW_VERIFICATION][COL_MLDSA65] = PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES; /* 1952 */

    /* ── Symmetric operations: same key/output length across all columns ─ */
    for (int c = 0; c < NUM_COLS; c++) {
        key_length_bytes[ROW_HKDF_EXTRACT][c]  = 32;   /* PRK output = 32 bytes */
        key_length_bytes[ROW_HKDF_EXPAND][c]   = HKDF_OKM_LEN; /* OKM = 32 bytes */
        key_length_bytes[ROW_HASH][c]           = crypto_hash_sha256_BYTES; /* 32 */
        key_length_bytes[ROW_AEAD_ENCRYPT][c]   = crypto_aead_xchacha20poly1305_ietf_KEYBYTES; /* 32 */
        key_length_bytes[ROW_AEAD_DECRYPT][c]   = crypto_aead_xchacha20poly1305_ietf_KEYBYTES; /* 32 */
    }

    /* ── Key Exchange (full): combined public key length (both DH/KEM) ─ */
    key_length_bytes[ROW_KEY_EXCHANGE][COL_X25519]  = crypto_scalarmult_curve25519_BYTES;       /* 32 */
    key_length_bytes[ROW_KEY_EXCHANGE][COL_MLKEM768]= PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES; /* 1184 */
    key_length_bytes[ROW_KEY_EXCHANGE][COL_HYBRID]  = crypto_scalarmult_curve25519_BYTES
                                                    + PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES;

    /* ── Shared Secret Derivation: output length ─────────────────────── */
    key_length_bytes[ROW_SECRET_DERIVE][COL_X25519]  = HKDF_OKM_LEN; /* 32 */
    key_length_bytes[ROW_SECRET_DERIVE][COL_MLKEM768]= HKDF_OKM_LEN;
    key_length_bytes[ROW_SECRET_DERIVE][COL_HYBRID]  = HKDF_OKM_LEN;
}

/* ==========================================================================
 * Timing helpers
 * ========================================================================== */
static inline uint64_t get_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int cmp_double(const void *a, const void *b)
{
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

/* Run a benchmark: call `fn` BENCH_ITERATIONS times, store timings.
 * Uses reservoir of RESERVOIR_SIZE samples for median to limit memory.
 * Reports progress every PROGRESS_INTERVAL iterations. */
typedef void (*bench_fn)(void *ctx);

#define RESERVOIR_SIZE    100000   /* samples kept for median/percentile   */
#define PROGRESS_INTERVAL 100000   /* report every N iterations            */

static int  bench_op_counter = 0;  /* global operation counter for display */
static int  bench_op_total   = 0;

static void run_bench(bench_fn fn, void *ctx, int row, int col)
{
    bench_op_counter++;

    /* Reservoir for median (capped to save RAM at 1M iterations) */
    int res_cap = (BENCH_ITERATIONS < RESERVOIR_SIZE)
                    ? BENCH_ITERATIONS : RESERVOIR_SIZE;
    double *reservoir = (double *)malloc(res_cap * sizeof(double));
    if (!reservoir) { perror("malloc"); exit(1); }

    /* Warmup */
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        fn(ctx);
    }

    /* Measure */
    double sum = 0.0, sum_sq = 0.0;
    double mn = 1e18, mx = 0.0;
    uint64_t wall_start = get_ns();

    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        uint64_t t0 = get_ns();
        fn(ctx);
        uint64_t t1 = get_ns();
        double us = (double)(t1 - t0) / 1000.0;  /* ns → µs */
        sum    += us;
        sum_sq += us * us;
        if (us < mn) mn = us;
        if (us > mx) mx = us;

        /* Reservoir sampling (Algorithm R) for median */
        if (i < res_cap) {
            reservoir[i] = us;
        } else {
            /* Replace element with decreasing probability */
            long r = rand() % (i + 1);
            if (r < res_cap)
                reservoir[r] = us;
        }

        /* Progress report */
        if ((i + 1) % PROGRESS_INTERVAL == 0) {
            double elapsed_s = (double)(get_ns() - wall_start) / 1e9;
            double pct = (double)(i + 1) / BENCH_ITERATIONS * 100.0;
            double eta_s = elapsed_s / (i + 1) * (BENCH_ITERATIONS - i - 1);
            printf("\r    [%d/%d] %-24s %-18s %6.1f%%  (%.0fs elapsed, ETA %.0fs)   ",
                   bench_op_counter, bench_op_total,
                   row_names[row], col_names[col], pct, elapsed_s, eta_s);
            fflush(stdout);
        }
    }

    double wall_total = (double)(get_ns() - wall_start) / 1e9;
    printf("\r    [%d/%d] %-24s %-18s  done  (%.1fs)                          \n",
           bench_op_counter, bench_op_total,
           row_names[row], col_names[col], wall_total);
    fflush(stdout);

    double mean = sum / BENCH_ITERATIONS;
    double variance = (sum_sq / BENCH_ITERATIONS) - (mean * mean);
    if (variance < 0.0) variance = 0.0;  /* numerical guard */

    /* Median from reservoir */
    qsort(reservoir, res_cap, sizeof(double), cmp_double);
    double med;
    if (res_cap % 2 == 0)
        med = (reservoir[res_cap/2 - 1] + reservoir[res_cap/2]) / 2.0;
    else
        med = reservoir[res_cap / 2];

    avg_us[row][col]    = mean;
    stddev_us[row][col] = sqrt(variance);
    min_us[row][col]    = mn;
    max_us[row][col]    = mx;
    median_us[row][col] = med;

    free(reservoir);
}

static void mark_na(int row, int col)
{
    avg_us[row][col]    = -1.0;
    stddev_us[row][col] = -1.0;
    min_us[row][col]    = -1.0;
    max_us[row][col]    = -1.0;
    median_us[row][col] = -1.0;
}

/* ==========================================================================
 * HKDF-SHA256 implementation using libsodium HMAC-SHA256
 * (libsodium 1.0.18 does not include HKDF natively)
 * ========================================================================== */
static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[32])
{
    crypto_auth_hmacsha256_state st;
    /* If key > 64 bytes, hash it first per HMAC spec.
       libsodium's init takes key directly. */
    crypto_auth_hmacsha256_init(&st, key, key_len);
    crypto_auth_hmacsha256_update(&st, data, data_len);
    crypto_auth_hmacsha256_final(&st, out);
}

static void hkdf_extract_sha256(const uint8_t *salt, size_t salt_len,
                                const uint8_t *ikm, size_t ikm_len,
                                uint8_t prk[32])
{
    if (salt == NULL || salt_len == 0) {
        uint8_t zero_salt[32];
        memset(zero_salt, 0, 32);
        hmac_sha256(zero_salt, 32, ikm, ikm_len, prk);
    } else {
        hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    }
}

static void hkdf_expand_sha256(const uint8_t prk[32],
                               const uint8_t *info, size_t info_len,
                               uint8_t *okm, size_t okm_len)
{
    uint8_t t[32];
    size_t done = 0;
    uint8_t counter = 1;
    size_t t_len = 0;

    while (done < okm_len) {
        crypto_auth_hmacsha256_state st;
        crypto_auth_hmacsha256_init(&st, prk, 32);
        if (t_len > 0)
            crypto_auth_hmacsha256_update(&st, t, t_len);
        crypto_auth_hmacsha256_update(&st, info, info_len);
        crypto_auth_hmacsha256_update(&st, &counter, 1);
        crypto_auth_hmacsha256_final(&st, t);
        t_len = 32;

        size_t chunk = okm_len - done;
        if (chunk > 32) chunk = 32;
        memcpy(okm + done, t, chunk);
        done += chunk;
        counter++;
    }
}

/* ==========================================================================
 * Benchmark contexts — hold pre-computed keys/data for each operation
 * ========================================================================== */

/* ── X25519 context ──────────────────────────────────────────────────────── */
typedef struct {
    uint8_t sk_a[crypto_scalarmult_curve25519_SCALARBYTES];
    uint8_t pk_a[crypto_scalarmult_curve25519_BYTES];
    uint8_t sk_b[crypto_scalarmult_curve25519_SCALARBYTES];
    uint8_t pk_b[crypto_scalarmult_curve25519_BYTES];
    uint8_t shared[crypto_scalarmult_curve25519_BYTES];
    /* For HKDF/Hash/AEAD — libsodium uses XChaCha20-Poly1305 */
    uint8_t msg[MSG_LEN];
    uint8_t aad[AAD_LEN];
    uint8_t ikm[HKDF_IKM_LEN];
    uint8_t salt[32];
    uint8_t prk[32];
    uint8_t info[HKDF_INFO_LEN];
    uint8_t okm[HKDF_OKM_LEN];
    uint8_t aead_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    uint8_t aead_nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    uint8_t ct[MSG_LEN + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned long long ct_len;
    uint8_t pt[MSG_LEN];
    unsigned long long pt_len;
    uint8_t hash_out[crypto_hash_sha256_BYTES];
} x25519_ctx_t;

/* ── Ed25519 context ─────────────────────────────────────────────────────── */
typedef struct {
    uint8_t pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_ed25519_SECRETKEYBYTES];
    uint8_t msg[MSG_LEN];
    uint8_t sig[crypto_sign_ed25519_BYTES];
    unsigned long long sig_len;
    /* Ed25519 also gets HKDF/Hash/AEAD for completeness */
    uint8_t ikm[HKDF_IKM_LEN];
    uint8_t salt[32];
    uint8_t prk[32];
    uint8_t info[HKDF_INFO_LEN];
    uint8_t okm[HKDF_OKM_LEN];
    uint8_t aead_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    uint8_t aead_nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    uint8_t aad[AAD_LEN];
    uint8_t ct[MSG_LEN + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned long long ct_len;
    uint8_t pt[MSG_LEN];
    unsigned long long pt_len;
    uint8_t hash_out[crypto_hash_sha256_BYTES];
} ed25519_ctx_t;

/* ── ML-KEM-768 context ──────────────────────────────────────────────────── */
typedef struct {
    uint8_t pk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ct[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss_enc[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    uint8_t ss_dec[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    /* Symmetric ops use SHA-256 + AES-256-GCM (or XChaCha20-Poly1305 fallback) */
    uint8_t msg[MSG_LEN];
    uint8_t aad[AAD_LEN];
    uint8_t ikm[HKDF_IKM_LEN];
    uint8_t salt[32];
    uint8_t prk[32];
    uint8_t info[HKDF_INFO_LEN];
    uint8_t okm[HKDF_OKM_LEN];
    uint8_t hash_out[32];
    /* AEAD: AES-256-GCM if available, else XChaCha20-Poly1305 */
    uint8_t aead_key[32];    /* max(AES-256-GCM key=32, XChaCha20 key=32) */
    uint8_t aead_nonce[24];  /* max(AES-256-GCM nonce=12, XChaCha20 nonce=24) */
    uint8_t ct_aead[MSG_LEN + 16 + 8]; /* max tag overhead */
    unsigned long long ct_aead_len;
    uint8_t pt_aead[MSG_LEN];
    unsigned long long pt_aead_len;
} mlkem_ctx_t;

/* ── ML-DSA-65 context ───────────────────────────────────────────────────── */
typedef struct {
    uint8_t pk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t msg[MSG_LEN];
    uint8_t sig[PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES];
    size_t  sig_len;
    /* Same symmetric ops */
    uint8_t ikm[HKDF_IKM_LEN];
    uint8_t salt[32];
    uint8_t prk[32];
    uint8_t info[HKDF_INFO_LEN];
    uint8_t okm[HKDF_OKM_LEN];
    uint8_t hash_out[32];
    uint8_t aad[AAD_LEN];
    uint8_t aead_key[32];
    uint8_t aead_nonce[24];
    uint8_t ct_aead[MSG_LEN + 16 + 8];
    unsigned long long ct_aead_len;
    uint8_t pt_aead[MSG_LEN];
    unsigned long long pt_aead_len;
} mldsa_ctx_t;

/* ── Hybrid context (X25519 + ML-KEM-768) ────────────────────────────────── */
typedef struct {
    /* X25519 part */
    uint8_t x_sk_a[crypto_scalarmult_curve25519_SCALARBYTES];
    uint8_t x_pk_a[crypto_scalarmult_curve25519_BYTES];
    uint8_t x_sk_b[crypto_scalarmult_curve25519_SCALARBYTES];
    uint8_t x_pk_b[crypto_scalarmult_curve25519_BYTES];
    uint8_t x_shared[crypto_scalarmult_curve25519_BYTES];
    /* ML-KEM part */
    uint8_t kem_pk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t kem_sk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t kem_ct[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t kem_ss_enc[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    uint8_t kem_ss_dec[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    /* Combined shared secret */
    uint8_t combined_ss[64];  /* x_shared || kem_ss → 32+32 */
    uint8_t derived_key[32];  /* HKDF output */
    /* Symmetric */
    uint8_t msg[MSG_LEN];
    uint8_t aad[AAD_LEN];
    uint8_t ikm[HKDF_IKM_LEN];
    uint8_t salt[32];
    uint8_t prk[32];
    uint8_t info[HKDF_INFO_LEN];
    uint8_t okm[HKDF_OKM_LEN];
    uint8_t hash_out[32];
    uint8_t aead_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    uint8_t aead_nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    uint8_t ct_aead[MSG_LEN + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned long long ct_aead_len;
    uint8_t pt_aead[MSG_LEN];
    unsigned long long pt_aead_len;
} hybrid_ctx_t;

/* ==========================================================================
 * X25519 benchmark functions
 * ========================================================================== */
static x25519_ctx_t x_ctx;

static void x25519_bench_keygen(void *ctx)
{
    (void)ctx;
    x25519_ctx_t *c = &x_ctx;
    randombytes_buf(c->sk_a, sizeof(c->sk_a));
    crypto_scalarmult_curve25519_base(c->pk_a, c->sk_a);
}

static void x25519_bench_encap(void *ctx)
{
    /* "Encap" for DH = compute DH from A's side: shared = sk_a * pk_b */
    (void)ctx;
    x25519_ctx_t *c = &x_ctx;
    crypto_scalarmult_curve25519(c->shared, c->sk_a, c->pk_b);
}

static void x25519_bench_decap(void *ctx)
{
    /* "Decap" for DH = compute DH from B's side: shared = sk_b * pk_a */
    (void)ctx;
    x25519_ctx_t *c = &x_ctx;
    crypto_scalarmult_curve25519(c->shared, c->sk_b, c->pk_a);
}

static void x25519_bench_hkdf_extract(void *ctx)
{
    (void)ctx;
    x25519_ctx_t *c = &x_ctx;
    hkdf_extract_sha256(c->salt, 32, c->ikm, HKDF_IKM_LEN, c->prk);
}

static void x25519_bench_hkdf_expand(void *ctx)
{
    (void)ctx;
    x25519_ctx_t *c = &x_ctx;
    hkdf_expand_sha256(c->prk, c->info, HKDF_INFO_LEN, c->okm, HKDF_OKM_LEN);
}

static void x25519_bench_hash(void *ctx)
{
    (void)ctx;
    x25519_ctx_t *c = &x_ctx;
    crypto_hash_sha256(c->hash_out, c->msg, MSG_LEN);
}

static void x25519_bench_aead_enc(void *ctx)
{
    (void)ctx;
    x25519_ctx_t *c = &x_ctx;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        c->ct, &c->ct_len,
        c->msg, MSG_LEN,
        c->aad, AAD_LEN,
        NULL,
        c->aead_nonce, c->aead_key);
}

static void x25519_bench_aead_dec(void *ctx)
{
    (void)ctx;
    x25519_ctx_t *c = &x_ctx;
    crypto_aead_xchacha20poly1305_ietf_decrypt(
        c->pt, &c->pt_len,
        NULL,
        c->ct, c->ct_len,
        c->aad, AAD_LEN,
        c->aead_nonce, c->aead_key);
}

static void x25519_bench_key_exchange(void *ctx)
{
    /* Full key exchange: keygen A, keygen B, DH both sides */
    (void)ctx;
    x25519_ctx_t *c = &x_ctx;
    uint8_t ska[32], pka[32], skb[32], pkb[32], sa[32], sb[32];
    randombytes_buf(ska, 32);
    crypto_scalarmult_curve25519_base(pka, ska);
    randombytes_buf(skb, 32);
    crypto_scalarmult_curve25519_base(pkb, skb);
    crypto_scalarmult_curve25519(sa, ska, pkb);
    crypto_scalarmult_curve25519(sb, skb, pka);
    (void)sa; (void)sb;
}

static void x25519_bench_secret_derive(void *ctx)
{
    /* HKDF Extract + Expand on the DH shared secret */
    (void)ctx;
    x25519_ctx_t *c = &x_ctx;
    uint8_t prk[32], okm[32];
    hkdf_extract_sha256(c->salt, 32, c->shared, 32, prk);
    hkdf_expand_sha256(prk, c->info, HKDF_INFO_LEN, okm, 32);
    (void)okm;
}

/* ==========================================================================
 * Ed25519 benchmark functions
 * ========================================================================== */
static ed25519_ctx_t ed_ctx;

static void ed25519_bench_sign(void *ctx)
{
    (void)ctx;
    ed25519_ctx_t *c = &ed_ctx;
    crypto_sign_ed25519_detached(c->sig, &c->sig_len, c->msg, MSG_LEN, c->sk);
}

static void ed25519_bench_verify(void *ctx)
{
    (void)ctx;
    ed25519_ctx_t *c = &ed_ctx;
    crypto_sign_ed25519_verify_detached(c->sig, c->msg, MSG_LEN, c->pk);
}

static void ed25519_bench_hkdf_extract(void *ctx)
{
    (void)ctx;
    ed25519_ctx_t *c = &ed_ctx;
    hkdf_extract_sha256(c->salt, 32, c->ikm, HKDF_IKM_LEN, c->prk);
}

static void ed25519_bench_hkdf_expand(void *ctx)
{
    (void)ctx;
    ed25519_ctx_t *c = &ed_ctx;
    hkdf_expand_sha256(c->prk, c->info, HKDF_INFO_LEN, c->okm, HKDF_OKM_LEN);
}

static void ed25519_bench_hash(void *ctx)
{
    (void)ctx;
    ed25519_ctx_t *c = &ed_ctx;
    crypto_hash_sha256(c->hash_out, c->msg, MSG_LEN);
}

static void ed25519_bench_aead_enc(void *ctx)
{
    (void)ctx;
    ed25519_ctx_t *c = &ed_ctx;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        c->ct, &c->ct_len,
        c->msg, MSG_LEN,
        c->aad, AAD_LEN,
        NULL,
        c->aead_nonce, c->aead_key);
}

static void ed25519_bench_aead_dec(void *ctx)
{
    (void)ctx;
    ed25519_ctx_t *c = &ed_ctx;
    crypto_aead_xchacha20poly1305_ietf_decrypt(
        c->pt, &c->pt_len,
        NULL,
        c->ct, c->ct_len,
        c->aad, AAD_LEN,
        c->aead_nonce, c->aead_key);
}

/* ==========================================================================
 * ML-KEM-768 benchmark functions
 * ========================================================================== */
static mlkem_ctx_t mk_ctx;

static void mlkem_bench_keygen(void *ctx)
{
    (void)ctx;
    mlkem_ctx_t *c = &mk_ctx;
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(c->pk, c->sk);
}

static void mlkem_bench_encap(void *ctx)
{
    (void)ctx;
    mlkem_ctx_t *c = &mk_ctx;
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(c->ct, c->ss_enc, c->pk);
}

static void mlkem_bench_decap(void *ctx)
{
    (void)ctx;
    mlkem_ctx_t *c = &mk_ctx;
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(c->ss_dec, c->ct, c->sk);
}

static void mlkem_bench_hkdf_extract(void *ctx)
{
    (void)ctx;
    mlkem_ctx_t *c = &mk_ctx;
    hkdf_extract_sha256(c->salt, 32, c->ikm, HKDF_IKM_LEN, c->prk);
}

static void mlkem_bench_hkdf_expand(void *ctx)
{
    (void)ctx;
    mlkem_ctx_t *c = &mk_ctx;
    hkdf_expand_sha256(c->prk, c->info, HKDF_INFO_LEN, c->okm, HKDF_OKM_LEN);
}

static void mlkem_bench_hash(void *ctx)
{
    (void)ctx;
    mlkem_ctx_t *c = &mk_ctx;
    crypto_hash_sha256(c->hash_out, c->msg, MSG_LEN);
}

static void mlkem_bench_aead_enc(void *ctx)
{
    (void)ctx;
    mlkem_ctx_t *c = &mk_ctx;
    /* Use XChaCha20-Poly1305 (always available, no HW dependency) */
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        c->ct_aead, &c->ct_aead_len,
        c->msg, MSG_LEN,
        c->aad, AAD_LEN,
        NULL,
        c->aead_nonce, c->aead_key);
}

static void mlkem_bench_aead_dec(void *ctx)
{
    (void)ctx;
    mlkem_ctx_t *c = &mk_ctx;
    crypto_aead_xchacha20poly1305_ietf_decrypt(
        c->pt_aead, &c->pt_aead_len,
        NULL,
        c->ct_aead, c->ct_aead_len,
        c->aad, AAD_LEN,
        c->aead_nonce, c->aead_key);
}

static void mlkem_bench_key_exchange(void *ctx)
{
    /* Full KEM exchange: keygen, encap, decap */
    (void)ctx;
    uint8_t pk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ct[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss1[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    uint8_t ss2[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss1, pk);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss2, ct, sk);
    (void)ss1; (void)ss2;
}

static void mlkem_bench_secret_derive(void *ctx)
{
    (void)ctx;
    mlkem_ctx_t *c = &mk_ctx;
    uint8_t prk[32], okm[32];
    hkdf_extract_sha256(c->salt, 32, c->ss_enc, PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES, prk);
    hkdf_expand_sha256(prk, c->info, HKDF_INFO_LEN, okm, 32);
    (void)okm;
}

/* ==========================================================================
 * ML-DSA-65 benchmark functions
 * ========================================================================== */
static mldsa_ctx_t ds_ctx;

static void mldsa_bench_sign(void *ctx)
{
    (void)ctx;
    mldsa_ctx_t *c = &ds_ctx;
    PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(c->sig, &c->sig_len,
                                                  c->msg, MSG_LEN, c->sk);
}

static void mldsa_bench_verify(void *ctx)
{
    (void)ctx;
    mldsa_ctx_t *c = &ds_ctx;
    PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(c->sig, c->sig_len,
                                              c->msg, MSG_LEN, c->pk);
}

static void mldsa_bench_hkdf_extract(void *ctx)
{
    (void)ctx;
    mldsa_ctx_t *c = &ds_ctx;
    hkdf_extract_sha256(c->salt, 32, c->ikm, HKDF_IKM_LEN, c->prk);
}

static void mldsa_bench_hkdf_expand(void *ctx)
{
    (void)ctx;
    mldsa_ctx_t *c = &ds_ctx;
    hkdf_expand_sha256(c->prk, c->info, HKDF_INFO_LEN, c->okm, HKDF_OKM_LEN);
}

static void mldsa_bench_hash(void *ctx)
{
    (void)ctx;
    mldsa_ctx_t *c = &ds_ctx;
    crypto_hash_sha256(c->hash_out, c->msg, MSG_LEN);
}

static void mldsa_bench_aead_enc(void *ctx)
{
    (void)ctx;
    mldsa_ctx_t *c = &ds_ctx;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        c->ct_aead, &c->ct_aead_len,
        c->msg, MSG_LEN,
        c->aad, AAD_LEN,
        NULL,
        c->aead_nonce, c->aead_key);
}

static void mldsa_bench_aead_dec(void *ctx)
{
    (void)ctx;
    mldsa_ctx_t *c = &ds_ctx;
    crypto_aead_xchacha20poly1305_ietf_decrypt(
        c->pt_aead, &c->pt_aead_len,
        NULL,
        c->ct_aead, c->ct_aead_len,
        c->aad, AAD_LEN,
        c->aead_nonce, c->aead_key);
}

/* ==========================================================================
 * Hybrid (X25519 + ML-KEM-768) benchmark functions
 * ========================================================================== */
static hybrid_ctx_t hy_ctx;

static void hybrid_bench_keygen(void *ctx)
{
    /* Generate both X25519 and ML-KEM-768 key pairs */
    (void)ctx;
    hybrid_ctx_t *c = &hy_ctx;
    randombytes_buf(c->x_sk_a, sizeof(c->x_sk_a));
    crypto_scalarmult_curve25519_base(c->x_pk_a, c->x_sk_a);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(c->kem_pk, c->kem_sk);
}

static void hybrid_bench_encap(void *ctx)
{
    /* X25519 DH + ML-KEM encap */
    (void)ctx;
    hybrid_ctx_t *c = &hy_ctx;
    crypto_scalarmult_curve25519(c->x_shared, c->x_sk_a, c->x_pk_b);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(c->kem_ct, c->kem_ss_enc, c->kem_pk);
}

static void hybrid_bench_decap(void *ctx)
{
    /* X25519 DH (other side) + ML-KEM decap */
    (void)ctx;
    hybrid_ctx_t *c = &hy_ctx;
    crypto_scalarmult_curve25519(c->x_shared, c->x_sk_b, c->x_pk_a);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(c->kem_ss_dec, c->kem_ct, c->kem_sk);
}

static void hybrid_bench_hkdf_extract(void *ctx)
{
    (void)ctx;
    hybrid_ctx_t *c = &hy_ctx;
    /* Extract from combined shared secret (X25519 || ML-KEM) */
    memcpy(c->combined_ss, c->x_shared, 32);
    memcpy(c->combined_ss + 32, c->kem_ss_enc, 32);
    hkdf_extract_sha256(c->salt, 32, c->combined_ss, 64, c->prk);
}

static void hybrid_bench_hkdf_expand(void *ctx)
{
    (void)ctx;
    hybrid_ctx_t *c = &hy_ctx;
    hkdf_expand_sha256(c->prk, c->info, HKDF_INFO_LEN, c->okm, HKDF_OKM_LEN);
}

static void hybrid_bench_hash(void *ctx)
{
    (void)ctx;
    hybrid_ctx_t *c = &hy_ctx;
    crypto_hash_sha256(c->hash_out, c->msg, MSG_LEN);
}

static void hybrid_bench_aead_enc(void *ctx)
{
    (void)ctx;
    hybrid_ctx_t *c = &hy_ctx;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        c->ct_aead, &c->ct_aead_len,
        c->msg, MSG_LEN,
        c->aad, AAD_LEN,
        NULL,
        c->aead_nonce, c->aead_key);
}

static void hybrid_bench_aead_dec(void *ctx)
{
    (void)ctx;
    hybrid_ctx_t *c = &hy_ctx;
    crypto_aead_xchacha20poly1305_ietf_decrypt(
        c->pt_aead, &c->pt_aead_len,
        NULL,
        c->ct_aead, c->ct_aead_len,
        c->aad, AAD_LEN,
        c->aead_nonce, c->aead_key);
}

static void hybrid_bench_key_exchange(void *ctx)
{
    /* Full hybrid key exchange */
    (void)ctx;
    uint8_t ska[32], pka[32], skb[32], pkb[32], dh_a[32], dh_b[32];
    uint8_t kem_pk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t kem_sk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t kem_ct[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t kem_ss1[32], kem_ss2[32];

    /* X25519 */
    randombytes_buf(ska, 32);
    crypto_scalarmult_curve25519_base(pka, ska);
    randombytes_buf(skb, 32);
    crypto_scalarmult_curve25519_base(pkb, skb);
    crypto_scalarmult_curve25519(dh_a, ska, pkb);
    crypto_scalarmult_curve25519(dh_b, skb, pka);

    /* ML-KEM */
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(kem_pk, kem_sk);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(kem_ct, kem_ss1, kem_pk);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(kem_ss2, kem_ct, kem_sk);

    /* Combine */
    uint8_t combined[64];
    memcpy(combined, dh_a, 32);
    memcpy(combined + 32, kem_ss1, 32);

    uint8_t prk[32], derived[32];
    hkdf_extract_sha256(NULL, 0, combined, 64, prk);
    hkdf_expand_sha256(prk, (const uint8_t *)"hybrid", 6, derived, 32);
    (void)derived;
}

static void hybrid_bench_secret_derive(void *ctx)
{
    (void)ctx;
    hybrid_ctx_t *c = &hy_ctx;
    uint8_t combined[64], prk[32], okm[32];
    memcpy(combined, c->x_shared, 32);
    memcpy(combined + 32, c->kem_ss_enc, 32);
    hkdf_extract_sha256(c->salt, 32, combined, 64, prk);
    hkdf_expand_sha256(prk, c->info, HKDF_INFO_LEN, okm, 32);
    (void)okm;
}

/* ==========================================================================
 * Initialization: fill contexts with random data / pre-computed keys
 * ========================================================================== */
static void init_contexts(void)
{
    /* ── X25519 ── */
    randombytes_buf(x_ctx.sk_a, sizeof(x_ctx.sk_a));
    crypto_scalarmult_curve25519_base(x_ctx.pk_a, x_ctx.sk_a);
    randombytes_buf(x_ctx.sk_b, sizeof(x_ctx.sk_b));
    crypto_scalarmult_curve25519_base(x_ctx.pk_b, x_ctx.sk_b);
    crypto_scalarmult_curve25519(x_ctx.shared, x_ctx.sk_a, x_ctx.pk_b);
    randombytes_buf(x_ctx.msg, MSG_LEN);
    randombytes_buf(x_ctx.aad, AAD_LEN);
    randombytes_buf(x_ctx.ikm, HKDF_IKM_LEN);
    randombytes_buf(x_ctx.salt, 32);
    randombytes_buf(x_ctx.info, HKDF_INFO_LEN);
    hkdf_extract_sha256(x_ctx.salt, 32, x_ctx.ikm, HKDF_IKM_LEN, x_ctx.prk);
    randombytes_buf(x_ctx.aead_key, sizeof(x_ctx.aead_key));
    randombytes_buf(x_ctx.aead_nonce, sizeof(x_ctx.aead_nonce));
    /* Pre-encrypt for decrypt bench */
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        x_ctx.ct, &x_ctx.ct_len,
        x_ctx.msg, MSG_LEN,
        x_ctx.aad, AAD_LEN,
        NULL, x_ctx.aead_nonce, x_ctx.aead_key);

    /* ── Ed25519 ── */
    crypto_sign_ed25519_keypair(ed_ctx.pk, ed_ctx.sk);
    randombytes_buf(ed_ctx.msg, MSG_LEN);
    crypto_sign_ed25519_detached(ed_ctx.sig, &ed_ctx.sig_len, ed_ctx.msg, MSG_LEN, ed_ctx.sk);
    randombytes_buf(ed_ctx.ikm, HKDF_IKM_LEN);
    randombytes_buf(ed_ctx.salt, 32);
    randombytes_buf(ed_ctx.info, HKDF_INFO_LEN);
    hkdf_extract_sha256(ed_ctx.salt, 32, ed_ctx.ikm, HKDF_IKM_LEN, ed_ctx.prk);
    randombytes_buf(ed_ctx.aead_key, sizeof(ed_ctx.aead_key));
    randombytes_buf(ed_ctx.aead_nonce, sizeof(ed_ctx.aead_nonce));
    randombytes_buf(ed_ctx.aad, AAD_LEN);
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ed_ctx.ct, &ed_ctx.ct_len,
        ed_ctx.msg, MSG_LEN,
        ed_ctx.aad, AAD_LEN,
        NULL, ed_ctx.aead_nonce, ed_ctx.aead_key);

    /* ── ML-KEM-768 ── */
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(mk_ctx.pk, mk_ctx.sk);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(mk_ctx.ct, mk_ctx.ss_enc, mk_ctx.pk);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(mk_ctx.ss_dec, mk_ctx.ct, mk_ctx.sk);
    randombytes_buf(mk_ctx.msg, MSG_LEN);
    randombytes_buf(mk_ctx.aad, AAD_LEN);
    randombytes_buf(mk_ctx.ikm, HKDF_IKM_LEN);
    randombytes_buf(mk_ctx.salt, 32);
    randombytes_buf(mk_ctx.info, HKDF_INFO_LEN);
    hkdf_extract_sha256(mk_ctx.salt, 32, mk_ctx.ikm, HKDF_IKM_LEN, mk_ctx.prk);
    randombytes_buf(mk_ctx.aead_key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    randombytes_buf(mk_ctx.aead_nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        mk_ctx.ct_aead, &mk_ctx.ct_aead_len,
        mk_ctx.msg, MSG_LEN,
        mk_ctx.aad, AAD_LEN,
        NULL, mk_ctx.aead_nonce, mk_ctx.aead_key);

    /* ── ML-DSA-65 ── */
    PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(ds_ctx.pk, ds_ctx.sk);
    randombytes_buf(ds_ctx.msg, MSG_LEN);
    PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(ds_ctx.sig, &ds_ctx.sig_len,
                                                  ds_ctx.msg, MSG_LEN, ds_ctx.sk);
    randombytes_buf(ds_ctx.ikm, HKDF_IKM_LEN);
    randombytes_buf(ds_ctx.salt, 32);
    randombytes_buf(ds_ctx.info, HKDF_INFO_LEN);
    hkdf_extract_sha256(ds_ctx.salt, 32, ds_ctx.ikm, HKDF_IKM_LEN, ds_ctx.prk);
    randombytes_buf(ds_ctx.aad, AAD_LEN);
    randombytes_buf(ds_ctx.aead_key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    randombytes_buf(ds_ctx.aead_nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ds_ctx.ct_aead, &ds_ctx.ct_aead_len,
        ds_ctx.msg, MSG_LEN,
        ds_ctx.aad, AAD_LEN,
        NULL, ds_ctx.aead_nonce, ds_ctx.aead_key);

    /* ── Hybrid ── */
    randombytes_buf(hy_ctx.x_sk_a, sizeof(hy_ctx.x_sk_a));
    crypto_scalarmult_curve25519_base(hy_ctx.x_pk_a, hy_ctx.x_sk_a);
    randombytes_buf(hy_ctx.x_sk_b, sizeof(hy_ctx.x_sk_b));
    crypto_scalarmult_curve25519_base(hy_ctx.x_pk_b, hy_ctx.x_sk_b);
    crypto_scalarmult_curve25519(hy_ctx.x_shared, hy_ctx.x_sk_a, hy_ctx.x_pk_b);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(hy_ctx.kem_pk, hy_ctx.kem_sk);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(hy_ctx.kem_ct, hy_ctx.kem_ss_enc, hy_ctx.kem_pk);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(hy_ctx.kem_ss_dec, hy_ctx.kem_ct, hy_ctx.kem_sk);
    memcpy(hy_ctx.combined_ss, hy_ctx.x_shared, 32);
    memcpy(hy_ctx.combined_ss + 32, hy_ctx.kem_ss_enc, 32);
    randombytes_buf(hy_ctx.msg, MSG_LEN);
    randombytes_buf(hy_ctx.aad, AAD_LEN);
    randombytes_buf(hy_ctx.ikm, HKDF_IKM_LEN);
    randombytes_buf(hy_ctx.salt, 32);
    randombytes_buf(hy_ctx.info, HKDF_INFO_LEN);
    hkdf_extract_sha256(hy_ctx.salt, 32, hy_ctx.combined_ss, 64, hy_ctx.prk);
    randombytes_buf(hy_ctx.aead_key, sizeof(hy_ctx.aead_key));
    randombytes_buf(hy_ctx.aead_nonce, sizeof(hy_ctx.aead_nonce));
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        hy_ctx.ct_aead, &hy_ctx.ct_aead_len,
        hy_ctx.msg, MSG_LEN,
        hy_ctx.aad, AAD_LEN,
        NULL, hy_ctx.aead_nonce, hy_ctx.aead_key);
}

/* ==========================================================================
 * Print helpers
 * ========================================================================== */
static void print_header(void)
{
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                     PURE CRYPTOGRAPHIC OPERATIONS BENCHMARK                                       ║\n");
    printf("║                     (No EDHOC, No Socket — Raw Algorithm Performance)                             ║\n");
    printf("╠══════════════════════════════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║  Classical : libsodium (X25519, Ed25519, XChaCha20-Poly1305, SHA-256, HKDF-SHA256)                ║\n");
    printf("║  PQ        : PQClean  (ML-KEM-768, ML-DSA-65) + libsodium (XChaCha20-Poly1305, SHA-256, HKDF)  ║\n");
    printf("║  Hybrid    : libsodium (X25519) + PQClean (ML-KEM-768) + libsodium symmetric                   ║\n");
    printf("║  Iterations: %d (warmup: %d)                                                               ║\n",
           BENCH_ITERATIONS, WARMUP_ITERATIONS);
    printf("╚══════════════════════════════════════════════════════════════════════════════════════════════════════╝\n\n");
}

static void print_table(void)
{
    /* Header row */
    printf("┌────────────────────────────┬──────────────────┬──────────────────┬──────────────────┬──────────────────┬──────────────────┐\n");
    printf("│ %-26s │ %-16s │ %-16s │ %-16s │ %-16s │ %-16s │\n",
           "Operation", col_names[0], col_names[1], col_names[2], col_names[3], col_names[4]);
    printf("│ %-26s │ %-16s │ %-16s │ %-16s │ %-16s │ %-16s │\n",
           "", "(µs)", "(µs)", "(µs)", "(µs)", "(µs)");
    printf("├────────────────────────────┼──────────────────┼──────────────────┼──────────────────┼──────────────────┼──────────────────┤\n");

    for (int r = 0; r < NUM_ROWS; r++) {
        printf("│ %-26s │", row_names[r]);
        for (int c = 0; c < NUM_COLS; c++) {
            if (avg_us[r][c] < 0.0) {
                printf("       N/A        │");
            } else {
                printf(" %11.3f ±%3.1f │", avg_us[r][c], stddev_us[r][c]);
            }
        }
        printf("\n");
    }
    printf("└────────────────────────────┴──────────────────┴──────────────────┴──────────────────┴──────────────────┴──────────────────┘\n\n");

    /* Size information */
    printf("┌────────────────────────────┬──────────────────┬──────────────────┬──────────────────┬──────────────────┬──────────────────┐\n");
    printf("│ %-26s │ %-16s │ %-16s │ %-16s │ %-16s │ %-16s │\n",
           "Key/Data Sizes (bytes)", col_names[0], col_names[1], col_names[2], col_names[3], col_names[4]);
    printf("├────────────────────────────┼──────────────────┼──────────────────┼──────────────────┼──────────────────┼──────────────────┤\n");
    printf("│ %-26s │ %16d │ %16d │ %16d │ %16d │ %16s │\n",
           "Public Key",
           (int)crypto_scalarmult_curve25519_BYTES,
           (int)crypto_sign_ed25519_PUBLICKEYBYTES,
           PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES,
           PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES,
           "32+1184");
    printf("│ %-26s │ %16d │ %16d │ %16d │ %16d │ %16s │\n",
           "Secret Key",
           (int)crypto_scalarmult_curve25519_SCALARBYTES,
           (int)crypto_sign_ed25519_SECRETKEYBYTES,
           PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES,
           PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES,
           "32+2400");
    printf("│ %-26s │ %16s │ %16s │ %16d │ %16s │ %16s │\n",
           "Ciphertext/Signature",
           "32 (DH output)",
           "64 (sig)",
           PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES,
           "3309 (sig)",
           "32+1088");
    printf("│ %-26s │ %16d │ %16s │ %16d │ %16s │ %16s │\n",
           "Shared Secret",
           (int)crypto_scalarmult_curve25519_BYTES,
           "N/A",
           PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES,
           "N/A",
           "64 (32+32)");
    printf("└────────────────────────────┴──────────────────┴──────────────────┴──────────────────┴──────────────────┴──────────────────┘\n\n");
}

static void write_csv(void)
{
    mkdir(OUTPUT_DIR, 0755);
    FILE *f = fopen(OUTPUT_FILE, "w");
    if (!f) {
        perror("fopen output CSV");
        return;
    }

    /* Header */
    fprintf(f, "operation,algorithm,avg_us,stddev_us,min_us,max_us,median_us,iterations,key_length\n");

    for (int r = 0; r < NUM_ROWS; r++) {
        for (int c = 0; c < NUM_COLS; c++) {
            if (r == ROW_KEYGEN && (c == COL_ED25519 || c == COL_MLDSA65)) {
                continue;
            }
            int kl = key_length_bytes[r][c];
            if (avg_us[r][c] < 0.0) {
                if (kl >= 0)
                    fprintf(f, "%s,%s,N/A,N/A,N/A,N/A,N/A,%d,%d\n",
                            row_names[r], col_names[c], BENCH_ITERATIONS, kl);
                else
                    fprintf(f, "%s,%s,N/A,N/A,N/A,N/A,N/A,%d,N/A\n",
                            row_names[r], col_names[c], BENCH_ITERATIONS);
            } else {
                if (kl >= 0)
                    fprintf(f, "%s,%s,%.3f,%.3f,%.3f,%.3f,%.3f,%d,%d\n",
                            row_names[r], col_names[c],
                            avg_us[r][c], stddev_us[r][c],
                            min_us[r][c], max_us[r][c], median_us[r][c],
                            BENCH_ITERATIONS, kl);
                else
                    fprintf(f, "%s,%s,%.3f,%.3f,%.3f,%.3f,%.3f,%d,N/A\n",
                            row_names[r], col_names[c],
                            avg_us[r][c], stddev_us[r][c],
                            min_us[r][c], max_us[r][c], median_us[r][c],
                            BENCH_ITERATIONS);
            }
        }
    }

    fclose(f);
    printf("  CSV output written to: %s\n\n", OUTPUT_FILE);
}

/* Also write a "matrix" style CSV (operations as rows, algorithms as columns) */
static void write_matrix_csv(void)
{
    const char *MATRIX_FILE = OUTPUT_DIR "/benchmark_crypto_matrix.csv";
    FILE *f = fopen(MATRIX_FILE, "w");
    if (!f) {
        perror("fopen matrix CSV");
        return;
    }

    /* Header */
    fprintf(f, "Operation");
    for (int c = 0; c < NUM_COLS; c++) {
        fprintf(f, ",%s (µs),%s key_length", col_names[c], col_names[c]);
    }
    fprintf(f, "\n");

    /* Data rows */
    for (int r = 0; r < NUM_ROWS; r++) {
        fprintf(f, "%s", row_names[r]);
        for (int c = 0; c < NUM_COLS; c++) {
            if (avg_us[r][c] < 0.0) {
                fprintf(f, ",N/A");
            } else {
                fprintf(f, ",%.3f", avg_us[r][c]);
            }
            if (key_length_bytes[r][c] >= 0) {
                fprintf(f, ",%d", key_length_bytes[r][c]);
            } else {
                fprintf(f, ",N/A");
            }
        }
        fprintf(f, "\n");
    }

    fclose(f);
    printf("  Matrix CSV written to: %s\n\n", MATRIX_FILE);
}

/* Write the simplified CSV: algorithm-grouped, only relevant ops per algo,
 * symmetric ops listed once at the bottom.
 * Format:
 *   algorithm,operation,avg_us,stddev_us,min_us,max_us,median_us,iterations,key_length
 */
static void write_simple_csv(void)
{
    const char *SIMPLE_FILE = OUTPUT_DIR "/benchmark_crypto_simple.csv";
    FILE *f = fopen(SIMPLE_FILE, "w");
    if (!f) { perror("fopen simple CSV"); return; }

    fprintf(f, "algorithm,operation,avg_us,stddev_us,min_us,max_us,median_us,iterations,key_length\n");

    /* Helper macro: print one data row.
     * first=1 → print algo name, first=0 → leave blank (grouped look) */
#define ROW(algo_str, op_str, row, col)                                  \
    do {                                                                 \
        if (avg_us[row][col] >= 0.0) {                                   \
            int _kl = key_length_bytes[row][col];                        \
            if (_kl >= 0)                                                \
                fprintf(f, "%s,%s,%.3f,%.3f,%.3f,%.3f,%.3f,%d,%d\n",    \
                        (algo_str), (op_str),                            \
                        avg_us[row][col], stddev_us[row][col],           \
                        min_us[row][col], max_us[row][col],              \
                        median_us[row][col], BENCH_ITERATIONS, _kl);     \
            else                                                         \
                fprintf(f, "%s,%s,%.3f,%.3f,%.3f,%.3f,%.3f,%d,N/A\n",   \
                        (algo_str), (op_str),                            \
                        avg_us[row][col], stddev_us[row][col],           \
                        min_us[row][col], max_us[row][col],              \
                        median_us[row][col], BENCH_ITERATIONS);          \
        }                                                                \
    } while (0)

    /* ── X25519 ─────────────────────────────────────────────────────── */
    ROW("X25519",            "Keygen",        ROW_KEYGEN,  COL_X25519);
    ROW("",                  "Shared Secret", ROW_ENCAP,   COL_X25519);

    /* ── Ed25519 ────────────────────────────────────────────────────── */
    ROW("Ed25519",           "Signature",     ROW_SIGNATURE,    COL_ED25519);
    ROW("",                  "Verification",  ROW_VERIFICATION, COL_ED25519);

    /* ── ML-KEM-768 ─────────────────────────────────────────────────── */
    ROW("ML-KEM-768",        "Keygen",        ROW_KEYGEN,  COL_MLKEM768);
    ROW("",                  "Encap",         ROW_ENCAP,   COL_MLKEM768);
    ROW("",                  "Decap",         ROW_DECAP,   COL_MLKEM768);

    /* ── ML-DSA-65 ──────────────────────────────────────────────────── */
    ROW("ML-DSA-65",         "Signature",     ROW_SIGNATURE,    COL_MLDSA65);
    ROW("",                  "Verification",  ROW_VERIFICATION, COL_MLDSA65);

    /* ── X25519+ML-KEM-768 (Hybrid) ─────────────────────────────────── */
    ROW("X25519+ML-KEM-768", "Keygen",        ROW_KEYGEN,  COL_HYBRID);
    ROW("",                  "Encap",         ROW_ENCAP,   COL_HYBRID);
    ROW("",                  "Decap",         ROW_DECAP,   COL_HYBRID);

    /* ── Symmetric (shared, benchmarked once via X25519 context) ───── */
    ROW("Hash (SHA-256)",    "Cryptography",  ROW_HASH,         COL_X25519);
    ROW("HKDF",              "Cryptography",  ROW_HKDF_EXTRACT, COL_X25519);
    ROW("AEAD Encrypt",      "Cryptography",  ROW_AEAD_ENCRYPT, COL_X25519);
    ROW("AEAD Decrypt",      "Cryptography",  ROW_AEAD_DECRYPT, COL_X25519);

#undef ROW

    fclose(f);
    printf("  Simple CSV written to: %s\n\n", SIMPLE_FILE);
}

/* ==========================================================================
 * MAIN
 * ========================================================================== */
int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "ERROR: sodium_init() failed\n");
        return 1;
    }

    srand((unsigned)time(NULL));

    print_header();

    /* Initialize all N/A */
    for (int r = 0; r < NUM_ROWS; r++)
        for (int c = 0; c < NUM_COLS; c++)
            mark_na(r, c);

    /* Initialize key length table */
    init_key_lengths();

    /* Count total bench operations for progress display */
    /* X25519: 10, Ed25519: 7, ML-KEM: 10, ML-DSA: 7, Hybrid: 10 = 44 */
    bench_op_total = 44;

    /* Initialize contexts */
    printf("  Initializing cryptographic contexts...\n");
    init_contexts();
    printf("  Done.\n\n");

    /* ====================================================================
     * X25519 column
     * ==================================================================== */
    printf("  [1/5] Benchmarking X25519 (libsodium)...\n");
    run_bench(x25519_bench_keygen,       NULL, ROW_KEYGEN,         COL_X25519);
    run_bench(x25519_bench_encap,        NULL, ROW_ENCAP,          COL_X25519);
    run_bench(x25519_bench_decap,        NULL, ROW_DECAP,          COL_X25519);
    /* Signature & Verification: N/A for X25519 (it's a key exchange only) */
    run_bench(x25519_bench_hkdf_extract, NULL, ROW_HKDF_EXTRACT,   COL_X25519);
    run_bench(x25519_bench_hkdf_expand,  NULL, ROW_HKDF_EXPAND,    COL_X25519);
    run_bench(x25519_bench_hash,         NULL, ROW_HASH,           COL_X25519);
    run_bench(x25519_bench_aead_enc,     NULL, ROW_AEAD_ENCRYPT,   COL_X25519);
    run_bench(x25519_bench_aead_dec,     NULL, ROW_AEAD_DECRYPT,   COL_X25519);
    run_bench(x25519_bench_key_exchange, NULL, ROW_KEY_EXCHANGE,    COL_X25519);
    run_bench(x25519_bench_secret_derive,NULL, ROW_SECRET_DERIVE,   COL_X25519);

    /* ====================================================================
     * Ed25519 column
     * ==================================================================== */
    printf("  [2/5] Benchmarking Ed25519 (libsodium)...\n");
    /* Keygen skipped: generated during certificate provisioning */
    /* Encap/Decap: N/A for signature scheme */
    run_bench(ed25519_bench_sign,         NULL, ROW_SIGNATURE,      COL_ED25519);
    run_bench(ed25519_bench_verify,       NULL, ROW_VERIFICATION,   COL_ED25519);
    run_bench(ed25519_bench_hkdf_extract, NULL, ROW_HKDF_EXTRACT,   COL_ED25519);
    run_bench(ed25519_bench_hkdf_expand,  NULL, ROW_HKDF_EXPAND,    COL_ED25519);
    run_bench(ed25519_bench_hash,         NULL, ROW_HASH,           COL_ED25519);
    run_bench(ed25519_bench_aead_enc,     NULL, ROW_AEAD_ENCRYPT,   COL_ED25519);
    run_bench(ed25519_bench_aead_dec,     NULL, ROW_AEAD_DECRYPT,   COL_ED25519);

    /* ====================================================================
     * ML-KEM-768 column
     * ==================================================================== */
    printf("  [3/5] Benchmarking ML-KEM-768 (PQClean)...\n");
    run_bench(mlkem_bench_keygen,        NULL, ROW_KEYGEN,          COL_MLKEM768);
    run_bench(mlkem_bench_encap,         NULL, ROW_ENCAP,           COL_MLKEM768);
    run_bench(mlkem_bench_decap,         NULL, ROW_DECAP,           COL_MLKEM768);
    /* Signature & Verification: N/A for KEM */
    run_bench(mlkem_bench_hkdf_extract,  NULL, ROW_HKDF_EXTRACT,    COL_MLKEM768);
    run_bench(mlkem_bench_hkdf_expand,   NULL, ROW_HKDF_EXPAND,     COL_MLKEM768);
    run_bench(mlkem_bench_hash,          NULL, ROW_HASH,            COL_MLKEM768);
    run_bench(mlkem_bench_aead_enc,      NULL, ROW_AEAD_ENCRYPT,    COL_MLKEM768);
    run_bench(mlkem_bench_aead_dec,      NULL, ROW_AEAD_DECRYPT,    COL_MLKEM768);
    run_bench(mlkem_bench_key_exchange,  NULL, ROW_KEY_EXCHANGE,     COL_MLKEM768);
    run_bench(mlkem_bench_secret_derive, NULL, ROW_SECRET_DERIVE,    COL_MLKEM768);

    /* ====================================================================
     * ML-DSA-65 column
     * ==================================================================== */
    printf("  [4/5] Benchmarking ML-DSA-65 (PQClean)...\n");
    /* Keygen skipped: generated during certificate provisioning */
    /* Encap/Decap: N/A for signature scheme */
    run_bench(mldsa_bench_sign,          NULL, ROW_SIGNATURE,       COL_MLDSA65);
    run_bench(mldsa_bench_verify,        NULL, ROW_VERIFICATION,    COL_MLDSA65);
    run_bench(mldsa_bench_hkdf_extract,  NULL, ROW_HKDF_EXTRACT,    COL_MLDSA65);
    run_bench(mldsa_bench_hkdf_expand,   NULL, ROW_HKDF_EXPAND,     COL_MLDSA65);
    run_bench(mldsa_bench_hash,          NULL, ROW_HASH,            COL_MLDSA65);
    run_bench(mldsa_bench_aead_enc,      NULL, ROW_AEAD_ENCRYPT,    COL_MLDSA65);
    run_bench(mldsa_bench_aead_dec,      NULL, ROW_AEAD_DECRYPT,    COL_MLDSA65);

    /* ====================================================================
     * Hybrid (X25519 + ML-KEM-768) column
     * ==================================================================== */
    printf("  [5/5] Benchmarking X25519 + ML-KEM-768 (Hybrid)...\n");
    run_bench(hybrid_bench_keygen,        NULL, ROW_KEYGEN,         COL_HYBRID);
    run_bench(hybrid_bench_encap,         NULL, ROW_ENCAP,          COL_HYBRID);
    run_bench(hybrid_bench_decap,         NULL, ROW_DECAP,          COL_HYBRID);
    /* Signature & Verification: N/A for key exchange */
    run_bench(hybrid_bench_hkdf_extract,  NULL, ROW_HKDF_EXTRACT,   COL_HYBRID);
    run_bench(hybrid_bench_hkdf_expand,   NULL, ROW_HKDF_EXPAND,    COL_HYBRID);
    run_bench(hybrid_bench_hash,          NULL, ROW_HASH,           COL_HYBRID);
    run_bench(hybrid_bench_aead_enc,      NULL, ROW_AEAD_ENCRYPT,   COL_HYBRID);
    run_bench(hybrid_bench_aead_dec,      NULL, ROW_AEAD_DECRYPT,   COL_HYBRID);
    run_bench(hybrid_bench_key_exchange,  NULL, ROW_KEY_EXCHANGE,    COL_HYBRID);
    run_bench(hybrid_bench_secret_derive, NULL, ROW_SECRET_DERIVE,   COL_HYBRID);

    printf("\n");

    /* ====================================================================
     * Output
     * ==================================================================== */
    print_table();
    write_csv();
    write_matrix_csv();
    write_simple_csv();

    printf("  Benchmark complete.\n\n");
    return 0;
}
