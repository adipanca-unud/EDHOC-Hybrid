/*
 * =============================================================================
 * EDHOC-Hybrid: Post-Quantum KEM Wrapper
 * =============================================================================
 *
 * Abstraksi KEM (Key Encapsulation Mechanism) menggunakan ML-KEM-768 dari
 * liboqs (Open Quantum Safe). Modul ini menyediakan fungsi-fungsi:
 *
 *   - pq_kem_keygen()   : Generate PQ key pair (pk, sk)
 *   - pq_kem_encaps()   : Encapsulate shared secret → (ct, ss)
 *   - pq_kem_decaps()   : Decapsulate ciphertext → ss
 *   - pq_hkdf_extract() : HKDF-Extract (SHA-256) wrapper
 *   - pq_hkdf_expand()  : HKDF-Expand (SHA-256) wrapper
 *   - pq_aead_encrypt() : AES-CCM-16-64-128 encrypt
 *   - pq_aead_decrypt() : AES-CCM-16-64-128 decrypt
 *   - pq_hash()         : SHA-256 hash
 *
 * Algoritma: ML-KEM-768 (NIST Level 3, ~AES-192 equivalent)
 *   - Public key  : 1184 bytes
 *   - Secret key  : 2400 bytes
 *   - Ciphertext  : 1088 bytes
 *   - Shared secret: 32 bytes
 *
 * =============================================================================
 */

#ifndef EDHOC_PQ_KEM_H
#define EDHOC_PQ_KEM_H

#include <stdint.h>
#include <stddef.h>

/* ML-KEM-768 sizes */
#define PQ_KEM_PK_LEN         1184
#define PQ_KEM_SK_LEN         2400
#define PQ_KEM_CT_LEN         1088
#define PQ_KEM_SS_LEN         32

/* HKDF/Hash sizes */
#define PQ_HASH_LEN           32    /* SHA-256 output */
#define PQ_PRK_LEN            32    /* PRK size = hash output */
#define PQ_AEAD_KEY_LEN       16    /* AES-CCM-16-64-128 key */
#define PQ_AEAD_NONCE_LEN     13    /* AES-CCM nonce */
#define PQ_AEAD_TAG_LEN       8     /* AES-CCM tag (64-bit) */

/* Algorithm name for display */
#define PQ_KEM_ALG_NAME       "ML-KEM-768"

/**
 * @brief Generate a PQ KEM key pair.
 * @param[out] pk  Public key buffer (PQ_KEM_PK_LEN bytes)
 * @param[out] sk  Secret key buffer (PQ_KEM_SK_LEN bytes)
 * @return 0 on success, -1 on error
 */
int pq_kem_keygen(uint8_t *pk, uint8_t *sk);

/**
 * @brief Encapsulate: generate shared secret and ciphertext from public key.
 * @param[out] ct  Ciphertext buffer (PQ_KEM_CT_LEN bytes)
 * @param[out] ss  Shared secret buffer (PQ_KEM_SS_LEN bytes)
 * @param[in]  pk  Public key (PQ_KEM_PK_LEN bytes)
 * @return 0 on success, -1 on error
 */
int pq_kem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

/**
 * @brief Decapsulate: recover shared secret from ciphertext using secret key.
 * @param[out] ss  Shared secret buffer (PQ_KEM_SS_LEN bytes)
 * @param[in]  ct  Ciphertext (PQ_KEM_CT_LEN bytes)
 * @param[in]  sk  Secret key (PQ_KEM_SK_LEN bytes)
 * @return 0 on success, -1 on error
 */
int pq_kem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/**
 * @brief HKDF-Extract (SHA-256): PRK = HMAC-SHA256(salt, IKM)
 * @param[in]  salt     Salt (can be NULL for zero salt)
 * @param[in]  salt_len Salt length
 * @param[in]  ikm      Input keying material
 * @param[in]  ikm_len  IKM length
 * @param[out] prk      Pseudorandom key (PQ_PRK_LEN bytes)
 * @return 0 on success, -1 on error
 */
int pq_hkdf_extract(const uint8_t *salt, size_t salt_len,
                     const uint8_t *ikm, size_t ikm_len,
                     uint8_t *prk);

/**
 * @brief HKDF-Expand (SHA-256): OKM = HKDF-Expand(PRK, info, L)
 * @param[in]  prk      Pseudorandom key (PQ_PRK_LEN bytes)
 * @param[in]  info     Context/info string
 * @param[in]  info_len Info length
 * @param[out] okm      Output keying material
 * @param[in]  okm_len  Desired output length
 * @return 0 on success, -1 on error
 */
int pq_hkdf_expand(const uint8_t *prk,
                    const uint8_t *info, size_t info_len,
                    uint8_t *okm, size_t okm_len);

/**
 * @brief AEAD Encrypt: AES-CCM-16-64-128
 * @param[in]  key       Key (PQ_AEAD_KEY_LEN bytes)
 * @param[in]  nonce     Nonce (PQ_AEAD_NONCE_LEN bytes)
 * @param[in]  aad       Additional authenticated data
 * @param[in]  aad_len   AAD length
 * @param[in]  plaintext Plaintext
 * @param[in]  pt_len    Plaintext length
 * @param[out] ciphertext Ciphertext output (pt_len + PQ_AEAD_TAG_LEN bytes)
 * @param[out] ct_len    Ciphertext length output
 * @return 0 on success, -1 on error
 */
int pq_aead_encrypt(const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *plaintext, size_t pt_len,
                     uint8_t *ciphertext, size_t *ct_len);

/**
 * @brief AEAD Decrypt: AES-CCM-16-64-128
 * @param[in]  key        Key (PQ_AEAD_KEY_LEN bytes)
 * @param[in]  nonce      Nonce (PQ_AEAD_NONCE_LEN bytes)
 * @param[in]  aad        Additional authenticated data
 * @param[in]  aad_len    AAD length
 * @param[in]  ciphertext Ciphertext (includes tag)
 * @param[in]  ct_len     Ciphertext length (plaintext + tag)
 * @param[out] plaintext  Plaintext output
 * @param[out] pt_len     Plaintext length output
 * @return 0 on success, -1 on error
 */
int pq_aead_decrypt(const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ciphertext, size_t ct_len,
                     uint8_t *plaintext, size_t *pt_len);

/**
 * @brief SHA-256 hash
 * @param[in]  data     Input data
 * @param[in]  data_len Data length
 * @param[out] hash_out Hash output (PQ_HASH_LEN bytes)
 * @return 0 on success, -1 on error
 */
int pq_hash_sha256(const uint8_t *data, size_t data_len, uint8_t *hash_out);

#endif /* EDHOC_PQ_KEM_H */
