/*
 * =============================================================================
 * EDHOC-Hybrid: Post-Quantum KEM Wrapper Implementation
 * =============================================================================
 *
 * Uses PQClean ML-KEM-768 / ML-DSA-65 when USE_PQCLEAN is defined (default)
 * and falls back to liboqs otherwise. Symmetric crypto (HKDF, AEAD, Hash)
 * continues to use mbedTLS PSA to reuse the same backend as classic EDHOC.
 * =============================================================================
 */

#include "edhoc_pq_kem.h"

#include <string.h>
#include <stdio.h>

/* PQ backends */
#ifdef USE_PQCLEAN
#include "crypto_kem/ml-kem-768/clean/api.h"
#include "crypto_sign/ml-dsa-65/clean/api.h"
#else
#include <oqs/oqs.h>
#endif
/* mbedTLS PSA for symmetric crypto */
#include "psa/crypto.h"

/* AES-CCM with 8-byte tag (AES-CCM-16-64-128) */
#define PQ_CCM_ALG PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, PQ_AEAD_TAG_LEN)

/* =============================================================================
 * PQ KEM Operations (ML-KEM-768)
 * =============================================================================
 */

int pq_kem_keygen(uint8_t *pk, uint8_t *sk)
{
#ifdef USE_PQCLEAN
	return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
#else
	OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
	if (kem == NULL)
		return -1;

	OQS_STATUS rc = OQS_KEM_keypair(kem, pk, sk);
	OQS_KEM_free(kem);
	return (rc == OQS_SUCCESS) ? 0 : -1;
#endif
}

int pq_kem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
#ifdef USE_PQCLEAN
	return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, pk);
#else
	OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
	if (kem == NULL)
		return -1;

	OQS_STATUS rc = OQS_KEM_encaps(kem, ct, ss, pk);
	OQS_KEM_free(kem);
	return (rc == OQS_SUCCESS) ? 0 : -1;
#endif
}

int pq_kem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
#ifdef USE_PQCLEAN
	return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, sk);
#else
	OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
	if (kem == NULL)
		return -1;

	OQS_STATUS rc = OQS_KEM_decaps(kem, ss, ct, sk);
	OQS_KEM_free(kem);
	return (rc == OQS_SUCCESS) ? 0 : -1;
#endif
}

/* =============================================================================
 * Symmetric Crypto Operations (mbedTLS PSA — same as classic EDHOC)
 * =============================================================================
 */

static int ensure_psa_init(void)
{
	static int initialized = 0;
	if (!initialized) {
		psa_status_t status = psa_crypto_init();
		if (status != PSA_SUCCESS && status != PSA_ERROR_BAD_STATE)
			return -1;
		initialized = 1;
	}
	return 0;
}

int pq_hkdf_extract(const uint8_t *salt, size_t salt_len,
                     const uint8_t *ikm, size_t ikm_len,
                     uint8_t *prk)
{
	if (ensure_psa_init() != 0)
		return -1;

	/*
	 * HKDF-Extract = HMAC-SHA256(salt, ikm)
	 * Using PSA MAC API with HMAC-SHA256.
	 */
	psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attrs, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);

	/* If salt is NULL, use zero salt */
	uint8_t zero_salt[PQ_PRK_LEN];
	if (salt == NULL || salt_len == 0) {
		memset(zero_salt, 0, PQ_PRK_LEN);
		salt = zero_salt;
		salt_len = PQ_PRK_LEN;
	}

	psa_key_id_t key_id;
	psa_status_t status = psa_import_key(&attrs, salt, salt_len, &key_id);
	if (status != PSA_SUCCESS)
		return -1;

	size_t mac_len = 0;
	status = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
	                         ikm, ikm_len,
	                         prk, PQ_PRK_LEN, &mac_len);

	psa_destroy_key(key_id);
	return (status == PSA_SUCCESS && mac_len == PQ_PRK_LEN) ? 0 : -1;
}

int pq_hkdf_expand(const uint8_t *prk,
                    const uint8_t *info, size_t info_len,
                    uint8_t *okm, size_t okm_len)
{
	if (ensure_psa_init() != 0)
		return -1;

	/*
	 * HKDF-Expand: T(1) = HMAC(PRK, info || 0x01)
	 * For okm_len <= 32 (one block), this is straightforward.
	 * For larger, we iterate.
	 */
	psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attrs, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);

	psa_key_id_t key_id;
	psa_status_t status = psa_import_key(&attrs, prk, PQ_PRK_LEN, &key_id);
	if (status != PSA_SUCCESS)
		return -1;

	uint8_t T[PQ_HASH_LEN];
	size_t T_len = 0;
	size_t offset = 0;
	uint8_t counter = 1;
	int ret = 0;

	while (offset < okm_len) {
		psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
		status = psa_mac_sign_setup(&op, key_id,
		                            PSA_ALG_HMAC(PSA_ALG_SHA_256));
		if (status != PSA_SUCCESS) { ret = -1; break; }

		/* T(i) = HMAC(PRK, T(i-1) || info || counter) */
		if (counter > 1) {
			status = psa_mac_update(&op, T, T_len);
			if (status != PSA_SUCCESS) {
				psa_mac_abort(&op);
				ret = -1; break;
			}
		}
		if (info_len > 0) {
			status = psa_mac_update(&op, info, info_len);
			if (status != PSA_SUCCESS) {
				psa_mac_abort(&op);
				ret = -1; break;
			}
		}
		status = psa_mac_update(&op, &counter, 1);
		if (status != PSA_SUCCESS) {
			psa_mac_abort(&op);
			ret = -1; break;
		}

		status = psa_mac_sign_finish(&op, T, PQ_HASH_LEN, &T_len);
		if (status != PSA_SUCCESS) { ret = -1; break; }

		size_t copy_len = okm_len - offset;
		if (copy_len > T_len)
			copy_len = T_len;
		memcpy(okm + offset, T, copy_len);
		offset += copy_len;
		counter++;
	}

	psa_destroy_key(key_id);
	return ret;
}

int pq_aead_encrypt(const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *plaintext, size_t pt_len,
                     uint8_t *ciphertext, size_t *ct_len)
{
	if (ensure_psa_init() != 0)
		return -1;

	psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_algorithm(&attrs, PQ_CCM_ALG);
	psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attrs, PQ_AEAD_KEY_LEN * 8);

	psa_key_id_t key_id;
	psa_status_t status = psa_import_key(&attrs, key, PQ_AEAD_KEY_LEN, &key_id);
	if (status != PSA_SUCCESS)
		return -1;

	status = psa_aead_encrypt(key_id, PQ_CCM_ALG,
	                          nonce, PQ_AEAD_NONCE_LEN,
	                          aad, aad_len,
	                          plaintext, pt_len,
	                          ciphertext, pt_len + PQ_AEAD_TAG_LEN, ct_len);

	psa_destroy_key(key_id);
	return (status == PSA_SUCCESS) ? 0 : -1;
}

int pq_aead_decrypt(const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ciphertext, size_t ct_len,
                     uint8_t *plaintext, size_t *pt_len)
{
	if (ensure_psa_init() != 0)
		return -1;

	psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attrs, PQ_CCM_ALG);
	psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attrs, PQ_AEAD_KEY_LEN * 8);

	psa_key_id_t key_id;
	psa_status_t status = psa_import_key(&attrs, key, PQ_AEAD_KEY_LEN, &key_id);
	if (status != PSA_SUCCESS)
		return -1;

	status = psa_aead_decrypt(key_id, PQ_CCM_ALG,
	                          nonce, PQ_AEAD_NONCE_LEN,
	                          aad, aad_len,
	                          ciphertext, ct_len,
	                          plaintext, ct_len - PQ_AEAD_TAG_LEN, pt_len);

	psa_destroy_key(key_id);
	return (status == PSA_SUCCESS) ? 0 : -1;
}

int pq_hash_sha256(const uint8_t *data, size_t data_len, uint8_t *hash_out)
{
	if (ensure_psa_init() != 0)
		return -1;

	size_t hash_len = 0;
	psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256,
	                                       data, data_len,
	                                       hash_out, PQ_HASH_LEN, &hash_len);

	return (status == PSA_SUCCESS && hash_len == PQ_HASH_LEN) ? 0 : -1;
}

/* =============================================================================
 * PQ Signature Operations (ML-DSA-65 via PQClean or liboqs)
 * =============================================================================
 */

int pq_sig_keygen(uint8_t *pk, uint8_t *sk)
{
#ifdef USE_PQCLEAN
	return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);
#else
	OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
	if (sig == NULL)
		return -1;

	OQS_STATUS rc = OQS_SIG_keypair(sig, pk, sk);
	OQS_SIG_free(sig);
	return (rc == OQS_SUCCESS) ? 0 : -1;
#endif
}

int pq_sig_sign(const uint8_t *msg, size_t msg_len,
				const uint8_t *sk,
				uint8_t *sig_out, size_t *sig_len)
{
#ifdef USE_PQCLEAN
	return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig_out, sig_len,
				msg, msg_len, sk);
#else
	OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
	if (sig == NULL)
		return -1;

	OQS_STATUS rc = OQS_SIG_sign(sig, sig_out, sig_len,
								  msg, msg_len, sk);
	OQS_SIG_free(sig);
	return (rc == OQS_SUCCESS) ? 0 : -1;
#endif
}

int pq_sig_verify(const uint8_t *msg, size_t msg_len,
				  const uint8_t *sig_in, size_t sig_len,
				  const uint8_t *pk)
{
#ifdef USE_PQCLEAN
	return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig_in, sig_len,
			msg, msg_len, pk);
#else
	OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
	if (sig == NULL)
		return -1;

	OQS_STATUS rc = OQS_SIG_verify(sig, msg, msg_len,
									sig_in, sig_len, pk);
	OQS_SIG_free(sig);
	return (rc == OQS_SUCCESS) ? 0 : -1;
#endif
}
