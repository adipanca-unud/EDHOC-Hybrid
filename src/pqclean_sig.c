// PQClean-backed ML-DSA-65 (Dilithium3) wrapper
#include <stdint.h>
#include <stddef.h>
#include "edhoc_pq_kem.h"

#ifdef USE_PQCLEAN
#include "crypto_sign/ml-dsa-65/clean/api.h"

int pq_sig_keygen(uint8_t *pk, uint8_t *sk)
{
	return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);
}

int pq_sig_sign(const uint8_t *msg, size_t msg_len,
		const uint8_t *sk,
		uint8_t *sig, size_t *sig_len)
{
	return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, sig_len,
						msg, msg_len, sk);
}

int pq_sig_verify(const uint8_t *msg, size_t msg_len,
		  const uint8_t *sig, size_t sig_len,
		  const uint8_t *pk)
{
	return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, sig_len,
					 msg, msg_len, pk);
}

#endif /* USE_PQCLEAN */