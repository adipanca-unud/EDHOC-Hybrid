// PQClean-backed ML-KEM-768 wrapper
#include <stdint.h>
#include <stddef.h>
#include "edhoc_pq_kem.h"

#ifdef USE_PQCLEAN
#include "crypto_kem/ml-kem-768/clean/api.h"

int pq_kem_keygen(uint8_t *pk, uint8_t *sk)
{
	return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
}

int pq_kem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
	return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, pk);
}

int pq_kem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
	return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, sk);
}

#endif /* USE_PQCLEAN */