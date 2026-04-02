/*
 * crypto_libsodium.c — Override WEAK crypto_wrapper functions with libsodium.
 *
 * The uoscore-uedhoc library's crypto_wrapper.c uses compact25519 (portable C)
 * for X25519 DH and EdDSA operations.  compact25519 is designed for small code
 * size (IoT) but is ~100× slower than libsodium on ARM64.
 *
 * This file provides NON-WEAK overrides that call libsodium instead.
 * Because these symbols are strong, the linker picks them over the WEAK
 * versions in libuoscore-uedhoc.a.
 *
 * Overridden functions:
 *   1. ephemeral_dh_key_gen(X25519, …) — X25519 key generation
 *   2. shared_secret_derive(X25519, …) — X25519 ECDH shared secret
 *   3. sign(EdDSA, …)                 — Ed25519 signature
 *   4. verify(EdDSA, …)               — Ed25519 signature verification
 */

#include <string.h>
#include <sodium.h>

#include "common/crypto_wrapper.h"
#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

#include "edhoc/suites.h"
#include "edhoc/buffer_sizes.h"

/* PSA Crypto for the SHA-256 seed expansion (same API the library uses) */
#include <psa/crypto.h>

/* ========================================================================
 * 1.  ephemeral_dh_key_gen  —  X25519 key pair from a seed
 * ======================================================================== */
enum err ephemeral_dh_key_gen(enum ecdh_alg alg, uint32_t seed,
			      struct byte_array *sk, struct byte_array *pk)
{
	if (alg != X25519)
		return unsupported_ecdh_curve;

	/*
	 * Deterministic keygen: expand the 4-byte seed into 32 bytes via
	 * SHA-256 (same approach as the original compact25519 code path).
	 * Then use crypto_scalarmult_base() for the public key.
	 */
	uint8_t seed_hash[32];
	size_t hash_len = 0;

	psa_status_t st = psa_hash_compute(PSA_ALG_SHA_256,
					   (const uint8_t *)&seed, sizeof(seed),
					   seed_hash, sizeof(seed_hash),
					   &hash_len);
	if (st != PSA_SUCCESS || hash_len != 32)
		return sha_failed;

	/* X25519 clamp (RFC 7748 §5) */
	seed_hash[0]  &= 248;
	seed_hash[31] &= 127;
	seed_hash[31] |= 64;

	/* sk = clamped seed_hash */
	memcpy(sk->ptr, seed_hash, 32);
	sk->len = 32;

	/* pk = scalar × basepoint */
	if (crypto_scalarmult_base(pk->ptr, sk->ptr) != 0)
		return crypto_operation_not_implemented;
	pk->len = 32;

	return ok;
}

/* ========================================================================
 * 2.  shared_secret_derive  —  X25519 ECDH
 * ======================================================================== */
enum err shared_secret_derive(enum ecdh_alg alg,
			      const struct byte_array *sk,
			      const struct byte_array *pk,
			      uint8_t *shared_secret)
{
	if (alg != X25519)
		return unsupported_ecdh_curve;

	if (crypto_scalarmult(shared_secret, sk->ptr, pk->ptr) != 0)
		return crypto_operation_not_implemented;

	return ok;
}

/* ========================================================================
 * 3.  sign  —  Ed25519 signature
 * ======================================================================== */
enum err sign(enum sign_alg alg, const struct byte_array *sk,
	      const struct byte_array *pk, const struct byte_array *msg,
	      uint8_t *out)
{
	if (alg != EdDSA)
		return unsupported_ecdh_curve;

	/*
	 * libsodium's crypto_sign_detached() expects a 64-byte "secret key"
	 * that is really (seed ‖ pk).  The EDHOC library passes sk (32 bytes)
	 * and pk (32 bytes) separately, so we concatenate them.
	 */
	uint8_t sk64[64];
	memcpy(sk64, sk->ptr, 32);
	memcpy(sk64 + 32, pk->ptr, 32);

	unsigned long long sig_len = 0;
	if (crypto_sign_detached(out, &sig_len, msg->ptr, msg->len, sk64) != 0)
		return sign_failed;

	return ok;
}

/* ========================================================================
 * 4.  verify  —  Ed25519 signature verification
 * ======================================================================== */
enum err verify(enum sign_alg alg, const struct byte_array *pk,
		struct const_byte_array *msg, struct const_byte_array *sgn,
		bool *result)
{
	if (alg != EdDSA)
		return unsupported_ecdh_curve;

	int rc = crypto_sign_verify_detached(sgn->ptr, msg->ptr, msg->len,
					     pk->ptr);
	*result = (rc == 0);
	return ok;
}
