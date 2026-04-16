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
 *   5. hash(SHA_256, …)               — SHA-256 hash
 *   6. hkdf_extract(SHA_256, …)       — HKDF-Extract (HMAC-SHA256)
 *   7. hkdf_expand(SHA_256, …)        — HKDF-Expand (HMAC-SHA256)
 */

#include <string.h>
#include <sodium.h>

#include "common/crypto_wrapper.h"
#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

#include "edhoc/suites.h"
#include "edhoc/buffer_sizes.h"

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

	if (crypto_hash_sha256(seed_hash,
			       (const uint8_t *)&seed, sizeof(seed)) != 0)
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

/* ========================================================================
 * 5.  hash  —  SHA-256 via libsodium
 * ======================================================================== */
enum err hash(enum hash_alg alg, const struct byte_array *in,
	      struct byte_array *out)
{
	if (alg != SHA_256)
		return crypto_operation_not_implemented;

	if (crypto_hash_sha256(out->ptr, in->ptr, in->len) != 0)
		return sha_failed;

	out->len = 32;
	return ok;
}

/* ========================================================================
 * 6.  hkdf_extract  —  HMAC-SHA256 via libsodium
 * ======================================================================== */
enum err hkdf_extract(enum hash_alg alg, const struct byte_array *salt,
		      struct byte_array *ikm, uint8_t *out)
{
	if (alg != SHA_256)
		return crypto_operation_not_implemented;

	crypto_auth_hmacsha256_state st;
	if (salt->ptr && salt->len > 0) {
		crypto_auth_hmacsha256_init(&st, salt->ptr, salt->len);
	} else {
		uint8_t zero_salt[32] = { 0 };
		crypto_auth_hmacsha256_init(&st, zero_salt, 32);
	}
	crypto_auth_hmacsha256_update(&st, ikm->ptr, ikm->len);
	crypto_auth_hmacsha256_final(&st, out);

	return ok;
}

/* ========================================================================
 * 7.  hkdf_expand  —  HMAC-SHA256 via libsodium
 * ======================================================================== */
enum err hkdf_expand(enum hash_alg alg, const struct byte_array *prk,
		     const struct byte_array *info, struct byte_array *out)
{
	if (alg != SHA_256)
		return crypto_operation_not_implemented;

	uint32_t iterations = (out->len + 31) / 32;
	if (iterations > 255)
		return hkdf_failed;

	uint8_t t[32];
	size_t t_len = 0;

	for (uint8_t i = 1; i <= (uint8_t)iterations; i++) {
		crypto_auth_hmacsha256_state st;
		crypto_auth_hmacsha256_init(&st, prk->ptr, prk->len);
		if (i > 1)
			crypto_auth_hmacsha256_update(&st, t, t_len);
		crypto_auth_hmacsha256_update(&st, info->ptr, info->len);
		crypto_auth_hmacsha256_update(&st, &i, 1);
		crypto_auth_hmacsha256_final(&st, t);
		t_len = 32;

		size_t remain = out->len - ((size_t)(i - 1) * 32);
		size_t chunk = (remain > 32) ? 32 : remain;
		memcpy(out->ptr + ((size_t)(i - 1) * 32), t, chunk);
	}

	return ok;
}
