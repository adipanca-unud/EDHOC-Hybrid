/*
 * =============================================================================
 * EDHOC-Hybrid: Type 3 Hybrid (ECDHE + KEM) Implementation
 * =============================================================================
 *
 * Hybrid EDHOC Type 3 combining X25519 ECDHE with ML-KEM-768 for key
 * agreement and static-ECDHE MAC-based authentication.
 *
 * PRK derivation uses chained HKDF-Extract that incorporates BOTH the
 * ECDHE shared secrets AND the KEM shared secret, so security holds if
 * either the classical DH or the KEM remains unbroken.
 *
 * === Protocol Flow (per user's mermaid diagram) ===
 *
 * PRECOMPUTATION (Initiator):
 *   (sk_KEM, PK_KEM) = KEM.KeyGen()
 *   (x, X) = ECDHE.KeyGen()
 *
 * STEP 1 — Initiator builds M1:
 *   M1 = (Method, Suites, CI, EAD1, X, PK_KEM)
 *   → send M1
 *
 * STEP 2 — Responder:
 *   parse M1
 *   (y, Y) = ECDHE.KeyGen()
 *   (k_KEM, C_KEM) = KEM.Enc(PK_KEM)
 *   TH2 = H(M1, Y, C_KEM)
 *   PRK2e = HKDF-Extract(X·y, k_KEM ‖ TH2)          [ECDHE + KEM]
 *   (EK2, IV2) = HKDF-Expand(PRK2e, X·b ‖ TH2)
 *   PRK3e2m = HKDF-Extract(X·b, PRK2e)               [static DH auth]
 *   MK2 = HKDF-Expand(PRK3e2m, TH2)
 *   MAC2 = KDF(MK2, R, B, TH2, EAD2)
 *   msg2 = (CR, R, EAD2, MAC2)
 *   → send M2 = (Y, Suites, C_KEM, AEAD(EK2, msg2))
 *
 * STEP 3 — Initiator:
 *   parse M2
 *   k_KEM = KEM.Dec(sk_KEM, C_KEM)
 *   TH2 = H(M1, Y, C_KEM)
 *   PRK2e = HKDF-Extract(Y·x, k_KEM ‖ TH2)
 *   (EK2, IV2) = HKDF-Expand(PRK2e, B·x ‖ TH2)
 *   msg2 = AEAD.Dec(EK2, …)
 *   PRK3e2m = HKDF-Extract(B·x, PRK2e)
 *   MK2 → verify MAC2
 *   TH3 = H(TH2, msg2, B)
 *   (EK3, IV3) = HKDF-Expand(PRK3e2m, TH3)
 *   PRK4e3m = HKDF-Extract(Y·a, PRK3e2m)             [Initiator static DH]
 *   MK3 → MAC3
 *   msg3 = (I, EAD3, MAC3)
 *   TH4 = H(TH3, msg3, A)
 *   PRK_out = HKDF-Expand(PRK4e3m, TH4)
 *   → send M3 = AEAD(EK3, msg3)
 *
 * STEP 4 — Responder:
 *   parse M3 → verify MAC3
 *   PRK4e3m = HKDF-Extract(A·y, PRK3e2m)
 *   TH4 → PRK_out = HKDF-Expand(PRK4e3m, TH4)
 *
 * =============================================================================
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include "edhoc_type3_hybrid.h"
#include "edhoc_pq_kem.h"
#include "edhoc_common.h"

/* crypto_wrapper for X25519 ECDHE */
#include "common/crypto_wrapper.h"
#include "edhoc/suites.h"

/* ── Timing helper ── */
static inline uint64_t hyb_get_time_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

__thread uint64_t hyb_txrx_ns = 0;

/* ── Shared message exchange (same pattern as PQ variants) ── */
#define HYB_MSG_BUF_SIZE 8192

struct hyb_msg_exchange {
	uint8_t  msg1_buf[HYB_MSG_BUF_SIZE];
	uint32_t msg1_len;
	uint8_t  msg2_buf[HYB_MSG_BUF_SIZE];
	uint32_t msg2_len;
	uint8_t  msg3_buf[HYB_MSG_BUF_SIZE];
	uint32_t msg3_len;
	pthread_mutex_t mutex;
	pthread_cond_t  cond_msg1_ready;
	pthread_cond_t  cond_msg2_ready;
	pthread_cond_t  cond_msg3_ready;
	int msg1_ready;
	int msg2_ready;
	int msg3_ready;
};

static struct hyb_msg_exchange g_hyb_exchange;

void hybrid_exchange_init(void)
{
	memset(&g_hyb_exchange, 0, sizeof(g_hyb_exchange));
	pthread_mutex_init(&g_hyb_exchange.mutex, NULL);
	pthread_cond_init(&g_hyb_exchange.cond_msg1_ready, NULL);
	pthread_cond_init(&g_hyb_exchange.cond_msg2_ready, NULL);
	pthread_cond_init(&g_hyb_exchange.cond_msg3_ready, NULL);
}

void hybrid_exchange_destroy(void)
{
	pthread_mutex_destroy(&g_hyb_exchange.mutex);
	pthread_cond_destroy(&g_hyb_exchange.cond_msg1_ready);
	pthread_cond_destroy(&g_hyb_exchange.cond_msg2_ready);
	pthread_cond_destroy(&g_hyb_exchange.cond_msg3_ready);
}

/* Info labels for HKDF-Expand derivations */
static const uint8_t HYB_EK2[]  = "EDHOC-HYB-EK2";
static const uint8_t HYB_EK3[]  = "EDHOC-HYB-EK3";
static const uint8_t HYB_MK2[]  = "EDHOC-HYB-MK2";
static const uint8_t HYB_MK3[]  = "EDHOC-HYB-MK3";
static const uint8_t HYB_PRK[]  = "EDHOC-HYB-PRK";
static const uint8_t HYB_AK[]   = "EDHOC-HYB-AK";
static const uint8_t HYB_ID_I[] = "EDHOC-HYB-Initiator";
static const uint8_t HYB_ID_R[] = "EDHOC-HYB-Responder";

/* ── Libsodium-based HKDF wrappers (same backend as classic EDHOC) ── */

/**
 * hyb_hkdf_extract — HKDF-Extract using libsodium HMAC-SHA256
 * (same code path as classic EDHOC's hkdf_extract() in crypto_wrapper.c)
 */
static int hyb_hkdf_extract(const uint8_t *salt, size_t salt_len,
			    const uint8_t *ikm, size_t ikm_len,
			    uint8_t *prk_out)
{
	struct byte_array salt_ba = {
		.len = (uint32_t)salt_len,
		.ptr = (uint8_t *)salt
	};
	struct byte_array ikm_ba = {
		.len = (uint32_t)ikm_len,
		.ptr = (uint8_t *)ikm
	};
	/* Handle NULL salt: crypto_wrapper checks salt->ptr internally */
	if (salt == NULL || salt_len == 0) {
		salt_ba.ptr = NULL;
		salt_ba.len = 0;
	}
	enum err r = hkdf_extract(SHA_256, &salt_ba, &ikm_ba, prk_out);
	return (r == ok) ? 0 : -1;
}

/**
 * hyb_hkdf_expand — HKDF-Expand using libsodium HMAC-SHA256
 * (same code path as classic EDHOC's hkdf_expand() in crypto_wrapper.c)
 */
static int hyb_hkdf_expand(const uint8_t *prk,
			   const uint8_t *info, size_t info_len,
			   uint8_t *okm, size_t okm_len)
{
	struct byte_array prk_ba = {
		.len = 32,
		.ptr = (uint8_t *)prk
	};
	struct byte_array info_ba = {
		.len = (uint32_t)info_len,
		.ptr = (uint8_t *)info
	};
	struct byte_array okm_ba = {
		.len = (uint32_t)okm_len,
		.ptr = okm
	};
	enum err r = hkdf_expand(SHA_256, &prk_ba, &info_ba, &okm_ba);
	return (r == ok) ? 0 : -1;
}

/**
 * hyb_hash_sha256 — SHA-256 using mbedTLS PSA hash
 * (same code path as classic EDHOC's hash() in crypto_wrapper.c)
 */
static int hyb_hash_sha256(const uint8_t *data, size_t data_len,
			   uint8_t *hash_out)
{
	struct byte_array in = {
		.len = (uint32_t)data_len,
		.ptr = (uint8_t *)data
	};
	struct byte_array out = {
		.len = 32,
		.ptr = hash_out
	};
	enum err r = hash(SHA_256, &in, &out);
	return (r == ok) ? 0 : -1;
}

/**
 * hyb_aead_encrypt — AES-CCM-16-64-128 encrypt using mbedTLS PSA
 * (same code path as classic EDHOC's aead() in crypto_wrapper.c)
 */
static int hyb_aead_encrypt(const uint8_t *key, const uint8_t *nonce,
			    const uint8_t *aad, size_t aad_len,
			    const uint8_t *pt, size_t pt_len,
			    uint8_t *ct, size_t *ct_len)
{
	uint8_t tag_buf[PQ_AEAD_TAG_LEN];
	struct byte_array plain  = { .len = (uint32_t)pt_len,  .ptr = (uint8_t *)pt };
	struct byte_array k_ba   = { .len = PQ_AEAD_KEY_LEN,   .ptr = (uint8_t *)key };
	struct byte_array n_ba   = { .len = PQ_AEAD_NONCE_LEN, .ptr = (uint8_t *)nonce };
	struct byte_array aad_ba = { .len = (uint32_t)aad_len, .ptr = (uint8_t *)aad };
	struct byte_array ciph   = { .len = (uint32_t)pt_len,  .ptr = ct };
	struct byte_array tag_ba = { .len = PQ_AEAD_TAG_LEN,   .ptr = tag_buf };

	enum err r = aead(ENCRYPT, &plain, &k_ba, &n_ba, &aad_ba, &ciph, &tag_ba);
	if (r != ok) return -1;

	/* Append tag after ciphertext (same layout as hyb_aead_encrypt) */
	memcpy(ct + pt_len, tag_buf, PQ_AEAD_TAG_LEN);
	*ct_len = pt_len + PQ_AEAD_TAG_LEN;
	return 0;
}

/**
 * hyb_aead_decrypt — AES-CCM-16-64-128 decrypt using mbedTLS PSA
 * (same code path as classic EDHOC's aead() in crypto_wrapper.c)
 */
static int hyb_aead_decrypt(const uint8_t *key, const uint8_t *nonce,
			    const uint8_t *aad, size_t aad_len,
			    const uint8_t *ct, size_t ct_len,
			    uint8_t *pt, size_t *pt_len)
{
	if (ct_len < PQ_AEAD_TAG_LEN) return -1;
	size_t plain_len = ct_len - PQ_AEAD_TAG_LEN;

	/* crypto_wrapper aead(DECRYPT) expects ct+tag concatenated as input */
	struct byte_array ct_ba  = { .len = (uint32_t)ct_len,       .ptr = (uint8_t *)ct };
	struct byte_array k_ba   = { .len = PQ_AEAD_KEY_LEN,        .ptr = (uint8_t *)key };
	struct byte_array n_ba   = { .len = PQ_AEAD_NONCE_LEN,      .ptr = (uint8_t *)nonce };
	struct byte_array aad_ba = { .len = (uint32_t)aad_len,      .ptr = (uint8_t *)aad };
	struct byte_array pt_ba  = { .len = (uint32_t)plain_len,    .ptr = pt };
	struct byte_array tag_ba = { .len = PQ_AEAD_TAG_LEN,
				     .ptr = (uint8_t *)(ct + plain_len) };

	enum err r = aead(DECRYPT, &ct_ba, &k_ba, &n_ba, &aad_ba, &pt_ba, &tag_ba);
	if (r != ok) return -1;
	*pt_len = plain_len;
	return 0;
}

/* ── Derive EK + IV from PRK using label ── */
static int hyb_derive_key_iv(const uint8_t *prk,
			     const uint8_t *label, size_t label_len,
			     const uint8_t *th, size_t th_len,
			     uint8_t *key, uint8_t *iv)
{
	/* info = label ‖ th */
	uint8_t info[128];
	size_t info_len = label_len + th_len;
	memcpy(info, label, label_len);
	memcpy(info + label_len, th, th_len);

	if (hyb_hkdf_expand(prk, info, info_len, key, PQ_AEAD_KEY_LEN) != 0)
		return -1;
	/* IV: XOR first byte of label to differentiate */
	info[0] ^= 0xFF;
	if (hyb_hkdf_expand(prk, info, info_len, iv, PQ_AEAD_NONCE_LEN) != 0)
		return -1;
	return 0;
}

/* ── X25519 ECDH wrapper (uses libsodium via crypto_wrapper) ── */
static int hyb_ecdh(const uint8_t *my_sk, const uint8_t *peer_pk,
		    uint8_t *shared_out)
{
	struct byte_array sk_ba = { .len = 32, .ptr = (uint8_t *)my_sk };
	struct byte_array pk_ba = { .len = 32, .ptr = (uint8_t *)peer_pk };
	enum err r = shared_secret_derive(X25519, &sk_ba, &pk_ba, shared_out);
	return (r == ok) ? 0 : -1;
}

/* =============================================================================
 * Initiator Thread
 * =============================================================================
 */
void *hybrid_initiator_thread(void *arg)
{
	struct hybrid_party_ctx *ctx = (struct hybrid_party_ctx *)arg;
	int ret;
	hyb_txrx_ns = 0;

	/* ────────────────────────────────────────────────────
	 * PRECOMPUTATION:
	 *   (x, X) = ECDHE.KeyGen()  — already in ctx->eph_sk/eph_pk
	 *   (sk_KEM, PK_KEM) = KEM.KeyGen()  — already in ctx->kem_sk/kem_pk
	 * ──────────────────────────────────────────────────── */

	/* ── Build M1 = (Method, Suites, CI, EAD1, X, PK_KEM) ── */
	uint8_t m1_buf[HYB_MSG_BUF_SIZE];
	uint32_t m1_len = 0;

	/* Header: method=3, suite=HYB, C_I */
	m1_buf[m1_len++] = 0x03;  /* METHOD = 3 (MAC-MAC) */
	m1_buf[m1_len++] = 0xFE;  /* SUITES = Hybrid marker */
	m1_buf[m1_len++] = 0x37;  /* C_I */

	/* Ephemeral ECDHE public key X (32 bytes) */
	memcpy(m1_buf + m1_len, ctx->eph_pk, 32);
	m1_len += 32;

	/* KEM public key PK_KEM */
	memcpy(m1_buf + m1_len, ctx->kem_pk, PQ_KEM_PK_LEN);
	m1_len += PQ_KEM_PK_LEN;

	/* ── Send M1 ── */
	{
		uint64_t t0 = hyb_get_time_ns();
		pthread_mutex_lock(&g_hyb_exchange.mutex);
		memcpy(g_hyb_exchange.msg1_buf, m1_buf, m1_len);
		g_hyb_exchange.msg1_len = m1_len;
		g_hyb_exchange.msg1_ready = 1;
		pthread_cond_signal(&g_hyb_exchange.cond_msg1_ready);
		pthread_mutex_unlock(&g_hyb_exchange.mutex);
		hyb_txrx_ns += (hyb_get_time_ns() - t0);
	}

	/* ── Receive M2 ── */
	{
		uint64_t t0 = hyb_get_time_ns();
		pthread_mutex_lock(&g_hyb_exchange.mutex);
		while (!g_hyb_exchange.msg2_ready)
			pthread_cond_wait(&g_hyb_exchange.cond_msg2_ready,
					  &g_hyb_exchange.mutex);
		pthread_mutex_unlock(&g_hyb_exchange.mutex);
		hyb_txrx_ns += (hyb_get_time_ns() - t0);
	}

	/* ── Parse M2 = (Y[32], C_KEM[1088], len16, AEAD_ct) ── */
	uint8_t *m2 = g_hyb_exchange.msg2_buf;
	uint32_t off = 0;

	uint8_t peer_eph_pk[32];
	memcpy(peer_eph_pk, m2 + off, 32); off += 32;  /* Y */

	uint8_t c_kem[PQ_KEM_CT_LEN];
	memcpy(c_kem, m2 + off, PQ_KEM_CT_LEN); off += PQ_KEM_CT_LEN;

	uint16_t ct2_len = (m2[off] << 8) | m2[off + 1]; off += 2;
	uint8_t ct2_aead[512 + PQ_AEAD_TAG_LEN];
	memcpy(ct2_aead, m2 + off, ct2_len);

	/* ── k_KEM = KEM.Dec(sk_KEM, C_KEM) ── */
	uint8_t k_kem[PQ_KEM_SS_LEN];
	ret = pq_kem_decaps(k_kem, c_kem, ctx->kem_sk);
	if (ret != 0) { print_error("HYB Init: KEM.Dec failed"); return NULL; }

	/* ── ECDH: Yx = Y·x (ephemeral shared secret) ── */
	uint8_t ss_eph[32];
	ret = hyb_ecdh(ctx->eph_sk, peer_eph_pk, ss_eph);
	if (ret != 0) { print_error("HYB Init: ECDH(Y,x) failed"); return NULL; }

	/* ── TH2 = H(M1, Y, C_KEM) ── */
	{
		uint8_t th2_in[HYB_MSG_BUF_SIZE];
		uint32_t th2_in_len = 0;
		memcpy(th2_in, m1_buf, m1_len); th2_in_len += m1_len;
		memcpy(th2_in + th2_in_len, peer_eph_pk, 32); th2_in_len += 32;
		memcpy(th2_in + th2_in_len, c_kem, PQ_KEM_CT_LEN); th2_in_len += PQ_KEM_CT_LEN;
		ret = hyb_hash_sha256(th2_in, th2_in_len, ctx->th2);
		if (ret != 0) { print_error("HYB Init: TH2 failed"); return NULL; }
	}

	/* ── PRK2e = HKDF-Extract(Yx, k_KEM ‖ TH2) ──
	 * salt = ss_eph (ECDHE shared secret)
	 * IKM  = k_kem ‖ TH2 (KEM shared secret + transcript hash) */
	{
		uint8_t ikm[PQ_KEM_SS_LEN + 32];
		memcpy(ikm, k_kem, PQ_KEM_SS_LEN);
		memcpy(ikm + PQ_KEM_SS_LEN, ctx->th2, 32);
		ret = hyb_hkdf_extract(ss_eph, 32, ikm, PQ_KEM_SS_LEN + 32, ctx->prk2e);
		if (ret != 0) { print_error("HYB Init: PRK2e failed"); return NULL; }
	}

	/* ── ECDH: Bx = B·x (static DH for auth) ── */
	uint8_t ss_bx[32];
	ret = hyb_ecdh(ctx->eph_sk, ctx->other_static_pk, ss_bx);
	if (ret != 0) { print_error("HYB Init: ECDH(B,x) failed"); return NULL; }

	/* ── (EK2, IV2) = HKDF-Expand(PRK2e, Bx ‖ TH2) ── */
	uint8_t ek2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
	{
		uint8_t expand_ctx[64];
		memcpy(expand_ctx, ss_bx, 32);
		memcpy(expand_ctx + 32, ctx->th2, 32);
		ret = hyb_derive_key_iv(ctx->prk2e, HYB_EK2, sizeof(HYB_EK2) - 1,
					expand_ctx, 64, ek2, iv2);
		if (ret != 0) { print_error("HYB Init: EK2/IV2 failed"); return NULL; }
	}

	/* ── Decrypt msg2 = AEAD.Dec(EK2, ct2) ── */
	uint8_t pt2[512];
	size_t pt2_len = 0;
	ret = hyb_aead_decrypt(ek2, iv2, NULL, 0, ct2_aead, ct2_len, pt2, &pt2_len);
	if (ret != 0) { print_error("HYB Init: AEAD dec msg2 failed"); return NULL; }

	/* ── PRK3e2m = HKDF-Extract(Bx, PRK2e) ── */
	ret = hyb_hkdf_extract(ss_bx, 32, ctx->prk2e, 32, ctx->prk3e2m);
	if (ret != 0) { print_error("HYB Init: PRK3e2m failed"); return NULL; }

	/* ── MK2 = HKDF-Expand(PRK3e2m, TH2) → Verify MAC2 ── */
	uint8_t mk2[PQ_AEAD_TAG_LEN];
	{
		uint8_t mk2_info[32 + 64];
		memcpy(mk2_info, ctx->th2, 32);
		memcpy(mk2_info + 32, HYB_ID_R, sizeof(HYB_ID_R) - 1);
		ret = hyb_hkdf_expand(ctx->prk3e2m, mk2_info,
				     32 + sizeof(HYB_ID_R) - 1,
				     mk2, PQ_AEAD_TAG_LEN);
		if (ret != 0) { print_error("HYB Init: MK2 failed"); return NULL; }
	}

	if (pt2_len < PQ_AEAD_TAG_LEN ||
	    memcmp(mk2, pt2 + pt2_len - PQ_AEAD_TAG_LEN, PQ_AEAD_TAG_LEN) != 0) {
		print_error("HYB Init: MAC2 verify FAILED");
		return NULL;
	}

	/* ── TH3 = H(TH2, msg2, B) ── */
	{
		uint8_t th3_in[HYB_MSG_BUF_SIZE];
		uint32_t len = 0;
		memcpy(th3_in, ctx->th2, 32); len += 32;
		memcpy(th3_in + len, g_hyb_exchange.msg2_buf, g_hyb_exchange.msg2_len);
		len += g_hyb_exchange.msg2_len;
		memcpy(th3_in + len, ctx->other_static_pk, 32); len += 32;
		ret = hyb_hash_sha256(th3_in, len, ctx->th3);
		if (ret != 0) { print_error("HYB Init: TH3 failed"); return NULL; }
	}

	/* ── (EK3, IV3) = HKDF-Expand(PRK3e2m, TH3) ── */
	uint8_t ek3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
	ret = hyb_derive_key_iv(ctx->prk3e2m, HYB_EK3, sizeof(HYB_EK3) - 1,
				ctx->th3, 32, ek3, iv3);
	if (ret != 0) { print_error("HYB Init: EK3/IV3 failed"); return NULL; }

	/* ── PRK4e3m = HKDF-Extract(Ya, PRK3e2m) ──
	 * Ya = Y·a (peer ephemeral × my static) */
	uint8_t ss_ya[32];
	ret = hyb_ecdh(ctx->static_sk, peer_eph_pk, ss_ya);
	if (ret != 0) { print_error("HYB Init: ECDH(Y,a) failed"); return NULL; }
	ret = hyb_hkdf_extract(ss_ya, 32, ctx->prk3e2m, 32, ctx->prk4e3m);
	if (ret != 0) { print_error("HYB Init: PRK4e3m failed"); return NULL; }

	/* ── MK3 → MAC3 ── */
	uint8_t mac3[PQ_AEAD_TAG_LEN];
	{
		uint8_t mk3_info[32 + 64];
		memcpy(mk3_info, ctx->th3, 32);
		memcpy(mk3_info + 32, HYB_ID_I, sizeof(HYB_ID_I) - 1);
		ret = hyb_hkdf_expand(ctx->prk4e3m, mk3_info,
				     32 + sizeof(HYB_ID_I) - 1,
				     mac3, PQ_AEAD_TAG_LEN);
		if (ret != 0) { print_error("HYB Init: MAC3 failed"); return NULL; }
	}

	/* ── msg3 plaintext = (I ‖ EAD3 ‖ MAC3) ── */
	uint8_t pt3[128];
	uint32_t pt3_len = 0;
	memcpy(pt3 + pt3_len, HYB_ID_I, sizeof(HYB_ID_I) - 1);
	pt3_len += sizeof(HYB_ID_I) - 1;
	memcpy(pt3 + pt3_len, mac3, PQ_AEAD_TAG_LEN);
	pt3_len += PQ_AEAD_TAG_LEN;

	uint8_t ct3_aead[128 + PQ_AEAD_TAG_LEN];
	size_t ct3_len = 0;
	ret = hyb_aead_encrypt(ek3, iv3, NULL, 0, pt3, pt3_len,
			      ct3_aead, &ct3_len);
	if (ret != 0) { print_error("HYB Init: AEAD enc msg3 failed"); return NULL; }

	/* ── TH4 = H(TH3, msg3, A) ── */
	{
		uint8_t th4_in[256];
		uint32_t len = 0;
		memcpy(th4_in, ctx->th3, 32); len += 32;
		memcpy(th4_in + len, ct3_aead, ct3_len); len += ct3_len;
		memcpy(th4_in + len, ctx->static_pk, 32); len += 32;
		ret = hyb_hash_sha256(th4_in, len, ctx->th4);
		if (ret != 0) { print_error("HYB Init: TH4 failed"); return NULL; }
	}

	/* ── PRK_out = HKDF-Expand(PRK4e3m, TH4) ── */
	ret = hyb_hkdf_expand(ctx->prk4e3m, ctx->th4, 32, ctx->prk_out, 32);
	if (ret != 0) { print_error("HYB Init: PRK_out failed"); return NULL; }

	/* ── Send M3 ── */
	{
		uint64_t t0 = hyb_get_time_ns();
		pthread_mutex_lock(&g_hyb_exchange.mutex);
		memcpy(g_hyb_exchange.msg3_buf, ct3_aead, ct3_len);
		g_hyb_exchange.msg3_len = (uint32_t)ct3_len;
		g_hyb_exchange.msg3_ready = 1;
		pthread_cond_signal(&g_hyb_exchange.cond_msg3_ready);
		pthread_mutex_unlock(&g_hyb_exchange.mutex);
		hyb_txrx_ns += (hyb_get_time_ns() - t0);
	}

	ctx->success = 1;
	ctx->txrx_ns = hyb_txrx_ns;
	print_success("HYB Initiator: EDHOC Hybrid exchange completed!");
	return NULL;
}

/* =============================================================================
 * Responder Thread
 * =============================================================================
 */
void *hybrid_responder_thread(void *arg)
{
	struct hybrid_party_ctx *ctx = (struct hybrid_party_ctx *)arg;
	int ret;
	hyb_txrx_ns = 0;

	/* ── Receive M1 ── */
	{
		uint64_t t0 = hyb_get_time_ns();
		pthread_mutex_lock(&g_hyb_exchange.mutex);
		while (!g_hyb_exchange.msg1_ready)
			pthread_cond_wait(&g_hyb_exchange.cond_msg1_ready,
					  &g_hyb_exchange.mutex);
		pthread_mutex_unlock(&g_hyb_exchange.mutex);
		hyb_txrx_ns += (hyb_get_time_ns() - t0);
	}

	/* ── Parse M1 = (method, suites, C_I, X[32], PK_KEM[1184]) ── */
	uint8_t *m1 = g_hyb_exchange.msg1_buf;
	uint32_t m1_len = g_hyb_exchange.msg1_len;
	uint32_t off = 3;  /* skip method + suites + C_I */

	uint8_t peer_eph_pk[32];
	memcpy(peer_eph_pk, m1 + off, 32); off += 32;  /* X */

	uint8_t pk_kem[PQ_KEM_PK_LEN];
	memcpy(pk_kem, m1 + off, PQ_KEM_PK_LEN);

	/* ── (y, Y) = ECDHE.KeyGen() ── */
	/* ctx->eph_sk/eph_pk already set by caller */

	/* ── (k_KEM, C_KEM) = KEM.Enc(PK_KEM) ── */
	uint8_t k_kem[PQ_KEM_SS_LEN], c_kem[PQ_KEM_CT_LEN];
	ret = pq_kem_encaps(c_kem, k_kem, pk_kem);
	if (ret != 0) { print_error("HYB Resp: KEM.Enc failed"); return NULL; }

	/* ── ECDH: Xy = X·y (ephemeral shared secret) ── */
	uint8_t ss_eph[32];
	ret = hyb_ecdh(ctx->eph_sk, peer_eph_pk, ss_eph);
	if (ret != 0) { print_error("HYB Resp: ECDH(X,y) failed"); return NULL; }

	/* ── TH2 = H(M1, Y, C_KEM) ── */
	{
		uint8_t th2_in[HYB_MSG_BUF_SIZE];
		uint32_t th2_in_len = 0;
		memcpy(th2_in, m1, m1_len); th2_in_len += m1_len;
		memcpy(th2_in + th2_in_len, ctx->eph_pk, 32); th2_in_len += 32;
		memcpy(th2_in + th2_in_len, c_kem, PQ_KEM_CT_LEN); th2_in_len += PQ_KEM_CT_LEN;
		ret = hyb_hash_sha256(th2_in, th2_in_len, ctx->th2);
		if (ret != 0) { print_error("HYB Resp: TH2 failed"); return NULL; }
	}

	/* ── PRK2e = HKDF-Extract(Xy, k_KEM ‖ TH2) ── */
	{
		uint8_t ikm[PQ_KEM_SS_LEN + 32];
		memcpy(ikm, k_kem, PQ_KEM_SS_LEN);
		memcpy(ikm + PQ_KEM_SS_LEN, ctx->th2, 32);
		ret = hyb_hkdf_extract(ss_eph, 32, ikm, PQ_KEM_SS_LEN + 32, ctx->prk2e);
		if (ret != 0) { print_error("HYB Resp: PRK2e failed"); return NULL; }
	}

	/* ── ECDH: Xb = X·b (static DH for auth) ── */
	uint8_t ss_xb[32];
	ret = hyb_ecdh(ctx->static_sk, peer_eph_pk, ss_xb);
	if (ret != 0) { print_error("HYB Resp: ECDH(X,b) failed"); return NULL; }

	/* ── (EK2, IV2) = HKDF-Expand(PRK2e, Xb ‖ TH2) ── */
	uint8_t ek2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
	{
		uint8_t expand_ctx[64];
		memcpy(expand_ctx, ss_xb, 32);
		memcpy(expand_ctx + 32, ctx->th2, 32);
		ret = hyb_derive_key_iv(ctx->prk2e, HYB_EK2, sizeof(HYB_EK2) - 1,
					expand_ctx, 64, ek2, iv2);
		if (ret != 0) { print_error("HYB Resp: EK2/IV2 failed"); return NULL; }
	}

	/* ── PRK3e2m = HKDF-Extract(Xb, PRK2e) ── */
	ret = hyb_hkdf_extract(ss_xb, 32, ctx->prk2e, 32, ctx->prk3e2m);
	if (ret != 0) { print_error("HYB Resp: PRK3e2m failed"); return NULL; }

	/* ── MK2 = HKDF-Expand(PRK3e2m, TH2) → MAC2 ── */
	uint8_t mac2[PQ_AEAD_TAG_LEN];
	{
		uint8_t mk2_info[32 + 64];
		memcpy(mk2_info, ctx->th2, 32);
		memcpy(mk2_info + 32, HYB_ID_R, sizeof(HYB_ID_R) - 1);
		ret = hyb_hkdf_expand(ctx->prk3e2m, mk2_info,
				     32 + sizeof(HYB_ID_R) - 1,
				     mac2, PQ_AEAD_TAG_LEN);
		if (ret != 0) { print_error("HYB Resp: MAC2 failed"); return NULL; }
	}

	/* ── msg2 plaintext = (CR, R, EAD2, MAC2) ── */
	uint8_t pt2[256];
	uint32_t pt2_len = 0;
	pt2[pt2_len++] = 0x27;  /* C_R */
	memcpy(pt2 + pt2_len, HYB_ID_R, sizeof(HYB_ID_R) - 1);
	pt2_len += sizeof(HYB_ID_R) - 1;
	memcpy(pt2 + pt2_len, mac2, PQ_AEAD_TAG_LEN);
	pt2_len += PQ_AEAD_TAG_LEN;

	uint8_t ct2_aead[512 + PQ_AEAD_TAG_LEN];
	size_t ct2_aead_len = 0;
	ret = hyb_aead_encrypt(ek2, iv2, NULL, 0, pt2, pt2_len,
			      ct2_aead, &ct2_aead_len);
	if (ret != 0) { print_error("HYB Resp: AEAD enc msg2 failed"); return NULL; }

	/* ── Send M2 = (Y[32], C_KEM[1088], len16, AEAD_ct) ── */
	{
		uint64_t t0 = hyb_get_time_ns();
		pthread_mutex_lock(&g_hyb_exchange.mutex);
		{
			uint8_t *p = g_hyb_exchange.msg2_buf;
			uint32_t o = 0;
			memcpy(p + o, ctx->eph_pk, 32);     o += 32;
			memcpy(p + o, c_kem, PQ_KEM_CT_LEN); o += PQ_KEM_CT_LEN;
			p[o++] = (uint8_t)(ct2_aead_len >> 8);
			p[o++] = (uint8_t)(ct2_aead_len & 0xFF);
			memcpy(p + o, ct2_aead, ct2_aead_len); o += ct2_aead_len;
			g_hyb_exchange.msg2_len = o;
			g_hyb_exchange.msg2_ready = 1;
		}
		pthread_cond_signal(&g_hyb_exchange.cond_msg2_ready);
		pthread_mutex_unlock(&g_hyb_exchange.mutex);
		hyb_txrx_ns += (hyb_get_time_ns() - t0);
	}

	/* ── Receive M3 ── */
	{
		uint64_t t0 = hyb_get_time_ns();
		pthread_mutex_lock(&g_hyb_exchange.mutex);
		while (!g_hyb_exchange.msg3_ready)
			pthread_cond_wait(&g_hyb_exchange.cond_msg3_ready,
					  &g_hyb_exchange.mutex);
		pthread_mutex_unlock(&g_hyb_exchange.mutex);
		hyb_txrx_ns += (hyb_get_time_ns() - t0);
	}

	/* ── TH3 = H(TH2, msg2, B) ── */
	{
		uint8_t th3_in[HYB_MSG_BUF_SIZE];
		uint32_t len = 0;
		memcpy(th3_in, ctx->th2, 32); len += 32;
		memcpy(th3_in + len, g_hyb_exchange.msg2_buf, g_hyb_exchange.msg2_len);
		len += g_hyb_exchange.msg2_len;
		memcpy(th3_in + len, ctx->static_pk, 32); len += 32;
		ret = hyb_hash_sha256(th3_in, len, ctx->th3);
		if (ret != 0) { print_error("HYB Resp: TH3 failed"); return NULL; }
	}

	/* ── (EK3, IV3) = HKDF-Expand(PRK3e2m, TH3) ── */
	uint8_t ek3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
	ret = hyb_derive_key_iv(ctx->prk3e2m, HYB_EK3, sizeof(HYB_EK3) - 1,
				ctx->th3, 32, ek3, iv3);
	if (ret != 0) { print_error("HYB Resp: EK3/IV3 failed"); return NULL; }

	/* ── Decrypt msg3 ── */
	uint8_t pt3[128];
	size_t pt3_len = 0;
	ret = hyb_aead_decrypt(ek3, iv3, NULL, 0,
			      g_hyb_exchange.msg3_buf, g_hyb_exchange.msg3_len,
			      pt3, &pt3_len);
	if (ret != 0) { print_error("HYB Resp: AEAD dec msg3 failed"); return NULL; }

	/* ── PRK4e3m = HKDF-Extract(Ay, PRK3e2m)
	 *    Ay = A·y (peer static × my ephemeral) ── */
	uint8_t ss_ay[32];
	ret = hyb_ecdh(ctx->eph_sk, ctx->other_static_pk, ss_ay);
	if (ret != 0) { print_error("HYB Resp: ECDH(A,y) failed"); return NULL; }
	ret = hyb_hkdf_extract(ss_ay, 32, ctx->prk3e2m, 32, ctx->prk4e3m);
	if (ret != 0) { print_error("HYB Resp: PRK4e3m failed"); return NULL; }

	/* ── MK3 → Verify MAC3 ── */
	uint8_t mac3_exp[PQ_AEAD_TAG_LEN];
	{
		uint8_t mk3_info[32 + 64];
		memcpy(mk3_info, ctx->th3, 32);
		memcpy(mk3_info + 32, HYB_ID_I, sizeof(HYB_ID_I) - 1);
		ret = hyb_hkdf_expand(ctx->prk4e3m, mk3_info,
				     32 + sizeof(HYB_ID_I) - 1,
				     mac3_exp, PQ_AEAD_TAG_LEN);
		if (ret != 0) { print_error("HYB Resp: MK3 failed"); return NULL; }
	}

	/* MAC3 is at the end of pt3 */
	if (pt3_len < PQ_AEAD_TAG_LEN ||
	    memcmp(mac3_exp, pt3 + pt3_len - PQ_AEAD_TAG_LEN, PQ_AEAD_TAG_LEN) != 0) {
		print_error("HYB Resp: MAC3 verify FAILED");
		return NULL;
	}

	/* ── TH4 = H(TH3, msg3, A) ── */
	{
		uint8_t th4_in[256];
		uint32_t len = 0;
		memcpy(th4_in, ctx->th3, 32); len += 32;
		memcpy(th4_in + len, g_hyb_exchange.msg3_buf, g_hyb_exchange.msg3_len);
		len += g_hyb_exchange.msg3_len;
		memcpy(th4_in + len, ctx->other_static_pk, 32); len += 32;
		ret = hyb_hash_sha256(th4_in, len, ctx->th4);
		if (ret != 0) { print_error("HYB Resp: TH4 failed"); return NULL; }
	}

	/* ── PRK_out = HKDF-Expand(PRK4e3m, TH4) ── */
	ret = hyb_hkdf_expand(ctx->prk4e3m, ctx->th4, 32, ctx->prk_out, 32);
	if (ret != 0) { print_error("HYB Resp: PRK_out failed"); return NULL; }

	ctx->success = 1;
	ctx->txrx_ns = hyb_txrx_ns;
	print_success("HYB Responder: EDHOC Hybrid exchange completed!");
	return NULL;
}

/* =============================================================================
 * Main entry point
 * =============================================================================
 */
int run_edhoc_type3_hybrid(void)
{
	print_header("EDHOC Type 3 Hybrid: ECDHE (X25519) + KEM (ML-KEM-768)");
	printf("\n");
	print_info("Hybrid EDHOC Type 3 — dual key agreement (classical + PQ)");
	print_info("Key Exchange: X25519 ECDHE + ML-KEM-768 KEM (combined)");
	print_info("Authentication: X25519 Static DH + MAC (MAC-MAC)");
	print_info("Symmetric: AES-CCM-16-64-128, SHA-256, HKDF");
	printf("\n");

	struct hybrid_party_ctx init_ctx, resp_ctx;
	memset(&init_ctx, 0, sizeof(init_ctx));
	memset(&resp_ctx, 0, sizeof(resp_ctx));

	/* Generate static ECDHE key pairs (long-term, pre-provisioned) */
	print_info("Generating static ECDHE key pairs...");
	{
		struct byte_array sk = { .len = 32, .ptr = init_ctx.static_sk };
		struct byte_array pk = { .len = 32, .ptr = init_ctx.static_pk };
		if (ephemeral_dh_key_gen(X25519, 100, &sk, &pk) != ok) {
			print_error("Failed to generate Initiator static keys");
			return -1;
		}
	}
	{
		struct byte_array sk = { .len = 32, .ptr = resp_ctx.static_sk };
		struct byte_array pk = { .len = 32, .ptr = resp_ctx.static_pk };
		if (ephemeral_dh_key_gen(X25519, 200, &sk, &pk) != ok) {
			print_error("Failed to generate Responder static keys");
			return -1;
		}
	}
	memcpy(init_ctx.other_static_pk, resp_ctx.static_pk, 32);
	memcpy(resp_ctx.other_static_pk, init_ctx.static_pk, 32);

	/* Generate ephemeral ECDHE key pairs */
	print_info("Generating ephemeral ECDHE key pairs...");
	{
		struct byte_array sk = { .len = 32, .ptr = init_ctx.eph_sk };
		struct byte_array pk = { .len = 32, .ptr = init_ctx.eph_pk };
		if (ephemeral_dh_key_gen(X25519, 300, &sk, &pk) != ok) {
			print_error("Failed to generate Initiator ephemeral keys");
			return -1;
		}
	}
	{
		struct byte_array sk = { .len = 32, .ptr = resp_ctx.eph_sk };
		struct byte_array pk = { .len = 32, .ptr = resp_ctx.eph_pk };
		if (ephemeral_dh_key_gen(X25519, 400, &sk, &pk) != ok) {
			print_error("Failed to generate Responder ephemeral keys");
			return -1;
		}
	}

	/* Generate ephemeral KEM key pair (Initiator only) */
	print_info("Generating ephemeral KEM key pair (ML-KEM-768)...");
	if (pq_kem_keygen(init_ctx.kem_pk, init_ctx.kem_sk) != 0) {
		print_error("Failed to generate Initiator KEM key pair");
		return -1;
	}

	print_success("All key pairs generated and trust anchors exchanged.");
	printf("\n");

	hybrid_exchange_init();

	pthread_t tid_i, tid_r;
	print_info("Starting EDHOC Hybrid handshake (Type 3)...");
	printf("\n");

	pthread_create(&tid_r, NULL, hybrid_responder_thread, &resp_ctx);
	pthread_create(&tid_i, NULL, hybrid_initiator_thread, &init_ctx);
	pthread_join(tid_i, NULL);
	pthread_join(tid_r, NULL);

	hybrid_exchange_destroy();

	printf("\n");
	print_header("EDHOC Type 3 Hybrid - Results");
	printf("\n");

	if (!init_ctx.success || !resp_ctx.success) {
		print_error("EDHOC Hybrid Type 3 exchange failed!");
		return -1;
	}

	print_hex("Initiator PRK_out", init_ctx.prk_out, 32);
	print_hex("Responder PRK_out", resp_ctx.prk_out, 32);

	if (memcmp(init_ctx.prk_out, resp_ctx.prk_out, 32) == 0) {
		print_success("PRK_out MATCH: Initiator and Responder agree!");
	} else {
		print_error("PRK_out MISMATCH!");
		return -1;
	}

	printf("\n");
	print_success("EDHOC Type 3 Hybrid (X25519 + ML-KEM-768) completed successfully!");
	printf("\n");
	return 0;
}
