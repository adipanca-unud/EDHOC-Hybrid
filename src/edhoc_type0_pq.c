/*
 * =============================================================================
 * EDHOC-Hybrid: Type 0 PQ Implementation (KEM-based Sig-like)
 * =============================================================================
 *
 * Post-Quantum EDHOC variant using ML-KEM-768 for both key exchange and
 * implicit authentication. This is a standalone simulation (not using
 * uoscore-uedhoc library) that follows the user's sequence diagram:
 *
 * === PROTOCOL FLOW (Type 0 PQ — "Sig-like" KEM Authentication) ===
 *
 *   Pre-provisioned:
 *     Initiator: long-term PQ key pair (pkI, skI)
 *     Responder: long-term PQ key pair (pkR, skR)
 *     Both know each other's long-term public keys (via cert/trust anchor)
 *
 *   Step 1 — Initiator:
 *     1. Generate ephemeral PQ KEM key pair: (pk_eph, sk_eph)
 *     2. ss_R = KEM.Encaps(pkR) → (ct_R, ss_R)
 *     3. PRK1 = HKDF-Extract(salt=0, ikm=ss_R)
 *     4. K1, IV1 = HKDF-Expand(PRK1, "K1"/"IV1")
 *     5. Send Message 1: (pk_eph, ct_R, AEAD_K1(METHOD, SUITES, ID_CRED_I, C_I))
 *
 *   Step 2 — Responder:
 *     1. ss_R = KEM.Decaps(ct_R, skR)
 *     2. PRK1 → K1 (derive, decrypt AEAD, verify)
 *     3. (ss_eph, ct_eph2) = KEM.Encaps(pk_eph)
 *     4. PRK2 = HKDF-Extract(PRK1, ss_eph)
 *     5. K2, IV2 = HKDF-Expand(PRK2, "K2"/"IV2")
 *     6. TH2 = Hash(msg1 || ct_eph2)
 *     7. MAC2 = HKDF-Expand(PRK2, TH2 || ID_CRED_R)
 *     8. (ss_I, ct_I) = KEM.Encaps(pkI) → for mutual auth
 *     9. PRK3 = HKDF-Extract(PRK2, ss_I) → "PRK_2e3m equivalent"
 *     10. K3, IV3 = HKDF-Expand(PRK3, "K3"/"IV3")
 *     11. Send Message 2: (ct_eph2, ct_I, AEAD_K2(C_R, ID_CRED_R, MAC2))
 *
 *   Step 3 — Initiator:
 *     1. ss_eph = KEM.Decaps(ct_eph2, sk_eph)
 *     2. PRK2 → K2 (derive, decrypt AEAD, verify)
 *     3. Verify MAC2
 *     4. ss_I = KEM.Decaps(ct_I, skI)
 *     5. PRK3 = HKDF-Extract(PRK2, ss_I)
 *     6. TH3 = Hash(TH2 || msg2)
 *     7. MAC3 = HKDF-Expand(PRK3, TH3 || ID_CRED_I)
 *     8. K3, IV3 = HKDF-Expand(PRK3, "K3_enc"/"IV3_enc")
 *     9. Send Message 3: AEAD_K3(MAC3)
 *
 *   Step 4 — Responder:
 *     1. Verify MAC3
 *     2. PRK_out = HKDF-Expand(PRK3, TH4)
 *
 * === Crypto Operations Count (per Initiator) ===
 *   KEM.KeyGen:    1 (ephemeral)
 *   KEM.Encaps:    1 (to pkR in Step 1)
 *   KEM.Decaps:    2 (ct_eph2 in Step 3, ct_I in Step 3)
 *   HKDF:          ~8 (Extract×3 + Expand×5)
 *   AEAD Encrypt:  1 (msg1) + 1 (msg3) = 2
 *   AEAD Decrypt:  1 (msg2)
 *   Hash:          ~3 (TH2, TH3, TH4)
 *
 * === Crypto Operations Count (per Responder) ===
 *   KEM.KeyGen:    0 (uses pre-provisioned long-term key)
 *   KEM.Encaps:    2 (to pk_eph in Step 2, to pkI in Step 2)
 *   KEM.Decaps:    1 (ct_R in Step 2)
 *   HKDF:          ~8 (Extract×3 + Expand×5)
 *   AEAD Encrypt:  1 (msg2)
 *   AEAD Decrypt:  1 (msg1) + 1 (msg3) = 2
 *   Hash:          ~3 (TH2, TH3, TH4)
 *
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "edhoc_pq_kem.h"
#include "edhoc_type0_pq.h"
#include "edhoc_common.h"

/* =============================================================================
 * Shared state for PQ protocol simulation
 * We use a simple struct-based message passing between threads.
 * =============================================================================
 */

/* Maximum buffer sizes for PQ messages (much larger than classic due to KEM) */
#define PQ_MSG_BUF_SIZE 8192

struct pq_msg_exchange {
	uint8_t msg1_buf[PQ_MSG_BUF_SIZE];
	uint32_t msg1_len;
	uint8_t msg2_buf[PQ_MSG_BUF_SIZE];
	uint32_t msg2_len;
	uint8_t msg3_buf[PQ_MSG_BUF_SIZE];
	uint32_t msg3_len;

	pthread_mutex_t mutex;
	pthread_cond_t cond_msg1_ready;
	pthread_cond_t cond_msg2_ready;
	pthread_cond_t cond_msg3_ready;
	int msg1_ready;
	int msg2_ready;
	int msg3_ready;
};

static struct pq_msg_exchange g_pq_exchange;

static void pq_exchange_init(void)
{
	memset(&g_pq_exchange, 0, sizeof(g_pq_exchange));
	pthread_mutex_init(&g_pq_exchange.mutex, NULL);
	pthread_cond_init(&g_pq_exchange.cond_msg1_ready, NULL);
	pthread_cond_init(&g_pq_exchange.cond_msg2_ready, NULL);
	pthread_cond_init(&g_pq_exchange.cond_msg3_ready, NULL);
}

static void pq_exchange_destroy(void)
{
	pthread_mutex_destroy(&g_pq_exchange.mutex);
	pthread_cond_destroy(&g_pq_exchange.cond_msg1_ready);
	pthread_cond_destroy(&g_pq_exchange.cond_msg2_ready);
	pthread_cond_destroy(&g_pq_exchange.cond_msg3_ready);
}

/* =============================================================================
 * Protocol context for each party
 * =============================================================================
 */

struct pq_party_ctx {
	/* Long-term KEM keys (pre-provisioned) */
	uint8_t lt_pk[PQ_KEM_PK_LEN];
	uint8_t lt_sk[PQ_KEM_SK_LEN];

	/* Other party's long-term public key (trust anchor) */
	uint8_t other_lt_pk[PQ_KEM_PK_LEN];

	/* Ephemeral KEM keys (Initiator only generates these) */
	uint8_t eph_pk[PQ_KEM_PK_LEN];
	uint8_t eph_sk[PQ_KEM_SK_LEN];

	/* Derived PRK chain */
	uint8_t prk1[PQ_PRK_LEN];   /* From ss_R */
	uint8_t prk2[PQ_PRK_LEN];   /* From ss_eph */
	uint8_t prk3[PQ_PRK_LEN];   /* From ss_I (PRK_2e3m equivalent) */

	/* Transcript hashes */
	uint8_t th2[PQ_HASH_LEN];
	uint8_t th3[PQ_HASH_LEN];
	uint8_t th4[PQ_HASH_LEN];

	/* PRK_out (final shared secret) */
	uint8_t prk_out[PQ_PRK_LEN];

	/* Success flag */
	int success;
};

/* Simple info labels for KDF */
static const uint8_t INFO_K1[]    = "EDHOC-PQ-K1";
static const uint8_t INFO_IV1[]   = "EDHOC-PQ-IV1";
static const uint8_t INFO_K2[]    = "EDHOC-PQ-K2";
static const uint8_t INFO_IV2[]   = "EDHOC-PQ-IV2";
static const uint8_t INFO_K3[]    = "EDHOC-PQ-K3";
static const uint8_t INFO_IV3[]   = "EDHOC-PQ-IV3";
static const uint8_t INFO_MAC2[]  = "EDHOC-PQ-MAC2";
static const uint8_t INFO_MAC3[]  = "EDHOC-PQ-MAC3";
static const uint8_t INFO_OUT[]   = "EDHOC-PQ-PRK_out";

/* Simple "credential" identifiers */
static const uint8_t ID_CRED_I[] = "EDHOC-PQ-Initiator";
static const uint8_t ID_CRED_R[] = "EDHOC-PQ-Responder";

/* =============================================================================
 * Helper: derive AEAD key + nonce from PRK
 * =============================================================================
 */
static int derive_key_iv(const uint8_t *prk, const uint8_t *label, size_t label_len,
                          uint8_t *key, uint8_t *iv)
{
	/* Key info = label || "_key" */
	uint8_t key_info[64];
	size_t key_info_len = label_len;
	memcpy(key_info, label, label_len);

	if (pq_hkdf_expand(prk, key_info, key_info_len,
	                    key, PQ_AEAD_KEY_LEN) != 0)
		return -1;

	/* IV info = label with offset for differentiation */
	uint8_t iv_info[64];
	memcpy(iv_info, label, label_len);
	iv_info[0] ^= 0xFF; /* Differentiate from key */

	if (pq_hkdf_expand(prk, iv_info, label_len,
	                    iv, PQ_AEAD_NONCE_LEN) != 0)
		return -1;

	return 0;
}

/* =============================================================================
 * Initiator Thread
 * =============================================================================
 */
static void *pq_type0_initiator_thread(void *arg)
{
	struct pq_party_ctx *ctx = (struct pq_party_ctx *)arg;
	int ret;

	/*
	 * === Step 1: Initiator generates and sends Message 1 ===
	 */

	/* 1a. Generate ephemeral PQ KEM key pair */
	ret = pq_kem_keygen(ctx->eph_pk, ctx->eph_sk);
	if (ret != 0) {
		print_error("PQ Initiator: ephemeral keygen failed");
		return NULL;
	}

	/* 1b. ss_R = KEM.Encaps(pkR) → authenticate to Responder */
	uint8_t ct_R[PQ_KEM_CT_LEN];
	uint8_t ss_R[PQ_KEM_SS_LEN];
	ret = pq_kem_encaps(ct_R, ss_R, ctx->other_lt_pk);
	if (ret != 0) {
		print_error("PQ Initiator: KEM.Encaps(pkR) failed");
		return NULL;
	}

	/* 1c. PRK1 = HKDF-Extract(salt=0, ikm=ss_R) */
	ret = pq_hkdf_extract(NULL, 0, ss_R, PQ_KEM_SS_LEN, ctx->prk1);
	if (ret != 0) {
		print_error("PQ Initiator: PRK1 derivation failed");
		return NULL;
	}

	/* 1d. K1, IV1 = HKDF-Expand(PRK1, ...) */
	uint8_t k1[PQ_AEAD_KEY_LEN], iv1[PQ_AEAD_NONCE_LEN];
	ret = derive_key_iv(ctx->prk1, INFO_K1, sizeof(INFO_K1) - 1, k1, iv1);
	if (ret != 0) {
		print_error("PQ Initiator: K1/IV1 derivation failed");
		return NULL;
	}

	/* 1e. Build plaintext for Message 1: METHOD || SUITES || ID_CRED_I || C_I */
	uint8_t pt1[256];
	uint32_t pt1_len = 0;
	pt1[pt1_len++] = 0x00;  /* METHOD = 0 (Type 0 PQ) */
	pt1[pt1_len++] = 0x00;  /* SUITES = PQ */
	memcpy(pt1 + pt1_len, ID_CRED_I, sizeof(ID_CRED_I) - 1);
	pt1_len += sizeof(ID_CRED_I) - 1;
	pt1[pt1_len++] = 0x37;  /* C_I */

	/* 1f. AEAD Encrypt */
	uint8_t ct1_aead[256 + PQ_AEAD_TAG_LEN];
	size_t ct1_aead_len = 0;
	ret = pq_aead_encrypt(k1, iv1, NULL, 0, pt1, pt1_len,
	                       ct1_aead, &ct1_aead_len);
	if (ret != 0) {
		print_error("PQ Initiator: AEAD encrypt msg1 failed");
		return NULL;
	}

	/* 1g. Compose Message 1: pk_eph || ct_R || AEAD_ct */
	pthread_mutex_lock(&g_pq_exchange.mutex);
	{
		uint8_t *p = g_pq_exchange.msg1_buf;
		uint32_t off = 0;

		/* pk_eph (1184 bytes) */
		memcpy(p + off, ctx->eph_pk, PQ_KEM_PK_LEN);
		off += PQ_KEM_PK_LEN;

		/* ct_R (1088 bytes) */
		memcpy(p + off, ct_R, PQ_KEM_CT_LEN);
		off += PQ_KEM_CT_LEN;

		/* AEAD ciphertext length (2 bytes big-endian) */
		p[off++] = (uint8_t)(ct1_aead_len >> 8);
		p[off++] = (uint8_t)(ct1_aead_len & 0xFF);

		/* AEAD ciphertext */
		memcpy(p + off, ct1_aead, ct1_aead_len);
		off += ct1_aead_len;

		g_pq_exchange.msg1_len = off;
		g_pq_exchange.msg1_ready = 1;
	}
	pthread_cond_signal(&g_pq_exchange.cond_msg1_ready);
	pthread_mutex_unlock(&g_pq_exchange.mutex);

	/*
	 * === Step 3: Receive and process Message 2 ===
	 */
	pthread_mutex_lock(&g_pq_exchange.mutex);
	while (!g_pq_exchange.msg2_ready)
		pthread_cond_wait(&g_pq_exchange.cond_msg2_ready,
		                  &g_pq_exchange.mutex);
	pthread_mutex_unlock(&g_pq_exchange.mutex);

	/* Parse Message 2: ct_eph2 || ct_I || aead_len || AEAD_ct */
	uint8_t *msg2 = g_pq_exchange.msg2_buf;
	uint32_t msg2_off = 0;

	uint8_t ct_eph2[PQ_KEM_CT_LEN];
	memcpy(ct_eph2, msg2 + msg2_off, PQ_KEM_CT_LEN);
	msg2_off += PQ_KEM_CT_LEN;

	uint8_t ct_I[PQ_KEM_CT_LEN];
	memcpy(ct_I, msg2 + msg2_off, PQ_KEM_CT_LEN);
	msg2_off += PQ_KEM_CT_LEN;

	uint16_t ct2_aead_len = (msg2[msg2_off] << 8) | msg2[msg2_off + 1];
	msg2_off += 2;

	uint8_t ct2_aead[512 + PQ_AEAD_TAG_LEN];
	memcpy(ct2_aead, msg2 + msg2_off, ct2_aead_len);

	/* 3a. ss_eph = KEM.Decaps(ct_eph2, sk_eph) */
	uint8_t ss_eph[PQ_KEM_SS_LEN];
	ret = pq_kem_decaps(ss_eph, ct_eph2, ctx->eph_sk);
	if (ret != 0) {
		print_error("PQ Initiator: KEM.Decaps(ct_eph2) failed");
		return NULL;
	}

	/* 3b. PRK2 = HKDF-Extract(PRK1, ss_eph) */
	ret = pq_hkdf_extract(ctx->prk1, PQ_PRK_LEN,
	                       ss_eph, PQ_KEM_SS_LEN, ctx->prk2);
	if (ret != 0) {
		print_error("PQ Initiator: PRK2 derivation failed");
		return NULL;
	}

	/* 3c. K2, IV2 for decrypting AEAD */
	uint8_t k2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
	ret = derive_key_iv(ctx->prk2, INFO_K2, sizeof(INFO_K2) - 1, k2, iv2);
	if (ret != 0) {
		print_error("PQ Initiator: K2/IV2 derivation failed");
		return NULL;
	}

	/* 3d. Decrypt Message 2 AEAD */
	uint8_t pt2[512];
	size_t pt2_len = 0;
	ret = pq_aead_decrypt(k2, iv2, NULL, 0, ct2_aead, ct2_aead_len,
	                       pt2, &pt2_len);
	if (ret != 0) {
		print_error("PQ Initiator: AEAD decrypt msg2 failed");
		return NULL;
	}

	/* 3e. Compute TH2 for MAC2 verification */
	uint8_t th2_input[PQ_MSG_BUF_SIZE];
	uint32_t th2_input_len = g_pq_exchange.msg1_len + PQ_KEM_CT_LEN;
	memcpy(th2_input, g_pq_exchange.msg1_buf, g_pq_exchange.msg1_len);
	memcpy(th2_input + g_pq_exchange.msg1_len, ct_eph2, PQ_KEM_CT_LEN);
	ret = pq_hash_sha256(th2_input, th2_input_len, ctx->th2);
	if (ret != 0) {
		print_error("PQ Initiator: TH2 hash failed");
		return NULL;
	}

	/* 3f. Verify MAC2: MAC2_expected = HKDF-Expand(PRK2, TH2 || ID_CRED_R) */
	uint8_t mac2_info[PQ_HASH_LEN + 64];
	memcpy(mac2_info, ctx->th2, PQ_HASH_LEN);
	memcpy(mac2_info + PQ_HASH_LEN, ID_CRED_R, sizeof(ID_CRED_R) - 1);
	uint8_t mac2_expected[PQ_AEAD_TAG_LEN];
	ret = pq_hkdf_expand(ctx->prk2, mac2_info,
	                      PQ_HASH_LEN + sizeof(ID_CRED_R) - 1,
	                      mac2_expected, PQ_AEAD_TAG_LEN);
	if (ret != 0) {
		print_error("PQ Initiator: MAC2 derivation failed");
		return NULL;
	}

	/* MAC2 is at end of plaintext: pt2 = C_R || ID_CRED_R || MAC2 */
	if (pt2_len < PQ_AEAD_TAG_LEN) {
		print_error("PQ Initiator: msg2 plaintext too short");
		return NULL;
	}
	uint8_t *mac2_received = pt2 + pt2_len - PQ_AEAD_TAG_LEN;
	if (memcmp(mac2_expected, mac2_received, PQ_AEAD_TAG_LEN) != 0) {
		print_error("PQ Initiator: MAC2 verification FAILED");
		return NULL;
	}

	/* 3g. ss_I = KEM.Decaps(ct_I, skI) — mutual authentication */
	uint8_t ss_I[PQ_KEM_SS_LEN];
	ret = pq_kem_decaps(ss_I, ct_I, ctx->lt_sk);
	if (ret != 0) {
		print_error("PQ Initiator: KEM.Decaps(ct_I) failed");
		return NULL;
	}

	/* 3h. PRK3 = HKDF-Extract(PRK2, ss_I) */
	ret = pq_hkdf_extract(ctx->prk2, PQ_PRK_LEN,
	                       ss_I, PQ_KEM_SS_LEN, ctx->prk3);
	if (ret != 0) {
		print_error("PQ Initiator: PRK3 derivation failed");
		return NULL;
	}

	/* 3i. TH3 = Hash(TH2 || msg2) */
	uint8_t th3_input[PQ_MSG_BUF_SIZE];
	memcpy(th3_input, ctx->th2, PQ_HASH_LEN);
	memcpy(th3_input + PQ_HASH_LEN, g_pq_exchange.msg2_buf,
	       g_pq_exchange.msg2_len);
	ret = pq_hash_sha256(th3_input, PQ_HASH_LEN + g_pq_exchange.msg2_len,
	                      ctx->th3);
	if (ret != 0) {
		print_error("PQ Initiator: TH3 hash failed");
		return NULL;
	}

	/* 3j. MAC3 = HKDF-Expand(PRK3, TH3 || ID_CRED_I) */
	uint8_t mac3_info[PQ_HASH_LEN + 64];
	memcpy(mac3_info, ctx->th3, PQ_HASH_LEN);
	memcpy(mac3_info + PQ_HASH_LEN, ID_CRED_I, sizeof(ID_CRED_I) - 1);
	uint8_t mac3[PQ_AEAD_TAG_LEN];
	ret = pq_hkdf_expand(ctx->prk3, mac3_info,
	                      PQ_HASH_LEN + sizeof(ID_CRED_I) - 1,
	                      mac3, PQ_AEAD_TAG_LEN);
	if (ret != 0) {
		print_error("PQ Initiator: MAC3 derivation failed");
		return NULL;
	}

	/* 3k. K3, IV3 for encrypting Message 3 */
	uint8_t k3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
	ret = derive_key_iv(ctx->prk3, INFO_K3, sizeof(INFO_K3) - 1, k3, iv3);
	if (ret != 0) {
		print_error("PQ Initiator: K3/IV3 derivation failed");
		return NULL;
	}

	/* 3l. Send Message 3: AEAD(MAC3) */
	uint8_t ct3_aead[64 + PQ_AEAD_TAG_LEN];
	size_t ct3_aead_len = 0;
	ret = pq_aead_encrypt(k3, iv3, NULL, 0, mac3, PQ_AEAD_TAG_LEN,
	                       ct3_aead, &ct3_aead_len);
	if (ret != 0) {
		print_error("PQ Initiator: AEAD encrypt msg3 failed");
		return NULL;
	}

	pthread_mutex_lock(&g_pq_exchange.mutex);
	memcpy(g_pq_exchange.msg3_buf, ct3_aead, ct3_aead_len);
	g_pq_exchange.msg3_len = ct3_aead_len;
	g_pq_exchange.msg3_ready = 1;
	pthread_cond_signal(&g_pq_exchange.cond_msg3_ready);
	pthread_mutex_unlock(&g_pq_exchange.mutex);

	/* Derive PRK_out */
	uint8_t th4_input[PQ_HASH_LEN + 64];
	memcpy(th4_input, ctx->th3, PQ_HASH_LEN);
	memcpy(th4_input + PQ_HASH_LEN, ct3_aead, ct3_aead_len);
	ret = pq_hash_sha256(th4_input, PQ_HASH_LEN + ct3_aead_len, ctx->th4);
	if (ret != 0) {
		print_error("PQ Initiator: TH4 hash failed");
		return NULL;
	}

	ret = pq_hkdf_expand(ctx->prk3, ctx->th4, PQ_HASH_LEN,
	                      ctx->prk_out, PQ_PRK_LEN);
	if (ret != 0) {
		print_error("PQ Initiator: PRK_out derivation failed");
		return NULL;
	}

	ctx->success = 1;
	print_success("PQ Initiator: EDHOC exchange completed successfully!");
	return NULL;
}

/* =============================================================================
 * Responder Thread
 * =============================================================================
 */
static void *pq_type0_responder_thread(void *arg)
{
	struct pq_party_ctx *ctx = (struct pq_party_ctx *)arg;
	int ret;

	/*
	 * === Step 2: Receive Message 1 and send Message 2 ===
	 */
	pthread_mutex_lock(&g_pq_exchange.mutex);
	while (!g_pq_exchange.msg1_ready)
		pthread_cond_wait(&g_pq_exchange.cond_msg1_ready,
		                  &g_pq_exchange.mutex);
	pthread_mutex_unlock(&g_pq_exchange.mutex);

	/* Parse Message 1: pk_eph || ct_R || aead_len || AEAD_ct */
	uint8_t *msg1 = g_pq_exchange.msg1_buf;
	uint32_t msg1_off = 0;

	uint8_t pk_eph[PQ_KEM_PK_LEN];
	memcpy(pk_eph, msg1 + msg1_off, PQ_KEM_PK_LEN);
	msg1_off += PQ_KEM_PK_LEN;

	uint8_t ct_R[PQ_KEM_CT_LEN];
	memcpy(ct_R, msg1 + msg1_off, PQ_KEM_CT_LEN);
	msg1_off += PQ_KEM_CT_LEN;

	uint16_t ct1_aead_len = (msg1[msg1_off] << 8) | msg1[msg1_off + 1];
	msg1_off += 2;

	uint8_t ct1_aead[256 + PQ_AEAD_TAG_LEN];
	memcpy(ct1_aead, msg1 + msg1_off, ct1_aead_len);

	/* 2a. ss_R = KEM.Decaps(ct_R, skR) */
	uint8_t ss_R[PQ_KEM_SS_LEN];
	ret = pq_kem_decaps(ss_R, ct_R, ctx->lt_sk);
	if (ret != 0) {
		print_error("PQ Responder: KEM.Decaps(ct_R) failed");
		return NULL;
	}

	/* 2b. PRK1 = HKDF-Extract(salt=0, ikm=ss_R) */
	ret = pq_hkdf_extract(NULL, 0, ss_R, PQ_KEM_SS_LEN, ctx->prk1);
	if (ret != 0) {
		print_error("PQ Responder: PRK1 derivation failed");
		return NULL;
	}

	/* 2c. K1, IV1 → decrypt Message 1 AEAD */
	uint8_t k1[PQ_AEAD_KEY_LEN], iv1[PQ_AEAD_NONCE_LEN];
	ret = derive_key_iv(ctx->prk1, INFO_K1, sizeof(INFO_K1) - 1, k1, iv1);
	if (ret != 0) {
		print_error("PQ Responder: K1/IV1 derivation failed");
		return NULL;
	}

	uint8_t pt1[256];
	size_t pt1_len = 0;
	ret = pq_aead_decrypt(k1, iv1, NULL, 0, ct1_aead, ct1_aead_len,
	                       pt1, &pt1_len);
	if (ret != 0) {
		print_error("PQ Responder: AEAD decrypt msg1 failed");
		return NULL;
	}

	/* 2d. (ss_eph, ct_eph2) = KEM.Encaps(pk_eph) */
	uint8_t ct_eph2[PQ_KEM_CT_LEN];
	uint8_t ss_eph[PQ_KEM_SS_LEN];
	ret = pq_kem_encaps(ct_eph2, ss_eph, pk_eph);
	if (ret != 0) {
		print_error("PQ Responder: KEM.Encaps(pk_eph) failed");
		return NULL;
	}

	/* 2e. PRK2 = HKDF-Extract(PRK1, ss_eph) */
	ret = pq_hkdf_extract(ctx->prk1, PQ_PRK_LEN,
	                       ss_eph, PQ_KEM_SS_LEN, ctx->prk2);
	if (ret != 0) {
		print_error("PQ Responder: PRK2 derivation failed");
		return NULL;
	}

	/* 2f. K2, IV2 for AEAD */
	uint8_t k2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
	ret = derive_key_iv(ctx->prk2, INFO_K2, sizeof(INFO_K2) - 1, k2, iv2);
	if (ret != 0) {
		print_error("PQ Responder: K2/IV2 derivation failed");
		return NULL;
	}

	/* 2g. TH2 = Hash(msg1 || ct_eph2) */
	uint8_t th2_input[PQ_MSG_BUF_SIZE];
	uint32_t th2_input_len = g_pq_exchange.msg1_len + PQ_KEM_CT_LEN;
	memcpy(th2_input, g_pq_exchange.msg1_buf, g_pq_exchange.msg1_len);
	memcpy(th2_input + g_pq_exchange.msg1_len, ct_eph2, PQ_KEM_CT_LEN);
	ret = pq_hash_sha256(th2_input, th2_input_len, ctx->th2);
	if (ret != 0) {
		print_error("PQ Responder: TH2 hash failed");
		return NULL;
	}

	/* 2h. MAC2 = HKDF-Expand(PRK2, TH2 || ID_CRED_R) */
	uint8_t mac2_info[PQ_HASH_LEN + 64];
	memcpy(mac2_info, ctx->th2, PQ_HASH_LEN);
	memcpy(mac2_info + PQ_HASH_LEN, ID_CRED_R, sizeof(ID_CRED_R) - 1);
	uint8_t mac2[PQ_AEAD_TAG_LEN];
	ret = pq_hkdf_expand(ctx->prk2, mac2_info,
	                      PQ_HASH_LEN + sizeof(ID_CRED_R) - 1,
	                      mac2, PQ_AEAD_TAG_LEN);
	if (ret != 0) {
		print_error("PQ Responder: MAC2 derivation failed");
		return NULL;
	}

	/* 2i. (ss_I, ct_I) = KEM.Encaps(pkI) → for mutual auth */
	uint8_t ct_I[PQ_KEM_CT_LEN];
	uint8_t ss_I[PQ_KEM_SS_LEN];
	ret = pq_kem_encaps(ct_I, ss_I, ctx->other_lt_pk);
	if (ret != 0) {
		print_error("PQ Responder: KEM.Encaps(pkI) failed");
		return NULL;
	}

	/* 2j. PRK3 = HKDF-Extract(PRK2, ss_I) */
	ret = pq_hkdf_extract(ctx->prk2, PQ_PRK_LEN,
	                       ss_I, PQ_KEM_SS_LEN, ctx->prk3);
	if (ret != 0) {
		print_error("PQ Responder: PRK3 derivation failed");
		return NULL;
	}

	/* 2k. Build plaintext for Message 2: C_R || ID_CRED_R || MAC2 */
	uint8_t pt2[256];
	uint32_t pt2_len = 0;
	pt2[pt2_len++] = 0x27;  /* C_R */
	memcpy(pt2 + pt2_len, ID_CRED_R, sizeof(ID_CRED_R) - 1);
	pt2_len += sizeof(ID_CRED_R) - 1;
	memcpy(pt2 + pt2_len, mac2, PQ_AEAD_TAG_LEN);
	pt2_len += PQ_AEAD_TAG_LEN;

	/* 2l. AEAD Encrypt Message 2 */
	uint8_t ct2_aead[512 + PQ_AEAD_TAG_LEN];
	size_t ct2_aead_len = 0;
	ret = pq_aead_encrypt(k2, iv2, NULL, 0, pt2, pt2_len,
	                       ct2_aead, &ct2_aead_len);
	if (ret != 0) {
		print_error("PQ Responder: AEAD encrypt msg2 failed");
		return NULL;
	}

	/* 2m. Compose and send Message 2: ct_eph2 || ct_I || aead_len || AEAD_ct */
	pthread_mutex_lock(&g_pq_exchange.mutex);
	{
		uint8_t *p = g_pq_exchange.msg2_buf;
		uint32_t off = 0;

		memcpy(p + off, ct_eph2, PQ_KEM_CT_LEN);
		off += PQ_KEM_CT_LEN;

		memcpy(p + off, ct_I, PQ_KEM_CT_LEN);
		off += PQ_KEM_CT_LEN;

		p[off++] = (uint8_t)(ct2_aead_len >> 8);
		p[off++] = (uint8_t)(ct2_aead_len & 0xFF);

		memcpy(p + off, ct2_aead, ct2_aead_len);
		off += ct2_aead_len;

		g_pq_exchange.msg2_len = off;
		g_pq_exchange.msg2_ready = 1;
	}
	pthread_cond_signal(&g_pq_exchange.cond_msg2_ready);
	pthread_mutex_unlock(&g_pq_exchange.mutex);

	/*
	 * === Step 4: Receive and verify Message 3 ===
	 */
	pthread_mutex_lock(&g_pq_exchange.mutex);
	while (!g_pq_exchange.msg3_ready)
		pthread_cond_wait(&g_pq_exchange.cond_msg3_ready,
		                  &g_pq_exchange.mutex);
	pthread_mutex_unlock(&g_pq_exchange.mutex);

	/* 4a. K3, IV3 for decrypting Message 3 */
	uint8_t k3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
	ret = derive_key_iv(ctx->prk3, INFO_K3, sizeof(INFO_K3) - 1, k3, iv3);
	if (ret != 0) {
		print_error("PQ Responder: K3/IV3 derivation failed");
		return NULL;
	}

	/* 4b. Decrypt Message 3 */
	uint8_t pt3[64];
	size_t pt3_len = 0;
	ret = pq_aead_decrypt(k3, iv3, NULL, 0,
	                       g_pq_exchange.msg3_buf,
	                       g_pq_exchange.msg3_len,
	                       pt3, &pt3_len);
	if (ret != 0) {
		print_error("PQ Responder: AEAD decrypt msg3 failed");
		return NULL;
	}

	/* 4c. TH3 = Hash(TH2 || msg2) */
	uint8_t th3_input[PQ_MSG_BUF_SIZE];
	memcpy(th3_input, ctx->th2, PQ_HASH_LEN);
	memcpy(th3_input + PQ_HASH_LEN, g_pq_exchange.msg2_buf,
	       g_pq_exchange.msg2_len);
	ret = pq_hash_sha256(th3_input, PQ_HASH_LEN + g_pq_exchange.msg2_len,
	                      ctx->th3);
	if (ret != 0) {
		print_error("PQ Responder: TH3 hash failed");
		return NULL;
	}

	/* 4d. Verify MAC3 */
	uint8_t mac3_info[PQ_HASH_LEN + 64];
	memcpy(mac3_info, ctx->th3, PQ_HASH_LEN);
	memcpy(mac3_info + PQ_HASH_LEN, ID_CRED_I, sizeof(ID_CRED_I) - 1);
	uint8_t mac3_expected[PQ_AEAD_TAG_LEN];
	ret = pq_hkdf_expand(ctx->prk3, mac3_info,
	                      PQ_HASH_LEN + sizeof(ID_CRED_I) - 1,
	                      mac3_expected, PQ_AEAD_TAG_LEN);
	if (ret != 0) {
		print_error("PQ Responder: MAC3 derivation failed");
		return NULL;
	}

	if (pt3_len != PQ_AEAD_TAG_LEN ||
	    memcmp(mac3_expected, pt3, PQ_AEAD_TAG_LEN) != 0) {
		print_error("PQ Responder: MAC3 verification FAILED");
		return NULL;
	}

	/* 4e. TH4 & PRK_out */
	uint8_t th4_input[PQ_HASH_LEN + 64];
	memcpy(th4_input, ctx->th3, PQ_HASH_LEN);
	memcpy(th4_input + PQ_HASH_LEN, g_pq_exchange.msg3_buf,
	       g_pq_exchange.msg3_len);
	ret = pq_hash_sha256(th4_input, PQ_HASH_LEN + g_pq_exchange.msg3_len,
	                      ctx->th4);
	if (ret != 0) {
		print_error("PQ Responder: TH4 hash failed");
		return NULL;
	}

	ret = pq_hkdf_expand(ctx->prk3, ctx->th4, PQ_HASH_LEN,
	                      ctx->prk_out, PQ_PRK_LEN);
	if (ret != 0) {
		print_error("PQ Responder: PRK_out derivation failed");
		return NULL;
	}

	ctx->success = 1;
	print_success("PQ Responder: EDHOC exchange completed successfully!");
	return NULL;
}

/* =============================================================================
 * Main entry point for Type 0 PQ
 * =============================================================================
 */
int run_edhoc_type0_pq(void)
{
	print_header("EDHOC Type 0 PQ: KEM-based Authentication (ML-KEM-768)");
	printf("\n");
	print_info("Post-Quantum EDHOC Type 0 using ML-KEM-768 (NIST Level 3)");
	print_info("Key Exchange: Ephemeral KEM (forward secrecy)");
	print_info("Authentication: Long-term KEM Encaps/Decaps (implicit auth)");
	print_info("Symmetric: AES-CCM-16-64-128, SHA-256, HKDF");
	printf("\n");

	/* Generate long-term key pairs */
	struct pq_party_ctx initiator_ctx, responder_ctx;
	memset(&initiator_ctx, 0, sizeof(initiator_ctx));
	memset(&responder_ctx, 0, sizeof(responder_ctx));

	print_info("Generating long-term PQ key pairs...");

	if (pq_kem_keygen(initiator_ctx.lt_pk, initiator_ctx.lt_sk) != 0) {
		print_error("Failed to generate Initiator long-term key pair");
		return -1;
	}
	if (pq_kem_keygen(responder_ctx.lt_pk, responder_ctx.lt_sk) != 0) {
		print_error("Failed to generate Responder long-term key pair");
		return -1;
	}

	/* Exchange trust anchors */
	memcpy(initiator_ctx.other_lt_pk, responder_ctx.lt_pk, PQ_KEM_PK_LEN);
	memcpy(responder_ctx.other_lt_pk, initiator_ctx.lt_pk, PQ_KEM_PK_LEN);

	print_success("Key pairs generated and trust anchors exchanged.");
	printf("\n");

	/* Initialize message exchange */
	pq_exchange_init();

	/* Create threads */
	pthread_t tid_initiator, tid_responder;
	print_info("Starting EDHOC PQ handshake...");
	printf("\n");

	pthread_create(&tid_responder, NULL, pq_type0_responder_thread,
	               &responder_ctx);
	pthread_create(&tid_initiator, NULL, pq_type0_initiator_thread,
	               &initiator_ctx);

	pthread_join(tid_initiator, NULL);
	pthread_join(tid_responder, NULL);

	pq_exchange_destroy();

	/* Verify results */
	printf("\n");
	print_header("EDHOC Type 0 PQ - Results");
	printf("\n");

	if (!initiator_ctx.success || !responder_ctx.success) {
		print_error("EDHOC PQ exchange failed!");
		return -1;
	}

	print_hex("Initiator PRK_out", initiator_ctx.prk_out, PQ_PRK_LEN);
	print_hex("Responder PRK_out", responder_ctx.prk_out, PQ_PRK_LEN);

	if (memcmp(initiator_ctx.prk_out, responder_ctx.prk_out, PQ_PRK_LEN) == 0) {
		print_success("PRK_out MATCH: Initiator and Responder agree!");
	} else {
		print_error("PRK_out MISMATCH!");
		return -1;
	}

	printf("\n");
	print_success("EDHOC Type 0 PQ (ML-KEM-768) completed successfully!");
	printf("\n");

	return 0;
}
