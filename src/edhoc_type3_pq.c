/*
 * =============================================================================
 * EDHOC-Hybrid: Type 3 PQ Implementation (KEM-based MAC-MAC)
 * =============================================================================
 *
 * Post-Quantum EDHOC Type 3 variant using ML-KEM-768.
 * Same underlying protocol flow as Type 0 PQ (both use KEM for auth),
 * but this variant emphasizes MAC-based verification semantics:
 *   - No signatures at any point
 *   - Authentication purely via KEM Encaps/Decaps of long-term keys
 *   - MAC values verify key possession
 *
 * The protocol flow is identical to Type 0 PQ (since PQ KEM replaces
 * both Sig and DH in the classic variants). The distinction is for
 * benchmarking comparison purposes: Type 0 PQ vs Type 3 PQ will show
 * identical crypto costs since the PQ KEM flow is uniform.
 *
 * === PROTOCOL FLOW (Type 3 PQ — KEM-based MAC-MAC) ===
 *
 *   Step 1 — Initiator:
 *     1. Generate ephemeral PQ KEM key pair: (pk_eph, sk_eph)
 *     2. (ct_R, ss_R) = KEM.Encaps(pkR)
 *     3. PRK1 = HKDF-Extract(0, ss_R)
 *     4. K1, IV1 = KDF(PRK1)
 *     5. Send msg1: (pk_eph, ct_R, AEAD_K1(METHOD=3, SUITES, ID_CRED_I, C_I))
 *
 *   Step 2 — Responder:
 *     1. ss_R = KEM.Decaps(ct_R, skR)
 *     2. PRK1 → K1, decrypt msg1
 *     3. (ct_eph2, ss_eph) = KEM.Encaps(pk_eph)
 *     4. PRK2 = HKDF-Extract(PRK1, ss_eph)
 *     5. TH2 = Hash(msg1 || ct_eph2)
 *     6. MAC2 = KDF(PRK2, TH2 || ID_CRED_R)
 *     7. (ct_I, ss_I) = KEM.Encaps(pkI)
 *     8. PRK3 = HKDF-Extract(PRK2, ss_I)
 *     9. Send msg2: (ct_eph2, ct_I, AEAD_K2(C_R, ID_CRED_R, MAC2))
 *
 *   Step 3 — Initiator:
 *     1. ss_eph = KEM.Decaps(ct_eph2, sk_eph)
 *     2. PRK2, K2, decrypt msg2, verify MAC2
 *     3. ss_I = KEM.Decaps(ct_I, skI)
 *     4. PRK3 = HKDF-Extract(PRK2, ss_I)
 *     5. TH3, MAC3 = KDF(PRK3, TH3 || ID_CRED_I)
 *     6. Send msg3: AEAD_K3(MAC3)
 *
 *   Step 4 — Responder:
 *     1. Verify MAC3
 *     2. PRK_out = KDF(PRK3, TH4)
 *
 * === Crypto Operations (same as Type 0 PQ) ===
 *   Initiator: KeyGen=1, Encaps=1, Decaps=2, HKDF≈8, AEAD_Enc=2, AEAD_Dec=1, Hash=3
 *   Responder: KeyGen=0, Encaps=2, Decaps=1, HKDF≈8, AEAD_Enc=1, AEAD_Dec=2, Hash=3
 *
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "edhoc_pq_kem.h"
#include "edhoc_type3_pq.h"
#include "edhoc_common.h"

/* ── PQ Message Exchange ── */
#define PQ_MSG_BUF_SIZE 8192

struct pq3_msg_exchange {
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

static struct pq3_msg_exchange g_pq3_exchange;

static void pq3_exchange_init(void)
{
	memset(&g_pq3_exchange, 0, sizeof(g_pq3_exchange));
	pthread_mutex_init(&g_pq3_exchange.mutex, NULL);
	pthread_cond_init(&g_pq3_exchange.cond_msg1_ready, NULL);
	pthread_cond_init(&g_pq3_exchange.cond_msg2_ready, NULL);
	pthread_cond_init(&g_pq3_exchange.cond_msg3_ready, NULL);
}

static void pq3_exchange_destroy(void)
{
	pthread_mutex_destroy(&g_pq3_exchange.mutex);
	pthread_cond_destroy(&g_pq3_exchange.cond_msg1_ready);
	pthread_cond_destroy(&g_pq3_exchange.cond_msg2_ready);
	pthread_cond_destroy(&g_pq3_exchange.cond_msg3_ready);
}

/* ── Party Context ── */
struct pq3_party_ctx {
	uint8_t lt_pk[PQ_KEM_PK_LEN];
	uint8_t lt_sk[PQ_KEM_SK_LEN];
	uint8_t other_lt_pk[PQ_KEM_PK_LEN];
	uint8_t eph_pk[PQ_KEM_PK_LEN];
	uint8_t eph_sk[PQ_KEM_SK_LEN];
	uint8_t prk1[PQ_PRK_LEN];
	uint8_t prk2[PQ_PRK_LEN];
	uint8_t prk3[PQ_PRK_LEN];
	uint8_t th2[PQ_HASH_LEN];
	uint8_t th3[PQ_HASH_LEN];
	uint8_t th4[PQ_HASH_LEN];
	uint8_t prk_out[PQ_PRK_LEN];
	int success;
};

/* Info labels */
static const uint8_t T3PQ_K1[]   = "EDHOC-T3PQ-K1";
static const uint8_t T3PQ_IV1[]  = "EDHOC-T3PQ-IV1";
static const uint8_t T3PQ_K2[]   = "EDHOC-T3PQ-K2";
static const uint8_t T3PQ_IV2[]  = "EDHOC-T3PQ-IV2";
static const uint8_t T3PQ_K3[]   = "EDHOC-T3PQ-K3";
static const uint8_t T3PQ_IV3[]  = "EDHOC-T3PQ-IV3";
static const uint8_t T3PQ_ID_I[] = "EDHOC-T3PQ-Initiator";
static const uint8_t T3PQ_ID_R[] = "EDHOC-T3PQ-Responder";

/* ── derive key + iv from PRK ── */
static int t3pq_derive_key_iv(const uint8_t *prk,
                               const uint8_t *label, size_t label_len,
                               uint8_t *key, uint8_t *iv)
{
	if (pq_hkdf_expand(prk, label, label_len, key, PQ_AEAD_KEY_LEN) != 0)
		return -1;
	uint8_t iv_info[64];
	memcpy(iv_info, label, label_len);
	iv_info[0] ^= 0xFF;
	if (pq_hkdf_expand(prk, iv_info, label_len, iv, PQ_AEAD_NONCE_LEN) != 0)
		return -1;
	return 0;
}

/* =============================================================================
 * Initiator Thread (Type 3 PQ)
 * =============================================================================
 */
static void *pq3_initiator_thread(void *arg)
{
	struct pq3_party_ctx *ctx = (struct pq3_party_ctx *)arg;
	int ret;

	/* ── Step 1: Generate ephemeral + Encaps to pkR ── */
	ret = pq_kem_keygen(ctx->eph_pk, ctx->eph_sk);
	if (ret != 0) { print_error("T3PQ Init: keygen failed"); return NULL; }

	uint8_t ct_R[PQ_KEM_CT_LEN], ss_R[PQ_KEM_SS_LEN];
	ret = pq_kem_encaps(ct_R, ss_R, ctx->other_lt_pk);
	if (ret != 0) { print_error("T3PQ Init: Encaps(pkR) failed"); return NULL; }

	ret = pq_hkdf_extract(NULL, 0, ss_R, PQ_KEM_SS_LEN, ctx->prk1);
	if (ret != 0) { print_error("T3PQ Init: PRK1 failed"); return NULL; }

	uint8_t k1[PQ_AEAD_KEY_LEN], iv1[PQ_AEAD_NONCE_LEN];
	ret = t3pq_derive_key_iv(ctx->prk1, T3PQ_K1, sizeof(T3PQ_K1) - 1, k1, iv1);
	if (ret != 0) { print_error("T3PQ Init: K1/IV1 failed"); return NULL; }

	uint8_t pt1[256];
	uint32_t pt1_len = 0;
	pt1[pt1_len++] = 0x03;  /* METHOD = 3 (Type 3 PQ) */
	pt1[pt1_len++] = 0x00;  /* SUITES = PQ */
	memcpy(pt1 + pt1_len, T3PQ_ID_I, sizeof(T3PQ_ID_I) - 1);
	pt1_len += sizeof(T3PQ_ID_I) - 1;
	pt1[pt1_len++] = 0x37;  /* C_I */

	uint8_t ct1_aead[256 + PQ_AEAD_TAG_LEN];
	size_t ct1_aead_len = 0;
	ret = pq_aead_encrypt(k1, iv1, NULL, 0, pt1, pt1_len,
	                       ct1_aead, &ct1_aead_len);
	if (ret != 0) { print_error("T3PQ Init: AEAD enc msg1 failed"); return NULL; }

	/* ── Send msg1 ── */
	pthread_mutex_lock(&g_pq3_exchange.mutex);
	{
		uint8_t *p = g_pq3_exchange.msg1_buf;
		uint32_t off = 0;
		memcpy(p + off, ctx->eph_pk, PQ_KEM_PK_LEN); off += PQ_KEM_PK_LEN;
		memcpy(p + off, ct_R, PQ_KEM_CT_LEN);        off += PQ_KEM_CT_LEN;
		p[off++] = (uint8_t)(ct1_aead_len >> 8);
		p[off++] = (uint8_t)(ct1_aead_len & 0xFF);
		memcpy(p + off, ct1_aead, ct1_aead_len);      off += ct1_aead_len;
		g_pq3_exchange.msg1_len = off;
		g_pq3_exchange.msg1_ready = 1;
	}
	pthread_cond_signal(&g_pq3_exchange.cond_msg1_ready);
	pthread_mutex_unlock(&g_pq3_exchange.mutex);

	/* ── Receive msg2 ── */
	pthread_mutex_lock(&g_pq3_exchange.mutex);
	while (!g_pq3_exchange.msg2_ready)
		pthread_cond_wait(&g_pq3_exchange.cond_msg2_ready,
		                  &g_pq3_exchange.mutex);
	pthread_mutex_unlock(&g_pq3_exchange.mutex);

	uint8_t *msg2 = g_pq3_exchange.msg2_buf;
	uint32_t m2off = 0;
	uint8_t ct_eph2[PQ_KEM_CT_LEN];
	memcpy(ct_eph2, msg2 + m2off, PQ_KEM_CT_LEN); m2off += PQ_KEM_CT_LEN;
	uint8_t ct_I[PQ_KEM_CT_LEN];
	memcpy(ct_I, msg2 + m2off, PQ_KEM_CT_LEN);    m2off += PQ_KEM_CT_LEN;
	uint16_t ct2_aead_len = (msg2[m2off] << 8) | msg2[m2off + 1]; m2off += 2;
	uint8_t ct2_aead[512 + PQ_AEAD_TAG_LEN];
	memcpy(ct2_aead, msg2 + m2off, ct2_aead_len);

	/* ── Step 3: Decaps ephemeral ── */
	uint8_t ss_eph[PQ_KEM_SS_LEN];
	ret = pq_kem_decaps(ss_eph, ct_eph2, ctx->eph_sk);
	if (ret != 0) { print_error("T3PQ Init: Decaps(eph) failed"); return NULL; }

	ret = pq_hkdf_extract(ctx->prk1, PQ_PRK_LEN, ss_eph, PQ_KEM_SS_LEN, ctx->prk2);
	if (ret != 0) { print_error("T3PQ Init: PRK2 failed"); return NULL; }

	uint8_t k2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
	ret = t3pq_derive_key_iv(ctx->prk2, T3PQ_K2, sizeof(T3PQ_K2) - 1, k2, iv2);
	if (ret != 0) { print_error("T3PQ Init: K2/IV2 failed"); return NULL; }

	uint8_t pt2[512];
	size_t pt2_len = 0;
	ret = pq_aead_decrypt(k2, iv2, NULL, 0, ct2_aead, ct2_aead_len, pt2, &pt2_len);
	if (ret != 0) { print_error("T3PQ Init: AEAD dec msg2 failed"); return NULL; }

	/* TH2 = Hash(msg1 || ct_eph2) */
	uint8_t th2_buf[PQ_MSG_BUF_SIZE];
	uint32_t th2_len = g_pq3_exchange.msg1_len + PQ_KEM_CT_LEN;
	memcpy(th2_buf, g_pq3_exchange.msg1_buf, g_pq3_exchange.msg1_len);
	memcpy(th2_buf + g_pq3_exchange.msg1_len, ct_eph2, PQ_KEM_CT_LEN);
	ret = pq_hash_sha256(th2_buf, th2_len, ctx->th2);
	if (ret != 0) { print_error("T3PQ Init: TH2 failed"); return NULL; }

	/* Verify MAC2 */
	uint8_t mac2_info[PQ_HASH_LEN + 64];
	memcpy(mac2_info, ctx->th2, PQ_HASH_LEN);
	memcpy(mac2_info + PQ_HASH_LEN, T3PQ_ID_R, sizeof(T3PQ_ID_R) - 1);
	uint8_t mac2_exp[PQ_AEAD_TAG_LEN];
	ret = pq_hkdf_expand(ctx->prk2, mac2_info,
	                      PQ_HASH_LEN + sizeof(T3PQ_ID_R) - 1,
	                      mac2_exp, PQ_AEAD_TAG_LEN);
	if (ret != 0) { print_error("T3PQ Init: MAC2 derive failed"); return NULL; }
	if (pt2_len < PQ_AEAD_TAG_LEN ||
	    memcmp(mac2_exp, pt2 + pt2_len - PQ_AEAD_TAG_LEN, PQ_AEAD_TAG_LEN) != 0) {
		print_error("T3PQ Init: MAC2 verify FAILED");
		return NULL;
	}

	/* Decaps ct_I (mutual auth) */
	uint8_t ss_I[PQ_KEM_SS_LEN];
	ret = pq_kem_decaps(ss_I, ct_I, ctx->lt_sk);
	if (ret != 0) { print_error("T3PQ Init: Decaps(ct_I) failed"); return NULL; }

	ret = pq_hkdf_extract(ctx->prk2, PQ_PRK_LEN, ss_I, PQ_KEM_SS_LEN, ctx->prk3);
	if (ret != 0) { print_error("T3PQ Init: PRK3 failed"); return NULL; }

	/* TH3 = Hash(TH2 || msg2) */
	uint8_t th3_buf[PQ_MSG_BUF_SIZE];
	memcpy(th3_buf, ctx->th2, PQ_HASH_LEN);
	memcpy(th3_buf + PQ_HASH_LEN, g_pq3_exchange.msg2_buf, g_pq3_exchange.msg2_len);
	ret = pq_hash_sha256(th3_buf, PQ_HASH_LEN + g_pq3_exchange.msg2_len, ctx->th3);
	if (ret != 0) { print_error("T3PQ Init: TH3 failed"); return NULL; }

	/* MAC3 */
	uint8_t mac3_info[PQ_HASH_LEN + 64];
	memcpy(mac3_info, ctx->th3, PQ_HASH_LEN);
	memcpy(mac3_info + PQ_HASH_LEN, T3PQ_ID_I, sizeof(T3PQ_ID_I) - 1);
	uint8_t mac3[PQ_AEAD_TAG_LEN];
	ret = pq_hkdf_expand(ctx->prk3, mac3_info,
	                      PQ_HASH_LEN + sizeof(T3PQ_ID_I) - 1,
	                      mac3, PQ_AEAD_TAG_LEN);
	if (ret != 0) { print_error("T3PQ Init: MAC3 derive failed"); return NULL; }

	uint8_t k3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
	ret = t3pq_derive_key_iv(ctx->prk3, T3PQ_K3, sizeof(T3PQ_K3) - 1, k3, iv3);
	if (ret != 0) { print_error("T3PQ Init: K3/IV3 failed"); return NULL; }

	uint8_t ct3_aead[64 + PQ_AEAD_TAG_LEN];
	size_t ct3_aead_len = 0;
	ret = pq_aead_encrypt(k3, iv3, NULL, 0, mac3, PQ_AEAD_TAG_LEN,
	                       ct3_aead, &ct3_aead_len);
	if (ret != 0) { print_error("T3PQ Init: AEAD enc msg3 failed"); return NULL; }

	/* ── Send msg3 ── */
	pthread_mutex_lock(&g_pq3_exchange.mutex);
	memcpy(g_pq3_exchange.msg3_buf, ct3_aead, ct3_aead_len);
	g_pq3_exchange.msg3_len = ct3_aead_len;
	g_pq3_exchange.msg3_ready = 1;
	pthread_cond_signal(&g_pq3_exchange.cond_msg3_ready);
	pthread_mutex_unlock(&g_pq3_exchange.mutex);

	/* PRK_out */
	uint8_t th4_in[PQ_HASH_LEN + 64];
	memcpy(th4_in, ctx->th3, PQ_HASH_LEN);
	memcpy(th4_in + PQ_HASH_LEN, ct3_aead, ct3_aead_len);
	ret = pq_hash_sha256(th4_in, PQ_HASH_LEN + ct3_aead_len, ctx->th4);
	if (ret != 0) { print_error("T3PQ Init: TH4 failed"); return NULL; }
	ret = pq_hkdf_expand(ctx->prk3, ctx->th4, PQ_HASH_LEN,
	                      ctx->prk_out, PQ_PRK_LEN);
	if (ret != 0) { print_error("T3PQ Init: PRK_out failed"); return NULL; }

	ctx->success = 1;
	print_success("T3PQ Initiator: EDHOC exchange completed!");
	return NULL;
}

/* =============================================================================
 * Responder Thread (Type 3 PQ)
 * =============================================================================
 */
static void *pq3_responder_thread(void *arg)
{
	struct pq3_party_ctx *ctx = (struct pq3_party_ctx *)arg;
	int ret;

	/* ── Receive msg1 ── */
	pthread_mutex_lock(&g_pq3_exchange.mutex);
	while (!g_pq3_exchange.msg1_ready)
		pthread_cond_wait(&g_pq3_exchange.cond_msg1_ready,
		                  &g_pq3_exchange.mutex);
	pthread_mutex_unlock(&g_pq3_exchange.mutex);

	uint8_t *msg1 = g_pq3_exchange.msg1_buf;
	uint32_t m1off = 0;
	uint8_t pk_eph[PQ_KEM_PK_LEN];
	memcpy(pk_eph, msg1 + m1off, PQ_KEM_PK_LEN); m1off += PQ_KEM_PK_LEN;
	uint8_t ct_R[PQ_KEM_CT_LEN];
	memcpy(ct_R, msg1 + m1off, PQ_KEM_CT_LEN);   m1off += PQ_KEM_CT_LEN;
	uint16_t ct1_aead_len = (msg1[m1off] << 8) | msg1[m1off + 1]; m1off += 2;
	uint8_t ct1_aead[256 + PQ_AEAD_TAG_LEN];
	memcpy(ct1_aead, msg1 + m1off, ct1_aead_len);

	/* ── Step 2: Decaps ct_R ── */
	uint8_t ss_R[PQ_KEM_SS_LEN];
	ret = pq_kem_decaps(ss_R, ct_R, ctx->lt_sk);
	if (ret != 0) { print_error("T3PQ Resp: Decaps(ct_R) failed"); return NULL; }

	ret = pq_hkdf_extract(NULL, 0, ss_R, PQ_KEM_SS_LEN, ctx->prk1);
	if (ret != 0) { print_error("T3PQ Resp: PRK1 failed"); return NULL; }

	uint8_t k1[PQ_AEAD_KEY_LEN], iv1[PQ_AEAD_NONCE_LEN];
	ret = t3pq_derive_key_iv(ctx->prk1, T3PQ_K1, sizeof(T3PQ_K1) - 1, k1, iv1);
	if (ret != 0) { print_error("T3PQ Resp: K1/IV1 failed"); return NULL; }

	uint8_t pt1[256];
	size_t pt1_len = 0;
	ret = pq_aead_decrypt(k1, iv1, NULL, 0, ct1_aead, ct1_aead_len, pt1, &pt1_len);
	if (ret != 0) { print_error("T3PQ Resp: AEAD dec msg1 failed"); return NULL; }

	/* Encaps to pk_eph */
	uint8_t ct_eph2[PQ_KEM_CT_LEN], ss_eph[PQ_KEM_SS_LEN];
	ret = pq_kem_encaps(ct_eph2, ss_eph, pk_eph);
	if (ret != 0) { print_error("T3PQ Resp: Encaps(eph) failed"); return NULL; }

	ret = pq_hkdf_extract(ctx->prk1, PQ_PRK_LEN, ss_eph, PQ_KEM_SS_LEN, ctx->prk2);
	if (ret != 0) { print_error("T3PQ Resp: PRK2 failed"); return NULL; }

	uint8_t k2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
	ret = t3pq_derive_key_iv(ctx->prk2, T3PQ_K2, sizeof(T3PQ_K2) - 1, k2, iv2);
	if (ret != 0) { print_error("T3PQ Resp: K2/IV2 failed"); return NULL; }

	/* TH2 = Hash(msg1 || ct_eph2) */
	uint8_t th2_buf[PQ_MSG_BUF_SIZE];
	uint32_t th2_len = g_pq3_exchange.msg1_len + PQ_KEM_CT_LEN;
	memcpy(th2_buf, g_pq3_exchange.msg1_buf, g_pq3_exchange.msg1_len);
	memcpy(th2_buf + g_pq3_exchange.msg1_len, ct_eph2, PQ_KEM_CT_LEN);
	ret = pq_hash_sha256(th2_buf, th2_len, ctx->th2);
	if (ret != 0) { print_error("T3PQ Resp: TH2 failed"); return NULL; }

	/* MAC2 */
	uint8_t mac2_info[PQ_HASH_LEN + 64];
	memcpy(mac2_info, ctx->th2, PQ_HASH_LEN);
	memcpy(mac2_info + PQ_HASH_LEN, T3PQ_ID_R, sizeof(T3PQ_ID_R) - 1);
	uint8_t mac2[PQ_AEAD_TAG_LEN];
	ret = pq_hkdf_expand(ctx->prk2, mac2_info,
	                      PQ_HASH_LEN + sizeof(T3PQ_ID_R) - 1,
	                      mac2, PQ_AEAD_TAG_LEN);
	if (ret != 0) { print_error("T3PQ Resp: MAC2 derive failed"); return NULL; }

	/* Encaps to pkI (mutual auth) */
	uint8_t ct_I[PQ_KEM_CT_LEN], ss_I[PQ_KEM_SS_LEN];
	ret = pq_kem_encaps(ct_I, ss_I, ctx->other_lt_pk);
	if (ret != 0) { print_error("T3PQ Resp: Encaps(pkI) failed"); return NULL; }

	ret = pq_hkdf_extract(ctx->prk2, PQ_PRK_LEN, ss_I, PQ_KEM_SS_LEN, ctx->prk3);
	if (ret != 0) { print_error("T3PQ Resp: PRK3 failed"); return NULL; }

	/* msg2 plaintext: C_R || ID_CRED_R || MAC2 */
	uint8_t pt2[256];
	uint32_t pt2_len = 0;
	pt2[pt2_len++] = 0x27; /* C_R */
	memcpy(pt2 + pt2_len, T3PQ_ID_R, sizeof(T3PQ_ID_R) - 1);
	pt2_len += sizeof(T3PQ_ID_R) - 1;
	memcpy(pt2 + pt2_len, mac2, PQ_AEAD_TAG_LEN);
	pt2_len += PQ_AEAD_TAG_LEN;

	uint8_t ct2_aead[512 + PQ_AEAD_TAG_LEN];
	size_t ct2_aead_len = 0;
	ret = pq_aead_encrypt(k2, iv2, NULL, 0, pt2, pt2_len,
	                       ct2_aead, &ct2_aead_len);
	if (ret != 0) { print_error("T3PQ Resp: AEAD enc msg2 failed"); return NULL; }

	/* ── Send msg2 ── */
	pthread_mutex_lock(&g_pq3_exchange.mutex);
	{
		uint8_t *p = g_pq3_exchange.msg2_buf;
		uint32_t off = 0;
		memcpy(p + off, ct_eph2, PQ_KEM_CT_LEN); off += PQ_KEM_CT_LEN;
		memcpy(p + off, ct_I, PQ_KEM_CT_LEN);    off += PQ_KEM_CT_LEN;
		p[off++] = (uint8_t)(ct2_aead_len >> 8);
		p[off++] = (uint8_t)(ct2_aead_len & 0xFF);
		memcpy(p + off, ct2_aead, ct2_aead_len);  off += ct2_aead_len;
		g_pq3_exchange.msg2_len = off;
		g_pq3_exchange.msg2_ready = 1;
	}
	pthread_cond_signal(&g_pq3_exchange.cond_msg2_ready);
	pthread_mutex_unlock(&g_pq3_exchange.mutex);

	/* ── Receive msg3 ── */
	pthread_mutex_lock(&g_pq3_exchange.mutex);
	while (!g_pq3_exchange.msg3_ready)
		pthread_cond_wait(&g_pq3_exchange.cond_msg3_ready,
		                  &g_pq3_exchange.mutex);
	pthread_mutex_unlock(&g_pq3_exchange.mutex);

	uint8_t k3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
	ret = t3pq_derive_key_iv(ctx->prk3, T3PQ_K3, sizeof(T3PQ_K3) - 1, k3, iv3);
	if (ret != 0) { print_error("T3PQ Resp: K3/IV3 failed"); return NULL; }

	uint8_t pt3[64];
	size_t pt3_len = 0;
	ret = pq_aead_decrypt(k3, iv3, NULL, 0,
	                       g_pq3_exchange.msg3_buf, g_pq3_exchange.msg3_len,
	                       pt3, &pt3_len);
	if (ret != 0) { print_error("T3PQ Resp: AEAD dec msg3 failed"); return NULL; }

	/* TH3 = Hash(TH2 || msg2) */
	uint8_t th3_buf[PQ_MSG_BUF_SIZE];
	memcpy(th3_buf, ctx->th2, PQ_HASH_LEN);
	memcpy(th3_buf + PQ_HASH_LEN, g_pq3_exchange.msg2_buf, g_pq3_exchange.msg2_len);
	ret = pq_hash_sha256(th3_buf, PQ_HASH_LEN + g_pq3_exchange.msg2_len, ctx->th3);
	if (ret != 0) { print_error("T3PQ Resp: TH3 failed"); return NULL; }

	/* Verify MAC3 */
	uint8_t mac3_info[PQ_HASH_LEN + 64];
	memcpy(mac3_info, ctx->th3, PQ_HASH_LEN);
	memcpy(mac3_info + PQ_HASH_LEN, T3PQ_ID_I, sizeof(T3PQ_ID_I) - 1);
	uint8_t mac3_exp[PQ_AEAD_TAG_LEN];
	ret = pq_hkdf_expand(ctx->prk3, mac3_info,
	                      PQ_HASH_LEN + sizeof(T3PQ_ID_I) - 1,
	                      mac3_exp, PQ_AEAD_TAG_LEN);
	if (ret != 0) { print_error("T3PQ Resp: MAC3 derive failed"); return NULL; }
	if (pt3_len != PQ_AEAD_TAG_LEN ||
	    memcmp(mac3_exp, pt3, PQ_AEAD_TAG_LEN) != 0) {
		print_error("T3PQ Resp: MAC3 verify FAILED");
		return NULL;
	}

	/* PRK_out */
	uint8_t th4_in[PQ_HASH_LEN + 64];
	memcpy(th4_in, ctx->th3, PQ_HASH_LEN);
	memcpy(th4_in + PQ_HASH_LEN, g_pq3_exchange.msg3_buf, g_pq3_exchange.msg3_len);
	ret = pq_hash_sha256(th4_in, PQ_HASH_LEN + g_pq3_exchange.msg3_len, ctx->th4);
	if (ret != 0) { print_error("T3PQ Resp: TH4 failed"); return NULL; }
	ret = pq_hkdf_expand(ctx->prk3, ctx->th4, PQ_HASH_LEN,
	                      ctx->prk_out, PQ_PRK_LEN);
	if (ret != 0) { print_error("T3PQ Resp: PRK_out failed"); return NULL; }

	ctx->success = 1;
	print_success("T3PQ Responder: EDHOC exchange completed!");
	return NULL;
}

/* =============================================================================
 * Main entry point for Type 3 PQ
 * =============================================================================
 */
int run_edhoc_type3_pq(void)
{
	print_header("EDHOC Type 3 PQ: KEM-based MAC-MAC (ML-KEM-768)");
	printf("\n");
	print_info("Post-Quantum EDHOC Type 3 using ML-KEM-768 (NIST Level 3)");
	print_info("Key Exchange: Ephemeral KEM (forward secrecy)");
	print_info("Authentication: Long-term KEM Encaps/Decaps + MAC verification");
	print_info("Symmetric: AES-CCM-16-64-128, SHA-256, HKDF");
	printf("\n");

	struct pq3_party_ctx init_ctx, resp_ctx;
	memset(&init_ctx, 0, sizeof(init_ctx));
	memset(&resp_ctx, 0, sizeof(resp_ctx));

	print_info("Generating long-term PQ key pairs...");
	if (pq_kem_keygen(init_ctx.lt_pk, init_ctx.lt_sk) != 0) {
		print_error("Failed to generate Initiator key pair");
		return -1;
	}
	if (pq_kem_keygen(resp_ctx.lt_pk, resp_ctx.lt_sk) != 0) {
		print_error("Failed to generate Responder key pair");
		return -1;
	}
	memcpy(init_ctx.other_lt_pk, resp_ctx.lt_pk, PQ_KEM_PK_LEN);
	memcpy(resp_ctx.other_lt_pk, init_ctx.lt_pk, PQ_KEM_PK_LEN);
	print_success("Key pairs generated and trust anchors exchanged.");
	printf("\n");

	pq3_exchange_init();

	pthread_t tid_i, tid_r;
	print_info("Starting EDHOC PQ handshake (Type 3)...");
	printf("\n");

	pthread_create(&tid_r, NULL, pq3_responder_thread, &resp_ctx);
	pthread_create(&tid_i, NULL, pq3_initiator_thread, &init_ctx);
	pthread_join(tid_i, NULL);
	pthread_join(tid_r, NULL);

	pq3_exchange_destroy();

	printf("\n");
	print_header("EDHOC Type 3 PQ - Results");
	printf("\n");

	if (!init_ctx.success || !resp_ctx.success) {
		print_error("EDHOC PQ Type 3 exchange failed!");
		return -1;
	}

	print_hex("Initiator PRK_out", init_ctx.prk_out, PQ_PRK_LEN);
	print_hex("Responder PRK_out", resp_ctx.prk_out, PQ_PRK_LEN);

	if (memcmp(init_ctx.prk_out, resp_ctx.prk_out, PQ_PRK_LEN) == 0) {
		print_success("PRK_out MATCH: Initiator and Responder agree!");
	} else {
		print_error("PRK_out MISMATCH!");
		return -1;
	}

	printf("\n");
	print_success("EDHOC Type 3 PQ (ML-KEM-768) completed successfully!");
	printf("\n");
	return 0;
}
