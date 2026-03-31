/*
 * =============================================================================
 * EDHOC-Hybrid: Type 3 Hybrid (ECDHE + KEM) Header
 * =============================================================================
 *
 * Hybrid EDHOC Type 3 variant combining classical ECDHE (X25519) with
 * post-quantum KEM (ML-KEM-768) for key agreement, and MAC-based
 * authentication via static ECDHE keys.
 *
 * Key Agreement (hybrid):
 *   - Ephemeral ECDHE: X25519 (x,X) ↔ (y,Y) for classical forward secrecy
 *   - Ephemeral KEM:   ML-KEM-768 KEM.Enc(PK_KEM) → (k_KEM, C_KEM)
 *     for post-quantum security
 *
 * Authentication:
 *   - Static ECDHE: Initiator (a,A), Responder (b,B) — MAC-based auth
 *     (same as classic Type 3, no signatures)
 *
 * PRK derivation combines BOTH ECDHE shared secrets AND KEM shared secret
 * via chained HKDF-Extract, ensuring security if either primitive holds.
 *
 * Algorithm: X25519 + ML-KEM-768 + AES-CCM-16-64-128 + SHA-256 + HKDF
 *
 * === Protocol Flow ===
 *
 *   msg1: I→R: M1 = (Method, Suites, CI, EAD1, X, PK_KEM)
 *   msg2: R→I: M2 = (Y, Suites, C_KEM, AEAD(EK2, msg2))
 *     where msg2 = (CR, R, EAD2, MAC2)
 *   msg3: I→R: M3 = AEAD(EK3, msg3)
 *     where msg3 = (I, EAD3, MAC3)
 *
 * === Crypto Operations per Role ===
 *
 *   Initiator: X25519 KeyGen=1(eph), KEM.KeyGen=1(eph),
 *              ECDH=2(Yx,Bx), KEM.Dec=1(C_KEM),
 *              HKDF≈10, AEAD_Enc=1, AEAD_Dec=1, Hash=3
 *   Responder: X25519 KeyGen=1(eph),
 *              ECDH=2(Xy,Ay), KEM.Enc=1(PK_KEM),
 *              HKDF≈10, AEAD_Enc=1, AEAD_Dec=1, Hash=3
 */

#ifndef EDHOC_TYPE3_HYBRID_H
#define EDHOC_TYPE3_HYBRID_H

#include <stdint.h>
#include "edhoc_pq_kem.h"

/* ── Hybrid party context ── */
struct hybrid_party_ctx {
	/* Static ECDHE keys (long-term, for MAC auth) — a/A or b/B */
	uint8_t static_sk[32];           /* X25519 static private key */
	uint8_t static_pk[32];           /* X25519 static public key  */
	uint8_t other_static_pk[32];     /* Peer's static public key  */

	/* Ephemeral ECDHE keys — x/X or y/Y */
	uint8_t eph_sk[32];              /* X25519 ephemeral private key */
	uint8_t eph_pk[32];              /* X25519 ephemeral public key  */

	/* Ephemeral KEM keys (Initiator generates, Responder encapsulates) */
	uint8_t kem_pk[PQ_KEM_PK_LEN];  /* KEM public key   */
	uint8_t kem_sk[PQ_KEM_SK_LEN];  /* KEM secret key   */

	/* Derived key material */
	uint8_t prk2e[32];               /* PRK2e  = HKDF-Extract(Xy, k_KEM, TH2)  */
	uint8_t prk3e2m[32];             /* PRK3e2m = HKDF-Extract(Xb, PRK2e)       */
	uint8_t prk4e3m[32];             /* PRK4e3m = HKDF-Extract(Ya, PRK3e2m)     */
	uint8_t th2[32];                 /* TH2 = H(M1, Y, C_KEM) */
	uint8_t th3[32];                 /* TH3 = H(TH2, msg2, B) */
	uint8_t th4[32];                 /* TH4 = H(TH3, msg3, A) */
	uint8_t prk_out[32];             /* PRK_out = HKDF-Expand(PRK4e3m, TH4) */

	int success;
	uint64_t txrx_ns;  /* Accumulated message exchange time (ns) */
};

/**
 * @brief Run EDHOC Type 3 Hybrid (ECDHE + KEM) protocol simulation.
 * @return 0 on success, -1 on failure
 */
int run_edhoc_type3_hybrid(void);

/* ── Benchmark support ── */
void hybrid_exchange_init(void);
void hybrid_exchange_destroy(void);
void *hybrid_initiator_thread(void *arg);
void *hybrid_responder_thread(void *arg);

#endif /* EDHOC_TYPE3_HYBRID_H */
