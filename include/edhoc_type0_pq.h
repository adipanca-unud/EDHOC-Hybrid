/*
 * =============================================================================
 * EDHOC-Hybrid: Type 0 PQ (KEM-based Sig-like) Header
 * =============================================================================
 *
 * Post-Quantum variant of EDHOC Type 0. Replaces classical ECDH+EdDSA
 * with ML-KEM-768 KEM operations. Based on the user's sequence diagram:
 *
 * Authentication: Both parties use PQ KEM encaps/decaps of long-term keys
 * to prove identity (analogous to Signature-based in classic Type 0, but
 * the flow uses KEM Encap of the other party's long-term pk as implicit
 * authentication — similar to KEMTLS model).
 *
 * Key Exchange:
 *   - Ephemeral KEM: Fresh KEM key pair per session (forward secrecy)
 *   - Long-term KEM: Encaps to long-term pk for authentication
 *
 * Message Flow (3 messages, same as classic EDHOC):
 *   msg1: Initiator → Responder: ct_R (KEM.Encaps(pkR)), AEAD(METHOD, ...)
 *   msg2: Responder → Initiator: ct_eph (KEM.Encaps(pk_eph)), ct_I, AEAD(...)
 *   msg3: Initiator → Responder: AEAD(MAC3)
 *
 * Algorithm: ML-KEM-768 + AES-CCM-16-64-128 + SHA-256 + HKDF
 */

#ifndef EDHOC_TYPE0_PQ_H
#define EDHOC_TYPE0_PQ_H

#include <stdint.h>

/**
 * @brief Run EDHOC Type 0 PQ (KEM-based) protocol simulation.
 *
 * Simulates a full 3-message EDHOC handshake between Initiator and
 * Responder using ML-KEM-768 for key exchange and authentication.
 *
 * @return 0 on success, -1 on failure
 */
int run_edhoc_type0_pq(void);

/* ── Benchmark support: expose internal thread functions ─────────────── */
#include "edhoc_pq_kem.h"  /* PQ_KEM_PK_LEN, PQ_KEM_SK_LEN, etc. */

struct pq_party_ctx {
	/* KEM long-term keys (used for key exchange / encaps to other party) */
	uint8_t lt_pk[PQ_KEM_PK_LEN];
	uint8_t lt_sk[PQ_KEM_SK_LEN];
	uint8_t other_lt_pk[PQ_KEM_PK_LEN];
	/* Signature long-term keys (ML-DSA-65, for Type 0 PQ SigSig auth) */
	uint8_t sig_pk[PQ_SIG_PK_LEN];
	uint8_t sig_sk[PQ_SIG_SK_LEN];
	uint8_t other_sig_pk[PQ_SIG_PK_LEN];
	/* Ephemeral KEM keys */
	uint8_t eph_pk[PQ_KEM_PK_LEN];
	uint8_t eph_sk[PQ_KEM_SK_LEN];
	/* Derived key material */
	uint8_t prk1[PQ_PRK_LEN];
	uint8_t prk2[PQ_PRK_LEN];
	uint8_t prk3[PQ_PRK_LEN];
	uint8_t th2[PQ_HASH_LEN];
	uint8_t th3[PQ_HASH_LEN];
	uint8_t th4[PQ_HASH_LEN];
	uint8_t prk_out[PQ_PRK_LEN];
	int success;
	uint64_t txrx_ns;  /* Accumulated message exchange time (ns) */
};

void pq_exchange_init(void);
void pq_exchange_destroy(void);
void *pq_type0_initiator_thread(void *arg);
void *pq_type0_responder_thread(void *arg);

#endif /* EDHOC_TYPE0_PQ_H */
