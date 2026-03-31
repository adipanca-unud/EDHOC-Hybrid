/*
 * =============================================================================
 * EDHOC-Hybrid: Type 3 PQ (KEM-based MAC-like) Header
 * =============================================================================
 *
 * Post-Quantum variant of EDHOC Type 3. Uses same protocol flow as Type 0 PQ
 * but authentication is purely KEM-based MAC (no signatures at all).
 *
 * In the PQ context, both Type 0 PQ and Type 3 PQ use KEM for authentication.
 * Type 3 PQ emphasizes MAC-based verification of the KEM-derived keys,
 * analogous to how classic Type 3 uses Static DH + MAC instead of Signature.
 *
 * Key Exchange:
 *   - Ephemeral KEM: Fresh KEM key pair per session (forward secrecy)
 *   - Long-term KEM: KEM Encaps/Decaps for mutual authentication
 *
 * Algorithm: ML-KEM-768 + AES-CCM-16-64-128 + SHA-256 + HKDF
 */

#ifndef EDHOC_TYPE3_PQ_H
#define EDHOC_TYPE3_PQ_H

#include <stdint.h>

/**
 * @brief Run EDHOC Type 3 PQ (KEM-based MAC) protocol simulation.
 *
 * Simulates a full 3-message EDHOC handshake between Initiator and
 * Responder using ML-KEM-768 for key exchange and MAC authentication.
 *
 * @return 0 on success, -1 on failure
 */
int run_edhoc_type3_pq(void);

/* ── Benchmark support: expose internal thread functions ─────────────── */
#include "edhoc_pq_kem.h"

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
	uint64_t txrx_ns;  /* Accumulated message exchange time (ns) */
};

void pq3_exchange_init(void);
void pq3_exchange_destroy(void);
void *pq3_initiator_thread(void *arg);
void *pq3_responder_thread(void *arg);

#endif /* EDHOC_TYPE3_PQ_H */
