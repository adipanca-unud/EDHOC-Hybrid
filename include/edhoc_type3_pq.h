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

/**
 * @brief Run EDHOC Type 3 PQ (KEM-based MAC) protocol simulation.
 *
 * Simulates a full 3-message EDHOC handshake between Initiator and
 * Responder using ML-KEM-768 for key exchange and MAC authentication.
 *
 * @return 0 on success, -1 on failure
 */
int run_edhoc_type3_pq(void);

#endif /* EDHOC_TYPE3_PQ_H */
