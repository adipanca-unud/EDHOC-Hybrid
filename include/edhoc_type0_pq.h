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

/**
 * @brief Run EDHOC Type 0 PQ (KEM-based) protocol simulation.
 *
 * Simulates a full 3-message EDHOC handshake between Initiator and
 * Responder using ML-KEM-768 for key exchange and authentication.
 *
 * @return 0 on success, -1 on failure
 */
int run_edhoc_type0_pq(void);

#endif /* EDHOC_TYPE0_PQ_H */
