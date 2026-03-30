/*
 * EDHOC-Hybrid: Type 0 Signature-Signature (Classic) header
 * RFC 9528 - Method 0: Initiator Signature Key, Responder Signature Key
 * Cipher Suite 0: AES-CCM-16-64-128, SHA-256, 8, X25519, EdDSA
 *
 * Pada Type 0, Initiator dan Responder berkomunikasi melalui 3 pesan:
 *   message_1: Initiator → Responder (METHOD=0, SUITES_I, G_X, C_I)
 *   message_2: Responder → Initiator (G_Y, C_R, CIPHERTEXT_2)
 *              CIPHERTEXT_2 berisi Signature_2 = Sign(sk_R, MAC_2)
 *   message_3: Initiator → Responder (CIPHERTEXT_3)
 *              CIPHERTEXT_3 berisi Signature_3 = Sign(sk_I, MAC_3)
 *
 * Classic algorithm: X25519 untuk ephemeral DH, EdDSA untuk Sign + Verify
 * Autentikasi: Signature (tanda tangan digital) + Verify (verifikasi)
 */

#ifndef EDHOC_TYPE0_CLASSIC_H
#define EDHOC_TYPE0_CLASSIC_H

/*
 * Run EDHOC Type 0 (Signature-Signature) Classic protocol.
 * Uses RFC 9529 test vectors (Suite 0, Method 0, X25519+EdDSA).
 * Returns 0 on success, non-zero on failure.
 */
int run_edhoc_type0_classic(void);

#endif /* EDHOC_TYPE0_CLASSIC_H */
