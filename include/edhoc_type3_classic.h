/*
 * EDHOC-Hybrid: Type 3 MAC-MAC (Classic) header
 * RFC 9528 - Method 3: Initiator Static DH Key, Responder Static DH Key
 * Cipher Suite 0: AES-CCM-16-64-128, SHA-256, 8, X25519, EdDSA
 *
 * Pada Type 3, Initiator dan Responder berkomunikasi melalui 3 pesan:
 *   message_1: Initiator → Responder (METHOD=3, SUITES_I=0, G_X, C_I)
 *   message_2: Responder → Initiator (G_Y, C_R, CIPHERTEXT_2)
 *              CIPHERTEXT_2 berisi MAC_2 = HMAC(PRK_3e2m, context_2)
 *              PRK_3e2m dihasilkan dari X25519: r × G_X (static DH Responder)
 *   message_3: Initiator → Responder (CIPHERTEXT_3)
 *              CIPHERTEXT_3 berisi MAC_3 = HMAC(PRK_4e3m, context_3)
 *              PRK_4e3m dihasilkan dari X25519: i × G_Y (static DH Initiator)
 *
 * Classic algorithm: X25519 Diffie-Hellman untuk ephemeral DH dan static DH
 * Autentikasi: Static DH + MAC (bukan Signature + Verify seperti Type 0)
 */

#ifndef EDHOC_TYPE3_CLASSIC_H
#define EDHOC_TYPE3_CLASSIC_H

/*
 * Run EDHOC Type 3 (MAC-MAC) Classic protocol.
 * Uses X25519 keys (Suite 0, Method 3) with RFC 9529 credentials.
 * Returns 0 on success, non-zero on failure.
 */
int run_edhoc_type3_classic(void);

#endif /* EDHOC_TYPE3_CLASSIC_H */
