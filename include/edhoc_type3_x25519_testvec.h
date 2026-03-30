/*
 * =============================================================================
 * EDHOC Type 3 (MAC-MAC) with X25519 — Test Vectors
 * =============================================================================
 *
 * Method 3 (Static DH Key + Static DH Key) with Suite 0 (X25519 + EdDSA)
 *
 * Kunci-kunci berikut dibangkitkan menggunakan X25519 (Curve25519):
 *   - Ephemeral DH keys: (x, G_X) dan (y, G_Y)
 *   - Static DH keys:    (i, G_I) dan (r, G_R)
 *
 * Credentials (ID_CRED, CRED) diambil dari RFC 9529 karena format
 * credential di EDHOC bersifat opaque — library hanya mencocokkan
 * ID_CRED untuk lookup, sedangkan kunci DH diambil dari field .g
 * pada struct other_party_cred (bukan dari dalam sertifikat).
 *
 * Suite 0: AES-CCM-16-64-128, SHA-256, MAC8, X25519, EdDSA
 * =============================================================================
 */

#ifndef EDHOC_TYPE3_X25519_TESTVEC_H
#define EDHOC_TYPE3_X25519_TESTVEC_H

#include <stdint.h>

/* Method = 3 (Initiator Static DH Key, Responder Static DH Key) */
static const uint8_t T3_X25519_METHOD = 0x03;

/* Suite = 0 (X25519 + EdDSA, AES-CCM-16-64-128, SHA-256, MAC8) */
static const uint8_t T3_X25519_SUITES_I[] = { 0x00 };
static const uint32_t T3_X25519_SUITES_I_LEN = sizeof(T3_X25519_SUITES_I);
static const uint8_t T3_X25519_SUITES_R[] = { 0x00 };
static const uint32_t T3_X25519_SUITES_R_LEN = sizeof(T3_X25519_SUITES_R);

/* Connection Identifiers */
static const uint8_t T3_X25519_C_I[] = { 0x37 };  /* CBOR int -24 */
static const uint32_t T3_X25519_C_I_LEN = sizeof(T3_X25519_C_I);
static const uint8_t T3_X25519_C_R[] = { 0x27 };  /* CBOR int -8 */
static const uint32_t T3_X25519_C_R_LEN = sizeof(T3_X25519_C_R);

/*
 * ---- Ephemeral X25519 Keys (untuk key agreement / forward secrecy) ----
 *
 * Initiator: (x, G_X) — ephemeral DH key pair
 * Responder: (y, G_Y) — ephemeral DH key pair
 * ECDH ephemeral: x × G_Y = y × G_X → shared secret
 */

/* Initiator ephemeral private key (x) — 32 bytes X25519 */
static const uint8_t T3_X25519_X[] = {
	0xe8, 0x21, 0xd2, 0x6b, 0xfa, 0x94, 0x51, 0x07,
	0x10, 0x45, 0xd0, 0x74, 0xe6, 0xbc, 0x42, 0x1f,
	0x5e, 0x2b, 0xe4, 0xf5, 0x30, 0x0b, 0x0b, 0x0b,
	0xfb, 0x9c, 0x94, 0x73, 0xef, 0xf2, 0x4c, 0x68
};
static const uint32_t T3_X25519_X_LEN = sizeof(T3_X25519_X);

/* Initiator ephemeral public key (G_X) — 32 bytes X25519 */
static const uint8_t T3_X25519_G_X[] = {
	0xbc, 0x8f, 0x1e, 0xd3, 0xb7, 0xd8, 0x00, 0x26,
	0x76, 0x93, 0x05, 0xa7, 0x0c, 0x2a, 0x61, 0xb7,
	0x47, 0xbd, 0xfc, 0x64, 0x27, 0xf3, 0x42, 0x62,
	0x4a, 0x32, 0xa1, 0xf7, 0xc8, 0x5f, 0x19, 0x03
};
static const uint32_t T3_X25519_G_X_LEN = sizeof(T3_X25519_G_X);

/* Responder ephemeral private key (y) — 32 bytes X25519 */
static const uint8_t T3_X25519_Y[] = {
	0x40, 0x66, 0x78, 0xa9, 0x98, 0xd7, 0xc5, 0x81,
	0xce, 0x5b, 0xf8, 0x9a, 0x6a, 0xee, 0xfb, 0xb7,
	0x7a, 0xac, 0x10, 0xea, 0xab, 0xc5, 0x77, 0xb5,
	0x06, 0xef, 0xa5, 0x28, 0x7d, 0x05, 0x72, 0x43
};
static const uint32_t T3_X25519_Y_LEN = sizeof(T3_X25519_Y);

/* Responder ephemeral public key (G_Y) — 32 bytes X25519 */
static const uint8_t T3_X25519_G_Y[] = {
	0xf5, 0xfb, 0x90, 0x57, 0xb2, 0x96, 0xe9, 0x56,
	0x9b, 0xd3, 0x95, 0x55, 0x79, 0x87, 0x15, 0x6e,
	0xea, 0x0f, 0x9b, 0x1d, 0x57, 0x0c, 0xc7, 0xa3,
	0x6a, 0xcf, 0x64, 0xd2, 0x2b, 0x91, 0xe9, 0x17
};
static const uint32_t T3_X25519_G_Y_LEN = sizeof(T3_X25519_G_Y);

/*
 * ---- Static DH X25519 Keys (untuk autentikasi Classic DH + MAC) ----
 *
 * Ini adalah "Classic Algorithm" = X25519 Static Diffie-Hellman.
 * Autentikasi BUKAN menggunakan signature — melainkan ECDH static DH + MAC.
 *
 * Initiator: (i, G_I) — static DH key pair
 *   - Responder menghitung G_I × y → PRK_4e3m → verifikasi MAC_3
 * Responder: (r, G_R) — static DH key pair
 *   - Initiator menghitung G_R × x → PRK_3e2m → verifikasi MAC_2
 */

/* Initiator static DH private key (i) — 32 bytes X25519 */
static const uint8_t T3_X25519_I[] = {
	0x88, 0x51, 0x6a, 0x89, 0xe8, 0x05, 0xe6, 0x9f,
	0x2d, 0x76, 0x41, 0xae, 0x9b, 0x5f, 0x07, 0x3b,
	0x04, 0xdd, 0x87, 0x2b, 0x4d, 0xb0, 0xb6, 0xc4,
	0x37, 0xeb, 0x4b, 0xdd, 0x34, 0x16, 0x78, 0x52
};
static const uint32_t T3_X25519_I_LEN = sizeof(T3_X25519_I);

/* Initiator static DH public key (G_I) — 32 bytes X25519 */
static const uint8_t T3_X25519_G_I[] = {
	0xb7, 0x32, 0xf7, 0x7f, 0x8f, 0x5b, 0x47, 0x32,
	0xd2, 0x78, 0x78, 0x67, 0xa0, 0x37, 0x02, 0x7e,
	0xbc, 0xb6, 0xc9, 0xc4, 0x6e, 0x1d, 0x90, 0xb9,
	0x10, 0x41, 0x6d, 0x79, 0x2c, 0x06, 0x51, 0x02
};
static const uint32_t T3_X25519_G_I_LEN = sizeof(T3_X25519_G_I);

/* Responder static DH private key (r) — 32 bytes X25519 */
static const uint8_t T3_X25519_R[] = {
	0x98, 0x59, 0x6c, 0xf7, 0x4b, 0x89, 0x39, 0x9f,
	0x8f, 0xbc, 0xb0, 0x89, 0xbe, 0xd9, 0x18, 0x85,
	0x0e, 0xad, 0x40, 0x21, 0xf1, 0x89, 0x34, 0x9f,
	0xa8, 0x22, 0xfb, 0x24, 0x7f, 0x68, 0xfc, 0x62
};
static const uint32_t T3_X25519_R_LEN = sizeof(T3_X25519_R);

/* Responder static DH public key (G_R) — 32 bytes X25519 */
static const uint8_t T3_X25519_G_R[] = {
	0xd8, 0xfe, 0x21, 0x2a, 0x55, 0xab, 0x33, 0x9a,
	0x46, 0x16, 0x06, 0xa2, 0x1c, 0xbb, 0x8e, 0xc3,
	0x17, 0x9d, 0xf8, 0x58, 0xc9, 0x20, 0xef, 0x42,
	0x23, 0xc1, 0xd3, 0xf0, 0x42, 0xae, 0xcd, 0x02
};
static const uint32_t T3_X25519_G_R_LEN = sizeof(T3_X25519_G_R);

/*
 * ---- Credentials ----
 *
 * Credentials diambil dari RFC 9529 test vectors. Pada Method 3 (MAC-MAC),
 * library tidak mengekstrak kunci dari dalam sertifikat X.509 untuk DH —
 * library menggunakan field .g dari struct other_party_cred yang kita set
 * secara eksplisit dengan X25519 static DH public key di atas.
 *
 * ID_CRED_I / ID_CRED_R: digunakan untuk lookup credential
 * CRED_I / CRED_R: opaque credential (X.509 cert, berisi info identitas)
 */

/* Reuse RFC 9529 credentials — defined in edhoc_test_vectors_rfc9529.c */

#endif /* EDHOC_TYPE3_X25519_TESTVEC_H */
