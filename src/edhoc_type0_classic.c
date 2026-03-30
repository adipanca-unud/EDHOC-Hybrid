/*
 * =============================================================================
 * EDHOC-Hybrid: Type 0 Signature-Signature (Classic) Implementation
 * =============================================================================
 *
 * RFC 9528 - EDHOC Method 0: Initiator Signature Key, Responder Signature Key
 * Cipher Suite 0: AES-CCM-16-64-128, SHA-256, 8, X25519, EdDSA
 * Test Vectors: RFC 9529 (Test 1, Method 0, Suite 0)
 *
 * ---- Classic Algorithm: EdDSA Signature + Verify ----
 *
 *   Pada Type 0 (Signature-Signature), kedua pihak (Initiator dan Responder)
 *   menggunakan TANDA TANGAN DIGITAL (Digital Signature) sebagai mekanisme
 *   autentikasi klasik. Algoritma yang dipakai:
 *
 *     - Ephemeral Key Exchange : X25519 (Curve25519 ECDH)
 *     - Authentication         : EdDSA (Ed25519 Signature + Verify)
 *     - Hash                   : SHA-256
 *     - AEAD Encryption        : AES-CCM-16-64-128
 *
 *   Alur autentikasi:
 *     1. Initiator MENANDATANGANI (Sign) data menggunakan private key EdDSA (SK_I)
 *        → menghasilkan Signature_or_MAC_3 yang dikirim dalam message_3
 *     2. Responder MEMVERIFIKASI (Verify) tanda tangan tersebut menggunakan
 *        public key EdDSA Initiator (PK_I)
 *     3. Responder MENANDATANGANI (Sign) data menggunakan private key EdDSA (SK_R)
 *        → menghasilkan Signature_or_MAC_2 yang dikirim dalam message_2
 *     4. Initiator MEMVERIFIKASI (Verify) tanda tangan tersebut menggunakan
 *        public key EdDSA Responder (PK_R)
 *
 * ---- Alur Komunikasi EDHOC (3-Message Handshake) ----
 *
 *   Initiator dan Responder berkomunikasi melalui 3 pesan EDHOC:
 *
 *     Initiator (Thread 1)                    Responder (Thread 2)
 *          |                                        |
 *          |  ──── message_1 ────────────────────>  |
 *          |       (METHOD, SUITES_I, G_X, C_I)     |
 *          |       Initiator mengirim method=0,      |
 *          |       ephemeral public key G_X (X25519),|
 *          |       dan connection identifier C_I     |
 *          |                                        |
 *          |  <──── message_2 ────────────────────  |
 *          |       (G_Y, CIPHERTEXT_2)              |
 *          |       Responder mengirim ephemeral      |
 *          |       public key G_Y (X25519), dan      |
 *          |       CIPHERTEXT_2 yang berisi:         |
 *          |         - C_R (connection id responder) |
 *          |         - ID_CRED_R (credential id)     |
 *          |         - Signature_or_MAC_2 (EdDSA     |
 *          |           SIGNATURE dari Responder)     |
 *          |       Initiator MEMVERIFIKASI signature |
 *          |       Responder menggunakan PK_R        |
 *          |                                        |
 *          |  ──── message_3 ────────────────────>  |
 *          |       (CIPHERTEXT_3)                   |
 *          |       Initiator mengirim CIPHERTEXT_3   |
 *          |       yang berisi:                      |
 *          |         - ID_CRED_I (credential id)     |
 *          |         - Signature_or_MAC_3 (EdDSA     |
 *          |           SIGNATURE dari Initiator)     |
 *          |       Responder MEMVERIFIKASI signature |
 *          |       Initiator menggunakan PK_I        |
 *          |                                        |
 *          |  Kedua pihak menurunkan PRK_out         |
 *          |  → prk_exporter → OSCORE Master Secret  |
 *          |    + OSCORE Master Salt                 |
 *
 *   Catatan:
 *   - Ephemeral DH (X25519) digunakan untuk key agreement (forward secrecy)
 *   - EdDSA digunakan untuk Sign + Verify (autentikasi klasik)
 *   - sk_i / sk_r = private signing key (EdDSA)
 *   - pk_i / pk_r = public verification key (EdDSA)
 *   - g_i / g_r   = TIDAK digunakan pada Method 0 (hanya untuk static DH)
 *
 * =============================================================================
 */

#include <pthread.h>
#include "edhoc_common.h"
#include "edhoc_type0_classic.h"
#include "edhoc_test_vectors_rfc9529.h"

/* ===== Thread argument structure ===== */
struct thread_result {
	enum err error;
	uint8_t prk_out_buf[32];
	struct byte_array prk_out;
};

/* ===== Initiator Thread =====
 *
 * Thread ini menjalankan sisi Initiator dari protokol EDHOC.
 * Initiator memulai handshake dengan mengirim message_1,
 * menerima message_2 (berisi signature Responder, lalu MEMVERIFIKASI),
 * dan mengirim message_3 (berisi signature Initiator yang di-SIGN dengan SK_I).
 *
 * Alur pemanggilan internal oleh edhoc_initiator_run():
 *   1. tx_initiator(message_1) → kirim METHOD=0, SUITES_I, G_X, C_I
 *   2. rx_initiator(message_2) → terima G_Y, CIPHERTEXT_2 dari Responder
 *      - Decrypt CIPHERTEXT_2 → dapatkan ID_CRED_R + Signature_or_MAC_2
 *      - VERIFY Signature_or_MAC_2 menggunakan PK_R (EdDSA Verify)
 *   3. tx_initiator(message_3) → kirim CIPHERTEXT_3
 *      - SIGN data menggunakan SK_I (EdDSA Sign) → Signature_or_MAC_3
 *      - Encrypt → CIPHERTEXT_3
 *   4. Output: PRK_out (shared secret key)
 */
static void *thread_initiator(void *arg)
{
	struct thread_result *res = (struct thread_result *)arg;
	res->prk_out.ptr = res->prk_out_buf;
	res->prk_out.len = sizeof(res->prk_out_buf);

	uint8_t err_msg_buf[64];
	struct byte_array err_msg = {
		.ptr = err_msg_buf,
		.len = sizeof(err_msg_buf)
	};

	/* ---- Configure Initiator context ----
	 * Initiator menggunakan:
	 *   - method = 0 (Signature-Signature): kedua pihak Sign+Verify
	 *   - Suite 0: X25519 (ephemeral DH) + EdDSA (signature)
	 */
	struct edhoc_initiator_context c_i;
	memset(&c_i, 0, sizeof(c_i));

	c_i.sock = NULL;
	c_i.method = (enum method_type)T1_RFC9529__METHOD;  /* Method 0: Sig-Sig */

	/* C_I: Connection Identifier Initiator (dikirim dalam message_1) */
	c_i.c_i.len = T1_RFC9529__C_I_LEN;
	c_i.c_i.ptr = (uint8_t *)T1_RFC9529__C_I;

	/* SUITES_I: Cipher suites yang didukung Initiator (dikirim dalam message_1) */
	c_i.suites_i.len = T1_RFC9529__SUITES_I_LEN;
	c_i.suites_i.ptr = (uint8_t *)T1_RFC9529__SUITES_I;

	/* EAD (External Authorization Data) - tidak digunakan */
	c_i.ead_1.len = 0;
	c_i.ead_1.ptr = NULL;
	c_i.ead_3.len = 0;
	c_i.ead_3.ptr = NULL;

	/* ID_CRED_I & CRED_I: Credential Initiator (dikirim dalam message_3) */
	c_i.id_cred_i.len = T1_RFC9529__ID_CRED_I_LEN;
	c_i.id_cred_i.ptr = (uint8_t *)T1_RFC9529__ID_CRED_I;

	c_i.cred_i.len = T1_RFC9529__CRED_I_LEN;
	c_i.cred_i.ptr = (uint8_t *)T1_RFC9529__CRED_I;

	/*
	 * Ephemeral DH keys (X25519) — digunakan untuk key agreement
	 *   G_X = public ephemeral key Initiator (dikirim dalam message_1)
	 *   x   = private ephemeral key Initiator
	 * X25519 ECDH menghasilkan shared secret untuk menurunkan session keys
	 */
	c_i.g_x.len = T1_RFC9529__G_X_LEN;
	c_i.g_x.ptr = (uint8_t *)T1_RFC9529__G_X;
	c_i.x.len = T1_RFC9529__X_LEN;
	c_i.x.ptr = (uint8_t *)T1_RFC9529__X;

	/*
	 * EdDSA Signature Keys — digunakan untuk SIGN (autentikasi klasik)
	 *   SK_I = private signing key → untuk membuat Signature_or_MAC_3
	 *   PK_I = public verification key → diberikan ke Responder untuk Verify
	 *
	 * Method 0: Menggunakan signature keys, BUKAN static DH keys.
	 *   g_i = NULL (static DH public key - tidak dipakai pada Method 0)
	 *   i   = NULL (static DH private key - tidak dipakai pada Method 0)
	 */
	c_i.sk_i.len = T1_RFC9529__SK_I_LEN;
	c_i.sk_i.ptr = (uint8_t *)T1_RFC9529__SK_I;
	c_i.pk_i.len = T1_RFC9529__PK_I_LEN;
	c_i.pk_i.ptr = (uint8_t *)T1_RFC9529__PK_I;
	c_i.g_i.len = 0;   /* Tidak dipakai: Method 0 bukan static DH */
	c_i.g_i.ptr = NULL;
	c_i.i.len = 0;     /* Tidak dipakai: Method 0 bukan static DH */
	c_i.i.ptr = NULL;

	/*
	 * ---- Responder credential (trust anchor untuk Initiator) ----
	 * Initiator perlu mengetahui public key Responder (PK_R) agar bisa
	 * MEMVERIFIKASI signature dalam message_2.
	 *
	 *   pk  = PK_R: public verification key EdDSA Responder
	 *   g   = NULL: tidak dipakai (g hanya untuk static DH, Method 3)
	 *   ca  = NULL: CA certificate (tidak digunakan pada test vector ini)
	 */
	struct other_party_cred cred_r;
	memset(&cred_r, 0, sizeof(cred_r));

	cred_r.id_cred.len = T1_RFC9529__ID_CRED_R_LEN;
	cred_r.id_cred.ptr = (uint8_t *)T1_RFC9529__ID_CRED_R;
	cred_r.cred.len = T1_RFC9529__CRED_R_LEN;
	cred_r.cred.ptr = (uint8_t *)T1_RFC9529__CRED_R;
	cred_r.pk.len = T1_RFC9529__PK_R_LEN;
	cred_r.pk.ptr = (uint8_t *)T1_RFC9529__PK_R;
	cred_r.g.len = 0;
	cred_r.g.ptr = NULL;
	cred_r.ca.len = 0;
	cred_r.ca.ptr = NULL;
	cred_r.ca_pk.len = 0;
	cred_r.ca_pk.ptr = NULL;

	struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r };

	print_info("Initiator: Starting EDHOC exchange...");

	/*
	 * ---- Run Initiator (3-message handshake) ----
	 *
	 * edhoc_initiator_run() menjalankan seluruh protokol EDHOC sisi Initiator:
	 *   1. Membentuk & mengirim message_1 via tx_initiator()
	 *      → message_1 = (METHOD=0, SUITES_I, G_X, C_I)
	 *   2. Menerima message_2 via rx_initiator()
	 *      → message_2 = (G_Y, CIPHERTEXT_2) dari Responder
	 *      → Decrypt CIPHERTEXT_2, lalu VERIFY signature Responder (EdDSA)
	 *   3. Membentuk & mengirim message_3 via tx_initiator()
	 *      → SIGN menggunakan SK_I (EdDSA) → Signature_or_MAC_3
	 *      → message_3 = (CIPHERTEXT_3)
	 *   4. Menurunkan PRK_out sebagai output akhir
	 */
	res->error = edhoc_initiator_run(&c_i, &cred_r_array, &err_msg,
					 &res->prk_out,
					 tx_initiator, rx_initiator,
					 ead_process);

	if (res->error != ok) {
		char buf[128];
		snprintf(buf, sizeof(buf),
			 "Initiator: EDHOC failed with error code %d",
			 res->error);
		print_error(buf);
	} else {
		print_success("Initiator: EDHOC exchange completed successfully!");
	}

	return NULL;
}

/* ===== Responder Thread =====
 *
 * Thread ini menjalankan sisi Responder dari protokol EDHOC.
 * Responder menunggu message_1 dari Initiator,
 * lalu mengirim message_2 (berisi signature Responder yang di-SIGN dengan SK_R),
 * dan menerima message_3 (berisi signature Initiator, lalu MEMVERIFIKASI).
 *
 * Alur pemanggilan internal oleh edhoc_responder_run():
 *   1. rx_responder(message_1) → terima METHOD=0, SUITES_I, G_X, C_I
 *   2. tx_responder(message_2) → kirim G_Y, CIPHERTEXT_2
 *      - SIGN data menggunakan SK_R (EdDSA Sign) → Signature_or_MAC_2
 *      - Encrypt → CIPHERTEXT_2
 *   3. rx_responder(message_3) → terima CIPHERTEXT_3 dari Initiator
 *      - Decrypt CIPHERTEXT_3 → dapatkan ID_CRED_I + Signature_or_MAC_3
 *      - VERIFY Signature_or_MAC_3 menggunakan PK_I (EdDSA Verify)
 *   4. Output: PRK_out (shared secret key)
 */
static void *thread_responder(void *arg)
{
	struct thread_result *res = (struct thread_result *)arg;
	res->prk_out.ptr = res->prk_out_buf;
	res->prk_out.len = sizeof(res->prk_out_buf);

	uint8_t err_msg_buf[64];
	struct byte_array err_msg = {
		.ptr = err_msg_buf,
		.len = sizeof(err_msg_buf)
	};

	/* ---- Configure Responder context ----
	 * Responder menggunakan:
	 *   - Suite 0: X25519 (ephemeral DH) + EdDSA (signature)
	 *   - Method 0 (ditentukan oleh Initiator via message_1)
	 */
	struct edhoc_responder_context c_r;
	memset(&c_r, 0, sizeof(c_r));

	c_r.sock = NULL;

	/* C_R: Connection Identifier Responder (dikirim dalam message_2) */
	c_r.c_r.len = T1_RFC9529__C_R_LEN;
	c_r.c_r.ptr = (uint8_t *)T1_RFC9529__C_R;

	/* SUITES_R: Cipher suites yang didukung Responder */
	c_r.suites_r.len = T1_RFC9529__SUITES_R_LEN;
	c_r.suites_r.ptr = (uint8_t *)T1_RFC9529__SUITES_R;

	/* EAD (External Authorization Data) - tidak digunakan */
	c_r.ead_2.len = 0;
	c_r.ead_2.ptr = NULL;
	c_r.ead_4.len = 0;
	c_r.ead_4.ptr = NULL;

	/* ID_CRED_R & CRED_R: Credential Responder (dikirim dalam message_2) */
	c_r.id_cred_r.len = T1_RFC9529__ID_CRED_R_LEN;
	c_r.id_cred_r.ptr = (uint8_t *)T1_RFC9529__ID_CRED_R;

	c_r.cred_r.len = T1_RFC9529__CRED_R_LEN;
	c_r.cred_r.ptr = (uint8_t *)T1_RFC9529__CRED_R;

	/*
	 * Ephemeral DH keys (X25519) — digunakan untuk key agreement
	 *   G_Y = public ephemeral key Responder (dikirim dalam message_2)
	 *   y   = private ephemeral key Responder
	 */
	c_r.g_y.len = T1_RFC9529__G_Y_LEN;
	c_r.g_y.ptr = (uint8_t *)T1_RFC9529__G_Y;
	c_r.y.len = T1_RFC9529__Y_LEN;
	c_r.y.ptr = (uint8_t *)T1_RFC9529__Y;

	/*
	 * EdDSA Signature Keys — digunakan untuk SIGN (autentikasi klasik)
	 *   SK_R = private signing key → untuk membuat Signature_or_MAC_2
	 *   PK_R = public verification key → diberikan ke Initiator untuk Verify
	 *
	 * Method 0: Menggunakan signature keys, BUKAN static DH keys.
	 *   g_r = NULL (static DH public key - tidak dipakai pada Method 0)
	 *   r   = NULL (static DH private key - tidak dipakai pada Method 0)
	 */
	c_r.sk_r.len = T1_RFC9529__SK_R_LEN;
	c_r.sk_r.ptr = (uint8_t *)T1_RFC9529__SK_R;
	c_r.pk_r.len = T1_RFC9529__PK_R_LEN;
	c_r.pk_r.ptr = (uint8_t *)T1_RFC9529__PK_R;
	c_r.g_r.len = 0;   /* Tidak dipakai: Method 0 bukan static DH */
	c_r.g_r.ptr = NULL;
	c_r.r.len = 0;     /* Tidak dipakai: Method 0 bukan static DH */
	c_r.r.ptr = NULL;

	/*
	 * ---- Initiator credential (trust anchor untuk Responder) ----
	 * Responder perlu mengetahui public key Initiator (PK_I) agar bisa
	 * MEMVERIFIKASI signature dalam message_3.
	 *
	 *   pk  = PK_I: public verification key EdDSA Initiator
	 *   g   = NULL: tidak dipakai (g hanya untuk static DH, Method 3)
	 */
	struct other_party_cred cred_i;
	memset(&cred_i, 0, sizeof(cred_i));

	cred_i.id_cred.len = T1_RFC9529__ID_CRED_I_LEN;
	cred_i.id_cred.ptr = (uint8_t *)T1_RFC9529__ID_CRED_I;
	cred_i.cred.len = T1_RFC9529__CRED_I_LEN;
	cred_i.cred.ptr = (uint8_t *)T1_RFC9529__CRED_I;
	cred_i.pk.len = T1_RFC9529__PK_I_LEN;
	cred_i.pk.ptr = (uint8_t *)T1_RFC9529__PK_I;
	cred_i.g.len = 0;
	cred_i.g.ptr = NULL;
	cred_i.ca.len = 0;
	cred_i.ca.ptr = NULL;
	cred_i.ca_pk.len = 0;
	cred_i.ca_pk.ptr = NULL;

	struct cred_array cred_i_array = { .len = 1, .ptr = &cred_i };

	print_info("Responder: Waiting for EDHOC exchange...");

	/*
	 * ---- Run Responder (3-message handshake) ----
	 *
	 * edhoc_responder_run() menjalankan seluruh protokol EDHOC sisi Responder:
	 *   1. Menerima message_1 via rx_responder()
	 *      → message_1 = (METHOD=0, SUITES_I, G_X, C_I) dari Initiator
	 *   2. Membentuk & mengirim message_2 via tx_responder()
	 *      → SIGN menggunakan SK_R (EdDSA) → Signature_or_MAC_2
	 *      → message_2 = (G_Y, CIPHERTEXT_2)
	 *   3. Menerima message_3 via rx_responder()
	 *      → message_3 = (CIPHERTEXT_3) dari Initiator
	 *      → Decrypt CIPHERTEXT_3, lalu VERIFY signature Initiator (EdDSA)
	 *   4. Menurunkan PRK_out sebagai output akhir
	 */
	res->error = edhoc_responder_run(&c_r, &cred_i_array, &err_msg,
					 &res->prk_out,
					 tx_responder, rx_responder,
					 ead_process);

	if (res->error != ok) {
		char buf[128];
		snprintf(buf, sizeof(buf),
			 "Responder: EDHOC failed with error code %d",
			 res->error);
		print_error(buf);
	} else {
		print_success("Responder: EDHOC exchange completed successfully!");
	}

	return NULL;
}

/* ===== Main entry point for Type 0 =====
 *
 * Menjalankan EDHOC Type 0 (Signature-Signature Classic):
 *   - Membuat 2 thread: Initiator dan Responder
 *   - Initiator dan Responder berkomunikasi melalui message_1, message_2, message_3
 *   - Autentikasi menggunakan EdDSA Signature + Verify (algoritma klasik)
 *   - Setelah handshake selesai, memverifikasi PRK_out kedua pihak cocok
 *   - Menurunkan OSCORE Master Secret + Salt dari PRK_out
 */
int run_edhoc_type0_classic(void)
{
	print_header("EDHOC Type 0: Signature-Signature (Classic)");
	printf("\n");
	print_info("RFC 9528 - Method 0: Initiator Sig Key, Responder Sig Key");
	print_info("Cipher Suite 0: AES-CCM-16-64-128, SHA-256, 8, X25519, EdDSA");
	print_info("Classic Algorithm: EdDSA Signature + Verify (Sign & Verify)");
	print_info("Test vectors: RFC 9529");
	printf("\n");

	/* Initialize message exchange */
	msg_exchange_init();

	/* Thread results */
	struct thread_result initiator_res, responder_res;
	memset(&initiator_res, 0, sizeof(initiator_res));
	memset(&responder_res, 0, sizeof(responder_res));

	/* Create threads */
	pthread_t tid_initiator, tid_responder;

	print_info("Creating Initiator and Responder threads...");
	printf("\n");

	int rc;
	rc = pthread_create(&tid_responder, NULL, thread_responder,
			    &responder_res);
	if (rc != 0) {
		print_error("Failed to create Responder thread");
		msg_exchange_destroy();
		return -1;
	}

	rc = pthread_create(&tid_initiator, NULL, thread_initiator,
			    &initiator_res);
	if (rc != 0) {
		print_error("Failed to create Initiator thread");
		msg_exchange_destroy();
		return -1;
	}

	/* Wait for both threads to complete */
	pthread_join(tid_initiator, NULL);
	pthread_join(tid_responder, NULL);

	msg_exchange_destroy();

	/* ---- Verify results ---- */
	printf("\n");
	print_header("EDHOC Type 0 - Results");
	printf("\n");

	if (initiator_res.error != ok || responder_res.error != ok) {
		print_error("EDHOC exchange failed!");
		return -1;
	}

	/* Display PRK_out */
	print_hex("Initiator PRK_out", initiator_res.prk_out.ptr,
		  initiator_res.prk_out.len);
	print_hex("Responder PRK_out", responder_res.prk_out.ptr,
		  responder_res.prk_out.len);

	/* Verify both sides computed the same PRK_out */
	if (memcmp(initiator_res.prk_out.ptr, responder_res.prk_out.ptr,
		   initiator_res.prk_out.len) == 0) {
		print_success("PRK_out MATCH: Initiator and Responder agree!");
	} else {
		print_error("PRK_out MISMATCH: Initiator and Responder disagree!");
		return -1;
	}

	/* Verify against expected test vector value */
	if (memcmp(initiator_res.prk_out.ptr, T1_RFC9529__PRK_out,
		   initiator_res.prk_out.len) == 0) {
		print_success("PRK_out matches RFC 9529 test vector!");
	} else {
		print_error("PRK_out does NOT match RFC 9529 test vector!");
		return -1;
	}

	/* Derive OSCORE keys */
	printf("\n");
	print_info("Deriving OSCORE keys (Initiator side)...");
	int ret = derive_oscore_keys("Initiator", &initiator_res.prk_out);
	if (ret != 0) {
		print_error("Failed to derive OSCORE keys for Initiator");
		return -1;
	}

	printf("\n");
	print_info("Deriving OSCORE keys (Responder side)...");
	ret = derive_oscore_keys("Responder", &responder_res.prk_out);
	if (ret != 0) {
		print_error("Failed to derive OSCORE keys for Responder");
		return -1;
	}

	printf("\n");
	print_success("EDHOC Type 0 (Signature-Signature Classic) completed successfully!");
	printf("\n");

	return 0;
}
