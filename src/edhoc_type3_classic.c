/*
 * =============================================================================
 * EDHOC-Hybrid: Type 3 MAC-MAC (Classic) Implementation
 * =============================================================================
 *
 * RFC 9528 - EDHOC Method 3: Initiator Static DH Key, Responder Static DH Key
 * Cipher Suite 0: AES-CCM-16-64-128, SHA-256, 8, X25519, EdDSA
 *
 * ---- Classic Algorithm: X25519 Static Diffie-Hellman + MAC ----
 *
 *   Pada Type 3 (MAC-MAC), kedua pihak (Initiator dan Responder)
 *   menggunakan X25519 STATIC DIFFIE-HELLMAN KEY EXCHANGE + MAC sebagai
 *   mekanisme autentikasi klasik. TIDAK ada tanda tangan digital (signature).
 *   Algoritma yang dipakai:
 *
 *     - Ephemeral Key Exchange : X25519 (Curve25519 ECDH, forward secrecy)
 *     - Authentication         : X25519 Static DH + MAC (HMAC-based)
 *                                (Classic Diffie-Hellman key exchange
 *                                 menggunakan kurva Curve25519)
 *     - Hash                   : SHA-256
 *     - AEAD Encryption        : AES-CCM-16-64-128
 *
 *   Perbedaan utama dengan Type 0 (Signature):
 *
 *   ┌──────────────────┬─────────────────────────┬──────────────────────────┐
 *   │                  │  Type 0 (Sig-Sig)       │  Type 3 (MAC-MAC)        │
 *   ├──────────────────┼─────────────────────────┼──────────────────────────┤
 *   │ Method           │  0 (Sig-Sig)            │  3 (MAC-MAC)             │
 *   │ Suite            │  0 (X25519 + EdDSA)     │  0 (X25519 + EdDSA)      │
 *   │ Autentikasi      │  Signature + Verify     │  X25519 Static DH + MAC  │
 *   │ Key autentikasi  │  SK (Sign) / PK (Verify)│  Static DH key pair      │
 *   │ Signature_or_MAC │  Signature (EdDSA)      │  MAC (HMAC dari X25519)  │
 *   │ Ephemeral DH     │  X25519                 │  X25519                  │
 *   │ g_i / g_r        │  NULL (tidak dipakai)   │  X25519 public DH key    │
 *   │ i / r            │  NULL (tidak dipakai)   │  X25519 private DH key   │
 *   │ sk_i / sk_r      │  EdDSA signing key      │  Tidak digunakan         │
 *   └──────────────────┴─────────────────────────┴──────────────────────────┘
 *
 *   Alur autentikasi (X25519 Static DH + MAC):
 *     1. Responder menghitung shared secret dari:
 *        - X25519 Static DH private key Responder (r) × Ephemeral public key (G_X)
 *        → menghasilkan PRK_3e2m yang digunakan untuk MAC_2
 *     2. Responder menghitung MAC_2 = HMAC(PRK_3e2m, context_2)
 *        → MAC_2 dikirim sebagai Signature_or_MAC_2 dalam message_2
 *     3. Initiator memverifikasi MAC_2 dengan menghitung ulang:
 *        - X25519 Static DH public key Responder (G_R) × Ephemeral private key (x)
 *        → harus menghasilkan MAC_2 yang sama
 *     4. Initiator menghitung MAC_3 dari:
 *        - X25519 Static DH private key Initiator (i) × Ephemeral public key (G_Y)
 *        → PRK_4e3m → MAC_3
 *     5. Responder memverifikasi MAC_3 dengan menghitung ulang
 *
 * ---- Alur Komunikasi EDHOC (3-Message Handshake) ----
 *
 *   Initiator dan Responder berkomunikasi melalui 3 pesan EDHOC:
 *
 *     Initiator (Thread 1)                    Responder (Thread 2)
 *          |                                        |
 *          |  ──── message_1 ────────────────────>  |
 *          |       (METHOD=3, SUITES_I=0, G_X, C_I) |
 *          |       Initiator mengirim method=3,      |
 *          |       ephemeral pubkey G_X (X25519),    |
 *          |       dan connection identifier C_I     |
 *          |                                        |
 *          |  <──── message_2 ────────────────────  |
 *          |       (G_Y, CIPHERTEXT_2)              |
 *          |       Responder mengirim ephemeral      |
 *          |       pubkey G_Y (X25519), dan          |
 *          |       CIPHERTEXT_2 yang berisi:         |
 *          |         - C_R (connection id responder) |
 *          |         - ID_CRED_R (credential id)     |
 *          |         - Signature_or_MAC_2 (MAC       |
 *          |           dari X25519 Static DH + HMAC) |
 *          |       Initiator MEMVERIFIKASI MAC_2     |
 *          |       dengan X25519: G_R × x            |
 *          |                                        |
 *          |  ──── message_3 ────────────────────>  |
 *          |       (CIPHERTEXT_3)                   |
 *          |       Initiator mengirim CIPHERTEXT_3   |
 *          |       yang berisi:                      |
 *          |         - ID_CRED_I (credential id)     |
 *          |         - Signature_or_MAC_3 (MAC       |
 *          |           dari X25519 Static DH + HMAC) |
 *          |       Responder MEMVERIFIKASI MAC_3     |
 *          |       dengan X25519: G_I × y            |
 *          |                                        |
 *          |  Kedua pihak menurunkan PRK_out         |
 *          |  → prk_exporter → OSCORE Master Secret  |
 *          |    + OSCORE Master Salt                 |
 *
 *   Catatan:
 *   - Ephemeral DH (X25519) untuk key agreement (forward secrecy)
 *   - Static DH (X25519) + MAC untuk autentikasi (classic algorithm)
 *   - g_i / g_r = X25519 static DH public key (untuk autentikasi)
 *   - i / r     = X25519 static DH private key (untuk autentikasi)
 *   - sk_i/sk_r = TIDAK digunakan pada Method 3 (hanya untuk signature)
 *
 * =============================================================================
 */

#include <pthread.h>
#include "edhoc_common.h"
#include "edhoc_type3_classic.h"

/*
 * Include X25519 test vectors for Method 3 (MAC-MAC) with Suite 0.
 * Kunci X25519 dibangkitkan secara acak, credentials diambil dari RFC 9529.
 */
#include "edhoc_type3_x25519_testvec.h"
#include "edhoc_test_vectors_rfc9529.h"

/* ===== Thread argument structure ===== */
struct thread_result {
	enum err error;
	uint8_t prk_out_buf[32];
	struct byte_array prk_out;
};

/* ===== Initiator Thread =====
 *
 * Thread ini menjalankan sisi Initiator dari protokol EDHOC Method 3.
 * Initiator memulai handshake dengan mengirim message_1,
 * menerima message_2 (berisi MAC_2 dari Responder, lalu MEMVERIFIKASI
 * dengan menghitung ulang X25519 static DH),
 * dan mengirim message_3 (berisi MAC_3 yang dihitung dari static DH Initiator).
 *
 * Alur pemanggilan internal oleh edhoc_initiator_run():
 *   1. tx_initiator(message_1) → kirim METHOD=3, SUITES_I=0, G_X, C_I
 *   2. rx_initiator(message_2) → terima G_Y, CIPHERTEXT_2 dari Responder
 *      - Decrypt CIPHERTEXT_2 → dapatkan ID_CRED_R + Signature_or_MAC_2
 *      - Hitung X25519: G_R (static DH pubkey Responder) × x (ephemeral privkey)
 *      - VERIFY: hitung ulang MAC_2 dan bandingkan (MAC verification)
 *   3. tx_initiator(message_3) → kirim CIPHERTEXT_3
 *      - Hitung X25519: i (static DH privkey) × G_Y (ephemeral pubkey Responder)
 *      - Hitung MAC_3 = HMAC(PRK_4e3m, context_3) → Signature_or_MAC_3
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
	 *   - method = 3 (MAC-MAC): kedua pihak X25519 Static DH + MAC
	 *   - Suite 0: X25519 (ephemeral + static DH) + EdDSA + SHA-256
	 */
	struct edhoc_initiator_context c_i;
	memset(&c_i, 0, sizeof(c_i));

	c_i.sock = NULL;
	c_i.method = (enum method_type)T3_X25519_METHOD;  /* Method 3: MAC-MAC */

	/* C_I: Connection Identifier Initiator (dikirim dalam message_1) */
	c_i.c_i.len = T3_X25519_C_I_LEN;
	c_i.c_i.ptr = (uint8_t *)T3_X25519_C_I;

	/* SUITES_I: Suite 0 = X25519 + EdDSA (dikirim dalam message_1) */
	c_i.suites_i.len = T3_X25519_SUITES_I_LEN;
	c_i.suites_i.ptr = (uint8_t *)T3_X25519_SUITES_I;

	/* EAD (External Authorization Data) - tidak digunakan */
	c_i.ead_1.len = 0;
	c_i.ead_1.ptr = NULL;
	c_i.ead_3.len = 0;
	c_i.ead_3.ptr = NULL;

	/* ID_CRED_I & CRED_I: Credential Initiator (dari RFC 9529, dikirim dalam message_3) */
	c_i.id_cred_i.len = T1_RFC9529__ID_CRED_I_LEN;
	c_i.id_cred_i.ptr = (uint8_t *)T1_RFC9529__ID_CRED_I;
	c_i.cred_i.len = T1_RFC9529__CRED_I_LEN;
	c_i.cred_i.ptr = (uint8_t *)T1_RFC9529__CRED_I;

	/*
	 * Ephemeral X25519 DH keys — digunakan untuk key agreement (forward secrecy)
	 *   G_X = public ephemeral key Initiator (dikirim dalam message_1)
	 *   x   = private ephemeral key Initiator
	 * X25519 ECDH: x × G_Y = y × G_X → shared secret
	 */
	c_i.g_x.len = T3_X25519_G_X_LEN;
	c_i.g_x.ptr = (uint8_t *)T3_X25519_G_X;
	c_i.x.len = T3_X25519_X_LEN;
	c_i.x.ptr = (uint8_t *)T3_X25519_X;

	/*
	 * Static X25519 DH keys — digunakan untuk autentikasi (classic algorithm)
	 *   G_I = X25519 public static DH key Initiator
	 *   i   = X25519 private static DH key Initiator → untuk menghitung MAC_3
	 *
	 * Method 3: Menggunakan X25519 static DH keys, BUKAN EdDSA signature keys.
	 * Ini adalah "Classic Algorithm" = X25519 Diffie-Hellman.
	 *
	 *   sk_i / pk_i = TIDAK digunakan pada Method 3
	 */
	c_i.g_i.len = T3_X25519_G_I_LEN;
	c_i.g_i.ptr = (uint8_t *)T3_X25519_G_I;
	c_i.i.len = T3_X25519_I_LEN;
	c_i.i.ptr = (uint8_t *)T3_X25519_I;
	c_i.sk_i.len = 0;
	c_i.sk_i.ptr = NULL;
	c_i.pk_i.len = 0;
	c_i.pk_i.ptr = NULL;

	/*
	 * ---- Responder credential (trust anchor untuk Initiator) ----
	 * Initiator perlu mengetahui X25519 static DH public key Responder (G_R)
	 * agar bisa MEMVERIFIKASI MAC_2 dalam message_2 (classic DH verification).
	 *
	 *   g  = G_R: X25519 public static DH key Responder (untuk ECDH + MAC verify)
	 *   pk = Tidak digunakan (pk hanya untuk Signature-based methods)
	 */
	struct other_party_cred cred_r;
	memset(&cred_r, 0, sizeof(cred_r));

	cred_r.id_cred.len = T1_RFC9529__ID_CRED_R_LEN;
	cred_r.id_cred.ptr = (uint8_t *)T1_RFC9529__ID_CRED_R;
	cred_r.cred.len = T1_RFC9529__CRED_R_LEN;
	cred_r.cred.ptr = (uint8_t *)T1_RFC9529__CRED_R;
	/* G_R: X25519 Static DH public key Responder — untuk MAC verification */
	cred_r.g.len = T3_X25519_G_R_LEN;
	cred_r.g.ptr = (uint8_t *)T3_X25519_G_R;
	cred_r.pk.len = 0;
	cred_r.pk.ptr = NULL;
	cred_r.ca.len = 0;
	cred_r.ca.ptr = NULL;
	cred_r.ca_pk.len = 0;
	cred_r.ca_pk.ptr = NULL;

	struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r };

	print_info("Initiator: Starting EDHOC exchange (MAC-MAC, X25519)...");

	/*
	 * ---- Run Initiator (3-message handshake) ----
	 *
	 * edhoc_initiator_run() menjalankan seluruh protokol EDHOC sisi Initiator:
	 *   1. Membentuk & mengirim message_1 via tx_initiator()
	 *      → message_1 = (METHOD=3, SUITES_I=0, G_X, C_I)
	 *   2. Menerima message_2 via rx_initiator()
	 *      → Decrypt CIPHERTEXT_2, lalu VERIFY MAC_2
	 *        menggunakan X25519: G_R × x → hitung ulang MAC dan bandingkan
	 *   3. Membentuk & mengirim message_3 via tx_initiator()
	 *      → Hitung MAC_3 dari X25519 Static DH: i × G_Y
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
 * Thread ini menjalankan sisi Responder dari protokol EDHOC Method 3.
 * Responder menunggu message_1 dari Initiator,
 * lalu mengirim message_2 (berisi MAC_2 dari X25519 static DH + HMAC),
 * dan menerima message_3 (berisi MAC_3 dari Initiator, lalu MEMVERIFIKASI
 * dengan menghitung ulang X25519 static DH).
 *
 * Alur pemanggilan internal oleh edhoc_responder_run():
 *   1. rx_responder(message_1) → terima METHOD=3, SUITES_I=0, G_X, C_I
 *   2. tx_responder(message_2) → kirim G_Y, CIPHERTEXT_2
 *      - Hitung X25519: r (static DH privkey) × G_X (ephemeral pubkey Initiator)
 *      - Hitung MAC_2 = HMAC(PRK_3e2m, context_2) → Signature_or_MAC_2
 *      - Encrypt → CIPHERTEXT_2
 *   3. rx_responder(message_3) → terima CIPHERTEXT_3 dari Initiator
 *      - Decrypt CIPHERTEXT_3 → dapatkan ID_CRED_I + Signature_or_MAC_3
 *      - Hitung X25519: G_I (static DH pubkey Initiator) × y (ephemeral privkey)
 *      - VERIFY: hitung ulang MAC_3 dan bandingkan (MAC verification)
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
	 * Konfigurasi konteks Responder untuk Method 3 (Static DH + MAC).
	 * Berbeda dengan Type 0 yang menggunakan signing key (EdDSA),
	 * di sini Responder menggunakan:
	 *   - Static X25519 DH key pair (r, G_R) untuk autentikasi via DH
	 *   - Ephemeral X25519 DH key pair (y, G_Y) untuk forward secrecy
	 * Responder TIDAK menandatangani apapun — hanya menghitung MAC
	 * dari shared secret yang dihasilkan oleh X25519 DH.
	 */
	struct edhoc_responder_context c_r;
	memset(&c_r, 0, sizeof(c_r));

	/* Socket: NULL karena kita menggunakan shared memory (msg_exchange) */
	c_r.sock = NULL;

	/* C_R: Connection identifier Responder (dikirim dalam message_2) */
	c_r.c_r.len = T3_X25519_C_R_LEN;
	c_r.c_r.ptr = (uint8_t *)T3_X25519_C_R;

	/* SUITES_R: Suite 0 = X25519 + EdDSA + AES-CCM-16-64-128 + SHA-256 */
	c_r.suites_r.len = T3_X25519_SUITES_R_LEN;
	c_r.suites_r.ptr = (uint8_t *)T3_X25519_SUITES_R;

	/* EAD (External Authorization Data) - tidak digunakan */
	c_r.ead_2.len = 0;
	c_r.ead_2.ptr = NULL;
	c_r.ead_4.len = 0;
	c_r.ead_4.ptr = NULL;

	/* ID_CRED_R & CRED_R: Credential Responder (dari RFC 9529) */
	c_r.id_cred_r.len = T1_RFC9529__ID_CRED_R_LEN;
	c_r.id_cred_r.ptr = (uint8_t *)T1_RFC9529__ID_CRED_R;
	c_r.cred_r.len = T1_RFC9529__CRED_R_LEN;
	c_r.cred_r.ptr = (uint8_t *)T1_RFC9529__CRED_R;

	/* Ephemeral X25519 DH key pair:
	 * - G_Y: public ephemeral key (dikirim ke Initiator dalam message_2)
	 * - y:   private ephemeral key (digunakan untuk X25519 DH)
	 * X25519 ephemeral: y × G_X → shared secret untuk derivasi kunci sesi */
	c_r.g_y.len = T3_X25519_G_Y_LEN;
	c_r.g_y.ptr = (uint8_t *)T3_X25519_G_Y;
	c_r.y.len = T3_X25519_Y_LEN;
	c_r.y.ptr = (uint8_t *)T3_X25519_Y;

	/* Static X25519 DH key pair — KUNCI UTAMA untuk autentikasi MAC:
	 * - G_R: public static DH key (diketahui oleh Initiator via credential)
	 * - r:   private static DH key (untuk menghitung X25519: r × G_X)
	 * Perhitungan X25519 static: r × G_X → PRK_3e2m → MAC_2
	 * Ini yang menggantikan Signature di Type 0
	 *
	 *   sk_r / pk_r = TIDAK digunakan pada Method 3 */
	c_r.g_r.len = T3_X25519_G_R_LEN;
	c_r.g_r.ptr = (uint8_t *)T3_X25519_G_R;
	c_r.r.len = T3_X25519_R_LEN;
	c_r.r.ptr = (uint8_t *)T3_X25519_R;
	c_r.sk_r.len = 0;
	c_r.sk_r.ptr = NULL;
	c_r.pk_r.len = 0;
	c_r.pk_r.ptr = NULL;

	/* ---- Initiator credential (trust anchor untuk Responder) ----
	 * Responder perlu mengetahui credential Initiator agar dapat:
	 *   1. Memverifikasi identitas Initiator dari ID_CRED_I di message_3
	 *   2. Mendapatkan G_I (X25519 static DH public key Initiator)
	 *   3. Menghitung X25519: G_I × y → PRK_4e3m → verifikasi MAC_3
	 *
	 * Perbedaan dengan Type 0:
	 *   - Type 0: cred_i.pk = EdDSA public key → untuk VERIFY signature
	 *   - Type 3: cred_i.g  = X25519 static DH pubkey → untuk DH → MAC verify
	 */
	struct other_party_cred cred_i;
	memset(&cred_i, 0, sizeof(cred_i));

	/* ID_CRED_I: identifier credential Initiator (untuk lookup) */
	cred_i.id_cred.len = T1_RFC9529__ID_CRED_I_LEN;
	cred_i.id_cred.ptr = (uint8_t *)T1_RFC9529__ID_CRED_I;
	/* CRED_I: credential lengkap Initiator (CBOR dari RFC 9529) */
	cred_i.cred.len = T1_RFC9529__CRED_I_LEN;
	cred_i.cred.ptr = (uint8_t *)T1_RFC9529__CRED_I;
	/* G_I: X25519 Static DH public key Initiator
	 * Digunakan oleh Responder untuk X25519: G_I × y → shared secret
	 * Ini adalah "classic algorithm" — autentikasi via DH, bukan signature */
	cred_i.g.len = T3_X25519_G_I_LEN;
	cred_i.g.ptr = (uint8_t *)T3_X25519_G_I;
	cred_i.pk.len = 0;
	cred_i.pk.ptr = NULL;
	cred_i.ca.len = 0;
	cred_i.ca.ptr = NULL;
	cred_i.ca_pk.len = 0;
	cred_i.ca_pk.ptr = NULL;

	struct cred_array cred_i_array = { .len = 1, .ptr = &cred_i };

	print_info("Responder: Waiting for EDHOC exchange (MAC-MAC, X25519)...");

	/* ---- Run Responder ----
	 * Menjalankan state machine Responder untuk handshake 3-message:
	 *
	 * Step 1: rx_responder(message_1)
	 *   - Terima METHOD=3, SUITES_I=0, G_X, C_I dari Initiator
	 *   - Validasi suite yang dipilih Initiator
	 *
	 * Step 2: tx_responder(message_2)
	 *   - Hitung X25519 ephemeral: y × G_X → shared secret
	 *   - Hitung X25519 static DH: r × G_X → PRK_3e2m
	 *   - Hitung MAC_2 = HMAC(PRK_3e2m, context_2)
	 *     (BUKAN signature — ini perbedaan utama dengan Type 0!)
	 *   - Encrypt: AEAD(K_2, IV_2, ID_CRED_R || MAC_2) → CIPHERTEXT_2
	 *   - Kirim message_2 = (G_Y, C_R, CIPHERTEXT_2)
	 *
	 * Step 3: rx_responder(message_3)
	 *   - Terima CIPHERTEXT_3 dari Initiator
	 *   - Decrypt → dapatkan ID_CRED_I + Signature_or_MAC_3
	 *   - Lookup credential Initiator dari cred_i_array
	 *   - Hitung X25519: G_I × y → PRK_4e3m
	 *   - VERIFY MAC_3: hitung ulang MAC_3 dan bandingkan
	 *     (autentikasi Initiator berhasil jika MAC cocok)
	 *   - Derive PRK_out = HKDF(PRK_4e3m, ...)
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

/* ===== Main entry point for Type 3 (MAC-MAC Classic) =====
 *
 * Fungsi utama yang menjalankan simulasi lengkap protokol EDHOC Method 3.
 * Membuat 2 thread: Initiator dan Responder yang berkomunikasi via
 * shared memory (msg_exchange) melalui 3 pesan:
 *
 *   message_1: Initiator → Responder  (METHOD, SUITES_I, G_X, C_I)
 *   message_2: Responder → Initiator  (G_Y, C_R, CIPHERTEXT_2 berisi MAC_2)
 *   message_3: Initiator → Responder  (CIPHERTEXT_3 berisi MAC_3)
 *
 * Autentikasi: X25519 Static DH + MAC (bukan Signature+Verify seperti Type 0)
 * Classic algorithm: X25519 untuk ephemeral DH dan static DH
 * Hasil: PRK_out (shared secret) → diturunkan menjadi OSCORE keys
 */
int run_edhoc_type3_classic(void)
{
	print_header("EDHOC Type 3: MAC-MAC (Classic)");
	printf("\n");
	print_info("RFC 9528 - Method 3: Initiator Static DH Key, Responder Static DH Key");
	print_info("Cipher Suite 0: AES-CCM-16-64-128, SHA-256, 8, X25519, EdDSA");
	print_info("Classic Algorithm: X25519 Diffie-Hellman (Ephemeral + Static DH)");
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
	print_header("EDHOC Type 3 - Results");
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
	print_success("EDHOC Type 3 (MAC-MAC Classic) completed successfully!");
	printf("\n");

	return 0;
}
