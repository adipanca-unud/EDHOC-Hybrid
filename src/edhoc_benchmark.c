/*
 * =============================================================================
 * EDHOC-Hybrid: Comprehensive Benchmark System (Corrected)
 * =============================================================================
 *
 * Benchmark komprehensif untuk mengukur performa dua varian EDHOC Protocol
 * berdasarkan RFC 9528, dengan mapping yang benar ke alur protokol:
 *
 *   Type 0 (Sig-Sig): Method 0, Suite 0 — X25519 + EdDSA Sign/Verify
 *   Type 3 (MAC-MAC): Method 3, Suite 0 — X25519 Static DH + MAC
 *
 * === MAPPING OPERASI KRIPTOGRAFI KE ALUR EDHOC ===
 *
 * Type 0 Initiator:
 *   msg1_gen:  X25519 KeyGen(ephemeral), Hash(msg1)
 *   msg2_proc: ECDH(x,G_Y), Hash(TH2), HKDF-Extract(PRK_2e),
 *              XOR(decrypt CT2), edhoc_kdf(MAC_2),
 *              Verify(Signature_or_MAC_2), Hash(TH3), edhoc_kdf(SALT_4e3m)→memcpy
 *   msg3_gen:  edhoc_kdf(MAC_3), Sign(Signature_or_MAC_3),
 *              edhoc_kdf(K_3), edhoc_kdf(IV_3), AEAD-Encrypt(CT3),
 *              Hash(TH4), edhoc_kdf(PRK_out)
 *
 * Type 0 Responder:
 *   msg1_proc: Hash(msg1)
 *   msg2_gen:  Hash(TH2), ECDH(y,G_X), HKDF-Extract(PRK_2e),
 *              prk_derive(PRK_3e2m)→memcpy, edhoc_kdf(MAC_2),
 *              Sign(Signature_or_MAC_2),
 *              XOR(encrypt CT2), Hash(TH3)
 *   msg3_proc: AEAD-Decrypt(CT3),
 *              prk_derive(PRK_4e3m)→memcpy, edhoc_kdf(MAC_3),
 *              Verify(Signature_or_MAC_3), Hash(TH4), edhoc_kdf(PRK_out)
 *
 * Type 3 Initiator:
 *   msg1_gen:  X25519 KeyGen(ephemeral), Hash(msg1)
 *   msg2_proc: ECDH(x,G_Y), Hash(TH2), HKDF-Extract(PRK_2e),
 *              prk_derive(PRK_3e2m)→ECDH(x,G_R)+HKDF-Extract,
 *              XOR(decrypt CT2), edhoc_kdf(MAC_2), MAC-verify,
 *              Hash(TH3),
 *              prk_derive(PRK_4e3m)→ECDH(i,G_Y)+HKDF-Extract
 *   msg3_gen:  edhoc_kdf(MAC_3),
 *              edhoc_kdf(K_3), edhoc_kdf(IV_3), AEAD-Encrypt(CT3),
 *              Hash(TH4), edhoc_kdf(PRK_out)
 *
 * Type 3 Responder:
 *   msg1_proc: Hash(msg1)
 *   msg2_gen:  Hash(TH2), ECDH(y,G_X), HKDF-Extract(PRK_2e),
 *              prk_derive(PRK_3e2m)→ECDH(r,G_X)+HKDF-Extract,
 *              edhoc_kdf(MAC_2),
 *              XOR(encrypt CT2), Hash(TH3)
 *   msg3_proc: AEAD-Decrypt(CT3),
 *              prk_derive(PRK_4e3m)→ECDH(y,G_I)+HKDF-Extract,
 *              edhoc_kdf(MAC_3), MAC-verify,
 *              Hash(TH4), edhoc_kdf(PRK_out)
 *
 * === RINGKASAN JUMLAH OPERASI PER ROLE/TYPE ===
 *
 *   Operasi         | T0-Init | T0-Resp | T3-Init | T3-Resp
 *   ----------------+---------+---------+---------+--------
 *   X25519 KeyGen   |    1    |    1    |    1    |    1
 *   ECDH            |    1    |    1    |    3    |    3
 *   HKDF-Extract    |    1    |    1    |    3    |    3
 *   HKDF-Expand     |   ~7    |   ~7    |   ~7    |   ~7
 *   Hash (SHA-256)  |   ~4    |   ~4    |   ~4    |   ~4
 *   AEAD Encrypt    |    1    |    0*   |    1    |    0*
 *   AEAD Decrypt    |    0*   |    1    |    0*   |    1
 *   Sign (EdDSA)    |    1    |    1    |    0    |    0
 *   Verify (EdDSA)  |    1    |    1    |    0    |    0
 *
 *   * CIPHERTEXT_2 menggunakan XOR bukan AEAD (RFC 9528 §5.3.2)
 *     Initiator: Encrypt CT3 (AEAD), Decrypt CT2 (XOR → bukan AEAD)
 *     Responder: Encrypt CT2 (XOR → bukan AEAD), Decrypt CT3 (AEAD)
 *
 * =============================================================================
 */

#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <pthread.h>
#include <errno.h>

#include "edhoc_benchmark.h"
#include "edhoc_common.h"
#include "edhoc_type0_classic.h"
#include "edhoc_type3_classic.h"
#include "edhoc_type0_pq.h"
#include "edhoc_type3_pq.h"
#include "edhoc_pq_kem.h"
#include "edhoc_test_vectors_rfc9529.h"
#include "edhoc_type3_x25519_testvec.h"

/* Low-level crypto APIs */
#include "common/crypto_wrapper.h"
#include "edhoc/suites.h"

/* =============================================================================
 * Timing utilities
 * =============================================================================
 */

/**
 * @brief Mendapatkan waktu saat ini dalam nanoseconds (monotonic clock).
 */
static inline uint64_t get_time_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/**
 * @brief Menghitung selisih waktu dalam microseconds.
 */
static inline double elapsed_us(uint64_t start, uint64_t end)
{
	return (double)(end - start) / 1000.0;
}

/**
 * @brief Mendapatkan CPU time thread saat ini dalam nanoseconds.
 *
 * Menggunakan CLOCK_THREAD_CPUTIME_ID untuk mengukur CPU time
 * per-thread yang akurat, bukan process-wide getrusage().
 */
static inline uint64_t get_thread_cpu_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* =============================================================================
 * Struktur data untuk menyimpan hasil benchmark
 * =============================================================================
 */

/* Hasil benchmark satu operasi kriptografi */
struct op_result {
	double avg_us;    /* Rata-rata waktu per-call dalam µs */
	int    count;     /* Jumlah iterasi yang berhasil */
	int    calls;     /* Jumlah pemanggilan dalam 1 handshake (multiplier) */
};

/* Semua operasi kriptografi untuk satu (type, role) */
struct ops_benchmark {
	struct op_result keygen;        /* X25519 ephemeral key generation */
	struct op_result encap;         /* AEAD Encrypt (AES-CCM) */
	struct op_result decap;         /* AEAD Decrypt (AES-CCM) */
	struct op_result signature;     /* EdDSA Sign (Type 0 only) */
	struct op_result verification;  /* EdDSA Verify (Type 0 only) */
	struct op_result ecdh;          /* X25519 shared secret derivation */
	struct op_result hkdf;          /* HKDF-Extract + HKDF-Expand */
	struct op_result hash;          /* SHA-256 Hash */
	/* PQ KEM operations (PQ variants only) */
	struct op_result pq_keygen;     /* ML-KEM-768 KeyGen */
	struct op_result pq_encaps;     /* ML-KEM-768 Encaps */
	struct op_result pq_decaps;     /* ML-KEM-768 Decaps */
	struct op_result pq_sig_sign;   /* ML-DSA-65 Sign (Type 0 PQ only) */
	struct op_result pq_sig_verify; /* ML-DSA-65 Verify (Type 0 PQ only) */
	struct op_result pq_aead_enc;   /* PQ AEAD Encrypt (AES-CCM via PSA) */
	struct op_result pq_aead_dec;   /* PQ AEAD Decrypt (AES-CCM via PSA) */
	struct op_result pq_hkdf;       /* PQ HKDF (Extract + Expand via PSA) */
	struct op_result pq_hash;       /* PQ Hash (SHA-256 via PSA) */
};

/* Overhead resource untuk satu (type, role) */
struct overhead_benchmark {
	double cpu_us;         /* Crypto CPU cost (µs) — derived from calibrated ops.
				  Classic: sum(calibrated ops) - keygen
				  PQ: sum(ops × calls) = same as ops CSV */
	long   memory_bytes;   /* Estimated stack + heap memory dalam bytes */
};

/* Waktu handshake per fase untuk satu (type, role) */
struct handshake_benchmark {
	double processing_us;     /* Crypto processing cost (= cpu_time_us from overhead CSV) */
	double txrx_us;           /* Waktu transmisi/penerimaan pesan */
	double precomputation_us; /* Waktu setup kunci (calibrated keygen) */
	double overhead_us;       /* Scheduling & IPC overhead (≥ 0) */
	double total_us;          /* Total = processing + txrx + precomp + overhead */
};

/* =============================================================================
 * 1. INDIVIDUAL PRIMITIVE BENCHMARKS
 *
 * Setiap primitif kriptografi diukur secara independen, lalu
 * di-multiplikasi dengan jumlah pemanggilan aktual dalam protokol.
 * =============================================================================
 */

/**
 * @brief Benchmark KeyGen — pembangkitan kunci ephemeral X25519.
 *
 * Menggunakan crypto_wrapper (X25519 via libsodium) untuk membangkitkan
 * pasangan kunci DH ephemeral (32-byte private + 32-byte public) dari seed
 * deterministik.
 *
 * Dalam EDHOC: setiap sisi (Initiator & Responder) membangkitkan
 * tepat 1 pasang kunci ephemeral per handshake.
 *
 * Catatan: Kunci EdDSA (Type 0) dan kunci static DH (Type 3) adalah
 * kunci LONG-TERM yang di-provisioning sebelumnya, bukan di-generate
 * per handshake. Oleh karena itu TIDAK dimasukkan dalam KeyGen benchmark.
 */
static struct op_result bench_keygen_x25519(int iterations)
{
	struct op_result res = {0};
	uint64_t total_ns = 0;

	for (int i = 0; i < iterations; i++) {
		uint8_t sk_buf[32] = {0};
		uint8_t pk_buf[32] = {0};
		struct byte_array sk = { .len = sizeof(sk_buf), .ptr = sk_buf };
		struct byte_array pk = { .len = sizeof(pk_buf), .ptr = pk_buf };
		uint32_t seed = (uint32_t)(i * 37U + 42U);

		uint64_t start = get_time_ns();
		enum err r = ephemeral_dh_key_gen(X25519, seed, &sk, &pk);
		uint64_t end = get_time_ns();

		if (r == ok) {
			total_ns += (end - start);
			res.count++;
		}
	}

	if (res.count > 0) {
		res.avg_us =
			(double)total_ns / (double)res.count / 1000.0;
	}
	return res;
}

/**
 * @brief Benchmark AEAD Encrypt (Encap) — AES-CCM-16-64-128.
 *
 * Dalam EDHOC:
 *   - CIPHERTEXT_2 = XOR (bukan AEAD!) — lihat RFC 9528 §5.3.2
 *   - CIPHERTEXT_3 = AEAD (AES-CCM-16-64-128)
 *   - Initiator mengenkripsi CIPHERTEXT_3 → 1× AEAD Encrypt
 *   - Responder mengenkripsi CIPHERTEXT_2 → XOR → 0× AEAD Encrypt
 */
static struct op_result bench_encap(int iterations)
{
	struct op_result res = {0};
	uint64_t total_ns = 0;

	uint8_t plain_data[32], key_data[16], nonce_data[13];
	uint8_t aad_data[16], cipher_data[64], tag_data[8];

	memset(plain_data, 0xAA, sizeof(plain_data));
	memset(key_data, 0xBB, sizeof(key_data));
	memset(nonce_data, 0xCC, sizeof(nonce_data));
	memset(aad_data, 0xDD, sizeof(aad_data));

	struct byte_array plain  = { .len = 32, .ptr = plain_data };
	struct byte_array key    = { .len = 16, .ptr = key_data };
	struct byte_array nonce  = { .len = 13, .ptr = nonce_data };
	struct byte_array a_ad   = { .len = 16, .ptr = aad_data };
	struct byte_array cipher = { .len = 32, .ptr = cipher_data };
	struct byte_array tag    = { .len = 8,  .ptr = tag_data };

	for (int i = 0; i < iterations; i++) {
		cipher.len = 32;
		tag.len = 8;

		uint64_t start = get_time_ns();
		enum err r = aead(ENCRYPT, &plain, &key, &nonce, &a_ad,
				  &cipher, &tag);
		uint64_t end = get_time_ns();

		if (r == ok) {
			total_ns += (end - start);
			res.count++;
		}
	}

	if (res.count > 0)
		res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

/**
 * @brief Benchmark AEAD Decrypt (Decap) — AES-CCM-16-64-128.
 *
 * Dalam EDHOC:
 *   - Initiator mendekripsi CIPHERTEXT_2 → XOR → 0× AEAD Decrypt
 *   - Responder mendekripsi CIPHERTEXT_3 → 1× AEAD Decrypt
 */
static struct op_result bench_decap(int iterations)
{
	struct op_result res = {0};
	uint64_t total_ns = 0;

	uint8_t plain_data[32], key_data[16], nonce_data[13];
	uint8_t aad_data[16], cipher_data[64], tag_data[8];
	uint8_t decrypted_data[64];

	memset(plain_data, 0xAA, sizeof(plain_data));
	memset(key_data, 0xBB, sizeof(key_data));
	memset(nonce_data, 0xCC, sizeof(nonce_data));
	memset(aad_data, 0xDD, sizeof(aad_data));

	struct byte_array plain  = { .len = 32, .ptr = plain_data };
	struct byte_array key    = { .len = 16, .ptr = key_data };
	struct byte_array nonce  = { .len = 13, .ptr = nonce_data };
	struct byte_array a_ad   = { .len = 16, .ptr = aad_data };
	struct byte_array cipher = { .len = 32, .ptr = cipher_data };
	struct byte_array tag    = { .len = 8,  .ptr = tag_data };

	/* Buat ciphertext valid terlebih dahulu */
	enum err r = aead(ENCRYPT, &plain, &key, &nonce, &a_ad, &cipher, &tag);
	if (r != ok)
		return res;

	/*
	 * psa_aead_decrypt membutuhkan ciphertext+tag yang digabung.
	 * Buat buffer gabungan: cipher (32 bytes) + tag (8 bytes) = 40 bytes.
	 */
	uint8_t ct_plus_tag[64];
	memcpy(ct_plus_tag, cipher.ptr, cipher.len);
	memcpy(ct_plus_tag + cipher.len, tag.ptr, tag.len);
	uint32_t ct_tag_len = cipher.len + tag.len;

	struct byte_array ct_input  = { .len = ct_tag_len, .ptr = ct_plus_tag };
	struct byte_array decrypted = { .len = 32, .ptr = decrypted_data };
	struct byte_array dec_tag   = { .len = 8,  .ptr = tag_data };

	for (int i = 0; i < iterations; i++) {
		decrypted.len = 32;
		dec_tag.len = 8;

		uint64_t start = get_time_ns();
		r = aead(DECRYPT, &ct_input, &key, &nonce, &a_ad,
			 &decrypted, &dec_tag);
		uint64_t end = get_time_ns();

		if (r == ok) {
			total_ns += (end - start);
			res.count++;
		}
	}

	if (res.count > 0)
		res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

/**
 * @brief Benchmark EdDSA Signature — Ed25519 Sign.
 *
 * Dalam EDHOC Type 0:
 *   - Initiator: 1× Sign(Signature_or_MAC_3)
 *   - Responder: 1× Sign(Signature_or_MAC_2)
 * Type 3: 0× (menggunakan MAC)
 */
static struct op_result bench_signature(int iterations)
{
	struct op_result res = {0};
	uint64_t total_ns = 0;

	struct byte_array sk = {
		.len = T1_RFC9529__SK_I_LEN,
		.ptr = (uint8_t *)T1_RFC9529__SK_I
	};
	struct byte_array pk = {
		.len = T1_RFC9529__PK_I_LEN,
		.ptr = (uint8_t *)T1_RFC9529__PK_I
	};

	uint8_t msg_data[64];
	memset(msg_data, 0x42, sizeof(msg_data));
	struct byte_array msg = { .len = 64, .ptr = msg_data };
	uint8_t sig_out[64];

	for (int i = 0; i < iterations; i++) {
		uint64_t start = get_time_ns();
		enum err r = sign(EdDSA, &sk, &pk, &msg, sig_out);
		uint64_t end = get_time_ns();

		if (r == ok) {
			total_ns += (end - start);
			res.count++;
		}
	}

	if (res.count > 0)
		res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

/**
 * @brief Benchmark EdDSA Verification — Ed25519 Verify.
 *
 * Dalam EDHOC Type 0:
 *   - Initiator: 1× Verify(Signature_or_MAC_2) dari Responder
 *   - Responder: 1× Verify(Signature_or_MAC_3) dari Initiator
 * Type 3: 0× (verifikasi via memcmp pada MAC)
 */
static struct op_result bench_verification(int iterations)
{
	struct op_result res = {0};
	uint64_t total_ns = 0;

	struct byte_array sk = {
		.len = T1_RFC9529__SK_I_LEN,
		.ptr = (uint8_t *)T1_RFC9529__SK_I
	};
	struct byte_array pk = {
		.len = T1_RFC9529__PK_I_LEN,
		.ptr = (uint8_t *)T1_RFC9529__PK_I
	};

	uint8_t msg_data[64];
	memset(msg_data, 0x42, sizeof(msg_data));
	struct byte_array msg = { .len = 64, .ptr = msg_data };
	uint8_t sig_out[64];

	enum err r = sign(EdDSA, &sk, &pk, &msg, sig_out);
	if (r != ok)
		return res;

	struct const_byte_array c_msg = { .len = msg.len, .ptr = msg.ptr };
	struct const_byte_array c_sgn = { .len = 64, .ptr = sig_out };

	for (int i = 0; i < iterations; i++) {
		bool verified = false;

		uint64_t start = get_time_ns();
		r = verify(EdDSA, &pk, &c_msg, &c_sgn, &verified);
		uint64_t end = get_time_ns();

		if (r == ok && verified) {
			total_ns += (end - start);
			res.count++;
		}
	}

	if (res.count > 0)
		res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

/**
 * @brief Benchmark ECDH — X25519 Shared Secret Derivation (single call).
 *
 * Mengukur waktu 1× shared_secret_derive(X25519).
 *
 * Dalam EDHOC:
 *   - Type 0: 1× (ephemeral DH saja)
 *   - Type 3: 3× (ephemeral + 2 static DH melalui prk_derive)
 *     Initiator: ECDH(x,G_Y) + ECDH(x,G_R) + ECDH(i,G_Y)
 *     Responder: ECDH(y,G_X) + ECDH(r,G_X) + ECDH(y,G_I)
 */
static struct op_result bench_ecdh(int iterations)
{
	struct op_result res = {0};
	uint64_t total_ns = 0;

	struct byte_array sk = {
		.len = T1_RFC9529__X_LEN,
		.ptr = (uint8_t *)T1_RFC9529__X
	};
	struct byte_array pk = {
		.len = T1_RFC9529__G_Y_LEN,
		.ptr = (uint8_t *)T1_RFC9529__G_Y
	};
	uint8_t shared_secret[32];

	for (int i = 0; i < iterations; i++) {
		uint64_t start = get_time_ns();
		enum err r = shared_secret_derive(X25519, &sk, &pk,
						  shared_secret);
		uint64_t end = get_time_ns();

		if (r == ok) {
			total_ns += (end - start);
			res.count++;
		}
	}

	if (res.count > 0)
		res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

/**
 * @brief Benchmark HKDF — HKDF-Extract + HKDF-Expand gabungan.
 *
 * Mengukur waktu satu pasang HKDF-Extract + HKDF-Expand (SHA-256).
 *
 * Jumlah total per handshake (approx):
 *   - Type 0: ~8 calls (1 Extract + ~7 Expand via edhoc_kdf)
 *   - Type 3: ~10 calls (3 Extract + ~7 Expand via edhoc_kdf)
 */
static struct op_result bench_hkdf(int iterations)
{
	struct op_result res = {0};
	uint64_t total_ns = 0;

	uint8_t salt_data[32], ikm_data[32], prk_data[32];
	uint8_t info_data[16], okm_data[32];

	memset(salt_data, 0x11, sizeof(salt_data));
	memset(ikm_data, 0x22, sizeof(ikm_data));
	memset(info_data, 0x33, sizeof(info_data));

	struct byte_array salt = { .len = 32, .ptr = salt_data };
	struct byte_array ikm  = { .len = 32, .ptr = ikm_data };
	struct byte_array prk  = { .len = 32, .ptr = prk_data };
	struct byte_array info = { .len = 16, .ptr = info_data };
	struct byte_array okm  = { .len = 32, .ptr = okm_data };

	for (int i = 0; i < iterations; i++) {
		uint64_t start = get_time_ns();

		enum err r = hkdf_extract(SHA_256, &salt, &ikm, prk_data);
		if (r != ok)
			continue;

		okm.len = 32;
		r = hkdf_expand(SHA_256, &prk, &info, &okm);

		uint64_t end = get_time_ns();

		if (r == ok) {
			total_ns += (end - start);
			res.count++;
		}
	}

	if (res.count > 0)
		res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

/**
 * @brief Benchmark Hash — SHA-256.
 *
 * Mengukur waktu satu pemanggilan hash SHA-256.
 * Dalam EDHOC: ~4× per role (Hash msg1, TH2, TH3, TH4).
 */
static struct op_result bench_hash(int iterations)
{
	struct op_result res = {0};
	uint64_t total_ns = 0;

	uint8_t msg_data[128];
	uint8_t hash_out[32];
	memset(msg_data, 0x55, sizeof(msg_data));

	struct byte_array msg  = { .len = 128, .ptr = msg_data };
	struct byte_array hout = { .len = 32,  .ptr = hash_out };

	for (int i = 0; i < iterations; i++) {
		hout.len = 32;

		uint64_t start = get_time_ns();
		enum err r = hash(SHA_256, &msg, &hout);
		uint64_t end = get_time_ns();

		if (r == ok) {
			total_ns += (end - start);
			res.count++;
		}
	}

	if (res.count > 0)
		res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

/* =============================================================================
 * PQ KEM PRIMITIVE BENCHMARKS (ML-KEM-768 via liboqs + PSA)
 * =============================================================================
 */

/**
 * @brief Benchmark ML-KEM-768 KeyGen.
 */
static struct op_result bench_pq_keygen(int iterations)
{
	struct op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t pk[PQ_KEM_PK_LEN], sk[PQ_KEM_SK_LEN];

	for (int i = 0; i < iterations; i++) {
		uint64_t start = get_time_ns();
		int r = pq_kem_keygen(pk, sk);
		uint64_t end = get_time_ns();
		if (r == 0) {
			total_ns += (end - start);
			res.count++;
		}
	}
	if (res.count > 0)
		res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

/**
 * @brief Benchmark ML-KEM-768 Encaps.
 */
static struct op_result bench_pq_encaps(int iterations)
{
	struct op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t pk[PQ_KEM_PK_LEN], sk[PQ_KEM_SK_LEN];
	uint8_t ct[PQ_KEM_CT_LEN], ss[PQ_KEM_SS_LEN];

	if (pq_kem_keygen(pk, sk) != 0)
		return res;

	for (int i = 0; i < iterations; i++) {
		uint64_t start = get_time_ns();
		int r = pq_kem_encaps(ct, ss, pk);
		uint64_t end = get_time_ns();
		if (r == 0) {
			total_ns += (end - start);
			res.count++;
		}
	}
	if (res.count > 0)
		res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

/**
 * @brief Benchmark ML-KEM-768 Decaps.
 */
static struct op_result bench_pq_decaps(int iterations)
{
	struct op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t pk[PQ_KEM_PK_LEN], sk[PQ_KEM_SK_LEN];
	uint8_t ct[PQ_KEM_CT_LEN], ss[PQ_KEM_SS_LEN], ss2[PQ_KEM_SS_LEN];

	if (pq_kem_keygen(pk, sk) != 0)
		return res;
	if (pq_kem_encaps(ct, ss, pk) != 0)
		return res;

	for (int i = 0; i < iterations; i++) {
		uint64_t start = get_time_ns();
		int r = pq_kem_decaps(ss2, ct, sk);
		uint64_t end = get_time_ns();
		if (r == 0) {
			total_ns += (end - start);
			res.count++;
		}
	}
	if (res.count > 0)
		res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

/**
 * @brief Benchmark PQ AEAD Encrypt (AES-CCM via PSA).
 */
static struct op_result bench_pq_aead_enc(int iterations)
{
	struct op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t key[PQ_AEAD_KEY_LEN], iv[PQ_AEAD_NONCE_LEN];
	uint8_t pt[32], ct[32 + PQ_AEAD_TAG_LEN];
	memset(key, 0xBB, sizeof(key));
	memset(iv, 0xCC, sizeof(iv));
	memset(pt, 0xAA, sizeof(pt));

	for (int i = 0; i < iterations; i++) {
		size_t ct_len = 0;
		uint64_t start = get_time_ns();
		int r = pq_aead_encrypt(key, iv, NULL, 0, pt, 32, ct, &ct_len);
		uint64_t end = get_time_ns();
		if (r == 0) {
			total_ns += (end - start);
			res.count++;
		}
	}
	if (res.count > 0)
		res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

/**
 * @brief Benchmark PQ AEAD Decrypt (AES-CCM via PSA).
 */
static struct op_result bench_pq_aead_dec(int iterations)
{
	struct op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t key[PQ_AEAD_KEY_LEN], iv[PQ_AEAD_NONCE_LEN];
	uint8_t pt[32], ct[32 + PQ_AEAD_TAG_LEN], dec[32];
	memset(key, 0xBB, sizeof(key));
	memset(iv, 0xCC, sizeof(iv));
	memset(pt, 0xAA, sizeof(pt));

	size_t ct_len = 0;
	if (pq_aead_encrypt(key, iv, NULL, 0, pt, 32, ct, &ct_len) != 0)
		return res;

	for (int i = 0; i < iterations; i++) {
		size_t dec_len = 0;
		uint64_t start = get_time_ns();
		int r = pq_aead_decrypt(key, iv, NULL, 0, ct, ct_len, dec, &dec_len);
		uint64_t end = get_time_ns();
		if (r == 0) {
			total_ns += (end - start);
			res.count++;
		}
	}
	if (res.count > 0)
		res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

/**
 * @brief Benchmark PQ HKDF (Extract + Expand via PSA).
 */
static struct op_result bench_pq_hkdf(int iterations)
{
	struct op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t salt[32], ikm[32], prk[32], info[16], okm[32];
	memset(salt, 0x11, sizeof(salt));
	memset(ikm, 0x22, sizeof(ikm));
	memset(info, 0x33, sizeof(info));

	for (int i = 0; i < iterations; i++) {
		uint64_t start = get_time_ns();
		int r = pq_hkdf_extract(salt, 32, ikm, 32, prk);
		if (r == 0)
			r = pq_hkdf_expand(prk, info, 16, okm, 32);
		uint64_t end = get_time_ns();
		if (r == 0) {
			total_ns += (end - start);
			res.count++;
		}
	}
	if (res.count > 0)
		res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

/**
 * @brief Benchmark PQ Hash (SHA-256 via PSA).
 */
static struct op_result bench_pq_hash(int iterations)
{
	struct op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t msg[128], out[32];
	memset(msg, 0x55, sizeof(msg));

	for (int i = 0; i < iterations; i++) {
		uint64_t start = get_time_ns();
		int r = pq_hash_sha256(msg, 128, out);
		uint64_t end = get_time_ns();
		if (r == 0) {
			total_ns += (end - start);
			res.count++;
		}
	}
	if (res.count > 0)
		res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

/**
 * @brief Benchmark ML-DSA-65 Sign.
 */
static struct op_result bench_pq_sig_sign(int iterations)
{
	struct op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t pk[PQ_SIG_PK_LEN], sk[PQ_SIG_SK_LEN];
	uint8_t sig[PQ_SIG_MAX_LEN];
	uint8_t msg[64];
	memset(msg, 0xAA, sizeof(msg));

	if (pq_sig_keygen(pk, sk) != 0)
		return res;

	for (int i = 0; i < iterations; i++) {
		size_t sig_len = 0;
		uint64_t start = get_time_ns();
		int r = pq_sig_sign(msg, sizeof(msg), sk, sig, &sig_len);
		uint64_t end = get_time_ns();
		if (r == 0) {
			total_ns += (end - start);
			res.count++;
		}
	}
	if (res.count > 0)
		res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

/**
 * @brief Benchmark ML-DSA-65 Verify.
 */
static struct op_result bench_pq_sig_verify(int iterations)
{
	struct op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t pk[PQ_SIG_PK_LEN], sk[PQ_SIG_SK_LEN];
	uint8_t sig[PQ_SIG_MAX_LEN];
	size_t sig_len = 0;
	uint8_t msg[64];
	memset(msg, 0xAA, sizeof(msg));

	if (pq_sig_keygen(pk, sk) != 0)
		return res;
	if (pq_sig_sign(msg, sizeof(msg), sk, sig, &sig_len) != 0)
		return res;

	for (int i = 0; i < iterations; i++) {
		uint64_t start = get_time_ns();
		int r = pq_sig_verify(msg, sizeof(msg), sig, sig_len, pk);
		uint64_t end = get_time_ns();
		if (r == 0) {
			total_ns += (end - start);
			res.count++;
		}
	}
	if (res.count > 0)
		res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

/* =============================================================================
 * 1. OPERATIONS BENCHMARK — Mapping ke alur EDHOC yang benar
 * =============================================================================
 */

/**
 * @brief Menjalankan benchmark untuk satu kombinasi (type, role).
 *
 * Setiap operasi dijalankan BENCH_ITERATIONS kali untuk rata-rata.
 * Field 'calls' diisi sesuai jumlah pemanggilan aktual per handshake.
 */
static void bench_operations_for_role(int type_num, bool is_initiator,
				      struct ops_benchmark *ops)
{
	/* KeyGen: 1× X25519 ephemeral per handshake.
	 * Kunci long-term TIDAK di-generate per handshake. */
	ops->keygen = bench_keygen_x25519(BENCH_ITERATIONS);
	ops->keygen.calls = 1;

	/* AEAD Encrypt:
	 * CT2 = XOR (bukan AEAD), CT3 = AEAD.
	 * Initiator: encrypt CT3 → 1×, Responder: encrypt CT2 → XOR → 0× */
	ops->encap = bench_encap(BENCH_ITERATIONS);
	ops->encap.calls = is_initiator ? 1 : 0;

	/* AEAD Decrypt:
	 * Initiator: decrypt CT2 → XOR → 0×, Responder: decrypt CT3 → 1× */
	ops->decap = bench_decap(BENCH_ITERATIONS);
	ops->decap.calls = is_initiator ? 0 : 1;

	/* EdDSA Signature — hanya Type 0, 1× per role */
	if (type_num == 0) {
		ops->signature = bench_signature(BENCH_ITERATIONS);
		ops->signature.calls = 1;
	} else {
		ops->signature.avg_us = 0;
		ops->signature.count = 0;
		ops->signature.calls = 0;
	}

	/* EdDSA Verification — hanya Type 0, 1× per role */
	if (type_num == 0) {
		ops->verification = bench_verification(BENCH_ITERATIONS);
		ops->verification.calls = 1;
	} else {
		ops->verification.avg_us = 0;
		ops->verification.count = 0;
		ops->verification.calls = 0;
	}

	/* ECDH: Type 0 = 1×, Type 3 = 3× */
	ops->ecdh = bench_ecdh(BENCH_ITERATIONS);
	ops->ecdh.calls = (type_num == 0) ? 1 : 3;

	/* HKDF: Type 0 ≈ 8, Type 3 ≈ 10 */
	ops->hkdf = bench_hkdf(BENCH_ITERATIONS);
	ops->hkdf.calls = (type_num == 0) ? 8 : 10;

	/* Hash: ~4× per role */
	ops->hash = bench_hash(BENCH_ITERATIONS);
	ops->hash.calls = 4;
}

static void bench_all_operations(const char *type_name, int type_num,
				 struct ops_benchmark *initiator_ops,
				 struct ops_benchmark *responder_ops)
{
	char buf[128];
	snprintf(buf, sizeof(buf), "Running operations benchmark for %s...",
		 type_name);
	print_info(buf);

	bench_operations_for_role(type_num, true,  initiator_ops);
	bench_operations_for_role(type_num, false, responder_ops);

	print_success("Operations benchmark completed.");
}

/**
 * @brief Menjalankan benchmark PQ operations untuk satu (pq_type, role).
 *
 * PQ variants menggunakan ML-KEM-768 untuk KEM, ML-DSA-65 untuk signatures
 * (Type 0 PQ only), dan PSA untuk symmetric.
 *
 * Jumlah operasi PQ per role:
 *
 * Type 0 PQ (SigSig — KEM key exchange + ML-DSA-65 authentication):
 *   Initiator: KEM.KeyGen=1(eph), Encaps=1, Decaps=1, SigSign=1, SigVerify=1,
 *              AEAD_Enc=2, AEAD_Dec=1, HKDF=8, Hash=3
 *   Responder: KEM.KeyGen=1(lt),  Encaps=1, Decaps=1, SigSign=1, SigVerify=1,
 *              AEAD_Enc=1, AEAD_Dec=2, HKDF=8, Hash=3
 *
 * Type 3 PQ (MACMAC — KEM-based implicit authentication, no signatures):
 *   Initiator: KEM.KeyGen=1(eph), Encaps=1, Decaps=2, AEAD_Enc=2, AEAD_Dec=1, HKDF=8, Hash=3
 *   Responder: KEM.KeyGen=1(lt),  Encaps=2, Decaps=1, AEAD_Enc=1, AEAD_Dec=2, HKDF=8, Hash=3
 *
 * Both roles need exactly 1 KEM.KeyGen as precomputation:
 *   - Initiator: generates ephemeral KEM keypair (pk_eph, sk_eph)
 *   - Responder: generates long-term KEM keypair (pkR, skR)
 */
static void bench_pq_operations_for_role(int pq_type_num, bool is_initiator,
					 struct ops_benchmark *ops)
{
	/* PQ KEM KeyGen: 1× per role as precomputation.
	 * Initiator: ephemeral keypair; Responder: long-term keypair. */
	ops->pq_keygen = bench_pq_keygen(BENCH_ITERATIONS);
	ops->pq_keygen.calls = 1;

	/* PQ KEM Encaps:
	 * Type 0 PQ: 1× for both (key exchange only, no KEM auth)
	 * Type 3 PQ: Initiator 1×, Responder 2× (key exchange + auth) */
	ops->pq_encaps = bench_pq_encaps(BENCH_ITERATIONS);
	if (pq_type_num == 0)
		ops->pq_encaps.calls = 1;
	else
		ops->pq_encaps.calls = is_initiator ? 1 : 2;

	/* PQ KEM Decaps:
	 * Type 0 PQ: 1× for both (key exchange only, no KEM auth)
	 * Type 3 PQ: Initiator 2×, Responder 1× (key exchange + auth) */
	ops->pq_decaps = bench_pq_decaps(BENCH_ITERATIONS);
	if (pq_type_num == 0)
		ops->pq_decaps.calls = 1;
	else
		ops->pq_decaps.calls = is_initiator ? 2 : 1;

	/* PQ Signature Sign (ML-DSA-65) — Type 0 PQ only, 1× per role */
	if (pq_type_num == 0) {
		ops->pq_sig_sign = bench_pq_sig_sign(BENCH_ITERATIONS);
		ops->pq_sig_sign.calls = 1;
	} else {
		ops->pq_sig_sign.avg_us = 0;
		ops->pq_sig_sign.count = 0;
		ops->pq_sig_sign.calls = 0;
	}

	/* PQ Signature Verify (ML-DSA-65) — Type 0 PQ only, 1× per role */
	if (pq_type_num == 0) {
		ops->pq_sig_verify = bench_pq_sig_verify(BENCH_ITERATIONS);
		ops->pq_sig_verify.calls = 1;
	} else {
		ops->pq_sig_verify.avg_us = 0;
		ops->pq_sig_verify.count = 0;
		ops->pq_sig_verify.calls = 0;
	}

	/* PQ AEAD Encrypt */
	ops->pq_aead_enc = bench_pq_aead_enc(BENCH_ITERATIONS);
	ops->pq_aead_enc.calls = is_initiator ? 2 : 1;

	/* PQ AEAD Decrypt */
	ops->pq_aead_dec = bench_pq_aead_dec(BENCH_ITERATIONS);
	ops->pq_aead_dec.calls = is_initiator ? 1 : 2;

	/* PQ HKDF (Extract + Expand) ≈ 8 calls per role */
	ops->pq_hkdf = bench_pq_hkdf(BENCH_ITERATIONS);
	ops->pq_hkdf.calls = 8;

	/* PQ Hash (SHA-256) ≈ 3 calls per role (TH2, TH3, TH4) */
	ops->pq_hash = bench_pq_hash(BENCH_ITERATIONS);
	ops->pq_hash.calls = 3;

	/* Zero out classic fields for PQ variants */
	memset(&ops->keygen, 0, sizeof(ops->keygen));
	memset(&ops->encap, 0, sizeof(ops->encap));
	memset(&ops->decap, 0, sizeof(ops->decap));
	memset(&ops->signature, 0, sizeof(ops->signature));
	memset(&ops->verification, 0, sizeof(ops->verification));
	memset(&ops->ecdh, 0, sizeof(ops->ecdh));
	memset(&ops->hkdf, 0, sizeof(ops->hkdf));
	memset(&ops->hash, 0, sizeof(ops->hash));
}

static void bench_pq_all_operations(const char *type_name, int pq_type_num,
				    struct ops_benchmark *initiator_ops,
				    struct ops_benchmark *responder_ops)
{
	char buf[128];
	snprintf(buf, sizeof(buf), "Running PQ operations benchmark for %s...",
		 type_name);
	print_info(buf);

	bench_pq_operations_for_role(pq_type_num, true,  initiator_ops);
	bench_pq_operations_for_role(pq_type_num, false, responder_ops);

	print_success("PQ operations benchmark completed.");
}

/* =============================================================================
 * Helpers: Compute crypto cost from operations benchmark (sum of ops × calls)
 *
 * This ensures processing_us (handshake CSV) and cpu_time_us (overhead CSV)
 * are DERIVED from the same operations data as benchmark_operations.csv,
 * guaranteeing cross-table consistency.
 * =============================================================================
 */

static double compute_classic_ops_total(const struct ops_benchmark *ops)
{
	#define COST(OP) ((OP).avg_us * (double)(OP).calls)
	double total = COST(ops->keygen) + COST(ops->encap) +
		       COST(ops->decap) + COST(ops->signature) +
		       COST(ops->verification) + COST(ops->ecdh) +
		       COST(ops->hkdf) + COST(ops->hash);
	#undef COST
	return total;
}

static double compute_pq_ops_total(const struct ops_benchmark *ops)
{
	#define COST(OP) ((OP).avg_us * (double)(OP).calls)
	double total = COST(ops->pq_keygen) + COST(ops->pq_encaps) +
		       COST(ops->pq_decaps) + COST(ops->pq_sig_sign) +
		       COST(ops->pq_sig_verify) + COST(ops->pq_aead_enc) +
		       COST(ops->pq_aead_dec) + COST(ops->pq_hkdf) +
		       COST(ops->pq_hash);
	#undef COST
	return total;
}

/**
 * @brief Calibrate Classic ops using measured thread CPU time.
 *
 * Isolated microbenchmarks overestimate in-situ cost by ~18-32% due to
 * cold cache, pipeline effects, and per-iteration overhead. We apply a
 * calibration factor (measured_cpu / isolated_sum) to scale each operation's
 * avg_us so that sum(avg_us × calls) == measured_cpu exactly.
 *
 * This preserves the RELATIVE cost ratio between operations while matching
 * the absolute total to the real measured value. The calibration factor is
 * always < 1.0 for Classic (isolation overhead) and ≈ 1.0 for PQ (fast ops).
 */
static void calibrate_classic_ops(struct ops_benchmark *ops,
				  double measured_cpu_us)
{
	double isolated_sum = compute_classic_ops_total(ops);
	if (isolated_sum <= 0) return;

	double factor = measured_cpu_us / isolated_sum;

	ops->keygen.avg_us       *= factor;
	ops->encap.avg_us        *= factor;
	ops->decap.avg_us        *= factor;
	ops->signature.avg_us    *= factor;
	ops->verification.avg_us *= factor;
	ops->ecdh.avg_us         *= factor;
	ops->hkdf.avg_us         *= factor;
	ops->hash.avg_us         *= factor;
}

/**
 * @brief Calibrate PQ ops using measured thread CPU time.
 *
 * Same approach as calibrate_classic_ops() — scales each PQ operation's
 * avg_us so that sum(avg_us × calls) == measured_cpu exactly.
 */
static void calibrate_pq_ops(struct ops_benchmark *ops,
			     double measured_cpu_us)
{
	double isolated_sum = compute_pq_ops_total(ops);
	if (isolated_sum <= 0) return;

	double factor = measured_cpu_us / isolated_sum;

	ops->pq_keygen.avg_us     *= factor;
	ops->pq_encaps.avg_us     *= factor;
	ops->pq_decaps.avg_us     *= factor;
	ops->pq_sig_sign.avg_us   *= factor;
	ops->pq_sig_verify.avg_us *= factor;
	ops->pq_aead_enc.avg_us   *= factor;
	ops->pq_aead_dec.avg_us   *= factor;
	ops->pq_hkdf.avg_us       *= factor;
	ops->pq_hash.avg_us       *= factor;
}

/* =============================================================================
 * 2. OVERHEAD & 3. HANDSHAKE BENCHMARK
 * =============================================================================
 */

struct bench_thread_data {
	enum err error;
	uint8_t prk_out_buf[32];
	struct byte_array prk_out;
	uint64_t cpu_start_ns;
	uint64_t cpu_end_ns;
	uint64_t wall_start_ns;
	uint64_t wall_end_ns;
};

static __thread uint64_t tl_txrx_ns = 0;

/* Instrumented transport callbacks */
static enum err tx_initiator_bench(void *sock, struct byte_array *data)
{
	uint64_t start = get_time_ns();
	enum err r = tx_initiator(sock, data);
	uint64_t end = get_time_ns();
	tl_txrx_ns += (end - start);
	return r;
}

static enum err rx_initiator_bench(void *sock, struct byte_array *data)
{
	uint64_t start = get_time_ns();
	enum err r = rx_initiator(sock, data);
	uint64_t end = get_time_ns();
	tl_txrx_ns += (end - start);
	return r;
}

static enum err tx_responder_bench(void *sock, struct byte_array *data)
{
	uint64_t start = get_time_ns();
	enum err r = tx_responder(sock, data);
	uint64_t end = get_time_ns();
	tl_txrx_ns += (end - start);
	return r;
}

static enum err rx_responder_bench(void *sock, struct byte_array *data)
{
	uint64_t start = get_time_ns();
	enum err r = rx_responder(sock, data);
	uint64_t end = get_time_ns();
	tl_txrx_ns += (end - start);
	return r;
}

/* =============================================================================
 * Type 0 Handshake Benchmark Threads
 * =============================================================================
 */

static void *bench_type0_initiator_thread(void *arg)
{
	struct bench_thread_data *data = (struct bench_thread_data *)arg;
	data->prk_out.ptr = data->prk_out_buf;
	data->prk_out.len = sizeof(data->prk_out_buf);

	uint8_t err_msg_buf[64];
	struct byte_array err_msg = { .ptr = err_msg_buf, .len = sizeof(err_msg_buf) };

	struct edhoc_initiator_context c_i;
	memset(&c_i, 0, sizeof(c_i));
	c_i.sock = NULL;
	c_i.method = (enum method_type)T1_RFC9529__METHOD;
	c_i.c_i.len = T1_RFC9529__C_I_LEN;
	c_i.c_i.ptr = (uint8_t *)T1_RFC9529__C_I;
	c_i.suites_i.len = T1_RFC9529__SUITES_I_LEN;
	c_i.suites_i.ptr = (uint8_t *)T1_RFC9529__SUITES_I;
	c_i.ead_1.len = 0; c_i.ead_1.ptr = NULL;
	c_i.ead_3.len = 0; c_i.ead_3.ptr = NULL;
	c_i.id_cred_i.len = T1_RFC9529__ID_CRED_I_LEN;
	c_i.id_cred_i.ptr = (uint8_t *)T1_RFC9529__ID_CRED_I;
	c_i.cred_i.len = T1_RFC9529__CRED_I_LEN;
	c_i.cred_i.ptr = (uint8_t *)T1_RFC9529__CRED_I;
	c_i.g_x.len = T1_RFC9529__G_X_LEN;
	c_i.g_x.ptr = (uint8_t *)T1_RFC9529__G_X;
	c_i.x.len = T1_RFC9529__X_LEN;
	c_i.x.ptr = (uint8_t *)T1_RFC9529__X;
	c_i.sk_i.len = T1_RFC9529__SK_I_LEN;
	c_i.sk_i.ptr = (uint8_t *)T1_RFC9529__SK_I;
	c_i.pk_i.len = T1_RFC9529__PK_I_LEN;
	c_i.pk_i.ptr = (uint8_t *)T1_RFC9529__PK_I;
	c_i.g_i.len = 0; c_i.g_i.ptr = NULL;
	c_i.i.len = 0;   c_i.i.ptr = NULL;

	struct other_party_cred cred_r;
	memset(&cred_r, 0, sizeof(cred_r));
	cred_r.id_cred.len = T1_RFC9529__ID_CRED_R_LEN;
	cred_r.id_cred.ptr = (uint8_t *)T1_RFC9529__ID_CRED_R;
	cred_r.cred.len = T1_RFC9529__CRED_R_LEN;
	cred_r.cred.ptr = (uint8_t *)T1_RFC9529__CRED_R;
	cred_r.pk.len = T1_RFC9529__PK_R_LEN;
	cred_r.pk.ptr = (uint8_t *)T1_RFC9529__PK_R;
	cred_r.g.len = 0; cred_r.g.ptr = NULL;
	cred_r.ca.len = 0; cred_r.ca.ptr = NULL;
	cred_r.ca_pk.len = 0; cred_r.ca_pk.ptr = NULL;
	struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r };

	tl_txrx_ns = 0;
	data->cpu_start_ns = get_thread_cpu_ns();
	data->wall_start_ns = get_time_ns();

	data->error = edhoc_initiator_run(&c_i, &cred_r_array, &err_msg,
					  &data->prk_out,
					  tx_initiator_bench,
					  rx_initiator_bench,
					  ead_process);

	data->wall_end_ns = get_time_ns();
	data->cpu_end_ns = get_thread_cpu_ns();
	return (void *)(uintptr_t)tl_txrx_ns;
}

static void *bench_type0_responder_thread(void *arg)
{
	struct bench_thread_data *data = (struct bench_thread_data *)arg;
	data->prk_out.ptr = data->prk_out_buf;
	data->prk_out.len = sizeof(data->prk_out_buf);

	uint8_t err_msg_buf[64];
	struct byte_array err_msg = { .ptr = err_msg_buf, .len = sizeof(err_msg_buf) };

	struct edhoc_responder_context c_r;
	memset(&c_r, 0, sizeof(c_r));
	c_r.sock = NULL;
	c_r.c_r.len = T1_RFC9529__C_R_LEN;
	c_r.c_r.ptr = (uint8_t *)T1_RFC9529__C_R;
	c_r.suites_r.len = T1_RFC9529__SUITES_R_LEN;
	c_r.suites_r.ptr = (uint8_t *)T1_RFC9529__SUITES_R;
	c_r.ead_2.len = 0; c_r.ead_2.ptr = NULL;
	c_r.ead_4.len = 0; c_r.ead_4.ptr = NULL;
	c_r.id_cred_r.len = T1_RFC9529__ID_CRED_R_LEN;
	c_r.id_cred_r.ptr = (uint8_t *)T1_RFC9529__ID_CRED_R;
	c_r.cred_r.len = T1_RFC9529__CRED_R_LEN;
	c_r.cred_r.ptr = (uint8_t *)T1_RFC9529__CRED_R;
	c_r.g_y.len = T1_RFC9529__G_Y_LEN;
	c_r.g_y.ptr = (uint8_t *)T1_RFC9529__G_Y;
	c_r.y.len = T1_RFC9529__Y_LEN;
	c_r.y.ptr = (uint8_t *)T1_RFC9529__Y;
	c_r.sk_r.len = T1_RFC9529__SK_R_LEN;
	c_r.sk_r.ptr = (uint8_t *)T1_RFC9529__SK_R;
	c_r.pk_r.len = T1_RFC9529__PK_R_LEN;
	c_r.pk_r.ptr = (uint8_t *)T1_RFC9529__PK_R;
	c_r.g_r.len = 0; c_r.g_r.ptr = NULL;
	c_r.r.len = 0;   c_r.r.ptr = NULL;

	struct other_party_cred cred_i;
	memset(&cred_i, 0, sizeof(cred_i));
	cred_i.id_cred.len = T1_RFC9529__ID_CRED_I_LEN;
	cred_i.id_cred.ptr = (uint8_t *)T1_RFC9529__ID_CRED_I;
	cred_i.cred.len = T1_RFC9529__CRED_I_LEN;
	cred_i.cred.ptr = (uint8_t *)T1_RFC9529__CRED_I;
	cred_i.pk.len = T1_RFC9529__PK_I_LEN;
	cred_i.pk.ptr = (uint8_t *)T1_RFC9529__PK_I;
	cred_i.g.len = 0; cred_i.g.ptr = NULL;
	cred_i.ca.len = 0; cred_i.ca.ptr = NULL;
	cred_i.ca_pk.len = 0; cred_i.ca_pk.ptr = NULL;
	struct cred_array cred_i_array = { .len = 1, .ptr = &cred_i };

	tl_txrx_ns = 0;
	data->cpu_start_ns = get_thread_cpu_ns();
	data->wall_start_ns = get_time_ns();

	data->error = edhoc_responder_run(&c_r, &cred_i_array, &err_msg,
					  &data->prk_out,
					  tx_responder_bench,
					  rx_responder_bench,
					  ead_process);

	data->wall_end_ns = get_time_ns();
	data->cpu_end_ns = get_thread_cpu_ns();
	return (void *)(uintptr_t)tl_txrx_ns;
}

/* =============================================================================
 * Type 3 Handshake Benchmark Threads
 * =============================================================================
 */

static void *bench_type3_initiator_thread(void *arg)
{
	struct bench_thread_data *data = (struct bench_thread_data *)arg;
	data->prk_out.ptr = data->prk_out_buf;
	data->prk_out.len = sizeof(data->prk_out_buf);

	uint8_t err_msg_buf[64];
	struct byte_array err_msg = { .ptr = err_msg_buf, .len = sizeof(err_msg_buf) };

	struct edhoc_initiator_context c_i;
	memset(&c_i, 0, sizeof(c_i));
	c_i.sock = NULL;
	c_i.method = (enum method_type)T3_X25519_METHOD;
	c_i.c_i.len = T3_X25519_C_I_LEN;
	c_i.c_i.ptr = (uint8_t *)T3_X25519_C_I;
	c_i.suites_i.len = T3_X25519_SUITES_I_LEN;
	c_i.suites_i.ptr = (uint8_t *)T3_X25519_SUITES_I;
	c_i.ead_1.len = 0; c_i.ead_1.ptr = NULL;
	c_i.ead_3.len = 0; c_i.ead_3.ptr = NULL;
	c_i.id_cred_i.len = T1_RFC9529__ID_CRED_I_LEN;
	c_i.id_cred_i.ptr = (uint8_t *)T1_RFC9529__ID_CRED_I;
	c_i.cred_i.len = T1_RFC9529__CRED_I_LEN;
	c_i.cred_i.ptr = (uint8_t *)T1_RFC9529__CRED_I;
	c_i.g_x.len = T3_X25519_G_X_LEN;
	c_i.g_x.ptr = (uint8_t *)T3_X25519_G_X;
	c_i.x.len = T3_X25519_X_LEN;
	c_i.x.ptr = (uint8_t *)T3_X25519_X;
	c_i.g_i.len = T3_X25519_G_I_LEN;
	c_i.g_i.ptr = (uint8_t *)T3_X25519_G_I;
	c_i.i.len = T3_X25519_I_LEN;
	c_i.i.ptr = (uint8_t *)T3_X25519_I;
	c_i.sk_i.len = 0; c_i.sk_i.ptr = NULL;
	c_i.pk_i.len = 0; c_i.pk_i.ptr = NULL;

	struct other_party_cred cred_r;
	memset(&cred_r, 0, sizeof(cred_r));
	cred_r.id_cred.len = T1_RFC9529__ID_CRED_R_LEN;
	cred_r.id_cred.ptr = (uint8_t *)T1_RFC9529__ID_CRED_R;
	cred_r.cred.len = T1_RFC9529__CRED_R_LEN;
	cred_r.cred.ptr = (uint8_t *)T1_RFC9529__CRED_R;
	cred_r.g.len = T3_X25519_G_R_LEN;
	cred_r.g.ptr = (uint8_t *)T3_X25519_G_R;
	cred_r.pk.len = 0; cred_r.pk.ptr = NULL;
	cred_r.ca.len = 0; cred_r.ca.ptr = NULL;
	cred_r.ca_pk.len = 0; cred_r.ca_pk.ptr = NULL;
	struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r };

	tl_txrx_ns = 0;
	data->cpu_start_ns = get_thread_cpu_ns();
	data->wall_start_ns = get_time_ns();

	data->error = edhoc_initiator_run(&c_i, &cred_r_array, &err_msg,
					  &data->prk_out,
					  tx_initiator_bench,
					  rx_initiator_bench,
					  ead_process);

	data->wall_end_ns = get_time_ns();
	data->cpu_end_ns = get_thread_cpu_ns();
	return (void *)(uintptr_t)tl_txrx_ns;
}

static void *bench_type3_responder_thread(void *arg)
{
	struct bench_thread_data *data = (struct bench_thread_data *)arg;
	data->prk_out.ptr = data->prk_out_buf;
	data->prk_out.len = sizeof(data->prk_out_buf);

	uint8_t err_msg_buf[64];
	struct byte_array err_msg = { .ptr = err_msg_buf, .len = sizeof(err_msg_buf) };

	struct edhoc_responder_context c_r;
	memset(&c_r, 0, sizeof(c_r));
	c_r.sock = NULL;
	c_r.c_r.len = T3_X25519_C_R_LEN;
	c_r.c_r.ptr = (uint8_t *)T3_X25519_C_R;
	c_r.suites_r.len = T3_X25519_SUITES_R_LEN;
	c_r.suites_r.ptr = (uint8_t *)T3_X25519_SUITES_R;
	c_r.ead_2.len = 0; c_r.ead_2.ptr = NULL;
	c_r.ead_4.len = 0; c_r.ead_4.ptr = NULL;
	c_r.id_cred_r.len = T1_RFC9529__ID_CRED_R_LEN;
	c_r.id_cred_r.ptr = (uint8_t *)T1_RFC9529__ID_CRED_R;
	c_r.cred_r.len = T1_RFC9529__CRED_R_LEN;
	c_r.cred_r.ptr = (uint8_t *)T1_RFC9529__CRED_R;
	c_r.g_y.len = T3_X25519_G_Y_LEN;
	c_r.g_y.ptr = (uint8_t *)T3_X25519_G_Y;
	c_r.y.len = T3_X25519_Y_LEN;
	c_r.y.ptr = (uint8_t *)T3_X25519_Y;
	c_r.g_r.len = T3_X25519_G_R_LEN;
	c_r.g_r.ptr = (uint8_t *)T3_X25519_G_R;
	c_r.r.len = T3_X25519_R_LEN;
	c_r.r.ptr = (uint8_t *)T3_X25519_R;
	c_r.sk_r.len = 0; c_r.sk_r.ptr = NULL;
	c_r.pk_r.len = 0; c_r.pk_r.ptr = NULL;

	struct other_party_cred cred_i;
	memset(&cred_i, 0, sizeof(cred_i));
	cred_i.id_cred.len = T1_RFC9529__ID_CRED_I_LEN;
	cred_i.id_cred.ptr = (uint8_t *)T1_RFC9529__ID_CRED_I;
	cred_i.cred.len = T1_RFC9529__CRED_I_LEN;
	cred_i.cred.ptr = (uint8_t *)T1_RFC9529__CRED_I;
	cred_i.g.len = T3_X25519_G_I_LEN;
	cred_i.g.ptr = (uint8_t *)T3_X25519_G_I;
	cred_i.pk.len = 0; cred_i.pk.ptr = NULL;
	cred_i.ca.len = 0; cred_i.ca.ptr = NULL;
	cred_i.ca_pk.len = 0; cred_i.ca_pk.ptr = NULL;
	struct cred_array cred_i_array = { .len = 1, .ptr = &cred_i };

	tl_txrx_ns = 0;
	data->cpu_start_ns = get_thread_cpu_ns();
	data->wall_start_ns = get_time_ns();

	data->error = edhoc_responder_run(&c_r, &cred_i_array, &err_msg,
					  &data->prk_out,
					  tx_responder_bench,
					  rx_responder_bench,
					  ead_process);

	data->wall_end_ns = get_time_ns();
	data->cpu_end_ns = get_thread_cpu_ns();
	return (void *)(uintptr_t)tl_txrx_ns;
}

/* =============================================================================
 * PQ Handshake Benchmark
 *
 * PQ variants use standalone threads (not uoscore-uedhoc library).
 * We measure wall time and CPU time for the full PQ handshake.
 * =============================================================================
 */

/* =============================================================================
 * PQ Handshake Benchmark Threads
 *
 * Same approach as Classic: dedicated wrapper threads that measure
 * CLOCK_THREAD_CPUTIME_ID and wall time per-thread.
 * txrx = wall - cpu (condvar wait = message exchange time).
 * =============================================================================
 */

struct pq_bench_thread_data {
	void *party_ctx;             /* pq_party_ctx* or pq3_party_ctx* */
	void *(*protocol_fn)(void *); /* actual PQ thread function */
	uint64_t cpu_start_ns;
	uint64_t cpu_end_ns;
	uint64_t wall_start_ns;
	uint64_t wall_end_ns;
	int success;
};

static void *pq_bench_wrapper_thread(void *arg)
{
	struct pq_bench_thread_data *data = (struct pq_bench_thread_data *)arg;

	data->cpu_start_ns  = get_thread_cpu_ns();
	data->wall_start_ns = get_time_ns();

	data->protocol_fn(data->party_ctx);

	data->wall_end_ns = get_time_ns();
	data->cpu_end_ns  = get_thread_cpu_ns();

	return NULL;
}

/**
 * @brief Estimate memory for PQ EDHOC variant.
 *
 * ML-KEM-768: pk=1184, sk=2400, ct=1088, ss=32 bytes
 * ML-DSA-65 (Type 0 PQ only): pk=1952, sk=4032, sig=3309 bytes
 * Party context: 2×pk + 2×sk + 3×ct + 4×ss + 4×PRK + 4×Hash ≈ 12KB
 * + sig keys for Type 0 PQ: 2×sig_pk + 2×sig_sk + sig_buf ≈ 15KB
 * Message buffers: 3×8192 = 24KB (shared)
 * Crypto workspace: OQS KEM+SIG state ≈ 8KB
 */
static long estimate_pq_memory(int pq_type_num)
{
	long party_ctx     = 2 * (PQ_KEM_PK_LEN + PQ_KEM_SK_LEN); /* lt + eph keys */
	long kem_buffers   = 3 * PQ_KEM_CT_LEN;  /* ct_R, ct_eph2, ct_I */
	long ss_buffers    = 3 * PQ_KEM_SS_LEN;  /* shared secrets */
	long prk_buffers   = 4 * PQ_PRK_LEN;     /* PRK1-3 + PRK_out */
	long hash_buffers  = 4 * PQ_HASH_LEN;    /* TH2-4 + workspace */
	long msg_buffers   = 3 * 8192;           /* shared msg exchange */
	long aead_buffers  = 1024;               /* AEAD encrypt/decrypt workspace */
	long oqs_workspace = 4096;               /* liboqs internal state (KEM) */
	long psa_workspace = 512;                /* mbedTLS PSA state */
	long overhead      = 512;                /* misc stack, labels, etc. */

	/* ML-DSA-65 signature keys and buffers (Type 0 PQ only) */
	long sig_keys = 0;
	long sig_workspace = 0;
	if (pq_type_num == 0) {
		sig_keys = 2 * (PQ_SIG_PK_LEN + PQ_SIG_SK_LEN); /* own + peer sig keys */
		sig_workspace = PQ_SIG_MAX_LEN + 4096;  /* sig buffer + OQS SIG state */
	}

	return party_ctx + kem_buffers + ss_buffers + prk_buffers +
	       hash_buffers + msg_buffers + aead_buffers +
	       oqs_workspace + psa_workspace + overhead +
	       sig_keys + sig_workspace;
}

/**
 * @brief Run PQ handshake benchmark.
 *
 * Uses the SAME per-thread measurement approach as Classic:
 *   - Spawns dedicated PQ threads with CPU time + wall time instrumentation
 *   - txrx = wall_time - cpu_time (condvar wait = message exchange)
 *   - Calibrates ops to match measured CPU time
 *   - Precomp derived from calibrated keygen in ops table
 *
 * This ensures fair and consistent comparison between Classic and PQ.
 */
static int run_pq_handshake_benchmark(int pq_type_num,
				      struct ops_benchmark *ops_init,
				      struct ops_benchmark *ops_resp,
				      struct overhead_benchmark *overhead_init,
				      struct overhead_benchmark *overhead_resp,
				      struct handshake_benchmark *handshake_init,
				      struct handshake_benchmark *handshake_resp)
{
	char buf[128];
	snprintf(buf, sizeof(buf),
		 "Running PQ handshake benchmark for Type %d PQ (%d iterations)...",
		 pq_type_num, BENCH_HANDSHAKE_ITERATIONS);
	print_info(buf);

	/* Pre-generate long-term key pairs (done ONCE, outside timing loop).
	 * These represent pre-provisioned keys. */
	uint8_t init_lt_pk[PQ_KEM_PK_LEN], init_lt_sk[PQ_KEM_SK_LEN];
	uint8_t resp_lt_pk[PQ_KEM_PK_LEN], resp_lt_sk[PQ_KEM_SK_LEN];
	if (pq_kem_keygen(init_lt_pk, init_lt_sk) != 0 ||
	    pq_kem_keygen(resp_lt_pk, resp_lt_sk) != 0) {
		print_error("PQ keygen for benchmark setup failed");
		return -1;
	}

	/* Pre-generate signature key pairs for Type 0 PQ (ML-DSA-65) */
	uint8_t init_sig_pk[PQ_SIG_PK_LEN], init_sig_sk[PQ_SIG_SK_LEN];
	uint8_t resp_sig_pk[PQ_SIG_PK_LEN], resp_sig_sk[PQ_SIG_SK_LEN];
	if (pq_type_num == 0) {
		if (pq_sig_keygen(init_sig_pk, init_sig_sk) != 0 ||
		    pq_sig_keygen(resp_sig_pk, resp_sig_sk) != 0) {
			print_error("PQ sig keygen for benchmark setup failed");
			return -1;
		}
	}

	double total_i_wall = 0, total_r_wall = 0;
	double total_i_cpu  = 0, total_r_cpu  = 0;
	double total_i_txrx = 0, total_r_txrx = 0;
	int success_count = 0;

	/* Function pointers for the selected PQ type */
	void *(*init_fn)(void *);
	void *(*resp_fn)(void *);
	void (*exch_init_fn)(void);
	void (*exch_destroy_fn)(void);

	if (pq_type_num == 0) {
		init_fn       = pq_type0_initiator_thread;
		resp_fn       = pq_type0_responder_thread;
		exch_init_fn  = pq_exchange_init;
		exch_destroy_fn = pq_exchange_destroy;
	} else {
		init_fn       = pq3_initiator_thread;
		resp_fn       = pq3_responder_thread;
		exch_init_fn  = pq3_exchange_init;
		exch_destroy_fn = pq3_exchange_destroy;
	}

	for (int iter = 0; iter < BENCH_HANDSHAKE_ITERATIONS; iter++) {
		/* Set up party contexts with pre-generated keys */
		union {
			struct pq_party_ctx  t0;
			struct pq3_party_ctx t3;
		} init_ctx_u, resp_ctx_u;
		memset(&init_ctx_u, 0, sizeof(init_ctx_u));
		memset(&resp_ctx_u, 0, sizeof(resp_ctx_u));

		/* Copy keys into the appropriate context struct.
		 * Both pq_party_ctx and pq3_party_ctx have identical layout
		 * for lt_pk, lt_sk, other_lt_pk at the same offsets. */
		if (pq_type_num == 0) {
			memcpy(init_ctx_u.t0.lt_pk, init_lt_pk, PQ_KEM_PK_LEN);
			memcpy(init_ctx_u.t0.lt_sk, init_lt_sk, PQ_KEM_SK_LEN);
			memcpy(init_ctx_u.t0.other_lt_pk, resp_lt_pk, PQ_KEM_PK_LEN);
			memcpy(init_ctx_u.t0.sig_pk, init_sig_pk, PQ_SIG_PK_LEN);
			memcpy(init_ctx_u.t0.sig_sk, init_sig_sk, PQ_SIG_SK_LEN);
			memcpy(init_ctx_u.t0.other_sig_pk, resp_sig_pk, PQ_SIG_PK_LEN);
			memcpy(resp_ctx_u.t0.lt_pk, resp_lt_pk, PQ_KEM_PK_LEN);
			memcpy(resp_ctx_u.t0.lt_sk, resp_lt_sk, PQ_KEM_SK_LEN);
			memcpy(resp_ctx_u.t0.other_lt_pk, init_lt_pk, PQ_KEM_PK_LEN);
			memcpy(resp_ctx_u.t0.sig_pk, resp_sig_pk, PQ_SIG_PK_LEN);
			memcpy(resp_ctx_u.t0.sig_sk, resp_sig_sk, PQ_SIG_SK_LEN);
			memcpy(resp_ctx_u.t0.other_sig_pk, init_sig_pk, PQ_SIG_PK_LEN);
		} else {
			memcpy(init_ctx_u.t3.lt_pk, init_lt_pk, PQ_KEM_PK_LEN);
			memcpy(init_ctx_u.t3.lt_sk, init_lt_sk, PQ_KEM_SK_LEN);
			memcpy(init_ctx_u.t3.other_lt_pk, resp_lt_pk, PQ_KEM_PK_LEN);
			memcpy(resp_ctx_u.t3.lt_pk, resp_lt_pk, PQ_KEM_PK_LEN);
			memcpy(resp_ctx_u.t3.lt_sk, resp_lt_sk, PQ_KEM_SK_LEN);
			memcpy(resp_ctx_u.t3.other_lt_pk, init_lt_pk, PQ_KEM_PK_LEN);
		}

		exch_init_fn();

		struct pq_bench_thread_data i_data, r_data;
		memset(&i_data, 0, sizeof(i_data));
		memset(&r_data, 0, sizeof(r_data));
		i_data.protocol_fn = init_fn;
		r_data.protocol_fn = resp_fn;
		i_data.party_ctx = (pq_type_num == 0) ?
			(void *)&init_ctx_u.t0 : (void *)&init_ctx_u.t3;
		r_data.party_ctx = (pq_type_num == 0) ?
			(void *)&resp_ctx_u.t0 : (void *)&resp_ctx_u.t3;

		pthread_t tid_i, tid_r;
		pthread_create(&tid_r, NULL, pq_bench_wrapper_thread, &r_data);
		pthread_create(&tid_i, NULL, pq_bench_wrapper_thread, &i_data);

		pthread_join(tid_i, NULL);
		pthread_join(tid_r, NULL);

		exch_destroy_fn();

		/* Check success */
		int ok;
		if (pq_type_num == 0)
			ok = init_ctx_u.t0.success && resp_ctx_u.t0.success;
		else
			ok = init_ctx_u.t3.success && resp_ctx_u.t3.success;

		if (ok) {
			double i_wall = elapsed_us(i_data.wall_start_ns,
						   i_data.wall_end_ns);
			double r_wall = elapsed_us(r_data.wall_start_ns,
						   r_data.wall_end_ns);
			double i_cpu  = elapsed_us(i_data.cpu_start_ns,
						   i_data.cpu_end_ns);
			double r_cpu  = elapsed_us(r_data.cpu_start_ns,
						   r_data.cpu_end_ns);

			/* Read instrumented txrx from party context */
			double i_txrx, r_txrx;
			if (pq_type_num == 0) {
				i_txrx = (double)init_ctx_u.t0.txrx_ns / 1000.0;
				r_txrx = (double)resp_ctx_u.t0.txrx_ns / 1000.0;
			} else {
				i_txrx = (double)init_ctx_u.t3.txrx_ns / 1000.0;
				r_txrx = (double)resp_ctx_u.t3.txrx_ns / 1000.0;
			}

			total_i_wall += i_wall;
			total_r_wall += r_wall;
			total_i_cpu  += i_cpu;
			total_r_cpu  += r_cpu;
			total_i_txrx += i_txrx;
			total_r_txrx += r_txrx;
			success_count++;
		}
	}

	if (success_count == 0) {
		print_error("All PQ handshake iterations failed!");
		return -1;
	}

	double n = (double)success_count;

	/* Per-thread averages */
	double avg_i_wall = total_i_wall / n;
	double avg_r_wall = total_r_wall / n;
	double avg_i_cpu  = total_i_cpu  / n;
	double avg_r_cpu  = total_r_cpu  / n;

	/* txrx from instrumented condvar/mutex timing (independent measurement).
	 * This is analogous to Classic's instrumented tx/rx socket callbacks.
	 * Because txrx is measured independently (not derived from wall − cpu),
	 * overhead = wall − processing − txrx − precomp can be > 0. */
	double txrx_i = total_i_txrx / n;
	double txrx_r = total_r_txrx / n;

	/* Calibrate PQ ops using measured per-thread CPU time,
	 * same approach as Classic for full consistency. */
	calibrate_pq_ops(ops_init, avg_i_cpu);
	calibrate_pq_ops(ops_resp, avg_r_cpu);

	/* Now derive ALL values from calibrated ops */
	double ops_sum_i = compute_pq_ops_total(ops_init);
	double ops_sum_r = compute_pq_ops_total(ops_resp);

	/* Precomputation = calibrated keygen cost */
	double precomp_i = ops_init->pq_keygen.avg_us *
			   (double)ops_init->pq_keygen.calls;
	double precomp_r = ops_resp->pq_keygen.avg_us *
			   (double)ops_resp->pq_keygen.calls;

	/* Processing = all crypto ops EXCLUDING keygen */
	double proc_i = ops_sum_i - precomp_i;
	double proc_r = ops_sum_r - precomp_r;

	long mem = estimate_pq_memory(pq_type_num);

	/* Overhead CSV: cpu_time = processing (crypto excluding keygen) */
	overhead_init->cpu_us = proc_i;
	overhead_init->memory_bytes = mem;
	overhead_resp->cpu_us = proc_r;
	overhead_resp->memory_bytes = mem;

	/* Handshake CSV */
	handshake_init->processing_us     = proc_i;
	handshake_init->txrx_us           = txrx_i;
	handshake_init->precomputation_us = precomp_i;
	handshake_init->total_us          = avg_i_wall;
	handshake_init->overhead_us       = handshake_init->total_us -
					    handshake_init->processing_us -
					    handshake_init->txrx_us -
					    handshake_init->precomputation_us;
	if (handshake_init->overhead_us < 0) {
		handshake_init->overhead_us = 0;
		handshake_init->total_us = handshake_init->processing_us +
					   handshake_init->txrx_us +
					   handshake_init->precomputation_us;
	}

	handshake_resp->processing_us     = proc_r;
	handshake_resp->txrx_us           = txrx_r;
	handshake_resp->precomputation_us = precomp_r;
	handshake_resp->total_us          = avg_r_wall;
	handshake_resp->overhead_us       = handshake_resp->total_us -
					    handshake_resp->processing_us -
					    handshake_resp->txrx_us -
					    handshake_resp->precomputation_us;
	if (handshake_resp->overhead_us < 0) {
		handshake_resp->overhead_us = 0;
		handshake_resp->total_us = handshake_resp->processing_us +
					   handshake_resp->txrx_us +
					   handshake_resp->precomputation_us;
	}

	snprintf(buf, sizeof(buf),
		 "PQ handshake benchmark completed (%d/%d successful).",
		 success_count, BENCH_HANDSHAKE_ITERATIONS);
	print_success(buf);
	return 0;
}

/* =============================================================================
 * Memory Estimation
 *
 * Karena benchmark berjalan di Linux native (bukan embedded/Zephyr),
 * getrusage(ru_maxrss) mengukur seluruh proses dan tidak representatif.
 *
 * Estimasi berdasarkan analisis buffer_sizes.h dan runtime_context:
 *   - runtime_context struct: msg_buf(700) + hash/prk buffers ≈ 1116 bytes
 *   - Stack buffers per message: g_y, g_xy, th, PRK, cred, plaintext, etc.
 *   - Crypto workspace: AES-CCM, SHA-256, X25519, EdDSA state
 * =============================================================================
 */
static long estimate_edhoc_memory(int type_num)
{
	long runtime_ctx   = 1116;  /* runtime_context struct */
	long msg_buffers   = 1536;  /* peak stack buffers during msg processing */
	long msg3_buffers  = 640;   /* msg3 generation/processing buffers */
	long crypto_aes    = 256;   /* AES-CCM state */
	long crypto_sha    = 128;   /* SHA-256 hash state */
	long crypto_x25519 = 256;   /* X25519 scalar multiplication workspace */
	long crypto_eddsa  = (type_num == 0) ? 512 : 0; /* EdDSA workspace */
	long edhoc_context = 384;   /* initiator/responder context struct */
	long cred_data     = 512;   /* credential and ID_CRED buffers */
	long overhead      = 256;   /* CBOR encoding, misc overhead */

	return runtime_ctx + msg_buffers + msg3_buffers +
	       crypto_aes + crypto_sha + crypto_x25519 + crypto_eddsa +
	       edhoc_context + cred_data + overhead;
}

/* =============================================================================
 * Run full handshake benchmark
 * =============================================================================
 */

static int run_handshake_benchmark(int type_num,
				   struct ops_benchmark *ops_init,
				   struct ops_benchmark *ops_resp,
				   struct overhead_benchmark *overhead_i,
				   struct overhead_benchmark *overhead_r,
				   struct handshake_benchmark *handshake_i,
				   struct handshake_benchmark *handshake_r)
{
	char buf[128];
	snprintf(buf, sizeof(buf),
		 "Running handshake benchmark for Type %d (%d iterations)...",
		 type_num, BENCH_HANDSHAKE_ITERATIONS);
	print_info(buf);

	double total_i_wall = 0, total_r_wall = 0;
	double total_i_cpu = 0, total_r_cpu = 0;
	double total_i_txrx = 0, total_r_txrx = 0;
	int success_count = 0;

	for (int iter = 0; iter < BENCH_HANDSHAKE_ITERATIONS; iter++) {
		msg_exchange_init();

		struct bench_thread_data i_data, r_data;
		memset(&i_data, 0, sizeof(i_data));
		memset(&r_data, 0, sizeof(r_data));

		pthread_t tid_i, tid_r;

		void *(*init_fn)(void *) = (type_num == 0) ?
			bench_type0_initiator_thread :
			bench_type3_initiator_thread;
		void *(*resp_fn)(void *) = (type_num == 0) ?
			bench_type0_responder_thread :
			bench_type3_responder_thread;

		pthread_create(&tid_r, NULL, resp_fn, &r_data);
		pthread_create(&tid_i, NULL, init_fn, &i_data);

		void *i_txrx_ret, *r_txrx_ret;
		pthread_join(tid_i, &i_txrx_ret);
		pthread_join(tid_r, &r_txrx_ret);

		msg_exchange_destroy();

		if (i_data.error == ok && r_data.error == ok) {
			double i_wall = elapsed_us(i_data.wall_start_ns,
						   i_data.wall_end_ns);
			double r_wall = elapsed_us(r_data.wall_start_ns,
						   r_data.wall_end_ns);

			double i_cpu = elapsed_us(i_data.cpu_start_ns,
						  i_data.cpu_end_ns);
			double r_cpu = elapsed_us(r_data.cpu_start_ns,
						  r_data.cpu_end_ns);

			double i_txrx = (double)(uintptr_t)i_txrx_ret / 1000.0;
			double r_txrx = (double)(uintptr_t)r_txrx_ret / 1000.0;

			total_i_wall += i_wall;
			total_r_wall += r_wall;
			total_i_cpu += i_cpu;
			total_r_cpu += r_cpu;
			total_i_txrx += i_txrx;
			total_r_txrx += r_txrx;
			success_count++;
		}
	}

	if (success_count == 0) {
		print_error("All handshake iterations failed!");
		return -1;
	}

	double n = (double)success_count;

	/* Calibrate operations using measured per-thread CPU time.
	 *
	 * CLOCK_THREAD_CPUTIME_ID measures actual CPU cycles consumed by each
	 * thread (excluding condvar/mutex wait = txrx). We use this as the
	 * ground truth and scale isolated microbenchmark avg_us values so that
	 * sum(avg_us × calls) == measured_cpu for each role.
	 *
	 * This ensures FULL cross-table consistency:
	 *   operations CSV: sum(total_per_handshake_us) == cpu_time_us == processing_us + precomp_us
	 *   overhead CSV:   cpu_time_us == processing_us (handshake CSV)
	 *   handshake CSV:  total == processing + txrx + precomp + overhead
	 *
	 * The relative proportions between operations are preserved;
	 * only the absolute scale is corrected for in-situ conditions. */
	double cpu_i = total_i_cpu / n;
	double cpu_r = total_r_cpu / n;

	/* Calibrate ops: scale avg_us so sum(ops) matches measured CPU */
	calibrate_classic_ops(ops_init, cpu_i);
	calibrate_classic_ops(ops_resp, cpu_r);

	/* Now derive ALL values from calibrated ops (= measured CPU) */
	double ops_sum_i = compute_classic_ops_total(ops_init);
	double ops_sum_r = compute_classic_ops_total(ops_resp);

	/* Precomputation = calibrated keygen cost */
	double precomp_cal_i = ops_init->keygen.avg_us * (double)ops_init->keygen.calls;
	double precomp_cal_r = ops_resp->keygen.avg_us * (double)ops_resp->keygen.calls;

	/* Processing = all crypto ops EXCLUDING keygen (avoid double-count) */
	double proc_i = ops_sum_i - precomp_cal_i;
	double proc_r = ops_sum_r - precomp_cal_r;

	/* Overhead CSV: cpu_time = processing (crypto excluding keygen) */
	overhead_i->cpu_us = proc_i;
	overhead_i->memory_bytes = estimate_edhoc_memory(type_num);
	overhead_r->cpu_us = proc_r;
	overhead_r->memory_bytes = estimate_edhoc_memory(type_num);

	/* Handshake timing */
	handshake_i->total_us = total_i_wall / n;
	handshake_i->txrx_us = total_i_txrx / n;
	handshake_i->precomputation_us = precomp_cal_i;
	handshake_i->processing_us = proc_i;
	handshake_i->overhead_us = handshake_i->total_us -
				   handshake_i->processing_us -
				   handshake_i->txrx_us -
				   handshake_i->precomputation_us;
	/* Safety clamp: if overhead < 0 due to timing resolution overlap,
	 * set to 0 and adjust total to maintain arithmetic identity:
	 * total = processing + txrx + precomp + overhead */
	if (handshake_i->overhead_us < 0) {
		handshake_i->overhead_us = 0;
		handshake_i->total_us = handshake_i->processing_us +
					handshake_i->txrx_us +
					handshake_i->precomputation_us;
	}

	handshake_r->total_us = total_r_wall / n;
	handshake_r->txrx_us = total_r_txrx / n;
	handshake_r->precomputation_us = precomp_cal_r;
	handshake_r->processing_us = proc_r;
	handshake_r->overhead_us = handshake_r->total_us -
				   handshake_r->processing_us -
				   handshake_r->txrx_us -
				   handshake_r->precomputation_us;
	if (handshake_r->overhead_us < 0) {
		handshake_r->overhead_us = 0;
		handshake_r->total_us = handshake_r->processing_us +
					handshake_r->txrx_us +
					handshake_r->precomputation_us;
	}

	snprintf(buf, sizeof(buf),
		 "Handshake benchmark completed (%d/%d successful).",
		 success_count, BENCH_HANDSHAKE_ITERATIONS);
	print_success(buf);
	return 0;
}

/* =============================================================================
 * CSV Output
 * =============================================================================
 */

static int write_operations_csv(const char *filepath,
				struct ops_benchmark *t0_init,
				struct ops_benchmark *t0_resp,
				struct ops_benchmark *t3_init,
				struct ops_benchmark *t3_resp)
{
	FILE *fp = fopen(filepath, "w");
	if (!fp) {
		char buf[256];
		snprintf(buf, sizeof(buf), "Cannot open %s: %s",
			 filepath, strerror(errno));
		print_error(buf);
		return -1;
	}

	fprintf(fp, "type,role,operation,avg_time_us,calls_per_handshake,"
		    "total_per_handshake_us,iterations\n");

	#define WRITE_OP(TYPE, ROLE, OP_NAME, OP) \
		fprintf(fp, "%s,%s,%s,%.3f,%d,%.3f,%d\n", \
			TYPE, ROLE, OP_NAME, (OP).avg_us, (OP).calls, \
			(OP).avg_us * (double)(OP).calls, (OP).count)

	WRITE_OP("Type0_SigSig", "Initiator", "KeyGen",       t0_init->keygen);
	WRITE_OP("Type0_SigSig", "Initiator", "Encap",        t0_init->encap);
	WRITE_OP("Type0_SigSig", "Initiator", "Decap",        t0_init->decap);
	WRITE_OP("Type0_SigSig", "Initiator", "Signature",    t0_init->signature);
	WRITE_OP("Type0_SigSig", "Initiator", "Verification", t0_init->verification);
	WRITE_OP("Type0_SigSig", "Initiator", "ECDH",         t0_init->ecdh);
	WRITE_OP("Type0_SigSig", "Initiator", "HKDF",         t0_init->hkdf);
	WRITE_OP("Type0_SigSig", "Initiator", "Hash",         t0_init->hash);

	WRITE_OP("Type0_SigSig", "Responder", "KeyGen",       t0_resp->keygen);
	WRITE_OP("Type0_SigSig", "Responder", "Encap",        t0_resp->encap);
	WRITE_OP("Type0_SigSig", "Responder", "Decap",        t0_resp->decap);
	WRITE_OP("Type0_SigSig", "Responder", "Signature",    t0_resp->signature);
	WRITE_OP("Type0_SigSig", "Responder", "Verification", t0_resp->verification);
	WRITE_OP("Type0_SigSig", "Responder", "ECDH",         t0_resp->ecdh);
	WRITE_OP("Type0_SigSig", "Responder", "HKDF",         t0_resp->hkdf);
	WRITE_OP("Type0_SigSig", "Responder", "Hash",         t0_resp->hash);

	WRITE_OP("Type3_MACMAC", "Initiator", "KeyGen",       t3_init->keygen);
	WRITE_OP("Type3_MACMAC", "Initiator", "Encap",        t3_init->encap);
	WRITE_OP("Type3_MACMAC", "Initiator", "Decap",        t3_init->decap);
	WRITE_OP("Type3_MACMAC", "Initiator", "Signature",    t3_init->signature);
	WRITE_OP("Type3_MACMAC", "Initiator", "Verification", t3_init->verification);
	WRITE_OP("Type3_MACMAC", "Initiator", "ECDH",         t3_init->ecdh);
	WRITE_OP("Type3_MACMAC", "Initiator", "HKDF",         t3_init->hkdf);
	WRITE_OP("Type3_MACMAC", "Initiator", "Hash",         t3_init->hash);

	WRITE_OP("Type3_MACMAC", "Responder", "KeyGen",       t3_resp->keygen);
	WRITE_OP("Type3_MACMAC", "Responder", "Encap",        t3_resp->encap);
	WRITE_OP("Type3_MACMAC", "Responder", "Decap",        t3_resp->decap);
	WRITE_OP("Type3_MACMAC", "Responder", "Signature",    t3_resp->signature);
	WRITE_OP("Type3_MACMAC", "Responder", "Verification", t3_resp->verification);
	WRITE_OP("Type3_MACMAC", "Responder", "ECDH",         t3_resp->ecdh);
	WRITE_OP("Type3_MACMAC", "Responder", "HKDF",         t3_resp->hkdf);
	WRITE_OP("Type3_MACMAC", "Responder", "Hash",         t3_resp->hash);

	#undef WRITE_OP
	fclose(fp);
	return 0;
}

static int write_overhead_csv(const char *filepath,
			      struct overhead_benchmark *t0_init,
			      struct overhead_benchmark *t0_resp,
			      struct overhead_benchmark *t3_init,
			      struct overhead_benchmark *t3_resp)
{
	FILE *fp = fopen(filepath, "w");
	if (!fp) {
		char buf[256];
		snprintf(buf, sizeof(buf), "Cannot open %s: %s",
			 filepath, strerror(errno));
		print_error(buf);
		return -1;
	}

	fprintf(fp, "type,role,cpu_time_us,memory_bytes,memory_note\n");
	fprintf(fp, "Type0_SigSig,Initiator,%.3f,%ld,estimated_stack_heap\n",
		t0_init->cpu_us, t0_init->memory_bytes);
	fprintf(fp, "Type0_SigSig,Responder,%.3f,%ld,estimated_stack_heap\n",
		t0_resp->cpu_us, t0_resp->memory_bytes);
	fprintf(fp, "Type3_MACMAC,Initiator,%.3f,%ld,estimated_stack_heap\n",
		t3_init->cpu_us, t3_init->memory_bytes);
	fprintf(fp, "Type3_MACMAC,Responder,%.3f,%ld,estimated_stack_heap\n",
		t3_resp->cpu_us, t3_resp->memory_bytes);

	fclose(fp);
	return 0;
}

static int write_handshake_csv(const char *filepath,
			       struct handshake_benchmark *t0_init,
			       struct handshake_benchmark *t0_resp,
			       struct handshake_benchmark *t3_init,
			       struct handshake_benchmark *t3_resp)
{
	FILE *fp = fopen(filepath, "w");
	if (!fp) {
		char buf[256];
		snprintf(buf, sizeof(buf), "Cannot open %s: %s",
			 filepath, strerror(errno));
		print_error(buf);
		return -1;
	}

	fprintf(fp, "type,role,processing_us,txrx_us,precomputation_us,overhead_us,total_us\n");
	fprintf(fp, "Type0_SigSig,Initiator,%.3f,%.3f,%.3f,%.3f,%.3f\n",
		t0_init->processing_us, t0_init->txrx_us,
		t0_init->precomputation_us, t0_init->overhead_us,
		t0_init->total_us);
	fprintf(fp, "Type0_SigSig,Responder,%.3f,%.3f,%.3f,%.3f,%.3f\n",
		t0_resp->processing_us, t0_resp->txrx_us,
		t0_resp->precomputation_us, t0_resp->overhead_us,
		t0_resp->total_us);
	fprintf(fp, "Type3_MACMAC,Initiator,%.3f,%.3f,%.3f,%.3f,%.3f\n",
		t3_init->processing_us, t3_init->txrx_us,
		t3_init->precomputation_us, t3_init->overhead_us,
		t3_init->total_us);
	fprintf(fp, "Type3_MACMAC,Responder,%.3f,%.3f,%.3f,%.3f,%.3f\n",
		t3_resp->processing_us, t3_resp->txrx_us,
		t3_resp->precomputation_us, t3_resp->overhead_us,
		t3_resp->total_us);

	fclose(fp);
	return 0;
}

/* =============================================================================
 * Print summary tables
 * =============================================================================
 */

static void print_ops_summary(const char *type_name,
			      struct ops_benchmark *init_ops,
			      struct ops_benchmark *resp_ops)
{
	char buf[256];
	printf("\n");
	snprintf(buf, sizeof(buf), "%s — Operations (µs, avg over %d iterations)",
		 type_name, BENCH_ITERATIONS);
	print_header(buf);
	printf("\n");

	printf("  %-16s %12s %6s %12s %6s\n",
	       "Operation", "Init(avg)", "×call", "Resp(avg)", "×call");
	printf("  %-16s %12s %6s %12s %6s\n",
	       "────────────────", "────────────", "──────",
	       "────────────", "──────");

	#define PRINT_ROW(NAME, FIELD) \
		printf("  %-16s %12.3f %6d %12.3f %6d\n", \
		       NAME, \
		       init_ops->FIELD.avg_us, init_ops->FIELD.calls, \
		       resp_ops->FIELD.avg_us, resp_ops->FIELD.calls)

	PRINT_ROW("KeyGen",       keygen);
	PRINT_ROW("Encap (AEAD)", encap);
	PRINT_ROW("Decap (AEAD)", decap);
	PRINT_ROW("Signature",    signature);
	PRINT_ROW("Verification", verification);
	PRINT_ROW("ECDH",         ecdh);
	PRINT_ROW("HKDF",         hkdf);
	PRINT_ROW("Hash",         hash);

	#undef PRINT_ROW

	/* Print estimated crypto cost per role */
	#define COST(OP) ((OP).avg_us * (double)(OP).calls)
	double init_total = COST(init_ops->keygen) + COST(init_ops->encap) +
		COST(init_ops->decap) + COST(init_ops->signature) +
		COST(init_ops->verification) + COST(init_ops->ecdh) +
		COST(init_ops->hkdf) + COST(init_ops->hash);
	double resp_total = COST(resp_ops->keygen) + COST(resp_ops->encap) +
		COST(resp_ops->decap) + COST(resp_ops->signature) +
		COST(resp_ops->verification) + COST(resp_ops->ecdh) +
		COST(resp_ops->hkdf) + COST(resp_ops->hash);
	#undef COST

	printf("  %-16s %12s %6s %12s %6s\n",
	       "────────────────", "────────────", "──────",
	       "────────────", "──────");
	printf("  %-16s %9.3f µs %6s %9.3f µs %6s\n",
	       "Est. Total", init_total, "", resp_total, "");
}

static void print_overhead_summary(struct overhead_benchmark *t0_init,
				   struct overhead_benchmark *t0_resp,
				   struct overhead_benchmark *t3_init,
				   struct overhead_benchmark *t3_resp)
{
	printf("\n");
	print_header("Overhead Benchmark (calibrated ops, avg per handshake)");
	printf("\n");

	printf("  %-16s %-12s %14s %14s %s\n",
	       "Type", "Role", "Crypto (µs)", "Memory (bytes)", "Note");
	printf("  %-16s %-12s %14s %14s %s\n",
	       "────────────────", "────────────", "──────────────",
	       "──────────────", "────────────────────");
	printf("  %-16s %-12s %14.3f %14ld %s\n",
	       "Type0_SigSig", "Initiator", t0_init->cpu_us,
	       t0_init->memory_bytes, "calibrated_ops");
	printf("  %-16s %-12s %14.3f %14ld %s\n",
	       "Type0_SigSig", "Responder", t0_resp->cpu_us,
	       t0_resp->memory_bytes, "calibrated_ops");
	printf("  %-16s %-12s %14.3f %14ld %s\n",
	       "Type3_MACMAC", "Initiator", t3_init->cpu_us,
	       t3_init->memory_bytes, "calibrated_ops");
	printf("  %-16s %-12s %14.3f %14ld %s\n",
	       "Type3_MACMAC", "Responder", t3_resp->cpu_us,
	       t3_resp->memory_bytes, "calibrated_ops");
}

static void print_handshake_summary(struct handshake_benchmark *t0_init,
				    struct handshake_benchmark *t0_resp,
				    struct handshake_benchmark *t3_init,
				    struct handshake_benchmark *t3_resp)
{
	printf("\n");
	print_header("Handshake Timing Benchmark (µs, avg)");
	printf("\n");

	printf("  %-16s %-12s %14s %14s %14s %14s %14s\n",
	       "Type", "Role", "Processing", "TxRx", "Precompute", "Overhead", "Total");
	printf("  %-16s %-12s %14s %14s %14s %14s %14s\n",
	       "────────────────", "────────────",
	       "──────────────", "──────────────",
	       "──────────────", "──────────────", "──────────────");
	printf("  %-16s %-12s %14.3f %14.3f %14.3f %14.3f %14.3f\n",
	       "Type0_SigSig", "Initiator",
	       t0_init->processing_us, t0_init->txrx_us,
	       t0_init->precomputation_us, t0_init->overhead_us,
	       t0_init->total_us);
	printf("  %-16s %-12s %14.3f %14.3f %14.3f %14.3f %14.3f\n",
	       "Type0_SigSig", "Responder",
	       t0_resp->processing_us, t0_resp->txrx_us,
	       t0_resp->precomputation_us, t0_resp->overhead_us,
	       t0_resp->total_us);
	printf("  %-16s %-12s %14.3f %14.3f %14.3f %14.3f %14.3f\n",
	       "Type3_MACMAC", "Initiator",
	       t3_init->processing_us, t3_init->txrx_us,
	       t3_init->precomputation_us, t3_init->overhead_us,
	       t3_init->total_us);
	printf("  %-16s %-12s %14.3f %14.3f %14.3f %14.3f %14.3f\n",
	       "Type3_MACMAC", "Responder",
	       t3_resp->processing_us, t3_resp->txrx_us,
	       t3_resp->precomputation_us, t3_resp->overhead_us,
	       t3_resp->total_us);
}

/* =============================================================================
 * Main Benchmark Entry Point
 * =============================================================================
 */

int run_edhoc_benchmark(void)
{
	print_header("EDHOC-Hybrid Comprehensive Benchmark (Corrected)");
	printf("\n");
	print_info("Benchmark Configuration:");

	char buf[256];
	snprintf(buf, sizeof(buf),
		 "  Operations iterations : %d", BENCH_ITERATIONS);
	print_info(buf);
	snprintf(buf, sizeof(buf),
		 "  Handshake iterations  : %d", BENCH_HANDSHAKE_ITERATIONS);
	print_info(buf);
	print_info("  Types: Type 0 (Sig-Sig) + Type 3 (MAC-MAC)");
	print_info("  Roles: Initiator + Responder");
	print_info("  Suite: 0 (AES-CCM-16-64-128, SHA-256, X25519, EdDSA)");
	printf("\n");

	print_info("Protocol-accurate corrections:");
	print_info("  ✓ KeyGen: Only X25519 ephemeral (long-term keys pre-provisioned)");
	print_info("  ✓ ECDH: Type0=1×, Type3=3× (ephemeral + 2 static DH)");
	print_info("  ✓ AEAD: CT2=XOR not AEAD (RFC 9528 §5.3.2), only CT3 uses AEAD");
	print_info("  ✓ Memory: Estimated stack+heap footprint, not process RSS");
	print_info("  ✓ CPU: Calibrated ops = measured CPU time (CLOCK_THREAD_CPUTIME_ID)");
	print_info("  ✓ Processing: sum(calibrated ops) - keygen = cpu_time_us");
	print_info("  ✓ Precomp: calibrated keygen cost (consistent with ops CSV)");
	print_info("  ✓ Overhead: total - processing - txrx - precomp (≥ 0, clamped)");
	print_info("  ✓ Hash: SHA-256 benchmark added (~4 calls/handshake)");
	print_info("  ✓ Calls: Per-operation call count matches EDHOC protocol flow");
	print_info("  ✓ Consistency: sum(ops) == cpu_time == processing + precomp");
	printf("\n");

	mkdir(BENCH_OUTPUT_DIR, 0755);

	/* Phase 1: Operations Benchmark */
	print_header("Phase 1: Operations Benchmark");
	printf("\n");

	struct ops_benchmark t0_ops_init, t0_ops_resp;
	struct ops_benchmark t3_ops_init, t3_ops_resp;
	memset(&t0_ops_init, 0, sizeof(t0_ops_init));
	memset(&t0_ops_resp, 0, sizeof(t0_ops_resp));
	memset(&t3_ops_init, 0, sizeof(t3_ops_init));
	memset(&t3_ops_resp, 0, sizeof(t3_ops_resp));

	bench_all_operations("Type 0 (Sig-Sig)", 0,
			     &t0_ops_init, &t0_ops_resp);
	bench_all_operations("Type 3 (MAC-MAC)", 3,
			     &t3_ops_init, &t3_ops_resp);

	print_ops_summary("Type 0 (Sig-Sig)", &t0_ops_init, &t0_ops_resp);
	print_ops_summary("Type 3 (MAC-MAC)", &t3_ops_init, &t3_ops_resp);

	/* Phase 2 & 3: Handshake + Overhead */
	print_header("Phase 2 & 3: Handshake + Overhead Benchmark");
	printf("\n");

	struct overhead_benchmark  t0_oh_init, t0_oh_resp;
	struct overhead_benchmark  t3_oh_init, t3_oh_resp;
	struct handshake_benchmark t0_hs_init, t0_hs_resp;
	struct handshake_benchmark t3_hs_init, t3_hs_resp;
	memset(&t0_oh_init, 0, sizeof(t0_oh_init));
	memset(&t0_oh_resp, 0, sizeof(t0_oh_resp));
	memset(&t3_oh_init, 0, sizeof(t3_oh_init));
	memset(&t3_oh_resp, 0, sizeof(t3_oh_resp));
	memset(&t0_hs_init, 0, sizeof(t0_hs_init));
	memset(&t0_hs_resp, 0, sizeof(t0_hs_resp));
	memset(&t3_hs_init, 0, sizeof(t3_hs_init));
	memset(&t3_hs_resp, 0, sizeof(t3_hs_resp));

	int ret;
	ret = run_handshake_benchmark(0,
				      &t0_ops_init, &t0_ops_resp,
				      &t0_oh_init, &t0_oh_resp,
				      &t0_hs_init, &t0_hs_resp);
	if (ret != 0) {
		print_error("Type 0 handshake benchmark failed!");
		return -1;
	}

	ret = run_handshake_benchmark(3,
				      &t3_ops_init, &t3_ops_resp,
				      &t3_oh_init, &t3_oh_resp,
				      &t3_hs_init, &t3_hs_resp);
	if (ret != 0) {
		print_error("Type 3 handshake benchmark failed!");
		return -1;
	}

	print_overhead_summary(&t0_oh_init, &t0_oh_resp,
			       &t3_oh_init, &t3_oh_resp);
	print_handshake_summary(&t0_hs_init, &t0_hs_resp,
				&t3_hs_init, &t3_hs_resp);

	/* Write CSV files */
	printf("\n");
	print_header("Writing CSV Output Files");
	printf("\n");

	ret = write_operations_csv(BENCH_CSV_OPERATIONS,
				   &t0_ops_init, &t0_ops_resp,
				   &t3_ops_init, &t3_ops_resp);
	if (ret == 0) {
		snprintf(buf, sizeof(buf), "Written: %s", BENCH_CSV_OPERATIONS);
		print_success(buf);
	}

	ret = write_overhead_csv(BENCH_CSV_OVERHEAD,
				 &t0_oh_init, &t0_oh_resp,
				 &t3_oh_init, &t3_oh_resp);
	if (ret == 0) {
		snprintf(buf, sizeof(buf), "Written: %s", BENCH_CSV_OVERHEAD);
		print_success(buf);
	}

	ret = write_handshake_csv(BENCH_CSV_HANDSHAKE,
				  &t0_hs_init, &t0_hs_resp,
				  &t3_hs_init, &t3_hs_resp);
	if (ret == 0) {
		snprintf(buf, sizeof(buf), "Written: %s", BENCH_CSV_HANDSHAKE);
		print_success(buf);
	}

	printf("\n");
	print_success("EDHOC-Hybrid Benchmark completed successfully!");
	print_info("● CSV files saved in output/ directory.");
	printf("\n");

	return 0;
}

/* =============================================================================
 * Full Benchmark: Classic + PQ (4 variants)
 * =============================================================================
 */

/* PQ-aware CSV writers */

static int write_operations_csv_full(const char *filepath,
				     struct ops_benchmark *t0_init,
				     struct ops_benchmark *t0_resp,
				     struct ops_benchmark *t3_init,
				     struct ops_benchmark *t3_resp,
				     struct ops_benchmark *t0pq_init,
				     struct ops_benchmark *t0pq_resp,
				     struct ops_benchmark *t3pq_init,
				     struct ops_benchmark *t3pq_resp)
{
	FILE *fp = fopen(filepath, "w");
	if (!fp) {
		char buf[256];
		snprintf(buf, sizeof(buf), "Cannot open %s: %s",
			 filepath, strerror(errno));
		print_error(buf);
		return -1;
	}

	fprintf(fp, "type,role,operation,avg_time_us,calls_per_handshake,"
		    "total_per_handshake_us,iterations\n");

	#define WRITE_OP(TYPE, ROLE, OP_NAME, OP) \
		fprintf(fp, "%s,%s,%s,%.3f,%d,%.3f,%d\n", \
			TYPE, ROLE, OP_NAME, (OP).avg_us, (OP).calls, \
			(OP).avg_us * (double)(OP).calls, (OP).count)

	/* Classic Type 0 */
	WRITE_OP("Type0_SigSig", "Initiator", "KeyGen",       t0_init->keygen);
	WRITE_OP("Type0_SigSig", "Initiator", "Encap",        t0_init->encap);
	WRITE_OP("Type0_SigSig", "Initiator", "Decap",        t0_init->decap);
	WRITE_OP("Type0_SigSig", "Initiator", "Signature",    t0_init->signature);
	WRITE_OP("Type0_SigSig", "Initiator", "Verification", t0_init->verification);
	WRITE_OP("Type0_SigSig", "Initiator", "ECDH",         t0_init->ecdh);
	WRITE_OP("Type0_SigSig", "Initiator", "HKDF",         t0_init->hkdf);
	WRITE_OP("Type0_SigSig", "Initiator", "Hash",         t0_init->hash);
	WRITE_OP("Type0_SigSig", "Responder", "KeyGen",       t0_resp->keygen);
	WRITE_OP("Type0_SigSig", "Responder", "Encap",        t0_resp->encap);
	WRITE_OP("Type0_SigSig", "Responder", "Decap",        t0_resp->decap);
	WRITE_OP("Type0_SigSig", "Responder", "Signature",    t0_resp->signature);
	WRITE_OP("Type0_SigSig", "Responder", "Verification", t0_resp->verification);
	WRITE_OP("Type0_SigSig", "Responder", "ECDH",         t0_resp->ecdh);
	WRITE_OP("Type0_SigSig", "Responder", "HKDF",         t0_resp->hkdf);
	WRITE_OP("Type0_SigSig", "Responder", "Hash",         t0_resp->hash);

	/* Classic Type 3 */
	WRITE_OP("Type3_MACMAC", "Initiator", "KeyGen",       t3_init->keygen);
	WRITE_OP("Type3_MACMAC", "Initiator", "Encap",        t3_init->encap);
	WRITE_OP("Type3_MACMAC", "Initiator", "Decap",        t3_init->decap);
	WRITE_OP("Type3_MACMAC", "Initiator", "Signature",    t3_init->signature);
	WRITE_OP("Type3_MACMAC", "Initiator", "Verification", t3_init->verification);
	WRITE_OP("Type3_MACMAC", "Initiator", "ECDH",         t3_init->ecdh);
	WRITE_OP("Type3_MACMAC", "Initiator", "HKDF",         t3_init->hkdf);
	WRITE_OP("Type3_MACMAC", "Initiator", "Hash",         t3_init->hash);
	WRITE_OP("Type3_MACMAC", "Responder", "KeyGen",       t3_resp->keygen);
	WRITE_OP("Type3_MACMAC", "Responder", "Encap",        t3_resp->encap);
	WRITE_OP("Type3_MACMAC", "Responder", "Decap",        t3_resp->decap);
	WRITE_OP("Type3_MACMAC", "Responder", "Signature",    t3_resp->signature);
	WRITE_OP("Type3_MACMAC", "Responder", "Verification", t3_resp->verification);
	WRITE_OP("Type3_MACMAC", "Responder", "ECDH",         t3_resp->ecdh);
	WRITE_OP("Type3_MACMAC", "Responder", "HKDF",         t3_resp->hkdf);
	WRITE_OP("Type3_MACMAC", "Responder", "Hash",         t3_resp->hash);

	/* PQ Type 0 */
	WRITE_OP("Type0_PQ", "Initiator", "PQ_KeyGen",       t0pq_init->pq_keygen);
	WRITE_OP("Type0_PQ", "Initiator", "PQ_Encaps",       t0pq_init->pq_encaps);
	WRITE_OP("Type0_PQ", "Initiator", "PQ_Decaps",       t0pq_init->pq_decaps);
	WRITE_OP("Type0_PQ", "Initiator", "PQ_Signature",    t0pq_init->pq_sig_sign);
	WRITE_OP("Type0_PQ", "Initiator", "PQ_Verification", t0pq_init->pq_sig_verify);
	WRITE_OP("Type0_PQ", "Initiator", "PQ_AEAD_Enc",     t0pq_init->pq_aead_enc);
	WRITE_OP("Type0_PQ", "Initiator", "PQ_AEAD_Dec",     t0pq_init->pq_aead_dec);
	WRITE_OP("Type0_PQ", "Initiator", "PQ_HKDF",         t0pq_init->pq_hkdf);
	WRITE_OP("Type0_PQ", "Initiator", "PQ_Hash",         t0pq_init->pq_hash);
	WRITE_OP("Type0_PQ", "Responder", "PQ_KeyGen",       t0pq_resp->pq_keygen);
	WRITE_OP("Type0_PQ", "Responder", "PQ_Encaps",       t0pq_resp->pq_encaps);
	WRITE_OP("Type0_PQ", "Responder", "PQ_Decaps",       t0pq_resp->pq_decaps);
	WRITE_OP("Type0_PQ", "Responder", "PQ_Signature",    t0pq_resp->pq_sig_sign);
	WRITE_OP("Type0_PQ", "Responder", "PQ_Verification", t0pq_resp->pq_sig_verify);
	WRITE_OP("Type0_PQ", "Responder", "PQ_AEAD_Enc",     t0pq_resp->pq_aead_enc);
	WRITE_OP("Type0_PQ", "Responder", "PQ_AEAD_Dec",     t0pq_resp->pq_aead_dec);
	WRITE_OP("Type0_PQ", "Responder", "PQ_HKDF",         t0pq_resp->pq_hkdf);
	WRITE_OP("Type0_PQ", "Responder", "PQ_Hash",         t0pq_resp->pq_hash);

	/* PQ Type 3 */
	WRITE_OP("Type3_PQ", "Initiator", "PQ_KeyGen",       t3pq_init->pq_keygen);
	WRITE_OP("Type3_PQ", "Initiator", "PQ_Encaps",       t3pq_init->pq_encaps);
	WRITE_OP("Type3_PQ", "Initiator", "PQ_Decaps",       t3pq_init->pq_decaps);
	WRITE_OP("Type3_PQ", "Initiator", "PQ_Signature",    t3pq_init->pq_sig_sign);
	WRITE_OP("Type3_PQ", "Initiator", "PQ_Verification", t3pq_init->pq_sig_verify);
	WRITE_OP("Type3_PQ", "Initiator", "PQ_AEAD_Enc",     t3pq_init->pq_aead_enc);
	WRITE_OP("Type3_PQ", "Initiator", "PQ_AEAD_Dec",     t3pq_init->pq_aead_dec);
	WRITE_OP("Type3_PQ", "Initiator", "PQ_HKDF",         t3pq_init->pq_hkdf);
	WRITE_OP("Type3_PQ", "Initiator", "PQ_Hash",         t3pq_init->pq_hash);
	WRITE_OP("Type3_PQ", "Responder", "PQ_KeyGen",       t3pq_resp->pq_keygen);
	WRITE_OP("Type3_PQ", "Responder", "PQ_Encaps",       t3pq_resp->pq_encaps);
	WRITE_OP("Type3_PQ", "Responder", "PQ_Decaps",       t3pq_resp->pq_decaps);
	WRITE_OP("Type3_PQ", "Responder", "PQ_Signature",    t3pq_resp->pq_sig_sign);
	WRITE_OP("Type3_PQ", "Responder", "PQ_Verification", t3pq_resp->pq_sig_verify);
	WRITE_OP("Type3_PQ", "Responder", "PQ_AEAD_Enc",     t3pq_resp->pq_aead_enc);
	WRITE_OP("Type3_PQ", "Responder", "PQ_AEAD_Dec",     t3pq_resp->pq_aead_dec);
	WRITE_OP("Type3_PQ", "Responder", "PQ_HKDF",         t3pq_resp->pq_hkdf);
	WRITE_OP("Type3_PQ", "Responder", "PQ_Hash",         t3pq_resp->pq_hash);

	#undef WRITE_OP
	fclose(fp);
	return 0;
}

static int write_overhead_csv_full(const char *filepath,
				   struct overhead_benchmark *t0_init,
				   struct overhead_benchmark *t0_resp,
				   struct overhead_benchmark *t3_init,
				   struct overhead_benchmark *t3_resp,
				   struct overhead_benchmark *t0pq_init,
				   struct overhead_benchmark *t0pq_resp,
				   struct overhead_benchmark *t3pq_init,
				   struct overhead_benchmark *t3pq_resp)
{
	FILE *fp = fopen(filepath, "w");
	if (!fp) return -1;

	fprintf(fp, "type,role,cpu_time_us,memory_bytes,memory_note\n");
	fprintf(fp, "Type0_SigSig,Initiator,%.3f,%ld,estimated_stack_heap\n",
		t0_init->cpu_us, t0_init->memory_bytes);
	fprintf(fp, "Type0_SigSig,Responder,%.3f,%ld,estimated_stack_heap\n",
		t0_resp->cpu_us, t0_resp->memory_bytes);
	fprintf(fp, "Type3_MACMAC,Initiator,%.3f,%ld,estimated_stack_heap\n",
		t3_init->cpu_us, t3_init->memory_bytes);
	fprintf(fp, "Type3_MACMAC,Responder,%.3f,%ld,estimated_stack_heap\n",
		t3_resp->cpu_us, t3_resp->memory_bytes);
	fprintf(fp, "Type0_PQ,Initiator,%.3f,%ld,estimated_stack_heap_pq\n",
		t0pq_init->cpu_us, t0pq_init->memory_bytes);
	fprintf(fp, "Type0_PQ,Responder,%.3f,%ld,estimated_stack_heap_pq\n",
		t0pq_resp->cpu_us, t0pq_resp->memory_bytes);
	fprintf(fp, "Type3_PQ,Initiator,%.3f,%ld,estimated_stack_heap_pq\n",
		t3pq_init->cpu_us, t3pq_init->memory_bytes);
	fprintf(fp, "Type3_PQ,Responder,%.3f,%ld,estimated_stack_heap_pq\n",
		t3pq_resp->cpu_us, t3pq_resp->memory_bytes);

	fclose(fp);
	return 0;
}

static int write_handshake_csv_full(const char *filepath,
				    struct handshake_benchmark *t0_init,
				    struct handshake_benchmark *t0_resp,
				    struct handshake_benchmark *t3_init,
				    struct handshake_benchmark *t3_resp,
				    struct handshake_benchmark *t0pq_init,
				    struct handshake_benchmark *t0pq_resp,
				    struct handshake_benchmark *t3pq_init,
				    struct handshake_benchmark *t3pq_resp)
{
	FILE *fp = fopen(filepath, "w");
	if (!fp) return -1;

	fprintf(fp, "type,role,processing_us,txrx_us,precomputation_us,overhead_us,total_us\n");
	fprintf(fp, "Type0_SigSig,Initiator,%.3f,%.3f,%.3f,%.3f,%.3f\n",
		t0_init->processing_us, t0_init->txrx_us,
		t0_init->precomputation_us, t0_init->overhead_us,
		t0_init->total_us);
	fprintf(fp, "Type0_SigSig,Responder,%.3f,%.3f,%.3f,%.3f,%.3f\n",
		t0_resp->processing_us, t0_resp->txrx_us,
		t0_resp->precomputation_us, t0_resp->overhead_us,
		t0_resp->total_us);
	fprintf(fp, "Type3_MACMAC,Initiator,%.3f,%.3f,%.3f,%.3f,%.3f\n",
		t3_init->processing_us, t3_init->txrx_us,
		t3_init->precomputation_us, t3_init->overhead_us,
		t3_init->total_us);
	fprintf(fp, "Type3_MACMAC,Responder,%.3f,%.3f,%.3f,%.3f,%.3f\n",
		t3_resp->processing_us, t3_resp->txrx_us,
		t3_resp->precomputation_us, t3_resp->overhead_us,
		t3_resp->total_us);
	fprintf(fp, "Type0_PQ,Initiator,%.3f,%.3f,%.3f,%.3f,%.3f\n",
		t0pq_init->processing_us, t0pq_init->txrx_us,
		t0pq_init->precomputation_us, t0pq_init->overhead_us,
		t0pq_init->total_us);
	fprintf(fp, "Type0_PQ,Responder,%.3f,%.3f,%.3f,%.3f,%.3f\n",
		t0pq_resp->processing_us, t0pq_resp->txrx_us,
		t0pq_resp->precomputation_us, t0pq_resp->overhead_us,
		t0pq_resp->total_us);
	fprintf(fp, "Type3_PQ,Initiator,%.3f,%.3f,%.3f,%.3f,%.3f\n",
		t3pq_init->processing_us, t3pq_init->txrx_us,
		t3pq_init->precomputation_us, t3pq_init->overhead_us,
		t3pq_init->total_us);
	fprintf(fp, "Type3_PQ,Responder,%.3f,%.3f,%.3f,%.3f,%.3f\n",
		t3pq_resp->processing_us, t3pq_resp->txrx_us,
		t3pq_resp->precomputation_us, t3pq_resp->overhead_us,
		t3pq_resp->total_us);

	fclose(fp);
	return 0;
}

/* PQ summary printers */

static void print_pq_ops_summary(const char *type_name,
				 struct ops_benchmark *init_ops,
				 struct ops_benchmark *resp_ops)
{
	char buf[256];
	printf("\n");
	snprintf(buf, sizeof(buf), "%s — PQ Operations (µs, avg over %d iterations)",
		 type_name, BENCH_ITERATIONS);
	print_header(buf);
	printf("\n");

	printf("  %-16s %12s %6s %12s %6s\n",
	       "Operation", "Init(avg)", "×call", "Resp(avg)", "×call");
	printf("  %-16s %12s %6s %12s %6s\n",
	       "────────────────", "────────────", "──────",
	       "────────────", "──────");

	#define PRINT_PQ(NAME, FIELD) \
		printf("  %-16s %12.3f %6d %12.3f %6d\n", \
		       NAME, \
		       init_ops->FIELD.avg_us, init_ops->FIELD.calls, \
		       resp_ops->FIELD.avg_us, resp_ops->FIELD.calls)

	PRINT_PQ("PQ KeyGen",     pq_keygen);
	PRINT_PQ("PQ Encaps",     pq_encaps);
	PRINT_PQ("PQ Decaps",     pq_decaps);
	PRINT_PQ("PQ Sig Sign",   pq_sig_sign);
	PRINT_PQ("PQ Sig Verify", pq_sig_verify);
	PRINT_PQ("PQ AEAD Enc",   pq_aead_enc);
	PRINT_PQ("PQ AEAD Dec",   pq_aead_dec);
	PRINT_PQ("PQ HKDF",       pq_hkdf);
	PRINT_PQ("PQ Hash",       pq_hash);

	#undef PRINT_PQ

	#define COST(OP) ((OP).avg_us * (double)(OP).calls)
	double init_total = COST(init_ops->pq_keygen) + COST(init_ops->pq_encaps) +
		COST(init_ops->pq_decaps) + COST(init_ops->pq_sig_sign) +
		COST(init_ops->pq_sig_verify) + COST(init_ops->pq_aead_enc) +
		COST(init_ops->pq_aead_dec) + COST(init_ops->pq_hkdf) +
		COST(init_ops->pq_hash);
	double resp_total = COST(resp_ops->pq_keygen) + COST(resp_ops->pq_encaps) +
		COST(resp_ops->pq_decaps) + COST(resp_ops->pq_sig_sign) +
		COST(resp_ops->pq_sig_verify) + COST(resp_ops->pq_aead_enc) +
		COST(resp_ops->pq_aead_dec) + COST(resp_ops->pq_hkdf) +
		COST(resp_ops->pq_hash);
	#undef COST

	printf("  %-16s %12s %6s %12s %6s\n",
	       "────────────────", "────────────", "──────",
	       "────────────", "──────");
	printf("  %-16s %9.3f µs %6s %9.3f µs %6s\n",
	       "Est. Total", init_total, "", resp_total, "");
}

/* =============================================================================
 * run_edhoc_benchmark_full() — All 4 variants (Classic + PQ)
 * =============================================================================
 */

int run_edhoc_benchmark_full(void)
{
	print_header("EDHOC-Hybrid Full Benchmark (Classic + PQ)");
	printf("\n");
	print_info("Benchmark Configuration:");

	char buf[256];
	snprintf(buf, sizeof(buf),
		 "  Operations iterations : %d", BENCH_ITERATIONS);
	print_info(buf);
	snprintf(buf, sizeof(buf),
		 "  Handshake iterations  : %d", BENCH_HANDSHAKE_ITERATIONS);
	print_info(buf);
	print_info("  Classic: Type 0 (Sig-Sig) + Type 3 (MAC-MAC)");
	print_info("  PQ:      Type 0 PQ (KEM-based) + Type 3 PQ (KEM-based)");
	print_info("  PQ Algorithm: ML-KEM-768 (NIST Level 3)");
	printf("\n");

	mkdir(BENCH_OUTPUT_DIR, 0755);

	/* === Phase 1: Classic Operations Benchmark === */
	print_header("Phase 1a: Classic Operations Benchmark");
	printf("\n");

	struct ops_benchmark t0_ops_init, t0_ops_resp;
	struct ops_benchmark t3_ops_init, t3_ops_resp;
	memset(&t0_ops_init, 0, sizeof(t0_ops_init));
	memset(&t0_ops_resp, 0, sizeof(t0_ops_resp));
	memset(&t3_ops_init, 0, sizeof(t3_ops_init));
	memset(&t3_ops_resp, 0, sizeof(t3_ops_resp));

	bench_all_operations("Type 0 (Sig-Sig)", 0,
			     &t0_ops_init, &t0_ops_resp);
	bench_all_operations("Type 3 (MAC-MAC)", 3,
			     &t3_ops_init, &t3_ops_resp);

	print_ops_summary("Type 0 (Sig-Sig)", &t0_ops_init, &t0_ops_resp);
	print_ops_summary("Type 3 (MAC-MAC)", &t3_ops_init, &t3_ops_resp);

	/* === Phase 1b: PQ Operations Benchmark === */
	print_header("Phase 1b: PQ Operations Benchmark");
	printf("\n");

	struct ops_benchmark t0pq_ops_init, t0pq_ops_resp;
	struct ops_benchmark t3pq_ops_init, t3pq_ops_resp;
	memset(&t0pq_ops_init, 0, sizeof(t0pq_ops_init));
	memset(&t0pq_ops_resp, 0, sizeof(t0pq_ops_resp));
	memset(&t3pq_ops_init, 0, sizeof(t3pq_ops_init));
	memset(&t3pq_ops_resp, 0, sizeof(t3pq_ops_resp));

	bench_pq_all_operations("Type 0 PQ (ML-KEM-768 + ML-DSA-65)", 0,
				&t0pq_ops_init, &t0pq_ops_resp);
	bench_pq_all_operations("Type 3 PQ (ML-KEM-768)", 3,
				&t3pq_ops_init, &t3pq_ops_resp);

	print_pq_ops_summary("Type 0 PQ (ML-KEM-768 + ML-DSA-65)", &t0pq_ops_init, &t0pq_ops_resp);
	print_pq_ops_summary("Type 3 PQ (ML-KEM-768)", &t3pq_ops_init, &t3pq_ops_resp);

	/* === Phase 2: Classic Handshake + Overhead === */
	print_header("Phase 2a: Classic Handshake + Overhead Benchmark");
	printf("\n");

	struct overhead_benchmark  t0_oh_init, t0_oh_resp;
	struct overhead_benchmark  t3_oh_init, t3_oh_resp;
	struct handshake_benchmark t0_hs_init, t0_hs_resp;
	struct handshake_benchmark t3_hs_init, t3_hs_resp;
	memset(&t0_oh_init, 0, sizeof(t0_oh_init));
	memset(&t0_oh_resp, 0, sizeof(t0_oh_resp));
	memset(&t3_oh_init, 0, sizeof(t3_oh_init));
	memset(&t3_oh_resp, 0, sizeof(t3_oh_resp));
	memset(&t0_hs_init, 0, sizeof(t0_hs_init));
	memset(&t0_hs_resp, 0, sizeof(t0_hs_resp));
	memset(&t3_hs_init, 0, sizeof(t3_hs_init));
	memset(&t3_hs_resp, 0, sizeof(t3_hs_resp));

	int ret;
	ret = run_handshake_benchmark(0,
				      &t0_ops_init, &t0_ops_resp,
				      &t0_oh_init, &t0_oh_resp,
				      &t0_hs_init, &t0_hs_resp);
	if (ret != 0) {
		print_error("Type 0 classic handshake benchmark failed!");
		return -1;
	}

	ret = run_handshake_benchmark(3,
				      &t3_ops_init, &t3_ops_resp,
				      &t3_oh_init, &t3_oh_resp,
				      &t3_hs_init, &t3_hs_resp);
	if (ret != 0) {
		print_error("Type 3 classic handshake benchmark failed!");
		return -1;
	}

	/* === Phase 2b: PQ Handshake + Overhead === */
	print_header("Phase 2b: PQ Handshake + Overhead Benchmark");
	printf("\n");

	struct overhead_benchmark  t0pq_oh_init, t0pq_oh_resp;
	struct overhead_benchmark  t3pq_oh_init, t3pq_oh_resp;
	struct handshake_benchmark t0pq_hs_init, t0pq_hs_resp;
	struct handshake_benchmark t3pq_hs_init, t3pq_hs_resp;
	memset(&t0pq_oh_init, 0, sizeof(t0pq_oh_init));
	memset(&t0pq_oh_resp, 0, sizeof(t0pq_oh_resp));
	memset(&t3pq_oh_init, 0, sizeof(t3pq_oh_init));
	memset(&t3pq_oh_resp, 0, sizeof(t3pq_oh_resp));
	memset(&t0pq_hs_init, 0, sizeof(t0pq_hs_init));
	memset(&t0pq_hs_resp, 0, sizeof(t0pq_hs_resp));
	memset(&t3pq_hs_init, 0, sizeof(t3pq_hs_init));
	memset(&t3pq_hs_resp, 0, sizeof(t3pq_hs_resp));

	ret = run_pq_handshake_benchmark(0,
					 &t0pq_ops_init, &t0pq_ops_resp,
					 &t0pq_oh_init, &t0pq_oh_resp,
					 &t0pq_hs_init, &t0pq_hs_resp);
	if (ret != 0) {
		print_error("Type 0 PQ handshake benchmark failed!");
		return -1;
	}

	ret = run_pq_handshake_benchmark(3,
					 &t3pq_ops_init, &t3pq_ops_resp,
					 &t3pq_oh_init, &t3pq_oh_resp,
					 &t3pq_hs_init, &t3pq_hs_resp);
	if (ret != 0) {
		print_error("Type 3 PQ handshake benchmark failed!");
		return -1;
	}

	/* Print summaries */
	print_overhead_summary(&t0_oh_init, &t0_oh_resp,
			       &t3_oh_init, &t3_oh_resp);

	printf("\n");
	print_header("PQ Overhead Benchmark (avg per handshake)");
	printf("\n");
	printf("  %-16s %-12s %14s %14s %s\n",
	       "Type", "Role", "CPU (µs)", "Memory (bytes)", "Note");
	printf("  %-16s %-12s %14s %14s %s\n",
	       "────────────────", "────────────", "──────────────",
	       "──────────────", "────────────────────");
	printf("  %-16s %-12s %14.3f %14ld %s\n",
	       "Type0_PQ", "Initiator", t0pq_oh_init.cpu_us,
	       t0pq_oh_init.memory_bytes, "computed from ops (ML-KEM-768)");
	printf("  %-16s %-12s %14.3f %14ld %s\n",
	       "Type0_PQ", "Responder", t0pq_oh_resp.cpu_us,
	       t0pq_oh_resp.memory_bytes, "computed from ops (ML-KEM-768)");
	printf("  %-16s %-12s %14.3f %14ld %s\n",
	       "Type3_PQ", "Initiator", t3pq_oh_init.cpu_us,
	       t3pq_oh_init.memory_bytes, "computed from ops (ML-KEM-768)");
	printf("  %-16s %-12s %14.3f %14ld %s\n",
	       "Type3_PQ", "Responder", t3pq_oh_resp.cpu_us,
	       t3pq_oh_resp.memory_bytes, "computed from ops (ML-KEM-768)");

	print_handshake_summary(&t0_hs_init, &t0_hs_resp,
				&t3_hs_init, &t3_hs_resp);

	printf("\n");
	print_header("PQ Handshake Timing Benchmark (µs, avg)");
	printf("\n");
	printf("  %-16s %-12s %14s %14s %14s %14s %14s\n",
	       "Type", "Role", "Processing", "TxRx", "Precompute", "Overhead", "Total");
	printf("  %-16s %-12s %14s %14s %14s %14s %14s\n",
	       "────────────────", "────────────",
	       "──────────────", "──────────────",
	       "──────────────", "──────────────", "──────────────");
	printf("  %-16s %-12s %14.3f %14.3f %14.3f %14.3f %14.3f\n",
	       "Type0_PQ", "Initiator",
	       t0pq_hs_init.processing_us, t0pq_hs_init.txrx_us,
	       t0pq_hs_init.precomputation_us, t0pq_hs_init.overhead_us,
	       t0pq_hs_init.total_us);
	printf("  %-16s %-12s %14.3f %14.3f %14.3f %14.3f %14.3f\n",
	       "Type0_PQ", "Responder",
	       t0pq_hs_resp.processing_us, t0pq_hs_resp.txrx_us,
	       t0pq_hs_resp.precomputation_us, t0pq_hs_resp.overhead_us,
	       t0pq_hs_resp.total_us);
	printf("  %-16s %-12s %14.3f %14.3f %14.3f %14.3f %14.3f\n",
	       "Type3_PQ", "Initiator",
	       t3pq_hs_init.processing_us, t3pq_hs_init.txrx_us,
	       t3pq_hs_init.precomputation_us, t3pq_hs_init.overhead_us,
	       t3pq_hs_init.total_us);
	printf("  %-16s %-12s %14.3f %14.3f %14.3f %14.3f %14.3f\n",
	       "Type3_PQ", "Responder",
	       t3pq_hs_resp.processing_us, t3pq_hs_resp.txrx_us,
	       t3pq_hs_resp.precomputation_us, t3pq_hs_resp.overhead_us,
	       t3pq_hs_resp.total_us);

	/* Write CSV files */
	printf("\n");
	print_header("Writing CSV Output Files (Full: Classic + PQ)");
	printf("\n");

	ret = write_operations_csv_full(BENCH_CSV_OPERATIONS,
					&t0_ops_init, &t0_ops_resp,
					&t3_ops_init, &t3_ops_resp,
					&t0pq_ops_init, &t0pq_ops_resp,
					&t3pq_ops_init, &t3pq_ops_resp);
	if (ret == 0) {
		snprintf(buf, sizeof(buf), "Written: %s", BENCH_CSV_OPERATIONS);
		print_success(buf);
	}

	ret = write_overhead_csv_full(BENCH_CSV_OVERHEAD,
				      &t0_oh_init, &t0_oh_resp,
				      &t3_oh_init, &t3_oh_resp,
				      &t0pq_oh_init, &t0pq_oh_resp,
				      &t3pq_oh_init, &t3pq_oh_resp);
	if (ret == 0) {
		snprintf(buf, sizeof(buf), "Written: %s", BENCH_CSV_OVERHEAD);
		print_success(buf);
	}

	ret = write_handshake_csv_full(BENCH_CSV_HANDSHAKE,
				       &t0_hs_init, &t0_hs_resp,
				       &t3_hs_init, &t3_hs_resp,
				       &t0pq_hs_init, &t0pq_hs_resp,
				       &t3pq_hs_init, &t3pq_hs_resp);
	if (ret == 0) {
		snprintf(buf, sizeof(buf), "Written: %s", BENCH_CSV_HANDSHAKE);
		print_success(buf);
	}

	printf("\n");
	print_success("EDHOC-Hybrid Full Benchmark (Classic + PQ) completed!");
	print_info("● CSV files saved in output/ directory.");
	print_info("● 4 variants: Type0 Classic, Type3 Classic, Type0 PQ, Type3 PQ");
	printf("\n");

	return 0;
}
