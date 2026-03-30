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
#include "edhoc_test_vectors_rfc9529.h"
#include "edhoc_type3_x25519_testvec.h"

/* Low-level crypto APIs */
#include "common/crypto_wrapper.h"
#include "edhoc/suites.h"

/* compact25519 for keygen */
#include "compact_x25519.h"
#include "compact_ed25519.h"

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
};

/* Overhead resource untuk satu (type, role) */
struct overhead_benchmark {
	double cpu_us;         /* CPU time (per-thread) dalam µs */
	long   memory_bytes;   /* Estimated stack + heap memory dalam bytes */
};

/* Waktu handshake per fase untuk satu (type, role) */
struct handshake_benchmark {
	double processing_us;     /* Waktu komputasi kriptografi */
	double txrx_us;           /* Waktu transmisi/penerimaan pesan */
	double precomputation_us; /* Waktu setup kunci (ephemeral keygen) */
	double total_us;          /* Total waktu handshake */
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
 * Menggunakan compact_x25519_keygen() untuk membangkitkan pasangan kunci
 * DH ephemeral (32-byte private + 32-byte public) dari random seed.
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
		uint8_t seed[32], sk[32], pk[32];
		for (int j = 0; j < 32; j++)
			seed[j] = (uint8_t)(i * 37 + j * 13 + 42);

		uint64_t start = get_time_ns();
		compact_x25519_keygen(sk, pk, seed);
		uint64_t end = get_time_ns();

		total_ns += (end - start);
	}

	res.avg_us = (double)total_ns / (double)iterations / 1000.0;
	res.count = iterations;
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

	/* Precomputation: hanya X25519 ephemeral keygen */
	double precomp_i_us = 0, precomp_r_us = 0;
	{
		uint8_t seed[32], sk[32], pk[32];
		uint64_t t0, t1;

		memset(seed, 0x42, 32);
		t0 = get_time_ns();
		compact_x25519_keygen(sk, pk, seed);
		t1 = get_time_ns();
		precomp_i_us = elapsed_us(t0, t1);

		memset(seed, 0x43, 32);
		t0 = get_time_ns();
		compact_x25519_keygen(sk, pk, seed);
		t1 = get_time_ns();
		precomp_r_us = elapsed_us(t0, t1);
	}

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

			/* Per-thread CPU time (accurate) */
			double i_cpu = (double)(i_data.cpu_end_ns -
						i_data.cpu_start_ns) / 1000.0;
			double r_cpu = (double)(r_data.cpu_end_ns -
						r_data.cpu_start_ns) / 1000.0;

			double i_txrx = (double)(uintptr_t)i_txrx_ret / 1000.0;
			double r_txrx = (double)(uintptr_t)r_txrx_ret / 1000.0;

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
		print_error("All handshake iterations failed!");
		return -1;
	}

	double n = (double)success_count;

	/* Overhead: per-thread CPU + estimated memory */
	overhead_i->cpu_us = total_i_cpu / n;
	overhead_i->memory_bytes = estimate_edhoc_memory(type_num);
	overhead_r->cpu_us = total_r_cpu / n;
	overhead_r->memory_bytes = estimate_edhoc_memory(type_num);

	/* Handshake timing */
	handshake_i->total_us = total_i_wall / n;
	handshake_i->txrx_us = total_i_txrx / n;
	handshake_i->precomputation_us = precomp_i_us;
	handshake_i->processing_us = handshake_i->total_us -
				     handshake_i->txrx_us -
				     handshake_i->precomputation_us;
	if (handshake_i->processing_us < 0)
		handshake_i->processing_us = 0;

	handshake_r->total_us = total_r_wall / n;
	handshake_r->txrx_us = total_r_txrx / n;
	handshake_r->precomputation_us = precomp_r_us;
	handshake_r->processing_us = handshake_r->total_us -
				     handshake_r->txrx_us -
				     handshake_r->precomputation_us;
	if (handshake_r->processing_us < 0)
		handshake_r->processing_us = 0;

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

	fprintf(fp, "type,role,processing_us,txrx_us,precomputation_us,total_us\n");
	fprintf(fp, "Type0_SigSig,Initiator,%.3f,%.3f,%.3f,%.3f\n",
		t0_init->processing_us, t0_init->txrx_us,
		t0_init->precomputation_us, t0_init->total_us);
	fprintf(fp, "Type0_SigSig,Responder,%.3f,%.3f,%.3f,%.3f\n",
		t0_resp->processing_us, t0_resp->txrx_us,
		t0_resp->precomputation_us, t0_resp->total_us);
	fprintf(fp, "Type3_MACMAC,Initiator,%.3f,%.3f,%.3f,%.3f\n",
		t3_init->processing_us, t3_init->txrx_us,
		t3_init->precomputation_us, t3_init->total_us);
	fprintf(fp, "Type3_MACMAC,Responder,%.3f,%.3f,%.3f,%.3f\n",
		t3_resp->processing_us, t3_resp->txrx_us,
		t3_resp->precomputation_us, t3_resp->total_us);

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
	print_header("Overhead Benchmark (avg per handshake)");
	printf("\n");

	printf("  %-16s %-12s %14s %14s %s\n",
	       "Type", "Role", "CPU (µs)", "Memory (bytes)", "Note");
	printf("  %-16s %-12s %14s %14s %s\n",
	       "────────────────", "────────────", "──────────────",
	       "──────────────", "────────────────────");
	printf("  %-16s %-12s %14.3f %14ld %s\n",
	       "Type0_SigSig", "Initiator", t0_init->cpu_us,
	       t0_init->memory_bytes, "est. stack+heap");
	printf("  %-16s %-12s %14.3f %14ld %s\n",
	       "Type0_SigSig", "Responder", t0_resp->cpu_us,
	       t0_resp->memory_bytes, "est. stack+heap");
	printf("  %-16s %-12s %14.3f %14ld %s\n",
	       "Type3_MACMAC", "Initiator", t3_init->cpu_us,
	       t3_init->memory_bytes, "est. stack+heap");
	printf("  %-16s %-12s %14.3f %14ld %s\n",
	       "Type3_MACMAC", "Responder", t3_resp->cpu_us,
	       t3_resp->memory_bytes, "est. stack+heap");
}

static void print_handshake_summary(struct handshake_benchmark *t0_init,
				    struct handshake_benchmark *t0_resp,
				    struct handshake_benchmark *t3_init,
				    struct handshake_benchmark *t3_resp)
{
	printf("\n");
	print_header("Handshake Timing Benchmark (µs, avg)");
	printf("\n");

	printf("  %-16s %-12s %14s %14s %14s %14s\n",
	       "Type", "Role", "Processing", "TxRx", "Precompute", "Total");
	printf("  %-16s %-12s %14s %14s %14s %14s\n",
	       "────────────────", "────────────",
	       "──────────────", "──────────────",
	       "──────────────", "──────────────");
	printf("  %-16s %-12s %14.3f %14.3f %14.3f %14.3f\n",
	       "Type0_SigSig", "Initiator",
	       t0_init->processing_us, t0_init->txrx_us,
	       t0_init->precomputation_us, t0_init->total_us);
	printf("  %-16s %-12s %14.3f %14.3f %14.3f %14.3f\n",
	       "Type0_SigSig", "Responder",
	       t0_resp->processing_us, t0_resp->txrx_us,
	       t0_resp->precomputation_us, t0_resp->total_us);
	printf("  %-16s %-12s %14.3f %14.3f %14.3f %14.3f\n",
	       "Type3_MACMAC", "Initiator",
	       t3_init->processing_us, t3_init->txrx_us,
	       t3_init->precomputation_us, t3_init->total_us);
	printf("  %-16s %-12s %14.3f %14.3f %14.3f %14.3f\n",
	       "Type3_MACMAC", "Responder",
	       t3_resp->processing_us, t3_resp->txrx_us,
	       t3_resp->precomputation_us, t3_resp->total_us);
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
	print_info("  ✓ CPU: Per-thread CLOCK_THREAD_CPUTIME_ID (not process-wide)");
	print_info("  ✓ Hash: SHA-256 benchmark added (~4 calls/handshake)");
	print_info("  ✓ Calls: Per-operation call count matches EDHOC protocol flow");
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
				      &t0_oh_init, &t0_oh_resp,
				      &t0_hs_init, &t0_hs_resp);
	if (ret != 0) {
		print_error("Type 0 handshake benchmark failed!");
		return -1;
	}

	ret = run_handshake_benchmark(3,
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
