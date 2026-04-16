/*
 * =============================================================================
 * EDHOC-Hybrid: Socket-based (TCP) Benchmark
 * =============================================================================
 *
 * Mirrors edhoc_benchmark.c but uses TCP localhost sockets for all
 * handshake message exchange.  The crypto operations benchmark is
 * identical (transport-independent).  The handshake benchmark spawns a
 * server thread (Responder) and a client thread (Initiator) that
 * communicate via TCP with length-prefix framing.
 *
 * CSV output goes to output/ so it can be verified independently.
 * =============================================================================
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include "edhoc_benchmark.h"
#include "edhoc_common.h"
#include "edhoc_type0_classic.h"
#include "edhoc_type3_classic.h"
#include "edhoc_type0_pq.h"
#include "edhoc_type3_pq.h"
#include "edhoc_type3_hybrid.h"
#include "edhoc_pq_kem.h"
#include "edhoc_test_vectors_rfc9529.h"
#include "edhoc_type3_x25519_testvec.h"
#include "heap_tracker.h"

/* Low-level crypto APIs */
#include "common/crypto_wrapper.h"
#include "edhoc/suites.h"

/*
 * PQ threads (ML-DSA-65 sign/verify) allocate ~55+ KB of stack for polyvec
 * matrices, plus ~31 KB for our own local buffers.  The default pthread
 * stack on ARM (Raspberry Pi) is only 128 KB, which is not enough and
 * causes heap-metadata corruption ("free(): invalid next size (fast)").
 * We use 1 MB per thread to be safe.
 */
#define BENCH_THREAD_STACK_SIZE (1U << 20) /* 1 MiB */

/* =============================================================================
 * Timing utilities (identical to edhoc_benchmark.c)
 * =============================================================================
 */
static inline uint64_t sck_get_time_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline double sck_elapsed_us(uint64_t start, uint64_t end)
{
	return (double)(end - start) / 1000.0;
}

static inline uint64_t sck_get_thread_cpu_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* =============================================================================
 * Benchmark data structures (identical to edhoc_benchmark.c)
 * =============================================================================
 */
struct sck_op_result {
	double avg_us;
	int    count;
	int    calls;
};

struct sck_ops_benchmark {
	struct sck_op_result keygen;
	struct sck_op_result aead_enc;
	struct sck_op_result aead_dec;
	struct sck_op_result signature;
	struct sck_op_result verification;
	struct sck_op_result ecdh;
	struct sck_op_result hkdf;
	struct sck_op_result hash;
	struct sck_op_result pq_keygen;
	struct sck_op_result pq_encaps;
	struct sck_op_result pq_decaps;
	struct sck_op_result pq_sig_sign;
	struct sck_op_result pq_sig_verify;
	struct sck_op_result pq_aead_enc;
	struct sck_op_result pq_aead_dec;
	struct sck_op_result pq_hkdf;
	struct sck_op_result pq_hash;
};

struct sck_overhead_benchmark {
	double cpu_us;
	long   memory_bytes;
};

struct sck_handshake_benchmark {
	double processing_us;
	double txrx_us;
	double precomputation_us;
	double overhead_us;
	double total_us;
};

/* =============================================================================
 * TCP Socket Helper Functions
 * =============================================================================
 */

/**
 * @brief Send a message over TCP with 4-byte length prefix (network byte order).
 */
static int sock_send_msg(int fd, const uint8_t *data, uint32_t len)
{
	uint32_t net_len = htonl(len);
	/* Send length prefix */
	ssize_t n = send(fd, &net_len, 4, MSG_NOSIGNAL);
	if (n != 4) return -1;
	/* Send payload */
	uint32_t sent = 0;
	while (sent < len) {
		n = send(fd, data + sent, len - sent, MSG_NOSIGNAL);
		if (n <= 0) return -1;
		sent += (uint32_t)n;
	}
	return 0;
}

/**
 * @brief Receive a message over TCP with 4-byte length prefix.
 * @param buf Output buffer (must be large enough)
 * @param buf_size Size of output buffer
 * @param out_len Output: number of bytes received
 */
static int sock_recv_msg(int fd, uint8_t *buf, uint32_t buf_size, uint32_t *out_len)
{
	uint32_t net_len;
	ssize_t n = 0;
	uint32_t got = 0;
	/* Read 4-byte length prefix */
	while (got < 4) {
		n = recv(fd, ((uint8_t *)&net_len) + got, 4 - got, 0);
		if (n <= 0) return -1;
		got += (uint32_t)n;
	}
	uint32_t msg_len = ntohl(net_len);
	if (msg_len > buf_size) return -1;
	/* Read payload */
	got = 0;
	while (got < msg_len) {
		n = recv(fd, buf + got, msg_len - got, 0);
		if (n <= 0) return -1;
		got += (uint32_t)n;
	}
	*out_len = msg_len;
	return 0;
}

/**
 * @brief Create a TCP server socket bound to localhost:port.
 * @return listening socket fd, or -1 on error
 */
static int sock_create_server(int port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;

	int opt = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons((uint16_t)port);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}
	if (listen(fd, 1) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/**
 * @brief Connect to localhost:port.
 * @return connected socket fd, or -1 on error
 */
static int sock_connect_client(int port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons((uint16_t)port);

	/* Retry connect a few times (server may not be ready yet) */
	for (int retry = 0; retry < 50; retry++) {
		if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0)
			return fd;
			   { struct timespec ts = {0, 1000 * 1000}; nanosleep(&ts, NULL); } /* 1ms */
	}
	close(fd);
	return -1;
}

/* =============================================================================
 * 1. CRYPTO PRIMITIVE BENCHMARKS (identical to edhoc_benchmark.c)
 * =============================================================================
 */

static struct sck_op_result sck_bench_keygen_x25519(int iterations)
{
	struct sck_op_result res = {0};
	uint64_t total_ns = 0;
	for (int i = 0; i < iterations; i++) {
		uint8_t sk_buf[32] = {0}, pk_buf[32] = {0};
		struct byte_array sk = { .len = 32, .ptr = sk_buf };
		struct byte_array pk = { .len = 32, .ptr = pk_buf };
		uint32_t seed = (uint32_t)(i * 37U + 42U);
		uint64_t start = sck_get_time_ns();
		enum err r = ephemeral_dh_key_gen(X25519, seed, &sk, &pk);
		uint64_t end = sck_get_time_ns();
		if (r == ok) { total_ns += (end - start); res.count++; }
	}
	if (res.count > 0) res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

static struct sck_op_result sck_bench_encap(int iterations)
{
	struct sck_op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t plain_data[32], key_data[16], nonce_data[13];
	uint8_t aad_data[16], cipher_data[64], tag_data[8];
	memset(plain_data, 0xAA, 32); memset(key_data, 0xBB, 16);
	memset(nonce_data, 0xCC, 13); memset(aad_data, 0xDD, 16);
	struct byte_array plain  = {.len=32,.ptr=plain_data};
	struct byte_array key    = {.len=16,.ptr=key_data};
	struct byte_array nonce  = {.len=13,.ptr=nonce_data};
	struct byte_array a_ad   = {.len=16,.ptr=aad_data};
	struct byte_array cipher = {.len=32,.ptr=cipher_data};
	struct byte_array tag    = {.len=8, .ptr=tag_data};
	for (int i = 0; i < iterations; i++) {
		cipher.len = 32; tag.len = 8;
		uint64_t start = sck_get_time_ns();
		enum err r = aead(ENCRYPT, &plain, &key, &nonce, &a_ad, &cipher, &tag);
		uint64_t end = sck_get_time_ns();
		if (r == ok) { total_ns += (end - start); res.count++; }
	}
	if (res.count > 0) res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

static struct sck_op_result sck_bench_decap(int iterations)
{
	struct sck_op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t plain_data[32], key_data[16], nonce_data[13];
	uint8_t aad_data[16], cipher_data[64], tag_data[8], decrypted_data[64];
	memset(plain_data, 0xAA, 32); memset(key_data, 0xBB, 16);
	memset(nonce_data, 0xCC, 13); memset(aad_data, 0xDD, 16);
	struct byte_array plain  = {.len=32,.ptr=plain_data};
	struct byte_array key    = {.len=16,.ptr=key_data};
	struct byte_array nonce  = {.len=13,.ptr=nonce_data};
	struct byte_array a_ad   = {.len=16,.ptr=aad_data};
	struct byte_array cipher = {.len=32,.ptr=cipher_data};
	struct byte_array tag    = {.len=8, .ptr=tag_data};
	enum err r = aead(ENCRYPT, &plain, &key, &nonce, &a_ad, &cipher, &tag);
	if (r != ok) return res;
	uint8_t ct_plus_tag[64];
	memcpy(ct_plus_tag, cipher.ptr, cipher.len);
	memcpy(ct_plus_tag + cipher.len, tag.ptr, tag.len);
	uint32_t ct_tag_len = cipher.len + tag.len;
	struct byte_array ct_input  = {.len=ct_tag_len,.ptr=ct_plus_tag};
	struct byte_array decrypted = {.len=32,.ptr=decrypted_data};
	struct byte_array dec_tag   = {.len=8, .ptr=tag_data};
	for (int i = 0; i < iterations; i++) {
		decrypted.len = 32; dec_tag.len = 8;
		uint64_t start = sck_get_time_ns();
		r = aead(DECRYPT, &ct_input, &key, &nonce, &a_ad, &decrypted, &dec_tag);
		uint64_t end = sck_get_time_ns();
		if (r == ok) { total_ns += (end - start); res.count++; }
	}
	if (res.count > 0) res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

static struct sck_op_result sck_bench_signature(int iterations)
{
	struct sck_op_result res = {0};
	uint64_t total_ns = 0;
	struct byte_array sk = {.len=T1_RFC9529__SK_I_LEN,.ptr=(uint8_t*)T1_RFC9529__SK_I};
	struct byte_array pk = {.len=T1_RFC9529__PK_I_LEN,.ptr=(uint8_t*)T1_RFC9529__PK_I};
	uint8_t msg_data[64]; memset(msg_data, 0x42, 64);
	struct byte_array msg = {.len=64,.ptr=msg_data};
	uint8_t sig_out[64];
	for (int i = 0; i < iterations; i++) {
		uint64_t start = sck_get_time_ns();
		enum err r = sign(EdDSA, &sk, &pk, &msg, sig_out);
		uint64_t end = sck_get_time_ns();
		if (r == ok) { total_ns += (end - start); res.count++; }
	}
	if (res.count > 0) res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

static struct sck_op_result sck_bench_verification(int iterations)
{
	struct sck_op_result res = {0};
	uint64_t total_ns = 0;
	struct byte_array sk = {.len=T1_RFC9529__SK_I_LEN,.ptr=(uint8_t*)T1_RFC9529__SK_I};
	struct byte_array pk = {.len=T1_RFC9529__PK_I_LEN,.ptr=(uint8_t*)T1_RFC9529__PK_I};
	uint8_t msg_data[64]; memset(msg_data, 0x42, 64);
	struct byte_array msg = {.len=64,.ptr=msg_data};
	uint8_t sig_out[64];
	enum err r = sign(EdDSA, &sk, &pk, &msg, sig_out);
	if (r != ok) return res;
	struct const_byte_array c_msg = {.len=msg.len,.ptr=msg.ptr};
	struct const_byte_array c_sgn = {.len=64,.ptr=sig_out};
	for (int i = 0; i < iterations; i++) {
		bool verified = false;
		uint64_t start = sck_get_time_ns();
		r = verify(EdDSA, &pk, &c_msg, &c_sgn, &verified);
		uint64_t end = sck_get_time_ns();
		if (r == ok && verified) { total_ns += (end - start); res.count++; }
	}
	if (res.count > 0) res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

static struct sck_op_result sck_bench_ecdh(int iterations)
{
	struct sck_op_result res = {0};
	uint64_t total_ns = 0;
	struct byte_array sk = {.len=T1_RFC9529__X_LEN,.ptr=(uint8_t*)T1_RFC9529__X};
	struct byte_array pk = {.len=T1_RFC9529__G_Y_LEN,.ptr=(uint8_t*)T1_RFC9529__G_Y};
	uint8_t shared[32];
	for (int i = 0; i < iterations; i++) {
		uint64_t start = sck_get_time_ns();
		enum err r = shared_secret_derive(X25519, &sk, &pk, shared);
		uint64_t end = sck_get_time_ns();
		if (r == ok) { total_ns += (end - start); res.count++; }
	}
	if (res.count > 0) res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

static struct sck_op_result sck_bench_hkdf(int iterations)
{
	struct sck_op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t salt_data[32], ikm_data[32], prk_data[32], info_data[16], okm_data[32];
	memset(salt_data, 0x11, 32); memset(ikm_data, 0x22, 32); memset(info_data, 0x33, 16);
	struct byte_array salt = {.len=32,.ptr=salt_data};
	struct byte_array ikm  = {.len=32,.ptr=ikm_data};
	struct byte_array prk  = {.len=32,.ptr=prk_data};
	struct byte_array info = {.len=16,.ptr=info_data};
	struct byte_array okm  = {.len=32,.ptr=okm_data};
	for (int i = 0; i < iterations; i++) {
		uint64_t start = sck_get_time_ns();
		enum err r = hkdf_extract(SHA_256, &salt, &ikm, prk_data);
		if (r != ok) continue;
		okm.len = 32;
		r = hkdf_expand(SHA_256, &prk, &info, &okm);
		uint64_t end = sck_get_time_ns();
		if (r == ok) { total_ns += (end - start); res.count++; }
	}
	if (res.count > 0) res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

static struct sck_op_result sck_bench_hash(int iterations)
{
	struct sck_op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t msg_data[128], hash_out[32];
	memset(msg_data, 0x55, 128);
	struct byte_array msg = {.len=128,.ptr=msg_data};
	struct byte_array hout = {.len=32,.ptr=hash_out};
	for (int i = 0; i < iterations; i++) {
		hout.len = 32;
		uint64_t start = sck_get_time_ns();
		enum err r = hash(SHA_256, &msg, &hout);
		uint64_t end = sck_get_time_ns();
		if (r == ok) { total_ns += (end - start); res.count++; }
	}
	if (res.count > 0) res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

/* PQ primitive benchmarks */
static struct sck_op_result sck_bench_pq_keygen(int iterations)
{
	struct sck_op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t pk[PQ_KEM_PK_LEN], sk[PQ_KEM_SK_LEN];
	for (int i = 0; i < iterations; i++) {
		uint64_t start = sck_get_time_ns();
		int r = pq_kem_keygen(pk, sk);
		uint64_t end = sck_get_time_ns();
		if (r == 0) { total_ns += (end - start); res.count++; }
	}
	if (res.count > 0) res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

static struct sck_op_result sck_bench_pq_encaps(int iterations)
{
	struct sck_op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t pk[PQ_KEM_PK_LEN], sk[PQ_KEM_SK_LEN];
	uint8_t ct[PQ_KEM_CT_LEN], ss[PQ_KEM_SS_LEN];
	if (pq_kem_keygen(pk, sk) != 0) return res;
	for (int i = 0; i < iterations; i++) {
		uint64_t start = sck_get_time_ns();
		int r = pq_kem_encaps(ct, ss, pk);
		uint64_t end = sck_get_time_ns();
		if (r == 0) { total_ns += (end - start); res.count++; }
	}
	if (res.count > 0) res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

static struct sck_op_result sck_bench_pq_decaps(int iterations)
{
	struct sck_op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t pk[PQ_KEM_PK_LEN], sk[PQ_KEM_SK_LEN];
	uint8_t ct[PQ_KEM_CT_LEN], ss[PQ_KEM_SS_LEN], ss2[PQ_KEM_SS_LEN];
	if (pq_kem_keygen(pk, sk) != 0) return res;
	if (pq_kem_encaps(ct, ss, pk) != 0) return res;
	for (int i = 0; i < iterations; i++) {
		uint64_t start = sck_get_time_ns();
		int r = pq_kem_decaps(ss2, ct, sk);
		uint64_t end = sck_get_time_ns();
		if (r == 0) { total_ns += (end - start); res.count++; }
	}
	if (res.count > 0) res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

static struct sck_op_result sck_bench_pq_aead_enc(int iterations)
{
	struct sck_op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t key[PQ_AEAD_KEY_LEN], iv[PQ_AEAD_NONCE_LEN], pt[32], ct[32+PQ_AEAD_TAG_LEN];
	memset(key, 0xBB, sizeof(key)); memset(iv, 0xCC, sizeof(iv)); memset(pt, 0xAA, 32);
	for (int i = 0; i < iterations; i++) {
		size_t ct_len = 0;
		uint64_t start = sck_get_time_ns();
		int r = pq_aead_encrypt(key, iv, NULL, 0, pt, 32, ct, &ct_len);
		uint64_t end = sck_get_time_ns();
		if (r == 0) { total_ns += (end - start); res.count++; }
	}
	if (res.count > 0) res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

static struct sck_op_result sck_bench_pq_aead_dec(int iterations)
{
	struct sck_op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t key[PQ_AEAD_KEY_LEN], iv[PQ_AEAD_NONCE_LEN], pt[32], ct[32+PQ_AEAD_TAG_LEN], dec[32];
	memset(key, 0xBB, sizeof(key)); memset(iv, 0xCC, sizeof(iv)); memset(pt, 0xAA, 32);
	size_t ct_len = 0;
	if (pq_aead_encrypt(key, iv, NULL, 0, pt, 32, ct, &ct_len) != 0) return res;
	for (int i = 0; i < iterations; i++) {
		size_t dec_len = 0;
		uint64_t start = sck_get_time_ns();
		int r = pq_aead_decrypt(key, iv, NULL, 0, ct, ct_len, dec, &dec_len);
		uint64_t end = sck_get_time_ns();
		if (r == 0) { total_ns += (end - start); res.count++; }
	}
	if (res.count > 0) res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

static struct sck_op_result sck_bench_pq_hkdf(int iterations)
{
	struct sck_op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t salt[32], ikm[32], prk[32], info[16], okm[32];
	memset(salt, 0x11, 32); memset(ikm, 0x22, 32); memset(info, 0x33, 16);
	for (int i = 0; i < iterations; i++) {
		uint64_t start = sck_get_time_ns();
		int r = pq_hkdf_extract(salt, 32, ikm, 32, prk);
		if (r == 0) r = pq_hkdf_expand(prk, info, 16, okm, 32);
		uint64_t end = sck_get_time_ns();
		if (r == 0) { total_ns += (end - start); res.count++; }
	}
	if (res.count > 0) res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

static struct sck_op_result sck_bench_pq_hash(int iterations)
{
	struct sck_op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t msg[128], out[32]; memset(msg, 0x55, 128);
	for (int i = 0; i < iterations; i++) {
		uint64_t start = sck_get_time_ns();
		int r = pq_hash_sha256(msg, 128, out);
		uint64_t end = sck_get_time_ns();
		if (r == 0) { total_ns += (end - start); res.count++; }
	}
	if (res.count > 0) res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

static struct sck_op_result sck_bench_pq_sig_sign(int iterations)
{
	struct sck_op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t pk[PQ_SIG_PK_LEN], sk[PQ_SIG_SK_LEN], sig[PQ_SIG_MAX_LEN], msg[64];
	memset(msg, 0xAA, 64);
	if (pq_sig_keygen(pk, sk) != 0) return res;
	for (int i = 0; i < iterations; i++) {
		size_t sig_len = 0;
		uint64_t start = sck_get_time_ns();
		int r = pq_sig_sign(msg, 64, sk, sig, &sig_len);
		uint64_t end = sck_get_time_ns();
		if (r == 0) { total_ns += (end - start); res.count++; }
	}
	if (res.count > 0) res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

static struct sck_op_result sck_bench_pq_sig_verify(int iterations)
{
	struct sck_op_result res = {0};
	uint64_t total_ns = 0;
	uint8_t pk[PQ_SIG_PK_LEN], sk[PQ_SIG_SK_LEN], sig[PQ_SIG_MAX_LEN], msg[64];
	size_t sig_len = 0;
	memset(msg, 0xAA, 64);
	if (pq_sig_keygen(pk, sk) != 0) return res;
	if (pq_sig_sign(msg, 64, sk, sig, &sig_len) != 0) return res;
	for (int i = 0; i < iterations; i++) {
		uint64_t start = sck_get_time_ns();
		int r = pq_sig_verify(msg, 64, sig, sig_len, pk);
		uint64_t end = sck_get_time_ns();
		if (r == 0) { total_ns += (end - start); res.count++; }
	}
	if (res.count > 0) res.avg_us = (double)total_ns / (double)res.count / 1000.0;
	return res;
}

/* =============================================================================
 * Primitive timing cache (per role)
 *
 * NOTE:
 *   We keep separate caches for Initiator and Responder measurements so
 *   avg_time_us in benchmark_operations.csv is role-specific and not copied
 *   from one shared timing sample.
 * =============================================================================
 */
struct sck_prim_cache {
	/* Classic */
	struct sck_op_result keygen;      /* X25519 keygen */
	struct sck_op_result aead_enc;    /* AEAD encrypt (classic) */
	struct sck_op_result aead_dec;    /* AEAD decrypt (classic) */
	struct sck_op_result signature;   /* Ed25519 sign */
	struct sck_op_result verification;/* Ed25519 verify */
	struct sck_op_result ecdh;        /* X25519 shared secret */
	struct sck_op_result hkdf;        /* SHA-256 HKDF extract+expand */
	struct sck_op_result hash;        /* SHA-256 hash */
	/* PQ */
	struct sck_op_result pq_keygen;
	struct sck_op_result pq_encaps;
	struct sck_op_result pq_decaps;
	struct sck_op_result pq_sig_sign;
	struct sck_op_result pq_sig_verify;
	struct sck_op_result pq_aead_enc;
	struct sck_op_result pq_aead_dec;
	struct sck_op_result pq_hkdf;
	struct sck_op_result pq_hash;
};

static void sck_bench_all_primitives(struct sck_prim_cache *c)
{
	const int N = SOCK_BENCH_ITERATIONS;
	const int W = 20; /* warmup iterations — prime caches, results discarded */

	/* Warmup pass */
	(void)sck_bench_keygen_x25519(W);
	(void)sck_bench_encap(W);
	(void)sck_bench_decap(W);
	(void)sck_bench_signature(W);
	(void)sck_bench_verification(W);
	(void)sck_bench_ecdh(W);
	(void)sck_bench_hkdf(W);
	(void)sck_bench_hash(W);
	(void)sck_bench_pq_keygen(W);
	(void)sck_bench_pq_encaps(W);
	(void)sck_bench_pq_decaps(W);
	(void)sck_bench_pq_sig_sign(W);
	(void)sck_bench_pq_sig_verify(W);
	(void)sck_bench_pq_aead_enc(W);
	(void)sck_bench_pq_aead_dec(W);
	(void)sck_bench_pq_hkdf(W);
	(void)sck_bench_pq_hash(W);

	/* Measurement pass */
	/* Classic */
	c->keygen       = sck_bench_keygen_x25519(N);
	c->aead_enc     = sck_bench_encap(N);     /* actually AEAD encrypt */
	c->aead_dec     = sck_bench_decap(N);     /* actually AEAD decrypt */
	c->signature    = sck_bench_signature(N);
	c->verification = sck_bench_verification(N);
	c->ecdh         = sck_bench_ecdh(N);
	c->hkdf         = sck_bench_hkdf(N);
	c->hash         = sck_bench_hash(N);
	/* PQ */
	c->pq_keygen     = sck_bench_pq_keygen(N);
	c->pq_encaps     = sck_bench_pq_encaps(N);
	c->pq_decaps     = sck_bench_pq_decaps(N);
	c->pq_sig_sign   = sck_bench_pq_sig_sign(N);
	c->pq_sig_verify = sck_bench_pq_sig_verify(N);
	c->pq_aead_enc   = sck_bench_pq_aead_enc(N);
	c->pq_aead_dec   = sck_bench_pq_aead_dec(N);
	c->pq_hkdf       = sck_bench_pq_hkdf(N);
	c->pq_hash       = sck_bench_pq_hash(N);
}

/* Helper: copy timing from cache, set calls count */
static struct sck_op_result sck_op(const struct sck_op_result *src, int calls)
{
	if (calls <= 0)
		return (struct sck_op_result){0};

	struct sck_op_result r = *src;
	r.calls = calls;
	return r;
}

static struct sck_op_result sck_op_zero(void)
{
	return (struct sck_op_result){0};
}

/* =============================================================================
 * Operations benchmark assembly (same call counts as edhoc_benchmark.c)
 * =============================================================================
 */

static void sck_assemble_classic_ops(const struct sck_prim_cache *c,
				     int type_num, bool is_initiator,
				     struct sck_ops_benchmark *ops)
{
	ops->keygen       = sck_op(&c->keygen, 1);
	/* Classic EDHOC has no KEM encap/decap — uses AEAD encrypt/decrypt */
	ops->aead_enc     = sck_op(&c->aead_enc, is_initiator ? 1 : 0);
	ops->aead_dec     = sck_op(&c->aead_dec, is_initiator ? 0 : 1);
	if (type_num == 0) {
		ops->signature    = sck_op(&c->signature, 1);
		ops->verification = sck_op(&c->verification, 1);
	} else {
		ops->signature    = sck_op_zero();
		ops->verification = sck_op_zero();
	}
	ops->ecdh = sck_op(&c->ecdh, (type_num == 0) ? 2 : 4);
	ops->hkdf = sck_op(&c->hkdf, (type_num == 0) ? 8 : 10);
	ops->hash = sck_op(&c->hash, 4);
	/* Zero PQ fields */
	memset(&ops->pq_keygen, 0, sizeof(struct sck_op_result) * 9);
}

static void sck_assemble_pq_ops(const struct sck_prim_cache *c,
				int pq_type_num, bool is_initiator,
				struct sck_ops_benchmark *ops)
{
	ops->pq_keygen = sck_op(&c->pq_keygen, 1);
	ops->pq_encaps = sck_op(&c->pq_encaps,
		(pq_type_num == 0) ? 1 : (is_initiator ? 1 : 2));
	ops->pq_decaps = sck_op(&c->pq_decaps,
		(pq_type_num == 0) ? 1 : (is_initiator ? 2 : 1));
	if (pq_type_num == 0) {
		ops->pq_sig_sign   = sck_op(&c->pq_sig_sign, 1);
		ops->pq_sig_verify = sck_op(&c->pq_sig_verify, 1);
	} else {
		ops->pq_sig_sign   = sck_op_zero();
		ops->pq_sig_verify = sck_op_zero();
	}
	ops->pq_aead_enc = sck_op(&c->pq_aead_enc, is_initiator ? 2 : 1);
	ops->pq_aead_dec = sck_op(&c->pq_aead_dec, is_initiator ? 1 : 2);
	ops->pq_hkdf     = sck_op(&c->pq_hkdf, 8);
	ops->pq_hash     = sck_op(&c->pq_hash, 3);
	/* Zero classic fields */
	memset(&ops->keygen, 0, sizeof(struct sck_op_result) * 8);
}

static void sck_assemble_hybrid_ops(const struct sck_prim_cache *c,
				    bool is_initiator,
				    struct sck_ops_benchmark *ops)
{
	ops->keygen       = sck_op(&c->keygen, 1);
	/* Hybrid uses AEAD enc/dec (not KEM encap/decap for classic part) */
	ops->aead_enc     = sck_op(&c->aead_enc, 1);
	ops->aead_dec     = sck_op(&c->aead_dec, 1);
	ops->signature    = sck_op_zero();
	ops->verification = sck_op_zero();
	ops->ecdh         = sck_op(&c->ecdh, 4);
	ops->hkdf         = sck_op(&c->hkdf, 10);
	ops->hash         = sck_op(&c->hash, 3);
	/* PQ KEM encaps/decaps — actually measured */
	ops->pq_keygen    = sck_op(&c->pq_keygen, is_initiator ? 1 : 0);
	ops->pq_encaps    = sck_op(&c->pq_encaps, is_initiator ? 0 : 1);
	ops->pq_decaps    = sck_op(&c->pq_decaps, is_initiator ? 1 : 0);
	ops->pq_sig_sign  = sck_op_zero();
	ops->pq_sig_verify = sck_op_zero();
	ops->pq_aead_enc  = sck_op_zero();
	ops->pq_aead_dec  = sck_op_zero();
	ops->pq_hkdf      = sck_op_zero();
	ops->pq_hash      = sck_op_zero();
}

/* =============================================================================
 * Compute / Calibrate helpers
 * =============================================================================
 */

#define SCOST(OP) ((OP).avg_us * (double)(OP).calls)

/* Memory estimation (same as edhoc_benchmark.c) */
/*
 * Memory estimation per role (Initiator vs Responder).
 *
 * Methodology: We estimate PEAK concurrent memory usage as:
 *   context_struct + thread_data + peak_stack_frame
 *
 * For all EDHOC variants, the Responder uses MORE memory than the
 * Initiator because:
 *   - Classic: responder_context (240 B) > initiator_context (228 B),
 *              plus listen/accept socket overhead.
 *   - PQ/Hybrid: The responder must store the initiator's received
 *     ephemeral public key (pk_eph, 1184 B for PQ) while simultaneously
 *     preparing its response. The initiator generates its own ephemeral
 *     key in-place.
 *   - All: Responder has server-socket overhead (listen fd, accept, etc.)
 *
 * is_initiator: 1 = Initiator, 0 = Responder
 */

static long sck_estimate_classic_memory(int type_num, int is_initiator)
{
	/*
	 * Shared base: test vector credential buffers, PRK output,
	 * connection IDs, err_msg_buf[64], byte_array overhead,
	 * cred_array, other_party_cred struct.
	 */
	long shared = 1536 + 640 + 256 + 128 + 256 + 384 + 512 + 256;

	if (is_initiator) {
		/* edhoc_initiator_context: 228 bytes
		 * Type 0 adds sign-key buffers (sk_i, pk_i). */
		long ctx = 228;
		long keys = (type_num == 0) ? 512 : 0;
		return shared + ctx + keys;
	} else {
		/* edhoc_responder_context: 240 bytes (extra ead_4 field)
		 * Type 0 adds sign-key buffers (sk_r, pk_r).
		 * Server socket: listen_fd + accept overhead. */
		long ctx = 240;
		long keys = (type_num == 0) ? 512 : 0;
		long server = 64;
		return shared + ctx + keys + server;
	}
}

static long sck_estimate_pq_memory(int pq_type_num, int is_initiator)
{
	/*
	 * pq_party_ctx / pq3_party_ctx: stored on heap via thread data.
	 *   - lt_pk[1184], lt_sk[2400], other_lt_pk[1184]
	 *   - eph_pk[1184], eph_sk[2400]
	 *   - prk1[32], prk2[32], prk3[32], prk_out[32]
	 *   - th2[32], th3[32], th4[32]
	 *   - success(4), padding(4)
	 *   For Type 0: + sig_pk[1952], sig_sk[4032], other_sig_pk[1952], other_sig_sk pad
	 */
	long ctx_base = PQ_KEM_PK_LEN*3 + PQ_KEM_SK_LEN*2 +
			PQ_PRK_LEN*4 + PQ_HASH_LEN*3 + PQ_PRK_LEN + 16;
	if (pq_type_num == 0)
		ctx_base += 2*PQ_SIG_PK_LEN + 2*PQ_SIG_SK_LEN;

	/* Thread data: 3x msg_buf[8192] + lengths + timing fields */
	long thread_data = 3 * 8192 + 64;

	/*
	 * Peak stack frame — we estimate the MAXIMUM concurrent locals.
	 *
	 * Both roles share these temporaries (not all live at once):
	 *   - Key/IV pairs: k[16]+iv[13] = 29 each, up to 3 sets = 87
	 *   - Plaintext buffers: pt[256..512]
	 *   - Ciphertext/AEAD buffers: ct_aead[264..520]
	 *   - Hash inputs: th_input[8192] (reused across phases)
	 *   - MAC info+tag: mac_info[96]+mac[8] = 104
	 *
	 * Key difference:
	 *   Initiator: generates eph key in ctx (no extra buffer),
	 *              encaps to other_lt_pk → ct_R[1088]+ss_R[32]
	 *   Responder: receives pk_eph[1184] from msg1 parse,
	 *              decaps ct_R → ss_R[32],
	 *              encaps to pk_eph → ct_eph2[1088]+ss_eph[32]
	 *              plus server listen/accept overhead.
	 */
	long peak_common;
	if (pq_type_num == 0) {
		/* Type 0 (Sig-Sig): sig buffers + larger AEAD for sig */
		peak_common = 87 +        /* 3x key/iv */
			      1088 + 32 + /* ct_R + ss_R (or ct_eph2 + ss_eph) */
			      256 + 264 + /* pt1 + ct1_aead */
			      3309 +      /* sig buffer (sign or verify) */
			      512 + 520 + /* pt2 + ct2_aead */
			      8192 +      /* th_input (largest hash input) */
			      104 +       /* mac_info + mac tag */
			      3413;       /* th4_in (for PRK_out) */
	} else {
		/* Type 3 (MAC-MAC): no sig buffers, smaller AEAD for MAC */
		peak_common = 87 +
			      1088 + 32 + /* ct_R + ss_R */
			      256 + 264 + /* pt1 + ct1_aead */
			      512 + 520 + /* pt2 + ct2_aead */
			      8192 +      /* th_input */
			      104 +       /* mac_info + mac */
			      96;         /* th4_in */
	}

	if (is_initiator) {
		/* Initiator generates ephemeral key in-place (ctx->eph_pk/sk).
		 * Peak frame: common + msg2 parse (ct_eph2[1088] for decap). */
		long extra = 1088;  /* ct_eph2 from msg2 parse */
		if (pq_type_num == 3)
			extra += 1088;  /* ct_I from msg2 parse (Type 3 static KEM) */
		return ctx_base + thread_data + peak_common + extra;
	} else {
		/* Responder receives initiator's pk_eph[1184] from msg1.
		 * Plus server listen/accept overhead. */
		long extra = PQ_KEM_PK_LEN; /* pk_eph from msg1 */
		if (pq_type_num == 3)
			extra += 1088 + 32;  /* ct_I + ss_I (encaps to other_lt_pk) */
		long server = 64;
		return ctx_base + thread_data + peak_common + extra + server;
	}
}

static long sck_estimate_hybrid_memory(int is_initiator)
{
	/*
	 * hybrid_party_ctx:
	 *   static_sk[32], static_pk[32], other_static_pk[32]
	 *   eph_sk[32], eph_pk[32]                           = 160
	 *   kem_pk[1184], kem_sk[2400]                       (initiator only)
	 *   prk2e[32], prk3e2m[32], prk4e3m[32], prk_out[32] = 128
	 *   th2[32], th3[32], th4[32]                         = 96
	 *   success(4) + padding                              = 16
	 * Total = 160 + 3584 + 128 + 96 + 16 = 3984
	 *
	 * NOTE: hybrid_party_ctx includes kem_pk[1184]+kem_sk[2400] for
	 * BOTH roles (same struct), so ctx size is identical.
	 */
	long ctx_size = 5*32 + PQ_KEM_PK_LEN + PQ_KEM_SK_LEN +
			4*32 + 32 + 16;

	/* Thread data: 3x msg_buf[8192] + lengths + timing */
	long thread_data = 3 * 8192 + 64;

	/*
	 * Peak stack frame — shared between roles:
	 *   peer_eph[32], ss_eph[32]
	 *   c_kem[1088], k_kem[32]
	 *   th_input[8192] (block-scoped, reused)
	 *   ikm[64], ss_DH[32] (e.g. ss_bx or ss_xb)
	 *   ek[16]+iv[13] = 29, ec[64]
	 *   mac[8]+mac_info[96] = 104
	 *   pt[256]+ct_aead[520]
	 *   th4_in[256]
	 */
	long peak_common = 32 + 32 +    /* peer_eph + ss_eph */
			   1088 + 32 +   /* c_kem + k_kem */
			   8192 + 64 +   /* th_input + ikm */
			   32 + 29 + 64 + /* ss_DH + ek/iv + ec */
			   104 +          /* mac + mac_info */
			   256 + 520 +    /* pt2 + ct2_aead */
			   128 + 136 +    /* pt3 + ct3_aead */
			   256;           /* th4_in */

	if (is_initiator) {
		/* Initiator generates kem_pk+kem_sk in ctx (m1 contains X+PK_KEM).
		 * No extra stack beyond peak_common. */
		return ctx_size + thread_data + peak_common;
	} else {
		/* Responder receives initiator's pk_kem from msg1 parse —
		 * this is an additional stack local beyond the ctx's own kem_pk.
		 * Plus server listen/accept overhead. */
		long pk_kem_received = PQ_KEM_PK_LEN;
		long server = 64;
		return ctx_size + thread_data + peak_common + pk_kem_received + server;
	}
}

/* =============================================================================
 * Socket-based Classic Handshake (Type 0 / Type 3)
 *
 * Classic variants use the uoscore-uedhoc library's edhoc_initiator_run /
 * edhoc_responder_run which take tx/rx callback function pointers.
 * We provide socket-based tx/rx callbacks here.
 * =============================================================================
 */

/* Per-thread socket fd and txrx accumulator */
static __thread int tl_sock_fd = -1;
static __thread uint64_t tl_sock_txrx_ns = 0;

/* Classic Initiator tx: send data over socket (Initiator → Responder) */
static enum err sock_tx_initiator(void *sock, struct byte_array *data)
{
	uint64_t start = sck_get_time_ns();
	int r = sock_send_msg(tl_sock_fd, data->ptr, data->len);
	uint64_t end = sck_get_time_ns();
	tl_sock_txrx_ns += (end - start);
	return (r == 0) ? ok : buffer_to_small;
}

/* Classic Initiator rx: receive data from socket */
static enum err sock_rx_initiator(void *sock, struct byte_array *data)
{
	uint64_t start = sck_get_time_ns();
	uint32_t recv_len = 0;
	int r = sock_recv_msg(tl_sock_fd, data->ptr, data->len, &recv_len);
	uint64_t end = sck_get_time_ns();
	tl_sock_txrx_ns += (end - start);
	if (r != 0) return buffer_to_small;
	data->len = recv_len;
	return ok;
}

/* Classic Responder tx: send data over socket */
static enum err sock_tx_responder(void *sock, struct byte_array *data)
{
	uint64_t start = sck_get_time_ns();
	int r = sock_send_msg(tl_sock_fd, data->ptr, data->len);
	uint64_t end = sck_get_time_ns();
	tl_sock_txrx_ns += (end - start);
	return (r == 0) ? ok : buffer_to_small;
}

/* Classic Responder rx: receive data from socket */
static enum err sock_rx_responder(void *sock, struct byte_array *data)
{
	uint64_t start = sck_get_time_ns();
	uint32_t recv_len = 0;
	int r = sock_recv_msg(tl_sock_fd, data->ptr, data->len, &recv_len);
	uint64_t end = sck_get_time_ns();
	tl_sock_txrx_ns += (end - start);
	if (r != 0) return buffer_to_small;
	data->len = recv_len;
	return ok;
}

/* Thread data for classic handshake benchmark */
struct sck_classic_thread_data {
	int type_num;
	int port;         /* TCP port */
	enum err error;
	uint8_t prk_out_buf[32];
	struct byte_array prk_out;
	uint64_t cpu_start_ns, cpu_end_ns;
	uint64_t wall_start_ns, wall_end_ns;
	uint64_t txrx_ns;
	size_t   heap_peak_bytes;
};

/* Classic Initiator thread (client: connects to Responder) */
static void *sck_classic_initiator_thread(void *arg)
{
	struct sck_classic_thread_data *d = (struct sck_classic_thread_data *)arg;
	d->prk_out.ptr = d->prk_out_buf;
	d->prk_out.len = sizeof(d->prk_out_buf);

	uint8_t err_msg_buf[64];
	struct byte_array err_msg = {.ptr = err_msg_buf, .len = sizeof(err_msg_buf)};

	/* Connect to responder (server) */
	tl_sock_fd = sock_connect_client(d->port);
	if (tl_sock_fd < 0) { d->error = buffer_to_small; return NULL; }
	int opt = 1;
	setsockopt(tl_sock_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

	tl_sock_txrx_ns = 0;
	heap_tracker_reset();

	if (d->type_num == 0) {
		struct edhoc_initiator_context c_i;
		memset(&c_i, 0, sizeof(c_i));
		c_i.sock = NULL;
		c_i.method = (enum method_type)T1_RFC9529__METHOD;
		c_i.c_i.len = T1_RFC9529__C_I_LEN; c_i.c_i.ptr = (uint8_t*)T1_RFC9529__C_I;
		c_i.suites_i.len = T1_RFC9529__SUITES_I_LEN; c_i.suites_i.ptr = (uint8_t*)T1_RFC9529__SUITES_I;
		c_i.ead_1.len = 0; c_i.ead_1.ptr = NULL;
		c_i.ead_3.len = 0; c_i.ead_3.ptr = NULL;
		c_i.id_cred_i.len = T1_RFC9529__ID_CRED_I_LEN; c_i.id_cred_i.ptr = (uint8_t*)T1_RFC9529__ID_CRED_I;
		c_i.cred_i.len = T1_RFC9529__CRED_I_LEN; c_i.cred_i.ptr = (uint8_t*)T1_RFC9529__CRED_I;
		c_i.g_x.len = T1_RFC9529__G_X_LEN; c_i.g_x.ptr = (uint8_t*)T1_RFC9529__G_X;
		c_i.x.len = T1_RFC9529__X_LEN; c_i.x.ptr = (uint8_t*)T1_RFC9529__X;
		c_i.sk_i.len = T1_RFC9529__SK_I_LEN; c_i.sk_i.ptr = (uint8_t*)T1_RFC9529__SK_I;
		c_i.pk_i.len = T1_RFC9529__PK_I_LEN; c_i.pk_i.ptr = (uint8_t*)T1_RFC9529__PK_I;
		c_i.g_i.len = 0; c_i.g_i.ptr = NULL;
		c_i.i.len = 0; c_i.i.ptr = NULL;
		struct other_party_cred cred_r;
		memset(&cred_r, 0, sizeof(cred_r));
		cred_r.id_cred.len = T1_RFC9529__ID_CRED_R_LEN; cred_r.id_cred.ptr = (uint8_t*)T1_RFC9529__ID_CRED_R;
		cred_r.cred.len = T1_RFC9529__CRED_R_LEN; cred_r.cred.ptr = (uint8_t*)T1_RFC9529__CRED_R;
		cred_r.pk.len = T1_RFC9529__PK_R_LEN; cred_r.pk.ptr = (uint8_t*)T1_RFC9529__PK_R;
		cred_r.g.len = 0; cred_r.g.ptr = NULL;
		cred_r.ca.len = 0; cred_r.ca.ptr = NULL; cred_r.ca_pk.len = 0; cred_r.ca_pk.ptr = NULL;
		struct cred_array ca = {.len = 1, .ptr = &cred_r};

		d->cpu_start_ns = sck_get_thread_cpu_ns();
		d->wall_start_ns = sck_get_time_ns();
		d->error = edhoc_initiator_run(&c_i, &ca, &err_msg, &d->prk_out,
					       sock_tx_initiator, sock_rx_initiator, ead_process);
		d->wall_end_ns = sck_get_time_ns();
		d->cpu_end_ns = sck_get_thread_cpu_ns();
	} else {
		/* Type 3 */
		struct edhoc_initiator_context c_i;
		memset(&c_i, 0, sizeof(c_i));
		c_i.sock = NULL;
		c_i.method = (enum method_type)T3_X25519_METHOD;
		c_i.c_i.len = T3_X25519_C_I_LEN; c_i.c_i.ptr = (uint8_t*)T3_X25519_C_I;
		c_i.suites_i.len = T3_X25519_SUITES_I_LEN; c_i.suites_i.ptr = (uint8_t*)T3_X25519_SUITES_I;
		c_i.ead_1.len = 0; c_i.ead_1.ptr = NULL;
		c_i.ead_3.len = 0; c_i.ead_3.ptr = NULL;
		c_i.id_cred_i.len = T1_RFC9529__ID_CRED_I_LEN; c_i.id_cred_i.ptr = (uint8_t*)T1_RFC9529__ID_CRED_I;
		c_i.cred_i.len = T1_RFC9529__CRED_I_LEN; c_i.cred_i.ptr = (uint8_t*)T1_RFC9529__CRED_I;
		c_i.g_x.len = T3_X25519_G_X_LEN; c_i.g_x.ptr = (uint8_t*)T3_X25519_G_X;
		c_i.x.len = T3_X25519_X_LEN; c_i.x.ptr = (uint8_t*)T3_X25519_X;
		c_i.g_i.len = T3_X25519_G_I_LEN; c_i.g_i.ptr = (uint8_t*)T3_X25519_G_I;
		c_i.i.len = T3_X25519_I_LEN; c_i.i.ptr = (uint8_t*)T3_X25519_I;
		c_i.sk_i.len = 0; c_i.sk_i.ptr = NULL;
		c_i.pk_i.len = 0; c_i.pk_i.ptr = NULL;
		struct other_party_cred cred_r;
		memset(&cred_r, 0, sizeof(cred_r));
		cred_r.id_cred.len = T1_RFC9529__ID_CRED_R_LEN; cred_r.id_cred.ptr = (uint8_t*)T1_RFC9529__ID_CRED_R;
		cred_r.cred.len = T1_RFC9529__CRED_R_LEN; cred_r.cred.ptr = (uint8_t*)T1_RFC9529__CRED_R;
		cred_r.g.len = T3_X25519_G_R_LEN; cred_r.g.ptr = (uint8_t*)T3_X25519_G_R;
		cred_r.pk.len = 0; cred_r.pk.ptr = NULL;
		cred_r.ca.len = 0; cred_r.ca.ptr = NULL; cred_r.ca_pk.len = 0; cred_r.ca_pk.ptr = NULL;
		struct cred_array ca = {.len = 1, .ptr = &cred_r};

		heap_tracker_reset();
		d->cpu_start_ns = sck_get_thread_cpu_ns();
		d->wall_start_ns = sck_get_time_ns();
		d->error = edhoc_initiator_run(&c_i, &ca, &err_msg, &d->prk_out,
					       sock_tx_initiator, sock_rx_initiator, ead_process);
		d->wall_end_ns = sck_get_time_ns();
		d->cpu_end_ns = sck_get_thread_cpu_ns();
	}

	d->txrx_ns = tl_sock_txrx_ns;
	d->heap_peak_bytes = heap_tracker_get_peak();
	close(tl_sock_fd);
	tl_sock_fd = -1;
	return NULL;
}

/* Classic Responder thread (server: accepts connection from Initiator) */
static void *sck_classic_responder_thread(void *arg)
{
	struct sck_classic_thread_data *d = (struct sck_classic_thread_data *)arg;
	d->prk_out.ptr = d->prk_out_buf;
	d->prk_out.len = sizeof(d->prk_out_buf);

	uint8_t err_msg_buf[64];
	struct byte_array err_msg = {.ptr = err_msg_buf, .len = sizeof(err_msg_buf)};

	/* Create server socket and accept connection */
	int listen_fd = sock_create_server(d->port);
	if (listen_fd < 0) { d->error = buffer_to_small; return NULL; }

	tl_sock_fd = accept(listen_fd, NULL, NULL);
	close(listen_fd);
	if (tl_sock_fd < 0) { d->error = buffer_to_small; return NULL; }
	int opt = 1;
	setsockopt(tl_sock_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

	tl_sock_txrx_ns = 0;
	heap_tracker_reset();

	if (d->type_num == 0) {
		struct edhoc_responder_context c_r;
		memset(&c_r, 0, sizeof(c_r));
		c_r.sock = NULL;
		c_r.c_r.len = T1_RFC9529__C_R_LEN; c_r.c_r.ptr = (uint8_t*)T1_RFC9529__C_R;
		c_r.suites_r.len = T1_RFC9529__SUITES_R_LEN; c_r.suites_r.ptr = (uint8_t*)T1_RFC9529__SUITES_R;
		c_r.ead_2.len = 0; c_r.ead_2.ptr = NULL;
		c_r.ead_4.len = 0; c_r.ead_4.ptr = NULL;
		c_r.id_cred_r.len = T1_RFC9529__ID_CRED_R_LEN; c_r.id_cred_r.ptr = (uint8_t*)T1_RFC9529__ID_CRED_R;
		c_r.cred_r.len = T1_RFC9529__CRED_R_LEN; c_r.cred_r.ptr = (uint8_t*)T1_RFC9529__CRED_R;
		c_r.g_y.len = T1_RFC9529__G_Y_LEN; c_r.g_y.ptr = (uint8_t*)T1_RFC9529__G_Y;
		c_r.y.len = T1_RFC9529__Y_LEN; c_r.y.ptr = (uint8_t*)T1_RFC9529__Y;
		c_r.sk_r.len = T1_RFC9529__SK_R_LEN; c_r.sk_r.ptr = (uint8_t*)T1_RFC9529__SK_R;
		c_r.pk_r.len = T1_RFC9529__PK_R_LEN; c_r.pk_r.ptr = (uint8_t*)T1_RFC9529__PK_R;
		c_r.g_r.len = 0; c_r.g_r.ptr = NULL;
		c_r.r.len = 0; c_r.r.ptr = NULL;
		struct other_party_cred cred_i;
		memset(&cred_i, 0, sizeof(cred_i));
		cred_i.id_cred.len = T1_RFC9529__ID_CRED_I_LEN; cred_i.id_cred.ptr = (uint8_t*)T1_RFC9529__ID_CRED_I;
		cred_i.cred.len = T1_RFC9529__CRED_I_LEN; cred_i.cred.ptr = (uint8_t*)T1_RFC9529__CRED_I;
		cred_i.pk.len = T1_RFC9529__PK_I_LEN; cred_i.pk.ptr = (uint8_t*)T1_RFC9529__PK_I;
		cred_i.g.len = 0; cred_i.g.ptr = NULL;
		cred_i.ca.len = 0; cred_i.ca.ptr = NULL; cred_i.ca_pk.len = 0; cred_i.ca_pk.ptr = NULL;
		struct cred_array ca = {.len = 1, .ptr = &cred_i};

		d->cpu_start_ns = sck_get_thread_cpu_ns();
		d->wall_start_ns = sck_get_time_ns();
		d->error = edhoc_responder_run(&c_r, &ca, &err_msg, &d->prk_out,
					       sock_tx_responder, sock_rx_responder, ead_process);
		d->wall_end_ns = sck_get_time_ns();
		d->cpu_end_ns = sck_get_thread_cpu_ns();
	} else {
		/* Type 3 */
		struct edhoc_responder_context c_r;
		memset(&c_r, 0, sizeof(c_r));
		c_r.sock = NULL;
		c_r.c_r.len = T3_X25519_C_R_LEN; c_r.c_r.ptr = (uint8_t*)T3_X25519_C_R;
		c_r.suites_r.len = T3_X25519_SUITES_R_LEN; c_r.suites_r.ptr = (uint8_t*)T3_X25519_SUITES_R;
		c_r.ead_2.len = 0; c_r.ead_2.ptr = NULL;
		c_r.ead_4.len = 0; c_r.ead_4.ptr = NULL;
		c_r.id_cred_r.len = T1_RFC9529__ID_CRED_R_LEN; c_r.id_cred_r.ptr = (uint8_t*)T1_RFC9529__ID_CRED_R;
		c_r.cred_r.len = T1_RFC9529__CRED_R_LEN; c_r.cred_r.ptr = (uint8_t*)T1_RFC9529__CRED_R;
		c_r.g_y.len = T3_X25519_G_Y_LEN; c_r.g_y.ptr = (uint8_t*)T3_X25519_G_Y;
		c_r.y.len = T3_X25519_Y_LEN; c_r.y.ptr = (uint8_t*)T3_X25519_Y;
		c_r.g_r.len = T3_X25519_G_R_LEN; c_r.g_r.ptr = (uint8_t*)T3_X25519_G_R;
		c_r.r.len = T3_X25519_R_LEN; c_r.r.ptr = (uint8_t*)T3_X25519_R;
		c_r.sk_r.len = 0; c_r.sk_r.ptr = NULL;
		c_r.pk_r.len = 0; c_r.pk_r.ptr = NULL;
		struct other_party_cred cred_i;
		memset(&cred_i, 0, sizeof(cred_i));
		cred_i.id_cred.len = T1_RFC9529__ID_CRED_I_LEN; cred_i.id_cred.ptr = (uint8_t*)T1_RFC9529__ID_CRED_I;
		cred_i.cred.len = T1_RFC9529__CRED_I_LEN; cred_i.cred.ptr = (uint8_t*)T1_RFC9529__CRED_I;
		cred_i.g.len = T3_X25519_G_I_LEN; cred_i.g.ptr = (uint8_t*)T3_X25519_G_I;
		cred_i.pk.len = 0; cred_i.pk.ptr = NULL;
		cred_i.ca.len = 0; cred_i.ca.ptr = NULL; cred_i.ca_pk.len = 0; cred_i.ca_pk.ptr = NULL;
		struct cred_array ca = {.len = 1, .ptr = &cred_i};

		heap_tracker_reset();
		d->cpu_start_ns = sck_get_thread_cpu_ns();
		d->wall_start_ns = sck_get_time_ns();
		d->error = edhoc_responder_run(&c_r, &ca, &err_msg, &d->prk_out,
					       sock_tx_responder, sock_rx_responder, ead_process);
		d->wall_end_ns = sck_get_time_ns();
		d->cpu_end_ns = sck_get_thread_cpu_ns();
	}

	d->txrx_ns = tl_sock_txrx_ns;
	d->heap_peak_bytes = heap_tracker_get_peak();
	close(tl_sock_fd);
	tl_sock_fd = -1;
	return NULL;
}

/* =============================================================================
 * Socket-based PQ Type 0 Handshake (ML-KEM-768 + ML-DSA-65)
 *
 * Complete reimplementation of the PQ Type 0 initiator/responder threads
 * that exchanges all 3 messages via real TCP socket instead of the
 * pthread-based global g_pq_exchange struct.
 *
 * Each thread keeps LOCAL copies of raw wire messages (needed for
 * transcript hash computation: TH2 = H(msg1||ct_eph2), etc.).
 * =============================================================================
 */

#define SCK_PQ_MSG_BUF_SIZE  8192

/* ── PQ Type 0 key-derivation helpers (same as edhoc_type0_pq.c) ─── */
static const uint8_t SCK_PQ0_K1[]   = "EDHOC-PQ-K1";
static const uint8_t SCK_PQ0_IV1[]  = "EDHOC-PQ-IV1";
static const uint8_t SCK_PQ0_K2[]   = "EDHOC-PQ-K2";
static const uint8_t SCK_PQ0_IV2[]  = "EDHOC-PQ-IV2";
static const uint8_t SCK_PQ0_K3[]   = "EDHOC-PQ-K3";
static const uint8_t SCK_PQ0_IV3[]  = "EDHOC-PQ-IV3";
static const uint8_t SCK_PQ0_MAC2[] = "EDHOC-PQ-MAC2";
static const uint8_t SCK_PQ0_MAC3[] = "EDHOC-PQ-MAC3";
static const uint8_t SCK_PQ0_OUT[]  = "EDHOC-PQ-PRK_out";
static const uint8_t SCK_PQ0_IDI[]  = "EDHOC-PQ-Initiator";
static const uint8_t SCK_PQ0_IDR[]  = "EDHOC-PQ-Responder";

static int sck_pq0_derive_key_iv(const uint8_t *prk, const uint8_t *label,
				  size_t label_len, uint8_t *key, uint8_t *iv)
{
	uint8_t info[64];
	memcpy(info, label, label_len);
	if (pq_hkdf_expand(prk, info, label_len, key, PQ_AEAD_KEY_LEN) != 0)
		return -1;
	uint8_t iv_info[64];
	memcpy(iv_info, label, label_len);
	iv_info[0] ^= 0xFF;
	if (pq_hkdf_expand(prk, iv_info, label_len, iv, PQ_AEAD_NONCE_LEN) != 0)
		return -1;
	return 0;
}

/* Thread data for socket-based PQ handshake */
struct sck_pq_thread_data {
	int sock_fd;                     /* connected TCP socket (set internally) */
	int port;                        /* TCP port for accept/connect */
	struct pq_party_ctx *ctx;        /* PQ crypto context */
	int error;                       /* 0=ok, -1=fail */
	uint64_t cpu_start_ns, cpu_end_ns;
	uint64_t wall_start_ns, wall_end_ns;
	uint64_t txrx_ns;
	/* Local message buffers for transcript hash */
	uint8_t msg1_buf[SCK_PQ_MSG_BUF_SIZE]; uint32_t msg1_len;
	uint8_t msg2_buf[SCK_PQ_MSG_BUF_SIZE]; uint32_t msg2_len;
	uint8_t msg3_buf[SCK_PQ_MSG_BUF_SIZE]; uint32_t msg3_len;
	size_t  heap_peak_bytes;
};

/* ── PQ Type 0 Initiator (socket-based, client) ─────────────────────── */
static void *sck_pq0_initiator_thread(void *arg)
{
	struct sck_pq_thread_data *d = (struct sck_pq_thread_data *)arg;
	struct pq_party_ctx *ctx = d->ctx;
	int ret;
	d->txrx_ns = 0;
	d->error = -1;

	/* Connect to responder */
	d->sock_fd = sock_connect_client(d->port);
	if (d->sock_fd < 0) return NULL;
	int opt = 1;
	setsockopt(d->sock_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

	heap_tracker_reset();
	d->cpu_start_ns = sck_get_thread_cpu_ns();
	d->wall_start_ns = sck_get_time_ns();

	/* Step 1: Generate ephemeral KEM key pair */
	ret = pq_kem_keygen(ctx->eph_pk, ctx->eph_sk);
	if (ret != 0) goto fail;

	/* Encaps to pkR */
	uint8_t ct_R[PQ_KEM_CT_LEN], ss_R[PQ_KEM_SS_LEN];
	ret = pq_kem_encaps(ct_R, ss_R, ctx->other_lt_pk);
	if (ret != 0) goto fail;

	/* PRK1 */
	ret = pq_hkdf_extract(NULL, 0, ss_R, PQ_KEM_SS_LEN, ctx->prk1);
	if (ret != 0) goto fail;

	/* K1, IV1 */
	uint8_t k1[PQ_AEAD_KEY_LEN], iv1[PQ_AEAD_NONCE_LEN];
	ret = sck_pq0_derive_key_iv(ctx->prk1, SCK_PQ0_K1, sizeof(SCK_PQ0_K1)-1, k1, iv1);
	if (ret != 0) goto fail;

	/* Plaintext: METHOD || SUITES || C_I */
	uint8_t pt1[256]; uint32_t pt1_len = 0;
	pt1[pt1_len++] = 0x00; pt1[pt1_len++] = 0x00; pt1[pt1_len++] = 0x37;

	/* AEAD encrypt msg1 */
	uint8_t ct1_aead[256+PQ_AEAD_TAG_LEN]; size_t ct1_aead_len = 0;
	ret = pq_aead_encrypt(k1, iv1, NULL, 0, pt1, pt1_len, ct1_aead, &ct1_aead_len);
	if (ret != 0) goto fail;

	/* Build wire msg1: pk_eph || ct_R || aead_len(2) || AEAD_ct */
	{
		uint8_t *p = d->msg1_buf; uint32_t off = 0;
		memcpy(p+off, ctx->eph_pk, PQ_KEM_PK_LEN); off += PQ_KEM_PK_LEN;
		memcpy(p+off, ct_R, PQ_KEM_CT_LEN); off += PQ_KEM_CT_LEN;
		p[off++] = (uint8_t)(ct1_aead_len >> 8);
		p[off++] = (uint8_t)(ct1_aead_len & 0xFF);
		memcpy(p+off, ct1_aead, ct1_aead_len); off += ct1_aead_len;
		d->msg1_len = off;
	}

	/* Send msg1 via TCP */
	{
		uint64_t t0 = sck_get_time_ns();
		ret = sock_send_msg(d->sock_fd, d->msg1_buf, d->msg1_len);
		d->txrx_ns += (sck_get_time_ns() - t0);
		if (ret != 0) goto fail;
	}

	/* Receive msg2 via TCP */
	{
		uint64_t t0 = sck_get_time_ns();
		ret = sock_recv_msg(d->sock_fd, d->msg2_buf, SCK_PQ_MSG_BUF_SIZE, &d->msg2_len);
		d->txrx_ns += (sck_get_time_ns() - t0);
		if (ret != 0) goto fail;
	}

	/* Parse msg2: ct_eph2 || sig2_len(2) || sig2 || aead_len(2) || AEAD_ct */
	uint8_t *msg2 = d->msg2_buf; uint32_t m2off = 0;
	uint8_t ct_eph2[PQ_KEM_CT_LEN];
	memcpy(ct_eph2, msg2+m2off, PQ_KEM_CT_LEN); m2off += PQ_KEM_CT_LEN;
	uint16_t sig2_len = (msg2[m2off]<<8)|msg2[m2off+1]; m2off += 2;
	uint8_t sig2_buf[PQ_SIG_MAX_LEN];
	memcpy(sig2_buf, msg2+m2off, sig2_len); m2off += sig2_len;
	uint16_t ct2_aead_len = (msg2[m2off]<<8)|msg2[m2off+1]; m2off += 2;
	uint8_t ct2_aead[512+PQ_AEAD_TAG_LEN];
	memcpy(ct2_aead, msg2+m2off, ct2_aead_len);

	/* Decaps ct_eph2 */
	uint8_t ss_eph[PQ_KEM_SS_LEN];
	ret = pq_kem_decaps(ss_eph, ct_eph2, ctx->eph_sk);
	if (ret != 0) goto fail;

	/* PRK2 */
	ret = pq_hkdf_extract(ctx->prk1, PQ_PRK_LEN, ss_eph, PQ_KEM_SS_LEN, ctx->prk2);
	if (ret != 0) goto fail;

	uint8_t k2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
	ret = sck_pq0_derive_key_iv(ctx->prk2, SCK_PQ0_K2, sizeof(SCK_PQ0_K2)-1, k2, iv2);
	if (ret != 0) goto fail;

	uint8_t pt2[512]; size_t pt2_len = 0;
	ret = pq_aead_decrypt(k2, iv2, NULL, 0, ct2_aead, ct2_aead_len, pt2, &pt2_len);
	if (ret != 0) goto fail;

	/* TH2 = Hash(msg1 || ct_eph2) */
	uint8_t th2_input[SCK_PQ_MSG_BUF_SIZE];
	uint32_t th2_input_len = d->msg1_len + PQ_KEM_CT_LEN;
	memcpy(th2_input, d->msg1_buf, d->msg1_len);
	memcpy(th2_input + d->msg1_len, ct_eph2, PQ_KEM_CT_LEN);
	ret = pq_hash_sha256(th2_input, th2_input_len, ctx->th2);
	if (ret != 0) goto fail;

	/* MAC2 verify */
	uint8_t mac2_info[PQ_HASH_LEN+64];
	memcpy(mac2_info, ctx->th2, PQ_HASH_LEN);
	memcpy(mac2_info+PQ_HASH_LEN, SCK_PQ0_IDR, sizeof(SCK_PQ0_IDR)-1);
	uint8_t mac2_exp[PQ_AEAD_TAG_LEN];
	ret = pq_hkdf_expand(ctx->prk2, mac2_info, PQ_HASH_LEN+sizeof(SCK_PQ0_IDR)-1,
			     mac2_exp, PQ_AEAD_TAG_LEN);
	if (ret != 0) goto fail;

	/* Verify signature */
	ret = pq_sig_verify(mac2_exp, PQ_AEAD_TAG_LEN, sig2_buf, sig2_len, ctx->other_sig_pk);
	if (ret != 0) goto fail;

	/* PRK3 */
	ret = pq_hkdf_extract(ctx->prk2, PQ_PRK_LEN, ctx->th2, PQ_HASH_LEN, ctx->prk3);
	if (ret != 0) goto fail;

	/* TH3 = Hash(TH2 || msg2) */
	uint8_t th3_input[SCK_PQ_MSG_BUF_SIZE];
	memcpy(th3_input, ctx->th2, PQ_HASH_LEN);
	memcpy(th3_input+PQ_HASH_LEN, d->msg2_buf, d->msg2_len);
	ret = pq_hash_sha256(th3_input, PQ_HASH_LEN + d->msg2_len, ctx->th3);
	if (ret != 0) goto fail;

	/* MAC3 + Sign */
	uint8_t mac3_info[PQ_HASH_LEN+64];
	memcpy(mac3_info, ctx->th3, PQ_HASH_LEN);
	memcpy(mac3_info+PQ_HASH_LEN, SCK_PQ0_IDI, sizeof(SCK_PQ0_IDI)-1);
	uint8_t mac3[PQ_AEAD_TAG_LEN];
	ret = pq_hkdf_expand(ctx->prk3, mac3_info, PQ_HASH_LEN+sizeof(SCK_PQ0_IDI)-1,
			     mac3, PQ_AEAD_TAG_LEN);
	if (ret != 0) goto fail;

	uint8_t sig3_buf[PQ_SIG_MAX_LEN]; size_t sig3_len = 0;
	ret = pq_sig_sign(mac3, PQ_AEAD_TAG_LEN, ctx->sig_sk, sig3_buf, &sig3_len);
	if (ret != 0) goto fail;

	uint8_t k3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
	ret = sck_pq0_derive_key_iv(ctx->prk3, SCK_PQ0_K3, sizeof(SCK_PQ0_K3)-1, k3, iv3);
	if (ret != 0) goto fail;

	uint8_t ct3_aead[PQ_SIG_MAX_LEN+64+PQ_AEAD_TAG_LEN]; size_t ct3_aead_len = 0;
	ret = pq_aead_encrypt(k3, iv3, NULL, 0, sig3_buf, sig3_len, ct3_aead, &ct3_aead_len);
	if (ret != 0) goto fail;

	/* Send msg3 via TCP */
	memcpy(d->msg3_buf, ct3_aead, ct3_aead_len);
	d->msg3_len = (uint32_t)ct3_aead_len;
	{
		uint64_t t0 = sck_get_time_ns();
		ret = sock_send_msg(d->sock_fd, d->msg3_buf, d->msg3_len);
		d->txrx_ns += (sck_get_time_ns() - t0);
		if (ret != 0) goto fail;
	}

	/* PRK_out */
	uint8_t th4_in[PQ_HASH_LEN+PQ_SIG_MAX_LEN+64+PQ_AEAD_TAG_LEN];
	memcpy(th4_in, ctx->th3, PQ_HASH_LEN);
	memcpy(th4_in+PQ_HASH_LEN, ct3_aead, ct3_aead_len);
	ret = pq_hash_sha256(th4_in, PQ_HASH_LEN+ct3_aead_len, ctx->th4);
	if (ret != 0) goto fail;
	ret = pq_hkdf_expand(ctx->prk3, ctx->th4, PQ_HASH_LEN, ctx->prk_out, PQ_PRK_LEN);
	if (ret != 0) goto fail;

	ctx->success = 1;
	d->error = 0;
	d->wall_end_ns = sck_get_time_ns();
	d->cpu_end_ns = sck_get_thread_cpu_ns();
	d->heap_peak_bytes = heap_tracker_get_peak();
	close(d->sock_fd); d->sock_fd = -1;
	return NULL;
fail:
	ctx->success = 0;
	d->wall_end_ns = sck_get_time_ns();
	d->cpu_end_ns = sck_get_thread_cpu_ns();
	d->heap_peak_bytes = heap_tracker_get_peak();
	if (d->sock_fd >= 0) { close(d->sock_fd); d->sock_fd = -1; }
	return NULL;
}

/* ── PQ Type 0 Responder (socket-based, server) ─────────────────────── */
static void *sck_pq0_responder_thread(void *arg)
{
	struct sck_pq_thread_data *d = (struct sck_pq_thread_data *)arg;
	struct pq_party_ctx *ctx = d->ctx;
	int ret;
	d->txrx_ns = 0;
	d->error = -1;

	/* Create server, accept connection */
	int listen_fd = sock_create_server(d->port);
	if (listen_fd < 0) return NULL;
	d->sock_fd = accept(listen_fd, NULL, NULL);
	close(listen_fd);
	if (d->sock_fd < 0) return NULL;
	int opt = 1;
	setsockopt(d->sock_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

	heap_tracker_reset();
	d->cpu_start_ns = sck_get_thread_cpu_ns();
	d->wall_start_ns = sck_get_time_ns();

	/* Receive msg1 via TCP */
	{
		uint64_t t0 = sck_get_time_ns();
		ret = sock_recv_msg(d->sock_fd, d->msg1_buf, SCK_PQ_MSG_BUF_SIZE, &d->msg1_len);
		d->txrx_ns += (sck_get_time_ns() - t0);
		if (ret != 0) goto fail;
	}

	/* Parse msg1: pk_eph || ct_R || aead_len(2) || AEAD_ct */
	uint8_t *msg1 = d->msg1_buf; uint32_t m1off = 0;
	uint8_t pk_eph[PQ_KEM_PK_LEN];
	memcpy(pk_eph, msg1+m1off, PQ_KEM_PK_LEN); m1off += PQ_KEM_PK_LEN;
	uint8_t ct_R[PQ_KEM_CT_LEN];
	memcpy(ct_R, msg1+m1off, PQ_KEM_CT_LEN); m1off += PQ_KEM_CT_LEN;
	uint16_t ct1_aead_len = (msg1[m1off]<<8)|msg1[m1off+1]; m1off += 2;
	uint8_t ct1_aead[256+PQ_AEAD_TAG_LEN];
	memcpy(ct1_aead, msg1+m1off, ct1_aead_len);

	/* Decaps ct_R */
	uint8_t ss_R[PQ_KEM_SS_LEN];
	ret = pq_kem_decaps(ss_R, ct_R, ctx->lt_sk);
	if (ret != 0) goto fail;

	ret = pq_hkdf_extract(NULL, 0, ss_R, PQ_KEM_SS_LEN, ctx->prk1);
	if (ret != 0) goto fail;

	uint8_t k1[PQ_AEAD_KEY_LEN], iv1[PQ_AEAD_NONCE_LEN];
	ret = sck_pq0_derive_key_iv(ctx->prk1, SCK_PQ0_K1, sizeof(SCK_PQ0_K1)-1, k1, iv1);
	if (ret != 0) goto fail;

	uint8_t pt1[256]; size_t pt1_len = 0;
	ret = pq_aead_decrypt(k1, iv1, NULL, 0, ct1_aead, ct1_aead_len, pt1, &pt1_len);
	if (ret != 0) goto fail;

	/* Encaps to pk_eph */
	uint8_t ct_eph2[PQ_KEM_CT_LEN], ss_eph[PQ_KEM_SS_LEN];
	ret = pq_kem_encaps(ct_eph2, ss_eph, pk_eph);
	if (ret != 0) goto fail;

	ret = pq_hkdf_extract(ctx->prk1, PQ_PRK_LEN, ss_eph, PQ_KEM_SS_LEN, ctx->prk2);
	if (ret != 0) goto fail;

	uint8_t k2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
	ret = sck_pq0_derive_key_iv(ctx->prk2, SCK_PQ0_K2, sizeof(SCK_PQ0_K2)-1, k2, iv2);
	if (ret != 0) goto fail;

	/* TH2 = Hash(msg1 || ct_eph2) */
	uint8_t th2_input[SCK_PQ_MSG_BUF_SIZE];
	uint32_t th2_input_len = d->msg1_len + PQ_KEM_CT_LEN;
	memcpy(th2_input, d->msg1_buf, d->msg1_len);
	memcpy(th2_input + d->msg1_len, ct_eph2, PQ_KEM_CT_LEN);
	ret = pq_hash_sha256(th2_input, th2_input_len, ctx->th2);
	if (ret != 0) goto fail;

	/* MAC2 */
	uint8_t mac2_info[PQ_HASH_LEN+64];
	memcpy(mac2_info, ctx->th2, PQ_HASH_LEN);
	memcpy(mac2_info+PQ_HASH_LEN, SCK_PQ0_IDR, sizeof(SCK_PQ0_IDR)-1);
	uint8_t mac2[PQ_AEAD_TAG_LEN];
	ret = pq_hkdf_expand(ctx->prk2, mac2_info, PQ_HASH_LEN+sizeof(SCK_PQ0_IDR)-1,
			     mac2, PQ_AEAD_TAG_LEN);
	if (ret != 0) goto fail;

	/* Sign MAC2 */
	uint8_t sig2_buf[PQ_SIG_MAX_LEN]; size_t sig2_len = 0;
	ret = pq_sig_sign(mac2, PQ_AEAD_TAG_LEN, ctx->sig_sk, sig2_buf, &sig2_len);
	if (ret != 0) goto fail;

	/* PRK3 */
	ret = pq_hkdf_extract(ctx->prk2, PQ_PRK_LEN, ctx->th2, PQ_HASH_LEN, ctx->prk3);
	if (ret != 0) goto fail;

	/* Build msg2 plaintext */
	uint8_t pt2[256]; uint32_t pt2_len = 0;
	pt2[pt2_len++] = 0x27;
	memcpy(pt2+pt2_len, SCK_PQ0_IDR, sizeof(SCK_PQ0_IDR)-1);
	pt2_len += sizeof(SCK_PQ0_IDR)-1;

	uint8_t ct2_aead[512+PQ_AEAD_TAG_LEN]; size_t ct2_aead_len = 0;
	ret = pq_aead_encrypt(k2, iv2, NULL, 0, pt2, pt2_len, ct2_aead, &ct2_aead_len);
	if (ret != 0) goto fail;

	/* Build wire msg2: ct_eph2 || sig2_len(2) || sig2 || aead_len(2) || AEAD_ct */
	{
		uint8_t *p = d->msg2_buf; uint32_t off = 0;
		memcpy(p+off, ct_eph2, PQ_KEM_CT_LEN); off += PQ_KEM_CT_LEN;
		p[off++] = (uint8_t)(sig2_len >> 8);
		p[off++] = (uint8_t)(sig2_len & 0xFF);
		memcpy(p+off, sig2_buf, sig2_len); off += sig2_len;
		p[off++] = (uint8_t)(ct2_aead_len >> 8);
		p[off++] = (uint8_t)(ct2_aead_len & 0xFF);
		memcpy(p+off, ct2_aead, ct2_aead_len); off += ct2_aead_len;
		d->msg2_len = off;
	}

	/* Send msg2 via TCP */
	{
		uint64_t t0 = sck_get_time_ns();
		ret = sock_send_msg(d->sock_fd, d->msg2_buf, d->msg2_len);
		d->txrx_ns += (sck_get_time_ns() - t0);
		if (ret != 0) goto fail;
	}

	/* Receive msg3 via TCP */
	{
		uint64_t t0 = sck_get_time_ns();
		ret = sock_recv_msg(d->sock_fd, d->msg3_buf, SCK_PQ_MSG_BUF_SIZE, &d->msg3_len);
		d->txrx_ns += (sck_get_time_ns() - t0);
		if (ret != 0) goto fail;
	}

	/* Decrypt msg3 */
	uint8_t k3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
	ret = sck_pq0_derive_key_iv(ctx->prk3, SCK_PQ0_K3, sizeof(SCK_PQ0_K3)-1, k3, iv3);
	if (ret != 0) goto fail;

	uint8_t pt3[PQ_SIG_MAX_LEN+64]; size_t pt3_len = 0;
	ret = pq_aead_decrypt(k3, iv3, NULL, 0, d->msg3_buf, d->msg3_len, pt3, &pt3_len);
	if (ret != 0) goto fail;

	/* TH3 = Hash(TH2 || msg2) */
	uint8_t th3_input[SCK_PQ_MSG_BUF_SIZE];
	memcpy(th3_input, ctx->th2, PQ_HASH_LEN);
	memcpy(th3_input+PQ_HASH_LEN, d->msg2_buf, d->msg2_len);
	ret = pq_hash_sha256(th3_input, PQ_HASH_LEN + d->msg2_len, ctx->th3);
	if (ret != 0) goto fail;

	/* Verify MAC3 signature */
	uint8_t mac3_info[PQ_HASH_LEN+64];
	memcpy(mac3_info, ctx->th3, PQ_HASH_LEN);
	memcpy(mac3_info+PQ_HASH_LEN, SCK_PQ0_IDI, sizeof(SCK_PQ0_IDI)-1);
	uint8_t mac3_exp[PQ_AEAD_TAG_LEN];
	ret = pq_hkdf_expand(ctx->prk3, mac3_info, PQ_HASH_LEN+sizeof(SCK_PQ0_IDI)-1,
			     mac3_exp, PQ_AEAD_TAG_LEN);
	if (ret != 0) goto fail;
	ret = pq_sig_verify(mac3_exp, PQ_AEAD_TAG_LEN, pt3, pt3_len, ctx->other_sig_pk);
	if (ret != 0) goto fail;

	/* TH4 & PRK_out */
	uint8_t th4_in[PQ_HASH_LEN+PQ_SIG_MAX_LEN+64+PQ_AEAD_TAG_LEN];
	memcpy(th4_in, ctx->th3, PQ_HASH_LEN);
	memcpy(th4_in+PQ_HASH_LEN, d->msg3_buf, d->msg3_len);
	ret = pq_hash_sha256(th4_in, PQ_HASH_LEN + d->msg3_len, ctx->th4);
	if (ret != 0) goto fail;
	ret = pq_hkdf_expand(ctx->prk3, ctx->th4, PQ_HASH_LEN, ctx->prk_out, PQ_PRK_LEN);
	if (ret != 0) goto fail;

	ctx->success = 1;
	d->error = 0;
	d->wall_end_ns = sck_get_time_ns();
	d->cpu_end_ns = sck_get_thread_cpu_ns();
	d->heap_peak_bytes = heap_tracker_get_peak();
	close(d->sock_fd); d->sock_fd = -1;
	return NULL;
fail:
	ctx->success = 0;
	d->wall_end_ns = sck_get_time_ns();
	d->cpu_end_ns = sck_get_thread_cpu_ns();
	d->heap_peak_bytes = heap_tracker_get_peak();
	if (d->sock_fd >= 0) { close(d->sock_fd); d->sock_fd = -1; }
	return NULL;
}

/* =============================================================================
 * Socket-based PQ Type 3 Handshake (ML-KEM-768 only, MAC-MAC)
 * =============================================================================
 */

static const uint8_t SCK_T3PQ_K1[]   = "EDHOC-T3PQ-K1";
static const uint8_t SCK_T3PQ_K2[]   = "EDHOC-T3PQ-K2";
static const uint8_t SCK_T3PQ_K3[]   = "EDHOC-T3PQ-K3";
static const uint8_t SCK_T3PQ_IDI[]  = "EDHOC-T3PQ-Initiator";
static const uint8_t SCK_T3PQ_IDR[]  = "EDHOC-T3PQ-Responder";

static int sck_t3pq_derive_key_iv(const uint8_t *prk, const uint8_t *label,
				   size_t label_len, uint8_t *key, uint8_t *iv)
{
	if (pq_hkdf_expand(prk, label, label_len, key, PQ_AEAD_KEY_LEN) != 0)
		return -1;
	uint8_t iv_info[64];
	memcpy(iv_info, label, label_len);
	iv_info[0] ^= 0xFF;
	if (pq_hkdf_expand(prk, iv_info, label_len, iv, PQ_AEAD_NONCE_LEN) != 0)
		return -1;
	return 0;
}

/* PQ Type 3 thread data reuses sck_pq_thread_data but with pq3_party_ctx */
struct sck_pq3_thread_data {
	int sock_fd;
	int port;
	struct pq3_party_ctx *ctx;
	int error;
	uint64_t cpu_start_ns, cpu_end_ns;
	uint64_t wall_start_ns, wall_end_ns;
	uint64_t txrx_ns;
	uint8_t msg1_buf[SCK_PQ_MSG_BUF_SIZE]; uint32_t msg1_len;
	uint8_t msg2_buf[SCK_PQ_MSG_BUF_SIZE]; uint32_t msg2_len;
	uint8_t msg3_buf[SCK_PQ_MSG_BUF_SIZE]; uint32_t msg3_len;
	size_t  heap_peak_bytes;
};

/* ── PQ Type 3 Initiator (socket-based, client) ─────────────────────── */
static void *sck_pq3_initiator_thread(void *arg)
{
	struct sck_pq3_thread_data *d = (struct sck_pq3_thread_data *)arg;
	struct pq3_party_ctx *ctx = d->ctx;
	int ret;
	d->txrx_ns = 0;
	d->error = -1;

	/* Connect to responder */
	d->sock_fd = sock_connect_client(d->port);
	if (d->sock_fd < 0) return NULL;
	int opt = 1;
	setsockopt(d->sock_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

	heap_tracker_reset();
	d->cpu_start_ns = sck_get_thread_cpu_ns();
	d->wall_start_ns = sck_get_time_ns();

	/* Ephemeral keygen + Encaps to pkR */
	ret = pq_kem_keygen(ctx->eph_pk, ctx->eph_sk);
	if (ret != 0) goto fail;
	uint8_t ct_R[PQ_KEM_CT_LEN], ss_R[PQ_KEM_SS_LEN];
	ret = pq_kem_encaps(ct_R, ss_R, ctx->other_lt_pk);
	if (ret != 0) goto fail;

	ret = pq_hkdf_extract(NULL, 0, ss_R, PQ_KEM_SS_LEN, ctx->prk1);
	if (ret != 0) goto fail;

	uint8_t k1[PQ_AEAD_KEY_LEN], iv1[PQ_AEAD_NONCE_LEN];
	ret = sck_t3pq_derive_key_iv(ctx->prk1, SCK_T3PQ_K1, sizeof(SCK_T3PQ_K1)-1, k1, iv1);
	if (ret != 0) goto fail;

	uint8_t pt1[256]; uint32_t pt1_len = 0;
	pt1[pt1_len++] = 0x03; pt1[pt1_len++] = 0x00;
	memcpy(pt1+pt1_len, SCK_T3PQ_IDI, sizeof(SCK_T3PQ_IDI)-1);
	pt1_len += sizeof(SCK_T3PQ_IDI)-1;
	pt1[pt1_len++] = 0x37;

	uint8_t ct1_aead[256+PQ_AEAD_TAG_LEN]; size_t ct1_aead_len = 0;
	ret = pq_aead_encrypt(k1, iv1, NULL, 0, pt1, pt1_len, ct1_aead, &ct1_aead_len);
	if (ret != 0) goto fail;

	/* Build wire msg1 */
	{
		uint8_t *p = d->msg1_buf; uint32_t off = 0;
		memcpy(p+off, ctx->eph_pk, PQ_KEM_PK_LEN); off += PQ_KEM_PK_LEN;
		memcpy(p+off, ct_R, PQ_KEM_CT_LEN); off += PQ_KEM_CT_LEN;
		p[off++] = (uint8_t)(ct1_aead_len >> 8);
		p[off++] = (uint8_t)(ct1_aead_len & 0xFF);
		memcpy(p+off, ct1_aead, ct1_aead_len); off += ct1_aead_len;
		d->msg1_len = off;
	}

	/* Send msg1 */
	{
		uint64_t t0 = sck_get_time_ns();
		ret = sock_send_msg(d->sock_fd, d->msg1_buf, d->msg1_len);
		d->txrx_ns += (sck_get_time_ns() - t0);
		if (ret != 0) goto fail;
	}

	/* Receive msg2 */
	{
		uint64_t t0 = sck_get_time_ns();
		ret = sock_recv_msg(d->sock_fd, d->msg2_buf, SCK_PQ_MSG_BUF_SIZE, &d->msg2_len);
		d->txrx_ns += (sck_get_time_ns() - t0);
		if (ret != 0) goto fail;
	}

	/* Parse msg2: ct_eph2 || ct_I || aead_len(2) || AEAD_ct */
	uint8_t *msg2 = d->msg2_buf; uint32_t m2off = 0;
	uint8_t ct_eph2[PQ_KEM_CT_LEN];
	memcpy(ct_eph2, msg2+m2off, PQ_KEM_CT_LEN); m2off += PQ_KEM_CT_LEN;
	uint8_t ct_I[PQ_KEM_CT_LEN];
	memcpy(ct_I, msg2+m2off, PQ_KEM_CT_LEN); m2off += PQ_KEM_CT_LEN;
	uint16_t ct2_aead_len = (msg2[m2off]<<8)|msg2[m2off+1]; m2off += 2;
	uint8_t ct2_aead[512+PQ_AEAD_TAG_LEN];
	memcpy(ct2_aead, msg2+m2off, ct2_aead_len);

	/* Decaps ephemeral */
	uint8_t ss_eph[PQ_KEM_SS_LEN];
	ret = pq_kem_decaps(ss_eph, ct_eph2, ctx->eph_sk);
	if (ret != 0) goto fail;

	ret = pq_hkdf_extract(ctx->prk1, PQ_PRK_LEN, ss_eph, PQ_KEM_SS_LEN, ctx->prk2);
	if (ret != 0) goto fail;

	uint8_t k2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
	ret = sck_t3pq_derive_key_iv(ctx->prk2, SCK_T3PQ_K2, sizeof(SCK_T3PQ_K2)-1, k2, iv2);
	if (ret != 0) goto fail;

	uint8_t pt2[512]; size_t pt2_len = 0;
	ret = pq_aead_decrypt(k2, iv2, NULL, 0, ct2_aead, ct2_aead_len, pt2, &pt2_len);
	if (ret != 0) goto fail;

	/* TH2 = Hash(msg1 || ct_eph2) */
	uint8_t th2_buf[SCK_PQ_MSG_BUF_SIZE];
	uint32_t th2_len = d->msg1_len + PQ_KEM_CT_LEN;
	memcpy(th2_buf, d->msg1_buf, d->msg1_len);
	memcpy(th2_buf + d->msg1_len, ct_eph2, PQ_KEM_CT_LEN);
	ret = pq_hash_sha256(th2_buf, th2_len, ctx->th2);
	if (ret != 0) goto fail;

	/* Verify MAC2 */
	uint8_t mac2_info[PQ_HASH_LEN+64];
	memcpy(mac2_info, ctx->th2, PQ_HASH_LEN);
	memcpy(mac2_info+PQ_HASH_LEN, SCK_T3PQ_IDR, sizeof(SCK_T3PQ_IDR)-1);
	uint8_t mac2_exp[PQ_AEAD_TAG_LEN];
	ret = pq_hkdf_expand(ctx->prk2, mac2_info, PQ_HASH_LEN+sizeof(SCK_T3PQ_IDR)-1,
			     mac2_exp, PQ_AEAD_TAG_LEN);
	if (ret != 0) goto fail;
	if (pt2_len < PQ_AEAD_TAG_LEN ||
	    memcmp(mac2_exp, pt2+pt2_len-PQ_AEAD_TAG_LEN, PQ_AEAD_TAG_LEN) != 0)
		goto fail;

	/* Decaps ct_I (mutual auth) */
	uint8_t ss_I[PQ_KEM_SS_LEN];
	ret = pq_kem_decaps(ss_I, ct_I, ctx->lt_sk);
	if (ret != 0) goto fail;

	ret = pq_hkdf_extract(ctx->prk2, PQ_PRK_LEN, ss_I, PQ_KEM_SS_LEN, ctx->prk3);
	if (ret != 0) goto fail;

	/* TH3 = Hash(TH2 || msg2) */
	uint8_t th3_buf[SCK_PQ_MSG_BUF_SIZE];
	memcpy(th3_buf, ctx->th2, PQ_HASH_LEN);
	memcpy(th3_buf+PQ_HASH_LEN, d->msg2_buf, d->msg2_len);
	ret = pq_hash_sha256(th3_buf, PQ_HASH_LEN + d->msg2_len, ctx->th3);
	if (ret != 0) goto fail;

	/* MAC3 */
	uint8_t mac3_info[PQ_HASH_LEN+64];
	memcpy(mac3_info, ctx->th3, PQ_HASH_LEN);
	memcpy(mac3_info+PQ_HASH_LEN, SCK_T3PQ_IDI, sizeof(SCK_T3PQ_IDI)-1);
	uint8_t mac3[PQ_AEAD_TAG_LEN];
	ret = pq_hkdf_expand(ctx->prk3, mac3_info, PQ_HASH_LEN+sizeof(SCK_T3PQ_IDI)-1,
			     mac3, PQ_AEAD_TAG_LEN);
	if (ret != 0) goto fail;

	uint8_t k3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
	ret = sck_t3pq_derive_key_iv(ctx->prk3, SCK_T3PQ_K3, sizeof(SCK_T3PQ_K3)-1, k3, iv3);
	if (ret != 0) goto fail;

	uint8_t ct3_aead[64+PQ_AEAD_TAG_LEN]; size_t ct3_aead_len = 0;
	ret = pq_aead_encrypt(k3, iv3, NULL, 0, mac3, PQ_AEAD_TAG_LEN, ct3_aead, &ct3_aead_len);
	if (ret != 0) goto fail;

	/* Send msg3 */
	memcpy(d->msg3_buf, ct3_aead, ct3_aead_len);
	d->msg3_len = (uint32_t)ct3_aead_len;
	{
		uint64_t t0 = sck_get_time_ns();
		ret = sock_send_msg(d->sock_fd, d->msg3_buf, d->msg3_len);
		d->txrx_ns += (sck_get_time_ns() - t0);
		if (ret != 0) goto fail;
	}

	/* PRK_out */
	uint8_t th4_in[PQ_HASH_LEN+64];
	memcpy(th4_in, ctx->th3, PQ_HASH_LEN);
	memcpy(th4_in+PQ_HASH_LEN, ct3_aead, ct3_aead_len);
	ret = pq_hash_sha256(th4_in, PQ_HASH_LEN+ct3_aead_len, ctx->th4);
	if (ret != 0) goto fail;
	ret = pq_hkdf_expand(ctx->prk3, ctx->th4, PQ_HASH_LEN, ctx->prk_out, PQ_PRK_LEN);
	if (ret != 0) goto fail;

	ctx->success = 1;
	d->error = 0;
	d->wall_end_ns = sck_get_time_ns();
	d->cpu_end_ns = sck_get_thread_cpu_ns();
	d->heap_peak_bytes = heap_tracker_get_peak();
	close(d->sock_fd); d->sock_fd = -1;
	return NULL;
fail:
	ctx->success = 0;
	d->wall_end_ns = sck_get_time_ns();
	d->cpu_end_ns = sck_get_thread_cpu_ns();
	d->heap_peak_bytes = heap_tracker_get_peak();
	if (d->sock_fd >= 0) { close(d->sock_fd); d->sock_fd = -1; }
	return NULL;
}

/* ── PQ Type 3 Responder (socket-based, server) ─────────────────────── */
static void *sck_pq3_responder_thread(void *arg)
{
	struct sck_pq3_thread_data *d = (struct sck_pq3_thread_data *)arg;
	struct pq3_party_ctx *ctx = d->ctx;
	int ret;
	d->txrx_ns = 0;
	d->error = -1;

	/* Create server, accept connection */
	int listen_fd = sock_create_server(d->port);
	if (listen_fd < 0) return NULL;
	d->sock_fd = accept(listen_fd, NULL, NULL);
	close(listen_fd);
	if (d->sock_fd < 0) return NULL;
	int opt = 1;
	setsockopt(d->sock_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

	heap_tracker_reset();
	d->cpu_start_ns = sck_get_thread_cpu_ns();
	d->wall_start_ns = sck_get_time_ns();

	/* Receive msg1 */
	{
		uint64_t t0 = sck_get_time_ns();
		ret = sock_recv_msg(d->sock_fd, d->msg1_buf, SCK_PQ_MSG_BUF_SIZE, &d->msg1_len);
		d->txrx_ns += (sck_get_time_ns() - t0);
		if (ret != 0) goto fail;
	}

	uint8_t *msg1 = d->msg1_buf; uint32_t m1off = 0;
	uint8_t pk_eph[PQ_KEM_PK_LEN];
	memcpy(pk_eph, msg1+m1off, PQ_KEM_PK_LEN); m1off += PQ_KEM_PK_LEN;
	uint8_t ct_R[PQ_KEM_CT_LEN];
	memcpy(ct_R, msg1+m1off, PQ_KEM_CT_LEN); m1off += PQ_KEM_CT_LEN;
	uint16_t ct1_aead_len = (msg1[m1off]<<8)|msg1[m1off+1]; m1off += 2;
	uint8_t ct1_aead[256+PQ_AEAD_TAG_LEN];
	memcpy(ct1_aead, msg1+m1off, ct1_aead_len);

	/* Decaps ct_R */
	uint8_t ss_R[PQ_KEM_SS_LEN];
	ret = pq_kem_decaps(ss_R, ct_R, ctx->lt_sk);
	if (ret != 0) goto fail;

	ret = pq_hkdf_extract(NULL, 0, ss_R, PQ_KEM_SS_LEN, ctx->prk1);
	if (ret != 0) goto fail;

	uint8_t k1[PQ_AEAD_KEY_LEN], iv1[PQ_AEAD_NONCE_LEN];
	ret = sck_t3pq_derive_key_iv(ctx->prk1, SCK_T3PQ_K1, sizeof(SCK_T3PQ_K1)-1, k1, iv1);
	if (ret != 0) goto fail;

	uint8_t pt1[256]; size_t pt1_len = 0;
	ret = pq_aead_decrypt(k1, iv1, NULL, 0, ct1_aead, ct1_aead_len, pt1, &pt1_len);
	if (ret != 0) goto fail;

	/* Encaps to pk_eph */
	uint8_t ct_eph2[PQ_KEM_CT_LEN], ss_eph[PQ_KEM_SS_LEN];
	ret = pq_kem_encaps(ct_eph2, ss_eph, pk_eph);
	if (ret != 0) goto fail;

	ret = pq_hkdf_extract(ctx->prk1, PQ_PRK_LEN, ss_eph, PQ_KEM_SS_LEN, ctx->prk2);
	if (ret != 0) goto fail;

	uint8_t k2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
	ret = sck_t3pq_derive_key_iv(ctx->prk2, SCK_T3PQ_K2, sizeof(SCK_T3PQ_K2)-1, k2, iv2);
	if (ret != 0) goto fail;

	/* TH2 */
	uint8_t th2_buf[SCK_PQ_MSG_BUF_SIZE];
	uint32_t th2_len = d->msg1_len + PQ_KEM_CT_LEN;
	memcpy(th2_buf, d->msg1_buf, d->msg1_len);
	memcpy(th2_buf + d->msg1_len, ct_eph2, PQ_KEM_CT_LEN);
	ret = pq_hash_sha256(th2_buf, th2_len, ctx->th2);
	if (ret != 0) goto fail;

	/* MAC2 */
	uint8_t mac2_info[PQ_HASH_LEN+64];
	memcpy(mac2_info, ctx->th2, PQ_HASH_LEN);
	memcpy(mac2_info+PQ_HASH_LEN, SCK_T3PQ_IDR, sizeof(SCK_T3PQ_IDR)-1);
	uint8_t mac2[PQ_AEAD_TAG_LEN];
	ret = pq_hkdf_expand(ctx->prk2, mac2_info, PQ_HASH_LEN+sizeof(SCK_T3PQ_IDR)-1,
			     mac2, PQ_AEAD_TAG_LEN);
	if (ret != 0) goto fail;

	/* Encaps to pkI (mutual auth) */
	uint8_t ct_I[PQ_KEM_CT_LEN], ss_I[PQ_KEM_SS_LEN];
	ret = pq_kem_encaps(ct_I, ss_I, ctx->other_lt_pk);
	if (ret != 0) goto fail;

	ret = pq_hkdf_extract(ctx->prk2, PQ_PRK_LEN, ss_I, PQ_KEM_SS_LEN, ctx->prk3);
	if (ret != 0) goto fail;

	/* msg2 plaintext */
	uint8_t pt2[256]; uint32_t pt2_len = 0;
	pt2[pt2_len++] = 0x27;
	memcpy(pt2+pt2_len, SCK_T3PQ_IDR, sizeof(SCK_T3PQ_IDR)-1);
	pt2_len += sizeof(SCK_T3PQ_IDR)-1;
	memcpy(pt2+pt2_len, mac2, PQ_AEAD_TAG_LEN);
	pt2_len += PQ_AEAD_TAG_LEN;

	uint8_t ct2_aead[512+PQ_AEAD_TAG_LEN]; size_t ct2_aead_len = 0;
	ret = pq_aead_encrypt(k2, iv2, NULL, 0, pt2, pt2_len, ct2_aead, &ct2_aead_len);
	if (ret != 0) goto fail;

	/* Build wire msg2: ct_eph2 || ct_I || aead_len(2) || AEAD_ct */
	{
		uint8_t *p = d->msg2_buf; uint32_t off = 0;
		memcpy(p+off, ct_eph2, PQ_KEM_CT_LEN); off += PQ_KEM_CT_LEN;
		memcpy(p+off, ct_I, PQ_KEM_CT_LEN); off += PQ_KEM_CT_LEN;
		p[off++] = (uint8_t)(ct2_aead_len >> 8);
		p[off++] = (uint8_t)(ct2_aead_len & 0xFF);
		memcpy(p+off, ct2_aead, ct2_aead_len); off += ct2_aead_len;
		d->msg2_len = off;
	}

	/* Send msg2 */
	{
		uint64_t t0 = sck_get_time_ns();
		ret = sock_send_msg(d->sock_fd, d->msg2_buf, d->msg2_len);
		d->txrx_ns += (sck_get_time_ns() - t0);
		if (ret != 0) goto fail;
	}

	/* Receive msg3 */
	{
		uint64_t t0 = sck_get_time_ns();
		ret = sock_recv_msg(d->sock_fd, d->msg3_buf, SCK_PQ_MSG_BUF_SIZE, &d->msg3_len);
		d->txrx_ns += (sck_get_time_ns() - t0);
		if (ret != 0) goto fail;
	}

	/* Decrypt msg3 */
	uint8_t k3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
	ret = sck_t3pq_derive_key_iv(ctx->prk3, SCK_T3PQ_K3, sizeof(SCK_T3PQ_K3)-1, k3, iv3);
	if (ret != 0) goto fail;

	uint8_t pt3[64]; size_t pt3_len = 0;
	ret = pq_aead_decrypt(k3, iv3, NULL, 0, d->msg3_buf, d->msg3_len, pt3, &pt3_len);
	if (ret != 0) goto fail;

	/* TH3 = Hash(TH2 || msg2) */
	uint8_t th3_buf[SCK_PQ_MSG_BUF_SIZE];
	memcpy(th3_buf, ctx->th2, PQ_HASH_LEN);
	memcpy(th3_buf+PQ_HASH_LEN, d->msg2_buf, d->msg2_len);
	ret = pq_hash_sha256(th3_buf, PQ_HASH_LEN + d->msg2_len, ctx->th3);
	if (ret != 0) goto fail;

	/* Verify MAC3 */
	uint8_t mac3_info[PQ_HASH_LEN+64];
	memcpy(mac3_info, ctx->th3, PQ_HASH_LEN);
	memcpy(mac3_info+PQ_HASH_LEN, SCK_T3PQ_IDI, sizeof(SCK_T3PQ_IDI)-1);
	uint8_t mac3_exp[PQ_AEAD_TAG_LEN];
	ret = pq_hkdf_expand(ctx->prk3, mac3_info, PQ_HASH_LEN+sizeof(SCK_T3PQ_IDI)-1,
			     mac3_exp, PQ_AEAD_TAG_LEN);
	if (ret != 0) goto fail;
	if (pt3_len != PQ_AEAD_TAG_LEN || memcmp(mac3_exp, pt3, PQ_AEAD_TAG_LEN) != 0)
		goto fail;

	/* PRK_out */
	uint8_t th4_in[PQ_HASH_LEN+64];
	memcpy(th4_in, ctx->th3, PQ_HASH_LEN);
	memcpy(th4_in+PQ_HASH_LEN, d->msg3_buf, d->msg3_len);
	ret = pq_hash_sha256(th4_in, PQ_HASH_LEN + d->msg3_len, ctx->th4);
	if (ret != 0) goto fail;
	ret = pq_hkdf_expand(ctx->prk3, ctx->th4, PQ_HASH_LEN, ctx->prk_out, PQ_PRK_LEN);
	if (ret != 0) goto fail;

	ctx->success = 1;
	d->error = 0;
	d->wall_end_ns = sck_get_time_ns();
	d->cpu_end_ns = sck_get_thread_cpu_ns();
	d->heap_peak_bytes = heap_tracker_get_peak();
	close(d->sock_fd); d->sock_fd = -1;
	return NULL;
fail:
	ctx->success = 0;
	d->wall_end_ns = sck_get_time_ns();
	d->cpu_end_ns = sck_get_thread_cpu_ns();
	d->heap_peak_bytes = heap_tracker_get_peak();
	if (d->sock_fd >= 0) { close(d->sock_fd); d->sock_fd = -1; }
	return NULL;
}

/* =============================================================================
 * Socket-based Hybrid Type 3 Handshake (X25519 + ML-KEM-768)
 *
 * Complete reimplementation with TCP socket transport.
 * Uses the same crypto wrappers as edhoc_type3_hybrid.c but with
 * local message buffers and socket send/recv for all msg exchange.
 * =============================================================================
 */

/* Hybrid labels (same as edhoc_type3_hybrid.c) */
static const uint8_t SCK_HYB_EK2[]  = "EDHOC-HYB-EK2";
static const uint8_t SCK_HYB_EK3[]  = "EDHOC-HYB-EK3";
static const uint8_t SCK_HYB_IDI[]  = "EDHOC-HYB-Initiator";
static const uint8_t SCK_HYB_IDR[]  = "EDHOC-HYB-Responder";

/* Hybrid crypto wrappers — identical to edhoc_type3_hybrid.c static fns */
static int sck_hyb_hkdf_extract(const uint8_t *salt, size_t salt_len,
				const uint8_t *ikm, size_t ikm_len,
				uint8_t *prk_out)
{
	struct byte_array s = { .len=(uint32_t)salt_len, .ptr=(uint8_t*)salt };
	struct byte_array i = { .len=(uint32_t)ikm_len,  .ptr=(uint8_t*)ikm };
	if (!salt || salt_len == 0) { s.ptr = NULL; s.len = 0; }
	return (hkdf_extract(SHA_256, &s, &i, prk_out) == ok) ? 0 : -1;
}

static int sck_hyb_hkdf_expand(const uint8_t *prk, const uint8_t *info,
			       size_t info_len, uint8_t *okm, size_t okm_len)
{
	struct byte_array p = { .len=32, .ptr=(uint8_t*)prk };
	struct byte_array inf = { .len=(uint32_t)info_len, .ptr=(uint8_t*)info };
	struct byte_array o = { .len=(uint32_t)okm_len, .ptr=okm };
	return (hkdf_expand(SHA_256, &p, &inf, &o) == ok) ? 0 : -1;
}

static int sck_hyb_hash(const uint8_t *data, size_t len, uint8_t *out)
{
	struct byte_array in = { .len=(uint32_t)len, .ptr=(uint8_t*)data };
	struct byte_array o = { .len=32, .ptr=out };
	return (hash(SHA_256, &in, &o) == ok) ? 0 : -1;
}

static int sck_hyb_aead_enc(const uint8_t *key, const uint8_t *nonce,
			    const uint8_t *aad, size_t aad_len,
			    const uint8_t *pt, size_t pt_len,
			    uint8_t *ct, size_t *ct_len)
{
	uint8_t tag[PQ_AEAD_TAG_LEN];
	struct byte_array p = { .len=(uint32_t)pt_len,  .ptr=(uint8_t*)pt };
	struct byte_array k = { .len=PQ_AEAD_KEY_LEN,   .ptr=(uint8_t*)key };
	struct byte_array n = { .len=PQ_AEAD_NONCE_LEN, .ptr=(uint8_t*)nonce };
	struct byte_array a = { .len=(uint32_t)aad_len, .ptr=(uint8_t*)aad };
	struct byte_array c = { .len=(uint32_t)pt_len,  .ptr=ct };
	struct byte_array t = { .len=PQ_AEAD_TAG_LEN,   .ptr=tag };
	if (aead(ENCRYPT, &p, &k, &n, &a, &c, &t) != ok) return -1;
	memcpy(ct+pt_len, tag, PQ_AEAD_TAG_LEN);
	*ct_len = pt_len + PQ_AEAD_TAG_LEN;
	return 0;
}

static int sck_hyb_aead_dec(const uint8_t *key, const uint8_t *nonce,
			    const uint8_t *aad, size_t aad_len,
			    const uint8_t *ct, size_t ct_len,
			    uint8_t *pt, size_t *pt_len)
{
	if (ct_len < PQ_AEAD_TAG_LEN) return -1;
	size_t plain_len = ct_len - PQ_AEAD_TAG_LEN;
	struct byte_array c = { .len=(uint32_t)ct_len,    .ptr=(uint8_t*)ct };
	struct byte_array k = { .len=PQ_AEAD_KEY_LEN,     .ptr=(uint8_t*)key };
	struct byte_array n = { .len=PQ_AEAD_NONCE_LEN,   .ptr=(uint8_t*)nonce };
	struct byte_array a = { .len=(uint32_t)aad_len,   .ptr=(uint8_t*)aad };
	struct byte_array p = { .len=(uint32_t)plain_len, .ptr=pt };
	struct byte_array t = { .len=PQ_AEAD_TAG_LEN, .ptr=(uint8_t*)(ct+plain_len) };
	if (aead(DECRYPT, &c, &k, &n, &a, &p, &t) != ok) return -1;
	*pt_len = plain_len;
	return 0;
}

static int sck_hyb_derive_key_iv(const uint8_t *prk, const uint8_t *label,
				 size_t label_len, const uint8_t *th, size_t th_len,
				 uint8_t *key, uint8_t *iv)
{
	uint8_t info[128];
	size_t info_len = label_len + th_len;
	memcpy(info, label, label_len);
	memcpy(info+label_len, th, th_len);
	if (sck_hyb_hkdf_expand(prk, info, info_len, key, PQ_AEAD_KEY_LEN) != 0)
		return -1;
	info[0] ^= 0xFF;
	if (sck_hyb_hkdf_expand(prk, info, info_len, iv, PQ_AEAD_NONCE_LEN) != 0)
		return -1;
	return 0;
}

static int sck_hyb_ecdh(const uint8_t *my_sk, const uint8_t *peer_pk, uint8_t *out)
{
	struct byte_array sk = { .len=32, .ptr=(uint8_t*)my_sk };
	struct byte_array pk = { .len=32, .ptr=(uint8_t*)peer_pk };
	return (shared_secret_derive(X25519, &sk, &pk, out) == ok) ? 0 : -1;
}

#define SCK_HYB_MSG_BUF_SIZE 8192

struct sck_hyb_thread_data {
	int sock_fd;
	int port;
	struct hybrid_party_ctx *ctx;
	int error;
	uint64_t cpu_start_ns, cpu_end_ns;
	uint64_t wall_start_ns, wall_end_ns;
	uint64_t txrx_ns;
	uint8_t msg1_buf[SCK_HYB_MSG_BUF_SIZE]; uint32_t msg1_len;
	uint8_t msg2_buf[SCK_HYB_MSG_BUF_SIZE]; uint32_t msg2_len;
	uint8_t msg3_buf[SCK_HYB_MSG_BUF_SIZE]; uint32_t msg3_len;
	size_t  heap_peak_bytes;
};

/* ── Hybrid Initiator (socket-based, client) ────────────────────────── */
static void *sck_hyb_initiator_thread(void *arg)
{
	struct sck_hyb_thread_data *d = (struct sck_hyb_thread_data *)arg;
	struct hybrid_party_ctx *ctx = d->ctx;
	int ret;
	d->txrx_ns = 0;
	d->error = -1;

	/* Connect to responder */
	d->sock_fd = sock_connect_client(d->port);
	if (d->sock_fd < 0) return NULL;
	int opt = 1;
	setsockopt(d->sock_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

	heap_tracker_reset();
	d->cpu_start_ns = sck_get_thread_cpu_ns();
	d->wall_start_ns = sck_get_time_ns();

	/* Build M1 = (Method, Suites, CI, X[32], PK_KEM) */
	uint8_t m1[SCK_HYB_MSG_BUF_SIZE]; uint32_t m1_len = 0;
	m1[m1_len++] = 0x03; m1[m1_len++] = 0xFE; m1[m1_len++] = 0x37;
	memcpy(m1+m1_len, ctx->eph_pk, 32); m1_len += 32;
	memcpy(m1+m1_len, ctx->kem_pk, PQ_KEM_PK_LEN); m1_len += PQ_KEM_PK_LEN;

	memcpy(d->msg1_buf, m1, m1_len); d->msg1_len = m1_len;

	/* Send M1 */
	{
		uint64_t t0 = sck_get_time_ns();
		ret = sock_send_msg(d->sock_fd, d->msg1_buf, d->msg1_len);
		d->txrx_ns += (sck_get_time_ns() - t0);
		if (ret != 0) goto fail;
	}

	/* Receive M2 */
	{
		uint64_t t0 = sck_get_time_ns();
		ret = sock_recv_msg(d->sock_fd, d->msg2_buf, SCK_HYB_MSG_BUF_SIZE, &d->msg2_len);
		d->txrx_ns += (sck_get_time_ns() - t0);
		if (ret != 0) goto fail;
	}

	/* Parse M2: Y[32], C_KEM[1088], len16, AEAD_ct */
	uint8_t *m2 = d->msg2_buf; uint32_t off = 0;
	uint8_t peer_eph_pk[32];
	memcpy(peer_eph_pk, m2+off, 32); off += 32;
	uint8_t c_kem[PQ_KEM_CT_LEN];
	memcpy(c_kem, m2+off, PQ_KEM_CT_LEN); off += PQ_KEM_CT_LEN;
	uint16_t ct2_len = (m2[off]<<8)|m2[off+1]; off += 2;
	uint8_t ct2_aead[512+PQ_AEAD_TAG_LEN];
	memcpy(ct2_aead, m2+off, ct2_len);

	/* KEM.Dec */
	uint8_t k_kem[PQ_KEM_SS_LEN];
	ret = pq_kem_decaps(k_kem, c_kem, ctx->kem_sk);
	if (ret != 0) goto fail;

	/* ECDH: Yx */
	uint8_t ss_eph[32];
	ret = sck_hyb_ecdh(ctx->eph_sk, peer_eph_pk, ss_eph);
	if (ret != 0) goto fail;

	/* TH2 = H(M1, Y, C_KEM) */
	{
		uint8_t th2_in[SCK_HYB_MSG_BUF_SIZE]; uint32_t tl = 0;
		memcpy(th2_in, m1, m1_len); tl += m1_len;
		memcpy(th2_in+tl, peer_eph_pk, 32); tl += 32;
		memcpy(th2_in+tl, c_kem, PQ_KEM_CT_LEN); tl += PQ_KEM_CT_LEN;
		ret = sck_hyb_hash(th2_in, tl, ctx->th2);
		if (ret != 0) goto fail;
	}

	/* PRK2e = Extract(Yx, k_KEM || TH2) */
	{
		uint8_t ikm[PQ_KEM_SS_LEN+32];
		memcpy(ikm, k_kem, PQ_KEM_SS_LEN);
		memcpy(ikm+PQ_KEM_SS_LEN, ctx->th2, 32);
		ret = sck_hyb_hkdf_extract(ss_eph, 32, ikm, PQ_KEM_SS_LEN+32, ctx->prk2e);
		if (ret != 0) goto fail;
	}

	/* ECDH: Bx */
	uint8_t ss_bx[32];
	ret = sck_hyb_ecdh(ctx->eph_sk, ctx->other_static_pk, ss_bx);
	if (ret != 0) goto fail;

	/* EK2/IV2 */
	uint8_t ek2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
	{
		uint8_t ec[64]; memcpy(ec, ss_bx, 32); memcpy(ec+32, ctx->th2, 32);
		ret = sck_hyb_derive_key_iv(ctx->prk2e, SCK_HYB_EK2, sizeof(SCK_HYB_EK2)-1, ec, 64, ek2, iv2);
		if (ret != 0) goto fail;
	}

	/* Decrypt msg2 */
	uint8_t pt2[512]; size_t pt2_len = 0;
	ret = sck_hyb_aead_dec(ek2, iv2, NULL, 0, ct2_aead, ct2_len, pt2, &pt2_len);
	if (ret != 0) goto fail;

	/* PRK3e2m */
	ret = sck_hyb_hkdf_extract(ss_bx, 32, ctx->prk2e, 32, ctx->prk3e2m);
	if (ret != 0) goto fail;

	/* Verify MAC2 */
	uint8_t mk2[PQ_AEAD_TAG_LEN];
	{
		uint8_t mk2_info[32+64];
		memcpy(mk2_info, ctx->th2, 32);
		memcpy(mk2_info+32, SCK_HYB_IDR, sizeof(SCK_HYB_IDR)-1);
		ret = sck_hyb_hkdf_expand(ctx->prk3e2m, mk2_info, 32+sizeof(SCK_HYB_IDR)-1, mk2, PQ_AEAD_TAG_LEN);
		if (ret != 0) goto fail;
	}
	if (pt2_len < PQ_AEAD_TAG_LEN || memcmp(mk2, pt2+pt2_len-PQ_AEAD_TAG_LEN, PQ_AEAD_TAG_LEN) != 0)
		goto fail;

	/* TH3 = H(TH2, msg2, B) */
	{
		uint8_t th3_in[SCK_HYB_MSG_BUF_SIZE]; uint32_t len = 0;
		memcpy(th3_in, ctx->th2, 32); len += 32;
		memcpy(th3_in+len, d->msg2_buf, d->msg2_len); len += d->msg2_len;
		memcpy(th3_in+len, ctx->other_static_pk, 32); len += 32;
		ret = sck_hyb_hash(th3_in, len, ctx->th3);
		if (ret != 0) goto fail;
	}

	/* EK3/IV3 */
	uint8_t ek3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
	ret = sck_hyb_derive_key_iv(ctx->prk3e2m, SCK_HYB_EK3, sizeof(SCK_HYB_EK3)-1, ctx->th3, 32, ek3, iv3);
	if (ret != 0) goto fail;

	/* PRK4e3m = Extract(Ya, PRK3e2m) */
	uint8_t ss_ya[32];
	ret = sck_hyb_ecdh(ctx->static_sk, peer_eph_pk, ss_ya);
	if (ret != 0) goto fail;
	ret = sck_hyb_hkdf_extract(ss_ya, 32, ctx->prk3e2m, 32, ctx->prk4e3m);
	if (ret != 0) goto fail;

	/* MAC3 */
	uint8_t mac3[PQ_AEAD_TAG_LEN];
	{
		uint8_t mk3_info[32+64];
		memcpy(mk3_info, ctx->th3, 32);
		memcpy(mk3_info+32, SCK_HYB_IDI, sizeof(SCK_HYB_IDI)-1);
		ret = sck_hyb_hkdf_expand(ctx->prk4e3m, mk3_info, 32+sizeof(SCK_HYB_IDI)-1, mac3, PQ_AEAD_TAG_LEN);
		if (ret != 0) goto fail;
	}

	/* msg3 plaintext */
	uint8_t pt3[128]; uint32_t pt3_len = 0;
	memcpy(pt3+pt3_len, SCK_HYB_IDI, sizeof(SCK_HYB_IDI)-1);
	pt3_len += sizeof(SCK_HYB_IDI)-1;
	memcpy(pt3+pt3_len, mac3, PQ_AEAD_TAG_LEN);
	pt3_len += PQ_AEAD_TAG_LEN;

	uint8_t ct3_aead[128+PQ_AEAD_TAG_LEN]; size_t ct3_len = 0;
	ret = sck_hyb_aead_enc(ek3, iv3, NULL, 0, pt3, pt3_len, ct3_aead, &ct3_len);
	if (ret != 0) goto fail;

	/* TH4 = H(TH3, msg3, A) */
	{
		uint8_t th4_in[256]; uint32_t len = 0;
		memcpy(th4_in, ctx->th3, 32); len += 32;
		memcpy(th4_in+len, ct3_aead, ct3_len); len += ct3_len;
		memcpy(th4_in+len, ctx->static_pk, 32); len += 32;
		ret = sck_hyb_hash(th4_in, len, ctx->th4);
		if (ret != 0) goto fail;
	}

	/* PRK_out */
	ret = sck_hyb_hkdf_expand(ctx->prk4e3m, ctx->th4, 32, ctx->prk_out, 32);
	if (ret != 0) goto fail;

	/* Send M3 */
	memcpy(d->msg3_buf, ct3_aead, ct3_len);
	d->msg3_len = (uint32_t)ct3_len;
	{
		uint64_t t0 = sck_get_time_ns();
		ret = sock_send_msg(d->sock_fd, d->msg3_buf, d->msg3_len);
		d->txrx_ns += (sck_get_time_ns() - t0);
		if (ret != 0) goto fail;
	}

	ctx->success = 1;
	d->error = 0;
	d->wall_end_ns = sck_get_time_ns();
	d->cpu_end_ns = sck_get_thread_cpu_ns();
	d->heap_peak_bytes = heap_tracker_get_peak();
	close(d->sock_fd); d->sock_fd = -1;
	return NULL;
fail:
	ctx->success = 0;
	d->wall_end_ns = sck_get_time_ns();
	d->cpu_end_ns = sck_get_thread_cpu_ns();
	d->heap_peak_bytes = heap_tracker_get_peak();
	if (d->sock_fd >= 0) { close(d->sock_fd); d->sock_fd = -1; }
	return NULL;
}

/* ── Hybrid Responder (socket-based, server) ────────────────────────── */
static void *sck_hyb_responder_thread(void *arg)
{
	struct sck_hyb_thread_data *d = (struct sck_hyb_thread_data *)arg;
	struct hybrid_party_ctx *ctx = d->ctx;
	int ret;
	d->txrx_ns = 0;
	d->error = -1;

	/* Create server, accept connection */
	int listen_fd = sock_create_server(d->port);
	if (listen_fd < 0) return NULL;
	d->sock_fd = accept(listen_fd, NULL, NULL);
	close(listen_fd);
	if (d->sock_fd < 0) return NULL;
	int opt = 1;
	setsockopt(d->sock_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

	heap_tracker_reset();
	d->cpu_start_ns = sck_get_thread_cpu_ns();
	d->wall_start_ns = sck_get_time_ns();

	/* Receive M1 */
	{
		uint64_t t0 = sck_get_time_ns();
		ret = sock_recv_msg(d->sock_fd, d->msg1_buf, SCK_HYB_MSG_BUF_SIZE, &d->msg1_len);
		d->txrx_ns += (sck_get_time_ns() - t0);
		if (ret != 0) goto fail;
	}

	/* Parse M1: method(1), suites(1), C_I(1), X(32), PK_KEM */
	uint8_t *m1 = d->msg1_buf;
	uint32_t m1_len = d->msg1_len;
	uint32_t off = 3;
	uint8_t peer_eph_pk[32];
	memcpy(peer_eph_pk, m1+off, 32); off += 32;
	uint8_t pk_kem[PQ_KEM_PK_LEN];
	memcpy(pk_kem, m1+off, PQ_KEM_PK_LEN);

	/* KEM.Enc */
	uint8_t k_kem[PQ_KEM_SS_LEN], c_kem[PQ_KEM_CT_LEN];
	ret = pq_kem_encaps(c_kem, k_kem, pk_kem);
	if (ret != 0) goto fail;

	/* ECDH: Xy */
	uint8_t ss_eph[32];
	ret = sck_hyb_ecdh(ctx->eph_sk, peer_eph_pk, ss_eph);
	if (ret != 0) goto fail;

	/* TH2 = H(M1, Y, C_KEM) */
	{
		uint8_t th2_in[SCK_HYB_MSG_BUF_SIZE]; uint32_t tl = 0;
		memcpy(th2_in, m1, m1_len); tl += m1_len;
		memcpy(th2_in+tl, ctx->eph_pk, 32); tl += 32;
		memcpy(th2_in+tl, c_kem, PQ_KEM_CT_LEN); tl += PQ_KEM_CT_LEN;
		ret = sck_hyb_hash(th2_in, tl, ctx->th2);
		if (ret != 0) goto fail;
	}

	/* PRK2e */
	{
		uint8_t ikm[PQ_KEM_SS_LEN+32];
		memcpy(ikm, k_kem, PQ_KEM_SS_LEN);
		memcpy(ikm+PQ_KEM_SS_LEN, ctx->th2, 32);
		ret = sck_hyb_hkdf_extract(ss_eph, 32, ikm, PQ_KEM_SS_LEN+32, ctx->prk2e);
		if (ret != 0) goto fail;
	}

	/* ECDH: Xb */
	uint8_t ss_xb[32];
	ret = sck_hyb_ecdh(ctx->static_sk, peer_eph_pk, ss_xb);
	if (ret != 0) goto fail;

	/* EK2/IV2 */
	uint8_t ek2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
	{
		uint8_t ec[64]; memcpy(ec, ss_xb, 32); memcpy(ec+32, ctx->th2, 32);
		ret = sck_hyb_derive_key_iv(ctx->prk2e, SCK_HYB_EK2, sizeof(SCK_HYB_EK2)-1, ec, 64, ek2, iv2);
		if (ret != 0) goto fail;
	}

	/* PRK3e2m */
	ret = sck_hyb_hkdf_extract(ss_xb, 32, ctx->prk2e, 32, ctx->prk3e2m);
	if (ret != 0) goto fail;

	/* MAC2 */
	uint8_t mac2[PQ_AEAD_TAG_LEN];
	{
		uint8_t mk2_info[32+64];
		memcpy(mk2_info, ctx->th2, 32);
		memcpy(mk2_info+32, SCK_HYB_IDR, sizeof(SCK_HYB_IDR)-1);
		ret = sck_hyb_hkdf_expand(ctx->prk3e2m, mk2_info, 32+sizeof(SCK_HYB_IDR)-1, mac2, PQ_AEAD_TAG_LEN);
		if (ret != 0) goto fail;
	}

	/* msg2 plaintext */
	uint8_t pt2[256]; uint32_t pt2_len = 0;
	pt2[pt2_len++] = 0x27;
	memcpy(pt2+pt2_len, SCK_HYB_IDR, sizeof(SCK_HYB_IDR)-1);
	pt2_len += sizeof(SCK_HYB_IDR)-1;
	memcpy(pt2+pt2_len, mac2, PQ_AEAD_TAG_LEN);
	pt2_len += PQ_AEAD_TAG_LEN;

	uint8_t ct2_aead[512+PQ_AEAD_TAG_LEN]; size_t ct2_aead_len = 0;
	ret = sck_hyb_aead_enc(ek2, iv2, NULL, 0, pt2, pt2_len, ct2_aead, &ct2_aead_len);
	if (ret != 0) goto fail;

	/* Build wire M2: Y[32], C_KEM, len16, AEAD_ct */
	{
		uint8_t *p = d->msg2_buf; uint32_t o = 0;
		memcpy(p+o, ctx->eph_pk, 32); o += 32;
		memcpy(p+o, c_kem, PQ_KEM_CT_LEN); o += PQ_KEM_CT_LEN;
		p[o++] = (uint8_t)(ct2_aead_len >> 8);
		p[o++] = (uint8_t)(ct2_aead_len & 0xFF);
		memcpy(p+o, ct2_aead, ct2_aead_len); o += ct2_aead_len;
		d->msg2_len = o;
	}

	/* Send M2 */
	{
		uint64_t t0 = sck_get_time_ns();
		ret = sock_send_msg(d->sock_fd, d->msg2_buf, d->msg2_len);
		d->txrx_ns += (sck_get_time_ns() - t0);
		if (ret != 0) goto fail;
	}

	/* Receive M3 */
	{
		uint64_t t0 = sck_get_time_ns();
		ret = sock_recv_msg(d->sock_fd, d->msg3_buf, SCK_HYB_MSG_BUF_SIZE, &d->msg3_len);
		d->txrx_ns += (sck_get_time_ns() - t0);
		if (ret != 0) goto fail;
	}

	/* TH3 = H(TH2, msg2, B) */
	{
		uint8_t th3_in[SCK_HYB_MSG_BUF_SIZE]; uint32_t len = 0;
		memcpy(th3_in, ctx->th2, 32); len += 32;
		memcpy(th3_in+len, d->msg2_buf, d->msg2_len); len += d->msg2_len;
		memcpy(th3_in+len, ctx->static_pk, 32); len += 32;
		ret = sck_hyb_hash(th3_in, len, ctx->th3);
		if (ret != 0) goto fail;
	}

	/* EK3/IV3 */
	uint8_t ek3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
	ret = sck_hyb_derive_key_iv(ctx->prk3e2m, SCK_HYB_EK3, sizeof(SCK_HYB_EK3)-1, ctx->th3, 32, ek3, iv3);
	if (ret != 0) goto fail;

	/* Decrypt msg3 */
	uint8_t pt3[128]; size_t pt3_len = 0;
	ret = sck_hyb_aead_dec(ek3, iv3, NULL, 0, d->msg3_buf, d->msg3_len, pt3, &pt3_len);
	if (ret != 0) goto fail;

	/* PRK4e3m = Extract(Ay, PRK3e2m) */
	uint8_t ss_ay[32];
	ret = sck_hyb_ecdh(ctx->eph_sk, ctx->other_static_pk, ss_ay);
	if (ret != 0) goto fail;
	ret = sck_hyb_hkdf_extract(ss_ay, 32, ctx->prk3e2m, 32, ctx->prk4e3m);
	if (ret != 0) goto fail;

	/* Verify MAC3 */
	uint8_t mac3_exp[PQ_AEAD_TAG_LEN];
	{
		uint8_t mk3_info[32+64];
		memcpy(mk3_info, ctx->th3, 32);
		memcpy(mk3_info+32, SCK_HYB_IDI, sizeof(SCK_HYB_IDI)-1);
		ret = sck_hyb_hkdf_expand(ctx->prk4e3m, mk3_info, 32+sizeof(SCK_HYB_IDI)-1, mac3_exp, PQ_AEAD_TAG_LEN);
		if (ret != 0) goto fail;
	}
	if (pt3_len < PQ_AEAD_TAG_LEN || memcmp(mac3_exp, pt3+pt3_len-PQ_AEAD_TAG_LEN, PQ_AEAD_TAG_LEN) != 0)
		goto fail;

	/* TH4 = H(TH3, msg3, A) */
	{
		uint8_t th4_in[256]; uint32_t len = 0;
		memcpy(th4_in, ctx->th3, 32); len += 32;
		memcpy(th4_in+len, d->msg3_buf, d->msg3_len); len += d->msg3_len;
		memcpy(th4_in+len, ctx->other_static_pk, 32); len += 32;
		ret = sck_hyb_hash(th4_in, len, ctx->th4);
		if (ret != 0) goto fail;
	}

	/* PRK_out */
	ret = sck_hyb_hkdf_expand(ctx->prk4e3m, ctx->th4, 32, ctx->prk_out, 32);
	if (ret != 0) goto fail;

	ctx->success = 1;
	d->error = 0;
	d->wall_end_ns = sck_get_time_ns();
	d->cpu_end_ns = sck_get_thread_cpu_ns();
	d->heap_peak_bytes = heap_tracker_get_peak();
	close(d->sock_fd); d->sock_fd = -1;
	return NULL;
fail:
	ctx->success = 0;
	d->wall_end_ns = sck_get_time_ns();
	d->cpu_end_ns = sck_get_thread_cpu_ns();
	d->heap_peak_bytes = heap_tracker_get_peak();
	if (d->sock_fd >= 0) { close(d->sock_fd); d->sock_fd = -1; }
	return NULL;
}

/* =============================================================================
 * Handshake Benchmark Runners
 * =============================================================================
 */

static int sck_run_classic_handshake(int type_num, int base_port,
				     struct sck_ops_benchmark *ops_init,
				     struct sck_ops_benchmark *ops_resp,
				     struct sck_overhead_benchmark *oh_init,
				     struct sck_overhead_benchmark *oh_resp,
				     struct sck_handshake_benchmark *hs_init,
				     struct sck_handshake_benchmark *hs_resp)
{
	char buf[128];
	snprintf(buf, sizeof(buf),
		 "Socket: Classic Type %d handshake (%d iterations)...",
		 type_num, SOCK_BENCH_HANDSHAKE_ITERATIONS);
	print_info(buf);

	double total_i_wall = 0, total_r_wall = 0;
	double total_i_cpu  = 0, total_r_cpu  = 0;
	double total_i_txrx = 0, total_r_txrx = 0;
	size_t max_heap_i = 0, max_heap_r = 0;
	int success_count = 0;

	for (int iter = 0; iter < SOCK_BENCH_HANDSHAKE_ITERATIONS; iter++) {
		int port = base_port + iter;

		struct sck_classic_thread_data i_data, r_data;
		memset(&i_data, 0, sizeof(i_data));
		memset(&r_data, 0, sizeof(r_data));
		i_data.type_num = type_num;
		i_data.port = port;
		r_data.type_num = type_num;
		r_data.port = port;

		pthread_t tid_r, tid_i;
		/* Start responder (server) first, then initiator (client) */
		pthread_create(&tid_r, NULL, sck_classic_responder_thread, &r_data);
			   { struct timespec ts = {0, 2000 * 1000}; nanosleep(&ts, NULL); } /* 2ms to let server bind+listen */
		pthread_create(&tid_i, NULL, sck_classic_initiator_thread, &i_data);

		pthread_join(tid_i, NULL);
		pthread_join(tid_r, NULL);

		if (i_data.error == ok && r_data.error == ok) {
			total_i_wall += sck_elapsed_us(i_data.wall_start_ns, i_data.wall_end_ns);
			total_r_wall += sck_elapsed_us(r_data.wall_start_ns, r_data.wall_end_ns);
			total_i_cpu  += sck_elapsed_us(i_data.cpu_start_ns,  i_data.cpu_end_ns);
			total_r_cpu  += sck_elapsed_us(r_data.cpu_start_ns,  r_data.cpu_end_ns);
			total_i_txrx += (double)i_data.txrx_ns / 1000.0;
			total_r_txrx += (double)r_data.txrx_ns / 1000.0;
			if (i_data.heap_peak_bytes > max_heap_i) max_heap_i = i_data.heap_peak_bytes;
			if (r_data.heap_peak_bytes > max_heap_r) max_heap_r = r_data.heap_peak_bytes;
			success_count++;
		}
	}

	if (success_count == 0) {
		print_error("All Classic socket handshake iterations failed!");
		return -1;
	}

	double n = (double)success_count;
	double cpu_i = total_i_cpu / n, cpu_r = total_r_cpu / n;

	/* No calibration — keep raw operation benchmarks.
	 * Derive processing_us directly from measured CPU time. */
	double pre_i = SCOST(ops_init->keygen);
	double pre_r = SCOST(ops_resp->keygen);
	double proc_i = cpu_i - pre_i;
	double proc_r = cpu_r - pre_r;
	if (proc_i < 0) proc_i = 0;
	if (proc_r < 0) proc_r = 0;

	oh_init->cpu_us = proc_i;
	oh_init->memory_bytes = (long)max_heap_i;
	oh_resp->cpu_us = proc_r;
	oh_resp->memory_bytes = (long)max_heap_r;

	hs_init->processing_us     = proc_i;
	hs_init->txrx_us           = total_i_txrx / n;
	hs_init->precomputation_us = pre_i;
	hs_init->total_us          = total_i_wall / n;
	hs_init->overhead_us       = hs_init->total_us - hs_init->processing_us -
				     hs_init->txrx_us - hs_init->precomputation_us;
	if (hs_init->overhead_us < 0) {
		hs_init->overhead_us = 0;
		hs_init->total_us = hs_init->processing_us + hs_init->txrx_us + hs_init->precomputation_us;
	}

	hs_resp->processing_us     = proc_r;
	hs_resp->txrx_us           = total_r_txrx / n;
	hs_resp->precomputation_us = pre_r;
	hs_resp->total_us          = total_r_wall / n;
	hs_resp->overhead_us       = hs_resp->total_us - hs_resp->processing_us -
				     hs_resp->txrx_us - hs_resp->precomputation_us;
	if (hs_resp->overhead_us < 0) {
		hs_resp->overhead_us = 0;
		hs_resp->total_us = hs_resp->processing_us + hs_resp->txrx_us + hs_resp->precomputation_us;
	}

	snprintf(buf, sizeof(buf), "Classic Type %d socket handshake: %d/%d successful.",
		 type_num, success_count, SOCK_BENCH_HANDSHAKE_ITERATIONS);
	print_success(buf);
	return 0;
}

static int sck_run_pq_handshake(int pq_type_num, int base_port,
				struct sck_ops_benchmark *ops_init,
				struct sck_ops_benchmark *ops_resp,
				struct sck_overhead_benchmark *oh_init,
				struct sck_overhead_benchmark *oh_resp,
				struct sck_handshake_benchmark *hs_init,
				struct sck_handshake_benchmark *hs_resp)
{
	char buf[128];
	snprintf(buf, sizeof(buf),
		 "Socket: PQ Type %d handshake (%d iterations, TCP)...",
		 pq_type_num, SOCK_BENCH_HANDSHAKE_ITERATIONS);
	print_info(buf);

	uint8_t init_lt_pk[PQ_KEM_PK_LEN], init_lt_sk[PQ_KEM_SK_LEN];
	uint8_t resp_lt_pk[PQ_KEM_PK_LEN], resp_lt_sk[PQ_KEM_SK_LEN];
	if (pq_kem_keygen(init_lt_pk, init_lt_sk) != 0 ||
	    pq_kem_keygen(resp_lt_pk, resp_lt_sk) != 0) {
		print_error("PQ keygen setup failed"); return -1;
	}

	uint8_t init_sig_pk[PQ_SIG_PK_LEN], init_sig_sk[PQ_SIG_SK_LEN];
	uint8_t resp_sig_pk[PQ_SIG_PK_LEN], resp_sig_sk[PQ_SIG_SK_LEN];
	if (pq_type_num == 0) {
		if (pq_sig_keygen(init_sig_pk, init_sig_sk) != 0 ||
		    pq_sig_keygen(resp_sig_pk, resp_sig_sk) != 0) {
			print_error("PQ sig keygen setup failed"); return -1;
		}
	}

	double total_i_wall = 0, total_r_wall = 0;
	double total_i_cpu  = 0, total_r_cpu  = 0;
	double total_i_txrx = 0, total_r_txrx = 0;
	size_t max_heap_i = 0, max_heap_r = 0;
	int success_count = 0;

	/* PQ threads need a large stack (ML-DSA-65 polyvec matrices ≈ 55 KB) */
	pthread_attr_t tattr;
	pthread_attr_init(&tattr);
	pthread_attr_setstacksize(&tattr, BENCH_THREAD_STACK_SIZE);

	for (int iter = 0; iter < SOCK_BENCH_HANDSHAKE_ITERATIONS; iter++) {
		int port = base_port + iter;

		if (pq_type_num == 0) {
			/* ── PQ Type 0 ── */
			struct pq_party_ctx init_ctx, resp_ctx;
			memset(&init_ctx, 0, sizeof(init_ctx));
			memset(&resp_ctx, 0, sizeof(resp_ctx));
			memcpy(init_ctx.lt_pk, init_lt_pk, PQ_KEM_PK_LEN);
			memcpy(init_ctx.lt_sk, init_lt_sk, PQ_KEM_SK_LEN);
			memcpy(init_ctx.other_lt_pk, resp_lt_pk, PQ_KEM_PK_LEN);
			memcpy(init_ctx.sig_pk, init_sig_pk, PQ_SIG_PK_LEN);
			memcpy(init_ctx.sig_sk, init_sig_sk, PQ_SIG_SK_LEN);
			memcpy(init_ctx.other_sig_pk, resp_sig_pk, PQ_SIG_PK_LEN);
			memcpy(resp_ctx.lt_pk, resp_lt_pk, PQ_KEM_PK_LEN);
			memcpy(resp_ctx.lt_sk, resp_lt_sk, PQ_KEM_SK_LEN);
			memcpy(resp_ctx.other_lt_pk, init_lt_pk, PQ_KEM_PK_LEN);
			memcpy(resp_ctx.sig_pk, resp_sig_pk, PQ_SIG_PK_LEN);
			memcpy(resp_ctx.sig_sk, resp_sig_sk, PQ_SIG_SK_LEN);
			memcpy(resp_ctx.other_sig_pk, init_sig_pk, PQ_SIG_PK_LEN);

			struct sck_pq_thread_data id, rd;
			memset(&id, 0, sizeof(id)); memset(&rd, 0, sizeof(rd));
			id.ctx = &init_ctx; id.port = port;
			rd.ctx = &resp_ctx; rd.port = port;

			pthread_t tid_r, tid_i;
			pthread_create(&tid_r, &tattr, sck_pq0_responder_thread, &rd);
					   { struct timespec ts = {0, 2000 * 1000}; nanosleep(&ts, NULL); }
			pthread_create(&tid_i, &tattr, sck_pq0_initiator_thread, &id);
			pthread_join(tid_i, NULL);
			pthread_join(tid_r, NULL);

			if (id.error == 0 && rd.error == 0) {
				total_i_wall += sck_elapsed_us(id.wall_start_ns, id.wall_end_ns);
				total_r_wall += sck_elapsed_us(rd.wall_start_ns, rd.wall_end_ns);
				total_i_cpu  += sck_elapsed_us(id.cpu_start_ns,  id.cpu_end_ns);
				total_r_cpu  += sck_elapsed_us(rd.cpu_start_ns,  rd.cpu_end_ns);
				total_i_txrx += (double)id.txrx_ns / 1000.0;
				total_r_txrx += (double)rd.txrx_ns / 1000.0;
				if (id.heap_peak_bytes > max_heap_i) max_heap_i = id.heap_peak_bytes;
				if (rd.heap_peak_bytes > max_heap_r) max_heap_r = rd.heap_peak_bytes;
				success_count++;
			}
		} else {
			/* ── PQ Type 3 ── */
			struct pq3_party_ctx init_ctx, resp_ctx;
			memset(&init_ctx, 0, sizeof(init_ctx));
			memset(&resp_ctx, 0, sizeof(resp_ctx));
			memcpy(init_ctx.lt_pk, init_lt_pk, PQ_KEM_PK_LEN);
			memcpy(init_ctx.lt_sk, init_lt_sk, PQ_KEM_SK_LEN);
			memcpy(init_ctx.other_lt_pk, resp_lt_pk, PQ_KEM_PK_LEN);
			memcpy(resp_ctx.lt_pk, resp_lt_pk, PQ_KEM_PK_LEN);
			memcpy(resp_ctx.lt_sk, resp_lt_sk, PQ_KEM_SK_LEN);
			memcpy(resp_ctx.other_lt_pk, init_lt_pk, PQ_KEM_PK_LEN);

			struct sck_pq3_thread_data id, rd;
			memset(&id, 0, sizeof(id)); memset(&rd, 0, sizeof(rd));
			id.ctx = &init_ctx; id.port = port;
			rd.ctx = &resp_ctx; rd.port = port;

			pthread_t tid_r, tid_i;
			pthread_create(&tid_r, &tattr, sck_pq3_responder_thread, &rd);
					   { struct timespec ts = {0, 2000 * 1000}; nanosleep(&ts, NULL); }
			pthread_create(&tid_i, &tattr, sck_pq3_initiator_thread, &id);
			pthread_join(tid_i, NULL);
			pthread_join(tid_r, NULL);

			if (id.error == 0 && rd.error == 0) {
				total_i_wall += sck_elapsed_us(id.wall_start_ns, id.wall_end_ns);
				total_r_wall += sck_elapsed_us(rd.wall_start_ns, rd.wall_end_ns);
				total_i_cpu  += sck_elapsed_us(id.cpu_start_ns,  id.cpu_end_ns);
				total_r_cpu  += sck_elapsed_us(rd.cpu_start_ns,  rd.cpu_end_ns);
				total_i_txrx += (double)id.txrx_ns / 1000.0;
				total_r_txrx += (double)rd.txrx_ns / 1000.0;
				if (id.heap_peak_bytes > max_heap_i) max_heap_i = id.heap_peak_bytes;
				if (rd.heap_peak_bytes > max_heap_r) max_heap_r = rd.heap_peak_bytes;
				success_count++;
			}
		}
	}

	if (success_count == 0) { print_error("All PQ socket handshake failed!"); pthread_attr_destroy(&tattr); return -1; }

	double n = (double)success_count;
	double cpu_i = total_i_cpu / n, cpu_r = total_r_cpu / n;

	/* No calibration — keep raw operation benchmarks. */
	double pre_i = SCOST(ops_init->pq_keygen);
	double pre_r = SCOST(ops_resp->pq_keygen);
	double proc_i = cpu_i - pre_i;
	double proc_r = cpu_r - pre_r;
	if (proc_i < 0) proc_i = 0;
	if (proc_r < 0) proc_r = 0;

	oh_init->cpu_us = proc_i; oh_init->memory_bytes = (long)max_heap_i;
	oh_resp->cpu_us = proc_r; oh_resp->memory_bytes = (long)max_heap_r;

	hs_init->processing_us = proc_i; hs_init->txrx_us = total_i_txrx / n;
	hs_init->precomputation_us = pre_i; hs_init->total_us = total_i_wall / n;
	hs_init->overhead_us = hs_init->total_us - proc_i - hs_init->txrx_us - pre_i;
	if (hs_init->overhead_us < 0) { hs_init->overhead_us = 0; hs_init->total_us = proc_i + hs_init->txrx_us + pre_i; }

	hs_resp->processing_us = proc_r; hs_resp->txrx_us = total_r_txrx / n;
	hs_resp->precomputation_us = pre_r; hs_resp->total_us = total_r_wall / n;
	hs_resp->overhead_us = hs_resp->total_us - proc_r - hs_resp->txrx_us - pre_r;
	if (hs_resp->overhead_us < 0) { hs_resp->overhead_us = 0; hs_resp->total_us = proc_r + hs_resp->txrx_us + pre_r; }

	snprintf(buf, sizeof(buf), "PQ Type %d socket handshake: %d/%d successful.",
		 pq_type_num, success_count, SOCK_BENCH_HANDSHAKE_ITERATIONS);
	print_success(buf);
	pthread_attr_destroy(&tattr);
	return 0;
}

static int sck_run_hybrid_handshake(int base_port,
				    struct sck_ops_benchmark *ops_init,
				    struct sck_ops_benchmark *ops_resp,
				    struct sck_overhead_benchmark *oh_init,
				    struct sck_overhead_benchmark *oh_resp,
				    struct sck_handshake_benchmark *hs_init,
				    struct sck_handshake_benchmark *hs_resp)
{
	print_info("Socket: Hybrid Type 3 handshake (TCP)...");

	uint8_t init_static_sk[32], init_static_pk[32];
	uint8_t resp_static_sk[32], resp_static_pk[32];
	{
		struct byte_array sk = {.len=32,.ptr=init_static_sk};
		struct byte_array pk = {.len=32,.ptr=init_static_pk};
		if (ephemeral_dh_key_gen(X25519, 100, &sk, &pk) != ok) return -1;
	}
	{
		struct byte_array sk = {.len=32,.ptr=resp_static_sk};
		struct byte_array pk = {.len=32,.ptr=resp_static_pk};
		if (ephemeral_dh_key_gen(X25519, 200, &sk, &pk) != ok) return -1;
	}

	double total_i_wall = 0, total_r_wall = 0;
	double total_i_cpu  = 0, total_r_cpu  = 0;
	double total_i_txrx = 0, total_r_txrx = 0;
	size_t max_heap_i = 0, max_heap_r = 0;
	int success_count = 0;

	/* Hybrid threads use ML-KEM-768 which needs extra stack on ARM */
	pthread_attr_t tattr;
	pthread_attr_init(&tattr);
	pthread_attr_setstacksize(&tattr, BENCH_THREAD_STACK_SIZE);

	for (int iter = 0; iter < SOCK_BENCH_HANDSHAKE_ITERATIONS; iter++) {
		int port = base_port + iter;

		struct hybrid_party_ctx init_ctx, resp_ctx;
		memset(&init_ctx, 0, sizeof(init_ctx));
		memset(&resp_ctx, 0, sizeof(resp_ctx));
		memcpy(init_ctx.static_sk, init_static_sk, 32);
		memcpy(init_ctx.static_pk, init_static_pk, 32);
		memcpy(resp_ctx.static_sk, resp_static_sk, 32);
		memcpy(resp_ctx.static_pk, resp_static_pk, 32);
		memcpy(init_ctx.other_static_pk, resp_static_pk, 32);
		memcpy(resp_ctx.other_static_pk, init_static_pk, 32);
		{
			struct byte_array sk = {.len=32,.ptr=init_ctx.eph_sk};
			struct byte_array pk = {.len=32,.ptr=init_ctx.eph_pk};
			ephemeral_dh_key_gen(X25519, 300+iter, &sk, &pk);
		}
		{
			struct byte_array sk = {.len=32,.ptr=resp_ctx.eph_sk};
			struct byte_array pk = {.len=32,.ptr=resp_ctx.eph_pk};
			ephemeral_dh_key_gen(X25519, 400+iter, &sk, &pk);
		}
		pq_kem_keygen(init_ctx.kem_pk, init_ctx.kem_sk);

		struct sck_hyb_thread_data id, rd;
		memset(&id, 0, sizeof(id)); memset(&rd, 0, sizeof(rd));
		id.ctx = &init_ctx; id.port = port;
		rd.ctx = &resp_ctx; rd.port = port;

		pthread_t tid_r, tid_i;
		pthread_create(&tid_r, &tattr, sck_hyb_responder_thread, &rd);
			   { struct timespec ts = {0, 2000 * 1000}; nanosleep(&ts, NULL); }
		pthread_create(&tid_i, &tattr, sck_hyb_initiator_thread, &id);
		pthread_join(tid_i, NULL);
		pthread_join(tid_r, NULL);

		if (id.error == 0 && rd.error == 0) {
			total_i_wall += sck_elapsed_us(id.wall_start_ns, id.wall_end_ns);
			total_r_wall += sck_elapsed_us(rd.wall_start_ns, rd.wall_end_ns);
			total_i_cpu  += sck_elapsed_us(id.cpu_start_ns,  id.cpu_end_ns);
			total_r_cpu  += sck_elapsed_us(rd.cpu_start_ns,  rd.cpu_end_ns);
			total_i_txrx += (double)id.txrx_ns / 1000.0;
			total_r_txrx += (double)rd.txrx_ns / 1000.0;
			if (id.heap_peak_bytes > max_heap_i) max_heap_i = id.heap_peak_bytes;
			if (rd.heap_peak_bytes > max_heap_r) max_heap_r = rd.heap_peak_bytes;
			success_count++;
		}
	}

	if (success_count == 0) { print_error("All Hybrid socket handshake failed!"); pthread_attr_destroy(&tattr); return -1; }

	double n = (double)success_count;
	double cpu_i = total_i_cpu / n, cpu_r = total_r_cpu / n;

	/* No calibration — keep raw operation benchmarks.
	 * Hybrid precomp = X25519 keygen + PQ keygen. */
	double pre_i = SCOST(ops_init->keygen) + SCOST(ops_init->pq_keygen);
	double pre_r = SCOST(ops_resp->keygen) + SCOST(ops_resp->pq_keygen);
	double proc_i = cpu_i - pre_i;
	double proc_r = cpu_r - pre_r;
	if (proc_i < 0) proc_i = 0;
	if (proc_r < 0) proc_r = 0;

	oh_init->cpu_us = proc_i; oh_init->memory_bytes = (long)max_heap_i;
	oh_resp->cpu_us = proc_r; oh_resp->memory_bytes = (long)max_heap_r;

	hs_init->processing_us = proc_i; hs_init->txrx_us = total_i_txrx / n;
	hs_init->precomputation_us = pre_i; hs_init->total_us = total_i_wall / n;
	hs_init->overhead_us = hs_init->total_us - proc_i - hs_init->txrx_us - pre_i;
	if (hs_init->overhead_us < 0) { hs_init->overhead_us = 0; hs_init->total_us = proc_i + hs_init->txrx_us + pre_i; }

	hs_resp->processing_us = proc_r; hs_resp->txrx_us = total_r_txrx / n;
	hs_resp->precomputation_us = pre_r; hs_resp->total_us = total_r_wall / n;
	hs_resp->overhead_us = hs_resp->total_us - proc_r - hs_resp->txrx_us - pre_r;
	if (hs_resp->overhead_us < 0) { hs_resp->overhead_us = 0; hs_resp->total_us = proc_r + hs_resp->txrx_us + pre_r; }

	char buf[128];
	snprintf(buf, sizeof(buf), "Hybrid socket handshake: %d/%d successful.",
		 success_count, SOCK_BENCH_HANDSHAKE_ITERATIONS);
	print_success(buf);
	pthread_attr_destroy(&tattr);
	return 0;
}

/* =============================================================================
 * CSV Writers (identical format to edhoc_benchmark.c)
 * =============================================================================
 */

#define SWRITE_OP(TYPE, ROLE, OP_NAME, OP) \
	fprintf(fp, "%s,%s,%s,%.3f,%d,%.3f,%d\n", \
		TYPE, ROLE, OP_NAME, (OP).avg_us, (OP).calls, \
		(OP).avg_us * (double)(OP).calls, (OP).count)

static int sck_write_operations_csv(const char *path,
	const char *role_suffix,
	struct sck_ops_benchmark *t0i, struct sck_ops_benchmark *t0r,
	struct sck_ops_benchmark *t3i, struct sck_ops_benchmark *t3r,
	struct sck_ops_benchmark *t0pi, struct sck_ops_benchmark *t0pr,
	struct sck_ops_benchmark *t3pi, struct sck_ops_benchmark *t3pr,
	struct sck_ops_benchmark *thi, struct sck_ops_benchmark *thr)
{
	FILE *fp = fopen(path, "w");
	if (!fp) return -1;
	fprintf(fp, "type,role,operation,avg_time_us,calls_per_handshake,total_per_handshake_us,iterations\n");

	/* Determine which roles to include based on role_suffix */
	int write_initiator = 1, write_responder = 1;
	if (role_suffix && strcmp(role_suffix, "initiator") == 0)
		write_responder = 0;
	else if (role_suffix && strcmp(role_suffix, "responder") == 0)
		write_initiator = 0;

	/* Classic Type 0 */
	if (write_initiator) {
	SWRITE_OP("Type0_SigSig","Initiator","KeyGen",t0i->keygen);
	SWRITE_OP("Type0_SigSig","Initiator","Encap",t0i->pq_encaps);
	SWRITE_OP("Type0_SigSig","Initiator","Decap",t0i->pq_decaps);
	SWRITE_OP("Type0_SigSig","Initiator","AEAD_Enc",t0i->aead_enc);
	SWRITE_OP("Type0_SigSig","Initiator","AEAD_Dec",t0i->aead_dec);
	SWRITE_OP("Type0_SigSig","Initiator","Signature",t0i->signature);
	SWRITE_OP("Type0_SigSig","Initiator","Verification",t0i->verification);
	SWRITE_OP("Type0_SigSig","Initiator","ECDH",t0i->ecdh);
	SWRITE_OP("Type0_SigSig","Initiator","HKDF",t0i->hkdf);
	SWRITE_OP("Type0_SigSig","Initiator","Hash",t0i->hash);
	}
	if (write_responder) {
	SWRITE_OP("Type0_SigSig","Responder","KeyGen",t0r->keygen);
	SWRITE_OP("Type0_SigSig","Responder","Encap",t0r->pq_encaps);
	SWRITE_OP("Type0_SigSig","Responder","Decap",t0r->pq_decaps);
	SWRITE_OP("Type0_SigSig","Responder","AEAD_Enc",t0r->aead_enc);
	SWRITE_OP("Type0_SigSig","Responder","AEAD_Dec",t0r->aead_dec);
	SWRITE_OP("Type0_SigSig","Responder","Signature",t0r->signature);
	SWRITE_OP("Type0_SigSig","Responder","Verification",t0r->verification);
	SWRITE_OP("Type0_SigSig","Responder","ECDH",t0r->ecdh);
	SWRITE_OP("Type0_SigSig","Responder","HKDF",t0r->hkdf);
	SWRITE_OP("Type0_SigSig","Responder","Hash",t0r->hash);
	}

	/* Classic Type 3 */
	if (write_initiator) {
	SWRITE_OP("Type3_MACMAC","Initiator","KeyGen",t3i->keygen);
	SWRITE_OP("Type3_MACMAC","Initiator","Encap",t3i->pq_encaps);
	SWRITE_OP("Type3_MACMAC","Initiator","Decap",t3i->pq_decaps);
	SWRITE_OP("Type3_MACMAC","Initiator","AEAD_Enc",t3i->aead_enc);
	SWRITE_OP("Type3_MACMAC","Initiator","AEAD_Dec",t3i->aead_dec);
	SWRITE_OP("Type3_MACMAC","Initiator","Signature",t3i->signature);
	SWRITE_OP("Type3_MACMAC","Initiator","Verification",t3i->verification);
	SWRITE_OP("Type3_MACMAC","Initiator","ECDH",t3i->ecdh);
	SWRITE_OP("Type3_MACMAC","Initiator","HKDF",t3i->hkdf);
	SWRITE_OP("Type3_MACMAC","Initiator","Hash",t3i->hash);
	}
	if (write_responder) {
	SWRITE_OP("Type3_MACMAC","Responder","KeyGen",t3r->keygen);
	SWRITE_OP("Type3_MACMAC","Responder","Encap",t3r->pq_encaps);
	SWRITE_OP("Type3_MACMAC","Responder","Decap",t3r->pq_decaps);
	SWRITE_OP("Type3_MACMAC","Responder","AEAD_Enc",t3r->aead_enc);
	SWRITE_OP("Type3_MACMAC","Responder","AEAD_Dec",t3r->aead_dec);
	SWRITE_OP("Type3_MACMAC","Responder","Signature",t3r->signature);
	SWRITE_OP("Type3_MACMAC","Responder","Verification",t3r->verification);
	SWRITE_OP("Type3_MACMAC","Responder","ECDH",t3r->ecdh);
	SWRITE_OP("Type3_MACMAC","Responder","HKDF",t3r->hkdf);
	SWRITE_OP("Type3_MACMAC","Responder","Hash",t3r->hash);
	}

	/* PQ Type 0 */
	if (write_initiator) {
	SWRITE_OP("Type0_PQ","Initiator","PQ_KeyGen",t0pi->pq_keygen);
	SWRITE_OP("Type0_PQ","Initiator","PQ_Encaps",t0pi->pq_encaps);
	SWRITE_OP("Type0_PQ","Initiator","PQ_Decaps",t0pi->pq_decaps);
	SWRITE_OP("Type0_PQ","Initiator","PQ_Signature",t0pi->pq_sig_sign);
	SWRITE_OP("Type0_PQ","Initiator","PQ_Verification",t0pi->pq_sig_verify);
	SWRITE_OP("Type0_PQ","Initiator","PQ_AEAD_Enc",t0pi->pq_aead_enc);
	SWRITE_OP("Type0_PQ","Initiator","PQ_AEAD_Dec",t0pi->pq_aead_dec);
	SWRITE_OP("Type0_PQ","Initiator","PQ_HKDF",t0pi->pq_hkdf);
	SWRITE_OP("Type0_PQ","Initiator","PQ_Hash",t0pi->pq_hash);
	}
	if (write_responder) {
	SWRITE_OP("Type0_PQ","Responder","PQ_KeyGen",t0pr->pq_keygen);
	SWRITE_OP("Type0_PQ","Responder","PQ_Encaps",t0pr->pq_encaps);
	SWRITE_OP("Type0_PQ","Responder","PQ_Decaps",t0pr->pq_decaps);
	SWRITE_OP("Type0_PQ","Responder","PQ_Signature",t0pr->pq_sig_sign);
	SWRITE_OP("Type0_PQ","Responder","PQ_Verification",t0pr->pq_sig_verify);
	SWRITE_OP("Type0_PQ","Responder","PQ_AEAD_Enc",t0pr->pq_aead_enc);
	SWRITE_OP("Type0_PQ","Responder","PQ_AEAD_Dec",t0pr->pq_aead_dec);
	SWRITE_OP("Type0_PQ","Responder","PQ_HKDF",t0pr->pq_hkdf);
	SWRITE_OP("Type0_PQ","Responder","PQ_Hash",t0pr->pq_hash);
	}

	/* PQ Type 3 */
	if (write_initiator) {
	SWRITE_OP("Type3_PQ","Initiator","PQ_KeyGen",t3pi->pq_keygen);
	SWRITE_OP("Type3_PQ","Initiator","PQ_Encaps",t3pi->pq_encaps);
	SWRITE_OP("Type3_PQ","Initiator","PQ_Decaps",t3pi->pq_decaps);
	SWRITE_OP("Type3_PQ","Initiator","PQ_Signature",t3pi->pq_sig_sign);
	SWRITE_OP("Type3_PQ","Initiator","PQ_Verification",t3pi->pq_sig_verify);
	SWRITE_OP("Type3_PQ","Initiator","PQ_AEAD_Enc",t3pi->pq_aead_enc);
	SWRITE_OP("Type3_PQ","Initiator","PQ_AEAD_Dec",t3pi->pq_aead_dec);
	SWRITE_OP("Type3_PQ","Initiator","PQ_HKDF",t3pi->pq_hkdf);
	SWRITE_OP("Type3_PQ","Initiator","PQ_Hash",t3pi->pq_hash);
	}
	if (write_responder) {
	SWRITE_OP("Type3_PQ","Responder","PQ_KeyGen",t3pr->pq_keygen);
	SWRITE_OP("Type3_PQ","Responder","PQ_Encaps",t3pr->pq_encaps);
	SWRITE_OP("Type3_PQ","Responder","PQ_Decaps",t3pr->pq_decaps);
	SWRITE_OP("Type3_PQ","Responder","PQ_Signature",t3pr->pq_sig_sign);
	SWRITE_OP("Type3_PQ","Responder","PQ_Verification",t3pr->pq_sig_verify);
	SWRITE_OP("Type3_PQ","Responder","PQ_AEAD_Enc",t3pr->pq_aead_enc);
	SWRITE_OP("Type3_PQ","Responder","PQ_AEAD_Dec",t3pr->pq_aead_dec);
	SWRITE_OP("Type3_PQ","Responder","PQ_HKDF",t3pr->pq_hkdf);
	SWRITE_OP("Type3_PQ","Responder","PQ_Hash",t3pr->pq_hash);
	}

	/* Hybrid Type 3 */
	if (write_initiator) {
	SWRITE_OP("Type3_Hybrid","Initiator","KeyGen",thi->keygen);
	SWRITE_OP("Type3_Hybrid","Initiator","AEAD_Enc",thi->aead_enc);
	SWRITE_OP("Type3_Hybrid","Initiator","AEAD_Dec",thi->aead_dec);
	SWRITE_OP("Type3_Hybrid","Initiator","ECDH",thi->ecdh);
	SWRITE_OP("Type3_Hybrid","Initiator","HKDF",thi->hkdf);
	SWRITE_OP("Type3_Hybrid","Initiator","Hash",thi->hash);
	SWRITE_OP("Type3_Hybrid","Initiator","PQ_KeyGen",thi->pq_keygen);
	SWRITE_OP("Type3_Hybrid","Initiator","PQ_Encaps",thi->pq_encaps);
	SWRITE_OP("Type3_Hybrid","Initiator","PQ_Decaps",thi->pq_decaps);
	}
	if (write_responder) {
	SWRITE_OP("Type3_Hybrid","Responder","KeyGen",thr->keygen);
	SWRITE_OP("Type3_Hybrid","Responder","AEAD_Enc",thr->aead_enc);
	SWRITE_OP("Type3_Hybrid","Responder","AEAD_Dec",thr->aead_dec);
	SWRITE_OP("Type3_Hybrid","Responder","ECDH",thr->ecdh);
	SWRITE_OP("Type3_Hybrid","Responder","HKDF",thr->hkdf);
	SWRITE_OP("Type3_Hybrid","Responder","Hash",thr->hash);
	SWRITE_OP("Type3_Hybrid","Responder","PQ_KeyGen",thr->pq_keygen);
	SWRITE_OP("Type3_Hybrid","Responder","PQ_Encaps",thr->pq_encaps);
	SWRITE_OP("Type3_Hybrid","Responder","PQ_Decaps",thr->pq_decaps);
	}

	fclose(fp);
	return 0;
}

static int sck_write_overhead_csv(const char *path,
	const char *role_suffix,
	struct sck_overhead_benchmark *t0i, struct sck_overhead_benchmark *t0r,
	struct sck_overhead_benchmark *t3i, struct sck_overhead_benchmark *t3r,
	struct sck_overhead_benchmark *t0pi, struct sck_overhead_benchmark *t0pr,
	struct sck_overhead_benchmark *t3pi, struct sck_overhead_benchmark *t3pr,
	struct sck_overhead_benchmark *thi, struct sck_overhead_benchmark *thr)
{
	FILE *fp = fopen(path, "w");
	if (!fp) return -1;
	fprintf(fp, "type,role,cpu_time_us,memory_bytes,memory_note\n");

	/* Determine which roles to include based on role_suffix */
	int write_initiator = 1, write_responder = 1;
	if (role_suffix && strcmp(role_suffix, "initiator") == 0)
		write_responder = 0;
	else if (role_suffix && strcmp(role_suffix, "responder") == 0)
		write_initiator = 0;

	if (write_initiator)
		fprintf(fp, "Type0_SigSig,Initiator,%.3f,%ld,actual_heap\n", t0i->cpu_us, t0i->memory_bytes);
	if (write_responder)
		fprintf(fp, "Type0_SigSig,Responder,%.3f,%ld,actual_heap\n", t0r->cpu_us, t0r->memory_bytes);
	if (write_initiator)
		fprintf(fp, "Type3_MACMAC,Initiator,%.3f,%ld,actual_heap\n", t3i->cpu_us, t3i->memory_bytes);
	if (write_responder)
		fprintf(fp, "Type3_MACMAC,Responder,%.3f,%ld,actual_heap\n", t3r->cpu_us, t3r->memory_bytes);
	if (write_initiator)
		fprintf(fp, "Type0_PQ,Initiator,%.3f,%ld,actual_heap\n", t0pi->cpu_us, t0pi->memory_bytes);
	if (write_responder)
		fprintf(fp, "Type0_PQ,Responder,%.3f,%ld,actual_heap\n", t0pr->cpu_us, t0pr->memory_bytes);
	if (write_initiator)
		fprintf(fp, "Type3_PQ,Initiator,%.3f,%ld,actual_heap\n", t3pi->cpu_us, t3pi->memory_bytes);
	if (write_responder)
		fprintf(fp, "Type3_PQ,Responder,%.3f,%ld,actual_heap\n", t3pr->cpu_us, t3pr->memory_bytes);
	if (write_initiator)
		fprintf(fp, "Type3_Hybrid,Initiator,%.3f,%ld,actual_heap\n", thi->cpu_us, thi->memory_bytes);
	if (write_responder)
		fprintf(fp, "Type3_Hybrid,Responder,%.3f,%ld,actual_heap\n", thr->cpu_us, thr->memory_bytes);
	fclose(fp);
	return 0;
}

static int sck_write_handshake_csv(const char *path,
	const char *role_suffix,
	struct sck_handshake_benchmark *t0i, struct sck_handshake_benchmark *t0r,
	struct sck_handshake_benchmark *t3i, struct sck_handshake_benchmark *t3r,
	struct sck_handshake_benchmark *t0pi, struct sck_handshake_benchmark *t0pr,
	struct sck_handshake_benchmark *t3pi, struct sck_handshake_benchmark *t3pr,
	struct sck_handshake_benchmark *thi, struct sck_handshake_benchmark *thr)
{
	FILE *fp = fopen(path, "w");
	if (!fp) return -1;
	fprintf(fp, "type,role,processing_us,txrx_us,precomputation_us,overhead_us,total_us\n");

	/* Determine which roles to include based on role_suffix */
	int write_initiator = 1, write_responder = 1;
	if (role_suffix && strcmp(role_suffix, "initiator") == 0)
		write_responder = 0;
	else if (role_suffix && strcmp(role_suffix, "responder") == 0)
		write_initiator = 0;

	#define WHS(T,R,D) fprintf(fp, "%s,%s,%.3f,%.3f,%.3f,%.3f,%.3f\n", T, R, \
		(D)->processing_us, (D)->txrx_us, (D)->precomputation_us, (D)->overhead_us, (D)->total_us)
	if (write_initiator) WHS("Type0_SigSig","Initiator",t0i);
	if (write_responder) WHS("Type0_SigSig","Responder",t0r);
	if (write_initiator) WHS("Type3_MACMAC","Initiator",t3i);
	if (write_responder) WHS("Type3_MACMAC","Responder",t3r);
	if (write_initiator) WHS("Type0_PQ","Initiator",t0pi);
	if (write_responder) WHS("Type0_PQ","Responder",t0pr);
	if (write_initiator) WHS("Type3_PQ","Initiator",t3pi);
	if (write_responder) WHS("Type3_PQ","Responder",t3pr);
	if (write_initiator) WHS("Type3_Hybrid","Initiator",thi);
	if (write_responder) WHS("Type3_Hybrid","Responder",thr);
	#undef WHS
	fclose(fp);
	return 0;
}

/* =============================================================================
 * Main Entry: run_edhoc_benchmark_socket()
 * =============================================================================
 */

int run_edhoc_benchmark_socket(const char *role_suffix)
{
	setvbuf(stdout, NULL, _IONBF, 0); /* disable buffering for crash debugging */
	print_header("EDHOC Socket-based Benchmark (TCP localhost, All 5 Variants)");
	printf("\n");
	char buf[256];

	/*
	 * When two processes run mode-9 simultaneously on the same machine
	 * (loopback test), both execute Phase B on localhost.  We offset the
	 * base port for the "responder" role so the two port ranges never
	 * overlap.  5 variant groups × 1000 ports ≈ 5000 ports consumed,
	 * so a 6000-port gap is safe.
	 */
	int bp = SOCK_BENCH_BASE_PORT;
	if (role_suffix && strcmp(role_suffix, "responder") == 0)
		bp += 6000;   /* responder → 25000-29999, initiator → 19000-23999 */
	snprintf(buf, sizeof(buf), "  Operations iterations : %d", SOCK_BENCH_ITERATIONS);
	print_info(buf);
	snprintf(buf, sizeof(buf), "  Handshake iterations  : %d", SOCK_BENCH_HANDSHAKE_ITERATIONS);
	print_info(buf);
	print_info("  Transport: TCP localhost (127.0.0.1)");
	print_info("  Variants: Type0, Type3, Type0_PQ, Type3_PQ, Type3_Hybrid");
	printf("\n");

	mkdir(SOCK_BENCH_OUTPUT_DIR, 0755);

	/* === Phase 1: Benchmark each crypto primitive per role === */
	print_header("Phase 1: Crypto Primitive Benchmarks");
	printf("\n");
	print_info("Benchmarking all primitives for Initiator role...");
	struct sck_prim_cache pcache_i;
	memset(&pcache_i, 0, sizeof(pcache_i));
	sck_bench_all_primitives(&pcache_i);
	print_info("Benchmarking all primitives for Responder role...");
	struct sck_prim_cache pcache_r;
	memset(&pcache_r, 0, sizeof(pcache_r));
	sck_bench_all_primitives(&pcache_r);
	print_success("Primitive benchmarks done.");

	/* Assemble per-variant ops from role-specific caches */
	struct sck_ops_benchmark t0_oi, t0_or, t3_oi, t3_or;
	memset(&t0_oi, 0, sizeof(t0_oi)); memset(&t0_or, 0, sizeof(t0_or));
	memset(&t3_oi, 0, sizeof(t3_oi)); memset(&t3_or, 0, sizeof(t3_or));
	sck_assemble_classic_ops(&pcache_i, 0, true, &t0_oi);
	sck_assemble_classic_ops(&pcache_r, 0, false, &t0_or);
	sck_assemble_classic_ops(&pcache_i, 3, true, &t3_oi);
	sck_assemble_classic_ops(&pcache_r, 3, false, &t3_or);

	struct sck_ops_benchmark t0p_oi, t0p_or, t3p_oi, t3p_or;
	memset(&t0p_oi, 0, sizeof(t0p_oi)); memset(&t0p_or, 0, sizeof(t0p_or));
	memset(&t3p_oi, 0, sizeof(t3p_oi)); memset(&t3p_or, 0, sizeof(t3p_or));
	sck_assemble_pq_ops(&pcache_i, 0, true, &t0p_oi);
	sck_assemble_pq_ops(&pcache_r, 0, false, &t0p_or);
	sck_assemble_pq_ops(&pcache_i, 3, true, &t3p_oi);
	sck_assemble_pq_ops(&pcache_r, 3, false, &t3p_or);

	struct sck_ops_benchmark th_oi, th_or;
	memset(&th_oi, 0, sizeof(th_oi)); memset(&th_or, 0, sizeof(th_or));
	sck_assemble_hybrid_ops(&pcache_i, true, &th_oi);
	sck_assemble_hybrid_ops(&pcache_r, false, &th_or);
	print_success("All variant ops assembled.");

	/* === Phase 2: Socket-based Handshakes === */
	print_header("Phase 2a: Classic Handshake (TCP Socket)");
	printf("\n");
	struct sck_overhead_benchmark t0_ohi, t0_ohr, t3_ohi, t3_ohr;
	struct sck_handshake_benchmark t0_hi, t0_hr, t3_hi, t3_hr;
	memset(&t0_ohi, 0, sizeof(t0_ohi)); memset(&t0_ohr, 0, sizeof(t0_ohr));
	memset(&t3_ohi, 0, sizeof(t3_ohi)); memset(&t3_ohr, 0, sizeof(t3_ohr));
	memset(&t0_hi, 0, sizeof(t0_hi)); memset(&t0_hr, 0, sizeof(t0_hr));
	memset(&t3_hi, 0, sizeof(t3_hi)); memset(&t3_hr, 0, sizeof(t3_hr));

	if (sck_run_classic_handshake(0, bp,
		&t0_oi, &t0_or, &t0_ohi, &t0_ohr, &t0_hi, &t0_hr) != 0)
		return -1;
	if (sck_run_classic_handshake(3, bp + 1000,
		&t3_oi, &t3_or, &t3_ohi, &t3_ohr, &t3_hi, &t3_hr) != 0)
		return -1;

	print_header("Phase 2b: PQ Handshake");
	printf("\n");
	struct sck_overhead_benchmark t0p_ohi, t0p_ohr, t3p_ohi, t3p_ohr;
	struct sck_handshake_benchmark t0p_hi, t0p_hr, t3p_hi, t3p_hr;
	memset(&t0p_ohi, 0, sizeof(t0p_ohi)); memset(&t0p_ohr, 0, sizeof(t0p_ohr));
	memset(&t3p_ohi, 0, sizeof(t3p_ohi)); memset(&t3p_ohr, 0, sizeof(t3p_ohr));
	memset(&t0p_hi, 0, sizeof(t0p_hi)); memset(&t0p_hr, 0, sizeof(t0p_hr));
	memset(&t3p_hi, 0, sizeof(t3p_hi)); memset(&t3p_hr, 0, sizeof(t3p_hr));

	if (sck_run_pq_handshake(0, bp + 2000,
		&t0p_oi, &t0p_or, &t0p_ohi, &t0p_ohr, &t0p_hi, &t0p_hr) != 0)
		return -1;
	if (sck_run_pq_handshake(3, bp + 3000,
		&t3p_oi, &t3p_or, &t3p_ohi, &t3p_ohr, &t3p_hi, &t3p_hr) != 0)
		return -1;

	print_header("Phase 2c: Hybrid Handshake");
	printf("\n");
	struct sck_overhead_benchmark th_ohi, th_ohr;
	struct sck_handshake_benchmark th_hi, th_hr;
	memset(&th_ohi, 0, sizeof(th_ohi)); memset(&th_ohr, 0, sizeof(th_ohr));
	memset(&th_hi, 0, sizeof(th_hi)); memset(&th_hr, 0, sizeof(th_hr));

	if (sck_run_hybrid_handshake(bp + 4000,
		&th_oi, &th_or, &th_ohi, &th_ohr, &th_hi, &th_hr) != 0)
		return -1;

	/* === Phase 3: Write CSV === */
	print_header("Writing Socket Benchmark CSV Files");
	printf("\n");

	/* Build role-suffixed filenames */
	char csv_ops[512], csv_ovh[512], csv_hs[512];
	if (role_suffix && role_suffix[0]) {
		snprintf(csv_ops, sizeof(csv_ops), "%s/benchmark_operations_%s.csv",
			 SOCK_BENCH_OUTPUT_DIR, role_suffix);
		snprintf(csv_ovh, sizeof(csv_ovh), "%s/benchmark_overhead_%s.csv",
			 SOCK_BENCH_OUTPUT_DIR, role_suffix);
		snprintf(csv_hs, sizeof(csv_hs), "%s/benchmark_handshake_%s.csv",
			 SOCK_BENCH_OUTPUT_DIR, role_suffix);
	} else {
		snprintf(csv_ops, sizeof(csv_ops), "%s", SOCK_CSV_OPERATIONS);
		snprintf(csv_ovh, sizeof(csv_ovh), "%s", SOCK_CSV_OVERHEAD);
		snprintf(csv_hs, sizeof(csv_hs), "%s", SOCK_CSV_HANDSHAKE);
	}

	int ret;
	ret = sck_write_operations_csv(csv_ops, role_suffix,
		&t0_oi, &t0_or, &t3_oi, &t3_or,
		&t0p_oi, &t0p_or, &t3p_oi, &t3p_or,
		&th_oi, &th_or);
	if (ret == 0) { snprintf(buf, sizeof(buf), "Written: %s", csv_ops); print_success(buf); }

	ret = sck_write_overhead_csv(csv_ovh, role_suffix,
		&t0_ohi, &t0_ohr, &t3_ohi, &t3_ohr,
		&t0p_ohi, &t0p_ohr, &t3p_ohi, &t3p_ohr,
		&th_ohi, &th_ohr);
	if (ret == 0) { snprintf(buf, sizeof(buf), "Written: %s", csv_ovh); print_success(buf); }

	ret = sck_write_handshake_csv(csv_hs, role_suffix,
		&t0_hi, &t0_hr, &t3_hi, &t3_hr,
		&t0p_hi, &t0p_hr, &t3p_hi, &t3p_hr,
		&th_hi, &th_hr);
	if (ret == 0) { snprintf(buf, sizeof(buf), "Written: %s", csv_hs); print_success(buf); }

	/* === Summary === */
	printf("\n");
	print_header("Socket Benchmark — Handshake Summary (µs, avg)");
	printf("\n");
	printf("  %-16s %-12s %14s %14s %14s %14s %14s\n", "Type", "Role", "Processing", "TxRx", "Precompute", "Overhead", "Total");
	printf("  %-16s %-12s %14s %14s %14s %14s %14s\n", "────────────────", "────────────", "──────────────", "──────────────", "──────────────", "──────────────", "──────────────");

	#define PROW(T,R,D) do { printf("  %-16s %-12s %14.3f %14.3f %14.3f %14.3f %14.3f\n", T, R, \
		(D).processing_us, (D).txrx_us, (D).precomputation_us, (D).overhead_us, (D).total_us); fflush(stdout); } while(0)

	PROW("Type0_SigSig","Initiator",t0_hi); PROW("Type0_SigSig","Responder",t0_hr);
	PROW("Type3_MACMAC","Initiator",t3_hi); PROW("Type3_MACMAC","Responder",t3_hr);
	PROW("Type0_PQ","Initiator",t0p_hi); PROW("Type0_PQ","Responder",t0p_hr);
	PROW("Type3_PQ","Initiator",t3p_hi); PROW("Type3_PQ","Responder",t3p_hr);
	PROW("Type3_Hybrid","Initiator",th_hi); PROW("Type3_Hybrid","Responder",th_hr);

	#undef PROW
	printf("\n");
	print_success("Socket-based benchmark completed!");
	print_info("● CSV files saved in output/ directory.");
	print_info("● Verify with: python3 verify_benchmark.py  (after pointing to output/)");
	printf("\n");
	return 0;
}
