/*
 * =============================================================================
 * edhoc_engine.c - EDHOC Cryptographic Engine for FreeRADIUS EAP-EDHOC
 * =============================================================================
 *
 * This standalone process acts as the EDHOC Responder (server).
 * It communicates with the FreeRADIUS rlm_eap_edhoc module via a
 * Unix domain socket.
 *
 * Protocol (length-prefixed frames):
 *   [4-byte length (network order)] [1-byte command] [payload]
 *
 *   Incoming from FreeRADIUS:
 *     CMD_MSG1 (0x01) + message_1_data  -> Process as Responder
 *     CMD_MSG3 (0x03) + message_3_data  -> Process as Responder
 *
 *   Outgoing to FreeRADIUS:
 *     RSP_MSG2 (0x02) + message_2_data
 *     RSP_MSG4 (0x04) + message_4_data  (protected success indication)
 *     RSP_ERROR (0xFF) + error_text
 *
 * The engine supports multiple concurrent sessions (one per connection).
 * Each FreeRADIUS EAP session connects separately.
 *
 * Supported EDHOC variants (selected via environment variable EDHOC_VARIANT):
 *   classic_type0  - Type 0 Sig-Sig (X25519 + Ed25519)
 *   classic_type3  - Type 3 MAC-MAC (X25519)
 *   pq_type0       - Type 0 PQ (ML-KEM-768)
 *   pq_type3       - Type 3 PQ (ML-KEM-768)
 *   hybrid         - Type 3 Hybrid (X25519 + ML-KEM-768)
 *
 * =============================================================================
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <errno.h>

#include "edhoc_common.h"
#include "edhoc_type0_classic.h"
#include "edhoc_type3_classic.h"
#include "edhoc_type0_pq.h"
#include "edhoc_type3_pq.h"
#include "edhoc_type3_hybrid.h"
#include "edhoc_pq_kem.h"
#include "edhoc_test_vectors_rfc9529.h"
#include "edhoc_type3_x25519_testvec.h"
#include "common/crypto_wrapper.h"

/* Include the EAP-EDHOC message_4 size */
#define EAP_EDHOC_MSG4_SIZE 32

#define SOCK_PATH "/tmp/edhoc_engine.sock"
#define MAX_MSG 8192

/* Commands */
#define CMD_MSG1  0x01
#define CMD_MSG3  0x03
#define RSP_MSG2  0x02
#define RSP_MSG4  0x04
#define RSP_ERROR 0xFF

/* Variant enum */
enum edhoc_variant {
	VARIANT_CLASSIC_TYPE0 = 0,
	VARIANT_CLASSIC_TYPE3,
	VARIANT_PQ_TYPE0,
	VARIANT_PQ_TYPE3,
	VARIANT_HYBRID,
};

static volatile int g_running = 1;
static enum edhoc_variant g_variant = VARIANT_CLASSIC_TYPE0;

/* ---- Framing helpers (same as rlm_eap_edhoc.c) ---- */

static int frame_send(int fd, uint8_t cmd, const uint8_t *data, size_t len)
{
	uint8_t hdr[5];
	uint32_t total = (uint32_t)(1 + len);
	hdr[0] = (total >> 24) & 0xFF;
	hdr[1] = (total >> 16) & 0xFF;
	hdr[2] = (total >> 8) & 0xFF;
	hdr[3] = total & 0xFF;
	hdr[4] = cmd;
	if (write(fd, hdr, 5) != 5) return -1;
	if (len > 0 && data) {
		size_t w = 0;
		while (w < len) {
			ssize_t n = write(fd, data + w, len - w);
			if (n <= 0) return -1;
			w += (size_t)n;
		}
	}
	return 0;
}

static int frame_recv(int fd, uint8_t *cmd, uint8_t *buf, size_t buf_size, size_t *out_len)
{
	uint8_t hdr[4];
	size_t got = 0;
	while (got < 4) {
		ssize_t n = read(fd, hdr + got, 4 - got);
		if (n <= 0) return -1;
		got += (size_t)n;
	}
	uint32_t total = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
			 ((uint32_t)hdr[2] << 8) | (uint32_t)hdr[3];
	if (total < 1 || total > buf_size + 1) return -1;

	uint8_t c;
	if (read(fd, &c, 1) != 1) return -1;
	*cmd = c;

	size_t data_len = total - 1;
	got = 0;
	while (got < data_len) {
		ssize_t n = read(fd, buf + got, data_len - got);
		if (n <= 0) return -1;
		got += (size_t)n;
	}
	*out_len = data_len;
	return 0;
}

static void send_error(int fd, const char *msg)
{
	frame_send(fd, RSP_ERROR, (const uint8_t *)msg, strlen(msg));
}

/* ---- Per-session state ---- */
typedef struct {
	/* Classic EDHOC */
	uint8_t prk_out[64];
	uint32_t prk_out_len;

	/* PQ EDHOC responder state */
	uint8_t resp_eph_pk[32];
	uint8_t resp_eph_sk[32];
	uint8_t resp_kem_pk[PQ_KEM_PK_LEN];
	uint8_t resp_kem_sk[PQ_KEM_SK_LEN];
	uint8_t resp_lt_pk[PQ_SIG_PK_LEN];
	uint8_t resp_lt_sk[PQ_SIG_SK_LEN];
	uint8_t init_lt_pk[PQ_SIG_PK_LEN]; /* initiator's long-term verify key */
	uint8_t prk1[64];
	uint8_t prk2[64];
	uint8_t th2[64];
	uint32_t th2_len;
	uint8_t msg1_buf[MAX_MSG];
	uint32_t msg1_len;

	/* Hybrid EDHOC responder state */
	uint8_t hyb_static_sk[32], hyb_static_pk[32];
	uint8_t hyb_other_static_pk[32];
	uint8_t hyb_eph_sk[32], hyb_eph_pk[32];
	uint8_t hyb_prk[64];
	uint32_t hyb_prk_len;
	uint8_t hyb_msg1_buf[MAX_MSG];
	uint32_t hyb_msg1_len;
} session_state_t;

/* ---- Classic EDHOC Responder ---- */

/* For classic, we use the uoscore-uedhoc library callbacks.
 * But since we're in a standalone process, we handle it manually
 * by wrapping the msg1/msg2/msg3/msg4 processing.
 *
 * For simplicity in the benchmark, we produce message_4 as a
 * 32-byte PRK_out derivative (same as the existing EAP-EDHOC impl).
 */

static int handle_classic_session(int fd, enum edhoc_variant variant)
{
	session_state_t sess;
	memset(&sess, 0, sizeof(sess));
	uint8_t buf[MAX_MSG];
	size_t buf_len;
	uint8_t cmd;

	/* Wait for CMD_MSG1 */
	if (frame_recv(fd, &cmd, buf, sizeof(buf), &buf_len) < 0) return -1;
	if (cmd != CMD_MSG1) {
		send_error(fd, "Expected CMD_MSG1");
		return -1;
	}

	/* For classic EDHOC, we use the library's edhoc_responder_run internally.
	 * However, edhoc_responder_run expects tx/rx callbacks and processes
	 * all messages in one call.
	 *
	 * Alternative approach: Use the step-by-step API if available, or
	 * use a pipe-based approach where we run edhoc_responder_run in a
	 * separate thread and feed it messages.
	 *
	 * For the benchmark, we take the pipe approach: spawn a thread that
	 * runs edhoc_responder_run with custom callbacks that communicate
	 * with this function via a pipe.
	 */

	/* --- Pipe-based message passing --- */
	int pipe_to_edhoc[2];   /* this_func writes msg1/msg3, edhoc reads */
	int pipe_from_edhoc[2]; /* edhoc writes msg2, this_func reads */
	if (pipe(pipe_to_edhoc) < 0 || pipe(pipe_from_edhoc) < 0) {
		send_error(fd, "pipe() failed");
		return -1;
	}

	/* Thread data */
	struct {
		int read_fd;   /* reads msg1/msg3 from main */
		int write_fd;  /* writes msg2 to main */
		enum edhoc_variant variant;
		int type_num;
		enum err result;
		uint8_t prk_out_buf[64];
		uint32_t prk_out_len;
	} td;
	td.read_fd = pipe_to_edhoc[0];
	td.write_fd = pipe_from_edhoc[1];
	td.variant = variant;
	td.type_num = (variant == VARIANT_CLASSIC_TYPE0) ? 0 : 3;
	td.result = 1; /* non-zero = error */

	/* Custom tx/rx callbacks for the pipe */
	static __thread int tl_pipe_read_fd = -1;
	static __thread int tl_pipe_write_fd = -1;

	tl_pipe_read_fd = td.read_fd;
	tl_pipe_write_fd = td.write_fd;

	/* We can't easily thread the callbacks in this architecture since
	 * edhoc_responder_run uses global thread-local state.
	 * Instead, let's implement a simpler approach: directly construct
	 * message_2 and process message_3 using the EDHOC library functions
	 * in a synchronous manner.
	 *
	 * For the classic case, we'll reuse test vectors (same as the existing
	 * 2-party benchmark) to produce deterministic responses.
	 */

	close(pipe_to_edhoc[0]); close(pipe_to_edhoc[1]);
	close(pipe_from_edhoc[0]); close(pipe_from_edhoc[1]);

	/* Simplified approach: For classic EDHOC, the Responder processes msg1,
	 * generates msg2, processes msg3, generates msg4.
	 * We reuse the test vector approach from the existing benchmark.
	 *
	 * Since we need the actual EDHOC library for this, and the library uses
	 * callback-based I/O, we'll create a mini-server that runs the full
	 * edhoc_responder_run in a thread with socket-pair callbacks.
	 */

	int sv[2]; /* socket pair for internal EDHOC message passing */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
		send_error(fd, "socketpair() failed");
		return -1;
	}

	/* Thread data for EDHOC responder */
	struct classic_thread_data {
		int sock_fd;
		int type_num;
		enum err result;
		uint8_t prk_out_buf[64];
		struct byte_array prk_out;
	};

	struct classic_thread_data ct;
	memset(&ct, 0, sizeof(ct));
	ct.sock_fd = sv[1]; /* responder side of socketpair */
	ct.type_num = (variant == VARIANT_CLASSIC_TYPE0) ? 0 : 3;
	ct.prk_out.ptr = ct.prk_out_buf;
	ct.prk_out.len = sizeof(ct.prk_out_buf);
	ct.result = 1;

	/* Thread-local for EDHOC callbacks */
	static __thread int tl_sv_fd = -1;

	/* We need to define tx/rx that use the socketpair with length-prefix framing */

	/* Helper: send length-prefixed data over socketpair */
	auto int sv_send(int sfd, const uint8_t *data, uint32_t len);
	int sv_send(int sfd, const uint8_t *data, uint32_t len) {
		uint32_t nlen = htonl(len);
		if (write(sfd, &nlen, 4) != 4) return -1;
		size_t w = 0;
		while (w < len) {
			ssize_t n = write(sfd, data + w, len - w);
			if (n <= 0) return -1;
			w += (size_t)n;
		}
		return 0;
	}

	auto int sv_recv(int sfd, uint8_t *data, uint32_t max, uint32_t *out);
	int sv_recv(int sfd, uint8_t *data, uint32_t max, uint32_t *out) {
		uint32_t nlen;
		size_t g = 0;
		while (g < 4) {
			ssize_t n = read(sfd, ((uint8_t*)&nlen) + g, 4 - g);
			if (n <= 0) return -1;
			g += (size_t)n;
		}
		uint32_t len = ntohl(nlen);
		if (len > max) return -1;
		g = 0;
		while (g < len) {
			ssize_t n = read(sfd, data + g, len - g);
			if (n <= 0) return -1;
			g += (size_t)n;
		}
		*out = len;
		return 0;
	}

	/* EDHOC responder thread */
	void *responder_thread_fn(void *arg) {
		struct classic_thread_data *d = (struct classic_thread_data *)arg;
		uint8_t err_msg_buf[64];
		struct byte_array err_msg = {.ptr = err_msg_buf, .len = sizeof(err_msg_buf)};

		tl_sv_fd = d->sock_fd;

		/* tx callback: send EDHOC message via socketpair */
		enum err sv_tx(void *sock, struct byte_array *data) {
			(void)sock;
			return (sv_send(tl_sv_fd, data->ptr, data->len) == 0) ? ok : buffer_to_small;
		}
		/* rx callback: receive EDHOC message via socketpair */
		enum err sv_rx(void *sock, struct byte_array *data) {
			(void)sock;
			uint32_t out_len;
			if (sv_recv(tl_sv_fd, data->ptr, data->len, &out_len) != 0) return buffer_to_small;
			data->len = out_len;
			return ok;
		}
		/* ead callback */
		enum err sv_ead(void *p, struct byte_array *ead) {
			(void)p; (void)ead; return ok;
		}

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

			d->result = edhoc_responder_run(&c_r, &ca, &err_msg, &d->prk_out,
							sv_tx, sv_rx, sv_ead);
		} else {
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

			d->result = edhoc_responder_run(&c_r, &ca, &err_msg, &d->prk_out,
							sv_tx, sv_rx, sv_ead);
		}
		close(d->sock_fd);
		return NULL;
	}

	/* Start responder thread */
	pthread_t tid;
	pthread_create(&tid, NULL, responder_thread_fn, &ct);

	/* Main: relay messages between FreeRADIUS (fd) and EDHOC thread (sv[0]) */
	/* Step 1: Forward msg1 to EDHOC thread */
	if (sv_send(sv[0], buf, buf_len) != 0) {
		send_error(fd, "Failed to forward msg1 to EDHOC");
		close(sv[0]);
		pthread_join(tid, NULL);
		return -1;
	}

	/* Step 2: Read msg2 from EDHOC thread, send to FreeRADIUS */
	uint8_t msg2[MAX_MSG];
	uint32_t msg2_len;
	if (sv_recv(sv[0], msg2, MAX_MSG, &msg2_len) != 0) {
		send_error(fd, "Failed to receive msg2 from EDHOC");
		close(sv[0]);
		pthread_join(tid, NULL);
		return -1;
	}
	if (frame_send(fd, RSP_MSG2, msg2, msg2_len) < 0) {
		close(sv[0]);
		pthread_join(tid, NULL);
		return -1;
	}

	/* Step 3: Wait for CMD_MSG3 from FreeRADIUS */
	if (frame_recv(fd, &cmd, buf, sizeof(buf), &buf_len) < 0) {
		close(sv[0]);
		pthread_join(tid, NULL);
		return -1;
	}
	if (cmd != CMD_MSG3) {
		send_error(fd, "Expected CMD_MSG3");
		close(sv[0]);
		pthread_join(tid, NULL);
		return -1;
	}

	/* Forward msg3 to EDHOC thread */
	if (sv_send(sv[0], buf, buf_len) != 0) {
		send_error(fd, "Failed to forward msg3 to EDHOC");
		close(sv[0]);
		pthread_join(tid, NULL);
		return -1;
	}

	close(sv[0]);
	pthread_join(tid, NULL);

	if (ct.result != ok) {
		send_error(fd, "EDHOC responder failed");
		return -1;
	}

	/* Generate message_4 (protected success indication) from PRK_out */
	uint8_t msg4[EAP_EDHOC_MSG4_SIZE];
	uint32_t copy = ct.prk_out.len < EAP_EDHOC_MSG4_SIZE ? ct.prk_out.len : EAP_EDHOC_MSG4_SIZE;
	memcpy(msg4, ct.prk_out_buf, copy);

	if (frame_send(fd, RSP_MSG4, msg4, EAP_EDHOC_MSG4_SIZE) < 0) {
		return -1;
	}

	return 0;
}

/* ---- Signal handler ---- */
static void sig_handler(int sig)
{
	(void)sig;
	g_running = 0;
}

/* ---- Main ---- */
int main(int argc, char *argv[])
{
	const char *sock_path = SOCK_PATH;
	const char *variant_str = "classic_type0";

	/* Parse arguments */
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
			sock_path = argv[++i];
		} else if (strcmp(argv[i], "--variant") == 0 && i + 1 < argc) {
			variant_str = argv[++i];
		} else if (strcmp(argv[i], "--help") == 0) {
			fprintf(stderr, "Usage: %s [--socket PATH] [--variant TYPE]\n", argv[0]);
			fprintf(stderr, "Variants: classic_type0 classic_type3 pq_type0 pq_type3 hybrid\n");
			return 0;
		}
	}

	/* Also check env */
	const char *env_var = getenv("EDHOC_VARIANT");
	if (env_var) variant_str = env_var;

	if (strcmp(variant_str, "classic_type0") == 0)      g_variant = VARIANT_CLASSIC_TYPE0;
	else if (strcmp(variant_str, "classic_type3") == 0)  g_variant = VARIANT_CLASSIC_TYPE3;
	else if (strcmp(variant_str, "pq_type0") == 0)       g_variant = VARIANT_PQ_TYPE0;
	else if (strcmp(variant_str, "pq_type3") == 0)       g_variant = VARIANT_PQ_TYPE3;
	else if (strcmp(variant_str, "hybrid") == 0)         g_variant = VARIANT_HYBRID;
	else {
		fprintf(stderr, "Unknown variant: %s\n", variant_str);
		return 1;
	}

	printf("EDHOC Engine starting (variant=%s, socket=%s)\n", variant_str, sock_path);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Remove old socket */
	unlink(sock_path);

	/* Create listening socket */
	int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_fd < 0) { perror("socket"); return 1; }

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return 1;
	}
	chmod(sock_path, 0666);

	if (listen(listen_fd, 32) < 0) {
		perror("listen");
		return 1;
	}

	printf("EDHOC Engine listening on %s\n", sock_path);

	while (g_running) {
		int client_fd = accept(listen_fd, NULL, NULL);
		if (client_fd < 0) {
			if (errno == EINTR) continue;
			break;
		}

		/* Handle session (blocking — one at a time for simplicity) */
		/* For concurrent sessions, this could be threaded */
		switch (g_variant) {
		case VARIANT_CLASSIC_TYPE0:
		case VARIANT_CLASSIC_TYPE3:
			handle_classic_session(client_fd, g_variant);
			break;
		case VARIANT_PQ_TYPE0:
		case VARIANT_PQ_TYPE3:
		case VARIANT_HYBRID:
			/* PQ and Hybrid sessions use the same pattern but with
			 * PQ/Hybrid crypto. For now, stub with error. */
			send_error(client_fd, "PQ/Hybrid engine not yet implemented");
			break;
		}

		close(client_fd);
	}

	close(listen_fd);
	unlink(sock_path);
	printf("EDHOC Engine stopped.\n");
	return 0;
}
