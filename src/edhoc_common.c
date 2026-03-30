/*
 * EDHOC-Hybrid: Common utilities implementation
 * Provides message exchange (pthread-based), print helpers, and OSCORE key derivation.
 *
 * Modul ini menyediakan lapisan transport simulasi untuk protokol EDHOC.
 * Pada implementasi nyata (real-world), message_1, message_2, message_3
 * dikirim melalui CoAP/UDP. Di sini, kita menggunakan shared memory
 * dengan pthread mutex/condvar agar Initiator dan Responder (berjalan
 * di thread terpisah) dapat bertukar pesan secara sinkron.
 *
 * Alur transport untuk 3-message handshake EDHOC:
 *
 *   Initiator Thread            Shared Buffer            Responder Thread
 *   ─────────────────          ─────────────            ─────────────────
 *   tx_initiator(msg_1) ──→   [buf] ──→               rx_responder(msg_1)
 *                              [buf] ←──               tx_responder(msg_2)
 *   rx_initiator(msg_2) ←──   [buf]
 *   tx_initiator(msg_3) ──→   [buf] ──→               rx_responder(msg_3)
 *
 * Sinkronisasi:
 *   - initiator_msg_ready: flag bahwa Initiator telah menulis pesan
 *   - responder_msg_ready: flag bahwa Responder telah menulis pesan
 *   - cond_initiator_sent: condition variable untuk wake-up Responder
 *   - cond_responder_sent: condition variable untuk wake-up Initiator
 */

#include "edhoc_common.h"

/* Global message exchange state */
struct msg_exchange g_msg_exchange;

/* ===== Message exchange init/destroy ===== */
void msg_exchange_init(void)
{
	memset(&g_msg_exchange, 0, sizeof(g_msg_exchange));
	pthread_mutex_init(&g_msg_exchange.mutex, NULL);
	pthread_cond_init(&g_msg_exchange.cond_initiator_sent, NULL);
	pthread_cond_init(&g_msg_exchange.cond_responder_sent, NULL);
	g_msg_exchange.initiator_msg_ready = false;
	g_msg_exchange.responder_msg_ready = false;
}

void msg_exchange_destroy(void)
{
	pthread_mutex_destroy(&g_msg_exchange.mutex);
	pthread_cond_destroy(&g_msg_exchange.cond_initiator_sent);
	pthread_cond_destroy(&g_msg_exchange.cond_responder_sent);
}

/* ===== Transport callback functions ===== */

/*
 * tx_initiator: Called when the Initiator sends a message.
 * Copies data into the shared buffer and signals the Responder.
 */
enum err tx_initiator(void *sock, struct byte_array *data)
{
	(void)sock;
	pthread_mutex_lock(&g_msg_exchange.mutex);

	if (data->len > MSG_BUF_SIZE) {
		pthread_mutex_unlock(&g_msg_exchange.mutex);
		return buffer_to_small;
	}

	memcpy(g_msg_exchange.buf, data->ptr, data->len);
	g_msg_exchange.len = data->len;
	g_msg_exchange.initiator_msg_ready = true;

	pthread_cond_signal(&g_msg_exchange.cond_initiator_sent);
	pthread_mutex_unlock(&g_msg_exchange.mutex);
	return ok;
}

/*
 * rx_initiator: Called when the Initiator receives a message (from Responder).
 * Waits until the Responder has sent a message, then copies it out.
 */
enum err rx_initiator(void *sock, struct byte_array *data)
{
	(void)sock;
	pthread_mutex_lock(&g_msg_exchange.mutex);

	while (!g_msg_exchange.responder_msg_ready) {
		pthread_cond_wait(&g_msg_exchange.cond_responder_sent,
				  &g_msg_exchange.mutex);
	}

	if (g_msg_exchange.len > data->len) {
		pthread_mutex_unlock(&g_msg_exchange.mutex);
		return buffer_to_small;
	}

	memcpy(data->ptr, g_msg_exchange.buf, g_msg_exchange.len);
	data->len = g_msg_exchange.len;
	g_msg_exchange.responder_msg_ready = false;

	pthread_mutex_unlock(&g_msg_exchange.mutex);
	return ok;
}

/*
 * tx_responder: Called when the Responder sends a message.
 * Copies data into the shared buffer and signals the Initiator.
 */
enum err tx_responder(void *sock, struct byte_array *data)
{
	(void)sock;
	pthread_mutex_lock(&g_msg_exchange.mutex);

	if (data->len > MSG_BUF_SIZE) {
		pthread_mutex_unlock(&g_msg_exchange.mutex);
		return buffer_to_small;
	}

	memcpy(g_msg_exchange.buf, data->ptr, data->len);
	g_msg_exchange.len = data->len;
	g_msg_exchange.responder_msg_ready = true;

	pthread_cond_signal(&g_msg_exchange.cond_responder_sent);
	pthread_mutex_unlock(&g_msg_exchange.mutex);
	return ok;
}

/*
 * rx_responder: Called when the Responder receives a message (from Initiator).
 * Waits until the Initiator has sent a message, then copies it out.
 */
enum err rx_responder(void *sock, struct byte_array *data)
{
	(void)sock;
	pthread_mutex_lock(&g_msg_exchange.mutex);

	while (!g_msg_exchange.initiator_msg_ready) {
		pthread_cond_wait(&g_msg_exchange.cond_initiator_sent,
				  &g_msg_exchange.mutex);
	}

	if (g_msg_exchange.len > data->len) {
		pthread_mutex_unlock(&g_msg_exchange.mutex);
		return buffer_to_small;
	}

	memcpy(data->ptr, g_msg_exchange.buf, g_msg_exchange.len);
	data->len = g_msg_exchange.len;
	g_msg_exchange.initiator_msg_ready = false;

	pthread_mutex_unlock(&g_msg_exchange.mutex);
	return ok;
}

/*
 * ead_process: EAD processing callback (no-op for these test implementations).
 */
enum err ead_process(void *params, struct byte_array *ead)
{
	(void)params;
	(void)ead;
	return ok;
}

/* ===== Utility Functions ===== */

void print_hex(const char *label, const uint8_t *data, uint32_t len)
{
	printf("  %s%s%s (%u bytes): ", CLR_CYAN, label, CLR_RESET, len);
	for (uint32_t i = 0; i < len; i++) {
		printf("%02x", data[i]);
		if (i < len - 1 && (i + 1) % 32 == 0)
			printf("\n    ");
	}
	printf("\n");
}

void print_separator(void)
{
	printf("%s════════════════════════════════════════════════"
	       "════════════════%s\n", CLR_BLUE, CLR_RESET);
}

void print_header(const char *title)
{
	printf("\n");
	print_separator();
	printf("%s%s  %s%s\n", CLR_BOLD, CLR_MAGENTA, title, CLR_RESET);
	print_separator();
}

void print_success(const char *msg)
{
	printf("  %s✓ %s%s\n", CLR_GREEN, msg, CLR_RESET);
}

void print_error(const char *msg)
{
	printf("  %s✗ %s%s\n", CLR_RED, msg, CLR_RESET);
}

void print_info(const char *msg)
{
	printf("  %s● %s%s\n", CLR_YELLOW, msg, CLR_RESET);
}

/* ===== OSCORE Key Derivation =====
 *
 * Setelah handshake EDHOC selesai (message_1 → message_3), kedua pihak
 * memiliki PRK_out yang sama. Dari PRK_out, kita menurunkan kunci OSCORE:
 *
 *   PRK_out → PRK_exporter → OSCORE Master Secret + OSCORE Master Salt
 *
 * Kunci-kunci ini digunakan untuk melindungi komunikasi CoAP selanjutnya
 * menggunakan OSCORE (Object Security for Constrained RESTful Environments).
 *
 * Langkah:
 *   1. prk_out2exporter: PRK_out → PRK_exporter (HKDF-Expand)
 *   2. edhoc_exporter(OSCORE_MASTER_SECRET): PRK_exporter → Master Secret (16 bytes)
 *   3. edhoc_exporter(OSCORE_MASTER_SALT):   PRK_exporter → Master Salt  (8 bytes)
 */

int derive_oscore_keys(const char *role, struct byte_array *prk_out)
{
	enum err r;

	uint8_t prk_exporter_buf[32];
	struct byte_array prk_exporter = {
		.ptr = prk_exporter_buf,
		.len = sizeof(prk_exporter_buf)
	};

	uint8_t master_secret_buf[16];
	struct byte_array master_secret = {
		.ptr = master_secret_buf,
		.len = sizeof(master_secret_buf)
	};

	uint8_t master_salt_buf[8];
	struct byte_array master_salt = {
		.ptr = master_salt_buf,
		.len = sizeof(master_salt_buf)
	};

	/* Step 1: PRK_out -> PRK_exporter */
	r = prk_out2exporter(SHA_256, prk_out, &prk_exporter);
	if (r != ok) {
		print_error("prk_out2exporter failed");
		return (int)r;
	}
	print_hex("PRK_exporter", prk_exporter.ptr, prk_exporter.len);

	/* Step 2: Derive OSCORE Master Secret */
	r = edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &prk_exporter,
			   &master_secret);
	if (r != ok) {
		print_error("edhoc_exporter (Master Secret) failed");
		return (int)r;
	}
	print_hex("OSCORE Master Secret", master_secret.ptr, master_secret.len);

	/* Step 3: Derive OSCORE Master Salt */
	r = edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &prk_exporter,
			   &master_salt);
	if (r != ok) {
		print_error("edhoc_exporter (Master Salt) failed");
		return (int)r;
	}
	print_hex("OSCORE Master Salt", master_salt.ptr, master_salt.len);

	return 0;
}
