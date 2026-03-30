/*
 * EDHOC-Hybrid: Common utilities for EDHOC protocol implementation
 * Based on RFC 9528
 *
 * Header ini mendefinisikan:
 *   - Struktur shared memory untuk pertukaran pesan antar thread
 *     (simulasi transport layer untuk message_1, message_2, message_3)
 *   - Callback functions: tx_initiator, rx_initiator, tx_responder, rx_responder
 *     (digunakan oleh library uoscore-uedhoc untuk mengirim/menerima pesan)
 *   - Utility functions: print helpers, hex dump, OSCORE key derivation
 *
 * Digunakan oleh kedua tipe:
 *   - Type 0 (Sig-Sig): Signature + Verify, X25519 + EdDSA
 *   - Type 3 (MAC-MAC): Static DH + MAC, P-256 ECDH
 */

#ifndef EDHOC_COMMON_H
#define EDHOC_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "edhoc.h"

/* Maximum sizes for message exchange buffers */
#define MSG_BUF_SIZE 1024

/* ===== Color Codes for Terminal Output ===== */
#define CLR_RESET   "\033[0m"
#define CLR_RED     "\033[31m"
#define CLR_GREEN   "\033[32m"
#define CLR_YELLOW  "\033[33m"
#define CLR_BLUE    "\033[34m"
#define CLR_MAGENTA "\033[35m"
#define CLR_CYAN    "\033[36m"
#define CLR_BOLD    "\033[1m"

/* ===== Shared message exchange state ===== */
struct msg_exchange {
	uint8_t buf[MSG_BUF_SIZE];
	uint32_t len;
	pthread_mutex_t mutex;
	pthread_cond_t cond_initiator_sent;
	pthread_cond_t cond_responder_sent;
	bool initiator_msg_ready;
	bool responder_msg_ready;
};

/* Global message exchange state */
extern struct msg_exchange g_msg_exchange;

/* ===== Callback functions for message transport ===== */
enum err tx_initiator(void *sock, struct byte_array *data);
enum err rx_initiator(void *sock, struct byte_array *data);
enum err tx_responder(void *sock, struct byte_array *data);
enum err rx_responder(void *sock, struct byte_array *data);
enum err ead_process(void *params, struct byte_array *ead);

/* ===== Utility Functions ===== */
void print_hex(const char *label, const uint8_t *data, uint32_t len);
void print_separator(void);
void print_header(const char *title);
void print_success(const char *msg);
void print_error(const char *msg);
void print_info(const char *msg);
void msg_exchange_init(void);
void msg_exchange_destroy(void);

/* ===== PRK_out / OSCORE key derivation ===== */
int derive_oscore_keys(const char *role, struct byte_array *prk_out);

#endif /* EDHOC_COMMON_H */
