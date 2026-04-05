/*
 * =============================================================================
 * radius_client.h - Lightweight RADIUS client for EAP-EDHOC 3-party benchmark
 * =============================================================================
 *
 * Implements the minimal RADIUS protocol needed for EAP pass-through:
 *   - Access-Request  (Authenticator -> AAA Server)
 *   - Access-Challenge (AAA Server -> Authenticator)
 *   - Access-Accept   (AAA Server -> Authenticator)
 *   - Access-Reject   (AAA Server -> Authenticator)
 *
 * This is NOT a full RADIUS implementation. It handles only EAP-Message
 * and State attributes needed for EAP pass-through authentication.
 *
 * Reference: RFC 2865, RFC 3579 (RADIUS + EAP)
 * =============================================================================
 */

#ifndef RADIUS_CLIENT_H
#define RADIUS_CLIENT_H

#include <stdint.h>
#include <stddef.h>

/* RADIUS packet codes */
#define RADIUS_CODE_ACCESS_REQUEST   1
#define RADIUS_CODE_ACCESS_ACCEPT    2
#define RADIUS_CODE_ACCESS_REJECT    3
#define RADIUS_CODE_ACCESS_CHALLENGE 11

/* RADIUS attribute types */
#define RADIUS_ATTR_USER_NAME        1
#define RADIUS_ATTR_NAS_IP_ADDRESS   4
#define RADIUS_ATTR_NAS_PORT         5
#define RADIUS_ATTR_STATE            24
#define RADIUS_ATTR_MESSAGE_AUTH     80
#define RADIUS_ATTR_EAP_MESSAGE      79
#define RADIUS_ATTR_NAS_PORT_TYPE    61

/* RADIUS header size: Code(1) + Identifier(1) + Length(2) + Authenticator(16) */
#define RADIUS_HDR_SIZE   20
#define RADIUS_AUTH_SIZE  16
#define RADIUS_MAX_PACKET 8192

/* Maximum EAP message in a single RADIUS packet */
#define RADIUS_MAX_EAP_CHUNK 253

/* RADIUS shared secret (for benchmark) */
#define RADIUS_SHARED_SECRET "edhoc_bench_secret"
#define RADIUS_SECRET_LEN    18

/**
 * @brief A RADIUS packet with parsed attributes.
 */
struct radius_packet {
	uint8_t  code;
	uint8_t  identifier;
	uint16_t length;
	uint8_t  authenticator[RADIUS_AUTH_SIZE];

	/* EAP-Message (may span multiple attributes, reassembled) */
	uint8_t  eap_message[RADIUS_MAX_PACKET];
	uint32_t eap_message_len;

	/* State attribute (for session tracking) */
	uint8_t  state[256];
	uint32_t state_len;

	/* Raw packet for Message-Authenticator calculation */
	uint8_t  raw[RADIUS_MAX_PACKET];
	uint32_t raw_len;
};

/**
 * @brief RADIUS client context (Authenticator side).
 */
struct radius_ctx {
	int      sock_fd;        /* UDP socket to AAA server */
	uint8_t  identifier;     /* Next RADIUS packet identifier */
	uint8_t  state[256];     /* Current State attribute from server */
	uint32_t state_len;
};

/**
 * @brief Initialize RADIUS client context.
 * @param ctx    Context to initialize
 * @param server_ip   AAA server IP address (e.g., "127.0.0.1")
 * @param server_port AAA server auth port (e.g., 18120)
 * @return 0 on success, -1 on error
 */
int radius_init(struct radius_ctx *ctx, const char *server_ip, uint16_t server_port);

/**
 * @brief Close RADIUS client context.
 */
void radius_close(struct radius_ctx *ctx);

/**
 * @brief Send Access-Request with EAP-Message.
 *
 * Wraps the EAP message in a RADIUS Access-Request with:
 *   - User-Name (from EAP identity or anonymous)
 *   - NAS-IP-Address (127.0.0.1)
 *   - EAP-Message attribute(s)
 *   - State attribute (if available from previous exchange)
 *   - Message-Authenticator
 *
 * @param ctx       RADIUS context
 * @param eap_data  Raw EAP packet data
 * @param eap_len   Length of EAP data
 * @param username  User-Name string
 * @return 0 on success, -1 on error
 */
int radius_send_access_request(struct radius_ctx *ctx,
			       const uint8_t *eap_data, uint32_t eap_len,
			       const char *username);

/**
 * @brief Receive RADIUS response (Access-Challenge, Access-Accept, or Access-Reject).
 *
 * @param ctx   RADIUS context
 * @param pkt   Parsed RADIUS packet (output)
 * @return RADIUS code (2=Accept, 3=Reject, 11=Challenge), or -1 on error
 */
int radius_recv_response(struct radius_ctx *ctx, struct radius_packet *pkt);

/**
 * @brief Calculate overhead bytes for a full EAP-EDHOC exchange via RADIUS.
 *
 * Includes RADIUS headers, attributes, and Message-Authenticator for
 * each round-trip in the EAP-EDHOC exchange.
 *
 * @param num_roundtrips  Number of RADIUS round-trips
 * @param eap_sizes       Array of EAP message sizes per round-trip
 * @return Total RADIUS overhead in bytes
 */
uint32_t radius_edhoc_overhead_bytes(int num_roundtrips, const uint32_t *eap_sizes);

/* =========================================================================
 * Built-in RADIUS AAA Server (for 3-party benchmark without FreeRADIUS)
 * =========================================================================
 */

/**
 * @brief RADIUS server context (AAA server side).
 */
struct radius_server_ctx {
	int      sock_fd;        /* UDP socket */
	uint8_t  state_counter;  /* Session state counter */
	struct sockaddr_in client_addr;  /* Last client address */
	socklen_t client_addr_len;
	/* Last received request authenticator (for response auth) */
	uint8_t  last_request_auth[RADIUS_AUTH_SIZE];
	uint8_t  last_identifier;
};

/**
 * @brief Initialize RADIUS server (bind to port).
 */
int radius_server_init(struct radius_server_ctx *srv, uint16_t port);

/**
 * @brief Close RADIUS server.
 */
void radius_server_close(struct radius_server_ctx *srv);

/**
 * @brief Receive Access-Request and extract EAP-Message.
 * @return 0 on success, -1 on error
 */
int radius_server_recv_request(struct radius_server_ctx *srv,
			       struct radius_packet *pkt);

/**
 * @brief Send Access-Challenge with EAP-Message.
 * @return 0 on success, -1 on error
 */
int radius_server_send_challenge(struct radius_server_ctx *srv,
				 const uint8_t *eap_data, uint32_t eap_len);

/**
 * @brief Send Access-Accept with EAP-Message (EAP-Success).
 * @return 0 on success, -1 on error
 */
int radius_server_send_accept(struct radius_server_ctx *srv,
			      const uint8_t *eap_data, uint32_t eap_len);

#endif /* RADIUS_CLIENT_H */
