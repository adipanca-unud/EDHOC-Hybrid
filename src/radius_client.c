/*
 * =============================================================================
 * radius_client.c - Lightweight RADIUS client for EAP-EDHOC 3-party benchmark
 * =============================================================================
 *
 * Minimal RADIUS protocol implementation for EAP pass-through.
 * Only supports the attributes needed for EAP-EDHOC benchmarking.
 *
 * Uses mbedtls (already available in the project) for MD5 and HMAC-MD5
 * instead of OpenSSL to avoid adding an external dependency.
 *
 * Reference:
 *   RFC 2865 - Remote Authentication Dial In User Service (RADIUS)
 *   RFC 3579 - RADIUS (Remote Authentication Dial In User Service) Support
 *              For Extensible Authentication Protocol (EAP)
 * =============================================================================
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "radius_client.h"
#include "mbedtls/md5.h"
#include "mbedtls/md.h"

/* --------------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------------- */

/**
 * @brief Generate random Request Authenticator (16 bytes).
 */
static void radius_random_authenticator(uint8_t auth[RADIUS_AUTH_SIZE])
{
	FILE *f = fopen("/dev/urandom", "rb");
	if (f) {
		if (fread(auth, 1, RADIUS_AUTH_SIZE, f) != RADIUS_AUTH_SIZE) {
			/* Fallback: zero + counter */
			memset(auth, 0, RADIUS_AUTH_SIZE);
		}
		fclose(f);
	}
}

/**
 * @brief Calculate Message-Authenticator HMAC-MD5.
 *
 * RFC 3579 section 3.2:
 *   Message-Authenticator = HMAC-MD5(shared_secret, RADIUS packet)
 *   where the Message-Authenticator field in the packet is set to 0 during
 *   calculation.
 */
static void radius_calc_message_authenticator(const uint8_t *packet, uint32_t pkt_len,
					      const char *secret, uint32_t secret_len,
					      uint8_t hmac_out[16])
{
	mbedtls_md_context_t ctx;
	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);

	mbedtls_md_init(&ctx);
	mbedtls_md_setup(&ctx, md_info, 1); /* 1 = HMAC mode */
	mbedtls_md_hmac_starts(&ctx, (const unsigned char *)secret, secret_len);
	mbedtls_md_hmac_update(&ctx, packet, pkt_len);
	mbedtls_md_hmac_finish(&ctx, hmac_out);
	mbedtls_md_free(&ctx);
}

/**
 * @brief Verify Response Authenticator.
 *
 * RFC 2865 section 3:
 *   ResponseAuth = MD5(Code + ID + Length + RequestAuth + Attributes + Secret)
 */
static int radius_verify_response_auth(const uint8_t *response, uint32_t resp_len,
					const uint8_t request_auth[RADIUS_AUTH_SIZE],
					const char *secret, uint32_t secret_len)
{
	uint8_t buf[RADIUS_MAX_PACKET + 256];
	uint8_t expected[16];

	if (resp_len > RADIUS_MAX_PACKET)
		return -1;

	/* Build: Code + ID + Length + RequestAuth + Attributes */
	memcpy(buf, response, 4);              /* Code, ID, Length */
	memcpy(buf + 4, request_auth, 16);     /* Request Authenticator */
	if (resp_len > 20)
		memcpy(buf + 20, response + 20, resp_len - 20); /* Attributes */

	/* Append secret and hash */
	mbedtls_md5_context md5;
	mbedtls_md5_init(&md5);
	mbedtls_md5_starts(&md5);
	mbedtls_md5_update(&md5, buf, resp_len);
	mbedtls_md5_update(&md5, (const unsigned char *)secret, secret_len);
	mbedtls_md5_finish(&md5, expected);
	mbedtls_md5_free(&md5);

	return memcmp(expected, response + 4, 16) == 0 ? 0 : -1;
}

/**
 * @brief Append a RADIUS attribute to a buffer.
 * @return Number of bytes appended.
 */
static uint32_t radius_append_attr(uint8_t *buf, uint8_t type,
				   const uint8_t *value, uint8_t value_len)
{
	buf[0] = type;
	buf[1] = (uint8_t)(2 + value_len);
	memcpy(buf + 2, value, value_len);
	return 2 + value_len;
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

int radius_init(struct radius_ctx *ctx, const char *server_ip, uint16_t server_port)
{
	struct sockaddr_in addr;

	memset(ctx, 0, sizeof(*ctx));
	ctx->identifier = 0;
	ctx->state_len = 0;

	ctx->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ctx->sock_fd < 0) {
		perror("radius_init: socket");
		return -1;
	}

	/* Set receive timeout (5 seconds for benchmark) */
	struct timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	setsockopt(ctx->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(server_port);
	if (inet_pton(AF_INET, server_ip, &addr.sin_addr) != 1) {
		fprintf(stderr, "radius_init: invalid server IP '%s'\n", server_ip);
		close(ctx->sock_fd);
		return -1;
	}

	if (connect(ctx->sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("radius_init: connect");
		close(ctx->sock_fd);
		return -1;
	}

	return 0;
}

void radius_close(struct radius_ctx *ctx)
{
	if (ctx && ctx->sock_fd >= 0) {
		close(ctx->sock_fd);
		ctx->sock_fd = -1;
	}
}

int radius_send_access_request(struct radius_ctx *ctx,
			       const uint8_t *eap_data, uint32_t eap_len,
			       const char *username)
{
	uint8_t pkt[RADIUS_MAX_PACKET];
	uint32_t offset = RADIUS_HDR_SIZE;
	uint8_t request_auth[RADIUS_AUTH_SIZE];

	/* Header */
	pkt[0] = RADIUS_CODE_ACCESS_REQUEST;
	pkt[1] = ctx->identifier++;
	/* Length filled in later */

	/* Random Request Authenticator */
	radius_random_authenticator(request_auth);
	memcpy(pkt + 4, request_auth, RADIUS_AUTH_SIZE);

	/* User-Name attribute */
	if (username && strlen(username) > 0) {
		uint8_t name_len = (uint8_t)strlen(username);
		if (name_len > 253) name_len = 253;
		offset += radius_append_attr(pkt + offset, RADIUS_ATTR_USER_NAME,
					     (const uint8_t *)username, name_len);
	}

	/* NAS-IP-Address (127.0.0.1) */
	{
		uint32_t nas_ip = htonl(0x7f000001);
		offset += radius_append_attr(pkt + offset, RADIUS_ATTR_NAS_IP_ADDRESS,
					     (const uint8_t *)&nas_ip, 4);
	}

	/* NAS-Port (1) */
	{
		uint32_t nas_port = htonl(1);
		offset += radius_append_attr(pkt + offset, RADIUS_ATTR_NAS_PORT,
					     (const uint8_t *)&nas_port, 4);
	}

	/* NAS-Port-Type (Virtual = 5) */
	{
		uint32_t port_type = htonl(5);
		offset += radius_append_attr(pkt + offset, RADIUS_ATTR_NAS_PORT_TYPE,
					     (const uint8_t *)&port_type, 4);
	}

	/* EAP-Message attribute(s) — split into 253-byte chunks */
	{
		uint32_t remaining = eap_len;
		const uint8_t *p = eap_data;
		while (remaining > 0) {
			uint8_t chunk = (remaining > 253) ? 253 : (uint8_t)remaining;
			offset += radius_append_attr(pkt + offset, RADIUS_ATTR_EAP_MESSAGE,
						     p, chunk);
			p += chunk;
			remaining -= chunk;
		}
	}

	/* State attribute (if present from previous response) */
	if (ctx->state_len > 0) {
		offset += radius_append_attr(pkt + offset, RADIUS_ATTR_STATE,
					     ctx->state, (uint8_t)ctx->state_len);
	}

	/* Message-Authenticator (18 bytes: type + length + 16 HMAC) */
	{
		uint32_t ma_offset = offset;
		pkt[offset]     = RADIUS_ATTR_MESSAGE_AUTH;
		pkt[offset + 1] = 18;
		memset(pkt + offset + 2, 0, 16); /* Zero for calculation */
		offset += 18;

		/* Set packet length in header */
		pkt[2] = (uint8_t)(offset >> 8);
		pkt[3] = (uint8_t)(offset & 0xFF);

		/* Calculate HMAC-MD5 */
		uint8_t hmac[16];
		radius_calc_message_authenticator(pkt, offset,
						  RADIUS_SHARED_SECRET, RADIUS_SECRET_LEN,
						  hmac);
		memcpy(pkt + ma_offset + 2, hmac, 16);
	}

	/* Send */
	ssize_t sent = send(ctx->sock_fd, pkt, offset, 0);
	if (sent < 0) {
		perror("radius_send_access_request: send");
		return -1;
	}
	if ((uint32_t)sent != offset) {
		fprintf(stderr, "radius_send: short write %zd/%u\n", sent, offset);
		return -1;
	}

	return 0;
}

int radius_recv_response(struct radius_ctx *ctx, struct radius_packet *pkt)
{
	uint8_t buf[RADIUS_MAX_PACKET];
	ssize_t n;

	memset(pkt, 0, sizeof(*pkt));

	n = recv(ctx->sock_fd, buf, sizeof(buf), 0);
	if (n < 0) {
		perror("radius_recv_response: recv");
		return -1;
	}
	if (n < RADIUS_HDR_SIZE) {
		fprintf(stderr, "radius_recv: short packet %zd bytes\n", n);
		return -1;
	}

	/* Parse header */
	pkt->code       = buf[0];
	pkt->identifier = buf[1];
	pkt->length     = ((uint16_t)buf[2] << 8) | buf[3];
	memcpy(pkt->authenticator, buf + 4, RADIUS_AUTH_SIZE);

	/* Save raw packet */
	memcpy(pkt->raw, buf, n);
	pkt->raw_len = (uint32_t)n;

	/* Sanity */
	if (pkt->length > (uint32_t)n) {
		fprintf(stderr, "radius_recv: declared length %u > received %zd\n",
			pkt->length, n);
		return -1;
	}

	/* Parse attributes */
	uint32_t pos = RADIUS_HDR_SIZE;
	pkt->eap_message_len = 0;
	pkt->state_len = 0;

	while (pos + 2 <= pkt->length) {
		uint8_t attr_type = buf[pos];
		uint8_t attr_len  = buf[pos + 1];

		if (attr_len < 2 || pos + attr_len > pkt->length)
			break;

		uint8_t *attr_value = buf + pos + 2;
		uint8_t value_len   = attr_len - 2;

		switch (attr_type) {
		case RADIUS_ATTR_EAP_MESSAGE:
			/* Reassemble fragmented EAP-Message */
			if (pkt->eap_message_len + value_len <= sizeof(pkt->eap_message)) {
				memcpy(pkt->eap_message + pkt->eap_message_len,
				       attr_value, value_len);
				pkt->eap_message_len += value_len;
			}
			break;

		case RADIUS_ATTR_STATE:
			if (value_len <= sizeof(pkt->state)) {
				memcpy(pkt->state, attr_value, value_len);
				pkt->state_len = value_len;
			}
			break;

		default:
			/* Ignore other attributes */
			break;
		}

		pos += attr_len;
	}

	/* Update context State for next request */
	if (pkt->state_len > 0) {
		memcpy(ctx->state, pkt->state, pkt->state_len);
		ctx->state_len = pkt->state_len;
	}

	return (int)pkt->code;
}

uint32_t radius_edhoc_overhead_bytes(int num_roundtrips, const uint32_t *eap_sizes)
{
	/*
	 * Per RADIUS Access-Request:
	 *   Header:              20 bytes
	 *   User-Name:           ~20 bytes (2 + ~18 chars)
	 *   NAS-IP-Address:       6 bytes
	 *   NAS-Port:             6 bytes
	 *   NAS-Port-Type:        6 bytes
	 *   State:                variable (~18 bytes: 2 + 16)
	 *   Message-Authenticator: 18 bytes
	 *   EAP-Message overhead:  2 bytes per 253-byte chunk
	 *
	 * Per RADIUS Response (Access-Challenge / Access-Accept):
	 *   Header:              20 bytes
	 *   State:               ~18 bytes
	 *   Message-Authenticator: 18 bytes
	 *   EAP-Message overhead:  2 bytes per 253-byte chunk
	 */
	uint32_t overhead = 0;

	for (int i = 0; i < num_roundtrips; i++) {
		uint32_t eap_size = eap_sizes ? eap_sizes[i] : 100;
		uint32_t eap_chunks = (eap_size + 252) / 253;

		/* Access-Request overhead */
		overhead += 20;                 /* RADIUS header */
		overhead += 20;                 /* User-Name */
		overhead += 6;                  /* NAS-IP-Address */
		overhead += 6;                  /* NAS-Port */
		overhead += 6;                  /* NAS-Port-Type */
		overhead += 18;                 /* Message-Authenticator */
		overhead += eap_chunks * 2;     /* EAP-Message attr headers */
		if (i > 0)
			overhead += 18;         /* State attribute */

		/* Access-Challenge/Accept overhead */
		overhead += 20;                 /* RADIUS header */
		overhead += 18;                 /* State */
		overhead += 18;                 /* Message-Authenticator */
		overhead += eap_chunks * 2;     /* EAP-Message attr headers */
	}

	return overhead;
}

/* ==========================================================================
 * Built-in RADIUS Server Functions
 * ==========================================================================
 */

int radius_server_init(struct radius_server_ctx *srv, uint16_t port)
{
	memset(srv, 0, sizeof(*srv));
	srv->state_counter = 1;

	srv->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (srv->sock_fd < 0) {
		perror("radius_server_init: socket");
		return -1;
	}

	int opt = 1;
	setsockopt(srv->sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	setsockopt(srv->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(port);

	if (bind(srv->sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("radius_server_init: bind");
		close(srv->sock_fd);
		return -1;
	}

	return 0;
}

void radius_server_close(struct radius_server_ctx *srv)
{
	if (srv && srv->sock_fd >= 0) {
		close(srv->sock_fd);
		srv->sock_fd = -1;
	}
}

int radius_server_recv_request(struct radius_server_ctx *srv,
			       struct radius_packet *pkt)
{
	uint8_t buf[RADIUS_MAX_PACKET];
	memset(pkt, 0, sizeof(*pkt));

	srv->client_addr_len = sizeof(srv->client_addr);
	ssize_t n = recvfrom(srv->sock_fd, buf, sizeof(buf), 0,
			     (struct sockaddr *)&srv->client_addr,
			     &srv->client_addr_len);
	if (n < 0) {
		perror("radius_server_recv: recvfrom");
		return -1;
	}
	if (n < RADIUS_HDR_SIZE) {
		fprintf(stderr, "radius_server_recv: short packet %zd\n", n);
		return -1;
	}

	/* Parse header */
	pkt->code       = buf[0];
	pkt->identifier = buf[1];
	pkt->length     = ((uint16_t)buf[2] << 8) | buf[3];
	memcpy(pkt->authenticator, buf + 4, RADIUS_AUTH_SIZE);

	/* Save for response */
	memcpy(srv->last_request_auth, buf + 4, RADIUS_AUTH_SIZE);
	srv->last_identifier = pkt->identifier;

	/* Save raw */
	memcpy(pkt->raw, buf, n);
	pkt->raw_len = (uint32_t)n;

	/* Parse attributes */
	uint32_t pos = RADIUS_HDR_SIZE;
	pkt->eap_message_len = 0;
	pkt->state_len = 0;

	while (pos + 2 <= pkt->length) {
		uint8_t attr_type = buf[pos];
		uint8_t attr_len  = buf[pos + 1];
		if (attr_len < 2 || pos + attr_len > pkt->length) break;

		uint8_t *attr_value = buf + pos + 2;
		uint8_t value_len   = attr_len - 2;

		switch (attr_type) {
		case RADIUS_ATTR_EAP_MESSAGE:
			if (pkt->eap_message_len + value_len <= sizeof(pkt->eap_message)) {
				memcpy(pkt->eap_message + pkt->eap_message_len,
				       attr_value, value_len);
				pkt->eap_message_len += value_len;
			}
			break;
		case RADIUS_ATTR_STATE:
			if (value_len <= sizeof(pkt->state)) {
				memcpy(pkt->state, attr_value, value_len);
				pkt->state_len = value_len;
			}
			break;
		default:
			break;
		}
		pos += attr_len;
	}

	return 0;
}

/**
 * @brief Internal: build and send a RADIUS response (Challenge or Accept).
 */
static int radius_server_send_response(struct radius_server_ctx *srv,
				       uint8_t code,
				       const uint8_t *eap_data, uint32_t eap_len)
{
	uint8_t pkt[RADIUS_MAX_PACKET];
	uint32_t offset = RADIUS_HDR_SIZE;

	/* Header */
	pkt[0] = code;
	pkt[1] = srv->last_identifier;
	/* Authenticator initially = Request Authenticator (for computation) */
	memcpy(pkt + 4, srv->last_request_auth, RADIUS_AUTH_SIZE);

	/* EAP-Message attribute(s) */
	{
		uint32_t remaining = eap_len;
		const uint8_t *p = eap_data;
		while (remaining > 0) {
			uint8_t chunk = (remaining > 253) ? 253 : (uint8_t)remaining;
			offset += radius_append_attr(pkt + offset, RADIUS_ATTR_EAP_MESSAGE,
						     p, chunk);
			p += chunk;
			remaining -= chunk;
		}
	}

	/* State attribute (for session tracking in Access-Challenge) */
	if (code == RADIUS_CODE_ACCESS_CHALLENGE) {
		uint8_t state_val[16];
		FILE *frand = fopen("/dev/urandom", "rb");
		if (frand) {
			if (fread(state_val, 1, sizeof(state_val), frand) != sizeof(state_val))
				memset(state_val, 0, sizeof(state_val));
			fclose(frand);
		} else {
			memset(state_val, 0, sizeof(state_val));
		}
		state_val[0] = srv->state_counter++;
		offset += radius_append_attr(pkt + offset, RADIUS_ATTR_STATE,
					     state_val, 16);
	}

	/* Message-Authenticator (zeroed for HMAC calculation) */
	uint32_t ma_offset = offset;
	pkt[offset]     = RADIUS_ATTR_MESSAGE_AUTH;
	pkt[offset + 1] = 18;
	memset(pkt + offset + 2, 0, 16);
	offset += 18;

	/* Set length in header */
	pkt[2] = (uint8_t)(offset >> 8);
	pkt[3] = (uint8_t)(offset & 0xFF);

	/* Calculate Message-Authenticator HMAC */
	uint8_t hmac[16];
	radius_calc_message_authenticator(pkt, offset,
					  RADIUS_SHARED_SECRET, RADIUS_SECRET_LEN,
					  hmac);
	memcpy(pkt + ma_offset + 2, hmac, 16);

	/* Calculate Response Authenticator:
	 * MD5(Code + ID + Length + RequestAuth + Attributes + Secret) */
	{
		mbedtls_md5_context md5;
		uint8_t resp_auth[16];
		mbedtls_md5_init(&md5);
		mbedtls_md5_starts(&md5);
		mbedtls_md5_update(&md5, pkt, offset);
		mbedtls_md5_update(&md5, (const unsigned char *)RADIUS_SHARED_SECRET,
				   RADIUS_SECRET_LEN);
		mbedtls_md5_finish(&md5, resp_auth);
		mbedtls_md5_free(&md5);
		memcpy(pkt + 4, resp_auth, 16);
	}

	/* Send */
	ssize_t sent = sendto(srv->sock_fd, pkt, offset, 0,
			      (struct sockaddr *)&srv->client_addr,
			      srv->client_addr_len);
	if (sent < 0) {
		perror("radius_server_send: sendto");
		return -1;
	}

	return 0;
}

int radius_server_send_challenge(struct radius_server_ctx *srv,
				 const uint8_t *eap_data, uint32_t eap_len)
{
	return radius_server_send_response(srv, RADIUS_CODE_ACCESS_CHALLENGE,
					   eap_data, eap_len);
}

int radius_server_send_accept(struct radius_server_ctx *srv,
			      const uint8_t *eap_data, uint32_t eap_len)
{
	return radius_server_send_response(srv, RADIUS_CODE_ACCESS_ACCEPT,
					   eap_data, eap_len);
}
