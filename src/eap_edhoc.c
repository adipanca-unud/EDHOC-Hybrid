/*
 * =============================================================================
 * EAP-EDHOC: EAP wrapper implementation
 * =============================================================================
 *
 * Implements EAP-EDHOC framing per draft-ingles-eap-edhoc-05.
 *
 * This module provides:
 *   1. EAP packet building/serializing/parsing functions
 *   2. The framing overhead is purely additive — the underlying EDHOC
 *      crypto operations are unchanged.
 *
 * EAP-EDHOC Message Flow (successful authentication):
 *
 *   EAP Peer (Initiator)                  EAP Server (Responder)
 *        |                                      |
 *        |  <-- EAP-Request/Identity ---------- |  (1)
 *        |  --- EAP-Response/Identity --------> |  (2)
 *        |  <-- EAP-Request(Start, S=1) ------- |  (3)
 *        |  --- EAP-Response(message_1) ------> |  (4)
 *        |  <-- EAP-Request(message_2) -------- |  (5)
 *        |  --- EAP-Response(message_3) ------> |  (6)
 *        |  <-- EAP-Request(message_4) -------- |  (7)
 *        |  --- EAP-Response(empty ACK) ------> |  (8)
 *        |  <-- EAP-Success ------------------- |  (9)
 *        |                                      |
 *
 * Total: 9 EAP packets over wire (vs 3 EDHOC messages)
 *        = 3 extra round-trips overhead
 *        (Identity exchange, Start, message_4 + ACK + Success)
 *
 * =============================================================================
 */

#include <string.h>
#include <arpa/inet.h>  /* htons, ntohs */

#include "eap_edhoc.h"

/* ===== Packet Building Functions ===== */

void eap_build_request_identity(struct eap_packet *pkt, uint8_t identifier)
{
	memset(pkt, 0, sizeof(*pkt));
	pkt->code = EAP_CODE_REQUEST;
	pkt->identifier = identifier;
	pkt->type = EAP_TYPE_IDENTITY;
	pkt->flags = 0;
	pkt->data_len = 0;
	/* Length = header(4) + type(1) = 5 */
	pkt->length = EAP_HEADER_SIZE + 1;
}

void eap_build_response_identity(struct eap_packet *pkt, uint8_t identifier)
{
	memset(pkt, 0, sizeof(*pkt));
	pkt->code = EAP_CODE_RESPONSE;
	pkt->identifier = identifier;
	pkt->type = EAP_TYPE_IDENTITY;
	pkt->flags = 0;
	/* Data = anonymous NAI */
	const char *nai = EAP_IDENTITY_NAI;
	uint32_t nai_len = (uint32_t)strlen(nai);
	memcpy(pkt->data, nai, nai_len);
	pkt->data_len = nai_len;
	/* Length = header(4) + type(1) + NAI */
	pkt->length = EAP_HEADER_SIZE + 1 + (uint16_t)nai_len;
}

void eap_build_edhoc_start(struct eap_packet *pkt, uint8_t identifier)
{
	memset(pkt, 0, sizeof(*pkt));
	pkt->code = EAP_CODE_REQUEST;
	pkt->identifier = identifier;
	pkt->type = EAP_TYPE_EDHOC;
	pkt->flags = EAP_EDHOC_FLAG_S;  /* S bit set */
	pkt->data_len = 0;
	/* Length = header(4) + type(1) + flags(1) = 6 */
	pkt->length = EAP_HEADER_SIZE + EAP_EDHOC_SUBHDR_SIZE;
}

void eap_build_edhoc_message(struct eap_packet *pkt, uint8_t code,
			     uint8_t identifier,
			     const uint8_t *edhoc_data, uint32_t edhoc_len)
{
	memset(pkt, 0, sizeof(*pkt));
	pkt->code = code;
	pkt->identifier = identifier;
	pkt->type = EAP_TYPE_EDHOC;
	pkt->flags = 0;  /* No fragmentation, no L bit for unfragmented messages */
	if (edhoc_data && edhoc_len > 0) {
		uint32_t copy_len = edhoc_len;
		if (copy_len > sizeof(pkt->data))
			copy_len = sizeof(pkt->data);
		memcpy(pkt->data, edhoc_data, copy_len);
		pkt->data_len = copy_len;
	} else {
		pkt->data_len = 0;
	}
	/* Length = header(4) + type(1) + flags(1) + EDHOC data */
	pkt->length = EAP_HEADER_SIZE + EAP_EDHOC_SUBHDR_SIZE + (uint16_t)pkt->data_len;
}

void eap_build_edhoc_ack(struct eap_packet *pkt, uint8_t identifier)
{
	memset(pkt, 0, sizeof(*pkt));
	pkt->code = EAP_CODE_RESPONSE;
	pkt->identifier = identifier;
	pkt->type = EAP_TYPE_EDHOC;
	pkt->flags = 0;
	pkt->data_len = 0;
	/* Length = header(4) + type(1) + flags(1) = 6 */
	pkt->length = EAP_HEADER_SIZE + EAP_EDHOC_SUBHDR_SIZE;
}

void eap_build_success(struct eap_packet *pkt, uint8_t identifier)
{
	memset(pkt, 0, sizeof(*pkt));
	pkt->code = EAP_CODE_SUCCESS;
	pkt->identifier = identifier;
	pkt->type = 0;
	pkt->flags = 0;
	pkt->data_len = 0;
	/* EAP-Success has no Type field: Length = header(4) = 4 */
	pkt->length = EAP_HEADER_SIZE;
}

/* ===== Serialization ===== */

uint32_t eap_wire_size(const struct eap_packet *pkt)
{
	return (uint32_t)pkt->length;
}

int eap_serialize(const struct eap_packet *pkt, uint8_t *buf, uint32_t buf_size)
{
	uint32_t total = eap_wire_size(pkt);
	if (total > buf_size) return -1;

	uint32_t off = 0;

	/* Code + Identifier + Length */
	buf[off++] = pkt->code;
	buf[off++] = pkt->identifier;
	uint16_t net_len = htons(pkt->length);
	memcpy(buf + off, &net_len, 2);
	off += 2;

	/* EAP-Success and EAP-Failure have no Type/Data */
	if (pkt->code == EAP_CODE_SUCCESS || pkt->code == EAP_CODE_FAILURE) {
		return (int)off;
	}

	/* Type */
	buf[off++] = pkt->type;

	/* For EAP-EDHOC type, add Flags */
	if (pkt->type == EAP_TYPE_EDHOC) {
		buf[off++] = pkt->flags;
	}

	/* Data payload (Identity data or EDHOC data) */
	if (pkt->data_len > 0) {
		memcpy(buf + off, pkt->data, pkt->data_len);
		off += pkt->data_len;
	}

	return (int)off;
}

int eap_parse(const uint8_t *buf, uint32_t buf_len, struct eap_packet *pkt)
{
	if (buf_len < EAP_HEADER_SIZE) return -1;

	memset(pkt, 0, sizeof(*pkt));

	uint32_t off = 0;
	pkt->code = buf[off++];
	pkt->identifier = buf[off++];
	uint16_t net_len;
	memcpy(&net_len, buf + off, 2);
	pkt->length = ntohs(net_len);
	off += 2;

	if (pkt->length > buf_len) return -1;

	/* EAP-Success / EAP-Failure: no further fields */
	if (pkt->code == EAP_CODE_SUCCESS || pkt->code == EAP_CODE_FAILURE) {
		return 0;
	}

	if (off >= pkt->length) return -1;
	pkt->type = buf[off++];

	/* For EAP-EDHOC type, parse Flags */
	if (pkt->type == EAP_TYPE_EDHOC && off < pkt->length) {
		pkt->flags = buf[off++];
	}

	/* Remaining bytes = data */
	if (off < pkt->length) {
		pkt->data_len = pkt->length - (uint16_t)off;
		if (pkt->data_len > sizeof(pkt->data))
			pkt->data_len = sizeof(pkt->data);
		memcpy(pkt->data, buf + off, pkt->data_len);
	}

	return 0;
}

/* ===== Overhead Calculation ===== */

uint32_t eap_edhoc_overhead_bytes(uint32_t msg1_len, uint32_t msg2_len,
				  uint32_t msg3_len)
{
	uint32_t overhead = 0;

	/* (1) EAP-Request/Identity: Code(1)+Id(1)+Len(2)+Type(1) = 5 bytes */
	overhead += 5;

	/* (2) EAP-Response/Identity: 5 + NAI length */
	overhead += 5 + (uint32_t)strlen(EAP_IDENTITY_NAI);

	/* (3) EAP-Request(Start): Code(1)+Id(1)+Len(2)+Type(1)+Flags(1) = 6 */
	overhead += EAP_HEADER_SIZE + EAP_EDHOC_SUBHDR_SIZE;

	/* (4) EAP-Response(msg1): header overhead = 4+2 = 6 on top of msg1_len */
	overhead += EAP_HEADER_SIZE + EAP_EDHOC_SUBHDR_SIZE;

	/* (5) EAP-Request(msg2): 6 on top of msg2_len */
	overhead += EAP_HEADER_SIZE + EAP_EDHOC_SUBHDR_SIZE;

	/* (6) EAP-Response(msg3): 6 on top of msg3_len */
	overhead += EAP_HEADER_SIZE + EAP_EDHOC_SUBHDR_SIZE;

	/* (7) EAP-Request(msg4): 6 + msg4 payload (32 bytes) */
	overhead += EAP_HEADER_SIZE + EAP_EDHOC_SUBHDR_SIZE + EAP_EDHOC_MSG4_SIZE;

	/* (8) EAP-Response(empty ACK): 6 */
	overhead += EAP_HEADER_SIZE + EAP_EDHOC_SUBHDR_SIZE;

	/* (9) EAP-Success: 4 */
	overhead += EAP_HEADER_SIZE;

	return overhead;
}
