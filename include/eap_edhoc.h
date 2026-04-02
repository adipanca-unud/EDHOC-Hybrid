/*
 * =============================================================================
 * EAP-EDHOC: EAP wrapper for EDHOC protocol
 * =============================================================================
 *
 * Implements the EAP-EDHOC method as defined in:
 *   draft-ingles-eap-edhoc-05 (draft-ietf-emu-eap-edhoc)
 *
 * EAP-EDHOC wraps the 3-message EDHOC handshake inside EAP packets,
 * adding:
 *   1. EAP-Request/Identity + EAP-Response/Identity
 *   2. EAP-Request(EAP-EDHOC Start) [S bit set]
 *   3. EAP-Response(EDHOC message_1)
 *   4. EAP-Request(EDHOC message_2)
 *   5. EAP-Response(EDHOC message_3)
 *   6. EAP-Request(EDHOC message_4)  [protected success indication]
 *   7. EAP-Response(empty)           [acknowledgement]
 *   8. EAP-Success
 *
 * Total: 8 EAP messages (vs 3 EDHOC messages)
 *        = 3 extra round-trips of overhead
 *
 * The underlying EDHOC crypto is identical — EAP only adds framing
 * overhead and additional message exchanges.
 *
 * EAP Packet Format (RFC 3748):
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |     Code      |  Identifier   |            Length             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |     Type      |    Flags      |         EDHOC Data ...
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * EAP Codes:
 *   1 = Request  (Server → Peer)
 *   2 = Response (Peer → Server)
 *   3 = Success  (Server → Peer)
 *   4 = Failure  (Server → Peer)
 *
 * EAP-EDHOC Flags:
 *   Bit 0 (0x80): L = Length included (4-byte EDHOC Message Length field)
 *   Bit 1 (0x40): M = More fragments
 *   Bit 2 (0x20): S = EAP-EDHOC Start (only in first EAP-Request)
 *
 * For our benchmarks, messages are small enough to avoid fragmentation.
 * =============================================================================
 */

#ifndef EAP_EDHOC_H
#define EAP_EDHOC_H

#include <stdint.h>
#include <stddef.h>

/* ===== EAP Constants ===== */
#define EAP_CODE_REQUEST    1
#define EAP_CODE_RESPONSE   2
#define EAP_CODE_SUCCESS    3
#define EAP_CODE_FAILURE    4

/* EAP Type for EAP-EDHOC (TBD1 in draft, using 255 as placeholder) */
#define EAP_TYPE_EDHOC      255

/* EAP Type for Identity */
#define EAP_TYPE_IDENTITY   1

/* EAP-EDHOC Flags */
#define EAP_EDHOC_FLAG_L    0x80  /* Length included */
#define EAP_EDHOC_FLAG_M    0x40  /* More fragments */
#define EAP_EDHOC_FLAG_S    0x20  /* EAP-EDHOC Start */

/* EAP header size: Code(1) + Identifier(1) + Length(2) = 4 bytes */
#define EAP_HEADER_SIZE     4

/* EAP-EDHOC sub-header: Type(1) + Flags(1) = 2 bytes (no L field if unfragmented) */
#define EAP_EDHOC_SUBHDR_SIZE  2

/* Maximum EAP packet size */
#define EAP_MAX_PACKET_SIZE  8192

/* Anonymous NAI for EAP-Response/Identity (privacy-friendly per Section 3.1.5) */
#define EAP_IDENTITY_NAI    "@edhoc-hybrid.local"

/* EDHOC message_4: protected success indication
 * In a real implementation, message_4 is a CBOR-encoded EDHOC message.
 * For our simulation, we use a fixed 32-byte protected payload derived
 * from the EDHOC transcript.
 */
#define EAP_EDHOC_MSG4_SIZE  32

/* ===== EAP Packet Structure ===== */
struct eap_packet {
	uint8_t  code;
	uint8_t  identifier;
	uint16_t length;      /* Total EAP packet length (including header) */
	uint8_t  type;        /* EAP Type (only for Request/Response) */
	uint8_t  flags;       /* EAP-EDHOC flags (only for EAP-EDHOC type) */
	uint8_t  data[EAP_MAX_PACKET_SIZE];
	uint32_t data_len;    /* Length of EDHOC data payload */
};

/* ===== EAP-EDHOC Framing Functions ===== */

/**
 * @brief Build an EAP-Request/Identity packet.
 * @param pkt Output packet structure
 * @param identifier EAP Identifier value
 */
void eap_build_request_identity(struct eap_packet *pkt, uint8_t identifier);

/**
 * @brief Build an EAP-Response/Identity packet with anonymous NAI.
 * @param pkt Output packet structure
 * @param identifier EAP Identifier (must match request)
 */
void eap_build_response_identity(struct eap_packet *pkt, uint8_t identifier);

/**
 * @brief Build an EAP-Request with EAP-EDHOC Start (S bit set, no data).
 * @param pkt Output packet structure
 * @param identifier EAP Identifier value
 */
void eap_build_edhoc_start(struct eap_packet *pkt, uint8_t identifier);

/**
 * @brief Build an EAP-Request or EAP-Response carrying an EDHOC message.
 * @param pkt Output packet structure
 * @param code EAP_CODE_REQUEST or EAP_CODE_RESPONSE
 * @param identifier EAP Identifier value
 * @param edhoc_data EDHOC message payload
 * @param edhoc_len Length of EDHOC message
 */
void eap_build_edhoc_message(struct eap_packet *pkt, uint8_t code,
			     uint8_t identifier,
			     const uint8_t *edhoc_data, uint32_t edhoc_len);

/**
 * @brief Build an EAP-Response with no data (ACK after message_4).
 * @param pkt Output packet structure
 * @param identifier EAP Identifier value
 */
void eap_build_edhoc_ack(struct eap_packet *pkt, uint8_t identifier);

/**
 * @brief Build an EAP-Success packet.
 * @param pkt Output packet structure
 * @param identifier EAP Identifier value
 */
void eap_build_success(struct eap_packet *pkt, uint8_t identifier);

/**
 * @brief Serialize an EAP packet into a wire buffer.
 * @param pkt Source packet structure
 * @param buf Output buffer
 * @param buf_size Size of output buffer
 * @return Number of bytes written, or -1 on error
 */
int eap_serialize(const struct eap_packet *pkt, uint8_t *buf, uint32_t buf_size);

/**
 * @brief Parse a wire buffer into an EAP packet structure.
 * @param buf Input buffer
 * @param buf_len Length of input data
 * @param pkt Output packet structure
 * @return 0 on success, -1 on error
 */
int eap_parse(const uint8_t *buf, uint32_t buf_len, struct eap_packet *pkt);

/**
 * @brief Get the total serialized size of an EAP packet.
 * @param pkt Packet structure
 * @return Total wire size in bytes
 */
uint32_t eap_wire_size(const struct eap_packet *pkt);

/**
 * @brief Compute EAP-EDHOC overhead in bytes for the full exchange.
 *
 * Calculates the total additional bytes added by EAP framing compared
 * to raw EDHOC. This includes:
 *   - EAP-Request/Identity + EAP-Response/Identity
 *   - EAP-EDHOC Start
 *   - EAP headers around message_1, message_2, message_3
 *   - EAP-Request(message_4) + EAP-Response(ACK)
 *   - EAP-Success
 *
 * @param msg1_len Raw EDHOC message_1 length
 * @param msg2_len Raw EDHOC message_2 length
 * @param msg3_len Raw EDHOC message_3 length
 * @return Total EAP overhead in bytes
 */
uint32_t eap_edhoc_overhead_bytes(uint32_t msg1_len, uint32_t msg2_len,
				  uint32_t msg3_len);

#endif /* EAP_EDHOC_H */
