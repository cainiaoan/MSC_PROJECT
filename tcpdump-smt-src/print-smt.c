/*
 * Copyright (c) 2026 University of Edinburgh
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, and
 * (2) distributions including binary code include the above copyright notice
 * and this paragraph in its entirety in the documentation or other materials
 * provided with the distribution.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* \summary: Secure Message Transport (SMT), based on Homa */

#include <config.h>

#include "netdissect-stdinc.h"
#include "netdissect.h"
#include "extract.h"

#define SMT_COMMON_HEADER_LEN		28
#define SMT_DATA_HEADER_LEN		52
#define SMT_GRANT_HEADER_LEN		33
#define SMT_RESEND_HEADER_LEN		37
#define SMT_CUTOFFS_HEADER_LEN		62
#define SMT_ACK_HEADER_LEN		80

#define SMT_TYPE_OFFSET			11
#define SMT_DOFF_OFFSET			12
#define SMT_SENDER_ID_OFFSET		20

#define SMT_DATA			0x10
#define SMT_GRANT			0x11
#define SMT_RESEND			0x12
#define SMT_UNKNOWN			0x13
#define SMT_BUSY			0x14
#define SMT_CUTOFFS			0x15
#define SMT_FREEZE			0x16
#define SMT_NEED_ACK			0x17
#define SMT_ACK				0x18

#define SMT_TLS_CONTENT_TYPE		0x17
#define SMT_TLS_VERSION			0x0303
#define SMT_TLS_HEADER_LEN		5
#define SMT_TLS_EXPLICIT_NONCE_LEN	8
#define SMT_TLS_TAG_LEN			16

#define SMT_MAX_ACKS			5
#define SMT_ACK_LEN			10
#define SMT_MAX_PRIORITIES		8

static const struct tok smt_packet_types[] = {
	{ SMT_DATA, "DATA" },
	{ SMT_GRANT, "GRANT" },
	{ SMT_RESEND, "RESEND" },
	{ SMT_UNKNOWN, "UNKNOWN" },
	{ SMT_BUSY, "BUSY" },
	{ SMT_CUTOFFS, "CUTOFFS" },
	{ SMT_FREEZE, "FREEZE" },
	{ SMT_NEED_ACK, "NEED_ACK" },
	{ SMT_ACK, "ACK" },
	{ 0, NULL }
};

static void
smt_tls_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	uint16_t record_len;
	uint64_t record_seq;
	u_int record_available;

	if (length < SMT_TLS_HEADER_LEN ||
	    GET_U_1(bp) != SMT_TLS_CONTENT_TYPE ||
	    GET_BE_U_2(bp + 1) != SMT_TLS_VERSION) {
		ND_PRINT(", record continuation %u bytes", length);
		return;
	}

	record_len = GET_BE_U_2(bp + 3);
	ND_PRINT(", TLS 1.2 record len %u", record_len);

	if (length >= SMT_TLS_HEADER_LEN + SMT_TLS_EXPLICIT_NONCE_LEN) {
		record_seq = GET_BE_U_8(bp + SMT_TLS_HEADER_LEN);
		ND_PRINT(", record seq %" PRIu64, record_seq);
	}

	record_available = length - SMT_TLS_HEADER_LEN;
	if (record_available < record_len)
		ND_PRINT(", partial %u/%u", record_available, record_len);
	else if (record_len >= SMT_TLS_EXPLICIT_NONCE_LEN + SMT_TLS_TAG_LEN &&
	    ndo->ndo_vflag)
		ND_PRINT(", encrypted data %u",
		    record_len - SMT_TLS_EXPLICIT_NONCE_LEN - SMT_TLS_TAG_LEN);
}

static void
smt_data_print(netdissect_options *ndo, const u_char *bp, u_int length,
    uint32_t sequence)
{
	uint32_t message_len, incoming;
	uint64_t ack_client_id;
	uint16_t ack_server_port, cutoff_version;
	uint8_t retransmit;
	uint32_t resend_offset;

	ND_ICHECK_U(length, <, SMT_DATA_HEADER_LEN);

	message_len = GET_BE_U_4(bp + 28);
	incoming = GET_BE_U_4(bp + 32);
	ack_client_id = GET_BE_U_8(bp + 36);
	ack_server_port = GET_BE_U_2(bp + 44);
	cutoff_version = GET_BE_U_2(bp + 46);
	retransmit = GET_U_1(bp + 48);
	resend_offset = GET_BE_U_3(bp + 49);

	ND_PRINT(", offset %u, msglen %u", sequence, message_len);
	if (ndo->ndo_vflag) {
		ND_PRINT(", incoming %u, cutoff %u", incoming, cutoff_version);
		if (ack_client_id != 0)
			ND_PRINT(", ack id %" PRIu64 " server-port %u",
			    ack_client_id, ack_server_port);
		if (retransmit != 0)
			ND_PRINT(", retransmit 0x%02x, resend-offset %u",
			    retransmit, resend_offset);
	}

	smt_tls_print(ndo, bp + SMT_DATA_HEADER_LEN,
	    length - SMT_DATA_HEADER_LEN);
	return;

invalid:
	nd_print_invalid(ndo);
}

static void
smt_cutoffs_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	u_int i;

	ND_ICHECK_U(length, <, SMT_CUTOFFS_HEADER_LEN);
	ND_PRINT(", version %u", GET_BE_U_2(bp + 60));
	if (ndo->ndo_vflag) {
		ND_PRINT(", cutoffs [");
		for (i = 0; i < SMT_MAX_PRIORITIES; i++) {
			ND_PRINT("%s%u", i == 0 ? "" : ",",
			    GET_BE_U_4(bp + 28 + (4 * i)));
		}
		ND_PRINT("]");
	}
	return;

invalid:
	nd_print_invalid(ndo);
}

static void
smt_ack_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	uint16_t num_acks;
	u_int i, displayed;

	ND_ICHECK_U(length, <, SMT_ACK_HEADER_LEN);
	num_acks = GET_BE_U_2(bp + 28);
	ND_PRINT(", %u ack%s", num_acks, num_acks == 1 ? "" : "s");

	displayed = num_acks;
	if (displayed > SMT_MAX_ACKS)
		displayed = SMT_MAX_ACKS;
	if (ndo->ndo_vflag && displayed != 0) {
		ND_PRINT(" [");
		for (i = 0; i < displayed; i++) {
			const u_char *ack = bp + 30 + (i * SMT_ACK_LEN);

			ND_PRINT("%sid %" PRIu64 " port %u",
			    i == 0 ? "" : ", ",
			    GET_BE_U_8(ack), GET_BE_U_2(ack + 8));
		}
		ND_PRINT("]");
	}
	if (num_acks > SMT_MAX_ACKS)
		ND_PRINT(", invalid count");
	return;

invalid:
	nd_print_invalid(ndo);
}

void
smt_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	uint16_t sport, dport;
	uint32_t sequence;
	uint64_t sender_id;
	uint8_t type, doff;

	ndo->ndo_protocol = "smt";
	nd_print_protocol_caps(ndo);

	ND_ICHECK_U(length, <, SMT_COMMON_HEADER_LEN);

	sport = GET_BE_U_2(bp);
	dport = GET_BE_U_2(bp + 2);
	sequence = GET_BE_U_4(bp + 4);
	type = GET_U_1(bp + SMT_TYPE_OFFSET);
	doff = GET_U_1(bp + SMT_DOFF_OFFSET) >> 4;
	sender_id = GET_BE_U_8(bp + SMT_SENDER_ID_OFFSET);

	ND_PRINT(" %u > %u, %s, id %" PRIu64,
	    sport, dport, tok2str(smt_packet_types, "type 0x%02x", type),
	    sender_id);
	if (ndo->ndo_vflag)
		ND_PRINT(", doff %u", doff);

	switch (type) {
	case SMT_DATA:
		smt_data_print(ndo, bp, length, sequence);
		break;

	case SMT_GRANT:
		ND_ICHECK_U(length, <, SMT_GRANT_HEADER_LEN);
		ND_PRINT(", offset %u, priority %u",
		    GET_BE_U_4(bp + 28), GET_U_1(bp + 32));
		break;

	case SMT_RESEND:
		ND_ICHECK_U(length, <, SMT_RESEND_HEADER_LEN);
		ND_PRINT(", offset %u, length %u, priority %u",
		    GET_BE_U_4(bp + 28), GET_BE_U_4(bp + 32),
		    GET_U_1(bp + 36));
		break;

	case SMT_CUTOFFS:
		smt_cutoffs_print(ndo, bp, length);
		break;

	case SMT_ACK:
		smt_ack_print(ndo, bp, length);
		break;

	case SMT_UNKNOWN:
	case SMT_BUSY:
	case SMT_FREEZE:
	case SMT_NEED_ACK:
	default:
		break;
	}
	return;

invalid:
	nd_print_invalid(ndo);
}
