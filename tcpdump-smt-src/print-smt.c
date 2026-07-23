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

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_LIBCRYPTO
#include <openssl/evp.h>
#endif

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
#define SMT_TLS_KEY_LEN			16
#define SMT_TLS_FIXED_IV_LEN		4
#define SMT_TLS_NONCE_LEN		12
#define SMT_TLS_AAD_LEN			13

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

#ifdef HAVE_LIBCRYPTO
#ifndef HAVE_EVP_CIPHER_CTX_NEW
static EVP_CIPHER_CTX *
EVP_CIPHER_CTX_new(void)
{
	return calloc(1, sizeof(EVP_CIPHER_CTX));
}

static void
EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx)
{
	EVP_CIPHER_CTX_cleanup(ctx);
	free(ctx);
}
#endif

static int
smt_hex_digit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int
smt_decode_hex(const char *hex, size_t hex_len, u_char *output,
    size_t output_len)
{
	size_t i;
	int high, low;

	if (hex_len != output_len * 2)
		return 0;
	for (i = 0; i < output_len; i++) {
		high = smt_hex_digit(hex[i * 2]);
		low = smt_hex_digit(hex[i * 2 + 1]);
		if (high < 0 || low < 0)
			return 0;
		output[i] = (u_char)((high << 4) | low);
	}
	return 1;
}

/*
 * Configure TLS 1.2 AES-128-GCM keys from:
 * server-port,client-key,client-iv,server-key,server-iv
 *
 * An IV may contain either the four-byte TLS fixed IV or the full 12-byte
 * value supplied by SMT; TLS 1.2 uses its first four bytes with the explicit
 * eight-byte record nonce.
 */
int
smt_set_decryption_secret(netdissect_options *ndo, const char *arg)
{
	const char *field[4], *end;
	char *port_end;
	size_t field_len[4], iv_len;
	unsigned long port;
	u_char client_key[SMT_TLS_KEY_LEN], client_iv[SMT_TLS_NONCE_LEN];
	u_char server_key[SMT_TLS_KEY_LEN], server_iv[SMT_TLS_NONCE_LEN];
	u_int i;

	errno = 0;
	port = strtoul(arg, &port_end, 10);
	end = port_end;
	if (errno != 0 || end == arg || port == 0 || port > UINT16_MAX ||
	    *end != ',')
		return 0;

	end++;
	for (i = 0; i < 4; i++) {
		const char *comma;

		field[i] = end;
		comma = strchr(end, ',');
		if (i != 3) {
			if (comma == NULL)
				return 0;
			field_len[i] = (size_t)(comma - end);
			end = comma + 1;
		} else {
			if (comma != NULL)
				return 0;
			field_len[i] = strlen(end);
		}
	}

	if (!smt_decode_hex(field[0], field_len[0], client_key,
	    sizeof(client_key)) ||
	    !smt_decode_hex(field[2], field_len[2], server_key,
	    sizeof(server_key)))
		return 0;

	if (field_len[1] == SMT_TLS_FIXED_IV_LEN * 2)
		iv_len = SMT_TLS_FIXED_IV_LEN;
	else if (field_len[1] == SMT_TLS_NONCE_LEN * 2)
		iv_len = SMT_TLS_NONCE_LEN;
	else
		return 0;
	if (!smt_decode_hex(field[1], field_len[1], client_iv, iv_len))
		return 0;

	if (field_len[3] == SMT_TLS_FIXED_IV_LEN * 2)
		iv_len = SMT_TLS_FIXED_IV_LEN;
	else if (field_len[3] == SMT_TLS_NONCE_LEN * 2)
		iv_len = SMT_TLS_NONCE_LEN;
	else
		return 0;
	if (!smt_decode_hex(field[3], field_len[3], server_iv, iv_len))
		return 0;

	ndo->ndo_smt_server_port = (uint16_t)port;
	memcpy(ndo->ndo_smt_client_key, client_key, sizeof(client_key));
	memcpy(ndo->ndo_smt_client_iv, client_iv, SMT_TLS_FIXED_IV_LEN);
	memcpy(ndo->ndo_smt_server_key, server_key, sizeof(server_key));
	memcpy(ndo->ndo_smt_server_iv, server_iv, SMT_TLS_FIXED_IV_LEN);
	ndo->ndo_smt_decrypt = 1;
	return 1;
}

static int
smt_tls_decrypt(const u_char *record, uint16_t record_len,
    const u_char *key, const u_char *fixed_iv, u_char **plaintext,
    u_int *plaintext_len)
{
	EVP_CIPHER_CTX *ctx;
	u_char nonce[SMT_TLS_NONCE_LEN], aad[SMT_TLS_AAD_LEN];
	const u_char *ciphertext, *tag;
	u_int ciphertext_len;
	int len, final_len, ok;

	if (record_len < SMT_TLS_EXPLICIT_NONCE_LEN + SMT_TLS_TAG_LEN)
		return 0;
	ciphertext_len =
	    record_len - SMT_TLS_EXPLICIT_NONCE_LEN - SMT_TLS_TAG_LEN;
	ciphertext = record + SMT_TLS_HEADER_LEN + SMT_TLS_EXPLICIT_NONCE_LEN;
	tag = ciphertext + ciphertext_len;

	memcpy(nonce, fixed_iv, SMT_TLS_FIXED_IV_LEN);
	memcpy(nonce + SMT_TLS_FIXED_IV_LEN, record + SMT_TLS_HEADER_LEN,
	    SMT_TLS_EXPLICIT_NONCE_LEN);
	memcpy(aad, record + SMT_TLS_HEADER_LEN, SMT_TLS_EXPLICIT_NONCE_LEN);
	memcpy(aad + SMT_TLS_EXPLICIT_NONCE_LEN, record, 3);
	aad[11] = (u_char)(ciphertext_len >> 8);
	aad[12] = (u_char)ciphertext_len;

	*plaintext = malloc(ciphertext_len + EVP_MAX_BLOCK_LENGTH);
	if (*plaintext == NULL)
		return 0;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		free(*plaintext);
		*plaintext = NULL;
		return 0;
	}

	len = 0;
	final_len = 0;
	ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) == 1 &&
	    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
	    SMT_TLS_NONCE_LEN, NULL) == 1 &&
	    EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
	    EVP_DecryptUpdate(ctx, NULL, &final_len, aad, sizeof(aad)) == 1 &&
	    EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext,
	    ciphertext_len) == 1 &&
	    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SMT_TLS_TAG_LEN,
	    (void *)tag) == 1 &&
	    EVP_DecryptFinal_ex(ctx, *plaintext + len, &final_len) == 1;
	EVP_CIPHER_CTX_free(ctx);

	if (!ok) {
		free(*plaintext);
		*plaintext = NULL;
		return 0;
	}
	*plaintext_len = (u_int)(len + final_len);
	return 1;
}
#endif

static void
smt_tls_print(netdissect_options *ndo, const u_char *bp, u_int length,
    const u_char *key, const u_char *fixed_iv)
{
	uint16_t record_len;
	uint64_t record_seq;
	u_int record_available;
#ifdef HAVE_LIBCRYPTO
	u_char *plaintext;
	u_int plaintext_len;
#else
	(void)key;
	(void)fixed_iv;
#endif

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

#ifdef HAVE_LIBCRYPTO
	if (key == NULL || record_available < record_len)
		return;
	if (!ND_TTEST_LEN(bp, SMT_TLS_HEADER_LEN + record_len)) {
		nd_print_trunc(ndo);
		return;
	}
	if (!smt_tls_decrypt(bp, record_len, key, fixed_iv, &plaintext,
	    &plaintext_len)) {
		ND_PRINT(", decrypt failed (authentication)");
		return;
	}
	ND_PRINT(", decrypted payload %u bytes", plaintext_len);
	if (!nd_push_buffer(ndo, plaintext, plaintext, plaintext_len)) {
		free(plaintext);
		(*ndo->ndo_error)(ndo, S_ERR_ND_MEM_ALLOC,
		    "%s: can't push decryption buffer", __func__);
	}
	hex_and_ascii_print(ndo, "\n\t", plaintext, plaintext_len);
	nd_pop_packet_info(ndo);
#endif
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
	const u_char *key, *fixed_iv;

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

	key = NULL;
	fixed_iv = NULL;
#ifdef HAVE_LIBCRYPTO
	if (ndo->ndo_smt_decrypt) {
		if (GET_BE_U_2(bp) == ndo->ndo_smt_server_port) {
			key = ndo->ndo_smt_server_key;
			fixed_iv = ndo->ndo_smt_server_iv;
		} else if (GET_BE_U_2(bp + 2) == ndo->ndo_smt_server_port) {
			key = ndo->ndo_smt_client_key;
			fixed_iv = ndo->ndo_smt_client_iv;
		} else {
			ND_PRINT(", decrypt skipped (server port %u not present)",
			    ndo->ndo_smt_server_port);
		}
	}
#endif
	smt_tls_print(ndo, bp + SMT_DATA_HEADER_LEN,
	    length - SMT_DATA_HEADER_LEN, key, fixed_iv);
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
