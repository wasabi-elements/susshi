/*!
 *
 * @brief       PASETO v4.public token verification
 *
 * @ingroup     shared
 *
 * @copyright   Copyright (C) 2026 Wasabi Elements GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * @author      Oliver Rauscher <oliver@susshi.io>
 * @date        2026-07-05
 *
 * @defgroup    paseto PASETO v4.public methods
 * @{
 */

#include "shared/common.h"
#include "shared/base64.h"
#include "shared/paseto.h"

#define PASETO_V4_PUBLIC_HEADER             "v4.public."
#define PASETO_V4_PUBLIC_HEADER_LEN         10
#define PASETO_V4_PUBLIC_SIGNATURE_BYTES    64

/* Prototypes */
static void paseto_le64(size_t value, unsigned char *out);


/*!
 * @brief       Encode an integer as a 64-bit little-endian byte sequence
 *
 * Used for the Pre-Authentication Encoding (PAE) as defined by the PASETO
 * specification.
 *
 * @param       value   value to encode; must be below 2^63
 * @param       out     output buffer, must be at least 8 bytes
 */

static void
paseto_le64(size_t value, unsigned char *out) {
	int i;

	for (i = 0; i < 8; i++) {
		out[i] = (unsigned char) (value & 0xff);
		value >>= 8;
	}
}


/*!
 * @brief       Verify a PASETO v4.public token (Ed25519 signature)
 *
 * Implements the verification part of PASETO v4.public as defined by
 * https://github.com/paseto-standard/paseto-spec — the Ed25519 signature
 * covers the Pre-Authentication Encoding of header, message, footer and
 * (empty) implicit assertion.
 *
 * On success, a heap-allocated, null-terminated copy of the verified message
 * is written to @p *message. The caller is responsible for freeing it.
 * On failure, @p *message is set to @c NULL.
 *
 * @param       token           Null-terminated PASETO token string
 * @param       pubkey          Raw Ed25519 public key,
 *                              @c SUSSHI_PASETO_V4_PUBLIC_PUBKEY_BYTES bytes
 * @param       message         Receives a pointer to the verified message
 * @param       message_len     If non-NULL, receives the message length in bytes
 *
 * @return      @c true if the signature verifies, @c false on invalid
 *              arguments, malformed tokens or signature mismatch
 */

bool
susshi_paseto_v4_public_verify(const char *token, const unsigned char *pubkey, unsigned char **message, size_t *message_len) {
	bool rc;
	const char *payload_b64 = NULL, *footer_b64 = NULL, *separator;
	char *payload_copy = NULL;
	unsigned char *decoded = NULL, *footer = NULL, *pae = NULL, *p;
	size_t payload_b64_len = 0, decoded_len = 0, footer_len = 0, msg_len = 0, pae_len;
	EVP_PKEY *key = NULL;
	EVP_MD_CTX *ctx = NULL;

	rc = (token != NULL) && (pubkey != NULL) && (message != NULL);

	if (rc) {
		*message = NULL;
		rc = strncmp(token, PASETO_V4_PUBLIC_HEADER, PASETO_V4_PUBLIC_HEADER_LEN) == 0;
	}

	/* Split the token into payload and optional footer; extra separators are invalid */
	if (rc) {
		payload_b64 = token + PASETO_V4_PUBLIC_HEADER_LEN;
		separator   = strchr(payload_b64, '.');

		if (separator) {
			payload_b64_len = (size_t) (separator - payload_b64);
			footer_b64      = separator + 1;
			rc = (*footer_b64 != '\0') && (strchr(footer_b64, '.') == NULL);
		} else {
			payload_b64_len = strlen(payload_b64);
		}

		if (rc)
			rc = (payload_b64_len > 0);
	}

	if (rc) {
		payload_copy = (char *) xmalloc(payload_b64_len + 1);
		memcpy(payload_copy, payload_b64, payload_b64_len);
		payload_copy[payload_b64_len] = '\0';

		rc = susshi_unbase64(payload_copy, &decoded, &decoded_len);
	}

	if (rc)
		rc = (decoded_len >= PASETO_V4_PUBLIC_SIGNATURE_BYTES);

	if (rc && footer_b64)
		rc = susshi_unbase64(footer_b64, &footer, &footer_len);

	/* Build the Pre-Authentication Encoding: PAE([header, message, footer, implicit]) */
	if (rc) {
		msg_len = decoded_len - PASETO_V4_PUBLIC_SIGNATURE_BYTES;
		pae_len = (5 * 8) + PASETO_V4_PUBLIC_HEADER_LEN + msg_len + footer_len;

		pae = (unsigned char *) xmalloc(pae_len);
		p = pae;
		paseto_le64(4, p);                                        p += 8;
		paseto_le64(PASETO_V4_PUBLIC_HEADER_LEN, p);              p += 8;
		memcpy(p, PASETO_V4_PUBLIC_HEADER, PASETO_V4_PUBLIC_HEADER_LEN);
		                                                          p += PASETO_V4_PUBLIC_HEADER_LEN;
		paseto_le64(msg_len, p);                                  p += 8;
		memcpy(p, decoded, msg_len);                              p += msg_len;
		paseto_le64(footer_len, p);                               p += 8;
		if (footer_len > 0) {
			memcpy(p, footer, footer_len);                        p += footer_len;
		}
		paseto_le64(0, p);

		key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubkey, SUSSHI_PASETO_V4_PUBLIC_PUBKEY_BYTES);
		ctx = EVP_MD_CTX_new();
		rc = (key != NULL) && (ctx != NULL);
	}

	if (rc)
		rc = (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1);

	if (rc)
		rc = (EVP_DigestVerify(ctx, decoded + msg_len, PASETO_V4_PUBLIC_SIGNATURE_BYTES, pae, pae_len) == 1);

	if (rc) {
		*message = (unsigned char *) xmalloc(msg_len + 1);
		memcpy(*message, decoded, msg_len);
		(*message)[msg_len] = '\0';

		if (message_len)
			*message_len = msg_len;
	}

	if (ctx)
		EVP_MD_CTX_free(ctx);
	if (key)
		EVP_PKEY_free(key);
	if (pae)
		xfree(pae);
	if (footer)
		xfree(footer);
	if (decoded)
		xfree(decoded);
	if (payload_copy)
		xfree(payload_copy);

	return rc;
}

/*! @} */
