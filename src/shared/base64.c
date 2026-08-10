/*!
 *
 * @brief       Base64 Encoding and Decoding methods
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
 * @date        2026-02-01
 *
 * @defgroup    base64 Base64 methods
 * @{
 */

#include "shared/common.h"
#include "shared/base64.h"

/*!
 * @brief       Encode binary data as a standard (padded) Base64 string
 *
 * On success, a heap-allocated, null-terminated Base64 string is written to @p *output.
 * The caller is responsible for freeing it. On failure, @p *output is set to @c NULL.
 *
 * @param       input           Binary data to encode; must not be @c NULL
 * @param       input_len       Length of @p input in bytes
 * @param       output          Receives a pointer to the allocated Base64 string; must not be @c NULL
 * @param       output_len      If non-NULL, receives the length of the encoded string (excluding null terminator)
 *
 * @return      @c true on success, @c false on invalid arguments or allocation/encoding failure
 */

bool
susshi_base64(const unsigned char *input, size_t input_len, char **output, size_t *output_len) {
	int actual_len;
	size_t encoded_len;

	if (!input || !output)
		return false;

	encoded_len = 4 * ((input_len + 2) / 3);

	*output = (char *) xmalloc(encoded_len + 1);
	if (!*output)
		return false;

	actual_len = EVP_EncodeBlock((unsigned char *) *output, input, input_len);

	if (actual_len < 0) {
		xfree(*output);
		*output = NULL;
		return false;
	}

	(*output)[actual_len] = '\0';

	if (output_len)
		*output_len = actual_len;

	return true;
}


/*!
 * @brief       Normalize a Base64 or Base64URL string to padded standard Base64
 *
 * Translates Base64URL characters (@c '-' → @c '+', @c '_' → @c '/')
 * and appends the @c '=' padding characters required by RFC 4648 §4 when
 * they are absent.  The result is a heap-allocated, null-terminated standard
 * Base64 string suitable for passing directly to an RFC 4648-compliant decoder.
 *
 * On success, the allocated string is written to @p *output and the caller is
 * responsible for freeing it.  On failure, @p *output is set to @c NULL.
 *
 * @param       input       Null-terminated Base64 or Base64URL string, with or
 *                          without trailing @c '=' padding; must not be @c NULL
 * @param       output      Receives a pointer to the allocated normalized string;
 *                          must not be @c NULL
 * @param       output_len  If non-NULL, receives the length of the normalized
 *                          string (excluding the null terminator)
 *
 * @return      @c true on success, @c false on invalid arguments or allocation
 *              failure
 */

bool
susshi_base64url_normalize(const char *input, char **output, size_t *output_len) {
	size_t input_len, padding, padded_len;
	char *normalized;

	if (!input || !output)
		return false;

	input_len = strlen(input);

	/* Determine padding needed; a remainder of 1 is never valid */
	switch (input_len % 4) {
	case 0: padding = 0; break;
	case 2: padding = 2; break;
	case 3: padding = 1; break;
	default: return false;
	}

	/* Validate '=' placement on the input before allocating */
	for (size_t i = 0; i < (input_len > 2 ? input_len - 2 : 0); i++) {
		if (input[i] == '=')
			return false;
	}
	if (padding == 0 && input_len >= 2
			&& input[input_len - 2] == '=' && input[input_len - 1] != '=')
		return false;

	padded_len = input_len + padding;

	normalized = (char *) xmalloc(padded_len + 1);
	if (!normalized)
		return false;

	/* Translate Base64URL chars; standard chars pass through unchanged */
	for (size_t i = 0; i < input_len; i++) {
		char c = input[i];
		if      (c == '-') c = '+';
		else if (c == '_') c = '/';
		normalized[i] = c;
	}
	memset(normalized + input_len, '=', padding);
	normalized[padded_len] = '\0';

	*output = normalized;
	if (output_len)
		*output_len = padded_len;

	return true;
}


/*!
 * @brief       Decode a Base64 or Base64URL string into binary data
 *
 * Accepts standard Base64 (RFC 4648 §4) as well as Base64URL (RFC 4648 §5,
 * using @c '-' in place of @c '+' and @c '_' in place of @c '/').
 * Trailing @c '=' padding is optional — it is computed from the input length
 * when absent.
 *
 * On success, a heap-allocated buffer containing the decoded bytes is written
 * to @p *output.  The caller is responsible for freeing it.  On failure,
 * @p *output is set to @c NULL.
 *
 * @param       input           Null-terminated Base64 or Base64URL string to
 *                              decode; must not be @c NULL
 * @param       output          Receives a pointer to the allocated decoded
 *                              buffer; must not be @c NULL
 * @param       output_len      If non-NULL, receives the number of decoded bytes
 *
 * @return      @c true on success, @c false on invalid arguments or
 *              allocation/decoding failure
 */

bool
susshi_unbase64(const char *input, unsigned char **output, size_t *output_len) {
	char *normalized;
	size_t normalized_len, total_padding;
	int decoded_len;

	if (!input || !output)
		return false;

	if (!susshi_base64url_normalize(input, &normalized, &normalized_len))
		return false;

	/* EVP_DecodeBlock overcounts by the number of trailing '=' chars */
	total_padding = 0;
	if (normalized_len >= 1 && normalized[normalized_len - 1] == '=') total_padding++;
	if (normalized_len >= 2 && normalized[normalized_len - 2] == '=') total_padding++;

	*output = (unsigned char *) xmalloc(3 * (normalized_len / 4));
	if (!*output) {
		xfree(normalized);
		return false;
	}

	decoded_len = EVP_DecodeBlock(*output, (const unsigned char *) normalized, (int) normalized_len);
	xfree(normalized);

	if (decoded_len < 0) {
		xfree(*output);
		*output = NULL;
		return false;
	}

	decoded_len -= (int) total_padding;

	if (output_len)
		*output_len = decoded_len;

	return true;
}

/*! @} */
