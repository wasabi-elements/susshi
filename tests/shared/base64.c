/*!
 *
 * @brief		Shared Library Tests - Base64
 *
 * @ingroup		tests_shared
 *
 * @copyright	Copyright (C) 2026 Wasabi Elements GmbH
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
 * @author		Oliver Rauscher <oliver@susshi.io>
 * @date		2026-02-01
 *
 * @defgroup 	tests_shared_base64	Tests for shared Library | Base64
 * @{
 */

#include "shared/common.h"
#include "shared/base64.h"
#include "common.h"

void encode_base64_empty_params(void);
void encode_base64_valid(void);
void decode_base64_empty_params(void);
void decode_base64_valid(void);
void decode_base64_roundtrip(void);
void decode_base64_invalid_chars(void);
void decode_base64_bad_length(void);
void decode_base64_misplaced_padding(void);
void decode_base64url_chars(void);
void decode_base64_no_padding_1(void);
void decode_base64_no_padding_2(void);
void decode_base64url_no_padding(void);
void normalize_base64url_empty_params(void);
void normalize_base64url_noop(void);
void normalize_base64url_chars(void);
void normalize_base64url_no_padding_1(void);
void normalize_base64url_no_padding_2(void);
void normalize_base64url_combined(void);

#define PLAINTEXT "This is plaintext.\n"
#define BASE64TEXT "VGhpcyBpcyBwbGFpbnRleHQuCg=="

const char *text = PLAINTEXT;

char *base64 = NULL;
char *decoded = NULL;

size_t base64_len;
size_t decoded_len;

void fatal(const char *fmt,...) {}
void setUp(void) {}
void tearDown(void) {}

void encode_base64_empty_params(void) {
	bool rc = false;

	rc = susshi_base64(NULL, strlen(PLAINTEXT), &base64, &base64_len);
	TEST_ASSERT_EQUAL(false, rc);

	rc = susshi_base64((unsigned char *) text, strlen(text), NULL, NULL);
	TEST_ASSERT_EQUAL(false, rc);
}


void decode_base64_empty_params(void) {
	bool rc = false;

	rc = susshi_unbase64(NULL, (unsigned char**) &decoded, NULL);
	TEST_ASSERT_EQUAL(false, rc);

	rc = susshi_unbase64(base64, NULL, NULL);
	TEST_ASSERT_EQUAL(false, rc);
}


void encode_base64_valid(void) {
	char *out = NULL;
	size_t out_len = 0;

	bool rc = susshi_base64((const unsigned char *) PLAINTEXT, strlen(PLAINTEXT), &out, &out_len);
	TEST_ASSERT_EQUAL(true, rc);
	TEST_ASSERT_NOT_NULL(out);
	TEST_ASSERT_EQUAL_STRING(BASE64TEXT, out);
	TEST_ASSERT_EQUAL(strlen(BASE64TEXT), out_len);

	free(out);
}


void decode_base64_valid(void) {
	unsigned char *out = NULL;
	size_t out_len = 0;

	bool rc = susshi_unbase64(BASE64TEXT, &out, &out_len);
	TEST_ASSERT_EQUAL(true, rc);
	TEST_ASSERT_NOT_NULL(out);
	TEST_ASSERT_EQUAL(strlen(PLAINTEXT), out_len);
	TEST_ASSERT_EQUAL_STRING(PLAINTEXT, (char *) out);

	free(out);
}


void decode_base64_roundtrip(void) {
	char *rt_encoded = NULL;
	unsigned char *rt_decoded = NULL;
	size_t rt_encoded_len = 0, rt_decoded_len = 0;

	bool rc = susshi_base64((const unsigned char *) PLAINTEXT, strlen(PLAINTEXT), &rt_encoded, &rt_encoded_len);
	TEST_ASSERT_EQUAL(true, rc);
	TEST_ASSERT_NOT_NULL(rt_encoded);

	rc = susshi_unbase64(rt_encoded, &rt_decoded, &rt_decoded_len);
	TEST_ASSERT_EQUAL(true, rc);
	TEST_ASSERT_NOT_NULL(rt_decoded);
	TEST_ASSERT_EQUAL(strlen(PLAINTEXT), rt_decoded_len);
	TEST_ASSERT_EQUAL_STRING(PLAINTEXT, (char *) rt_decoded);

	free(rt_encoded);
	free(rt_decoded);
}


void decode_base64_invalid_chars(void) {
	/* Characters outside the base64 alphabet must be rejected */
	unsigned char *out = NULL;
	bool rc = susshi_unbase64("!!!!!", &out, NULL);
	TEST_ASSERT_EQUAL(false, rc);
	TEST_ASSERT_NULL(out);
}


void decode_base64_bad_length(void) {
	/* A length that is 1 mod 4 is never valid Base64 or Base64URL */
	unsigned char *out = NULL;
	bool rc = susshi_unbase64("a", &out, NULL);
	TEST_ASSERT_EQUAL(false, rc);
	TEST_ASSERT_NULL(out);
}


void decode_base64_misplaced_padding(void) {
	/* Padding character in the middle of input must be rejected */
	unsigned char *out = NULL;
	bool rc = susshi_unbase64("VG=p", &out, NULL);
	TEST_ASSERT_EQUAL(false, rc);
	TEST_ASSERT_NULL(out);
}


void decode_base64url_chars(void) {
	/* '-' and '_' are the Base64URL equivalents of '+' and '/' */
	/* "-__-" is the Base64URL encoding of { 0xFB, 0xFF, 0xFE } */
	unsigned char *out = NULL;
	size_t out_len = 0;
	const unsigned char expected[] = { 0xFB, 0xFF, 0xFE };

	bool rc = susshi_unbase64("-__-", &out, &out_len);
	TEST_ASSERT_EQUAL(true, rc);
	TEST_ASSERT_NOT_NULL(out);
	TEST_ASSERT_EQUAL(3, out_len);
	TEST_ASSERT_EQUAL_MEMORY(expected, out, 3);

	free(out);
}


void decode_base64_no_padding_1(void) {
	/* Remainder 3: one '=' of padding is missing — "Zm9vYmE" -> "fooba" */
	unsigned char *out = NULL;
	size_t out_len = 0;

	bool rc = susshi_unbase64("Zm9vYmE", &out, &out_len);
	TEST_ASSERT_EQUAL(true, rc);
	TEST_ASSERT_NOT_NULL(out);
	TEST_ASSERT_EQUAL(5, out_len);
	TEST_ASSERT_EQUAL_MEMORY("fooba", out, 5);

	free(out);
}


void decode_base64_no_padding_2(void) {
	/* Remainder 2: two '=' of padding are missing — "Zg" -> "f" */
	unsigned char *out = NULL;
	size_t out_len = 0;

	bool rc = susshi_unbase64("Zg", &out, &out_len);
	TEST_ASSERT_EQUAL(true, rc);
	TEST_ASSERT_NOT_NULL(out);
	TEST_ASSERT_EQUAL(1, out_len);
	TEST_ASSERT_EQUAL_MEMORY("f", out, 1);

	free(out);
}


void decode_base64url_no_padding(void) {
	/* Combined: Base64URL chars ('-', '_') and missing padding */
	/* "-_8" is the Base64URL encoding (no padding) of { 0xFB, 0xFF } */
	unsigned char *out = NULL;
	size_t out_len = 0;
	const unsigned char expected[] = { 0xFB, 0xFF };

	bool rc = susshi_unbase64("-_8", &out, &out_len);
	TEST_ASSERT_EQUAL(true, rc);
	TEST_ASSERT_NOT_NULL(out);
	TEST_ASSERT_EQUAL(2, out_len);
	TEST_ASSERT_EQUAL_MEMORY(expected, out, 2);

	free(out);
}


void normalize_base64url_empty_params(void) {
	char *out = NULL;

	bool rc = susshi_base64url_normalize(NULL, &out, NULL);
	TEST_ASSERT_EQUAL(false, rc);

	rc = susshi_base64url_normalize(BASE64TEXT, NULL, NULL);
	TEST_ASSERT_EQUAL(false, rc);
}


void normalize_base64url_noop(void) {
	/* Already-standard padded Base64 must pass through unchanged */
	char *out = NULL;
	size_t out_len = 0;

	bool rc = susshi_base64url_normalize(BASE64TEXT, &out, &out_len);
	TEST_ASSERT_EQUAL(true, rc);
	TEST_ASSERT_NOT_NULL(out);
	TEST_ASSERT_EQUAL_STRING(BASE64TEXT, out);
	TEST_ASSERT_EQUAL(strlen(BASE64TEXT), out_len);

	free(out);
}


void normalize_base64url_chars(void) {
	/* '-' and '_' are translated to '+' and '/' */
	char *out = NULL;

	bool rc = susshi_base64url_normalize("-__-", &out, NULL);
	TEST_ASSERT_EQUAL(true, rc);
	TEST_ASSERT_EQUAL_STRING("+//+", out);

	free(out);
}


void normalize_base64url_no_padding_1(void) {
	/* Remainder 3: one missing '=' is appended — "Zm9vYmE" -> "Zm9vYmE=" */
	char *out = NULL;
	size_t out_len = 0;

	bool rc = susshi_base64url_normalize("Zm9vYmE", &out, &out_len);
	TEST_ASSERT_EQUAL(true, rc);
	TEST_ASSERT_NOT_NULL(out);
	TEST_ASSERT_EQUAL_STRING("Zm9vYmE=", out);
	TEST_ASSERT_EQUAL(8, out_len);

	free(out);
}


void normalize_base64url_no_padding_2(void) {
	/* Remainder 2: two missing '=' are appended — "Zg" -> "Zg==" */
	char *out = NULL;
	size_t out_len = 0;

	bool rc = susshi_base64url_normalize("Zg", &out, &out_len);
	TEST_ASSERT_EQUAL(true, rc);
	TEST_ASSERT_NOT_NULL(out);
	TEST_ASSERT_EQUAL_STRING("Zg==", out);
	TEST_ASSERT_EQUAL(4, out_len);

	free(out);
}


void normalize_base64url_combined(void) {
	/* URL chars translated and missing padding appended in one step */
	/* "-_8" (Base64URL, no padding) -> "+/8=" (standard Base64) */
	char *out = NULL;

	bool rc = susshi_base64url_normalize("-_8", &out, NULL);
	TEST_ASSERT_EQUAL(true, rc);
	TEST_ASSERT_EQUAL_STRING("+/8=", out);

	free(out);
}


int main(void) {
	UNITY_BEGIN();

	RUN_TEST(encode_base64_empty_params);
	RUN_TEST(encode_base64_valid);
	RUN_TEST(decode_base64_empty_params);
	RUN_TEST(decode_base64_valid);
	RUN_TEST(decode_base64_roundtrip);
	RUN_TEST(decode_base64_invalid_chars);
	RUN_TEST(decode_base64_bad_length);
	RUN_TEST(decode_base64_misplaced_padding);
	RUN_TEST(decode_base64url_chars);
	RUN_TEST(decode_base64_no_padding_1);
	RUN_TEST(decode_base64_no_padding_2);
	RUN_TEST(decode_base64url_no_padding);
	RUN_TEST(normalize_base64url_empty_params);
	RUN_TEST(normalize_base64url_noop);
	RUN_TEST(normalize_base64url_chars);
	RUN_TEST(normalize_base64url_no_padding_1);
	RUN_TEST(normalize_base64url_no_padding_2);
	RUN_TEST(normalize_base64url_combined);

	return UNITY_END();
}
