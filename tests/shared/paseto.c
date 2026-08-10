/*!
 *
 * @brief		shared Tests - PASETO v4.public methods
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
 * @date		2026-07-05
 *
 * @defgroup 	tests_shared_paseto	Tests for shared | PASETO
 * @{
 */

#include "shared/common.h"
#include "shared/paseto.h"
#include "common.h"

void fatal(const char *fmt,...);
void paseto_verify_official_vector_4_s_1(void);
void paseto_verify_official_vector_without_length(void);
void paseto_verify_token_with_footer(void);
void paseto_reject_tampered_payload(void);
void paseto_reject_wrong_public_key(void);
void paseto_reject_malformed_tokens(void);
void paseto_reject_null_arguments(void);

void fatal(const char *fmt,...) {}
void setUp(void) {}
void tearDown(void) {}

/* Official PASETO test vector 4-S-1, see https://github.com/paseto-standard/test-vectors (v4.json) */
static const unsigned char vector_pubkey[SUSSHI_PASETO_V4_PUBLIC_PUBKEY_BYTES] = {
	0x1e, 0xb9, 0xdb, 0xbb, 0xbc, 0x04, 0x7c, 0x03, 0xfd, 0x70, 0x60, 0x4e, 0x00, 0x71, 0xf0, 0x98,
	0x7e, 0x16, 0xb2, 0x8b, 0x75, 0x72, 0x25, 0xc1, 0x1f, 0x00, 0x41, 0x5d, 0x0e, 0x20, 0xb1, 0xa2
};

#define VECTOR_PAYLOAD	"{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"
#define VECTOR_TOKEN	"v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA"

/* Same payload and key as 4-S-1, signed with footer {"kid":"test"} */
#define FOOTER_TOKEN	"v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9vbgdOxEnLJ3k0qCtL0LjMApZEI21mltXutA-_yoVHreUZLKFJbO0cSl6Es3N0ML95buBf1LqxoZ3Uw1YlRHiCg.eyJraWQiOiJ0ZXN0In0"

/* 63 decoded bytes — shorter than an Ed25519 signature */
#define SHORT_TOKEN		"v4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


void paseto_verify_official_vector_4_s_1(void) {
	unsigned char *message = NULL;
	size_t message_len = 0;

	TEST_ASSERT_TRUE(susshi_paseto_v4_public_verify(VECTOR_TOKEN, vector_pubkey, &message, &message_len));
	TEST_ASSERT_NOT_NULL(message);
	TEST_ASSERT_EQUAL_size_t(strlen(VECTOR_PAYLOAD), message_len);
	TEST_ASSERT_EQUAL_STRING(VECTOR_PAYLOAD, (const char *) message);

	xfree(message);
}


void paseto_verify_official_vector_without_length(void) {
	unsigned char *message = NULL;

	TEST_ASSERT_TRUE(susshi_paseto_v4_public_verify(VECTOR_TOKEN, vector_pubkey, &message, NULL));
	TEST_ASSERT_NOT_NULL(message);
	TEST_ASSERT_EQUAL_STRING(VECTOR_PAYLOAD, (const char *) message);

	xfree(message);
}


void paseto_verify_token_with_footer(void) {
	unsigned char *message = NULL;
	size_t message_len = 0;

	TEST_ASSERT_TRUE(susshi_paseto_v4_public_verify(FOOTER_TOKEN, vector_pubkey, &message, &message_len));
	TEST_ASSERT_NOT_NULL(message);
	TEST_ASSERT_EQUAL_STRING(VECTOR_PAYLOAD, (const char *) message);

	xfree(message);
}


void paseto_reject_tampered_payload(void) {
	unsigned char *message = NULL;
	char tampered[256];

	strlcpy(tampered, VECTOR_TOKEN, sizeof(tampered));
	tampered[20] = (tampered[20] == 'a') ? 'b' : 'a';

	TEST_ASSERT_FALSE(susshi_paseto_v4_public_verify(tampered, vector_pubkey, &message, NULL));
	TEST_ASSERT_NULL(message);
}


void paseto_reject_wrong_public_key(void) {
	unsigned char *message = NULL;
	unsigned char wrong_pubkey[SUSSHI_PASETO_V4_PUBLIC_PUBKEY_BYTES];

	memcpy(wrong_pubkey, vector_pubkey, sizeof(wrong_pubkey));
	wrong_pubkey[0] ^= 0xff;

	TEST_ASSERT_FALSE(susshi_paseto_v4_public_verify(VECTOR_TOKEN, wrong_pubkey, &message, NULL));
	TEST_ASSERT_NULL(message);
}


void paseto_reject_malformed_tokens(void) {
	unsigned char *message = NULL;
	int i;

	const char *malformed[] = {
		"",
		"v4.public",
		"v4.public.",
		"v2.public.abc",
		"v4.local.abc",
		"v4.public.!!not-base64!!",
		VECTOR_TOKEN ".Zm9vdGVy.ZXh0cmE",
		VECTOR_TOKEN ".",
		SHORT_TOKEN,
		NULL
	};

	for (i = 0; malformed[i] != NULL; i++) {
		message = NULL;
		TEST_ASSERT_FALSE_MESSAGE(susshi_paseto_v4_public_verify(malformed[i], vector_pubkey, &message, NULL), malformed[i]);
		TEST_ASSERT_NULL(message);
	}
}


void paseto_reject_null_arguments(void) {
	unsigned char *message = NULL;

	TEST_ASSERT_FALSE(susshi_paseto_v4_public_verify(NULL, vector_pubkey, &message, NULL));
	TEST_ASSERT_FALSE(susshi_paseto_v4_public_verify(VECTOR_TOKEN, NULL, &message, NULL));
	TEST_ASSERT_FALSE(susshi_paseto_v4_public_verify(VECTOR_TOKEN, vector_pubkey, NULL, NULL));
}


int main(void) {
	UNITY_BEGIN();

	RUN_TEST(paseto_verify_official_vector_4_s_1);
	RUN_TEST(paseto_verify_official_vector_without_length);
	RUN_TEST(paseto_verify_token_with_footer);
	RUN_TEST(paseto_reject_tampered_payload);
	RUN_TEST(paseto_reject_wrong_public_key);
	RUN_TEST(paseto_reject_malformed_tokens);
	RUN_TEST(paseto_reject_null_arguments);

	return UNITY_END();
}

/*! @} */
