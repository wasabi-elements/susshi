/*!
 *
 * @brief		Shared Library Tests - Hash
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
 * @date		2026-03-06
 *
 * @defgroup 	tests_shared_hash	Tests for shared Library | Hash
 * @{
 */

#include "shared/common.h"
#include "shared/hash.h"
#include "common.h"

void fatal(const char *fmt,...);
void sha256_known_vector_abc(void);
void sha256_known_vector_empty(void);
void sha256_deterministic(void);
void sha256_different_inputs_differ(void);
void display_hash_blob_prefix(void);
void display_hash_blob_no_padding(void);
void display_hash_blob_deterministic(void);
void display_hash_blob_different_inputs_differ(void);
void display_hash_blob_empty(void);

void fatal(const char *fmt,...) {}
void setUp(void) {}
void tearDown(void) {}


void sha256_known_vector_abc(void) {
	unsigned char expected[SHA256_DIGEST_LENGTH];
	unsigned char actual[SHA256_DIGEST_LENGTH];

	SHA256((const unsigned char *)"abc", 3, expected);
	susshi_hash_sha256("abc", 3, actual);
	TEST_ASSERT_EQUAL_MEMORY(expected, actual, SHA256_DIGEST_LENGTH);
}


void sha256_known_vector_empty(void) {
	unsigned char expected[SHA256_DIGEST_LENGTH];
	unsigned char actual[SHA256_DIGEST_LENGTH];

	SHA256((const unsigned char *)"", 0, expected);
	susshi_hash_sha256("", 0, actual);
	TEST_ASSERT_EQUAL_MEMORY(expected, actual, SHA256_DIGEST_LENGTH);
}


void sha256_deterministic(void) {
	unsigned char hash1[SHA256_DIGEST_LENGTH];
	unsigned char hash2[SHA256_DIGEST_LENGTH];

	susshi_hash_sha256("hello world", 11, hash1);
	susshi_hash_sha256("hello world", 11, hash2);
	TEST_ASSERT_EQUAL_MEMORY(hash1, hash2, SHA256_DIGEST_LENGTH);
}


void sha256_different_inputs_differ(void) {
	unsigned char hash1[SHA256_DIGEST_LENGTH];
	unsigned char hash2[SHA256_DIGEST_LENGTH];

	susshi_hash_sha256("foo", 3, hash1);
	susshi_hash_sha256("bar", 3, hash2);
	TEST_ASSERT_NOT_EQUAL(0, memcmp(hash1, hash2, SHA256_DIGEST_LENGTH));
}


void display_hash_blob_prefix(void) {
	const char *fp = susshi_display_hash_from_blob("test", 4);

	TEST_ASSERT_NOT_NULL(fp);
	TEST_ASSERT_EQUAL_INT(0, strncmp("SHA256:", fp, 7));

	free((void *) fp);
}


void display_hash_blob_no_padding(void) {
	/* The fingerprint must not contain any Base64 padding characters */
	const char *fp = susshi_display_hash_from_blob("test", 4);

	TEST_ASSERT_NOT_NULL(fp);
	TEST_ASSERT_NULL(strchr(fp, '='));

	free((void *) fp);
}


void display_hash_blob_deterministic(void) {
	const char *fp1 = susshi_display_hash_from_blob("hello", 5);
	const char *fp2 = susshi_display_hash_from_blob("hello", 5);

	TEST_ASSERT_NOT_NULL(fp1);
	TEST_ASSERT_NOT_NULL(fp2);
	TEST_ASSERT_EQUAL_STRING(fp1, fp2);

	free((void *) fp1);
	free((void *) fp2);
}


void display_hash_blob_different_inputs_differ(void) {
	const char *fp1 = susshi_display_hash_from_blob("foo", 3);
	const char *fp2 = susshi_display_hash_from_blob("bar", 3);

	TEST_ASSERT_NOT_NULL(fp1);
	TEST_ASSERT_NOT_NULL(fp2);
	TEST_ASSERT_NOT_EQUAL(0, strcmp(fp1, fp2));

	free((void *) fp1);
	free((void *) fp2);
}


void display_hash_blob_empty(void) {
	/* An empty blob is still a valid input — SHA-256 is defined for zero bytes */
	const char *fp = susshi_display_hash_from_blob("", 0);

	TEST_ASSERT_NOT_NULL(fp);
	TEST_ASSERT_EQUAL_INT(0, strncmp("SHA256:", fp, 7));
	TEST_ASSERT_NULL(strchr(fp, '='));

	free((void *) fp);
}


int main(void) {
	UNITY_BEGIN();

	RUN_TEST(sha256_known_vector_abc);
	RUN_TEST(sha256_known_vector_empty);
	RUN_TEST(sha256_deterministic);
	RUN_TEST(sha256_different_inputs_differ);
	RUN_TEST(display_hash_blob_prefix);
	RUN_TEST(display_hash_blob_no_padding);
	RUN_TEST(display_hash_blob_deterministic);
	RUN_TEST(display_hash_blob_different_inputs_differ);
	RUN_TEST(display_hash_blob_empty);

	return UNITY_END();
}

/*! @} */
