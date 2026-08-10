/*!
 *
 * @brief		Shared Library Tests - Memcrypt
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
 * @defgroup 	tests_shared_memcrypt	Tests for shared Library | Memcrypt
 * @{
 */

#include "shared/common.h"
#include "shared/memcrypt.h"
#include "common.h"

void fatal(const char *fmt,...);
void init_memcrypt(void);
void memcrypt_same_keys(void);
void memcrypt_decrypt_from_chef(void);
void memcrypt_encrypt_decrypt(void);

#define PLAINTEXT "This is plaintext.\n"
#define ENCRYPTED_FROM_CHEF "XER5En7OlLNrC/o+GZIe8mfc59R+aJ/Em4baEaSVTvLv9ay9B8RDKSBb1hZgMdTVmA=="
#define ENCRYPTED_FROM_CHEF_WITH_KEY "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define DECRYPTED_FROM_CHEF "This is a text string"

void fatal(const char *fmt,...) {}

void setUp(void) {}

void tearDown(void) {}

void init_memcrypt(void) {
	bool rc = false;

	rc = susshi_memcrypt_init();

	TEST_ASSERT_EQUAL(true, rc);
}

void memcrypt_same_keys(void) {
	bstring my_key = NULL;
	bstring first_key = NULL;

	for (int i = 0; i < 20; i++) {
		my_key = susshi_memcrypt_key();

		TEST_ASSERT_NOT_NULL(my_key);
		TEST_ASSERT_EQUAL_INT(SUSSHI_MEMCRYPT_KEY_LEN, blength(my_key));

		if (i == 0) {
			first_key = bstrcpy(my_key);
			printf("First KEY: %s\n", bdata(first_key));
			TEST_ASSERT_NOT_NULL(first_key);
		}

		if (my_key)
			printf("%0d. KEY: %s\n", i, bdata(my_key));

		TEST_ASSERT_EQUAL(0, bstrcmp(first_key, my_key));

		susshi_memcrypt_key_free(my_key);
	}
}

void memcrypt_decrypt_from_chef(void) {
	bstring decrypted = NULL;

	decrypted = susshi_memcrypt_decrypt_bstring(
		bfromcstr(ENCRYPTED_FROM_CHEF), bfromcstr(ENCRYPTED_FROM_CHEF_WITH_KEY));

	TEST_ASSERT_NOT_NULL(decrypted);
	TEST_ASSERT_EQUAL_INT(strlen(DECRYPTED_FROM_CHEF), blength(decrypted));
	TEST_ASSERT_EQUAL_STRING(DECRYPTED_FROM_CHEF, bdata(decrypted));
}


void memcrypt_encrypt_decrypt(void) {
	bstring plaintext = NULL;
	bstring encrypted = NULL;

	plaintext = bfromcstr(PLAINTEXT);

	printf("Plaintext: %s\n", bdata(plaintext));

	encrypted = susshi_memcrypt_encrypt_bstring(plaintext, NULL);
	printf("Encrypted: %s\n", bdata(encrypted));

	TEST_ASSERT_NOT_NULL(encrypted);

	bdestroy(plaintext);
	plaintext = susshi_memcrypt_decrypt_bstring(encrypted, NULL);
	printf("Decrypted: %s\n", bdata(plaintext));

	TEST_ASSERT_EQUAL_STRING(PLAINTEXT, bdata(plaintext));
	TEST_ASSERT_EQUAL(strlen(PLAINTEXT), blength(plaintext));
}

int main(void) {
	UNITY_BEGIN();

	RUN_TEST(init_memcrypt);
	RUN_TEST(memcrypt_same_keys);
	RUN_TEST(memcrypt_decrypt_from_chef);
	RUN_TEST(memcrypt_encrypt_decrypt);

	return UNITY_END();
}
