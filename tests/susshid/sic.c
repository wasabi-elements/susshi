/*!
 *
 * @brief		susshid Tests - SIC methods
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
 * @defgroup 	tests_susshid_sic	Tests for susshid | SIC
 * @{
 */

#include "susshid/common.h"
#include <unity/unity.h>

bool sic_parse_url(const char *c_url, const char *port, const char *c_host, const char *c_id, const char *c_psk, const char *c_spki);
void sic_parse_url1(void);
void sic_parse_url2(void);
void sic_parse_url3(void);
void sic_parse_url4(void);
void sic_parse_url5(void);
void sic_parse_url6(void);

void setUp(void) {
	susshi_memcrypt_init();
	susshi_cfg_init();
	chef_cfg_init();
}

void tearDown(void) {
	susshi_cfg_free();
	susshi_memcrypt_cleanup();
}

#define SIC_URL_HOST "https://susshi-chef.susshi.io"
#define SIC_URL_PORT "8443"
#define SIC_URL_SPKI_PATH "sha256::6SVkS3+wigHWxDK8EaGL3sBND9h5PHRwzfj0Bl6oYZA="
#define SIC_URL_SPKI "sha256//6SVkS3+wigHWxDK8EaGL3sBND9h5PHRwzfj0Bl6oYZA="
#define SIC_URL_ID "0001"
#define SIC_URL_PSK "6bdaf9cdb3c80bf9f51fa7f52aa7f84e"
#define SIC_URL SIC_URL_HOST "/" SIC_URL_ID "/" SIC_URL_PSK "/" SIC_URL_SPKI_PATH

void sic_parse_url1(void) {
	bool rc = false;

	rc = sic_parse_url(SIC_URL, SIC_URL_PORT, SIC_URL_HOST, SIC_URL_ID, SIC_URL_PSK, SIC_URL_SPKI);
	TEST_ASSERT_EQUAL(true, rc);
	TEST_ASSERT_EQUAL_STRING(SIC_URL_HOST ":" SIC_URL_PORT, bdata(chef_cfg.chef_server_urls.all[0]));
	TEST_ASSERT_EQUAL(true, susshi_sic_validate_params(false));
}

#undef SIC_URL
#undef SIC_URL_HOST
#undef SIC_URL_PORT
#undef SIC_URL_ID
#undef SIC_URL_SPKI
#undef SIC_URL_PSK

#define SIC_URL_HOST "http://127.0.0.1:3000"
#define SIC_URL_PORT "3000"
#define SIC_URL_SPKI_PATH "sha256::6SVkS3+wigHWxDK8EaGL3sBND9h5PHRwzfj0Bl6oYZA="
#define SIC_URL_SPKI "sha256//6SVkS3+wigHWxDK8EaGL3sBND9h5PHRwzfj0Bl6oYZA="
#define SIC_URL_ID "0002"
#define SIC_URL_PSK "6bdaf9cdb3c80bf9f51fa7f52aa7f84e"
#define SIC_URL SIC_URL_HOST "/" SIC_URL_ID "/" SIC_URL_PSK "/" SIC_URL_SPKI_PATH

void sic_parse_url2(void) {
	bool rc = false;

	rc = sic_parse_url(SIC_URL, SIC_URL_PORT, SIC_URL_HOST, SIC_URL_ID, SIC_URL_PSK, SIC_URL_SPKI);
	TEST_ASSERT_EQUAL(true, rc);
	TEST_ASSERT_EQUAL_STRING(SIC_URL_HOST, bdata(chef_cfg.chef_server_urls.all[0]));
	TEST_ASSERT_EQUAL(true, susshi_sic_validate_params(false));
}

#undef SIC_URL
#undef SIC_URL_HOST
#undef SIC_URL_PORT
#undef SIC_URL_ID
#undef SIC_URL_SPKI
#undef SIC_URL_PSK


#define SIC_URL_HOST "http://susshi-chef.susshi.io:3000"
#define SIC_URL_PORT "3000"
#define SIC_URL_SPKI_PATH "sha256::6SVkS3+wigHWxDK8EaGL3sBND9h5PHRwzfj0Bl6oYZA="
#define SIC_URL_SPKI "sha256//6SVkS3+wigHWxDK8EaGL3sBND9h5PHRwzfj0Bl6oYZA="
#define SIC_URL_ID "0003"
#define SIC_URL_PSK "6bdaf9cdb3c80bf9f51fa7f52aa7f84e"
#define SIC_URL SIC_URL_HOST "/" SIC_URL_ID "/" SIC_URL_PSK "/" SIC_URL_SPKI_PATH

void sic_parse_url3(void) {
	bool rc = false;

	/* Only http://127.0.0.1 should be allowed */
	rc = sic_parse_url(SIC_URL, SIC_URL_PORT, SIC_URL_HOST, SIC_URL_ID, SIC_URL_PSK, SIC_URL_SPKI);
	TEST_ASSERT_EQUAL(false, rc);
	TEST_ASSERT_EQUAL(false, susshi_sic_validate_params(false));
}

#undef SIC_URL
#undef SIC_URL_HOST
#undef SIC_URL_PORT
#undef SIC_URL_ID
#undef SIC_URL_SPKI
#undef SIC_URL_PSK


#define SIC_URL_SPKI_PATH_COMMON "sha256::6SVkS3+wigHWxDK8EaGL3sBND9h5PHRwzfj0Bl6oYZA="
#define SIC_URL_ID_COMMON "0004"
#define SIC_URL_PSK_COMMON "6bdaf9cdb3c80bf9f51fa7f52aa7f84e"

void sic_parse_url4(void) {
	/* Port number too large (> 65535) must be rejected */
	bstring url = bfromcstr("https://susshi-chef.susshi.io:99999/" SIC_URL_ID_COMMON "/" SIC_URL_PSK_COMMON "/" SIC_URL_SPKI_PATH_COMMON);
	TEST_ASSERT_EQUAL(false, susshi_sic_parse_url(url));
	TEST_ASSERT_EQUAL(false, susshi_sic_validate_params(false));
	bstrWipe(url);
}

void sic_parse_url5(void) {
	/* Non-numeric port must be rejected */
	bstring url = bfromcstr("https://susshi-chef.susshi.io:abc/" SIC_URL_ID_COMMON "/" SIC_URL_PSK_COMMON "/" SIC_URL_SPKI_PATH_COMMON);
	TEST_ASSERT_EQUAL(false, susshi_sic_parse_url(url));
	TEST_ASSERT_EQUAL(false, susshi_sic_validate_params(false));
	bstrWipe(url);
}

void sic_parse_url6(void) {
	/* Port zero must be rejected */
	bstring url = bfromcstr("https://susshi-chef.susshi.io:0/" SIC_URL_ID_COMMON "/" SIC_URL_PSK_COMMON "/" SIC_URL_SPKI_PATH_COMMON);
	TEST_ASSERT_EQUAL(false, susshi_sic_parse_url(url));
	TEST_ASSERT_EQUAL(false, susshi_sic_validate_params(false));
	bstrWipe(url);
}

#undef SIC_URL_SPKI_PATH_COMMON
#undef SIC_URL_ID_COMMON
#undef SIC_URL_PSK_COMMON


bool
sic_parse_url(const char *c_url, const char* port, const char *c_host, const char *c_id, const char *c_psk, const char *c_spki) {
	bool rc = false;
	bstring url = bfromcstr(c_url);

	printf("url: %s\n", bdata(url));

	if ((rc = susshi_sic_parse_url(url))) {
		bstring decrypted = NULL;

		printf("chef_cfg.chef_server_urls.all[0]: %s\n", bdata(chef_cfg.chef_server_urls.all[0]));
		printf("chef_cfg.susshid_id: %s\n", bdata(chef_cfg.susshid_id));
		printf("chef_cfg.sic_psk_memcrypt: %s\n", bdata(chef_cfg.sic_psk_memcrypt));

		decrypted = susshi_memcrypt_decrypt_bstring(chef_cfg.sic_psk_memcrypt, NULL);
		printf("chef_cfg.sic_psk_memcrypt (decrypted): %s\n", bdata(decrypted));
		printf("chef_cfg.sic_spki_sha256: %s\n", bdata(chef_cfg.sic_spki));

		TEST_ASSERT_NOT_NULL(decrypted);
		TEST_ASSERT_EQUAL_STRING(c_id, bdata(chef_cfg.susshid_id));
		TEST_ASSERT_EQUAL_STRING(c_spki, bdata(chef_cfg.sic_spki));
		TEST_ASSERT_EQUAL_STRING(c_psk, bdata(decrypted));

		bstrWipe(decrypted);
	}

	return rc;
}


int main(void) {
	UNITY_BEGIN();

	RUN_TEST(sic_parse_url1);
	RUN_TEST(sic_parse_url2);
	RUN_TEST(sic_parse_url3);
	RUN_TEST(sic_parse_url4);
	RUN_TEST(sic_parse_url5);
	RUN_TEST(sic_parse_url6);

	return UNITY_END();
}
