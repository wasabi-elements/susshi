/*!
 *
 * @brief		Shared Library Tests - Misc
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
 * @defgroup	tests_shared_misc	Tests for shared Library | Misc
 * @{
 */

#include "shared/common.h"
#include "shared/misc.h"
#include "common.h"

void fatal(const char *fmt, ...) {}
void setUp(void) {}
void tearDown(void) {}

/* ------------------------------------------------------------------ chop -- */

void chop_no_newline(void);
void chop_unix_newline(void);
void chop_carriage_return(void);
void chop_newline_at_start(void);
void chop_returns_same_pointer(void);

void chop_no_newline(void) {
	char s[] = "hello";
	chop(s);
	TEST_ASSERT_EQUAL_STRING("hello", s);
}

void chop_unix_newline(void) {
	char s[] = "hello\nworld";
	chop(s);
	TEST_ASSERT_EQUAL_STRING("hello", s);
}

void chop_carriage_return(void) {
	char s[] = "hello\rworld";
	chop(s);
	TEST_ASSERT_EQUAL_STRING("hello", s);
}

void chop_newline_at_start(void) {
	char s[] = "\nhello";
	chop(s);
	TEST_ASSERT_EQUAL_STRING("", s);
}

void chop_returns_same_pointer(void) {
	char s[] = "hello\n";
	TEST_ASSERT_EQUAL_PTR(s, chop(s));
}

/* ----------------------------------------------------------------- a2port -- */

void a2port_valid_ssh(void);
void a2port_zero(void);
void a2port_max(void);
void a2port_too_large(void);
void a2port_negative(void);
void a2port_non_numeric(void);
void a2port_trailing_chars(void);

void a2port_valid_ssh(void) {
	TEST_ASSERT_EQUAL_INT(22, a2port("22"));
}

void a2port_zero(void) {
	TEST_ASSERT_EQUAL_INT(0, a2port("0"));
}

void a2port_max(void) {
	TEST_ASSERT_EQUAL_INT(65535, a2port("65535"));
}

void a2port_too_large(void) {
	TEST_ASSERT_EQUAL_INT(-1, a2port("65536"));
}

void a2port_negative(void) {
	TEST_ASSERT_EQUAL_INT(-1, a2port("-1"));
}

void a2port_non_numeric(void) {
	TEST_ASSERT_EQUAL_INT(-1, a2port("ssh"));
}

void a2port_trailing_chars(void) {
	/* "22abc" must be rejected — not a clean decimal integer */
	TEST_ASSERT_EQUAL_INT(-1, a2port("22abc"));
}

/* --------------------------------------------------------------- strtonum -- */

void strtonum_valid(void);
void strtonum_too_small(void);
void strtonum_too_large(void);
void strtonum_invalid(void);
void strtonum_bad_range(void);
void strtonum_null_errstrp(void);

void strtonum_valid(void) {
	const char *err = "sentinel";
	long long v = strtonum("42", 0, 100, &err);
	TEST_ASSERT_EQUAL_INT64(42, v);
	TEST_ASSERT_NULL(err);
}

void strtonum_too_small(void) {
	const char *err = NULL;
	long long v = strtonum("5", 10, 100, &err);
	TEST_ASSERT_EQUAL_INT64(0, v);
	TEST_ASSERT_NOT_NULL(err);
	TEST_ASSERT_EQUAL_STRING("too small", err);
}

void strtonum_too_large(void) {
	const char *err = NULL;
	long long v = strtonum("200", 0, 100, &err);
	TEST_ASSERT_EQUAL_INT64(0, v);
	TEST_ASSERT_NOT_NULL(err);
	TEST_ASSERT_EQUAL_STRING("too large", err);
}

void strtonum_invalid(void) {
	const char *err = NULL;
	long long v = strtonum("abc", 0, 100, &err);
	TEST_ASSERT_EQUAL_INT64(0, v);
	TEST_ASSERT_NOT_NULL(err);
	TEST_ASSERT_EQUAL_STRING("invalid", err);
}

void strtonum_bad_range(void) {
	/* minval > maxval must yield "invalid" */
	const char *err = NULL;
	long long v = strtonum("50", 100, 0, &err);
	TEST_ASSERT_EQUAL_INT64(0, v);
	TEST_ASSERT_NOT_NULL(err);
	TEST_ASSERT_EQUAL_STRING("invalid", err);
}

void strtonum_null_errstrp(void) {
	/* NULL errstrp must not crash */
	long long v = strtonum("42", 0, 100, NULL);
	TEST_ASSERT_EQUAL_INT64(42, v);
}

/* ---------------------------------------------------------------- convtime -- */

void convtime_null(void);
void convtime_empty(void);
void convtime_seconds_plain(void);
void convtime_seconds_suffix_lower(void);
void convtime_seconds_suffix_upper(void);
void convtime_minutes(void);
void convtime_hours(void);
void convtime_days(void);
void convtime_weeks(void);
void convtime_compound(void);
void convtime_invalid_suffix(void);
void convtime_negative(void);
void convtime_overflow_minutes(void);
void convtime_overflow_hours(void);
void convtime_overflow_days(void);
void convtime_overflow_weeks(void);

void convtime_null(void) {
	TEST_ASSERT_EQUAL_INT(-1, convtime(NULL));
}

void convtime_empty(void) {
	TEST_ASSERT_EQUAL_INT(-1, convtime(""));
}

void convtime_seconds_plain(void) {
	TEST_ASSERT_EQUAL_INT(30, convtime("30"));
}

void convtime_seconds_suffix_lower(void) {
	TEST_ASSERT_EQUAL_INT(30, convtime("30s"));
}

void convtime_seconds_suffix_upper(void) {
	TEST_ASSERT_EQUAL_INT(30, convtime("30S"));
}

void convtime_minutes(void) {
	TEST_ASSERT_EQUAL_INT(120, convtime("2m"));
	TEST_ASSERT_EQUAL_INT(120, convtime("2M"));
}

void convtime_hours(void) {
	TEST_ASSERT_EQUAL_INT(3600, convtime("1h"));
	TEST_ASSERT_EQUAL_INT(3600, convtime("1H"));
}

void convtime_days(void) {
	TEST_ASSERT_EQUAL_INT(86400, convtime("1d"));
	TEST_ASSERT_EQUAL_INT(86400, convtime("1D"));
}

void convtime_weeks(void) {
	TEST_ASSERT_EQUAL_INT(604800, convtime("1w"));
	TEST_ASSERT_EQUAL_INT(604800, convtime("1W"));
}

void convtime_compound(void) {
	/* 1h30m = 3600 + 1800 = 5400 */
	TEST_ASSERT_EQUAL_INT(5400, convtime("1h30m"));
}

void convtime_invalid_suffix(void) {
	TEST_ASSERT_EQUAL_INT(-1, convtime("10x"));
}

void convtime_negative(void) {
	TEST_ASSERT_EQUAL_INT(-1, convtime("-5"));
}

/* Multiplier constants mirrored from misc.c (private there) */
#define CT_MINUTES	60L
#define CT_HOURS	3600L
#define CT_DAYS		86400L
#define CT_WEEKS	604800L

void convtime_overflow_minutes(void) {
	char buf[64];
	snprintf(buf, sizeof(buf), "%ldm", LONG_MAX / CT_MINUTES + 1);
	TEST_ASSERT_EQUAL_INT(-1, convtime(buf));
}

void convtime_overflow_hours(void) {
	char buf[64];
	snprintf(buf, sizeof(buf), "%ldh", LONG_MAX / CT_HOURS + 1);
	TEST_ASSERT_EQUAL_INT(-1, convtime(buf));
}

void convtime_overflow_days(void) {
	char buf[64];
	snprintf(buf, sizeof(buf), "%ldd", LONG_MAX / CT_DAYS + 1);
	TEST_ASSERT_EQUAL_INT(-1, convtime(buf));
}

void convtime_overflow_weeks(void) {
	char buf[64];
	snprintf(buf, sizeof(buf), "%ldw", LONG_MAX / CT_WEEKS + 1);
	TEST_ASSERT_EQUAL_INT(-1, convtime(buf));
}

/* --------------------------------------------------- host_port_delimiter -- */

void hpd_null(void);
void hpd_host_port(void);
void hpd_host_slash(void);
void hpd_ipv6_bracket(void);
void hpd_no_delimiter(void);
void hpd_unclosed_bracket(void);
void hpd_ipv6_then_cleanhostname(void);

void hpd_null(void) {
	TEST_ASSERT_NULL(host_port_delimiter(NULL));
}

void hpd_host_port(void) {
	char buf[] = "example.com:22";
	char *cp = buf;
	char *token = host_port_delimiter(&cp);

	TEST_ASSERT_NOT_NULL(token);
	TEST_ASSERT_EQUAL_STRING("example.com", token);
	TEST_ASSERT_NOT_NULL(cp);
	TEST_ASSERT_EQUAL_STRING("22", cp);
}

void hpd_host_slash(void) {
	char buf[] = "example.com/path";
	char *cp = buf;
	char *token = host_port_delimiter(&cp);

	TEST_ASSERT_NOT_NULL(token);
	TEST_ASSERT_EQUAL_STRING("example.com", token);
	TEST_ASSERT_NOT_NULL(cp);
	TEST_ASSERT_EQUAL_STRING("path", cp);
}

void hpd_ipv6_bracket(void) {
	char buf[] = "[::1]:22";
	char *cp = buf;
	char *token = host_port_delimiter(&cp);

	TEST_ASSERT_NOT_NULL(token);
	TEST_ASSERT_EQUAL_STRING("[::1]", token);
	TEST_ASSERT_NOT_NULL(cp);
	TEST_ASSERT_EQUAL_STRING("22", cp);
}

void hpd_no_delimiter(void) {
	char buf[] = "example.com";
	char *cp = buf;
	char *token = host_port_delimiter(&cp);

	TEST_ASSERT_NOT_NULL(token);
	TEST_ASSERT_EQUAL_STRING("example.com", token);
	TEST_ASSERT_NULL(cp);
}

void hpd_unclosed_bracket(void) {
	char buf[] = "[::1:22";
	char *cp = buf;
	TEST_ASSERT_NULL(host_port_delimiter(&cp));
}

void hpd_ipv6_then_cleanhostname(void) {
	/* Integration: parse IPv6 host:port, then strip the brackets */
	char buf[] = "[2001:db8::1]:443";
	char *cp = buf;
	char *token = host_port_delimiter(&cp);
	char *host  = cleanhostname(token);

	TEST_ASSERT_EQUAL_STRING("2001:db8::1", host);
	TEST_ASSERT_EQUAL_STRING("443", cp);
}

/* --------------------------------------------------------- cleanhostname -- */

void clean_plain(void);
void clean_bracketed(void);
void clean_ipv6(void);

void clean_plain(void) {
	char s[] = "example.com";
	TEST_ASSERT_EQUAL_STRING("example.com", cleanhostname(s));
}

void clean_bracketed(void) {
	char s[] = "[example.com]";
	TEST_ASSERT_EQUAL_STRING("example.com", cleanhostname(s));
}

void clean_ipv6(void) {
	char s[] = "[::1]";
	TEST_ASSERT_EQUAL_STRING("::1", cleanhostname(s));
}

/* ------------------------------------------------------- percent_expand -- */

void pct_no_escape(void);
void pct_double_percent(void);
void pct_single_substitution(void);
void pct_multiple_substitutions(void);
void pct_sanitises_special_chars(void);
void pct_allowed_special_chars(void);

void pct_no_escape(void) {
	char *out = percent_expand("hello world", false, (char *)NULL);
	TEST_ASSERT_EQUAL_STRING("hello world", out);
	free(out);
}

void pct_double_percent(void) {
	char *out = percent_expand("100%%", false, (char *)NULL);
	TEST_ASSERT_EQUAL_STRING("100%", out);
	free(out);
}

void pct_single_substitution(void) {
	char *out = percent_expand("host=%h", false, "h", "example.com", (char *)NULL);
	TEST_ASSERT_EQUAL_STRING("host=example.com", out);
	free(out);
}

void pct_multiple_substitutions(void) {
	char *out = percent_expand("%h:%p", false, "h", "myhost", "p", "22", (char *)NULL);
	TEST_ASSERT_EQUAL_STRING("myhost:22", out);
	free(out);
}

void pct_sanitises_special_chars(void) {
	/* A space in the replacement value must be replaced with '_' */
	char *out = percent_expand("%n", false, "n", "my host", (char *)NULL);
	TEST_ASSERT_EQUAL_STRING("my_host", out);
	free(out);
}

void pct_allowed_special_chars(void) {
	/* Characters in ".@_-:" must pass through unsanitised */
	char *out = percent_expand("%u", false, "u", "user.name@host_a-b:c", (char *)NULL);
	TEST_ASSERT_EQUAL_STRING("user.name@host_a-b:c", out);
	free(out);
}

/* ------------------------------------------ susshi_parse_version_info -- */

void pvi_two_components_valid(void);
void pvi_three_components_valid(void);
void pvi_single_component(void);
void pvi_empty_string(void);
void pvi_v0_invalid(void);
void pvi_v0_out_of_range(void);
void pvi_zero_zero_zero(void);
void pvi_max_values(void);
void pvi_v2_invalid_ignored(void);
void pvi_extra_components_ignored(void);
void pvi_v1_invalid_two_component(void);

void pvi_two_components_valid(void) {
	bstring ver = bfromcstr("1.2");
	uint32_t v = 0;
	TEST_ASSERT_TRUE(susshi_parse_version_info(ver, &v));
	TEST_ASSERT_EQUAL_UINT32(10200, v);
	bdestroy(ver);
}

void pvi_three_components_valid(void) {
	bstring ver = bfromcstr("1.2.3");
	uint32_t v = 0;
	TEST_ASSERT_TRUE(susshi_parse_version_info(ver, &v));
	TEST_ASSERT_EQUAL_UINT32(10203, v);
	bdestroy(ver);
}

void pvi_single_component(void) {
	bstring ver = bfromcstr("1");
	uint32_t v = 0xdeadbeef;
	TEST_ASSERT_FALSE(susshi_parse_version_info(ver, &v));
	/* output must not be modified on failure */
	TEST_ASSERT_EQUAL_UINT32(0xdeadbeef, v);
	bdestroy(ver);
}

void pvi_empty_string(void) {
	bstring ver = bfromcstr("");
	uint32_t v = 0xdeadbeef;
	TEST_ASSERT_FALSE(susshi_parse_version_info(ver, &v));
	TEST_ASSERT_EQUAL_UINT32(0xdeadbeef, v);
	bdestroy(ver);
}

void pvi_v0_invalid(void) {
	bstring ver = bfromcstr("abc.2.3");
	uint32_t v = 0xdeadbeef;
	TEST_ASSERT_FALSE(susshi_parse_version_info(ver, &v));
	TEST_ASSERT_EQUAL_UINT32(0xdeadbeef, v);
	bdestroy(ver);
}

void pvi_v0_out_of_range(void) {
	/* major > 99 must fail */
	bstring ver = bfromcstr("100.0.0");
	uint32_t v = 0xdeadbeef;
	TEST_ASSERT_FALSE(susshi_parse_version_info(ver, &v));
	TEST_ASSERT_EQUAL_UINT32(0xdeadbeef, v);
	bdestroy(ver);
}

void pvi_zero_zero_zero(void) {
	bstring ver = bfromcstr("0.0.0");
	uint32_t v = 0xdeadbeef;
	TEST_ASSERT_TRUE(susshi_parse_version_info(ver, &v));
	TEST_ASSERT_EQUAL_UINT32(0, v);
	bdestroy(ver);
}

void pvi_max_values(void) {
	/* 99*10000 + 99*100 + 99 = 999999 */
	bstring ver = bfromcstr("99.99.99");
	uint32_t v = 0;
	TEST_ASSERT_TRUE(susshi_parse_version_info(ver, &v));
	TEST_ASSERT_EQUAL_UINT32(999999, v);
	bdestroy(ver);
}

void pvi_v2_invalid_ignored(void) {
	/* invalid patch component is silently skipped; major.minor still encoded */
	bstring ver = bfromcstr("1.2.abc");
	uint32_t v = 0;
	TEST_ASSERT_TRUE(susshi_parse_version_info(ver, &v));
	TEST_ASSERT_EQUAL_UINT32(10200, v);
	bdestroy(ver);
}

void pvi_extra_components_ignored(void) {
	/* only first three dot-separated components are consumed */
	bstring ver = bfromcstr("1.2.3.4");
	uint32_t v = 0;
	TEST_ASSERT_TRUE(susshi_parse_version_info(ver, &v));
	TEST_ASSERT_EQUAL_UINT32(10203, v);
	bdestroy(ver);
}

void pvi_v1_invalid_two_component(void) {
	/* invalid minor treated as 0; function still returns true */
	bstring ver = bfromcstr("1.abc");
	uint32_t v = 0;
	TEST_ASSERT_TRUE(susshi_parse_version_info(ver, &v));
	TEST_ASSERT_EQUAL_UINT32(10000, v);
	bdestroy(ver);
}

/* --------------------------------------------------- is_local_http_url -- */

void local_url_loopback_ip(void);
void local_url_localhost(void);
void local_url_https_rejected(void);
void local_url_remote_rejected(void);
void local_url_loopback_ip(void) {
	TEST_ASSERT_EQUAL(true, is_local_http_url("http://127.0.0.1/callback"));
}

void local_url_localhost(void) {
	TEST_ASSERT_EQUAL(true, is_local_http_url("http://localhost/callback"));
}

void local_url_https_rejected(void) {
	TEST_ASSERT_EQUAL(false, is_local_http_url("https://127.0.0.1/callback"));
	TEST_ASSERT_EQUAL(false, is_local_http_url("https://localhost/callback"));
}

void local_url_remote_rejected(void) {
	TEST_ASSERT_EQUAL(false, is_local_http_url("http://example.com/callback"));
}

int main(void) {
	UNITY_BEGIN();

	RUN_TEST(chop_no_newline);
	RUN_TEST(chop_unix_newline);
	RUN_TEST(chop_carriage_return);
	RUN_TEST(chop_newline_at_start);
	RUN_TEST(chop_returns_same_pointer);

	RUN_TEST(a2port_valid_ssh);
	RUN_TEST(a2port_zero);
	RUN_TEST(a2port_max);
	RUN_TEST(a2port_too_large);
	RUN_TEST(a2port_negative);
	RUN_TEST(a2port_non_numeric);
	RUN_TEST(a2port_trailing_chars);

	RUN_TEST(strtonum_valid);
	RUN_TEST(strtonum_too_small);
	RUN_TEST(strtonum_too_large);
	RUN_TEST(strtonum_invalid);
	RUN_TEST(strtonum_bad_range);
	RUN_TEST(strtonum_null_errstrp);

	RUN_TEST(convtime_null);
	RUN_TEST(convtime_empty);
	RUN_TEST(convtime_seconds_plain);
	RUN_TEST(convtime_seconds_suffix_lower);
	RUN_TEST(convtime_seconds_suffix_upper);
	RUN_TEST(convtime_minutes);
	RUN_TEST(convtime_hours);
	RUN_TEST(convtime_days);
	RUN_TEST(convtime_weeks);
	RUN_TEST(convtime_compound);
	RUN_TEST(convtime_invalid_suffix);
	RUN_TEST(convtime_negative);
	RUN_TEST(convtime_overflow_minutes);
	RUN_TEST(convtime_overflow_hours);
	RUN_TEST(convtime_overflow_days);
	RUN_TEST(convtime_overflow_weeks);

	RUN_TEST(hpd_null);
	RUN_TEST(hpd_host_port);
	RUN_TEST(hpd_host_slash);
	RUN_TEST(hpd_ipv6_bracket);
	RUN_TEST(hpd_no_delimiter);
	RUN_TEST(hpd_unclosed_bracket);
	RUN_TEST(hpd_ipv6_then_cleanhostname);

	RUN_TEST(clean_plain);
	RUN_TEST(clean_bracketed);
	RUN_TEST(clean_ipv6);

	RUN_TEST(pct_no_escape);
	RUN_TEST(pct_double_percent);
	RUN_TEST(pct_single_substitution);
	RUN_TEST(pct_multiple_substitutions);
	RUN_TEST(pct_sanitises_special_chars);
	RUN_TEST(pct_allowed_special_chars);

	RUN_TEST(local_url_loopback_ip);
	RUN_TEST(local_url_localhost);
	RUN_TEST(local_url_https_rejected);
	RUN_TEST(local_url_remote_rejected);

	RUN_TEST(pvi_two_components_valid);
	RUN_TEST(pvi_three_components_valid);
	RUN_TEST(pvi_single_component);
	RUN_TEST(pvi_empty_string);
	RUN_TEST(pvi_v0_invalid);
	RUN_TEST(pvi_v0_out_of_range);
	RUN_TEST(pvi_zero_zero_zero);
	RUN_TEST(pvi_max_values);
	RUN_TEST(pvi_v2_invalid_ignored);
	RUN_TEST(pvi_extra_components_ignored);
	RUN_TEST(pvi_v1_invalid_two_component);

	return UNITY_END();
}

/*! @} */
