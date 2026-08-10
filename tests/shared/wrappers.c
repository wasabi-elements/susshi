/*!
 *
 * @brief		Shared Library Tests - Wrappers
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
 * @defgroup	tests_shared_wrappers	Tests for shared Library | Wrappers
 * @{
 */

#include "shared/common.h"
#include "shared/wrappers.h"
#include "common.h"

void fatal(const char *fmt, ...) {}
void setUp(void) {}
void tearDown(void) {}

/* --------------------------------------------------------------- xmalloc -- */

void xmalloc_returns_non_null(void);
void xmalloc_memory_is_writable(void);

void xmalloc_returns_non_null(void) {
	void *ptr = xmalloc(64);
	TEST_ASSERT_NOT_NULL(ptr);
	free(ptr);
}

void xmalloc_memory_is_writable(void) {
	unsigned char *ptr = xmalloc(8);
	TEST_ASSERT_NOT_NULL(ptr);
	memset(ptr, 0xAB, 8);
	TEST_ASSERT_EQUAL_HEX8(0xAB, ptr[0]);
	TEST_ASSERT_EQUAL_HEX8(0xAB, ptr[7]);
	free(ptr);
}

/* --------------------------------------------------------------- xcalloc -- */

void xcalloc_returns_non_null(void);
void xcalloc_memory_is_zeroed(void);

void xcalloc_returns_non_null(void) {
	void *ptr = xcalloc(4, 16);
	TEST_ASSERT_NOT_NULL(ptr);
	free(ptr);
}

void xcalloc_memory_is_zeroed(void) {
	unsigned char *ptr = xcalloc(16, sizeof(unsigned char));
	TEST_ASSERT_NOT_NULL(ptr);
	for (int i = 0; i < 16; i++)
		TEST_ASSERT_EQUAL_HEX8(0x00, ptr[i]);
	free(ptr);
}

/* -------------------------------------------------------------- xrealloc -- */

void xrealloc_null_ptr_acts_as_malloc(void);
void xrealloc_grows_and_preserves_content(void);

void xrealloc_null_ptr_acts_as_malloc(void) {
	/* Passing NULL behaves like malloc(nmemb * size) */
	void *ptr = xrealloc(NULL, 1, 64);
	TEST_ASSERT_NOT_NULL(ptr);
	free(ptr);
}

void xrealloc_grows_and_preserves_content(void) {
	char *ptr = xmalloc(8);
	strlcpy(ptr, "hello", 8);

	ptr = xrealloc(ptr, 1, 64);
	TEST_ASSERT_NOT_NULL(ptr);
	TEST_ASSERT_EQUAL_STRING("hello", ptr);
	free(ptr);
}

/* --------------------------------------------------------------- xstrdup -- */

void xstrdup_content_matches(void);
void xstrdup_different_pointer(void);
void xstrdup_empty_string(void);

void xstrdup_content_matches(void) {
	char *dup = xstrdup("hello world");
	TEST_ASSERT_EQUAL_STRING("hello world", dup);
	free(dup);
}

void xstrdup_different_pointer(void) {
	const char *orig = "hello";
	char *dup = xstrdup(orig);
	TEST_ASSERT_NOT_EQUAL((void *)orig, (void *)dup);
	free(dup);
}

void xstrdup_empty_string(void) {
	char *dup = xstrdup("");
	TEST_ASSERT_NOT_NULL(dup);
	TEST_ASSERT_EQUAL_STRING("", dup);
	free(dup);
}

/* -------------------------------------------------------------- xasprintf -- */

void xasprintf_simple_string(void);
void xasprintf_with_format_args(void);
void xasprintf_returns_char_count(void);

void xasprintf_simple_string(void) {
	char *out = NULL;
	xasprintf(&out, "hello");
	TEST_ASSERT_NOT_NULL(out);
	TEST_ASSERT_EQUAL_STRING("hello", out);
	free(out);
}

void xasprintf_with_format_args(void) {
	char *out = NULL;
	xasprintf(&out, "%s:%d", "port", 22);
	TEST_ASSERT_NOT_NULL(out);
	TEST_ASSERT_EQUAL_STRING("port:22", out);
	free(out);
}

void xasprintf_returns_char_count(void) {
	char *out = NULL;
	int n = xasprintf(&out, "hello");
	TEST_ASSERT_EQUAL_INT(5, n);
	free(out);
}

/* --------------------------------------------------- susshi_gai_strerror -- */

void gai_strerror_eai_system_returns_strerror(void);
void gai_strerror_other_error_delegates(void);

void gai_strerror_eai_system_returns_strerror(void) {
	/* EAI_SYSTEM must map to strerror(errno) */
	const char *result = NULL, *expected = NULL;
	errno = EPERM;
	result   = susshi_gai_strerror(EAI_SYSTEM);
	expected = strerror(EPERM);
	TEST_ASSERT_EQUAL_STRING(expected, result);
}

void gai_strerror_other_error_delegates(void) {
	/* Any other error code must delegate to gai_strerror() */
	const char *result   = susshi_gai_strerror(EAI_NONAME);
	const char *expected = gai_strerror(EAI_NONAME);
	TEST_ASSERT_EQUAL_STRING(expected, result);
}

/* ---------------------------------------------------------- bstrListWipe -- */

void bstrlistwipe_null_is_safe(void);
void bstrlistwipe_clears_entries(void);

void bstrlistwipe_null_is_safe(void) {
	/* NULL must not crash */
	bstrListWipe(NULL);
}

void bstrlistwipe_clears_entries(void) {
	bstring src = bfromcstr("alpha:beta:gamma");
	bstrList list = bsplit(src, ':');
	bdestroy(src);
	TEST_ASSERT_NOT_NULL(list);
	TEST_ASSERT_EQUAL_INT(3, list->qty);
	/* Must not crash and must destroy all entries */
	bstrListWipe(list);
}

/* -------------------------------------------------------------- bstrWipe -- */

void bstrwipe_sets_pointer_null(void);
void bstrwipe_null_is_safe(void);

void bstrwipe_sets_pointer_null(void) {
	bstring b = bfromcstr("secret");
	TEST_ASSERT_NOT_NULL(b);
	bstrWipe(b);
	TEST_ASSERT_NULL(b);
}

void bstrwipe_null_is_safe(void) {
	bstring b = NULL;
	/* bstrWipe guards against NULL — must not crash */
	bstrWipe(b);
}

/* ----------------------------------------------------------------- xwipe -- */

void xwipe_valid_pointer(void);

void xwipe_valid_pointer(void) {
	unsigned char *ptr = xmalloc(8);
	memset(ptr, 0xFF, 8);
	/* xwipe zeroes and frees; just verify it does not crash */
	xwipe(ptr, 8);
}


int main(void) {
	UNITY_BEGIN();

	RUN_TEST(xmalloc_returns_non_null);
	RUN_TEST(xmalloc_memory_is_writable);

	RUN_TEST(xcalloc_returns_non_null);
	RUN_TEST(xcalloc_memory_is_zeroed);

	RUN_TEST(xrealloc_null_ptr_acts_as_malloc);
	RUN_TEST(xrealloc_grows_and_preserves_content);

	RUN_TEST(xstrdup_content_matches);
	RUN_TEST(xstrdup_different_pointer);
	RUN_TEST(xstrdup_empty_string);

	RUN_TEST(xasprintf_simple_string);
	RUN_TEST(xasprintf_with_format_args);
	RUN_TEST(xasprintf_returns_char_count);

	RUN_TEST(gai_strerror_eai_system_returns_strerror);
	RUN_TEST(gai_strerror_other_error_delegates);

	RUN_TEST(bstrlistwipe_null_is_safe);
	RUN_TEST(bstrlistwipe_clears_entries);

	RUN_TEST(bstrwipe_sets_pointer_null);
	RUN_TEST(bstrwipe_null_is_safe);

	RUN_TEST(xwipe_valid_pointer);

	return UNITY_END();
}

/*! @} */
