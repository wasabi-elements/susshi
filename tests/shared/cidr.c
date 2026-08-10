/*!
 *
 * @brief		Shared Library Tests - CIDR
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
 * @defgroup 	tests_shared_cidr	Tests for shared Library | CIDR
 * @{
 */

#include "shared/common.h"
#include "shared/cidr.h"
#include "common.h"

void cidr4_address_in_network(void);
void cidr4_address_not_in_network(void);
void cidr4_host_route(void);
void cidr4_default_route(void);
void cidr4_network_boundary_low(void);
void cidr4_network_boundary_high(void);
void cidr6_address_in_network(void);
void cidr6_address_not_in_network(void);
void cidr6_host_route(void);
void cidr6_default_route(void);
void cidr6_no_prefix(void);
void cidr_mixed_family(void);

void setUp(void) {}
void tearDown(void) {}


void cidr4_address_in_network(void) {
	bstring ip  = bfromcstr("192.168.1.50");
	bstring net = bfromcstr("192.168.1.0/24");

	TEST_ASSERT_EQUAL(true, susshi_match_cidr(ip, net));

	bdestroy(ip);
	bdestroy(net);
}


void cidr4_address_not_in_network(void) {
	bstring ip  = bfromcstr("10.0.0.1");
	bstring net = bfromcstr("192.168.1.0/24");

	TEST_ASSERT_EQUAL(false, susshi_match_cidr(ip, net));

	bdestroy(ip);
	bdestroy(net);
}


void cidr4_host_route(void) {
	bstring ip      = bfromcstr("172.16.0.1");
	bstring net     = bfromcstr("172.16.0.1/32");
	bstring net_bad = bfromcstr("172.16.0.2/32");

	TEST_ASSERT_EQUAL(true,  susshi_match_cidr(ip, net));
	TEST_ASSERT_EQUAL(false, susshi_match_cidr(ip, net_bad));

	bdestroy(ip);
	bdestroy(net);
	bdestroy(net_bad);
}


void cidr4_default_route(void) {
	bstring ip  = bfromcstr("1.2.3.4");
	bstring net = bfromcstr("0.0.0.0/0");

	TEST_ASSERT_EQUAL(true, susshi_match_cidr(ip, net));

	bdestroy(ip);
	bdestroy(net);
}


void cidr4_network_boundary_low(void) {
	/* First address of the subnet */
	bstring ip  = bfromcstr("10.0.0.0");
	bstring net = bfromcstr("10.0.0.0/8");

	TEST_ASSERT_EQUAL(true, susshi_match_cidr(ip, net));

	bdestroy(ip);
	bdestroy(net);
}


void cidr4_network_boundary_high(void) {
	/* Last address of the subnet */
	bstring ip      = bfromcstr("10.255.255.255");
	bstring net     = bfromcstr("10.0.0.0/8");
	bstring net_out = bfromcstr("10.0.0.0/16");

	TEST_ASSERT_EQUAL(true,  susshi_match_cidr(ip, net));
	TEST_ASSERT_EQUAL(false, susshi_match_cidr(ip, net_out));

	bdestroy(ip);
	bdestroy(net);
	bdestroy(net_out);
}


void cidr6_address_in_network(void) {
	bstring ip  = bfromcstr("2001:db8::1");
	bstring net = bfromcstr("2001:db8::/32");

	TEST_ASSERT_EQUAL(true, susshi_match_cidr(ip, net));

	bdestroy(ip);
	bdestroy(net);
}


void cidr6_address_not_in_network(void) {
	bstring ip  = bfromcstr("2001:db9::1");
	bstring net = bfromcstr("2001:db8::/32");

	TEST_ASSERT_EQUAL(false, susshi_match_cidr(ip, net));

	bdestroy(ip);
	bdestroy(net);
}


void cidr6_host_route(void) {
	bstring ip      = bfromcstr("fe80::1");
	bstring net     = bfromcstr("fe80::1/128");
	bstring net_bad = bfromcstr("fe80::2/128");

	TEST_ASSERT_EQUAL(true,  susshi_match_cidr(ip, net));
	TEST_ASSERT_EQUAL(false, susshi_match_cidr(ip, net_bad));

	bdestroy(ip);
	bdestroy(net);
	bdestroy(net_bad);
}


void cidr6_default_route(void) {
	bstring ip  = bfromcstr("2001:db8::1");
	bstring net = bfromcstr("::/0");

	TEST_ASSERT_EQUAL(true, susshi_match_cidr(ip, net));

	bdestroy(ip);
	bdestroy(net);
}


void cidr6_no_prefix(void) {
	/* Address with no prefix length — treated as /128 */
	bstring ip      = bfromcstr("::1");
	bstring net     = bfromcstr("::1");
	bstring net_bad = bfromcstr("::2");

	TEST_ASSERT_EQUAL(true,  susshi_match_cidr(ip, net));
	TEST_ASSERT_EQUAL(false, susshi_match_cidr(ip, net_bad));

	bdestroy(ip);
	bdestroy(net);
	bdestroy(net_bad);
}


void cidr_mixed_family(void) {
	/* An IPv4 address must never match an IPv6 network and vice versa */
	bstring ip4  = bfromcstr("192.168.1.1");
	bstring ip6  = bfromcstr("::1");
	bstring net4 = bfromcstr("192.168.0.0/16");
	bstring net6 = bfromcstr("::1/128");

	TEST_ASSERT_EQUAL(false, susshi_match_cidr(ip4, net6));
	TEST_ASSERT_EQUAL(false, susshi_match_cidr(ip6, net4));

	bdestroy(ip4);
	bdestroy(ip6);
	bdestroy(net4);
	bdestroy(net6);
}


int main(void) {
	UNITY_BEGIN();

	RUN_TEST(cidr4_address_in_network);
	RUN_TEST(cidr4_address_not_in_network);
	RUN_TEST(cidr4_host_route);
	RUN_TEST(cidr4_default_route);
	RUN_TEST(cidr4_network_boundary_low);
	RUN_TEST(cidr4_network_boundary_high);
	RUN_TEST(cidr6_address_in_network);
	RUN_TEST(cidr6_address_not_in_network);
	RUN_TEST(cidr6_host_route);
	RUN_TEST(cidr6_default_route);
	RUN_TEST(cidr6_no_prefix);
	RUN_TEST(cidr_mixed_family);

	return UNITY_END();
}

/*! @} */
