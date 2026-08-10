/*!
 *
 * @brief       CIDR methods
 *
 * @ingroup     shared
 *
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996,1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * @date        2026-02-01
 *
 * @defgroup    cidr CIDR methods
 * @{
 */

#include "shared/common.h"
#include "shared/cidr.h"

/* Prototypes */
static bool cidr4_match(const struct in_addr *address, const struct in_addr *network, uint8_t bits);
static bool cidr6_match(const struct in6_addr *address, const struct in6_addr *network, uint8_t bits);
static int inet_net_pton_ipv6(const char *src, void *dst, size_t size);
static int getv4(const char *src, u_char *dst, int *bitsp);
static int getbits(const char *src, int *bitsp);


/*!
 * @brief       Check if an IPv4 or IPv6 address fits into a CIDR network.
 *
 * @param       ip_address  bstring representing the ip_address
 * @param       network     bstring representing the network (with or without prefix mask)
 *
 * @return      True if of same address family and ip_address fits into network
 */

bool
susshi_match_cidr(bstring ip_address, bstring network) {
	int af_ip, af_net;
	int bits;

	af_ip = (strstr(bdata(ip_address), ":") != NULL) ? AF_INET6 : AF_INET;
	af_net = (strstr(bdata(network), ":") != NULL) ? AF_INET6 : AF_INET;

	if (af_ip != af_net)
		return false;

	switch(af_ip) {
		case AF_INET: {
			struct in_addr in_addr_ip, in_addr_net;

			if (inet_pton(af_ip, bdata(ip_address), &in_addr_ip) == 1) {
				if ((bits = inet_net_pton(af_ip, bdata(network), &in_addr_net, sizeof(struct in_addr))) != -1) {
					return(cidr4_match(&in_addr_ip, &in_addr_net, (uint8_t) bits));
				}
			}
		} break;
		case AF_INET6: {
			struct in6_addr in6_addr_ip, in6_addr_net;

			if (inet_pton(AF_INET6, bdata(ip_address), &in6_addr_ip) == 1) {
				if ((bits = inet_net_pton_ipv6(bdata(network), &in6_addr_net, sizeof(struct in6_addr))) != -1) {
					return(cidr6_match(&in6_addr_ip, &in6_addr_net, (uint8_t) bits));
				}
			}
		}
		default:
			return false;
	}
	return false;
}


/*!
 * @brief       Check whether an IPv4 address falls within a network given a prefix length
 *
 * @param       address     IPv4 address to test
 * @param       network     Network address (host bits must be zero)
 * @param       bits        Prefix length in bits (0–32)
 *
 * @return      @c true if @p address is within the network, @c false otherwise
 */

static bool
cidr4_match(const struct in_addr *address, const struct in_addr *network, uint8_t bits) {

	struct in_addr in_addr_ip_masked;

	if (bits == 0)
		in_addr_ip_masked.s_addr = htonl(0);
	else
		in_addr_ip_masked.s_addr = address->s_addr & htonl(0xFFFFFFFFu << (32 - bits));

	return (in_addr_ip_masked.s_addr == network->s_addr);
}


/*!
 * @brief       Check whether an IPv6 address falls within a network given a prefix length
 *
 * @param       address     IPv6 address to test
 * @param       network     Network address (host bits must be zero)
 * @param       bits        Prefix length in bits (0–128)
 *
 * @return      @c true if @p address is within the network, @c false otherwise
 */

static bool
cidr6_match(const struct in6_addr *address, const struct in6_addr *network, uint8_t bits) {
#ifdef LINUX
	const uint32_t *a = address->s6_addr32;
	const uint32_t *n = network->s6_addr32;
#else
	const uint32_t *a = address->__u6_addr.__u6_addr32;
	const uint32_t *n = network->__u6_addr.__u6_addr32;
#endif
	int bits_whole, bits_incomplete;

	bits_whole = bits >> 5;         // number of whole u32

	bits_incomplete = bits & 0x1f;  // number of bits in incomplete u32

	if (bits_whole) {
		if (memcmp(a, n, bits_whole << 2)) {
			return false;
		}
	}
	if (bits_incomplete) {
		uint32_t mask = htonl((0xFFFFFFFFu) << (32 - bits_incomplete));
		if ((a[bits_whole] ^ n[bits_whole]) & mask) {
			return false;
		}
	}
	return true;
}


/*!
 * @brief       Parse an IPv6 network address string with optional prefix length into binary form
 *
 * Provided because the Linux standard @c libc @c inet_net_pton does not support @c AF_INET6.
 *
 * @param       src     Null-terminated IPv6 CIDR string (e.g. @c "2001:db8::/32")
 * @param       dst     Output buffer to receive the binary network address
 * @param       size    Size of @p dst in bytes; must be at least @c NS_IN6ADDRSZ
 *
 * @return      Prefix length in bits on success, @c -1 on parse error (@c errno set to @c ENOENT)
 *              or @c -1 if @p dst is too small (@c errno set to @c EMSGSIZE)
 */

static int
inet_net_pton_ipv6(const char *src, void *dst, size_t size) {
	static const char xdigits_l[] = "0123456789abcdef",
					  xdigits_u[] = "0123456789ABCDEF";
	u_char tmp[NS_IN6ADDRSZ], *tp, *endp, *colonp;
	const char *xdigits, *curtok;
	int ch, saw_xdigit;
	u_int val;
	int digits;
	int bits;
	size_t bytes;
	int words;
	int ipv4;

	memset((tp = tmp), '\0', NS_IN6ADDRSZ);
	endp = tp + NS_IN6ADDRSZ;
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			goto enoent;

	curtok = src;
	saw_xdigit = 0;
	val = 0;
	digits = 0;
	bits = -1;
	ipv4 = 0;

	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			val <<= 4;
			val |= (pch - xdigits);
			if (++digits > 4)
				goto enoent;
			saw_xdigit = 1;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp)
					goto enoent;
				colonp = tp;
				continue;
			} else if (*src == '\0')
				goto enoent;
			if (tp + NS_INT16SZ > endp)
				return (0);
			*tp++ = (u_char) (val >> 8) & 0xff;
			*tp++ = (u_char) val & 0xff;
			saw_xdigit = 0;
			digits = 0;
			val = 0;
			continue;
		}
		if (ch == '.' && ((tp + NS_INADDRSZ) <= endp) &&
			getv4(curtok, tp, &bits) > 0) {
			tp += NS_INADDRSZ;
			saw_xdigit = 0;
			ipv4 = 1;
			break;	/*%< '\\0' was seen by inet_pton4(). */
		}
		if (ch == '/' && getbits(src, &bits) > 0)
			break;
		goto enoent;
	}
	if (saw_xdigit) {
		if (tp + NS_INT16SZ > endp)
			goto enoent;
		*tp++ = (u_char) (val >> 8) & 0xff;
		*tp++ = (u_char) val & 0xff;
	}
	if (bits == -1)
		bits = 128;

	words = (bits + 15) / 16;
	if (words < 2)
		words = 2;
	if (ipv4)
		words = 8;
	endp =  tmp + 2 * words;

	if (colonp != NULL) {
		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
		const int n = tp - colonp;
		int i;

		if (tp == endp && n != 0)
			goto enoent;
		for (i = 1; i <= n; i++) {
			endp[- i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		goto enoent;

	bytes = (bits + 7) / 8;
	if (bytes > size)
		goto emsgsize;
	memcpy(dst, tmp, bytes);
	return (bits);

	enoent:
	errno = ENOENT;
	return (-1);

	emsgsize:
	errno = EMSGSIZE;
	return (-1);
}


/*!
 * @brief       Parse a dotted-decimal IPv4 address (with optional trailing @c /) from @p src into @p dst
 *
 * If a @c / is encountered, delegates to @c getbits() to parse the prefix length.
 *
 * @param       src     Pointer to the start of a dotted-decimal IPv4 string
 * @param       dst     Output buffer receiving the parsed address bytes (must hold at least 4 bytes)
 * @param       bitsp   Receives the prefix length if a @c / suffix is present
 *
 * @return      @c 1 on success, @c 0 on parse error
 */

static int
getv4(const char *src, u_char *dst, int *bitsp) {
	static const char digits[] = "0123456789";
	u_char *odst = dst;
	int n;
	u_int val;
	char ch;

	val = 0;
	n = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		pch = strchr(digits, ch);
		if (pch != NULL) {
			if (n++ != 0 && val == 0)	/*%< no leading zeros */
				return (0);
			val *= 10;
			val += (pch - digits);
			if (val > 255)			/*%< range */
				return (0);
			continue;
		}
		if (ch == '.' || ch == '/') {
			if (dst - odst > 3)		/*%< too many octets? */
				return (0);
			*dst++ = val;
			if (ch == '/')
				return (getbits(src, bitsp));
			val = 0;
			n = 0;
			continue;
		}
		return (0);
	}
	if (n == 0)
		return (0);
	if (dst - odst > 3)		/*%< too many octets? */
		return (0);
	*dst++ = val;
	return (1);
}


/*!
 * @brief       Parse a decimal prefix-length string into an integer
 *
 * Rejects leading zeros and values greater than 128.
 *
 * @param       src     Pointer to a null-terminated decimal string (the part after @c /)
 * @param       bitsp   Receives the parsed prefix length on success
 *
 * @return      @c 1 on success, @c 0 on parse error or out-of-range value
 */

static int
getbits(const char *src, int *bitsp) {
	static const char digits[] = "0123456789";
	int n;
	int val;
	char ch;

	val = 0;
	n = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		pch = strchr(digits, ch);
		if (pch != NULL) {
			if (n++ != 0 && val == 0)	/*%< no leading zeros */
				return (0);
			val *= 10;
			val += (pch - digits);
			if (val > 128)			/*%< range */
				return (0);
			continue;
		}
		return (0);
	}
	if (n == 0)
		return (0);
	*bitsp = val;
	return (1);
}

/*! @} */
