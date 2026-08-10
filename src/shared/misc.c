/*!
 *
 * @brief       Miscellaneous methods
 *
 * @ingroup     shared
 *
 * @copyright   Copyright (C) 2026 Wasabi Elements GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later AND BSD-2-Clause
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
 * ---
 *
 * Portions of this file (sanitise_stdfd, tilde_expand_filename, percent_expand,
 * chop, a2port, host_port_delimiter, cleanhostname, convtime) are derived from
 * OpenSSH misc.c:
 *
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2005, 2006 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ---
 *
 * strtonum is derived from OpenBSD strtonum.c:
 *
 * Copyright (c) 2004 Ted Unangst and Todd Miller
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * ---
 *
 * @author      Oliver Rauscher <oliver@susshi.io>
 * @date        2026-02-01
 *
 * @defgroup    misc    Miscellaneous methods
 * @{
 */

#ifdef LINUX
#define _GNU_SOURCE
#endif

#include "shared/common.h"
#include "shared/misc.h"

/* Static seed for miscellaneous identifiers */
const unsigned char susshi_misc_seed[32] = { 0x76, 0x2a, 0xfc, 0x9a, 0x06, 0xaf, 0x04, 0xdd, 0x94, 0x83, 0xb3, 0xc4, 0x94, 0x2d, 0x3c, 0x80, 0x20, 0x76, 0x6c, 0x01, 0xb9, 0xb0, 0x94, 0xbc, 0xb4, 0x00, 0x73, 0xc7, 0xd6, 0x51, 0x9d, 0x53 };


/*!
 * @brief       Ensure file descriptors 0, 1, and 2 are open, redirecting any that are closed to @c /dev/null
 *
 * Should be called early in program startup to prevent accidental reuse of
 * stdin/stdout/stderr file descriptor numbers by subsequently opened files.
 */

void
sanitise_stdfd(void)
{
	int nullfd, dupfd;

	if ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fatal("Couldn't open /dev/null: %s\n", strerror(errno));
	}
	while (++dupfd <= 2) {
		/* Only clobber closed fds */
		if (fcntl(dupfd, F_GETFL, 0) >= 0)
			continue;
		if (dup2(nullfd, dupfd) == -1) {
			fatal("dup2: %s\n", strerror(errno));
		}
	}
	if (nullfd > 2)
		close(nullfd);
}

/*!
 * @brief       Expands tildes in the file name
 *
 * Warning: this calls getpw*.
 *
 * @param       filename    Filename
 * @param       uid         UserID
 *
 * @return      Expanded filename (allocated with xmalloc)
 */

char *
tilde_expand_filename(const char *filename, uid_t uid)
{
	const char *path;
	char user[128], ret[MAXPATHLEN];
	struct passwd *pw;
	u_int len, slash;

	if (*filename != '~')
		return (xstrdup(filename));
	filename++;

	path = strchr(filename, '/');
	if (path != NULL && path > filename) {          /* ~user/path */
		slash = path - filename;
		if (slash > sizeof(user) - 1)
			fatal("tilde_expand_filename: ~username too long");
		memcpy(user, filename, slash);
		user[slash] = '\0';
		if ((pw = getpwnam(user)) == NULL)
			fatal("tilde_expand_filename: No such user %s", user);
	} else if ((pw = getpwuid(uid)) == NULL)        /* ~/path */
		fatal("tilde_expand_filename: No such uid %ld", (long)uid);

	len = strlcpy(ret, pw->pw_dir, sizeof(ret));
	if (len >= sizeof(ret))
		fatal("tilde_expand_filename: Path too long");

	/* Make sure directory has a trailing '/' */
	if (len == 0 || pw->pw_dir[len - 1] != '/') {
		if (strlcat(ret, "/", sizeof(ret)) >= sizeof(ret))
			fatal("tilde_expand_filename: Path too long");
	}

	/* Skip leading '/' from specified path */
	if (path != NULL)
		filename = path + 1;
	if (strlcat(ret, filename, sizeof(ret)) >= sizeof(ret))
		fatal("tilde_expand_filename: Path too long");

	return (xstrdup(ret));
}


#define EXPAND_MAX_KEYS	16

/*!
 * @brief       Expand percent-escape sequences in a string using caller-supplied substitution pairs
 *
 * Escapes are specified as variadic @c (const char *keys, const char *replacement) pairs,
 * terminated by a @c NULL key. Each @c %c in @p string is replaced by the corresponding
 * @p replacement; @c %% is replaced by a literal @c %.
 * Non-alphanumeric replacement characters not in @c ".@_-:" are sanitised to @c '_'.
 * Up to @c EXPAND_MAX_KEYS (16) key/replacement pairs are supported; more causes @c fatal().
 *
 * @param       string				String containing @c % escape sequences to expand
 * @param       allow_asterics      Allow asterics in replacement strings
 * @param       ...					Null-terminated list of @c (const char *keys, const char *replacement) pairs
 *
 * @return      Expanded string allocated with @c xmalloc; caller must free
 */

char *
percent_expand(const char *string, bool allow_asterics, ...)
{
	u_int num_keys, i, j;
	struct {
		const char *key;
		const char *repl;
	} keys[EXPAND_MAX_KEYS];
	char *buf;
	char c;
	va_list ap;
	size_t max_repl_len, max_out;
	char *result = NULL;

	/* Gather keys */
	va_start(ap, string);
	for (num_keys = 0; num_keys < EXPAND_MAX_KEYS; num_keys++) {
		keys[num_keys].key = va_arg(ap, char *);
		if (keys[num_keys].key == NULL)
			break;
		keys[num_keys].repl = va_arg(ap, char *);
		if (keys[num_keys].repl == NULL)
			fatal("%s: NULL replacement for key %%%s.", __func__, keys[num_keys].key);
	}
	if (num_keys == EXPAND_MAX_KEYS && va_arg(ap, char *) != NULL)
		fatal("%s: too many keys", __func__);
	va_end(ap);

	/* Compute upper bound: each input byte expands to at most max_repl_len output bytes */
	max_repl_len = 1;
	for (j = 0; j < num_keys; j++) {
		size_t rlen = strlen(keys[j].repl);
		if (rlen > max_repl_len)
			max_repl_len = rlen;
	}
	max_out = strlen(string) * max_repl_len + 1;
	if (max_out > (1024 * 1024))
		fatal("%s: expansion too large", __func__);
	buf = xcalloc(1, max_out);

	/* Expand string */
	for (i = 0; *string != '\0'; string++) {
		if (*string != '%') {
			append:
			buf[i++] = *string;
			if (i >= max_out)
				fatal("%s: string too long", __func__);
			buf[i] = '\0';
			continue;
		}
		string++;
		/* %% case */
		if (*string == '%')
			goto append;
		for (j = 0; j < num_keys; j++) {
			if (strchr(keys[j].key, *string) != NULL) {
				for(unsigned long s=0; s < strlen(keys[j].repl); s++) {
					if (i >= max_out)
						fatal("%s: string too long", __func__);
					c = keys[j].repl[s];
					if ((isalnum(c) == 0) && (strchr(".@_-:*", c) == NULL)) {
						if ((c == '*') && (allow_asterics == true))
							c = '*';
						else
							c='_';
					}
					buf[i++]=c;
				}
				break;
			}
		}
		if (j >= num_keys)
			fatal("%s: unknown key %%%c", __func__, *string);
	}
	result = xstrdup(buf);
	free(buf);
	return result;
}

#undef EXPAND_MAX_KEYS


/*!
 * @brief       Truncate a string at the first @c '\\n' or @c '\\r' character, modifying it in place
 *
 * @param       s       String to truncate; modified in place
 *
 * @return      @p s (same pointer, for convenience)
 */

char *
chop(char *s)
{
	char *t = s;
	while (*t) {
		if (*t == '\n' || *t == '\r') {
			*t = '\0';
			return s;
		}
		t++;
	}
	return s;

}

/*!
 * @brief       Parse a decimal string as a TCP/UDP port number
 *
 * @param       s       Null-terminated decimal string to parse
 *
 * @return      Port number in the range [0, 65535], or @c -1 if @p s is invalid or out of range
 */

int
a2port(const char *s)
{
	long long port;
	const char *errstr;

	port = strtonum(s, 0, 65535, &errstr);
	if (errstr != NULL)
		return -1;
	return (int)port;
}

#define INVALID 	1
#define TOOSMALL 	2
#define TOOLARGE 	3

/*!
 * @brief       String to number (long long)
 *
 * @param       numstr      Input
 * @param       minval      Minimum value
 * @param       maxval      Maximum value
 * @param       errstrp     Pointer to pointer for storing error string
 *
 * @return      Number
 */

long long
strtonum(const char *numstr, long long minval, long long maxval, const char **errstrp)
{
	long long ll = 0;
	char *ep;
	int error = 0;
	struct errval {
		const char *errstr;
		int err;
	} ev[4] = {
			{ NULL,		0 },
			{ "invalid",	EINVAL },
			{ "too small",	ERANGE },
			{ "too large",	ERANGE },
	};

	ev[0].err = errno;
	errno = 0;
	if (minval > maxval)
		error = INVALID;
	else {
		ll = strtoll(numstr, &ep, 10);
		if (numstr == ep || *ep != '\0')
			error = INVALID;
		else if ((ll == LLONG_MIN && errno == ERANGE) || ll < minval)
			error = TOOSMALL;
		else if ((ll == LLONG_MAX && errno == ERANGE) || ll > maxval)
			error = TOOLARGE;
	}
	if (errstrp != NULL)
		*errstrp = ev[error].errstr;
	errno = ev[error].err;
	if (error)
		ll = 0;

	return (ll);
}

/*!
 * @brief       Extract the next host or address token from a @c host:port or @c [host]:port string
 *
 * @p *cp is modified: the token is null-terminated in place, and @p *cp is advanced past the
 * delimiter to the start of the next field. If no further field exists, @p *cp is set to @c NULL.
 * Bracketed IPv6 addresses (@c [::1]) are handled correctly.
 *
 * @param       cp      Pointer to the current parse position; updated on return
 *
 * @return      Pointer to the start of the extracted token, or @c NULL on parse error
 */


char *
host_port_delimiter(char **cp)
{
	char *s, *old;

	if (cp == NULL || *cp == NULL)
		return NULL;

	old = s = *cp;
	if (*s == '[') {
		if ((s = strchr(s, ']')) == NULL)
			return NULL;
		else
			s++;
	} else if ((s = strpbrk(s, ":/")) == NULL)
		s = *cp + strlen(*cp); /* skip to end (see first case below) */

	switch (*s) {
		case '\0':
			*cp = NULL;	/* no more fields*/
			break;

		case ':':
		case '/':
			*s = '\0';	/* terminate */
			*cp = s + 1;
			break;

		default:
			return NULL;
	}

	return old;
}


/*!
 * @brief       Strip surrounding square brackets from a hostname string, modifying it in place
 *
 * If @p host is of the form @c "[name]", the closing bracket is overwritten with @c '\\0'
 * and a pointer to the character after the opening bracket is returned.
 * If no brackets are present, @p host is returned unchanged.
 *
 * @param       host        Hostname string, optionally surrounded by @c '[' and @c ']'
 *
 * @return      Pointer into @p host with brackets removed, or @p host if no brackets were found
 */

char *
cleanhostname(char *host)
{
	if (*host == '[' && host[strlen(host) - 1] == ']') {
		host[strlen(host) - 1] = '\0';
		return (host + 1);
	} else
		return host;
}

/*
 * Convert a time string into seconds; format is
 * a sequence of:
 *      time[qualifier]
 *
 * Valid time qualifiers are:
 *      <none>  seconds
 *      s|S     seconds
 *      m|M     minutes
 *      h|H     hours
 *      d|D     days
 *      w|W     weeks
 *
 * Examples:
 *      90m     90 minutes
 *      1h30m   90 minutes
 *      2d      2 days
 *      1w      1 week
 *
 * Return -1 if time string is invalid.
 */

#define SECONDS		1
#define MINUTES		(SECONDS * 60)
#define HOURS		(MINUTES * 60)
#define DAYS		(HOURS * 24)
#define WEEKS		(DAYS * 7)


/*!
 * @brief       Convert a time string into seconds
 *
 * a sequence of:
 *      @c time[qualifier]
 * ```
 * Valid time qualifiers are:
 *      'none'  seconds
 *      s|S     seconds
 *      m|M     minutes
 *      h|H     hours
 *      d|D     days
 *      w|W     weeks
 * ```
 *
 * Examples:
 * ```
 *      90m     90 minutes
 *      1h30m   90 minutes
 *      2d      2 days
 *      1w      1 week
 * ```
 *
 * @param       s       Input
 *
 * @return      seconds, -1 if time string is invalid.
 */

long
convtime(const char *s)
{
	long total, secs;
	const char *p;
	char *endp;

	errno = 0;
	total = 0;
	p = s;

	if (p == NULL || *p == '\0')
		return -1;

	while (*p) {
		secs = strtol(p, &endp, 10);
		if (p == endp ||
			(errno == ERANGE && (secs == LONG_MIN || secs == LONG_MAX)) ||
			secs < 0)
			return -1;

		switch (*endp++) {
			case '\0':
				endp--;
				break;
			case 's':
			case 'S':
				break;
			case 'm':
			case 'M':
				if (secs > LONG_MAX / MINUTES)
					return -1;
				secs *= MINUTES;
				break;
			case 'h':
			case 'H':
				if (secs > LONG_MAX / HOURS)
					return -1;
				secs *= HOURS;
				break;
			case 'd':
			case 'D':
				if (secs > LONG_MAX / DAYS)
					return -1;
				secs *= DAYS;
				break;
			case 'w':
			case 'W':
				if (secs > LONG_MAX / WEEKS)
					return -1;
				secs *= WEEKS;
				break;
			default:
				return -1;
		}
		total += secs;
		if (total < 0)
			return -1;
		p = endp;
	}

	return total;
}

/*!
 * @brief       Return the username of the current effective user
 *
 * The returned pointer is owned by the system's @c passwd entry and must not be freed.
 * Returns the static string @c "(unknown ?)" if the effective UID has no @c passwd entry.
 *
 * @return      Username string; do not free
 */

char *
username(void) {
	struct passwd *pw;

	pw = getpwuid(geteuid());

	if (pw) {
		return (pw->pw_name);
	} else {
		return((char *) "(unknown ?)");
	}
}



/*!
 * @brief       Recursively create all missing parent directories for the given path
 *
 * Walks each @c / component in @p path and creates any directory that does not yet exist.
 * Does not create the final path component (treats it as a filename).
 * Calls @c fatal() if a directory cannot be created.
 *
 * @param       path        Full file path whose parent directory tree should be created
 */


void
create_subdir(bstring path) {
	struct stat stat_buf;
	char dirname[1024];
	char *p;

	for (p = bdata(path); (p = strchr(p, '/')); p++) {
		if (p == bdata(path))
			continue;

		if ((size_t) (p - bdata(path)) >= sizeof(dirname))
			fatal("create_subdir: path component too long");

		memcpy(dirname, bdata(path), p - bdata(path));
		dirname[p - bdata(path)] = '\0';

		if (stat(dirname, &stat_buf) < 0) {
			int e = 0;
			if (errno != ENOENT) {
				e = errno;
				fatal("Failed to create directory %s as user %s: %s", dirname, username(), strerror(e));
			} else {
				if ((mkdir(dirname, SUSSHI_LOGDIR_MODE) < 0) && (errno != EEXIST)) {
					e = errno;
					fatal("Failed to create directory %s as user %s: %s", dirname, username(), strerror(e));
				}
			}
		}
	}
}


/*!
 * @brief       Check whether a URL is a local HTTP URL (loopback only, no TLS)
 *
 * Matches URLs beginning with @c "http://127.0.0.1" or @c "http://localhost".
 *
 * @param       url     Null-terminated URL string to check
 *
 * @return      @c true if the URL targets localhost over plain HTTP, @c false otherwise
 */


bool is_local_http_url(const char *url) {
	return ((strncmp(url, "http://127.0.0.1", 16) == 0) || (strncmp(url, "http://localhost", 16) == 0));
}


/*!
 * @brief       Parse a dotted-decimal suSSHi version string into a compact uint32_t
 *
 * Splits @p susshi_version on @c '.' and interprets up to three numeric components
 * (major, minor, patch), each in the range [0, 99].  The result is encoded as:
 *
 * @code
 *   *susshi_version_uint32 = major * 10000 + minor * 100 + patch
 * @endcode
 *
 * At least two components (major.minor) must be present for the call to succeed.
 * If the patch component is absent it is treated as zero.  An invalid or
 * out-of-range patch component is silently ignored (the output reflects only
 * major and minor).  Additional components beyond the third are ignored.
 *
 * @param[in]   susshi_version          Bstring containing the version string,
 *                                      e.g. @c "26.03.4".
 * @param[out]  susshi_version_uint32   Receives the encoded version on success.
 *                                      Left unmodified when the function returns
 *                                      @c false.
 *
 * @return      @c true  on success (at least major.minor parsed, major valid), \n
 *              @c false if fewer than two components are present or the major
 *              component cannot be parsed as an integer in [0, 99].
 */

bool
susshi_parse_version_info(bstring susshi_version, uint32_t *susshi_version_uint32) {
	bstrList splitversion;
	const char *errstr = NULL;
	long long v0, v1;
	bool rc = false;

	splitversion = bsplit(susshi_version, '.');

	if (splitversion->qty >= 2) {
		v0 = strtonum(bdata(splitversion->entry[0]), 0, 99, &errstr);

		if (!errstr) {
			v1 = strtonum(bdata(splitversion->entry[1]), 0, 99, &errstr);

			*susshi_version_uint32 =
					(uint32_t) v0 * 10000 +
					(uint32_t) v1 * 100;

			if (splitversion->qty > 2) {
				long long v2 = strtonum(bdata(splitversion->entry[2]), 0, 99, &errstr);
				if (!errstr)
					*susshi_version_uint32 += (uint32_t) v2;
			}
			rc = true;
		} else {
			return false;
		}
	}

	if (splitversion)
		bstrListDestroy(splitversion);

	return rc;
}

/*! @} */
