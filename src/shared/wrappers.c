/*!
 *
 * @brief       Wrapper methods
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
 * Portions of this file (xmalloc, xcalloc, xrealloc, xstrdup, xasprintf)
 * are derived from OpenSSH xmalloc.c:
 *
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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
 * @author      Oliver Rauscher <oliver@susshi.io>
 * @date        2026-02-01
 *
 * @defgroup    wrappers Wrapper methods
 * @{
 */

#include "shared/common.h"


/*!
 * @brief       Zero out all string data in a @c bstrList, then destroy it
 *
 * Safe to call with @c NULL — returns immediately without action.
 *
 * @param       list        The @c bstrList to be wiped and destroyed
 */

void bstrListWipe(bstrList list) {
	if (list == NULL)
		return;

	for (int i=0; i<list->qty; i++)
		if (list->entry[i] != NULL)
			explicit_bzero(bdata(list->entry[i]), blength(list->entry[i]));

	bstrListDestroy(list);
}

/*!
 * @brief       Wrapper for @c gai_strerror that handles @c EAI_SYSTEM by falling back to @c strerror(errno)
 *
 * @param       gaierr      Error code returned by @c getaddrinfo or related functions
 *
 * @return      Human-readable error string; do not free
 */

const char *
susshi_gai_strerror(int gaierr)
{
	if (gaierr == EAI_SYSTEM)
		return strerror(errno);
	return gai_strerror(gaierr);
}


#ifdef HAVE_SETPROCTITLE
#define MSGBUFSIZE 256

/*!
 * @brief       Wrapper for setproctitle to overcome faulty va_args calls
 *
 * @param       fmt     Formatstring
 */

void
susshi_setproctitle(const char *fmt,...)
{
	va_list args;
	char msgbuf[MSGBUFSIZE];

	// Add susshi log prefix
	va_start(args, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, args);
	va_end(args);

	setproctitle("%s", msgbuf);
}
#endif


/*!
 * @brief       Wrapper for malloc
 *
 * The function will never return when allocation fails.
 * It will call fatal() instead which must be provided by the code using this wrapper.
 *
 * @param       size        Amount of memory to be allocated
 *
 * @return      Pointer to allocated memory
 */

void *
xmalloc(size_t size)
{
	void *ptr;

	if (size == 0)
		fatal("xmalloc: zero size");
	ptr = malloc(size);
	if (ptr == NULL)
		fatal("xmalloc: out of memory (allocating %lu bytes)", (u_long) size);
	return ptr;
}


/*!
 * @brief       Wrapper for calloc - Allocates memory for an array of num objects of size
 *
 * The function will never return when allocation fails.
 * It will call fatal() instead which must be provided by the code using this wrapper.
 *
 * @param       nmemb       Number of objects
 * @param       size        Amount of memory to be allocated per object
 *
 * @return      Pointer to allocated memory
 */

void *
xcalloc(size_t nmemb, size_t size)
{
	void *ptr;

	if (size == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	if (SIZE_T_MAX / nmemb < size)
		fatal("xcalloc: nmemb * size > SIZE_T_MAX");
	ptr = calloc(nmemb, size);
	if (ptr == NULL)
		fatal("xcalloc: out of memory (allocating %lu bytes)",
			  (u_long)(size * nmemb));
	return ptr;
}


/*!
 * @brief       Wrapper for realloc - Reallocates memory for an array of num objects of size
 *
 * The function will never return when allocation fails.
 * It will call fatal() instead which must be provided by the code using this wrapper.
 *
 * @param       ptr         Pointer to existing memory
 * @param       nmemb       Number of objects
 * @param       size        Amount of memory to be allocated per object
 *
 * @return      Pointer to allocated memory
 */

void *
xrealloc(void *ptr, size_t nmemb, size_t size)
{
	void *new_ptr;
	size_t new_size = nmemb * size;

	if (new_size == 0)
		fatal("xrealloc: zero size");
	if (SIZE_T_MAX / nmemb < size)
		fatal("xrealloc: nmemb * size > SIZE_T_MAX");
	if (ptr == NULL)
		new_ptr = malloc(new_size);
	else
		new_ptr = realloc(ptr, new_size);
	if (new_ptr == NULL)
		fatal("xrealloc: out of memory (new_size %lu bytes)",
			  (u_long) new_size);
	return new_ptr;
}


/*!
 * @brief       Wrapper for strdup - Copies a string into a new xmalloc'd memory
 *
 * @param       str         Pointer to source string
 *
 * @return      Pointer to string copy
 */

char *
xstrdup(const char *str)
{
	size_t len;
	char *cp;

	len = strlen(str) + 1;
	cp = xmalloc(len);
	strlcpy(cp, str, len);
	return cp;
}


/*!
 * @brief       Wrapper for @c asprintf that calls @c fatal() instead of returning an error
 *
 * Unlike @c asprintf, this function never returns on allocation failure — it calls @c fatal().
 *
 * @param       ret         Receives a pointer to the newly allocated formatted string; must be freed by the caller
 * @param       fmt         @c printf -style format string
 * @param       ...         Format arguments
 *
 * @return      Number of characters written, as per @c asprintf
 */

int
xasprintf(char **ret, const char *fmt, ...)
{
	va_list ap;
	int i;

	va_start(ap, fmt);
	i = vasprintf(ret, fmt, ap);
	va_end(ap);

	if (i < 0 || *ret == NULL)
		fatal("xasprintf: could not allocate memory");

	return (i);
}

/*! @} */
