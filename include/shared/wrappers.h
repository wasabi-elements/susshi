/*!
 *
 * @brief       Wrapper methods
 *
 * @copyright   Copyright (C) 2026 Wasabi Elements GmbH
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
 * @author      Oliver Rauscher <oliver@susshi.io>
 * @date        2026-02-01
 *
 */


#ifndef SUSSHI_WRAPPERS_H
#define SUSSHI_WRAPPERS_H

#include <bstrlib.h>
#include "shared/types.h"


#define xwipe(ptr, len) do { if (ptr == NULL) fatal("xfree: NULL pointer given as argument in line %d in %s().", __LINE__, __func__); else { explicit_bzero(ptr, len); free(ptr); } } while(0)

#define bstrWipe(b)     do { if ((b) != NULL && (b)->slen >= 0 && (b)->mlen >= (b)->slen) { explicit_bzero(bdata(b), b->mlen); bdestroy (b); (b) = NULL; } } while(0)

void bstrListWipe(bstrList list);

const char *susshi_gai_strerror(int gaierr);

void susshi_setproctitle(const char *fmt, ...);

void *xmalloc(size_t);

void *xcalloc(size_t, size_t);

void *xrealloc(void *, size_t, size_t);

void xfree(void *);

#define xfree(ptr) do { if (ptr == NULL) fatal("xfree: NULL pointer given as argument in line %d in %s().", __LINE__, __func__); else free(ptr); } while(0)

int xasprintf(char **, const char *, ...)
	__attribute__((__format__ (printf, 2, 3)))
	__attribute__((__nonnull__ (2)));

char *xstrdup(const char *);


#endif //SUSSHI_WRAPPERS_H
