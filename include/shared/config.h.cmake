/*!
 *
 * @brief		suSSHi Shared library
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
 * @date 2026-20-010
 *
 */

#ifndef SUSSHI_CONFIG_H
#define SUSSHI_CONFIG_H

#define COMPILE_USER "$ENV{USER}"

/* Name of package */
#cmakedefine APPLICATION_NAME "${APPLICATION_NAME}"

/* Version number of package */
#cmakedefine APPLICATION_VERSION "${APPLICATION_VERSION}"

/* suSSHi Version */
#define SUSSHI_VERSION APPLICATION_VERSION

#define SUSSHI_NAME "suSSHi2"

/* suSSHi Build */
#ifndef SUSSHI_BUILD
#define SUSSHI_BUILD "${CMAKE_BUILD_TYPE}"
#endif
#define SUSSHI_BUILD_STR "(" SUSSHI_BUILD " build)"

// Copyright string
#define APPLICATION_COPYRIGHT "(c) 2017-2025 Wasabi Elements GmbH"
#define SUSSHI_COPYRIGHT APPLICATION_COPYRIGHT

#define SUSSHI_RELEASE SUSSHI_VERSION " " SUSSHI_BUILD_STR
#define SUSSHI_WELCOME " - suSSHi2 " SUSSHI_VERSION " by Wasabi Elements"

/* Maximum File Path Lengths */
#ifndef MAXPATHLEN
# ifdef PATH_MAX
#  define MAXPATHLEN PATH_MAX
# else /* PATH_MAX */
#  define MAXPATHLEN 64
/* realpath uses a fixed buffer of size MAXPATHLEN, so force use of ours */
#  ifndef BROKEN_REALPATH
#   define BROKEN_REALPATH 1
#  endif /* BROKEN_REALPATH */
# endif /* PATH_MAX */
#endif /* MAXPATHLEN */

/*************************** ENDIAN *****************************/

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#cmakedefine WORDS_BIGENDIAN 1

#endif //SUSSHI_CONFIG_H
