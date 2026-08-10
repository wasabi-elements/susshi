/*!
 *
 * @brief       Common Include
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
 * @date        2026-06-22
 *
 * @ingroup     susshi_decrypt
 * @{
 */

#ifndef SUSSHI_DECRYPT_COMMON_H
#define SUSSHI_DECRYPT_COMMON_H

#define _GNU_SOURCE
#define SIZE_T_MAX ((size_t) -1)

#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include <sodium.h>

/* Better String library */
#include <bstraux.h>

/* suSSHi suite-wide shared */
#include "shared/config.h"
#include "shared/log-enc.h"
#include "shared/wrappers.h"

#include "version.h"

#endif /* SUSSHI_DECRYPT_COMMON_H */

/*! @} */
