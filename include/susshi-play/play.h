/*!
 *
 * @brief       Play Include
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
 * @ingroup     susshi_play
 * @{
 */


#ifndef SUSSHI_PLAY_DISCOVER_H
#define SUSSHI_PLAY_DISCOVER_H

#define	OPT_VERBOSE	1

#define BIN_PATH_IPBT       "/opt/wasabi/susshi/bin/susshi-ipbt"
#define BIN_PATH_TERMREC    "/usr/local/bin/TermRecord"
#define BIN_PATH_CAT        "/bin/cat"

typedef enum {
	UNKNOWN,
	ACT_CONVERT_TTYREC,
	ACT_CONVERT_HTML,
	ACT_PLAY_SESSION,
	ACT_PRINT_FILE_RAW
} Action;

#endif

/*! @} */
