/*!
 *
 * @brief       Helper methods
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


void    susshi_cleanup(void);

/*!
 * @ingroup     susshid
 * @{
 */

void    fatal(const char *fmt, ...);

bool    validate_string_chars_regex(bstring string, const char *allowed_chars);

void    susshi_prepare_unprivileged_user(void);

#ifdef LINUX

#define CMD_USERMOD "/usr/sbin/usermod"
#define CMD_GROUPMOD "/usr/sbin/groupmod"

#define ENV_SUSSHI_UID  "SUSSHI_UID"
#define ENV_SUSSHI_GID  "SUSSHI_GID"

#endif

/*! @} */
