/*!
 *
 * @brief       Simple hexdump in hex editor style
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
#ifndef SUSSHI_HEXDUMP_H
#define SUSSHI_HEXDUMP_H

void do_susshi_hexdump(const char *data, size_t datalen);

void do_susshi_hexdump_ssh_buffer(ssh_buffer buffer);

#ifdef WITH_FULL_DEBUG_OPTIONS
#define debug_susshi_hexdump(...)			    if (log_level >= LOG_DEBUG_PACKET) do_susshi_hexdump(__VA_ARGS__)
#define debug_susshi_hexdump_ssh_buffer(...)	if (log_level >= LOG_DEBUG_PACKET) do_susshi_hexdump_ssh_buffer(__VA_ARGS__)
#else
#define debug_susshi_hexdump(...)
#define debug_susshi_hexdump_ssh_buffer(...)
#endif


#endif //SUSSHI_HEXDUMP_H
