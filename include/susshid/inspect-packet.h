/*!
 *
 * @brief       Packet Inspection
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
 * @ingroup     inspection
 * @{
 */

#ifndef SUSSHI_INSPECT_PACKET_H
#define SUSSHI_INSPECT_PACKET_H

/* Range of Messages intercepted / understood by suSSHi */
#define RANGE_SSH2_MSG_SUSSHI_RANGE1_MIN                   1
#define RANGE_SSH2_MSG_SUSSHI_RANGE1_MAX                   6
#define RANGE_SSH2_MSG_SUSSHI_RANGE2_MIN                   50
#define RANGE_SSH2_MSG_SUSSHI_RANGE2_MAX                   100

/* Prototypes */

bool	susshi_inspect_packet(Side sender, u_int type, ssh_buffer buffer);
bool    susshi_inspect_unimplemented_message(Side sender, u_int type, ssh_buffer buffer);
void	do_susshi_debug_remaining_packet(ssh_buffer buffer);

#ifdef WITH_FULL_DEBUG_OPTIONS
#define susshi_debug_remaining_packet(buffer)	if (log_level >= LOG_DEBUG_PACKETDUMP) do_susshi_debug_remaining_packet(buffer)
#else
#define susshi_debug_remaining_packet(...)
#endif

#endif //SUSSHI_INSPECT_PACKET_H

/*! @} */
