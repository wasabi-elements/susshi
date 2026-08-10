/*!
 *
 * @brief       Unix Socket Inspection
 *
 * @ingroup     inspection
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
 * @defgroup    inspection_unixsock Unix Domain Socket Forwarding Inspection
 * @brief       Functions to inspect Unix domain socket forwarding communication.
 *
 * @{
 */

#include "susshid/common.h"


/*!
 * @brief       Inspect Socket Forwarding Data
 *
 * @param       cid             Channel ID
 * @param       sender          Side this bytestream packet comes from
 * @param       buffer_copy     A copy of the packet
 */

void
susshi_inspect_socketfwd_data(int cid, Side sender, ssh_buffer buffer_copy) {

	ssh_string datastr = NULL;

	if (ssh_buffer_unpack(buffer_copy, "S", &datastr) != SSH_OK) {
		fatal("Packet decoding returned with fatal error: Inspect Socket Forwarding Data.");
	}

	do_log_tcp(cid, sender, datastr);
	SSH_STRING_FREE(datastr);
}

/*! @} */
