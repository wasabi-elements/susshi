/*!
 *
 * @brief       Packet Inspection
 *
 * @ingroup     susshid
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
 * @defgroup    inspection Susshid Deep Inspection
 * @brief       Functions to handle inspection within different layers.
 * @ingroup     susshid
 *
 * @defgroup    inspection_packet Packet Inspection
 * @brief       Functions to handle packet inspection.
 * @ingroup     inspection
 *
 * @{
 */

#include "susshid/common.h"


/*!
 * @brief       Inspect packet
 *
 * @param       sender      Side of sender
 * @param       type        Packet type
 * @param       buffer      ssh_buffer
 *
 * @return      true on success
 */

bool
susshi_inspect_packet(Side sender, u_int type, ssh_buffer buffer)
{
	bool copy = false;
	uint32_t packet_len;
	// uint8_t padding;

	/* Padding is in the buffer but libssh already read ahead */
	// padding = (uint8_t) *(buffer->data + buffer->pos -2);

	packet_len = ssh_buffer_get_len(buffer);

	debug4_dir(sender, TheOtherSide(sender), "Received packet of type %d and length %d",
			   type, packet_len);

	debug_susshi_hexdump_ssh_buffer(buffer);

	if (sender == CLIENT)
		susshi_report.client_in_bytes += packet_len;
	else
		susshi_report.target_in_bytes += packet_len;

	switch (type) {
		case SSH2_MSG_CHANNEL_DATA:
		case SSH2_MSG_CHANNEL_EXTENDED_DATA:
			copy = susshi_inspect_channel_data(sender, type, buffer);
			break;

		case SSH2_MSG_GLOBAL_REQUEST:
			copy = susshi_inspect_global_request(sender, type, buffer);
			break;

		case SSH2_MSG_CHANNEL_OPEN:
			copy = susshi_inspect_channel_open(sender, type, buffer);
			break;

		case SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
			copy = susshi_inspect_channel_open_confirm(sender, type, buffer);
			break;

		case SSH2_MSG_CHANNEL_OPEN_FAILURE:
			copy = susshi_inspect_channel_open_failure(sender, type, buffer);
			break;

		case SSH2_MSG_CHANNEL_CLOSE:
			copy = susshi_inspect_channel_close(sender, type, buffer);
			break;

		case SSH2_MSG_CHANNEL_REQUEST:
			copy = susshi_inspect_channel_request(sender, type, buffer);
			break;

		case SSH2_MSG_CHANNEL_SUCCESS:
			copy = susshi_inspect_channel_success(sender, type, buffer);
			break;

		case SSH2_MSG_CHANNEL_FAILURE:
			copy = susshi_inspect_channel_failure(sender, type, buffer);
			break;

		case SSH2_MSG_REQUEST_SUCCESS:
			copy = susshi_inspect_request_success(sender, type, buffer);
			break;

		case SSH2_MSG_REQUEST_FAILURE:
			debug2_dir(sender, TheOtherSide(sender), "CHANNEL REQUEST FAILURE message.");

			// Do not update last_io (idle timer) - could be response to keepalive-message
			susshi_report.update_last_io_time = false;

			copy = true;
			break;

		case SSH2_MSG_CHANNEL_WINDOW_ADJUST:
			copy = susshi_inspect_channel_window_adjust(sender, type, buffer);
			break;

		case SSH2_MSG_CHANNEL_EOF:
			copy = susshi_inspect_channel_eof(sender, type, buffer);
			break;

		case SSH2_MSG_IGNORE:
			// We have to forward IGNORE messages as well
			debug4_dir(sender, TheOtherSide(sender), "IGNORE message.");
			copy = true;
			break;

		case SSH2_MSG_UNIMPLEMENTED:
			copy = susshi_inspect_unimplemented_message(sender, type, buffer);
			break;

		case SSH2_MSG_DEBUG:
			copy = susshi_inspect_debug_message(sender, type, buffer);
			break;

		case SSH2_MSG_DISCONNECT:
			copy = susshi_inspect_disconnect(sender, type, buffer);
			break;

		default:
			if ((type >= RANGE_SSH2_MSG_SUSSHI_RANGE1_MIN && type <= RANGE_SSH2_MSG_SUSSHI_RANGE1_MAX) ||
				(type >= RANGE_SSH2_MSG_SUSSHI_RANGE2_MIN && type <= RANGE_SSH2_MSG_SUSSHI_RANGE2_MAX)) {
				log_session(sender, TheOtherSide(sender), "WARNING! Received message that is in "
						SUSSHI_NAME	"'s range but not handled specific. Message not forwarded!");
				copy = false;
			} else if ((type <= RANGE_SSH2_MSG_SUSSHI_RANGE1_MIN || type >= RANGE_SSH2_MSG_SUSSHI_RANGE1_MAX) &&
					   (type <= RANGE_SSH2_MSG_SUSSHI_RANGE2_MIN || type >= RANGE_SSH2_MSG_SUSSHI_RANGE2_MAX)) {
				log_session(sender, TheOtherSide(sender),
							"WARNING! Received message of UNKNOWN TYPE (%u): %u bytes - Message is forwarded."
							"Do you need a new software version of "
									SUSSHI_NAME
									"?", type, ssh_buffer_get_len(buffer));
				copy = true;
			} else {
				copy = true;
			}

			debug_susshi_hexdump_ssh_buffer(buffer);

			break;
	}

	if (copy) {
		if (sender == CLIENT)
			susshi_report.target_out_bytes += packet_len;
		else
			susshi_report.client_out_bytes += packet_len;
	}

	return copy;
}


/*!
 * @brief       Dump remaining content of a packet
 *
 * @param       buffer      ssh_buffer
 */

void
do_susshi_debug_remaining_packet(ssh_buffer buffer)
{
	uint32_t len;

	if ((len = ssh_buffer_get_len(buffer)) > 0) {
		debug4("Remaining data in packet after inspection (%d bytes):", len);
		do_susshi_hexdump_ssh_buffer(buffer);
	}
}


/*!
 * @brief        Inspect UNIMPLEMENTED message
 *
 * ### RFC 4253 - 11.4.  Reserved Messages
 *
 * ```
 * byte      SSH_MSG_UNIMPLEMENTED
 * uint32    packet sequence number of rejected message
 * ```
 *
 * @param       sender      Side of sender
 * @param       type        Packet type
 * @param       buffer      ssh_buffer
 *
 * @return      true on success
 */

bool
susshi_inspect_unimplemented_message(Side sender, u_int type, ssh_buffer buffer)
{
	bool copy = true;
	struct ssh_buffer_struct buffer_copy;
	ssh_session session;
	u_int32_t seq;

	session = (sender == CLIENT) ? susshi_session.client_session : susshi_session.target_session;

	if (ssh_buffer_get_len(buffer) == 0)
		return false;

	susshi_buffer_duplicate(&buffer_copy, buffer);

	if (ssh_buffer_unpack(&buffer_copy, "d", &seq) != SSH_OK)
		goto decode_error;

	if ((session->flags & SSH_SESSION_FLAG_AUTHENTICATED) &&
		(session->dh_handshake_state != DH_STATE_FINISHED)) {

		/* If we receive an SSH2_MSG_UNIMPLEMENTED packet and we are in state of rekeying, do not forward */
		debug4_dir(sender, GATEWAY, "Received UNIMPLEMENTED message (sequence number %d). Ignored in KEX state.", seq);
		copy = false;
	} else {
		debug4_dir(sender, TheOtherSide(sender), "Received UNIMPLEMENTED message (sequence number %d).", seq);
		copy = true;
	}

	return copy;

	decode_error:
	{
		fatal("Packet decoding returned with fatal error: Inspect Unimplemented Message.");
		return false;
	}
}

/*! @} */
