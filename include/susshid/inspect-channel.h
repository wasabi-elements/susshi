/*!
 *
 * @brief       Channel Inspection
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
 * @ingroup     inspection_channel
 * @{
 */

#ifndef SUSSHI_INSPECT_CHANNEL_H
#define SUSSHI_INSPECT_CHANNEL_H

#define TheOtherSide(x) (x == CLIENT) ? TARGET : CLIENT

typedef enum {
	OK=0,
	FAIL=1,
	REJECT=2,
	UNKNOWN=3
} ChannelResponse;

typedef enum {
	NONE=0,
	SESS=1,		// Just a state - no real logging
	TEXT=2,
	EXEC=3,
	EXEC_TEXT=4,
	SFTP=5,
	SCP=6,
	TCPIP=7,
	X11=8,
	AGENT=9,
	SOCKET_FWD=10
} ChannelLogging;

typedef enum {
	SCP_UNKNOWN=0,
	SCP_SOURCE=1,
	SCP_SINK=2
} ChannelSCPMode;

typedef struct SusshiChannelStruct SusshiChannel;

#include "inspect-sftp.h"
#include "shared/log.h"

/*
 * Whenever a Channel is opened, we document the requestor (either CLIENT or TARGET) that requested the channel
 * - The requestor_ch is the "sender channel" learned during Channel Open
 * - The provider_ch is the "sender channel" learned during Channel Open Confirmation
 */

struct SusshiChannelStruct {
	int                 cid;                // Channel ID in list
	Side				requestor;			// Where the channel was opened from
	char				*ctype;				// type string
	uint32_t			requestor_ch;		// channel identifier of requestor
	uint32_t			provider_ch;		// channel identifier of recipient
	uint32_t            gateway_requestor_ch;
	uint32_t            gateway_provider_ch;
	int					state;				// Simply a copy of PACKET-TYPE
	long unsigned int	requestor_send;		// Bytes send by requestor
	long unsigned int	provider_send;		// Bytes send by recipient
	struct in_addr		client_forward_in_addr;
	uint				client_forward_port;
	struct in_addr		target_forward_in_addr;
	uint				target_forward_port;
	ChannelLogging		logging;			// Type of audit trail logging if requested
	SusshiLog			log_target_output;	// Target output loghandle
	SusshiLog			log_client_input;	// Client input (keystrokes) loghandle
	SusshiLog			log_timing;			// Timeing file loghandle
	SusshiLog			log_protocol;		// Protocol-specific logging (SFTP, SCP, TCP/IP ...)
	ChannelSCPMode		scp_requestor_mode;	// SCP_SOURCE or SCP_SINK mode the requestor runs in
	long			    scp_read_ahead;		// Number of bytes that should get skipped on next data from SOURCE to SINK
	bstring				scp_dir_name;		// Current directory
	int					scp_dir_depth;		// Depth in directory recursion

	SftpSession        *sftp_session;       // SftpSession reference if this channel handles sftp session

	bool                proxied_channel;    // True if proxied in Public Key Agent Authentication mode
};


/* Prototypes */
void    susshi_send_shell_env(void);
int     susshi_alloc_new_channel(void);
void    susshi_channel_set_logging(int channel_id, ChannelLogging logtype, bstring termsize, const char *terminal);

bool    susshi_inspect_global_request(Side sender, u_int type, ssh_buffer buffer);
bool    susshi_inspect_channel_open(Side sender, u_int type, ssh_buffer buffer);
bool    susshi_inspect_channel_open_confirm(Side sender, u_int type, ssh_buffer buffer);
bool    susshi_inspect_channel_open_failure(Side sender, u_int type, ssh_buffer buffer);
bool    susshi_inspect_channel_data(Side sender, u_int type, ssh_buffer buffer);
bool    susshi_inspect_channel_close(Side sender, u_int type, ssh_buffer buffer);
bool    susshi_inspect_channel_request(Side sender, u_int type, ssh_buffer buffer);
bool    susshi_inspect_channel_success(Side sender, u_int type, ssh_buffer buffer);
bool    susshi_inspect_channel_failure(Side sender, u_int type, ssh_buffer buffer);
ChannelResponse susshi_inspect_channel_request_exec(Side sender, int channel_id,
													ChannelLogging *logtype, bstring *logtext, ssh_string command,
													ChannelSCPMode *scp_requestor_mode, bstring *scp_dir_name);
ChannelResponse susshi_inspect_channel_request_subsystem(Side sender, int channel_id,
														 ChannelLogging *logtype, bstring *logtext, ssh_string command);
bool    susshi_inspect_channel_window_adjust(Side sender, u_int type, ssh_buffer buffer);
bool    susshi_inspect_channel_eof(Side sender, u_int type, ssh_buffer buffer);
bool    susshi_inspect_debug_message(Side sender, u_int type, ssh_buffer buffer);
bool    susshi_inspect_disconnect(Side sender, u_int type, ssh_buffer buffer);
bool    susshi_inspect_request_success(Side sender, u_int type, ssh_buffer buffer);
void    susshi_free_channel(u_int id);
int     susshi_num_open_channels(void);

#endif //SUSSHI_INSPECT_CHANNEL_H

/*! @} */
