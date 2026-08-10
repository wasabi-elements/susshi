/*!
 *
 * @brief       Channel Inspection
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
 * @defgroup    inspection_channel Channel Inspection
 * @brief       Functions to handle packet inspection.
 *
 * @{
 */

#include <susshid/common.h>


const char *ChannelLoggingString[] = { "NONE","SESS","TEXT","EXEC","EXEC_TEXT","SFTP","SCP","TCPIP","X11","AGENT","SOCKET" };
const char *ChannelResponseString[] = { "accepted", "failed", "rejected", "unknown and rejected" };
const char *ChannelSCPmodeString[] = { "n/a", "SOURCE", "SINK" };

extern LogLevel log_level;

/* Prototypes */
static void buffer_put_u32(void *vp, uint32_t v);
static int  susshi_find_channel(Side sender, uint32_t sender_ch, uint32_t recipient_ch);
static void susshi_inspect_channel_rewrite_recipientch_on_proxied_channel(Side sender, ssh_buffer buffer, SusshiChannel *channel);
static void susshi_inspect_channel_rewrite_senderch_on_proxied_channel(Side sender, ssh_buffer buffer, SusshiChannel *channel);
static void susshi_inspect_channel_update_proctitle(void);

#define ENV_SUSSHI_USER "SUSSHI_USER"
#define ENV_SUSSHI_MAX_SESSION "SUSSHI_MAX_SESSION"
#define ENV_SUSSHI_MAX_IDLE "SUSSHI_MAX_IDLE"
#define ENV_SUSSHI_SESSION_ID "SUSSHI_SESSION_ID"
#define ENV_SUSSHI_SSH_CONNECTION "SUSSHI_SSH_CONNECTION"


/*!
 * @brief       Writes a 32-bit unsigned integer into a buffer in little-endian byte order.
 *
 * @param       vp  Pointer to the destination buffer. Must point to at least 4 bytes of writable memory.
 * @param       v   The 32-bit unsigned integer value to write.
 *
 * @note        The value is stored in little-endian order (LSB at the lowest address).
 *              No bounds checking is performed on the destination buffer.
 */

static void
buffer_put_u32(void *vp, uint32_t v) {
	uint8_t *p = (uint8_t *)vp;

	p[3] = (uint8_t)(v >> 24) & 0xff;
	p[2] = (uint8_t)(v >> 16) & 0xff;
	p[1] = (uint8_t)(v >> 8) & 0xff;
	p[0] = (uint8_t)v & 0xff;
}


/*!
 * @brief       Rewrite recipient channel on proxied channel
 *
 * @param       sender      Side of sender
 * @param       buffer      ssh_buffer
 * @param       channel     SusshiChannel
 */

static void
susshi_inspect_channel_rewrite_recipientch_on_proxied_channel(Side sender, ssh_buffer buffer, SusshiChannel *channel) {

	if_debug5() {
		uint32_t orig_id;

		orig_id = *(uint32_t *) ssh_buffer_get(buffer);

		if (sender == CLIENT) {
			do_debug5("Rewriting recipient_channel_id on proxied channel from %" PRIu32 " to channel->provider_ch (%" PRIu32 ")", ntohl(orig_id), channel->provider_ch);
		} else {
			do_debug5("Rewriting recipient_channel_id on proxied channel from %" PRIu32 " to channel->requestor_ch (%" PRIu32 ")", ntohl(orig_id), channel->requestor_ch);
		}
	};

	if (sender == CLIENT) {
		buffer_put_u32(ssh_buffer_get(buffer), htonl(channel->provider_ch));
	} else {
		buffer_put_u32(ssh_buffer_get(buffer), htonl(channel->requestor_ch));
	}

}


/*!
 * @brief       Rewrite sender channel on proxied channel
 *
 * @param       sender      Side of sender
 * @param       buffer      ssh_buffer
 * @param       channel     SusshiChannel
 */

static void
susshi_inspect_channel_rewrite_senderch_on_proxied_channel(Side sender, ssh_buffer buffer, SusshiChannel *channel) {

	if_debug5() {
		uint32_t orig_id;

		orig_id = *(uint32_t *) ssh_buffer_get(buffer);

		if (sender == CLIENT) {
			do_debug5("Rewriting sender_channel_id on proxied channel from %" PRIu32 " to channel->gateway_requestor_ch (%" PRIu32 ")", ntohl(orig_id), channel->gateway_requestor_ch);
		} else {
			do_debug5("Rewriting sender_channel_id on proxied channel from %" PRIu32 " to channel->gateway_provider_ch (%" PRIu32 ")", ntohl(orig_id), channel->gateway_provider_ch);
		}
	};

	if (sender == CLIENT) {
		buffer_put_u32(ssh_buffer_get(buffer), htonl(channel->gateway_requestor_ch));
	} else {
		buffer_put_u32(ssh_buffer_get(buffer), htonl(channel->gateway_provider_ch));
	}

}


/*!
 * @brief       Update process proctitle with new process information
 */

static void
susshi_inspect_channel_update_proctitle(void) {

	SETPROCTITLE("%s %s %s@%s",
				 bdata(susshi_session.susshi_uniqid),
				 susshi_report_features(),
				 bdata(susshi_session.susshi_user),
				 bdata(susshi_session.target_identifier));

}


/*!
 * @brief       Send Environment Variable on stored channel (number) to target
 *
 * ### RFC 4254 - 6.4.  Environment Variable Passing
 *
 * ```
 * byte      SSH_MSG_CHANNEL_REQUEST
 * uint32    recipient channel
 * string    "env"
 * boolean   want reply
 * string    variable name
 * string    variable value
 * ```
 */

void
susshi_send_shell_env(void)
{
	if (susshi_session.send_shell_env) {


		// -- SUSSHI_USER
		if (ssh_buffer_pack(susshi_session.target_session->out_buffer, "bdsbss",
							SSH2_MSG_CHANNEL_REQUEST,
							susshi_session.send_shell_env_channel, "env",
							0, ENV_SUSSHI_USER,
							bdata(susshi_session.susshi_user)) != SSH_OK)
			goto encode_error;

		debug3("Sending env " ENV_SUSSHI_USER " = %s on channel %d to target.",
			   bdata(susshi_session.susshi_user), susshi_session.send_shell_env_channel);

		if (ssh_packet_send(susshi_session.target_session) != SSH_OK)
			goto encode_error;

		// -- SUSSHI_SSH_CONNECTION
		{
			bstring ssh_connection = bformat("%s %d %s %d", bdata(susshi_session.client_ip), susshi_session.client_port,
											 bdata(susshi_session.target_ip), susshi_session.target_port);

			if (ssh_buffer_pack(susshi_session.target_session->out_buffer, "bdsbss",
								SSH2_MSG_CHANNEL_REQUEST,
								susshi_session.send_shell_env_channel, "env",
								0, ENV_SUSSHI_SSH_CONNECTION,
								bdata(ssh_connection)) != SSH_OK)
				goto encode_error;

			debug3("Sending env " ENV_SUSSHI_SSH_CONNECTION " = %s on channel %d to target.",
				   bdata(ssh_connection), susshi_session.send_shell_env_channel);

			if (ssh_packet_send(susshi_session.target_session) != SSH_OK)
				goto encode_error;

			bstrFree(ssh_connection);
		}

		// -- SUSSHI_SESSION_ID
		if (ssh_buffer_pack(susshi_session.target_session->out_buffer, "bdsbss",
							SSH2_MSG_CHANNEL_REQUEST,
							susshi_session.send_shell_env_channel, "env",
							0, ENV_SUSSHI_SESSION_ID,
							bdata(susshi_session.susshi_uniqid)) != SSH_OK)
			goto encode_error;

		debug3("Sending env " ENV_SUSSHI_SESSION_ID " = %s on channel %d to target.",
			   bdata(susshi_session.susshi_uniqid), susshi_session.send_shell_env_channel);

		if (ssh_packet_send(susshi_session.target_session) != SSH_OK)
			goto encode_error;

		// -- SUSSHI_MAX_SESSION
		// On target server, user may print this with ' date --date="@$SUSSHI_MAX_SESSION" '
		if (susshi_session.max_session_secs < (uint32_t) -1) {
			bstring numbuf = bformat("%ld", time(NULL)+susshi_session.max_session_secs);

			if (ssh_buffer_pack(susshi_session.target_session->out_buffer, "bdsbss",
								SSH2_MSG_CHANNEL_REQUEST,
								susshi_session.send_shell_env_channel, "env",
								0, ENV_SUSSHI_MAX_SESSION,
								bdata(numbuf)) != SSH_OK)
				goto encode_error;

			debug3("Sending env " ENV_SUSSHI_MAX_SESSION " = %s on channel %d to target.",
				   bdata(numbuf), susshi_session.send_shell_env_channel);

			if (ssh_packet_send(susshi_session.target_session) != SSH_OK)
				goto encode_error;

			bstrFree(numbuf);
		}

		// -- SUSSHI_MAX_IDLE
		if (susshi_session.max_session_idle_secs < (uint32_t) -1) {
			bstring numbuf = bformat("%ld", susshi_session.max_session_idle_secs);
			if (ssh_buffer_pack(susshi_session.target_session->out_buffer, "bdsbss",
								SSH2_MSG_CHANNEL_REQUEST,
								susshi_session.send_shell_env_channel, "env",
								0, ENV_SUSSHI_MAX_IDLE,
								bdata(numbuf)) != SSH_OK)
				goto encode_error;

			debug3("Sending env " ENV_SUSSHI_MAX_IDLE " = %s on channel %d to target.",
				   bdata(numbuf), susshi_session.send_shell_env_channel);

			if (ssh_packet_send(susshi_session.target_session) != SSH_OK)
				goto encode_error;

			bstrFree(numbuf);
		}

		// Clear flag and channel
		susshi_session.send_shell_env = false;
		susshi_session.send_shell_env_channel = -1;
	} else {
		debug3("ALARM! All defect");
	}

	return;

	encode_error:
	{
		fatal("Packet encoding returned with fatal error: Send Shell environment.");
	}
}


/*!
 * @brief       Get number of open channels
 * @return      Number of open channels
 */

int
susshi_num_open_channels(void)
{
	uint32_t i, found;

	for(found = 0, i = 0; i < susshi_session.channels_alloc; i++) {
		if (susshi_session.channels[i] != NULL)
			found++;
	}
	return found;
}


/*!
 * @brief       Allocate new SusshiChannel
 */

int
susshi_alloc_new_channel(void)
{
	SusshiChannel *c;
	u_int i, found;

	/* Do initial allocation if this is the first call. */
	if (susshi_session.channels_alloc == 0) {
		susshi_session.channels_alloc = 10;
		susshi_session.channels = xcalloc(susshi_session.channels_alloc, sizeof(SusshiChannel *));
		for (i = 0; i < susshi_session.channels_alloc; i++)
			susshi_session.channels[i] = NULL;
	}

	/* Try to find a free slot where to put the new channel in. */
	for (i = 0; i < susshi_session.channels_alloc; i++)
		if (susshi_session.channels[i] == NULL) {
			debug4("Allocated susshi_channel with cid=%d.", i);
			/* Found a free slot. */
			c = susshi_session.channels[i] = xcalloc(1, sizeof(SusshiChannel));
			memset(c, 0, sizeof(SusshiChannel));
			return(i);
		}

	/* There are no free slots.  Take last+1 slot and expand the array.  */

	found = susshi_session.channels_alloc;
	if (susshi_session.channels_alloc > 10000)
		fatal("susshi_alloc_new_channel: internal error: channels_alloc %d "
					  "too big.", susshi_session.channels_alloc);
	susshi_session.channels = xrealloc(susshi_session.channels, susshi_session.channels_alloc + 10,
								sizeof(SusshiChannel *));
	susshi_session.channels_alloc += 10;

	debug4("susshi_alloc_new_channel: expanding %d", susshi_session.channels_alloc);

	for (i = found; i < susshi_session.channels_alloc; i++)
		susshi_session.channels[i] = NULL;

	c = susshi_session.channels[found] = xcalloc(1, sizeof(SusshiChannel));
	memset(c, 0, sizeof(SusshiChannel));

	debug4("Allocated susshi_channel with cid=%d.", found);
	return(found);
}


/*!
 * @brief       Free Channel
 *
 * @param       id Channel ID
 */

void
susshi_free_channel(u_int id)
{
	SusshiChannel *c;

	if (id <= susshi_session.channels_alloc && susshi_session.channels[id] != NULL)	{
		c = susshi_session.channels[id];
		// Close log file if in use
		susshi_close_logfile(&c->log_target_output);
		susshi_close_logfile(&c->log_client_input);
		susshi_close_logfile(&c->log_timing);
		susshi_close_logfile(&c->log_protocol);

		// Free memory for string
		if (c->ctype != NULL)
			xfree(c->ctype);

		// Free memory for SusshiChannel
		xfree(susshi_session.channels[id]);
		susshi_session.channels[id]=NULL;
		debug4("Removed susshi_channel with cid=%d.", id);
	}
}


/*!
 * @brief       Find Susshi Channel
 *
 * @param       sender          Side of sender
 * @param       sender_ch       Sender Channel ID
 * @param       recipient_ch    Recipient Channel ID
 *
 * @return      Susshi Channel ID
 */

static int
susshi_find_channel(Side sender, uint32_t sender_ch, uint32_t recipient_ch) {
	uint32_t i;
	bool found = false;

	debug5("susshi_find_channel(requestor = %s, sender_ch = %u, recipient_ch = %u): susshi_session.channels_alloc = %d",
		   SideString[sender], sender_ch, recipient_ch, susshi_session.channels_alloc);

	for (i = 0; i < susshi_session.channels_alloc; i++) {
		// Skip free channels

		if (susshi_session.channels[i] == NULL)
			continue;

		if_debug5() {
			if (susshi_session.channels[i]->proxied_channel) {
				do_debug5("susshi_find_channel(): susshi_session.channels[%u]: proxied_channel = true, requestor = %s, gateway_provider_ch = %u, gateway_requestor_ch = %u,  requestor_ch = %u, provider_ch = %u",
						  i, SideString[susshi_session.channels[i]->requestor],
						  susshi_session.channels[i]->gateway_provider_ch,
						  susshi_session.channels[i]->gateway_requestor_ch,
						  susshi_session.channels[i]->requestor_ch,
						  susshi_session.channels[i]->provider_ch);

			} else {
				do_debug5("susshi_find_channel(): susshi_session.channels[%u]: requestor = %s, requestor_ch = %u, provider_ch = %u",
						  i, SideString[susshi_session.channels[i]->requestor], susshi_session.channels[i]->requestor_ch,
						  susshi_session.channels[i]->provider_ch);

			}
		}

		if (susshi_session.channels[i]->requestor == sender) {

			if (susshi_session.channels[i]->proxied_channel) {
				if (sender_ch != (uint32_t) -1 && susshi_session.channels[i]->gateway_requestor_ch == sender_ch) {
					debug5("susshi_find_channel(): found channel on channels[%u]->gateway_requestor_ch == sender_ch", i);
					found = true;
				}
				if (recipient_ch != (uint32_t) -1 && susshi_session.channels[i]->gateway_provider_ch == recipient_ch) {
					debug5("susshi_find_channel(): found channel on channels[%u]->gateway_provider_ch == recipient_ch", i);
					found = true;
				}
			} else {
				if (sender_ch != (uint32_t) -1 && susshi_session.channels[i]->requestor_ch == sender_ch) {
					debug5("susshi_find_channel(): found channel on channels[%u]->requestor_ch == sender_ch", i);
					found = true;
				}
				if (recipient_ch != (uint32_t) -1 && susshi_session.channels[i]->provider_ch == recipient_ch) {
					debug5("susshi_find_channel(): found channel on channels[%u]->provider_ch == recipient_ch", i);
					found = true;
				}
			}
		}
		if (found)
			return (i);
	}
	debug5("susshi_find_channel(): No matching channel found!");
	return -1;
}


/*!
 * @brief       Set Logging information for channel
 *
 * @param       channel_id      Channel ID
 * @param       logtype         ChannelLogging logtype
 * @param       termsize        Formated "<x>x<y> <xp>x<yp>" string
 * @param       terminal        Terminal
 */

void
susshi_channel_set_logging(int channel_id, ChannelLogging logtype, bstring termsize, const char *terminal) {
	SusshiChannel *channel;

	channel = susshi_session.channels[channel_id];

	switch (logtype) {
		case AGENT: {
			channel->log_protocol.filetype = bfromcstr("agent");
		} break;
		case TEXT:
		case EXEC_TEXT: {
			channel->log_target_output.filetype = bfromcstr("session");
			channel->log_client_input.filetype = bfromcstr("client");
			channel->log_timing.filetype = bfromcstr("time");

			if (terminal)
				bformata(termsize, " %s", terminal);

			/* Create & Init timing Log  */
			if (susshi_session.logging_mask & (SUSSHI_AUDITLOG_TRAIL_CLIENT|SUSSHI_AUDITLOG_TRAIL_TARGET))
				do_log_timing(channel_id, CLIENT, 0, bdata(termsize));

		} break;
		case SCP: {
			channel->log_protocol.filetype = bfromcstr("scp");
			channel->log_protocol.enc_requested = (susshi_cfg.num_session_log_encryption_keys > 0);
		} break;
		case SFTP: {
			channel->log_protocol.filetype = bfromcstr("sftp");
			channel->log_protocol.enc_requested = (susshi_cfg.num_session_log_encryption_keys > 0);
		} break;
		case X11: {
			channel->log_protocol.filetype = bfromcstr("x11.pcap");
		} break;
		default: {
			channel->log_protocol.filetype = bfromcstr("unknown");
		}
	}
}


/*!
 * @brief       Inspect GLOBAL REQUEST message
 *
 * ### RFC 4254 - 4.  Global Requests
 *
 * ```
 * byte      SSH_MSG_GLOBAL_REQUEST
 * string    request name in US-ASCII only
 * boolean   want reply
 * ....      request-specific data follows
 * ```
 *
 * @param       sender      Side of sender
 * @param       type        Unused
 * @param       buffer      ssh_buffer
 *
 * @return      true on success
 */

bool
susshi_inspect_global_request(Side sender, u_int type, ssh_buffer buffer)
{
	uint32_t port;
	ChannelResponse resp = FAIL;
	struct ssh_buffer_struct buffer_copy;
	const char *rname = NULL, *addr = NULL, *spath = NULL;
	u_char want_reply;

	if (ssh_buffer_get_len(buffer) == 0)
		return false;

	susshi_buffer_duplicate(&buffer_copy, buffer);

	if (ssh_buffer_unpack(&buffer_copy, "sb", &rname, &want_reply) != SSH_OK)
		goto decode_error;

	debug2_dir(sender, TheOtherSide(sender), "GLOBAL REQUEST: '%s' / want_reply = %s",
			   rname, (want_reply == 1) ? "yes" : "no");

	if (strcmp(rname, "no-more-sessions@openssh.com") == 0) {

		/* ---- no-more-sessions@openssh.com ----- */
		susshi_session.no_more_sessions = 1;
		resp = OK;
		log_session(sender, TheOtherSide(sender), "OpenSSH - No more sessions requested.");

	} else if (strcmp(rname, "simple@putty.projects.tartarus.org") == 0 ) {

		/* ---- Same meaning as no-more-sessions@openssh.com ----- */
		susshi_session.no_more_sessions = 1;
		resp = OK;
		log_session(sender, TheOtherSide(sender), "PuTTy - No more sessions requested.");

	} else if (strcmp(rname, "tcpip-forward") == 0) {

		/* --- Remote port forwarding */
		if (ssh_buffer_unpack(&buffer_copy, "sd", &addr, &port) != SSH_OK)
			goto decode_error;

		debug3("listen address = %s, listen port = %d", addr, port);

		if (susshi_chef_authz_acl_socket("SSHRemoteForwards", addr, port) == SUSSHI_ACL_ALLOW) {
			debug2("Remote port forwarding accepted by ACL.");
			if (port == 0) {
				if (want_reply) {
					susshi_session.global_req_remote_port_listen_port_0 = true;
					debug2_dir(sender, TheOtherSide(sender), "User requested dynamic port assignment on remote site (port = 0) and should receive server assigned port with next MSG_SUCCESS.");
				}
			}
			resp = OK;
			susshi_report.remote_forwards_accepted++;
		} else {
			resp = REJECT;
			susshi_report.remote_forwards_rejected++;
		}

		log_session(sender, TheOtherSide(sender),
					"Remote port forwarding requested ( listen-address = %s, listen-port = %d ) and %s by ACL.",
					addr, port, ChannelResponseString[resp]);

	} else if (strcmp(rname, "cancel-tcpip-forward") == 0) {

		/* --- Cancel Remote port forwarding request */
		if (ssh_buffer_unpack(&buffer_copy, "sd", &addr, &port) != SSH_OK)
			goto decode_error;

		debug3("listen address = %s, listen port = %d", addr, port);
		resp = OK;

		log_session(sender, TheOtherSide(sender),
					"Cancel of remote port forwarding requested ( listen-address = %s, listen-port = %d ).",
					addr, port);

		susshi_report.remote_forwards_canceled++;

	} else if (strcmp(rname, "keepalive@openssh.com") == 0 || strcmp(rname, "keep-alive@bitvise.com") == 0) {

		/* --- Keepalive support --- */

		// Do not update last_io (idle timer)
		susshi_report.update_last_io_time = false;

		resp = OK;

	} else if (strcmp(rname, "hostkeys-00@openssh.com") == 0) {

		/* --- We will always block attempts to send new host keys towards client --- */
		log_session(sender, TheOtherSide(sender),
					"Requested Hostkey update and rotation (%s) denied.", rname);

		resp = REJECT;
	} else if (strcmp(rname, "hostkeys-prove-00@openssh.com") == 0) {
		if (sender == CLIENT) {
			susshi_hostkeys_update_prove_hostkeys(&buffer_copy);
			return false;
		} else {
			log_session(sender, TheOtherSide(sender),
						"Target should not send hostkeys-prove-00@openssh.com requests! Denied.");
			resp = REJECT;
		}

	} else if (strcmp(rname, "streamlocal-forward@openssh.com") == 0) {

		/* --- Remote port forwarding */
		if (ssh_buffer_unpack(&buffer_copy, "s", &spath) != SSH_OK)
			goto decode_error;

		debug3("socket path = %s", spath);

		if (susshi_chef_authz_acl_bool("SSHSocketForward", true) == SUSSHI_ACL_ALLOW) {
			debug2("Remote Unix domain socket forwarding accepted by ACL.");
			resp = OK;
			susshi_report.remote_forwards_accepted++;
		} else {
			resp = REJECT;
			susshi_report.remote_forwards_rejected++;
		}

		log_session(sender, TheOtherSide(sender),
					"Remote Unix domain socket forwarding accepted requested ( socket path = %s ) and %s by ACL.",
					spath, ChannelResponseString[resp]);

	} else if (strcmp(rname, "cancel-streamlocal-forward@openssh.com") == 0) {

		/* --- Remote port forwarding */
		if (ssh_buffer_unpack(&buffer_copy, "s", &spath) != SSH_OK)
			goto decode_error;

		debug3("socket path = %s", spath);
		resp = OK;

		log_session(sender, TheOtherSide(sender),
					"Cancel of Unix domain socket forwarding requested ( socket path = %s ).", spath);

	}

	susshi_debug_remaining_packet(&buffer_copy);

	if (addr) xfree((void *) addr);
	if (rname) xfree((void *) rname);
	if (spath) xfree((void *) spath);

	if (resp == OK) {
		debug2("GLOBAL REQUEST accepted by ACL.");
		susshi_ssh_set_global_request_state(susshi_session.target_session, SSH_CHANNEL_REQ_STATE_PENDING);
		return true;
	} else {
		if (ssh_buffer_pack((sender == CLIENT) ?
							susshi_session.client_session->out_buffer : susshi_session.target_session->out_buffer,
							"b", SSH2_MSG_REQUEST_FAILURE) != SSH_OK)
			goto encode_error;

		if (ssh_packet_send((sender == CLIENT) ? susshi_session.client_session : susshi_session.target_session) != SSH_OK)
			goto encode_error;

		debug2_dir(GATEWAY, sender, "GLOBAL REQUEST failed by ACL.");
		return false;
	}

	decode_error:
	{
		fatal("Packet decoding returned with fatal error: Inspect Global Request.");
		return false;
	}

	encode_error:
	{
		fatal("Packet encoding returned with fatal error: Inspect Global Request.");
		return false;
	}

}


/*!
 * @brief       Inspect GLOBAL REQUEST message
 *
 * ### RFC 4254 - 4.  Global Requests
 *
 * ```
 * byte     SSH_MSG_REQUEST_SUCCESS
 * ....     response specific data
 * ```
 *
 * @param       sender      Side of sender
 * @param       type        Unused
 * @param       buffer      ssh_buffer
 *
 * @return      true on success
 */

bool
susshi_inspect_request_success(Side sender, u_int type, ssh_buffer buffer) {

	debug2_dir(sender, TheOtherSide(sender), "CHANNEL REQUEST SUCCESS message.");

	if (susshi_session.global_req_remote_port_listen_port_0) {
		uint32_t port;
		struct ssh_buffer_struct buffer_copy;

		if (ssh_buffer_get_len(buffer) == 0)
			return false;

		susshi_buffer_duplicate(&buffer_copy, buffer);

		if (ssh_buffer_unpack(&buffer_copy, "d", &port) == SSH_OK) {
			log_session(sender, TheOtherSide(sender),
						"Server assigned dynamic listen port %d for remote forward.", port);
		}
		susshi_session.global_req_remote_port_listen_port_0 = false;
	}

	/* Keep libSSH Packet-Filter in the right state */
	susshi_session.num_remote_tcp_requests_pending--;
	if (susshi_session.num_remote_tcp_requests_pending > 0) {
		susshi_session.target_session->global_req_state = SSH_CHANNEL_REQ_STATE_PENDING;
	}

	return true;
}


/*!
 * @brief       Inspect CHANNEL OPEN message
 *
 * ### RFC 4254 - 5.1. Opening a Channel
 *
 * ```
 * byte      SSH_MSG_CHANNEL_OPEN
 * string    channel type in US-ASCII only
 * uint32    sender channel
 * uint32    initial window size
 * uint32    maximum packet size
 * ....      channel type specific data follows
 * ```
 *
 * @param       sender      Side of sender
 * @param       type        Unused
 * @param       buffer      ssh_buffer
 *
 * @return      true on success
 */

bool
susshi_inspect_channel_open(Side sender, u_int type, ssh_buffer buffer)
{
	struct ssh_buffer_struct buffer_copy;
	char *ctype = NULL, *srcaddr = NULL, *dstaddr = NULL, *spath = NULL;
	const char *crtxt = NULL;
	uint32_t srcport, dstport;
	uint32_t sender_ch;
	uint32_t max_window;
	uint32_t max_packet;
	int cid = -1;
	SusshiChannel *c;
	ChannelResponse resp = FAIL;
	ChannelLogging logtype = NONE;

	if(ssh_buffer_get_len(buffer) == 0)
		return 0;

	susshi_buffer_duplicate(&buffer_copy, buffer);
	if (ssh_buffer_unpack(&buffer_copy, "sddd", &ctype, &sender_ch, &max_window, &max_packet) != SSH_OK)
		goto decode_error;

	debug2_dir(sender, TheOtherSide(sender), "CHANNEL OPEN: '%s', sender channel = %d, max window = %d, max packet = %d", ctype, sender_ch, max_window, max_packet);

	if (strcmp(ctype, "session") == 0) {

		/* ----- Session ------------------------------------------------ */

		if (sender == CLIENT) {
			if (susshi_session.no_more_sessions == 1) {
				resp = REJECT;
				crtxt = "I can break rules, too. No more sessions allowed.";
			} else {
				resp = OK;
				logtype = SESS;
			}

			log_session(sender, TheOtherSide(sender),
						"Session channel requested and %s by ACL.",
						ChannelResponseString[resp]);

			if (susshi_cfg.send_shell_env == 1) {
				susshi_session.send_shell_env = true;
				debug4("Prepare for env request of SUSSHI_USERNAME (stage 1).");
				susshi_session.send_shell_env_channel = -1;
			}
		} else {
			/* Targets are not allowed to request session on client (see RFC5254 6.1) */
			resp = REJECT;
			crtxt = "Target requested 'session' - looks like a corrupt server.";
		}
	}
	else if (strcmp(ctype, "direct-tcpip") == 0) {

		/* ----- Local port forwarding ---------------------------------- */
		if (ssh_buffer_unpack(&buffer_copy, "sdsd", &dstaddr, &dstport, &srcaddr, &srcport) != SSH_OK)
			goto decode_error;

		debug2_dir(sender, TheOtherSide(sender), "local port-forwarding [%05ld] ( src-address = %s, src-port = %d -> dst-address = %s, dst-port = %d )",
				   susshi_session.uniq_channel_id, srcaddr, srcport, dstaddr, dstport);

		if (susshi_chef_authz_acl_socket("SSHLocalForwards", dstaddr, dstport) == SUSSHI_ACL_ALLOW) {
			resp = OK;
			logtype = TCPIP;
			susshi_report.local_forwards_accepted++;
			log_session(sender, TheOtherSide(sender),
						"Local port forwarding channel requested [%05ld] ( src-address = %s, src-port = %d -> dst-address = %s, dst-port = %d ) "
						"and %s by ACL.",
						susshi_session.uniq_channel_id, srcaddr, srcport, dstaddr, dstport, ChannelResponseString[resp]);
		} else {
			resp = REJECT;
			crtxt = "Port forwarding denied by ACL.";
			susshi_report.local_forwards_rejected++;
			log_session(sender, TheOtherSide(sender),
						"Local port forwarding channel requested ( src-address = %s, src-port = %d -> dst-address = %s, dst-port = %d ) "
						"and %s by ACL.",
						srcaddr, srcport, dstaddr, dstport, ChannelResponseString[resp]);
		}

		debug2("Port forwarding %s by ACL.", ChannelResponseString[resp]);

	} else if (strcmp(ctype, "forwarded-tcpip") == 0) {

		/* ----- Remote port forwarding --------------------------------- */
		if (ssh_buffer_unpack(&buffer_copy, "sdsd", &dstaddr, &dstport, &srcaddr, &srcport) != SSH_OK)
			goto decode_error;

		debug2_dir(sender, TheOtherSide(sender), "remote port-forwarding [%05ld] ( src-address = %s, src-port = %d -> listen-address = %s, listen-port = %d -> target on client side (unknown) )",
				   susshi_session.uniq_channel_id, srcaddr, srcport, dstaddr, dstport);

		// We already checked against ACL in GLOBAL REQUEST, but we check twice
		if (susshi_chef_authz_acl_socket("SSHRemoteForwards", dstaddr, dstport) == SUSSHI_ACL_ALLOW) {
			resp = OK;
			logtype = TCPIP;

			log_session(sender, TheOtherSide(sender),
						"Remote port forwarding channel requested [%05ld] ( src-address = %s, src-port = %d -> listen-address = %s, "
						"listen-port = %d -> target on client side (unknown) ) "
						"and %s by ACL.",
						susshi_session.uniq_channel_id, srcaddr, srcport, dstaddr, dstport, ChannelResponseString[resp]);
		} else {
			resp = REJECT;
			crtxt = "Remote port forwarding denied by ACL.";

			log_session(sender, TheOtherSide(sender),
						"Remote port forwarding channel requested ( src-address = %s, src-port = %d -> listen-address = %s, "
						"listen-port = %d -> target on client side (unknown) ) "
						"and %s by ACL.",
						srcaddr, srcport, dstaddr, dstport, ChannelResponseString[resp]);		}

		debug2("Remote port forwarding %s by ACL.", ChannelResponseString[resp]);

	} else if (strcmp(ctype, "x11") == 0) {

		/* ----- X11 Forwarding -------------------------------------- */
		if (ssh_buffer_unpack(&buffer_copy, "sd", &srcaddr, &srcport) != SSH_OK)
			goto decode_error;

		resp = OK;
		logtype = X11;

		log_session(sender, TheOtherSide(sender),
					"X11 channel requested ( originator: %s, port %d ) and %s by ACL.",
					srcaddr, srcport, ChannelResponseString[resp]);

	} else if (strcmp(ctype, "tun@openssh.com") == 0) {

		/* ----- Tunnel Interfaces -------------------------------------- */

		resp = REJECT;
		crtxt = "Hey dude, using a tunnel interface will break the rules.";

		log_session(sender, TheOtherSide(sender),
					"Tunnel Interface (tun@openssh.com) requested but denied by " SUSSHI_NAME ".");

		susshi_report.tunnel_interfaces_rejected++;

	} else if (strncmp(ctype, "auth-agent", 10) == 0) {

		/* ----- Auth-Agent --------------------------------------------- */

		if (susshi_chef_authz_acl_bool("SSHAgentForward", true) == SUSSHI_ACL_ALLOW) {
			resp = OK;
			logtype = AGENT;
			susshi_report.agent_forwards_accepted++;
		} else {
			resp = REJECT;
			susshi_report.agent_forwards_rejected++;
		}

		log_session(sender, TheOtherSide(sender),
					"Auth-Agent channel requested and %s by ACL.",
					ChannelResponseString[resp]);

	} else if (strcmp(ctype, "direct-streamlocal@openssh.com") == 0) {

		/* ----- Direct Stream Local (Client->Server) ---------------------------------- */
		/*
		 * 	byte		SSH_MSG_CHANNEL_OPEN
		 * 	(string		"direct-streamlocal@openssh.com"  )
		 * 	(uint32		sender channel                    )
		 * 	(uint32		initial window size               )
		 * 	(uint32		maximum packet size               )
		 * 	---
		 * 	string		socket path
		 * 	string		reserved
		 * 	uint32		reserved
		 */
		if (ssh_buffer_unpack(&buffer_copy, "s", &spath) != SSH_OK)
			goto decode_error;

		debug2_dir(sender, TheOtherSide(sender), "Local Unix domain socket forwarding [%05ld] ( socket-path = %s )",
				   susshi_session.uniq_channel_id, spath);

		if (susshi_chef_authz_acl_bool("SSHSocketForward", true) == SUSSHI_ACL_ALLOW) {
			resp = OK;
			logtype = SOCKET_FWD;
			susshi_report.local_forwards_accepted++;
			log_session(sender, TheOtherSide(sender),
						"Local Unix domain socket forwarding requested [%05ld] ( socket-path = %s ) "
						"and %s by ACL.",
						susshi_session.uniq_channel_id, spath, ChannelResponseString[resp]);
		} else {
			resp = REJECT;
			crtxt = "Local Unix domain socket forwarding denied by ACL.";
			susshi_report.local_forwards_rejected++;
			log_session(sender, TheOtherSide(sender),
						"Local Unix domain socket forwarding requested [%05ld] ( socket-path = %s ) "
						"and %s by ACL.",
						susshi_session.uniq_channel_id, spath, ChannelResponseString[resp]);
		}

		debug2("Local Unix domain socket forwarding %s by ACL.", ChannelResponseString[resp]);

	} else if (strcmp(ctype, "forwarded-streamlocal@openssh.com") == 0) {

		/* ----- Direct Stream Local (Server->Client) ---------------------------------- */
		/*
		 * 	byte		SSH_MSG_CHANNEL_OPEN
		 * 	(string		"forwarded-streamlocal@openssh.com"  )
		 * 	(uint32		sender channel                       )
		 * 	(uint32		initial window size                  )
		 * 	(uint32		maximum packet size                  )
		 * 	---
		 * 	string		socket path
		 * 	string		reserved
		 */
		if (ssh_buffer_unpack(&buffer_copy, "s", &spath) != SSH_OK)
			goto decode_error;

		debug2_dir(sender, TheOtherSide(sender), "Remote Unix domain socket forwarding [%05ld] ( socket-path = %s )",
				   susshi_session.uniq_channel_id, spath);

		if (susshi_chef_authz_acl_bool("SSHSocketForward", true) == SUSSHI_ACL_ALLOW) {
			resp = OK;
			logtype = SOCKET_FWD;
			susshi_report.local_forwards_accepted++;
			log_session(sender, TheOtherSide(sender),
						"Remote Unix domain socket forwarding requested [%05ld] ( socket-path = %s ) "
						"and %s by ACL.",
						susshi_session.uniq_channel_id, spath, ChannelResponseString[resp]);
		} else {
			resp = REJECT;
			crtxt = "Remote Unix domain socket forwarding denied by ACL.";
			susshi_report.local_forwards_rejected++;
			log_session(sender, TheOtherSide(sender),
						"Remote Unix domain socket forwarding requested [%05ld] ( socket-path = %s ) "
						"and %s by ACL.",
						susshi_session.uniq_channel_id, spath, ChannelResponseString[resp]);
		}

		debug2("Remote Unix domain socket forwarding %s by ACL.", ChannelResponseString[resp]);

	} else {

		/* ----- Unknown ------------------------------------------------ */

		resp = UNKNOWN;
		crtxt = "Unknown channel type.";

		log_session(sender, TheOtherSide(sender),
					"Unknown channel type (%s) requested and denied by " SUSSHI_NAME ".", ctype);
	}

	susshi_debug_remaining_packet(&buffer_copy);

	if (resp == OK) {
		cid = susshi_alloc_new_channel();
		c = susshi_session.channels[cid];
		c->cid = cid;
		c->requestor=sender;
		c->ctype = xmalloc(strlen(ctype)+1);
		strncpy(c->ctype, ctype, strlen(ctype)+1);

		/* Now we get the requestor_ch in "sender channel" */
		c->requestor_ch = sender_ch;
		c->provider_ch = -1;
		c->logging = logtype;
		c->state = SSH2_MSG_CHANNEL_OPEN;
		c->proxied_channel = false;

		// c->sftp_data_sender = NODIR;

		// Initialize Log file descriptors and options

		c->log_target_output.fd = NULL;
		c->log_target_output.logformat = susshi_cfg.logfile_audit;
		c->log_target_output.filename = NULL;
		c->log_target_output.ucid = susshi_session.uniq_channel_id;
		c->log_target_output.enc_requested = (susshi_cfg.num_session_log_encryption_keys > 0);

		c->log_client_input.fd = NULL;
		c->log_client_input.logformat = susshi_cfg.logfile_audit;
		c->log_client_input.filename = NULL;
		c->log_client_input.ucid = susshi_session.uniq_channel_id;
		c->log_client_input.enc_requested = (susshi_cfg.num_session_log_encryption_keys > 0);

		c->log_timing.fd = NULL;
		c->log_timing.logformat = susshi_cfg.logfile_audit;
		c->log_timing.filename = NULL;
		c->log_timing.ucid = susshi_session.uniq_channel_id;
		c->log_timing.enc_requested = (susshi_cfg.num_session_log_encryption_keys > 0);

		c->log_protocol.fd = NULL;
		c->log_protocol.logformat = susshi_cfg.logfile_audit;
		c->log_protocol.filename = NULL;
		c->log_protocol.ucid = susshi_session.uniq_channel_id;

		susshi_session.uniq_channel_id++;

		if (logtype == TCPIP) {
			c->log_protocol.filetype = bfromcstr("portfwd.pcap");
			c->log_protocol.enc_requested = (susshi_cfg.num_session_log_encryption_keys > 0);
			c->client_forward_in_addr.s_addr = (127<<24) + (1<<16) + (1<<8) + 1;
			c->client_forward_port = srcport;
			c->target_forward_in_addr.s_addr = (127<<24) + (2<<16) + (2<<8) + 2;
			c->target_forward_port = dstport;
		} else if (logtype == X11) {
			if (c->log_protocol.filetype != NULL)
				bstrFree(c->log_protocol.filetype);
			c->log_protocol.filetype = bfromcstr("x11.pcap");
			c->log_protocol.enc_requested = (susshi_cfg.num_session_log_encryption_keys > 0);

			c->client_forward_in_addr.s_addr = (127<<24) + (1<<16) + (1<<8) + 1;
			c->client_forward_port = (uint) -1;
			c->target_forward_in_addr.s_addr = (127<<24) + (2<<16) + (2<<8) + 2;
			c->target_forward_port = 6000;
		} else if (logtype == SOCKET_FWD) {
			if (c->log_protocol.filetype != NULL)
				bstrFree(c->log_protocol.filetype);
			c->log_protocol.filetype = bfromcstr("socket.pcap");
			c->log_protocol.enc_requested = (susshi_cfg.num_session_log_encryption_keys > 0);

			c->client_forward_in_addr.s_addr = (127<<24) + (1<<16) + (1<<8) + 1;
			c->client_forward_port = (uint) -1;
			c->target_forward_in_addr.s_addr = (127<<24) + (2<<16) + (2<<8) + 2;
			c->target_forward_port = (uint) -1;
		} else {
			// For all other log types the c->log_protocol.filetype is set later at susshi_inspect_channel_request()
			if (c->log_protocol.filetype != NULL)
				bstrFree(c->log_protocol.filetype);
		}

		susshi_report.channels_opened++;
		susshi_inspect_channel_update_proctitle();

		if(ctype)
			xfree((void *) ctype);
		if(srcaddr)
			xfree((void *) srcaddr);
		if(dstaddr)
			xfree((void *) dstaddr);
		if (spath)
			xfree((void *) spath);

		return true;

	} else {

		if (ssh_buffer_pack((sender == CLIENT) ?
							susshi_session.client_session->out_buffer : susshi_session.target_session->out_buffer,
							"bddss", SSH2_MSG_CHANNEL_OPEN_FAILURE, sender_ch,
							(resp == UNKNOWN) ? SSH2_OPEN_UNKNOWN_CHANNEL_TYPE : SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED,
							crtxt, "") != SSH_OK)
			goto encode_error;

		if (ssh_packet_send((sender == CLIENT) ? susshi_session.client_session : susshi_session.target_session) != SSH_OK)
			goto encode_error;

		debug2_dir(GATEWAY, sender, "%s - Sending a CHANNEL OPEN FAILURE message to %s.", crtxt, SideString[sender]);

		susshi_report.channels_rejected++;

		if (ctype)
			xfree((void *) ctype);
		if (srcaddr)
			xfree((void *) srcaddr);
		if (dstaddr)
			xfree((void *) dstaddr);
		if (spath)
			xfree((void *) spath);

		return false;
	}


	decode_error:
	{
		fatal("Packet decoding returned with fatal error: Inspect Channel Open.");
		return false;
	}

	encode_error:
	{
		fatal("Packet encoding returned with fatal error: Inspect Channel Open.");
		return false;
	}
}


/*!
 * @brief       Inscpect OPEN CONFIRM message
 *
 * ### RFC 4254 - 5.1. Opening a Channel
 *
 * ```
 * byte      SSH_MSG_CHANNEL_OPEN_CONFIRMATION
 * uint32    recipient channel
 * uint32    sender channel
 * uint32    initial window size
 * uint32    maximum packet size
 * ....      channel type specific data follows
 * ```
 *
 * @param       sender      Side of sender
 * @param       type        Unused
 * @param       buffer      ssh_buffer
 *
 * @return      true on success
 */

bool
susshi_inspect_channel_open_confirm(Side sender, u_int type, ssh_buffer buffer)
{
	int cid = -1;
	uint32_t recipient_channel;
	SusshiChannel *c;
	struct ssh_buffer_struct buffer_copy;
	bool copy = false;

	if(ssh_buffer_get_len(buffer) == 0)
		return false;

	susshi_buffer_duplicate(&buffer_copy, buffer);

	/* For the side that confirms an open request, the sender is the recipient and vise versa */

	if (ssh_buffer_unpack(&buffer_copy, "d", &recipient_channel) != SSH_OK)
		goto decode_error;

	cid = susshi_find_channel(TheOtherSide(sender), recipient_channel, (uint32_t) -1);

	if (cid > -1)
	{
		uint32_t init_win, max_win;

		c = susshi_session.channels[cid];

		/* Now we get the provider_ch in "sender channel" */
		if (ssh_buffer_unpack(&buffer_copy, "ddd", &c->provider_ch, &init_win, &max_win) != SSH_OK)
			goto decode_error;

		c->state = SSH2_MSG_CHANNEL_OPEN_CONFIRMATION;

		/* Clear out counters - important if channel is reused */
		c->requestor_send = 0;
		c->provider_send = 0;

		debug2_dir(sender, TheOtherSide(sender), "CHANNEL OPEN CONFIRMATION: '%s', recipient channel = %d,"
												 "initial window size = %d, maximum window size = %d",
												 c->ctype, recipient_channel, init_win, max_win);
		log_session(sender, TheOtherSide(sender), "Channel open for '%s' confirmed.", c->ctype);

		/* For proxied connections, we have to rewrite the recipient and sender channel ids in the original packet */
		if (c->proxied_channel) {
			susshi_inspect_channel_rewrite_recipientch_on_proxied_channel(sender, buffer, c);
			susshi_inspect_channel_rewrite_senderch_on_proxied_channel(sender, buffer + 4, c);
		}
		copy = true;

		if (susshi_session.send_shell_env) {
			susshi_session.send_shell_env_channel = c->provider_ch;
			susshi_send_shell_env();
		}

	} else {
		log_system(LOG_LEVEL_EMERG, "Fatal: Could not map CHANNEL_OPEN_CONFIRMATION to CHANNEL_OPEN request.");
		copy = false;
	}

	susshi_debug_remaining_packet(&buffer_copy);

	susshi_ssh_set_global_request_state(susshi_session.target_session, SSH_CHANNEL_REQ_STATE_ACCEPTED);

	return copy;

	decode_error:
	{
		fatal("Packet decoding returned with fatal error: Inspect Channel Open Confirm.");
		return false;
	}
}


/*!
 * @brief       Inspect CHANNEL OPEN FAILURE message
 *
 * ### RFC 4254 - 5.1. Opening a Channel
 *
 * ```
 * byte      SSH_MSG_CHANNEL_OPEN_FAILURE
 * uint32    recipient channel
 * uint32    reason code
 * string    description in ISO-10646 UTF-8 encoding [RFC3629]
 * string    language tag [RFC3066]
 * ```
 *
 * @param       sender      Side of sender
 * @param       type        Unused
 * @param       buffer      ssh_buffer
 *
 * @return      true on success
 */

bool
susshi_inspect_channel_open_failure(Side sender, u_int type, ssh_buffer buffer)
{
	struct ssh_buffer_struct buffer_copy;
	bool copy = false;

	int cid = -1;
	uint32_t recipient_channel, reasonc;
	const char *reasons = NULL, *langtag = NULL;

	if(ssh_buffer_get_len(buffer) == 0)
		return false;

	susshi_buffer_duplicate(&buffer_copy, buffer);

	if (ssh_buffer_unpack(&buffer_copy, "ddss", &recipient_channel, &reasonc, &reasons, &langtag) != SSH_OK)
		goto decode_error;

	cid = susshi_find_channel(TheOtherSide(sender), recipient_channel, (uint32_t) -1);

	if (cid != -1)
	{
		log_session(sender, TheOtherSide(sender),
					"CHANNEL OPEN FAILURE: '%s' ... cid = %d, reason = '%s' (code %d), langtag = '%s'",
					susshi_session.channels[cid]->ctype, cid, reasons, reasonc, langtag);

		debug2_dir(sender, TheOtherSide(sender),
				   "CHANNEL OPEN FAILURE: '%s' ... cid = %d, reason = '%s' (code %d), langtag = '%s'",
				   susshi_session.channels[cid]->ctype, cid, reasons, reasonc, langtag);

		if (susshi_session.send_shell_env == true) {
			debug3("Cancel preparation for env request of SUSSHI_* variables.");
			susshi_session.send_shell_env = false;
		}

		/* For proxied connections, we have to rewrite the recipient channel id in the original packet */
		if (susshi_session.channels[cid]->proxied_channel) {
			susshi_inspect_channel_rewrite_recipientch_on_proxied_channel(sender, buffer, susshi_session.channels[cid]);
		}

		susshi_report.channels_failed++;
		susshi_free_channel(cid);
		copy = true;
	}
	else {
		debug2_dir(sender, TheOtherSide(sender), "CHANNEL OPEN FAILURE: Unknown error");
	}

	susshi_ssh_set_global_request_state(susshi_session.target_session, SSH_CHANNEL_REQ_STATE_DENIED);

	if(reasons)	xfree((void *) reasons);
	if(langtag)	xfree((void *) langtag);
	return copy;

	decode_error:
	{
		fatal("Packet decoding returned with fatal error: Inspect Channel Open Failure.");
		return false;
	}
}


/*!
 * @brief       Inspect CHANNEL DATA message
 *
 * ### RFC 4254 - 5.2. Data Transfer
 *
 * ```
 * byte      SSH_MSG_CHANNEL_DATA
 * uint32    recipient channel
 * string    data
 * ```
 *
 * @param       sender      Side of sender
 * @param       type        Type
 * @param       buffer      ssh_buffer
 *
 * @return      true on success
 */

bool
susshi_inspect_channel_data(Side sender, u_int type, ssh_buffer buffer)
{
	struct ssh_buffer_struct buffer_copy;
	bool copy = false;

	int cid = -1;
	size_t datalen;
	uint32_t len, recipient_channel, exttype;
	ssh_string data = NULL;
	SusshiChannel *c;

	if ((len = ssh_buffer_get_len(buffer)) == 0)
		return false;

	susshi_buffer_duplicate(&buffer_copy, buffer);

	if (ssh_buffer_unpack(&buffer_copy, "d", &recipient_channel) != SSH_OK)
		goto decode_error;

	if (type == SSH2_MSG_CHANNEL_EXTENDED_DATA) {
		if (ssh_buffer_unpack(&buffer_copy, "d", &exttype) != SSH_OK)
			goto decode_error;
	} else {
		exttype = 0;
	}

	cid = susshi_find_channel(sender, (uint32_t) -1, recipient_channel);

	if (cid == -1)
		cid = susshi_find_channel(TheOtherSide(sender), recipient_channel, (uint32_t) -1);

	if (cid != -1) {

		c = susshi_session.channels[cid];

		debug4_dir(sender, TheOtherSide(sender), "%sCHANNEL DATA (%d bytes): '%s' / recipient_ch = %d / logging = %s",
				   (type == SSH2_MSG_CHANNEL_EXTENDED_DATA) ? "EXTENDED " : "", len,
				   c->ctype, recipient_channel,
				   ChannelLoggingString[c->logging]);

		copy = true;

		switch (c->logging) {
			case SCP:
				/* SCP inspection */
				if (susshi_session.logging_mask & SUSSHI_AUDITLOG_FILETRANSFER) {
					susshi_inspect_scp_data(cid, sender, &buffer_copy);
				}
				break;

			case SFTP:
				/* SFTP inspection */
				if (susshi_session.logging_mask & SUSSHI_AUDITLOG_FILETRANSFER) {
					if (c->sftp_session == NULL) {
						if (sender == CLIENT) {
							susshi_new_sftp_session(cid, &buffer_copy);
						} else {
							fatal("SFTP reply from target but without request from client before.");
						}
					} else {
						susshi_inspect_sftp_packet(c->sftp_session, sender, &buffer_copy);
					}
				}
				break;

			case TEXT:
				/* Standard interactive session inspection */
				if (ssh_buffer_unpack(&buffer_copy, "S", &data) != SSH_OK)
					goto decode_error;

				datalen = ssh_string_len(data);

				/* Target (server) output logging */
				if ((sender == TARGET) && (susshi_session.logging_mask & SUSSHI_AUDITLOG_TRAIL_TARGET))
					do_log_target_output(cid, ssh_string_get_char(data), ssh_string_len(data));

				/* Keystroke logging */
				if ((sender == CLIENT) && (susshi_session.logging_mask & SUSSHI_AUDITLOG_TRAIL_CLIENT))
					do_log_client_input(cid, ssh_string_get_char(data), datalen);

				break;

			case EXEC_TEXT:

				/* Target (server) output logging */
				if ((sender == TARGET) &&
					(susshi_session.logging_mask & SUSSHI_AUDITLOG_TRAIL_TARGET) &&
					(c->log_target_output.filesize < susshi_cfg.logfile_exec_max_size)) {
					if (ssh_buffer_unpack(&buffer_copy, "S", &data) != SSH_OK)
						goto decode_error;
					do_log_target_output(cid, ssh_string_get_char(data), ssh_string_len(data));
				}

				// Keystroke logging
				if ((sender == CLIENT) &&
					(susshi_session.logging_mask & SUSSHI_AUDITLOG_TRAIL_CLIENT) &&
					(c->log_client_input.filesize < susshi_cfg.logfile_exec_max_size)) {
					if (ssh_buffer_unpack(&buffer_copy, "S", &data) != SSH_OK)
						goto decode_error;
					do_log_client_input(cid, ssh_string_get_char(data), ssh_string_len(data));
				}

				break;

			case EXEC:
				/* Exec session inspection */
				break;

			case TCPIP:
				/* Port forwarding inspection */
				if (susshi_session.logging_mask & SUSSHI_AUDITLOG_PORTFORWARD) {
					copy = susshi_inspect_pfwd_data(cid, sender, &buffer_copy);
				}
				break;

			case X11:
				/* X11 inspection */
				if (susshi_session.logging_mask & SUSSHI_AUDITLOG_X11) {
					susshi_inspect_x11_data(cid, sender, &buffer_copy);
				}
				break;

			case AGENT:
				/* SSH-Agent Inspection */
				if (susshi_session.logging_mask & SUSSHI_AUDITLOG_AGENT) {
					susshi_inspect_agent_data(cid, sender, &buffer_copy);
				}
				break;

			case SOCKET_FWD:
				/* Unix domain socket forwarding inspection */
				if (susshi_session.logging_mask & SUSSHI_AUDITLOG_SOCKET) {
					susshi_inspect_socketfwd_data(cid, sender, &buffer_copy);
				}
				break;

			default:
				if_debug5() {
					if (ssh_buffer_unpack(&buffer_copy, "S", &data) != SSH_OK)
						goto decode_error;

					// Dump data in hex editor style
					do_susshi_hexdump(ssh_string_get_char(data), (size_t) ssh_string_len(data));
				}
				if (exttype == SSH2_EXTENDED_DATA_STDERR) {
					// stderr logging
					// Prepend (stderr) to loglines ???
				}
				break;
		}
		// Count bytes send through this channel
		if (sender == c->requestor)
			c->requestor_send += len;
		else
			c->provider_send += len;

		/* For proxied connections, we have to rewrite the recipient channel id in the original packet */
		if (c->proxied_channel) {
			susshi_inspect_channel_rewrite_recipientch_on_proxied_channel(sender, buffer, c);
		}
	}
	else {
		debug2_dir(sender, TheOtherSide(sender), "CHANNEL %d not found !?! ... I can break rules, too.",
				   recipient_channel);
		copy = false;
	}

	if (data) SSH_STRING_FREE(data);

	return copy;

	decode_error:
	{
		fatal("Packet decoding returned with fatal error: Inspect Channel Data.");
		return false;
	}
}


/*!
 * @brief       Inspect CHANNEL CLOSE message
 *
 * ### RFC 4254 - 5.3. Closing a Channel
 *
 * ```
 * byte      SSH_MSG_CHANNEL_CLOSE
 * uint32    recipient channel
 * ```
 *
 * @param       sender      Side of sender
 * @param       type        Unused
 * @param       buffer      ssh_buffer
 *
 * @return      true on success
 */

bool
susshi_inspect_channel_close(Side sender, u_int type, ssh_buffer buffer)
{
	struct ssh_buffer_struct buffer_copy;

	int cid;
	uint32_t recipient_channel;

	if(ssh_buffer_get_len(buffer) == 0)
		return false;

	susshi_buffer_duplicate(&buffer_copy, buffer);

	if (ssh_buffer_unpack(&buffer_copy, "d", &recipient_channel) != SSH_OK)
		goto decode_error;

	cid = susshi_find_channel(TheOtherSide(sender), recipient_channel, (uint32_t) -1);

	if (cid == -1)
		cid = susshi_find_channel(sender, (uint32_t) -1, recipient_channel);

	if (cid != -1) {
		if (susshi_session.channels[cid]->logging == SFTP)
			susshi_free_sftp_session(cid);

		log_session(sender, TheOtherSide(sender),
					"Channel close for '%s' requested [%05ld] - %lu bytes transfered by client, %lu bytes by target.",
					susshi_session.channels[cid]->ctype,
					susshi_session.channels[cid]->log_protocol.ucid,
					(susshi_session.channels[cid]->requestor == CLIENT) ? susshi_session.channels[cid]->requestor_send : susshi_session.channels[cid]->provider_send,
					(susshi_session.channels[cid]->requestor == TARGET) ? susshi_session.channels[cid]->requestor_send : susshi_session.channels[cid]->provider_send);

		debug2_dir(sender, TheOtherSide(sender), "CHANNEL CLOSE: '%s' [%05ld] - %lu bytes transfered by client, %lu bytes by target.",
				   susshi_session.channels[cid]->ctype,
				   susshi_session.channels[cid]->log_protocol.ucid,
				   (susshi_session.channels[cid]->requestor == CLIENT) ? susshi_session.channels[cid]->requestor_send : susshi_session.channels[cid]->provider_send,
				   (susshi_session.channels[cid]->requestor == TARGET) ? susshi_session.channels[cid]->requestor_send : susshi_session.channels[cid]->provider_send);

		/* For proxied connections, we have to rewrite the recipient channel id in the original packet */
		if (susshi_session.channels[cid]->proxied_channel) {
			susshi_inspect_channel_rewrite_recipientch_on_proxied_channel(sender, buffer, susshi_session.channels[cid]);
		}

		if (susshi_session.channels[cid]->state == SSH2_MSG_CHANNEL_CLOSE) {
			/* We already got an CHANNEL_CLOSE from TheOtherSide, so it is save to finally free the channel */
			susshi_free_channel(cid);
			susshi_report.channels_closed++;
		} else {
			/* This is the first CHANNEL_CLOSE message from "Side", we did not receive one from TheOtherSide as well */
			susshi_session.channels[cid]->state = SSH2_MSG_CHANNEL_CLOSE;
		}
	}
	else {
		debug2_dir(sender, TheOtherSide(sender), "CHANNEL CLOSE: We got a second close message for channel %d ?", recipient_channel);
	}
	return true;

	decode_error:
	{
		fatal("Packet decoding returned with fatal error: Inspect Channel Close.");
		return false;
	}
}


#define SCP_PATH_LEN 4096
#define SCP_OPTION_LEN 100


/*!
 * @brief       Inspection (helper) for exec requests
 *
 * @param       sender              Requesting Side
 * @param       channel_id          Channel ID
 * @param       logtype
 * @param       logtext
 * @param       command             Exec command
 * @param       scp_requestor_mode
 * @param       scp_dir_name
 *
 * @return      ChannelResponse
 */

ChannelResponse
susshi_inspect_channel_request_exec(Side sender, int channel_id,
									ChannelLogging *logtype, bstring *logtext, ssh_string command,
									ChannelSCPMode *scp_requestor_mode, bstring *scp_dir_name) {

	ChannelResponse response = FAIL;

	const char *cmd;
	size_t cmd_len;

	pcre2_code *pcre_re;
	int pcre_errorcode = 0;
	PCRE2_SIZE pcre_erroffset;

	bstring scp_path1 = NULL,
			scp_path2 = NULL,
			scp_options = NULL;

	cmd = ssh_string_get_char(command);
	cmd_len = ssh_string_len(command);

	/*
	 * Look for a "scp" call in exec string
	 */

	pcre_re = pcre2_compile((PCRE2_SPTR)"^(/[\\/a-zA-Z0-9]*|)scp(( -[-dfpqrtv])+)\\s(.*).*$",
							PCRE2_ZERO_TERMINATED, 0, &pcre_errorcode, &pcre_erroffset, NULL);

	if (pcre_re != NULL) {

		pcre2_match_data *pcre_md = pcre2_match_data_create_from_pattern(pcre_re, NULL);
		if (pcre_md != NULL && pcre2_match(pcre_re, (PCRE2_SPTR)cmd, cmd_len, 0, 0, pcre_md, NULL) >= 0) {
			PCRE2_SIZE *pcre_ovector = pcre2_get_ovector_pointer(pcre_md);

			/* Now we have to check the pathnames given in substrings $1 and $4 */

			scp_path1 = bformat("%.*s", (int)(pcre_ovector[2 * 1 + 1] - pcre_ovector[2 * 1]), cmd + pcre_ovector[2 * 1]);
			scp_path2 = bformat("%.*s", (int)(pcre_ovector[2 * 4 + 1] - pcre_ovector[2 * 4]), cmd + pcre_ovector[2 * 4]);

			if ((scp_path1 == NULL) || (blength(scp_path1) > SCP_PATH_LEN) ||
				(scp_path2 == NULL) || (blength(scp_path2) > SCP_PATH_LEN)) {
				log_session(sender, TheOtherSide(sender), "Malformed SCP request. Path to long. Disconnecting.");
				susshi_disconnect_standard(BOTH, DISCONNECT_INTERNAL_ERROR);
			}

			debug2("scp_path1=%s, scp_path2=%s", bdata(scp_path1), bdata(scp_path2));

			if (is_valid_scp_filepath(scp_path1) || is_valid_scp_filepath(scp_path2)) {

				*logtype = SCP;
				*scp_requestor_mode = SCP_UNKNOWN;

				// Now we have to distinguish between SOURCE and SINK mode

				// We look into $2 substring to check for option "-f" or "-t" representing SOURCE or SINK mode
				scp_options = bformat("%.*s", (int)(pcre_ovector[2 * 2 + 1] - pcre_ovector[2 * 2]), cmd + pcre_ovector[2 * 2]);

				if (strstr(bdata(scp_options), "-f") != NULL) {
					// SCP SINK mode
					*scp_requestor_mode = SCP_SINK;
				} else if (strstr(bdata(scp_options), "-t") != NULL) {
					// SCP SOURCE mode
					*scp_requestor_mode = SCP_SOURCE;
				}

				if (*scp_requestor_mode != SCP_UNKNOWN) {
					if (susshi_chef_authz_acl_bool("SSHSecureCopy", true) == SUSSHI_ACL_ALLOW) {
						if (is_valid_scp_filepath(scp_path1))
							*scp_dir_name = bstrcpy(scp_path1);
						if (is_valid_scp_filepath(scp_path2))
							*scp_dir_name = bfromcstr(dirname(bdata(scp_path2)));

						*logtext = bformat("SCP request '%s' accepted by ACL. %s in SCP %s mode.",
										   cmd, SideString[sender],
										   ChannelSCPmodeString[*scp_requestor_mode]);
						response = OK;
						susshi_report.scp_sessions++;

						if (susshi_session.logging_mask & SUSSHI_AUDITLOG_FILETRANSFER) {
							log_session(sender, TheOtherSide(sender),
										"Start %s journaling on susshi channel id %d",
										ChannelLoggingString[*logtype], channel_id);
						}

					} else {
						*logtext = bformat("SCP request '%s' denied by ACL.", cmd);
						response = REJECT;
					}

				} else {
					*logtext = bformat("Malformed SCP request '%s' denied by ACL.", cmd);
					response = REJECT;
					susshi_report.command_execs_rejected++;
				}
			}
		}
		pcre2_match_data_free(pcre_md);
		pcre2_code_free(pcre_re);
	} else {
		PCRE2_UCHAR errbuf[256];
		pcre2_get_error_message(pcre_errorcode, errbuf, sizeof(errbuf));
		debug3("susshi_inspect_channel_request: PCRE compile error %s", (char *)errbuf);
		fatal("susshi_inspect_channel_request: PCRE compile error");
	}

	if (*logtype != SCP) {

		if ((susshi_chef_authz_acl_bool("SSHInteractive", true) == SUSSHI_ACL_ALLOW) ||
			susshi_chef_authz_acl_regex("SSHCommandExecs", (char *) cmd, true) == SUSSHI_ACL_ALLOW) {
			*logtext = bformat("Exec request '%s' accepted by ACL.", cmd);
			response = OK;

			// If we already got a pty-req, logtype is already set to TEXT
			if (*logtype != TEXT) {

				// Determine if a stop pattern prevents logging of the EXEC command.
				*logtype = EXEC_TEXT;

				for(int i=0; i < susshi_cfg.num_exec_log_stop_pattern; i++) {
					pcre2_match_data *stop_md = pcre2_match_data_create_from_pattern(susshi_cfg.exec_log_stop_pattern_pcre[i], NULL);
					if (stop_md != NULL && pcre2_match(susshi_cfg.exec_log_stop_pattern_pcre[i], (PCRE2_SPTR)cmd, cmd_len, 0, 0, stop_md, NULL) >= 0) {
						debug2("Log stop pattern '%s' (#%d) matched. Logging of EXEC command disabled.",
							   bdata(susshi_cfg.exec_log_stop_pattern[i]), i+1);
						log_session(sender, TheOtherSide(sender),
									"Log stop pattern (#%d) matched. Logging of EXEC command disabled.", i+1);
						*logtype = EXEC;
					}
					pcre2_match_data_free(stop_md);
				}

				if (*logtype == EXEC_TEXT) {
					log_session(sender, TheOtherSide(sender),
								"Warning! The exec logging file size is limited to about %ld bytes by %s.",
								susshi_cfg.logfile_exec_max_size,
								susshi_cfg.logfile_exec_max_size == SUSSHI_LOGFILE_EXEC_MAX_SIZE ? "default"
																								 : "configuration");
				}

				if ((*logtype == EXEC_TEXT) &&
					(susshi_session.logging_mask & SUSSHI_AUDITLOG_TRAIL_TARGET ||
					 susshi_session.logging_mask & SUSSHI_AUDITLOG_TRAIL_CLIENT)) {
					log_session(sender, TheOtherSide(sender),
								"Start %s journaling on susshi channel id %d.",
								ChannelLoggingString[*logtype], channel_id);
				}

				susshi_report.command_execs_accepted++;
			}
			else {
				log_session(sender, TheOtherSide(sender),
							"We seen a PTY request before, so we keep logging in %s mode without size limit.",
							ChannelLoggingString[*logtype]);

				susshi_report.command_execs_accepted++;
			}
		} else {
			*logtext = bformat("Exec request '%s' denied by ACL.", cmd);
			response = REJECT;
			susshi_report.command_execs_rejected++;
		}
	}

	return response;
}


/*!
 * @brief       Inspection (helper) for subsystem requests
 *
 * @param       sender      Requesting Side
 * @param       channel_id  Channel ID
 * @param       logtype
 * @param       logtext
 * @param       command     Subsystem command
 *
 * @return      ChannelResponse
 */

ChannelResponse
susshi_inspect_channel_request_subsystem(Side sender, int channel_id,
										 ChannelLogging *logtype, bstring *logtext, ssh_string command) {

	ChannelResponse response = FAIL;

	if (strcmp(ssh_string_get_char(command), "sftp") == 0) {
		/* ----- SFTP --------------------------------------- */
		if (susshi_chef_authz_acl_bool("SSHSecureFileTransfer", true) == SUSSHI_ACL_ALLOW) {
			*logtext = bfromcstr("SFTP subsystem request accepted by ACL.");
			*logtype = SFTP;
			response = OK;
			susshi_report.sftp_sessions++;

			if (susshi_session.logging_mask & SUSSHI_AUDITLOG_FILETRANSFER) {
				log_session(sender, TheOtherSide(sender),
							"Start SFTP journaling on susshi channel id %d.", channel_id);
			}
		} else {
			*logtext = bformat("Requested Secure File Transfer (SFTP subsystem) denied by ACL.");
			response = REJECT;
		}
	} else {
		// ----- Unknown -------------------------------------
		if (susshi_chef_authz_acl_string("SSHSessionSubsystems", ssh_string_get_char(command)) == SUSSHI_ACL_ALLOW) {
			*logtext = bformat(
					"Requested subsystem '%s' is not supported by " SUSSHI_NAME " but accepted by ACL.",
					ssh_string_get_char(command));
			*logtype = TEXT;
			response = OK;

			susshi_report.unkown_subsystems_accepted++;

			if (susshi_session.logging_mask & SUSSHI_AUDITLOG_TRAIL_TARGET ||
				susshi_session.logging_mask & SUSSHI_AUDITLOG_TRAIL_CLIENT) {
				log_session(sender, TheOtherSide(sender),
							"Start TEXT journaling on susshi channel id %d.", channel_id);
			}
		} else {
			*logtext = bformat("Requested subsystem '%s' denied by ACL.", ssh_string_get_char(command));
			response = REJECT;
		}
	}

	return response;
}


/*!
 * @brief       Inspect CHANNEL REQUEST message
 *
 * ### RFC 4254 - 5.4. Channel-Specific Requests
 *
 * ```
 * byte      SSH_MSG_CHANNEL_REQUEST
 * uint32    recipient channel
 * string    request type in US-ASCII characters only
 * boolean   want reply
 * ....      type-specific data follows
 * ```
 *
 * @param       sender      Side of sender
 * @param       type        Unused
 * @param       buffer      ssh_buffer
 *
 * @return      true on success
 */

bool
susshi_inspect_channel_request(Side sender, u_int type, ssh_buffer buffer)
{
	struct ssh_buffer_struct buffer_copy;
	bool copy;

	int cid;
	uint32_t recipient_channel;
	SusshiChannel *c;

	ssh_string datastr;

	const char *crtxt = NULL,
			   *rname = NULL,
			   *envname = NULL,
			   *envvalue = NULL,
			   *term = NULL;

	bstring termsize = NULL;
	char *rtxt_ptr = NULL;
	u_char want_reply;

	ChannelResponse resp = FAIL;
	ChannelLogging logtype;
	bstring rtxt = NULL;

	uint32_t tx = UINT32_MAX,
			 ty, txp, typ, exit_status;

	if (ssh_buffer_get_len(buffer) == 0)
		return false;

	susshi_buffer_duplicate(&buffer_copy, buffer);

	if (ssh_buffer_unpack(&buffer_copy, "dsb", &recipient_channel, &rname, &want_reply) != SSH_OK)
		goto decode_error;

	debug2_dir(sender, TheOtherSide(sender), "CHANNEL REQUEST: '%s' / want_reply = %s",
			   rname, (want_reply == 1) ? "yes" : "no");

	cid = susshi_find_channel(sender, (uint32_t) -1, recipient_channel);

	if (cid == -1)
		cid = susshi_find_channel(TheOtherSide(sender), recipient_channel, (uint32_t) -1);

	if (cid == -1) {
		error("susshi_inspect_channel_request() - We should never reach this code.");
		goto decode_error;
	}

	// Channel found, so we continue
	logtype = susshi_session.channels[cid]->logging;

	if (susshi_session.paa_target_replay_phase) {
		debug4_dir(sender, TheOtherSide(sender), PAA_PREFIX "On the first channel request from one of the parties, it is time to end the PAA replay phase and let responses through.");
		susshi_session.paa_target_replay_phase = false;
	}

	if (strcmp(rname, "shell") == 0) {

		/* ----- Interactive Shell -------------------------------------- */

		if (susshi_chef_authz_acl_bool("SSHInteractive", true) == SUSSHI_ACL_ALLOW) {

			crtxt = "Interactive shell request accepted by ACL.";
			resp = OK;
			logtype = TEXT;
			susshi_report.interactive_sessions_accepted++;

			if (susshi_session.logging_mask & SUSSHI_AUDITLOG_TRAIL_TARGET || susshi_session.logging_mask & SUSSHI_AUDITLOG_TRAIL_CLIENT) {
				log_session(sender, TheOtherSide(sender),
							"Start %s journaling on susshi channel id %d.", ChannelLoggingString[logtype], cid);
			}

			/* Set session to interactive / disable Nagle */
			susshi_session_interactive();

		} else {
			crtxt = "Interactive shell request denied by ACL.";
			resp = REJECT;
			susshi_report.interactive_sessions_rejected++;
		}

	} else if (strcmp(rname, "exec") == 0) {

		/* ----- Command Exec ------------------------------------------- */

		if (ssh_buffer_unpack(&buffer_copy, "S", &datastr) != SSH_OK)
			goto decode_error;

		resp = susshi_inspect_channel_request_exec(sender, cid, &logtype, &rtxt, datastr,
												   &(susshi_session.channels[cid]->scp_requestor_mode),
												   &(susshi_session.channels[cid]->scp_dir_name));

		SSH_STRING_FREE(datastr);

	} else if (strcmp(rname, "subsystem") == 0) {

		/* ----- Subsystems --------------------------------------------- */

		if (ssh_buffer_unpack(&buffer_copy, "S", &datastr) != SSH_OK)
			goto decode_error;

		resp = susshi_inspect_channel_request_subsystem(sender, cid, &logtype, &rtxt, datastr);

		SSH_STRING_FREE(datastr);

	} else if (strcmp(rname, "x11-req") == 0) {

		/* ----- X11-Request -------------------------------------------- */

		if (susshi_chef_authz_acl_bool("SSHX11Forward", true) == SUSSHI_ACL_ALLOW) {
			crtxt = "X11 request accepted by ACL.";
			resp = OK;
			logtype = X11;
			susshi_report.x11_sessions_accepted++;

			if (susshi_session.logging_mask & SUSSHI_AUDITLOG_X11) {
				log_session(sender, TheOtherSide(sender),
							"Start %s journaling on susshi channel id %d.", ChannelLoggingString[logtype], cid);
			}
		} else {
			crtxt = "X11 request denied by ACL.";
			resp = REJECT;
			susshi_report.x11_sessions_rejected++;
		}

	} else if (strncmp(rname, "auth-agent-req", 14) == 0) {

		/* ----- Agent-Forwarding --------------------------------------- */

		if (susshi_chef_authz_acl_bool("SSHAgentForward", true) == SUSSHI_ACL_ALLOW) {
			crtxt = "Auth-Agent forwarding request accepted by ACL.";
			resp = OK;
			logtype = AGENT;
			susshi_report.agent_forwards_accepted++;

		} else {
			crtxt = "Auth-Agent forwarding request denied by ACL.";
			resp = REJECT;
			susshi_report.agent_forwards_rejected++;
		}
	} else if (strcmp(rname, "exit-status") == 0) {

		/* ----- Exit status --------------------------------- */

		if (ssh_buffer_unpack(&buffer_copy, "d", &exit_status) != SSH_OK)
			goto decode_error;

		rtxt = bformat("Exit with status %d.", exit_status);
		resp = OK;

	} else if (strcmp(rname, "exit-signal") == 0) {

		const char *sig_name = NULL,
				*err_msg = NULL;
		bool core_dumped;

		/* ----- Exit signal --------------------------------- */

		if (ssh_buffer_unpack(&buffer_copy, "sbs", &sig_name, &core_dumped, &err_msg) != SSH_OK)
			goto decode_error;

		rtxt = bformat("Exit signal %s %s error-message: %s", sig_name, (core_dumped ? "(core dumped) -" : "-"), err_msg);
		resp = OK;

		if (sig_name) xfree((void *) sig_name);
		if (err_msg) xfree((void *) err_msg);

	} else if (strcmp(rname, "pty-req") == 0) {

		/* ----- PTY request --------------------------------- */

		/* On pty-req we start TEXT logging even if 'exec' is requested subsequently */

		/* term = TERM environment variable value (e.g., vt100)
		 * tx =   terminal width, characters (e.g., 80)
		 * ty =   terminal height, rows (e.g., 24)
		 * txp =  terminal width, pixels (e.g., 640)
		 * typ =  terminal height, pixels (e.g., 480)
		 */

		if (ssh_buffer_unpack(&buffer_copy, "sdddd", &term, &tx, &ty, &txp, &typ) != SSH_OK)
			goto decode_error;

		rtxt = bformat("PTY request for TERM='%s', size %dx%d (%dx%d pixels) accepted. So we start logging in TEXT mode.",
					   term, tx, ty, txp, typ);
		logtype = TEXT;
		resp = OK;

	} else if (strcmp(rname, "window-change") == 0) {

		/* ----- Window change requests --------------------------------- */

		debug1("WINDOW Change request");

		if (ssh_buffer_unpack(&buffer_copy, "dddd", &tx, &ty, &txp, &typ) != SSH_OK)
			goto decode_error;

		crtxt = NULL;
		resp = OK;

	} else if (strcmp(rname, "env") == 0) {

		/* ----- ENV requests --------------------------------- */

		if (ssh_buffer_unpack(&buffer_copy, "ss", &envname, &envvalue) != SSH_OK)
			goto decode_error;

		rtxt = bformat("ENV request (%s=%s) accepted.", envname, envvalue);
		resp = OK;

	} else if (strcmp(rname, "keepalive@openssh.com") == 0 || strcmp(rname, "keep-alive@bitvise.com") == 0)  {

		/* ----- Keepalive Channel requests --------------------------------- */
		debug2("%s channel request accepted. Expecting CHANNEL FAILURE message from client.", rname);

		crtxt = NULL;
		resp = OK;

	} else if (strcmp(rname, "winadj@putty.projects.tartarus.org") == 0) {

		/* ----- PUTTY message ---------------------------------
		 *
		 * PuTTY sends this request along with some SSH_MSG_CHANNEL_WINDOW_ADJUST messages as part of its
		 * window-size tuning. It can be sent on any type of channel. Servers MUST treat it as an unrecognised
		 * request and respond with SSH_MSG_CHANNEL_FAILURE.
		 */
		debug2("%s channel request rejected. Expecting CHANNEL FAILURE message from client.", rname);

		crtxt = NULL;
		resp = OK;

	} else if (strcmp(rname, "signal") == 0 ||
			   strcmp(rname, "xon-xoff") == 0 ||
			   strcmp(rname, "eow@openssh.com") == 0) {

		/* ----- Other allowed requests --------------------------------- */

		rtxt = bformat("%s request accepted.", rname);
		resp = OK;

	} else {

		/* ----- Unknown ------------------------------------------------ */

		rtxt = bformat("'%s' request rejected.", rname);
		resp = REJECT;
		logtype = NONE;
	}

	rtxt_ptr = (rtxt != NULL) ? bdata(rtxt) : (char *) crtxt;

	if (rtxt_ptr != NULL) {
		log_session(sender, TheOtherSide(sender), "%s", rtxt_ptr);
		debug2_dir(sender, TheOtherSide(sender), "%s", rtxt_ptr);
	}

	if (resp == OK) {
		c=susshi_session.channels[cid];

		c->logging = logtype;

		if ((tx != UINT32_MAX) && (susshi_session.logging_mask & SUSSHI_AUDITLOG_TRAIL_CLIENT)) {
			termsize = bformat("%dx%d %dx%d", tx, ty, txp, typ);
		}

		susshi_channel_set_logging(cid, logtype, termsize, term);

		/* For proxied connections, we have to rewrite the recipient channel id in the original packet */
		if (susshi_session.channels[cid]->proxied_channel) {
			susshi_inspect_channel_rewrite_recipientch_on_proxied_channel(sender, buffer,
																		  susshi_session.channels[cid]);
		}

		copy = true;

	} else {

		/* Cancel send ENV if set */
		susshi_session.send_shell_env = false;

		/* On REJECT just send a FAILURE if want_reply is set */
		if (want_reply == 1) {
			if (ssh_buffer_pack((sender == CLIENT) ?
								susshi_session.client_session->out_buffer : susshi_session.target_session->out_buffer,
								"bd", SSH2_MSG_CHANNEL_FAILURE, susshi_session.channels[cid]->requestor_ch) != SSH_OK)
				goto encode_error;

			if (ssh_packet_send((sender == CLIENT) ? susshi_session.client_session : susshi_session.target_session) != SSH_OK)
				goto encode_error;
			debug2_dir(GATEWAY, sender, "%s - Sending a CHANNEL FAILURE message to %s.", rtxt_ptr, SideString[sender]);
		} else {
			debug2_dir(GATEWAY, sender, "%s - No reply message expected by %s.", rtxt_ptr, SideString[sender]);
		}
		copy = false;
	}

	susshi_debug_remaining_packet(&buffer_copy);

	susshi_inspect_channel_update_proctitle();

	if (rtxt) bstrFree(rtxt);
	if (rname) xfree((void *) rname);
	if (envname) xfree((void *) envname);
	if (envvalue) xfree((void *) envvalue);
	if (term) xfree((void *) term);
	if (termsize) bstrFree(termsize);

	return copy;

	decode_error:
	{
		fatal("Packet decoding returned with fatal error: Inspect Channel Request.");
		return false;
	}

	encode_error:
	{
		fatal("Packet encoding returned with fatal error: Inspect Channel Request.");
		return false;
	}

}

#undef SCP_PATH_LEN
#undef SCP_OPTION_LEN


/*!
 * @brief       Inspect CHANNEL SUCCESS message
 *
 * ### RFC 4254 - 5.4. Channel-Specific Requests
 *
 * ```
 * byte      SSH_MSG_CHANNEL_SUCCESS
 * uint32    recipient channel
 * ```
 *
 * @param       sender      Side of sender
 * @param       type        Unused
 * @param       buffer      ssh_buffer
 *
 * @return      true on success
 */

bool
susshi_inspect_channel_success(Side sender, u_int type, ssh_buffer buffer)
{
	struct ssh_buffer_struct buffer_copy;

	int cid;
	uint32_t recipient_channel;

	if (ssh_buffer_get_len(buffer) == 0)
		return false;

	susshi_buffer_duplicate(&buffer_copy, buffer);

	if (ssh_buffer_unpack(&buffer_copy, "d", &recipient_channel) != SSH_OK)
		goto decode_error;

	debug2_dir(sender, TheOtherSide(sender), "CHANNEL SUCCESS message.");

	cid = susshi_find_channel(TheOtherSide(sender), recipient_channel, (uint32_t) -1);

	if (cid == -1) {
		error("susshi_inspect_channel_request() - We should never reach this code.");
		goto decode_error;
	}

	/* During PAA replay phase, we have to Drop the message since it is already sent by the gateway during session setup */
	if (susshi_session.paa_target_replay_phase) {
		debug4(PAA_PREFIX "Packet not forwarded, because it is the answer from target we already sent to client during session setup.");
		return false;
	}

	/* For proxied connections, we have to rewrite the recipient channel id in the original packet */
	if (susshi_session.channels[cid]->proxied_channel) {
		susshi_inspect_channel_rewrite_recipientch_on_proxied_channel(sender, buffer,
																	  susshi_session.channels[cid]);
	}

	return true;

	decode_error:
	{
		fatal("Packet decoding returned with fatal error: Inspect Channel Success.");
		return false;
	}
}

/*!
 * @brief       Inspect CHANNEL FAILURE message
 *
 * ### RFC 4254 - 5.4. Channel-Specific Requests
 *
 * ```
 * byte      SSH_MSG_CHANNEL_FAILURE
 * uint32    recipient channel
 * ```
 *
 * @param       sender      Side of sender
 * @param       type        Unused
 * @param       buffer      ssh_buffer
 *
 * @return      true on success
 */

bool
susshi_inspect_channel_failure(Side sender, u_int type, ssh_buffer buffer)
{
	struct ssh_buffer_struct buffer_copy;

	int cid;
	uint32_t recipient_channel;

	if (ssh_buffer_get_len(buffer) == 0)
		return false;

	susshi_buffer_duplicate(&buffer_copy, buffer);

	if (ssh_buffer_unpack(&buffer_copy, "d", &recipient_channel) != SSH_OK)
		goto decode_error;

	debug2_dir(sender, TheOtherSide(sender), "CHANNEL FAILURE message: recipient_ch = %u", recipient_channel);

	cid = susshi_find_channel(TheOtherSide(sender), recipient_channel, (uint32_t) -1);

	if (cid == -1)
		cid = susshi_find_channel(sender, (uint32_t) -1, recipient_channel);

	if (cid == -1) {
		error("susshi_inspect_channel_failure() - We should never reach this code.");
		goto decode_error;
	}

	/* During PAA replay phase, we have to Drop the message since it is already sent by the gateway during session setup */
	if (susshi_session.paa_target_replay_phase) {
		debug4(PAA_PREFIX "Packet not forwarded, because it is the answer from target we already sent to client during session setup.");
		return false;
	}

	/* For proxied connections, we have to rewrite the recipient channel id in the original packet */
	if (susshi_session.channels[cid]->proxied_channel) {
		susshi_inspect_channel_rewrite_recipientch_on_proxied_channel(sender, buffer,
																	  susshi_session.channels[cid]);
	}

	return true;

	decode_error:
	{
		fatal("Packet decoding returned with fatal error: Inspect Channel Failure.");
		return false;
	}
}


/*!
 * @brief       Inspect DEBUG message
 *
 * ### RFC 4253 - 11.3. Debug Message
 *
 * ```
 * byte      SSH_MSG_DEBUG
 * boolean   always_display
 * string    message in ISO-10646 UTF-8 encoding [RFC3629]
 * string    language tag [RFC3066]
 * ```
 *
 * @param       sender      Side of sender
 * @param       type        Unused
 * @param       buffer      ssh_buffer
 *
 * @return      true on success
 */

bool
susshi_inspect_debug_message(Side sender, u_int type, ssh_buffer buffer)
{
	bool copy = true;
	struct ssh_buffer_struct buffer_copy;
	const char displ = '\0', *msg = NULL, *lang = NULL;

	if (ssh_buffer_get_len(buffer) == 0)
		return false;

	susshi_buffer_duplicate(&buffer_copy, buffer);

	if (ssh_buffer_unpack(&buffer_copy, "bss", &displ, &msg, &lang) != SSH_OK)
		goto decode_error;

	debug2_dir(sender, TheOtherSide(sender), "Remote: %.900s", msg);

	if (msg) xfree((void *) msg);
	if (lang) xfree((void *) lang);

	return copy;

	decode_error:
	{
		fatal("Packet decoding returned with fatal error: Inspect Debug Message.");
		return false;
	}

}


/*!
 * @brief       Inspect WINDOW ADJUST message
 *
 * ### RFC 4254 - 5.2. Data Transfer
 *
 * ```
 * byte      SSH_MSG_CHANNEL_WINDOW_ADJUST
 * uint32    recipient channel
 * uint32    bytes to add
 * ```
 *
 * @param       sender      Side of sender
 * @param       type        Unused
 * @param       buffer      ssh_buffer
 *
 * @return      true on success
 */

bool
susshi_inspect_channel_window_adjust(Side sender, u_int type, ssh_buffer buffer) {

	struct ssh_buffer_struct buffer_copy;
	int cid;
	uint32_t recipient_channel, radd;

	if (ssh_buffer_get_len(buffer) == 0)
		return false;

	susshi_buffer_duplicate(&buffer_copy, buffer);

	if (ssh_buffer_unpack(&buffer_copy, "dd", &recipient_channel, &radd) != SSH_OK)
		goto decode_error;

	cid = susshi_find_channel(sender, (uint32_t) -1, recipient_channel);

	if (cid == -1)
		cid = susshi_find_channel(TheOtherSide(sender), recipient_channel, (uint32_t) -1);

	if (cid == -1) {
		error("susshi_inspect_channel_window_adjust() - We should never reach this code.");
		goto decode_error;
	}

	debug4_dir(sender, TheOtherSide(sender), "CHANNEL WINDOW ADJUST message. Add %d bytes.", radd);

	/* For proxied connections, we have to rewrite the recipient channel id in the original packet */
	if (susshi_session.channels[cid]->proxied_channel) {
		susshi_inspect_channel_rewrite_recipientch_on_proxied_channel(sender, buffer, susshi_session.channels[cid]);
	}

	return true;

	decode_error:
	{
		fatal("Packet decoding returned with fatal error: Inspect Channel Window Adjust.");
		return false;
	}
}


/*!
 * @brief       Inspect EOF message
 *
 * ### RFC 4254 - 5.3.  Closing a Channel
 *
 * ```
 * byte      SSH_MSG_CHANNEL_EOF
 * uint32    recipient channel
 * ```
 *
 * @param       sender      Side of sender
 * @param       type        Unused
 * @param       buffer      ssh_buffer
 *
 * @return      true on success
 */

bool
susshi_inspect_channel_eof(Side sender, u_int type, ssh_buffer buffer) {

	struct ssh_buffer_struct buffer_copy;
	int cid;
	uint32_t recipient_channel;


	if (ssh_buffer_get_len(buffer) == 0)
		return false;

	susshi_buffer_duplicate(&buffer_copy, buffer);

	if (ssh_buffer_unpack(&buffer_copy, "d", &recipient_channel) != SSH_OK)
		goto decode_error;

	debug4_dir(sender, TheOtherSide(sender), "CHANNEL EOF message");

	cid = susshi_find_channel(sender, (uint32_t) -1, recipient_channel);

	if (cid == -1)
		cid = susshi_find_channel(TheOtherSide(sender), recipient_channel, (uint32_t) -1);

	/* For proxied connections, we have to rewrite the recipient channel id in the original packet */
	if ((cid != -1) && (susshi_session.channels[cid]->proxied_channel)) {
		susshi_inspect_channel_rewrite_recipientch_on_proxied_channel(sender, buffer, susshi_session.channels[cid]);
	}

	return true;

	decode_error:
	{
		fatal("Packet decoding returned with fatal error: Inspect Channel EOF.");
		return false;
	}
}


/*!
 * @brief       Inspect DISCONNECT message
 *
 * ### RFC 4253 - 11.1.  Disconnection Message
 *
 * ```
 * byte      SSH_MSG_DISCONNECT
 * uint32    reason code
 * string    description in ISO-10646 UTF-8 encoding [RFC3629]
 * string    language tag [RFC3066]
 * ```
 *
 * @param       sender      Side of sender
 * @param       type        Unused
 * @param       buffer      ssh_buffer
 *
 * @return      true on success
 */

bool
susshi_inspect_disconnect(Side sender, u_int type, ssh_buffer buffer)
{
	bool copy = true;
	struct ssh_buffer_struct buffer_copy;
	int cmsglen;
	uint32_t reasonc;
	char *msg = NULL, *cmsg = NULL;

	if (ssh_buffer_get_len(buffer) == 0)
		return false;

	susshi_buffer_duplicate(&buffer_copy, buffer);

	if (ssh_buffer_unpack(&buffer_copy, "ds", &reasonc, &msg) != SSH_OK)
		goto decode_error;

	log_system(LOG_LEVEL_INFO, "Received disconnect from %s (%s): %u: %.400s.",
			   SideString[sender], bdata(susshi_session.target_ip), reasonc, msg);
	log_session(sender, TheOtherSide(sender), "Received disconnect from %s (%s): %u: %.400s.",
				SideString[sender], bdata(susshi_session.target_ip), reasonc, msg);

	if (sender == CLIENT) {
		susshi_session.client_closed = true;
	} else {
		susshi_session.target_closed = true;
		cmsglen = strlen(msg) + 1024;
		cmsg = malloc(cmsglen);
		snprintf(cmsg, cmsglen, "Message from target (%s): %s", bdata(susshi_session.target_host), msg);
		xfree((void *) msg);
		susshi_disconnect_individual(CLIENT, SSH2_DISCONNECT_CONNECTION_LOST, cmsg);
	}

	if (msg) xfree((void *) msg);

	return copy;

	decode_error:
	{
		fatal("Packet decoding returned with fatal error: Inspect Disconnect.");
		return false;
	}
}

/*! @} */
