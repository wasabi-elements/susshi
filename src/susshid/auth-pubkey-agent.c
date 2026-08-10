/*!
 *
 * @brief       PublicKey Agent Authentication
 *
 * Target Authentication with PublicKey Agent support from Client
 *
 * @ingroup     susshid
 *
 * @copyright   Copyright (C) 2026 Wasabi Elements GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later AND LGPL-2.1-or-later
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
 * ---
 *
 * Portions of this file (ssh_userauth_get_response, agent_get_u32, agent_put_u32, and
 * agent_atomicio are derived from or directly access internals of libssh (auth.c, agent.c):
 *
 * Copyright (c) 2003-2019 Aris Adamantiadis
 * Copyright (c) 2009-2019 Andreas Schneider <asn@cryptomilk.org>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
 * ---
 * 
 * @author      Oliver Rauscher <oliver@susshi.io>
 * @date        2026-02-01
 *
 * @defgroup    auth_pubkey_agent PublicKey Agent Authentication
 * @brief       Functions to authenticate with a target talking to client's Public Key Agent.
 * @{
 *
 * @defgroup    auth_pubkey_agent_cc PublicKey Agent Authentication (callback methods)
 * @brief       Functions handling client session and channel requests
 * @ingroup     auth_pubkey_agent
 */

#include <susshid/common.h>


/* Prototypes */
static int susshi_agent_auth_response_termination(void *user);
static int ssh_userauth_get_response(ssh_session session);
static uint32_t agent_get_u32(const void *vp);
static void     agent_put_u32(void *vp, uint32_t v);
static size_t   agent_atomicio(void *buf, size_t n, bool do_read);

/* Client Communication Callback functions */
static ssh_channel ccb_channel_open_request(ssh_session session, void *userdata);

static int  ccb_session_data(ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr,
							 void *userdata);
static void ccb_session_eof(ssh_session session, ssh_channel channel, void *userdata);
static int  ccb_session_pty_request(ssh_session session, ssh_channel channel, const char *term, int cols, int rows,
									int px, int py, void *userdata);
static int  ccb_session_pty_window_change(ssh_session session, ssh_channel channel, int cols, int rows, int px, int py,
										  void *userdata);
static int  ccb_session_env_request(ssh_session session, ssh_channel channel, const char *env_name,
									const char *env_value, void *userdata);
static void ccb_session_auth_agent_request(ssh_session session, ssh_channel channel, void *userdata);

static void ccb_session_x11_request(ssh_session session, ssh_channel channel, int single_connection,
									const char *auth_protocol, const char *auth_cookie, uint32_t screen_number,
									void *userdata);
static int  ccb_session_shell_request(ssh_session session, ssh_channel channel, void *userdata);

static int  ccb_session_exec_request(ssh_session session, ssh_channel channel, const char *command, void *userdata);

/* Agent communication */
static bool       susshi_agent_talk(ssh_buffer request, ssh_buffer reply);
static void       susshi_agent_request_channel(void);
static void       susshi_agent_request_identities(void);
static ssh_string susshi_agent_request_signature(ssh_session session, ssh_key public_key, ssh_string key_blob);

/* Target Public Key Authentication */
static int susshi_agent_authenticate_target(void);
int susshi_agent_target_send_pubkey_signature(ssh_session session, ssh_key public_key, ssh_string key_blob, ssh_string signature);
bool susshi_pubkey_agent_replay_to_target(void);

#define MAX_ENVS  20
#define MAX_REMOTETCP  20

typedef enum {
	SUSSHI_AGENT_START = 0,
	SUSSHI_AGENT_AVAILABLE,
	SUSSHI_AGENT_READY,
	SUSSHI_AGENT_CHANNEL_OPEN,
	SUSSHI_AGENT_IDS_RECEIVED,
	SUSSHI_AGENT_SEND_CLOSE,
	SUSSHI_AGENT_CLOSE_SENT,
	SUSSHI_AGENT_COMPLETE,
	SUSSHI_AGENT_ATOM_ACTION,
	SUSSHI_AGENT_ERROR = -1
} susshi_agent_state;

typedef enum {
	INIT_AGENT_SESSION,
	SHELL,
	EXECCMD,
	SUBSYSTEM
} susshi_agent_session;

/*! @cond */
static struct {
	susshi_agent_state state;
	susshi_agent_session session_mode;

	ssh_channel session_channel;
	ssh_channel agent_channel;

	int num_identities;
	ssh_buffer identities_buffer;

	bool requested_pty;
	bool requested_auth_agent;
	bool requested_x11;
	bool requested_subsystem;
	bool requested_eof;

	bstring requested_cmd;

	int cid;

	int num_env_requests;
	struct {
		bstring name;
		bstring value;
	} env_requests[MAX_ENVS];

	int num_remote_tcp_requests;
	struct {
		uint8_t want_reply;
		bstring bind_address;
		uint32_t bind_port;
	} remote_tcp_requests[MAX_REMOTETCP];

	struct {
		bstring term;
		int cols, rows, px, py;
	} terminal;

	struct {
		int single_connection;
		bstring auth_protocol;
		bstring auth_cookie;
		uint32_t screen_number;
	} x11;
	
	ssh_buffer delayed_client_data;

} int_store = {
		.state = SUSSHI_AGENT_START,
		.session_mode = INIT_AGENT_SESSION,
		.session_channel = NULL,
		.agent_channel = NULL,
		.identities_buffer = NULL,
		.num_identities = 0,
		.num_env_requests = 0,
		.requested_cmd = NULL,
		.requested_auth_agent = false,
		.requested_x11 = false,
		.requested_pty = false,
		.requested_subsystem = false,
		.requested_eof = false,
		.delayed_client_data = NULL,
		.terminal = {
				.term = NULL,
				.cols = 0,
				.rows = 0,
				.px = 0,
				.py = 0
		}
};
/*! @endcond */

#define SSH_AGENT_RSA_SHA2_256                   0x02
#define SSH_AGENT_RSA_SHA2_512                   0x04

/*!
 * @brief       Polling termination predicate: returns true when an authentication result is available
 *
 * Passed to @c ssh_handle_packets_termination() as the termination callback.
 * Mirrors the logic of the libssh-internal @c ssh_auth_response_termination().
 *
 * @param       user    The @c ssh_session to inspect (cast from @c void*)
 *
 * @return      @c 1 when the session auth state is @c SSH_AUTH_STATE_SUCCESS or
 *              @c SSH_AUTH_STATE_FAILED (polling should stop), @c 0 otherwise
 */

static int
susshi_agent_auth_response_termination(void *user) {
	ssh_session session = (ssh_session) user;

	return ((session->auth.state == SSH_AUTH_STATE_SUCCESS) || (session->auth.state == SSH_AUTH_STATE_FAILED)) ? 1 : 0;
}


/*!
 * @brief       Wait for an authentication response from a session and map the result to an @c SSH_AUTH_* code
 *
 * Calls @c ssh_handle_packets_termination() using @c susshi_agent_auth_response_termination()
 * as the stop condition, then translates the internal @c session->auth.state to the
 * corresponding public @c SSH_AUTH_* return value. Derived from the libssh-internal
 * @c ssh_userauth_get_response().
 *
 * @param       session     The @c ssh_session to wait on
 *
 * @return      @c SSH_AUTH_SUCCESS, @c SSH_AUTH_DENIED, @c SSH_AUTH_PARTIAL,
 *              @c SSH_AUTH_AGAIN, or @c SSH_AUTH_ERROR
 */

static int
ssh_userauth_get_response(ssh_session session) {

	int rc = SSH_AUTH_ERROR;
	int rc_ssh;

	rc_ssh = ssh_handle_packets_termination(session, SSH_TIMEOUT_USER,
											susshi_agent_auth_response_termination, session);
	if (rc_ssh == SSH_ERROR) {
		return SSH_AUTH_ERROR;
	}

	if (!susshi_agent_auth_response_termination(session)){
		return SSH_AUTH_AGAIN;
	}

	switch(session->auth.state) {
		case SSH_AUTH_STATE_ERROR:
			rc = SSH_AUTH_ERROR;
			break;
		case SSH_AUTH_STATE_FAILED:
			rc = SSH_AUTH_DENIED;
			break;
		case SSH_AUTH_STATE_INFO:
			rc = SSH_AUTH_INFO;
			break;
		case SSH_AUTH_STATE_PARTIAL:
			rc = SSH_AUTH_PARTIAL;
			break;
		case SSH_AUTH_STATE_PK_OK:
		case SSH_AUTH_STATE_SUCCESS:
			rc = SSH_AUTH_SUCCESS;
			break;
		case SSH_AUTH_STATE_KBDINT_SENT:
		case SSH_AUTH_STATE_GSSAPI_REQUEST_SENT:
		case SSH_AUTH_STATE_GSSAPI_TOKEN:
		case SSH_AUTH_STATE_GSSAPI_MIC_SENT:
		case SSH_AUTH_STATE_PUBKEY_OFFER_SENT:
		case SSH_AUTH_STATE_PUBKEY_AUTH_SENT:
		case SSH_AUTH_STATE_PASSWORD_AUTH_SENT:
		case SSH_AUTH_STATE_AUTH_NONE_SENT:
		case SSH_AUTH_STATE_NONE:
		default:
			/* not reached */
			rc = SSH_AUTH_ERROR;
			break;
	}

	return rc;
}


/*!
 * @brief       Read a 4-byte big-endian @c uint32_t from an unaligned byte buffer
 *
 * Derived from the libssh-internal @c agent_get_u32() in @c agent.c.
 *
 * @param       vp      Pointer to at least 4 bytes of data
 *
 * @return      The @c uint32_t value stored at @p vp in network byte order
 */
static uint32_t agent_get_u32(const void *vp) {
	const uint8_t *p = (const uint8_t *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << (uint8_t) 24;
	v |= (uint32_t)p[1] << (uint8_t) 16;
	v |= (uint32_t)p[2] << (uint8_t) 8;
	v |= (uint32_t)p[3];

	return v;
}

/*!
 * @brief       Write a 4-byte big-endian @c uint32_t into an unaligned byte buffer
 *
 * Derived from the libssh-internal @c agent_put_u32() in @c agent.c.
 *
 * @param       vp      Pointer to at least 4 bytes of writable storage
 * @param       v       Value to encode in network byte order
 */
static void agent_put_u32(void *vp, uint32_t v) {
	uint8_t *p = (uint8_t *)vp;

	p[0] = (uint8_t)(v >> (uint8_t) 24) & (uint8_t) 0xff;
	p[1] = (uint8_t)(v >> (uint8_t) 16) & (uint8_t) 0xff;
	p[2] = (uint8_t)(v >> (uint8_t) 8) & (uint8_t) 0xff;
	p[3] = (uint8_t)v & (uint8_t) 0xff;
}


/*!
 * @brief       Perform an atomic read or write of exactly @p n bytes on the agent channel
 *
 * Loops over @c ssh_channel_read() or @c ssh_channel_write() until all @p n bytes
 * have been transferred, retrying transparently on @c SSH_AGAIN. Returns @c 0
 * immediately on @c SSH_ERROR. Derived from the libssh-internal @c atomicio() in
 * @c agent.c.
 *
 * @param       buf     Buffer to read into or write from
 * @param       n       Number of bytes to transfer
 * @param       do_read @c true to read from the channel, @c false to write
 *
 * @return      Number of bytes successfully transferred; @c 0 on error
 */
static size_t agent_atomicio(void *buf, size_t n, bool do_read) {
	char *b = buf;
	size_t pos;
	ssize_t res;

	for(pos = 0; n > pos; pos += (size_t)res ) {

		if (do_read)
			res = ssh_channel_read(int_store.agent_channel,b + pos, n-pos, 0);
		else
			res = ssh_channel_write(int_store.agent_channel, b+pos, n-pos);

		if (res == SSH_AGAIN)
			continue;

		if (res == SSH_ERROR)
			return 0;
	}
	return pos;
}


/*!
 * @brief       libssh global-request callback: handle @c tcpip-forward requests from the client
 *
 * Accepts @c SSH_GLOBAL_REQUEST_TCPIP_FORWARD requests that pass the
 * @c SSHRemoteForwards ACL check and records them in @c int_store.remote_tcp_requests
 * for later replay to the target. Requests exceeding @c MAX_REMOTETCP or rejected
 * by the ACL are denied and counted in @c susshi_report.remote_forwards_rejected.
 *
 * @ingroup     auth_pubkey_agent_cc
 * @see         libssh Callback definitions
 *
 * @param       session     The client @c ssh_session (unused)
 * @param       message     The incoming @c ssh_message containing the global request
 * @param       userdata    Unused
 */

static void
ccb_global_request (ssh_session session, ssh_message message, void *userdata) {
	(void) userdata;

	debug3_dir(CLIENT, GATEWAY, PAA_PREFIX "GLOBAL REQUEST: %d", message->global_request.type);

	if (message->global_request.type == SSH_GLOBAL_REQUEST_TCPIP_FORWARD) {
		if (int_store.num_remote_tcp_requests < MAX_REMOTETCP) {
			int r = int_store.num_remote_tcp_requests;

			const char *bind_address = message->global_request.bind_address;
			uint16_t    bind_port    = message->global_request.bind_port;
			bool        want_reply   = message->global_request.want_reply;

			debug3_dir(CLIENT, GATEWAY, PAA_PREFIX "GLOBAL REQUEST: 'tcpip-forward' [%s]:%d (want-reply = %s)",
					   message->global_request.bind_address, message->global_request.bind_port,
					   want_reply ? "yes" : "no");

			if (susshi_chef_authz_acl_socket("SSHRemoteForwards", bind_address, bind_port) == SUSSHI_ACL_ALLOW) {
				debug2("Remote port forwarding accepted by ACL.");
				susshi_report.remote_forwards_accepted++;

				int_store.remote_tcp_requests[r].bind_address = bfromcstr(message->global_request.bind_address);
				int_store.remote_tcp_requests[r].bind_port = message->global_request.bind_port;
				int_store.remote_tcp_requests[r].want_reply = message->global_request.want_reply;
				int_store.num_remote_tcp_requests++;

				if (bind_port == 0) {
					if (want_reply) {
						debug2_dir(CLIENT, TARGET, "User requested dynamic port assignment on remote site (port = 0) and should receive server assigned port with next MSG_SUCCESS.");
					}
				}

				log_session(CLIENT, TARGET,
							"Remote port forwarding requested ( listen-address = %s, listen-port = %d ) and accepted by ACL.",
							bind_address, bind_port);

			} else {
				debug2("Remote port forwarding denied by ACL.");

				log_session(CLIENT, TARGET,
							"Remote port forwarding requested ( listen-address = %s, listen-port = %d ) and rejected by ACL.",
							bind_address, bind_port);

				susshi_report.remote_forwards_rejected++;
			}
		} else {
			debug3_dir(CLIENT, GATEWAY, PAA_PREFIX "GLOBAL REQUEST: 'tcpip-forward' / MAX REACHED & DENIED [%s]:%d",
					   message->global_request.bind_address, message->global_request.bind_port);
		}
	}
}


/*!
 * @brief       libssh channel-open callback: accept a session channel from the client
 *
 * Creates a new @c ssh_channel and stores it in @c int_store.session_channel.
 *
 * @ingroup     auth_pubkey_agent_cc
 * @see         libssh Callback definitions
 *
 * @param       session     The client @c ssh_session
 * @param       userdata    Unused
 *
 * @return      The newly created @c ssh_channel
 */

static ssh_channel
ccb_channel_open_request(ssh_session session, void *userdata) {
	(void) userdata;

	int_store.session_channel = ssh_channel_new(session);

	debug3_dir(CLIENT, GATEWAY, PAA_PREFIX "CHANNEL OPEN: 'session'");

	return int_store.session_channel;
}


/*!
 * @brief       libssh channel-data callback: buffer incoming client data for later replay to the target
 *
 * Appends @p data to @c int_store.delayed_client_data. Data arriving before the target
 * channel is established is held here and flushed during the replay phase.
 *
 * @ingroup     auth_pubkey_agent_cc
 * @see         libssh Callback definitions
 *
 * @param       session     Unused
 * @param       channel     Unused
 * @param       data        Pointer to the received data bytes
 * @param       len         Number of bytes in @p data
 * @param       is_stderr   Non-zero if data is on the stderr stream (unused)
 * @param       userdata    Unused
 *
 * @return      @p len (number of bytes consumed, as required by the libssh callback contract)
 */

static int
ccb_session_data(ssh_session session, ssh_channel channel, void *data,
				 uint32_t len, int is_stderr, void *userdata) {
	(void) session;
	(void) channel;
	(void) is_stderr;

	debug3_dir(CLIENT, GATEWAY, PAA_PREFIX "CHANNEL DATA (into buffer): len: %d", len);
	ssh_buffer_add_data(int_store.delayed_client_data, data, len);

	return len;
}


/*!
 * @brief       libssh channel-EOF callback: record that the client has sent EOF
 *
 * Sets @c int_store.requested_eof to @c true so that the EOF is forwarded to the
 * target channel during the replay phase.
 *
 * @ingroup     auth_pubkey_agent_cc
 * @see         libssh Callback definitions
 *
 * @param       session     Unused
 * @param       channel     Unused
 * @param       userdata    Unused
 */

static void
ccb_session_eof(ssh_session session, ssh_channel channel, void *userdata) {
	(void) session;
	(void) channel;

	debug3_dir(CLIENT, GATEWAY, PAA_PREFIX "CHANNEL EOF");
	int_store.requested_eof = true;
}


/*!
 * @brief       libssh PTY-request callback: record the client's terminal parameters for replay
 *
 * Stores the terminal type string and dimensions in @c int_store.terminal and
 * sets @c int_store.requested_pty to @c true so the PTY is requested on the target
 * during the replay phase.
 *
 * @ingroup     auth_pubkey_agent_cc
 * @see         libssh Callback definitions
 *
 * @param       session     Unused
 * @param       channel     Unused
 * @param       term        Terminal type string (e.g. @c "xterm-256color")
 * @param       cols        Terminal width in characters
 * @param       rows        Terminal height in characters
 * @param       px          Terminal width in pixels
 * @param       py          Terminal height in pixels
 * @param       userdata    Unused
 *
 * @return      @c SSH_OK (always)
 */

static int
ccb_session_pty_request(ssh_session session, ssh_channel channel,
						const char *term, int cols, int rows, int px, int py, void *userdata) {
	(void) session;
	(void) channel;
	(void) term;
	(void) userdata;

	int_store.terminal.term = bfromcstr(term);
	int_store.terminal.cols = cols;
	int_store.terminal.rows = rows;
	int_store.terminal.px = px;
	int_store.terminal.py = py;

	debug3_dir(CLIENT, GATEWAY, PAA_PREFIX "CHANNEL REQUEST: 'pty-req' / want_reply = yes / %s - %dx%d - %dx%dpx",
			   bdata(int_store.terminal.term), cols, rows, px, py);

	int_store.requested_pty = true;
	return SSH_OK;
}


/*!
 * @brief       libssh window-change callback: update the stored terminal dimensions
 *
 * Updates @c int_store.terminal with the new size. The updated dimensions are applied
 * to the target PTY during the session once it is established.
 *
 * @ingroup     auth_pubkey_agent_cc
 * @see         libssh Callback definitions
 *
 * @param       session     Unused
 * @param       channel     Unused
 * @param       cols        New terminal width in characters
 * @param       rows        New terminal height in characters
 * @param       px          New terminal width in pixels
 * @param       py          New terminal height in pixels
 * @param       userdata    Unused
 *
 * @return      @c SSH_OK (always)
 */

static int
ccb_session_pty_window_change(ssh_session session, ssh_channel channel,
							  int cols, int rows, int px, int py, void *userdata) {
	(void) session;
	(void) channel;
	(void) userdata;

	int_store.terminal.cols = cols;
	int_store.terminal.rows = rows;
	int_store.terminal.px = px;
	int_store.terminal.py = py;

	debug3_dir(CLIENT, GATEWAY, PAA_PREFIX "CHANNEL REQUEST: 'window-change' / want_reply = yes / %s - %dx%d - %dx%dpx",
			   bdata(int_store.terminal.term), cols, rows, px, py);

	return SSH_OK;
}

/*!
 * @brief       libssh env-request callback: record a client environment variable for replay
 *
 * Stores the name/value pair in @c int_store.env_requests for later forwarding to
 * the target. Silently ignores requests exceeding @c MAX_ENVS.
 *
 * @ingroup     auth_pubkey_agent_cc
 * @see         libssh Callback definitions
 *
 * @param       session     Unused
 * @param       channel     Unused
 * @param       env_name    Name of the environment variable to set
 * @param       env_value   Value of the environment variable
 * @param       userdata    Unused
 *
 * @return      @c SSH_OK (always)
 */

static int
ccb_session_env_request(ssh_session session, ssh_channel channel,
						const char *env_name, const char *env_value, void *userdata) {
	(void) session;
	(void) channel;
	(void) userdata;

	if (int_store.num_env_requests < MAX_ENVS) {
		debug3_dir(CLIENT, GATEWAY, PAA_PREFIX "CHANNEL REQUEST: 'env' / env_name = %s", env_name);
		int_store.env_requests[int_store.num_env_requests].name = bfromcstr(env_name);
		int_store.env_requests[int_store.num_env_requests].value = bfromcstr(env_value);
		int_store.num_env_requests++;
		return SSH_OK;
	} else {
		debug3_dir(CLIENT, GATEWAY, PAA_PREFIX "CHANNEL REQUEST: 'env' / MAX REACHED & DENIED / env_name = %s", env_name);
		return SSH_OK;
	}

}


/*!
 * @brief       libssh auth-agent-request callback: record that the client wants agent forwarding
 *
 * Sets @c int_store.requested_auth_agent to @c true and advances the state machine
 * to @c SUSSHI_AGENT_AVAILABLE, signalling that the client's SSH agent is ready to be
 * contacted via an @c auth-agent@openssh.com channel.
 *
 * @ingroup     auth_pubkey_agent_cc
 * @see         libssh Callback definitions
 *
 * @param       session     Unused
 * @param       channel     Unused
 * @param       userdata    Unused
 */

static void
ccb_session_auth_agent_request(ssh_session session, ssh_channel channel, void *userdata) {
	(void) session;
	(void) channel;
	(void) userdata;

	debug3_dir(CLIENT, GATEWAY, PAA_PREFIX "CHANNEL REQUEST: 'auth-agent-req@openssh.com' / want_reply = (unknown, but handled by libssh)");

	int_store.requested_auth_agent = true;
	int_store.state = SUSSHI_AGENT_AVAILABLE;
}


/*!
 * @brief       libssh X11-request callback: record the client's X11 forwarding parameters for replay
 *
 * Stores the X11 parameters in @c int_store.x11 and sets @c int_store.requested_x11
 * to @c true, but only if the @c SSHX11Forward ACL check passes. If the ACL denies
 * the request the parameters are discarded silently.
 *
 * @ingroup     auth_pubkey_agent_cc
 * @see         libssh Callback definitions
 *
 * @param       session             Unused
 * @param       channel             Unused
 * @param       single_connection   Whether the X11 channel should be closed after the first use
 * @param       auth_protocol       X11 authentication protocol name
 * @param       auth_cookie         X11 authentication cookie
 * @param       screen_number       X11 screen number
 * @param       userdata            Unused
 */

static void
ccb_session_x11_request(ssh_session session, ssh_channel channel,
						int single_connection, const char *auth_protocol,
						const char *auth_cookie, uint32_t screen_number, void *userdata) {
	(void) session;
	(void) channel;
	(void) userdata;

	debug3_dir(CLIENT, GATEWAY, PAA_PREFIX "CHANNEL REQUEST: 'x11-req' / want_reply = no");

	if (susshi_chef_authz_acl_bool("SSHX11Forward", true) == SUSSHI_ACL_ALLOW) {
		int_store.x11.single_connection = single_connection;
		int_store.x11.auth_protocol = bfromcstr(auth_protocol);
		int_store.x11.auth_cookie = bfromcstr(auth_cookie);
		int_store.x11.screen_number = screen_number;
		int_store.requested_x11 = true;
	}
}


/*!
 * @brief       libssh shell-request callback: accept or reject an interactive shell request
 *
 * Checks the @c SSHInteractive ACL. On allow, advances the state machine to
 * @c SUSSHI_AGENT_READY with @c session_mode set to @c SHELL. On deny, disconnects
 * both sides with @c DISCONNECT_ACL_SHELL_REQUEST_DENIED.
 *
 * @ingroup     auth_pubkey_agent_cc
 * @see         libssh Callback definitions
 *
 * @param       session     Unused
 * @param       channel     Unused
 * @param       userdata    Unused
 *
 * @return      @c SSH_OK if the shell request was accepted, @c SSH_ERROR if denied
 */

static int
ccb_session_shell_request(ssh_session session, ssh_channel channel, void *userdata) {
	(void) session;
	(void) channel;
	(void) userdata;

	if (susshi_chef_authz_acl_bool("SSHInteractive", true) == SUSSHI_ACL_ALLOW) {
		debug3_dir(CLIENT, GATEWAY, PAA_PREFIX "CHANNEL REQUEST: 'shell' / want_reply = yes");
		int_store.state = SUSSHI_AGENT_READY;
		int_store.session_mode = SHELL;
		log_session(CLIENT, TARGET, "Interactive shell request accepted by ACL.");

		return SSH_OK;
	} else {
		log_session(CLIENT, TARGET, "Interactive shell request denied by ACL.");
		susshi_disconnect_standard(BOTH, DISCONNECT_ACL_SHELL_REQUEST_DENIED);
		return SSH_ERROR;
	}
}


/*!
 * @brief       libssh exec-request callback: record the command for later ACL check and replay
 *
 * Stores @p command in @c int_store.requested_cmd and advances the state machine to
 * @c SUSSHI_AGENT_READY with @c session_mode set to @c EXECCMD. Access control is
 * evaluated later in @c susshi_pubkey_agent_replay_to_target() before the command
 * is forwarded to the target.
 *
 * @ingroup     auth_pubkey_agent_cc
 * @see         libssh Callback definitions
 *
 * @param       session     Unused
 * @param       channel     Unused
 * @param       command     The command string requested by the client
 * @param       userdata    Unused
 *
 * @return      @c SSH_OK (always)
 */

static int
ccb_session_exec_request(ssh_session session, ssh_channel channel,
						 const char *command, void *userdata) {

	(void) session;
	(void) channel;
	(void) userdata;

	/* Access Control is handled later before executing the command on target */

	debug3_dir(CLIENT, GATEWAY, PAA_PREFIX "CHANNEL REQUEST: 'exec-request' / want_reply = yes");

	int_store.requested_cmd = bfromcstr(command);
	int_store.state = SUSSHI_AGENT_READY;

	int_store.session_mode = EXECCMD;

	return SSH_OK;
}


/*!
 * @brief       libssh subsystem-request callback: record the subsystem name for later ACL check and replay
 *
 * Stores @p subsystem in @c int_store.requested_cmd and advances the state machine to
 * @c SUSSHI_AGENT_READY with @c session_mode set to @c SUBSYSTEM. Access control is
 * evaluated later in @c susshi_pubkey_agent_replay_to_target() before the subsystem
 * is forwarded to the target.
 *
 * @ingroup     auth_pubkey_agent_cc
 * @see         libssh Callback definitions
 *
 * @param       session     Unused
 * @param       channel     Unused
 * @param       subsystem   The subsystem name requested by the client (e.g. @c "sftp")
 * @param       userdata    Unused
 *
 * @return      @c SSH_OK (always)
 */

static int
ccb_session_subsystem_request(ssh_session session, ssh_channel channel,
						 const char *subsystem, void *userdata) {

	(void) session;
	(void) channel;
	(void) userdata;

	/* Access Control is handled later before executing the subsystem on target */

	debug3_dir(CLIENT, GATEWAY, PAA_PREFIX "CHANNEL REQUEST: 'subsystem' / %s / want_reply = yes", subsystem);

	int_store.requested_cmd = bfromcstr(subsystem);
	int_store.state = SUSSHI_AGENT_READY;
	int_store.session_mode = SUBSYSTEM;

	return SSH_OK;
}


/*!
 * @brief       Send a request to the client's SSH agent and read the response
 *
 * Writes the 4-byte length-prefixed contents of @p request to the open agent
 * channel via @c agent_atomicio(), then reads the response length and body back
 * into @p reply. Rejects responses larger than 256 KiB.
 *
 * @param       request     Packed request buffer (e.g. @c SSH2_AGENTC_REQUEST_IDENTITIES message)
 * @param       reply       Output buffer; filled with the agent's response on success
 *
 * @return      @c true if the request was sent and a response was received successfully,
 *              @c false on any I/O error or oversized response
 */

static bool
susshi_agent_talk(ssh_buffer request, ssh_buffer reply) {

	uint32_t len = 0;
	uint8_t payload[1024] = {0};

	bool rc = false;

	len = ssh_buffer_get_len(request);
	debug4_dir(GATEWAY, CLIENT, PAA_PREFIX "Request length: %u", len);
	agent_put_u32(payload, len);

	if (agent_atomicio(payload, 4, 0) == 4) {
		if (agent_atomicio(ssh_buffer_get(request), len, false) == len) {

			/* wait for response, read the length of the response packet */
			if (agent_atomicio(payload, 4, 1) != 4) {
				debug4(PAA_PREFIX "Read response length failed: %s.", strerror(errno));
				return false;
			}

			len = agent_get_u32(payload);

			if (len <= 256 * 1024) {
				debug4_dir(CLIENT, GATEWAY, PAA_PREFIX "Response length: %u", len);

				while (len > 0) {
					size_t n = len;
					if (n > sizeof(payload)) {
						n = sizeof(payload);
					}
					if (agent_atomicio(payload, n, 1) == n) {
						if (ssh_buffer_add_data(reply, payload, n) == SSH_OK) {
							len -= n;
						} else {
							debug4("Not enough space");
							return false;
						}
					} else {
						debug4(PAA_PREFIX "Error reading response from agent.");
						return false;
					}
				}
				rc = true;

			} else {
				debug4(PAA_PREFIX "Authentication response too long: %u.", len);
			}
		} else {
			debug4(PAA_PREFIX "sending request failed: %s.", strerror(errno));
		}
	} else {
		debug4(PAA_PREFIX "sending request length failed: %s.", strerror(errno));
	}
	return rc;

}


/*!
 * @brief       Open an @c auth-agent@openssh.com channel to the client's SSH agent
 *
 * Does nothing and sets the state to @c SUSSHI_AGENT_ERROR if no agent-forwarding
 * request was received from the client (@c int_store.requested_auth_agent is @c false).
 * On success, stores the open channel in @c int_store.agent_channel and advances the
 * state to @c SUSSHI_AGENT_CHANNEL_OPEN.
 *
 * @ingroup     auth_pubkey_agent
 */

static void
susshi_agent_request_channel(void) {
	int_store.state = SUSSHI_AGENT_ERROR;

	/* We did not receive any auth-agent@openssh.com request so far, so the story ends here */
	if (int_store.requested_auth_agent == false) {
		int_store.state = SUSSHI_AGENT_ERROR;
		return;
	}

	int_store.agent_channel = ssh_channel_new(susshi_session.client_session);

	if (int_store.agent_channel) {
		debug3_dir(GATEWAY, CLIENT, PAA_PREFIX "CHANNEL OPEN: 'auth-agent@openssh.com' / want_reply = no");

		if (ssh_channel_open_auth_agent(int_store.agent_channel) == SSH_OK) {
			if (ssh_channel_is_open(int_store.agent_channel)) {
				debug3_dir(CLIENT, GATEWAY,
						   PAA_PREFIX "CHANNEL OPEN: 'auth-agent@openssh.com' successfull  (lchannel = %d)",
						   int_store.agent_channel->local_channel);
				int_store.state = SUSSHI_AGENT_CHANNEL_OPEN;
			}
		}
	}
}


/*!
 * @brief       Request the list of public-key identities from the client's SSH agent
 *
 * Sends an @c SSH2_AGENTC_REQUEST_IDENTITIES message via @c susshi_agent_talk() and
 * parses the @c SSH2_AGENT_IDENTITIES_ANSWER response. On success, stores the number
 * of identities in @c int_store.num_identities, retains the response buffer in
 * @c int_store.identities_buffer, and advances the state to
 * @c SUSSHI_AGENT_IDS_RECEIVED. Disconnects if the agent reports zero identities.
 * Sets the state to @c SUSSHI_AGENT_ERROR on protocol or I/O failure.
 *
 * @ingroup     auth_pubkey_agent
 */

static void
susshi_agent_request_identities(void) {

	uint8_t type;
	uint32_t identities;
	uint8_t buf[4] = {0};

	ssh_buffer request = ssh_buffer_new();
	ssh_buffer reply = ssh_buffer_new();

	int_store.state = SUSSHI_AGENT_ERROR;

	ssh_buffer_pack(request, "b",
					SSH2_AGENTC_REQUEST_IDENTITIES);

	debug3_dir(GATEWAY, CLIENT, PAA_PREFIX "Request Identities");

	if (susshi_agent_talk(request, reply)) {

		/* get message type and verify the answer */
		if (ssh_buffer_get_u8(reply, (uint8_t *) &type) == sizeof(uint8_t)) {
			if (type == SSH2_AGENT_IDENTITIES_ANSWER) {

				if (ssh_buffer_get_u32(reply, (uint32_t *) buf) == 4) {

					identities = agent_get_u32(buf);
					debug3_dir(CLIENT, GATEWAY, PAA_PREFIX "Identities Answer containing %d keys.", identities);
					if (identities > 0) {
						if (identities < 1024) {
							int_store.num_identities = identities;
							int_store.identities_buffer = reply;
							int_store.state = SUSSHI_AGENT_IDS_RECEIVED;
						} else {
							debug3(PAA_PREFIX "Too many identities in authentication reply: %d", identities);
						}
					} else {
						susshi_disconnect_standard(BOTH, DISCONNECT_AUTH_AGENT_NO_IDENTITIES);
					}
				}
			} else {
				debug3(PAA_PREFIX "Bad authentication reply messsage type: %u.", type);
			}
		} else {
			debug3(PAA_PREFIX "Bad authentication reply size.");
		}
	}

	SSH_BUFFER_FREE(request);
}


/*!
 * @brief       Ask the client's SSH agent to sign the target session's authentication data
 *
 * Constructs the @c SSH2_AGENTC_SIGN_REQUEST payload containing @p key_blob and the
 * @c SSH2_MSG_USERAUTH_REQUEST data blob (session ID, user, service, method, key).
 * Sets the appropriate RSA flags (@c SSH_AGENT_RSA_SHA2_256 / @c SSH_AGENT_RSA_SHA2_512)
 * based on the negotiated signature algorithm. Sends the request via @c susshi_agent_talk()
 * and extracts the signature from the @c SSH2_AGENT_SIGN_RESPONSE.
 *
 * @param       session     The target @c ssh_session (used to obtain session ID and crypto context)
 * @param       public_key  The public key for which a signature is requested
 * @param       key_blob    Wire-format blob of @p public_key (as sent to the target during probing)
 *
 * @return      Heap-allocated @c ssh_string containing the signature, or @c NULL on failure;
 *              the caller must free it with @c SSH_STRING_FREE()
 */

static ssh_string
susshi_agent_request_signature(ssh_session session, ssh_key public_key, ssh_string key_blob) {

	uint8_t type;
	const char *type_c;

	ssh_buffer request = ssh_buffer_new();
	ssh_buffer reply = ssh_buffer_new();
	ssh_buffer data = ssh_buffer_new();
	ssh_string signature = NULL;
	ssh_string session_id = NULL;
	struct ssh_crypto_struct *crypto;

	type_c = ssh_key_get_signature_algorithm(session, public_key->type);

	/* Prepare Data Signing request message */
	crypto = susshi_session.target_session->current_crypto ? susshi_session.target_session->current_crypto :
															 susshi_session.target_session->next_crypto;

	/*
	 * A client may use the following message to request signing of data using a protocol 2 key:
	 *
	 * 	byte			SSH2_AGENTC_SIGN_REQUEST
	 * string			key_blob
	 * string			data (*)
	 * uint32			flags
	 *
	 * (*) The value of 'signature' is a signature by the corresponding private
	 *     key over the following data, in the following order:
	 *
	 *       string    session identifier
	 *       byte      SSH_MSG_USERAUTH_REQUEST
	 *       string    user name
	 *       string    service name
	 *       string    "publickey"
	 *       boolean   TRUE
	 *       string    public key algorithm name
	 *       string    public key to be used for authentication
	 */

	session_id = ssh_string_new(crypto->digest_len);
	ssh_string_fill(session_id, crypto->session_id, crypto->digest_len);

	ssh_buffer_pack(data, "SbsssbsS",
					session_id,
					SSH2_MSG_USERAUTH_REQUEST,
					bdata(susshi_session.target_user),
					"ssh-connection",
					"publickey",
					1,
					type_c,
					key_blob
	);

	ssh_buffer_add_u8(request, SSH2_AGENTC_SIGN_REQUEST);
	ssh_buffer_add_ssh_string(request, key_blob);
	ssh_buffer_add_u32(request, htonl(ssh_buffer_get_len(data)));
	ssh_buffer_add_data(request, ssh_buffer_get(data), ssh_buffer_get_len(data));

	// Add Signature flags (see at https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#page-13)
	if (strcmp(type_c, "rsa-sha2-256") == 0) {
		ssh_buffer_add_u32(request,  htonl(SSH_AGENT_RSA_SHA2_256));
	} else if (strcmp(type_c, "rsa-sha2-512") == 0) {
		ssh_buffer_add_u32(request, htonl(SSH_AGENT_RSA_SHA2_512));
	} else {
		ssh_buffer_add_u32(request,  htonl(0));
	}

	debug3_dir(GATEWAY, CLIENT, PAA_PREFIX "Request signing with algorithm %s.", type_c);

	if (susshi_agent_talk(request, reply)) {
		/* get message type and verify the answer */
		if (ssh_buffer_get_u8(reply, (uint8_t *) &type) == sizeof(uint8_t)) {
			if (type == SSH2_AGENT_SIGN_RESPONSE) {
				signature = ssh_buffer_get_ssh_string(reply);
				debug3_dir(CLIENT, GATEWAY, PAA_PREFIX "Received signature of length %ld bytes.", ssh_string_len(signature));

			} else {
				debug3(PAA_PREFIX "Bad signing reply messsage type: %u.", type);
			}
		} else {
			debug3(PAA_PREFIX "Bad signing reply size.");
		}
	}

	SSH_BUFFER_FREE(data);
	SSH_STRING_FREE(session_id);
	SSH_BUFFER_FREE(request);
	SSH_BUFFER_FREE(reply);

	return signature;
}


/*!
 * @brief       Transmit a signed @c SSH2_MSG_USERAUTH_REQUEST to the target and wait for the result
 *
 * Packs and sends a publickey authentication request containing @p key_blob and
 * @p signature to the target session. Sets the auth state to
 * @c SSH_AUTH_STATE_PUBKEY_AUTH_SENT and calls @c ssh_userauth_get_response() to
 * poll for the target's reply.
 *
 * @param       session     The target @c ssh_session to authenticate against
 * @param       public_key  The public key used to determine the signature algorithm
 * @param       key_blob    Wire-format blob of @p public_key
 * @param       signature   Signature produced by the client's SSH agent
 *
 * @return      @c SSH_AUTH_SUCCESS on success, or another @c SSH_AUTH_* code from
 *              @c ssh_userauth_get_response()
 */

int
susshi_agent_target_send_pubkey_signature(ssh_session session, ssh_key public_key, ssh_string key_blob, ssh_string signature)
{
	int rc = SSH_AUTH_ERROR;
	int rc_ssh;
	const char *type_c;

	type_c = ssh_key_get_signature_algorithm(session, public_key->type);

	/* request */

	/*
	 *  To perform actual authentication, the client MAY then send a
	 *  signature generated using the private key.  The client MAY send the
	 *  signature directly without first verifying whether the key is
	 *  acceptable.  The signature is sent using the following packet:
	 *
	 *        byte      SSH_MSG_USERAUTH_REQUEST
	 *        string    user name
	 *        string    service name
	 *        string    "publickey"
	 *        boolean   TRUE
	 *        string    public key algorithm name
	 *        string    public key to be used for authentication
	 *        string    signature
	 *
	 */

	rc_ssh = ssh_buffer_pack(susshi_session.target_session->out_buffer, "bsssbsSS",
							 SSH2_MSG_USERAUTH_REQUEST,
							 bdata(susshi_session.target_user),
							 "ssh-connection",
							 "publickey",
							 1,
							 type_c,
							 key_blob,
							 signature);

	if (rc_ssh == SSH_OK) {
		if (ssh_packet_send(susshi_session.target_session) == SSH_OK) {
			susshi_ssh_set_auth_state(susshi_session.target_session, SSH_AUTH_STATE_PUBKEY_AUTH_SENT);
			rc = ssh_userauth_get_response(susshi_session.target_session);
		}
	}

	return rc;
}


/*!
 * @brief       libssh EOF callback for the agent channel: log the event
 *
 * Called when the client sends EOF on the @c auth-agent@openssh.com channel.
 * Only logs; actual state transition happens in the close callback.
 *
 * @ingroup     auth_pubkey_agent_cc
 * @see         libssh Callback definitions
 *
 * @param       session     Unused
 * @param       channel     The agent channel that received EOF (used for logging its local channel ID)
 * @param       userdata    Unused
 */

static void
ccb_agentchannel_session_eof(ssh_session session, ssh_channel channel, void *userdata) {
	(void) session;
	(void) channel;
	(void) userdata;

	debug3_dir(CLIENT, GATEWAY, PAA_PREFIX "Auth-Agent CHANNEL EOF (lchannel = %d)", channel->local_channel);
}


/*!
 * @brief       libssh close callback for the agent channel: signal agent I/O completion
 *
 * Advances the state machine to @c SUSSHI_AGENT_COMPLETE, causing the
 * @c susshi_pubkey_agent_client_ready() event loop to exit.
 *
 * @ingroup     auth_pubkey_agent_cc
 * @see         libssh Callback definitions
 *
 * @param       session     Unused
 * @param       channel     The agent channel that was closed (used for logging its local channel ID)
 * @param       userdata    Unused
 */

static void
cbc_agentchannel_session_close_function(ssh_session session, ssh_channel channel, void *userdata) {

	(void) session;
	(void) channel;
	(void) userdata;

	debug3_dir(CLIENT, GATEWAY, PAA_PREFIX "Auth-Agent CHANNEL CLOSE (lchannel = %d)", channel->local_channel);
	int_store.state = SUSSHI_AGENT_COMPLETE;
}


/*!
 * @brief       Authenticate against the target using keys provided by the client's SSH agent
 *
 * Iterates over the identities previously received from the agent
 * (@c int_store.identities_buffer). For each key, calls
 * @c ssh_userauth_try_publickey() to probe whether the target accepts it, then
 * asks the agent to sign the session data via @c susshi_agent_request_signature()
 * and sends the signed request to the target via
 * @c susshi_agent_target_send_pubkey_signature(). Both key blobs and the signature
 * are burned (zeroed) immediately after use. Advances the state to
 * @c SUSSHI_AGENT_SEND_CLOSE on success or leaves it at @c SUSSHI_AGENT_ERROR
 * on failure.
 *
 * @return      @c SSH_AUTH_SUCCESS on success, otherwise another @c SSH_AUTH_* code
 */

static int
susshi_agent_authenticate_target(void) {
	int k, use_key;
	int rc = SSH_AUTH_ERROR;
	ssh_string key_blob = NULL;
	ssh_string key_comment = NULL;
	ssh_key key = NULL;
	ssh_string signature = NULL;

	int_store.state = SUSSHI_AGENT_ERROR;

	// Iterate Keys and send them to target to probe which key may fit
	for(k=0; ((k < int_store.num_identities) && (rc != SSH_AUTH_SUCCESS)); k++) {

		key_blob = ssh_buffer_get_ssh_string(int_store.identities_buffer);

		if (ssh_pki_import_pubkey_blob(key_blob, &key) == SSH_OK) {

			key_comment = ssh_buffer_get_ssh_string(int_store.identities_buffer);

			if_debug3() {
				const char *fp = susshi_display_hash_from_key(key);

				do_debug3_dir(GATEWAY, TARGET, PAA_PREFIX "Trying public key #%d: %s %s (%s)", k + 1,
						   susshi_ssh_key_type_to_char(key), fp, ssh_string_get_char(key_comment));

				if (fp)
					xfree((void *) fp);
			}

			SSH_STRING_FREE(key_comment);

			rc = ssh_userauth_try_publickey(susshi_session.target_session, bdata(susshi_session.target_user), key);

			if (rc == SSH_AUTH_SUCCESS) {
				use_key = k;
			} else {
				if (rc == SSH_AUTH_DENIED) {
					debug3_dir(GATEWAY, TARGET, PAA_PREFIX "Public key #%d not accepted: %s", k + 1,
							   ssh_get_error(susshi_session.target_session));
				}

				SSH_KEY_FREE(key);
			}
		}

		if (rc != SSH_AUTH_SUCCESS) {
			debug4(PAA_PREFIX "Burning target authentication key %d", k+1);
			ssh_string_burn(key_blob);
			SSH_STRING_FREE(key_blob);
		}

		if (rc == SSH_AUTH_SUCCESS) {

			debug3_dir(TARGET, GATEWAY, PAA_PREFIX "Target will accept key #%d", use_key + 1);

			/* Request signature from Agent on Client */
			signature = susshi_agent_request_signature(susshi_session.target_session, key, key_blob);

			if (signature) {

				debug3_dir(GATEWAY, TARGET, PAA_PREFIX "Send key with signature to Target");

				/* Send key with signature to Target */
				rc = susshi_agent_target_send_pubkey_signature(susshi_session.target_session, key, key_blob, signature);

				if (rc == SSH_AUTH_SUCCESS) {
					int_store.state = SUSSHI_AGENT_SEND_CLOSE;
					debug3_dir(TARGET, GATEWAY,
							   PAA_PREFIX "Target has accepted signed message with key #%d", use_key + 1);
				} else {
					debug3_dir(TARGET, GATEWAY,
							   PAA_PREFIX "Target rejected our signed key even it accepted the unsigned key before");
					continue;
				}
				ssh_string_burn(signature);
				SSH_STRING_FREE(signature);

			} else {
				debug3(PAA_PREFIX "Did not receive signature");
				susshi_disconnect_standard(BOTH, DISCONNECT_AUTH_AGENT_SIGNATURE_INVALID);
			}

			debug4(PAA_PREFIX "Burning target authentication key %d", use_key + 1);
			ssh_string_burn(key_blob);
			SSH_STRING_FREE(key_blob);

			// Freeing the key also burns the key
			SSH_KEY_FREE(key);
		}
	}

	return rc;
}


/*!
 * @brief       Replay the client's recorded session setup onto the target connection
 *
 * Opens a session channel to the target, then replays — in order — all requests
 * that were recorded during the agent authentication phase: X11 forwarding, agent
 * forwarding, PTY, environment variables, suSSHi shell-env variables, and the
 * session service (shell, exec, or subsystem). Allocates a @c SusshiChannel for
 * logging and packet inspection. Adjusts SSH window sizes on both sides to avoid
 * flow-control mismatches. Replays any data buffered in @c int_store.delayed_client_data
 * and forwards any pending EOF. Also replays all recorded @c tcpip-forward global
 * requests. Disconnects with @c DISCONNECT_TARGET_PROTOCOL_ERROR on any failure.
 *
 * @return      @c true if the full replay succeeded, @c false otherwise
 */

bool
susshi_pubkey_agent_replay_to_target(void) {
	int req_rc;

	static ssh_channel target_session_channel;
	SusshiChannel *c;
	bstring logtext = NULL;
	bstring termsize = NULL;

	int_store.cid = -1;

	/* Open Channel to Target */
	if ((target_session_channel = ssh_channel_new(susshi_session.target_session))) {

		debug3_dir(GATEWAY, TARGET, PAA_PREFIX "CHANNEL OPEN: Request session channel");

		/* Channel-IDs start-range in PubKeyAgent mode (proxied channels) */
		susshi_session.target_session->maxchannel = (uint32_t) SUSSHI_SESSION_TARGET_CHANNEL_START;

		/* Open session */
		if (ssh_channel_open_session(target_session_channel) == SSH_OK) {

			debug4_dir(GATEWAY, TARGET, PAA_PREFIX "Starting target replay phase.");
			susshi_session.paa_target_replay_phase = true;

			/* Request X11 */
			if (int_store.requested_x11) {
				if (susshi_chef_authz_acl_bool("SSHX11Forward", true) == SUSSHI_ACL_ALLOW) {
					debug3_dir(GATEWAY, TARGET, PAA_PREFIX "CHANNEL REQUEST: 'x11-req' / want_reply = no");
					ssh_channel_request_x11(target_session_channel, int_store.x11.single_connection, bdata(int_store.x11.auth_protocol),
											bdata(int_store.x11.auth_cookie), int_store.x11.screen_number);
				}
			}

			/* Request Agent Forwarding */
			if (int_store.session_mode != SUBSYSTEM) {
				if (susshi_chef_authz_acl_bool("SSHAgentForward", true) == SUSSHI_ACL_ALLOW) {
					debug3_dir(GATEWAY, TARGET, PAA_PREFIX "CHANNEL REQUEST: 'auth-agent@openssh.com' / want_reply = no");
					ssh_channel_request_auth_agent(target_session_channel);
				}
			}

			/* Request PTY */
			if (int_store.requested_pty) {
				debug3_dir(GATEWAY, TARGET, PAA_PREFIX "CHANNEL REQUEST: 'pty-req' / want_reply = yes / %s - %dx%d - 0x0px",
						   bdata(int_store.terminal.term), int_store.terminal.cols, int_store.terminal.rows);
				ssh_channel_request_pty_size(target_session_channel, bdata(int_store.terminal.term),
											 int_store.terminal.cols, int_store.terminal.rows);
				termsize = bformat("%dx%d 0x0", int_store.terminal.cols, int_store.terminal.rows);
			}

			/* Request ENV variables */
			for(int i=0; i < int_store.num_env_requests; i++) {
				debug3_dir(GATEWAY, TARGET, PAA_PREFIX "CHANNEL REQUEST: 'env' / env_name = %s.", bdata(int_store.env_requests[i].name));
				ssh_channel_request_env(target_session_channel, bdata(int_store.env_requests[i].name), bdata(int_store.env_requests[i].value));
			}

			/* Send suSSHi ENV variables as well */
			if (susshi_cfg.send_shell_env == 1) {
				susshi_session.send_shell_env = true;
				susshi_session.send_shell_env_channel = target_session_channel->remote_channel;
				susshi_send_shell_env();
				susshi_session.send_shell_env = false;
			}

			/* Prepare suSSHi Channel for Logging and further Packet Inspection */
			int_store.cid = susshi_alloc_new_channel();
			c = susshi_session.channels[int_store.cid];
			c->requestor=CLIENT;
			c->ctype = xmalloc(sizeof("session"));
			strncpy(c->ctype, "session", sizeof("session"));

			c->requestor_ch = int_store.session_channel->remote_channel;
			c->provider_ch = target_session_channel->remote_channel;
			c->gateway_provider_ch = int_store.session_channel->local_channel;
			c->gateway_requestor_ch = target_session_channel->local_channel;
			c->proxied_channel = true;

			c->logging = NONE;
			c->state = SSH2_MSG_CHANNEL_OPEN_CONFIRMATION;

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

			c->log_protocol.filetype = NULL;

			c->requestor_send = 0;
			c->provider_send = 0;

			susshi_report.channels_opened++;

			req_rc = SSH_ERROR;

			/* Request Service */
			switch(int_store.session_mode) {
				case SHELL: {
					debug3_dir(GATEWAY, TARGET, PAA_PREFIX "CHANNEL REQUEST: 'shell' / want_reply = yes");

					c->logging = TEXT;
					susshi_channel_set_logging(int_store.cid, c->logging, termsize, bdata(int_store.terminal.term));

					/* req_rc = ssh_channel_request_shell(target_session_channel); */

					ssh_buffer_pack(susshi_session.target_session->out_buffer,
									"bdsb",
									SSH2_MSG_CHANNEL_REQUEST,
									target_session_channel->remote_channel,
									"shell",
									1);

					req_rc = ssh_packet_send(susshi_session.target_session);

					if (req_rc == SSH_OK) {
						if (ssh_buffer_get_len(int_store.delayed_client_data) > 0) {

							debug3_dir(CLIENT, GATEWAY, "Logging buffered data of length %d.",
									   ssh_buffer_get_len(int_store.delayed_client_data));

							log_client_input(int_store.cid, ssh_buffer_get(int_store.delayed_client_data),
											 ssh_buffer_get_len(int_store.delayed_client_data));
						}
					}

					/* Set session to interactive / disable Nagle */
					susshi_session_interactive();

					susshi_report.interactive_sessions_accepted++;

				} break;

				case EXECCMD: {
					ChannelResponse response;
					ssh_string cmd = ssh_string_from_char(bdata(int_store.requested_cmd));

					debug3_dir(GATEWAY, TARGET, PAA_PREFIX "CHANNEL REQUEST: 'exec-request' / want_reply = yes");

					// Adjust Channel data according further inspection
					response = susshi_inspect_channel_request_exec(CLIENT, int_store.cid, &c->logging, &logtext, cmd,
																   &(c->scp_requestor_mode), &(c->scp_dir_name));

					if (logtext) {
						debug2_dir(CLIENT, TARGET, "%s", bdata(logtext));
						log_session(CLIENT, TARGET, "%s", bdata(logtext));
						bstrFree(logtext);
					}

					if (response == OK) {
						susshi_channel_set_logging(int_store.cid, c->logging, termsize, bdata(int_store.terminal.term));

						/* req_rc = ssh_channel_request_exec(target_session_channel, bdata(int_store.requested_cmd)); */

						ssh_buffer_pack(susshi_session.target_session->out_buffer,
										"bdsbs",
										SSH2_MSG_CHANNEL_REQUEST,
										target_session_channel->remote_channel,
										"exec",
										1,
										bdata(int_store.requested_cmd));

						req_rc = ssh_packet_send(susshi_session.target_session);

						if (req_rc == SSH_OK) {
							if (ssh_buffer_get_len(int_store.delayed_client_data) > 0) {

								debug3_dir(CLIENT, GATEWAY, "Logging buffered data of length %d.",
										   ssh_buffer_get_len(int_store.delayed_client_data));

								log_client_input(int_store.cid, ssh_buffer_get(int_store.delayed_client_data),
												 ssh_buffer_get_len(int_store.delayed_client_data));
							}
						}
					} else {
						susshi_disconnect_standard(BOTH, DISCONNECT_ACL_EXEC_REQUEST_DENIED);
					}

					susshi_report.command_execs_accepted++;

					SSH_STRING_FREE(cmd);

				} break;

				case SUBSYSTEM: {
					ChannelResponse response;
					ssh_string cmd = ssh_string_from_char(bdata(int_store.requested_cmd));

					debug3_dir(GATEWAY, TARGET, PAA_PREFIX "CHANNEL REQUEST: 'subsystem' (%s) / want_reply = yes",
							   bdata(int_store.requested_cmd));

					// Adjust Channel data according further inspection
					response = susshi_inspect_channel_request_subsystem(CLIENT, int_store.cid, &c->logging, &logtext, cmd);
					SSH_STRING_FREE(cmd);

					if (logtext) {
						debug2_dir(CLIENT, TARGET, "%s", bdata(logtext));
						log_session(CLIENT, TARGET, "%s", bdata(logtext));
						bstrFree(logtext);
					}

					if (response == OK) {
						susshi_channel_set_logging(int_store.cid, c->logging, NULL, NULL);

						ssh_buffer_pack(susshi_session.target_session->out_buffer,
										"bdsbs",
										SSH2_MSG_CHANNEL_REQUEST,
										target_session_channel->remote_channel,
										"subsystem",
										1,
										bdata(int_store.requested_cmd));

						req_rc = ssh_packet_send(susshi_session.target_session);

						if (req_rc == SSH_OK) {
							if (ssh_buffer_get_len(int_store.delayed_client_data) > 0) {
								debug3_dir(CLIENT, GATEWAY, "Logging buffered data of length %d.",
										   ssh_buffer_get_len(int_store.delayed_client_data));
							}
						}
					} else {
						susshi_disconnect_standard(BOTH, DISCONNECT_ACL_SUBS_REQUEST_DENIED);
					}

					if (strcmp(bdata(int_store.requested_cmd), "sftp") == 0) {
						susshi_report.sftp_sessions++; }
					else {
						susshi_report.unkown_subsystems_accepted++;
					}

				} break;

				default: {
				} break;
			}


			if (req_rc == SSH_OK) {

				/*
				 * Adjust Windows to match peer
				 *
				 * The plan:
				 * 1. If Client allows a larger window than we sent to Target, we send an adjustment to Target
				 * 2. If Target allows a larger window than we sent to Client, we send an adjustment to Client
				 */

				/*
				debug5("Window-Target Adjust remote_window = %d / local_window = %d",
						int_store.session_channel->remote_window, target_session_channel->local_window);
				*/

				/* Adjust Window on Target Side */
				if (int_store.session_channel->remote_window > target_session_channel->local_window) {
					uint32_t adjust_by = int_store.session_channel->remote_window - target_session_channel->local_window;

					if (ssh_channel_is_open(target_session_channel)) {
						debug3_dir(GATEWAY, TARGET, PAA_PREFIX
								"We adjust Target-side window-size by %d to accept at least same window-size %d we got from Client.",
								   adjust_by, int_store.session_channel->remote_window);

						ssh_buffer_pack(susshi_session.target_session->out_buffer, "bdd",
										SSH2_MSG_CHANNEL_WINDOW_ADJUST,
										target_session_channel->remote_channel,
										adjust_by);
						ssh_packet_send(susshi_session.target_session);

						target_session_channel->local_window = int_store.session_channel->remote_window;
					}
				}

				/*
				debug5("Window-Client Adjust remote_window = %d / local_window = %d, ssh_channel_is_open(int_store.session_channel) = %d",
						target_session_channel->remote_window, int_store.session_channel->local_window, ssh_channel_is_open(int_store.session_channel));
				*/

				/* Adjust Window on Client Side */
				if (target_session_channel->remote_window > int_store.session_channel->local_window) {
					uint32_t adjust_by = target_session_channel->remote_window - int_store.session_channel->local_window;

					if (ssh_channel_is_open(int_store.session_channel)) {
						debug3_dir(GATEWAY, CLIENT, PAA_PREFIX
								"We adjust Client-side window-size by %d to accept at least same window-size %d we got from Target.",
								   adjust_by, target_session_channel->remote_window);

						ssh_buffer_pack(susshi_session.client_session->out_buffer, "bdd",
										SSH2_MSG_CHANNEL_WINDOW_ADJUST,
										int_store.session_channel->remote_channel,
										adjust_by);
						ssh_packet_send(susshi_session.client_session);

						int_store.session_channel->local_window = target_session_channel->remote_window;
					}
				}

				/* Replay recorded DATA from client on target channel */
				if ((ssh_buffer_get_len(int_store.delayed_client_data) > 0)
					&& (ssh_channel_is_open(target_session_channel))) {

					debug3_dir(GATEWAY, TARGET, "Sending buffered data of length %d.",
							   ssh_buffer_get_len(int_store.delayed_client_data));

					ssh_channel_write(target_session_channel,
									  ssh_buffer_get(int_store.delayed_client_data),
									  ssh_buffer_get_len(int_store.delayed_client_data));

					ssh_channel_flush(target_session_channel);
				}

				/* Request EOF */
				if ((int_store.requested_eof)
					&& (ssh_channel_is_open(target_session_channel))) {
					debug3_dir(GATEWAY, TARGET, "Forward EOF request from client.");

					ssh_buffer_pack(susshi_session.target_session->out_buffer,
										  "bd",
										  SSH2_MSG_CHANNEL_EOF,
										  target_session_channel->remote_channel);
					ssh_packet_send(susshi_session.target_session);
				}

				/* Prevent libssh from iterating over channels list afterwards */
				if (susshi_session.target_session->channels) {
					ssh_list_free(susshi_session.target_session->channels);
					susshi_session.target_session->channels = NULL;
				}

				if (susshi_session.client_session->channels) {
					ssh_list_free(susshi_session.client_session->channels);
					susshi_session.client_session->channels = NULL;
				}

				/* Request Remote TCP forwards */
				for(int i=0; i < int_store.num_remote_tcp_requests; i++) {

					debug3_dir(GATEWAY, TARGET, PAA_PREFIX "GLOBAL REQUEST: 'tcpip-forward' [%s]:%d (want-reply = %s)",
							   bdata(int_store.remote_tcp_requests[i].bind_address),
							   int_store.remote_tcp_requests[i].bind_port,
							   int_store.remote_tcp_requests[i].want_reply ? "yes" : "no");

					ssh_buffer_pack(susshi_session.target_session->out_buffer,
									"bsbsd",
									SSH2_MSG_GLOBAL_REQUEST,
									"tcpip-forward",
									int_store.remote_tcp_requests[i].want_reply,
									bdata(int_store.remote_tcp_requests[i].bind_address),
									int_store.remote_tcp_requests[i].bind_port);

					susshi_session.target_session->global_req_state = SSH_CHANNEL_REQ_STATE_PENDING;
					susshi_session.num_remote_tcp_requests_pending++;

					ssh_packet_send(susshi_session.target_session);

					susshi_report.remote_forwards_accepted++;
				}

				return true;
			}
		}
	}

	susshi_disconnect_standard(BOTH, DISCONNECT_TARGET_PROTOCOL_ERROR);

	return false;
}


/*!
 * @brief       Run the SSH agent forwarding state machine and authenticate the target using the client's agent
 *
 * Installs libssh callbacks on the client session, then enters an event loop that
 * drives the @c susshi_agent_state machine through:
 * @c SUSSHI_AGENT_READY → open agent channel → request identities → authenticate
 * target → close agent channel → @c SUSSHI_AGENT_COMPLETE.
 * Once complete, calls @c susshi_pubkey_agent_replay_to_target() to replay the
 * recorded client session onto the target. Restores the previous libssh callbacks
 * before returning. Disconnects the client if it never sent an agent-forwarding
 * request.
 *
 * @return      @c SSH_AUTH_SUCCESS if target authentication and session replay succeeded,
 *              @c SSH_AUTH_ERROR otherwise
 */

int
susshi_pubkey_agent_client_ready(void) {

	int rc = SSH_AUTH_ERROR;
	int poll_rc;
	int session_ready_timeout = 0;
	ssh_event event_ctxt;
	struct ssh_server_callbacks_struct *previous_server_callbacks = susshi_session.client_session->server_callbacks;
	struct ssh_callbacks_struct *previous_callbacks = susshi_session.client_session->common.callbacks;

	struct ssh_callbacks_struct ssh_cb = {
			.global_request_function = ccb_global_request
	};

	struct ssh_server_callbacks_struct server_cb = {
			.channel_open_request_session_function = ccb_channel_open_request
	};

	struct ssh_channel_callbacks_struct channel_cb = {
			.userdata = &int_store,
			.channel_pty_request_function = ccb_session_pty_request,
			.channel_pty_window_change_function = ccb_session_pty_window_change,
			.channel_shell_request_function = ccb_session_shell_request,
			.channel_auth_agent_req_function = ccb_session_auth_agent_request,
			.channel_exec_request_function = ccb_session_exec_request,
			.channel_env_request_function = ccb_session_env_request,
			.channel_x11_req_function = ccb_session_x11_request,
			.channel_data_function = ccb_session_data,
			.channel_eof_function = ccb_session_eof,
			.channel_subsystem_request_function = ccb_session_subsystem_request
	};

	struct ssh_channel_callbacks_struct agent_channel_cb = {
			.userdata = &int_store,
			.channel_eof_function = ccb_agentchannel_session_eof,
			.channel_close_function = cbc_agentchannel_session_close_function
	};

	/* Init callbacks */
	ssh_callbacks_init(&ssh_cb);
	ssh_callbacks_init(&server_cb);
	ssh_callbacks_init(&channel_cb);
	ssh_callbacks_init(&agent_channel_cb);

	ssh_set_callbacks(susshi_session.client_session, &ssh_cb);
	ssh_set_server_callbacks(susshi_session.client_session, &server_cb);

	event_ctxt = ssh_event_new();
	ssh_event_add_session(event_ctxt, susshi_session.client_session);

	int_store.state = SUSSHI_AGENT_START;
	int_store.delayed_client_data = ssh_buffer_new();

	/* Wait for channel open request */
	while (int_store.session_channel == NULL) {
		poll_rc = ssh_event_dopoll(event_ctxt, 1000);
		if (poll_rc == SSH_ERROR) {
			log_system(LOG_LEVEL_CRIT, "Error while waiting for session channel: %s\n", ssh_get_error(susshi_session.client_session));
			return false;
		}
		if (++session_ready_timeout > 3) {
			susshi_disconnect_standard(CLIENT, DISCONNECT_AUTH_AGENT_SESSION_MISSING);
		}
	}

	/* We have a channel */

	/* Wait for other requests and loop through data */
	ssh_set_channel_callbacks(int_store.session_channel, &channel_cb);

	/*
	 * The status SUSSHI_AGENT_ATOM_ACTION is used when ssh_even_dopoll() returns
	 * with SSH_AGAIN to prevent branching back to the same state branch.
	 */

	do {
		poll_rc = ssh_event_dopoll(event_ctxt, 10);

		if ((poll_rc == SSH_ERROR) ||
			(ssh_channel_is_open(int_store.session_channel) == 0)) {
			int_store.state = SUSSHI_AGENT_ERROR;
		}

		debug4(PAA_PREFIX "State: %d (enum)", int_store.state);

		switch(int_store.state) {
			case SUSSHI_AGENT_READY: {
				int_store.state = SUSSHI_AGENT_ATOM_ACTION;
				susshi_agent_request_channel();
			} break;
			case SUSSHI_AGENT_CHANNEL_OPEN: {
				int_store.state = SUSSHI_AGENT_ATOM_ACTION;
				susshi_agent_request_identities();
			} break;
			case SUSSHI_AGENT_IDS_RECEIVED: {
				int_store.state = SUSSHI_AGENT_ATOM_ACTION;
				susshi_agent_authenticate_target();
			} break;
			case SUSSHI_AGENT_SEND_CLOSE: {
				/*
				 * We have completed AuthAgent-I/O and now close the channel and wait for
				 * CHANNEL_CLOSE and EOF messages from client
				 * */
				int_store.state = SUSSHI_AGENT_ATOM_ACTION;
				ssh_set_channel_callbacks(int_store.agent_channel, &agent_channel_cb);

				debug3_dir(GATEWAY, CLIENT, PAA_PREFIX "Auth-Agent CHANNEL CLOSE");
				ssh_channel_flush(int_store.agent_channel);
				ssh_channel_close(int_store.agent_channel);
				if (int_store.state == SUSSHI_AGENT_COMPLETE) {
					/* Client has already sent close for Agent Channel, so we do not wait for close here */
					debug4_dir(CLIENT, GATEWAY, PAA_PREFIX "We've already received the CLOSE from client, so we are done here.");
				} else {
					/* Wait for close from client */
					int_store.state = SUSSHI_AGENT_CLOSE_SENT;
				}
			} break;
			case SUSSHI_AGENT_COMPLETE: {
				ssh_remove_channel_callbacks(int_store.agent_channel, &agent_channel_cb);
			} break;

			/*
			 * The status SUSSHI_AGENT_ATOM_ACTION is used when ssh_even_dopoll() returns
			 * with SSH_AGAIN to prevent branching back to the same state branch.
			 */
			case SUSSHI_AGENT_ATOM_ACTION:
				break;

			case SUSSHI_AGENT_CLOSE_SENT: {
				debug3_dir(GATEWAY, CLIENT, PAA_PREFIX "Auth-Agent CHANNEL CLOSE sent, waiting for CLOSE from client.");
			} break;
			case SUSSHI_AGENT_START:
			case SUSSHI_AGENT_AVAILABLE:
			case SUSSHI_AGENT_ERROR: {
			} break;
		}

	} while((int_store.state != SUSSHI_AGENT_COMPLETE) &&
			(int_store.state != SUSSHI_AGENT_ERROR));

	ssh_remove_channel_callbacks(int_store.session_channel, &channel_cb);
	ssh_event_free(event_ctxt);

	/* Remove registered callbacks / Set back to previous ones */
	susshi_session.client_session->server_callbacks = previous_server_callbacks;
	susshi_session.client_session->common.callbacks = previous_callbacks;

	if (int_store.state == SUSSHI_AGENT_COMPLETE) {
		susshi_session.pubkey_ssh_agent_mode = true;
		if (susshi_pubkey_agent_replay_to_target()) {
			rc = SSH_AUTH_SUCCESS;
		}
	}

	if (int_store.requested_auth_agent == false) {
		susshi_disconnect_standard(CLIENT, DISCONNECT_AUTH_AGENT_MISSING);
	}

	SSH_BUFFER_FREE(int_store.delayed_client_data);
	return rc;
}

/*! @} */
