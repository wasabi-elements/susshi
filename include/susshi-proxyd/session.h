/*!
 *
 * @brief       Session methods
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
 * @ingroup     proxy_session
 * @{
 *
 */

#ifndef SUSSHI_PROXYD_SESSION_H
#define SUSSHI_PROXYD_SESSION_H

/* Prototypes */
void	proxy_end_session(void);
void    susshi_proxy_disconnect(Side side, int error_code, const char *fmt,...) __attribute__((format(printf, 3, 4)));

/* Maximum number of listen sockets */
#define SUSSHI_MAX_LISTEN_SOCKS 32

/* Listen backlog for master process */
#define SUSSHI_LISTEN_BACKLOG   128

/* Maximum number of target_address_infos we will walk through */
#define SUSSHI_MAX_TARGET_IPS   32

typedef enum {
	PHASE_NOT_CONNECTED = 0,
	PHASE_CONNECTED = 1,
	PHASE_PROTOCOL_IDENT = 2,
	PHASE_KEX = 3,
	PHASE_AUTH_START = 4,
	PHASE_AUTH_NONE = 5,
	PHASE_AUTH_PUBKEY_GATEWAY_KEY = 6,
	PHASE_AUTHENTICATED = 11,
	PHASE_SESSION_STARTED = 13
} PeerPhase;

typedef struct {
	bstring     ip;                             // IP as string
	int	        ai_family;	                    // PF_xxx
	bool        used;                           // Set to true if used
} AddressInfo;

typedef enum {
	OP_MODE_PROXY,
	OP_MODE_PROXY_CHEF_REMOTE,
	OP_MODE_PROXY_BASTION
} OpMode;


/* Data structure representing the suSSHi User-Session */
typedef struct {
	ssh_session gateway_session;                // libSSH gateway session
	PeerPhase	gateway_phase;					// Actual phase of session from gateway
	PeerPhase	target_phase;					// Actual phase of session from gateway

	bstring		hostname;				        // Hostname susshi_proxyd runs on

	bool        host_has_ipv4;                 // Host has an IPv4 listener
	bool        host_has_ipv6;                 // Host has an IPv6 listener

	nfds_t      num_listen_socks;              // Number of active listen sockets
	socket_t    listen_socks[SUSSHI_MAX_LISTEN_SOCKS]; // Listen sockets

	bstring		gateway_ip;						// Client IP address
	int			gateway_port;					// Client Port
	socket_t    gateway_socket;
	OpMode      operation_mode;                 // Mode, daemon is running (Proxy, Bastion or ChefRemote)

	bstring		login_string;					// Complete login string in form session_identifier@<target>
	int         embryonic_slot_id;              // ID of embryonic slot used for this child

	struct addrinfo *target_addrs;              // Target IP Addresses resolved
	AddressInfo     target_ips[SUSSHI_MAX_TARGET_IPS];
	int             num_target_ips;

	bstring		target_host;					// Target Hostname
	bstring     target_host_fqdn;               // Target Hostname after DNS resolving
	bstring     target_ips_list;                // List of all target IP addresses as string
	bstring		target_ip;						// Target IP address
	int			target_port;					// Target Port
	bool        target_connected_by_fqdn;       // Set to true, if target_ip we are now connected to was not known by chef but access was accepted
	bstring     target_identifier;
	socket_t    target_socket;

	// --- Authentication States
	bool		gateway_authenticated;			// Flag, if set to 1, the gateway has been authenticated successful
	bool        gateway_auth_finish_sent;       // Flag, set to true when gateway authentication already has been finished
	ssh_message gateway_message;                // Not NULL, if last authentication method with gateway is keyboard interactive
	bstring     proxy_auth_fp;

	bstring		susshi_uniqid;					// Uniq Identifier for this run

	// --- Session Flags
	int	volatile gateway_closed;					// Gateway connection closed
	int	volatile target_closed;					// Target connection closed
	int	volatile proxy_closed;					// Proxy will close connection (e.g. by session exceeded).
	bstring	volatile proxy_closed_reason;			// Reason text why gateway closed the connection.
	int	volatile received_sigterm;				// Received SIGTERM
	bool volatile received_sigint;              // Received SIGINT

	// --- Session timers ---
	u_int32_t	max_session_idle_secs;			// Maximum Session Time in seconds as period (as send at login)

	// --- Disconnect message ---
	const char *disconnect_message;

	// --- Master process control ---
	bool    received_signal_for_restart;
	pid_t   master_pid;

	// --- Monitoring / Health-Probe ---
	pid_t   monitor_pid;

	// --- Bastion ---
	pid_t bastion_pid;

	// --- Un-privileged user UID
	uid_t unprivileged_user_uid;
	uid_t unprivileged_user_gid;

} SusshiSession;

extern SusshiSession proxy_session;


typedef enum {
	STRING_OK = 0,
	ILLEGAL_CHARS = 1,
	USERNAME_INVALID = 2,
	TARGET_RESOLVE_FAILED = 3,
	TARGET_PORT_INVALID = 4,
	UNKNOWN_ERROR = -1
} SplitLoginStringReturn;


/* Prototypes */
void    init_proxy_session(void);
void    store_client_socket_into_session(socket_t socket);
SplitLoginStringReturn store_splitted_loginstring_into_proxy_session(const char *user);
void	store_target_identifier_into_session(void);
void	proxy_session_interactive(void);
bool    proxy_set_blocking_mode(int socket, bool is_blocking);
void    proxy_socket_set_v6only(socket_t fd);
void    proxy_socket_set_nodelay(socket_t fd);
void proxy_drop_privileges(const char *proc_name, bool permanent);
void    proxy_restore_privileges(void);

#endif //SUSSHI_SUSSHI_PROXYD_SESSION_H

/*! @} */
