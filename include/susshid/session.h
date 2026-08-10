/*!
 *
 * @brief       Session
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
 * @ingroup     session
 * @{
 */

#ifndef SUSSHI_SESSION_H
#define SUSSHI_SESSION_H

#include "inspect-channel.h"
#include "inspect-sftp.h"

#define SUSSHI_SERVER_VERSION_BANNER

#define SUSSHI_CONNECT_IDENTIFIER "susshi-connect"

/* Maximum number of listen sockets */
#define SUSSHI_MAX_LISTEN_SOCKS 32

/* Listen backlog for master process */
#define SUSSHI_LISTEN_BACKLOG   128

/* Maximum number of target_address_infos we will walk through */
#define SUSSHI_MAX_TARGET_IPS   32

/* Channel-IDs start-range in PubKeyAgent mode (proxied channels) */
#define SUSSHI_SESSION_CLIENT_CHANNEL_START      9100000
#define SUSSHI_SESSION_TARGET_CHANNEL_START      9200000

#define SUSSHI_SHELL_TARGET                      "shell"

#define SSH_IDENTIFICATION_OPENSSH               "SSH-2.0-OpenSSH"
#define SSH_IDENTIFICATION_PUTTY                 "SSH-2.0-PuTTY"
#define SSH_IDENTIFICATION_SECURECRT             "SSH-2.0-SecureCRT"
#define SSH_IDENTIFICATION_SECUREFX              "SSH-2.0-SecureFX"
#define SSH_IDENTIFICATION_FLOWSSH_REGEX         "^SSH-2.0-[0-9. ]+FlowSsh.*"
#define SSH_IDENTIFICATION_XSHELL                "SSH-2.0-nsssh2"
#define SSH_IDENTIFICATION_WINSCP                "SSH-2.0-WinSCP"
#define SSH_IDENTIFICATION_FILEZILLA             "SSH-2.0-FileZilla"

typedef enum {
    PHASE_NOT_CONNECTED = 0,
    PHASE_CONNECTED = 1,
    PHASE_PROTOCOL_IDENT = 2,
    PHASE_KEX = 3,
    PHASE_AUTH_START = 4,
    PHASE_AUTH_NONE = 5,
	PHASE_AUTH_PUBKEY_TEST_OK = 6,
    PHASE_AUTH_PUBKEY_GATEWAY_KEY = 7,
    PHASE_AUTH_PUBKEY_LOCAL = 8,
    PHASE_AUTH_PUBKEY_SSH_AGENT = 9,
    PHASE_AUTH_PASSWORD = 10,
    PHASE_AUTH_KEYBOARD_INTERACTIVE = 11,
    PHASE_AUTHENTICATED = 12,
    PHASE_SSH_AGENT_STARTED = 13,
    PHASE_SESSION_STARTED = 14
} PeerPhase;

typedef struct {
	bstring     ip;                             // IP as string
	int	        ai_family;	                    // PF_xxx
	bool        used;                           // Set to true if used
} AddressInfo;

typedef enum {
	HK_LEARNING_NEVER,
	HK_LEARNING_UPDATE,
	HK_LEARNING_IFUNKNOWN,
	HK_LEARNING_PROMPT
} HostKeyLearning;

typedef enum {
	OP_MODE_GATEWAY = 0,
	OP_MODE_BASTION,
	OP_MODE_SHELL,
	OP_MODE_CHEF_REMOTE
} OpMode;

typedef enum {
	PWS_DIALOG = 0,
	PWS_PRESERVE,
	PWS_STATIC,
	PWS_DOTP
} PwSourceMode;

typedef enum {
	PROC_ROLE_MASTER = 0,
	PROC_ROLE_REPORT,
	PROC_ROLE_MONITOR,
	PROC_ROLE_RSYSLOG,
	PROC_ROLE_SESSION
} ProcessRole;

typedef enum {
	CLIENT_IS_UNKNOWN = 0,
	CLIENT_IS_OPENSSH,
	CLIENT_IS_PUTTY,
	CLIENT_IS_SECURECRT,
	CLIENT_IS_SECUREFX,
	CLIENT_IS_FLOWSSH,
	CLIENT_IS_XSHELL,
	CLIENT_IS_WINSCP,
	CLIENT_IS_FILEZILLA
} ClientProduct;

#include "auth-target.h"

/* Data structure representing the suSSHi User-Session */
typedef struct {
    ssh_session client_session;                // libSSH client session
    ssh_session target_session;                // libSSH target session
    PeerPhase	client_phase;				   // Actual phase of client session
    PeerPhase	target_phase;				   // Actual phase of target session

    bstring		hostname;				       // Hostname susshid runs on

	bool        host_has_ipv4;                 // Host has an IPv4 listener
	bool        host_has_ipv6;                 // Host has an IPv6 listener

	nfds_t      num_listen_socks;              // Number of active listen sockets
	socket_t    listen_socks[SUSSHI_MAX_LISTEN_SOCKS]; // Listen sockets

    bstring		client_ip;						// Client IP address
    int			client_port;					// Client Port

	bstring		login_string;					// Complete login string in form <gwuser>@<remoteuser>@<remotehost>
    bstring		susshi_user;					// Gateway user
    bstring		susshi_userfp;					// Gateway user PublicKey FingerPrint
    bstring		susshi_outip;					// Outgoing IP address used for target connection
    int			susshi_outport;					// Outgoing port used for target connection
	OpMode      operation_mode;                 // Mode, daemon is running (Gateway, Bastion, Shell or ChefRemote)
	bool        susshi_shell_mode_allowed;      // User is allowed to login into suSSHi shell (In return of chef context)
	int         embryonic_slot_id;              // ID of embryonic slot used for this child

	struct addrinfo *target_addrs;              // Target IP Addresses resolved
	AddressInfo     target_ips[SUSSHI_MAX_TARGET_IPS];
	int             num_target_ips;

    bstring		target_host;					// Target Hostname
    bstring     target_host_orig;
	bstring     target_host_resolved;           // Target Hostname after DNS resolving
	bstring     target_ips_list;                // List of all target IP addresses as string
    bstring		target_ip;						// Target IP address
    int			target_port;					// Target Port
    bstring		target_identifier;				// Target Identifier "target_user@target_host[:target_port] \[target_ip:[target_port]\]"
    bstring		target_user;					// Target Username
    bstring		target_userpw;					// Target User Password
	HostKeyLearning target_hostkey_learning;    // How to handle new hostkeys
    bstring		client_ssh_identification;		// SSH Identification string of client
    bstring		target_ssh_identification;		// SSH Identification string of target
    bstring     proxy_version;
    uint32_t    proxy_version_uint32;
	bool        target_connected_by_fqdn;       // Set to true, if target_ip we are now connected to was not known by chef but access was accepted
	u_int64_t   target_id;                      // Target object ID in suSSHi Chef
	bstring     target_id_bstr;                 // Target object ID in suSSHi Chef in bstring representation

	// --- Target auth information from Chef ---
	PwSourceMode target_password_source;        // Where does the target password come from? dialog|preserve|static|dotp
	const char *target_chef_password;           // If we got a target password from chef
	const char *overwrite_target_user;          // Chef tells us to overwrite target user with this user
	bool target_password_continue;              // Should we continue after preserve, static or dotp password auth failed?

	/* susshi-proxyd connection */
	ssh_session target_proxy_session;           // libSSH susshi-proxyd session
	bstring     target_proxy_realm;             // Target Proxy Realm
	bstring     target_proxy_hostname;          // Target Proxy Hostname returned by Chef
	bstring     target_proxy_login_user;        // Target Proxy Login User
	int			target_proxy_port;				// Target Proxy Port returned by Chef
	bstring     target_proxy_ip;                // IP Address got from socket after connected
	bool        use_target_proxy;               // Set to true if Target Proxy is used
	PeerPhase	target_proxy_phase;             // Actual phase of proxy session
	int         key_used_for_proxy_auth;        // ID used for proxy authentication (reused in phase 2)
	int         target_proxy_error;             // If we received an error, this is != 0

    u_char     *target_session_id2;
    u_int		target_session_id2_len;

	ClientProduct client_product;

    // --- Session Flags
    bool        timeout_alarm_registered;
    u_char		no_more_sessions;				// Flag used in susshi-inspect-channels.c
    bool	volatile client_closed;				// Client connection closed
    bool	volatile target_closed;				// Target connection closed
    bool	volatile gateway_closed;			// Gateway will close connection (e.g. by session exceeded).
    bstring	volatile gateway_closed_reason;		// Reason text why gateway closed the connection.
    int	volatile received_signal;				// Received SIGTERM
	bool volatile received_sigint;              // Received SIGINT
	bool        session_is_interactive;         // Set to true if interactive
	bool        global_req_remote_port_listen_port_0;   // Set to true if latest global request was remote-forward request with port = 0
	bool        preserve_password;              // Preserve user's gateway password for target authentication if set to true
	bool        use_preserved_password;         // Use preserved user's gateway password for target authentication if set to true
	bool        use_extracted_password;         // Use password extracted from user's gateway password (after split-string) for target authentication if set to true
	bool        pubkey_ssh_agent_mode;          // Session is run in PubkeySSHAgent mode
	bool        too_many_auth_failures;         // Set to true if chef returns that there are too many authentication failures during interactive authentication
	bool        paa_target_replay_phase;        // True if we should not forward the packets to client (during replay of gateway to server in Public Key Agent Authentication mode)

    // --- Channel Inspection
    SusshiChannel  **channels;					// Screened Channels
	uint32_t    channels_alloc;					// Number of channels allocated
    long int    uniq_channel_id;                // ID (counter) for uniq channel-ids, used in filename generation
	bool        tcp_forward_ssh_allowed;        // User is allowed to tunnel SSH through TCP forwards
	u_int       num_remote_tcp_requests_pending;

    // --- Logging
    u_int		logging_mask;					// Logging Mask (see susshi-auth.h)
    bstring		susshi_uniqid;					// Uniq Identifier for this run
    bool volatile log_live_view;				// Live-View flag: when set, log files will get flushed right after write
    SusshiLog	log_system;						// System Loghandle
    SusshiLog	log_session;					// Session Loghandle
	ReportSessionState report_state;

    // --- Environment requesting
    bool		send_shell_env;					// Flag used to trigger sending of Shell env variable
    int		    send_shell_env_channel;			// Channel id we have to send the Shell env variable on

    // --- Session Context
    json_t      *session_context;

    // --- Authentication States
    u_int       client_auth_set_id;             // Authentication Set (id), received by chef context, send to interactive input validation controller
    bstring		client_authmethod;				// Method, the client has been authenticated with (used in target auth process and reporting)
	bstring		target_authmethod;				// Method, the target has been authenticated with (used in reporting)
	bool		client_authenticated;			// Flag, if set to 1, the client has been authenticated successful
    bool		target_authenticated;			// Flag, if set to 1, the target has accepted our authentication credentials
	bool        client_auth_finish_sent;        // Flag, set to true when client authentication already has been finished
	ssh_message client_message;                 // Not NULL, if last authentication method with client is keyboard interactive
	const char *auth_secret;                    // The OpenID Connect secret

	// --- Session timers ---
    u_int32_t	max_session_secs;				// Maximum Session Time in seconds as period (as returned from Chef)
    u_int32_t	max_session_idle_secs;			// Maximum Session Time in seconds as period (as returned from Chef)

	// --- Disconnect message ---
	const char *disconnect_message;

	// --- Process Role ---
	ProcessRole process_role;

	// --- Master process control ---
	bool    received_signal_for_restart;
	pid_t   master_pid;

	// --- Reporting ---
	pid_t report_pid;

	// --- Monitoring / Health-Probe ---
	pid_t monitor_pid;

	// --- rsyslogd ---
	pid_t rsyslog_pid;

	// --- Meta Information from chef ---
	json_int_t rule_id;
	json_int_t bastion_rule_id;
	const char *profile_name;

	// --- Bastion ---
	pid_t bastion_pid;

	// --- PCAP
	ssh_pcap_file client_pcap_file;
	ssh_pcap_file target_pcap_file;
	ssh_pcap_file proxy_pcap_file;

	// --- Un-privileged user UID
	uid_t unprivileged_user_uid;
	uid_t unprivileged_user_gid;

} SusshiSession;

extern SusshiSession susshi_session;


typedef enum {
    STRING_OK = 0,
    ILLEGAL_CHARS = 1,
    USERNAME_INVALID = 2,
    TARGET_RESOLVE_FAILED = 3,
    TARGET_PORT_INVALID = 4,
    TARGET_DENIED = 5,
    TARGET_RESOLVE_WRONG_AF = 6,
    TARGET_GATEWAY_BASTION = 7,
    UNKNOWN_ERROR = -1
} SplitLoginStringReturn;


typedef enum {
	DISCONNECT_INTERNAL_ERROR = 0,
	DISCONNECT_PROTOCOLL_ERROR,
	DISCONNECT_NOT_ALLOWED,
	DISCONNECT_DENIED_TARGET,
	DISCONNECT_ACL_SHELL_REQUEST_DENIED,
	DISCONNECT_ACL_EXEC_REQUEST_DENIED,
	DISCONNECT_ACL_SUBS_REQUEST_DENIED,
	DISCONNECT_AUTH_AGENT_MISSING,
	DISCONNECT_AUTH_AGENT_SIGNATURE_INVALID,
	DISCONNECT_AUTH_AGENT_SESSION_MISSING,
	DISCONNECT_AUTH_AGENT_NO_IDENTITIES,
	DISCONNECT_AUTH_FAILED,
	DISCONNECT_AUTH_ILLEGAL_USERNAME,
	DISCONNECT_AUTH_ILLEGAL_USERNAME_CHARS,
	DISCONNECT_AUTH_KBDINT_MISSING,
	DISCONNECT_AUTH_TOO_MANY_FAILURES,
	DISCONNECT_SERVICE_NOT_AVAILABLE,
	DISCONNECT_TARGET_CONNECT_FAILED,
	DISCONNECT_TARGET_HOSTKEY_FAILED,
	DISCONNECT_TARGET_PROXY_CONNECT_FAILED,
	DISCONNECT_TARGET_PROXY_LOGIN_FAILED,
	DISCONNECT_TARGET_PROXY_UNKNOWN,
	DISCONNECT_TARGET_PROXY_BASTION_VERSION,
	DISCONNECT_TARGET_PROXY_BASTION_FAILED,
	DISCONNECT_TARGET_RESOLVE_FAILED,
	DISCONNECT_TARGET_RESOLVE_FAILED_AF,
	DISCONNECT_TARGET_PORT_INVALID,
	DISCONNECT_TARGET_PROTOCOL_ERROR,
	DISCONNECT_TARGET_GATEWAY_BASTION,
	DISCONNECT_CONNECTION_LOST,
	DISCONNECT_DEFAULT      // Has to be last in list
} DisconnectError;


/* Prototypes */
void    init_susshi_session(bool first_startup);
void    store_client_socket_into_session(socket_t socket);
SplitLoginStringReturn store_splitted_loginstring_into_session(const char *user);
void	store_target_identifier_into_session(void);
void	susshi_session_interactive(void);
int	    susshi_socket_set_nonblock(socket_t fd);
void    susshi_socket_set_v6only(socket_t fd);
void    susshi_socket_set_nodelay(socket_t fd);

void	susshi_end_session(void);
void    susshi_disconnect_individual(Side side, int error_code, const char *fmt, ...);
void    susshi_disconnect_standard(Side side, DisconnectError error);
void    susshi_session_timeout_alarm_handler(void);
void    susshi_session_set_timeout_alarm(time_t tv_sec_timeout);
void    susshi_drop_privileges(const char *proc_name, bool permanent);
void    susshi_restore_privileges(void);


#endif //SUSSHI_SUSSHI_SESSION_H

/*! @} */
