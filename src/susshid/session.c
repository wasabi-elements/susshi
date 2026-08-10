/*!
 *
 * @brief       Session
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
 * @defgroup    session Session
 * @brief       Functions handling the global susshi session context
 * @{
 */

#include <susshid/common.h>
#include <susshid/report.h>


/* SuSSHi Session options */
SusshiSession susshi_session;

/* Prototypes */
static SplitLoginStringReturn store_target_address_into_session(void);
static void susshi_disconnect_session(ssh_session session, int error_code, const char *message);


#define default_message_NOT_ALLOWED "Access denied"
#define default_message_AUTH_FAILED "Authentication failed"
#define default_message_INTERNAL_ERROR "Internal Server Error"
#define default_message_PROTOCOL_ERROR  "Protocol error"
#define default_message_SERVICE_NOT_AVAILABLE  "Service not available"

static struct {
	DisconnectError code;
	int ssh2_code;
	int susshi_error_code_major;
	int susshi_error_code_minor;
	const char *message_verbose;
	const char *message_strict;
} disconnect_messages[] = {
		{DISCONNECT_INTERNAL_ERROR,               SSH2_DISCONNECT_PROTOCOL_ERROR,                 500, 1,
				"Gateway is suffering from internal error. Please come back later",
				default_message_INTERNAL_ERROR
		},
		{DISCONNECT_PROTOCOLL_ERROR,              SSH2_DISCONNECT_PROTOCOL_ERROR,                 500, 2,
				"SSH protocol error",
				default_message_PROTOCOL_ERROR
		},
		{DISCONNECT_SERVICE_NOT_AVAILABLE,        SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE,          500, 3,
				default_message_SERVICE_NOT_AVAILABLE,
				default_message_SERVICE_NOT_AVAILABLE
		},
		{DISCONNECT_TARGET_GATEWAY_BASTION,       SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE,          500, 4,
				"Bastion mode is available with suSSHi proxy only",
				default_message_SERVICE_NOT_AVAILABLE
		},
		{DISCONNECT_NOT_ALLOWED,                  SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT,    403, 1,
				"User is not allowed to connect to target",
				default_message_NOT_ALLOWED
		},
		{DISCONNECT_ACL_SHELL_REQUEST_DENIED,     SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT,    403, 2,
				"Interactive shell request not allowed",
				default_message_NOT_ALLOWED
		},
		{DISCONNECT_ACL_EXEC_REQUEST_DENIED,      SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT,    403, 3,
				"Exec request not allowed",
				default_message_NOT_ALLOWED
		},
		{DISCONNECT_DENIED_TARGET,                SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT,    403, 4,
				"User is not allowed to connect to target",
				default_message_NOT_ALLOWED
		},
		{DISCONNECT_ACL_SUBS_REQUEST_DENIED,      SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT,    403, 5,
				"Subsystem request is not allowed",
				default_message_NOT_ALLOWED
		},
		{DISCONNECT_AUTH_AGENT_MISSING,           SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, 405, 2,
				"Authentication agent missing or unreachable. Please allow connection to the authentication agent (-A flag)",
				"Authentication failed. Authentication agent missing or unreachable"
		},
		{DISCONNECT_AUTH_FAILED,                  SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, 401, 1,
				"Authentication failed. No more auth methods available",
				default_message_AUTH_FAILED
		},
		{DISCONNECT_AUTH_AGENT_SIGNATURE_INVALID, SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, 401, 2,
				"Signature received from agent is not valid",
				default_message_AUTH_FAILED
		},
		{DISCONNECT_AUTH_AGENT_NO_IDENTITIES,     SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, 401, 3,
				"Client responds with no identities from SSH agent",
				"Client responds with no identities from SSH agent",
		},
		{DISCONNECT_AUTH_TOO_MANY_FAILURES,       SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, 401, 4,
				"Too many authentication failures. Please come back later.",
				"Too many authentication failures. Please come back later."
		},
		{DISCONNECT_AUTH_AGENT_SESSION_MISSING,   SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE,          405, 3,
				"For this connection, the policy requires the use of an SSH authentication agent, but the client has not requested "
				"an interactive or command execution session, so the authentication agent mode does not work (maybe the -N flag was used?)",
				"No session requested. Authentication agent mode is not working without interactive session or remote command."
		},
		{DISCONNECT_AUTH_ILLEGAL_USERNAME,        SSH2_DISCONNECT_ILLEGAL_USER_NAME,              400, 1,
				"Invalid username. Please try again with <gwuser>@<targetuser>@<target>[@<proxy>]",
				"Authentication failed - invalid username"
		},
		{DISCONNECT_AUTH_ILLEGAL_USERNAME_CHARS,  SSH2_DISCONNECT_ILLEGAL_USER_NAME,              400, 2,
				"Authentication failed - invalid characters in username",
				"Authentication failed - invalid username"
		},
		{DISCONNECT_AUTH_KBDINT_MISSING,          SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED,     405, 1,
				"Target requires keyboard-interactive authentication to be allowed on client. "
				"Please activate keyboard-interactive authentication and reconnect",
				"Target requires keyboard-interactive authentication to be allowed on client. "
				"Please activate keyboard-interactive authentication and reconnect"
		},
		{DISCONNECT_TARGET_CONNECT_FAILED,        SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE,          408, 1,
				"Failed to connect to target",
				"Failed to connect to target"
		},
		{DISCONNECT_TARGET_HOSTKEY_FAILED,        SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE,        409, 1,
				"Target host key could not be verified",
				"Target host key could not be verified"
		},
		{DISCONNECT_TARGET_PORT_INVALID,          SSH2_DISCONNECT_ILLEGAL_USER_NAME,              400, 3,
				"Invalid port given. Please try again",
				"Invalid port given. Please try again"
		},
		{DISCONNECT_CONNECTION_LOST,              SSH2_DISCONNECT_CONNECTION_LOST,                502, 1,
				"Connection lost",
				"Connection lost"
		},
		{DISCONNECT_TARGET_PROXY_UNKNOWN,         SSH2_DISCONNECT_ILLEGAL_USER_NAME,              502, 2,
				"Failed to connect to target proxy gateway. Please check availability of the proxy gateway for specified realm",
				"Failed to connect to target proxy gateway. Please check availability of the proxy gateway for specified realm"
		},
		{DISCONNECT_TARGET_PROXY_BASTION_VERSION, SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE,          502, 3,
				"The suSSHi proxy server runs on an older version, that does not support the suSSHi Bastion feature. "
				"Please contact the administrator of the suSSHi proxy server to update it to a newer version.",
				"The suSSHi proxy server runs on an older version, that does not support the suSSHi Bastion feature. "
				"Please contact the administrator of the suSSHi proxy server to update it to a newer version."
		},
		{DISCONNECT_TARGET_PROXY_BASTION_FAILED,  SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE,          502, 4,
				"The suSSHi proxy failed to start Bastion feature. "
				"Please contact the administrator of the suSSHi proxy server to check health.",
				"The suSSHi proxy failed to start Bastion feature. "
				"Please contact the administrator of the suSSHi proxy server to check health."
		},
		{DISCONNECT_TARGET_PROTOCOL_ERROR,        SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED,     503, 1,
				"Could not talk to target as expected",
				default_message_PROTOCOL_ERROR
		},
		{DISCONNECT_TARGET_RESOLVE_FAILED,        SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE,          503, 2,
				"Failed to resolve target hostname",
				"Failed to resolve target hostname"
		},
		{DISCONNECT_TARGET_RESOLVE_FAILED_AF,     SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE,          503, 3,
				"Failed to resolve target hostname - resolved address family not configured on gateway",
				"Failed to resolve target hostname - resolved address family not configured on gateway"
		},
		{DISCONNECT_TARGET_PROXY_CONNECT_FAILED,  SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE,          504, 1,
				"Failed to connect to target proxy gateway.",
				"Failed to connect to target proxy gateway. Please check availability of the proxy gateway for specified realm"
		},
		{DISCONNECT_TARGET_PROXY_LOGIN_FAILED,    SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE,          504, 2,
				"Failed to login into target proxy gateway.",
				"Failed to connect to target proxy gateway. Please check availability of the proxy gateway for specified realm"
		},
		{DISCONNECT_DEFAULT,                      SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE,          900, 1,
				"Something went wrong",
				"Something went wrong"
		}
};


/*!
 * @brief       Init susshi_session
 *
 * @param       first_startup   set to true on first startup
 */

void
init_susshi_session(bool first_startup)
{
	/* Preserve PIDs */
	pid_t master_pid = susshi_session.master_pid;
	pid_t report_pid = susshi_session.report_pid;
	pid_t monitor_pid = susshi_session.monitor_pid;
	pid_t rsyslog_pid = susshi_session.rsyslog_pid;

	memset(&susshi_session, 0, sizeof(SusshiSession));

	susshi_session.client_phase = PHASE_NOT_CONNECTED;
	susshi_session.target_phase = PHASE_NOT_CONNECTED;
	susshi_session.target_port = 22;
	susshi_session.target_hostkey_learning = HK_LEARNING_NEVER;
	susshi_session.send_shell_env_channel = -1;
	susshi_session.embryonic_slot_id = -1;

	/* May get overwritten by session Chef context module (REST), but for now we set it to (uint_32 -> ~ 136 years) */
	susshi_session.max_session_secs = (uint32_t) -1L;
	susshi_session.max_session_idle_secs = (uint32_t) -1;

	/* Store actual UID / GID into susshi_session */
	get_unprivileged_user_uid_gid(&susshi_session.unprivileged_user_uid, &susshi_session.unprivileged_user_gid);

	/* Fill in preserved PIDs if not on first startup */
	if (!first_startup) {
		susshi_session.master_pid = master_pid;
		susshi_session.report_pid = report_pid;
		susshi_session.monitor_pid = monitor_pid;
		susshi_session.rsyslog_pid = rsyslog_pid;
	} else {
		susshi_session.report_pid = -1;
		susshi_session.monitor_pid = -1;
		susshi_session.rsyslog_pid = -1;
	}
}


/*!
 * @brief       Get remote IP and port from given socket and fill client_ip and client_port in susshi_session
 *
 * @param       socket      The TCP socket
 */

void
store_client_socket_into_session(socket_t socket) {
	socklen_t socket_len;
	struct sockaddr_storage addr;
	char ipstr[INET6_ADDRSTRLEN];
	int port;

	socket_len = sizeof addr;
	getpeername(socket, (struct sockaddr*)&addr, &socket_len);

	if (addr.ss_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)&addr;
		port = ntohs(s->sin_port);
		inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
	} else { // AF_INET6
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
		port = ntohs(s->sin6_port);
		inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
	}

	susshi_session.client_ip = bfromcstr(ipstr);
	susshi_session.client_port = port;
}


/*!
 * @brief       Split loginstring (from authentication user) and store information in susshi_session
 *
 * Different login string formats are supported:
 * ```
 * 4 Terms:  gwuser@tuser@target@proxy
 * 3 Terms:  gwuser@tuser@target
 * 2 Terms:  gwuser@target
 *           -> tuser = gwuser
 *           gwuser@<SUSSHI_GATEWAY_TARGET>
 *           -> Shell Mode (not supported yet)
 *           gwuser@<proxy>
 *           -> Bastion Mode on proxy
 * 1 Term:   gwuser
 *           -> Bastion mode
 * ```
 *
 * @param       user        The username from the actual session
 *
 * @return      Enum of @p SplitLoginStringReturn
 */

SplitLoginStringReturn
store_splitted_loginstring_into_session(const char *user)
{
	bstrList splitlogin, splithost, splitport;
	char splitchar;
	bstring splitchars = bfromcstr("@,+/?%");
	int splitchar_pos;

	if (susshi_session.login_string != NULL) {
		// Function has already run before
		return STRING_OK;
	}

	susshi_session.login_string = bfromcstr(user);

	if (!validate_string_chars_regex(susshi_session.login_string, "^[a-zA-Z0-9\\[\\]:\\\\_#@,+/?%.-]+$"))
		return ILLEGAL_CHARS;

	// Split Character
	splitchar_pos = binchr(susshi_session.login_string, 0, splitchars);

	if (splitchar_pos == BSTR_ERR) {
		splitchar = '@';
		debug1("Login string is using default split character '%c'.", splitchar);
	} else {
		splitchar = bdata(susshi_session.login_string)[splitchar_pos];
		debug1("Login string is using split character '%c'.", splitchar);
	}

	// Split Login
	splitlogin = bsplit(susshi_session.login_string, splitchar);

	switch (splitlogin->qty) {
		case 4:
			susshi_session.susshi_user = bstrcpy(splitlogin->entry[0]);
			susshi_session.target_user = bstrcpy(splitlogin->entry[1]);
			susshi_session.target_host = bstrcpy(splitlogin->entry[2]);
			susshi_session.target_host_orig = bstrcpy(susshi_session.target_host);
			susshi_session.target_proxy_realm = bstrcpy(splitlogin->entry[3]);
			susshi_session.operation_mode = OP_MODE_GATEWAY;
			break;
		case 3:
			susshi_session.susshi_user = bstrcpy(splitlogin->entry[0]);
			susshi_session.target_user = bstrcpy(splitlogin->entry[1]);
			susshi_session.target_host = bstrcpy(splitlogin->entry[2]);
			susshi_session.operation_mode = OP_MODE_GATEWAY;
			break;
		case 2:
			susshi_session.susshi_user = bstrcpy(splitlogin->entry[0]);
			susshi_session.target_user = bstrcpy(splitlogin->entry[0]);

			if (!validate_string_chars_regex(susshi_session.susshi_user, "^[a-zA-Z0-9@\\.\\/\\\\_-]+$"))
				return USERNAME_INVALID;

			/* Check if second term is SUSSHI_SHELL_TARGET --> Login ON suSSHi gateway */
			if (biseqcstr(splitlogin->entry[1], SUSSHI_SHELL_TARGET)) {
				susshi_session.operation_mode = OP_MODE_SHELL;
				log_system(LOG_LEVEL_INFO, "Login string split into gwuser=%s. Mode: SHELL.",
						   bdata(susshi_session.susshi_user));
				return STRING_OK;
			}

			/* Check if second term is a proxy --> Bastion Mode */
			susshi_session.target_proxy_realm = bstrcpy(splitlogin->entry[1]);

			if (susshi_chef_lookup_proxy()) {
				susshi_session.operation_mode = OP_MODE_BASTION;

				susshi_session.use_target_proxy = true;
				susshi_session.target_host = bfromcstr("bastion");
				susshi_session.target_host_resolved = bfromcstr("Bastion");
				susshi_session.target_connected_by_fqdn = true;
				susshi_session.target_ips[susshi_session.num_target_ips++].ip = bfromcstr(BASTION_LISTEN_IP);
				susshi_session.target_ips_list = bfromcstr(BASTION_LISTEN_IP);
				susshi_session.target_port = BASTION_LISTEN_PORT;
				susshi_session.target_user = bfromcstr(BASTION_USER);

				log_system(LOG_LEVEL_INFO, "Login string split into gwuser=%s, proxy-realm=%s. Mode: BASTION.",
						   bdata(susshi_session.susshi_user), bdata(susshi_session.target_proxy_realm));
				return STRING_OK;
			} else {
				/* Not a proxy realm --> GATEWAY mode */
				susshi_session.operation_mode = OP_MODE_GATEWAY;

				bstrFree(susshi_session.target_proxy_realm);
				susshi_session.target_proxy_realm = NULL;
				susshi_session.target_host = bstrcpy(splitlogin->entry[1]);
			}
			break;
		case 1:
			if (susshi_session.susshi_user != NULL && susshi_session.target_host != NULL) {
				/* We already got the input from the clear text identification exchange */
				susshi_session.target_user = bstrcpy(splitlogin->entry[0]);
			} else if (susshi_session.susshi_user == NULL) {
				/* Login to Bastion or Remote Command */
				susshi_session.susshi_user = bstrcpy(splitlogin->entry[0]);
				bstrListDestroy(splitlogin);
				if (biseqcstr(susshi_session.susshi_user, SUSSHI_CHEF_REMOTE_USER)) {
					susshi_session.operation_mode = OP_MODE_CHEF_REMOTE;
					return STRING_OK;
				} else {
					susshi_session.operation_mode = OP_MODE_BASTION;

					/* We do not support Bastion mode on gateway right now */
					return TARGET_GATEWAY_BASTION;

					/*
					 * If we will support Bastion mode on gateway in future, this code will help:
					 *

					log_system(LOG_LEVEL_INFO, "Login string split into gwuser=%s. Mode: BASTION.",
							   bdata(susshi_session.susshi_user));

					if (!validate_string_chars_regex(susshi_session.susshi_user, "^[a-zA-Z0-9@\\.\\/\\\\_-]+$"))
						return USERNAME_INVALID;

					susshi_session.target_host = bfromcstr("bastion");
					susshi_session.target_host_resolved = bfromcstr("Bastion");
					susshi_session.target_connected_by_fqdn = true;
					susshi_session.target_ips[susshi_session.num_target_ips++].ip = bfromcstr(BASTION_LISTEN_IP);
					susshi_session.target_ips_list = bfromcstr(BASTION_LISTEN_IP);
					susshi_session.target_port = BASTION_LISTEN_PORT;
					susshi_session.target_user = bfromcstr(BASTION_USER);

					return STRING_OK;
					*/
				}
			} else {
				// Wrong usage
				bstrListDestroy(splitlogin);
				return USERNAME_INVALID;
			}
			break;
		default:
			bstrListDestroy(splitlogin);
			return USERNAME_INVALID;	// Error: To few or to many arguments given
	}

	bstrListDestroy(splitlogin);

	if (!validate_string_chars_regex(susshi_session.susshi_user, "^[a-zA-Z0-9./\\\\_-]+$"))
		return ILLEGAL_CHARS;

	if (!validate_string_chars_regex(susshi_session.target_user, "^[a-zA-Z0-9@.:/\\\\_-]+$"))
		return ILLEGAL_CHARS;

	if (!validate_string_chars_regex(susshi_session.target_host, "^[a-zA-Z0-9.\\[\\]:-]+$"))
		return ILLEGAL_CHARS;

	if ((susshi_session.target_proxy_realm != NULL) && (!validate_string_chars_regex(susshi_session.target_proxy_realm, "^[a-zA-Z0-9-_]+$")))
		return ILLEGAL_CHARS;

	/*
	 * a. Extract port if given in form:
	 *	1. <host>:<port>
	 *	2. [<ipv6_ip>]:<port>
	 *
	 * b. Replace target_host in form [<ipv6_ip>] or [<ipv6_ip>]:<port> with <ipv6_ip>
	 */

	// IPv6 form
	splithost = bsplits(susshi_session.target_host, bfromcstr("[]"));

	if (splithost->qty > 1) {
		// Hostname is in form [<ipv6_ip>] or [<ipv6_ip>]:<port>
		if (splithost->qty > 2)
		{
			// IPv6 port is given in form [<ipv6_ip>]:<port>
			splitport = bsplit(splithost->entry[2], ':');
			if (splitport->qty > 1) {
				susshi_session.target_port = a2port(bdata(splitport->entry[1]));
				debug4("port is %d.", susshi_session.target_port);
			}
			bstrListDestroy(splitport);
		}
		// Replace target_host in form [<ipv6_ip>] or [<ipv6_ip>]:<port> with <ipv6_ip>
		susshi_session.target_host = bstrcpy(splithost->entry[1]);
		bstrListDestroy(splithost);
	}

	// IPv4 form
	splitport = bsplit(susshi_session.target_host, ':');

	if (splitport->qty == 2) {
		susshi_session.target_host = bstrcpy(splitport->entry[0]);
		susshi_session.target_port = a2port(bdata(splitport->entry[1]));
	}

	if (susshi_session.target_port < 1 || susshi_session.target_port > 65535) {
		log_system(LOG_LEVEL_INFO, "Invalid port (%d) given. Disconnecting client.", susshi_session.target_port);
		return(TARGET_PORT_INVALID);
	}

	// Gateway User and Target Host are case-insensitiv, Target User is case-sensitive
	btolower(susshi_session.susshi_user);
	btolower(susshi_session.target_host);

	log_system(LOG_LEVEL_INFO, "Login string split into gwuser=%s, targetuser=%s, targethost=%s, targetport=%d, proxy-realm=%s, Mode: GATEWAY.",
			   bdata(susshi_session.susshi_user), bdata(susshi_session.target_user), bdata(susshi_session.target_host),
			   susshi_session.target_port, bdata(susshi_session.target_proxy_realm));

	if (susshi_session.target_proxy_realm) {
		/* If we have a proxy realm, we have to look it up if it is valid */

		if (susshi_chef_lookup_proxy() == false) {
			susshi_disconnect_standard(CLIENT, DISCONNECT_TARGET_PROXY_UNKNOWN);
		}
		susshi_session.use_target_proxy = true;

		/* We do not resolve any target addresses at susshid, this is done by the proxy himself */
		susshi_session.target_host_resolved = bstrcpy(susshi_session.target_host);

		return STRING_OK;
	} else {
		/* Store target information (resolved address, target_identifier ...) in susshi_session as well */
		return store_target_address_into_session();
	}
}


/*!
 * @brief       Resolve target addresses
 *
 * Resolve target addresses (from hostname filled in by store_splitted_loginstring_into_session())
 * and store them together with other target information in susshi_session
 *
 * @return      Enum of @p SplitLoginStringReturn
 */

static SplitLoginStringReturn
store_target_address_into_session(void)
{
	SplitLoginStringReturn rc = UNKNOWN_ERROR;
	struct addrinfo hints_name, hints_ip, *ai;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV];
	int gai_error, i;
	bstring fqdn = NULL;

	susshi_session.target_addrs = NULL;

	memset(&hints_ip, 0, sizeof(hints_ip));
	hints_ip.ai_family = AF_UNSPEC;
	hints_ip.ai_socktype = SOCK_STREAM;
	hints_ip.ai_protocol = IPPROTO_TCP;
	hints_ip.ai_flags = AI_ADDRCONFIG | AI_NUMERICHOST;
	
	memset(&hints_name, 0, sizeof(hints_name));
	hints_name.ai_family = AF_UNSPEC;
	hints_name.ai_socktype = SOCK_STREAM;
	hints_name.ai_protocol = IPPROTO_TCP;
	hints_name.ai_flags = AI_ADDRCONFIG | AI_V4MAPPED | AI_ALL;

	snprintf(strport, sizeof strport, "%u", susshi_session.target_port);

	debug1("Trying to resolve given target host into an IP address.");

	if ((gai_error = getaddrinfo(bdata(susshi_session.target_host), strport, &hints_ip, &susshi_session.target_addrs)) == 0) {
		debug3("Given hostname is an IP address.");
		susshi_session.target_host_resolved = bstrcpy(susshi_session.target_host);
	} else {

		debug3("getaddrinfo() for IP lookup returned with error '%s'", gai_strerror(gai_error));

		if (!validate_string_chars_regex(susshi_session.target_host, "^[a-zA-Z0-9\\._-]+$"))
			return TARGET_RESOLVE_FAILED;

		if (susshi_cfg.num_dns_searchdomains > 0) {

			bstring hostname = NULL;
			bstrList terms = NULL;

			/* Trim dots from right */
			for (int c = blength(susshi_session.target_host) - 1; c > 0; c--) {
				if (bdata(susshi_session.target_host)[c] != '.')
					break;
				bdata(susshi_session.target_host)[c] = ' ';
			}
			btrimws(susshi_session.target_host);

			/* Split target_host on '.' to extract hostname and domain parts */
			terms = bsplit(susshi_session.target_host, '.');

			if (terms->qty > 1) {
				/* target_host contains a domain */
				debug3("Trying %s", bdata(susshi_session.target_host));
				if ((gai_error = getaddrinfo(bdata(susshi_session.target_host), strport, &hints_name, &susshi_session.target_addrs)) == 0) {
					susshi_session.target_host_resolved = bstrcpy(susshi_session.target_host);
				} else {
					debug3("getaddrinfo() for hostname lookup returned with error '%s'", gai_strerror(gai_error));
				}
			} else {
				hostname = bstrcpy(susshi_session.target_host);
				debug3("Iterate through DNS search list with %d elements.", susshi_cfg.num_dns_searchdomains);

				for (i = 0; i < susshi_cfg.num_dns_searchdomains; i++) {
					btrimws(susshi_cfg.dns_searchdomains[i]);

					if (fqdn != NULL) bstrFree(fqdn);
					fqdn = bformat("%s.%s", bdata(hostname), bdata(susshi_cfg.dns_searchdomains[i]));

					debug3("Trying %s", bdata(fqdn));
					if ((gai_error = getaddrinfo(bdata(fqdn), strport, &hints_name, &susshi_session.target_addrs)) == 0) {
						susshi_session.target_host_resolved = bstrcpy(fqdn);
						break;
					}
					debug3("getaddrinfo() for hostname lookup returned with error '%s'", gai_strerror(gai_error));

					if ((susshi_session.target_addrs == NULL) || (susshi_session.target_addrs->ai_family != AF_INET &&
																  susshi_session.target_addrs->ai_family != AF_INET6))
						continue;
				}

				bstrListDestroy(terms);
				if (hostname)
					bstrFree(hostname);
			}

		} else {
			/* Without a domains search list, try with standard system DNS config */
			hints_name.ai_flags |= AI_CANONNAME;
			if ((getaddrinfo(bdata(susshi_session.target_host), strport, &hints_name, &susshi_session.target_addrs)) == 0) {
				debug3("Found hostname with standard system DNS config.");
				susshi_session.target_host_resolved = bstrcpy(susshi_session.target_host);
			}
		}
	}


	if (susshi_session.target_addrs != NULL) {

		/* Loop through addrinfo list and store all IP addresses */
		for (ai = susshi_session.target_addrs; (ai) && (susshi_session.num_target_ips < SUSSHI_MAX_TARGET_IPS); ai = ai->ai_next) {
			bool denied_target_ip=false;

			if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
				continue;

			/* Skip IPv4 addresses if host has no IPv4 interface */
			if (ai->ai_family == AF_INET && !susshi_session.host_has_ipv4) {
				debug2("DNS IPv4 response skipped since gateway has no IPv4 address.");
				rc = TARGET_RESOLVE_WRONG_AF;
				continue;
			}

			/* Skip IPv6 addresses if host has no IPv6 interface */
			if (ai->ai_family == AF_INET6 && !susshi_session.host_has_ipv6) {
				debug2("DNS IPv6 response skipped since gateway has no IPv6 address.");
				rc = TARGET_RESOLVE_WRONG_AF;
				continue;
			}

			if (getnameinfo(ai->ai_addr, ai->ai_addrlen,
							ntop, sizeof(ntop), strport, sizeof(strport),
							NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
				error("ssh_connect: getnameinfo failed");
				continue;
			}

			susshi_session.target_ips[susshi_session.num_target_ips].ip = bfromcstr(ntop);

			for(int ip=0; ip < susshi_cfg.num_deny_targets; ip++) {
				if (susshi_match_cidr(susshi_session.target_ips[susshi_session.num_target_ips].ip, susshi_cfg.deny_targets[ip]))
					denied_target_ip = true;
			}

			if (denied_target_ip) {
				log_system(LOG_LEVEL_WARNING, "Target IP %s is in list of denied targets.",
						bdata(susshi_session.target_ips[susshi_session.num_target_ips].ip));
				rc = TARGET_DENIED;
				continue;
			}

			susshi_session.target_ips[susshi_session.num_target_ips].ai_family = ai->ai_family;
			if ((susshi_session.target_host_resolved == NULL) && (ai->ai_canonname != NULL)) {
				susshi_session.target_host_resolved = bfromcstr(ai->ai_canonname);
			}

			debug2("Resolved %s (%s) to %s.", bdata(susshi_session.target_host),
				   bdata(susshi_session.target_host_resolved),
				   bdata(susshi_session.target_ips[susshi_session.num_target_ips].ip));

			if (susshi_session.num_target_ips == 0) {
				susshi_session.target_ips_list = bfromcstr("");
			} else {
				bcatcstr(susshi_session.target_ips_list, ", ");
			}

			bconcat(susshi_session.target_ips_list, susshi_session.target_ips[susshi_session.num_target_ips].ip);

			rc = STRING_OK;
			susshi_session.num_target_ips++;
		}
	} else {
		rc = TARGET_RESOLVE_FAILED;
	}

	if (susshi_session.num_target_ips == SUSSHI_MAX_TARGET_IPS) {
		error("Warning! More than %d IPs for target '%s' found. Only using the first %d ones.",
			  SUSSHI_MAX_TARGET_IPS, bdata(susshi_session.target_host), SUSSHI_MAX_TARGET_IPS);
	}

	if (susshi_session.target_addrs != NULL)
		freeaddrinfo(susshi_session.target_addrs);

	if (rc == TARGET_RESOLVE_FAILED) {
		log_system(LOG_LEVEL_INFO, "Target host '%s' could not be resolved.", bdata(susshi_session.target_host));
	} else {
		if (susshi_session.target_ips_list) {
			log_system(LOG_LEVEL_INFO, "Target host '%s' resolved to: %s", bdata(susshi_session.target_host), bdata(susshi_session.target_ips_list));
		}
	}

	if (fqdn != NULL)
		bstrFree(fqdn);

	return rc;
}


/*!
 * @brief       Create target_identifier and store it to susshi_session
 */

void
store_target_identifier_into_session(void) {
	bstring portbuf = NULL;
	bstring proxybuf = NULL;

	if (susshi_session.target_port != 22)
		portbuf = bformat(":%d", susshi_session.target_port);
	else
		portbuf = bfromcstr("");

	if (susshi_session.target_proxy_realm)
		proxybuf = bformat("@%s", bdata(susshi_session.target_proxy_realm));
	else
		proxybuf = bfromcstr("");

	if (susshi_session.target_identifier)
		bstrFree(susshi_session.target_identifier);

	susshi_session.target_identifier = bformat("%s@%s%s%s (%s%s)",
											   bdata(susshi_session.target_user),
											   bdata(susshi_session.target_host), bdata(portbuf),
											   bdata(proxybuf),
											   bdata(susshi_session.target_ip), bdata(portbuf));
	bstrFree(portbuf);
	bstrFree(proxybuf);
}


/*!
 * @brief       Set Session to interactive / disable Nagle
 */

void
susshi_session_interactive(void) {
	socket_t fd;

	if (susshi_session.session_is_interactive)
		return;

	susshi_session.session_is_interactive = true;

	if ((susshi_session.client_session) && ((fd = ssh_get_fd(susshi_session.client_session)) != -1)) {
		debug3("Set client session to interactive / disable Nagle's algorithm.");
		susshi_socket_set_nodelay(fd);
	}

	if ((susshi_session.target_session) && ((fd = ssh_get_fd(susshi_session.target_session)) != -1)) {
		debug3("Set target session to interactive / disable Nagle's algorithm.");
		susshi_socket_set_nodelay(fd);
	}
}


/*!
 * @brief       End a (suSSHi) session
 *
 * This terminates open client and target ssh sessions as well.
 */

void
susshi_end_session(void)
{
	bstring target = NULL;

	if (susshi_session.target_identifier != NULL) {
		target = bstrcpy(susshi_session.target_identifier);
	} else {
		target = bformat("%s@%s (unresolved)", bdata(susshi_session.target_user), bdata(susshi_session.target_host));
	}

	if (susshi_session.client_closed || susshi_session.target_closed || susshi_session.gateway_closed) {

		if (susshi_session.client_closed || susshi_session.target_closed ) {
			log_session((susshi_session.client_closed == 1) ? CLIENT : TARGET,
						(susshi_session.client_closed == 1) ? TARGET : CLIENT,
						"Session terminated by %s after %ld seconds. Running cleanup.",
						(susshi_session.client_closed == 1) ? "client" : "target",
						time(NULL) - susshi_report.session_start_time);

			log_system(LOG_LEVEL_INFO, "End session %s for '%s@%s -> %s' on Host %s (susshid-ID %s)",
					   bdata(susshi_session.susshi_uniqid),
					   bdata(susshi_session.susshi_user), bdata(susshi_session.client_ip),
					   bdata(target),
					   bdata(susshi_session.hostname), bdata(chef_cfg.susshid_id));

			log_system(LOG_LEVEL_INFO, "Session terminated by %s after %ld seconds",
					   (susshi_session.client_closed == 1) ? "client" : "target server",
					   time(NULL) - susshi_report.session_start_time);
		} else {
			log_system(LOG_LEVEL_INFO, "End session %s for '%s@%s -> %s' on Host %s (susshid-ID %s)",
					   bdata(susshi_session.susshi_uniqid),
					   bdata(susshi_session.susshi_user), bdata(susshi_session.client_ip),
					   bdata(target),
					   bdata(susshi_session.hostname), bdata(chef_cfg.susshid_id));

			if (susshi_session.gateway_closed_reason) {
				log_system(LOG_LEVEL_INFO, "Session terminated by " SUSSHI_NAME " after %ld seconds. %s",
						   time(NULL) - susshi_report.session_start_time, bdata(susshi_session.gateway_closed_reason));
			} else {
				log_system(LOG_LEVEL_INFO, "Session terminated by " SUSSHI_NAME " after %ld seconds.",
						   time(NULL) - susshi_report.session_start_time);
			}

			if ((susshi_report.session_start_time > 0) && (susshi_session.target_phase >= PHASE_SESSION_STARTED)) {
				if (susshi_session.gateway_closed_reason) {
					log_session(NODIR, NODIR, "Session terminated by " SUSSHI_NAME " after %ld seconds. %s",
								time(NULL) - susshi_report.session_start_time, bdata(susshi_session.gateway_closed_reason));
				} else {
					log_session(NODIR, NODIR, "Session terminated by " SUSSHI_NAME " after %ld seconds.",
								time(NULL) - susshi_report.session_start_time);
				}

			}
		}

		/* An active connection has been terminated. */

		if ((susshi_report.session_start_time > 0) && (susshi_session.target_phase >= PHASE_SESSION_STARTED)) {
			// Write Report
			susshi_report_client_send_report(REPORT_LAST);

			// Write Last Login log
			susshi_report_last_log(true);

			log_session(CLIENT, GATEWAY, "Transferred with client: received %lu, sent %lu bytes",
						susshi_report.client_in_bytes, susshi_report.client_out_bytes);

			log_session(GATEWAY, TARGET, "Transferred with target: sent %lu, received %lu bytes",
						susshi_report.target_out_bytes, susshi_report.target_in_bytes);

		}
	} else {

		susshi_report_client_send_report(REPORT_FAILED);

		log_session(NODIR, NODIR,
					"Session failed during session setup. Running cleanup.");

		susshi_hooks_run(HOOK_SESSION_FAILED);

		log_system(LOG_LEVEL_WARNING, "Session failed for '%s@%s -> %s' on Host %s (susshid-ID %s) during session setup. (%s)",
				   (susshi_session.susshi_user != NULL) ? bdata(susshi_session.susshi_user) : "(wrong user)",
				   bdata(susshi_session.client_ip),
				   bdata(target),
				   (susshi_session.hostname != NULL) ? bdata(susshi_session.hostname) : "(wrong hostname)",
				   bdata(chef_cfg.susshid_id),
				   bdata(susshi_session.susshi_uniqid));
	}

}


/*!
 * @brief       Disconnect a session (and the other side)
 *
 * @param       session
 * @param       error_code
 * @param       message
 */

static void
susshi_disconnect_session(ssh_session session, int error_code, const char *message) {

	if (session == NULL)
		return;

	ssh_buffer_pack(session->out_buffer,
					"bdss",
					SSH2_MSG_DISCONNECT,
					error_code,
					message,
					"");

	ssh_packet_send(session);
	ssh_blocking_flush(session, 1);
}


/*!
 * @brief       Disconnect CLIENT and/or TARGET and cleanup what needs to be cleaned up
 *
 * @param       side
 * @param       error_code
 * @param       fmt
 * @param       ...
 */

void
susshi_disconnect_individual(Side side, int error_code, const char *fmt, ...)
{
	char message[1024];
	va_list args;
	static int disconnecting = 0;

	if (disconnecting)	/* Guard against recursive invocations. */
		fatal("packet_disconnect called recursively.");
	disconnecting = 1;

	// Format the message.  Note that the caller must make sure the message is of limited size.
	va_start(args, fmt);
	vsnprintf(message, sizeof(message), fmt, args);
	va_end(args);

	// Log the error
	log_system(LOG_LEVEL_INFO, "Disconnecting %s with message '%.1024s'", bdata(susshi_session.client_ip), message);
	log_session(NODIR, NODIR, "Disconnecting %s with message '%.1024s'", bdata(susshi_session.client_ip), message);

	// Store message for report as well if not already set
	if (susshi_report.message == NULL)
		susshi_report.message = bfromcstr(message);

	if (side == CLIENT || side == BOTH) {
		// Send disconnect message to the CLIENT
		if ((susshi_session.client_phase != PHASE_NOT_CONNECTED)
		 && (ssh_socket_is_open(susshi_session.client_session->socket))) {
			debug1("Disconnecting client.");
			susshi_disconnect_session(susshi_session.client_session, error_code, message);
			ssh_socket_close(susshi_session.client_session->socket);
		}
	}

	if (side == TARGET || side == BOTH) {
		// Send disconnect message to the TARGET.
		if ((susshi_session.target_phase != PHASE_NOT_CONNECTED)
			&& (ssh_socket_is_open(susshi_session.target_session->socket))) {
			debug1("Disconnecting target.");
			susshi_disconnect_session(susshi_session.target_session, error_code, message);
			ssh_socket_close(susshi_session.target_session->socket);
		}
	}

	susshi_end_session();

	exit(1);
}


/*!
 * @brief       Disconnect CLIENT and/or TARGET and cleanup what needs to be cleaned up
 *
 * @param       side
 * @param       error
 */

void
susshi_disconnect_standard(Side side, DisconnectError error)
{
	const char *message;
	bstring bmessage = NULL;
	static int disconnecting = 0;
	int i, index;

	if (disconnecting)	/* Guard against recursive invocations. */
		fatal("packet_disconnect called multiple times.");

	disconnecting = 1;

	for(index = -1, i = 0; disconnect_messages[i].code != DISCONNECT_DEFAULT; i++) {
		if (disconnect_messages[i].code == error) {
			index = i;
			break;
		}
	}

	if (index == -1)
		index = i;	// default to DISCONNECT_DEFAULT

	/* Verbose or strict message */
	message = susshi_cfg.verbose_disconnect ? disconnect_messages[index].message_verbose : disconnect_messages[index].message_strict;

	bmessage = bformat(SUSSHI_NAME " - %s (status code #%d%d).", message, disconnect_messages[index].susshi_error_code_major,
					   disconnect_messages[index].susshi_error_code_minor);

	// Store message for report as well if not already set
	if (susshi_report.message == NULL)
		susshi_report.message = bformat("%s.", message);

	// Log the error
	log_system(LOG_LEVEL_INFO, "Disconnecting %s with message '%.1024s'", bdata(susshi_session.client_ip), message);
	log_session(NODIR, NODIR, "Disconnecting %s with message '%.1024s'", bdata(susshi_session.client_ip), message);

	if (side == CLIENT || side == BOTH) {
		// Send disconnect message to the CLIENT
		if (susshi_session.client_phase != PHASE_NOT_CONNECTED) {
			debug1("Disconnecting client.");
			susshi_disconnect_session(susshi_session.client_session, disconnect_messages[index].ssh2_code, bdata(bmessage));
			ssh_socket_close(susshi_session.client_session->socket);
		}
	}

	if (side == TARGET || side == BOTH) {
		// Send disconnect message to the TARGET.
		if (susshi_session.target_phase != PHASE_NOT_CONNECTED) {
			debug1("Disconnecting target.");
			susshi_disconnect_session(susshi_session.target_session, disconnect_messages[index].ssh2_code, bdata(bmessage));
			ssh_socket_close(susshi_session.target_session->socket);
		}

		if (susshi_session.target_proxy_phase != PHASE_NOT_CONNECTED) {
			debug1("Disconnecting target proxy.");
			susshi_disconnect_session(susshi_session.target_proxy_session, disconnect_messages[index].ssh2_code, bdata(bmessage));
			ssh_socket_close(susshi_session.target_proxy_session->socket);
		}
	}

	bstrFree(bmessage);

	susshi_end_session();

	exit(1);
}


/*!
 * @brief       Set/unset filedescriptor to non-blocking
 */

int
susshi_socket_set_nonblock(socket_t fd)
{
	int val;

	val = fcntl(fd, F_GETFL, 0);
	if (val < 0) {
		error("fcntl(%d, F_GETFL, 0): %s", fd, strerror(errno));
		return (-1);
	}
	if (val & O_NONBLOCK) {
		debug4("Socket %d is O_NONBLOCK", fd);
		return (0);
	}

	debug4("Set socket %d O_NONBLOCK", fd);

	val |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, val) == -1) {
		debug4("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
			   strerror(errno));
		return (-1);
	}
	return (0);
}


/*!
 * @brief       Set socket to IPv6 only
 *
 * @param       fd      Filedescriptor
 */

void
susshi_socket_set_v6only(socket_t fd)
{
#ifdef IPV6_V6ONLY
	int on = 1;

	debug3("Set socket %d IPV6_V6ONLY", fd);
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) == -1)
		error("Setsockopt IPV6_V6ONLY: %s.", strerror(errno));
#endif
}


/*!
 * @brief       Disable Nagle on socket
 *
 * @param       fd      Filedescriptor
 */

void
susshi_socket_set_nodelay(socket_t fd)
{
	int opt;
	socklen_t optlen;

	optlen = sizeof opt;
	if (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug4("Getsockopt TCP_NODELAY: %.100s", strerror(errno));
		return;
	}
	if (opt == 1) {
		debug4("Socket %d is TCP_NODELAY", fd);
		return;
	}
	opt = 1;
	debug4("Set socket %d TCP_NODELAY", fd);
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof opt) == -1)
		error("Setsockopt TCP_NODELAY: %.100s", strerror(errno));
}


/*!
 * @brief       Timout Signals Handler
 *
 * Will get called if something during target or proxy connection / authentication is going to hang
 */

void
susshi_session_timeout_alarm_handler(void) {

	susshi_report_client_send_report(REPORT_FAILED);

	if (susshi_session.use_target_proxy) {
		debug3("Received timeout signal during proxy connection / authentication.");
		susshi_disconnect_standard(BOTH, DISCONNECT_TARGET_PROXY_CONNECT_FAILED);
	} else {
		debug3("Received timeout signal during target connection / authentication.");
		susshi_disconnect_standard(BOTH, DISCONNECT_TARGET_CONNECT_FAILED);
	}
}


/*!
 * @brief       Timout Signal Alarm Registry
 *
 * Register timer for timeout during target or proxy connection / authentication
 *
 * @param       tv_sec_timeout      Timeout
 */

void
susshi_session_set_timeout_alarm(time_t tv_sec_timeout) {
	struct itimerval it_val;

	if (!susshi_session.timeout_alarm_registered) {
		debug3("Register timeout signal handler to be triggered after %ld seconds.", tv_sec_timeout);

		if (signal(SIGALRM, (void (*)(int)) susshi_session_timeout_alarm_handler) == SIG_ERR) {
			fatal("Unable to catch SIGALRM");
		}
		susshi_session.timeout_alarm_registered = true;
	} else {
		debug4("Overwrite timeout signal handler with %ld seconds timeout.", tv_sec_timeout);
	}

	memset(&it_val, 0, sizeof(struct itimerval));

	it_val.it_value.tv_sec=tv_sec_timeout;
	it_val.it_value.tv_usec = 0;

	if (setitimer(ITIMER_REAL, &it_val, NULL) == -1) {
		fatal("Error calling setitimer()");
	}
}


/*!
 * @brief       Timout Signal Alarm Cancel
 *
 * Cancel timer for timeout during target or proxy connection / authentication
 */

void
susshi_session_cancel_timeout_alarm(void) {
	struct itimerval it_val;

	if (susshi_session.timeout_alarm_registered) {
		memset(&it_val, 0, sizeof(struct itimerval));
		it_val.it_value.tv_sec = 0;
		it_val.it_value.tv_usec = 0;

		debug3("Cancel timeout signal handler.");

		/* Ignore Signal */
		signal(SIGALRM, SIG_IGN);

		if (setitimer(ITIMER_REAL, &it_val, NULL) == -1) {
			fatal("Error calling setitimer()");
		}
		susshi_session.timeout_alarm_registered = false;
	}
}


/*!
 * @brief       Drop privileges
 *
 * Drop privileges of process
 *
 * @param       proc_name       (unused)
 * @param       permanent       if set true, privileges are dropped permanently. If false, they can be restored.
 *
 */

void
susshi_drop_privileges(const char *proc_name, bool permanent) {
	drop_privileges(permanent, susshi_session.unprivileged_user_uid, susshi_session.unprivileged_user_gid);
	debug4("%s: dropped privileges %s (egid=%d, euid=%d, gid=%d, uid=%d).",
			proc_name, permanent ? "permanently" : "temporarily", getegid(), geteuid(), getgid(), getuid());
}


/*!
 * @brief       Restore privileges
 */

void
susshi_restore_privileges(void) {
	restore_privileges();
	debug4("Restored privileges (egid=%d, euid=%d, gid=%d, uid=%d).", getegid(), geteuid(), getgid(), getuid());
}

/*! @} */
