/*!
 *
 * @brief       Session methods
 *
 * @ingroup     susshi_proxyd
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
 * @defgroup    proxy_session Session methods
 * @brief       Functions handling the global susshi proxy session context.
 * @{
 *
 */

#include <susshi-proxyd/common.h>


/* SuSSHi Session options */
SusshiSession proxy_session;

/* Prototypes */
static SplitLoginStringReturn store_target_address_into_session(void);
static void proxy_disconnect_session(ssh_session session, int error_code, const char *message);


/*!
 * @brief       Init proxy_session
 */

void
init_proxy_session(void)
{
	memset(&proxy_session, 0, sizeof(SusshiSession));

	proxy_session.gateway_phase = PHASE_NOT_CONNECTED;
	proxy_session.target_port = 22;
	proxy_session.embryonic_slot_id = -1;

#ifdef LINUX
	get_unprivileged_user_uid_gid(&proxy_session.unprivileged_user_uid, &proxy_session.unprivileged_user_gid);
#endif
}


/*!
 * @brief       Get remote IP and port from given socket and fill client_ip and client_port in proxy_session
 *
 * @param       socket      TCP socket
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

	proxy_session.gateway_ip = bfromcstr(ipstr);
	proxy_session.gateway_port = port;
}


/*!
 * @brief       Split loginstring (from authentication user) and store information in proxy_session
 *
 * @param       user        The username from the actual session
 *
 * @return      Enum of @p SplitLoginStringReturn
 */

SplitLoginStringReturn
store_splitted_loginstring_into_proxy_session(const char *user)
{
	bstrList splitlogin, splithost, splitport;

	if (proxy_session.login_string != NULL) {
		// Function has already run before
		return STRING_OK;
	}

	proxy_session.login_string = bfromcstr(user);

	if (!validate_string_chars_regex(proxy_session.login_string, "^[a-zA-Z0-9@\\.\\[\\]:\\\\\\/_#-]+$"))
		return ILLEGAL_CHARS;

	splitlogin = bsplits(proxy_session.login_string, bfromcstr("@/"));

	if (splitlogin->qty == 3) {
		if (strcmp(bdata(splitlogin->entry[0]), "susshi-hostkey-scanner") == 0) {
			proxy_session.susshi_uniqid = bfromcstr("unset");
			proxy_session.operation_mode = OP_MODE_PROXY_CHEF_REMOTE;
		} else {
			proxy_session.operation_mode = OP_MODE_PROXY;
			proxy_session.susshi_uniqid = bstrcpy(splitlogin->entry[0]);

			if (!validate_string_chars_regex(proxy_session.susshi_uniqid, "^[a-z0-9\\._-]+$"))
				return ILLEGAL_CHARS;
		}

		proxy_session.target_host = bstrcpy(splitlogin->entry[1]);
		if (strncmp(bdata(proxy_session.target_host), "bastion", strlen("bastion")) == 0) {
			proxy_session.operation_mode = OP_MODE_PROXY_BASTION;
		}

		proxy_session.max_session_idle_secs = (uint32_t) atol(bdata(splitlogin->entry[2]));

		if (proxy_session.max_session_idle_secs == 0) {
			log_system(LOG_LEVEL_WARNING,
					   "Unable to interpret max session idle timer from gateway, " "setting it to 30 minutes");
			proxy_session.max_session_idle_secs = 1800;
		}

		bstrListDestroy(splitlogin);

		if (!validate_string_chars_regex(proxy_session.target_host, "^[a-zA-Z0-9\\.\\[\\]:-]+$"))
			return ILLEGAL_CHARS;

	} else {
		bstrListDestroy(splitlogin);
		return USERNAME_INVALID;
	}

	/*
	 * a. Extract port if given in form:
	 *	1. <host>:<port>
	 *	2. [<ipv6_ip>]:<port>
	 *
	 * b. Replace target_host in form [<ipv6_ip>] or [<ipv6_ip>]:<port> with <ipv6_ip>
	 */

	// IPv6 form
	splithost = bsplits(proxy_session.target_host, bfromcstr("[]"));

	if (splithost->qty > 1) {
		// Hostname is in form [<ipv6_ip>] or [<ipv6_ip>]:<port>
		if (splithost->qty > 2)
		{
			// IPv6 port is given in form [<ipv6_ip>]:<port>
			splitport = bsplit(splithost->entry[2], ':');
			if (splitport->qty > 1)
			{
				proxy_session.target_port = atoi(bdata(splitport->entry[1]));
				debug4("port is %d.", proxy_session.target_port);
			}
			bstrListDestroy(splitport);
		}
		// Replace target_host in form [<ipv6_ip>] or [<ipv6_ip>]:<port> with <ipv6_ip>
		proxy_session.target_host = bstrcpy(splithost->entry[1]);
		bstrListDestroy(splithost);
	}

	// IPv4 form
	splitport = bsplit(proxy_session.target_host, ':');

	if (splitport->qty == 2) {
		proxy_session.target_host = bstrcpy(splitport->entry[0]);
		proxy_session.target_port = atoi(bdata(splitport->entry[1]));
	}

	if (proxy_session.target_port < 1 || proxy_session.target_port > 65535) {
		log_system(LOG_LEVEL_INFO, "Invalid port (%d) given. Disconnecting client.", proxy_session.target_port);
		return(TARGET_PORT_INVALID);
	}

	btolower(proxy_session.target_host);

	if (proxy_session.operation_mode == OP_MODE_PROXY_BASTION) {
		proxy_session.target_ips[0].ip = bfromcstr(BASTION_LISTEN_IP);
		proxy_session.target_ips[0].ai_family = AF_INET;
		proxy_session.num_target_ips++;

		return STRING_OK;
	}

	log_system(LOG_LEVEL_INFO, "Login string split into uniqid=%s, targethost=%s, targetport=%d",
			   bdata(proxy_session.susshi_uniqid), bdata(proxy_session.target_host), proxy_session.target_port);

	// Store target information (resolved address, target_identifier ...) in proxy_session as well
	return store_target_address_into_session();
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
	int gai_error;

	proxy_session.target_addrs = NULL;

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

	snprintf(strport, sizeof strport, "%u", proxy_session.target_port);

	debug1("Trying to resolve given target hostname into an IP address.");

	if ((gai_error = getaddrinfo(bdata(proxy_session.target_host), strport, &hints_ip, &proxy_session.target_addrs)) == 0) {
		debug3("Given hostname is an IP address.");
		proxy_session.target_host_fqdn = bstrcpy(proxy_session.target_host);
	} else {
		debug3("getaddrinfo for IP lookup returned with error '%s'", gai_strerror(gai_error));

		if (!validate_string_chars_regex(proxy_session.target_host, "^[a-zA-Z0-9\\._-]+$"))
			return TARGET_RESOLVE_FAILED;

		if ((gai_error = getaddrinfo(bdata(proxy_session.target_host), strport, &hints_name, &proxy_session.target_addrs)) == 0) {
			proxy_session.target_host_fqdn = bstrcpy(proxy_session.target_host);
		} else {
			debug3("getaddrinfo for hostname lookup returned with error '%s'", gai_strerror(gai_error));
		}
	}

	if (proxy_session.target_addrs != NULL) {

		/* Loop through addrinfo list and store all IP addresses */
		for (ai = proxy_session.target_addrs; (ai) && (proxy_session.num_target_ips < SUSSHI_MAX_TARGET_IPS); ai = ai->ai_next) {
			if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
				continue;

			/* Skip IPv4 addresses if host has no IPv4 interface */
			if (ai->ai_family == AF_INET && !proxy_session.host_has_ipv4) {
				debug2("DNS IPv4 response skipped.");
				continue;
			}

			/* Skip IPv6 addresses if host has no IPv6 interface */
			if (ai->ai_family == AF_INET6 && !proxy_session.host_has_ipv6) {
				debug2("DNS IPv6 response skipped.");
				continue;
			}

			if (getnameinfo(ai->ai_addr, ai->ai_addrlen,
							ntop, sizeof(ntop), strport, sizeof(strport),
							NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
				error("ssh_connect: getnameinfo failed");
				continue;
			}

			proxy_session.target_ips[proxy_session.num_target_ips].ip = bfromcstr(ntop);
			proxy_session.target_ips[proxy_session.num_target_ips].ai_family = ai->ai_family;
			if ((proxy_session.target_host_fqdn == NULL) && (ai->ai_canonname != NULL)) {
				proxy_session.target_host_fqdn = bfromcstr(ai->ai_canonname);
			}

			debug2("Resolved %s (%s) to %s.", bdata(proxy_session.target_host),
				   bdata(proxy_session.target_host_fqdn),
				   bdata(proxy_session.target_ips[proxy_session.num_target_ips].ip));

			if (proxy_session.num_target_ips == 0) {
				proxy_session.target_ips_list = bfromcstr("");
			} else {
				bcatcstr(proxy_session.target_ips_list, ", ");
			}

			bconcat(proxy_session.target_ips_list, proxy_session.target_ips[proxy_session.num_target_ips].ip);

			rc = STRING_OK;
			proxy_session.num_target_ips++;
		}
	} else {
		rc = TARGET_RESOLVE_FAILED;
	}

	if (proxy_session.num_target_ips == SUSSHI_MAX_TARGET_IPS) {
		error("Warning! More than %d IPs for target '%s' found. Only using the first %d ones.",
			  SUSSHI_MAX_TARGET_IPS, bdata(proxy_session.target_host), SUSSHI_MAX_TARGET_IPS);
	}

	if (proxy_session.target_addrs != NULL)
		freeaddrinfo(proxy_session.target_addrs);

	if (rc == TARGET_RESOLVE_FAILED) {
		log_system(LOG_LEVEL_INFO, "Target host '%s' could not be resolved.", bdata(proxy_session.target_host));
	} else {
		if (proxy_session.target_ips_list) {
			log_system(LOG_LEVEL_INFO, "Target host '%s' resolved to: %s", bdata(proxy_session.target_host), bdata(proxy_session.target_ips_list));
		} else {
			rc = TARGET_RESOLVE_FAILED;
			log_system(LOG_LEVEL_INFO, "Target host '%s' did not resolve to any IP or is incompatible with address family the proxy is running on.",
					bdata(proxy_session.target_host));
		}
	}

	return rc;
}


/*!
 * @brief       End a (suSSHi) session
 *
 * This terminates open client and target ssh sessions as well.
 */

void
proxy_end_session(void)
{
	if (proxy_session.gateway_closed == 1 || proxy_session.target_closed == 1 || proxy_session.proxy_closed == 1) {

		if (proxy_session.gateway_closed == 1 || proxy_session.target_closed == 1) {
			log_system(LOG_LEVEL_INFO, "End session %s on Host %s (susshid-ID %s)",
					   bdata(proxy_session.susshi_uniqid),
					   bdata(proxy_session.hostname), bdata(proxy_cfg.susshid_id));
		} else {
			log_system(LOG_LEVEL_INFO, "End session %s for on Host %s (susshid-ID %s)",
					   bdata(proxy_session.susshi_uniqid),
					   bdata(proxy_session.hostname), bdata(proxy_cfg.susshid_id));
		}

	} else {
		log_system(LOG_LEVEL_INFO, "Session %s on Host %s (susshid-ID %s) failed during session setup.",
				   bdata(proxy_session.susshi_uniqid),
				   (proxy_session.hostname != NULL) ? bdata(proxy_session.hostname) : "(wrong hostname)",
				   bdata(proxy_cfg.susshid_id));
	}
}


/*!
 * @brief       Disconnect a session
 *
 * @param       session
 * @param       error_code
 * @param       message
 */

static void
proxy_disconnect_session(ssh_session session, int error_code, const char *message) {

	if (session == NULL)
		return;

	ssh_buffer_pack(session->out_buffer,
					"bdss",
					SSH2_MSG_DISCONNECT,
					error_code,
					message,
					"");

	ssh_packet_send(session);
}


/*!
 * @brief       Disconnect CLIENT and/or TARGET and cleanup what needs to be cleaned up
 *
 * @param       side        The Side
 * @param       error_code  The Error code
 * @param       fmt         Format string
 */

void
susshi_proxy_disconnect(Side side, int error_code, const char *fmt,...)
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
	log_system(LOG_LEVEL_INFO, "Disconnecting %s with message '%.1024s'", bdata(proxy_session.gateway_ip), message);

	if (side == GATEWAY || side == BOTH) {
		// Send disconnect message to the CLIENT
		if (proxy_session.gateway_phase != PHASE_NOT_CONNECTED) {
			debug1("Disconnecting gateway.");
			proxy_disconnect_session(proxy_session.gateway_session, error_code, message);
			ssh_socket_close(proxy_session.gateway_session->socket);
		}
	}

	if (side == TARGET || side == BOTH) {
		// Send disconnect message to the TARGET.
		if (proxy_session.target_phase != PHASE_NOT_CONNECTED) {
			debug1("Disconnecting target.");
/*
			proxy_disconnect_session(proxy_session.target_session, error_code, message);
			ssh_socket_close(proxy_session.target_session->socket);
*/
		}
	}

	proxy_end_session();

	exit(1);
}


/*!
 * @brief       Create target_identifier and store it to proxy_session
 */

void
store_target_identifier_into_session(void) {
	bstring portbuf = NULL;

	if (proxy_session.target_port != 22)
		portbuf = bformat(":%d", proxy_session.target_port);
	else
		portbuf = bfromcstr("");

	proxy_session.target_identifier = bformat("%s%s (%s%s)",
											   bdata(proxy_session.target_host), bdata(portbuf),
											   bdata(proxy_session.target_ip), bdata(portbuf));
	bstrFree(portbuf);
}


/*!
 * @brief       Set/unset filedescriptor to blocking / non-blocking
 *
 * @param       socket          The socket
 * @param       is_blocking     true = blocking, false = unblocking
 */

bool
proxy_set_blocking_mode(int socket, bool is_blocking)
{
	bool ret = true;

	const int flags = fcntl(socket, F_GETFL, 0);
	if ((flags & O_NONBLOCK) && !is_blocking) { debug2("set_blocking_mode(): socket was already in non-blocking mode"); return ret; }
	if (!(flags & O_NONBLOCK) && is_blocking) { debug2("set_blocking_mode(): socket was already in blocking mode"); return ret; }
	ret = 0 == fcntl(socket, F_SETFL, is_blocking ? flags ^ O_NONBLOCK : flags | O_NONBLOCK);

	return ret;
}


/*!
 * @brief       Set socket to IPv6 only
 *
 * @param       fd      The TCP socket
 */

void
proxy_socket_set_v6only(socket_t fd)
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
 * @param       fd      The TCP socket
 */

void
proxy_socket_set_nodelay(socket_t fd)
{
	int opt;
	socklen_t optlen;

	optlen = sizeof opt;
	if (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug4("Getsockopt TCP_NODELAY: %.100s", strerror(errno));
		return;
	}
	if (opt == 1) {
		debug3("Socket %d is TCP_NODELAY", fd);
		return;
	}
	opt = 1;
	debug3("Set socket %d TCP_NODELAY", fd);
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof opt) == -1)
		error("Setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/*!
 * @brief       Drop privileges
 *
 * Drop privileges of process.
 *
 * @param       proc_name
 * @param       permanent   if set true, privileges are dropped permanently. If false, they can be restored.
 *
 */

void
proxy_drop_privileges(const char *proc_name, bool permanent) {
	drop_privileges(permanent, proxy_session.unprivileged_user_uid, proxy_session.unprivileged_user_gid);
	debug4("%s: dropped privileges %s (egid=%d, euid=%d, gid=%d, uid=%d).",
		   proc_name, permanent ? "permanently" : "temporarily", getegid(), geteuid(), getgid(), getuid());
}


/*!
 * @brief       Restore privileges
 */

void
proxy_restore_privileges(void) {
	restore_privileges();
	debug4("Restored privileges (egid=%d, euid=%d, gid=%d, uid=%d).", getegid(), geteuid(), getgid(), getuid());
}


/*! @} */
