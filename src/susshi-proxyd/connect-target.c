/*!
 *
 * @brief       Target Connection
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
 * @defgroup    proxy_connect_target Target Connection
 * @brief       Functions handling the TCP connection to a target.
 * @{
 *
 */

#include <susshi-proxyd/common.h>

/* Prototypes */
static int proxy_select_next_target_ip(void);


/*!
 * @brief       Select next target IP address for (sequential) Happy Eyeballs
 *
 * This will honor the preferred target address family
 */

static int
proxy_select_next_target_ip(void) {
	int i;

	for(i=0; (i < proxy_session.num_target_ips); i++) {
		if (proxy_session.target_ips[i].ai_family != proxy_cfg.target_preferred_address_family)
			continue;
		if (proxy_session.target_ips[i].used)
			continue;
		proxy_session.target_ips[i].used = true;

		proxy_session.target_ip = proxy_session.target_ips[i].ip;
		store_target_identifier_into_session();

		return i;
	}

	for(i=0; i < proxy_session.num_target_ips; i++) {
		if (proxy_session.target_ips[i].used)
			continue;
		proxy_session.target_ips[i].used = true;

		proxy_session.target_ip = proxy_session.target_ips[i].ip;
		store_target_identifier_into_session();

		return i;
	}

	return -1;
}


/*!
 * @brief       Try to TCP connect to target
 *
 * @return      true on success
 */

bool
proxy_connect_target(void) {
	bool rc = false;
	struct addrinfo hints_ip;
	int gai_error;
	char strport[NI_MAXSERV];
	fd_set fdset;
	struct timeval tv;

	/* Special case when we receive a health probe request (which is actually just a hostkey scan on IP 127.0.0.1) */
	if ((proxy_session.operation_mode == OP_MODE_PROXY_CHEF_REMOTE) && (strcmp(bdata(proxy_session.target_ips[0].ip), "127.0.0.1") == 0)) {
		log_system(LOG_INFO, "Health probe request received.");
		/* In this case, we just point the target-port to the bastion sshd port instead of port 22 */
		proxy_session.target_port = BASTION_LISTEN_PORT;
	}

	do {
		/* (Sequential) Happy Eyeballs */
		if (proxy_select_next_target_ip() != -1) {

			debug1_dir(PROXY, TARGET, "Trying to connect to %s (%s).",
					   bdata(proxy_session.target_host), bdata(proxy_session.target_ip));

			memset(&hints_ip, 0, sizeof(hints_ip));
			hints_ip.ai_family = AF_UNSPEC;
			hints_ip.ai_socktype = SOCK_STREAM;
			hints_ip.ai_protocol = IPPROTO_TCP;
			hints_ip.ai_flags = AI_ADDRCONFIG | AI_NUMERICHOST;

			snprintf(strport, sizeof strport, "%u", proxy_session.target_port);

			if ((gai_error = getaddrinfo(bdata(proxy_session.target_ip), strport, &hints_ip, &proxy_session.target_addrs)) == 0) {

				/* Get a socket */
				proxy_session.target_socket = socket(proxy_session.target_addrs->ai_family, SOCK_STREAM, IPPROTO_TCP);
				fcntl(proxy_session.target_socket, F_SETFL, O_NONBLOCK);

				if (proxy_session.target_socket != -1) {

					setsockopt(proxy_session.target_socket, SOL_SOCKET, SO_KEEPALIVE, (int[]) {1}, sizeof(int));
					setsockopt(proxy_session.target_socket, IPPROTO_TCP, TCP_NODELAY, (int[]) {1}, sizeof(int));

					connect(proxy_session.target_socket, proxy_session.target_addrs->ai_addr, proxy_session.target_addrs->ai_addrlen);

					FD_ZERO(&fdset);
					FD_SET(proxy_session.target_socket, &fdset);

					if (proxy_session.operation_mode == OP_MODE_PROXY_CHEF_REMOTE)
						tv.tv_sec = 2;     /* 2 seconds timeout */
					else
						tv.tv_sec = 5;     /* 5 seconds timeout */

					tv.tv_usec = 0;

					if (select(proxy_session.target_socket + 1, NULL, &fdset, NULL, &tv) == 1) {

						int so_error;
						socklen_t len = sizeof so_error;

						getsockopt(proxy_session.target_socket, SOL_SOCKET, SO_ERROR, &so_error, &len);

						switch(so_error) {
							case 0:
								/* Finally we are connected */
								log_system(LOG_LEVEL_INFO, "Connection to %s:%d established.",
										   bdata(proxy_session.target_ip), proxy_session.target_port);
								rc = true;
								break;
							case EAFNOSUPPORT:
								log_system(LOG_LEVEL_INFO, "Address %s in the specified address family cannot be used with this socket.",
										   bdata(proxy_session.target_ip));
								break;
							case ECONNRESET:
							case ECONNREFUSED:
								log_system(LOG_LEVEL_INFO, "Connection refused by %s:%d.",
										   bdata(proxy_session.target_ip), proxy_session.target_port);
								break;
							case ENETUNREACH:
							case EHOSTUNREACH:
								log_system(LOG_LEVEL_INFO, "Target %s:%d is unreachable.",
										   bdata(proxy_session.target_ip), proxy_session.target_port);
								break;
							default:
								log_system(LOG_LEVEL_INFO, "Connection to %s:%d failed (so_error %d).",
										   bdata(proxy_session.target_ip), proxy_session.target_port, so_error);
						}
					} else {
						log_system(LOG_LEVEL_WARNING, "Connection to %s:%d timed out after %d seconds.",
								   bdata(proxy_session.target_ip), proxy_session.target_port, 5);
					}

				}

			} else {
				log_system(LOG_LEVEL_CRIT, "getaddrinfo for IP lookup returned with error '%s'", gai_strerror(gai_error));
			}

		} else {
			/* No more IP addresses to walk */
			proxy_gateway_auth_send_error_json(SUSSHI_PROXY_ERROR_CODE_TARGET_CONNECT_FAILED);
			log_system(LOG_LEVEL_WARNING, "Could not connect to target. Aborting");
			return false;
		}
	} while (!rc);

	return rc;
}

/*! @} */
