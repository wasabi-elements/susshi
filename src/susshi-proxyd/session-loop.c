/*!
 *
 * @brief       Session Loop
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
 * @defgroup    proxy_session_loop Session Loop methods
 * @brief       Functions of the session loop, looping through the whole session
 * @{
 *
 */

#include <susshi-proxyd/common.h>


#define PROXY_TCP_TIMEOUT (30 * 1000)   /* For testing only 30 seconds, later: (8 * 60 * 1000) */
#define PROXY_TCP_CHUNK_SIZE 16384



/*!
 * @brief       Receives data from a socket into a buffer.
*
* @param        side      Identifies the connection side for logging.
* @param        socket    Source socket to read from.
* @param        buffer    Destination buffer for received data.
*
* @return       true on success or EWOULDBLOCK, false on connection close or error.
*/

static bool
receive_into_buffer(Side side, socket_t socket, ssh_buffer buffer) {
	u_char *tmpbuf[PROXY_TCP_CHUNK_SIZE+1];
	ssize_t bytes_received;

	bytes_received = recv(socket, tmpbuf, PROXY_TCP_CHUNK_SIZE, 0);

	if (bytes_received == 0) {
		log_system(LOG_LEVEL_INFO, "Connection closed by %s. Session aborted.", SideString[side]);
		return false;
	}

	if (bytes_received > 0) {
		int rc;
		rc = ssh_buffer_add_data(buffer, tmpbuf, (uint32_t ) bytes_received);
		debug3_dir(side, PROXY, "Received %d bytes of data.", ssh_buffer_get_len(buffer));
		debug_susshi_hexdump_ssh_buffer(buffer);

		return rc == SSH_OK;
	}

	if (bytes_received < 0) {
		if (errno == EWOULDBLOCK) {
			return true;
		}
		log_system(LOG_LEVEL_INFO, "Connection closed due to error %s.", strerror(errno));
	}

	return false;
}


/*!
 * @brief       Sends buffered data out through a socket.
 *
 * @param       side      Identifies the connection side for logging.
 * @param       socket    Destination socket to write to.
 * @param       buffer    Source buffer containing data to send.
 *
 * @return      true if data was sent or buffer was empty, false on send error.
 */

static bool
send_from_buffer(Side side, socket_t socket, ssh_buffer buffer) {
	ssize_t bytes_to_send, bytes_send;

	if ((bytes_to_send = ssh_buffer_get_len(buffer)) > 0) {
		bytes_send = send(socket, ssh_buffer_get(buffer), (size_t) bytes_to_send, 0);

		if (bytes_send > 0) {
			debug3_dir(PROXY, side, "Send %d bytes of data.", ssh_buffer_get_len(buffer));

			debug_susshi_hexdump_ssh_buffer(buffer);

			buffer->pos+=bytes_send;
			return true;
		}
	} else {
		return true;
	}

	return false;
}


/*!
 * @brief       Runs the main proxy I/O loop between gateway and target.
 *
 * Entered after both connections are established and authenticated.
 * Uses poll(2) to multiplex bidirectional data flow, with a semaphore
 * that withholds data to the gateway until the target banner is received.
 * Exits on idle timeout, signal, or connection close from either side.
 */

void
proxy_session_loop(void) {

	struct pollfd fds[2];
	int rc;

	ssh_buffer buffer_gateway_target;
	ssh_buffer buffer_target_gateway;

	/*
	 * We use this as a semaphore to not send data to gateway until we received data (the banner)
	 * This prevents data to be sent to early until gateway is not already in right state
	 */
	bool received_data_from_gateway = false;

	/* Register Signal-Handlers */
	proxy_session_loop_signal_register();

	debug1("Entering " SUSSHI_PROXYD_NAME " server loop.");

	/* This might prevent from packets arriving to early on gateway */
	debug4("Sleeping for 100 ms before starting copying packets.");
	usleep(100 * 1000);

	log_system(LOG_LEVEL_INFO, "Start session %s to %s:%d (%s:%d).",
			   bdata(proxy_session.susshi_uniqid),
			   bdata(proxy_session.target_host), proxy_session.target_port,
			   bdata(proxy_session.target_ip), proxy_session.target_port);

	SETPROCTITLE("%s (Running Session)",
						bdata(proxy_session.susshi_uniqid));

	/* Set Gateway Socket */
	proxy_session.gateway_socket = ssh_get_fd(proxy_session.gateway_session);

	/* Set sockets to blocking */
	set_socket_blocking_mode(proxy_session.gateway_socket, true);
	set_socket_blocking_mode(proxy_session.target_socket, true);

	/* Disable Nagle */
	proxy_socket_set_nodelay(proxy_session.gateway_socket);
	proxy_socket_set_nodelay(proxy_session.target_socket);

	fds[0].fd = proxy_session.gateway_socket;
	fds[0].revents = 0;
	fds[1].fd = proxy_session.target_socket;
	fds[1].revents = 0;

	buffer_gateway_target = ssh_buffer_new();
	buffer_target_gateway = ssh_buffer_new();

	debug3("In SSH-Buffer: %d bytes in gateway-out_buffer", ssh_buffer_get_len(proxy_session.gateway_session->out_buffer));
	debug3("In SSH-Buffer: %d bytes in gateway-in_buffer", ssh_buffer_get_len(proxy_session.gateway_session->in_buffer));

	debug2("Max session idle-secs: %d", proxy_session.max_session_idle_secs);

	/* THE LOOP */
	do {
		fds[0].events = POLLIN;
		fds[1].events = POLLIN;

		if (ssh_buffer_get_len(buffer_gateway_target) > 0) {
			fds[1].events |= POLLOUT;
		}

		if (ssh_buffer_get_len(buffer_target_gateway) > 0) {
			fds[0].events |= POLLOUT;
		}

		if ((rc = poll(fds, 2, proxy_session.max_session_idle_secs * 1000)) >= 0) {

			if (rc == 0) {
				proxy_session.proxy_closed = true;
				log_system(LOG_LEVEL_INFO, "Exiting after idle time of %d seconds.", proxy_session.max_session_idle_secs);
				break;
			}

			if (proxy_session.received_sigterm) {
				proxy_session.proxy_closed = true;
				log_system(LOG_LEVEL_INFO, "Exiting on signal %d", proxy_session.received_sigterm);
				break;
			}

			if (proxy_session.received_sigint) {
				proxy_session.proxy_closed = true;
				break;
			}

			if (proxy_session.gateway_closed || proxy_session.target_closed || proxy_session.proxy_closed)
				break;

			// debug1("loop: fds[gateway].revents=%d", fds[0].revents);
			// debug1("loop: fds[target].revents=%d", fds[1].revents);

			if (fds[1].revents & POLLIN) {
				// Read from Target and store in Gateway buffer
				if (!receive_into_buffer(TARGET, fds[1].fd, buffer_target_gateway)) {
					proxy_session.target_closed = true;
				}
			}

			if ((fds[0].revents & POLLOUT) && (received_data_from_gateway)) {
				// Read from Gateway Buffer and send to Gateway
				if (!send_from_buffer(GATEWAY, fds[0].fd, buffer_target_gateway)) {
					proxy_session.gateway_closed = true;
				}
			}

			if (fds[0].revents & POLLIN) {
				// Read from Gateway and store in Target buffer
				if (receive_into_buffer(GATEWAY, fds[0].fd, buffer_gateway_target)) {
					received_data_from_gateway = true;
				} else {
					proxy_session.gateway_closed = true;
				}
			}

			if (fds[1].revents & POLLOUT) {
				// Read from Target Buffer and send to Target
				if (!send_from_buffer(TARGET, fds[1].fd, buffer_gateway_target)) {
					proxy_session.target_closed = true;
				}
			}

		} else {
			log_system(LOG_LEVEL_WARNING, "Received socket error: %s. Disconnecting gateway and target.", strerror(errno));
			proxy_session.proxy_closed = 1;
			break;
		};

	} while(true);

	if (proxy_session.gateway_closed == 1) {
		susshi_proxy_disconnect(BOTH, SSH2_DISCONNECT_BY_APPLICATION, "Session closed by gateway.");
	} else {
		proxy_end_session();
	}
}

/*! @} */
