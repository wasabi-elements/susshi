/*!
 *
 * @brief       Session Loop
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
 * @defgroup    session_loop Session Loop
 * @brief       Functions of the session loop, looping through the whole session and calling inspection handlers.
 * @{
 */

#include <susshid/common.h>


/*
 * This callbacks are defined in a global scope to overcome issues with Release-builds we've been faced
 * for unknown reason. Not sure if this is dependent to optimizer settings > O0 or FORTIFY_SOURCE or a
 * combination of both.
 *
 * A long series of tests showed that the definition of these variables as global variables no longer leads to a crash in libSSH.
 */

static ssh_packet_callback *client_packet_callbacks_1;
static ssh_packet_callback *client_packet_callbacks_2;
static ssh_packet_callback *target_packet_callbacks_1;
static ssh_packet_callback *target_packet_callbacks_2;
static struct ssh_packet_callbacks_struct client_callbacks_1;
static struct ssh_packet_callbacks_struct client_callbacks_2;
static struct ssh_packet_callbacks_struct target_callbacks_1;
static struct ssh_packet_callbacks_struct target_callbacks_2;


/*!
 * @brief       Callback for all packets received from client
 *
 * Params are session, type, packet, user
 *
 * @return      SSH_PACKET_USED
 */

static
SSH_PACKET_CALLBACK(susshi_client_packet_callback) {

	// May be set to false during packet inspection
	susshi_report.update_last_io_time = true;

	if (susshi_inspect_packet(CLIENT, type, packet)) {
		ssh_buffer_add_u8(susshi_session.target_session->out_buffer, type);
		ssh_buffer_add_buffer(susshi_session.target_session->out_buffer, packet);
		if ((ssh_packet_send(susshi_session.target_session) != SSH_OK) ||
			(susshi_session.target_session->session_state == SSH_SESSION_STATE_ERROR) ||
			(susshi_session.target_session->session_state == SSH_SESSION_STATE_DISCONNECTED)) {
			susshi_session.target_session->alive = 0;
			susshi_session.target_closed = true;
		}
	}

	/* Update the last I/O timer (used to calculate the idle time of a session in signal handler) */
	if (susshi_report.update_last_io_time)
		susshi_report.last_io_time = time(NULL);

	return SSH_PACKET_USED;
}


/*!
 * @brief       Callback for all packets received from target
 *
 * Params are session, type, packet, user
 *
 * @return      SSH_PACKET_USED
 */

static
SSH_PACKET_CALLBACK(susshi_target_packet_callback){

	// May be set to false during packet inspection
	susshi_report.update_last_io_time = true;

	if (susshi_inspect_packet(TARGET, type, packet)) {
		ssh_buffer_add_u8(susshi_session.client_session->out_buffer, type);
		ssh_buffer_add_buffer(susshi_session.client_session->out_buffer, packet);
		if ((ssh_packet_send(susshi_session.client_session) != SSH_OK) ||
			(susshi_session.client_session->session_state == SSH_SESSION_STATE_ERROR) ||
			(susshi_session.client_session->session_state == SSH_SESSION_STATE_DISCONNECTED)) {
			susshi_session.client_session->alive = 0;
			susshi_session.client_closed = true;
		}
	}

	/* Update the last I/O timer (used to calculate the idle time of a session in signal handler) */
	if (susshi_report.update_last_io_time)
		susshi_report.last_io_time = time(NULL);

	return SSH_PACKET_USED;
}


/*!
 * @brief       suSSHi Session Loop
 *
 * Called after connection from client & to target are established and authenticated.
 * Will handle all further I/O between Client and Target.
 */

void
susshi_session_loop(void) {

	ssh_event event_ctxt;
	uint8_t min, max, n_callbacks;

	int poll_rc;

	/*
	 * Skip session-loop if we come from PubkeySSHAgent mode and do not have at minimum 1 channel open
	 * This could happen if short-run command like "exit 1" has been send to target and target
	 * responds immediately with an exit code message, thus susshi_session_loop() would hang.
	 */

	/*
	 * --> Seems to be not the best idea. Keep it for future code review
	 *
	if ((susshi_session.pubkey_ssh_agent_mode == true) && (susshi_num_open_channels() == 0)) {
		debug4("Immediate exit code received. Skipping susshi_session_loop()");
		susshi_session.target_closed = 1;
		susshi_end_session();
		return;
	}
	*/

	/* Remove all default callbacks - ssh_packet_set_callbacks() will always *add* a new list */
	susshi_session.client_session->packet_callbacks = NULL;
	susshi_session.target_session->packet_callbacks = NULL;

	/* Prepare callbacks (1st List) */
	min = RANGE_SSH2_MSG_SUSSHI_RANGE1_MIN;
	max = RANGE_SSH2_MSG_SUSSHI_RANGE1_MAX;

	n_callbacks = max-min+1;

	client_packet_callbacks_1 = xmalloc(sizeof(ssh_packet_callback)*(n_callbacks));
	target_packet_callbacks_1 = xmalloc(sizeof(ssh_packet_callback)*(n_callbacks));

	memset(client_packet_callbacks_1, 0, sizeof(ssh_packet_callback)*(n_callbacks));
	memset(target_packet_callbacks_1, 0, sizeof(ssh_packet_callback)*(n_callbacks));

	/* Fill whole array with same handler */
	for(int i=0; i < n_callbacks; i++) {
		client_packet_callbacks_1[i] = susshi_client_packet_callback;
		target_packet_callbacks_1[i] = susshi_target_packet_callback;
	}

	client_callbacks_1.start=min;
	client_callbacks_1.n_callbacks=n_callbacks;
	client_callbacks_1.callbacks=client_packet_callbacks_1;
	client_callbacks_1.user=susshi_session.client_session;

	target_callbacks_1.start=min;
	target_callbacks_1.n_callbacks=n_callbacks;
	target_callbacks_1.callbacks=target_packet_callbacks_1;
	target_callbacks_1.user=susshi_session.target_session;

	/* Add new callbacks */
	ssh_packet_set_callbacks(susshi_session.client_session, &client_callbacks_1);
	ssh_packet_set_callbacks(susshi_session.target_session, &target_callbacks_1);


	/* Prepare callbacks (2nd List) */
	min = RANGE_SSH2_MSG_SUSSHI_RANGE2_MIN;
	max = RANGE_SSH2_MSG_SUSSHI_RANGE2_MAX;

	n_callbacks = max-min+1;

	client_packet_callbacks_2 = xmalloc(sizeof(ssh_packet_callback)*(n_callbacks));
	target_packet_callbacks_2 = xmalloc(sizeof(ssh_packet_callback)*(n_callbacks));

	memset(client_packet_callbacks_2, 0, sizeof(ssh_packet_callback)*(n_callbacks));
	memset(target_packet_callbacks_2, 0, sizeof(ssh_packet_callback)*(n_callbacks));

	/* Fill whole array with same handler */
	for(int i=0; i < n_callbacks; i++) {
		client_packet_callbacks_2[i] = susshi_client_packet_callback;
		target_packet_callbacks_2[i] = susshi_target_packet_callback;
	}

	client_callbacks_2.start=min;
	client_callbacks_2.n_callbacks=n_callbacks;
	client_callbacks_2.callbacks=client_packet_callbacks_2;
	client_callbacks_2.user=susshi_session.client_session;

	target_callbacks_2.start=min;
	target_callbacks_2.n_callbacks=n_callbacks;
	target_callbacks_2.callbacks=target_packet_callbacks_2;
	target_callbacks_2.user=susshi_session.target_session;

	/* Add new callbacks */
	ssh_packet_set_callbacks(susshi_session.client_session, &client_callbacks_2);
	ssh_packet_set_callbacks(susshi_session.target_session, &target_callbacks_2);


	/* Add default packet-handlers (list) to get the handlers for 7-49 (Extension and Algorithm Exchange, Key Exchange) back */
	ssh_packet_set_default_callbacks(susshi_session.client_session);
	ssh_packet_set_default_callbacks(susshi_session.target_session);

	/* Create a new libssh event context */
	event_ctxt = ssh_event_new();

	/* Assign sessions to it */
	ssh_event_add_session(event_ctxt, susshi_session.client_session);
	ssh_event_add_session(event_ctxt, susshi_session.target_session);

	/* Set sessions to non-blocking */
	ssh_set_blocking(susshi_session.client_session, 0);
	ssh_set_blocking(susshi_session.target_session, 0);

	/* Register Signal-Handlers */
	susshi_session_loop_signal_register();

	debug1("Entering " SUSSHID_NAME " server loop.");

	log_system(LOG_LEVEL_INFO, "Session started for '%s@%s -> %s' on Host %s (susshid-ID %s). (%s)",
			   bdata(susshi_session.susshi_user), bdata(susshi_session.client_ip),
			   bdata(susshi_session.target_identifier),
			   bdata(susshi_session.hostname),
			   bdata(chef_cfg.susshid_id),
			   bdata(susshi_session.susshi_uniqid));

	SETPROCTITLE("%s (New Session) %s@%s",
						bdata(susshi_session.susshi_uniqid),
						bdata(susshi_session.susshi_user),
						bdata(susshi_session.target_identifier));

	susshi_session.target_phase = PHASE_SESSION_STARTED;

	debug4("Client: out buffer %d", ssh_buffer_get_len(susshi_session.client_session->out_buffer));
	debug4("Target: out buffer %d", ssh_buffer_get_len(susshi_session.target_session->out_buffer));

	/* Send hostkeys-00@openssh.com GLOBAL-REQUEST */
	susshi_hostkeys_update_send_hostkeys();

	/* THE LOOP */

	do {
		poll_rc = ssh_event_dopoll(event_ctxt, 5*1000);

		if ((poll_rc == SSH_OK) || (poll_rc == SSH_AGAIN)) {

			if (susshi_session.received_signal) {
				susshi_session.gateway_closed = true;

				if (susshi_session.received_signal == SIGINT) {
					susshi_session.gateway_closed_reason = bfromcstr("The session was ended by an administrator or because the user signed out.");
					susshi_report.message = bfromcstr("The session was ended by an administrator or because the user signed out.");
					log_system(LOG_LEVEL_INFO, "Terminating session after receiving termination command.");
				} else {
					log_system(LOG_LEVEL_INFO, "Exiting on signal %d (%s)",
							   susshi_session.received_signal, strsignal(susshi_session.received_signal));
				}
				break;
			}

			if (!ssh_is_connected(susshi_session.client_session)) {
				log_system(LOG_LEVEL_ERROR, "Impolite disconnect from client.");
				susshi_session.client_closed = true;
				break;
			}

			if (!ssh_is_connected(susshi_session.target_session)) {
				log_system(LOG_LEVEL_ERROR, "Impolite disconnect from target.");
				susshi_session.target_closed = true;
				break;
			}

			if (susshi_session.client_closed || susshi_session.target_closed || susshi_session.gateway_closed)
				break;

		} else {
			if (errno == 0) {
				log_system(LOG_LEVEL_WARNING, "Impolite disconnect from client (PuTTY?).");
				susshi_session.client_closed = true;
				break;
			}
			if (errno != EINTR) {
				if (!ssh_is_connected(susshi_session.client_session)) {
					log_system(LOG_LEVEL_WARNING, "Received socket error on client side: %s. Impolite disconnect from client.", strerror(errno));
					susshi_session.client_closed = true;
				} else if (!ssh_is_connected(susshi_session.target_session)) {
					log_system(LOG_LEVEL_WARNING, "Received socket error on target side: %s. Impolite disconnect from target.", strerror(errno));
					susshi_session.target_closed = true;
				} else {
					log_system(LOG_LEVEL_WARNING, "Received socket error: %s. Disconnecting client and target.", strerror(errno));
					susshi_session.gateway_closed = true;
				}
				break;
			}
		};

	} while(true);

	if (susshi_session.gateway_closed) {
		if (susshi_session.gateway_closed_reason) {
			susshi_disconnect_individual(BOTH, SSH2_DISCONNECT_BY_APPLICATION,
										 bdata(susshi_session.gateway_closed_reason));
		} else {
			susshi_disconnect_individual(BOTH, SSH2_DISCONNECT_BY_APPLICATION, "Session closed by gateway.");
		}
	} else {
		susshi_end_session();
	}
}

/*! @} */
