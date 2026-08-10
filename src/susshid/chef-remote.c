/*!
 *
 * @brief       Chef Control Commands
 *              Functions handling Chef Control from chef to susshi
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
 * @defgroup    chef_remote Chef Remote Control
 * @{
 */

#include <susshid/common.h>


/* Prototypes */
static void execute_cmd(bstring command);
static bool execute_cmd_status(json_t *result);
static bool execute_cmd_status_proxy(json_t *result, const char *args);
static bool execute_cmd_scan_hostkeys(json_t *result, const char *args);
static bool execute_cmd_scan_hostkeys_proxy(json_t *result, const char *args);
static bool execute_cmd_restart(json_t *result);
static bool execute_cmd_shutdown(json_t *result);
static bool execute_cmd_terminate(json_t *result, const char *args);
static bool execute_cmd_auth_grant(json_t *result, const char *args);
static json_t *receive_hostkey(bstring target);

/*! @cond */
static struct {
	ssh_channel channel;
	bstring command;
	bool exec_requested;
} int_store = {
		.command = NULL,
		.exec_requested = false
};
/*! @endcond */


/*!
 * @brief       Open Channel request handler
 *
 * @param       session     ssh_session
 * @param       userdata
 *
 * @return      ssh_channel
 */

static ssh_channel
channel_open_request(ssh_session session, void *userdata) {
	(void) userdata;

	int_store.channel = ssh_channel_new(session);

	return int_store.channel;
}


/*!
 * @brief       Channel PTY request handler
 *
 * @param       session     ssh_session
 * @param       channel     ssh_channel
 * @param       term        Terminal
 * @param       cols        Columns
 * @param       rows        Rows
 * @param       px          Pixel X
 * @param       py          Pixel Y
 * @param       userdata    userdata
 *
 * @return      SSH_ERROR
 */

static int
channel_pty_request(ssh_session session, ssh_channel channel,
					const char *term, int cols, int rows, int py, int px,
					void *userdata) {
	return SSH_ERROR;
}


/*!
 * @brief       Channel PTY window change handler
 *
 * @param       session     ssh_session
 * @param       channel     ssh_channel
 * @param       cols        Columns
 * @param       rows        Rows
 * @param       px          Pixel X
 * @param       py          Pixel Y
 * @param       userdata    userdata
 *
 * @return      SSH_ERROR
 */

static int
channel_pty_window_change(ssh_session session, ssh_channel channel, int cols,
						  int rows, int py, int px, void *userdata) {
	return SSH_ERROR;
}


/*!
 * @brief       Channel Shell request with PTY
 *
 * @param       session     ssh_session
 * @param       channel     ssh_channel
 * @param       userdata    userdata
 *
 * @return      SSH_ERROR
 */

static int
channel_shell_request(ssh_session session, ssh_channel channel,
					  void *userdata) {

	return SSH_ERROR;
}


/*!
 * @brief       Exec request with given command
 *
 * @param       session     ssh_session
 * @param       channel     ssh_channel
 * @param       command     command
 * @param       userdata    userdata
 *
 * @return      SSH_OK
 */

static int
channel_exec_request(ssh_session session, ssh_channel channel,
					 const char *command, void *userdata) {

	(void) session;

	int_store.command = bfromcstr(command);
	int_store.exec_requested = true;

	return SSH_OK;
}


/*!
 * @brief       Execute given command
 *
 * @param       command
 */

static void
execute_cmd(bstring command) {
	bool rc = false;
	int split;
	char *cmd, *args;
	json_t *result = json_object();

	cmd = xmalloc(64);
	args = xmalloc(blength(command));

	split = sscanf(bdata(command), "%63[^ ]%*[ ]%63[^\n]", cmd, args);

	if ((split > 0) && (result)) {
		char *json_str;

		if (strcmp(cmd, RCMD_STATUS) == 0) {
			rc = execute_cmd_status(result);

		} else if (strcmp(cmd, RCMD_STATUS_PROXY) == 0) {
			rc = execute_cmd_status_proxy(result, args);

		} else if (strcmp(cmd, RCMD_RESTART) == 0) {
			rc = execute_cmd_restart(result);

		} else if (strcmp(cmd, RCMD_SHUTDOWN) == 0) {
			rc = execute_cmd_shutdown(result);

		} else if (strcmp(cmd, RCMD_SUSPEND) == 0) {
			rc = suspend_monitor_server();

		} else if (strcmp(cmd, RCMD_UNSUSPEND) == 0) {
			rc = unsuspend_monitor_server();

		} else if (strcmp(cmd, RCMD_TERM_SESSION) == 0) {
			rc = execute_cmd_terminate(result, args);

		} else if (strcmp(cmd, RCMD_SCAN_HOSTKEYS) == 0) {
			rc = execute_cmd_scan_hostkeys(result, args);

		} else if (strcmp(cmd, RCMD_SCAN_HOSTKEYS_PROXY) == 0) {
			rc = execute_cmd_scan_hostkeys_proxy(result, args);

		} else if (strcmp(cmd, RCMD_AUTH_GRANT) == 0) {
			rc = execute_cmd_auth_grant(result, args);

		} else {
			json_object_set(result, "fail_reason", json_string("command not found or parameter missing."));

		}

		log_system(LOG_LEVEL_INFO, "Received and executed remote control command '%s' %s.", cmd, rc ? "successfully" : "with failure");

		int_store.exec_requested = true;

		json_object_set(result, "command", json_string(cmd));
		json_object_set(result, "return", json_string(rc ? "success" : "failed"));

		json_str = json_dumps(result, JSON_ENSURE_ASCII | JSON_SORT_KEYS);

		if (json_str) {
			bstring json_text = bformat("%s\n", json_str);
			ssh_channel_write(int_store.channel, bdata(json_text), (uint32_t) blength(json_text));
			bstrFree(json_text);
			xfree(json_str);
			xfree(result);
		} else {
			rc = false;
		}
	} else {
		rc = false;
	}

	xfree(cmd);
	xfree(args);

	ssh_channel_request_send_exit_status(int_store.channel, rc ? 1:0);
}


#define MAX_TIME_STR 100


/*!
 * @brief       Commands - Return status information of susshid
 *
 * @param       result          Pointer to JSON struct where to store answer
 *
 * @return      true on success
 */

static bool
execute_cmd_status(json_t *result) {
	time_t now;
	struct tm tm_now;
	char str_time[MAX_TIME_STR];

	now = time(NULL);
	localtime_r(&now, &tm_now);
	strftime(str_time, MAX_TIME_STR, "%a %b %d %T %Z %G", &tm_now);

	json_object_set(result, "status", json_string("running"));
	json_object_set(result, "susshid_id", json_string(bdata(chef_cfg.susshid_id)));
	if (susshi_cfg.config_version)
		json_object_set(result, "version", json_integer(susshi_cfg.config_version));

	json_object_set(result, "software_version", json_string(SUSSHI_VERSION));
	json_object_set(result, "system_time", json_string(str_time));
	json_object_set(result, "master_pid", json_integer(susshi_session.master_pid));
	json_object_set(result, "active_sessions", json_integer(susshi_count_and_signal_processes(SUSSHID_PROCESS_PATTERN_WORKERS, -1, false)));
	json_object_set(result, "suspended", json_boolean(monitor_server_suspended()));

	return true;
}

#undef MAX_TIME_STR


/*!
 * @brief       Commands - Return status information of suSSHi Proxy
 *
 * @param       result      Pointer to JSON struct where to store answer
 * @param       args        Command Arguments
 *
 * @return      true on success
 */

static bool
execute_cmd_status_proxy(json_t *result, const char *args) {

	bool rc = false;

	json_t *scan_result = json_object();
	bstring scan_hostkeys_args = NULL;

	debug2("Trying to reach proxy %s", args);

	susshi_cfg.session.target_connection_timeout = 5;

	scan_hostkeys_args = bformat("%s 127.0.0.1", args);
	execute_cmd_scan_hostkeys_proxy(scan_result, bdata(scan_hostkeys_args));

	if (json_object_iter(scan_result)) {
		rc = true;
		json_object_set(result, "status", json_string("reachable"));
		json_object_set(result, "proxy_version", json_string(bdata(susshi_session.proxy_version)));
	} else {
		switch(susshi_session.target_proxy_phase) {
			case PHASE_KEX:
				json_object_set(result, "status", json_string("not-proxy"));
				break;
			case PHASE_CONNECTED:
				json_object_set(result, "status", json_string("unknown-proxy"));
				break;
			case PHASE_AUTH_START:
				/*
				 * reachable with errors
				 * could happen if proxy is not responding to authentication correctly (older versions ?)
				 * return = "failed", status  = "reachable"
				 */
				json_object_set(result, "proxy_version", json_string(bdata(susshi_session.proxy_version)));
				json_object_set(result, "status", json_string("reachable"));
				break;
			default:
				json_object_set(result, "status", json_string("unreachable"));
		}
		json_object_set(result, "susshid_id", json_string(bdata(chef_cfg.susshid_id)));
	}

	if (susshi_session.target_proxy_ip)
		json_object_set(result, "ip_address", json_string(bdata(susshi_session.target_proxy_ip)));

	return rc;
}


/*!
 * @brief       Commands - Restart master process and load new configuration
 *
 * @param       result      Pointer to JSON struct where to store answer
 *
 * @return      true on success
 */

static bool
execute_cmd_restart(json_t *result) {

	if (susshi_session.master_pid > 0) {
		kill(susshi_session.master_pid, SIGHUP);
		return true;
	} else {
		json_object_set(result, "fail_reason", json_string("No master PID found"));
	}

	return false;
}


/*!
 * @brief       Commands - Shutdown master process
 *
 * @param       result      Pointer to JSON struct where to store answer
 *
 * @return      true on success
 */

static bool
execute_cmd_shutdown(json_t *result) {

	if (susshi_session.master_pid > 0) {

		// Find session daemons and send SIGTERM to them
		susshi_count_and_signal_processes(SUSSHID_PROCESS_PATTERN_WORKERS, SIGINT, true);

		// Terminate master process (reporting daemon gets terminated as well)
		kill(susshi_session.master_pid, SIGINT);
		return true;

	} else {
		json_object_set(result, "fail_reason", json_string("No master PID found"));
	}

	return false;
}


/*!
 * @brief       Commands - Terminate session by sending SIGTERM to (session) process
 *
 * @param       result      Pointer to JSON struct where to store answer (not used)
 * @param       args        Arguments for proc matching
 *
 * @return      true on success
 */

static bool
execute_cmd_terminate(json_t *result, const char *args) {
	bstring proc_string = NULL;
	int count = 0;

	log_system(LOG_LEVEL_INFO, "Received terminate %s command", args);

	proc_string = bformat(SUSSHID_NAME ": %s", args);

	count = susshi_count_and_signal_processes(bdata(proc_string), SIGINT, true);

	bstrFree(proc_string);

	/* We should have killed exactly one session process */
	if (count == 1)
		return true;

	return false;
}


/*!
 * @brief       Commands - Scan hostkeys
 *
 * @param       result      Pointer to JSON struct where to store answer
 * @param       args        List of IP addresses, comma separated
 *
 * @return      true on success
 */

static bool
execute_cmd_scan_hostkeys(json_t *result, const char *args) {

	json_t *host_keys;
	bstrList targets = NULL;

	host_keys = json_object();
	targets = bsplit(bfromcstr(args), ' ');

	for(int i=0; i < targets->qty; i++) {
		json_t *values;
		values = receive_hostkey(targets->entry[i]);
		if (values != NULL)
			json_object_set(host_keys, bdata(susshi_session.target_ip), values);
	}
	if (targets)
		bstrListDestroy(targets);

	if (json_object_size(host_keys) > 0) {
		json_object_set(result, "hostkeys", host_keys);
		json_object_set(result, "return", json_string("success"));
		return true;
	} else {
		return false;
	}

}


/*!
 * @brief       Commands - Scan hostkeys via proxy
 *
 * @param       result      Pointer to JSON struct where to store answer
 * @param       args        List of IP addresses, comma separated
 *
 * @return      true on success
 */

static bool
execute_cmd_scan_hostkeys_proxy(json_t *result, const char *args) {

	json_t *host_keys;
	bstrList targets = NULL;

	host_keys = json_object();

	debug2("Scan targets: %s", args);

	targets = bsplit(bfromcstr(args), ' ');
	susshi_session.target_proxy_realm = targets->entry[0];

	for(int i=1; i < targets->qty; i++) {
		json_t *values;

		values = receive_hostkey(targets->entry[i]);
		if (values != NULL)
			json_object_set(host_keys, bdata(susshi_session.target_ip), values);
	}
	if (targets)
		bstrListDestroy(targets);

	if (json_object_size(host_keys) > 0) {
		json_object_set(result, "hostkeys", host_keys);
		json_object_set(result, "return", json_string("success"));
		return true;
	} else {
		return false;
	}

}


/*!
 * @brief       Commands - Grant access
 *
 * Grant access on OpenID-Connect authentication by signaling SIGIO to (session) process
 *
 * @param       result      Pointer to JSON struct where to store answer
 * @param       args        Arguments for proc matching
 *
 * @return      true on success
 */

bool
execute_cmd_auth_grant(json_t *result, const char *args) {
	bstring proc_string = NULL;
	int count = 0;

	log_system(LOG_LEVEL_INFO, "Grant OpenID connect access for session %s", args);

	proc_string = bformat(SUSSHID_NAME ": %s", args);

	count = susshi_count_and_signal_processes(bdata(proc_string), SIGIO, false);

	bstrFree(proc_string);

	/* We should have killed exactly one session process */
	if (count == 1) {
		return true;
	} else if (count == 0) {
		json_object_set(result, "fail_reason", json_string("session not found"));
	}

	return false;
}


/*!
 * @brief       Receive one hostkey from target
 *
 * @param       target      Traget
 *
 * @return      JSON Object in form of { "base64": "....", "fingerprint": "..." } or (JSON) null-Object
 */

static json_t *
receive_hostkey(bstring target) {

	json_t *result = NULL;

	bstrList splithost = NULL;
	bstrList splitport = NULL;

	long timeout = 2;
	static int SSH_false = 0, SSH_true = 1;
	ssh_key target_pubkey;

	if (susshi_session.target_ip) {
		bstrFree(susshi_session.target_ip);
		susshi_session.target_ip = NULL;
	}

	susshi_session.target_port = 22;

	/*
	  * a. Extract port if given in form:
	  *	1. <host>:<port>
	  *	2. [<ipv6_ip>]:<port>
	  *
	  * b. Replace target_host in form [<ipv6_ip>] or [<ipv6_ip>]:<port> with <ipv6_ip>
	  */

	if ((susshi_session.target_session = ssh_new()) != NULL) {

		if (susshi_session.target_proxy_realm) {

			susshi_session.target_host = target;
			susshi_session.target_host_resolved = target;

			init_susshi_identifier();

			susshi_session.target_proxy_login_user = bformat("%s@%s:%d@%d",
					"susshi-hostkey-scanner",
					bdata(susshi_session.target_host_resolved),
					susshi_session.target_port,
					2);

			/* Connect through proxy */
			if (!susshi_chef_lookup_proxy())
				return NULL;

			if (!susshi_proxy_connect_phase1())
				return NULL;

			if (!susshi_proxy_connect_phase2()) {
				return NULL;
			}

			susshi_session.target_session->opts.fd = ssh_get_fd(susshi_session.target_proxy_session);

			/* Required for libSSH, even if we have already set an FD socket. */
			ssh_options_set(susshi_session.target_session, SSH_OPTIONS_HOST,
							bdata(susshi_session.target_host_resolved));
			ssh_options_set(susshi_session.target_session, SSH_OPTIONS_PORT,
							&susshi_session.target_port);

			timeout = 1;

		} else {
			// IPv6 form
			splithost = bsplits(target, bfromcstr("[]"));

			if (splithost->qty > 1) {
				// Hostname is in form [<ipv6_ip>] or [<ipv6_ip>]:<port>
				if (splithost->qty > 2) {
					// IPv6 port is given in form [<ipv6_ip>]:<port>
					splitport = bsplit(splithost->entry[2], ':');
					if (splitport->qty > 1) {
						susshi_session.target_port = a2port(bdata(splitport->entry[1]));
						debug4("port is %d.", susshi_session.target_port);
					}
					bstrListDestroy(splitport);
				}
				// Replace target_host in form [<ipv6_ip>] or [<ipv6_ip>]:<port> with <ipv6_ip>
				susshi_session.target_ip = bstrcpy(splithost->entry[1]);
				bstrListDestroy(splithost);
			}

			// IPv4 form
			splitport = bsplit(target, ':');

			if (splitport->qty == 2) {
				susshi_session.target_ip = bstrcpy(splitport->entry[0]);
				susshi_session.target_port = a2port(bdata(splitport->entry[1]));
			}

			if (susshi_session.target_port < 1 || susshi_session.target_port > 65535) {
				return json_null();
			}

			if (susshi_session.target_ip == NULL) {
				susshi_session.target_ip = bstrcpy(target);
			}

			debug1_dir(GATEWAY, TARGET, "Trying to receive host_keys from %s.", bdata(susshi_session.target_ip));

			ssh_options_set(susshi_session.target_session, SSH_OPTIONS_HOST, bdata(susshi_session.target_ip));
			ssh_options_set(susshi_session.target_session, SSH_OPTIONS_PORT, &susshi_session.target_port);
		}

		ssh_options_set(susshi_session.target_session, SSH_OPTIONS_TIMEOUT, &timeout);
		ssh_options_set(susshi_session.target_session, SSH_OPTIONS_SSH1, &SSH_false);
		ssh_options_set(susshi_session.target_session, SSH_OPTIONS_SSH2, &SSH_true);
		ssh_options_set(susshi_session.target_session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &SSH_false);
		ssh_options_set(susshi_session.target_session, SSH_OPTIONS_USER, "susshi-hostkey-scanner");
		ssh_options_set(susshi_session.target_session, SSH_OPTIONS_CIPHERS_C_S, "aes256-ctr,aes256-cbc,aes256-gcm@openssh.com,aes192-ctr,aes192-cbc,aes128-ctr,aes128-cbc,aes128-gcm@openssh.com,blowfish-cbc,chacha20-poly1305");
		ssh_options_set(susshi_session.target_session, SSH_OPTIONS_CIPHERS_S_C, "aes256-ctr,aes256-cbc,aes256-gcm@openssh.com,aes192-ctr,aes192-cbc,aes128-ctr,aes128-cbc,aes128-gcm@openssh.com,blowfish-cbc,chacha20-poly1305");

		susshi_session.target_session->clientbanner = strdup(SUSSHI_SSH_VERSION_BANNER_FULL);

		if (susshi_cfg.session.target_hostkey_algorithms) {
			ssh_options_set(susshi_session.target_session, SSH_OPTIONS_HOSTKEYS,
							bdata(susshi_cfg.session.target_hostkey_algorithms));
			debug2_dir(GATEWAY, TARGET,
					   "List of preferred host key algorithms is set to %s according to configuration.",
					   bdata(susshi_cfg.session.target_hostkey_algorithms));
		} else {
			ssh_options_set(susshi_session.target_session, SSH_OPTIONS_HOSTKEYS,
							DEFAULT_PREFERRED_HOST_KEY_ALGOS);
			debug2_dir(GATEWAY, TARGET, "List of preferred host key algorithms is set to default.");
		}

		susshi_libssh_set_verbosity(susshi_session.target_session, TARGET);

		if (ssh_connect(susshi_session.target_session) == SSH_OK) {
			const char *dishash = NULL;

			susshi_session.target_phase = PHASE_KEX;

			/* Receive and store target banner */
			susshi_session.target_ssh_identification = bfromcstr(
					ssh_get_serverbanner(susshi_session.target_session));

			if (ssh_get_server_publickey(susshi_session.target_session, &target_pubkey) == SSH_OK) {
				char *blob;

				/* We received the public key */

				if (ssh_pki_export_pubkey_base64(target_pubkey, &blob) == SSH_OK) {
					dishash = susshi_display_hash_from_key(target_pubkey);
					if (dishash) {
						json_t *key_data = json_object();

						debug2("Received Hostkey of type %s with hash '%s' from target.",
							   susshi_ssh_key_type_to_char(target_pubkey), dishash);

						if (key_data) {
							result = json_object();
							json_object_set(key_data, "base64", json_string(blob));
							json_object_set(key_data, "fingerprint", json_string(dishash));
							json_object_set(result, susshi_ssh_key_type_to_char(target_pubkey), key_data);
						}

						xfree((void *) dishash);
					}
					xfree((void *) blob);

				}
			}
		}
		ssh_disconnect(susshi_session.target_session);
		ssh_free(susshi_session.target_session);
	}

	if (splithost)
		bstrListDestroy(splithost);
	if (splitport)
		bstrListDestroy(splitport);

	if (result == NULL)
		return NULL;
	else
		return json_object_size(result) > 0 ? result : json_null();
}


/*!
 * @brief       Setup the Command executer and run the loop
 *
 */

void
susshi_chef_remote_loop(void) {

	ssh_event event_ctxt;
	int n;

	struct ssh_channel_callbacks_struct channel_cb = {
			.channel_pty_request_function = channel_pty_request,
			.channel_pty_window_change_function = channel_pty_window_change,
			.channel_shell_request_function = channel_shell_request,
			.channel_exec_request_function = channel_exec_request
			// .channel_subsystem_request_function = subsystem_request
	};

	struct ssh_server_callbacks_struct server_cb = {
			.channel_open_request_session_function = channel_open_request,
	};

	int_store.channel = NULL;

	/* Init callbacks */
	ssh_callbacks_init(&server_cb);
	ssh_callbacks_init(&channel_cb);

	/* Wait for channel open request */
	ssh_set_server_callbacks(susshi_session.client_session, &server_cb);

	event_ctxt = ssh_event_new();
	ssh_event_add_session(event_ctxt, susshi_session.client_session);

	while (int_store.channel == NULL) {
		if (ssh_event_dopoll(event_ctxt, -1) == SSH_ERROR) {
			debug1("SSH ERROR --------------");
			fprintf(stderr, "%s\n", ssh_get_error(susshi_session.client_session));
			return;
		}
	}

	/* We have a channel */

	/* Wait for other requests and loop through data */
	ssh_set_channel_callbacks(int_store.channel, &channel_cb);

	SETPROCTITLE("suSSHi-Chef Remote Control");

	do {
		if (ssh_event_dopoll(event_ctxt, -1) == SSH_ERROR)
			ssh_channel_close(int_store.channel);

	} while(ssh_channel_is_open(int_store.channel) &&
			!int_store.exec_requested);

	if (int_store.command) {
		execute_cmd(int_store.command);
	}

	ssh_channel_send_eof(int_store.channel);
	ssh_channel_close(int_store.channel);

	/* Wait up to 5 seconds for the client to terminate the session. */
	for (n = 0; n < 50 && (ssh_get_status(susshi_session.client_session) & ((SSH_CLOSED | SSH_CLOSED_ERROR))) == 0; n++) {
		ssh_event_dopoll(event_ctxt, 100);
	}

	ssh_event_free(event_ctxt);
}

/*! @} */
