/*!
 *
 * @brief       Client Authentication
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
 * @defgroup    auth_client Client Authentication
 * @{
 *
 * @defgroup    auth_client_methods Client Authentication (authentication methods)
 * @brief       Specific client authentication methods
 * @ingroup     auth_client
 */

#include <susshid/common.h>


//! @cond
static struct {
	int allowed_auth_methods;
	int required_auth_methods;
	int succeeded_auth_methods;
	bool authenticated;
	int auth_attempts;
	int auth_failures;
	bool banner_sent;
} int_store = {
		.allowed_auth_methods = 0,
		.required_auth_methods = 0,
		.succeeded_auth_methods = 0,
		.authenticated = false,
		.auth_attempts = 0,
		.auth_failures = -1,
		.banner_sent = false
};
/*! @endcond */

/* Prototypes */
static bool susshi_client_auth_dispatch(void);
static void susshi_client_auth_process_method_response(ssh_message message, enum ssh_auth_state_e auth_response, const char *method_name);
static void susshi_client_send_issue_banner(void);
static enum ssh_auth_state_e susshi_client_auth_password(ssh_message message);
static enum ssh_auth_state_e susshi_client_auth_publickey(ssh_message message);
static enum ssh_auth_state_e susshi_client_auth_interactive(ssh_message message);
static void susshi_client_auth_openid_connect_start(void);
static bool susshi_client_auth_openid_connect_wait(int timeout);


/*!
 * @brief       Initialize the client-side authentication state machine and run it to completion
 *
 * Sets the session phase to @c PHASE_AUTH_START, configures the libssh session states,
 * and enters the authentication dispatch loop. If no allowed authentication methods have
 * been configured yet, defaults to @c password, @c publickey, and @c keyboard-interactive.
 *
 * @return      @c true if the client authenticated successfully, @c false otherwise
 */

bool
susshi_client_auth_start(void) {

	/* Set allowed Authentication methods */
	if (int_store.allowed_auth_methods == 0)
		int_store.allowed_auth_methods = SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_INTERACTIVE;

	susshi_session.client_phase = PHASE_AUTH_START;
	susshi_ssh_set_session_state(susshi_session.client_session, SSH_SESSION_STATE_AUTHENTICATING);
	susshi_ssh_set_auth_state(susshi_session.client_session, SSH_AUTH_STATE_NONE);

	debug1("Client authentication started.");

	return susshi_client_auth_dispatch();
}

/*!
 * @brief       Clear all allowed client authentication methods
 *
 * Resets the allowed-methods bitmask to zero, effectively preventing any
 * authentication method from being accepted. Call @c susshi_client_auth_enable_method()
 * or @c susshi_client_auth_add_preferred_method() to re-enable individual methods.
 */

void
susshi_client_auth_disable_all_methods(void) {
	int_store.allowed_auth_methods = 0;
}


/*!
 * @brief       Remove an authentication method from the set of allowed methods
 *
 * Clears the bit(s) identified by @p method from the allowed-methods bitmask.
 *
 * @param       method      SSH auth method flag to remove (e.g. @c SSH_AUTH_METHOD_PASSWORD)
 */

void
susshi_client_auth_disable_method(u_int32_t method) {
	int_store.allowed_auth_methods &= ~(method);
}


/*!
 * @brief       Add an authentication method to the set of allowed methods
 *
 * Sets the bit(s) identified by @p method in the allowed-methods bitmask.
 *
 * @param       method      SSH auth method flag to add (e.g. @c SSH_AUTH_METHOD_PUBLICKEY)
 */

void
susshi_client_auth_enable_method(u_int32_t method) {
	int_store.allowed_auth_methods |= method;
}


/*!
 * @brief       Enable an authentication method by its protocol name string
 *
 * Accepted values for @p method are: @c "publickey", @c "password",
 * @c "keyboard-interactive", @c "interactive" (enables both password and
 * keyboard-interactive), and @c "openid-connect".
 *
 * @param       method      Protocol name of the method to enable
 *
 * @return      @c true if @p method is a recognised name, @c false otherwise
 */

bool
susshi_client_auth_add_preferred_method(const char *method) {

	if (strcmp(method, "publickey") == 0) {
		int_store.allowed_auth_methods |= SSH_AUTH_METHOD_PUBLICKEY;
		return true;
	}

	if (strcmp(method, "password") == 0) {
		int_store.allowed_auth_methods |= SSH_AUTH_METHOD_PASSWORD;
		return true;
	}

	if (strcmp(method, "keyboard-interactive") == 0) {
		int_store.allowed_auth_methods |= SSH_AUTH_METHOD_INTERACTIVE;
		return true;
	}

	if (strcmp(method, "interactive") == 0) {
		int_store.allowed_auth_methods |= SSH_AUTH_METHOD_PASSWORD;
		int_store.allowed_auth_methods |= SSH_AUTH_METHOD_INTERACTIVE;
		return true;
	}

	if (strcmp(method, "openid-connect") == 0) {
		int_store.allowed_auth_methods |= SSH_AUTH_METHOD_OPENID_CONNECT;
		return true;
	}

	return false;
}


/*!
 * @brief       Mark an authentication method as required for successful client authentication
 *
 * The client must satisfy all required methods (in addition to any preferred methods)
 * before authentication is considered complete. Accepted values for @p method are:
 * @c "publickey", @c "interactive", and @c "openid-connect".
 *
 * @param       method      Protocol name of the method to require
 *
 * @return      @c true if @p method is a recognised name, @c false otherwise
 */

bool
susshi_client_auth_add_required_method(const char *method) {

	if (strcmp(method, "publickey") == 0) {
		int_store.required_auth_methods |= SSH_AUTH_METHOD_PUBLICKEY;
		return true;
	}

	if (strcmp(method, "interactive") == 0) {
		int_store.required_auth_methods |= SSH_AUTH_METHOD_INTERACTIVE;
		return true;
	}

	if (strcmp(method, "openid-connect") == 0) {
		int_store.required_auth_methods |= SSH_AUTH_METHOD_OPENID_CONNECT;
		return true;
	}

	return false;
}


/*!
 * @brief       Authentication message loop: receive SSH messages and dispatch to the appropriate handler
 *
 * Reads @c ssh_message objects from the client session in a loop, dispatching each
 * @c SSH_REQUEST_AUTH message to the password, keyboard-interactive, or publickey handler.
 * Enforces the login grace time; returns early with @c false if the deadline is exceeded
 * or if the client disconnects. When only @c openid-connect remains as an allowed method,
 * starts the OIDC flow and waits for a signal from the master process instead.
 *
 * @note        The @c message pointer is deliberately stored in the session (@c susshi_session.client_message)
 *              so that @c susshi_client_auth_finish() can access the message stream.
 *
 * @return      @c true if the client authenticated successfully, @c false otherwise
 */

static bool
susshi_client_auth_dispatch(void) {
	SplitLoginStringReturn split_rc;
	ssh_message message = NULL;
	int mtype;
	time_t login_starttime = time(NULL);

	if (int_store.allowed_auth_methods == 0) {
		return false;
	}

	do {
		if ((time(NULL) - (time_t) susshi_cfg.login_grace_time) > login_starttime) {
			log_system(LOG_LEVEL_ERROR, "Authentication phase expired after login grace periode of %d sec.", susshi_cfg.login_grace_time);
			return false;
		}

		// Last remaining Auth method is openid-connect
		if (int_store.allowed_auth_methods == SSH_AUTH_METHOD_OPENID_CONNECT) {
			bool rc;

			debug2_dir(CLIENT, GATEWAY, "Authentication Method 'openid-connect'.");

			/* Send message to client */
			susshi_client_auth_openid_connect_start();

			/* Wait for signal from master-process (sent by chef remote command) */
			rc = susshi_client_auth_openid_connect_wait(susshi_cfg.login_grace_time);

			if (rc) {
				/* Successfully authenticated */
				int_store.succeeded_auth_methods |= SSH_AUTH_METHOD_OPENID_CONNECT;

				susshi_client_auth_process_method_response(
						message, SSH_AUTH_STATE_SUCCESS, "openid-connect");

				return susshi_session.client_authenticated;
			} else {
				susshi_disconnect_individual(CLIENT, DISCONNECT_AUTH_FAILED, "Authentication failed. OpenID Connect authentication took longer than %d seconds.", susshi_cfg.login_grace_time);
			}
		}

		message = ssh_message_get(susshi_session.client_session);

		if (!message) {
			if (!ssh_is_connected(susshi_session.client_session)) {
				log_system(LOG_LEVEL_ERROR, "Received disconnect from client during authentication. The connection may have been terminated on user-request.");
			} else {
				continue;
			}
			break;
		}

		debug4_dir(CLIENT, GATEWAY, "Got Message of type %d, subtype %d",
				   ssh_message_type(message), ssh_message_subtype(message));

		switch (ssh_message_type(message)) {
			case SSH_REQUEST_AUTH:

				/* Extract gwuser, targetuser and targethost from login string */
				split_rc = store_splitted_loginstring_into_session(ssh_message_auth_user(message));

				switch (split_rc) {

					case STRING_OK:

						if (susshi_session.operation_mode != OP_MODE_CHEF_REMOTE) {

							/* Mode is Gateway, Bastion or Shell */

							/* If we have to connect through proxy, initiate connection right now */
							if ((susshi_session.use_target_proxy) &&
								(susshi_session.target_proxy_phase == PHASE_NOT_CONNECTED)) {

								/* Set timout during proxy connection - on expiration, ALARM signal is sent to our process */
								susshi_session_set_timeout_alarm(MIN(susshi_cfg.session.target_connection_timeout + 3, 60));

								/* After this, we should have information about target_ips in session */
								if (!susshi_proxy_connect_phase1()) {
									susshi_disconnect_standard(CLIENT, DISCONNECT_TARGET_PROXY_CONNECT_FAILED);
								}
							}

							if (susshi_chef_get_session_context()) {

								SETPROCTITLE("%s (Client-Auth) %s",
											 bdata(susshi_session.susshi_uniqid),
											 bdata(susshi_session.susshi_user));

								/* If we have connected through proxy, continue proxy authentication and return target_ip */
								if ((susshi_session.use_target_proxy) &&
									(susshi_session.target_proxy_phase == PHASE_AUTH_PUBKEY_TEST_OK)) {

									/* After this, we should have information about target_ip in session */
									susshi_proxy_connect_phase2();

									/* Cancel timeout alarm */
									susshi_session_cancel_timeout_alarm();
								}

								/* On first attempt, send issue banner if configured */
								if ((int_store.auth_attempts == 0) && (int_store.banner_sent == false)) {
									susshi_client_send_issue_banner();
									int_store.banner_sent = true;
								}

								susshi_session.client_message = NULL;

								debug4_dir(CLIENT, GATEWAY, "Authentication attempt %d / failures %d.", int_store.auth_attempts, int_store.auth_failures);

								switch(mtype = ssh_message_subtype(message)){

									case SSH_AUTH_METHOD_PASSWORD:
										debug2_dir(CLIENT, GATEWAY, "Authentication Method 'password'.");
										susshi_client_auth_process_method_response(
												message, susshi_client_auth_password(message), "password");
										break;

									case SSH_AUTH_METHOD_INTERACTIVE:
										debug2_dir(CLIENT, GATEWAY, "Authentication Method 'keyboard-interactive'.");
										susshi_client_auth_process_method_response(
												message, susshi_client_auth_interactive(message), "keyboard-interactive");
										break;

									case SSH_AUTH_METHOD_PUBLICKEY:
										debug2_dir(CLIENT, GATEWAY, "Authentication Method 'publickey'.");
										susshi_client_auth_process_method_response(
												message, susshi_client_auth_publickey(message), "publickey");
										break;

									case SSH_AUTH_METHOD_NONE:
										debug2_dir(CLIENT, GATEWAY, "Authentication Method 'none'.");

									default:
										susshi_client_auth_process_method_response(
												message, SSH_AUTH_STATE_FAILED, mtype == SSH_AUTH_METHOD_NONE ? "none" : "unknown");
										break;
								}

								/* Break if there were to many authentication failures */
								if (susshi_session.too_many_auth_failures) {
									susshi_disconnect_standard(CLIENT, DISCONNECT_AUTH_TOO_MANY_FAILURES);
									return false;
								}

								/* Break if there are no auth methods left */
								if (!susshi_session.client_authenticated && (int_store.allowed_auth_methods == 0)) {
									/* Reply with USERAUTH_FAILURE */
									susshi_disconnect_standard(CLIENT, DISCONNECT_AUTH_FAILED);
									return false;
								}
							} else {
								susshi_disconnect_standard(CLIENT, DISCONNECT_INTERNAL_ERROR);
							}

						} else {

							/* Mode is Chef-Remote */

							susshi_session.client_message = NULL;
							int_store.allowed_auth_methods = SSH_AUTH_METHOD_PUBLICKEY;

							switch(mtype = ssh_message_subtype(message)){

								case SSH_AUTH_METHOD_PUBLICKEY:
									debug2_dir(CLIENT, GATEWAY, "Authentication Method 'publickey'.");
									susshi_client_auth_process_method_response(
											message, susshi_client_auth_publickey(message), "publickey");
									break;

								case SSH_AUTH_METHOD_NONE:
									debug2_dir(CLIENT, GATEWAY, "Authentication Method 'none'.");

								default:
									susshi_client_auth_process_method_response(
											message, SSH_AUTH_STATE_FAILED, mtype == SSH_AUTH_METHOD_NONE ? "none" : "unknown");
									break;
							}
						}
						break;

					case USERNAME_INVALID:
						log_system(LOG_LEVEL_WARNING, "Invalid user %s.", ssh_message_auth_user(message));
						// susshi_client_auth_send_invalid_user_banner();
						susshi_disconnect_standard(CLIENT, DISCONNECT_AUTH_ILLEGAL_USERNAME);
						break;

					case TARGET_RESOLVE_FAILED:
						log_system(LOG_LEVEL_WARNING, "Failed to resolve target.");
						susshi_disconnect_standard(CLIENT, DISCONNECT_TARGET_RESOLVE_FAILED);
						break;

					case TARGET_RESOLVE_WRONG_AF:
						log_system(LOG_LEVEL_WARNING, "Failed to resolve target. Wrong address family.");
						susshi_disconnect_standard(CLIENT, DISCONNECT_TARGET_RESOLVE_FAILED_AF);
						break;

					case TARGET_PORT_INVALID:
						log_system(LOG_LEVEL_WARNING, "Target port invalid.");
						susshi_disconnect_standard(CLIENT, DISCONNECT_TARGET_PORT_INVALID);
						break;

					case TARGET_GATEWAY_BASTION:
						log_system(LOG_LEVEL_WARNING, "Bastion mode is available with suSSHi Proxy only. "
												"Denied user '%s' from source-ip '%s'.",
												bdata(susshi_session.susshi_user),
												bdata(susshi_session.client_ip));
						susshi_disconnect_standard(CLIENT, DISCONNECT_TARGET_GATEWAY_BASTION);
						break;

					case TARGET_DENIED:
						log_system(LOG_LEVEL_WARNING, "Target IP is in list of denied targets.");
						susshi_disconnect_standard(CLIENT, DISCONNECT_DENIED_TARGET);
						break;

					case ILLEGAL_CHARS:
						log_system(LOG_LEVEL_WARNING, "Illegal characters in username.");
						susshi_disconnect_standard(CLIENT, DISCONNECT_AUTH_ILLEGAL_USERNAME_CHARS);
						break;

					default:
						fatal("Invalid return code %d from store_splitted_loginstring_into_session().", split_rc);
				}
				break;

			case SSH_REQUEST_SERVICE:
			default:
				ssh_message_reply_default(message);
				ssh_message_free(message);
		}

	} while(!susshi_session.client_authenticated);

	return susshi_session.client_authenticated;
}


/*!
 * @brief       Update session state and reply to the client based on an authentication method result
 *
 * Sets the libssh auth state on the client session, then acts on @p auth_response:
 * - @c SSH_AUTH_STATE_SUCCESS: marks the session authenticated if all required methods
 *   have been satisfied; otherwise sends a partial-success reply.
 * - @c SSH_AUTH_STATE_PK_OK: sends the remaining allowed methods (public-key probe accepted).
 * - @c SSH_AUTH_STATE_FAILED / @c ERROR: increments the failure counter, logs the failure
 *   (except for @c "none" and @c "publickey" probes), and sends a failure reply.
 *
 * @param       message         The @c ssh_message to reply to
 * @param       auth_response   Result returned by the per-method handler
 * @param       method_name     Human-readable method name used in log messages (e.g. @c "password")
 */

static void
susshi_client_auth_process_method_response(ssh_message message, enum ssh_auth_state_e auth_response, const char *method_name) {

	char *method_capitalize;

	susshi_ssh_set_auth_state(susshi_session.client_session, auth_response);

	switch(auth_response) {
		case SSH_AUTH_STATE_SUCCESS:
			if (strcmp(bdata(susshi_session.susshi_user), SUSSHI_CHEF_REMOTE_USER) != 0)
				log_system(LOG_LEVEL_INFO, "User '%s' successfully authenticated with method '%s'.", bdata(susshi_session.susshi_user), method_name);

			// debug1("*** %d & %d == %d", int_store.succeeded_auth_methods, int_store.required_auth_methods, int_store.required_auth_methods);

			if (int_store.succeeded_auth_methods > 1) {
				if ((int_store.succeeded_auth_methods & int_store.required_auth_methods) == int_store.required_auth_methods) {

					/* Succeeded auth methods matches required auth methods
					 *
					 * Match table
					 *
					 * required  succeeded
					 * --------  ---------
					 *   0 0    &   0 1   == required ?  --> yes
					 *   0 0    &   1 0   == required ?  --> yes
					 *   0 0    &   1 1   == required ?  --> yes
					 *   0 1    &   0 1   == required ?  --> yes
					 *   0 1    &   1 0   == required ?  --> no
					 *   0 1    &   1 1   == required ?  --> yes
					 *   1 0    &   0 1   == required ?  --> no
					 *   1 0    &   1 0   == required ?  --> yes
					 *   1 0    &   1 1   == required ?  --> yes
					 *   1 1    &   0 1   == required ?  --> no
					 *   1 1    &   1 0   == required ?  --> no
					 *   1 1    &   1 1   == required ?  --> yes
					 *
					 */

					/* For now, we just report that client has authenticated successfully
					 * But suSSHi_target_auth* functions may request more auth_methods (keyboard-interactive) from client,
					 * so we will not send this SUCCESS message to the client for now
					 */

					susshi_session.client_authenticated = true;

					if (int_store.succeeded_auth_methods == (SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_INTERACTIVE)
						|| int_store.succeeded_auth_methods == (SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_OPENID_CONNECT)) {
						susshi_session.client_authmethod = bfromcstr("multiple");
					} else {
						susshi_session.client_authmethod = bfromcstr(method_name);
					}
					susshi_session.client_phase = PHASE_AUTHENTICATED;
				} else {
					ssh_set_auth_methods(susshi_session.client_session, int_store.allowed_auth_methods);

					debug1_dir(GATEWAY, CLIENT, "Sending authentication partially successfully, but there are more required.");
					ssh_auth_reply_default(susshi_session.client_session, 1);
					susshi_ssh_set_auth_state(susshi_session.client_session, SSH_AUTH_STATE_PARTIAL);
				}
			}
			break;

		case SSH_AUTH_STATE_PK_OK:

			/* Set remaining allowed AUTH methods */
			ssh_set_auth_methods(susshi_session.client_session, int_store.allowed_auth_methods);
			break;

		case SSH_AUTH_STATE_INFO:
			break;

		case SSH_AUTH_STATE_ERROR:
		case SSH_AUTH_STATE_PARTIAL:
		case SSH_AUTH_STATE_FAILED:
		default:

			int_store.auth_failures++;

			method_capitalize = xmalloc(strlen(method_name)+1);
			strlcpy(method_capitalize, method_name, strlen(method_name)+1);
			method_capitalize[0]= (char) toupper(method_capitalize[0]);

			debug3_dir(GATEWAY, CLIENT, "%s authentication for '%s' failed.", method_capitalize, bdata(susshi_session.susshi_user));

			if ((strcmp(method_name, "none") != 0) && (strcmp(method_name, "publickey") != 0)) {
				// Silent ignore failed "none" or "publickey" requests
				log_system(LOG_LEVEL_WARNING, "%s authentication for '%s' failed.", method_capitalize, bdata(susshi_session.susshi_user));
			}

			xfree(method_capitalize);

			/* Set remaining allowed AUTH methods */
			ssh_set_auth_methods(susshi_session.client_session, int_store.allowed_auth_methods);

			if (auth_response == SSH_AUTH_STATE_PARTIAL) {
				/* Reply with USERAUTH_FAILURE / PARTIAL SUCCEEDED */
				ssh_message_auth_reply_success(message, 1);
			} else {
				/* Reply with USERAUTH_FAILURE */
				ssh_message_reply_default(message);
			}
	}
}


/*!
 * @brief       Conclude client-side authentication, sending a partial or full success reply
 *
 * Called by @c susshi_target_auth_* functions once target authentication has progressed.
 * When @p successful is @c false but the client has already authenticated, a partial-success
 * reply is sent and keyboard-interactive or password is left as the next required step.
 * When @p successful is @c true (or becomes @c true internally), the full
 * @c SSH2_MSG_USERAUTH_SUCCESS reply is sent — at most once per session.
 *
 * @param       successful      @c true to send a full authentication success reply;
 *                              @c false to determine from session state whether to send
 *                              a partial success or do nothing
 */

void
susshi_client_auth_finish(bool successful) {

	static bool partial_auth_success_sent = false;

	if (!successful) {
		if (susshi_session.client_authenticated) {
			if ((susshi_session.operation_mode == OP_MODE_SHELL) || (susshi_session.target_authenticated)) {
				/* Send SUCCESS message to client (see code below) */
				successful = true;
			} else {

				/* We are already in keyboard-interactive, so no partial authentication success message here */
				if (strcmp(bdata(susshi_session.client_authmethod), "keyboard-interactive.") == 0) {
					return;
				}

				if (partial_auth_success_sent == false) {

					if ((int_store.allowed_auth_methods & SSH_AUTH_METHOD_INTERACTIVE) ||
						(int_store.allowed_auth_methods & SSH_AUTH_METHOD_PASSWORD)) {
						/* Remove remaining allowed methods except keyboard-interactive and password */
						int_store.allowed_auth_methods &= SSH_AUTH_METHOD_INTERACTIVE | SSH_AUTH_METHOD_PASSWORD;

						ssh_set_auth_methods(susshi_session.client_session, int_store.allowed_auth_methods);

						debug1_dir(GATEWAY, CLIENT, "Completing authentication partially successfully.");
						ssh_auth_reply_default(susshi_session.client_session, 1);
						susshi_ssh_set_auth_state(susshi_session.client_session, SSH_AUTH_STATE_PARTIAL);
						partial_auth_success_sent = true;
					} else {
						susshi_disconnect_standard(CLIENT, DISCONNECT_AUTH_KBDINT_MISSING);
					}
				}
				return;
			}
		}
	}

	if (successful) {

		if (susshi_session.client_auth_finish_sent == false) {
			debug1_dir(GATEWAY, CLIENT, "Completing authentication successfully.");

			ssh_auth_reply_success(susshi_session.client_session, 0);

			susshi_ssh_set_auth_state(susshi_session.client_session, SSH_AUTH_STATE_SUCCESS);

			susshi_session.client_auth_finish_sent = true;
		} else {
			debug3_dir(GATEWAY, CLIENT, "Client authentication already finished. No authentication reply to be sent.");
		}

		susshi_ssh_set_session_state(susshi_session.client_session, SSH_SESSION_STATE_AUTHENTICATED);

		/* Enabling delayed compression is done by libssh on auth reply success already */
	}
}


/*!
 * @brief       Handle a password authentication request from the client
 *
 * Extracts the plaintext password from @p message and passes it to
 * @c susshi_chef_authn_interactive() for verification. On success, marks
 * @c SSH_AUTH_METHOD_INTERACTIVE as succeeded and disables both password and
 * keyboard-interactive from the allowed set. On empty password or extraction
 * failure, returns @c SSH_AUTH_STATE_FAILED and disables the password method.
 * The password is wiped from memory before returning.
 *
 * @note        Password change requests are not yet handled (TODO).
 *
 * @ingroup     auth_client_methods
 *
 * @param       message     The @c ssh_message carrying the password credential
 *
 * @return      @c SSH_AUTH_STATE_SUCCESS, @c SSH_AUTH_STATE_FAILED, or @c SSH_AUTH_STATE_ERROR
 */

static enum ssh_auth_state_e
susshi_client_auth_password(ssh_message message) {
	enum ssh_auth_state_e resp = SSH_AUTH_STATE_ERROR;
	bstring password = NULL;
	const char *cpassword;
	long timeout = 300;

	/* Change timeout for session during password authentication */
	ssh_options_set(susshi_session.client_session, SSH_OPTIONS_TIMEOUT, &timeout);

	int_store.auth_attempts++;

	bstrFree(susshi_session.target_userpw);

	cpassword = susshi_libssh_ssh_message_auth_password(message);
	if ((cpassword != NULL) && ((password = bfromcstr(cpassword)) != NULL)) {
		if (blength(password) > 0) {

			resp = susshi_chef_authn_interactive(password);

			if (resp == SSH_AUTH_STATE_SUCCESS) {
				/* We take password as well as "keyboard-interactive" since it is password-based */
				int_store.succeeded_auth_methods |= SSH_AUTH_METHOD_INTERACTIVE;
				susshi_client_auth_disable_method(SSH_AUTH_METHOD_PASSWORD);
				susshi_client_auth_disable_method(SSH_AUTH_METHOD_INTERACTIVE);
			}

			/* Store given password for target authentication if requested by chef */
			if ((resp == SSH_AUTH_STATE_SUCCESS) && (susshi_session.preserve_password)) {
				susshi_session.target_userpw = bstrcpy(password);
			}

			if (resp == SSH_AUTH_STATE_ERROR) {
				susshi_client_auth_disable_method(SSH_AUTH_METHOD_PASSWORD);
				susshi_client_auth_disable_method(SSH_AUTH_METHOD_INTERACTIVE);
				debug2_dir(GATEWAY, CLIENT, "Disabling methods Keyboard-Interactive and Password.");
			}
		} else {
			resp = SSH_AUTH_STATE_FAILED;

			/* Remove password authmethod from list that can continue */
			susshi_client_auth_disable_method(SSH_AUTH_METHOD_PASSWORD);
		}

		/* Wipe memory */
		memset(password->data, 'X', blength(password));
		bstrFree(password);

	} else {
		resp = SSH_AUTH_STATE_FAILED;

		/* Remove password authmethod from list that can continue */
		susshi_client_auth_disable_method(SSH_AUTH_METHOD_PASSWORD);
	}

	return resp;
}


/*!
 * @brief       Handle a keyboard-interactive authentication exchange with the client
 *
 * This function is called twice per login attempt. On the initial request
 * (@c ssh_message_auth_kbdint_is_response() returns false) it sends a single-prompt
 * challenge using the configured title, instruction, and prompt strings, then returns
 * @c SSH_AUTH_STATE_INFO. On the subsequent response call it reads the single answer,
 * passes it to @c susshi_chef_authn_interactive() for verification, and returns the result.
 * The answer is wiped from memory before returning. Disconnects with a protocol-error
 * code if the response contains a number of answers other than one.
 *
 * @ingroup     auth_client_methods
 *
 * @param       message     The @c ssh_message carrying the keyboard-interactive request or response
 *
 * @return      @c SSH_AUTH_STATE_INFO (challenge sent), @c SSH_AUTH_STATE_SUCCESS,
 *              @c SSH_AUTH_STATE_FAILED, or @c SSH_AUTH_STATE_ERROR
 */

static enum ssh_auth_state_e
susshi_client_auth_interactive(ssh_message message)
{
	const char *title = bdata(susshi_cfg.client_gateway_auth_title);
	const char *instruction = bdata(susshi_cfg.client_gateway_auth_instruction);
	const char *prompts[1];
	const char * cpassword;
	long timeout = 300;
	char echo[] = { 0 };
	enum ssh_auth_state_e resp = SSH_AUTH_STATE_ERROR;
	bstring password = NULL;

	prompts[0]= bdata(susshi_cfg.client_gateway_auth_prompt);

	/* Change timeout for session during interactive authentication */
	ssh_options_set(susshi_session.client_session, SSH_OPTIONS_TIMEOUT, &timeout);

	if (!ssh_message_auth_kbdint_is_response(message)) {
		/* Request */
		debug2_dir(GATEWAY, CLIENT, "Sending Keyboard Interactive request.");
		ssh_message_auth_interactive_request(message, title, instruction, 1, prompts, echo);
		resp = SSH_AUTH_STATE_INFO;

	} else {
		/* Response */
		int_store.auth_attempts++;

		if (ssh_userauth_kbdint_getnanswers(susshi_session.client_session) == 1) {

			debug2_dir(CLIENT, GATEWAY, "Received Keyboard Interactive response.");

			cpassword = ssh_userauth_kbdint_getanswer(susshi_session.client_session, 0);

			if ((cpassword != NULL) && ((password = bfromcstr(cpassword)) != NULL)) {

				resp = susshi_chef_authn_interactive(password);
				debug3_dir(CLIENT, GATEWAY, "Received password.");

				if (resp == SSH_AUTH_STATE_SUCCESS) {
					int_store.succeeded_auth_methods |= SSH_AUTH_METHOD_INTERACTIVE;
					susshi_client_auth_disable_method(SSH_AUTH_METHOD_PASSWORD);
					susshi_client_auth_disable_method(SSH_AUTH_METHOD_INTERACTIVE);
				}

				/* Store given password for target authentication if requested by chef */
				if ((resp == SSH_AUTH_STATE_SUCCESS) && (susshi_session.preserve_password)) {
					susshi_session.target_userpw = bstrcpy(password);
				}

				if (resp == SSH_AUTH_STATE_ERROR) {
					susshi_client_auth_disable_method(SSH_AUTH_METHOD_PASSWORD);
					susshi_client_auth_disable_method(SSH_AUTH_METHOD_INTERACTIVE);
					debug2_dir(GATEWAY, CLIENT, "Disabling methods Keyboard-Interactive and Password.");
				}

				/* Save client auth message for later usage on target auth */
				susshi_session.client_message = message;

				/* Wipe memory */
				memset(password->data, 'X', blength(password));
				bstrFree(password);
			} else {
				susshi_disconnect_standard(CLIENT, DISCONNECT_PROTOCOLL_ERROR);
			}
		} else {
			susshi_disconnect_standard(CLIENT, DISCONNECT_PROTOCOLL_ERROR);
		}
	}

	return resp;
}


/*!
 * @brief       Handle a public-key authentication request from the client
 *
 * Extracts the public key from @p message and inspects the signature state:
 * - @c SSH_PUBLICKEY_STATE_NONE: an unsigned probe — verifies the key is known via
 *   @c susshi_chef_authn_verify_pubkey() and, if so, replies with @c SSH_MSG_USERAUTH_PK_OK.
 *   Also enforces the configured @c public_key_algorithms allowlist.
 * - @c SSH_PUBLICKEY_STATE_VALID: a fully signed request already verified by libssh —
 *   confirms the key is known and marks publickey as succeeded on success.
 * - @c SSH_PUBLICKEY_STATE_WRONG: an invalid or disallowed signature — logs a warning
 *   and returns @c SSH_AUTH_STATE_FAILED.
 *
 * @ingroup     auth_client_methods
 *
 * @param       message     The @c ssh_message carrying the public-key authentication request
 *
 * @return      @c SSH_AUTH_STATE_SUCCESS, @c SSH_AUTH_STATE_FAILED, @c SSH_AUTH_STATE_PK_OK,
 *              or @c SSH_AUTH_STATE_ERROR
 */

static enum ssh_auth_state_e
susshi_client_auth_publickey(ssh_message message) {
	enum ssh_auth_state_e resp = SSH_AUTH_STATE_ERROR;
	ssh_key key;
	char *key_base64 = NULL;
	bstring key_base64_bstr = NULL;

	ssh_string key_blob = NULL;
	ssh_string key_type_str = NULL;


	if ((key = susshi_libssh_ssh_message_auth_pubkey(message)) != NULL) {
		int_store.auth_attempts++;

		if (ssh_key_is_public(key)) {

			ssh_pki_export_pubkey_base64(key, &key_base64);
			ssh_pki_export_pubkey_blob(key, &key_blob);

			if ((key_base64) && (key_blob)) {

				key_base64_bstr = bfromcstr(key_base64);

				switch (susshi_libssh_ssh_message_auth_publickey_state(message)) {

					/* PubKey is not signed (test message) */
					case SSH_PUBLICKEY_STATE_NONE: {
						const char *sig_algorithm = message->auth_request.sigtype;

						if_debug2() {
							const char *fp = NULL;
							do_debug3_dir(CLIENT, GATEWAY, "Received unsigned (test) public key: %s %s. Proposed signature algorithm is %s.",
									   susshi_ssh_key_type_to_char(key), fp = susshi_display_hash_from_key(key), sig_algorithm);
							if (fp)
								xfree((void *) fp);
						}

						/*
						 * For Chef-Remote commands, we have to allow the algorithms used by suSSHi Chef
						 *
						 * What is unclear, why the NET::SSH client is sending RSA key even when RSA is disabled at all?
						 */
						if (strcmp(bdata(susshi_session.susshi_user), SUSSHI_CHEF_REMOTE_USER) == 0) {
							ssh_options_set(susshi_session.client_session, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES, "ssh-ed25519,rsa-sha2-512,rsa-sha2-256");
							if (susshi_cfg.public_key_algorithms != NULL) {
								bstrFree(susshi_cfg.public_key_algorithms);
								susshi_cfg.public_key_algorithms = NULL;
							}
						}

						/* Check if PubKey algorithm is in list of allowed algorithms */
						if (susshi_cfg.public_key_algorithms != NULL) {
							debug4("Chef Remote access 2.");
							if (sig_algorithm) {
								if (match_group(bdata(susshi_cfg.public_key_algorithms),sig_algorithm) != 1) {
									const char *fp = NULL;

									log_system(LOG_LEVEL_INFO, "Received public key for '%s' with algorithm not allowed and fingerprint: %s / %s %s.",
											   bdata(susshi_session.susshi_user),
											   sig_algorithm, susshi_ssh_key_type_to_char(key), fp = susshi_display_hash_from_key(key));
									debug3("Allowed public key algorithms are %s.", bdata(susshi_cfg.public_key_algorithms));

									if (fp) xfree((void *) fp);
									resp = SSH_AUTH_STATE_FAILED;
									break;
								}
							} else {
								susshi_disconnect_standard(CLIENT, DISCONNECT_AUTH_AGENT_SIGNATURE_INVALID);
							}
						}

						if (susshi_chef_authn_verify_pubkey(key, key_base64)) {
							debug3_dir(GATEWAY, CLIENT,
									   "Key is acceptable. Sending SSH_MSG_USERAUTH_PK_OK message.");

							key_type_str = ssh_string_from_char(susshi_ssh_key_type_to_char(key));
							ssh_message_auth_reply_pk_ok(message, key_type_str, key_blob);
							SSH_STRING_FREE(key_type_str);

							resp = SSH_AUTH_STATE_PK_OK;
						} else {
							const char *fp = NULL;

							log_system(LOG_LEVEL_INFO, "Received unknown public key for '%s': %s %s.",
									   bdata(susshi_session.susshi_user),
									   susshi_ssh_key_type_to_char(key), fp = susshi_display_hash_from_key(key));
							debug3_dir(GATEWAY, CLIENT, "Key is not acceptable.");

							if (fp) xfree((void *) fp);
							resp = SSH_AUTH_STATE_FAILED;
						}
					} break;

					/* Message is signed and signature is already validated by libssh */
					case SSH_PUBLICKEY_STATE_VALID: {
						const char *fp = NULL;
						const char *sig_algorithm = message->auth_request.sigtype;

						if (susshi_session.susshi_userfp)
							bstrFree(susshi_session.susshi_userfp);

						susshi_session.susshi_userfp = bfromcstr(fp = susshi_display_hash_from_key(key));
						if (fp)
							xfree((void *) fp);

						debug3_dir(CLIENT, GATEWAY, "Received signed and valid public key: %s %s.",
								   susshi_ssh_key_type_to_char(key), bdata(susshi_session.susshi_userfp));

						if (susshi_chef_authn_verify_pubkey(key, key_base64)) {
							if (strcmp(bdata(susshi_session.susshi_user), SUSSHI_CHEF_REMOTE_USER) != 0) {
								log_system(LOG_LEVEL_INFO, "Publickey authentication for '%s' succeeded with algorithm and fingerprint: %s / %s %s.",
										   bdata(susshi_session.susshi_user),
										   sig_algorithm, susshi_ssh_key_type_to_char(key), bdata(susshi_session.susshi_userfp));
							}
							int_store.succeeded_auth_methods |= SSH_AUTH_METHOD_PUBLICKEY;
							susshi_client_auth_disable_method(SSH_AUTH_METHOD_PUBLICKEY);

							resp = SSH_AUTH_STATE_SUCCESS;
						} else {
							resp = SSH_AUTH_STATE_FAILED;
						};
					} break;

					case SSH_PUBLICKEY_STATE_WRONG: {
						const char *fp = NULL;
						const char *sig_algorithm = message->auth_request.sigtype;

						log_system(LOG_LEVEL_WARNING, "Received invalid signature or signature with algorithm not allowed and fingerprint: %s / %s %s.",
								   sig_algorithm, susshi_ssh_key_type_to_char(key), fp = susshi_display_hash_from_key(key));

						if (fp) xfree((void *) fp);
						resp = SSH_AUTH_STATE_FAILED;
					} break;

					default:
						debug4("Run into state %d.", susshi_libssh_ssh_message_auth_publickey_state(message));
						resp = SSH_AUTH_STATE_ERROR;
				}
				bstrFree(key_base64_bstr);
				xfree(key_base64);
				SSH_STRING_FREE(key_blob);
			}
		} else {
			debug3_dir(CLIENT, GATEWAY, "Received key, but is not public key.");
		}
		SSH_KEY_FREE(key);
	}
	return resp;
}


/*!
 * @brief       Send OpenID Connect authentication prompt banners to the client
 *
 * Transmits the configured title and instruction strings as SSH authentication banners,
 * then reads and discards one pending message from the client session to flush the
 * protocol exchange before the OIDC wait begins.
 *
 * @ingroup     auth_client_methods
 */

static void
susshi_client_auth_openid_connect_start(void)
{
	bstring text;

	debug2_dir(GATEWAY, CLIENT, "Sending Message for OpenID Connect Authentication.");

	/* Title */
	text = bformat("%s\n", bdata(susshi_cfg.client_gateway_auth_title));
	susshi_client_send_banner(bdata(text));
	bstrFree(text);

	/* Instruction */
	text = bformat("%s\n", bdata(susshi_cfg.client_gateway_auth_instruction));
	susshi_client_send_banner(bdata(text));
	bstrFree(text);

	ssh_message_get(susshi_session.client_session);
}


/*!
 * @brief       Block until suSSHi Chef signals OIDC authentication success, or until timeout
 *
 * Waits for a @c SIGIO signal (sent by the Chef master process via a remote command) using
 * @c sigtimedwait(). Returns immediately if the signal arrives within @p timeout seconds.
 * Calls @c fatal() on unexpected signal errors.
 *
 * @ingroup     auth_client_methods
 *
 * @param       timeout     Maximum time to wait in seconds
 *
 * @return      @c true if the @c SIGIO signal was received before the deadline,
 *              @c false if @p timeout expired without a signal
 */

static bool
susshi_client_auth_openid_connect_wait(int timeout)
{
	int sig;
	sigset_t set;
	siginfo_t info;

	struct timespec timer = { .tv_sec = timeout, .tv_nsec = 0 };

	/* Wait for signal from master-process (sent by chef remote command) */
	sigemptyset(&set);
	sigaddset(&set, SIGIO);

	debug3("Waiting for user to be authenticated via OpenID Connect (OIDC)");

	sigprocmask(SIG_BLOCK, &set, NULL);

	sig = sigtimedwait(&set, &info, &timer);

	if (sig == -1) {
		if (errno == EAGAIN) {
			debug3("Timeout expired (no signal within time)");
		} else {
			fatal("Fatal error while waiting for Openid Connect signal");
		}
	} else {
		debug3("Got 'authentication succeeded' signal from PID %d", info.si_pid);

		return true;
	}
	return false;
}


/*!
 * @brief       Send an @c SSH2_MSG_USERAUTH_BANNER message to the client
 *
 * Packs and transmits a raw SSH authentication banner packet. Unlike
 * @c susshi_client_send_issue_banner(), this function always sends immediately
 * and places no restrictions on the content of @p msg.
 *
 * @param       msg     NUL-terminated banner text to send; must not be @c NULL
 */

void
susshi_client_send_banner(const char *msg)
{
	ssh_buffer_pack(susshi_session.client_session->out_buffer, "bss",
					SSH2_MSG_USERAUTH_BANNER,
					msg,
					"");

	ssh_packet_send(susshi_session.client_session);
}


/*!
 * @brief       Send the configured login (issue) banner to the client
 *
 * Reads the banner text from @c susshi_cfg.banner and transmits it via
 * @c susshi_client_send_banner(). Does nothing if the banner is @c NULL
 * or its value equals @c "none" (case-insensitive). The call site is responsible
 * for ensuring this is called at most once per session.
 */

static void
susshi_client_send_issue_banner(void) {

	if (susshi_cfg.banner == NULL || strcasecmp(bdata(susshi_cfg.banner), "none") == 0)
		return;

	debug1_dir(GATEWAY, CLIENT, "Sending login banner");
	debug2_dir(GATEWAY, CLIENT, "Login banner:\n%s", bdata(susshi_cfg.banner));

	susshi_client_send_banner(bdata(susshi_cfg.banner));
}

/*! @} */


