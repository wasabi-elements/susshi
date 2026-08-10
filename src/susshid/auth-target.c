/*!
 *
 * @brief       Target Authentication methods
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
 * @defgroup    auth_target Target Authentication
 * @{
 *
 * @defgroup    auth_target_methods Target Authentication (authentication methods)
 * @brief       Specific target authentication methods
 * @ingroup     auth_target
 */

#include <susshid/common.h>


/*! @cond */
static struct {
	int allowed_auth_methods;
	int available_target_auth_methods;
	TargetAuthMethod *active_method;
	ssh_message message;
	TargetIdentity target_context_identities[MAX_USERKEYS];
	int num_target_context_identities;
	bool send_issue_banner;
} int_store = {
		.allowed_auth_methods = 0,
		.available_target_auth_methods = 0,
		.active_method = NULL,
		.send_issue_banner = true,
		.num_target_context_identities = 0
};
/*! @endcond */

/* Prototypes */
static int susshi_target_auth_pubkey(void);
static int susshi_target_auth_hostbased(void);
static int susshi_target_auth_pubkey_pre_sshagent(void);
static int susshi_target_auth_interactive(void);
static int susshi_target_auth_password(void);
static int susshi_target_auth_load_chef_context_identities(void);
static void susshi_target_auth_continue_or_abort_interactive(int rc);
static enum ssh_keytypes_e susshi_target_auth_keytype_from_string(const char *string);
static bstring susshi_target_auth_methods_list(int auth_methods);

TargetAuthMethod target_auth_methods[] = {
		{ SSH_AUTH_METHOD_PUBLICKEY,
				"publickey",
				&susshi_target_auth_pubkey,
				true,
				true },
		{ SSH_AUTH_METHOD_PUBLICKEY,
				"publickey-ssh-agent",
				&susshi_target_auth_pubkey_pre_sshagent,
				true,
				false },
		{ SSH_AUTH_METHOD_HOSTBASED,
				"hostbased",
				&susshi_target_auth_hostbased,
				false,
				false },
		{ SSH_AUTH_METHOD_INTERACTIVE,
				"keyboard-interactive",
				&susshi_target_auth_interactive,
				true,
				true },
		{ SSH_AUTH_METHOD_PASSWORD,
				"password",
				&susshi_target_auth_password,
				true,
				true },
		{ SSH_AUTH_METHOD_NONE,
				NULL,
				NULL,
				true,
				false }
};

static const char *password_source[] = {
		"user dialog", "preserve password", "static password", "dynamic otp"
};

/* Prototypes */
static bool susshi_target_auth_dispatch(void);


/*!
 * @brief       Find the index of an enabled authentication method by its alias name
 *
 * Searches @c target_auth_methods for an entry whose @c alias matches @p method
 * (case-insensitive) and whose @c enabled flag is set.
 *
 * @param       method      Method alias to search for (e.g. @c "publickey", @c "password")
 *
 * @return      Zero-based index into @c target_auth_methods, or @c -1 if not found or disabled
 */

int
susshi_target_auth_find_method(bstring method) {
	int i;

	for(i = 0; target_auth_methods[i].alias; i++) {
		if (strcasecmp(target_auth_methods[i].alias, bdata(method)) == 0) {
			if (target_auth_methods[i].enabled)
				return i;
		}
	}
	return -1;
}


/*!
 * @brief       Populate @c susshi_cfg with the default set of target authentication methods
 *
 * Iterates @c target_auth_methods and appends the index of every entry whose
 * @c enable_by_default flag is @c true to
 * @c susshi_cfg.global.target_preferred_authentications, incrementing the
 * corresponding counter. Preserves the order defined in @c target_auth_methods.
 */

void
susshi_target_auth_method_fill_susshi_cfg(void) {
	int i;
	for(i = 0; target_auth_methods[i].alias; i++) {
		if (target_auth_methods[i].enable_by_default) {
			susshi_cfg.global.target_preferred_authentications[susshi_cfg.global.num_target_preferred_authentications] = i;
			susshi_cfg.global.num_target_preferred_authentications++;
		}
	}
}


/*!
 * @brief       Initialize the target-side authentication state machine and run it to completion
 *
 * Sets the session phase to @c PHASE_AUTH_START and sends @c ssh_userauth_none to
 * obtain the target's allowed authentication methods. Returns @c true immediately if
 * the target accepts none-authentication. Otherwise enters the authentication dispatch
 * loop, optionally forwarding any received issue banner to the client on success.
 * Wipes @c target_userpw from memory before returning.
 *
 * @return      @c true if the target was authenticated successfully, @c false otherwise
 */

bool
susshi_target_auth(void) {

	bool success = false;
	char *issue_banner;
	int rc;

	susshi_session.target_phase = PHASE_AUTH_START;
	susshi_ssh_set_session_state(susshi_session.target_session, SSH_SESSION_STATE_AUTHENTICATING);

	debug1("Target authentication started.");

	// Initialize int_store
	memset((void *) &int_store, 0, sizeof(int_store));
	int_store.send_issue_banner = true;

	SETPROCTITLE("%s (Target-Auth) %s@%s",
				 bdata(susshi_session.susshi_uniqid),
				 bdata(susshi_session.susshi_user),
				 bdata(susshi_session.target_identifier));

	/* Send none auth request to receive allowed authentication methods */
	rc = ssh_userauth_none(susshi_session.target_session, NULL);

	if (rc == SSH_AUTH_SUCCESS) {
		return true;
	} else {
		if (rc != SSH_AUTH_ERROR) {
			/* Check if target sends an issue banner */
			issue_banner = ssh_get_issue_banner(susshi_session.target_session);

			success = susshi_target_auth_dispatch();

			if ((success) && (int_store.send_issue_banner)) {
				/* Send issue_banner only on successful authentication - otherwise disconnecting the client with
				 * a message breaks. Reason seems to be that some/all clients (for unknown reason) ignore the disconnect
				 * message after receiving an USERAUTH_BANNER */
				if (issue_banner) {
					log_session(TARGET, GATEWAY, "Received Issue Banner from target. Will forward to client.");
					debug2_dir(TARGET, GATEWAY, "Received Issue Banner from target. Will forward to client.");

					susshi_client_send_banner(issue_banner);
				}
			}
			if (issue_banner)
				xfree(issue_banner);
		} else {
			debug1_dir(TARGET, GATEWAY, "Target authentication failed with %s", ssh_get_error(susshi_session.target_session));
			susshi_session.disconnect_message = "Target disconnected in authentication start phase. This could also indicate a defective crypto library (e.g. old openssl library) on target!";
		}
	}

	if (susshi_session.client_message != NULL) {
		ssh_message_free(susshi_session.client_message);
	}

	/* Wipe memory */
	if (susshi_session.target_userpw != NULL) {
		bstrWipe(susshi_session.target_userpw);
		susshi_session.target_userpw = NULL;
	}

	return success;
}


/*!
 * @brief       Authentication method loop: select and invoke target authentication methods in preferred order
 *
 * After each attempt, refreshes the list of methods still accepted by the target via
 * @c ssh_userauth_list(). Picks the next method from the session's
 * @c target_preferred_authentications list that is both enabled and still offered by the target.
 * Loops until authentication succeeds, the target or client disconnects, or no further
 * methods are available. On failure, sets @c susshi_session.disconnect_message with a
 * human-readable description of what was tried.
 *
 * @return      @c true if target authentication completed successfully, @c false otherwise
 */

static bool
susshi_target_auth_dispatch(void) {

	int m;
	u_int i;
	int rc = SSH_AUTH_ERROR;


	do {
		/* Save allowed Authentication methods */
		int_store.allowed_auth_methods = ssh_userauth_list(susshi_session.target_session, NULL);
		if (int_store.available_target_auth_methods == 0) {
			int_store.available_target_auth_methods = int_store.allowed_auth_methods;
		}

		if (susshi_session.operation_mode == OP_MODE_BASTION) {
			int_store.available_target_auth_methods &= SSH_AUTH_METHOD_PUBLICKEY;
		}

		/* No more auth methods available on target side */
		if (int_store.allowed_auth_methods == 0)
			return false;

		/* active_method not set, active_method no longer in list of allowed methods or active_method disabled */
		if (    (int_store.active_method == NULL)
			|| !(int_store.allowed_auth_methods & int_store.active_method->method)
			|| !(int_store.active_method->enabled) ) {

			/* Find next auth method */
			int_store.active_method = NULL;

			/* Find first in list of preferred order */
			for (i = 0; i < susshi_cfg.session.num_target_preferred_authentications; i++) {
				m = susshi_cfg.session.target_preferred_authentications[i];
				if (target_auth_methods[m].enabled) {
					if (int_store.allowed_auth_methods & target_auth_methods[m].method) {
						int_store.active_method=&target_auth_methods[m];
						break;
					}
				}
			}
		}

		if ((int_store.active_method != NULL) && (int_store.active_method->auth_function != NULL)) {

			/* Call Auth Method Function */
			rc = int_store.active_method->auth_function();

			switch(rc) {
				case SSH_AUTH_SUCCESS:
					log_session(TARGET, GATEWAY, "Target authentication completed successfully with method '%s'.", int_store.active_method->alias);
					debug2_dir(TARGET, GATEWAY, "Target authentication completed successfully with method '%s'.", int_store.active_method->alias);
					susshi_session.target_authmethod = bfromcstr(int_store.active_method->alias);
					susshi_session.target_authenticated = true;
					susshi_session.target_phase = PHASE_AUTHENTICATED;
					return true;

				case SSH_AUTH_DENIED:
					/* We are already in target authentication, so client is always authenticated */
					log_session(TARGET, GATEWAY, "Target denied access with method '%s'.", int_store.active_method->alias);
					break;

				case SSH_AUTH_ERROR:
					log_session(TARGET, GATEWAY, "Target returned with authentication error for method '%s'.", int_store.active_method->alias);
					if (strcmp(int_store.active_method->alias, "publickey-ssh-agent") == 0) {
						susshi_session.disconnect_message = "Authentication on target failed. User key(s) loaded into SSH agent may not be accepted by target or maximum authentication attempts are reached.";
					} else {
						susshi_session.disconnect_message = "Target returned with a serious authentication error.";
					}
					break;

				case SSH_AUTH_PARTIAL:
					log_session(TARGET, GATEWAY, "Target returned with a authentication partial success message for method '%s'.", int_store.active_method->alias);
					break;
				default:
					return false;
			}
		} else {
			/* No more auth methods available on our side */
			int tm = 0;
			bstring allowed_in_session = NULL, allowed_on_target = NULL, message = NULL;
			for (i = 0; i < susshi_cfg.session.num_target_preferred_authentications; i++)
				tm |= target_auth_methods[susshi_cfg.session.target_preferred_authentications[i]].method;

			if (susshi_session.disconnect_message == NULL) {
				allowed_in_session = susshi_target_auth_methods_list(tm);
				allowed_on_target = susshi_target_auth_methods_list(int_store.available_target_auth_methods);
				message = bformat("Authentication failed. No more auth methods available. Tried %s. Target server supports %s.",
								  bdata(allowed_in_session), bdata(allowed_on_target));
				susshi_session.disconnect_message = bdata(message);
				bstrFree(allowed_in_session);
				bstrFree(allowed_on_target);
			}

			return false;
		}

	} while(ssh_is_connected(susshi_session.target_session) && ssh_is_connected(susshi_session.client_session));

	return false;
}


/*!
 * @brief       Authenticate against the target using public-key authentication
 *
 * First probes each available identity with @c ssh_userauth_try_publickey() to find
 * one the target will accept, then imports and sends the corresponding private key via
 * @c ssh_userauth_publickey(). Uses Chef session context identities when available,
 * falling back to the global gateway identities. The private key is freed immediately
 * after use. Disables this method on exit regardless of outcome.
 *
 * @ingroup     auth_target_methods
 *
 * @return      @c SSH_AUTH_SUCCESS on success, otherwise an @c SSH_AUTH_* error or denied code
 */

static int
susshi_target_auth_pubkey(void) {
	int k, use_key = -1, num_keys;
	int rc = SSH_AUTH_ERROR;
	long timeout = 30;
	bool context_keys = false;
	int ssh_ret;
	enum ssh_keytypes_e ssh_key_type;

	TargetIdentity *target_identity = NULL;
	bstrList split_public_blob = NULL;
	ssh_key public_key = NULL;
	ssh_key private_key = NULL;

	/* Change timeout for session during public key authentication */
	ssh_options_set(susshi_session.client_session, SSH_OPTIONS_TIMEOUT, &timeout);

	// Check if we have context identities or use (global) gateway identities
	if ((num_keys = susshi_target_auth_load_chef_context_identities()) > 0) {
		context_keys = true;
	} else {
		num_keys = susshi_cfg.num_target_identities;
	}

	// Iterate Keys and send them to target to probe which key may fit
	for (k = 0; ((k < num_keys) && (rc != SSH_AUTH_SUCCESS)); k++) {

		target_identity = context_keys ? &int_store.target_context_identities[k] : &susshi_cfg.target_identities[k];

		split_public_blob = bsplit(target_identity->public_blob, ' ');
		ssh_key_type = susshi_target_auth_keytype_from_string(bdata(target_identity->key_type));
		ssh_ret = ssh_pki_import_pubkey_base64(bdata(split_public_blob->entry[1]), ssh_key_type, &public_key);

		if (ssh_ret == SSH_OK) {
			if (ssh_key_is_public(public_key) == true) {

				debug3_dir(GATEWAY, TARGET, "Trying public %s key #%d: %s %s.", context_keys ? "context" : "gateway",
						   k + 1, bdata(target_identity->key_type), bdata(target_identity->fingerprint));

				rc = ssh_userauth_try_publickey(susshi_session.target_session, bdata(susshi_session.target_user),
												public_key);

				if (rc == SSH_AUTH_SUCCESS) {
					use_key = k;
					debug3_dir(TARGET, GATEWAY, "Target will accept key #%d", use_key + 1);
				}
			} else {
				log_system(LOG_LEVEL_WARNING,
						   "Could not import %s identity #%d. Seems to not be a public key in known format. Skipping.",
						   context_keys ? "context" : "gateway", k);
			}
		} else {
			log_system(LOG_LEVEL_WARNING, "Could not import %s identity #%d. Skipping.",
					   context_keys ? "context" : "gateway", k);
		}
		bstrListDestroy(split_public_blob);
		SSH_KEY_FREE(public_key);
	}

	// If one key fits, send it again, but now signed
	if ((rc == SSH_AUTH_SUCCESS) && (use_key > -1)) {

		rc = ssh_pki_import_privkey_base64(bdata(target_identity->private_blob), NULL,
										 susshi_memcrypt_ssh_privkey_callback,
										 bdata(susshi_cfg.installation_id),
										 &private_key);

		if (rc == SSH_OK) {
			if (ssh_key_is_private(private_key) == 1) {
				debug3_dir(GATEWAY, TARGET, "Sending signed public key #%d: %s %s.", use_key + 1,
						   bdata(target_identity->key_type), bdata(target_identity->fingerprint));

				rc = ssh_userauth_publickey(susshi_session.target_session, bdata(susshi_session.target_user),
											private_key);

				debug4("Burning target authentication private key.");
				SSH_KEY_FREE(private_key);
			} else {
				rc = SSH_ERROR;
				log_system(LOG_LEVEL_ERROR,
						   "Could not import %s identity #%d. Seems to not be a valid private key in known format. Aborting.",
						   context_keys ? "context" : "gateway", use_key);
			}
		} else {
			log_system(LOG_LEVEL_ERROR,
					   "Could not import %s identity #%d. Seems to not be a valid private key in known format. Aborting.",
					   context_keys ? "context" : "gateway", use_key);
		}
	}

	// Disable this method
	int_store.active_method->enabled = false;

	return (rc);
}



/*!
 * @brief       Stub for host-based target authentication (not yet implemented)
 *
 * Always disables itself and returns @c SSH_AUTH_DENIED. Hostbased authentication
 * with the suSSHi gateway hostkeys is not implemented.
 *
 * @ingroup     auth_target_methods
 *
 * @return      @c SSH_AUTH_DENIED (always)
 */

static int
susshi_target_auth_hostbased(void) {
	debug1_dir(GATEWAY, TARGET, "Trying hostbased authentication with " SUSSHI_NAME " gateway hostkeys.");

	int_store.active_method->enabled = false;
	return(SSH_AUTH_DENIED);
}


/*!
 * @brief       Authenticate against the target by forwarding the client's SSH agent
 *
 * Completes client-side authentication first (@c susshi_client_auth_finish(true)), then
 * calls @c susshi_pubkey_agent_client_ready() to negotiate agent forwarding with the
 * client and authenticate the target using keys held in the client's SSH agent
 * (see @c auth-pubkey-agent.c). Disables all other target authentication methods once
 * the client authentication phase is finished, since the client session can no longer
 * be used for further auth exchanges.
 *
 * @ingroup     auth_target_methods
 *
 * @return      @c SSH_AUTH_SUCCESS on success, otherwise an @c SSH_AUTH_* error code
 */

static int
susshi_target_auth_pubkey_pre_sshagent(void) {

	int rc = SSH_AUTH_ERROR;
	long timeout = 30;

	debug1_dir(GATEWAY, TARGET, "Trying pubkey authentication in ssh agent mode.");

	/* Set allowed public key algorithms for target authentication */
	if (susshi_cfg.public_key_algorithms != NULL)
		ssh_options_set(susshi_session.target_session, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES, bdata(susshi_cfg.public_key_algorithms));

	/* Change timeout for client session during public key authentication */
	ssh_options_set(susshi_session.client_session, SSH_OPTIONS_TIMEOUT, &timeout);

	/* Finish client authentication successful */
	susshi_client_auth_finish(true);

	/* Talk to client until we are able to send SSH Agent requests */
	rc = susshi_pubkey_agent_client_ready();

	int_store.send_issue_banner = false;

	int_store.active_method->enabled = false;

	/* Disable all other methods because we've finished authentication phase with client */
	debug3("Disabling all other target auth methods because we've finished authentication phase with client.");

	for (int i = 0; target_auth_methods[i].method != SSH_AUTH_METHOD_NONE; i++) {
		target_auth_methods[i].enabled = false;
	}

	return(rc);
}


/*!
 * @brief       Authenticate against the target using keyboard-interactive, relaying prompts to the client
 *
 * Implements a state machine (@c S_INIT, @c S_TARGET_INFO, @c S_CLIENT_START,
 * @c S_CLIENT_WAIT, @c S_CLIENT_ANSWER, @c S_TARGET_AGAIN) that bridges the
 * keyboard-interactive exchange between the target and the client. Supports
 * multiple password sources (@c PWS_DIALOG, @c PWS_PRESERVE, @c PWS_STATIC,
 * @c PWS_DOTP): in dialog mode the client is prompted interactively; in other
 * modes the stored @c target_userpw is submitted automatically. Wipes
 * @c target_userpw from memory and resets the password source to @c PWS_DIALOG
 * before returning.
 *
 * @ingroup     auth_target_methods
 *
 * @return      @c SSH_AUTH_SUCCESS on success, otherwise an @c SSH_AUTH_* error or denied code
 */

static int
susshi_target_auth_interactive(void) {
	// static int attempts = 0;
	int rc = SSH_AUTH_ERROR;
	int num_answers;
	int num_prompts;
	const char **prompts;
	char *echos;
	const char *instruction;
	const char *name;
	int i;
	long timeout = 300;
	static bool client_banner_sent = false;

	KbdIntStates state = S_INIT;

	/* Change timeout for client session during interactive authentication */
	ssh_options_set(susshi_session.client_session, SSH_OPTIONS_TIMEOUT, &timeout);

	debug1_dir(GATEWAY, TARGET, "Trying keyboard-interactive authentication in mode '%s'.",
			   password_source[susshi_session.target_password_source]);

	/* (Re-)enable keyboard-interactive auth if disabled by interactive user authentication before */
	susshi_client_auth_enable_method(SSH_AUTH_METHOD_INTERACTIVE);

	/* Disable password method with client if still set */
	susshi_client_auth_disable_method(SSH_AUTH_METHOD_PASSWORD);

	while ((rc != SSH_AUTH_SUCCESS) && (rc != SSH_AUTH_DENIED)
		   && (ssh_is_connected(susshi_session.target_session)) && (ssh_is_connected(susshi_session.client_session))) {

		switch (state) {
			case S_INIT: {
				/* ----- Initialize ------------------------------------------- */

				/* Send USERAUTH_REQUEST to target */
				rc = ssh_userauth_kbdint(susshi_session.target_session, bdata(susshi_session.target_user), NULL);

				switch (rc) {
					case SSH_AUTH_DENIED:
						int_store.active_method->enabled = false;
						break;
					case SSH_AUTH_INFO:
						state = S_TARGET_INFO;
						break;
					case SSH_AUTH_ERROR:
						return rc;
				}
			} break;

			case S_TARGET_INFO: {
				/* ----- Info from Target ------------------------------------------- */

				instruction = ssh_userauth_kbdint_getinstruction(susshi_session.target_session);
				num_prompts = ssh_userauth_kbdint_getnprompts(susshi_session.target_session);

				if (num_prompts > 0) {
					prompts = xmalloc(num_prompts * sizeof(char *));
					echos = xmalloc(num_prompts * sizeof(char));
					debug2_dir(TARGET, GATEWAY, "We've got info with %d prompt(s) from target.", num_prompts);

					for (i = 0; i < num_prompts; i++) {
						prompts[i] = ssh_userauth_kbdint_getprompt(susshi_session.target_session, i, &echos[i]);
					}

					switch(susshi_session.target_password_source) {

						case PWS_DIALOG: {

							if ((susshi_session.use_extracted_password == true) &&
								(susshi_session.target_userpw != NULL) &&
								(blength(susshi_session.target_userpw) > 0) &&
								(num_prompts == 1) &&
								(strncasecmp(prompts[0], "passwor", 7) == 0)) {

								/* We have an extracted password and will try to use it */

								debug2_dir(GATEWAY, TARGET, "We use the password extracted from gateway password and try it against target.");

								/* We have a password for target, so we will try to login with this password. */
								ssh_userauth_kbdint_setanswer(susshi_session.target_session, 0,
															  bdata(susshi_session.target_userpw));
								rc = ssh_userauth_kbdint(susshi_session.target_session, NULL, NULL);

								if (rc == SSH_AUTH_DENIED) {
									log_session(GATEWAY, TARGET,
												"Tried with extracted password (after split-string), but authentication with the gateway password failed for target.");
								}

								susshi_session.use_extracted_password = false;

							} else {
								/* We have no password for target */

								debug2("Preparing info for client with %d prompt(s).", num_prompts);

								if (client_banner_sent == false) {

									debug2("We will include a short message to client to inform the user that he now enters target credentials.");

									name = "Target Authentication";
									instruction = "\nAuthentication at " SUSSHI_NAME " gateway successfully completed."
												  "\nPlease authenticate yourself at the target.\n";
									client_banner_sent = true;
								} else {
									name = ssh_userauth_kbdint_getname(susshi_session.target_session);
								}

								state = S_CLIENT_START;
								continue;

							}

						} break;

						case PWS_PRESERVE:
						case PWS_STATIC:
						case PWS_DOTP: {

							if ((susshi_session.target_userpw != NULL) &&
								(blength(susshi_session.target_userpw) > 0) &&
								(num_prompts == 1) &&
								(strncasecmp(prompts[0], "passwor", 7) == 0)) {

								/* We have a password for target, so we will try to login with this password. */
								ssh_userauth_kbdint_setanswer(susshi_session.target_session, 0,
															  bdata(susshi_session.target_userpw));
								rc = ssh_userauth_kbdint(susshi_session.target_session, NULL, NULL);


								if (rc == SSH_AUTH_DENIED) {
									log_session(GATEWAY, TARGET,
												"Profile mode '%s', but authentication with given password failed for target.",
												password_source[susshi_session.target_password_source]);
								}

							} else {
								log_session(GATEWAY, TARGET,
											"Profile mode '%s', but no password given.",
											password_source[susshi_session.target_password_source]);
								rc = SSH_AUTH_ERROR;
							}

						} break;

						default:
							break;
					}

					switch (rc) {
						case SSH_AUTH_INFO:
							state = S_TARGET_INFO;
							break;
						case SSH_AUTH_ERROR:
							state = S_INIT;
							break;
						case SSH_AUTH_AGAIN:
							state = S_TARGET_AGAIN;
					}

					susshi_target_auth_continue_or_abort_interactive(rc);

					/* Reset to default PWS_DIALOG */
					susshi_session.target_password_source = PWS_DIALOG;

					/* Wipe memory */
					if (susshi_session.target_userpw != NULL) {
						memset(susshi_session.target_userpw->data, 'X', blength(susshi_session.target_userpw));
						bstrFree(susshi_session.target_userpw);
						susshi_session.target_userpw = NULL;
					}

				} else {
					/* The server can send an empty question set */
					rc = ssh_userauth_kbdint(susshi_session.target_session, NULL, NULL);
				}
			} break;

			case S_CLIENT_START: {

				/* Finish client authentiation */
				susshi_client_auth_finish(false);

				if (susshi_session.client_message == NULL) {
					/* We do not already have a keyboard interactive session with client */
					susshi_session.client_message = ssh_message_get(susshi_session.client_session);
				}

				if (!ssh_is_connected(susshi_session.client_session)) {
					susshi_disconnect_standard(BOTH, DISCONNECT_AUTH_FAILED);
				}

				debug2_dir(GATEWAY, CLIENT, "Sending short message and %d prompt(s) to client.", num_prompts);

				susshi_session.client_session->kbdint = NULL;
				ssh_message_auth_interactive_request(susshi_session.client_message, name,
													 instruction, (uint) num_prompts, prompts, echos);
				susshi_ssh_set_auth_state(susshi_session.client_session, SSH_AUTH_STATE_INFO);
				xfree(prompts);
				xfree(echos);

				state = S_CLIENT_WAIT;

			} break;

			case S_CLIENT_WAIT: {
				/* ----- Wait for client answer ------------------------------------------- */

				susshi_session.client_message = ssh_message_get(susshi_session.client_session);

				if (susshi_session.client_message) {
					/* We got answer from client */
					state = S_CLIENT_ANSWER;
				} else {
					/* Fatal */
					rc = SSH_AUTH_DENIED;
				}

			} break;

			case S_CLIENT_ANSWER: {
				/* ----- Answer(s) from Client ------------------------------------------- */

				num_answers = ssh_userauth_kbdint_getnanswers(susshi_session.client_session);

				if (num_answers > 0) {

					debug2_dir(CLIENT, GATEWAY, "We've got keyboard-interactive with %d answer(s) from client", num_answers);

					// attempts++;

					for (i = 0; i < num_answers; i++) {
						const char *answer;
						answer = ssh_userauth_kbdint_getanswer(susshi_session.client_session, i);
						ssh_userauth_kbdint_setanswer(susshi_session.target_session, i, answer);
					}

					/* Send Answers to Target */
					debug2_dir(GATEWAY, TARGET, "Sending keyboard-interactive with %d answer(s) to target",
							   num_answers);

					rc = ssh_userauth_kbdint(susshi_session.target_session, bdata(susshi_session.target_user), NULL);

					S_CLIENT_ANSWER_rc:

					switch (rc) {
						case SSH_AUTH_DENIED:
							debug2_dir(GATEWAY, CLIENT,
									   "Finish client auth again to go on with next method (or the same method on client's decision).");
							break;
						case SSH_AUTH_INFO:
							state = S_TARGET_INFO;
							break;
						case SSH_AUTH_ERROR:
							state = S_INIT;
							break;
						case SSH_AUTH_AGAIN:
							state = S_TARGET_AGAIN;
					}
				} else {
					state = S_CLIENT_WAIT;
				}
			} break;

			case S_TARGET_AGAIN: {
				/* ----- Send Answer(s) from Client to Target again ---------------------- */
				debug2_dir(GATEWAY, TARGET, "Sending keyboard-interactive with %d answer(s) to target again",
						   num_answers);

				rc = ssh_userauth_kbdint(susshi_session.target_session, bdata(susshi_session.target_user), NULL);

				goto S_CLIENT_ANSWER_rc;
			} break;
		}
	}
	return rc;
}


/*!
 * @brief       Send a keyboard-interactive password prompt to the client for target authentication
 *
 * On the first attempt (@p first_attempt is @c true), includes a contextual instruction
 * message informing the user that gateway authentication succeeded and target credentials
 * are now required, along with a prompt of the form @c "user@host's password:".
 * On subsequent attempts, sends only a "Permission denied, please try again" title with
 * the same password prompt.
 *
 * @ingroup     auth_target_methods
 *
 * @param       message         The pending @c ssh_message to reply to with the interactive request
 * @param       first_attempt   @c true to include the introductory instruction text, @c false for retry
 */

static void
susshi_client_auth_kbdint_send_request(ssh_message message, bool first_attempt) {
	bstring instruction = NULL;
	bstring portbuf = NULL;
	bstring prompt = NULL;
	const char *prompts[1];
	char echo[] = { 0 };

	prompt = bformat("%s@%s's password:", bdata(susshi_session.target_user), bdata(susshi_session.target_host));
	prompts[0] = bdata(prompt);

	if (!ssh_is_connected(susshi_session.client_session)) {
		susshi_disconnect_standard(BOTH, DISCONNECT_AUTH_FAILED);
	}

	if (first_attempt) {

		debug2_dir(GATEWAY, CLIENT, "Sending Keyboard Interactive request.");
		debug2_dir(GATEWAY, CLIENT, "We will include a short message to inform the user that he now enters target credentials.");

		if (susshi_session.target_port != 22)
			portbuf = bformat(":%d", susshi_session.target_port);
		else
			portbuf = bfromcstr("");

		instruction = bformat("Entering password authentication. Please enter password for %s@%s%s.\n",
							  bdata(susshi_session.target_user), bdata(susshi_session.target_host), bdata(portbuf));

		ssh_message_auth_interactive_request(message, "\nAuthentication on " SUSSHI_NAME " gateway completed successfully",
											 bdata(instruction), 1, prompts, echo);

		bstrFree(instruction);
		bstrFree(portbuf);
	} else {
		ssh_message_auth_interactive_request(message, "Permission on target denied, please try again", "", 1, prompts, echo);
	}
}


/*!
 * @brief       Collect a password from the client via keyboard-interactive or password auth and use it against the target
 *
 * Accepts either a @c SSH_REQUEST_AUTH password message or a keyboard-interactive
 * response from the client. Tries the supplied password against the target with
 * @c ssh_userauth_password(), re-prompting on failure for up to three attempts.
 * Disconnects the client with a protocol-error code if no response is received within
 * the configured timeout.
 *
 * @ingroup     auth_target_methods
 *
 * @return      @c SSH_AUTH_SUCCESS on success, @c SSH_AUTH_DENIED after exhausting retries
 */

static int
susshi_client_auth_kbdint_or_password(void) {

	int rc = SSH_AUTH_DENIED;
	long timeout = 300;
	const char *password = NULL;
	int attempts = 0;
	static bool request_send = false;

	/* (Re-)enable keyboard-interactive auth if disabled by interactive user authentication before */
	susshi_client_auth_enable_method(SSH_AUTH_METHOD_INTERACTIVE);

	/* Change timeout for session during interactive authentication */
	ssh_options_set(susshi_session.client_session, SSH_OPTIONS_TIMEOUT, &timeout);

	while ((rc != SSH_AUTH_SUCCESS) && (attempts < 3)) {

		if (request_send == false) {

			if (susshi_session.client_message == NULL) {
				/* We do not already have a keyboard interactive session with client or received a password */
				susshi_session.client_message = ssh_message_get(susshi_session.client_session);
			}

			if ((ssh_message_type(susshi_session.client_message) == SSH_REQUEST_AUTH) &&
			   ((password = susshi_libssh_ssh_message_auth_password(susshi_session.client_message)) != NULL)) {
				/* Password received */
				attempts++;
				debug2_dir(CLIENT, GATEWAY, "Received password / Attempt %d", attempts);
				rc = ssh_userauth_password(susshi_session.target_session, NULL, password);
				if (rc == SSH_AUTH_SUCCESS) {
					return rc;
				} else {
					ssh_message_reply_default(susshi_session.client_message);
					susshi_session.client_message = NULL;
				}
			} else {
				/* Keyboard Interactive request */
				susshi_client_auth_kbdint_send_request(susshi_session.client_message, true);
				susshi_ssh_set_auth_state(susshi_session.client_session, SSH_AUTH_STATE_INFO);
				request_send = true;
			}

		} else {
			susshi_session.client_message = ssh_message_get(susshi_session.client_session);

			if (susshi_session.client_message != NULL) {
				if (ssh_message_auth_kbdint_is_response(susshi_session.client_message)) {

					debug4_dir(CLIENT, GATEWAY, "Got Message of type %d, subtype %d",
							   ssh_message_type(susshi_session.client_message),
							   ssh_message_subtype(susshi_session.client_message));

					if (ssh_message_type(susshi_session.client_message) == SSH_REQUEST_AUTH) {

						if (ssh_userauth_kbdint_getnanswers(susshi_session.client_session) == 1) {

							debug2_dir(GATEWAY, CLIENT, "Received Keyboard Interactive response.");

							if ((password = ssh_userauth_kbdint_getanswer(susshi_session.client_session, 0)) != NULL) {
								attempts++;
								debug2_dir(CLIENT, GATEWAY, "Received password / Attempt %d", attempts);
								rc = ssh_userauth_password(susshi_session.target_session, NULL, password);
								if (rc != SSH_AUTH_SUCCESS) {
									/* Sending next request */
									susshi_client_auth_kbdint_send_request(susshi_session.client_message, false);
								}
							}
						}
					} else {
						rc = SSH_AUTH_DENIED;
					}
				}
			} else {
				if (susshi_session.client_session->session_state == SSH_SESSION_STATE_AUTHENTICATING) {
					susshi_disconnect_individual(BOTH, DISCONNECT_AUTH_FAILED, "The client did not sent a password response within %ld seconds.", timeout);
				} else {
					susshi_disconnect_standard(BOTH, DISCONNECT_PROTOCOLL_ERROR);
				}
			}
		}
	}

	return rc;
}


/*!
 * @brief       Authenticate against the target using password authentication
 *
 * Behaviour depends on @c susshi_session.target_password_source:
 * - @c PWS_DIALOG: if an extracted password is available and the prompt looks like a
 *   password prompt, tries it directly; otherwise finishes client authentication and
 *   calls @c susshi_client_auth_kbdint_or_password() to collect one from the user.
 * - @c PWS_PRESERVE, @c PWS_STATIC, @c PWS_DOTP: submits the stored @c target_userpw
 *   directly via @c ssh_userauth_password() without user interaction.
 *
 * Calls @c susshi_target_auth_continue_or_abort_interactive() with the result, then
 * wipes @c target_userpw from memory and resets the password source to @c PWS_DIALOG.
 *
 * @ingroup     auth_target_methods
 *
 * @return      @c SSH_AUTH_SUCCESS on success, otherwise an @c SSH_AUTH_* error or denied code
 */

static int
susshi_target_auth_password(void) {
	int rc = SSH_AUTH_DENIED;

	debug1_dir(GATEWAY, TARGET, "Trying password authentication in mode '%s'",
			   password_source[susshi_session.target_password_source]);

	/* For Password Auth with target, we can support those two methods with client: */
	susshi_client_auth_add_preferred_method("password");
	susshi_client_auth_add_preferred_method("keyboard-interactive");

	switch(susshi_session.target_password_source) {

		case PWS_DIALOG: {

			if ((susshi_session.use_extracted_password == true) &&
				(susshi_session.target_userpw != NULL) &&
				(blength(susshi_session.target_userpw) > 0)) {

				/* We have an extracted password and will try to use it */

				debug2_dir(GATEWAY, TARGET, "We use the password extracted from gateway password and try it against target.");

				rc = ssh_userauth_password(susshi_session.target_session, NULL, bdata(susshi_session.target_userpw));

				if (rc != SSH_AUTH_SUCCESS)
					log_session(GATEWAY, TARGET, "Tried with extracted password (after split-string), but authentication with the gateway password failed for target.");

				susshi_session.use_extracted_password = false;

			} else {
				/* We have no password for target, so we will start keyboard-interactive with client */

				/* Finish client authentication */
				susshi_client_auth_finish(false);

				/* Start keyboard-interactive with client */
				rc = susshi_client_auth_kbdint_or_password();

				int_store.active_method->enabled = false;
			}

		} break;

		case PWS_PRESERVE:
		case PWS_STATIC:
		case PWS_DOTP: {

			if ((susshi_session.target_userpw != NULL) &&
				(blength(susshi_session.target_userpw) > 0)) {
				/* We have a password for target, so we will try to login with this password. */

				rc = ssh_userauth_password(susshi_session.target_session, NULL, bdata(susshi_session.target_userpw));

				if (rc != SSH_AUTH_SUCCESS) {
					log_session(GATEWAY, TARGET,
								"Profile mode '%s', but authentication with given password failed for target.",
								password_source[susshi_session.target_password_source]);
				}

			} else {
				log_session(GATEWAY, TARGET,
							"Profile mode '%s', but no password given.",
							password_source[susshi_session.target_password_source]);
			}

		} break;

		default:
			break;
	}

	susshi_target_auth_continue_or_abort_interactive(rc);

	/* Reset to default PWS_DIALOG */
	susshi_session.target_password_source = PWS_DIALOG;

	/* Wipe memory */
	if (susshi_session.target_userpw != NULL) {
		memset(susshi_session.target_userpw->data, 'X', blength(susshi_session.target_userpw));
		bstrFree(susshi_session.target_userpw);
		susshi_session.target_userpw = NULL;
	}

	return(rc);

}


/*!
 * @brief       Load per-user target public/private key pairs from the Chef session context
 *
 * Unpacks the @c "TargetUserKeys" array from @c susshi_session.session_context and
 * stores each key's type, fingerprint, public blob, and private blob into
 * @c int_store.target_context_identities. Calls @c fatal() if the maximum number of
 * user keys (@c MAX_USERKEYS) is exceeded or a key cannot be parsed.
 *
 * @return      Number of key pairs successfully loaded (zero if the context has no @c TargetUserKeys)
 */

static int
susshi_target_auth_load_chef_context_identities(void) {
	json_t *keys;
	json_t *element;
	int json_ret;
	size_t index = 0;

	const char *type_ptr, *fp_ptr, *pub_ptr, *priv_ptr;
	json_ret = json_unpack(susshi_session.session_context, "{s:o}", "TargetUserKeys", &keys);
	if (json_ret == 0) {
		json_array_foreach(keys, index, element) {
			if (index == MAX_USERKEYS)
				fatal("User TargetIdentities: Maximal number of user-keys (%d) exceeded", MAX_USERKEYS);

			if (susshi_cfg_parse_ssh_key(element, &type_ptr, &fp_ptr, &pub_ptr, &priv_ptr,
										 "Context/TargetUserKeys") == true) {
				debug3("Got Target Identity Key from Chef: %s %s ", type_ptr, fp_ptr);

				int_store.target_context_identities[index].key_type = bfromcstr(type_ptr);
				int_store.target_context_identities[index].fingerprint = bfromcstr(fp_ptr);
				int_store.target_context_identities[index].public_blob = bfromcstr(pub_ptr);
				int_store.target_context_identities[index].private_blob = bfromcstr(priv_ptr);
				int_store.num_target_context_identities++;
			} else {
				fatal("User TargetIdentities: Could not parse ssh-key hash");
			}
		}
		debug3("Successfully imported %d context pub/private keys from Chef", (int) index);
	}

	return (int) index;
}


/*!
 * @brief       Map a key-type name string to an @c ssh_keytypes_e value, rejecting unsupported types
 *
 * Calls @c ssh_key_type_from_name() and then filters the result to only the types
 * supported by suSSHi (@c RSA, @c ECDSA, @c ED25519).
 *
 * @ingroup     auth_target_methods
 *
 * @param       string      Key-type name string (e.g. @c "ssh-rsa", @c "ssh-ed25519")
 *
 * @return      The matching @c ssh_keytypes_e value, or @c SSH_KEYTYPE_UNKNOWN for
 *              unrecognised or unsupported types
 */

static enum ssh_keytypes_e
susshi_target_auth_keytype_from_string(const char *string) {
	enum ssh_keytypes_e type;

	type = ssh_key_type_from_name(string);

	switch(type) {
		case SSH_KEYTYPE_RSA:
		case SSH_KEYTYPE_ECDSA:
		case SSH_KEYTYPE_ED25519:
			return type;
		default:
			return SSH_KEYTYPE_UNKNOWN; /* Unsupported by suSSHi2 */
	}
}


/*!
 * @brief       Build a comma-separated string listing the authentication methods present in a bitmask
 *
 * Recognises @c SSH_AUTH_METHOD_PASSWORD, @c SSH_AUTH_METHOD_PUBLICKEY, and
 * @c SSH_AUTH_METHOD_INTERACTIVE. Methods not set in @p auth_methods are omitted.
 *
 * @param       auth_methods    Bitmask of @c SSH_AUTH_METHOD_* flags
 *
 * @return      Heap-allocated @c bstring containing the method list (e.g. @c "publickey, password");
 *              the caller is responsible for freeing it with @c bstrFree()
 */


static bstring
susshi_target_auth_methods_list(int auth_methods) {

	bstring methods_text = NULL;

	struct Methods {
		int method;
		const char *text;
	};

	struct Methods methods[] = {
			{SSH_AUTH_METHOD_PASSWORD,    "password"},
			{SSH_AUTH_METHOD_PUBLICKEY,   "publickey"},
			{SSH_AUTH_METHOD_INTERACTIVE, "keyboard-interactive"}
	};

	methods_text = bfromcstr("");

	for(int c=0, a=0; c < 3; c++) {
		if (auth_methods & methods[c].method) {
			if (a > 0)
				bformata(methods_text, ", ");
			bformata(methods_text, "%s", methods[c].text);
			a++;
		}
	}

	return methods_text;
}

/*!
 * @brief       Decide whether to continue or disable password/keyboard-interactive methods after a failed attempt
 *
 * If @p rc indicates failure and the session profile does not permit continuing
 * (@c susshi_session.target_password_continue is @c false), disables both
 * @c SSH_AUTH_METHOD_INTERACTIVE and @c SSH_AUTH_METHOD_PASSWORD in
 * @c target_auth_methods and sets @c susshi_session.disconnect_message. If the
 * profile does permit continuation, only sets the disconnect message without disabling
 * methods. Does nothing when @p rc is @c SSH_AUTH_SUCCESS.
 *
 * @param       rc      The @c SSH_AUTH_* result code from the most recent authentication attempt
 */

static void
susshi_target_auth_continue_or_abort_interactive(int rc) {
	bstring message = NULL;

	if (rc != SSH_AUTH_SUCCESS) {
		if (susshi_session.target_password_continue) {
			log_session(GATEWAY, TARGET,
						"Profile is configured to continue with user dialog authentication.");

			message = bformat("Could not authenticate to target with given %s. Aborting.",
							  password_source[susshi_session.target_password_source]);
			susshi_session.disconnect_message = bdata(message);

		} else {
			log_session(GATEWAY, TARGET,
						"Profile is not configured to continue with user dialog authentication. Aborting.");

			message = bformat("Could not authenticate to target with given %s. Aborting.",
									  password_source[susshi_session.target_password_source]);
			susshi_session.disconnect_message = bdata(message);

			for (int m=0; target_auth_methods[m].method != SSH_AUTH_METHOD_NONE; m++) {
				if ((target_auth_methods[m].method == SSH_AUTH_METHOD_INTERACTIVE) || (target_auth_methods[m].method == SSH_AUTH_METHOD_PASSWORD))
					target_auth_methods[m].enabled = false;
			}
		}
	}

}

/*! @} */
