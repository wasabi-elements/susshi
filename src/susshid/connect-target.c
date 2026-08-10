/*!
 *
 * @brief       Target Connection
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
 * @defgroup    connect_target Target Connection
 * @{
 */

#include <susshid/common.h>


/* Prototypes */
static int susshi_select_next_target_ip(void);
static bool susshi_target_hostkey_prompt_user(KeyVerifyResponse key_state, ssh_key target_pubkey);
static KeyVerifyResponse susshi_target_verify_bastion_hostkey(void);

/*!
 * @brief       Select next target IP address for (sequential) Happy Eyeballs
 *
 * This will honor the preferred target address family
 *
 * @return      index number or -1 if no more address is found
 */

static int
susshi_select_next_target_ip(void) {
	int i;

	/* Lookup preferred AFI first */
	for(i=0; (i < susshi_session.num_target_ips); i++) {
		if (susshi_session.target_ips[i].ai_family != susshi_cfg.session.target_preferred_address_family)
			continue;
		if (susshi_session.target_ips[i].used)
			continue;
		susshi_session.target_ips[i].used = true;

		susshi_session.target_ip = susshi_session.target_ips[i].ip;
		store_target_identifier_into_session();

		return i;
	}

	/* Lookup in remaining IPs */
	for(i=0; i < susshi_session.num_target_ips; i++) {
		if (susshi_session.target_ips[i].used)
			continue;
		susshi_session.target_ips[i].used = true;

		susshi_session.target_ip = susshi_session.target_ips[i].ip;
		store_target_identifier_into_session();

		return i;
	}

	return -1;
}

/*!
 * @brief       Try to connect to and login into target
 *
 * @return      true if successful
 */

bool
susshi_target_login(void) {
	bool rc = false;
	static int SSH_false = 0;
	static int SSH_true = 1;
	time_t now;
	bstring hostkey_types = NULL;
	uint32_t proxy_session_buflen;

	do {
		if ((susshi_session.target_session = ssh_new()) != NULL) {
			if (susshi_session.use_target_proxy) {

				/* Connect through proxy */
				susshi_session.target_session->opts.fd = ssh_get_fd(susshi_session.target_proxy_session);

				/* Required for libSSH, even if we have already set an FD socket. */
				ssh_options_set(susshi_session.target_session, SSH_OPTIONS_HOST,
								bdata(susshi_session.target_host_resolved));
				ssh_options_set(susshi_session.target_session, SSH_OPTIONS_PORT,
								&susshi_session.target_port);

				/* Continue with connection to target. See below. */

			} else {

				/* Connect directly */

				/* (Sequential) Happy Eyeballs */
				if ((susshi_select_next_target_ip()) != -1) {

					debug1_dir(GATEWAY, TARGET, "Trying to connect to %s (%s).",
							   bdata(susshi_session.target_host), bdata(susshi_session.target_ip));
					ssh_options_set(susshi_session.target_session, SSH_OPTIONS_HOST,
									bdata(susshi_session.target_ip));
					ssh_options_set(susshi_session.target_session, SSH_OPTIONS_PORT,
									&susshi_session.target_port);
					if (susshi_report.message != NULL) {
						bstrFree(susshi_report.message);
						susshi_report.message = NULL;
					}
				} else {
					return rc;
				}

				/* In Bastion mode, ensure that OpenSSH sshd is started */
				/* if (susshi_session.operation_mode == OP_MODE_BASTION) {
					run_bastion_sshd(susshi_cfg.num_host_key_files, susshi_cfg.host_key_files, susshi_cfg.num_target_identities, susshi_cfg.target_identities, &susshi_session.bastion_pid);
				}
				*/
			}

			if (susshi_chef_session_check_context_contains_target()) {
				if (susshi_chef_session_context_for_target()) {

					ssh_options_set(susshi_session.target_session, SSH_OPTIONS_TIMEOUT, &susshi_cfg.session.target_connection_timeout);
					ssh_options_set(susshi_session.target_session, SSH_OPTIONS_SSH2, &SSH_true);
					ssh_options_set(susshi_session.target_session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &SSH_true);
					ssh_options_set(susshi_session.target_session, SSH_OPTIONS_USER, bdata(susshi_session.target_user));

					debug2_dir(GATEWAY, TARGET, "Setting bi-directional allowed packet ciphers to %s",
							   bdata(susshi_cfg.session.target_ciphers));
					ssh_options_set(susshi_session.target_session, SSH_OPTIONS_CIPHERS_C_S, bdata(susshi_cfg.session.target_ciphers));
					ssh_options_set(susshi_session.target_session, SSH_OPTIONS_CIPHERS_S_C, bdata(susshi_cfg.session.target_ciphers));

					if (susshi_cfg.session.target_hmacs != NULL) {
						debug2_dir(GATEWAY, TARGET, "Setting bi-directional allowed packet hmacs to %s.",
								   bdata(susshi_cfg.session.target_hmacs));
						ssh_options_set(susshi_session.target_session, SSH_OPTIONS_HMAC_C_S, bdata(susshi_cfg.session.target_hmacs));
						ssh_options_set(susshi_session.target_session, SSH_OPTIONS_HMAC_S_C, bdata(susshi_cfg.session.target_hmacs));
					}

					if (susshi_cfg.session.target_kex_algorithms != NULL) {
						debug2_dir(GATEWAY, TARGET,
								   "Setting list of preferred kex algorithms to %s",
								   bdata(susshi_cfg.session.target_kex_algorithms));
						ssh_options_set(susshi_session.target_session, SSH_OPTIONS_KEY_EXCHANGE, bdata(susshi_cfg.session.target_kex_algorithms));
					}

					/* For testing only: */
					/*
					{
						static uint32_t SSH_rekey_data = 200*1024;
						ssh_options_set(susshi_session.target_session, SSH_OPTIONS_REKEY_DATA, &SSH_rekey_data);
					}
					*/

					if (susshi_session.rule_id > 0)
						debug2("Matching %s Rule ID is #%" JSON_INTEGER_FORMAT,
							   susshi_session.operation_mode == OP_MODE_BASTION ? "Bastion" : "Access",
							   susshi_session.rule_id);

					if (susshi_session.profile_name)
						debug2("Applied %s Profile is '%s'",
							   susshi_session.operation_mode == OP_MODE_BASTION ? "Bastion" : "Access",
							   susshi_session.profile_name);

					/* Prevent libssh from reading system / user ssh_config on ssh_connect */
					ssh_options_set(susshi_session.target_session, SSH_OPTIONS_PROCESS_CONFIG, &SSH_false);

					/* Set the preferred server host key types according the list of host keys we got from Chef (if any) */
					hostkey_types = susshi_chef_target_hostkey_types(susshi_session.target_ip);
					if (hostkey_types) {
						ssh_options_set(susshi_session.target_session, SSH_OPTIONS_HOSTKEYS,
										bdata(hostkey_types));
						debug2_dir(GATEWAY, TARGET,
								   "List of preferred host key algorithms is set to %s according to configuration and types of already known host keys for target.",
								   bdata(hostkey_types));
						bstrFree(hostkey_types);
					} else {
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
					}

					if (susshi_cfg.session.target_compression != -1) {
						ssh_options_set(susshi_session.target_session, SSH_OPTIONS_COMPRESSION,
										susshi_cfg.session.target_compression ? "zlib@openssh.com,zlib,none" : "no");
						susshi_report.target_compression = true;
					} else {
						// In case target_compression is not yes/no but undefined, if client has started with compression we try for target as well
						if (susshi_report.client_compression) {
							ssh_options_set(susshi_session.target_session, SSH_OPTIONS_COMPRESSION,
											"zlib@openssh.com,zlib,none");
							susshi_report.target_compression = true;
						}
					}

					/* Client banner we will send to target */
					if (susshi_cfg.session.preserve_client_banner) {
						if (strncmp("SSH-2.0-", bdata(susshi_session.client_ssh_identification), 8) == 0) {
							susshi_session.target_session->clientbanner = strdup(
									bdata(susshi_session.client_ssh_identification));
						} else {
							log_system(LOG_LEVEL_ERROR,
									   "Could not preserve client banner, client-banner is of different version than we would add to the gateway banner.");
							susshi_cfg.session.preserve_client_banner = 0;
						}
					} else {
						susshi_session.target_session->clientbanner = strdup(SUSSHI_SSH_VERSION_BANNER_FULL);
					}

					if (susshi_cfg.session.preserve_client_banner) {
						debug3_dir(GATEWAY, TARGET, "Using preserved USER_AUTH banner from client:\n%s\n",
								   bdata(susshi_session.client_ssh_identification));
					} else {
						debug3_dir(GATEWAY, TARGET, "Using suSSHi Gateway USER_AUTH banner (default).");
					}

					susshi_libssh_set_verbosity(susshi_session.target_session, TARGET);

					/* Prevent from reading local OpenSSH configuration file -> This is not good in debugging :-) ! */
					susshi_session.target_session->opts.config_processed = true;

					/*
					 * If there is already something in the proxy session buffer - not sure what to do with that ...
					 * Copying it to target_session->in_buffer did not work as expected.
					 */
					if ((susshi_session.target_proxy_session) &&
						(proxy_session_buflen = ssh_buffer_get_len(susshi_session.target_proxy_session->in_buffer)) > 0) {

						debug3("Already %d bytes in target_proxy_session buffer. Not copying it to ingress buffer of target_session:",
							   proxy_session_buflen);

						do_susshi_hexdump_ssh_buffer(susshi_session.target_proxy_session->in_buffer);

						/*
						// Copying it to target_session->in_buffer did not work as expected.
						ssh_buffer_add_data(susshi_session.target_session->in_buffer,
											ssh_buffer_get(susshi_session.target_proxy_session->in_buffer),
											proxy_session_buflen);
						*/

						error("Critical error occurred during target proxy connection/login. "
												   "Data in target proxy session buffer. Aborting.");

						susshi_disconnect_standard(CLIENT, DISCONNECT_TARGET_CONNECT_FAILED);
					}

					now = time(NULL);
					if (ssh_connect(susshi_session.target_session) == SSH_OK) {

						KeyVerifyResponse hostkey_verify;
						long timeout = 30;

						/* We are connected */

						/* Change timeout for session during target authentication */
						ssh_options_set(susshi_session.target_session, SSH_OPTIONS_TIMEOUT, &timeout);

						if (susshi_cfg.global.target_tcp_keep_alive != -1) {
							debug3_dir(GATEWAY, TARGET, "Setting TCP-Keepalive with Target %s.", susshi_cfg.global.target_tcp_keep_alive == 0 ? "OFF" : "ON");
							setsockopt(ssh_get_fd(susshi_session.target_session), SOL_SOCKET, SO_KEEPALIVE, (int[]) {susshi_cfg.global.target_tcp_keep_alive}, sizeof(int));
						}

						susshi_session.target_phase = PHASE_KEX;
						debug1_dir(GATEWAY, TARGET, "Connected to target.");

						log_session(CLIENT, TARGET, "Session started for '%s@%s -> %s' on Host %s (susshid-ID %s). (%s)",
									bdata(susshi_session.susshi_user), bdata(susshi_session.client_ip),
									bdata(susshi_session.target_identifier),
									bdata(susshi_session.hostname),
									bdata(chef_cfg.susshid_id),
									bdata(susshi_session.susshi_uniqid));

						log_session(CLIENT, GATEWAY, "Client software identification is '%s'.", bdata(susshi_session.client_ssh_identification));

						/* Receive and store target banner */
						susshi_session.target_ssh_identification = bfromcstr(
								ssh_get_serverbanner(susshi_session.target_session));

						if (susshi_session.operation_mode == OP_MODE_BASTION) {
							susshi_cfg.send_shell_env = 0;
							hostkey_verify = susshi_target_verify_bastion_hostkey();
						} else {
							log_session(TARGET, GATEWAY, "Target software identification is '%s'.", bdata(susshi_session.target_ssh_identification));
							hostkey_verify = susshi_target_verify_hostkey();
						}

						// Verify received host key
						if (hostkey_verify == KEY_OK) {

							if (susshi_target_auth()) {
								/* We are logged in and ready for THE loop */
								rc = true;
							} else {

								susshi_hooks_run(HOOK_SESSION_TARGET_AUTH_FAILED);

								if (susshi_session.disconnect_message) {
									log_session(TARGET, GATEWAY, "%s", susshi_session.disconnect_message);
									susshi_disconnect_individual(BOTH, SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED,
																 susshi_session.disconnect_message);
								} else {
									log_session(TARGET, GATEWAY, "Could not authenticate to target.");
									susshi_disconnect_standard(BOTH, DISCONNECT_AUTH_FAILED);
								}
							}

						} else {
							if (susshi_session.disconnect_message) {
								log_session(TARGET, GATEWAY, "%s", susshi_session.disconnect_message);
								susshi_disconnect_individual(BOTH, SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED,
															 susshi_session.disconnect_message);
							} else {
								log_session(TARGET, GATEWAY, "%s", "Hostkey could not be verified.");
								susshi_disconnect_standard(BOTH, DISCONNECT_TARGET_HOSTKEY_FAILED);
							}
						}
					} else {
						time_t delta;
						delta = time(NULL) - now;

						susshi_hooks_run(HOOK_SESSION_TARGET_CONNECT_FAILED);

						susshi_report.message = bformat("Target connection failed after %ld seconds: %s.", delta,
														ssh_get_error(susshi_session.target_session));

						error("Target connection failed after %ld seconds: %s.", delta,
							  ssh_get_error(susshi_session.target_session));

						if (susshi_session.use_target_proxy) {
							/* With target proxy (using fd), there is no second chance as with direct connections (potential list of IPs) */
							ssh_free(susshi_session.target_session);
							return false;
						}
					}

					/* Someone might think that it would be a good idea to call ssh_free() or ssh_disconnect() here,
					 * but libssh will not free up the resources correctly and thus will run into segfault / corrupted double-linked list
					 * issues when continuing with a new session (calling with ssh_new()) for another target IP.

					if (rc == false) {
						ssh_free(susshi_session.target_session);
					}
					*/
				} else {
					susshi_disconnect_standard(CLIENT, DISCONNECT_INTERNAL_ERROR);
				}
			} else {
				log_system(LOG_LEVEL_WARNING, "Target %s (%s) was not found in answer from Chef. Skipping.",
						   bdata(susshi_session.target_host_resolved), bdata(susshi_session.target_ip));
			}

		} else {
			fatal("Failed to allocate target session");
		}
	} while (!rc);

	return rc;
}


/*!
 * @brief       Verify target host key
 *
 * @return      KeyVerifyResponse
 */

KeyVerifyResponse
susshi_target_verify_hostkey(void) {
	KeyVerifyResponse resp = KEY_ERROR;
	ssh_key target_pubkey;
	const char *action;
	const char *dishash = NULL;

	if (ssh_get_server_publickey(susshi_session.target_session, &target_pubkey) == SSH_OK) {

		/* We received the public key */
		if_debug2() {
			dishash = susshi_display_hash_from_key(target_pubkey);

			do_debug2_dir(TARGET, GATEWAY, "Received Hostkey of type %s with hash '%s' from target.",
					   susshi_ssh_key_type_to_char(target_pubkey), dishash);
			if (dishash)
				xfree((void *) dishash);
		}

		resp = susshi_chef_verify_target_hostkey(target_pubkey, susshi_session.target_ip);

		switch (resp) {
			case KEY_OK:
				action = "accepted";
				break;
			case KEY_CHANGED:
				switch (susshi_session.target_hostkey_learning) {
					case HK_LEARNING_UPDATE: {
						action = "accepted. Key has changed, so we update chef with changed key as well";

						/* Update key on Chef*/
						susshi_chef_upload_target_hostkey(CHEF_REST_METHOD_UPDATE, susshi_session.target_ip,
														  susshi_session.target_port, target_pubkey);

						/* Accept key */
						resp = KEY_OK;
					} break;
					case HK_LEARNING_PROMPT: {
						if (susshi_target_hostkey_prompt_user(resp, target_pubkey)) {
							action = "accepted by user. Key has changed, so we update chef with changed key as well";

							/* Create new key on Chef */
							susshi_chef_upload_target_hostkey(CHEF_REST_METHOD_CREATE, susshi_session.target_ip,
															  susshi_session.target_port, target_pubkey);

							/* Accept key */
							resp = KEY_OK;
						} else {
							action = "not accepted by user (new changed)";
							susshi_session.disconnect_message = "Target host key has changed and user did not accept changed key.";
						}
					} break;
					default: {
						action = "not accepted (key changed)";
						susshi_session.disconnect_message = "Target host key has changed.";
					} break;
				}
				break;
			case KEY_NEW:
				switch (susshi_session.target_hostkey_learning) {
					case HK_LEARNING_UPDATE:
					case HK_LEARNING_IFUNKNOWN: {
						action = "accepted. Key is new, so we update chef with new key as well";

						/* Create new key on Chef */
						susshi_chef_upload_target_hostkey(CHEF_REST_METHOD_CREATE, susshi_session.target_ip,
														  susshi_session.target_port, target_pubkey);

						/* Accept key */
						resp = KEY_OK;
					} break;
					case HK_LEARNING_PROMPT: {
						if (susshi_target_hostkey_prompt_user(resp, target_pubkey)) {
							action = "accepted by user. Key is new, so we update chef with new key as well";

							/* Create new key on Chef */
							susshi_chef_upload_target_hostkey(CHEF_REST_METHOD_CREATE, susshi_session.target_ip,
															  susshi_session.target_port, target_pubkey);

							/* Accept key */
							resp = KEY_OK;
						} else {
							action = "not accepted by user (new key)";
							susshi_session.disconnect_message = "Target host key is unknown to " SUSSHI_NAME " and user did not accept key.";
						}
					} break;
					default: {
						action = "not accepted (new key)";
						susshi_session.disconnect_message = "Target host key is unknown to " SUSSHI_NAME ".";
					} break;
				}
				break;
			case KEY_REVOKED:
				action = "not accepted (key revoked)";
				susshi_session.disconnect_message = "Target host key has been revoked.";
				break;
			case KEY_ERROR:
				action = "not accepted (gateway error)";
				break;
			default:
				action = "not accepted (unknown error)";
		}

		dishash = susshi_display_hash_from_key(target_pubkey);
		log_session(TARGET, GATEWAY, "Received Hostkey of type %s with hash '%s' from target. Key is %s.",
					susshi_ssh_key_type_to_char(target_pubkey), dishash, action);
		if (dishash)
			xfree((void *) dishash);
	}
	SSH_KEY_FREE(target_pubkey);
	return resp;
}


/*!
 * @brief       Start keyboard-interactive dialog with client to ask user to accept target hostkey
 *
 * @param       key_state       State key check is actually
 * @param       target_pubkey   Target host publickey we've received
 *
 * @return      true on "yes" from client, false on "no"
 */

static bool
susshi_target_hostkey_prompt_user(KeyVerifyResponse key_state, ssh_key target_pubkey) {
	const char *message;
	// static int attempts = 0;
	int num_answers;
	const char *prompt;
	const char **prompts;
	char echos[] = {1};
	const char *instruction;
	long timeout = 300;

	instruction = "Please carefully verify the signature for the new key before accepting the key:\n"
				  "%s key fingerprint is %s.\n"
				  "If you are sure that the key is from the right source, you may continue to connect.\n";
	prompt = "Are you sure you want to continue connecting (yes/no)? ";

	switch (key_state) {
		case KEY_CHANGED:
			message = "\nWarning! The host publickey for target %s has CHANGED"
					  "\nand its authenticity can't be established."
					  "\n\nTHIS COULD INDICATE A MAN-IN-THE-MIDDLE ATTACK!\n";
			break;
		case KEY_NEW:
			message = "\nWarning! The host publickey for target %s is yet UNKNOWN"
					  "\nto " SUSSHI_NAME " and its authenticity can't be established.\n";
			break;
		default:
			fatal("We should never have reached this.");
	}

	prompts = &prompt;

	/* (Re-)enable keyboard-interactive auth if disabled by interactive user authentication before */
	susshi_client_auth_enable_method(SSH_AUTH_METHOD_INTERACTIVE);

	/* Finish client authentiation partial */
	susshi_client_auth_finish(false);

	/* Change timeout for session during interactive authentication */
	ssh_options_set(susshi_session.client_session, SSH_OPTIONS_TIMEOUT, &timeout);

	/* Wait for client answer */
	susshi_session.client_message = ssh_message_get(susshi_session.client_session);

	if (susshi_session.client_message == NULL) {
		susshi_report.message = bformat("It seems as if the user does not allow keyboard-interactive authentication, "
										"but this would be necessary to ask for the handling of the unknown public hostkey for %s. "
										"The client has already ended the session, so we cannot inform him.",
										bdata(susshi_session.target_host_resolved));
		susshi_disconnect_standard(BOTH, DISCONNECT_TARGET_HOSTKEY_FAILED);
	}

	do {
		if (susshi_session.client_message) {
			bstring bmessage = NULL;
			bstring binstrct = NULL;

			debug2_dir(GATEWAY, CLIENT, "We will ask user whether to accept key or not.");

			bmessage = bformat(message, bdata(susshi_session.target_host_resolved));
			binstrct = bformat(instruction, susshi_ssh_key_type_to_display_string(ssh_key_type(target_pubkey)),
							   susshi_display_hash_from_key(target_pubkey));

			susshi_session.client_session->kbdint = ssh_kbdint_new();
			ssh_message_auth_interactive_request(susshi_session.client_message, bdata(bmessage),
												 bdata(binstrct), 1, prompts, echos);

			susshi_session.client_session->auth.state = SSH_AUTH_STATE_INFO;
			bstrFree(bmessage);
			bstrFree(binstrct);

			/* Wait for client answer */
			susshi_session.client_message = ssh_message_get(susshi_session.client_session);

			if ((susshi_session.client_message != NULL) && (ssh_message_type(susshi_session.client_message) == SSH_REQUEST_AUTH)) {
				/* We got answer from client */
				num_answers = ssh_userauth_kbdint_getnanswers(susshi_session.client_session);

				if (num_answers == 1) {
					const char *answer;

					if ((answer = ssh_userauth_kbdint_getanswer(susshi_session.client_session, 0)) != NULL) {
						debug2_dir(CLIENT, GATEWAY, "We got answer '%s' from client.", answer);
						if (strcmp(answer, "yes") == 0) {

							log_system(LOG_LEVEL_INFO, "User %s accepted %s key for target %s by prompt.",
									   bdata(susshi_session.susshi_user), key_state == KEY_NEW ? "new":"changed",
									   bdata(susshi_session.target_ip));
							return true;

						} else if (strcmp(answer, "no") == 0) {

							log_system(LOG_LEVEL_INFO, "User %s denied %s key for target %s by prompt.",
									   bdata(susshi_session.susshi_user), key_state == KEY_NEW ? "new":"changed",
									   bdata(susshi_session.target_ip));
							return false;

						} else {
							message = "";
							instruction = "Please answer with \"yes\" or \"no\".";
						}
					};
					// attempts++;
				} else {
					/* Fatal */
					return false;
				}
			} else {
				/* Fatal */
				return false;
			}
		} else {
			return false;
		}
	} while (true);

}

/*!
 * @brief       Verify bastion host key
 *
 * @return      KeyVerifyResponse
 */

static KeyVerifyResponse
susshi_target_verify_bastion_hostkey(void) {

	/* Compare hostkeys with our own hostkeys since we use the same here */

	KeyVerifyResponse resp = KEY_ERROR;
	ssh_key bastion_pubkey;
	const char *dishash = NULL;
	enum ssh_keytypes_e keytype;
	bstring pub_path = NULL;
	ssh_key key_from_file;
	int i;

	if (ssh_get_server_publickey(susshi_session.target_session, &bastion_pubkey) == SSH_OK) {

		/* We received the public key */
		if_debug2() {
			dishash = susshi_display_hash_from_key(bastion_pubkey);

			do_debug4_dir(TARGET, GATEWAY, "Received Hostkey of type %s with hash '%s' from bastion.",
					   susshi_ssh_key_type_to_char(bastion_pubkey), dishash);
			if (dishash)
				xfree((void *) dishash);
		}

		keytype = ssh_key_type(bastion_pubkey);

		if (keytype != SSH_KEYTYPE_UNKNOWN) {

			for (i = 0; (i < susshi_cfg.num_host_key_files) && (resp != KEY_OK); i++) {
				pub_path = bformat("%s.pub", bdata(susshi_cfg.host_key_files[i]));
				if (ssh_pki_import_pubkey_file(bdata(pub_path), &key_from_file) == SSH_OK) {
					if (ssh_key_cmp(key_from_file, bastion_pubkey, SSH_KEY_CMP_PUBLIC) == 0) {
						resp = KEY_OK;
					}
					SSH_KEY_FREE(key_from_file);
				}
				bstrFree(pub_path);
			}
		}
		SSH_KEY_FREE(bastion_pubkey);
	}

	return resp;

}

/*! @} */
