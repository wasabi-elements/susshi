/*!
 *
 * @brief       Gateway Authentication
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
 * @defgroup    proxy_auth_gateway Gateway Authentication
 * @{
 *
 */

#include <susshi-proxyd/common.h>

/*! @cond */
static struct {
	bool authenticated;
	int auth_attempts;
	int auth_failures;
	bool banner_sent;
} int_store = {
		.authenticated = false,
		.auth_attempts = 0,
		.auth_failures = -1,
		.banner_sent = false
};
/*! @endcond */

/* Prototypes */

static bool proxy_gateway_auth_dispatch(void);
static void proxy_gateway_auth_process_method_response(ssh_message message, AuthState auth_response,
													   const char *method_name);
static bool proxy_gateway_auth_verify_pubkey(ssh_key key, const char *key_base64);
static AuthState proxy_gateway_auth_publickey(ssh_message message);
static void proxy_gateway_auth_send_target_ips_json(void);
static void proxy_gateway_auth_send_target_ip_json(void);

/*!
 * Initialize & Start Gateway Authentication
 *
 * @return true on success
 */

bool
proxy_gateway_auth_start(void) {

	/* Set allowed Authentication methods */
	ssh_set_auth_methods(proxy_session.gateway_session, SSH_AUTH_METHOD_PUBLICKEY);

	proxy_session.gateway_phase = PHASE_AUTH_START;
	debug1("Gateway authentication started.");

	return proxy_gateway_auth_dispatch();
}


/*!
 * @brief       Client Authentication Dispatcher
 *
 * Reads messages from ssh session and dispatches them to the corresponding functions according their type / subtype
 *
 * We have to store 'message' in int_store, because proxy_gateway_auth_finish() requires access to the message stream
 *
 * @return      true on success
 */

static bool
proxy_gateway_auth_dispatch(void) {
	SplitLoginStringReturn split_rc;
	ssh_message message;
	int mtype;
	time_t login_starttime = time(NULL);

	do {
		if ((time(NULL) - (time_t) 10) > login_starttime) {
			return false;
		}

		message = ssh_message_get(proxy_session.gateway_session);

		if (!message)
			break;

		debug4_dir(GATEWAY, PROXY, "Got Message of type %d, subtype %d",
				   ssh_message_type(message), ssh_message_subtype(message));

		switch (ssh_message_type(message)) {
			case SSH_REQUEST_AUTH:

				/* Extract susshi_uniqid, targethost and max_idle_timer from login string */
				split_rc = store_splitted_loginstring_into_proxy_session(ssh_message_auth_user(message));

				switch (split_rc) {

					case STRING_OK:

						SETPROCTITLE("%s (Gateway-Auth)",
									 bdata(proxy_session.susshi_uniqid));

						switch(mtype = ssh_message_subtype(message)){

							case SSH_AUTH_METHOD_PUBLICKEY:
								debug2_dir(GATEWAY, PROXY, "Authentication Method 'publickey'.");
								proxy_gateway_auth_process_method_response(
										message, proxy_gateway_auth_publickey(message), "publickey");
								break;

							case SSH_AUTH_METHOD_NONE:
								debug2_dir(GATEWAY, PROXY, "Authentication Method 'none'.");
								proxy_gateway_auth_process_method_response(message, SUSSHI_AUTH_STATE_FAILED, "none");
								break;

							default:
								proxy_gateway_auth_process_method_response(message, SUSSHI_AUTH_STATE_FAILED, "unknown");
								break;
						}

						debug2_dir(GATEWAY, PROXY, "Authentication attempt %d / failures %d.", int_store.auth_attempts, int_store.auth_failures);
						break;

					case USERNAME_INVALID:
						log_system(LOG_LEVEL_INFO, "Invalid user %s.", ssh_message_auth_user(message));
						susshi_proxy_disconnect(GATEWAY, SSH2_DISCONNECT_ILLEGAL_USER_NAME, "Gateway credentials not accepted.");
						break;

					case TARGET_RESOLVE_FAILED:
						log_system(LOG_LEVEL_INFO, "Failed to resolve target hostname.");
						proxy_gateway_auth_send_error_json(SUSSHI_PROXY_ERROR_CODE_TARGET_RESOLV_FAILED);
						ssh_message_reply_default(message);
						break;

					case ILLEGAL_CHARS:
						log_system(LOG_LEVEL_INFO, "Login string contains illegal characters. Disconnecting gateway.");
						susshi_proxy_disconnect(GATEWAY, SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, "Login string contains illegal characters.");
						break;

					default:
						fatal("Invalid return code %d from store_splitted_loginstring_into_proxy_session().", split_rc);
				}
				break;

			case SSH_REQUEST_SERVICE:
			default:
				ssh_message_reply_default(message);
				ssh_message_free(message);
		}

	} while(!proxy_session.gateway_authenticated);

	return proxy_session.gateway_authenticated;
}


/*!
 * @brief       Process Authentication Methode response
 *
 * @param       message         SSH Message
 * @param       auth_response   Response
 * @param       method_name     Methode
 */

static void
proxy_gateway_auth_process_method_response(ssh_message message, AuthState auth_response, const char *method_name) {

	switch(auth_response) {
		case SUSSHI_AUTH_STATE_SUCCESS:

			log_system(LOG_LEVEL_INFO, "Gateway successfully authenticated.");

			/* For now, we just document that gateway has authenticated successfully
			 * SUCCESS message will be send to the gateway after we reached the requested target */
			proxy_session.gateway_authenticated = true;
			proxy_session.gateway_phase = PHASE_AUTHENTICATED;
			break;

		case SUSSHI_AUTH_STATE_PK_OK:

			/* Set allowed Authentication methods */
			ssh_set_auth_methods(proxy_session.gateway_session, SSH_AUTH_METHOD_PUBLICKEY);
			break;

		case SUSSHI_AUTH_STATE_ERROR:
		case SUSSHI_AUTH_STATE_PARTIAL:
		case SUSSHI_AUTH_STATE_FAILED:
		default:

			if ((strcmp(method_name, "none") != 0) && (strcmp(method_name, "publickey") != 0)) {
				// Silent ignore failed "none" or "publickey" requests
				int_store.auth_failures++;
				debug3_dir(GATEWAY, PROXY, "Publickey authentication for '%s' failed.",
						   bdata(proxy_session.susshi_uniqid));
				log_system(LOG_LEVEL_INFO, "Publickey authentication for '%s' failed.",
						   bdata(proxy_session.susshi_uniqid));
			}

			/* Set remaining allowed AUTH methods */
			ssh_set_auth_methods(proxy_session.gateway_session, SSH_AUTH_METHOD_PUBLICKEY);

			if (auth_response == SUSSHI_AUTH_STATE_PARTIAL) {
				/* Reply with USERAUTH_FAILURE / PARTIAL SUCCEEDED */
				ssh_message_auth_reply_success(message, 1);
			} else {
				/* Reply with USERAUTH_FAILURE */
				ssh_message_reply_default(message);
			}
	}
}


/*!
 * @brief       Finish Gateway authentication SUCCESSFULL
 */

void
proxy_gateway_auth_finish(void) {

	if (proxy_session.gateway_auth_finish_sent == false) {

		/* Send resolved target IP address with DEBUG message back to Gateway */

		debug1("Send my target IP: %s", bdata(proxy_session.target_ip));
		proxy_gateway_auth_send_target_ip_json();

		debug1_dir(PROXY, GATEWAY, "Completing authentication successfully.");
		ssh_auth_reply_success(proxy_session.gateway_session, 0);

		proxy_session.gateway_auth_finish_sent = true;
	} else {
		debug3_dir(PROXY, GATEWAY, "Client authentication already finished. No authentication reply to be sent.");
	}
}


/*!
 * @brief       Verify if "key" is in list of configured gateway identities
 *
 * Changed from ssh_key_cmp on binary key blobs to strcmp on base64 key blobs, because ssh_key_cmp failed on ECDSA keys
 *
 * @param       key             the userkey received from gateway
 * @param       key_base64      The Base64 encode key from session
 *
 * @return      true if key is found
 */

static bool
proxy_gateway_auth_verify_pubkey(ssh_key key, const char *key_base64) {
	const char* keytype = NULL;
	const char* base64_key_blob_from_config;
	ssh_key ssh_key_from_config;
	int i;

	keytype = proxy_ssh_key_type_to_char(key);

	if (keytype != NULL) {

		// Iterate through keys
		for (i = 0; i < proxy_cfg.num_gateway_identities; i++) {
			base64_key_blob_from_config = bdata(proxy_cfg.gateway_identities[i].public_blob);

			if (ssh_pki_import_pubkey_base64(base64_key_blob_from_config, ssh_key_type(key), &ssh_key_from_config) == SSH_OK) {

				if (log_level >= LOG_DEBUG_PACKET) {
					const char *fp = NULL;
					debug4("Gateway Authkey: %s %s", keytype, fp = susshi_display_hash_from_key(ssh_key_from_config));
					if (fp)
						xfree((void *) fp);
				}

				SSH_KEY_FREE(ssh_key_from_config);

				if (strcmp(base64_key_blob_from_config, key_base64) == 0) {
					return true;
				}
			}
		}
	}
	return false;
}


/*
 * ============= AUTHENTICATION METHODS ======================================================================================
 */


/*!
 * @brief       Gateway Public Key Authentication
 *
 * @param       message     SSH message
 *
 * @return      AuthState value
 */

static AuthState
proxy_gateway_auth_publickey(ssh_message message) {
	AuthState resp = SUSSHI_AUTH_STATE_ERROR;
	ssh_key key;
	// enum ssh_keytypes_e key_type;
	char *key_base64 = NULL;
	bstring key_base64_bstr = NULL;

	ssh_string key_blob = NULL;
	ssh_string key_type_str = NULL;


	if ((key = susshi_libssh_ssh_message_auth_pubkey(message)) != NULL) {
		int_store.auth_attempts++;

		if (ssh_key_is_public(key)) {
			// key_type = ssh_key_type(key);

			ssh_pki_export_pubkey_base64(key, &key_base64);
			ssh_pki_export_pubkey_blob(key, &key_blob);

			if ((key_base64) && (key_blob)) {

				key_base64_bstr = bfromcstr(key_base64);

				switch (susshi_libssh_ssh_message_auth_publickey_state(message)) {

					/* PubKey is not signed (test message) */
					case SSH_PUBLICKEY_STATE_NONE: {

						if (log_level >= LOG_DEBUG_CONVERSATION) {
							const char *fp = NULL;
							debug3_dir(GATEWAY, PROXY, "Received unsigned (test) public key: %s %s.",
									   proxy_ssh_key_type_to_char(key), fp = susshi_display_hash_from_key(key));
							if (fp)
								xfree((void *) fp);
						}

						if (proxy_gateway_auth_verify_pubkey(key, key_base64)) {

							debug3_dir(GATEWAY, PROXY, "Key is acceptable. Sending SSH_MSG_USERAUTH_PK_OK message.");

							if (proxy_session.operation_mode != OP_MODE_PROXY_BASTION) {
								debug4_dir(PROXY, GATEWAY, "Sending resolved IP Addresses as DEBUG message to gateway.");
								proxy_gateway_auth_send_target_ips_json();
							}

							key_type_str = ssh_string_from_char(proxy_ssh_key_type_to_char(key));
							ssh_message_auth_reply_pk_ok(message, key_type_str, key_blob);
							SSH_STRING_FREE(key_type_str);

							resp = SUSSHI_AUTH_STATE_PK_OK;
						} else {

							debug3_dir(GATEWAY, PROXY, "Key is not acceptable.");
							resp = SUSSHI_AUTH_STATE_FAILED;
						};
					} break;

						/* Message is signed and signature is already validated by libssh */
					case SSH_PUBLICKEY_STATE_VALID: {
						const char *fp = NULL;

						if (proxy_session.proxy_auth_fp)
							bstrFree(proxy_session.proxy_auth_fp);

						proxy_session.proxy_auth_fp = bfromcstr(fp = susshi_display_hash_from_key(key));
						if (fp)
							xfree((void *) fp);

						debug3_dir(GATEWAY, PROXY, "Received signed and valid public key: %s %s.",
								  proxy_ssh_key_type_to_char(key), bdata(proxy_session.proxy_auth_fp));


						if (proxy_gateway_auth_verify_pubkey(key, key_base64)) {
							log_system(LOG_LEVEL_INFO, "Publickey authentication for '%s' succeeded with fingerprint %s.",
									   bdata(proxy_session.susshi_uniqid), bdata(proxy_session.proxy_auth_fp));
							resp = SUSSHI_AUTH_STATE_SUCCESS;
						} else {
							resp = SUSSHI_AUTH_STATE_FAILED;
						};
					} break;

					default:
						debug4("Run into state %d.", susshi_libssh_ssh_message_auth_publickey_state(message));
						resp = SUSSHI_AUTH_STATE_ERROR;
				}
				bstrFree(key_base64_bstr);
				xfree(key_base64);
			}
		} else {
			debug3_dir(GATEWAY, PROXY, "Received key, but is not a valid public key.");
		}
		SSH_KEY_FREE(key);
	}
	return resp;
}


/*!
 * @brief       Gateway Send Target Information in DEBUG Message
 */

static void
proxy_gateway_auth_send_target_ips_json(void) {
	bstring json_blob = NULL;

	json_blob = bfromcstr("{ \"target_ips\": [ ");

	for(int i = 0; i < proxy_session.num_target_ips; i++)
		bformata(json_blob, "\"%s|%d\"%s",
				bdata(proxy_session.target_ips[i].ip),
				proxy_session.target_ips[i].ai_family,
				(i+1 < proxy_session.num_target_ips) ? ", ":" ");

	bformata(json_blob, "] }");

	/* Send resolved target IPs address with DEBUG message back to Gateway */
	ssh_send_debug(proxy_session.gateway_session, bdata(json_blob), 1);

	debug1("Sending Target-IPs to Gateway: %s", bdata(json_blob));

	bstrFree(json_blob);
}


/*!
 * @brief       Gateway Send Target Information in DEBUG Message
 */

static void
proxy_gateway_auth_send_target_ip_json(void) {
	bstring json_blob = NULL;

	json_blob = bformat("{ \"target_ip\": \"%s\" }", bdata(proxy_session.target_ip));

	/* Send target IP we are connected to with DEBUG message back to Gateway */
	ssh_send_debug(proxy_session.gateway_session, bdata(json_blob), 1);

	bstrFree(json_blob);
}


/*!
 * @brief       Gateway Send Error in DEBUG Message
 *
 * @param       error_code  Error code
 */

void
proxy_gateway_auth_send_error_json(int error_code) {
	bstring json_blob = NULL;

	json_blob = bformat("{ \"error\": %d }", error_code);

	/* Send target IP we are connected to with DEBUG message back to Gateway */
	ssh_send_debug(proxy_session.gateway_session, bdata(json_blob), 1);

	bstrFree(json_blob);
}

/*! @} */
