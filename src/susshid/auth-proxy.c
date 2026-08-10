/*!
 *
 * @brief       Proxy Authentication
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
 * @defgroup    auth_proxy  Proxy Authentication
 * @brief       Proxy Authentication methods
 * @{
 *
 */

#include <susshid/common.h>


/* Prototypes */
static int susshi_proxy_auth_pubkey_phase1(void);
static int susshi_proxy_auth_pubkey_phase2(void);
static enum ssh_keytypes_e susshi_proxy_auth_keytype_from_string(const char *string);

/*! @cond */
static struct {
	TargetIdentity proxy_context_identities[MAX_USERKEYS];
	int num_proxy_context_identities;
	bool send_issue_banner;
} int_store = {
		.send_issue_banner = true,
		.num_proxy_context_identities = 0
};
/*! @endcond */


/*!
 * @brief       Begin proxy authentication by probing which gateway key the proxy will accept
 *
 * Sends an @c ssh_userauth_none request to the proxy to obtain the list of allowed
 * authentication methods, handles any error code already waiting in
 * @c susshi_session.target_proxy_error, then calls @c susshi_proxy_auth_pubkey_phase1()
 * to identify an acceptable public key. Returns @c true only when a key probe was
 * acknowledged by the proxy (@c SSH_AUTH_PARTIAL from phase 1), which means the session
 * is ready to continue with @c susshi_proxy_auth_phase2().
 *
 * @return      @c true if a suitable key was found and the proxy is ready for phase 2,
 *              @c false otherwise
 */

bool
susshi_proxy_auth_phase1(void) {

	char *issue_banner;
	int rc;

	susshi_session.target_proxy_phase = PHASE_AUTH_START;
	debug1("Proxy authentication started - phase 1.");

	// Initialize int_store
	memset((void *) &int_store, 0, sizeof(int_store));

	SETPROCTITLE("%s (Proxy-Auth) %s@%s via Proxy %s",
				 bdata(susshi_session.susshi_uniqid),
				 bdata(susshi_session.susshi_user),
				 bdata(susshi_session.target_identifier),
				 bdata(susshi_session.target_proxy_realm));

	/* Send none auth request to receive allowed authentication methods */
	rc = ssh_userauth_none(susshi_session.target_proxy_session, NULL);

	/* We may have received an error message already */
	switch(susshi_session.target_proxy_error) {
		case 0:
			break;
		case SUSSHI_PROXY_ERROR_CODE_TARGET_RESOLV_FAILED:
			debug1_dir(PROXY, GATEWAY, "Proxy could not resolve target.");
			susshi_report.message = bfromcstr("Proxy could not resolve target.");
			susshi_disconnect_standard(BOTH, DISCONNECT_TARGET_RESOLVE_FAILED);
			break;
		default:
			debug1_dir(PROXY, GATEWAY, "Unknown error returned from proxy.");
			susshi_report.message = bfromcstr("Unknown error returned from proxy.");
			susshi_disconnect_standard(BOTH, DISCONNECT_PROTOCOLL_ERROR);
			break;
	}

	if (rc == SSH_AUTH_DENIED) {
		/* Check if proxy sends an issue banner */
		issue_banner = ssh_get_issue_banner(susshi_session.target_proxy_session);

		if (issue_banner != NULL) {
			log_session(TARGET, PROXY, "Received Issue Banner from proxy. This seems weired");
			free(issue_banner);
		}

		return (susshi_proxy_auth_pubkey_phase1() == SSH_AUTH_PARTIAL);
	}

	return false;
}


/*!
 * @brief       Complete proxy authentication by sending the accepted key with a valid signature
 *
 * Calls @c susshi_proxy_auth_pubkey_phase2() to transmit the private key that was
 * identified in phase 1. Should only be called after @c susshi_proxy_auth_phase1()
 * has returned @c true.
 *
 * @return      @c true if the proxy accepted the signed key and authentication succeeded,
 *              @c false otherwise
 */

bool
susshi_proxy_auth_phase2(void) {

	susshi_session.target_proxy_phase = PHASE_AUTH_START;

	return (susshi_proxy_auth_pubkey_phase2() == SSH_AUTH_SUCCESS);
}


/*!
 * @brief       Probe each configured gateway identity against the proxy without signing (unsigned probe)
 *
 * Iterates over @c susshi_cfg.target_identities and calls @c ssh_userauth_try_publickey()
 * for each one. Stops at the first key the proxy accepts. On success, records the
 * accepted key index in @c susshi_session.key_used_for_proxy_auth and returns
 * @c SSH_AUTH_PARTIAL to signal that a matching key was found but authentication is
 * not yet complete. Returns the last @c SSH_AUTH_* code if no key was accepted.
 *
 * @return      @c SSH_AUTH_PARTIAL if an acceptable key was found,
 *              otherwise an @c SSH_AUTH_* error or denied code
 */

static int
susshi_proxy_auth_pubkey_phase1(void) {
	int k, rc = SSH_AUTH_ERROR;
	long timeout = 300;
	int ssh_ret;
	enum ssh_keytypes_e ssh_key_type;
	bstrList split_public_blob = NULL;
	ssh_key public_key = NULL;

	bool context_keys = false;

	/* Change timeout for session during interactive authentication */
	ssh_options_set(susshi_session.client_session, SSH_OPTIONS_TIMEOUT, &timeout);

	susshi_session.key_used_for_proxy_auth = -1;

	// Iterate Keys and send them to proxy to probe which key may fit
	for (k = 0; ((k < susshi_cfg.num_target_identities) && (rc != SSH_AUTH_SUCCESS)); k++) {

		split_public_blob = bsplit(susshi_cfg.target_identities[k].public_blob, ' ');
		ssh_key_type = susshi_proxy_auth_keytype_from_string(bdata(susshi_cfg.target_identities[k].key_type));
		ssh_ret = ssh_pki_import_pubkey_base64(bdata(split_public_blob->entry[1]), ssh_key_type, &public_key);

		if (ssh_ret == SSH_OK) {
			if (ssh_key_is_public(public_key) == true) {

				debug3_dir(GATEWAY, PROXY, "Trying public %s key #%d: %s %s", context_keys ? "context" : "gateway",
						   k + 1,
						   bdata(susshi_cfg.target_identities[k].key_type),
						   bdata(susshi_cfg.target_identities[k].fingerprint));

				rc = ssh_userauth_try_publickey(susshi_session.target_proxy_session, bdata(susshi_session.target_proxy_login_user),
												public_key);
				if (rc == SSH_AUTH_SUCCESS) {
					susshi_session.key_used_for_proxy_auth = k;
					debug3_dir(PROXY, GATEWAY, "Proxy will accept key #%d", susshi_session.key_used_for_proxy_auth + 1);
				}
			} else {
				log_system(LOG_LEVEL_WARNING,
						   "Could not import gateway identity #%d. Seems to not be a public key in known format. Skipping.", k);
			}
		} else {
			log_system(LOG_LEVEL_WARNING, "Could not import gateway identity #%d. Skipping.", k);
		}
		bstrListDestroy(split_public_blob);
		SSH_KEY_FREE(public_key);
	}

	/* If one key fits, we should receive the DEBUG Message containing the JSON blob with target_ips now */
	if ((rc == SSH_AUTH_SUCCESS) && (susshi_session.key_used_for_proxy_auth > -1)) {
		return SSH_AUTH_PARTIAL;
	}

	return (rc);
}


/*!
 * @brief       Complete public-key authentication against the proxy by sending the signed private key
 *
 * Imports the private key for the identity selected in phase 1
 * (@c susshi_session.key_used_for_proxy_auth) using the encrypted private blob and
 * the @c susshi_memcrypt_ssh_privkey_callback decryption callback, then calls
 * @c ssh_userauth_publickey(). The private key is freed immediately after use.
 * Does nothing and returns @c SSH_AUTH_ERROR if the proxy session is no longer connected
 * or no key was recorded by phase 1.
 *
 * @return      @c SSH_AUTH_SUCCESS on success, otherwise an @c SSH_AUTH_* error code
 */

static int
susshi_proxy_auth_pubkey_phase2(void) {
	int use_key;
	int rc = SSH_AUTH_ERROR;
	int ssh_ret;
	ssh_key private_key = NULL;

	if (ssh_is_connected(susshi_session.target_proxy_session)) {
		/* If one key fits, send it again, but now signed */
		if ((use_key = susshi_session.key_used_for_proxy_auth) > -1) {

			ssh_ret = ssh_pki_import_privkey_base64(bdata(susshi_cfg.target_identities[use_key].private_blob), NULL,
													susshi_memcrypt_ssh_privkey_callback,
													bdata(susshi_cfg.installation_id),
													&private_key);

			if (ssh_ret == SSH_OK) {
				if (ssh_key_is_private(private_key) == 1) {
					debug3_dir(GATEWAY, PROXY, "Sending signed public key #%d: %s %s.", use_key + 1,
							   bdata(susshi_cfg.target_identities[use_key].key_type),
							   bdata(susshi_cfg.target_identities[use_key].fingerprint));

					rc = ssh_userauth_publickey(susshi_session.target_proxy_session,
												bdata(susshi_session.target_proxy_login_user),
												private_key);

					debug4("Burning proxy authentication private key.");
					SSH_KEY_FREE(private_key);
				} else {
					log_system(LOG_LEVEL_ERROR,
							   "Could not import gateway identity #%d. Seems to not be a valid private key in known format. Aborting.",
							   use_key);
				}
			} else {
				log_system(LOG_LEVEL_ERROR,
						   "Could not import gateway identity #%d. Seems to not be a valid private key in known format. Aborting.",
						   use_key);
			}
		} else {
			rc = SSH_AUTH_ERROR;
		}
	}

	if (rc == SSH_AUTH_SUCCESS) {
		log_system(LOG_LEVEL_INFO, "Successfully authenticated at proxy @%s (%s:%d).",
				bdata(susshi_session.target_proxy_realm), bdata(susshi_session.target_proxy_hostname),
				susshi_session.target_proxy_port);
	}

	return(rc);
}


/*!
 * @brief       Map a key-type name string to an @c ssh_keytypes_e value, rejecting unsupported types
 *
 * Calls @c ssh_key_type_from_name() and then filters the result to only the types
 * supported by suSSHi (@c RSA, @c ECDSA, @c ED25519).
 *
 * @param       string      Key-type name string (e.g. @c "ssh-rsa", @c "ssh-ed25519")
 *
 * @return      The matching @c ssh_keytypes_e value, or @c SSH_KEYTYPE_UNKNOWN for
 *              unrecognised or unsupported types
 */

static enum ssh_keytypes_e
susshi_proxy_auth_keytype_from_string(const char *string) {
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

/*! @} */
