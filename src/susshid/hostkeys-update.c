/*!
 *
 * @brief       Hostkey Update and Rotation "hostkeys-00@openssh.com"
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
 * ### Details
 *
 * Hostkey update and rotation "hostkeys-00@openssh.com" and "hostkeys-prove-00@openssh.com"
 *
 * OpenSSH supports a protocol extension allowing a server to inform a client of all its protocol v.2 host
 * keys after user-authentication has completed.
 *
 * ```
 * byte     SSH_MSG_GLOBAL_REQUEST
 * string       "hostkeys-00@openssh.com"
 * string[] hostkeys
 * ```
 *
 * Upon receiving this message, a client should check which of the supplied host keys are present in known_hosts.
 *
 * Note that the server may send key types that the client does not support.
 * The client should disgregard such keys if they are received.
 *
 * If the client identifies any keys that are not present for the host, it should send a "hostkeys-prove@openssh.com"
 * message to request the server prove ownership of the private half of the key.
 *
 * ```
 * byte     SSH_MSG_GLOBAL_REQUEST
 * string       "hostkeys-prove-00@openssh.com"
 * char     1 // want-reply
 * string[] hostkeys
 * ```
 *
 * When a server receives this message, it should generate a signature using each requested key over the following:
 *
 * ```
 * string       "hostkeys-prove-00@openssh.com"
 * string       session identifier
 * string       hostkey
 * ```
 *
 * These signatures should be included in the reply, in the order matching  the hostkeys in the request:
 *
 * ```
 * byte     SSH_MSG_REQUEST_SUCCESS
 * string[] signatures
 * ```
 *
 * When the client receives this reply (and not a failure), it should validate the signatures and may update its
 * known_hosts file, adding keys that it has not seen before and deleting keys for the server host that
 * are no longer offered.
 *
 * These extensions let a client learn key types that it had not previously encountered, thereby allowing it
 * to potentially upgrade from weaker key algorithms to better ones. It also supports graceful key rotation:
 * a server may offer multiple keys of the same type for a period (to give clients an opportunity to learn
 * them using this extension) before removing the deprecated key from those offered.
 *
 * @author      Oliver Rauscher <oliver@susshi.io>
 * @date        2026-02-01
 *
 * @defgroup    hostkeys_update Hostkey Update and Rotation "hostkeys-00@openssh.com"
 * @{
 */

#include <susshid/common.h>


/*!
 * @brief       Send Gateway Host-Keys to Client - hostkeys-00@openssh.com Request
 *
 */

void
susshi_hostkeys_update_send_hostkeys(void) {


	if (susshi_cfg.client_hostkey_update) {

		/* Only OpenSSH and Bitvise FlowSsh support this feature */
		if ((susshi_session.client_product == CLIENT_IS_OPENSSH) ||
			(susshi_session.client_product == CLIENT_IS_FLOWSSH)) {

			debug3_dir(GATEWAY, CLIENT, "Sending Hostkeys update and rotation request 'hostkeys-00@openssh.com' "
										"with %d host keys in total.", susshi_cfg.num_host_key_files);

			ssh_buffer_pack(susshi_session.client_session->out_buffer, "bsb",
							SSH2_MSG_GLOBAL_REQUEST,
							"hostkeys-00@openssh.com",
							0);

			for (int i = 0; i < susshi_cfg.num_host_key_files; i++) {
				ssh_string pubkey_blob;

				if (ssh_pki_export_pubkey_blob(susshi_cfg.host_key_pubs[i], &pubkey_blob) == SSH_OK) {
					ssh_buffer_add_ssh_string(susshi_session.client_session->out_buffer, pubkey_blob);
					ssh_string_free(pubkey_blob);
				} else {
					fatal("susshi_hostkeys_update_send_hostkeys: Could not export pubkey blob.");
				}
			}

			ssh_packet_send(susshi_session.client_session);
		} else {
			debug4("Hostkeys update and rotation request 'hostkeys-00@openssh.com' is enabled, but not supported by client.");
		}
	} else {
		debug4("Hostkeys update and rotation request 'hostkeys-00@openssh.com' is not enabled.");
	}
}


/*!
 * @brief       Prove (Sign) Hostkeys received from Client on behalf of GLOBAL-REQUEST hostkeys-00@openssh.com
 *
 * @param       buffer_copy     Copy of the actual ssh_buffer
 *
 * @return      true if successful
 */

bool
susshi_hostkeys_update_prove_hostkeys(ssh_buffer buffer_copy) {
	ssh_string requested_pubkey_blob;
	ssh_string session_id;
	ssh_key requested_pubkey;
	struct ssh_crypto_struct *crypto = NULL;
	int s;

	ssh_buffer_pack(susshi_session.client_session->out_buffer, "b", SSH2_MSG_REQUEST_SUCCESS);

	debug3_dir(CLIENT, GATEWAY, "Received host key prove request 'hostkeys-prove-00@openssh.com' for at least one host key.");

	crypto = ssh_packet_get_current_crypto(susshi_session.client_session, SSH_DIRECTION_BOTH);
	if (crypto == NULL) {
		fatal("susshi_hostkeys_update_prove_hostkeys() - Could not get current crypto");
	}

	/* Get the session ID */
	session_id = ssh_string_new(crypto->digest_len);
	if (session_id == NULL) {
		fatal("Could not run without session_id");
	}
	ssh_string_fill(session_id, crypto->session_id, crypto->digest_len);

	for (s=0; ssh_buffer_unpack(buffer_copy, "S", &requested_pubkey_blob) == SSH_OK; s++) {

		debug3("Extracted public host key #%d from message.", s+1);

		if (ssh_pki_import_pubkey_blob(requested_pubkey_blob, &requested_pubkey) == SSH_OK) {

			for(int i=0; i < susshi_cfg.num_host_key_files; i++ ) {
				if (ssh_key_cmp(requested_pubkey, susshi_cfg.host_key_pubs[i], SSH_KEY_CMP_PUBLIC) == 0) {
					ssh_buffer buf = ssh_buffer_new();
					ssh_key privkey;
					ssh_signature signature;
					ssh_string signature_string;

					ssh_buffer_set_secure(buf);

					debug4("Received host key #%d is of type '%s' (FP: %s) and is one of ours.",
							s+1, ssh_key_type_to_char(ssh_key_type(requested_pubkey)), susshi_display_hash_from_key(requested_pubkey));

					debug4("Corresponding Host-Key File is %s", bdata(susshi_cfg.host_key_files[i]));

					if (ssh_pki_import_privkey_file(bdata(susshi_cfg.host_key_files[i]), NULL, NULL, NULL, &privkey) == SSH_OK) {

						/* Buffer to be signed */
						ssh_buffer_pack(buf, "sSS", "hostkeys-prove-00@openssh.com", session_id, requested_pubkey_blob);

						/* Sign buffer */
						if (ssh_key_type(requested_pubkey) == SSH_KEYTYPE_RSA) {
							/*
							 * For RSA keys, prefer to use the signature type negotiated during KEX to the default
							 * (From openssh/serverloop.c server_input_hostkeys_prove() comment)
							 */
							signature = pki_do_sign(privkey, ssh_buffer_get(buf), ssh_buffer_get_len(buf),
									susshi_session.client_session->srv.hostkey_digest);
						} else {
							signature = pki_do_sign(privkey, ssh_buffer_get(buf), ssh_buffer_get_len(buf),
													ssh_key_hash_from_name(ssh_key_type_to_char(ssh_key_type(requested_pubkey))));
						}

						if (ssh_pki_export_signature_blob(signature, &signature_string) == SSH_OK) {
							ssh_buffer_add_ssh_string(susshi_session.client_session->out_buffer, signature_string);
							debug3("Added signature for requested pubkey #%d to prove that we have the private key.",
									s+1);

							ssh_string_free(signature_string);
						}
						ssh_signature_free(signature);
						ssh_key_free(privkey);
					}
					ssh_buffer_free(buf);
				}
			}
		}
	}

	/* Send packet with signatures */
	ssh_packet_send(susshi_session.client_session);

	debug3_dir(GATEWAY, CLIENT, "Sending reply with signature(s) for %d key(s).", s);

	ssh_string_free(session_id);

	return true;
}

/*! @} */
