/*!
 *
 * @brief       libssh Helper methods
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
 * @defgroup    proxy_libssh_helper LibSSH Helper methods
 * @brief       Helper functions used in conjunction with libssh.
 * @{
 *
 */

#include "susshi-proxyd/common.h"


/*!
 * @brief Switch on libssh verbosity based on debug level
 *
 * @param   ssh_session     The SSH session
 */

void
proxy_libssh_set_verbosity(ssh_session ssh_session) {
	int verbosity;

	if (ssh_session == NULL)
		return;

	switch (log_level) {
		case LOG_DEBUG_PACKET:
			verbosity = SSH_LOG_PACKET;
			break;
		case LOG_DEBUG_PACKETDUMP:
			verbosity = SSH_LOG_FUNCTIONS;
			break;
		default:
			verbosity = SSH_LOG_NOLOG;
	}

	ssh_options_set(ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
}


/*!
 * @brief       Create a copy of the buffer struct, but not DATA
 *
 * On the duplicated buffer you are able to read ahead with buffer_get commands without changing the position of the original buffer.
 *
 * Use proxy_buffer_dup_free() only to free buffer! Using ssh_buffer_free() will free DATA as well.
 *
 * @param       buffer      The target ssh_buffer
 * @param       source      The source ssh_buffer
 *
 * @return      0
 */

int
proxy_buffer_dup(ssh_buffer *buffer, ssh_buffer source) {
	*buffer = ssh_buffer_new();
	memcpy(*buffer, source, sizeof(struct ssh_buffer_struct));
	return 0;
}


/*!
 * @brief       Free the duplicated buffer
 *
 * @param       buffer      The ssh_buffer to free
 */

void
proxy_buffer_dup_free(ssh_buffer buffer) {
	free(buffer);
}

/*!
 * @brief       Convert a key type to a string.
 *
 * This is just a wrapper function to libssh's ssh_key_type_to_char() because libssh is somehow mixing up between
 * ssh-ecdsa and ecdsa-sha2-nistp521.
 * So ssh_key_type_to_char() returns ssh-ecdsa, while protocol requires usage of ecdsa-sha2-nistp521.
 *
 * @param[in]   key     The type to convert.
 *
 * @return      A string for the keytype or NULL if unknown.
 */

const char *
proxy_ssh_key_type_to_char(struct ssh_key_struct* key) {

	if (key->type_c != NULL)
		return key->type_c;

	return ssh_key_type_to_char(ssh_key_type(key));
}

/*!
 * @brief       Convert a key type to a string.
 *
 * @param[in]   type     The type to convert.
 *
 * @return      A string for the keytype or NULL if unknown.
 */

const char *
proxy_ssh_key_type_to_display_string(enum ssh_keytypes_e type) {

	switch (type) {
		case SSH_KEYTYPE_RSA:
			return "RSA";
		case SSH_KEYTYPE_ECDSA:
			return "ECDSA";
		case SSH_KEYTYPE_ED25519:
			return "ED25519";
		case SSH_KEYTYPE_DSS_CERT01:
			return "DSS-CERT";
		case SSH_KEYTYPE_RSA_CERT01:
			return "RSA-CERT";
		default:
			return "UNKNOWN";
	}

	/* We should never reach this */
	return NULL;
}

/*
 * The following functions replace the original libSSH functions that gone depreciated with version 0.10.x
 */

/*!
 * @brief       Replacement for original libSSH functions that gone depreciated with version 0.10.x
 *
 * @param       msg     ssh_message
 *
 * @return      The public key of the auth request
 */

ssh_key
susshi_libssh_ssh_message_auth_pubkey(ssh_message msg) {
	if (msg == NULL) {
		return NULL;
	}

	return msg->auth_request.pubkey;
}


/*!
 * @brief       Replacement for original libSSH functions that gone depreciated with version 0.10.x
 *
 * @param       msg     ssh_message
 *
 * @return      The public signature state of the auth request
 */

enum ssh_publickey_state_e
susshi_libssh_ssh_message_auth_publickey_state(ssh_message msg){
	if (msg == NULL) {
		return -1;
	}
	return msg->auth_request.signature_state;
}


/*! @} */
