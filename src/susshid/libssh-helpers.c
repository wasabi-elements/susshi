/*!
 *
 * @brief       LibSSH Helpers
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
 * @defgroup    libssh_helper LibSSH Helper methods
 * @brief       Helper functions used in conjunction with libssh.
 * @{
 */


#include "susshid/common.h"

#ifdef WITH_FULL_DEBUG_OPTIONS


/*!
 * @brief       Open a PCAP capture file for a libssh session and attach it for cleartext traffic dumping
 *
 * The file is created at @c PATH_LIBSSH_PCAP/{client,proxy,target}.pcap depending on @p side.
 * Parent directories are created automatically. Only compiled in when @c WITH_FULL_DEBUG_OPTIONS is set.
 *
 * @param       ssh_session     The libssh session to attach the PCAP file to
 * @param       side            Which side of the session to capture (@c CLIENT, @c PROXY, or @c TARGET)
 */

static void
susshi_libssh_set_pcap(ssh_session ssh_session, Side side) {
	bstring pcap_file = NULL;
	ssh_pcap_file *pcap;

	switch(side) {
		case CLIENT:
			pcap_file = bfromcstr(PATH_LIBSSH_PCAP "client.pcap");
			pcap = &susshi_session.client_pcap_file;
			break;
		case PROXY:
			pcap_file = bfromcstr(PATH_LIBSSH_PCAP  "proxy.pcap");
			pcap = &susshi_session.proxy_pcap_file;
			break;
		case TARGET:
			pcap_file = bfromcstr(PATH_LIBSSH_PCAP  "target.pcap");
			pcap = &susshi_session.target_pcap_file;
			break;
		default:
			return;
	}

	if(!pcap_file)
		return;

	*pcap = ssh_pcap_file_new();

	if (*pcap) {

		create_subdir(pcap_file);

		if (ssh_pcap_file_open(*pcap, bdata(pcap_file)) == SSH_ERROR) {
			debug4("Error opening pcap file %s: %s", bdata(pcap_file), ssh_get_error(ssh_session));
			ssh_pcap_file_free(*pcap);
			return;
		} else {
			debug4("Set LibSSH to dump packets of %s session into PCAP file %s", SideString[side], bdata(pcap_file));
			ssh_set_pcap_file(ssh_session, *pcap);
		}
	} else {
		debug4("Could not allocated new pcap file.");
	}

}


/*!
 * @brief       Free and close all open libssh PCAP capture file handles for the current session
 *
 * Only compiled in when @c WITH_FULL_DEBUG_OPTIONS is set.
 */

void
susshi_libssh_close_pcaps(void) {
	if (susshi_session.client_pcap_file)
		ssh_pcap_file_free(susshi_session.client_pcap_file);
	if (susshi_session.proxy_pcap_file)
		ssh_pcap_file_free(susshi_session.proxy_pcap_file);
	if (susshi_session.target_pcap_file)
		ssh_pcap_file_free(susshi_session.target_pcap_file);
}

#else


/*!
 * @brief       No-op stub for @c susshi_libssh_set_pcap, compiled in without @c WITH_FULL_DEBUG_OPTIONS
 *
 * @param       ssh_session     Unused
 * @param       side            Unused
 */

static void
susshi_libssh_set_pcap(ssh_session ssh_session, Side side) {
	(void) ssh_session;
	(void) side;
}


/*!
 * @brief       No-op stub for @c susshi_libssh_close_pcaps, compiled in without @c WITH_FULL_DEBUG_OPTIONS
 */

void
susshi_libssh_close_pcaps(void) {
}

#endif


/*!
 * @brief       Configure libssh log verbosity for a session based on the current susshi log level
 *
 * At @c LOG_DEBUG_PACKETDUMP, PCAP capture is also enabled for @p side via @c susshi_libssh_set_pcap().
 * Has no effect if @p ssh_session is @c NULL.
 *
 * @param       ssh_session     The libssh session to configure
 * @param       side            The session side, passed to @c susshi_libssh_set_pcap() at the highest debug level
 */

void
susshi_libssh_set_verbosity(ssh_session ssh_session, Side side) {
	int verbosity;

	if (ssh_session == NULL)
		return;

	switch (log_level) {
		case LOG_DEBUG_PACKET:
			verbosity = SSH_LOG_PACKET;
			break;
		case LOG_DEBUG_PACKETDUMP:
			verbosity = SSH_LOG_FUNCTIONS;
			susshi_libssh_set_pcap(ssh_session, side);
			break;
		default:
			verbosity = SSH_LOG_NOLOG;
	}

	ssh_options_set(ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
}


/*!
 * @brief       Return the wire-format key type string for an @c ssh_key, preferring the key's own @c type_c field
 *
 * Works around a libssh inconsistency where @c ssh_key_type_to_char() returns @c "ssh-ecdsa"
 * but the SSH protocol requires @c "ecdsa-sha2-nistp521". When @c key->type_c is set it is
 * returned directly; otherwise falls back to @c ssh_key_type_to_char().
 *
 * @param[in]   key     The key whose wire-format type string to retrieve
 *
 * @return      Wire-format key type string (e.g. @c "ecdsa-sha2-nistp521"), or @c NULL if unknown
 */

const char *
susshi_ssh_key_type_to_char(struct ssh_key_struct* key) {

	if (key->type_c != NULL)
		return key->type_c;

	return ssh_key_type_to_char(ssh_key_type(key));
}


/*!
 * @brief       Return a short human-readable display label for a key type (e.g. @c "RSA", @c "ECDSA")
 *
 * Unlike @c susshi_ssh_key_type_to_char(), this returns an uppercase display name
 * rather than the wire-format protocol string.
 * Returns @c "UNKNOWN" for unrecognised types rather than @c NULL.
 *
 * @param[in]   type    The key type enum value to convert
 *
 * @return      Short display label string; never @c NULL
 */

const char *
susshi_ssh_key_type_to_display_string(enum ssh_keytypes_e type) {

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


/*!
 * @brief       Directly set the internal session state of a libssh session
 *
 * Accesses the libssh-internal @c session_state field, which has no public setter API.
 *
 * @param       session     The libssh session to modify
 * @param       state       The new session state to set
 */

void
susshi_ssh_set_session_state(ssh_session session, enum ssh_session_state_e state) {
	session->session_state = state;
}


/*!
 * @brief       Read the internal session state of a libssh session
 *
 * @param       session     The libssh session to query
 *
 * @return      Current session state
 */

enum ssh_session_state_e
susshi_ssh_get_session_state(ssh_session session) {
	return session->session_state;
}


/*!
 * @brief       Directly set the internal global request state of a libssh session
 *
 * Accesses the libssh-internal @c global_req_state field, which has no public setter API.
 *
 * @param       session     The libssh session to modify
 * @param       state       The new global request state to set
 */

void
susshi_ssh_set_global_request_state(ssh_session session, enum ssh_channel_request_state_e state) {
	session->global_req_state = state;
}


/*!
 * @brief       Read the internal global request state of a libssh session
 *
 * @param       session     The libssh session to query
 *
 * @return      Current global request state
 */

enum ssh_channel_request_state_e
susshi_ssh_get_global_request_state(ssh_session session) {
	return session->global_req_state;
}


/*!
 * @brief       Directly set the internal authentication state of a libssh session
 *
 * Accesses the libssh-internal @c auth.state field, which has no public setter API.
 *
 * @param       session     The libssh session to modify
 * @param       state       The new authentication state to set
 */

void
susshi_ssh_set_auth_state(ssh_session session, enum ssh_auth_state_e state) {
	session->auth.state = state;
}


/*!
 * @brief       Read the internal authentication state of a libssh session
 *
 * @param       session     The libssh session to query
 *
 * @return      Current authentication state
 */

enum ssh_auth_state_e
susshi_ssh_get_auth_state(ssh_session session) {
	return session->auth.state;
}

/*
 * The following functions replace libssh API functions that were removed as of version 0.10.x
 */


/*!
 * @brief       Replacement for the removed @c ssh_message_auth_password() libssh API function
 *
 * @param       msg     The @c ssh_message to query; may be @c NULL
 *
 * @return      The plaintext password from the authentication request, or @c NULL if @p msg is @c NULL
 */

const char *
susshi_libssh_ssh_message_auth_password(ssh_message msg){
	if (msg == NULL) {
		return NULL;
	}

	return msg->auth_request.password;
}


/*!
 * @brief       Replacement for the removed @c ssh_message_auth_pubkey() libssh API function
 *
 * @param       msg     The @c ssh_message to query; may be @c NULL
 *
 * @return      The public key from the authentication request, or @c NULL if @p msg is @c NULL
 */

ssh_key
susshi_libssh_ssh_message_auth_pubkey(ssh_message msg) {
	if (msg == NULL) {
		return NULL;
	}

	return msg->auth_request.pubkey;
}


/*!
 * @brief       Replacement for the removed @c ssh_message_auth_publickey_state() libssh API function
 *
 * @param       msg     The @c ssh_message to query; may be @c NULL
 *
 * @return      The signature state of the public key authentication request,
 *              or @c -1 if @p msg is @c NULL
 */

enum ssh_publickey_state_e
susshi_libssh_ssh_message_auth_publickey_state(ssh_message msg){
	if (msg == NULL) {
		return -1;
	}
	return msg->auth_request.signature_state;
}

/*! @} */
