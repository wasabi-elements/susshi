/*!
 *
 * @brief       OpenSSH Agent Inspection
 *
 * @ingroup     inspection
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
 * @defgroup    inspection_ossh OpenSSH Agent Inspection
 * @brief       Functions to inspect openSSH agent communication.
 * @brief       For protocol specifications see http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.agent?rev=HEAD
 *
 * @{
 */

#include "susshid/common.h"


/*!
 * @brief       Inspect Agent Data
 *
 * @param       cid         Channel ID
 * @param       sender      Side of sender
 * @param       buffer_copy Copy of actual ssh_buffer
 */

void
susshi_inspect_agent_data(int cid, Side sender, ssh_buffer buffer_copy)
{
	// SusshiChannel *c;
	ssh_string datastr = NULL;
	const char *data = NULL;
	uint32_t cmdlen, datalen;
	char cmd;
	uint32_t i;

	// c = susshi_session.channels[cid];

	/*
	 * All protocol messages are prefixed with their length in bytes, encoded as a 32 bit unsigned integer followed by the command
	 * -> This is basically an ssh_string
	 */

	if (ssh_buffer_unpack(buffer_copy, "dS", &cmdlen, &datastr) == SSH_OK) {

		data = ssh_string_get_char(datastr);
		datalen = (uint32_t) ssh_string_len(datastr);

		if_debug5() {
			do_debug4_dir(sender, TheOtherSide(sender), "####################### OSSH AGENT PACKET ###########################");
			do_susshi_hexdump(data, datalen);
		}

		cmd = data[0];

		switch (cmd) {
			case SSH2_AGENTC_REQUEST_IDENTITIES: {
				log_session(sender, TheOtherSide(sender), "SSH-Agent: Requesting Identities.");
			} break;

			case SSH2_AGENT_IDENTITIES_ANSWER: {
				uint32_t	num_keys;
				ssh_string  key_blob;
				ssh_string  key_comment;
				ssh_buffer  temp_buffer = ssh_buffer_new();
				const char *hashstr;

				ssh_buffer_add_data(temp_buffer, (const void *) &data[1], datalen -1);

				if (ssh_buffer_unpack(temp_buffer, "d", &num_keys) == SSH_OK) {
					debug3_dir(sender, TheOtherSide(sender), "SSH-Agent: Identities Answer containing %d keys", num_keys);
					for (i=0; i < num_keys; i++) {
						if (ssh_buffer_unpack(temp_buffer, "SS", &key_blob, &key_comment) == SSH_OK) {
							hashstr = susshi_display_hash_from_blob(ssh_string_get_char(key_blob), ssh_string_len(key_blob));
							log_session(sender, TheOtherSide(sender), "SSH-Agent: Identity answer(%d): FP %s, Comment %s",
										i + 1, hashstr, ssh_string_get_char(key_comment));
							xfree((void *) hashstr);
							SSH_STRING_FREE(key_blob);
							SSH_STRING_FREE(key_comment);
						}
					}
				}
				SSH_BUFFER_FREE(temp_buffer);
			} break;

			case SSH2_AGENTC_SIGN_REQUEST: {
				ssh_string  key_blob;
				ssh_string  sign_data;
				uint32_t    sign_flags;
				ssh_buffer  temp_buffer = ssh_buffer_new();
				const char *hashstr = NULL;

				ssh_buffer_add_data(temp_buffer, (const void *) &data[1], datalen -1);

				if (ssh_buffer_unpack(temp_buffer, "SSd", &key_blob, &sign_data, &sign_flags) == SSH_OK) {
					hashstr = susshi_display_hash_from_blob(ssh_string_get_char(key_blob), ssh_string_len(key_blob));
					log_session(sender, TheOtherSide(sender), "SSH-Agent: Signing Request for Key with FP %s", hashstr);
					debug3_dir(sender, TheOtherSide(sender), "SSH-Agent: Data to be signed: %s", ssh_string_get_char(sign_data));
					if (sign_flags == SSH_SIGN_FLAG_AGENT_OLD_SIGNATURE) {
						debug3_dir(sender, TheOtherSide(sender), "SSH-Agent: Sign-Flag 'Old Signature' set.");
					}


					xfree((void *) hashstr);
					SSH_STRING_FREE(key_blob);
					SSH_STRING_FREE(sign_data);
				}
				SSH_BUFFER_FREE(temp_buffer);
			} break;

			case SSH2_AGENT_SIGN_RESPONSE: {
				ssh_string  signature_blob;
				ssh_buffer  temp_buffer = ssh_buffer_new();

				ssh_buffer_add_data(temp_buffer, (const void *) &data[1], datalen -1);

				if (ssh_buffer_unpack(temp_buffer, "S", &signature_blob) == SSH_OK) {
					log_session(sender, TheOtherSide(sender), "SSH-Agent: Signed Response.");
					debug3_dir(sender, TheOtherSide(sender),
							   "SSH-Agent: Sign Response with signature blob of %ld bytes.", ssh_string_len(signature_blob));
					SSH_STRING_FREE(signature_blob);
				}
				SSH_BUFFER_FREE(temp_buffer);
			} break;

			case SSH_AGENTC_EXTENSION: {
				ssh_buffer  temp_buffer = ssh_buffer_new();
				ssh_string  extension;

				ssh_buffer_add_data(temp_buffer, (const void *) &data[1], datalen -1);

				if (ssh_buffer_unpack(temp_buffer, "S", &extension) == SSH_OK) {
					log_session(sender, TheOtherSide(sender), "SSH-Agent: Extension '%s' requested.", ssh_string_get_char(extension));
					SSH_STRING_FREE(extension);
				}
				SSH_BUFFER_FREE(temp_buffer);
			} break;

			case SSH_AGENT_SUCCESS:
				log_session(sender, TheOtherSide(sender), "SSH-Agent: Success.");
				break;

			case SSH_AGENT_FAILURE:
			case SSH2_AGENT_FAILURE:
				log_session(sender, TheOtherSide(sender), "SSH-Agent: Failure.");
				break;

			case SSH_AGENT_EXTENSION_RESPONSE: {
				ssh_buffer  temp_buffer = ssh_buffer_new();
				ssh_string  extension;

				ssh_buffer_add_data(temp_buffer, (const void *) &data[1], datalen -1);

				if (ssh_buffer_unpack(temp_buffer, "S", &extension) == SSH_OK) {
					log_session(sender, TheOtherSide(sender), "SSH-Agent: Extension '%s' response.", ssh_string_get_char(extension));
					SSH_STRING_FREE(extension);
				}
				SSH_BUFFER_FREE(temp_buffer);
			} break;

			case SSH_AGENT_EXTENSION_FAILURE:
				log_session(sender, TheOtherSide(sender), "SSH-Agent: Extension failure.");
				break;

			case SSH_COM_AGENT2_FAILURE:
				log_session(sender, TheOtherSide(sender), "SSH-Agent: Agent Failure (ssh.com's ssh-agent2).");
				break;

			default:
				log_session(sender, TheOtherSide(sender), "SSH-Agent: Unknown Request (%d)", cmd);
				break;
		}
		SSH_STRING_FREE(datastr);
	}
}

/*! @} */

