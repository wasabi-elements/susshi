/*!
 *
 * @brief       LibSSH Helpers
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
 * @ingroup     libssh_helper
 * @{
 */


#ifndef SUSSHI_LIBSSH_HELPERS_H
#define SUSSHI_LIBSSH_HELPERS_H

/* Prototypes */

void susshi_libssh_set_verbosity(ssh_session ssh_session, Side side);
int ssh_pki_export_pubkey_blob(const ssh_key key, ssh_string *pblob);
int ssh_pki_import_pubkey_blob(const ssh_string key_blob, ssh_key *pkey);
const char *susshi_ssh_key_type_to_char(struct ssh_key_struct* key);
const char *susshi_ssh_key_type_to_display_string(enum ssh_keytypes_e type);

void susshi_ssh_set_session_state(ssh_session session, enum ssh_session_state_e state);
enum ssh_session_state_e susshi_ssh_get_session_state(ssh_session session);
void susshi_ssh_set_global_request_state(ssh_session session, enum ssh_channel_request_state_e state);
enum ssh_channel_request_state_e susshi_ssh_get_global_request_state(ssh_session session);
void susshi_ssh_set_auth_state(ssh_session session, enum ssh_auth_state_e state);
enum ssh_auth_state_e susshi_ssh_get_auth_state(ssh_session session);
void susshi_libssh_close_pcaps(void);

ssh_signature pki_do_sign(const ssh_key privkey, const unsigned char *input, size_t input_len, enum ssh_digest_e hash_type);

/*
 * The following functions replace the original libSSH functions that gone depreciated with version 0.10.x
 */
const char *susshi_libssh_ssh_message_auth_password(ssh_message msg);
ssh_key susshi_libssh_ssh_message_auth_pubkey(ssh_message msg);
enum ssh_publickey_state_e susshi_libssh_ssh_message_auth_publickey_state(ssh_message msg);

#define susshi_buffer_duplicate(buffer_copy, buffer) memcpy(buffer_copy, buffer, sizeof(struct ssh_buffer_struct))

/* ssh_buffer_struct is an internal libssh type, exposed via our patch */
#include <libssh/buffer-struct.h>

#endif //SUSSHI_LIBSSH_HELPERS_H

/*! @} */
