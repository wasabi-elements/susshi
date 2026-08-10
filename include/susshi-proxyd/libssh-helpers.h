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
 * @ingroup     proxy_libssh_helper
 * @{
 */

#ifndef SUSSHI_PROXYD_LIBSSH_HELPERS_H
#define SUSSHI_PROXYD_LIBSSH_HELPERS_H

/* Prototypes */

void proxy_libssh_set_verbosity(ssh_session ssh_session);
int  proxy_buffer_dup(ssh_buffer *buffer, ssh_buffer source);
void proxy_buffer_dup_free(ssh_buffer buffer);
int ssh_pki_export_pubkey_blob(const ssh_key key, ssh_string *pblob);
int ssh_pki_import_pubkey_blob(const ssh_string key_blob, ssh_key *pkey);
const char *proxy_ssh_key_type_to_char(struct ssh_key_struct* key);
const char *proxy_ssh_key_type_to_display_string(enum ssh_keytypes_e type);

/*
 * The following functions replace the original libSSH functions that gone depreciated with version 0.10.x
 */
ssh_key susshi_libssh_ssh_message_auth_pubkey(ssh_message msg);
enum ssh_publickey_state_e susshi_libssh_ssh_message_auth_publickey_state(ssh_message msg);

/* ssh_buffer_struct is an internal libssh type, exposed via our patch */
#include <libssh/buffer-struct.h>

#endif //SUSSHI_PROXYD_LIBSSH_HELPERS_H

/*! @} */
