/*!
 *
 * @brief       Public-Key Agent Authentication
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
 * @ingroup     auth_pubkey_agent
 * @{
 */
#ifndef SUSSHI_AUTH_PUBKEY_AGENT_H
#define SUSSHI_AUTH_PUBKEY_AGENT_H

/* Messages for the authentication agent connection. */
#define SSH_AGENT_FAILURE                        5
#define SSH_AGENT_SUCCESS                        6

/* private OpenSSH extensions for SSH2 */
#define SSH2_AGENTC_REQUEST_IDENTITIES           11
#define SSH2_AGENT_IDENTITIES_ANSWER             12
#define SSH2_AGENTC_SIGN_REQUEST                 13
#define SSH2_AGENT_SIGN_RESPONSE                 14

#define PAA_PREFIX  "PubkeySSHAgent / "

int susshi_pubkey_agent_client_ready(void);

#endif //SUSSHI_AUTH_PUBKEY_AGENT_H

/*! @} */
