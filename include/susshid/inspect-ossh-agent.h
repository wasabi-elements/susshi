/*!
 *
 * @brief       OpenSSH Agent Inspection
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
 * @ingroup     inspection_ossh
 *
 * @{
 */


#ifndef SUSSHI_INSPECT_OSSH_AGENT_H
#define SUSSHI_INSPECT_OSSH_AGENT_H

/* Prototypes */
void susshi_inspect_agent_data(int cid, Side sender, ssh_buffer buffer_copy);

/* Messages for the authentication agent connection. */
#define SSH_AGENT_FAILURE                   5
#define SSH_AGENT_SUCCESS                   6

/* private OpenSSH extensions for SSH2 */
#define SSH2_AGENTC_REQUEST_IDENTITIES		11
#define SSH2_AGENT_IDENTITIES_ANSWER		12
#define SSH2_AGENTC_SIGN_REQUEST		    13
#define SSH2_AGENT_SIGN_RESPONSE		    14

/* generic extension mechanism */
#define SSH_AGENTC_EXTENSION                27
#define SSH_AGENT_EXTENSION_FAILURE         28
#define SSH_AGENT_EXTENSION_RESPONSE        29

/* extended failure messages */
#define SSH2_AGENT_FAILURE                  30

/* additional error code for ssh.com's ssh-agent2 */
#define SSH_COM_AGENT2_FAILURE              102

#define SSH_SIGN_FLAG_AGENT_OLD_SIGNATURE   1

#endif //SUSSHI_INSPECT_OSSH_AGENT_H

/*! @} */
