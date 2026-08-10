/*!
 *
 * @brief       Chef Control Commands
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
 * @ingroup     chef_remote
 * @{
 */

#ifndef SUSSHI_CHEF_REMOTE_H
#define SUSSHI_CHEF_REMOTE_H

/* Prototypes */
void    susshi_chef_remote_loop(void);

#define SUSSHI_CHEF_REMOTE_USER "#chef-remote#"

#define RCMD_STATUS "status"
#define RCMD_AUTH_GRANT "auth-grant"
#define RCMD_AUTH_GRANT_MATCH RCMD_AUTH_GRANT " "
#define RCMD_STATUS_PROXY "status-proxy"
#define RCMD_STATUS_PROXY_MATCH RCMD_STATUS_PROXY " "
#define RCMD_RESTART "restart"
#define RCMD_SCAN_HOSTKEYS "scan-hostkeys"
#define RCMD_SCAN_HOSTKEYS_MATCH RCMD_SCAN_HOSTKEYS " "
#define RCMD_SCAN_HOSTKEYS_PROXY "scan-hostkeys-proxy"
#define RCMD_SCAN_HOSTKEYS_PROXY_MATCH RCMD_SCAN_HOSTKEYS_PROXY " "
#define RCMD_TERM_SESSION "terminate"
#define RCMD_TERM_SESSION_MATCH RCMD_TERM_SESSION " "
#define RCMD_SHUTDOWN "shutdown"
#define RCMD_SUSPEND "suspend"
#define RCMD_UNSUSPEND "unsuspend"

#endif //SUSSHI_CHEF_REMOTE_H

/*! @} */
