/*!
 *
 * @brief       Proxy Gateway Authentication
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
 * @ingroup     proxy_auth_gateway
 * @{
 */

#ifndef SUSSHI_PROXYD_AUTH_GATEWAY_H
#define SUSSHI_PROXYD_AUTH_GATEWAY_H

/* Prototypes */
bool    proxy_gateway_auth_start(void);
void    proxy_gateway_auth_finish(void);
void    proxy_gateway_auth_send_error_json(int error_code);

#endif // SUSSHI_PROXYD_AUTH_GATEWAY_H

/*! @} */
