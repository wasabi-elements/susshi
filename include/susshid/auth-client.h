/*!
 *
 * @brief       Client Authentication
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
 * @ingroup     auth_client
 * @{
 */

#ifndef SUSSHI_AUTH_CLIENT_H
#define SUSSHI_AUTH_CLIENT_H

/* Prototypes */
void    susshi_client_auth_disable_all_methods(void);
void    susshi_client_auth_disable_method(u_int32_t method);
void    susshi_client_auth_enable_method(u_int32_t method);
bool    susshi_client_auth_add_method(const char *method);
bool    susshi_client_auth_add_preferred_method(const char *method);
bool    susshi_client_auth_add_required_method(const char *method);
bool    susshi_client_auth_start(void);
void    susshi_client_auth_finish(bool success);
void	susshi_client_send_banner(const char *msg);

#endif // SUSSHI_AUTH_CLIENT_H

/*! @} */
