/*!
 *
 * @brief       Authentication
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
 * @defgroup    auth    Authentication
 * @{
 */

#ifndef SUSSHI_AUTH_H
#define SUSSHI_AUTH_H

typedef enum  {
    /** No authentication asked */
			SUSSHI_AUTH_STATE_NONE=0,
    /** Last authentication response was a partial success */
			SUSSHI_AUTH_STATE_PARTIAL,
    /** Last authentication response was a success */
			SUSSHI_AUTH_STATE_SUCCESS,
    /** Last authentication response was failed */
			SUSSHI_AUTH_STATE_FAILED,
    /** Last authentication was erroneous */
			SUSSHI_AUTH_STATE_ERROR,
    /** Last state was a public key accepted for authentication */
			SUSSHI_AUTH_STATE_PK_OK,
    /** We asked for a keyboard-interactive authentication */
			SUSSHI_AUTH_STATE_KBDINT_SENT
} AuthState;

typedef enum  {
    /** ACL denied */
			SUSSHI_ACL_DENY = 0,
    /** ACL allowed */
			SUSSHI_ACL_ALLOW = 1,
} AclState;


#endif // SUSSHI_AUTH_H

/*! @} */
