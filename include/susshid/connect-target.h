/*!
 *
 * @brief       Hostkey Update and Rotation "hostkeys-00@openssh.com"
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
 * @ingroup     connect_target
 * @{
 */


#ifndef SUSSHI_CONNECT_TARGET_H
#define SUSSHI_CONNECT_TARGET_H

bool    susshi_target_login(void);
KeyVerifyResponse    susshi_target_verify_hostkey(void);

/*
 * This is the exact same list, preferred by libssh (as of 0.8.7) if SSH_OPTIONS_HOSTKEY is not set.
 */

#ifdef HAVE_DSA
#define DEFAULT_PREFERRED_HOST_KEY_ALGOS 		"ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss"
#else
#define DEFAULT_PREFERRED_HOST_KEY_ALGOS 		"ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-rsa"
#endif

#endif //SUSSHI_CONNECT_TARGET_H

/*! @} */
