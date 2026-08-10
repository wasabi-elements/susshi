/*!
 *
 * @brief       Target Authentication
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
 * @ingroup     auth_target
 * @{
 */

#ifndef SUSSHI_AUTH_TARGET_H
#define SUSSHI_AUTH_TARGET_H

// UserTargetKnownhosts Flags are marked in a bitmask

typedef struct {
	const int        method;                // Bitmask ID
	const char	    *alias;			        // string we use internally to identify the method more specific
	int            (*auth_function)(void);
	bool	         enabled;
	bool             enable_by_default;
} TargetAuthMethod;


typedef enum {
	S_INIT,
	S_TARGET_INFO,
	S_TARGET_AGAIN,
	S_CLIENT_START,
	S_CLIENT_WAIT,
	S_CLIENT_ANSWER
} KbdIntStates;

extern TargetAuthMethod target_auth_methods[];

/* Prototypes */
bool	susshi_target_auth(void);
int     susshi_target_auth_find_method(bstring method);
void    susshi_target_auth_method_fill_susshi_cfg(void);

#endif //SUSSHI_AUTH_TARGET_H

/*! @} */
