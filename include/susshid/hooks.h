/*!
 *
 * @brief       Administrator Hook System
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
 * @date        2026-06-19
 *
 * @ingroup     susshid
 * @{
 */

#ifndef SUSSHID_HOOKS_H
#define SUSSHID_HOOKS_H

typedef enum {
    HOOK_SESSION_FAILED = 0,
    HOOK_SESSION_AUTH_FAILED,
    HOOK_SESSION_TARGET_CONNECT_FAILED,
    HOOK_SESSION_TARGET_AUTH_FAILED,
    HOOK_SESSION_START,
    HOOK_GATEWAY_START,
    HOOK_GATEWAY_STOP,
    HOOK_CLIENT_CONNECT,
    HOOK_SESSION_FINISHED,
    HOOK_COUNT
} HookType;

/* Prototypes */
void susshi_hooks_init(void);
void susshi_hooks_run(HookType hook);

#endif /* SUSSHID_HOOKS_H */

/*! @} */
