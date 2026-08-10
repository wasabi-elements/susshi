/*!
 *
 * @brief       The suSSHi Gateway daemon
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
 * @{
 */

#ifndef SUSSHI_SUSSHID_MAIN_H
#define SUSSHI_SUSSHID_MAIN_H

extern bool flag_debug;
extern bool flag_no_daemon;
extern bool flag_main_process_in_foreground;

/* Prototypes */
void susshid_main(int argc, char **argv, char **envp, bool first_startup);
void usage(void);

#endif //SUSSHI_SUSSHID_MAIN_H

/*! @} */
