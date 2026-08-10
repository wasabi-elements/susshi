/*!
 *
 * @brief       Signal Handling
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
 * @ingroup     signal
 * @{
 */

#ifndef SUSSHI_SIGNAL_H
#define SUSSHI_SIGNAL_H

/* Prototypes */
void    susshi_sigaction(int signal, void (*handler)(int), int sa_flags);
void	susshi_timer_alarms_register(void);
void	susshi_session_loop_signal_register(void);
void	susshi_master_loop_signal_register(void);

#endif //SUSSHI_SIGNAL_H

/*! @} */
