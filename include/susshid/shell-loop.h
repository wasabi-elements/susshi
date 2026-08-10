/*!
 *
 * @brief       Shell Loop
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
 * @ingroup     shell_loop
 * @{
 */

#ifndef SUSSHI_SHELL_LOOP_H
#define SUSSHI_SHELL_LOOP_H

#define SHELL_BUF_SIZE 1048576

/* Prototypes */
void    susshi_shell_loop(void);

struct shell_channel_data_struct {
	pid_t child_pid;
	socket_t pty_master;
	socket_t pty_slave;
	socket_t child_stdin;
	socket_t child_stdout;
	socket_t child_stderr;
	ssh_event event;
	bstring term;
	struct winsize *winsize;
};

#endif //SUSSHI_SHELL_LOOP_H

/*! @} */
