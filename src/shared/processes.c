/*!
 *
 * @brief       Processes methods
 *
 * @ingroup     shared
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
 * @defgroup    processes Processes methods
 * @{
 */

#include "shared/common.h"
#include "shared/processes.h"
#include "shared/log.h"


/*!
 * @brief       Walk the process list, count matches by name prefix, and optionally signal them
 *
 * Process names are matched using @c strncmp against the start of @c argv[0].
 * If @p signal is @c -1, processes are counted only and no signal is sent.
 * If @p signal is >= 0, each matching process is sent that signal.
 *
 * @param       pattern         Prefix to match against process @c argv[0]
 * @param       signal          Signal to send to matching processes, or @c -1 to count only
 * @param       log_to_system   If @c true, a message about each signal sent is written to the system log
 *
 * @return      Number of matching processes found
 */

int
susshi_count_and_signal_processes(const char* pattern, int signal, bool log_to_system) {

	int sessions = 0;

#ifdef LINUX

	struct pids_info *pids_info = NULL;
	struct pids_fetch *pids_fetch = NULL;

	enum pids_item pids_items[] = { PIDS_ID_PID, PIDS_CMDLINE_V };

	/* Initial libproc2 interface for pids */
	if (procps_pids_new(&pids_info, pids_items, 2) < 0) {
		fatal("Failed to talk to procps_pids_new().");
	}

	/* Harvest all processes in one shot */
	pids_fetch = procps_pids_reap(pids_info, PIDS_FETCH_TASKS_ONLY);

	if (!pids_fetch) {
		procps_pids_unref(&pids_info);
		fatal("Failed to talk to procps_pids_reap()");
	}

	/* Loop over each returned stack */
	for (int i = 0; i < pids_fetch->counts->total; ++i) {
		struct pids_stack *stack = pids_fetch->stacks[i];
		int    pid     = PIDS_VAL(0, s_int, stack, pids_info);
		char **cmdline = PIDS_VAL(1, strv, stack, pids_info);

		if (cmdline && cmdline[0]) {

			/* Compare pattern with found process name */
			if (strncmp(pattern, cmdline[0], strlen(pattern)) == 0) {
				sessions++;
				if (signal > -1) {
					kill(pid, signal);
					debug4("Send %s signal to session worker child with pid %d", strsignal(signal), pid);
					if (log_to_system)
						log_system(LOG_LEVEL_INFO, "Send %s signal to session worker child with pid %d", strsignal(signal), pid);
				}
			}
		}
	}

	procps_pids_unref(&pids_info);

#endif

	return sessions;
}

/*! @} */
