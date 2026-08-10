/*!
 *
 * @brief       Signal Handler methods
 *
 * @ingroup     susshi_proxyd
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
 * @defgroup    proxy_signal Signal Handler methods
 * @brief       Functions handling signals.
 * @{
 *
 */

#include <susshi-proxyd/common.h>

/* Prototypes */
static void proxy_master_loop_restart_handler(int signal);
static void proxy_session_loop_sigterm_handler(int signal);
static void proxy_session_loop_sigint_handler(int signal);


/*!
 * @brief       Register signal handler using sigaction
 *
 * @param       signal      signal
 * @param       handler     signal handler function
 * @param       sa_flags    sigaction flags
 */

void
proxy_sigaction(int signal, void (*handler)(int), int sa_flags) {
	struct sigaction sa;

	/* Set up SIGCHLD handler. */
	sa.sa_handler = handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = sa_flags;

	if (sigaction(signal, &sa, NULL) != 0) {
		fatal("Failed to register signal %d handler.", signal);
	}
}


/*!
 * @brief       Master Loop - SIGTERM handler for cleaning up on termination.
 *
 * @param       signo
 */

static void
proxy_master_loop_sigterm_handler(int signo) {

	log_system(LOG_LEVEL_INFO, "Received signal: %d (%s)", signo, strsignal(signo));
	proxy_cleanup();
	exit(0);
}


/*!
 * @brief       Master Loop - Signal "Restart" Handler
 *
 * @param       signal
 */

static void
proxy_master_loop_restart_handler(int signal)
{
	proxy_session.received_signal_for_restart = true;
}


/*!
 * @brief       Session Loop - SIG(TERM|QUIT) Handler
 *
 * @param       signal
 */

static void
proxy_session_loop_sigterm_handler(int signal) {
	proxy_session.received_sigterm = signal;
}


/*!
 * @brief       Session Loop - SIGINT Handler
 *
 * @param       signal
 */

static void
proxy_session_loop_sigint_handler(int signal) {
	proxy_session.received_sigint = true;
}


/*!
 * @brief       Master Loop - Handler Registry
 */

void
proxy_master_loop_signal_register(void) {
	proxy_sigaction(SIGTERM, proxy_master_loop_sigterm_handler, 0);
	proxy_sigaction(SIGQUIT, proxy_master_loop_sigterm_handler, 0);
	proxy_sigaction(SIGINT, proxy_master_loop_sigterm_handler, 0);
	proxy_sigaction(SIGHUP, proxy_master_loop_restart_handler, SA_RESTART);
	// --> SIGCHLD is set in proxy_master_loop()
}


/*!
 * @brief       Session Loop - Handler Registry
 */

void
proxy_session_loop_signal_register(void) {
	proxy_sigaction(SIGTERM, proxy_session_loop_sigterm_handler, 0);
	proxy_sigaction(SIGQUIT, proxy_session_loop_sigterm_handler, 0);
	proxy_sigaction(SIGINT, proxy_session_loop_sigint_handler, 0);
}

/*! @} */
