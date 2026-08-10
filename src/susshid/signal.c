/*!
 *
 * @brief       Signal Handler
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
 * @defgroup    signal Signal Handler methods
 * @brief       Functions handling signals.
 * @{
 */

#include <susshid/common.h>


/* Prototypes */
static void susshi_master_loop_restart_handler(int signal);
static void susshi_session_loop_signal_handler(int signal);
static void susshi_last_signal_handler(int signal);
static void susshi_who_signal_handler(int signal);
static void susshi_liveview_signal_handler(int signal);
static void susshi_timer_alarm_handler(void);

/*!
 * @brief       Register signal handler using sigaction
 *
 * @param       signal      signal
 * @param       handler         signal handler function
 * @param       sa_flags        sigaction flags
 */

void
susshi_sigaction(int signal, void (*handler)(int), int sa_flags) {
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
 * @param       signal      signal
 */

static void
susshi_master_loop_signal_handler(int signal) {
	log_system(LOG_LEVEL_INFO, "Received signal: %d (%s)", signal, strsignal(signal));
	susshi_session.received_signal = signal;
}


/*!
 * @brief       Master Loop - Signal "Restart" Handler
 *
 * @param       signal      signal
 */

static void
susshi_master_loop_restart_handler(int signal) {
	susshi_session.received_signal_for_restart = true;
}


/*!
 * @brief       Session Loop - SIG(TERM|QUIT) Handler
 *
 * @param       signal      signal
 */

static void
susshi_session_loop_signal_handler(int signal) {
	susshi_session.received_signal = signal;
}


/*!
 * @brief       Session Loop - Signal "Write Last Log" Handler
 *
 * @param       signal      signal
 */

static void
susshi_last_signal_handler(int signal) {
	susshi_report_last_log(false);
}


/*!
 * @brief       Session Loop - Signal "Write Who" Handler
 *
 * @param       signal      signal
 */

static void
susshi_who_signal_handler(int signal) {
	susshi_report_who();
}


/*!
 * @brief       Session Loop - Signal "Log Liveview" Handler
 *
 * @param       signal      signal
 */

static void
susshi_liveview_signal_handler(int signal) {
	log_system(LOG_LEVEL_INFO, "Received SIG WINCH. So switched session into liveview logging.");

	susshi_session.log_live_view = true;

	// Flush the already opened log files
	flush_susshi_channel_logs();
}


/*!
 * @brief       Timer Signals Handler
 *
 * The Timer signals handler can be called for this reasons:
 *
 * 1. Session Max / Idle timer expired
 * 2. Logfile rotation at midnight
 * 3. Reporting
 */

static void
susshi_timer_alarm_handler(void) {
	time_t now;
	struct tm tm_now;

	now = time(NULL);

	debug3("Received timer alarm.");

	/* 1. Terminate session if max_session_time or max_session_idle_time is reached */
	if ((now - susshi_report.session_start_time) >= susshi_session.max_session_secs) {
		susshi_session.gateway_closed = true;
		susshi_session.gateway_closed_reason = bfromcstr("Maximum session time exceeded.");
	} else {
		if ((now - susshi_report.last_io_time) >= susshi_session.max_session_idle_secs) {
			susshi_session.gateway_closed = true;
			susshi_session.gateway_closed_reason = bfromcstr("Maximum session idle time exceeded.");
		}
	}

	if (susshi_session.gateway_closed) {
		susshi_disconnect_individual(BOTH, SSH2_DISCONNECT_BY_APPLICATION, bdata(susshi_session.gateway_closed_reason));
	}

	/* 2. Logfile rotation */
	localtime_r(&now, &tm_now);
	if ((tm_now.tm_hour == 0) && (tm_now.tm_min == 0)) {
		debug3("It's midnight - flushing all log files.");
		flush_susshi_channel_logs();
	}

	/* 3. Reporting */
	susshi_report_client_send_report(REPORT_PERIODIC);

	/* Register again */
	susshi_timer_alarms_register();
}


/*!
 * @brief       Timer Signal Alarm Registry
 *
 * Register next timer for whatever comes first:
 * 1. Session Max / Idle timer expired
 * 2. Logfile rotation at midnight
 * 3. Reporting
 *
 */

void
susshi_timer_alarms_register(void) {
	time_t now;
	time_t tv_sec_log;
	struct itimerval it_val;

	now = time(NULL);

	if (signal(SIGALRM, (void (*)(int)) susshi_timer_alarm_handler) == SIG_ERR) {
		fatal("Unable to catch SIGALRM");
	}

	/* 2. Trigger next log rotation (on midnight) */
	determine_next_log_period(&tv_sec_log);

	/* We will get triggered 5 seconds after midnight to rotate logs */
	tv_sec_log += 5;

	memset(&it_val, 0, sizeof(struct itimerval));

	/* 1. Max session time */
	it_val.it_value.tv_sec=MIN((susshi_report.session_start_time + susshi_session.max_session_secs - now), tv_sec_log);

	/* 2. Max session idle time */
	it_val.it_value.tv_sec=MIN(it_val.it_value.tv_sec, (susshi_report.last_io_time + susshi_session.max_session_idle_secs - now));

	/* 3. Reporting Timer */
	if (susshi_cfg.report_period != -1) {
		/* (start_time + ((runtime/period) + 1) * period) - now */
		it_val.it_value.tv_sec = MIN(it_val.it_value.tv_sec,
									 (susshi_report.session_start_time +
											 (((now - susshi_report.session_start_time)
											   / susshi_cfg.report_period) + 1) *
													 susshi_cfg.report_period) - now);
	}

	it_val.it_value.tv_usec = 0;

	// 2 seconds safety buffer for further calculations in susshi_timer_alarm_handler
	it_val.it_value.tv_sec += 2;

	if (setitimer(ITIMER_REAL, &it_val, NULL) == -1) {
		fatal("Error calling setitimer()");
	}
}


/*!
 * @brief       Master Loop - Handler Registry
 */

void
susshi_master_loop_signal_register(void) {
	susshi_sigaction(SIGTERM, susshi_master_loop_signal_handler, 0);
	susshi_sigaction(SIGQUIT, susshi_master_loop_signal_handler, 0);
	susshi_sigaction(SIGINT, susshi_master_loop_signal_handler, 0);
	susshi_sigaction(SIGHUP, susshi_master_loop_restart_handler, 0);
	// --> SIGCHLD is set in susshi_master_loop()
}


/*!
 * @brief       Session Loop - Handler Registry
 */

void
susshi_session_loop_signal_register(void) {
	susshi_sigaction(SIGTERM, susshi_session_loop_signal_handler, 0);
	susshi_sigaction(SIGQUIT, susshi_session_loop_signal_handler, 0);
	susshi_sigaction(SIGINT, susshi_session_loop_signal_handler, 0);
	susshi_sigaction(SIGUSR1, susshi_who_signal_handler, SA_RESTART);
	susshi_sigaction(SIGUSR2, susshi_last_signal_handler, SA_RESTART);
	susshi_sigaction(SIGWINCH, susshi_liveview_signal_handler, SA_RESTART);
}

/*! @} */
