/*!
 *
 * @brief       Reporting Server
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
 * @defgroup    report_daemon Reporting Server
 * @brief       Report daemon methods - only available on Linux
 * @{
 */

#include <susshid/common.h>


/* Prototypes */
static bool susshi_report_daemon_init(void);
static bool susshi_report_client_read_report_record(char **buf, ssize_t *buf_len, int wait_sec);
static int susshi_report_client_read_report_records(bool terminating);

static struct {
	mqd_t message_queue;
	struct mq_attr message_attr;
	char *message_buffer;
	volatile sig_atomic_t received_sigint;
} int_store = {
	.received_sigint = 0
};


/*!
 * @brief       Init Reporting daemon
 *
 * Open message queue for reading and allocate memory
 *
 * @return      true on success
 */

static bool
susshi_report_daemon_init(void) {

	/* Drop privileges permanently
	 * we have to drop it right here before opening the queue, otherwise the worker daemons are not able
	 * to open and communicate with the queue
	 */
	susshi_drop_privileges("Reporting-daemon", true);

	int_store.message_queue = mq_open(REPORT_QUEUE_NAME, O_RDONLY|O_CREAT, S_IRUSR|S_IWUSR, NULL);

	if (int_store.message_queue != -1) {
		if (mq_getattr(int_store.message_queue, &int_store.message_attr) == 0) {
			FILE *f;

			int_store.message_buffer = xmalloc(int_store.message_attr.mq_msgsize + 1);
			debug3("Reporting-daemon: Successfully opened message queue");

			/* Write out the pid file */
			f = fopen(PATH_SUSSHI_REPORT_PID_FILE, "w");

			if (f == NULL) {
				error("Couldn't create pid file \"%s\": %s",
					  PATH_SUSSHI_REPORT_PID_FILE, strerror(errno));
			} else {
				fprintf(f, "%ld\n", (long) getpid());
				fclose(f);
			}

			return true;
		}
	} else {
		log_system(LOG_LEVEL_ERROR, "Reporting-daemon: Could not open reporting message queue: %s", strerror(errno));
	}

	return false;
}


/*!
 * @brief       Read single record message from queue
 *
 * @param       buf             Pointer to pointer to buffer with message, user must not free memory.
 * @param       buf_len         Pointer to integer with len of read message
 * @param       wait_sec        Seconds to wait
 *
 * @return      true on success
 */

static bool
susshi_report_client_read_report_record(char **buf, ssize_t *buf_len, int wait_sec) {

	const struct timespec abs_timeout = {
			.tv_sec = time(NULL) + wait_sec,
			.tv_nsec = 0
	};

	/* Receive next message from queue */
	*buf_len = mq_timedreceive(int_store.message_queue, int_store.message_buffer, int_store.message_attr.mq_msgsize,
							   NULL, &abs_timeout);

	if (*buf_len > 0) {
		/* 0-terminate string */
		int_store.message_buffer[*buf_len] = 0;

		debug4("Reporting-daemon: Received report message of %ld bytes: %.50s ...", *buf_len, int_store.message_buffer);

		*buf = int_store.message_buffer;
		return true;
	} else {
		*buf = NULL;
		return false;
	}
}


/*!
 * @brief       Read Report records
 *
 * @param       terminating     Set to true on termination
 *
 * @return      Number of reports read
 */

static int
susshi_report_client_read_report_records(bool terminating) {

	bstring reports = NULL;
	char *report = NULL;
	ssize_t report_len;
	int wait_sec = 23;
	int r;

	reports = bfromcstr("[ ");

	/* On termination, wait 5 sec max. for records if queue is empty, otherwise 3 seconds */
	wait_sec = terminating ? 5 : 3;

	if (terminating) {
		sleep(5);
	}

	/* Receive max 100 messages in one bulk */
	for(r = 0; (r < 100) && (terminating == true || int_store.received_sigint == 0); r++) {
		if (susshi_report_client_read_report_record(&report, &report_len, wait_sec)) {

			if (r > 0)
				bformata(reports, ", ");
			bformata(reports, "%s", report);
			SETPROCTITLE("Reporting-daemon - %d report(s) in queue", r+1);

			if (terminating) {
				/* On termination, collect as many reports we can get from Queue without waiting. */
				wait_sec = 0;
			}

			/* Check if we received report with session_state: "new" */
			if ((wait_sec > 0) && (strstr((const char *) report, "\"session_state\":\"new\"") != NULL)) {
				wait_sec = 0; // We will no longer wait, but try to collect more reports from MQ
			}

		} else {
			/* We will stop here and send the reports collected so far */
			break;
		}
	}

	if (blength(reports) > 2) {
		bformata(reports, " ]");

		debug3("Report-daemon: Totally collected %d report(s). Uploading to Chef", r);

		SETPROCTITLE("Reporting-daemon - uploading reports to Chef");

		/* Upload reports to Chef */
		susshi_chef_upload_report(reports);

		SETPROCTITLE("Reporting-daemon");
	}
	bstrFree(reports);

	return(r);
}


/*!
 * @brief       SIGTERM handler for cleaning up and quit reporting daemon.
 *
 * @param       signal
 */

static void
susshi_report_daemon_sigint_handler(int signal) {
	(void) signal;

	int_store.received_sigint = 1;
}


/*!
 * @brief       Run the reporting daemon loop
 */

void
susshi_report_daemon_loop(void) {

	SETPROCTITLE("Reporting-daemon");

	/* Set up SIGINT handler. */
	susshi_sigaction(SIGINT, &susshi_report_daemon_sigint_handler, 0);
	int_store.received_sigint = false;

	if (susshi_report_daemon_init()) {
		while (int_store.received_sigint == 0) {
			susshi_report_client_read_report_records(false);
		}

		log_system(LOG_LEVEL_INFO, "Received signal for termination ... Stay calm, this would take about 5 seconds ...");

		SETPROCTITLE("Reporting-daemon - Terminating, please wait ...");

		/* Drain remaining messages from queue */
		while(susshi_report_client_read_report_records(true) >= 100) {}

		xfree((void *) int_store.message_buffer);
		mq_close(int_store.message_queue);

		/* Unlkink PID file */
		unlink(PATH_SUSSHI_REPORT_PID_FILE);

		log_system(LOG_LEVEL_INFO, "Reporting-daemon terminated. Bye bye,");
		exit(0);
	}
}


/*!
 * @brief       Fork a reporting daemon
 *
 * @return      true on success
 */

bool
susshi_fork_report_daemon(void) {

	int child_pid;

	if (susshi_session.report_pid > 0) {
		debug2("Reporting daemon already running with pid %d", susshi_session.report_pid);
		return true;
	}

	switch (child_pid = fork()) {
		case 0: { /* I am child = reporting-daemon */
			int fd;

			susshi_session.process_role = PROC_ROLE_REPORT;

			/* Ignore SIGCONT and SIGHUP used in master process */
			susshi_sigaction(SIGCONT, SIG_IGN, 0);
			susshi_sigaction(SIGHUP, SIG_IGN, 0);

			if ((fd = open(_PATH_DEVNULL, O_RDWR, 0)) != -1) {
				dup2(fd, STDIN_FILENO);
				dup2(fd, STDOUT_FILENO);
				if (fd > STDERR_FILENO)
					close(fd);
			}

			/* Run the daemon loop */
			susshi_report_daemon_loop();

			exit(0);
		}

		case -1: {
			error("Failed to fork reporting daemon");
			return false;
		}	break;

		default: { /* I am parent */

			susshi_session.report_pid = child_pid;
			log_system(LOG_LEVEL_INFO, "Forked reporting daemon with pid %d", susshi_session.report_pid);
			return true;
		}
	}
}

/*! @} */
