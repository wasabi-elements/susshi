/*!
 *
 * @brief       susshi-who
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
 * @defgroup    susshi_who      susshi-who
 * @brief       Print Who Output of who's logged in
 * @{
 */

#include "susshi-who/common.h"

/* Prototypes */
static void usage(void);
static void cleanup(void);
void fatal(const char *fmt,...);


/*!
 * @brief       Print Usage
 */

static void
usage(void)
{
	fprintf(stderr,
			"\n                         __________ __  __     ___"
			"\n             _______  __/ ___/ ___// / / (_)  |__ \\"
			"\n            / ___/ / / /\\__ \\\\__ \\/ /_/ / /   __/ /"
			"\n           (__  ) /_/ /___/ /__/ / __  / /   / __/"
			"\n          /____/\\__,_//____/____/_/ /_/_/   /____/"
			"\n          ----------- by Wasabi Elements GmbH ---"
			"\n"

			"\n" SUSSHI_NAME " " SUSSHI_RELEASE " - " SUSSHI_COPYRIGHT "\n"
			"\nUsage: " SUSSHI_WHO_NAME "\n\n"
			"\t-h, --help             This help.\n\n"
	);
}


/*!
 * @brief       Cleanup
 */

static void
cleanup(void) {

}


/*!
 * @brief       Fatal function called in fatal situations
 *
 * @param       fmt     Format string
 * @param       ...     Optional parameters referenced by format string
 */

void
fatal(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	fprintf(stderr, fmt, args);
	va_end(args);

	cleanup();

	_exit(1);
}



/*!
 * @brief       susshi-who main
 *
 * @param       argc            Argument Count
 * @param       argv            Argument Values
 * @param       envp            Environments
 *
 * @return      Exit code
 */

int
main(int argc, char **argv, char **envp) {
	extern char *optarg;
	extern int	optind;

	struct pids_info *pids_info = NULL;
	struct pids_fetch *pids_fetch = NULL;

	enum pids_item pids_items[] = { PIDS_ID_PID, PIDS_CMDLINE_V };

	int queue_count;

	mqd_t message_queue;
	struct mq_attr message_attr;
	char *message_buffer;
	ssize_t msg_len;
	int c;

	uid_t uid;
	uid_t gid;

	const struct timespec abs_timeout = {
			.tv_sec = time(NULL) + 3,
			.tv_nsec = 0
	};

	for(c=0; c != -1; ) {
		int option_index = 0;

		static struct option long_options[] = {
			{"help", no_argument, 0, 'h'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "f:hi:o:p:",
						 long_options, &option_index);

		switch (c) {
			case -1:
				break;

			case 0:     /* option set a flag */
				break;

			case 'h':
				usage();
				exit(0);
			case ':':
			case '?':
			default:
				usage();
				exit(1);
		}
	}

#ifdef LINUX
	/* Get UID and GID of unprivileged user */
	get_unprivileged_user_uid_gid(&uid, &gid);
#endif

	/* Drop privileges to ensure last-Queue can be opened by worker-processes running with dropped privileges */
	drop_privileges(false, uid,gid);

	message_queue = mq_open(WHO_QUEUE_NAME, O_RDONLY|O_CREAT, S_IRUSR|S_IWUSR, NULL);

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

	if (message_queue != -1) {
		if (mq_getattr(message_queue, &message_attr) == 0) {

			struct pids_stack *pids_stack = NULL;

			queue_count = 0;
			message_buffer = xmalloc(message_attr.mq_msgsize + 1);

			printf("suID   USER                   PID         LOGIN@             IDLE   SESSION-ID                       FEATURES    CLIENT                   TARGET (TARGET IP)\n");


			/*
			 * Signal all susshid daemons to write out who to queue
			 */

			do {
				pids_stack = procps_pids_get(pids_info, PIDS_FETCH_TASKS_ONLY);

				if (pids_stack) {
					int pid = PIDS_VAL(0, s_int, pids_stack, pids_info);
					char **cmdline = PIDS_VAL(1, strv, pids_stack, pids_info);

					/* Compare pattern with found process name */
					if (strncmp(SUSSHID_PROCESS_PATTERN_WORKERS, cmdline[0], strlen(SUSSHID_PROCESS_PATTERN_WORKERS)) == 0) {
						queue_count++;
						kill(pid, SIGUSR1);
					} else {
						continue;
					}
				}

				if ((queue_count == message_attr.mq_maxmsg) ||
					((pids_stack == NULL) && (queue_count > 0))) {
					do {
						msg_len = mq_timedreceive(message_queue, message_buffer, message_attr.mq_msgsize,
												  NULL, &abs_timeout);
						if (msg_len > 0) {
							message_buffer[msg_len] = '\0';
							printf("%s", message_buffer);
						}
					} while (msg_len > 0);
					queue_count = 0;
				}
			} while (pids_stack);

			procps_pids_unref(&pids_info);

			xfree(message_buffer);
		}
	} else {
		fprintf(stderr, "\nError! Could not access who message queue: %s. Aborting.\n\n", strerror(errno));
	}
}

/*! @} */
