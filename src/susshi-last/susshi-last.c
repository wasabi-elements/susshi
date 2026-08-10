/*!
 *
 * @brief       susshi-last
 *
 * @copyright	Copyright (C) 2026 Wasabi Elements GmbH
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
 * @defgroup    susshi_last susshi-last
 * @brief       Print Lastlog Output of who was or is currently logged in
 * @{
 */

#include "susshi-last/common.h"

/* Prototypes */
static void usage(void);
static void cleanup(void);
void fatal(const char *fmt,...);


/*!
 * @brief       Print Usage
 */

static void
usage(void) {
	fprintf(stderr,
					"\n                         __________ __  __     ___"
					"\n             _______  __/ ___/ ___// / / (_)  |__ \\"
					"\n            / ___/ / / /\\__ \\\\__ \\/ /_/ / /   __/ /"
					"\n           (__  ) /_/ /___/ /__/ / __  / /   / __/"
					"\n          /____/\\__,_//____/____/_/ /_/_/   /____/"
					"\n          ----------- by Wasabi Elements GmbH ---"
					"\n"

					"\n" SUSSHI_NAME " " SUSSHI_RELEASE " - " SUSSHI_COPYRIGHT "\n"
					"\nUsage: " SUSSHI_LAST_NAME " [-l lastlog-file] [-n lines | -###]\n\n"
					"\t-l, --lastlog       Lastlog filepath, if not set, env variable SUSSHI_LASTLOG is expected or default is used.\n"
					"\t-n, -###, --lines   Display number of session, including active and finished sessions. Defaults to 20.\n"
					"\t-h, --help          This help.\n\n"
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
	vfprintf(stderr, fmt, args);
	va_end(args);

	cleanup();

	_exit(1);
}

#define SESSION_ID_POS 86
#define SESSION_ID_LEN 25


/*!
 * @brief       Build a flat pointer array from the ssh_buffer contents.
 *
 * The ssh_buffer holds a contiguous sequence of null-terminated strings.
 * We walk it once to count them, allocate a pointer array, then fill it.
 *
 * @param       records     Populated ssh_buffer
 * @param       num_records Number of strings stored
 * @return      Heap-allocated array of char* pointing into a strdup'd copy of
 *              each record.  Caller must xfree() each pointer and then the
 *              array itself.
 */

static char **
build_record_array(ssh_buffer records, ssize_t num_records) {
	char **arr;
	const uint8_t *data;
	uint32_t data_len;
	const uint8_t *p, *end;
	ssize_t idx = 0;

	arr = xmalloc(num_records * sizeof(char *));

	data     = ssh_buffer_get(records);
	data_len = ssh_buffer_get_len(records);
	p        = data;
	end      = data + data_len;

	while ((p < end) && (idx < num_records)) {
		/* Each entry is a null-terminated string */
		arr[idx++] = strdup((const char *) p);
		p += strlen((const char *) p) + 1;
	}

	return arr;
}


/*!
 * @brief       Comparator for qsort: compares records by SESSION-ID field
 */
static int
record_comparator(const void *a, const void *b) {
	const char *sa = *(const char **) a;
	const char *sb = *(const char **) b;
	return strncmp(&sa[SESSION_ID_POS], &sb[SESSION_ID_POS], SESSION_ID_LEN);
}

/*!
 * @brief       susshi-last main
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
	int option_index = 0;
	bstring count_str = bfromcstr("");
	ssize_t number_of_lines = -1, count_lines = 0;

	/* ssh_buffer replaces SimpleBuffer */
	ssh_buffer records = NULL;
	ssize_t num_records = 0;
	char *new_message, *new_line;

	struct pids_info *pids_info = NULL;
	struct pids_fetch *pids_fetch = NULL;

	enum pids_item pids_items[] = { PIDS_ID_PID, PIDS_CMDLINE_V };

	int queue_count;

	FILE *last_file;
	char *last_file_name = (char *) "/var/log/susshi/lastlog";
	int last_file_accessable = -1;
	const char *env_path = NULL;
	char resolved_env_path[PATH_MAX];

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


		static struct option long_options[] = {
			{"help", no_argument, 0, 'h'},
			{"lastlog", required_argument, 0, 'l'},
			{"lastfile", required_argument, 0, 'l'},
			{"lines", required_argument, 0, 'n'},
			{"number", required_argument, 0, 'n'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "n:l:h0123456789",
						 long_options, &option_index);

		switch (c) {
			case -1:
				break;

			case 0:     /* option set a flag */
				break;

			case 'h':
				usage();
				exit(0);
			case 'l':
				last_file_name = optarg;
				break;
			case 'n':
				number_of_lines = atoll(optarg);
				if (number_of_lines < 0)
					number_of_lines *= -1;
				break;
			case '?':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
			case '0':
				bformata(count_str, "%c", c);
				break;
			case ':':
			default:
				usage();
				exit(1);
		}
	}

	if (number_of_lines == -1) {
		if (blength(count_str) > 0) {
			number_of_lines = atoi(bdata(count_str));
		} else {
			number_of_lines = 20;
		}
	}

	/* Initialise the ssh_buffer */
	records = ssh_buffer_new();
	if (records == NULL) {
		fatal("Failed to allocate ssh_buffer for records.\n");
	}

#ifdef LINUX

	/* Get UID and GID of unprivileged user */
	get_unprivileged_user_uid_gid(&uid, &gid);

#endif

	/* Drop privileges to ensure last-Queue can be opened by worker-processes running with dropped privileges */
	drop_privileges(false, uid,gid);

	message_queue = mq_open(LAST_QUEUE_NAME, O_RDONLY|O_CREAT, S_IRUSR|S_IWUSR, NULL);

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

			/*
			 * Signal all susshid session daemons to write out last to queue and collect messages from queue
			 */

			do {
				pids_stack = procps_pids_get(pids_info, PIDS_FETCH_TASKS_ONLY);

				if (pids_stack) {
					int pid        = PIDS_VAL(0, s_int, pids_stack, pids_info);
					char **cmdline = PIDS_VAL(1, strv, pids_stack, pids_info);

					/* Compare pattern with found process name */
					if (strncmp(SUSSHID_PROCESS_PATTERN_WORKERS, cmdline[0], strlen(SUSSHID_PROCESS_PATTERN_WORKERS)) == 0) {
						queue_count++;
						kill(pid, SIGUSR2);
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
							new_message = strdup(message_buffer);
							/* Append the string (including its null terminator) into the ssh_buffer */
							if (ssh_buffer_add_data(records, new_message, strlen(new_message) + 1) != SSH_OK) {
								fatal("Failed to append record to ssh_buffer.\n");
							}
							xfree(new_message);
							num_records++;
						}
					} while(msg_len > 0);
					queue_count = 0;
				}
			} while(pids_stack);

			procps_pids_unref(&pids_info);

			/*
			 * Read from last log
			 */

			if (num_records < number_of_lines) {

				ssize_t volatile num_from_file;

				num_from_file = (number_of_lines - num_records);

				if ((last_file_accessable = access(last_file_name, R_OK)) == -1) {
					env_path = getenv("SUSSHI_LASTLOG");
					if (env_path != NULL) {
						if (realpath(env_path, resolved_env_path) != NULL &&
							strncmp(resolved_env_path, "/var/log/susshi/",
									strlen("/var/log/susshi/")) == 0) {
							last_file_name = resolved_env_path;
							last_file_accessable = access(last_file_name, R_OK);
						} else {
							fprintf(stderr, "\nWarning! SUSSHI_LASTLOG path is outside the "
									"allowed log directory. Ignoring.\n\n");
						}
					}
				}

				if (last_file_accessable == 0) {

					last_file = fopen(last_file_name, "r");

					if (last_file != NULL) {

						char line[4096];
						long int pos;

						fseek(last_file, 0, SEEK_END);
						pos = ftell(last_file);

						while (pos) {
							fseek(last_file, --pos, SEEK_SET);
							if (fgetc(last_file) == '\n') {
								if (count_lines++ == num_from_file)
									break;
							}
						}

						if (count_lines < num_from_file)
							fseek(last_file, 0, SEEK_SET);

						while (fgets(line, sizeof(line), last_file) != NULL) {
							new_line = strdup(line);
							if (ssh_buffer_add_data(records, new_line, strlen(new_line) + 1) != SSH_OK) {
								fatal("Failed to append line to ssh_buffer.\n");
							}
							xfree(new_line);
							num_records++;
						}
						fclose(last_file);
					}
				} else {
					fprintf(stderr, "\nWarning! Could not access lastlog file. "
							"Please specify location with --lastlog or set env variable SUSSHI_LASTLOG correctly.\n\n");
				}
			}

			printf("suID   USER                   PID         LOGIN@                LOGOUT@         DURATION  SESSION-ID                       FEATURES    CLIENT                   TARGET (TARGET IP)\n");

			/*
			 * Print sorted records to stdout
			 */

			if (num_records > 0) {
				char **record_array = build_record_array(records, num_records);

				qsort(record_array, num_records, sizeof(char *), record_comparator);

				for (ssize_t i = 0; (i < num_records) && (i < number_of_lines); i++) {
					printf("%s", record_array[i]);
					xfree(record_array[i]);
				}

				xfree(record_array);
			}

			ssh_buffer_free(records);
		}
	} else {
		fprintf(stderr, "\nError! Could not access lastlog message queue: %s. Aborting.\n\n", strerror(errno));
	}
}

/*! @} */
