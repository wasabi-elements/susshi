/*!
 *
 * @brief       The suSSHi Gateway daemon
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
 * @defgroup    susshid     susshid - The suSSHi2 gateway daemon
 * @{
 */

#include <susshid/common.h>


bool flag_debug = false;
bool flag_no_daemon = false;
bool flag_main_process_in_foreground = true;


/*!
 * @brief       Show Usage
 */

void
usage(void)
{

#ifdef WITH_FULL_DEBUG_OPTIONS
#define MAX_DEBUG_OPTS "5"
#else
#define MAX_DEBUG_OPTS "3"
#endif

	fprintf(stderr,
			"\n                         __________ __  __     ___"
			"\n             _______  __/ ___/ ___// / / (_)  |__ \\"
			"\n            / ___/ / / /\\__ \\\\__ \\/ /_/ / /   __/ /"
			"\n           (__  ) /_/ /___/ /__/ / __  / /   / __/"
			"\n          /____/\\__,_//____/____/_/ /_/_/   /____/"
			"\n          ----------- by Wasabi Elements GmbH ---"
			"\n"

			"\n" SUSSHI_NAME " " SUSSHI_RELEASE " - " SUSSHI_COPYRIGHT "\n"
			"\nUsage: " SUSSHID_NAME " [-dDFe] [-f config_file.json] [-i susshid-identifier] [-p port] [-w sec] [-r retries] [-W sec] "
			"\n       " SUSSHID_NAME " [-d]    [-f config_file.json] [-i susshid-identifier] -s sic_psk\n"
			"\n         -d  Debug level, multiple -d (up to " MAX_DEBUG_OPTS ") increases the debug level."
			"\n         -D  Don't fork main process or sessions into background. This should be used for debugging only."
			"\n             Only one single client connection is handled before quitting."
			"\n         -e  Output system messages on stderr as well. All other messages are send to stderr only."
			"\n         -f  Specify configuration file in JSON format. This is normally not required, use option -s instead."
			"\n         -F  Fork into background. Main process forks into background. Default is to stay in foreground."
			"\n         -h  This help."
			"\n         -i  Overwrites the susshid-identifier found in configuration file."
			"\n         -p  Overwrites the listen port in configuration file."
			"\n         -P  Overwrites default listen port (" MONITOR_PORT_STRING ") for HTTP health probe interface."
			"\n         -r  On startup, retry n times to connect to susshi-chef. Default is 3 retries."
			"\n         -s  Provide suSSHi Chef URL for secure internal communication (sic). You may use SUSSHI_CHEF_URL instead."
			"\n         -w  On startup, wait n seconds before trying to connect to susshi-chef. Default is 15 seconds."
			"\n         -W  On startup, wait n seconds between retries. Default is 5 seconds.\n"
			"\n         --suspend    Suspend monitoring   - return 423 on monitor-server URL."
			"\n         --unsuspend  Unsuspend monitoring - return to normal monitor operation.\n\n"
	);
}


/*!
 * @brief       susshid (program) main
 *
 * @param       argc            Argument Count
 * @param       argv            Argument Values
 * @param       envp            Environments
 * @param       first_startup   true on process startup
 */

void
susshid_main(int argc, char **argv, char **envp, bool first_startup) {
	extern char *optarg;
	extern int	optind;
	bstring sic_url = NULL;
	int opt = 0;
	u_int startup_wait = 15;
	u_int startup_retry = 3;
	u_int startup_retry_wait = 5;

	static char *susshi_cfg_file = NULL;

	mode_t new_umask;

	// Initialize configuration options
	susshi_cfg_init();

	// Drop privileges temporarily
	susshi_drop_privileges(SUSSHID_NAME, false);

	// Reset getopt if called multiple times (on restart)
	optind = 1;

	if (getenv("MONITOR_PORT") != NULL) {
		susshi_cfg.health_monitor_port = a2port(getenv("MONITOR_PORT"));
		if (susshi_cfg.health_monitor_port <= 0) {
			fatal("Bad port number in environment variable MONITOR_PORT.");
		}
	}

	// Parse command-line arguments.
	while (opt != -1) {

		static struct option long_options[] = {
				{"suspend", no_argument, 0, 'x'},
				{"unsuspend", no_argument, 0, 'X'},
				{"help", no_argument, 0, 'h'},
				{0, 0, 0, 0}
		};

		int option_index = 0;

		opt = getopt_long(argc, argv, "adDef:Fhi:p:P:r:s:w:W:xX",
						long_options, &option_index);

		switch (opt) {
			case -1:
				break;
			case 0:     /* option set a flag */
				break;
			case 'd':
				if (!flag_debug) {
					flag_debug = true;
					susshi_cfg.log_level = LOG_DEBUG_MILESTONES;
				} else {
#ifdef WITH_FULL_DEBUG_OPTIONS
					if (susshi_cfg.log_level < LOG_DEBUG_PACKETDUMP)
						susshi_cfg.log_level++;
#else
					if (susshi_cfg.log_level < LOG_DEBUG_DETAILS)
						susshi_cfg.log_level++;
#endif
				}
				break;
			case 'D':
				flag_no_daemon = true;
				break;
			case 'e':
				log_on_stderr = true;
				break;
			case 'f':
				if (first_startup)
					susshi_cfg_file = strdup(optarg);
				break;
			case 'F':
				flag_main_process_in_foreground = false;
				break;
			case 'h':
				usage();
				exit(0);
			case 'i':
				chef_cfg.susshid_id = bfromcstr(optarg);
				if (blength(chef_cfg.susshid_id) != 4) {
					fatal("susshid-identifier: Please provide a string with exactly 4 characters.");
				}
				break;
			case 'p':
				if (first_startup) {
					susshi_cfg.ports_from_cmdline = true;
					if (susshi_cfg.num_ports >= MAX_PORTS) {
						fatal("Too many ports.");
					}
					susshi_cfg.ports[susshi_cfg.num_ports++] = a2port(optarg);
					if (susshi_cfg.ports[susshi_cfg.num_ports-1] <= 0) {
						fatal("Bad port number.");
					}
				}
				break;
			case 'P':
				susshi_cfg.health_monitor_port = a2port(optarg);
				if (susshi_cfg.health_monitor_port <= 0) {
					fatal("Bad health monitor port number.");
				}
				break;
			case 'r': {
				const char *errstr;
				startup_retry = (u_int) strtonum(optarg, 0, UINT_MAX, &errstr);
				if (errstr != NULL)
					fatal("Bad retry count (-r): %s", errstr);
				break;
			}
			case 's':
				sic_url = bfromcstr(optarg);
				memset((char *) optarg, 0, strlen(optarg));   // wipe from argv[]
				break;
			case 'w': {
				const char *errstr;
				startup_wait = (u_int) strtonum(optarg, 0, UINT_MAX, &errstr);
				if (errstr != NULL)
					fatal("Bad wait time (-w): %s", errstr);
				break;
			}
			case 'W': {
				const char *errstr;
				startup_retry_wait = (u_int) strtonum(optarg, 0, UINT_MAX, &errstr);
				if (errstr != NULL)
					fatal("Bad retry wait time (-W): %s", errstr);
				break;
			}
			case 'x':
				suspend_monitor_server();
				printf(SUSSHI_NAME " successfully suspended. The monitor-server will respond with 423 Locked messages now.\n");
				exit(0);
				break;
			case 'X':
				unsuspend_monitor_server();
				printf(SUSSHI_NAME " successfully unsuspended. The monitor-server returned to normal operation.\n");
				exit(0);
				break;
			case '?':
			default:
				usage();
				exit(1);
		}
	}

	// Set global log_level
	log_level = LOG_INFO;

	// Temporary switch on logging on stderr
	log_on_stderr = true;

	// Check that there are no remaining arguments.
	if (optind < argc) {
		fatal("Extra argument %s.\n", argv[optind]);
	}

	if (susshi_cfg_file) {
		// Load & parse susshid config
		SETPROCTITLE("Loading local configuration.");
		debug1("Loading local configuration from %s", susshi_cfg_file);
		susshi_cfg_load_configfile(susshi_cfg_file);
	}

	// Fill defaults
	susshi_cfg_fill_defaults();

	// Set global log_level after configuration
	log_level = susshi_cfg.log_level;

	// Init libCURL
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		fatal("Could not init curl library.");

	// Ensure that fds 0, 1 and 2 are open or directed to /dev/null
	sanitise_stdfd();

	/*
	 * If not in no_daemon and not flagged for foreground mode and it is the first startup,
	 * disconnect from the controlling terminal, and fork.
	 * The original process exits.
	 */

	if ((!flag_main_process_in_foreground) && (!flag_no_daemon) && (first_startup)) {
		int fd;

		if (daemon(0, 0) < 0)
			fatal("daemon() failed: %.200s", strerror(errno));

		/* Disconnect from the controlling tty. */

		fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
		if (fd >= 0) {
			(void) ioctl(fd, TIOCNOTTY, NULL);
			close(fd);
		}
	}

	// Ensure that umask disallows at least group and world write
	new_umask = umask(0077) | (mode_t) 0022;
	(void) umask(new_umask);

	// Chdir to the root directory so that the current disk can be unmounted if desired.
	if (chdir("/") == -1) {
		fatal("Could not chdir(/): %s", strerror(errno));
	}

	/* Ignore signals */
	susshi_sigaction(SIGPIPE, SIG_IGN, 0);
	susshi_sigaction(SIGUSR1, SIG_IGN, 0);
	susshi_sigaction(SIGUSR2, SIG_IGN, 0);
	susshi_sigaction(SIGCONT, SIG_IGN, 0);
	susshi_sigaction(SIGWINCH, SIG_IGN, 0);

	/* Write out the pid file */
	if (!flag_no_daemon) {
		FILE *f = fopen(PATH_SUSSHI_DAEMON_PID_FILE, "w");

		if (f == NULL) {
			error("Couldn't create pid file \"%s\": %s",
				  PATH_SUSSHI_DAEMON_PID_FILE, strerror(errno));
		} else {
			fprintf(f, "%ld\n", (long) getpid());
			fclose(f);
		}
	}

	// Init susshi log and report
	init_susshi_log();
	init_susshi_report();


	log_system(LOG_INFO, SUSSHI_NAME " - " SUSSHID_NAME " version %.100s started.", SUSSHI_RELEASE);

	// Init hooks
	susshi_hooks_init();

	susshi_hooks_run(HOOK_GATEWAY_START);

	// Dump Config
	if_debug3() {
		debug3("Dump susshid configuration (before Chef):");
		susshi_cfg_dump_config(CONTEXT_GLOBAL);
	}

	// Run in normal daemon mode
	SETPROCTITLE("Initializing chef communication.");

	/* Step 1 - SIC Preparation */
	if (first_startup) {
		if (sic_url == NULL) {
			const char *env_sic_url = getenv("SUSSHI_CHEF_URL");
			if (env_sic_url != NULL) {
				sic_url = bfromcstr(env_sic_url);
				/* Wipe value in env and delete it from the env table */
				memset((char *) env_sic_url, 0, strlen(env_sic_url));
				unsetenv("SUSSHI_CHEF_URL");
			}
		}

		/* Do we have a sic_url from -s or from env?
		 * Otherwise look if we already have all information from config file
		 */

		if (((sic_url != NULL) && susshi_sic_parse_url(sic_url)) || susshi_sic_validate_params(false)) {
			log_system(LOG_INFO, "Initializing Secure Internal Communication (SIC). Gathering gateway information ...");

			// Copy default chef URL to specific ones for gateway, session, and report
			chef_cfg_fill_server_urls();

			// Dump Config
			if_debug3() {
				debug3("Dump susshid configuration (after SIC initialize):");
				susshi_cfg_dump_config(CONTEXT_GLOBAL);
			}
		} else {
			log_system(LOG_EMERG, "At least one param for SIC initialization is missing. Have you specified the SUSSHI_CHEF_URL variable? Aborting.");
			susshi_sic_validate_params(true);
			exit(1);
		}
	}

	/* Step 2 - SIC Initialization */
	if (susshi_sic_initialize(startup_wait, startup_retry, startup_retry_wait)) {
		log_system(LOG_INFO, "SIC initialization completed successfully.");
	} else {
		log_system(LOG_EMERG, "ERROR! SIC initialization failed.");
		exit(1);
	}

	/* Step 3 - Load configuration from Chef */
	if (susshi_chef_init(0, startup_retry, startup_retry_wait)) {

		// log_on_stderr = false;

		// Still not filled from command line, configuration file or chef?
		if (susshi_cfg.num_ports == 0)
			susshi_cfg.ports[susshi_cfg.num_ports++] = SSH_DEFAULT_PORT;

		// Still not filled from configuration file or chef?
		if (susshi_cfg.listen_addrs == NULL)
			susshi_cfg_add_listen_addr(NULL, 0);

		// Dump Config
		if_debug3() {
			debug3("Dump susshid configuration (after Chef):");
			susshi_cfg_dump_config(CONTEXT_GLOBAL);
		}

		// Store master PID
		susshi_session.master_pid = getpid();

		// Set global log_level after configuration from Chef
		log_level = susshi_cfg.log_level;

		/* restore privileges to allow rebind of sockets to privileged ports */
		susshi_restore_privileges();

		if (chef_cfg.renew_sic) {
			/* 1. Do the SIC renewal */
			susshi_sic_initialize(0, startup_retry, startup_retry_wait);

			/* 2. Reach out again to chef, so chef can update ssl_client_fingerprint with the renewed certificate fingerprint */
			susshi_chef_init(0, startup_retry, startup_retry_wait);

			/* 3. Restart rsyslogd, because we should have received a new syslog client certificate as well */
			susshi_restart_rsyslog();
		}

		if (first_startup) {

			if (!flag_no_daemon) {
#ifdef LINUX
				/* Fork reporting daemon */
				if (susshi_fork_report_daemon() == false) {
					fatal("Failed to fork reporting daemon");
				}
#endif
				/* Fork Monitor daemon */
				if (susshi_fork_monitor_daemon() == false) {
					fatal("Failed to fork monitor daemon.");
				}

				/* For Syslog daemon */
				if (susshi_fork_rsyslog_daemon() == false) {
					error("Failed to fork rsyslog daemon.");
				}
			} else {
				/* We are in the role of a single session worker */
				susshi_session.process_role = PROC_ROLE_SESSION;
			}
		}

		// Server-Loop
		susshi_master_loop();

		susshi_hooks_run(HOOK_GATEWAY_STOP);

		// Free susshi cfg
		susshi_cfg_free();

	} else {
		fatal("Communication to Chef resulted in error. Giving up.");
	}
}

/*! @} */
