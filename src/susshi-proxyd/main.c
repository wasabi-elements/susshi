/*!
 *
 * @brief       suSSHi susshi-proxyd Main
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
 * @defgroup    susshi_proxyd     susshi-proxyd - The suSSHi2 proxy daemon
 * @brief       The suSSHi2 proxy daemon handles all proxied connections from gateways to targets
 * @{
 *
 */

#include <susshi-proxyd/common.h>

bool flag_debug = false;
bool flag_no_daemon = false;
bool flag_main_process_in_foreground = true;

/* Prototypes */
static void susshi_proxyd_main(int argc, char **argv, char **envp, bool first_startup);


/*!
 * @brief       Print Usage
 */

static void
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
			"\nUsage: " SUSSHI_PROXYD_NAME " [-dDFe] [-f config_file.json] [-p port]"
			"\n         -d  Debug level, multiple -d (up to " MAX_DEBUG_OPTS ") increases the debug level."
			"\n         -D  Don't fork main process or sessions into background. This should be used for debugging only."
			"\n             Only one single client connection is handled before quitting."
			"\n         -e  Output system messages on stderr as well."
			"\n         -f  Specify alternative configuration file."
			"\n             By default, " SUSSHI_PROXYD_NAME " looks at \"" SUSSHI_PROXYD_CONFIG_FILE1 "\","
			"\n             \"" SUSSHI_PROXYD_CONFIG_FILE2 "\" and \"" SUSSHI_PROXYD_CONFIG_FILE3 "\" for configuration file."
			"\n         -F  Fork into background. Main process forks into background. Default is to stay in foreground."
			"\n         -h  This help."
			"\n         -p  Overwrites the listen port in configuration file."
			"\n         -P  Overwrites default listen port (" MONITOR_PORT_STRING ") for HTTP health probe interface.\n"
			"\n         As an alternative to providing a configuration file, you can also specify the"
			"\n         configuration file as a Base64 encoded string in the ENV variable PROXY_CONFIG."
			"\n         Hint: cat config-file.json | base64\n\n"
	);
}


/*!
 * @brief       susshi-proxyd main
 *
 * @param       argc            Argument Count
 * @param       argv            Argument Values
 * @param       envp            Environments
 * @param       first_startup   Set to true on first startup
 */

static void
susshi_proxyd_main(int argc, char **argv, char **envp, bool first_startup) {
	extern char *optarg;
	extern int	optind;
	bool sic_initialization = false;
	int opt;

	static char *proxy_cfg_file = NULL;
	char *env_config;

	mode_t new_umask;

	// Init libSSH
	ssh_init();

	// Init suSSHi session struct
	init_proxy_session();

	// Initialize configuration options
	proxy_cfg_init();

	// Drop privileges temporarily
	proxy_drop_privileges(SUSSHI_PROXYD_NAME, false);

	// Reset getopt if called multiple times (on restart)
	optind = 1;

	if (getenv("MONITOR_PORT") != NULL) {
		proxy_cfg.health_monitor_port = a2port(getenv("MONITOR_PORT"));
		if (proxy_cfg.health_monitor_port <= 0) {
			fatal("Bad port number in environment variable MONITOR_PORT.");
		}
	}

	// Parse command-line arguments.
	while ((opt = getopt(argc, argv, "dDef:Fhp:P:")) != -1) {
		switch (opt) {
			case 'd':
				if (!flag_debug) {
					flag_debug = true;
					proxy_cfg.log_level = LOG_DEBUG_MILESTONES;
				} else {
#ifdef WITH_FULL_DEBUG_OPTIONS
					if (proxy_cfg.log_level < LOG_DEBUG_PACKETDUMP)
						proxy_cfg.log_level++;
#else
					if (proxy_cfg.log_level < LOG_DEBUG_DETAILS)
						proxy_cfg.log_level++;
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
					proxy_cfg_file = strdup(optarg);
				break;
			case 'F':
				flag_main_process_in_foreground = false;
				break;
			case 'h':
				usage();
				exit(0);
			case 'p':
				proxy_cfg.ports_from_cmdline = true;
				if (proxy_cfg.num_ports >= MAX_PORTS) {
					fatal("Too many ports.");
				}
				proxy_cfg.ports[proxy_cfg.num_ports++] = a2port(optarg);
				if (proxy_cfg.ports[proxy_cfg.num_ports-1] <= 0) {
					fatal("Bad port number.");
				}
				break;
			case 'P':
				proxy_cfg.health_monitor_port = a2port(optarg);
				if (proxy_cfg.health_monitor_port <= 0) {
					fatal("Bad health monitor port number.");
				}
				break;
			case '?':
			default:
				usage();
				exit(1);
		}
	}

	// Set global log_level
	log_level = LOG_INFO;

	// Check that there are no remaining arguments.
	if (optind < argc) {
		fatal("Extra argument %s.\n", argv[optind]);
	}

	debug1(SUSSHI_NAME " version %.100s", SUSSHI_RELEASE);

	// Load & parse susshid config
	SETPROCTITLE("Loading local configuration.");

	if ((proxy_cfg_file == NULL) && (env_config = getenv("PROXY_CONFIG")) != NULL) {

		/* Try to load configuration from Base64 encoded ENV variable */
		unsigned char *config = NULL;
		size_t config_len;
		if (susshi_unbase64(env_config, &config, &config_len)) {
			json_t *document;
			json_error_t json_error;

			document = json_loads((const char*) config, 0, &json_error);

			if (document) {
				if (proxy_cfg_read_json(document) == false) {
					fatal("The configuration JSON seems to be corrupted.");
				}
			}
			free(config);
		} else {
			fatal("The Base64 seems to be corrupted. Please check encoding.");
		}
	} else {

		/* Try to load configuration from specified file or default file list */
		if (proxy_cfg_load_configfile(proxy_cfg_file) == false) {
			fatal("The configuration files seem to be corrupted or not in JSON syntax.");
		}
	}

	// Fill defaults
	proxy_cfg_fill_defaults(sic_initialization);

	// Set global log_level after configuration
	log_level = proxy_cfg.log_level;

	if (geteuid() == 0 && setgroups(0, NULL) == -1)
		debug3("setgroups(): %.200s", strerror(errno));

	// Ensure that fds 0, 1 and 2 are open or directed to /dev/null
	sanitise_stdfd();

	/*
	 * If not in no_daemon and not flagged for foreground mode,
	 * disconnect from the controlling terminal, and fork.
	 * The original process exits.
	 */

	if ((!flag_main_process_in_foreground) && (!flag_no_daemon)) {
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

	// Initialize the random number generator.
	arc4random_stir();

	// Chdir to the root directory so that the current disk can be unmounted if desired.
	if (chdir("/") == -1) {
		fatal("Could not chdir(/): %s", strerror(errno));
	}

	/* Ignore signals */
	proxy_sigaction(SIGPIPE, SIG_IGN, 0);
	proxy_sigaction(SIGUSR1, SIG_IGN, 0);
	proxy_sigaction(SIGUSR2, SIG_IGN, 0);
	proxy_sigaction(SIGCONT, SIG_IGN, 0);
	proxy_sigaction(SIGWINCH, SIG_IGN, 0);

	// Write out the pid file after the sigterm handler is setup and the listen sockets are bound

	{
		FILE *f = fopen(bdata(proxy_cfg.pid_file), "w");

		if (f == NULL) {
			error("Couldn't create pid file \"%s\": %s",
				  bdata(proxy_cfg.pid_file), strerror(errno));
		} else {
			fprintf(f, "%ld\n", (long) getpid());
			fclose(f);
		}
	}

	// Init susshi log and report
	init_proxy_log();

	log_system(LOG_INFO, SUSSHI_NAME " - " SUSSHI_PROXYD_NAME " version %.100s started.", SUSSHI_RELEASE);

	// Dump Config
	debug3("Dump susshid configuration:");
	proxy_cfg_dump_config();

	// Still not filled from configuration file?
	if (proxy_cfg.num_ports == 0)
		proxy_cfg.ports[proxy_cfg.num_ports++] = SSH_DEFAULT_PORT;

	// Still not filled from configuration file?
	if (proxy_cfg.listen_addrs == NULL)
		proxy_cfg_add_listen_addr(NULL, 0);

	// Store master PID
	proxy_session.master_pid = getpid();

	/* restore privileges to allow rebind of sockets to privileged ports */
	proxy_restore_privileges();

	// Start HTTP Monitor Server
	/* Fork Monitor daemon */
	if (proxy_fork_monitor_daemon() == false) {
		fatal("Failed to fork monitor daemon.");
	}

	/* Remove old bastion PID file if exists, otherwise Bastion may not get forked on container restart */
	bastion_remove_daemon_pid_file();

	/* Start bastion sshd */
	run_bastion_sshd(proxy_cfg.num_host_key_files, proxy_cfg.host_key_files, proxy_cfg.num_gateway_identities, proxy_cfg.gateway_identities, &proxy_session.bastion_pid);

	// Server-Loop
	proxy_master_loop();

}


/*!
 * @brief       susshi-proxyd main
 *
 * @param       argc            Argument Count
 * @param       argv            Argument Values
 * @param       envp            Environments
 *
 * @return      Exit code
 */

int
main(int argc, char **argv, char **envp) {

	int argc_copy = argc;
	char** argv_copy;
	char** envp_copy;
	char *cwd;

	bool first_startup = true;

	/* Copy argv and evnp because they may get consumed by setproctitle later */
	{ 	// --- argv
		argv_copy = malloc((argc+1) * sizeof *argv_copy);

		for(int i = 0; i < argc; ++i)
			argv_copy[i] = strdup(argv[i]);

		argv_copy[argc] = NULL;
	}

	{   // --- envp
		int envc;

		for (envc = 0; envp[envc] != NULL; envc++);
		envp_copy = (char **) malloc(sizeof(char *) * (envc + 1));

		for (int i = 0; envp[i] != NULL; i++)
			envp_copy[i] = strdup(envp[i]);

		envp_copy[envc] = NULL;
	}

	// Save current working directory and reapply on reload
	cwd = getcwd(NULL, 0);

	// Init proctitle data
	SETPROCTITLE_INIT(argc, argv, envp);

	if (cwd) {

		// Init suSSHi session struct (NULL bytes)
		init_proxy_session();

		do {

			// Re-CD to working directory on startup
			if (chdir(cwd) == -1) {
				fatal("Could not chdir(%s): %s", cwd, strerror(errno));
			}

			susshi_proxyd_main(argc_copy, argv_copy, envp_copy, first_startup);
			proxy_cfg_free();
			first_startup = false;
			flag_debug = false;

		} while (proxy_session.received_signal_for_restart);

	} else {
		fatal("Could not determine current working directory. Aborting.");
	}

}

/*! @} */
