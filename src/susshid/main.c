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
 * @ingroup     susshid
 * @{
 */

#include <susshid/common.h>


/*!
 * @brief       susshid main
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
		if (!argv_copy)
			fatal("malloc failed for argv_copy.");

		for(int i = 0; i < argc; ++i) {
			argv_copy[i] = strdup(argv[i]);
			if (!argv_copy[i])
				fatal("strdup failed for argv_copy[%d].", i);
		}

		argv_copy[argc] = NULL;
	}

	{   // --- envp
		int envc;

		for (envc = 0; envp[envc] != NULL; envc++);
		envp_copy = (char **) malloc(sizeof(char *) * (envc + 1));
		if (!envp_copy)
			fatal("malloc failed for envp_copy.");

		for (int i = 0; envp[i] != NULL; i++) {
			envp_copy[i] = strdup(envp[i]);
			if (!envp_copy[i])
				fatal("strdup failed for envp_copy[%d].", i);
		}

		envp_copy[envc] = NULL;
	}

	// Save current working directory and reapply on reload
	cwd = getcwd(NULL, 0);

	// Init proctitle data
	SETPROCTITLE_INIT(argc, argv, envp);

	if (cwd) {
		// Initialize the random number generator.
		arc4random_stir();

		// Init suSSHi session struct
		init_susshi_session(first_startup);

		// Role Master
		susshi_session.process_role = PROC_ROLE_MASTER;

		// Initialize libSSH
		ssh_init();

		// Initialize Memcrypt
		susshi_memcrypt_init();

		// Initialize Chef config
		chef_cfg_init();

		// Create PID directory
		if (mkdir(PATH_SUSSHI_PIDDIR, 0755) == -1 && errno != EEXIST)
			fatal("Could not create directory " PATH_SUSSHI_PIDDIR ": %s", strerror(errno));


		// Call usermod/groupmod if environment variables tell us to change uid/gid for unprivileged user
		susshi_prepare_unprivileged_user();

		do {

			// Re-CD to working directory on startup
			if (chdir(cwd) == -1) {
				fatal("Could not chdir(%s): %s", cwd, strerror(errno));
			}

			// In case we've received a signal for restart, let's clear it here
			susshi_session.received_signal_for_restart = false;

			susshid_main(argc_copy, argv_copy, envp_copy, first_startup);

			first_startup = false;
			flag_debug = false;

		} while (susshi_session.received_signal_for_restart);

		chef_cfg_free();

	} else {
		fatal("Could not determine current working directory. Aborting.");
	}

}

/*! @} */
