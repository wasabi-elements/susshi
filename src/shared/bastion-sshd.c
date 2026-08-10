/*!
 *
 * @brief       Methods to run openSSH bastion server
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
 * @defgroup    bastion Bastion methods
 * @{
 */

#include "shared/common.h"
#include "shared/log.h"
#include "shared/bastion-sshd.h"
#include "shared/misc.h"

/* Prototypes */
static FILE *new_config_file(bstring filename);
static bool bastion_sshd_configuration(int num_host_keys, bstring *host_key_files, int num_target_identities, KeyIdentity *key_identities);
static bool bastion_sshd_exec(void);

static const char *bastion_argv[] = {
		PATH_BASTION_DAEMON,
		"-f",
		PATH_BASTION_CONFIG_FILE,
/*   	"-ddd", */
		NULL
};

static const char *bastion_file_config =
		"Protocol                        2\n"
		"ListenAddress                   " BASTION_LISTEN_IP ":" BASTION_LISTEN_PORT_STR "\n"
		"KexAlgorithms                   ecdh-sha2-nistp256\n"
		"Ciphers                         aes256-ctr\n"
		"MACs                            hmac-sha2-256\n"
		"AllowAgentForwarding            no\n"
		"AllowTcpForwarding              yes\n"
		"AllowUsers                      " BASTION_USER "\n"
		"AuthenticationMethods           publickey\n"
		"ChallengeResponseAuthentication no\n"
		"ClientAliveInterval             120\n"
		"ClientAliveCountMax             3\n"
		"GatewayPorts                    no\n"
		"HostbasedAuthentication         no\n"
		"KerberosAuthentication          no\n"
		"MaxSessions                     1\n"
		"PasswordAuthentication          no\n"
		"PermitEmptyPasswords            no\n"
		"PermitRootLogin                 no\n"
		"PermitTunnel                    no\n"
		"PermitTTY                       yes\n"
		"PrintMotd                       no\n"
		"PrintLastLog                    no\n"
		"StrictModes                     yes\n"
		"UsePAM                          yes\n"
		"X11Forwarding                   no\n"
		"VersionAddendum                 suSSHi Bastion\n"
		"PidFile                         " PATH_BASTION_PID_FILE "\n"
		"AuthorizedKeysFile              " PATH_BASTION_AUTHORIZED_KEYS "\n"
		"Banner                          " PATH_BASTION_BANNER "\n"
		"ForceCommand                    echo 'This login is restricted to port-forwarding only. Press enter to exit.'; read a; exit\n"
/*      "LogLevel                        DEBUG3\n" */
;


/*!
 * @brief       Check if we have already an OpenSSH bastion server running, otherwise fork one.
 *
 * @param       num_host_keys           Number of Host Keys
 * @param       host_key_files          Pointer to list of Host Key files (bstring)
 * @param       num_target_identities   Number of SSH (Gateway) Identities
 * @param       key_identities          Pointer to list of Identities (KeyIdentity)
 * @param       bastion_pid             PID of bastion process
 *
 * @note
 *
 * Run from susshid:
 *
 *  run_bastion_sshd(susshi_cfg.num_host_key_files, susshi_cfg.host_key_files, susshi_cfg.num_target_identities, susshi_cfg.target_identities, &susshi_session.bastion_pid);
 *
 * Run from proxyd:
 *
 *  run_bastion_sshd(proxy_cfg.num_host_key_files, proxy_cfg.host_key_files, proxy_cfg.num_gateway_identities, proxy_cfg.gateway_identities, &proxy_session.bastion_pid);
 *
 * @return   true on success
 */

bool
run_bastion_sshd(int num_host_keys, bstring *host_key_files, int num_target_identities, KeyIdentity *key_identities, int *bastion_pid) {

	int child_pid;

	if (bastion_lookup_daemon_pid(bastion_pid) > 0) {
		debug4("Another bastion daemon is already running on pid %d. No additional fork required.", *bastion_pid);
		return true;
	}

	switch (child_pid = fork()) {
		case 0: { /* I am child = bastion */
			int fd;

			if ((fd = open(_PATH_DEVNULL, O_RDWR, 0)) != -1) {
				dup2(fd, STDIN_FILENO);
				dup2(fd, STDOUT_FILENO);
				if (fd > STDERR_FILENO)
					close(fd);
			}

			/* Prepare configuration */
			if (bastion_sshd_configuration(num_host_keys, host_key_files, num_target_identities, key_identities)) {

				/* Start the OpenSSH Server */
				bastion_sshd_exec();
			}

			exit(0);
		} break;

		case -1: {
			error("Failed to fork bastion daemon");
			return false;
		} break;

		default: { /* I am parent */

			log_system(LOG_LEVEL_INFO, "Forked bastion daemon with pid %d", child_pid);

			/* Give ssh daemon some time for startup */
			sleep(2);

			return true;
		}
	}

}


/*!
 * @brief   Create configuration files for bastion
 *
 * @param    num_host_keys          Number of Host Keys
 * @param    host_key_files         Pointer to list of Host Key files (bstring)
 * @param    num_target_identities  Number of SSH (Gateway) Identities
 * @param    key_identities         Pointer to list of Identities (KeyIdentity)
 *
 * @return   true on success
 */

static bool
bastion_sshd_configuration(int num_host_keys, bstring *host_key_files, int num_target_identities, KeyIdentity *key_identities) {

	bstring path = NULL;
	FILE *file;
	size_t written;

	/* sshd_config file */

	debug1("Bastion - Generating %s ...", PATH_BASTION_CONFIG_FILE);

	path = bfromcstr(PATH_BASTION_CONFIG_FILE);
	if ((file = new_config_file(path))) {
		written = fwrite(bastion_file_config, 1, strlen(bastion_file_config), file);
		if (written == strlen(bastion_file_config)) {
			for(int i=0; i < num_host_keys; i++) {
				fprintf(file, "HostKey                         %s\n", bdata(host_key_files[i]));
			}
			fclose(file);
			bstrFree(path);
		} else {
			error("Failed to write %s: %s", PATH_BASTION_CONFIG_FILE, strerror(errno));
			fclose(file);
			bstrFree(path);
			return false;
		}
	} else {
		return false;
	}

	/* Banner file */

	debug1("Bastion - Generating %s ...", PATH_BASTION_BANNER);

	path = bfromcstr(PATH_BASTION_BANNER);
	if ((file = new_config_file(path))) {
		written = fwrite(BASTION_BANNER, 1, strlen(BASTION_BANNER), file);
		if (written == strlen(BASTION_BANNER)) {
			fflush(file);
			fclose(file);
			bstrFree(path);
		} else {
			error("Failed to write %s: %s", PATH_BASTION_BANNER, strerror(errno));
			fclose(file);
			bstrFree(path);
			return false;
		}
	} else {
		return false;
	}

	/* Authorized Keys file */

	debug1("Bastion - Generating %s ...", PATH_BASTION_AUTHORIZED_KEYS);

	path = bfromcstr(PATH_BASTION_AUTHORIZED_KEYS);
	if ((file = new_config_file(path))) {
		struct passwd *pwd;

		for(int i=0; i < num_target_identities; i++) {
			if (strncmp( bdata(key_identities[i].public_blob), "ssh-", 4) == 0)
				fprintf(file, "from=\"127.0.0.1,::1\",restrict,port-forwarding,pty %s\n", bdata(key_identities[i].public_blob));
			else
				fprintf(file, "from=\"127.0.0.1,::1\",restrict,port-forwarding,pty %s %s\n", bdata(key_identities[i].key_type), bdata(key_identities[i].public_blob));
		}
		fflush(file);
		fclose(file);
		bstrFree(path);

		/* Chown of authorized_keys file to bastion */
		pwd = getpwnam(BASTION_USER);
		if (pwd!= NULL) {
			if (chown(PATH_BASTION_AUTHORIZED_KEYS, pwd->pw_uid, 0) == -1)
				fatal("Could not change owner of file "PATH_BASTION_AUTHORIZED_KEYS" to other UID/GID.: %s", strerror(errno));
		}
	} else {
		return false;
	}

	return true;
}


/*!
 * @brief       Lookup Bastion Daemon PID
 *
 * Look if bastion_pid was already read from SSHD PID file into session
 * or if there is a PID file written by SSHD, we can read from
 *
 * @param       bastion_pid     Pointer to int where PID of the bastion process gets stored in
 *
 * @return      PID if found, otherwise <= 0
 */

pid_t
bastion_lookup_daemon_pid(int *bastion_pid) {
	FILE *pid_file;

	if (*bastion_pid <= 0) {
		if ((pid_file = fopen(PATH_BASTION_PID_FILE, "r"))) {
			if (fscanf(pid_file, "%d", bastion_pid) < 1 ||
				*bastion_pid <= 0 || *bastion_pid > PID_MAX_LIMIT)
				fatal("Invalid or missing PID in %s: %s", PATH_BASTION_PID_FILE, strerror(errno));
			fclose(pid_file);
		}
	}

	return *bastion_pid;
}


/*!
 * @brief       Remove bastion PID file if exists
 *
 */

void
bastion_remove_daemon_pid_file(void) {
	remove(PATH_BASTION_PID_FILE);
}


/*!
 * @brief       Execute the bastion daemon via @c execv, replacing the current process
 *
 * On success this function does not return — @c execv replaces the process image.
 * It only returns @c false if @c execv itself fails, which is a fatal condition.
 *
 * @return      @c false if @c execv fails (never returns on success)
 */

static bool
bastion_sshd_exec(void) {

	bstring pid_file = bfromcstr(PATH_BASTION_PID_FILE);

	/* Create directory for PID file */
	create_subdir(pid_file);
	bstrFree(pid_file);

	/* Exec SSHD */
	debug1("Starting Bastion daemon ... %s %s %s", bastion_argv[0], bastion_argv[1], bastion_argv[2]);
	execv(PATH_BASTION_DAEMON, (char **) bastion_argv);

	fatal("Failed to start Bastion daemon.");

	/* Should not return, otherwise execv() has failed to start the daemon */
	return false;
}


/*!
 * @brief       Create or truncate a configuration file and return an open handle for writing
 *
 * If the file's parent directory does not exist, it is created automatically.
 * The file is opened with mode 0660 (owner and group read/write).
 *
 * @param       filename    Absolute path of the file to create
 *
 * @return      Open @c FILE handle on success, or @c NULL on failure
 */

static FILE *
new_config_file(bstring filename) {
	int fd;

	// Open file
	fd = open(bdata(filename), O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW, ( S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP ));

	if ((fd < 0) && (errno == ENOENT)) {
		create_subdir(filename);
		fd = open(bdata(filename), O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW, ( S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP ));
	}

	if (fd < 0) {
		return NULL;
	}

	return(fdopen(fd, "a"));
}

/*! @} */
