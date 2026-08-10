/*!
 *
 * @brief       Helper methods
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

#include "susshid/common.h"


/*!
 * @brief       Run an external program safely without invoking a shell
 *
 * @param       path    Absolute path to the executable
 * @param       argv    NULL-terminated argument array (argv[0] = program name)
 *
 * @return      Exit status of the child, or -1 on error
 */

static int
run_execv(const char *path, const char *const argv[]) {
	pid_t pid;
	int status;

	pid = fork();
	if (pid == -1)
		return -1;

	if (pid == 0) {
		execv(path, (char *const *)argv);
		_exit(127);
	}

	if (waitpid(pid, &status, 0) == -1)
		return -1;

	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}


/*!
 * @brief       Cleanup after signal has been received
 */

void
susshi_cleanup(void) {

	/* This seems to cause crashes sometimes */
	// susshi_master_detach_embryonic_slots();

	if (susshi_session.process_role == PROC_ROLE_MASTER) {

		susshi_hooks_run(HOOK_GATEWAY_STOP);

		/* We restore privileges to be allowed to SIGTERM rsyslogd as well */
		susshi_restore_privileges();

		/* Send SIGINT to session worker childs if there are any running */
		if (susshi_count_and_signal_processes(SUSSHID_PROCESS_PATTERN_WORKERS, SIGINT, true) > 0) {
			while (sleep(3) != 0);
		}

		if (susshi_session.report_pid > 0) {
			/* We have a running reporting daemon */
			log_system(LOG_LEVEL_INFO, "Send SIGINT signal to reporting daemon with pid %d and wait for termination", susshi_session.report_pid);
			kill(susshi_session.report_pid, SIGINT);
			waitpid(susshi_session.report_pid, NULL, 0);
		}


		if (susshi_session.monitor_pid > 0) {
			log_system(LOG_LEVEL_INFO, "Send SIGINT signal to monitor daemon with pid %d and wait for termination", susshi_session.monitor_pid);
			kill(susshi_session.monitor_pid, SIGINT);
			waitpid(susshi_session.monitor_pid, NULL, 0);
		}

		if (susshi_session.rsyslog_pid > 0) {
			log_system(LOG_LEVEL_INFO, "Send SIGTERM signal to rsyslog daemon with pid %d and wait for termination", susshi_session.rsyslog_pid);
			kill(susshi_session.rsyslog_pid, SIGTERM);
			waitpid(susshi_session.rsyslog_pid, NULL, 0);
		}

		/* Remove PID file */
		remove(PATH_SUSSHI_DAEMON_PID_FILE);
		ssh_finalize();

	} else {
		susshi_libssh_close_pcaps();
		ssh_finalize();
	}

	susshi_memcrypt_cleanup();
	susshi_cfg_free();

	/*
	if (bastion_lookup_daemon_pid(&susshi_session.bastion_pid)) {
		// We have a running bastion SSHD
		log_system(LOG_LEVEL_INFO, "Send SIGTERM signal to bastion daemon with pid %d", susshi_session.bastion_pid);
		kill(susshi_session.bastion_pid, SIGTERM);
	}
	*/
}


/*!
 * @brief       Fatal function called in fatal situations
 *
 * Cleans Up everything and terminates process immediately
 *
 * param        fmt     Format string
 * @param       ...     Optional parameters referenced by format string
 */

void
fatal(const char *fmt, ...)
{
	va_list args;

	log_on_stderr = true;
	log_level = LOG_LEVEL_EMERG;

	va_start(args, fmt);
	do_log(LOG_LEVEL_EMERG, true, fmt, args);
	va_end(args);

	/* Let's try to send a last report */
	susshi_report_client_send_report(REPORT_FATAL);

	susshi_cleanup();

	_exit(255);
}


/*!
 * @brief       Validate string only containing allowed characters
 *
 * @param       string          string to be validated
 * @param       allowed_regex   regex for allowed characters
 *
 * @return      true if key string only contains allowed_chars, otherwise false
 */

bool
validate_string_chars_regex(bstring string, const char *allowed_regex) {
	bool rc = false;
	pcre2_code *code = NULL;
	int errorcode;
	PCRE2_SIZE erroffset;

	code = pcre2_compile((PCRE2_SPTR)allowed_regex, PCRE2_ZERO_TERMINATED, 0, &errorcode, &erroffset, NULL);
	if (code != NULL) {
		pcre2_match_data *md = pcre2_match_data_create_from_pattern(code, NULL);
		if (md != NULL && pcre2_match(code, (PCRE2_SPTR)bdata(string), blength(string), 0, 0, md, NULL) >= 0)
			rc = true;
		pcre2_match_data_free(md);
		pcre2_code_free(code);
	}

	return rc;
}

/*!
 * @brief       Prepare unprivileged user
 */

void
susshi_prepare_unprivileged_user(void) {

	char *env_uid;
	char *env_gid;
	const char *errstr;
	struct passwd *pwd;
	struct group *grp;
	uid_t uid = (uid_t) -1;
	gid_t gid = (gid_t) -1;

	/* Did we get an ENV with other uid than 900 ? */
	if ((env_uid = getenv(ENV_SUSSHI_UID)) != NULL) {
		uid = (uid_t) strtonum(env_uid, 1, (long long)((uid_t)-2), &errstr);
		if (errstr)
			fatal("SUSSHI_UID is not a valid UID: %s", errstr);

		pwd = getpwuid(uid);
		if ((pwd != NULL) && (strncmp(pwd->pw_name, SUSSHI_UNPRIVILEGED_USERNAME, strlen(SUSSHI_UNPRIVILEGED_USERNAME)) != 0)) {
			fatal("Another user (%s) with uid %d already exists.", pwd->pw_name, uid);
		}

		susshi_session.unprivileged_user_uid = uid;
	}

	/* Did we get an ENV with other gid than 900 ? */
	if ((env_gid = getenv(ENV_SUSSHI_GID)) != NULL) {
		gid = (gid_t) strtonum(env_gid, 1, (long long)((gid_t)-2), &errstr);
		if (errstr)
			fatal("SUSSHI_GID is not a valid GID: %s", errstr);

		grp = getgrgid(gid);
		if ((grp != NULL) && (strncmp(grp->gr_name, SUSSHI_UNPRIVILEGED_USERNAME, strlen(SUSSHI_UNPRIVILEGED_USERNAME)) != 0)) {
			fatal("Another group (%s) with gid %d already exists.", grp->gr_name, gid);
		}

		susshi_session.unprivileged_user_gid = gid;
	}

	pwd = getpwnam(SUSSHI_UNPRIVILEGED_USERNAME);

	if (pwd != NULL) {
		uid_t target_uid;
		gid_t target_gid;
		struct stat st;
		char uid_str[16], gid_str[16];

		if (gid != (gid_t) -1) {
			/* Modify susshi group if requested */
			snprintf(gid_str, sizeof(gid_str), "%u", (unsigned int) gid);
			{
				const char *args[] = { CMD_GROUPMOD, "-g", gid_str, SUSSHI_UNPRIVILEGED_USERNAME, NULL };
				if (run_execv(CMD_GROUPMOD, args) != 0)
					fatal("Could not change group to other GID.");
			}
		}

		if ((uid != (uid_t) -1) || (gid != (gid_t) -1)) {
			/* Modify susshi user if requested */
			const char *args[8];
			int argc = 0;

			args[argc++] = CMD_USERMOD;
			if (uid != (uid_t) -1) {
				snprintf(uid_str, sizeof(uid_str), "%u", (unsigned int) uid);
				args[argc++] = "-u";
				args[argc++] = uid_str;
			}
			if (gid != (gid_t) -1) {
				args[argc++] = "-g";
				args[argc++] = gid_str;
			}
			args[argc++] = SUSSHI_UNPRIVILEGED_USERNAME;
			args[argc]   = NULL;

			if (run_execv(CMD_USERMOD, args) != 0)
				fatal("Could not change user to other UID/GID.");
		}

		target_uid = (uid != (uid_t) -1) ? uid : pwd->pw_uid;
		target_gid = (gid != (gid_t) -1) ? gid : pwd->pw_gid;

		/* Ensure PID directory is owned by the unprivileged user */
		if (stat(PATH_SUSSHI_PIDDIR, &st) == 0) {
			if (st.st_uid != target_uid || st.st_gid != target_gid) {
				if (chown(PATH_SUSSHI_PIDDIR, target_uid, target_gid) == -1)
					fatal("Could not change owner of directory "PATH_SUSSHI_PIDDIR": %s", strerror(errno));
			}
		}

		/* Ensure PID directory is owned by the unprivileged user */
		if (stat(PATH_SUSSHI_DAEMON_PID_FILE, &st) == 0) {
			if (st.st_uid != target_uid || st.st_gid != target_gid) {
				if (chown(PATH_SUSSHI_DAEMON_PID_FILE, target_uid, target_gid) == -1)
					fatal("Could not change owner of directory "PATH_SUSSHI_PIDDIR": %s", strerror(errno));
			}
		}

		/* Ensure Temp directory is owned by the unprivileged user */
		if (stat(PATH_SUSSHID_TEMP_DIR, &st) == 0) {
			if (st.st_uid != target_uid || st.st_gid != target_gid) {
				if (chown(PATH_SUSSHID_TEMP_DIR, target_uid, target_gid) == -1)
					fatal("Could not change owner of directory "PATH_SUSSHI_PIDDIR": %s", strerror(errno));
			}
		}

		/* Here we try to chown Config directory we store hostkeys etc. in */
		if (chown(PATH_SUSSHID_CONFIG_DIR, susshi_session.unprivileged_user_uid, susshi_session.unprivileged_user_gid) == -1)
			error("Could not change owner of directory "PATH_SUSSHID_CONFIG_DIR" to other UID/GID.: %s", strerror(errno));

		/* Here we try to chown (base) Log directory */
		if (chown(PATH_SUSSHI_LOGDIR, susshi_session.unprivileged_user_uid, susshi_session.unprivileged_user_gid) == -1)
			error("Could not change owner of directory "PATH_SUSSHI_LOGDIR" to other UID/GID.: %s", strerror(errno));

	} else {
		fatal("Failed to get information about user %s", SUSSHI_UNPRIVILEGED_USERNAME);
	}
}


/*! @} */
