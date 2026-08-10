/*!
 *
 * @brief       Rsyslog methods
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
 * @defgroup    rsyslog Rsyslogd methods
 * @brief       All kinds of rsyslog(d) functions.
 * @{
 */

#include "susshid/common.h"

/* Prototypes */
static FILE *new_file(bstring filename);
static bool rsyslog_configuration(void);
static bool rsyslog_exec(void);

static const char *rsyslog_argv[] = {
		PATH_RSYSLOG_DAEMON,
		"-f",
		PATH_RSYSLOG_CONFIG_FILE,
		"-i",
		PATH_RSYSLOG_PID_FILE,
		"-n",
		NULL
};

/* rsyslog.conf - Part 1 */
static const char *rsyslogd_file_config_p1 =
	"module(load=\"imuxsock\")\n"
	"module(load=\"omrelp\" tls.tlslib=\"openssl\")\n"
	"template(name=\"ChefFormat\" type=\"list\") {\n"
	"    constant(value=\"<\")\n"
	"    property(name=\"pri\")\n"
	"    constant(value=\">\")\n"
	"    property(name=\"timestamp\" dateFormat=\"rfc3339\")\n"
	"    constant(value=\" \")\n"
;
/* rsyslog.conf - Constant Hostname goes here */
/* rsyslog.conf - Part 2 */
static const char *rsyslogd_file_config_p2 =
	"    constant(value=\" \")\n"
	"    property(name=\"syslogtag\" position.from=\"1\" position.to=\"32\")\n"
	"    property(name=\"msg\" spifno1stsp=\"on\" )\n"
	"    property(name=\"msg\")\n"
	"    }\n"
	""
;

/* rsyslog.conf - Actions */


/*!
 * @brief       Check if we have already an rsyslogd running, otherwise fork one.
 *
 * @return      true on success
 */

bool
susshi_fork_rsyslog_daemon(void) {

	int child_pid;

	if( access( PATH_RSYSLOG_DEV_LOG, F_OK ) != -1 ) {
		// file exists
		error("We've found an existing " PATH_RSYSLOG_DEV_LOG " - probably the special device was mapped into the container?" );
		error("Please remove mapping and restart container. Until then, the 'logging to suSSHi Chef' feature remains deactivated. " );
		return false;
	}

	if( susshi_cfg.syslog_tls_certificate == NULL ) {
		error("suSSHi Chef has not sent a Certificate for Syslog-over-TLS. Is suSSHi Chef of version >19.05 ?");
		error("The 'logging to suSSHi Chef' feature remains deactivated.");
		return false;
	}

	if (susshi_lookup_rsyslog_pid(&susshi_session.rsyslog_pid) > 0) {
		debug1("It seems there is another rsyslogd running. Not starting another one.");
		return true;
	}

	switch (child_pid = fork()) {
		case 0: { /* I am child = rsyslog */
			int fd;

			susshi_session.process_role = PROC_ROLE_RSYSLOG;

			if ((fd = open(_PATH_DEVNULL, O_RDWR, 0)) != -1) {
				dup2(fd, STDIN_FILENO);
				dup2(fd, STDOUT_FILENO);
				if (fd > STDERR_FILENO)
					close(fd);
			}

			/* Close System logfile */
			susshi_close_logfile(&susshi_session.log_system);

			/* Prepare configuration */
			if (rsyslog_configuration()) {

				/* Start rsyslogd */
				rsyslog_exec();
			}

			exit(0);
		} break;

		case -1: {
			error("Failed to fork rsyslog daemon");
			return false;
		} break;

		default: { /* I am parent */

			log_system(LOG_LEVEL_INFO, "Forked rsyslog daemon with pid %d", child_pid);
			susshi_session.rsyslog_pid = child_pid;

			return true;
		}
	}

}


/*!
 * @brief       Create configuration files for rsyslog
 *
 * @return      true on success
 */

static bool
rsyslog_configuration(void) {

	bstring path = NULL;
	FILE *file;
	size_t written;
	bool rc = false;

	pcre2_code *pcre_re = NULL;
	pcre2_match_data *pcre_md = NULL;
	int pcre_errorcode = 0;
	PCRE2_SIZE pcre_erroffset;

	/* rsyslogd.conf file */

	pcre_re = pcre2_compile((PCRE2_SPTR)":\\/\\/([^:\\/]+)",
							PCRE2_ZERO_TERMINATED, 0, &pcre_errorcode, &pcre_erroffset, NULL);

	if (pcre_re != NULL) {
		pcre_md = pcre2_match_data_create_from_pattern(pcre_re, NULL);

		// rsyslogd.conf
		path = bfromcstr(PATH_RSYSLOG_CONFIG_FILE);
		debug3("Syslog - Generating %s ...", bdata(path));

		if ((file = new_file(path))) {
			written = fwrite(rsyslogd_file_config_p1, 1, strlen(rsyslogd_file_config_p1), file);
			if (written == strlen(rsyslogd_file_config_p1)) {
				fprintf(file, "    constant(value=\"%s-%s\")\n", bdata(chef_cfg.susshid_id),
						bdata(susshi_cfg.syslog_gateway_name));
				written = fwrite(rsyslogd_file_config_p2, 1, strlen(rsyslogd_file_config_p2), file);
				if (written == strlen(rsyslogd_file_config_p2)) {
					for (int i = 0; i < chef_cfg.chef_server_urls.num_all; i++) {
						bstring uri = chef_cfg.chef_server_urls.report[i];

						if (pcre_md != NULL && pcre2_match(pcre_re, (PCRE2_SPTR)bdata(uri), blength(uri), 0, 0, pcre_md, NULL) > 0) {
							PCRE2_SIZE *pcre_ovector = pcre2_get_ovector_pointer(pcre_md);
							char *hostname = bdata(uri) + pcre_ovector[2 * 1];
							int hostname_length = (int)(pcre_ovector[2 * 1 + 1] - pcre_ovector[2 * 1]);

							fprintf(file,
									"*.*\taction(type=\"omrelp\" target=\"%.*s\" port=\"6514\""
									" template=\"ChefFormat\" tls=\"on\" "
									" tls.caCert=\"%s\" tls.myCert=\"%s\" tls.myPrivKey=\"%s\""
									" tls.authMode=\"name\" tls.permittedPeer=\"susshi-chef-api\"%s)\n",
									hostname_length, hostname,
									PATH_RSYSLOG_TLS_CA_FILE,
									PATH_RSYSLOG_TLS_CERT_FILE,
									PATH_RSYSLOG_TLS_KEY_FILE,
									i > 0 ? " action.execOnlyWhenPreviousIsSuspended=\"on\"" : "");
							rc = true;
						}
					}
				}
			}
			fclose(file);
		}
		bstrFree(path);

		// CA Certificate File (copy to temp dir so rsyslog can read it regardless of original file permissions)
		if (rc) {
			FILE *ca_src = NULL;

			path = bfromcstr(PATH_RSYSLOG_TLS_CA_FILE);
			debug3("Syslog - Generating %s ...", bdata(path));

			ca_src = fopen(bdata(chef_cfg.chef_ca_file), "r");

			if (ca_src == NULL) {
				error("Syslog - Failed to open CA cert %s: %s", bdata(chef_cfg.chef_ca_file), strerror(errno));
				rc = false;
			} else {
				if ((file = new_file(path))) {
					char ca_buf[4096];
					size_t ca_n;
					while ((ca_n = fread(ca_buf, 1, sizeof(ca_buf), ca_src)) > 0) {
						if (fwrite(ca_buf, 1, ca_n, file) != ca_n) {
							rc = false;
							break;
						}
					}
					fclose(file);
				} else {
					rc = false;
				}
				fclose(ca_src);
			}
			bstrFree(path);
		}

		// TLS Certificate File
		if (rc) {
			path = bfromcstr(PATH_RSYSLOG_TLS_CERT_FILE);
			debug3("Syslog - Generating %s ...", bdata(path));

			if ((file = new_file(path))) {
				written = fwrite(bdata(susshi_cfg.syslog_tls_certificate), 1, blength(susshi_cfg.syslog_tls_certificate), file);
				if (written != (size_t) blength(susshi_cfg.syslog_tls_certificate)) {
					rc = false;
				}
				fclose(file);
			}
			bstrFree(path);
		}

		// TLS Certificate File
		if (rc) {
			path = bfromcstr(PATH_RSYSLOG_TLS_KEY_FILE);
			debug3("Syslog - Generating %s ...", bdata(path));

			if ((file = new_file(path))) {
				written = fwrite(bdata(susshi_cfg.syslog_tls_key), 1, blength(susshi_cfg.syslog_tls_key), file);
				if (written != (size_t) blength(susshi_cfg.syslog_tls_key)) {
					rc = false;
				}
				fclose(file);
				if (chmod(bdata(path), S_IRUSR | S_IWUSR) == -1)
					fatal("chmod on %s failed: %s", bdata(path), strerror(errno));
			}
			bstrFree(path);
		}
	}
	pcre2_match_data_free(pcre_md);
	pcre2_code_free(pcre_re);
	return rc;
}


/*!
 * @brief       Look if rsyslogd_pid was already read from rsyslogd PID file into session
 *              or if there is a PID file written by rsyslogd, we can read from
 *
 * @param       rsyslog_pid     PID of rsyslogd
 *
 * @return      PID if found, otherwise <= 0
 */

pid_t
susshi_lookup_rsyslog_pid(int *rsyslog_pid) {
	FILE *pid_file;

	if (*rsyslog_pid <= 0) {
		if ((pid_file = fopen(PATH_RSYSLOG_PID_FILE, "r"))) {
			if (fscanf(pid_file, "%d", rsyslog_pid) < 1 ||
				*rsyslog_pid <= 0 || *rsyslog_pid > PID_MAX_LIMIT)
				fatal("Invalid or missing PID in %s.", PATH_RSYSLOG_PID_FILE);
			fclose(pid_file);
		}
	}

	if (*rsyslog_pid >= 1) {
		/* Check if process with the given PID is running, otherwise remove all traces */
		if (kill(*rsyslog_pid, 0) != 0) {
			debug1("Found "PATH_RSYSLOG_PID_FILE" but no process running. Removing all traces.");
			remove(PATH_RSYSLOG_PID_FILE);
			*rsyslog_pid = 0;
		}
	}

	return *rsyslog_pid;
}


/*!
 * @brief       Execute rsyslog daemon
 *
 * @return      true on success
 */

static bool
rsyslog_exec(void) {
	bstring pid_file = bfromcstr(PATH_RSYSLOG_PID_FILE);

	/* Create directory for PID file */
	create_subdir(pid_file);
	bstrFree(pid_file);

	/* Exec Rsyslogd */
	debug1("Starting rsyslogd daemon ...");
	execv(PATH_RSYSLOG_DAEMON, (char **) rsyslog_argv);

	/* Should not return, otherwise execv() has failed to start the daemon */
	return false;
}


/*!
 * @brief       Terminate rsyslog daemon
 *
 * @return      true on success
 */

bool
susshi_terminate_rsyslog(void) {
	if (susshi_session.rsyslog_pid > 0) {
		/* We have a running reporting daemon */
		log_system(LOG_LEVEL_INFO, "Send SIGTERM signal to rsyslog daemon with pid %d", susshi_session.rsyslog_pid);

		kill(susshi_session.rsyslog_pid, SIGTERM);
		remove(PATH_RSYSLOG_PID_FILE);

		return true;
	}
	return false;
}


/*!
 * @brief       Restart rsyslog daemon
 *
 * @return      true on success
 */

bool
susshi_restart_rsyslog(void) {
	if (susshi_terminate_rsyslog()) {
		sleep(1);
		return(susshi_fork_rsyslog_daemon());
	}
	return false;
}


/*!
 * @brief       Create new (empty) configuration file filled by rsyslog_configuration()
 *
 * @param       filename    Absolut filename
 *
 * @return      FILE handle
 */

static FILE *
new_file(bstring filename) {
	int fd;

	// O_CREAT|O_TRUNC handles existing files; O_NOFOLLOW refuses symlinks.
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
