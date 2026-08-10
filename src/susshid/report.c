/*!
 *
 * @brief       Reporting methods
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
 * @defgroup    reporting Reporting methods
 * @brief       All kinds of reporting functions
 * @{
 */

#include <susshid/common.h>
#include <susshid/report.h>


/* Prototypes */
static int susshi_report_compression_is_active(void);
static bool susshi_report_client_send_report_record(const char *json_str, int json_str_len, ReportSessionState state);
static char *susshi_idle_string(void);

SusshiReport susshi_report;

typedef enum {
	R_BOOL,
	R_BSTRING,
	R_CSTRING,
	R_INT,
	R_PERIOD,
	R_SSH_STRING,
	R_TIME,
	R_UINT32,
	R_UINT64,
	R_NONE
} report_type;

static struct {
	const char *key;
	report_type type;
	void **source;
	bool on_update;
	bool on_fail;
	uint32_t chef_version_min;
	long long last;
} report_keys_map[] = {
		{"susshi_user",    R_BSTRING, (void *) &susshi_session.susshi_user,                  false, true,  0,      -1},
		{"client_auth",    R_BSTRING, (void *) &susshi_session.client_authmethod,            false, true,  0,      -1},
		{"client_comp",    R_BOOL,    (void *) &susshi_report.client_compression,            false, true,  0,      -1},
		{"client_ip",      R_BSTRING, (void *) &susshi_session.client_ip,                    false, true,  0,      -1},
		{"client_port",    R_INT,     (void *) &susshi_session.client_port,                  false, true,  0,      -1},
		{"client_ssh",     R_BSTRING, (void *) &susshi_session.client_ssh_identification,    false, true,  0,      -1},
		{"target_auth",    R_BSTRING, (void *) &susshi_session.target_authmethod,            false, true,  0,      -1},
		{"target_comp",    R_BOOL,    (void *) &susshi_report.target_compression,            false, true,  0,      -1},
		{"target_host",    R_BSTRING, (void *) &susshi_session.target_host,                  false, true,  0,      -1},
		{"target_ip",      R_BSTRING, (void *) &susshi_session.target_ip,                    false, true,  0,      -1},
		{"target_port",    R_INT,     (void *) &susshi_session.target_port,                  false, true,  0,      -1},
		{"target_ssh",     R_BSTRING, (void *) &susshi_session.target_ssh_identification,    false, true,  0,      -1},
		{"target_user",    R_BSTRING, (void *) &susshi_session.target_user,                  false, true,  0,      -1},
		{"login_string",   R_BSTRING, (void *) &susshi_session.login_string,                 false, true,  0,      -1},
		{"session_start",  R_TIME,    (void *) &susshi_report.session_start_time,            false, true,  0,      -1},
		{"message",        R_BSTRING, (void *) &susshi_report.message,                       false, true,  0,      0},
		{"session_c_in",   R_UINT64,  (void *) &susshi_report.client_in_bytes,               true,  false, 0,      0},
		{"session_c_out",  R_UINT64,  (void *) &susshi_report.client_out_bytes,              true,  false, 0,      0},
		{"session_t_in",   R_UINT64,  (void *) &susshi_report.target_in_bytes,               true,  false, 0,      0},
		{"session_t_out",  R_UINT64,  (void *) &susshi_report.target_out_bytes,              true,  false, 0,      0},
		{"ch_accept",      R_INT,     (void *) &susshi_report.channels_opened,               true,  false, 0,      0},
		{"ch_reject",      R_INT,     (void *) &susshi_report.channels_rejected,             true,  false, 0,      0},
		{"ch_fail",        R_INT,     (void *) &susshi_report.channels_failed,               true,  false, 0,      0},
		{"ch_close",       R_INT,     (void *) &susshi_report.channels_closed,               true,  false, 0,      0},
		{"lf_accept",      R_INT,     (void *) &susshi_report.local_forwards_accepted,       true,  false, 0,      0},
		{"lf_reject",      R_INT,     (void *) &susshi_report.local_forwards_rejected,       true,  false, 0,      0},
		{"rf_accept",      R_INT,     (void *) &susshi_report.remote_forwards_accepted,      true,  false, 0,      0},
		{"rf_reject",      R_INT,     (void *) &susshi_report.remote_forwards_rejected,      true,  false, 0,      0},
		{"rf_cancel",      R_INT,     (void *) &susshi_report.remote_forwards_canceled,      true,  false, 0,      0},
		{"ti_reject",      R_INT,     (void *) &susshi_report.tunnel_interfaces_rejected,    true,  false, 0,      0},
		{"int_accept",     R_INT,     (void *) &susshi_report.interactive_sessions_accepted, true,  false, 0,      0},
		{"int_reject",     R_INT,     (void *) &susshi_report.interactive_sessions_rejected, true,  false, 0,      0},
		{"cmd_accept",     R_INT,     (void *) &susshi_report.command_execs_accepted,        true,  false, 0,      0},
		{"cmd_reject",     R_INT,     (void *) &susshi_report.command_execs_rejected,        true,  false, 0,      0},
		{"usub_accept",    R_INT,     (void *) &susshi_report.unkown_subsystems_accepted,    true,  false, 0,      0},
		{"x11_accept",     R_INT,     (void *) &susshi_report.x11_sessions_accepted,         true,  false, 0,      0},
		{"x11_reject",     R_INT,     (void *) &susshi_report.x11_sessions_rejected,         true,  false, 0,      0},
		{"agent_accept",   R_INT,     (void *) &susshi_report.agent_forwards_accepted,       true,  false, 0,      0},
		{"agent_reject",   R_INT,     (void *) &susshi_report.agent_forwards_rejected,       true,  false, 0,      0},
		{"sftp_sessions",  R_INT,     (void *) &susshi_report.sftp_sessions,                 true,  false, 0,      0},
		{"sftp_files_rd",  R_INT,     (void *) &susshi_report.sftp_files_read,               true,  false, 0,      0},
		{"sftp_files_wr",  R_INT,     (void *) &susshi_report.sftp_files_written,            true,  false, 0,      0},
		{"sftp_bytes_rd",  R_UINT64,  (void *) &susshi_report.sftp_bytes_read,               true,  false, 0,      0},
		{"sftp_bytes_wr",  R_UINT64,  (void *) &susshi_report.sftp_bytes_written,            true,  false, 0,      0},
		{"scp_sessions",   R_INT,     (void *) &susshi_report.scp_sessions,                  true,  false, 0,      0},
		{"scp_files_rd",   R_INT,     (void *) &susshi_report.scp_files_read,                true,  false, 0,      0},
		{"scp_files_wr",   R_INT,     (void *) &susshi_report.scp_files_written,             true,  false, 0,      0},
		{"scp_bytes_rd",   R_UINT64,  (void *) &susshi_report.scp_bytes_read,                true,  false, 200500, 0},
		{"scp_bytes_wr",   R_UINT64,  (void *) &susshi_report.scp_bytes_written,             true,  false, 0,      0},
		{"user_auth_fp",   R_BSTRING, (void *) &susshi_session.susshi_userfp,                false, true,  180705, -1},
		{"connect_used",   R_BOOL,    (void *) &susshi_report.client_used_connect,           false, true,  181000, -1},
		{"proxy_realm",    R_BSTRING, (void *) &susshi_session.target_proxy_realm,           false, true,  181000, -1},
		{"rule_id",        R_UINT64,  (void *) &susshi_session.rule_id,                      false, true,  190500, -1},
		{"profile_name",   R_CSTRING, (void *) &susshi_session.profile_name,                 false, true,  190500, -1},
		{"operation_mode", R_INT,     (void *) &susshi_session.operation_mode,               false, true,  200300, -1},
		{"ca_set_id",      R_INT,     (void *) &susshi_session.client_auth_set_id,           false, false, 230300, -1},
		{NULL,             R_NONE,    NULL,                                           false, false, 0,      -1}
};


/*!
 * @brief       Initialize Report Structures
 */

void
init_susshi_report(void)
{

	memset(&susshi_report, 0, sizeof(SusshiReport));

	// Start time of this process
	susshi_report.session_start_time =
	susshi_report.last_io_time = time(NULL);

}


#define MAX_IDLE_STRING 20

/*!
 * @brief       Return IDLE field for susshi lastlog
 *
 * @return      Pointer to string with idle information, must never be freed by caller
 */

static char *
susshi_idle_string(void)
{
	u_int32_t idle;
	static char idlestr[MAX_IDLE_STRING];

	// hh:mm
	// ##days

	idle = (u_int32_t) susshi_idle_time();

	if (idle < (100 * 3600)) {
		snprintf(idlestr, MAX_IDLE_STRING, "%2d:%02d ", idle/3600, (idle%3600)/60);
	} else {
		snprintf(idlestr, MAX_IDLE_STRING, "%2ddays", idle/(24*3600));
	}
	return idlestr;
}

#undef MAX_IDLE_STRING


/*!
 * @brief       Return the state in way of a bitmask that can be used for susshi-who / susshi-last or proctitle
 *
 * Features are:
 * ```
 *      I - Interactive Session
 *      E - Command Execution
 *      A - Agent Forwarding
 *      C - SCP
 *      F - SFTP
 *      L - Local port forwarding
 *      R - Remote port forwarding
 *      X - X11 forwarding
 *      Z - Compression
 * ```
 *
 * @return      pointer to char string with flags. Not to be freed by caller
 */

const char *
susshi_report_features(void) {
	static bstring features = NULL;

	if (features)
		bstrFree(features);

	features = bformat("%c%c%c%c%c%c%c%c%c",
					   (susshi_report.interactive_sessions_accepted > 0) ? 'I' : '-',
					   (susshi_report.command_execs_accepted > 0) ? 'E' : '-',
					   (susshi_report.agent_forwards_accepted > 0) ? 'A' : '-',
					   (susshi_report.scp_sessions > 0) ? 'C' : '-',
					   (susshi_report.sftp_sessions > 0) ? 'F' : '-',
					   (susshi_report.local_forwards_accepted > 0) ? 'L' : '-',
					   (susshi_report.remote_forwards_accepted > 0) ? 'R' : '-',
					   (susshi_report.x11_sessions_accepted > 0) ? 'X' : '-',
					   susshi_report_compression_is_active() ? 'Z' : '-'
	);

	return bdata(features);
}


/*!
 * @brief       Put susshi-who record on who-queue
 *
 * Format:
 * ```
 * User   process-id   Month Day Hour:Min   idle   session-id   features   client_ip:client_port -> target_user@target_host:target_port (target_ip)
 * ```
 *
 * For features see susshi_report_features(void);
 *
 * @see         susshi_report_features
 */

void
susshi_report_who(void)
{
	mqd_t message_queue;

	bstring repstr, clientsock = NULL;
	char *timestr;

	timestr = ctime((const time_t *) &susshi_report.session_start_time);
	timestr[19]='\0';

	clientsock = bformat("%s:%-5d", (susshi_session.client_ip != NULL) ?
									bdata(susshi_session.client_ip) : "", susshi_session.client_port);

	repstr = bformat("%.4s   %-20s   %-9d   %s   %s  %-30s   %s   %-21s -> %s@%s\n",
					 (chef_cfg.susshid_id != NULL) ? bdata(chef_cfg.susshid_id) : "----",
					 (susshi_session.susshi_user != NULL) ? bdata(susshi_session.susshi_user) : "",
					  getpid(),
					 &timestr[4],
					  susshi_idle_string(),
					  bdata(susshi_session.susshi_uniqid),
					  susshi_report_features(),
					  bdata(clientsock),
					 (susshi_session.target_user != NULL) ? bdata(susshi_session.target_user) : "",
					 (susshi_session.target_identifier != NULL) ? bdata(susshi_session.target_identifier) : ""
	);

	message_queue = mq_open(WHO_QUEUE_NAME, O_WRONLY|O_CREAT|O_NONBLOCK, S_IRUSR|S_IWUSR, NULL);

	if (message_queue != -1) {
		/* Put message on queue */
		debug4("Putting who report on queue: %s", bdata(repstr));

		mq_send(message_queue, bdata(repstr), blength(repstr), 0);
		mq_close(message_queue);
	} else {
		log_system(LOG_LEVEL_ERROR, "Could not open who message queue: %s", strerror(errno));
	}

	bstrFree(repstr);
	bstrFree(clientsock);
}


/*!
 * @brief       Write susshi-last file or put record on last message queue
 *
 * Format:
 * ```
 * User   process-id   Weekday Month Day Hour:Min - Month Day Hour:Min (duration)   session-id   features   client_ip:client_port -> target_user@target_host:target_port (target_ip)
 * ```
 * For features see susshi_report_features(void);
 *
 * @param       finished        Set to true if session is finished
 *
 * @see         susshi_report_features
 */

void
susshi_report_last_log(bool finished)
{
	bstring repstr = NULL, clientsock = NULL;
	char stimestr[26], etimestr[26];
	time_t etimet;
	time_t duration;
	int dhours, dminutes;


	ctime_r((const time_t *) &susshi_report.session_start_time, stimestr);
	stimestr[19]='\0';

	etimet = time(NULL);

	ctime_r((const time_t *) &etimet, etimestr);
	etimestr[19]='\0';

	duration = (time(NULL) - susshi_report.session_start_time)/60;
	dhours = (int) duration / 60;
	dminutes = (int) duration % 60;

	clientsock = bformat("%s:%-5d", (susshi_session.client_ip != NULL) ? bdata(susshi_session.client_ip) : "", susshi_session.client_port);

	repstr = bformat("%.4s   %-20s   %-9d   %s - %s (%02d:%02d)   %-30s   %s   %-21s -> %s@%s \n",
					 (chef_cfg.susshid_id != NULL) ? bdata(chef_cfg.susshid_id) : "----",
					 (susshi_session.susshi_user != NULL) ? bdata(susshi_session.susshi_user) : "",
					  getpid(),
					  stimestr,
					  finished ? &etimestr[4] : "still logged in",
					  dhours, dminutes,
					  bdata(susshi_session.susshi_uniqid),
					  susshi_report_features(),
					  bdata(clientsock),
					 (susshi_session.target_user != NULL) ? bdata(susshi_session.target_user) : "",
					 (susshi_session.target_identifier != NULL) ? bdata(susshi_session.target_identifier) : ""
	);

	if (finished) {

		int fdi;
		FILE *fd;

		/* Write to last-log file */

		debug3("Writing last log to log file %s", bdata(susshi_cfg.logfile_last));
		fdi = open(bdata(susshi_cfg.logfile_last), O_WRONLY | O_CREAT | O_APPEND, SUSSHI_LOGFILE_MODE);

		if ((fdi < 0) && (errno == ENOENT)) {
			create_subdir(susshi_cfg.logfile_last);
			fdi = open(bdata(susshi_cfg.logfile_last), O_WRONLY | O_CREAT | O_APPEND, SUSSHI_LOGFILE_MODE);
		}

		if (fdi >= 0) {
			fd = fdopen(fdi, "a");
			setvbuf(fd, NULL, _IOFBF, 0);

			if (fd == NULL)
				return;

			fwrite(bdata(repstr), blength(repstr), 1, fd);
			fclose(fd);
		}

	} else {

		/* Put mesage on last-log message queue */

		mqd_t message_queue;

		message_queue = mq_open(LAST_QUEUE_NAME, O_WRONLY|O_CREAT|O_NONBLOCK, S_IRUSR|S_IWUSR, NULL);

		if (message_queue != -1) {
			/* Put message on queue */
			debug4("Putting last report on queue: %s", bdata(repstr));

			mq_send(message_queue, bdata(repstr), blength(repstr), 0);
			mq_close(message_queue);
		} else {
			log_system(LOG_LEVEL_ERROR, "Could not open last message queue: %s", strerror(errno));
		}
	}

	if (clientsock != NULL)
		bstrFree(clientsock);

	if (repstr != NULL)
		bstrFree(repstr);

}


/*!
 * @brief       Check if compression is active
 *
 * @return      1 if compression is on, otherwise 0
 */

static int
susshi_report_compression_is_active(void) {
	return (susshi_session.client_session->current_crypto->do_compress_in |
			susshi_session.client_session->current_crypto->do_compress_out |
			susshi_session.target_session->current_crypto->do_compress_in |
			susshi_session.target_session->current_crypto->do_compress_out);
}


/*!
 * @brief       Send report from session fork to reporting fork
 *
 * @param       state   The state, the report is for (REPORT_FIRST, REPORT_PERIODIC, REPORT_LAST)
 *
 */

void
susshi_report_client_send_report(ReportSessionState state) {

	json_t *root;
	json_t *report;
	const char* json_str;
	int json_str_len;

	/* Prevent duplicate LAST report messages */
	if ((state == REPORT_LAST) && (susshi_session.report_state == REPORT_LAST))
		return;
	susshi_session.report_state = state;

	if (!flag_no_daemon) {
		report = json_object();

		switch(state) {
			case REPORT_FIRST:
				json_object_set_new(report, "session_state", json_string("new"));
				break;
			case REPORT_PERIODIC:
				json_object_set_new(report, "session_state", json_string("active"));
				break;
			case REPORT_LAST:
				json_object_set_new(report, "session_state", json_string("finished"));
				break;
			case REPORT_FATAL:
				susshi_report.message = bfromcstr("suSSHi reported a fatal condition.");
			case REPORT_FAILED:
				if (susshi_session.target_proxy_error == 0) {
					json_object_set_new(report, "session_state", susshi_session.client_authenticated ? json_string("failed") : json_string("denied"));
				} else {
					switch(susshi_session.target_proxy_error) {
						case SUSSHI_PROXY_ERROR_CODE_TARGET_RESOLV_FAILED:
							return;
						case SUSSHI_PROXY_ERROR_CODE_TARGET_CONNECT_FAILED:
						default:
							json_object_set_new(report, "session_state", json_string("failed"));
					}
				}
				break;
			case REPORT_NONE:
			default:
				return;
		}

		/* Update compression status */

		if ((susshi_session.client_session) && (susshi_session.client_session->current_crypto)){
			susshi_report.client_compression = (bool) susshi_session.client_session->current_crypto->do_compress_in;
		}
		if ((susshi_session.target_session) && (susshi_session.target_session->current_crypto)){
			susshi_report.target_compression = (bool) susshi_session.target_session->current_crypto->do_compress_out;
		}

		json_object_set_new(report, "session_time", json_integer(time(NULL) - susshi_report.session_start_time));

		if ((susshi_report.message == NULL) && (susshi_session.gateway_closed_reason != NULL)) {
			susshi_report.message = bstrcpy(susshi_session.gateway_closed_reason);
		}

		/* Serialize data */
		for (int i = 0; report_keys_map[i].type != R_NONE; i++) {

			if (chef_cfg.chef_version_uint32 < report_keys_map[i].chef_version_min)
				continue;

			/* On periodic updates, we do not send values marked as "no update" */
			if ((state == REPORT_PERIODIC) && (!report_keys_map[i].on_update))
				continue;

			/* On FAIL report, we do only send values marked as "on fail" */
			if ((state == REPORT_FAILED) && (!report_keys_map[i].on_fail))
				continue;

			switch (report_keys_map[i].type) {
				case R_BOOL: {
					if ((state == REPORT_FIRST) || (state == REPORT_PERIODIC)) {
						if (report_keys_map[i].on_update) {
							if (*((bool *) report_keys_map[i].source) == (bool) report_keys_map[i].last)
								break;
							else
								report_keys_map[i].last = (long long) *((bool *) report_keys_map[i].source);
						}
					}

					json_object_set_new(report, report_keys_map[i].key,
										json_boolean(*((bool *) report_keys_map[i].source)));
				} break;

				case R_BSTRING: {
					if (*((bstring *) report_keys_map[i].source))
						json_object_set_new(report, report_keys_map[i].key,
											json_string(bdata(*((bstring *) report_keys_map[i].source))));
					else
						json_object_set_new(report, report_keys_map[i].key,
											json_string(""));
				} break;

				case R_CSTRING: {
					if (*((const char **) report_keys_map[i].source))
						json_object_set_new(report, report_keys_map[i].key,
											json_string(*((const char **) report_keys_map[i].source)));
					else
						json_object_set_new(report, report_keys_map[i].key,
											json_string(""));
				} break;

				case R_INT: {
					if ((state == REPORT_FIRST) || (state == REPORT_PERIODIC)) {
						if (report_keys_map[i].on_update) {
							if (*((int *) report_keys_map[i].source) == (int) report_keys_map[i].last)
								break;
							else
								report_keys_map[i].last = (long long) *((int *) report_keys_map[i].source);
						}
					}

					json_object_set_new(report, report_keys_map[i].key,
										json_integer(*((int *) report_keys_map[i].source)));
				} break;

				case R_PERIOD: {
					if ((state == REPORT_FIRST) || (state == REPORT_PERIODIC)) {
						if (report_keys_map[i].on_update) {
							if (*((time_t *) report_keys_map[i].source) == (time_t) report_keys_map[i].last)
								break;
							else
								report_keys_map[i].last = (long long) *((time_t *) report_keys_map[i].source);
						}
					}

					json_object_set_new(report, report_keys_map[i].key,
										json_integer(time(NULL) - *((time_t *) report_keys_map[i].source)));
				} break;

				case R_SSH_STRING: {
					if (*((ssh_string *) report_keys_map[i].source))
						json_object_set_new(report, report_keys_map[i].key,
											json_string(ssh_string_get_char(*(ssh_string *) report_keys_map[i].source)));
					else
						json_object_set_new(report, report_keys_map[i].key,
											json_string(""));
				} break;

				case R_TIME: {
					if ((state == REPORT_FIRST) || (state == REPORT_PERIODIC)) {
						if (report_keys_map[i].on_update) {
							if (*((time_t *) report_keys_map[i].source) == (time_t) report_keys_map[i].last)
								break;
							else
								report_keys_map[i].last = (long long) *((time_t *) report_keys_map[i].source);
						}
					}

					json_object_set_new(report, report_keys_map[i].key,
										json_integer(*((time_t *) report_keys_map[i].source)));
				} break;

				case R_UINT32: {
					if ((state == REPORT_FIRST) || (state == REPORT_PERIODIC)) {
						if (report_keys_map[i].on_update) {
							if (*((u_int32_t *) report_keys_map[i].source) == (u_int32_t) report_keys_map[i].last)
								break;
							else
								report_keys_map[i].last = (long long) *((u_int32_t *) report_keys_map[i].source);
						}
					}

					json_object_set_new(report, report_keys_map[i].key,
										json_integer(*((u_int32_t *) report_keys_map[i].source)));

				} break;

				case R_UINT64: {
					if ((state == REPORT_FIRST) || (state == REPORT_PERIODIC)) {
						if (report_keys_map[i].on_update) {
							if (*((u_int64_t *) report_keys_map[i].source) == (u_int64_t) report_keys_map[i].last)
								break;
							else
								report_keys_map[i].last = (long long) *((u_int64_t *) report_keys_map[i].source);
						}
					}

					json_object_set_new(report, report_keys_map[i].key,
										json_integer(*((u_int64_t *) report_keys_map[i].source)));

				}	break;

				default:
					fatal("Error in report_io_map");
			}
		}

		/* Pack report into <susshi_uniqid>: */
		root = json_object();
		json_object_set_new(root, bdata(susshi_session.susshi_uniqid), report);

		json_str = json_dumps(root, JSON_COMPACT | JSON_ENSURE_ASCII);
		json_str_len = strlen(json_str);

		if (json_str) {
			susshi_report_client_send_report_record(json_str, json_str_len, state);
			xfree((void *) json_str);
		}

		json_delete(root);
	}
}


/*!
 * @brief       Send single record to message queue
 *
 * @param       json_str        JSON message string
 * @param       json_str_len    Length of JSON message
 * @param       state           Current state of susshi
 *
 * @return      true on success
 */

static bool
susshi_report_client_send_report_record(const char *json_str, int json_str_len, ReportSessionState state) {
	bool rc = false;

	mqd_t message_queue;

	message_queue = mq_open(REPORT_QUEUE_NAME, O_WRONLY|O_CREAT|O_NONBLOCK, S_IRUSR|S_IWUSR, NULL);

	if (message_queue != -1) {

		/* Put message on queue */
		debug4("Sending report message of %d bytes: %.50s ...", json_str_len, json_str);

		if (mq_send(message_queue, json_str, json_str_len, 0) == 0)
			rc = true;

		mq_close(message_queue);
	} else {
		log_system(LOG_LEVEL_ERROR, "Could not open reporting message queue: %s", strerror(errno));
	}

	return rc;
}

/*! @} */
