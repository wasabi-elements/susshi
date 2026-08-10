/*!
 *
 * @brief       Logging methods
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
 * @defgroup    logging Logging methods
 * @brief       All kinds of logging functions.
 * @{
 */


#include "susshid/common.h"

// Global log_level for process
LogLevel log_level = LOG_LEVEL_INFO;
bool log_on_stderr = false;

const char SideChar[] = { 'C', 'T', 'G', 'P' };
const char *SideString[] = { "Client", "Target", "Gateway", "Proxy", "Client and Server" };
const char *LogLevelString[] = { "emerg ",
								 "alert ",
								 "crit  ",
								 "error ",
								 "warn  ",
								 "notice",
								 "info  ",
								 "debug1",
								 "debug2",
								 "debug3",
								 "debug4",
								 "debug5" };

#define MSGBUFSIZE 2048

typedef struct _code {
	const char    *c_name;
	const int     c_val;
} syslog_facility_names;

syslog_facility_names syslog_facilitynames[] = {
		{ "auth",       LOG_AUTH },
		{ "daemon",     LOG_DAEMON },
		{ "security",   LOG_AUTH },
		{ "user",       LOG_USER },
		{ "local0",     LOG_LOCAL0 },
		{ "local1",     LOG_LOCAL1 },
		{ "local2",     LOG_LOCAL2 },
		{ "local3",     LOG_LOCAL3 },
		{ "local4",     LOG_LOCAL4 },
		{ "local5",     LOG_LOCAL5 },
		{ "local6",     LOG_LOCAL6 },
		{ "local7",     LOG_LOCAL7 },
		{ 0,            -1 }
};

/* textual representation of log-facilities/levels */

static struct {
	const char *name;
	SyslogFacility val;
} log_facilities[] = {
		{ "DAEMON",	SYSLOG_FACILITY_DAEMON },
		{ "USER",	SYSLOG_FACILITY_USER },
		{ "AUTH",	SYSLOG_FACILITY_AUTH },
		{ "LOCAL0",	SYSLOG_FACILITY_LOCAL0 },
		{ "LOCAL1",	SYSLOG_FACILITY_LOCAL1 },
		{ "LOCAL2",	SYSLOG_FACILITY_LOCAL2 },
		{ "LOCAL3",	SYSLOG_FACILITY_LOCAL3 },
		{ "LOCAL4",	SYSLOG_FACILITY_LOCAL4 },
		{ "LOCAL5",	SYSLOG_FACILITY_LOCAL5 },
		{ "LOCAL6",	SYSLOG_FACILITY_LOCAL6 },
		{ "LOCAL7",	SYSLOG_FACILITY_LOCAL7 },
		{ NULL,		SYSLOG_FACILITY_NOT_SET }
};


/*!
 * @brief       Look up the name of a syslog facility by its enum value.
 *
 * Iterates over the global @c log_facilities table and returns the
 * string name corresponding to the given @p facility value.
 *
 * @param       facility    The SyslogFacility enum value to look up
 *
 * @return      Pointer to the facility name string, or NULL if not found
 */

const char *
log_facility_name(SyslogFacility facility)
{
	u_int i;

	for (i = 0;  log_facilities[i].name; i++)
		if (log_facilities[i].val == facility)
			return log_facilities[i].name;
	return NULL;
}


/*!
 * @brief       Convert a syslog facility name string to its integer value.
 *
 * Performs a case-insensitive search through the system @c syslog_facilitynames
 * table to find the integer constant corresponding to @p name.
 *
 * @param       name    The facility name string to look up (e.g. "daemon", "local0")
 *
 * @return      The integer value of the matching facility, or -1 if not found
 */

int
syslog_facility_int(const char *name)
{
	int c;
	for (c = 0; syslog_facilitynames[c].c_name != NULL; c++) {
		if (strcasecmp(name, syslog_facilitynames[c].c_name) == 0) {
			return(syslog_facilitynames[c].c_val);
		}
	}
	return(-1);
}


/*!
 * @brief       Initialize and return a unique session identifier for the current susshi session.
 *
 * Generates a unique ID string based on the current UTC time and the process ID,
 * formatted as: @c YYYYMMDD-HHMMSS-__susshid_id__-__pid__. The result is stored in
 * @c susshi_session.susshi_uniqid and a pointer to its raw C string is returned.
 *
 * @note        The returned pointer is owned by @c susshi_session.susshi_uniqid and must
 *              not be freed by the caller.
 *
 * @return      Pointer to the newly created unique session ID string.
 */

char *
init_susshi_identifier(void)
{
	time_t now;
	struct tm tm_now;

	now = time(NULL);
	gmtime_r(&now, &tm_now);

	susshi_session.susshi_uniqid = bformat("%d%02d%02d-%02d%02d%02d-%s-%05d",
									tm_now.tm_year + 1900, tm_now.tm_mon + 1, tm_now.tm_mday,
									tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec,
									bdata(chef_cfg.susshid_id), getpid());
	return(bdata(susshi_session.susshi_uniqid));
}


/*!
 * @brief       Expand a log filename format string using session and time-based tokens.
 *
 * Substitutes percent-encoded tokens in @p logformat with runtime values to
 * produce a concrete log filename, storing the result in @p *filename. If
 * @p logformat is NULL or empty, @p *filename is freed and set to NULL.
 *
 * The following format tokens are supported:
 * | Token | Expands to                                  |
 * |-------|---------------------------------------------|
 * | @c %d | Day of month (two digits)                   |
 * | @c %m | Month (two digits)                          |
 * | @c %y | Four-digit year                             |
 * | @c %f | File type string (@p filetype)              |
 * | @c %t | Target host (FQDN or IP) with optional realm|
 * | @c %u | Authenticated susshi username               |
 * | @c %s | Unique session ID, optionally suffixed with @p cid |
 *
 * @param[out]  filename    Pointer to a bstring that will receive the expanded filename.
 *                          Any pre-existing value will be freed before assignment.
 * @param[in]   logformat   The format string containing percent-encoded tokens.
 * @param[in]   filetype    A bstring describing the log file type, substituted for @c %f.
 * @param[in]   cid         Connection ID appended to the session unique ID for @c %s.
 *                          Pass -1 to omit the connection ID suffix.
 */

void
log_filename_expand(bstring *filename, bstring logformat, bstring filetype, long int cid)
{
	time_t now;
	struct tm tm_now;
	char day[3], month[3], year[5];
	char *pe_str;
	bstring target = NULL;
	bstring uniqid = NULL;

	if(logformat == NULL || blength(logformat) == 0) {
		if (*filename != NULL)
			bstrFree(*filename);
		*filename = NULL;
		return;
	}

	now = time(NULL);
	localtime_r(&now, &tm_now);

	snprintf(day, 3, "%02d", tm_now.tm_mday);
	snprintf(month, 3, "%02d", tm_now.tm_mon + 1);
	snprintf(year, 5, "%04d", tm_now.tm_year + 1900);

	if (cid >= 0)
		uniqid = bformat("%s-%05ld", susshi_session.susshi_uniqid != NULL ? bdata(susshi_session.susshi_uniqid) : "not_set", cid);
	else if (cid == -1)
		uniqid = susshi_session.susshi_uniqid != NULL ? bstrcpy(susshi_session.susshi_uniqid) : bfromcstr("not_set");
	else if (cid == -2)
		uniqid = susshi_session.susshi_uniqid != NULL ? bformat("%s-*", bdata(susshi_session.susshi_uniqid)) : bfromcstr("not_set");

	target = susshi_session.target_connected_by_fqdn ? bstrcpy(susshi_session.target_host_resolved) : bstrcpy(susshi_session.target_ip);

	if (susshi_session.target_proxy_realm)
		bformata(target, "@%s", bdata(susshi_session.target_proxy_realm));

	*filename = bfromcstr(pe_str = percent_expand(bdata(logformat), (cid == -2),
										 "d", day,
										 "f", bdata(filetype),
										 "m", month,
										 "y", year,
										 "t", target != NULL ? bdata(target) : "not_set",
										 "u", susshi_session.susshi_user != NULL ? bdata(susshi_session.susshi_user) : "not_set",
										 "s", bdata(uniqid),
										 (char *) NULL));

	xfree(pe_str);
	bstrFree(uniqid);
	bstrFree(target);
}


/*!
 * @brief       Determine when it's time to rotate logfiles.
 *
 * Calculates the absolute time of the next log rotation period and,
 * optionally, the number of seconds until that point. Log rotation is
 * scheduled to occur at midnight, with a special case for times before
 * 04:00 to avoid daylight saving time edge cases — in that window the
 * next period is set to 05:00 instead of the following midnight.
 *
 * @param[out]  delta   Pointer to a @c time_t in which the number of seconds
 *                      until the next rotation will be stored. May be NULL if
 *                      the delta is not needed
 *
 * @return              Absolute @c time_t of the next scheduled log rotation
 */

time_t
determine_next_log_period(time_t *delta)
{
	time_t now;
	struct tm tm_now;
	time_t period;

	now = time(NULL);
	localtime_r(&now, &tm_now);
	if (tm_now.tm_hour < 4) {
		// Cheat to overcome daylight saving time issues
		// So we jump to somewhen later than 5.00 a.m. Then a new period will get generated.
		period = 5 * 3600;
	} else {
		period = (23 - tm_now.tm_hour) * 3600 + (59 - tm_now.tm_min) * 60 + (59 - tm_now.tm_sec);
	}

	if (delta != NULL)
		*delta = period;

	period += now;
	return(period);
}


/*!
 * @brief       Open or reuse a log file described by a SusshiLog structure.
 *
 * Expands the format string in @p log->logformat into a concrete filename,
 * then either returns the already-open file handle (if the expanded filename
 * is unchanged) or closes the old handle and opens a new one. If the target
 * directory does not yet exist it is created automatically. The file is opened
 * in append mode with full buffering (@c _IOFBF).
 *
 * On success, @p log->fd, @p log->filename, @p log->filesize, and @p log->tv
 * are all updated. On failure, @p log->fd is set to NULL and an error is
 * logged.
 *
 * @param[in,out] log   Pointer to the SusshiLog structure describing the log
 *                      file to open. Must not be NULL
 *
 * @return      The open @c FILE* on success, or NULL on failure
 */

FILE *
susshi_open_logfile(SusshiLog *log)
{
	int fd;
	bstring filename = NULL;
	struct stat stat;

	// Expand filename pattern into real filename
	log_filename_expand(&filename, log->logformat, log->filetype, log->ucid);

	// Udpate next period
	log->next_period = determine_next_log_period(NULL);

	// Compare if we still have the same result after expansion
	if ((log->fd != NULL) && (log->filename != NULL) && (bstrcmp(log->filename, filename)) == 0) {
		// Return already existing filehandle
		return log->fd;
	}

	// Copy new filename into session data
	if (log->filename != NULL)
		bstrFree(log->filename);
	log->filename = bstrcpy(filename);

	// Close old filehandle if it exists
	if (log->fd != NULL) {
		if (log->enc_state)
			log_session_enc_finalize(log);
		fflush(log->fd);
		fclose(log->fd);
	}

	// Open log file
	fd = open(bdata(filename), O_WRONLY|O_CREAT|O_APPEND, SUSSHI_LOGFILE_MODE);

	if ((fd < 0) && (errno == ENOENT)) {
		create_subdir(filename);
		fd = open(bdata(filename), O_WRONLY|O_CREAT|O_APPEND, SUSSHI_LOGFILE_MODE);
	}

	if (fd < 0) {
		int e = errno;
		log->fd = NULL;
		error("Could not open logfile %s as user %s: %s", bdata(log->filename), username(), strerror(e));
		bstrFree(log->filename);
		return NULL;
	}

	// Get Filesize and store it in our struct
	if (fstat(fd, &stat) == 0)
		log->filesize = stat.st_size;
	else
		log->filesize = 0;

	log->fd = fdopen(fd, "a");
	setvbuf(log->fd, NULL, _IOFBF, 0);

	if (log->enc_requested && susshi_cfg.num_session_log_encryption_keys > 0 && susshi_cfg.feature_audit_log_encryption == 1)
		log_session_enc_open(log);

	// Record time, when we opened the file
	gettimeofday(&log->tv, NULL);

	debug2("Opened logfile %s", bdata(log->filename));
	return log->fd;
}


/*!
 * @brief       Close one or all susshi log files.
 *
 * When @p log is NULL, closes both the system log (@c log_system) and the
 * session log (@c log_session) by recursively calling itself. When @p log
 * points to a specific @c SusshiLog, flushes and closes its file handle,
 * frees the filename bstring, and — if a pcap dump is attached — flushes
 * the pcap data and frees the associated memory.
 *
 * After a successful close, @p log->fd and @p log->filename are set to NULL.
 *
 * @note        Channel log files are not currently closed by the NULL code path;
 *              see the TODO comment in the implementation.
 *
 * @param[in,out] log   Pointer to the SusshiLog to close, or NULL to close
 *                      all global session log files.
 */

void
susshi_close_logfile(SusshiLog *log)
{
	if (log == NULL) {
		// Close all files
		susshi_close_logfile(&susshi_session.log_system);
		susshi_close_logfile(&susshi_session.log_session);
		// TODO: Really needed / used?
		// If yes: we have to close the channel log files as well
	} else {
		if (log->pcap != NULL) {
			pcap_dump_flush((pcap_dumper_t *) log->fd);
			xfree(log->pcap);
		}
		if (log->fd != NULL) {
			if (log->enc_state)
				log_session_enc_finalize(log);
			fflush(log->fd);
			fclose(log->fd);
			log->fd = NULL;
		}
		if (log->filename != NULL) {
			debug2("Closing logfile %s.", bdata(log->filename));
			bstrFree(log->filename);
			log->filename = NULL;
		}
	}
}


/*!
 * @brief       Initialize the susshi logging subsystem for the current session.
 *
 * Performs the following steps in order:
 * -# Resolves and stores the gateway hostname (from config or @c gethostname).
 * -# Generates the unique session identifier via @c init_susshi_identifier().
 * -# Initialises the system log and session log @c SusshiLog structures with
 *    their respective format strings, file types, and rotation periods.
 * -# Opens the system log file immediately; terminates the process with
 *    @c fatal() if it cannot be opened.
 * -# Sets the base logging mask to @c SUSSHI_SYSTEMLOG.
 * -# Enables live-view flushing when debug level 3 or higher is active.
 *
 * @note        This function must be called once during session startup, before any
 *              log output is attempted. It calls @c fatal() and does not return if
 *              the system log file cannot be opened.
 */

void
init_susshi_log(void)
{
	char host[256];

	// Get and store hostname susshid runs
	if (susshi_cfg.syslog_gateway_name) {
		susshi_session.hostname = bstrcpy(susshi_cfg.syslog_gateway_name);
	} else {
		if (gethostname(host, 256) == 0) {
			susshi_session.hostname = bfromcstr(host);
		} else {
			susshi_session.hostname = bfromcstr("unkown");
		}
	}

	// System Logs
	susshi_session.log_system.fd = NULL;
	susshi_session.log_system.logformat = susshi_cfg.logfile_system;
	susshi_session.log_system.filename = NULL;
	susshi_session.log_system.ucid = -1;
	susshi_session.log_system.next_period = determine_next_log_period(NULL);
	susshi_session.log_system.filetype = bfromcstr("log");

	// Session Logs
	susshi_session.log_session.fd = NULL;
	susshi_session.log_session.logformat = susshi_cfg.logfile_session;
	susshi_session.log_session.filename = NULL;
	susshi_session.log_session.ucid = -1;
	susshi_session.log_session.next_period = determine_next_log_period(NULL);
	susshi_session.log_session.filetype = bfromcstr("log");

	// At Init we only try to open the system log. All other logs are dependent to loggin_mask
	susshi_open_logfile(&susshi_session.log_system);

	if (susshi_session.log_system.fd == NULL)
		fatal("Fatal - can't open system logfile. Please fix issue.");

	// Always set, not maskable by Chef
	susshi_session.logging_mask = (u_int) SUSSHI_SYSTEMLOG;

	// Live View flush
	if_debug3()
		susshi_session.log_live_view = true;
	else
		susshi_session.log_live_view = false;
}


/*!
 * @brief       Flush (or rotate) all open channel log files.
 *
 * Iterates over every allocated channel in the current session and flushes
 * the following per-channel logs: target output, client input, timing, and
 * protocol. If the current time falls within the first 60 seconds after
 * midnight (i.e. the remaining period exceeds 24 * 60 * 59 seconds), each
 * log file is closed via @c susshi_close_logfile() to trigger rotation on
 * the next write; otherwise the file handle is simply flushed with @c fflush().
 *
 * Channels with a NULL slot in the channel table are skipped silently.
 */

void
flush_susshi_channel_logs(void)
{
	u_int i;
	int close = 0;
	time_t delta;

	// If we are close after midnight (00:00:00 - 00:00:59), we will close the files as well.
	determine_next_log_period(&delta);
	if (delta > 24*60*59)
		close = 1;

	for(i = 0; i < susshi_session.channels_alloc; i++)	{
		// Skip free channels
		if (susshi_session.channels[i] == NULL)
			continue;

		if (susshi_session.channels[i]->log_target_output.fd != NULL) {
			if (close) {
				susshi_close_logfile(&susshi_session.channels[i]->log_target_output);
			} else {
				fflush(susshi_session.channels[i]->log_target_output.fd);
			}
		}

		if (susshi_session.channels[i]->log_client_input.fd != NULL) {
			if (close) {
				susshi_close_logfile(&susshi_session.channels[i]->log_client_input);
			} else {
				fflush(susshi_session.channels[i]->log_client_input.fd);
			}
		}

		if (susshi_session.channels[i]->log_timing.fd != NULL) {
			if (close) {
				susshi_close_logfile(&susshi_session.channels[i]->log_timing);
			} else {
				fflush(susshi_session.channels[i]->log_timing.fd);
			}
		}

		if (susshi_session.channels[i]->log_protocol.fd != NULL) {
			if (close) {
				susshi_close_logfile(&susshi_session.channels[i]->log_protocol);
			} else {
				fflush(susshi_session.channels[i]->log_protocol.fd);
			}
		}
	}
}


/*!
 * @brief       Write a system-level log message to file, syslog, and optionally stderr.
 *
 * Formats and writes a log entry to the system log file, automatically
 * reopening or rotating it if the file handle is NULL or the current log
 * period has expired. The message is always also sent to syslog under the
 * configured system facility, regardless of the @c log_on_stderr setting.
 * If @c log_on_stderr is set, the message is additionally written to stderr
 * via @c do_log() with a @c "(system)" prefix.
 *
 * The file log entry is prefixed with the Unix timestamp, daemon ID, PID,
 * and log level string.
 *
 * @param       level   The log level for the message (e.g. @c LOG_INFO, @c LOG_DEBUG).
 *                      Values outside the valid range are clamped to @c LOG_DEBUG.
 * @param       fmt     A @c printf-style format string for the message.
 * @param       ...     Variable arguments matching @p fmt.
 */

void
log_system(LogLevel level, const char *fmt,...)
{
	va_list args;
	char fmtbuf[MSGBUFSIZE];
	char msgbuf[MSGBUFSIZE];
	time_t now = time(NULL);

	// --- Log to file ---
	va_start(args, fmt);
	snprintf(fmtbuf, sizeof(fmtbuf), "%ld susshid[%s-%05d] %s: %s\r\n", time(NULL), bdata(chef_cfg.susshid_id), getpid(),
			 level >= 0 ? LogLevelString[level] : "unknown", fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmtbuf, args);
	va_end(args);

	if ((susshi_session.log_system.fd == NULL) || (now > susshi_session.log_system.next_period))
		susshi_open_logfile(&susshi_session.log_system);

	// Write & flush
	fwrite(msgbuf, strlen(msgbuf), 1, susshi_session.log_system.fd);
	fflush(susshi_session.log_system.fd);

	// --- log_system() always logs to syslog, even log_on_stderr is set ---
	va_start(args, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, args);
	va_end(args);

	openlog(SUSSHID_NAME, LOG_PID | LOG_CONS, susshi_cfg.log_facility_system);
	if (level > LOG_DEBUG || level < 0)
		level = LOG_DEBUG;
	syslog(level, "%.500s", msgbuf);
	closelog();

	// --- Log on stderr ---
	if (log_on_stderr) {
		va_start(args, fmt);
		snprintf(fmtbuf, sizeof fmtbuf, "(system)  %s", fmt);
		do_log(level, false, fmtbuf, args);
		va_end(args);
	}
}


/*!
 * @brief       Core log dispatch function — formats and routes a message to stderr and/or syslog.
 *
 * Checks the message @p level against the global @c log_level threshold and
 * silently discards messages that exceed it or when @c log_level is
 * @c LOG_LEVEL_NOT_SET. The message is prefixed with the level string and PID
 * before being written.
 *
 * Output destinations:
 * - **stderr**: Written if @c log_on_stderr is set.
 * - **syslog**: Written only if @p _log_on_syslog is @c true, using the
 *   session facility. In session process role (@c PROC_ROLE_SESSION), the
 *   unique session ID is prepended to the syslog message.
 *
 * @note        @c errno is preserved across this call.
 *
 * @param       level           The log level of the message. Clamped to
 *                              @c LOG_DEBUG_PACKETDUMP if out of range.
 * @param       _log_on_syslog  If @c true, the message is also sent to syslog.
 * @param       fmt             A @c printf-style format string.
 * @param       args            A @c va_list of arguments matching @p fmt.
 */

void
do_log(LogLevel level, bool _log_on_syslog, const char *fmt, va_list args) {
	char msgbuf[MSGBUFSIZE + 50];
	char fmtbuf[MSGBUFSIZE];
	int saved_errno = errno;

	if (level > log_level)
		return;

	if (log_level == LOG_LEVEL_NOT_SET)
		return;

	if ((level < 0) || (level > LOG_DEBUG_PACKETDUMP))
		level = LOG_DEBUG_PACKETDUMP;

	snprintf(fmtbuf, sizeof(fmtbuf), "%s: [%05d] %s", LogLevelString[level], getpid(), fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmtbuf, args);

	// Preserve msgbuf in fmtbuf for syslog
	strncpy(fmtbuf, msgbuf, sizeof(fmtbuf));

	if (log_on_stderr) {
		snprintf(msgbuf, sizeof msgbuf, "%s\r\n", fmtbuf);
		if (write(STDERR_FILENO, msgbuf, strlen(msgbuf)) == -1)
			return; // errno set by write
	}

	if (_log_on_syslog) {

		// Syslog
		openlog(SUSSHID_NAME, LOG_PID, susshi_cfg.log_facility_session);
		if (level > LOG_DEBUG)
			level = LOG_DEBUG;

		if (susshi_session.process_role == PROC_ROLE_SESSION) {
			// Prepend Uniq ID
			snprintf(msgbuf, sizeof(msgbuf), "[%s] %s", bdata(susshi_session.susshi_uniqid), fmtbuf);
			syslog(level, "%.500s", msgbuf);
		} else {
			syslog(level, "%.500s", fmtbuf);
		}

		closelog();
	}

	errno = saved_errno;
}


/*!
 * @brief       Log an error-level message to syslog and stderr.
 *
 * Convenience wrapper around @c do_log() that always uses @c LOG_LEVEL_ERROR
 * and enables syslog output.
 *
 * @param       fmt     A @c printf-style format string.
 * @param       ...     Variable arguments matching @p fmt.
 */

void
error(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_LEVEL_ERROR, true, fmt, args);
	va_end(args);
}


/*!
 * @brief       Emit a milestone debug message (debug level 1) with the susshi log prefix.
 *
 * Prepends @c SUSSHI_LOG to the format string and forwards to @c do_log()
 * at @c LOG_DEBUG_MILESTONES with syslog output enabled.
 *
 * @param       fmt  A @c printf-style format string.
 * @param       ...  Variable arguments matching @p fmt.
 *
 */

void
do_debug1(const char *fmt,...)
{
	va_list args;
	char buf[MSGBUFSIZE];
	va_start(args, fmt);

	// Add susshi log prefix
	snprintf(buf, sizeof(buf), "%s%s", SUSSHI_LOG, fmt);

	do_log(LOG_DEBUG_MILESTONES, true, buf, args);
	va_end(args);
}


/*!
 * @brief       Emit a conversation debug message (debug level 2) with the susshi log prefix.
 *
 * Prepends @c SUSSHI_LOG to the format string and forwards to @c do_log()
 * at @c LOG_DEBUG_CONVERSATION with syslog output enabled.
 *
 * @param       fmt  A @c printf-style format string.
 * @param       ...  Variable arguments matching @p fmt.
 */

void
do_debug2(const char *fmt,...)
{
	va_list args;
	char buf[MSGBUFSIZE];
	va_start(args, fmt);

	// Add susshi log prefix
	snprintf(buf, sizeof(buf), "%s%s", SUSSHI_LOG, fmt);

	do_log(LOG_DEBUG_CONVERSATION, true, buf, args);
	va_end(args);
}


/*!
 * @brief       Emit a detail debug message (debug level 3) with the susshi log prefix.
 *
 * Prepends @c SUSSHI_LOG to the format string and forwards to @c do_log()
 * at @c LOG_DEBUG_DETAILS with syslog output enabled.
 *
 * @param       fmt  A @c printf-style format string.
 * @param       ...  Variable arguments matching @p fmt.
 */

void
do_debug3(const char *fmt,...)
{
	va_list args;
	char buf[MSGBUFSIZE];
	va_start(args, fmt);

	// Add susshi log prefix
	snprintf(buf, sizeof(buf), "%s%s", SUSSHI_LOG, fmt);

	do_log(LOG_DEBUG_DETAILS, true, buf, args);
	va_end(args);
}


/*!
 * @brief       Emit a packet debug message (debug level 4) with the susshi log prefix.
 *
 * Prepends @c SUSSHI_LOG to the format string and forwards to @c do_log()
 * at @c LOG_DEBUG_PACKET. Syslog output is disabled at this level.
 *
 * @param       fmt  A @c printf-style format string.
 * @param       ...  Variable arguments matching @p fmt.
 */

void
do_debug4(const char *fmt,...)
{
	va_list args;
	char buf[MSGBUFSIZE];
	va_start(args, fmt);

	// Add susshi log prefix
	snprintf(buf, sizeof(buf), "%s%s", SUSSHI_LOG, fmt);

	do_log(LOG_DEBUG_PACKET, false, buf, args);
	va_end(args);
}


/*!
 * @brief       Emit a packet-dump debug message (debug level 5) with the susshi log prefix.
 *
 * Prepends @c SUSSHI_LOG to the format string and forwards to @c do_log()
 * at @c LOG_DEBUG_PACKETDUMP. Syslog output is disabled at this level.
 *
 * @param       fmt  A @c printf-style format string.
 * @param       ...  Variable arguments matching @p fmt.
 */

void
do_debug5(const char *fmt,...)
{
	va_list args;
	char buf[MSGBUFSIZE];
	va_start(args, fmt);

	// Add susshi log prefix
	snprintf(buf, sizeof(buf), "%s%s", SUSSHI_LOG, fmt);

	do_log(LOG_DEBUG_PACKETDUMP, false, buf, args);
	va_end(args);
}


/*!
 * @brief       Emit a directional milestone debug message (debug level 1).
 *
 * Prepends a @c "( X->Y )" direction indicator to the format string and
 * forwards to @c do_log() at @c LOG_DEBUG_MILESTONES with syslog enabled.
 *
 * @param       requestor  The @c Side that originated the traffic.
 * @param       receiver   The @c Side that received the traffic.
 * @param       fmt        A @c printf-style format string.
 * @param       ...        Variable arguments matching @p fmt.
 */

void
do_debug1_dir(Side requestor, Side receiver, const char *fmt,...)
{
	va_list args;
	char buf[MSGBUFSIZE];

	// Add susshi log prefix
	snprintf(buf, sizeof(buf), "( %c->%c )  %s", SideChar[requestor], SideChar[receiver], fmt);

	va_start(args, fmt);
	do_log(LOG_DEBUG_MILESTONES, true, buf, args);
	va_end(args);
}


/*!
 * @brief       Emit a directional milestone debug message (debug level 2).
 *
 * Prepends a @c "( X->Y )" direction indicator to the format string and
 * forwards to @c do_log() at @c LOG_DEBUG_MILESTONES with syslog enabled.
 *
 * @param       requestor  The @c Side that originated the traffic.
 * @param       receiver   The @c Side that received the traffic.
 * @param       fmt        A @c printf-style format string.
 * @param       ...        Variable arguments matching @p fmt.
 */

void
do_debug2_dir(Side requestor, Side receiver, const char *fmt,...)
{
	va_list args;
	char buf[MSGBUFSIZE];
	// Add susshi log prefix
	snprintf(buf, sizeof(buf), "( %c->%c )  %s", SideChar[requestor], SideChar[receiver], fmt);

	va_start(args, fmt);
	do_log(LOG_DEBUG_CONVERSATION, true, buf, args);
	va_end(args);
}


/*!
 * @brief       Emit a directional milestone debug message (debug level 3).
 *
 * Prepends a @c "( X->Y )" direction indicator to the format string and
 * forwards to @c do_log() at @c LOG_DEBUG_MILESTONES with syslog enabled.
 *
 * @param       requestor  The @c Side that originated the traffic.
 * @param       receiver   The @c Side that received the traffic.
 * @param       fmt        A @c printf-style format string.
 * @param       ...        Variable arguments matching @p fmt.
 */

void
do_debug3_dir(Side requestor, Side receiver, const char *fmt,...)
{
	va_list args;
	char buf[MSGBUFSIZE];

	// Add susshi log prefix
	snprintf(buf, sizeof(buf), "( %c->%c )  %s", SideChar[requestor], SideChar[receiver], fmt);

	va_start(args, fmt);
	do_log(LOG_DEBUG_DETAILS, true, buf, args);
	va_end(args);
}


/*!
 * @brief       Emit a directional milestone debug message (debug level 4).
 *
 * Prepends a @c "( X->Y )" direction indicator to the format string and
 * forwards to @c do_log() at @c LOG_DEBUG_MILESTONES with syslog enabled.
 *
 * @param       requestor  The @c Side that originated the traffic.
 * @param       receiver   The @c Side that received the traffic.
 * @param       fmt        A @c printf-style format string.
 * @param       ...        Variable arguments matching @p fmt.
 */

void
do_debug4_dir(Side requestor, Side receiver, const char *fmt,...)
{
	va_list args;
	char buf[MSGBUFSIZE];

	// Add susshi log prefix
	snprintf(buf, sizeof(buf), "( %c->%c )  %s", SideChar[requestor], SideChar[receiver], fmt);

	va_start(args, fmt);
	do_log(LOG_DEBUG_PACKET, false, buf, args);
	va_end(args);
}


/*!
 * @brief       Emit a directional milestone debug message (debug level 5).
 *
 * Prepends a @c "( X->Y )" direction indicator to the format string and
 * forwards to @c do_log() at @c LOG_DEBUG_MILESTONES with syslog enabled.
 *
 * @param       requestor  The @c Side that originated the traffic.
 * @param       receiver   The @c Side that received the traffic.
 * @param       fmt        A @c printf-style format string.
 * @param       ...        Variable arguments matching @p fmt.
 */

void
do_debug5_dir(Side requestor, Side receiver, const char *fmt,...)
{
	va_list args;
	char buf[MSGBUFSIZE];

	// Add susshi log prefix
	snprintf(buf, sizeof(buf), "( %c->%c )  %s", SideChar[requestor], SideChar[receiver], fmt);

	va_start(args, fmt);
	do_log(LOG_DEBUG_PACKETDUMP, false, buf, args);
	va_end(args);
}

/*! @} */
