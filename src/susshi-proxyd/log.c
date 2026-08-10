/*!
 *
 * @brief       Logging methods
 *
 * @ingroup     susshi_proxyd
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
 * @defgroup    proxy_logging   Logging methods
 * @brief       All kinds of logging functions.
 * @{
 *
 */

#include "susshi-proxyd/common.h"

// Global log_level for process
LogLevel log_level = LOG_LEVEL_INFO;
bool log_on_stderr = false;

const char SideChar[] = { 'C', 'T', 'G', 'P' };
const char *SideString[] = { "Client", "Target", "Gateway", "Proxy", "Client and Server" };
const char *LogLevelString[] = { "emerg",
								 "alert",
								 "crit",
								 "err",
								 "warn",
								 "notice",
								 "info",
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

/*!
 * @brief       Look up the name of a syslog facility by its enum value.
 *
 * Iterates over the global @c log_facilities table and returns the
 * string name corresponding to the given @p facility value.
 *
 * @param       name    The SyslogFacility name to look up
 *
 * @return      Number of the Facility out of map
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
 * @brief       Initializes the proxy session logging context.
 *
 * Retrieves the current machine's hostname via @c gethostname() and stores it
 * in @c proxy_session.hostname as a bstring. Falls back to the string
 * @c "unknown" if the hostname cannot be determined.
 *
 * @note        This function must be called before any proxy logging takes place
 * @warning     The stored hostname bstring must be freed by the caller when the
 *              proxy session is torn down to avoid a memory leak
 */

void
init_proxy_log(void)
{
	char host[256];

	// Get and store hostname susshid runs
	if (gethostname(host, 256) == 0) {
		proxy_session.hostname = bfromcstr(host);
	} else {
		proxy_session.hostname = bfromcstr("unkown");
	}
}


/*!
 * @brief       Logs a formatted message to syslog and optionally to stderr.
 *
 * Formats the provided message using printf-style arguments and submits it
 * to syslog under the @c LOG_AUTH facility. If @c log_on_stderr is set, the
 * message is also written to stderr via @c do_log(), prefixed with
 * @c "(system)".
 *
 * If @p level is out of the valid syslog range it is clamped to
 * @c LOG_DEBUG before submission.
 *
 * @param       level   The log severity level (e.g., @c LOG_INFO, @c LOG_ERR).
 *                      Values outside the valid syslog range are clamped to @c LOG_DEBUG.
 * @param       fmt     A printf-style format string for the log message.
 * @param       ...     Variadic arguments corresponding to @p fmt.
 *
 */

void
log_system(LogLevel level, const char *fmt,...)
{
	va_list args;
	char fmtbuf[MSGBUFSIZE];
	char msgbuf[MSGBUFSIZE];

	// --- Log on syslog ---
	va_start(args, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, args);
	va_end(args);

	openlog(SUSSHI_PROXYD_NAME, LOG_PID | LOG_CONS, LOG_AUTH);
	if (level > LOG_DEBUG || level < 0)
		level = LOG_DEBUG ;
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
 * @brief       Core logging function that writes a formatted message to stderr or syslog.
 *
 * Prepends the log level string and the calling process's PID to the message,
 * then writes it to either stderr (as @c "\\r\\n"-terminated text) or syslog,
 * depending on the value of @c log_on_stderr. Messages whose @p level exceeds
 * the global @c log_level threshold, or when @c log_level is @c LOG_LEVEL_NOT_SET,
 * are silently discarded.
 *
 * @c errno is preserved across the call.
 *
 * @param       level            The log severity level for this message.
 * @param       _log_on_syslog   Reserved for future use; currently unused.
 * @param       fmt              A printf-style format string for the log message.
 * @param       args             A @c va_list of arguments corresponding to @p fmt.
 *
 * @note        Output is truncated to @c MSGBUFSIZE characters.
 */

void
do_log(LogLevel level, bool _log_on_syslog, const char *fmt, va_list args)
{
	char msgbuf[MSGBUFSIZE];
	char fmtbuf[MSGBUFSIZE];
	int saved_errno = errno;

	if (level > log_level)
		return;

	if (log_level == LOG_LEVEL_NOT_SET)
		return;

	snprintf(fmtbuf, sizeof(fmtbuf), "%s: [%d] %s", LogLevelString[level], getpid(), fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmtbuf, args);
	strncpy(fmtbuf, msgbuf, sizeof(fmtbuf));

	if (log_on_stderr) {
		snprintf(msgbuf, sizeof msgbuf, "%s\r\n", fmtbuf);
		if (write(STDERR_FILENO, msgbuf, strlen(msgbuf)) == -1)
			return; // errno set by write
	} else {
		// Syslog
		openlog(SUSSHI_PROXYD_NAME, LOG_PID | LOG_CONS, LOG_AUTH);
		if (level > LOG_DEBUG)
			level = LOG_DEBUG;
		syslog(level, "%.500s", fmtbuf);
		closelog();
	}

	errno = saved_errno;
}


/**
 * @brief       Logs a message at @c LOG_LEVEL_ERROR severity.
 *
 * Convenience wrapper around @c do_log() that fixes the log level to
 * @c LOG_LEVEL_ERROR. Syslog submission is delegated entirely to @c do_log().
 *
 * @param       fmt     A printf-style format string describing the error.
 * @param       ...     Variadic arguments corresponding to @p fmt.
 */

void
error(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_LEVEL_ERROR, false, fmt, args);
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

	do_log(LOG_DEBUG_MILESTONES, false, buf, args);
	va_end(args);
}


/*!
 * @brief       Emit a milestone debug message (debug level 2) with the susshi log prefix.
 *
 * Prepends @c SUSSHI_LOG to the format string and forwards to @c do_log()
 * at @c LOG_DEBUG_MILESTONES with syslog output enabled.
 *
 * @param       fmt  A @c printf-style format string.
 * @param       ...  Variable arguments matching @p fmt.
 *
 */

void
do_debug2(const char *fmt,...)
{
	va_list args;
	char buf[MSGBUFSIZE];
	va_start(args, fmt);

	// Add susshi log prefix
	snprintf(buf, sizeof(buf), "%s%s", SUSSHI_LOG, fmt);

	do_log(LOG_DEBUG_CONVERSATION, false, buf, args);
	va_end(args);
}


/*!
 * @brief       Emit a milestone debug message (debug level 3) with the susshi log prefix.
 *
 * Prepends @c SUSSHI_LOG to the format string and forwards to @c do_log()
 * at @c LOG_DEBUG_MILESTONES with syslog output enabled.
 *
 * @param       fmt  A @c printf-style format string.
 * @param       ...  Variable arguments matching @p fmt.
 *
 */

void
do_debug3(const char *fmt,...)
{
	va_list args;
	char buf[MSGBUFSIZE];
	va_start(args, fmt);

	// Add susshi log prefix
	snprintf(buf, sizeof(buf), "%s%s", SUSSHI_LOG, fmt);

	do_log(LOG_DEBUG_DETAILS, false, buf, args);
	va_end(args);
}


/*!
 * @brief       Emit a milestone debug message (debug level 4) with the susshi log prefix.
 *
 * Prepends @c SUSSHI_LOG to the format string and forwards to @c do_log()
 * at @c LOG_DEBUG_MILESTONES with syslog output enabled.
 *
 * @param       fmt  A @c printf-style format string.
 * @param       ...  Variable arguments matching @p fmt.
 *
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
	do_log(LOG_DEBUG_MILESTONES, false, buf, args);
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
	do_log(LOG_DEBUG_CONVERSATION, false, buf, args);
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
	do_log(LOG_DEBUG_DETAILS, false, buf, args);
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

/*! @} */
