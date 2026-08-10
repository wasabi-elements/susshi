/*!
 *
 * @brief       Session and channel logging methods
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
 * @defgroup    logging_session Session and channel logging methods
 * @brief       Logging functions for session events, channel I/O, and protocol inspection.
 * @{
 */


#include "susshid/common.h"

#define MSGBUFSIZE 2048


/*!
 * @brief       Write a session-level log entry describing traffic between two sides.
 *
 * Formats and writes a structured log message to the session log file and
 * syslog, identifying the direction of traffic between @p requestor and
 * @p receiver. The log entry includes the timestamp, PID, authenticated user,
 * client IP, target identifier, and a directional arrow (or the @c SUSSHI_LOG
 * prefix when either side is @c NODIR).
 *
 * The session log file is opened or rotated automatically if needed. The
 * syslog entry is always prefixed with the unique session ID. At debug level 2
 * or higher, the message is also emitted via @c do_log() with a
 * @c "(session)" prefix.
 *
 * If @c susshi_session.target_identifier is NULL the function does nothing.
 *
 * @param       requestor   The @c Side that originated the traffic.
 * @param       receiver    The @c Side that received the traffic.
 * @param       fmt         A @c printf-style format string for the message body.
 * @param       ...         Variable arguments matching @p fmt.
 */

void
do_log_session(Side requestor, Side receiver, const char *fmt,...)
{
	va_list args;
	char fmtbuf[MSGBUFSIZE];
	char msgbuf[MSGBUFSIZE];
	int o;
	time_t now = time(NULL);

	if (susshi_session.target_identifier != NULL) {

		va_start(args, fmt);

		o = snprintf(fmtbuf, sizeof(fmtbuf), "%ld susshid[%05d]: %s@%s ==> %s: ", now, getpid(),
					 bdata(susshi_session.susshi_user), bdata(susshi_session.client_ip),
					 bdata(susshi_session.target_identifier));

		if (requestor == NODIR || receiver == NODIR)
			o += snprintf(&fmtbuf[o], sizeof(fmtbuf) - o, SUSSHI_LOG);
		else
			o += snprintf(&fmtbuf[o], sizeof(fmtbuf) - o, "( %c->%c ) ", SideChar[requestor], SideChar[receiver]);

		if (o < 0 || o >= (int)sizeof(fmtbuf) - 2)
			o = (int)sizeof(fmtbuf) - 2;
		{
			size_t fmt_fit = strnlen(fmt, (size_t)(MSGBUFSIZE - o - 2));
			strncpy(&fmtbuf[o], fmt, fmt_fit);
			fmtbuf[o + fmt_fit]     = '\n';
			fmtbuf[o + fmt_fit + 1] = '\0';
		}
		vsnprintf(msgbuf, sizeof(msgbuf), fmtbuf, args);
		va_end(args);

		// --- Log to file ---
		if ((susshi_session.log_session.fd == NULL) || (now > susshi_session.log_session.next_period))
			susshi_open_logfile(&susshi_session.log_session);

		// Write & flush
		fwrite(msgbuf, strlen(msgbuf), 1, susshi_session.log_session.fd);
		fflush(susshi_session.log_session.fd);

		// --- Log on syslog ---

		// Prepend Uniq ID
		snprintf(fmtbuf, sizeof(fmtbuf), "[%s] %s", bdata(susshi_session.susshi_uniqid), fmt);

		va_start(args, fmt);
		vsnprintf(msgbuf, sizeof(msgbuf), fmtbuf, args);
		va_end(args);

		openlog(SUSSHID_NAME, LOG_PID, susshi_cfg.log_facility_session);
		syslog(LOG_INFO, "%.500s", msgbuf);
		closelog();

		if_debug2() {
			snprintf(fmtbuf, sizeof(fmtbuf), "(session) %s", fmt);
			va_start(args, fmt);
			do_log(LOG_DEBUG_CONVERSATION, false, fmtbuf, args);
			va_end(args);
		}
	}
}


/*!
 * @brief       Log raw target output data for a channel to its output log file.
 *
 * Writes @p datalen bytes from @p data to the target-output log file of
 * channel @p cid, opening or rotating the file if necessary. Updates the
 * running @c filesize counter on the channel log, records a timing entry via
 * @c do_log_timing(), and flushes the file immediately if live-view mode is
 * active.
 *
 * @param       cid      The channel ID whose target-output log should be written to.
 * @param       data     Pointer to the raw output data to log.
 * @param       datalen  Number of bytes in @p data to write.
 */

void
do_log_target_output(int cid, const char *data, size_t datalen)
{
	SusshiChannel *c;
	time_t now = time(NULL);

	if ((c = susshi_session.channels[cid]) != NULL) {
		// --- Log to file ---
		if ((c->log_target_output.fd == NULL) || (now > c->log_target_output.next_period))
			susshi_open_logfile(&c->log_target_output);

		if (c->log_target_output.enc_state)
			log_session_enc_write(&c->log_target_output, (const unsigned char *)data, datalen);
		else
			fwrite(data, (size_t) datalen, 1, c->log_target_output.fd);

		// Update filesize
		c->log_target_output.filesize += datalen;

		debug4("Target output logfile: %ld (%ld) bytes", c->log_target_output.filesize,  susshi_cfg.logfile_exec_max_size);

		// Record timing information
		do_log_timing(cid, TARGET, datalen, NULL);

		if (susshi_session.log_live_view) {
			fflush(c->log_target_output.fd);
		}
	}
	else {
		error("do_log_target_output: cid %d not found.", cid);
	}
}


/*!
 * @brief       Log raw client input data for a channel to its input log file.
 *
 * Writes @p datalen bytes from @p data to the client-input log file of
 * channel @p cid, opening or rotating the file if necessary. Updates the
 * running @c filesize counter, records a timing entry via @c do_log_timing(),
 * and flushes the target-output file handle if live-view mode is active.
 *
 * @param       cid      The channel ID whose client-input log should be written to.
 * @param       data     Pointer to the raw input data to log.
 * @param       datalen  Number of bytes in @p data to write.
 */

void
do_log_client_input(int cid, const char *data, size_t datalen)
{
	SusshiChannel *c;
	time_t now = time(NULL);

	if ((c = susshi_session.channels[cid]) != NULL) {
		// --- Log to file ---
		if ((c->log_client_input.fd == NULL) || (now > c->log_client_input.next_period))
			susshi_open_logfile(&c->log_client_input);

		if (c->log_client_input.enc_state)
			log_session_enc_write(&c->log_client_input, (const unsigned char *)data, datalen);
		else
			fwrite(data, (size_t) datalen, 1, c->log_client_input.fd);

		// Update filesize
		c->log_client_input.filesize += datalen;

		// Record timing information

		do_log_timing(cid, CLIENT, datalen, NULL);

		if (susshi_session.log_live_view)
			fflush(c->log_target_output.fd);
	}
	else {
		error("do_log_client_input: cid %d not found.", cid);
	}
}


/*!
 * @brief       Append a timing record to a channel's timing log file.
 *
 * Calculates the elapsed time since the last timing entry for channel @p cid
 * and writes a scriptreplay-compatible record to the channel's timing log.
 * Two record formats are produced depending on @p windowsize:
 * - **Data record** (`windowsize == NULL`): `<side> <sec>.<usec> <datalen>`
 * - **Resize record** (`windowsize != NULL`): `<side> <sec>.<usec> 0 <windowsize>`
 *
 * The log file is opened or rotated automatically if needed. The timestamp
 * stored in @c log_timing.tv is updated after each write. The file is flushed
 * immediately if live-view mode is active.
 *
 * @param       cid         The channel ID whose timing log should be written to.
 * @param       side        The @c Side that produced the data (@c CLIENT or @c TARGET).
 * @param       datalen     Number of bytes transferred; used in data records.
 * @param       windowsize  Terminal window size string for resize records, or NULL
 *                          for a normal data record.
 */

void
do_log_timing(int cid, Side side, size_t datalen, char* windowsize)
{
	struct timeval tv;
	char timemsg[256];
	time_t sec;
	time_t usec;

	SusshiChannel *c;
	time_t now = time(NULL);

	if ((c = susshi_session.channels[cid]) != NULL) {
		// --- Log to file ---
		if ((c->log_timing.fd == NULL) || (now > c->log_timing.next_period))
			susshi_open_logfile(&c->log_timing);

		// Calculate delta from last log
		gettimeofday(&tv, NULL);

		sec = tv.tv_sec - c->log_timing.tv.tv_sec;
		usec = tv.tv_usec - c->log_timing.tv.tv_usec;

		if (usec < 0) {
			sec--;
			usec += 1000000;
		}

		if (windowsize != NULL) {
			// Resize message
			snprintf(timemsg, 256, "%c %ld.%06ld 0 %s\n", (side == CLIENT) ? 'C' : 'S', sec, usec, windowsize);
		}
		else {
			// Data message
			snprintf(timemsg, 256, "%c %ld.%06ld %ld\n", (side == CLIENT) ? 'C' : 'S', sec, usec, datalen);
		}

		// Save new timestamp
		c->log_timing.tv.tv_sec = tv.tv_sec;
		c->log_timing.tv.tv_usec = tv.tv_usec;

		if (c->log_timing.enc_state)
			log_session_enc_write(&c->log_timing, (const unsigned char *)timemsg, strlen(timemsg));
		else
			fwrite(timemsg, strlen(timemsg), 1, c->log_timing.fd);

		if (susshi_session.log_live_view) {
			fflush(c->log_timing.fd);
		}
	}
	else {
		error("do_log_timing: cid %d not found.", cid);
	}
}


/*!
 * @brief       Log an SFTP protocol event for a channel to its protocol log file.
 *
 * Formats and writes an SFTP protocol log entry to the protocol log of
 * channel @p cid, prefixed with the timestamp, traffic direction, and request
 * ID. If @p rid is negative, the request ID field is rendered as
 * @c "[start]" to mark session-initiation events. At debug level 3 or higher,
 * the entry is also emitted via @c do_debug3_dir(). The file is flushed
 * immediately if live-view mode is active.
 *
 * @param       cid       The channel ID whose protocol log should be written to.
 * @param       rid       The SFTP request ID, or a negative value for start events.
 * @param       requestor The @c Side that sent the SFTP request.
 * @param       receiver  The @c Side that received the SFTP request.
 * @param       fmt       A @c printf-style format string for the event description.
 * @param       ...       Variable arguments matching @p fmt.
 */

void
do_log_sftp(int cid, int rid, Side requestor, Side receiver, const char *fmt, ...)
{
	SusshiChannel *c;
	time_t now = time(NULL);
	va_list args;
	char fmtbuf[MSGBUFSIZE];
	char msgbuf[MSGBUFSIZE];

	if ((c = susshi_session.channels[cid]) != NULL) {
		// --- Log to file ---
		if ((c->log_protocol.fd == NULL) || (now > c->log_protocol.next_period))
			susshi_open_logfile(&c->log_protocol);

		if (rid >= 0)
			snprintf(fmtbuf, sizeof(fmtbuf), "%ld ( %c->%c ) [%05d] sftp> %s\n", now, SideChar[requestor], SideChar[receiver], rid, fmt);
		else
			snprintf(fmtbuf, sizeof(fmtbuf), "%ld ( %c->%c ) [start] sftp> %s\n", now, SideChar[requestor], SideChar[receiver], fmt);

		// va_copy(cargs, args);
		va_start(args, fmt);
		vsnprintf(msgbuf, sizeof(msgbuf), fmtbuf, args);
		va_end(args);

		if (c->log_protocol.enc_state)
			log_session_enc_write(&c->log_protocol, (const unsigned char *)msgbuf, strlen(msgbuf));
		else
			fwrite(msgbuf, strlen(msgbuf), 1, c->log_protocol.fd);

		if_debug3() {
			// Remove new-line character from msgbuf
			msgbuf[strlen(msgbuf)-1] = '\0';
			do_debug3_dir(requestor, receiver, "log_sftp: %s", msgbuf);
		}

		if (susshi_session.log_live_view)
			fflush(c->log_protocol.fd);
	}
	else {
		error("do_log_client_input: cid %d not found.", cid);
	}
}


/*!
 * @brief       Log an SCP protocol event for a channel to its protocol log file.
 *
 * Formats and writes an SCP protocol log entry to the protocol log of
 * channel @p cid, prefixed with the timestamp and traffic direction. The
 * message body is indented proportionally to the current SCP directory
 * traversal depth (@c scp_dir_depth) to visually reflect directory nesting.
 * At debug level 3 or higher, the entry is also emitted via
 * @c do_debug3_dir(). The file is flushed immediately if live-view mode is
 * active.
 *
 * @param       cid       The channel ID whose protocol log should be written to.
 * @param       requestor The @c Side that initiated the SCP operation.
 * @param       receiver  The @c Side that is receiving the SCP operation.
 * @param       fmt       A @c printf-style format string for the event description.
 * @param       ...       Variable arguments matching @p fmt.
 */

void
do_log_scp(int cid, Side requestor, Side receiver, const char *fmt,...)
{
	SusshiChannel *c;
	time_t now = time(NULL);
	va_list args;
	char fmtbuf[MSGBUFSIZE];
	char msgbuf[MSGBUFSIZE];
	int o, x;

	if ((c = susshi_session.channels[cid]) != NULL) {
		// --- Log to file ---
		if ((c->log_protocol.fd == NULL) || (now > c->log_protocol.next_period))
			susshi_open_logfile(&c->log_protocol);

		o = snprintf(fmtbuf, sizeof(fmtbuf), "%ld ( %c->%c ) scp> ", now, SideChar[requestor], SideChar[receiver]);
		if (o < 0 || (size_t)o >= sizeof(fmtbuf))
			o = (int)sizeof(fmtbuf) - 1;
		for (x = 0; x <= susshi_session.channels[cid]->scp_dir_depth && (o + x + 1) < (int)sizeof(fmtbuf); x++) {
			fmtbuf[x + o] = ' ';
		}
		o += x;
		o = snprintf(fmtbuf + o, sizeof(fmtbuf) - o, "%s\n", fmt);

		va_start(args, fmt);
		vsnprintf(msgbuf, sizeof(msgbuf), fmtbuf, args);
		va_end(args);

		if (c->log_protocol.enc_state)
			log_session_enc_write(&c->log_protocol, (const unsigned char *)msgbuf, strlen(msgbuf));
		else
			fwrite(msgbuf, strlen(msgbuf), 1, c->log_protocol.fd);

		if_debug3() {
			do_debug3_dir(requestor, receiver, "log_scp: %s", msgbuf);
		}

		if (susshi_session.log_live_view)
			fflush(c->log_protocol.fd);
	}
	else {
		error("do_log_client_input: cid %d not found.", cid);
	}

}

/*! @} */
