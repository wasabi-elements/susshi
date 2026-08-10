/*!
 *
 * @brief       Session and channel logging
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
 * @ingroup     logging
 * @{
 */


#ifndef SUSSHID_LOG_SESSION_H
#define SUSSHID_LOG_SESSION_H

/*
 * Logging Types
 *
 * 1. System Logging (not maskable)
 *		Types:	Logon/Logoff/Daemon
 *		File:	susshid logfile (per gw)
 *		Path:	system
 *
 * 2. Session Logging
 *		Types:	Channels, Channel Specific Logs (command, shell, sftp, scp ...) ...
 *		File:	<user...>
 *		Path:	<date>/<target>
 *
 * 3. Audit trail Logging - Target / Client response data
 *		Types:	Target response data of interactive sessions ("session" channel)
 *		File:	<user...>
 *		Path:	<date>/<target>
 *
 * 4. Audit trail Logging - Client data
 *		Types:	Client keystrokes of interactive sessions ("session" channel)
 *		File:	<user...>
 *		Path:	<date>/<target>
 *
 * Future (not to be implemented yet!)
 *
 * 5. Audit Trail Logging - Protocol inspection on forwarded ports
 *
 * 6. Audit Trail Logging - Filetransfer content on sftp, scp
 */

/*
 * Filename variables that can be used:
 *
 *		%d	is replaced by the day of the month as a decimal number (01-31).
 *		%m	is replaced by the month as a decimal number (01-12).
 *		%s	is replaced by the susshi handle id (<time>-<pid>-<sessionid>).
 *		%t	is replaced by the target hostname.
 *		%u	is replaced by the susshi userid.
 *		%y	is replaced by the year with century as a decimal number.
 *
 */

#define SUSSHI_AUDITLOG_SESSION				1
#define SUSSHI_AUDITLOG_TRAIL_TARGET		2
#define SUSSHI_AUDITLOG_TRAIL_CLIENT		4
#define SUSSHI_AUDITLOG_FILETRANSFER		8
#define SUSSHI_AUDITLOG_PORTFORWARD			16
#define SUSSHI_AUDITLOG_X11					32
#define SUSSHI_AUDITLOG_AGENT				64
#define SUSSHI_AUDITLOG_SOCKET				128

/* Prototypes */
void    do_log_session(Side requestor, Side receiver, const char *fmt,...) __attribute__((format(printf, 3, 4)));
void    do_log_target_output(int cid, const char *data, size_t datalen);
void    do_log_client_input(int cid, const char *data, size_t datalen);
void    do_log_sftp(int cid, int rid, Side requestor, Side receiver, const char *fmt,...) __attribute__((format(printf, 5, 6)));
void    do_log_scp(int cid, Side requestor, Side receiver, const char *fmt,...) __attribute__((format(printf, 4, 5)));
void    do_log_timing(int cid, Side side, size_t datalen, char* windowsize);

// Function wrappers for speedy code

#define log_session(...)	    if (susshi_session.logging_mask & SUSSHI_AUDITLOG_SESSION) do_log_session(__VA_ARGS__)
#define log_target_output(...)	if (susshi_session.logging_mask & SUSSHI_AUDITLOG_TRAIL_TARGET) do_log_output_target(__VA_ARGS__)
#define log_client_input(...)	if (susshi_session.logging_mask & SUSSHI_AUDITLOG_TRAIL_CLIENT) do_log_client_input(__VA_ARGS__)
#define log_sftp(...)		    if (susshi_session.logging_mask & SUSSHI_AUDITLOG_FILETRANSFER) do_log_sftp(__VA_ARGS__)
#define log_scp(...)		    if (susshi_session.logging_mask & SUSSHI_AUDITLOG_FILETRANSFER) do_log_scp(__VA_ARGS__)

#endif //SUSSHID_LOG_SESSION_H

/*! @} */
