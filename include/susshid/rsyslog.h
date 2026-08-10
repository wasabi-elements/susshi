/*!
 *
 * @brief       RSyslog
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
 * @ingroup     rsyslog
 * @{
 */

#ifndef SUSSHI_RSYSLOG_H
#define SUSSHI_RSYSLOG_H

#define PATH_RSYSLOG_DEV_LOG        "/dev/log"
#define PATH_RSYSLOG_CONFIG_FILE    PATH_SUSSHID_TEMP_DIR "/rsyslogd.conf"
#define PATH_RSYSLOG_PID_FILE       PATH_SUSSHID_TEMP_DIR "/rsyslogd.pid"
#define PATH_RSYSLOG_TLS_CA_FILE    PATH_SUSSHID_TEMP_DIR "/rsyslogd.ca.pem"
#define PATH_RSYSLOG_TLS_CERT_FILE  PATH_SUSSHID_TEMP_DIR "/rsyslogd.cert"
#define PATH_RSYSLOG_TLS_KEY_FILE   PATH_SUSSHID_TEMP_DIR "/rsyslogd.key"

#ifdef LINUX
#define PATH_RSYSLOG_DAEMON         "/usr/sbin/rsyslogd"
#else
#define PATH_RSYSLOG_DAEMON         "/usr/local/sbin/rsyslogd"
#endif

pid_t susshi_lookup_rsyslog_pid(int *rsyslog_pid);
bool susshi_fork_rsyslog_daemon(void);
bool susshi_terminate_rsyslog(void);
bool susshi_restart_rsyslog(void);

#endif //SUSSHI_RSYSLOG_H

/*! @} */
