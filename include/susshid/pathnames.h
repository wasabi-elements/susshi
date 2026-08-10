/*!
 *
 * @brief       Pathnames
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

#ifndef SUSSHI_PATHNAMES_H
#define SUSSHI_PATHNAMES_H

#define PATH_SUSSHI_PIDDIR              _PATH_VARRUN "susshi"
#define _PATH_SUSSHI_DIR                "/opt/wasabi/susshi"
#define PATH_SUSSHID_CONFIG_DIR         _PATH_SUSSHI_DIR "/config"
#define PATH_SUSSHID_TEMP_DIR           _PATH_SUSSHI_DIR "/tmp"
#define PATH_SUSSHI_HOOKS               _PATH_SUSSHI_DIR "/hooks"

#define SUSSHID_CONFIG_FILE		        PATH_SUSSHID_CONFIG_DIR "/susshid.json"

#define PATH_SUSSHI_DAEMON_PID_FILE     PATH_SUSSHI_PIDDIR "/susshid.pid"
#define PATH_SUSSHI_MONITOR_PID_FILE    PATH_SUSSHI_PIDDIR "/monitor.pid"
#define PATH_SUSSHI_REPORT_PID_FILE     PATH_SUSSHI_PIDDIR "/report.pid"
#define PATH_SUSSHI_KEYS		        PATH_SUSSHID_TEMP_DIR
#define PREFIX_SUSSHI_HOSTKEYS          "susshi_host_key_"
#define PREFIX_SUSSHI_AUTHKEYS          "susshi_auth_key_"

#ifdef LINUX
#define PATH_SUSSHI_LOGDIR              "/var/log/susshi"
#else
#define PATH_SUSSHI_LOGDIR              _PATH_SUSSHI_DIR "/log"
#endif

#define PATH_SUSSHI_RUNDIR              _PATH_VARRUN

#define PATH_MONITOR_SERVER_SUSPEND_DIR   PATH_SUSSHID_TEMP_DIR "/monitor-server"
#define PATH_MONITOR_SERVER_SUSPEND_FILE  PATH_MONITOR_SERVER_SUSPEND_DIR "/suspended"

#ifdef WITH_PCAP
#define PATH_LIBSSH_PCAP "/var/tmp/susshid-debug/"
#endif

#endif //SUSSHI_PATHNAMES_H

/*! @} */
