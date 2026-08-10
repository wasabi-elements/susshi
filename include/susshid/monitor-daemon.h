/*!
 *
 * @brief       Monitor Daemon
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
 * @ingroup     monitor_daemon
 * @{
 */

#ifndef SUSSHI_MONITOR_DAEMON_H
#define SUSSHI_MONITOR_DAEMON_H

#define MONITOR_STATUS_URL  "/susshi-health"
#define MONITOR_STATUS_PAGE "<html>"\
							"<head><title>" SUSSHI_NAME "</title></head>"\
							"<body><p>Status: Ok</p></body>"\
							"</html>\r\n"

#define MONITOR_NOT_FOUND_PAGE  "<html>"\
								"<head><title>" SUSSHI_NAME "</title></head>"\
								"<body><p>Error!</p></body>"\
								"</html>\r\n"

#define MONITOR_SVC_UNAVAILABLE_PAGE  "<html>"\
									  "<head><title>" SUSSHI_NAME "</title></head>"\
									  "<body><p>Error! Service is unavailable.</p></body>"\
									  "</html>\r\n"

#define MONITOR_SVC_SUSPENDED_PAGE  "<html>"\
									"<head><title>" SUSSHI_NAME "</title></head>"\
									"<body><p>Service is suspended. No new service requests are accepted.</p></body>"\
									"</html>\r\n"

#define MONITOR_PORT 80
#define MONITOR_PORT_STRING "80"

/* Prototypes */
bool susshi_fork_monitor_daemon(void);
bool suspend_monitor_server(void);
bool unsuspend_monitor_server(void);
bool monitor_server_suspended(void);

#endif //SUSSHI_MONITOR_DAEMON_H

/*! @} */
