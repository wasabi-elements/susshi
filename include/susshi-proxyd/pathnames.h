/*!
 *
 * @brief       Signal Handler methods
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
 * @ingroup     susshi_proxyd
 * @{
 *
 */

#ifndef SUSSHI_PROXYD_PATHNAMES_H
#define SUSSHI_PROXYD_PATHNAMES_H

#define _PATH_SUSSHI_PROXYD_PIDDIR              _PATH_VARRUN "susshi/"
#define _PATH_SUSSHI_PROXYD_DIR                 "/opt/wasabi/susshi/"
#define _PATH_SUSSHI_PROXYD_TEMP_DIR            _PATH_SUSSHI_PROXYD_DIR "tmp/"
#define _PATH_SUSSHI_PROXYD_CONFIG_DIR          _PATH_SUSSHI_PROXYD_DIR "config/"

#define PATH_SUSSHI_PROXYD_DAEMON_PID_FILE      _PATH_SUSSHI_PROXYD_PIDDIR "susshi-proxyd.pid"
#define PATH_SUSSHI_PROXYD_KEYS                 _PATH_SUSSHI_PROXYD_TEMP_DIR
#define PREFIX_SUSSHI_PROXYD_HOSTKEYS           "susshi_proxy_host_key_"
#define SUSSHI_PROXYD_CONFIG_FILE1               _PATH_SUSSHI_PROXYD_CONFIG_DIR "susshi-proxyd.json"
#define SUSSHI_PROXYD_CONFIG_FILE2               "/susshi-proxyd.json"
#define SUSSHI_PROXYD_CONFIG_FILE3               "/run/secrets/susshi-proxyd.json"

#ifdef LINUX
#define PATH_SUSSHI_PROXYD_LOGDIR               "/var/log/susshi"
#else
#define PATH_SUSSHI_PROXYD_LOGDIR               _PATH_SUSSHI_PROXYD_DIR "/log"
#endif

#define PATH_SUSSHI_PROXYD_RUNDIR              _PATH_VARRUN

#endif //SUSSHI_PROXYD_PATHNAMES_H

/*! @} */
