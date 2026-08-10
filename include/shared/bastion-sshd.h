/*!
 *
 * @brief       Bastion OpenSSH Server
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
 */

#ifndef SUSSHI_BASTION_SSHD_H
#define SUSSHI_BASTION_SSHD_H

/* Prototypes */
bool run_bastion_sshd(int num_host_keys, bstring *host_key_files, int num_target_identities, KeyIdentity *key_identities, int *bastion_pid);
pid_t bastion_lookup_daemon_pid(int *bastion_pid);
void bastion_remove_daemon_pid_file(void);

#define _PATH_BASTION_DIR		      "/opt/wasabi/susshi"
#define _PATH_BASTION_PIDDIR          _PATH_VARRUN

#define BASTION_DAEMON                "sshd"
#define BASTION_LISTEN_IP             "127.0.0.1"
#define BASTION_LISTEN_PORT_STR       "10022"
#define BASTION_LISTEN_PORT           10022
#define BASTION_BANNER                "You are connected to suSSHi Bastion.\n"

#define _PATH_BASTION_CONFIG_DIR      _PATH_BASTION_DIR "/bastion"

#define PATH_BASTION_CONFIG_FILE      _PATH_BASTION_CONFIG_DIR "/bastion_config"
#define PATH_BASTION_AUTHORIZED_KEYS  _PATH_BASTION_CONFIG_DIR "/authorized_keys"
#define PATH_BASTION_BANNER           _PATH_BASTION_CONFIG_DIR "/banner"
#define PATH_BASTION_PID_FILE         _PATH_BASTION_PIDDIR "/bastion.pid"

#define PATH_BASTION_DAEMON           "/usr/sbin/" BASTION_DAEMON
#define BASTION_USER                  "bastion"

#endif //SUSSHI_BASTION_SSHD_H
