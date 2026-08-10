/*!
 *
 * @brief       Common Include
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
 * @ingroup     susshi_last
 * @{
 */

#ifndef SUSSHI_LAST_COMMON_H
#define SUSSHI_LAST_COMMON_H

#define _GNU_SOURCE
#define	SIZE_T_MAX	((size_t) -1) /* max value for a size_t */

#define SUSSHID_UNPRIVILEGED_USER "susshi"

// System includes
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <paths.h>
#include <libgen.h>
#include <mqueue.h>
#include <time.h>

#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <getopt.h>

#include <bsd/string.h>
#include <bsd/stdlib.h>
#include <utmp.h>
#include <pty.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <resolv.h>
#include <libproc2/pids.h>

// libSSH
#include <libssh/libssh.h>

// OpenSSL library
#include <openssl/sha.h>

// Better String library
#include <bstraux.h>

// Editline
#include <histedit.h>

// suSSHi suite-wide shared
#include "shared/config.h"
#include "shared/privileges.h"
#include "shared/types.h"
#include "shared/misc.h"
#include "shared/processes.h"
#include "shared/wrappers.h"

#include "version.h"

#endif //SUSSHI_LAST_COMMON_H

/*! @} */
