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
 * @ingroup     susshi_proxyd
 * @{
 */

#ifndef SUSSHI_PROXYD_COMMON_H
#define SUSSHI_PROXYD_COMMON_H

#ifdef LINUX
	#define _GNU_SOURCE
	#define	SIZE_T_MAX	((size_t) -1) /* max value for a size_t */
	#define UINT32_MAX  4294967295U  /* max value for a uint32 */
#endif

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

#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>

#include <bsd/string.h>
#include <bsd/stdlib.h>
#include <bsd/unistd.h>
#include <utmp.h>
#include <pty.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <resolv.h>

// libSSH
#include <libssh/config.h>  // created during build process in build directory
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <libssh/ssh2.h>
#include <libssh/sftp.h>

// libSSH unofficial headers
#include <libssh/libssh-config.h> // original file is libssh/config.h, but conflicts with build/config.h
#include <libssh/buffer.h>
#include <libssh/packet.h>
#include <libssh/session.h>
#include <libssh/crypto.h>
#include <libssh/string.h>
#include <libssh/ssh2.h>
#include <libssh/socket.h>
#include <libssh/messages.h>
#include <libssh/pki.h>

// OpenSSL library
#include <openssl/sha.h>

// Better String library
#include <bstraux.h>

// libPCAP
#include <pcap/pcap.h>

// libPCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

// libcurl
#include <curl/curl.h>

// libjansson
#include <jansson.h>

// libbcrypt
// #include <bcrypt.h>

// Editline
#include <histedit.h>

// libmicrohttpd
#include <microhttpd.h>

// suSSHi suite-wide shared
#include "shared/config.h"
#include "shared/types.h"
#include "shared/privileges.h"
#include "shared/misc.h"
#include "shared/bastion-sshd.h"
#include "shared/wrappers.h"
#include "shared/base64.h"
#include "shared/hash.h"
#include "shared/hexdump.h"
#include "shared/cidr.h"

// Required by all modules
#include "version.h"
#include "helpers.h"
#include "pathnames.h"
#include "proxy-cfg.h"
#include "log.h"
#include "monitor-daemon.h"
#include "session.h"
#include "libssh-helpers.h"
#include "connect-target.h"
#include "auth.h"
#include "auth-gateway.h"
#include "master-loop.h"
#include "session-loop.h"
#include "signal.h"
#include "main.h"

#endif //SUSSHI_PROXYD_COMMON_H

/*! @} */
