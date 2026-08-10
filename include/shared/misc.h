/*!
 *
 * @brief       Miscellaneous methods
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

#ifndef SUSSHI_MISC_H
#define SUSSHI_MISC_H

extern const unsigned char susshi_misc_seed[32];

/* Highest configurable value of /proc/sys/kernel/pid_max (kernel's PID_MAX_LIMIT, not exported to userspace headers). */
#define PID_MAX_LIMIT (4 * 1024 * 1024)

#define LAST_QUEUE_NAME     "/susshid-last-queue"
#define WHO_QUEUE_NAME      "/susshid-who-queue"

#define SUSSHI_UNPRIVILEGED_USERNAME   "susshi"

#define SUSSHI_PROXY_ERROR_CODE_TARGET_RESOLV_FAILED   1
#define SUSSHI_PROXY_ERROR_CODE_TARGET_CONNECT_FAILED  2

#define SUSSHI_LOGDIR_MODE	( S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH )
#define SUSSHI_LOGFILE_MODE ( S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP )

typedef enum {
	CLIENT = 0,
	TARGET = 1,
	GATEWAY = 2,
	PROXY = 3,
	BOTH = 4,
	NODIR = 255
} Side;

typedef struct {
	bstring fingerprint;
	bstring key_type;
	bstring public_blob;
	bstring private_blob;
} KeyIdentity;

typedef enum {
	KEY_OK=0,
	KEY_ERROR=1,
	KEY_NEW=2,
	KEY_CHANGED=3,
	KEY_REVOKED=4
} KeyVerifyResponse;

#ifndef MIN
#define MIN(a, b)     ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b)     ((a) > (b) ? (a) : (b))
#endif

/* Prototypes */
int a2port(const char *s);

char *chop(char *s);

char *cleanhostname(char *host);

long convtime(const char *s);

void create_subdir(bstring path);

char *host_port_delimiter(char **cp);

char *percent_expand(const char *string, bool allow_asterics, ...);

char *tilde_expand_filename(const char *filename, uid_t uid);

void sanitise_stdfd(void);

char *strdelim(char **s);

long long strtonum(const char *numstr, long long minval, long long maxval, const char **errstrp);

char *username(void);

bool is_local_http_url(const char *url);

bool susshi_parse_version_info(bstring susshi_version, uint32_t *susshi_version_uint32);


#ifdef HAVE_SETPROCTITLE
//# define	SETPROCTITLE(...)	   setproctitle(__VA_ARGS__)
# define	SETPROCTITLE(...)       susshi_setproctitle(__VA_ARGS__)
#else
# define	SETPROCTITLE(...)      if (log_level >= LOG_DEBUG_DETAILS) do_debug3("SETPROCTITLE: " __VA_ARGS__)
#endif

#ifdef HAVE_SETPROCTITLE_INIT
# define	SETPROCTITLE_INIT(...)	   setproctitle_init(__VA_ARGS__)
#else
# define	SETPROCTITLE_INIT(...)
#endif

#endif //SUSSHI_MISC_H
