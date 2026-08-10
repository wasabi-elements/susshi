/*!
 *
 * @brief       Logging shares
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

#ifndef SUSSHI_LOG_H
#define SUSSHI_LOG_H

#include <sys/syslog.h>
#include "shared/misc.h"

/*
 * Loglevels
 * ---------
 * (defined in system's syslog.h)
 *
 * LOG_EMERG	0		system is unusable
 * LOG_ALERT	1		action must be taken immediately
 * LOG_CRIT		2		critical conditions
 * LOG_ERR		3		error conditions
 * LOG_WARNING	4		warning conditions
 * LOG_NOTICE	5		normal but significant condition
 * LOG_INFO		6		informational
 * LOG_DEBUG	7		debug-level messages
 *
 */

typedef enum {
	LOG_LEVEL_EMERG = LOG_EMERG,
	LOG_LEVEL_ALERT = LOG_ALERT,
	LOG_LEVEL_CRIT = LOG_CRIT,
	LOG_LEVEL_ERROR = LOG_ERR,
	LOG_LEVEL_WARNING = LOG_WARNING,
	LOG_LEVEL_NOTICE = LOG_NOTICE,
	LOG_LEVEL_INFO = LOG_INFO,
	LOG_DEBUG_MILESTONES = LOG_DEBUG,             // Debug-Level 1
	LOG_DEBUG_CONVERSATION = (LOG_DEBUG + 1),     // Debug-Level 2
	LOG_DEBUG_DETAILS = (LOG_DEBUG + 2),          // Debug-Level 3
	LOG_DEBUG_PACKET = (LOG_DEBUG + 3),           // Debug-Level 4
	LOG_DEBUG_PACKETDUMP = (LOG_DEBUG + 4),       // Debug-Level 5
	LOG_LEVEL_NOT_SET = -1
} LogLevel;

// Supported syslog facilities and levels.
typedef enum {
	SYSLOG_FACILITY_DAEMON,
	SYSLOG_FACILITY_USER,
	SYSLOG_FACILITY_AUTH,
	SYSLOG_FACILITY_LOCAL0,
	SYSLOG_FACILITY_LOCAL1,
	SYSLOG_FACILITY_LOCAL2,
	SYSLOG_FACILITY_LOCAL3,
	SYSLOG_FACILITY_LOCAL4,
	SYSLOG_FACILITY_LOCAL5,
	SYSLOG_FACILITY_LOCAL6,
	SYSLOG_FACILITY_LOCAL7,
	SYSLOG_FACILITY_NOT_SET = -1
} SyslogFacility;

/* Data structure to keep all information about a log (file) target */

typedef struct {
	FILE *fd;					// Filedescriptor
	bstring logformat;			// Logformat String as given by configuration
	bstring filename;			// Filename after filename expansion
	bstring filetype;			// Filetype (e.g. log, time, client, sftp, scp, pcap, x11)
	long int ucid;		        // Set uniq_cid to positive value if channel logging. Otherwise 0
	time_t next_period;			// Next time we have to check whether to open a new logfile
	struct timeval tv;			// Timeval of last log entry
	long int filesize;			// Bytes already written to the file.
	pcap_t *pcap;				// PCAP structure used for libpcap dumps
	u_short pcap_ip_id;			// IP-ID in pseudo IP headers used for libpcap dumps
	tcp_seq pcap_tcp_client_seq;   // Client TCP sequence numbers in pseudo TCP headers used for libpcap dumps
	tcp_seq pcap_tcp_target_seq;   // Target TCP sequence numbers in pseudo TCP headers used for libpcap dumps
	u_long	pcap_packets_num;	// Number of packets already captured
	bool    enc_requested;      // True if this log file should be encrypted
	void   *enc_state;          // Opaque stream encryption state (NULL = not encrypted)
} SusshiLog;


// Global log_level for process
extern LogLevel log_level;
extern bool log_on_stderr;

/*
 * Loglevels
 * ---------
 * (defined in system's syslog.h)
 *
 * LOG_EMERG	0		system is unusable
 * LOG_ALERT	1		action must be taken immediately
 * LOG_CRIT		2		critical conditions
 * LOG_ERR		3		error conditions
 * LOG_WARNING	4		warning conditions
 * LOG_NOTICE	5		normal but significant condition
 * LOG_INFO		6		informational
 * LOG_DEBUG	7		debug-level messages
 *
 */

#define SUSSHI_SYSTEMLOG					(1<<31)

#define SUSSHI_LOG "(susshi)  "

extern const char *LevelString[];
extern const char *SideString[];
extern const char SideChar[];

/* Prototypes */
void	do_debug1(const char *fmt,...) __attribute__((format(printf, 1, 2)));
void	do_debug2(const char *fmt,...) __attribute__((format(printf, 1, 2)));
void	do_debug3(const char *fmt,...) __attribute__((format(printf, 1, 2)));
void	do_debug4(const char *fmt,...) __attribute__((format(printf, 1, 2)));

void	do_debug1_dir(Side requestor, Side receiver, const char *fmt,...) __attribute__((format(printf, 3, 4)));
void	do_debug2_dir(Side requestor, Side receiver, const char *fmt,...) __attribute__((format(printf, 3, 4)));
void	do_debug3_dir(Side requestor, Side receiver, const char *fmt,...) __attribute__((format(printf, 3, 4)));
void	do_debug4_dir(Side requestor, Side receiver, const char *fmt,...) __attribute__((format(printf, 3, 4)));

void	do_log(LogLevel level, bool _log_on_syslog, const char *fmt, va_list args);

int		syslog_facility_int(const char *name);
void    log_system(LogLevel level, const char *fmt,...) __attribute__((format(printf, 2, 3)));
char *  init_proxy_identifier(void);
void    init_proxy_log(void);
void    error(const char *, ...) __attribute__((format(printf, 1, 2)));

SyslogFacility log_facility_number(char *name);
const char *log_facility_name(SyslogFacility facility);
LogLevel log_level_number(char *name);
const char *log_level_name(LogLevel level);

// Function wrappers for speedy code

#define debug1(...)			    if (log_level >= LOG_DEBUG_MILESTONES) do_debug1(__VA_ARGS__)
#define debug2(...)			    if (log_level >= LOG_DEBUG_CONVERSATION) do_debug2(__VA_ARGS__)
#define debug3(...)			    if (log_level >= LOG_DEBUG_DETAILS) do_debug3(__VA_ARGS__)
#define if_debug1()             if (log_level >= LOG_DEBUG_MILESTONES)
#define if_debug2()             if (log_level >= LOG_DEBUG_CONVERSATION)
#define if_debug3()             if (log_level >= LOG_DEBUG_DETAILS)

#define debug1_dir(...)		    if (log_level >= LOG_DEBUG_MILESTONES) do_debug1_dir(__VA_ARGS__)
#define debug2_dir(...)		    if (log_level >= LOG_DEBUG_CONVERSATION) do_debug2_dir(__VA_ARGS__)
#define debug3_dir(...)		    if (log_level >= LOG_DEBUG_DETAILS) do_debug3_dir(__VA_ARGS__)

#ifdef WITH_FULL_DEBUG_OPTIONS
#define debug4(...)			    if (log_level >= LOG_DEBUG_PACKET) do_debug4(__VA_ARGS__)
#define debug4_dir(...)		    if (log_level >= LOG_DEBUG_PACKET) do_debug4_dir(__VA_ARGS__)
#define if_debug4()             if (log_level >= LOG_DEBUG_PACKET)
#define debug5(...)			    if (log_level >= LOG_DEBUG_PACKETDUMP) do_debug5(__VA_ARGS__)
#define debug5_dir(...)		    if (log_level >= LOG_DEBUG_PACKETDUMP) do_debug5_dir(__VA_ARGS__)
#define if_debug5()             if (log_level >= LOG_DEBUG_PACKETDUMP)
#else
#define debug4(...)
#define debug4_dir(...)
#define if_debug4()             if (0)
#define debug5(...)
#define debug5_dir(...)
#define if_debug5()             if (0)
#endif

#endif //SUSSHI_LOG_H
