/*!
 *
 * @brief       Report
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
 * @ingroup     report
 * @{
 */

#ifndef SUSSHI_REPORT_H
#define SUSSHI_REPORT_H

#define susshi_idle_time() (time(NULL) - susshi_report.last_io_time)

#define REPORT_QUEUE_NAME   "/susshid-reporting-queue"

typedef enum {
	REPORT_NONE = 0,
	REPORT_FIRST,
	REPORT_PERIODIC,
	REPORT_LAST,
	REPORT_FAILED,
	REPORT_FATAL
} ReportSessionState;


typedef struct {
	time_t	 session_start_time;		 // Time when user was authenticated and session started
	time_t	 last_io_time;				 // Time when the last I/O was seen.
	bool     update_last_io_time;        // If set to true, last_io_time is updated
	uint64_t client_in_bytes;
	uint64_t client_out_bytes;
	uint64_t target_in_bytes;
	uint64_t target_out_bytes;
	int		 channels_opened;			 // Number of channels requested and accepted
	int		 channels_rejected;			 // Number of channels requested and rejected
	int		 channels_failed;			 // Number of channels requested and failed
	int		 channels_closed;			 // Number of channels closed
	bool	 client_used_connect;		 // Flag set when user has made use of the PROXY feature (during identification exchange)
	bool     client_compression;         // Flag set if client session is compressed
	bool     target_compression;         // Flag set if target session is compressed
	int		 client_rekeyings;
	int		 target_rekeyings;
	int		 local_forwards_accepted;
	int		 local_forwards_rejected;
	int		 remote_forwards_accepted;
	int		 remote_forwards_rejected;
	int		 remote_forwards_canceled;
	int		 tunnel_interfaces_rejected;
	int		 interactive_sessions_accepted;
	int		 interactive_sessions_rejected;
	int		 command_execs_accepted;
	int		 command_execs_rejected;
	int		 unkown_subsystems_accepted;
	int		 x11_sessions_accepted;
	int		 x11_sessions_rejected;
	int		 agent_forwards_accepted;
	int		 agent_forwards_rejected;
	int		 sftp_sessions;				 // Number of sftp sessions
	int		 sftp_files_read;			 // Number of sftp files read by client
	int		 sftp_files_written;		 // Number of sftp files written by client
	uint64_t sftp_bytes_read;			 // Number of sftp bytes (in files) read by client
	uint64_t sftp_bytes_written;		 // Number of sftp bytes (in files) written by client
	int		 scp_sessions;				 // Number of scp sessions
	int		 scp_files_read;			 // Number of scp files read by client
	int		 scp_files_written;			 // Number of scp files written by client
	uint64_t scp_bytes_read;			 // Number of scp bytes (in files) read by client
	uint64_t scp_bytes_written;			 // Number of scp bytes (in files) written by client
	int		 scp_files_maycount;		 // For internal usage in SCP inspection only
	int		 failed_target_connect;		 // Failure during connecting target
	int		 failed_target_userauth;	 // Userauth on target failed
	int		 failed_userauth;			 // Failed (final) userauths on gateway
	int		 authmethod_password;		 // Password authentication on gateway
	int		 authmethod_pubkey;			 // Pubkey authentication on gateway
	int		 target_authmethod_password; // Password authentication on target
	int		 target_authmethod_pubkey;	 // Pubkey authentication on target
	int		 target_authmethod_hostkey;	 // Hostkey authentication on target
	int		 target_authmethod_kbdint;	 // Keyboard-interactive authentication on target
	int		 target_connect_retries;	 // Retries until connection to target became established
	bstring  message;                    // Report message, mainly used for error messages
} SusshiReport;

extern SusshiReport susshi_report;

/* Prototypes */
void	init_susshi_report(void);
void	susshi_report_last_log(bool finished);
void	susshi_report_who(void);
const char *susshi_report_features(void);
void    susshi_report_client_send_report(ReportSessionState reason);


#endif //SUSSHI_REPORT_H

/*! @} */
