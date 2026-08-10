/*!
 *
 * @brief       SFTP Inspection
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
 * @ingroup     inspection_sftp
 * @{
 */

#ifndef SUSSHI_INSPECT_SFTP_H
#define SUSSHI_INSPECT_SFTP_H

#include <libssh/libssh.h>
#include "inspect-channel.h"

/* New Packet Types of version 6, not defined by libSSH yet */
#define SSH_FXP_LINK               21
#define SSH_FXP_BLOCK              22
#define SSH_FXP_UNBLOCK            23

/* Flags, not defined by libSSH yet */
#define SSH_FILEXFER_ATTR_BITS              0x00000200
#define SSH_FILEXFER_ATTR_ALLOCATION_SIZE   0x00000400
#define SSH_FILEXFER_ATTR_TEXT_HINT         0x00000800
#define SSH_FILEXFER_ATTR_MIME_TYPE         0x00001000
#define SSH_FILEXFER_ATTR_LINK_COUNT        0x00002000
#define SSH_FILEXFER_ATTR_UNTRANSLATED_NAME 0x00004000
#define SSH_FILEXFER_ATTR_CTIME             0x00008000

/* File Types, not defined by libSSH yet */
#define SSH_FILEXFER_TYPE_SOCKET           6
#define SSH_FILEXFER_TYPE_CHAR_DEVICE      7
#define SSH_FILEXFER_TYPE_BLOCK_DEVICE     8
#define SSH_FILEXFER_TYPE_FIFO             9

/* Text-Hints, not defined by libSSH yet */
#define SSH_FILEXFER_ATTR_KNOWN_TEXT        0x00
#define SSH_FILEXFER_ATTR_GUESSED_TEXT      0x01
#define SSH_FILEXFER_ATTR_KNOWN_BINARY      0x02
#define SSH_FILEXFER_ATTR_GUESSED_BINARY    0x03

/* ACE Types, not defined by libSSH yet */
#define ACE4_ACCESS_ALLOWED_ACE_TYPE 0x00000000
#define ACE4_ACCESS_DENIED_ACE_TYPE  0x00000001
#define ACE4_SYSTEM_AUDIT_ACE_TYPE   0x00000002
#define ACE4_SYSTEM_ALARM_ACE_TYPE   0x00000003

/* File flags, not defined by libSSH yet */
#define SSH_FXF_CREATE_NEW               0x00000000
#define SSH_FXF_CREATE_TRUNCATE          0x00000001
#define SSH_FXF_OPEN_EXISTING            0x00000002
#define SSH_FXF_OPEN_OR_CREATE           0x00000003
#define SSH_FXF_TRUNCATE_EXISTING        0x00000004
#define SSH_FXF_ACCESS_DISPOSITION       0x00000007
#define SSH_FXF_APPEND_DATA              0x00000008
#define SSH_FXF_APPEND_DATA_ATOMIC       0x00000010
#define SSH_FXF_TEXT_MODE                0x00000020
#define SSH_FXF_BLOCK_READ               0x00000040
#define SSH_FXF_BLOCK_WRITE              0x00000080
#define SSH_FXF_BLOCK_DELETE             0x00000100
#define SSH_FXF_BLOCK_ADVISORY           0x00000200
#define SSH_FXF_NOFOLLOW                 0x00000400
#define SSH_FXF_DELETE_ON_CLOSE          0x00000800
#define SSH_FXF_ACCESS_AUDIT_ALARM_INFO  0x00001000
#define SSH_FXF_ACCESS_BACKUP            0x00002000
#define SSH_FXF_BACKUP_STREAM            0x00004000
#define SSH_FXF_OVERRIDE_OWNER           0x00008000

typedef struct SftpRequest_struct    SftpRequest;

struct SftpRequest_struct {
    uint32_t        id;                     // ID as sent by client / target
    uint8_t         type;                   // The SFTP command the client requested
	uint8_t         sftp_target_type;       // The SFTP command the target responded with
    uint32_t        flags;
    uint32_t        desired_access;
	const char     *attributes;             // Already parsed "clear text" attributes.
    int             hid;                    // Handle ID
    ssh_string      path;
    ssh_string      data;                   // can be newpath of rename()
};

typedef enum {
	INIT=0,
	NEW=1,
	INCOMPLETE=2,
	COMPLETE=3
} SftpMessageState;

typedef struct {
	SftpMessageState    state;
	uint8_t             type;
	uint32_t            length;         // Total length of message as stated in header
	uint32_t            received;       // Number of bytes already received. received == length -> all data got
	uint32_t            id;
	ssh_buffer          header;         // First 5 bytes to get filled up for interpretation in state "NEW"
	ssh_buffer          buffer;
} SftpMessage;

typedef struct {
	int		        request_id;
	char		    handle[515];		// File handle
	ssh_string      path;
	uint64_t	    filesize;
	uint8_t         request_type;       // What request type caused this handle to be created?
} SftpHandle;

typedef struct {
	SusshiChannel      *susshi_channel;         // Reference to SSH Channel, this sftp session runs on
	uint32_t            client_version;
	uint32_t            target_version;

	SftpMessage         sftp_client_message;
	SftpMessage         sftp_target_message;

	SftpRequest	      **sftp_requests;	        // Pointer to an array of pointers to SFTP requests
	uint32_t			sftp_requests_alloc;    // Number of SFTP requests allocated
	SftpHandle		  **sftp_handles;		    // Pointer to an array of pointers to SFTP handles
	uint32_t			sftp_handles_alloc;	    // Number of SFTP handles allocated
} SftpSession;


/* Prototypes */

void susshi_new_sftp_session(uint32_t cid, ssh_buffer buffer_copy);
void susshi_free_sftp_session(uint32_t cid);
void susshi_show_sftprequest(int cid);
void susshi_show_sftphandles(int cid);
void data_to_hex(char *buffer, size_t buflen, u_char *data, size_t datalen);

void susshi_inspect_sftp_packet(SftpSession *sftp_session, Side side, ssh_buffer buffer_copy);

#endif //SUSSHI_INSPECT_SFTP_H

/*! @} */

