/*!
 *
 * @brief       SFTP Inspection
 *
 * @ingroup     inspection
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
 * ### Details
 *
 *              Please refer to IETF drafts accordingly:
 *              https://tools.ietf.org/html/draft-ietf-secsh-filexfer-XX
 *
 *              XX:
 *              01-02   SFTP-Version 3
 *              03-04   SFTP-Version 4
 *                 05   SFTP-Version 5
 *              06-13   SFTP-Version 6
 *
 *              IETF drafts diffs:
 *
 *              3 <-> 4 https://tools.ietf.org/tools/rfcdiff/rfcdiff.pyht?url1=draft-ietf-secsh-filexfer-02&url2=draft-ietf-secsh-filexfer-04
 *              3 <-> 5 https://tools.ietf.org/tools/rfcdiff/rfcdiff.pyht?url1=draft-ietf-secsh-filexfer-02&url2=draft-ietf-secsh-filexfer-05
 *              3 <-> 6 https://tools.ietf.org/tools/rfcdiff/rfcdiff.pyht?url1=draft-ietf-secsh-filexfer-02&url2=draft-ietf-secsh-filexfer-13
 *              4 <-> 5 https://tools.ietf.org/tools/rfcdiff/rfcdiff.pyht?url1=draft-ietf-secsh-filexfer-04&url2=draft-ietf-secsh-filexfer-05
 *              4 <-> 6 https://tools.ietf.org/tools/rfcdiff/rfcdiff.pyht?url1=draft-ietf-secsh-filexfer-04&url2=draft-ietf-secsh-filexfer-13
 *              5 <-> 6 https://tools.ietf.org/tools/rfcdiff/rfcdiff.pyht?url1=draft-ietf-secsh-filexfer-05&url2=draft-ietf-secsh-filexfer-13
 *
 * @author      Oliver Rauscher <oliver@susshi.io>
 * @date        2026-02-01
 *
 * @defgroup    inspection_sftp Secure File Transfer (sftp) Inspection
 * @brief       Functions to inspect sftp communication.
 *
 * @{
 */

#include "susshid/common.h"


extern LogLevel log_level;
extern const char *SideString[];
const char *SftpStateString[] = { "START", "CONTINUE", "CONTINUE_BUFFER", "COMPLETE", "UNKNOWN" };
const char *SftpStatusString[] = { "OK", "EOF", "No such file", "Permission denied", "Failure", "Bad message",
								   "No connection", "Connection lost", "Operation unsupported", "Invalid Handle",
								   "No such path", "File already exists", "Write protected", "No media",
								   "No media on filesystem", "Quota exceeded", "Unknown principal",
								   "Lock conflict", "Directory not empty", "Not a directory", "Invalid filename",
								   "Link loop", "Cannot delete", "Invalid parameter", "File is a directory",
								   "Byte-range lock conflict", "Byte-range lock refused", "Delete pending",
								   "File corrupt", "Owner invalid", "Group invalid", "No matching byte-range lock" };

/* Prototypes */
static const char *susshi_sftp_flags_string(SftpRequest *request);
static const char *susshi_sftp_pflags_string(SftpRequest *request);
static const char *susshi_sftp_acl_string(ssh_string acl_string);
static const char *susshi_sftp_data_file_attr(int cid, ssh_buffer buffer, uint32_t version);

static int susshi_alloc_new_sftprequest(int cid);
static void susshi_free_sftprequest(int cid, uint32_t rid);
static int susshi_find_sftprequest(int cid, uint32_t id);

static void inspect_sftp_request(SftpSession *sftp_session);
static void inspect_sftp_response(SftpSession *sftp_session);


/*!
 * @brief       Allocate new sftp session within channel
 *
 * @param       cid         SusshiChannel ID
 * @param       buffer_copy Copy of actual ssh_buffer
 */

void
susshi_new_sftp_session(uint32_t cid, ssh_buffer buffer_copy) {
	SusshiChannel *c;
	uint32_t packet_len, stringlen;
	uint8_t type;
	int rc;
	char *ext_name = NULL;
	char *ext_data = NULL;

	c = susshi_session.channels[cid];
	c->sftp_session = xcalloc(sizeof(SftpSession), sizeof(SftpSession));

	/* This function gets called on first sftp packet (SSH_FXP_INIT) from call, so we extract client's version right here */

	if (ssh_buffer_get_len(buffer_copy) == 0)
		return;

	if (ssh_buffer_unpack(buffer_copy, "ddbd", &stringlen, &packet_len, &type, &c->sftp_session->client_version) != SSH_OK)
		fatal("Decode error in SSH_FXP_INIT.");

	c->sftp_session->sftp_client_message.header = ssh_buffer_new();
	c->sftp_session->sftp_client_message.buffer = ssh_buffer_new();
	c->sftp_session->sftp_target_message.header = ssh_buffer_new();
	c->sftp_session->sftp_target_message.buffer = ssh_buffer_new();

	if (type == SSH_FXP_INIT) {
		c->sftp_session->susshi_channel = c;
		log_sftp(cid, -1, CLIENT, TARGET, "Client version is %u", c->sftp_session->client_version);
		debug3_dir(CLIENT, TARGET, "Client SFTP Init Request - Client version is %u", c->sftp_session->client_version);

		rc = ssh_buffer_unpack(buffer_copy, "s", &ext_name);
		while (rc == SSH_OK) {

			rc = ssh_buffer_unpack(buffer_copy, "s", &ext_data);
			if (rc == SSH_ERROR) {
				break;
			}
			log_sftp(cid, -1, CLIENT, TARGET, "SFTP Client extension: %s: %s", ext_name, ext_data);

			xfree(ext_name);
			xfree(ext_data);

			rc = ssh_buffer_unpack(buffer_copy, "s", &ext_name);
		}
	} else {
		fatal("Received SFTP Request but wasn't FXP_INIT.");
	}
}

/*
 * Free SFTP session
 */

void
susshi_free_sftp_session(uint32_t cid) {
	SusshiChannel *c;

	c = susshi_session.channels[cid];
	c->sftp_session = xcalloc(sizeof(SftpSession), sizeof(SftpSession));

	if (c->sftp_session->sftp_client_message.header) SSH_BUFFER_FREE(c->sftp_session->sftp_client_message.header);
	if (c->sftp_session->sftp_client_message.buffer) SSH_BUFFER_FREE(c->sftp_session->sftp_client_message.buffer);
	if (c->sftp_session->sftp_target_message.header) SSH_BUFFER_FREE(c->sftp_session->sftp_target_message.header);
	if (c->sftp_session->sftp_target_message.buffer) SSH_BUFFER_FREE(c->sftp_session->sftp_target_message.buffer);
}


/*!
 * @brief       Allocate new SFTP Request object
 *
 * @param       cid     SusshiChannel ID
 *
 * @return      Request ID
 */

static int
susshi_alloc_new_sftprequest(int cid) {
	SftpSession *session;
	uint32_t i;
	int found;

	session = susshi_session.channels[cid]->sftp_session;

	/* Do initial allocation if this is the first call. */
	if (session->sftp_requests_alloc == 0) {
		session->sftp_requests_alloc = 10;
		session->sftp_requests = xcalloc(session->sftp_requests_alloc, sizeof(SftpRequest *));
		for (i = 0; i < session->sftp_requests_alloc; i++)
			session->sftp_requests[i] = NULL;
	}
	/* Try to find a free slot where to put the new request in. */
	for (found = -1, i = 0; i < session->sftp_requests_alloc; i++)
		if (session->sftp_requests[i] == NULL) {
			debug4("Channel %d: Allocated sftprequest with ID %d", cid, i);
			/* Found a free slot. */
			session->sftp_requests[i] = xcalloc(1, sizeof(SftpRequest));
			return(i);
		}
	if (found < 0) {
		/* There are no free slots.  Take last+1 slot and expand the array.  */
		found = session->sftp_requests_alloc;
		if (session->sftp_requests_alloc > 10000)
			fatal("susshi_alloc_new_sftprequest: internal error: sftp_request_alloc %d "
						  "too big", session->sftp_requests_alloc);
		session->sftp_requests = xrealloc(session->sftp_requests, session->sftp_requests_alloc + 10,
									sizeof(SftpRequest *));
		session->sftp_requests_alloc += 10;
		debug4("Channel %d: Expanding sftprequests table to %d", cid, session->sftp_requests_alloc);
		for (i = found; i <  session->sftp_requests_alloc; i++)
			session->sftp_requests[i] = NULL;
	}

	session->sftp_requests[found] = xcalloc(1, sizeof(SftpRequest));

	debug4("Channel %d: Allocated new sftprequest with ID %d", cid, found);

	return(found);
}


/*!
 * @brief       Free SFTP Request object
 *
 * @param       cid     SusshiChannel ID
 * @param       rid     Request ID
 */

static void
susshi_free_sftprequest(int cid, uint32_t rid) {
	SftpSession *session;
	SftpRequest *r;

	session = susshi_session.channels[cid]->sftp_session;

	if (rid <= session->sftp_requests_alloc && session->sftp_requests[rid] != NULL)
	{
		r = session->sftp_requests[rid];

		/* Free buffers */
		if (r->path) SSH_STRING_FREE(r->path);
		if (r->attributes) xfree((void *) r->attributes);

		/* Clear & Free memory for SftpRequest */
		memset(r, 0, sizeof(SftpRequest));
		xfree((void *) r);
		session->sftp_requests[rid]=NULL;
		debug4(SUSSHI_LOG "Removed sftprequest with rid=%d", rid);
	}

}


/*!
 * @brief       Find SFTP Request object
 *
 * @param       cid     SusshiChannel ID
 * @param       id      Request ID
 *
 * @return      Request ID
 */

static int
susshi_find_sftprequest(int cid, uint32_t id) {
	SftpSession *session;
	uint32_t i;

	session = susshi_session.channels[cid]->sftp_session;

	for(i = 0; i < session->sftp_requests_alloc; i++)
	{
		// Skip free sftp_requests
		if (session->sftp_requests[i] == NULL)
			continue;

		if (session->sftp_requests[i]->id == id)
			return((int) i);
	}
	debug4("Channel %d: SFTP Request with ID %d was not found", cid, id);
	return -1;
}


/*!
 * @brief       Show all SFTP Request objects
 *
 * @param       cid     SusshiChannel ID
 */

void
susshi_show_sftprequest(int cid) {
	SftpSession *session;
	uint32_t i;

	session = susshi_session.channels[cid]->sftp_session;

	for(i = 0; i < session->sftp_requests_alloc; i++)
	{
		// Skip free sftp_requests
		if (session->sftp_requests[i] == NULL)
			continue;

		debug4("Request[%d]: request_id=%d, client = %d, target = %d",
			   i,  session->sftp_requests[i]->id,
			   session->sftp_requests[i]->type,
			   session->sftp_requests[i]->sftp_target_type);
	}
}


/*!
 * @brief       Allocated new SFTP Handle object
 *
 * @param       cid     SusshiChannel ID
 *
 * @return      Handle ID
 */

static int
susshi_alloc_new_sftphandle(int cid) {
	SftpSession *session;
	SftpHandle *h;
	uint32_t i;
	int found;

	session = susshi_session.channels[cid]->sftp_session;

	/* Do initial allocation if this is the first call. */
	if (session->sftp_handles_alloc == 0) {
		session->sftp_handles_alloc = 10;
		session->sftp_handles = xcalloc(session->sftp_handles_alloc, sizeof(SftpHandle *));
		for (i = 0; i < session->sftp_handles_alloc; i++)
			session->sftp_handles[i] = NULL;
	}
	/* Try to find a free slot where to put the new handle in. */
	for (found = -1, i = 0; i < session->sftp_handles_alloc; i++)
		if (session->sftp_handles[i] == NULL) {
			debug4(SUSSHI_LOG "Allocated sftphandle with hid=%d", i);
			/* Found a free slot. */
			h = session->sftp_handles[i] = xcalloc(1, sizeof(SftpHandle));
			memset(h, 0, sizeof(SftpHandle));
			return(i);
		}
	if (found < 0) {
		/* There are no free slots.  Take last+1 slot and expand the array.  */
		found = session->sftp_handles_alloc;
		if (session->sftp_handles_alloc > 10000)
			fatal("susshi_alloc_new_sftphandle: internal error: sftp_handles_alloc %d "
						  "too big", session->sftp_handles_alloc);
		session->sftp_handles = xrealloc(session->sftp_handles, session->sftp_handles_alloc + 10,
								   sizeof(SftpHandle *));
		session->sftp_handles_alloc += 10;
		debug4(SUSSHI_LOG "susshi_alloc_new_sftprequest: expanding %d",  session->sftp_handles_alloc);
		for (i = found; i <  session->sftp_handles_alloc; i++)
			session->sftp_handles[i] = NULL;
	}

	h = session->sftp_handles[found] = xcalloc(1, sizeof(SftpHandle));
	memset(h, 0, sizeof(SftpHandle));

	debug4(SUSSHI_LOG "Allocated sftphandle with hid=%d", found);
	return(found);
}


/*!
 * @brief       Free SFTP Handle object
 *
 * @param       cid     SusshiChannel ID
 * @param       hid     Handle ID
 */

static void
susshi_free_sftphandle(int cid, uint32_t hid) {
	SftpSession *session;
	SftpHandle *h;

	session = susshi_session.channels[cid]->sftp_session;

	if (hid <= session->sftp_handles_alloc && session->sftp_handles[hid] != NULL)
	{
		h = session->sftp_handles[hid];

		debug4(SUSSHI_LOG "Removed sftphandle %s with hid=%d", h->handle, hid);

		if (h->path) SSH_STRING_FREE(h->path);
		// Free memory for SftpRequest
		memset(h, 0, sizeof(SftpHandle));
		xfree(h);
		session->sftp_handles[hid]=NULL;
	}
}


/*!
 * @brief       Find SFTP Handle object
 *
 * @param       cid     SusshiChannel ID
 * @param       handle  Handle string
 *
 * @return      Handle ID
 */

static int
susshi_find_sftphandle(int cid, const char *handle) {
	SftpSession *session;
	uint32_t i;

	session = susshi_session.channels[cid]->sftp_session;

	for(i = 0; i < session->sftp_handles_alloc; i++)
	{
		// Skip free sftp_requests
		if (session->sftp_handles[i] == NULL)
			continue;

		if (strcmp(session->sftp_handles[i]->handle, handle) == 0)
			return(i);
	}
	return -1;
}


/*!
 * @brief       Show SFTP Handle objects
 *
 * @param       cid     SusshiChannel ID
 */

void
susshi_show_sftphandles(int cid) {
	SftpSession *session;
	uint32_t i;

	session = susshi_session.channels[cid]->sftp_session;

	for(i = 0; i < session->sftp_handles_alloc; i++)
	{
		// Skip free sftp_requests
		if (session->sftp_handles[i] == NULL)
			continue;

		debug4("Filehandle[%d]: request_id=%d, handle=%s, path=%s",
			   i, session->sftp_handles[i]->request_id, session->sftp_handles[i]->handle,
			   ssh_string_get_char(session->sftp_handles[i]->path));
	}
}

/*!
 * @brief       Inspect SFTP DATA message
 *
 * From susshi_inspect_data() we get a "string" in buffer.
 *
 * ### RFC 4254 - 5.2. Data Transfer
 *
 * ```
 * byte      SSH_MSG_CHANNEL_DATA   // Read by susshi_inspect_data  (type 94)
 * uint32    recipient channel      // Read by susshi_inspect_data
 * string    data                   // We are at position here (right before string)
 * ```
 *
 * So we read on with the string, but not as string ...
 *
 * Data (after the 4 bytes "string length") is:
 *
 * ```
 * uint32             length
 * byte               type
 * byte[length - 1]   data payload
 * ```
 *
 * The Packet stream:
 *
 * This function gets called on every new SSH packet:
 *
 * ```
 *  xxxx SSH packet 1 xxxxxxxx|xxxxxx SSH packet 2 xxxxxx|xxxxx SSH packet 3 xxxxxxx|xxxxxx SSH packet 4 xxxxxxxxx
 *  (######################### SFTP Message 1 ################################)|(####### SFTP Message 2 #####) ....
 *  NEW                        INCOMPLETE                 INCOMPLETE   COMPLETE|NEW  INCOMPLETE
 *  /---------------------- msg->length --------------------------------------/
 *  /---------------------- msg->received ---------------/ --> -->            /
 *  /------ take_bytes ------/
 * ```
 *
 * @param       sftp_session    SFTP session
 * @param       side            The side of the sender
 * @param       buffer_copy     Copy of the actual ssh_buffer
 */

void
susshi_inspect_sftp_packet(SftpSession *sftp_session, Side side, ssh_buffer buffer_copy) {
	// SusshiChannel *c;
	SftpMessage *msg;           // Pointer to the SFTP message we write the data to
	uint32_t msg_len;           // Overall length of the SFTP Message / Packet
	uint32_t datalen;           // Data length in the SSH Packet Buffer buffer_copy
	uint32_t take_bytes = 0;    // how many bytes do we take on this round from the buffer
	uint32_t copy_bytes;
	uint8_t type;
	int rc;
	ssh_string ext_name;
	ssh_string ext_data;

	debug4_dir(side, TheOtherSide(side), "####################### SFTP PACKET ###########################");

	// susshi_hexdump_ssh_buffer(buffer_copy);

	if (ssh_buffer_get_len(buffer_copy) == 0)
		return;

	/* Overall length of the SSH Packet we just received */
	if (ssh_buffer_unpack(buffer_copy, "d", &datalen) != SSH_OK)
		goto decode_error;

	if (sftp_session->target_version == 0) {
		/* This is the first time we get called and thus we know that this must be a SSH_FXP_VERSION MESSAGE from target. */
		if (ssh_buffer_unpack(buffer_copy, "dbd", &msg_len, &type, &sftp_session->target_version) != SSH_OK)
			fatal("Decode error in SSH_FXP_INIT.");

		if (type == SSH_FXP_VERSION) {
			log_sftp(sftp_session->susshi_channel->cid, -1, TARGET, CLIENT, "Server version is %u", sftp_session->target_version);
			debug3_dir(TARGET, CLIENT, "Target SFTP Version Response - Server version is %u", sftp_session->target_version);

			/*
			 * Client will choose from highest server version it supports also.
			 * The client may renegotiate with SSH_FXP_EXTENDED "version-select" request later
			 */
			if (sftp_session->client_version > sftp_session->target_version) {
				sftp_session->client_version = sftp_session->target_version;
			}

			rc = SSH_OK;

			while (ssh_buffer_get_len(buffer_copy) > 0 && rc == SSH_OK) {
				rc = ssh_buffer_unpack(buffer_copy, "SS", &ext_name, &ext_data);

				if (rc == SSH_OK) {
					log_sftp(sftp_session->susshi_channel->cid, -1, TARGET, CLIENT,
							 "SFTP Server extension: \"%s\" revision %s", ssh_string_get_char(ext_name),
							 ssh_string_get_char(ext_data));

					SSH_STRING_FREE(ext_name);
					SSH_STRING_FREE(ext_data);
				} else {
					break;
				}
			}
			return;
		} else {
			fatal("Received SFTP Response but wasn't FXP_VERSION.");
		}
	}

	// c = sftp_session->susshi_channel;

	if (side == CLIENT) {
		msg = &sftp_session->sftp_client_message;
	} else {
		msg = &sftp_session->sftp_target_message;
	}

	state_changed:

	switch(msg->state) {
		case INIT:
			take_bytes = MIN(ssh_buffer_get_len(buffer_copy), 5 - ssh_buffer_get_len(msg->header));
			// debug4_dir(side, TheOtherSide(side), "INIT: Take %u bytes SFTP data and put it in the header buffer", take_bytes);
			if (take_bytes > 0) {
				ssh_buffer_add_data(msg->header, ssh_buffer_get(buffer_copy), take_bytes);
				/* Adjust buffer position */
				ssh_buffer_pass_bytes(buffer_copy, take_bytes);
			}

			if (ssh_buffer_get_len(msg->header) == 5) {
				msg->state = NEW;
				goto state_changed;
			}
			break;

		case NEW:
			if (ssh_buffer_unpack(msg->header, "db", &msg->length, &msg->type) != SSH_OK)
				goto decode_error;

			/* Reduce datalen by number of bytes we have already consumed */
			datalen -= 5;

			/* Type field is also counted into data area */
			msg->length--;

			// debug4_dir(side, TheOtherSide(side), "SFTP message: datalen=%u, msg->length=%u, msg-type=%d, buffer=%u",
			//            datalen, msg->length, msg->type, ssh_buffer_get_len(buffer_copy));
			// susshi_hexdump_ssh_buffer(buffer_copy);

			take_bytes = MIN(ssh_buffer_get_len(buffer_copy), msg->length);
			msg->received += take_bytes;

			// debug4_dir(side, TheOtherSide(side), "Take %u bytes SFTP data", take_bytes);
			// debug4_dir(side, TheOtherSide(side), "Received %u bytes SFTP data", take_bytes);

			switch (msg->type) {
				case SSH_FXP_WRITE:
					/* Copy at least the first 272 bytes for later interpretation */
					copy_bytes = MIN(take_bytes, 272);
					ssh_buffer_add_data(msg->buffer, ssh_buffer_get(buffer_copy), copy_bytes);
					// debug4("SFTP: SSH_FXP_WRITE: Copy only up to 272 bytes of data for inspection (%d taken)", copy_bytes);
					break;

				case SSH_FXP_DATA:
					/* Copy at least the first 8 bytes for later interpretation */
					copy_bytes = MIN(take_bytes, 8);
					ssh_buffer_add_data(msg->buffer, ssh_buffer_get(buffer_copy), copy_bytes);
					// debug4("SFTP: SSH_FXP_DATA: Copy only up to 8 bytes of data for inspection (%d taken)", copy_bytes);
					break;

				default:
					// debug4("SFTP: Type %d data: copy data for inspection", msg->type);
					if (!msg->buffer)
						msg->buffer = ssh_buffer_new();
					ssh_buffer_add_data(msg->buffer, ssh_buffer_get(buffer_copy), take_bytes);
			}

			/* Adjust buffer position */
			ssh_buffer_pass_bytes(buffer_copy, take_bytes);

			if (msg->length == msg->received) {
				msg->state = COMPLETE;
				goto state_changed;
			} else {
				msg->state = INCOMPLETE;
			}
			break;

		case INCOMPLETE:

			if (msg->received > msg->length)
				msg->received = msg->length;

			take_bytes = MIN(msg->length - msg->received, datalen);

			msg->received += take_bytes;

			// debug4_dir(side, TheOtherSide(side), "SFTP: (Cont.) Take %u bytes SFTP data", take_bytes);
			// debug4_dir(side, TheOtherSide(side), "SFTP: (Cont.) Received %u bytes SFTP data so far", msg->received);
			// susshi_hexdump(ssh_buffer_get(buffer_copy), take_bytes);

			switch (msg->type) {
				case SSH_FXP_WRITE:
					/* Have the at least 272 bytes been copied on the first round ? */
					copy_bytes=MIN(272 - ssh_buffer_get_len(msg->buffer), 272);
					if (copy_bytes > 0) {
						ssh_buffer_add_data(msg->buffer, ssh_buffer_get(buffer_copy), copy_bytes);
					}
					// debug4("SFTP: (Cont.) SSH_FXP_WRITE: Copy only up to 272 bytes of data for inspection (%d taken)", copy_bytes);
					break;

				case SSH_FXP_DATA:
					/* Copy at least the first 8 bytes for later interpretation */
					copy_bytes = MIN(8 - ssh_buffer_get_len(msg->buffer), 8);
					ssh_buffer_add_data(msg->buffer, ssh_buffer_get(buffer_copy), copy_bytes);
					// debug4("SFTP: (Cont.) SSH_FXP_DATA: Copy only up to 8 bytes of data for inspection (%d taken)", copy_bytes);
					break;

				default:
					// debug4("SFTP: (Cont.) Type %d data: copy data for inspection", msg->type);
					ssh_buffer_add_data(msg->buffer, ssh_buffer_get(buffer_copy), take_bytes);
			}

			/* Adjust buffer position */
			ssh_buffer_pass_bytes(buffer_copy, take_bytes);

			if (msg->received == msg->length) {
				msg->state = COMPLETE;
				goto state_changed;
			}
			break;

		case COMPLETE:

			// debug4_dir(side, TheOtherSide(side), "SFTP: (Complete) SFTP Message of type %d and payload length %u arrived", msg->type, msg->length);
			if (side == CLIENT)
				inspect_sftp_request(sftp_session);
			else
				inspect_sftp_response(sftp_session);

			/* Reinit message buffers */
			if (msg->buffer)
				ssh_buffer_reinit(msg->buffer);

			if (msg->header)
				ssh_buffer_reinit(msg->header);

			/* Reset struct */
			msg->state=INIT;
			msg->type=0;
			msg->id=0;
			msg->length=0;
			msg->received=0;

			// debug4_dir(side, TheOtherSide(side), "datalen: %u", datalen);
			// debug4_dir(side, TheOtherSide(side), "take_bytes: %u", take_bytes);
			// debug4_dir(side, TheOtherSide(side), "bytes still in buffer: %u", ssh_buffer_get_len(buffer_copy));

			if (ssh_buffer_get_len(buffer_copy) > 0) {
				// debug4_dir(side, TheOtherSide(side), "We have at least another SFTP message in buffer (%u bytes in buffer left). Play it again, Sam ...", ssh_buffer_get_len(buffer_copy));
				// susshi_hexdump_ssh_buffer(buffer_copy);
				goto state_changed;
			}
			break;

		default:
			fatal("SFTP message is in unknown state.");
	}

	return;

	decode_error:
	{
		fatal("SFTP message decoding returned with fatal error.");
	}
}


/*!
 * @brief        Inspect SFTP requests from Client
 * @param       sftp_session    SFTP session
 */

static void
inspect_sftp_request(SftpSession *sftp_session) {

	SftpMessage *msg;
	ssh_buffer buffer;
	SftpRequest *request;
	uint32_t buffer_len;
	int cid, rid, hid;
	u_int32_t id;
	char handle_hex[515];
	ssh_string handle_str = NULL, path_str = NULL, extens_str = NULL;
	uint32_t version;

	debug4_dir(CLIENT, TARGET, "----------------------- SFTP Request Message ------------------");

	cid = sftp_session->susshi_channel->cid;

	msg = &sftp_session->sftp_client_message;
	buffer = msg->buffer;

	version = sftp_session->client_version;
	// susshi_hexdump_ssh_buffer(buffer);

	if (ssh_buffer_get_len(buffer) == 0)
		return;

	if (ssh_buffer_unpack(buffer, "d", &id) != SSH_OK)
		goto decode_error;

	debug4_dir(CLIENT, TARGET, "Received SFTP Request with id %u", id);

	/* Alloc new sftp request */
	rid = susshi_alloc_new_sftprequest(cid);

	request = sftp_session->sftp_requests[rid];

	/* Store request ID and request type */
	request->id = id;
	request->type = msg->type;

	if_debug4()
		susshi_show_sftphandles(cid);

	debug4("Request id %d: Client CMD %d", request->id, request->type);

	buffer_len = ssh_buffer_get_len(buffer);

	// Select on SFTP client request
	switch (request->type) {

		case SSH_FXP_REALPATH:
		{
			/* Version 3:
			 * uint32     id
			 * string     path
			 *
			 * Version 6:
			 *
			 *  uint32   request-id
			 *  string   original-path [UTF-8]
			 *  byte     control-byte [optional]        (ignored)
			 *  string   compose-path[0..n] [optional]  (ignored)
			 */

			/* Extract path & store in request path field */
			if (ssh_buffer_unpack(buffer, "S", &request->path) != SSH_OK)
				goto buffer_underrun;

			log_sftp(cid, request->id, CLIENT, TARGET, "Canonicalize request for %s", ssh_string_get_char(request->path));
			break;
		}

		case SSH_FXP_OPENDIR:
		{
			/*
			 * uint32     id
			 * string     path
			 */

			/* Extract path & store in request path field */
			if (ssh_buffer_unpack(buffer, "S", &request->path) != SSH_OK)
				goto buffer_underrun;

			log_sftp(cid, request->id, CLIENT, TARGET, "Open directory %s", ssh_string_get_char(request->path));
			break;
		}

		case SSH_FXP_READDIR:
		{
			/*
			 * uint32     id
			 * string     handle
			 */

			if (ssh_buffer_unpack(buffer, "S", &handle_str)!= SSH_OK)
				goto buffer_underrun;

			data_to_hex(handle_hex, 514, ssh_string_data(handle_str), ssh_string_len(handle_str));

			if ((hid = susshi_find_sftphandle(cid, handle_hex)) != -1) {
				log_sftp(cid, request->id, CLIENT, TARGET, "Read directory %s", ssh_string_get_char(sftp_session->sftp_handles[hid]->path));
			} else {
				log_sftp(cid, request->id, CLIENT, TARGET, "ERROR! Client is referring to a handle not requested previously.");
			}
			break;
		}

		case SSH_FXP_OPEN:
		{
			/*
			 * Version 3-4:
			 * uint32        id
			 * string        filename
			 * uint32        pflags
			 * ATTRS         attrs
			 *
			 * Version >4:
			 * uint32        id
			 * string        filename
			 * uint32        desired-access
			 * uint32        flags
			 * ATTRS         attrs
			 */

			const char *flags_str = NULL;

			if (version > 4) {
				if (ssh_buffer_unpack(buffer, "Sdd", &request->path, &request->flags, &request->desired_access)!= SSH_OK)
					goto buffer_underrun;

				request->attributes = susshi_sftp_data_file_attr(cid, buffer, version);
				flags_str = susshi_sftp_flags_string(request);

				log_sftp(cid, request->id, CLIENT, TARGET, "Open file %s [%s, ace=0x%x] (%s)",
						 ssh_string_get_char(request->path), flags_str, request->desired_access,
						 request->attributes ? request->attributes : "No Attributes");

			} else {
				if (ssh_buffer_unpack(buffer, "Sd", &request->path, &request->flags)!= SSH_OK)
					goto buffer_underrun;

				request->attributes = susshi_sftp_data_file_attr(cid, buffer, version);
				flags_str = susshi_sftp_pflags_string(request);

				log_sftp(cid, request->id, CLIENT, TARGET, "Open file %s [%s] (%s)",
						 ssh_string_get_char(request->path), flags_str,
						 request->attributes ? request->attributes : "No Attributes");

			}

			if (flags_str) xfree((void *) flags_str);

			break;
		}

		case SSH_FXP_READ:
		{
			/*
			 * uint32     id
			 * string     handle
			 * uint64     offset
			 * uint32     len
			 */
			uint64_t offset;
			uint32_t len;

			if (ssh_buffer_unpack(buffer, "Sqd", &handle_str, &offset, &len)!= SSH_OK)
				goto buffer_underrun;

			data_to_hex(handle_hex, 514, ssh_string_data(handle_str), ssh_string_len(handle_str));

			if ((hid = susshi_find_sftphandle(cid, handle_hex)) != -1) {
				sftp_session->sftp_handles[hid]->request_type = SSH_FXP_READ;
				sftp_session->sftp_handles[hid]->request_id = request->id;
				request->hid = hid;
				log_sftp(cid, request->id, CLIENT, TARGET, "Read file %s (%u bytes @ offset %lu)",
						 ssh_string_get_char(sftp_session->sftp_handles[hid]->path), len, offset);
			}
			break;
		}

		case SSH_FXP_WRITE:
		{
			/*
			 * uint32     id
			 * string     handle        # up to 256 bytes data
			 * uint64     offset
			 * string     data
			 */
			uint64_t offset;
			uint32_t len;

			if (ssh_buffer_unpack(buffer, "Sqd", &handle_str, &offset, &len)!= SSH_OK)
				goto buffer_underrun;

			data_to_hex(handle_hex, 514, ssh_string_data(handle_str), ssh_string_len(handle_str));

			if ((hid = susshi_find_sftphandle(cid, handle_hex)) != -1) {
				sftp_session->sftp_handles[hid]->request_type = SSH_FXP_WRITE;
				sftp_session->sftp_handles[hid]->request_id = request->id;
				request->hid = hid;
				log_sftp(cid, request->id, CLIENT, TARGET, "Writing to file %s (%u bytes @ offset %lu)",
						 ssh_string_get_char(sftp_session->sftp_handles[hid]->path), len, offset);
				susshi_report.sftp_bytes_written += len;
				sftp_session->sftp_handles[hid]->filesize += len;
			}
			break;
		}

		case SSH_FXP_CLOSE:
		{
			/*
			 * uint32     id
			 * string     handle
			 */

			/* This seems to be used by e.g. ForkLift for Keep-Alive ??? */
			if (buffer_len == 0)
				break;

			if (ssh_buffer_unpack(buffer, "S", &handle_str)!= SSH_OK)
				goto buffer_underrun;

			data_to_hex(handle_hex, 514, ssh_string_data(handle_str), ssh_string_len(handle_str));

			if ((hid = susshi_find_sftphandle(cid, handle_hex)) != -1) {
				log_sftp(cid, request->id, CLIENT, TARGET, "Close %s",
						 ssh_string_get_char(sftp_session->sftp_handles[hid]->path));

				if (sftp_session->sftp_handles[hid]->filesize) {
					switch(sftp_session->sftp_handles[hid]->request_type) {
						case SSH_FXP_WRITE:
							log_sftp(cid, request->id, CLIENT, TARGET, "%lu bytes written to %s",
									 sftp_session->sftp_handles[hid]->filesize,
									 ssh_string_get_char(sftp_session->sftp_handles[hid]->path));
							break;
					}
				}
				susshi_free_sftphandle(cid, hid);
			}
			break;
		}

		case SSH_FXP_REMOVE:
		{
			/*
			 * uint32     id
			 * string     filename
			 */

			if (ssh_buffer_unpack(buffer, "S", &path_str)!= SSH_OK)
				goto buffer_underrun;

			log_sftp(cid, request->id, CLIENT, TARGET, "Remove file %s",
					 ssh_string_get_char(path_str));
			break;
		}

		case SSH_FXP_MKDIR:
		{
			/*
			 * uint32     id
			 * string     path
			 * ATTRS      attrs
			 */
			const char *file_attr = NULL;

			if (ssh_buffer_unpack(buffer, "S", &path_str)!= SSH_OK)
				goto buffer_underrun;

			file_attr = susshi_sftp_data_file_attr(cid, buffer, version);

			log_sftp(cid, request->id, CLIENT, TARGET, "Make directory %s (%s)",
					 ssh_string_get_char(path_str), file_attr);

			if (file_attr != NULL) xfree((void *) file_attr);
			break;
		}

		case SSH_FXP_RMDIR:
		{
			/*
			 * uint32     id
			 * string     path
			 */

			if (ssh_buffer_unpack(buffer, "S", &path_str)!= SSH_OK)
				goto buffer_underrun;

			log_sftp(cid, request->id, CLIENT, TARGET, "Remove directory %s",
					 ssh_string_get_char(path_str));
			break;
		}

		case SSH_FXP_RENAME:
		{
			/*
			 * uint32     id
			 * string     oldpath
			 * string     newpath
			 * uint32     flags    (ignored)
			 */
			ssh_string new_path_str = NULL;

			if (ssh_buffer_unpack(buffer, "SS", &path_str, &new_path_str)!= SSH_OK)
				goto buffer_underrun;

			log_sftp(cid, request->id, CLIENT, TARGET, "Rename %s to %s",
					 ssh_string_get_char(path_str), ssh_string_get_char(new_path_str));

			if (new_path_str) SSH_STRING_FREE(new_path_str);
			break;
		}

		case SSH_FXP_READLINK:
		{
			/*
			 * uint32     id
			 * string     path
			 */

			if (ssh_buffer_unpack(buffer, "S", &path_str)!= SSH_OK)
				goto buffer_underrun;

			log_sftp(cid, request->id, CLIENT, TARGET, "Resolve link %s",
					 ssh_string_get_char(path_str));
			break;
		}

		case SSH_FXP_SYMLINK:
		{
			/*
			 * uint32     id
			 * string     linkpath
			 * string     targetpath
			 */
			ssh_string target_path_str = NULL;

			if (ssh_get_openssh_version(susshi_session.target_session)) {
				/*
				 * When OpenSSH's sftp-server was implemented, the order of the arguments
				 * to the SSH_FXP_SYMLINK method was inadvertently reversed. Unfortunately,
				 * the reversal was not noticed until the server was widely deployed. Since
				 * fixing this to follow the specification would cause incompatibility, the
				 * current order was retained. For correct operation, clients should send
				 * SSH_FXP_SYMLINK as follows:
				 *
				 * 	uint32		id
				 *	string		targetpath
				 *	string		linkpath
				 */

				if (ssh_buffer_unpack(buffer, "SS", &target_path_str, &path_str)!= SSH_OK)
					goto buffer_underrun;
			} else {
				/*
				 * Order as specified in draft (https://www.openssh.com/txt/draft-ietf-secsh-filexfer-02.txt)
				 *
				 * uint32     id
				 * string     linkpath
				 * string     targetpath
				 */

				if (ssh_buffer_unpack(buffer, "SS", &path_str, &target_path_str)!= SSH_OK)
					goto buffer_underrun;
			}

			log_sftp(cid, request->id, CLIENT, TARGET, "Link %s to %s",
					 ssh_string_get_char(path_str), ssh_string_get_char(target_path_str));

			SSH_STRING_FREE(target_path_str);
			break;
		}

		case SSH_FXP_STAT:
		case SSH_FXP_LSTAT:
		{
			/*
			 * uint32     id
			 * string     path
			 */

			if (ssh_buffer_unpack(buffer, "S", &path_str)!= SSH_OK)
				goto buffer_underrun;

			log_sftp(cid, request->id, CLIENT, TARGET, "Request attributes for %s",
					 ssh_string_get_char(path_str));
			break;
		}

		case SSH_FXP_FSTAT:
		{
			/*
			 * uint32     id
			 * string     handle
			 */

			if (ssh_buffer_unpack(buffer, "S", &handle_str)!= SSH_OK)
				goto buffer_underrun;

			data_to_hex(handle_hex, 514, ssh_string_data(handle_str), ssh_string_len(handle_str));

			if ((hid = susshi_find_sftphandle(cid, handle_hex)) != -1) {
				log_sftp(cid, request->id, CLIENT, TARGET, "Request attributes for %s",
						 ssh_string_get_char(sftp_session->sftp_handles[hid]->path));
				// susshi_free_sftphandle(cid, hid);  <-- Not sure, why we've closed the sftphandle in the past
			}
			break;
		}

		case SSH_FXP_SETSTAT:
		{
			/*
			 * uint32     id
			 * string     path
			 * ATTRS      attrs
			 */
			const char *file_attr = NULL;

			if (ssh_buffer_unpack(buffer, "S", &path_str)!= SSH_OK)
				goto buffer_underrun;

			file_attr = susshi_sftp_data_file_attr(cid, buffer, version);

			log_sftp(cid, request->id, CLIENT, TARGET, "Set attributes of %s to %s",
					 ssh_string_get_char(path_str), file_attr);

			if (file_attr != NULL) xfree((void *) file_attr);
			break;
		}

		case SSH_FXP_FSETSTAT:
		{
			/*
			 * uint32     id
			 * string     handle
			 * ATTRS      attrs
			 */
			const char *file_attr = NULL;

			if (ssh_buffer_unpack(buffer, "S", &handle_str)!= SSH_OK)
				goto buffer_underrun;

			file_attr = susshi_sftp_data_file_attr(cid, buffer, version);
			data_to_hex(handle_hex, 514, ssh_string_data(handle_str), ssh_string_len(handle_str));

			if ((hid = susshi_find_sftphandle(cid, handle_hex)) != -1) {
				log_sftp(cid, request->id, CLIENT, TARGET, "Set attributes for %s to %s",
						 ssh_string_get_char(sftp_session->sftp_handles[hid]->path), file_attr);
				// susshi_free_sftphandle(cid, hid);  <-- Not sure, why we've closed the sftphandle in the past
			}

			if (file_attr != NULL) xfree((void *) file_attr);
			break;
		}

		case SSH_FXP_EXTENDED:
		{
			/*
			 * For openSSH Extensions see https://anongit.mindrot.org/openssh.git/plain/PROTOCOL
			 */

			if (ssh_buffer_unpack(buffer, "S", &extens_str)!= SSH_OK)
				goto buffer_underrun;

			log_sftp(cid, request->id, CLIENT, TARGET, "Extension Request '%s'",
					 ssh_string_get_char(extens_str));

			if (strcmp(ssh_string_get_char(extens_str), "version-select") == 0) {

				/*
				 * uint32       id
				 * string       "version-select"
				 * string       version-from-list
				 */

				ssh_string new_version = NULL;

				ssh_buffer_unpack(buffer, "S", &new_version);
				{
					const char *errstr;
					long long v = strtonum(ssh_string_get_char(new_version), 0, INT_MAX, &errstr);
					version = errstr ? 0 : (int)v;
				}
				if (version < 3)
					version = 3;

				log_sftp(cid, request->id, CLIENT, TARGET, "Version re-negotiation to %s [%d]",
						ssh_string_get_char(new_version), version);

				sftp_session->client_version = version;
				sftp_session->target_version = version;

				SSH_STRING_FREE(new_version);

			} else if (strcmp(ssh_string_get_char(extens_str), "posix-rename@openssh.com") == 0) {

				/*
				 * uint32		id
				 * string		"posix-rename@openssh.com"
				 * string		oldpath
				 * string		newpath
				 */

				ssh_string target_path_str = NULL;

				if (ssh_buffer_unpack(buffer, "SS", &path_str, &target_path_str)!= SSH_OK)
					goto buffer_underrun;

				log_sftp(cid, request->id, CLIENT, TARGET, "Rename %s into %s",
						 ssh_string_get_char(path_str), ssh_string_get_char(target_path_str));

				SSH_STRING_FREE(target_path_str);

			} else if (strcmp(ssh_string_get_char(extens_str), "statvfs@openssh.com") == 0) {

				/*
				 * uint32		id
				 * string		"statvfs@openssh.com"
				 * string		path
				 */

				if (ssh_buffer_unpack(buffer, "S", &path_str)!= SSH_OK)
					goto buffer_underrun;

				log_sftp(cid, request->id, CLIENT, TARGET, "Retrieve file system information (statvfs) for %s",
						 ssh_string_get_char(path_str));

			} else if (strcmp(ssh_string_get_char(extens_str), "fstatvfs@openssh.com") == 0) {

				/*
				 * uint32		id
				 * string		"fstatvfs@openssh.com"
				 * string		handle
				 */

				if (ssh_buffer_unpack(buffer, "S", &handle_str)!= SSH_OK)
					goto buffer_underrun;

				data_to_hex(handle_hex, 514, ssh_string_data(handle_str), ssh_string_len(handle_str));

				if ((hid = susshi_find_sftphandle(cid, handle_hex)) != -1) {
					log_sftp(cid, request->id, CLIENT, TARGET, "Retrieve file system information (fstatvfs) for %s",
							 ssh_string_get_char(sftp_session->sftp_handles[hid]->path));
				}

			} else if (strcmp(ssh_string_get_char(extens_str), "hardlink@openssh.com") == 0) {

				/*
				 * uint32		id
				 * string		"hardlink@openssh.com"
				 * string		oldpath
				 * string		newpath
				 */

				ssh_string target_path_str = NULL;

				if (ssh_buffer_unpack(buffer, "SS", &path_str, &target_path_str)!= SSH_OK)
					goto buffer_underrun;

				log_sftp(cid, request->id, CLIENT, TARGET, "Hardlink %s to %s",
						 ssh_string_get_char(path_str), ssh_string_get_char(target_path_str));

				SSH_STRING_FREE(target_path_str);


			} else if (strcmp(ssh_string_get_char(extens_str), "fsync@openssh.com") == 0) {

				/*
				 * uint32		id
				 * string		"fsync@openssh.com"
				 * string		handle
				 */

				if (ssh_buffer_unpack(buffer, "S", &handle_str)!= SSH_OK)
					goto buffer_underrun;

				data_to_hex(handle_hex, 514, ssh_string_data(handle_str), ssh_string_len(handle_str));

				if ((hid = susshi_find_sftphandle(cid, handle_hex)) != -1) {
					log_sftp(cid, request->id, CLIENT, TARGET, "Call fsync on %s",
							 ssh_string_get_char(sftp_session->sftp_handles[hid]->path));
				}
			} else if (strcmp(ssh_string_get_char(extens_str), "expand-path@openssh.com") == 0) {

				/*
				 * uint32		id
				 * string		"expand-path@openssh.com
				 * string		path
				 */

				if (ssh_buffer_unpack(buffer, "S", &path_str)!= SSH_OK)
					goto buffer_underrun;

				log_sftp(cid, request->id, CLIENT, TARGET, "Expand Path request for %s",
						 ssh_string_get_char(path_str));

			} else if (strcmp(ssh_string_get_char(extens_str), "filename-charset") == 0) {

				/*
				 * uint32		id
				 * string		"filename-charset"
				 * string		charset-name
				 */

				ssh_string name = NULL;

				if (ssh_buffer_unpack(buffer, "S", &name)!= SSH_OK)
					goto buffer_underrun;

				log_sftp(cid, request->id, CLIENT, TARGET, "File name encoding set to %s", ssh_string_get_char(name));

				SSH_STRING_FREE(name);
			} else if (strcmp(ssh_string_get_char(extens_str), "filename-translation-control") == 0) {

				/*
				 * uint32		id
				 * string		"filename-translation-control"
				 * bool         do-translate
				 */

				char translate;

				if (ssh_buffer_unpack(buffer, "b", &translate)!= SSH_OK)
					goto buffer_underrun;

				log_sftp(cid, request->id, CLIENT, TARGET, "File name translation set %s",
						 translate == 0 ? "OFF" : "ON");
			} else if (strcmp(ssh_string_get_char(extens_str), "text-seek") == 0) {

				uint64_t line_num;
				/*
				 * uint32		id
				 * string		"text-seek"
				 * string		file-handle
				 * uint64       line-number
				 */

				if (ssh_buffer_unpack(buffer, "Sq", &handle_str, &line_num)!= SSH_OK)
					goto buffer_underrun;

				data_to_hex(handle_hex, 514, ssh_string_data(handle_str), ssh_string_len(handle_str));

				if ((hid = susshi_find_sftphandle(cid, handle_hex)) != -1) {
					log_sftp(cid, request->id, CLIENT, TARGET, "Text seek on %s to line-number %ld",
							 ssh_string_get_char(sftp_session->sftp_handles[hid]->path), line_num);
				}

			}
			break;
		}

		/* Version 6 */
		case SSH_FXP_LINK:
		{
			/*
			 * uint32     request-id
			 * string     linkpath
			 * string     targetpath
			 * bool       sym-link
			 */
			ssh_string target_path_str = NULL;
			char sym_link;

			if (ssh_buffer_unpack(buffer, "SSb", &path_str, &target_path_str, &sym_link)!= SSH_OK)
				goto buffer_underrun;

			log_sftp(cid, request->id, CLIENT, TARGET, "%s %s to %s",
					 sym_link == 1 ? "Symlink" : "Link",
					 ssh_string_get_char(path_str), ssh_string_get_char(target_path_str));

			SSH_STRING_FREE(target_path_str);
			break;
		}

		case SSH_FXP_BLOCK:
		{
			/*
			 * uint32    request-id
			 * string    handle
			 * uint64    offset
			 * uint64    length
			 * uint32    uLockMask
			 */
			uint64_t offset, length;
			uint32_t mask;

			if (ssh_buffer_unpack(buffer, "Sqqd", &handle_str, &offset, &length, &mask)!= SSH_OK)
				goto buffer_underrun;

			data_to_hex(handle_hex, 514, ssh_string_data(handle_str), ssh_string_len(handle_str));

			if ((hid = susshi_find_sftphandle(cid, handle_hex)) != -1) {
				log_sftp(cid, request->id, CLIENT, TARGET, "Byte-Range lock on %s on offset %ld with length %ld (mask 0x%x)",
						 ssh_string_get_char(sftp_session->sftp_handles[hid]->path), offset, length, mask);
			}

			break;
		}

		case SSH_FXP_UNBLOCK:
		{
			/*
			 * uint32    request-id
			 * string    handle
			 * uint64    offset
			 * uint64    length
			 * uint32    uLockMask
			 */
			uint64_t offset, length;

			if (ssh_buffer_unpack(buffer, "Sqqd", &handle_str, &offset, &length)!= SSH_OK)
				goto buffer_underrun;

			data_to_hex(handle_hex, 514, ssh_string_data(handle_str), ssh_string_len(handle_str));

			if ((hid = susshi_find_sftphandle(cid, handle_hex)) != -1) {
				log_sftp(cid, request->id, CLIENT, TARGET, "Byte-Range unlock on %s on offset %ld with length %ld",
						 ssh_string_get_char(sftp_session->sftp_handles[hid]->path), offset, length);
			}

			break;
		}

	}

	if (handle_str) SSH_STRING_FREE(handle_str);
	if (path_str) SSH_STRING_FREE(path_str);
	if (extens_str) SSH_STRING_FREE(extens_str);

	return;

	buffer_underrun:
	{
		log_sftp(cid, request->id, CLIENT, TARGET,  "SUSSHI-ERROR: buffer under-run on command %d. Only %d bytes in buffer", request->id, buffer_len);
		return;
	}

	decode_error:
	{
		log_sftp(cid, 0, CLIENT, TARGET, "SFTP request packet decoding returned with error");
	}
}


/*!
 * @brief       Inspect SFTP responses from Target
 *
 * @param       sftp_session    SFTP session
 */

static void
inspect_sftp_response(SftpSession *sftp_session) {

	ssh_buffer buffer;
	SftpRequest *request;
	SftpMessage *msg;
	int cid, rid, hid;
	u_int32_t id;
	ssh_string path_str = NULL, handle_str = NULL;
	uint32_t version;

	cid = sftp_session->susshi_channel->cid;
	msg = &sftp_session->sftp_target_message;
	buffer = msg->buffer;
	version = sftp_session->target_version;

	debug4_dir(TARGET, CLIENT, "----------------------- SFTP Response Message -----------------");
	// susshi_hexdump_ssh_buffer(buffer);

	if (ssh_buffer_get_len(buffer) == 0)
		return;

	if (ssh_buffer_unpack(buffer, "d", &id) != SSH_OK)
		goto decode_error;

	if ((rid = susshi_find_sftprequest(cid, id)) != -1) {
		request = sftp_session->sftp_requests[rid];
		request->sftp_target_type = msg->type;

		debug4("Request id %d: Client CMD %d -> Response CMD %d (Size: %d)", request->id, request->type,
				request->sftp_target_type, ssh_buffer_get_len(buffer));

		/* Request completed (Request sent and Response received) */
		if (request->type > 0 && request->sftp_target_type > 0) {

			/* Select on SFTP client request */
			switch (request->sftp_target_type) {

				case SSH_FXP_STATUS:
				{
					/*
					 * uint32     id
					 * uint32     error/status code
					 * string     error message (ISO-10646 UTF-8 [RFC-2279])
					 * string     language tag (as defined in [RFC-1766])
					 */
					{
						uint32_t status_code;
						ssh_string error_message = NULL;

						if (ssh_buffer_unpack(buffer, "d", &status_code)!= SSH_OK)
							goto buffer_underrun;

						switch(status_code) {
							case SSH_FX_OK:
								if ((request->type != SSH_FXP_READ) && (request->type != SSH_FXP_WRITE))
									log_sftp(cid, request->id, TARGET, CLIENT, "Request successful");
								break;

							case SSH_FX_EOF:
								switch (request->type) {
									case SSH_FXP_READ:
										log_sftp(cid, request->id, TARGET, CLIENT, "End of file");
										break;
									case SSH_FXP_READDIR:
										log_sftp(cid, request->id, TARGET, CLIENT, "End of listing");
										break;
									default:
										log_sftp(cid, request->id, TARGET, CLIENT, "End of file / listing");
								}
								break;

							default:
								if (ssh_buffer_unpack(buffer, "S", &error_message)!= SSH_OK)
									goto buffer_underrun;

								if (status_code < sizeof(SftpStatusString)) {
									log_sftp(cid, request->id, TARGET, CLIENT, "Request failed. %s - Received '%s'", SftpStatusString[status_code], ssh_string_get_char(error_message));
								} else {
									log_sftp(cid, request->id, TARGET, CLIENT, "Request failed. Unknown status code - Received '%s'", ssh_string_get_char(error_message));
								}
								SSH_STRING_FREE(error_message);
						}

						if (request->type == SSH_FXP_READ) {

							hid = request->hid;
							if ((sftp_session->sftp_handles[hid]) && (sftp_session->sftp_handles[hid]->filesize)) {
								log_sftp(cid, request->id, TARGET, CLIENT, "%lu bytes read from %s",
										 sftp_session->sftp_handles[hid]->filesize,
										 ssh_string_get_char(sftp_session->sftp_handles[hid]->path));
								susshi_free_sftphandle(cid, hid);
							}
						}
					}
					break;
				}

				case SSH_FXP_NAME:
				{
					/* Version up to 3:
					 * uint32     id
					 * uint32     count
					 * repeats count times:
					 *      string     filename
					 *      string     longname
					 *      ATTRS      attrs
					 *
					 * Version > 4:
					 *
					 * uint32     id
					 * byte   SSH_FXP_NAME
					 * uint32 request-id
					 * uint32 count
					 * repeats count times:
					 *      string     filename [UTF-8]
					 *      ATTRS      attrs
					 * bool end-of-list [optional] (ignored)
					 */

					uint32_t count;
					const char *file_attr = NULL;

					if (ssh_buffer_unpack(buffer, "d", &count)!= SSH_OK)
						goto buffer_underrun;

					if (count == 1) {

						if (version > 3) {
							if (ssh_buffer_unpack(buffer, "S", &path_str)!= SSH_OK)
								goto buffer_underrun;

						} else {
							ssh_string longname_str = NULL;
							if (ssh_buffer_unpack(buffer, "SS", &path_str, &longname_str)!= SSH_OK)
								goto buffer_underrun;

							if (longname_str != NULL) SSH_STRING_FREE(longname_str);
						}

						log_sftp(cid, request->id, TARGET, CLIENT, "Result: %s", ssh_string_get_char(path_str));
						if ((file_attr = susshi_sftp_data_file_attr(cid, buffer, version)) != NULL) {
							log_sftp(cid, request->id, TARGET, CLIENT, "        %s", file_attr);
							xfree((void *) file_attr);
						}
					} else {
						for (uint32_t i = 0; i < count; i++) {

							if (version > 3) {
								if (ssh_buffer_unpack(buffer, "S", &path_str)!= SSH_OK)
									goto buffer_underrun;

							} else {
								ssh_string longname_str = NULL;
								if (ssh_buffer_unpack(buffer, "SS", &path_str, &longname_str)!= SSH_OK)
									goto buffer_underrun;

								if (longname_str != NULL) SSH_STRING_FREE(longname_str);
							}
							file_attr = susshi_sftp_data_file_attr(cid, buffer, version);
							log_sftp(cid, request->id, TARGET, CLIENT, "    %-32s\t(%s)", ssh_string_get_char(path_str), file_attr);
							if (path_str != NULL) {
								SSH_STRING_FREE(path_str);
								path_str = NULL;
							}
							if (file_attr != NULL) xfree((void *) file_attr);
						}
					}
					break;
				}

				case SSH_FXP_HANDLE:
				{
					/*
					 * uint32     id
					 * string     handle
					 */

					/* Extract handle */
					if (ssh_buffer_unpack(buffer, "S", &handle_str)!= SSH_OK)
						goto buffer_underrun;

					if (request->path) {
						/* Allocate handle */
						hid = susshi_alloc_new_sftphandle(cid);
						sftp_session->sftp_handles[hid]->request_id = request->id;
						sftp_session->sftp_handles[hid]->path = ssh_string_copy(request->path);

						data_to_hex(sftp_session->sftp_handles[hid]->handle, 514, ssh_string_data(handle_str),
									ssh_string_len(handle_str));

						log_sftp(cid, request->id, TARGET, CLIENT, "Received handle for %s: %s",
								 ssh_string_get_char(request->path), sftp_session->sftp_handles[hid]->handle);
					} else {
						log_sftp(cid, request->id, TARGET, CLIENT, "ERROR! Received Handle without requested path before.");
					}
					break;
				}

				case SSH_FXP_ATTRS:
				{
					/*
					 * uint32     id
					 * ATTRS      attrs
					 */
					const char *file_attr = NULL;

					file_attr = susshi_sftp_data_file_attr(cid, buffer, version);
					log_sftp(cid, request->id, TARGET, CLIENT, "Received attributes: %s", file_attr);

					if (file_attr != NULL) xfree((void *) file_attr);
					break;
				}

				case SSH_FXP_DATA:
				{
					/*
					 * Version 3:
					 * uint32     id
					 * string     data
					 *
					 * Version 6:
					 * uint32     request-id
					 * string     data
					 * bool       end-of-file [optional] (ignored)
					 */
					uint32_t count;

					if (ssh_buffer_unpack(buffer, "d", &count)!= SSH_OK)
						goto buffer_underrun;


					/* Account data in Handle */
					sftp_session->sftp_handles[request->hid]->filesize += count;
					susshi_report.sftp_bytes_read += count;
					break;
				}

				case SSH_FX_OP_UNSUPPORTED:
				{
					log_sftp(cid, request->id, TARGET, CLIENT, "Request is not supported on target.");
					break;
				}

				case SSH_FXP_EXTENDED_REPLY:
				{
					log_sftp(cid, request->id, TARGET, CLIENT, "Vendor-Specific Extension Response.");
					break;
				}

				default:

					if_debug3() {
						debug3_dir(TARGET, CLIENT, "Unknown SFTP Response");
						do_susshi_hexdump_ssh_buffer(buffer);
					}
			}

			susshi_free_sftprequest(cid, rid);

			SSH_STRING_FREE(handle_str);
			SSH_STRING_FREE(path_str);

		} else {
			debug4("We should never have reached this ...");
		}

	} else {
		error("FATAL! Can't find request ID from previous request.");
	}

	return;

	buffer_underrun:
	{
		log_sftp(cid, request->id, CLIENT, TARGET,  "SUSSHI-ERROR: buffer under-run on command %d.", request->id);
		return;
	}

	decode_error:
	{
		log_sftp(cid, 0, CLIENT, TARGET, "SFTP response packet decoding returned with error");
	}
}


/*!
 * @brief       Convert given data into hexstring
 *
 * @param       buffer      Buffer
 * @param       buflen      Length of buffer
 * @param       data        Data
 * @param       datalen     Length of data
 */

void
data_to_hex(char *buffer, size_t buflen, u_char *data, size_t datalen) {
	size_t i, o=0;

	o = snprintf(buffer, buflen, "0x");
	if (o < 0 || (size_t)o >= buflen)
		return;

	for (i = 0; i < datalen && (o + i*2 + 3) <= buflen; i++)
		snprintf(&buffer[o + i*2], buflen - (o + i*2), "%02x", data[i]);
}

#define SSIZE 256


/*!
 * @brief       Generate Pflags string from request
 *
 * @param       request     Sftp Request
 *
 * @return      String
 */

static const char *
susshi_sftp_pflags_string(SftpRequest *request) {
	int num_flags = 6, f, o = 0;
	char *msgbuf;
	int flags[]=	{ SSH_FXF_READ, SSH_FXF_WRITE, SSH_FXF_APPEND, SSH_FXF_CREAT, SSH_FXF_TRUNC, SSH_FXF_EXCL, SSH_FXF_TEXT };
	const char *SftpPflagsString[] = {"read", "write", "append", "create", "truncate", "fail on exist", "text" };

	msgbuf = xmalloc(SSIZE);
	strncpy((char *) msgbuf, "", 1);

	for (f = 0; f < num_flags; f++) {
		if (request->flags & flags[f]) {
			o += snprintf((char *) &msgbuf[o], SSIZE - o, "%s%s", o>0 ? ", " : "", SftpPflagsString[f]);
		}
	}

	return((const char *) msgbuf);
}

#undef SSIZE

#define SSIZE 256


/*!
 * @brief       Generate Flags string from request
 *
 * @param       request     Sftp Request
 *
 * @return      String
 */

static const char *
susshi_sftp_flags_string(SftpRequest *request) {
	int num_flags = 6, f, o = 0;
	char *msgbuf;
	const char *dispo_str;
	int flags[]=	{ SSH_FXF_APPEND_DATA, SSH_FXF_APPEND_DATA_ATOMIC, SSH_FXF_TEXT_MODE, SSH_FXF_BLOCK_READ, SSH_FXF_BLOCK_WRITE,
					  SSH_FXF_BLOCK_DELETE, SSH_FXF_BLOCK_ADVISORY, SSH_FXF_NOFOLLOW, SSH_FXF_DELETE_ON_CLOSE, SSH_FXF_ACCESS_AUDIT_ALARM_INFO,
					  SSH_FXF_ACCESS_BACKUP, SSH_FXF_BACKUP_STREAM, SSH_FXF_OVERRIDE_OWNER};

	const char *SftpflagsString[] = {"append", "append atomic", "text mode", "block read", "block write",
									 "block delete", "block advisory", "nofollow", "delete on close", "audit alarm info",
									 "access backup", "backup stream", "override owner"};


	msgbuf = xmalloc(SSIZE);
	strncpy((char *) msgbuf, "", 1);

	switch(request->flags & SSH_FXF_ACCESS_DISPOSITION) {
		case SSH_FXF_CREATE_NEW:
			dispo_str="create new";
			break;
		case SSH_FXF_CREATE_TRUNCATE:
			dispo_str="create truncate";
			break;
		case SSH_FXF_OPEN_EXISTING:
			dispo_str="open existing";
			break;
		case SSH_FXF_OPEN_OR_CREATE:
			dispo_str="open or create";
			break;
		case SSH_FXF_TRUNCATE_EXISTING:
			dispo_str="truncate existing";
			break;
		default:
			dispo_str="Unknown";
	}

	o += snprintf((char *) &msgbuf[o], SSIZE - o, "%s", dispo_str);

	for (f = 0; f < num_flags; f++) {
		if (request->flags & flags[f]) {
			o += snprintf((char *) &msgbuf[o], SSIZE - o, "%s%s", o>0 ? ", " : "", SftpflagsString[f]);
		}
	}

	return((const char *) msgbuf);
}

#undef SSIZE


#define SSIZE 1024


/*!
 * @brief       Generate ACL string from request
 *
 * @param       acl_string      ACL string
 *
 * @return      String
 */

static const char *
susshi_sftp_acl_string(ssh_string acl_string) {
	int o = 0;
	uint32_t acl_flags, ace_count, c;
	uint32_t type, flag, mask;
	ssh_string who = NULL;
	const char *type_str;

	ssh_buffer buffer;

	char *msgbuf;

	msgbuf = xmalloc(SSIZE);
	strncpy((char *) msgbuf, "", 1);

	buffer = ssh_buffer_new();
	ssh_buffer_add_ssh_string(buffer, acl_string);

	if (ssh_buffer_unpack(buffer, "dd", &acl_flags, &ace_count) == SSH_OK) {
		o += snprintf((char *) &msgbuf[o], SSIZE - o, "acl-flags: 0x%x, ace(%d): ", acl_flags, ace_count);

		for (c = 0; c < ace_count; c++) {
			ssh_buffer_unpack(buffer, "dddS", &type, &flag, &mask, &who);

			switch (type) {
				case ACE4_ACCESS_ALLOWED_ACE_TYPE:
					type_str = "Allowed";
					break;
				case ACE4_ACCESS_DENIED_ACE_TYPE:
					type_str = "Denied";
					break;
				case ACE4_SYSTEM_AUDIT_ACE_TYPE:
					type_str = "Audit";
					break;
				case ACE4_SYSTEM_ALARM_ACE_TYPE:
					type_str = "Alarm";
					break;
				default:
					type_str = "Unknown";
			}

			o += snprintf((char *) &msgbuf[o], SSIZE - o, "%stype=%s flags=0x%x masks=0x%x who='%s'", c > 0 ? ", " : "",
						  type_str, flag, mask, ssh_string_get_char(who));

			SSH_STRING_FREE(who);
		}

		return ((const char *) msgbuf);
	}

	return NULL;

}

#undef SSIZE

#define SSIZE 2048


/*!
 * @brief       Generate Data file attributes string
 *
 * @param       cid         Channel ID (unsused)
 * @param       buffer      ssh_buffer
 * @param       version     SFTP version
 *
 * @return      String
 */

static const char *
susshi_sftp_data_file_attr(int cid, ssh_buffer buffer, uint32_t version) {
	uint32_t flags, perm;
	uint64_t size;
	char *msgbuf;
	int o = 0;

	msgbuf = xmalloc(SSIZE);
	msgbuf[0] = '\0';

	/* flags */
	if (ssh_buffer_unpack(buffer, "d", &flags) != SSH_OK)
		goto decode_error;

	/* type (Version >3) */
	if (version > 3) {
		char type;
		const char *type_str;

		if (ssh_buffer_unpack(buffer, "b", &type) != SSH_OK)
			goto decode_error;

		switch(type) {
			case SSH_FILEXFER_TYPE_REGULAR:
				type_str = "File";
				break;
			case SSH_FILEXFER_TYPE_DIRECTORY:
				type_str = "Directory";
				break;
			case SSH_FILEXFER_TYPE_SYMLINK:
				type_str = "Symlink";
				break;
			case SSH_FILEXFER_TYPE_SPECIAL:
				type_str = "Special";
				break;
			case SSH_FILEXFER_TYPE_SOCKET:
				type_str = "Socket";
				break;
			case SSH_FILEXFER_TYPE_CHAR_DEVICE:
				type_str = "Char Device";
				break;
			case SSH_FILEXFER_TYPE_BLOCK_DEVICE:
				type_str = "Block Device";
				break;
			case SSH_FILEXFER_TYPE_FIFO:
				type_str = "FIFO";
				break;
			case SSH_FILEXFER_TYPE_UNKNOWN:
			default:
				type_str = "Unknown";
		}
		o += snprintf(&msgbuf[o], SSIZE - o, "type=%s", type_str);
	}

	/* size */
	if (flags & SSH_FILEXFER_ATTR_SIZE) {
		if (ssh_buffer_unpack(buffer, "q", &size) != SSH_OK)
			goto decode_error;

		o += snprintf(&msgbuf[o], SSIZE - o, "%ssize=%lu", o>0 ? ", " : "", (long unsigned int) size);
	}

	/* allocation-size (Version > 5) */
	if (flags & SSH_FILEXFER_ATTR_ALLOCATION_SIZE) {
		if (ssh_buffer_unpack(buffer, "q", &size) != SSH_OK)
			goto decode_error;

		o += snprintf(&msgbuf[o], SSIZE - o, "%salloc-size=%lu", o>0 ? ", " : "", (long unsigned int) size);
	}

	if (version > 3) {
		/* owner, group (Version > 3) */
		if (flags & SSH_FILEXFER_ATTR_OWNERGROUP) {
			ssh_string owner = NULL, group = NULL;

			if (ssh_buffer_unpack(buffer, "SS", &owner, &group) != SSH_OK)
				goto decode_error;

			o += snprintf(&msgbuf[o], SSIZE - o, "%sowner=%s, group=%s", o>0 ? ", " : "",
						  ssh_string_get_char(owner), ssh_string_get_char(group));
			SSH_STRING_FREE(owner);
			SSH_STRING_FREE(group);
		}
	} else {
		/* uid/gid (Version < 4) */
		if (flags & SSH_FILEXFER_ATTR_UIDGID) {
			uint32_t uid, gid;
			if (ssh_buffer_unpack(buffer, "dd", &uid, &gid) != SSH_OK)
				goto decode_error;

			o += snprintf(&msgbuf[o], SSIZE - o, "%suid=%d, gid=%d", o>0 ? ", " : "", uid, gid);
		}
	}

	/* permissions */
	if (flags & SSH_FILEXFER_ATTR_PERMISSIONS)	{
		if (ssh_buffer_unpack(buffer, "d", &perm) != SSH_OK)
			goto decode_error;

		o += snprintf(&msgbuf[o], SSIZE - o, "%sperm=%o", o>0 ? ", " : "", perm);
	}

	if (version > 3) {
		uint64_t time;
		uint32_t stime;

		/* atime */
		if (flags & SSH_FILEXFER_ATTR_ACMODTIME) {
			if (ssh_buffer_unpack(buffer, "q", &time) != SSH_OK)
				goto decode_error;

			o += snprintf(&msgbuf[o], SSIZE - o, "%satime=%" PRIu64, o>0 ? ", " : "", time);
			/* atime_nseconds */
			if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES) {
				if (ssh_buffer_unpack(buffer, "d", &stime) != SSH_OK)
					goto decode_error;

				o += snprintf(&msgbuf[o], SSIZE - o, ":%d", stime);
			}
		}

		/* createtime_nseconds */
		if (flags & SSH_FILEXFER_ATTR_CREATETIME) {
			if (ssh_buffer_unpack(buffer, "q", &time) != SSH_OK)
				goto decode_error;

			o += snprintf(&msgbuf[o], SSIZE - o, "%screatetime=%" PRIu64, o>0 ? ", " : "", time);
			/* createtime_nseconds */
			if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES) {
				if (ssh_buffer_unpack(buffer, "d", &stime) != SSH_OK)
					goto decode_error;

				o += snprintf(&msgbuf[o], SSIZE - o, ":%d", stime);
			}
		}

		/* mtime */
		if (flags & SSH_FILEXFER_ATTR_MODIFYTIME) {
			if (ssh_buffer_unpack(buffer, "q", &time) != SSH_OK)
				goto decode_error;

			o += snprintf(&msgbuf[o], SSIZE - o, "%smtime=%" PRIu64, o>0 ? ", " : "", time);
			/* mtime_nseconds */
			if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES) {
				if (ssh_buffer_unpack(buffer, "d", &stime) != SSH_OK)
					goto decode_error;

				o += snprintf(&msgbuf[o], SSIZE - o, ":%d", stime);
			}
		}

		/* ctime */
		if (flags & SSH_FILEXFER_ATTR_CTIME) {
			if (ssh_buffer_unpack(buffer, "q", &time) != SSH_OK)
				goto decode_error;

			o += snprintf(&msgbuf[o], SSIZE - o, "%sctime=%" PRIu64, o>0 ? ", " : "", time);
			/* createtime_nseconds */
			if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES) {
				if (ssh_buffer_unpack(buffer, "d", &stime) != SSH_OK)
					goto decode_error;

				o += snprintf(&msgbuf[o], SSIZE - o, ":%d", stime);
			}
		}

		/* acl */
		if (flags & SSH_FILEXFER_ATTR_ACL) {
			ssh_string acl = NULL;
			const char *acl_str = NULL;

			if (ssh_buffer_unpack(buffer, "S", &acl) != SSH_OK)
				goto decode_error;

			acl_str = susshi_sftp_acl_string(acl);
			o += snprintf(&msgbuf[o], SSIZE - o, "%sacl=%s", o>0 ? ", " : "", acl_str);

			SSH_STRING_FREE(acl);
			if (acl_str != NULL) xfree((void *) acl_str);
		}

		/* bits */
		if (flags & SSH_FILEXFER_ATTR_BITS) {
			uint32_t abits, abitsv;

			if (ssh_buffer_unpack(buffer, "dd", &abits, &abitsv) != SSH_OK)
				goto decode_error;

			o += snprintf(&msgbuf[o], SSIZE - o, "%sattrib-bits=0x%x, attrib-bits-valid=0x%x", o>0 ? ", " : "", abits, abitsv);
		}

		/* text-hint */
		if (flags & SSH_FILEXFER_ATTR_TEXT_HINT) {
			char hint;
			const char *hint_str;

			if (ssh_buffer_unpack(buffer, "b", &hint) != SSH_OK)
				goto decode_error;

			switch(hint) {
				case SSH_FILEXFER_ATTR_KNOWN_TEXT:
					hint_str = "Text";
					break;
				case SSH_FILEXFER_ATTR_GUESSED_TEXT:
					hint_str = "Guess Text";
					break;
				case SSH_FILEXFER_ATTR_KNOWN_BINARY:
					hint_str = "Binary";
					break;
				case SSH_FILEXFER_ATTR_GUESSED_BINARY:
					hint_str = "Guess Binary";
					break;
				default:
					hint_str = "Unknown";
			}
			o += snprintf(&msgbuf[o], SSIZE - o, "%stext-hint=%s", o>0 ? ", " : "", hint_str);
		}

		/* mime-type */
		if (flags & SSH_FILEXFER_ATTR_MIME_TYPE) {
			ssh_string mime = NULL;

			if (ssh_buffer_unpack(buffer, "S", &mime) != SSH_OK)
				goto decode_error;

			o += snprintf(&msgbuf[o], SSIZE - o, "%smime-type=%s", o>0 ? ", " : "", ssh_string_get_char(mime));
			SSH_STRING_FREE(mime);
		}

		/* link-count */
		if (flags & SSH_FILEXFER_ATTR_LINK_COUNT) {
			uint32_t count;

			if (ssh_buffer_unpack(buffer, "d", &count) != SSH_OK)
				goto decode_error;

			o += snprintf(&msgbuf[o], SSIZE - o, "%slink-count=%d", o>0 ? ", " : "", count);
		}

		/* mime-type */
		if (flags & SSH_FILEXFER_ATTR_UNTRANSLATED_NAME) {
			ssh_string name;

			if (ssh_buffer_unpack(buffer, "S", &name) != SSH_OK)
				goto decode_error;

			o += snprintf(&msgbuf[o], SSIZE - o, "%suntranslated-name=%s", o>0 ? ", " : "", ssh_string_get_char(name));
			SSH_STRING_FREE(name);
		}

	} else {
		/* Version 3 */
		uint32_t atime, mtime;
		if (flags & SSH_FILEXFER_ATTR_ACMODTIME) {
			if (ssh_buffer_unpack(buffer, "dd", &atime, &mtime) != SSH_OK)
				goto decode_error;

			o += snprintf(&msgbuf[o], SSIZE - o, "%satime=%d, mtime=%d", o>0 ? ", " : "", atime, mtime);
		}
	}

	if (flags & SSH_FILEXFER_ATTR_EXTENDED) {
		ssh_string str1 = NULL, str2 = NULL;
		uint32_t count;

		if (ssh_buffer_unpack(buffer, "d", &count) != SSH_OK)
			goto decode_error;

		for (uint32_t i = 0; i < count; i++) {

			if (ssh_buffer_unpack(buffer, "SS", &str1, &str2) != SSH_OK)
				goto decode_error;

			o += snprintf(&msgbuf[o], SSIZE - o, "%s%s=%s", o>0 ? ", " : "", ssh_string_get_char(str1), ssh_string_get_char(str2));
			SSH_STRING_FREE(str1);
			SSH_STRING_FREE(str2);
		}
	}

	decode_error:
	if (strlen(msgbuf) > 0) {
		return msgbuf;
	} else {
		xfree((void *) msgbuf);
		return NULL;
	}

}

#undef SSIZE

/*! @} */
