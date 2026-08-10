/*!
 *
 * @brief       SCP Inspection
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
 * @author      Oliver Rauscher <oliver@susshi.io>
 * @date        2026-02-01
 *
 * @defgroup    inspection_scp Secure copy (scp) Inspection
 * @brief       Functions to inspect scp communication.
 *
 * @{
 */

#include "susshid/common.h"


const char *SCPSinkMessageString[] = { "OK", "Warning", "Fatal", "UNKNOWN" };


/*!
 * @brief       Inspect SCP data
 *
 * @param       cid         Channel-ID
 * @param       sender      Side of Requestor
 * @param       buffer      Copy of actual ssh_buffer
 */

void
susshi_inspect_scp_data(int cid, Side sender, ssh_buffer buffer) {

	SusshiChannel *c;
	ChannelSCPMode mode;
	char reply, cmd;

	ssh_string datastr = NULL;
	unsigned const char *data = NULL;
	char *dataptr, *dataptr2;
	size_t datalen;

	char fmode[5], fname[1024];
	long flength;
	long fatime, fmtime;

	c = susshi_session.channels[cid];

	if (sender == c->requestor) {
		if (c->scp_requestor_mode == SCP_SINK)
			mode = SCP_SINK;
		else
			mode = SCP_SOURCE;
	} else {
		if (c->scp_requestor_mode == SCP_SINK)
			mode = SCP_SOURCE;
		else
			mode = SCP_SINK;
	}

	if (ssh_buffer_unpack(buffer, "S", &datastr) != SSH_OK) {
		fatal("Packet decoding returned with fatal error: Inspect SCP Data.");
	}

	data = datastr->data;
	datalen = ssh_string_len(datastr);

	debug_susshi_hexdump((const char *) data, datalen);

	if (mode == SCP_SOURCE) {
		// Message from side in SOURCE mode

		// debug4("c->scp_read_ahead = %d", c->scp_read_ahead);

		if (c->scp_read_ahead > 0) {
			// Ignore data

			// Report file transfer
			if (susshi_report.scp_files_maycount == 1) {
				susshi_report.scp_files_maycount = 0;

				if (sender == CLIENT) {
					susshi_report.scp_files_written++;
					susshi_report.scp_bytes_written += c->scp_read_ahead;
				} else {
					susshi_report.scp_files_read++;
					susshi_report.scp_bytes_read += c->scp_read_ahead;
				}

			}

			debug4("Read ahead %ld/%ld.", c->scp_read_ahead, datalen);
			if (datalen > (size_t) (c->scp_read_ahead + 1)) {
				datalen -= c->scp_read_ahead;
				data += c->scp_read_ahead;
				c->scp_read_ahead = 0;
				goto readmsg;
			}
			c->scp_read_ahead = (c->scp_read_ahead > (int)datalen) ? c->scp_read_ahead - (int)datalen : 0;
		} else {

			readmsg:

			dataptr = (char *) data;

			while (dataptr < (char *) (data + datalen)) {
				cmd = dataptr[0];
				dataptr++;

				switch (cmd) {
					case 'C':
						// Single File copy
						if (sscanf(dataptr, "%4s %ld %1023s", fmode, &flength, fname) == 3) {
							log_scp(cid, sender, TheOtherSide(sender), "Copy file '%s%s%s' [%s] (%ld bytes)",
									bdata(c->scp_dir_name), blength(c->scp_dir_name) > 0 ? "/" : "",
									fname, fmode, flength);
							c->scp_read_ahead = flength;
							susshi_report.scp_files_maycount = 1;
							dataptr = (char *) data + datalen;
						}
						break;

					case 'D':
						// Recursive directory copy
						if (sscanf(dataptr, "%4s %ld %1023s", fmode, &flength, fname) == 3) {
							bformata(c->scp_dir_name, "%s%s", blength(c->scp_dir_name) > 0 ? "/" : "", fname);

							log_scp(cid, sender, TheOtherSide(sender), "Recursive copy directory '%s' [%s] (len: %ld)",
									bdata(c->scp_dir_name), fmode, flength);
						}
						c->scp_dir_depth++;
						dataptr = (char *) data + datalen;
						break;

					case 'E':
						// End of directory
						c->scp_dir_depth--;
						if (bstrrchr(c->scp_dir_name, '/') > 0)
							btrunc(c->scp_dir_name, bstrrchr(c->scp_dir_name, '/'));
						log_scp(cid, sender, TheOtherSide(sender), "<-- EOD");
						dataptr = (char *) data + datalen;
						break;

					case 'T':
						// Modification and Access Times
						if (sscanf(dataptr, "%ld 0 %ld 0", &fmtime, &fatime) == 2) {
							log_scp(cid, sender, TheOtherSide(sender),
									"Next file/directory with mtime = %ld, atime = %ld", fmtime, fatime);
						}
						dataptr = (char *) data + datalen;
						break;

					default:
						debug1("Datalen: %zu", datalen);
						if ((int) cmd > 0) {
							if (sscanf(dataptr, "%1023[^\n]", fname) == 1) {
								log_scp(cid, sender, TheOtherSide(sender), "[%d] %s - %s", (int) cmd,
										SCPSinkMessageString[MIN(3, (int) cmd)], fname);
								dataptr += strlen(fname) + 1;
							}
						}
						break;
				}

			}
		}

	} else {
		// Message from side in SINK mode
		reply = data[0];
		if (reply < 3) {
			if (reply > 0) {
				// Only Warning and Fatal messages may have an additional text
				dataptr = (char *) data + 1;
				dataptr2 = (char *) strchr((const char *) dataptr, '\n');
				if (dataptr2 != NULL)
					dataptr2[0] = '\0';
				log_scp(cid, sender, TheOtherSide(sender), "%s%s%s%s", SCPSinkMessageString[MIN(3, reply)],
						(datalen > 1 && dataptr2 != NULL) ? " (" : "",
						(datalen > 1 && dataptr2 != NULL) ? dataptr : "",
						(datalen > 1 && dataptr2 != NULL) ? ")" : "");
				c->scp_read_ahead = 0;
				susshi_report.scp_files_maycount = 0;
			} else {
				debug4_dir(sender, TheOtherSide(sender), "OK.");
			}

		} else {
			// Debug message
			dataptr2 = strchr((char *) data, '\n');
			if (dataptr2 != NULL) {
				*dataptr2 = '\0';
				debug3_dir(sender, TheOtherSide(sender), "%s", data);
			}
		}
	}

	if (datastr) SSH_STRING_FREE(datastr);
}


/*!
 * @brief       Validates filepath
 *
 * @param       path    Filepath
 *
 * @return  > 0 if given filepath is a valid scp path
 */

bool
is_valid_scp_filepath(bstring path)
{
	int errorcode;
	PCRE2_SIZE erroffset;
	pcre2_code *re;
	bool result = false;

	re = pcre2_compile((PCRE2_SPTR)"^([a-zA-Z0-9/\\~.+=:_\\s\\\"\\*][a-zA-Z0-9/\\~.+=\\-:_\\s\\\"\\*]*)$",
					   PCRE2_ZERO_TERMINATED, 0, &errorcode, &erroffset, NULL);

	if (!re) {
		PCRE2_UCHAR errbuf[256];
		pcre2_get_error_message(errorcode, errbuf, sizeof(errbuf));
		debug4("is_valid_scp_filepath: pcre_compile failed (offset: %d), %s\n", (int)erroffset, (char *)errbuf);
		fatal("is_valid_scp_filepath: pcre_compile failed.");
	} else {
		if (blength(path) > 0) {
			pcre2_match_data *md = pcre2_match_data_create_from_pattern(re, NULL);
			if (md != NULL && pcre2_match(re, (PCRE2_SPTR)bdata(path), blength(path), 0, 0, md, NULL) >= 0)
				result = true;
			pcre2_match_data_free(md);
		}
		pcre2_code_free(re);
	}
	return result;
}

/*! @} */
