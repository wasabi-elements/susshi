/*!
 *
 * @brief       Simple hexdump in hex editor style
 *
 * @ingroup     shared
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
 * @defgroup    hexdump Hexdump methods
 * @{
 */

#include "shared/common.h"
#include "shared/hexdump.h"


/*!
 * @brief       Dump binary data to @c stderr in hex editor style (offset, hex columns, ASCII)
 *
 * @param       data        Pointer to data to dump
 * @param       datalen     Length of @p data in bytes
 */

void
do_susshi_hexdump(const char *data, size_t datalen)
{
	uint32_t g,i;

	fprintf(stderr, "--------- [%05ld bytes] -------------------------------------------------------------------\n", datalen);
	for (g=0; g < datalen; g+=16)
	{
		fprintf(stderr, "%05x\t",g);
		for(i=0; (i < 16); i++)
		{
			if (g+i < datalen)
				fprintf(stderr, "%02x ", (unsigned char) data[g+i]);
			else
				fprintf(stderr, "   ");
		}
		fprintf(stderr, "    ");
		for(i=0; (i < 16) && (g+i < datalen); i++)
		{
			fprintf(stderr, "%c", ((data[g+i] > 31) && (data[g+i] < 127)) ? data[g+i] : '.');
		}
		fprintf(stderr, "\n");
	}
	fprintf(stderr, "-------------------------------------------------------------------------------------------\n");
}


/*!
 * @brief       Dump the contents of a libssh @c ssh_buffer to @c stderr in hex editor style
 *
 * @param       buffer      The @c ssh_buffer to dump
 */

void
do_susshi_hexdump_ssh_buffer(ssh_buffer buffer)
{
	do_susshi_hexdump(ssh_buffer_get(buffer), (size_t) ssh_buffer_get_len(buffer));
}

/*! @} */
