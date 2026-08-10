/*!
 *
 * @brief       Logging
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
 * @ingroup     logging
 * @{
 */


#ifndef SUSSHID_LOG_H
#define SUSSHID_LOG_H

#include "shared/log.h"

#define SUSSHI_LOGFILE_EXEC_MAX_SIZE        200 * 1024 * 1024

#define INDENT_LOG_SYSTEM_TEXT "                          "

/* Prototypes */
void	do_debug5(const char *fmt,...) __attribute__((format(printf, 1, 2)));
void	do_debug5_dir(Side requestor, Side receiver, const char *fmt,...) __attribute__((format(printf, 3, 4)));

void	flush_susshi_channel_logs(void);
time_t  determine_next_log_period(time_t *delta);
void    log_filename_expand(bstring *filename, bstring logformat, bstring filetype, long int cid);
FILE *  susshi_open_logfile(SusshiLog *log);
void    susshi_close_logfile(SusshiLog *log);
char *  init_susshi_identifier(void);
void    init_susshi_log(void);

#endif //SUSSHI_LOG_H

/*! @} */
