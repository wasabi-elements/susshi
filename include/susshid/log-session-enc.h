/*!
 *
 * @brief       Session log file encryption
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
 * @date        2026-06-21
 *
 * @ingroup     logging
 * @{
 */

#ifndef SUSSHID_LOG_SESSION_ENC_H
#define SUSSHID_LOG_SESSION_ENC_H

#include "shared/log-enc.h"

bool log_session_enc_open(SusshiLog *log);
void log_session_enc_write(SusshiLog *log, const unsigned char *data, size_t len);
void log_session_enc_finalize(SusshiLog *log);

#endif //SUSSHID_LOG_SESSION_ENC_H

/*! @} */
