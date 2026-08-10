/*!
 * @brief       Secure Internal Communication
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
 * @ingroup     sic
 * @{
 */

#ifndef SUSSHI_SIC_H
#define SUSSHI_SIC_H

#define PATH_SIC_CA_FILE		PATH_SUSSHID_TEMP_DIR "/ca.pem"
#define PATH_SIC_CERT_FILE		PATH_SUSSHID_TEMP_DIR "/cert-%s.p12"

bool susshi_sic_validate_params(bool show_error);
bool susshi_sic_parse_url(bstring sic_url);
bool susshi_sic_initialize(u_int wait, u_int retry, u_int retry_wait);
bool susshi_sic_store_normalized_spki(const bstring spki);

#endif //SUSSHI_SIC_H

/*! @} */
