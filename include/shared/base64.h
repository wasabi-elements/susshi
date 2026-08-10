/*!
 *
 * @brief       Base64 Functions
 *
 * @copyright   Copyright (C) 2026 Wasabi Elements GmbH<br>
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

#ifndef SUSSHI_BASE64_H
#define SUSSHI_BASE64_H

bool susshi_base64(const unsigned char *input, size_t length, char **output, size_t *output_length);

bool susshi_base64url_normalize(const char *input, char **output, size_t *output_len);

bool susshi_unbase64(const char *b64input, unsigned char **output, size_t *output_length);

#endif //SUSSHI_BASE64_H
