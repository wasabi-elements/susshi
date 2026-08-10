/*!
 *
 * @brief       Hash methods
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


#ifndef SUSSHI_HASH_H
#define SUSSHI_HASH_H

extern const unsigned char susshi_hash_salt[32];

void susshi_hash_sha256(const char *input, size_t inlen, unsigned char *hash);

const char *susshi_display_hash_from_key(ssh_key key);

const char *susshi_display_hash_from_blob(const char *blob, size_t bloblen);

#endif //SUSSHI_HASH_H
