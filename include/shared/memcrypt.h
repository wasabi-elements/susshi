/*!
 *
 * @brief       Memcrypt / Linear Congruential Generator (LCG)
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

#ifndef SUSSHI_MEMCRYPT_H
#define SUSSHI_MEMCRYPT_H

#include <bstraux.h>

#define SUSSHI_MEMCRYPT_POOL_SIZE   1024
#define SUSSHI_MEMCRYPT_KEY_LEN		32

// printable ASCII range: 33 ('!') ... 126 ('~')
#define SUSSHI_MEMCRYPT_CHAR_MIN    33
#define SUSSHI_MEMCRYPT_CHAR_MAX    126

// As set by openssl AES-256-GCM encryption on chef set
#define SUSSHI_MEMCRYPT_IV_LEN		12
#define SUSSHI_MEMCRYPT_TAG_LEN		16

bool susshi_memcrypt_init(void);

void susshi_memcrypt_cleanup(void);

bstring susshi_memcrypt_key(void);

void susshi_memcrypt_key_free(bstring key);

bstring susshi_memcrypt_encrypt_bstring(bstring plaintext, bstring key);

bstring susshi_memcrypt_decrypt_bstring(bstring base64_input, bstring key);

#define susshi_memcrypt_key_free(...)   bstrWipe(__VA_ARGS__)

int susshi_memcrypt_ssh_privkey_callback(const char *prompt, char *buf, size_t len, int echo, int verify, void *userdata);

#endif //SUSSHI_MEMCRYPT_H
