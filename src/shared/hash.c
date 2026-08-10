/*!
 *
 * @brief       Hash related methods
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
 * @defgroup    hash Hash methods
 * @{
 */

#include "shared/common.h"
#include "shared/hash.h"

/* Static salt for hash-based identifiers */
const unsigned char susshi_hash_salt[32] = { 0x2c, 0x19, 0x66, 0x29, 0x92, 0x3f, 0x7f, 0x24, 0x6f, 0x28, 0x54, 0xfb, 0x33, 0x8d, 0x8e, 0x5c, 0x52, 0xaa, 0x38, 0xef, 0x4a, 0xc7, 0x17, 0x6b, 0xc0, 0x6c, 0xf6, 0x08, 0x8a, 0x6e, 0x90, 0xec };

/* Prototypes */
static char *susshi_fingerprint_b64(const char *prefix, u_char *hash_raw, size_t hash_raw_len);


/*!
 * @brief       Generate a raw SHA-256 digest of the input data
 *
 * No error is signaled on failure; callers should ensure inputs are valid.
 *
 * @param       input   input data
 * @param       inlen   input data length in bytes
 * @param       hash    output buffer, must be at least @c SHA256_DIGEST_LENGTH bytes
 */

void
susshi_hash_sha256(const char *input, size_t inlen, unsigned char *hash)
{
	EVP_MD_CTX *sha256;
	unsigned int hash_len;
	int rc;

	sha256 = EVP_MD_CTX_new();
	if (sha256 == NULL)
		fatal("susshi_hash_sha256: EVP_MD_CTX_new failed");

	rc  = EVP_DigestInit_ex(sha256, EVP_sha256(), NULL);
	if (rc == 1) rc = EVP_DigestUpdate(sha256, input, inlen);
	if (rc == 1) rc = EVP_DigestFinal_ex(sha256, hash, &hash_len);

	EVP_MD_CTX_free(sha256);

	if (rc != 1)
		fatal("susshi_hash_sha256: digest operation failed");
}


/*!
 * @brief       Generate a @c SHA256: -prefixed Base64 fingerprint string from an ssh_key, for use in log/debug messages
 *
 * @param       key     ssh_key to fingerprint
 *
 * @return      On success, a heap-allocated string of the form @c "SHA256:" followed by a Base64 digest,
 *              that must be freed by the caller.
 *              On failure, a static @c "(NULL)" literal that must @b not be freed.
 */

const char*
susshi_display_hash_from_key(ssh_key key) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	size_t hlen;

	ssh_string blob;
	char *string = NULL;

	int rc;

	rc = ssh_pki_export_pubkey_blob(key, &blob);

	if (rc == SSH_OK) {
		hlen =  ssh_string_len(blob);
		susshi_hash_sha256(ssh_string_data(blob), hlen, hash);
		string = susshi_fingerprint_b64("SHA256", hash, SHA256_DIGEST_LENGTH);
		SSH_STRING_FREE(blob);
	} else {
		return "(NULL)";
	}

	return string;
}


/*!
 * @brief       Generate a @c SHA256: -prefixed Base64 fingerprint string from a raw binary blob
 *
 * @param       blob        Raw binary blob data to fingerprint
 * @param       bloblen     Length of @p blob in bytes
 *
 * @return      A heap-allocated string of the form @c "SHA256:" followed by a Base64 digest,
 *              that must be freed by the caller, or @c NULL on failure.
 */

const char*
susshi_display_hash_from_blob(const char *blob, size_t bloblen) {
	unsigned char hash[SHA256_DIGEST_LENGTH];

	susshi_hash_sha256(blob, bloblen, hash);
	return susshi_fingerprint_b64("SHA256", hash, SHA256_DIGEST_LENGTH);

}


/*!
 * @brief       Format a raw hash digest as a prefixed, unpadded Base64 fingerprint string
 *
 * The returned string has the form @c "prefix:base64", with trailing @c '=' padding stripped.
 * If @p hash_raw_len is 0, only the prefix and colon are returned.
 * @p prefix must not be @c NULL.
 *
 * @param       prefix          Prefix prepended to the Base64 digest, separated by @c ':'
 * @param       hash_raw        Pointer to raw hash digest bytes
 * @param       hash_raw_len    Length of @p hash_raw in bytes; must be <= 65536
 *
 * @return      A heap-allocated fingerprint string that must be freed by the caller,
 *              or @c NULL on allocation failure or if @p hash_raw_len exceeds the limit.
 */

static char *
susshi_fingerprint_b64(const char *prefix, u_char *hash_raw, size_t hash_raw_len)
{
	char *ret = NULL;
	size_t plen = strlen(prefix) + 1;
	size_t rlen = ((hash_raw_len + 2) / 3) * 4 + plen + 1;
	int r;

	if (hash_raw_len > 65536 || (ret = calloc(1, rlen)) == NULL)
		return NULL;
	strlcpy(ret, prefix, rlen);
	strlcat(ret, ":", rlen);
	if (hash_raw_len == 0)
		return ret;
	if ((r = b64_ntop(hash_raw, hash_raw_len,
					  ret + plen, rlen - plen)) == -1) {
		explicit_bzero(ret, rlen);
		free(ret);
		return NULL;
					  }
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	return ret;
}

/*! @} */
