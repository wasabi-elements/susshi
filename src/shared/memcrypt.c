/*!
 *
 * @brief       Memcrypt / Linear Congruential Generator (LCG) methods
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
 * @defgroup    memcrypt Memcrypt methods
 * @{
 */

#include "shared/common.h"
#include "shared/base64.h"
#include "shared/memcrypt.h"
#include "shared/memcrypt_constants.h"

static unsigned char pool[SUSSHI_MEMCRYPT_POOL_SIZE];
static uint32_t seed = 0;


/*!
 * @brief       Initialize susshi memcrypt functions including seed pool
 *
 * @return      true if successful, otherwise false
 */

bool
susshi_memcrypt_init(void)
{
	size_t i = 0;

	/* Initialize seed */
	seed = arc4random();

	/* Fill pool with pseudo-random printable ASCII characters using the given seed */
	for (i = 0; i < SUSSHI_MEMCRYPT_POOL_SIZE; i++) {
		pool[i] = (unsigned char) (SUSSHI_MEMCRYPT_CHAR_MIN + arc4random_uniform(SUSSHI_MEMCRYPT_CHAR_MAX - SUSSHI_MEMCRYPT_CHAR_MIN + 1));
	}

	return true;
}


/*!
 * @brief       Cleanup susshi memcrypt functions
 */

void
susshi_memcrypt_cleanup(void) {

	/* Clear pool */
	explicit_bzero(pool, SUSSHI_MEMCRYPT_POOL_SIZE);

	/* Wipe seed */
	seed = 0;
}


/*!
 * @brief       Derive the memory encryption key from the pool using a seeded LCG
 *
 * Selects @c SUSSHI_MEMCRYPT_KEY_LEN characters from the pool using a Linear Congruential
 * Generator (Numerical Recipes constants) seeded from the internal @c seed XOR @c 0xCEEFBEAF.
 * The high-order 16 bits of each LCG state are used as the pool index for better distribution.
 * The key is deterministic for a given @c seed, i.e. the same key is returned on every call
 * within a session.
 *
 * @return      Heap-allocated @c bstring containing the key, or @c NULL on allocation failure;
 *              caller should wipe and free with @c susshi_memcrypt_key_free()
 */

bstring
susshi_memcrypt_key(void)
{
	bstring key = NULL;

	unsigned int state = seed ^ 0xCEEFBEAF;

	key = bfromcstralloc(SUSSHI_MEMCRYPT_KEY_LEN + 1, "");

	if (key) {
		for (size_t i = 0; i < SUSSHI_MEMCRYPT_KEY_LEN; i++) {
			state = state * LCG_MULTIPLIER + LCG_INCREMENT;   /* Numerical Recipes LCG */
			bdata(key)[i] = pool[(state >> 16) % SUSSHI_MEMCRYPT_POOL_SIZE];
		}
		bdata(key)[SUSSHI_MEMCRYPT_KEY_LEN] = '\0';
		key->slen = SUSSHI_MEMCRYPT_KEY_LEN;
	}
	return key;
}


/*!
 * @brief       Encrypt a plaintext @c bstring with AES-256-GCM and return the result as Base64
 *
 * The Base64-encoded output encodes the concatenation: IV (12 bytes) + TAG (16 bytes) + ciphertext.
 * A fresh random IV is generated for each call.
 *
 * @param       plaintext   The plaintext to encrypt
 * @param       key         Encryption key, or @c NULL to derive it via @c susshi_memcrypt_key()
 *
 * @return      Heap-allocated Base64-encoded @c bstring on success, or @c NULL on failure
 */

bstring
susshi_memcrypt_encrypt_bstring(bstring plaintext, bstring key) {
	char *c_base64_output = NULL;
	int rc = 0;
	bool local_key = false;

	if (key == NULL) {
		local_key = true;
		key = susshi_memcrypt_key();
	}

	if (plaintext && key) {
		unsigned char iv[SUSSHI_MEMCRYPT_IV_LEN];
		unsigned char tag[SUSSHI_MEMCRYPT_TAG_LEN];
		unsigned char *ciphertext = NULL;
		EVP_CIPHER_CTX *ctx = NULL;

		size_t ciphertext_len = blength(plaintext);
		size_t ciphertext_alloc = ciphertext_len + 1;

		/* generate random IV */
		if (RAND_bytes(iv, SUSSHI_MEMCRYPT_IV_LEN) != 1) {
			if (local_key)
				susshi_memcrypt_key_free(key);
			return NULL;
		}

		ciphertext = xmalloc(ciphertext_alloc);

		ctx = EVP_CIPHER_CTX_new();

		if (ctx) {
			int len = 0;

			rc  = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
			if (rc == 1) rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SUSSHI_MEMCRYPT_IV_LEN, NULL);
			if (rc == 1) rc = EVP_EncryptInit_ex(ctx, NULL, NULL, (const unsigned char *) bdata(key), iv);
			if (rc == 1) rc = EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char *) bdata(plaintext), (int) ciphertext_len);

			ciphertext_len = len;

			if (rc == 1) rc = EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
			if (rc == 1) ciphertext_len += len;
			if (rc == 1) rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SUSSHI_MEMCRYPT_TAG_LEN, tag);

			EVP_CIPHER_CTX_free(ctx);
		}

		if (rc > 0) {
			size_t blob_len = SUSSHI_MEMCRYPT_IV_LEN + SUSSHI_MEMCRYPT_TAG_LEN + ciphertext_len;
			unsigned char *blob = xmalloc(blob_len);

			/* assemble: IV + TAG + ciphertext */
			memcpy(blob, iv, SUSSHI_MEMCRYPT_IV_LEN);
			memcpy(blob + SUSSHI_MEMCRYPT_IV_LEN, tag, SUSSHI_MEMCRYPT_TAG_LEN);
			memcpy(blob + SUSSHI_MEMCRYPT_IV_LEN + SUSSHI_MEMCRYPT_TAG_LEN, ciphertext, ciphertext_len);

			/* encode base64 */
			susshi_base64(blob, blob_len, &c_base64_output, NULL);

			/* wipe and free memory */
			explicit_bzero(blob, blob_len);
			free(blob);
		}

		/* wipe and free memory */
		explicit_bzero(iv, SUSSHI_MEMCRYPT_IV_LEN);
		explicit_bzero(tag, SUSSHI_MEMCRYPT_TAG_LEN);
		explicit_bzero(ciphertext, ciphertext_alloc);
		xfree(ciphertext);

		if (local_key)
			susshi_memcrypt_key_free(key);
	}

	if (c_base64_output) {
		bstring base64_output = bfromcstr(c_base64_output);
		xfree(c_base64_output);
		return base64_output;
	} else {
		return NULL;
	}
}


/*!
 * @brief       Decrypt a Base64-encoded AES-256-GCM ciphertext produced by @c susshi_memcrypt_encrypt_bstring
 *
 * The input must decode to at least IV (12 bytes) + TAG (16 bytes) of overhead followed by the ciphertext.
 * Returns @c NULL if decryption fails (e.g. authentication tag mismatch or malformed input).
 *
 * @param       base64_input    Base64-encoded ciphertext of the form IV + TAG + ciphertext
 * @param       key             Decryption key, or @c NULL to derive it via @c susshi_memcrypt_key()
 *
 * @return      Heap-allocated @c bstring containing the plaintext on success,
 *              or @c NULL on decryption failure or invalid input
 */

bstring
susshi_memcrypt_decrypt_bstring(bstring base64_input, bstring key) {

	unsigned char *c_plaintext = NULL;
	size_t c_plaintext_alloc = 0;
	int plaintext_len = 0;
	int rc = 0;
	bool local_key = false;

	if (key == NULL) {
		local_key = true;
		key = susshi_memcrypt_key();
	}

	if (key) {

		unsigned char *decoded = NULL;
		size_t decoded_len;

		if (susshi_unbase64(bdata(base64_input), &decoded, &decoded_len)) {

			unsigned char iv[SUSSHI_MEMCRYPT_IV_LEN];
			unsigned char tag[SUSSHI_MEMCRYPT_TAG_LEN];

			unsigned char *ciphertext = NULL;
			size_t ciphertext_len;

			EVP_CIPHER_CTX* ctx = NULL;
			if (decoded_len < SUSSHI_MEMCRYPT_IV_LEN + SUSSHI_MEMCRYPT_TAG_LEN) {
				free(decoded);
				if (local_key)
					susshi_memcrypt_key_free(key);
				return NULL;
			}

			/* extract IV (first SUSSHI_MEMCRYPT_IV_LEN bytes) */
			memcpy(iv, decoded, SUSSHI_MEMCRYPT_IV_LEN);

			/* extract TAG (second SUSSHI_MEMCRYPT_TAG_LEN bytes) */
			memcpy(tag, decoded + SUSSHI_MEMCRYPT_IV_LEN, SUSSHI_MEMCRYPT_TAG_LEN);

			ciphertext_len = decoded_len - SUSSHI_MEMCRYPT_IV_LEN - SUSSHI_MEMCRYPT_TAG_LEN;
			ciphertext = decoded + SUSSHI_MEMCRYPT_IV_LEN + SUSSHI_MEMCRYPT_TAG_LEN;

			/* Prepare bstring for plaintext */
			c_plaintext_alloc = ciphertext_len + 1;
			c_plaintext = xmalloc(c_plaintext_alloc);

			ctx = EVP_CIPHER_CTX_new();

			if (ctx) {
				int len = 0;

				rc  = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
				if (rc == 1) rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SUSSHI_MEMCRYPT_IV_LEN, NULL);
				if (rc == 1) rc = EVP_DecryptInit_ex(ctx, NULL, NULL, (const unsigned char *) bdata(key), iv);
				if (rc == 1) rc = EVP_DecryptUpdate(ctx, c_plaintext, &len, ciphertext, (int) ciphertext_len);
				if (rc == 1) rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SUSSHI_MEMCRYPT_TAG_LEN, tag);
				plaintext_len = len;

				if (rc == 1) {
					if ((rc = EVP_DecryptFinal_ex(ctx, c_plaintext + len, &len)) > 0)
						plaintext_len += len;
				}

				EVP_CIPHER_CTX_free(ctx);
			}

			/* wipe and free memory */
			explicit_bzero(iv, SUSSHI_MEMCRYPT_IV_LEN);
			explicit_bzero(tag, SUSSHI_MEMCRYPT_TAG_LEN);
			explicit_bzero(decoded, decoded_len);
			free(decoded);
		}
		if (local_key)
			susshi_memcrypt_key_free(key);
	}

	if (c_plaintext) {
		bstring plaintext = NULL;

		if (rc > 0) {
			c_plaintext[plaintext_len] = '\0';
			plaintext = bfromcstr((const char *) c_plaintext);
		}

		xwipe(c_plaintext, c_plaintext_alloc);
		return(plaintext);
	} else {
		return NULL;
	}
}


/*!
 * @brief       Memcrypt authentication callback
 *
 * Called from ssh_pki_import_privkey_base64 to provide passphrase protected SSH private key
 *
 * @param       prompt        Prompt to be displayed.
 * @param       buf           Buffer to save the password. You should null-terminate it.
 * @param       len           Length of the buffer.
 * @param       echo          Enable or disable the echo of what you type.
 * @param       verify        Should the password be verified?
 * @param       userdata      optional userdata
 *
 * @return              0 on success, < 0 on error.
 */

int
susshi_memcrypt_ssh_privkey_callback(const char *prompt, char *buf, size_t len, int echo, int verify, void *userdata) {
	int rc = -1;
	(void) prompt;	 /* unused */
	(void) echo;	 /* unused */
	(void) verify;	 /* unused */
	(void) userdata; /* unused */

	if (len > SUSSHI_MEMCRYPT_KEY_LEN) {
		bstring memcrypt_key = NULL;

		if ((memcrypt_key = susshi_memcrypt_key())) {
			strlcpy(buf, bdata(memcrypt_key), len);
			susshi_memcrypt_key_free(memcrypt_key);
			rc = 0;
		}
	} else {
		fatal("susshi_memcrypt_ssh_privkey_callback received buffer is too short");
	}

	return rc;
}


/*! @} */

