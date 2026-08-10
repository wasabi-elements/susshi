/*!
 *
 * @brief       Session log file encryption — shared primitives
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
 * @date        2026-06-21
 *
 * @defgroup    log_enc Session log encryption shared primitives
 * @{
 */

#include "shared/common.h"
#include "shared/base64.h"
#include "shared/log-enc.h"
#include <jansson.h>
#include <sodium.h>

/* Verify our manifest constants against the actual libsodium values. */
static_assert(SUSSHI_LOG_ENC_ED25519_PUB_BYTES == crypto_sign_PUBLICKEYBYTES,
              "SUSSHI_LOG_ENC_ED25519_PUB_BYTES mismatch");
static_assert(SUSSHI_LOG_ENC_ED25519_SK_BYTES == crypto_sign_SECRETKEYBYTES,
              "SUSSHI_LOG_ENC_ED25519_SK_BYTES mismatch");
static_assert(SUSSHI_LOG_ENC_SESSION_KEY_BYTES == crypto_secretstream_xchacha20poly1305_KEYBYTES,
              "SUSSHI_LOG_ENC_SESSION_KEY_BYTES mismatch");
static_assert(SUSSHI_LOG_ENC_HEADER_BYTES == crypto_secretstream_xchacha20poly1305_HEADERBYTES,
              "SUSSHI_LOG_ENC_HEADER_BYTES mismatch");
static_assert(SUSSHI_LOG_ENC_ABYTES == crypto_secretstream_xchacha20poly1305_ABYTES,
              "SUSSHI_LOG_ENC_ABYTES mismatch");

/* Verify that the OpenSSL ed25519 seed length matches libsodium's expectation. */
static_assert(crypto_sign_SEEDBYTES == ED25519_KEY_LEN,
              "crypto_sign_SEEDBYTES mismatch with ED25519_KEY_LEN");

/* Compile-time sizes used across multiple functions. */
#define CT_CHUNK  (SUSSHI_LOG_ENC_CHUNK_SIZE + SUSSHI_LOG_ENC_ABYTES)


/*!
 * @brief   Replace every character unsafe for a filename component with '_'.
 *
 * @param[in,out] filename  bstring to sanitize in place.
 */

static void
sanitize_for_filename(bstring filename) {
	for (int i = 0; i < blength(filename); i++) {
		unsigned char c = (unsigned char) bdata(filename)[i];
		if (!isalnum(c) && c != '-' && c != '_' && c != '.')
			bdata(filename)[i] = '_';
	}
}



/*!
 * @brief   Parse an SSH ed25519 public key string.
 *
 * Accepts the canonical format produced by ssh-keygen:
 *   @c "ssh-ed25519 BASE64BLOB [COMMENT]"
 *
 * @param[in]  keystr          Null-terminated key string.
 * @param[out] out_ed25519_pub 32-byte raw ed25519 public key.
 * @param[out] out_comment     Heap-allocated, filename-safe comment string
 *                             (@c "unnamed" when absent).  Caller must
 *                             @c free() this.  May be NULL if not needed.
 * @return true on success, false on any parse error.
 */

bool
susshi_log_enc_parse_pubkey(const char *keystr,
                            unsigned char out_ed25519_pub[SUSSHI_LOG_ENC_ED25519_PUB_BYTES],
                            char **out_comment) {
	bool rc = false;

	bstring list = NULL;
	struct bstrList *parts = NULL;
	ssh_key key = NULL;
	size_t pub_len;

	/* Split "ssh-ed25519 BASE64BLOB [COMMENT ...]" on spaces. */
	list = bfromcstr(keystr);
	parts = bsplit(list, ' ');

	if (parts && parts->qty >= 2) {

		if (ssh_pki_import_pubkey_base64(bdata(parts->entry[1]), SSH_KEYTYPE_ED25519, &key) == SSH_OK) {

			pub_len = SUSSHI_LOG_ENC_ED25519_PUB_BYTES;

			if ((EVP_PKEY_get_raw_public_key(key->key, out_ed25519_pub, &pub_len) == 1) &&
			    (pub_len == SUSSHI_LOG_ENC_ED25519_PUB_BYTES)) {

				if (out_comment) {
					bstring comment;

					if (parts->qty >= 3) {
						/* Rejoin comment words */
						comment = bstrcpy(parts->entry[2]);
						for (int i = 3; i < parts->qty; i++) {
							bconchar(comment, ' ');
							bconcat(comment, parts->entry[i]);
						}
					} else {
						comment = bfromcstr("unnamed");
					}

					brtrimws(comment);

					if (blength(comment) == 0) {
						bstrFree(comment);
						comment = bfromcstr("unnamed");
					}

					sanitize_for_filename(comment);
					*out_comment = bstr2cstr(comment, '\0');

					bstrFree(comment);
				}

				rc = true;
			}
		}
	}

	if (key)
		ssh_key_free(key);

	if (parts)
		bstrListDestroy(parts);

	if (list)
		bstrFree(list);

	return rc;
}


/*!
 * @brief   Seal the session key for all recipients and write a single JSON file.
 *
 * For each entry in @p recipients, a fresh ephemeral X25519 keypair is
 * generated, the recipient's ed25519 public key is converted to X25519, and
 * @c crypto_box_easy seals the session key.  All results are written to one
 * JSON file at @c "<base>.enc".
 *
 * @param[in] base        Session base path (log filename with the filetype
 *                        extension stripped).
 * @param[in] session_key 32-byte symmetric session key to seal.
 * @param[in] recipients  Array of recipient descriptors.
 * @param[in] count       Number of entries in @p recipients.
 *
 * @return true if the file was written successfully.
 */

bool
susshi_log_enc_write_recipients(const char *base,
                                const unsigned char session_key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES],
                                const susshi_log_enc_recipient *recipients,
                                int count) {
	json_t *root = json_object();
	json_t *recip_arr = json_array();
	bool enc_ok = true;
	bool rc = false;

	json_object_set_new(root, "version", json_integer(1));
	json_object_set_new(root, "recipients", recip_arr);

	for (int i = 0; i < count && enc_ok; i++) {
		unsigned char x25519_pub[crypto_box_PUBLICKEYBYTES];
		unsigned char ephemeral_pub[crypto_box_PUBLICKEYBYTES];
		unsigned char ephemeral_priv[crypto_box_SECRETKEYBYTES];
		unsigned char nonce[crypto_box_NONCEBYTES];
		unsigned char ciphertext[SUSSHI_LOG_ENC_SESSION_KEY_BYTES + crypto_box_MACBYTES];
		char *b64_ephem = NULL, *b64_nonce = NULL, *b64_ct = NULL;
		size_t b64_len;

		if (crypto_sign_ed25519_pk_to_curve25519(x25519_pub, recipients[i].ed25519_pub) == 0) {
			crypto_box_keypair(ephemeral_pub, ephemeral_priv);
			randombytes_buf(nonce, sizeof(nonce));

			if (crypto_box_easy(ciphertext,
			                    session_key, SUSSHI_LOG_ENC_SESSION_KEY_BYTES,
			                    nonce, x25519_pub, ephemeral_priv) == 0) {
				if (susshi_base64(ephemeral_pub, sizeof(ephemeral_pub), &b64_ephem, &b64_len) &&
				    susshi_base64(nonce, sizeof(nonce), &b64_nonce, &b64_len) &&
				    susshi_base64(ciphertext, sizeof(ciphertext), &b64_ct, &b64_len)) {
					json_t *entry = json_object();
					json_object_set_new(entry, "identity", json_string(recipients[i].identity));
					json_object_set_new(entry, "ephemeral_pub", json_string(b64_ephem));
					json_object_set_new(entry, "nonce", json_string(b64_nonce));
					json_object_set_new(entry, "ciphertext", json_string(b64_ct));
					json_array_append_new(recip_arr, entry);
				} else {
					enc_ok = false;
				}
			} else {
				enc_ok = false;
			}

			sodium_memzero(ephemeral_priv, sizeof(ephemeral_priv));
		} else {
			enc_ok = false;
		}

		if (b64_ephem)
			xfree(b64_ephem);
		if (b64_nonce)
			xfree(b64_nonce);
		if (b64_ct)
			xfree(b64_ct);
	}

	if (enc_ok) {
		char *serialized = json_dumps(root, JSON_INDENT(2));
		if (serialized) {
			bstring path = bformat("%s.enc", base);
			int fd = open(bdata(path), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
			bstrFree(path);
			if (fd >= 0) {
				size_t slen = strlen(serialized);
				ssize_t written = write(fd, serialized, slen);
				close(fd);
				rc = (written == (ssize_t) slen);
			}
			xfree(serialized);
		}
	}

	json_decref(root);

	return rc;
}


/*!
 * @brief   Read an OpenSSH ed25519 private key from a file.
 *
 * Delegates to libssh's @c ssh_pki_import_privkey_file, which handles the
 * standard OpenSSH PEM format including optional passphrase protection.
 *
 * Call with @p passphrase as @c NULL first; if the key is passphrase-protected
 * the function returns false and the caller may prompt the user, then call
 * again with the passphrase string.
 *
 * @param[in]  path           Path to the private key file.
 * @param[in]  passphrase     Passphrase for encrypted keys, or @c NULL for
 *                            unencrypted keys.
 * @param[out] out_ed25519_sk 64-byte libsodium secret key (seed ‖ pubkey).
 *
 * @return true on success.
 */

bool
susshi_log_enc_read_privkey(const char *path, const char *passphrase,
                            unsigned char out_ed25519_sk[SUSSHI_LOG_ENC_ED25519_SK_BYTES]) {
	bool rc = false;
	ssh_key key = NULL;
	size_t seed_len;

	unsigned char seed[crypto_sign_SEEDBYTES];
	unsigned char pub[crypto_sign_PUBLICKEYBYTES]; /* discarded; required by API */

	if (ssh_pki_import_privkey_file(path, passphrase, NULL, NULL, &key) == SSH_OK) {
		/*
		 * With HAVE_LIBCRYPTO the private key lives in an EVP_PKEY.
		 * EVP_PKEY_get_raw_private_key returns the 32-byte seed for ed25519.
		 * Reconstruct the 64-byte libsodium secret key (seed ‖ pubkey) via
		 * crypto_sign_seed_keypair.
		 */
		seed_len = sizeof(seed);

		if (ssh_key_type(key) == SSH_KEYTYPE_ED25519 &&
		    EVP_PKEY_get_raw_private_key(key->key, seed, &seed_len) == 1 &&
		    seed_len == crypto_sign_SEEDBYTES) {

			crypto_sign_seed_keypair(pub, out_ed25519_sk, seed);
			sodium_memzero(seed, sizeof(seed));
			(void) pub;

			rc = true;
		}
	}

	if (key)
		ssh_key_free(key);

	return rc;
}


/*!
 * @brief   Recover the session key from a JSON @c .enc file using a private key.
 *
 * Parses the recipient file with jansson, converts the ed25519 private key to
 * X25519, then tries @c crypto_box_open_easy for each recipient entry until
 * one succeeds.  The caller does not need to know which entry matches.
 *
 * @param[in]  enc_path        Path to the @c <base>.enc file.
 * @param[in]  ed25519_sk      64-byte libsodium ed25519 secret key.
 * @param[out] out_session_key 32-byte recovered session key.
 *
 * @return true on success; false if no entry decrypts with the given key.
 */

bool
susshi_log_enc_recover_session_key(const char *enc_path,
                                   const unsigned char ed25519_sk[SUSSHI_LOG_ENC_ED25519_SK_BYTES],
                                   unsigned char out_session_key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES]) {
	json_error_t jerr;
	json_t *root = json_load_file(enc_path, 0, &jerr);
	bool rc = false;

	if (root) {
		unsigned char x25519_priv[crypto_box_SECRETKEYBYTES];

		if (crypto_sign_ed25519_sk_to_curve25519(x25519_priv, ed25519_sk) == 0) {
			json_t *recip_arr = json_object_get(root, "recipients");

			if (json_is_array(recip_arr)) {
				for (size_t i = 0; i < json_array_size(recip_arr) && !rc; i++) {
					json_t *entry = json_array_get(recip_arr, i);
					const char *b64_ephem = json_string_value(json_object_get(entry, "ephemeral_pub"));
					const char *b64_nonce = json_string_value(json_object_get(entry, "nonce"));
					const char *b64_ct = json_string_value(json_object_get(entry, "ciphertext"));

					if (b64_ephem && b64_nonce && b64_ct) {
						unsigned char *ephem_pub = NULL, *nonce_buf = NULL, *ct_buf = NULL;
						size_t ephem_len, nonce_len, ct_len;

						if (susshi_unbase64(b64_ephem, &ephem_pub, &ephem_len) &&
						    susshi_unbase64(b64_nonce, &nonce_buf, &nonce_len) &&
						    susshi_unbase64(b64_ct, &ct_buf, &ct_len) &&
						    ephem_len == crypto_box_PUBLICKEYBYTES &&
						    nonce_len == crypto_box_NONCEBYTES &&
						    ct_len == SUSSHI_LOG_ENC_SESSION_KEY_BYTES + crypto_box_MACBYTES &&
						    crypto_box_open_easy(out_session_key,
						                         ct_buf, (unsigned long long) ct_len,
						                         nonce_buf, ephem_pub, x25519_priv) == 0)
							rc = true;

						if (ephem_pub)
							xfree(ephem_pub);
						if (nonce_buf)
							xfree(nonce_buf);
						if (ct_buf)
							xfree(ct_buf);
					}
				}
			}

			sodium_memzero(x25519_priv, sizeof(x25519_priv));
		}
		json_decref(root);
	}

	return rc;
}


/*!
 * @brief   Decrypt an encrypted session log file and write plaintext to @p output_fd.
 *
 * Reads the secretstream header, then decrypts chunks of
 * (SUSSHI_LOG_ENC_CHUNK_SIZE + SUSSHI_LOG_ENC_ABYTES) bytes at a time until
 * TAG_FINAL is received.  Returns false if authentication fails at any point.
 *
 * @param[in] encrypted_path Path to the encrypted log file.
 * @param[in] session_key    32-byte session key (recovered from sidecar).
 * @param[in] output_fd      Open, writable file descriptor for plaintext output.
 *
 * @return true on success and authenticated decryption.
 */

bool
susshi_log_enc_decrypt_file(const char *encrypted_path,
                            const unsigned char session_key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES],
                            int output_fd) {
	bool rc = false;
	int fd = -1;

	unsigned char header[SUSSHI_LOG_ENC_HEADER_BYTES];
	crypto_secretstream_xchacha20poly1305_state state;
	unsigned char *ct_buf = NULL;
	unsigned char *pt_buf = NULL;
	ssize_t bytes_read;
	unsigned long long pt_len;
	unsigned char tag;

	fd = open(encrypted_path, O_RDONLY);

	if (fd >= 0) {
		if (read(fd, header, sizeof(header)) == (ssize_t) sizeof(header)) {
			if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, session_key) == 0) {
				/*
				 * Read CT_CHUNK bytes per iteration.  Full chunks are exactly that size;
				 * the final chunk may be shorter (down to ABYTES).
				 * TAG_FINAL signals correct end-of-stream.
				 */

				ct_buf = xmalloc(CT_CHUNK);
				pt_buf = xmalloc(SUSSHI_LOG_ENC_CHUNK_SIZE);

				while (true) {
					bytes_read = read(fd, ct_buf, CT_CHUNK);

					if (bytes_read <= 0)
						break;

					if ((size_t) bytes_read < SUSSHI_LOG_ENC_ABYTES)
						break; /* too short to be a valid authenticated chunk */

					if (crypto_secretstream_xchacha20poly1305_pull(&state,
					                                               pt_buf, &pt_len, &tag,
					                                               ct_buf, (unsigned long long) bytes_read,
					                                               NULL, 0) != 0)
						break; /* authentication failure */

					if (pt_len > 0) {
						if (write(output_fd, pt_buf, (size_t) pt_len) != (ssize_t) pt_len)
							break;
					}

					if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
						rc = true;
						break;
					}
				}

				xfree(ct_buf);
				xfree(pt_buf);
			}
		}
		close(fd);
	}

	return rc;
}

/*!
 * @brief   Locate the @c .enc sidecar file for @p filepath.
 *
 * Strips filename extensions one by one and checks for a @c .enc file after
 * each strip (handles compound extensions such as @c .portfwd.pcap).  If still
 * not found, also strips the trailing @c -NNNNN channel-ID segment to locate
 * the session-level sidecar shared by all channels in the same session.
 * Directory path components containing dots are never consumed.
 *
 * @param[in]  filepath     Path to the encrypted log file.
 * @param[out] enc_path     Buffer that receives the sidecar path on success.
 * @param[in]  enc_path_len Size of @p enc_path in bytes.
 * @return true if a readable @c .enc sidecar was found.
 */

bool
susshi_log_enc_find_sidecar(const char *filepath, char *enc_path, size_t enc_path_len)
{
    char  base[PATH_MAX];
    char *slash;
    char *dot;
    char *dash;
    char *p;
    bool  all_digits;
    bool  rc;

    snprintf(base, sizeof(base), "%s", filepath);
    slash = strrchr(base, '/');
    dot   = strrchr(base, '.');
    rc    = false;

    /* Strip filename extensions one by one; dot > slash ensures directory
       dots (e.g. /var/log/susshi.2026/) are never consumed. */
    while (!rc && dot != NULL && (slash == NULL || dot > slash)) {
        *dot = '\0';
        snprintf(enc_path, enc_path_len, "%s.enc", base);
        if (access(enc_path, F_OK) == 0)
            rc = true;
        else
            dot = strrchr(base, '.');
    }

    /* Fallback: strip the trailing -NNNNN channel-ID segment and try again.
       This matches session-level .enc sidecars (written without the channel
       suffix so they are shared by all channels). */
    if (!rc) {
        dash = strrchr(base, '-');
        if (dash != NULL && (slash == NULL || dash > slash)) {
            all_digits = true;
            for (p = dash + 1; *p; p++) {
                if (*p < '0' || *p > '9') {
                    all_digits = false;
                    break;
                }
            }
            if (all_digits && p > dash + 1) {
                *dash = '\0';
                snprintf(enc_path, enc_path_len, "%s.enc", base);
                if (access(enc_path, F_OK) == 0)
                    rc = true;
            }
        }
    }

    return rc;
}


/*!
 * @brief   Load an ed25519 private key interactively.
 *
 * First attempts to import @p path without a passphrase.  If that fails the
 * user is prompted once via @c getpass(); the passphrase is not stored beyond
 * the second import attempt.
 *
 * @param[in]  path           Path to the OpenSSH private key file.
 * @param[in]  progname       Program name used as the prefix in error messages.
 * @param[out] out_ed25519_sk 64-byte buffer that receives the ed25519 secret key.
 * @return true on success.
 */

bool
susshi_log_enc_load_privkey_interactive(const char *path, const char *progname,
                                        unsigned char out_ed25519_sk[SUSSHI_LOG_ENC_ED25519_SK_BYTES])
{
    const char *passphrase;
    bool        rc;

    rc = false;

    if (access(path, F_OK) != 0) {
        fprintf(stderr, "%s: key file not found: %s\n", progname, path);
    } else if (susshi_log_enc_read_privkey(path, NULL, out_ed25519_sk)) {
        rc = true;
    } else {
        passphrase = getpass("Enter passphrase for private key: ");
        if (passphrase == NULL) {
            fprintf(stderr, "%s: could not read passphrase\n", progname);
        } else if (susshi_log_enc_read_privkey(path, passphrase, out_ed25519_sk)) {
            rc = true;
        } else {
            fprintf(stderr, "%s: failed to load key from %s\n", progname, path);
        }
    }
    return rc;
}

/*! @} */
