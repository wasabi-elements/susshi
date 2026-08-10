/*!
 *
 * @brief       Session log file encryption — shared primitives
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
 */

#ifndef SUSSHI_LOG_ENC_H
#define SUSSHI_LOG_ENC_H

/*
 * Byte-size constants for the log encryption scheme.
 * Exact values verified against libsodium with static_assert in log-enc.c.
 */
#define SUSSHI_LOG_ENC_ED25519_PUB_BYTES  32   /* crypto_sign_PUBLICKEYBYTES                        */
#define SUSSHI_LOG_ENC_ED25519_SK_BYTES   64   /* crypto_sign_SECRETKEYBYTES                        */
#define SUSSHI_LOG_ENC_SESSION_KEY_BYTES  32   /* crypto_secretstream_xchacha20poly1305_KEYBYTES    */
#define SUSSHI_LOG_ENC_HEADER_BYTES       24   /* crypto_secretstream_xchacha20poly1305_HEADERBYTES */
#define SUSSHI_LOG_ENC_ABYTES             17   /* crypto_secretstream_xchacha20poly1305_ABYTES      */

/*
 * Plaintext chunk size for the streaming encryption.
 *
 * The encoder accumulates plaintext until the buffer is full, then flushes
 * it as one secretstream chunk.  The final flush uses TAG_FINAL regardless
 * of how many bytes are in the buffer.
 *
 * The decoder reads (SUSSHI_LOG_ENC_CHUNK_SIZE + SUSSHI_LOG_ENC_ABYTES)
 * bytes per iteration.  When it reads fewer bytes, that is the final chunk.
 * TAG_FINAL confirms correct termination.
 */
#define SUSSHI_LOG_ENC_CHUNK_SIZE  65536

/*
 * Encrypted log file layout:
 *   [HEADER_BYTES]              crypto_secretstream header  (per log file)
 *   [CHUNK_SIZE + ABYTES] × n   full encrypted chunks
 *   [≤ CHUNK_SIZE + ABYTES]     final chunk  (TAG_FINAL, may be shorter)
 *
 * Sidecar file layout  (per recipient, 104 bytes):
 *   [32]  ephemeral X25519 public key  (fresh per sidecar)
 *   [24]  nonce
 *   [48]  crypto_box_easy(session_key) — 32 bytes plaintext + 16 bytes MAC
 *
 * The session key is shared by all encrypted log files of one session.
 * Each log file has its own secretstream header (= own nonce), so their
 * ciphertexts are independent even though the key is the same.
 * Sidecar files are written once at session start at the base path derived
 * from the first log file by stripping its filetype extension.
 */


/*
 * One entry in the recipients list passed to susshi_log_enc_write_recipients.
 * The identity must be filename-safe (only [A-Za-z0-9._-]); use
 * susshi_log_enc_parse_pubkey to obtain a sanitised identity from a key string.
 */
typedef struct {
    const char    *identity;
    unsigned char  ed25519_pub[SUSSHI_LOG_ENC_ED25519_PUB_BYTES];
} susshi_log_enc_recipient;


bool susshi_log_enc_parse_pubkey(const char *keystr,
                                  unsigned char out_ed25519_pub[SUSSHI_LOG_ENC_ED25519_PUB_BYTES],
                                  char **out_comment);

bool susshi_log_enc_write_recipients(const char *base,
                                      const unsigned char session_key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES],
                                      const susshi_log_enc_recipient *recipients,
                                      int count);

bool susshi_log_enc_read_privkey(const char *path, const char *passphrase,
                                  unsigned char out_ed25519_sk[SUSSHI_LOG_ENC_ED25519_SK_BYTES]);

bool susshi_log_enc_recover_session_key(const char *enc_path,
                                         const unsigned char ed25519_sk     [SUSSHI_LOG_ENC_ED25519_SK_BYTES],
                                         unsigned char       out_session_key [SUSSHI_LOG_ENC_SESSION_KEY_BYTES]);

bool susshi_log_enc_decrypt_file(const char *encrypted_path,
                                  const unsigned char session_key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES],
                                  int output_fd);

bool susshi_log_enc_find_sidecar(const char *filepath, char *enc_path, size_t enc_path_len);

bool susshi_log_enc_load_privkey_interactive(const char *path, const char *progname,
                                              unsigned char out_ed25519_sk[SUSSHI_LOG_ENC_ED25519_SK_BYTES]);

#endif /* SUSSHI_LOG_ENC_H */
