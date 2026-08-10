/*!
 *
 * @brief       Session log file encryption methods
 *
 * @ingroup     susshid
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
 * @defgroup    logging_session_enc Session log file encryption methods
 * @brief       susshid-side streaming encryption for session trail log files.
 *
 * Hybrid encryption for session trail log files using libsodium.
 *
 * Scheme (per session):
 *   - One random 32-byte symmetric key is generated for the entire session.
 *   - All log files belonging to the session (.session, .client, .time, …)
 *     are encrypted with this single key.
 *   - For each recipient ed25519 public key in SessionLogEncryptionKeys:
 *       · The ed25519 key is converted to X25519.
 *       · The session key is sealed with crypto_box_easy (ephemeral private ↔
 *         recipient X25519 public) and stored in a sidecar file written once
 *         at session start.
 *   - Each log file gets its own crypto_secretstream instance (and therefore
 *     its own random header / nonce), so ciphertexts are independent.
 *
 * Recipient file name:  <session-base>.enc
 *   <session-base> = log filename with the filetype extension stripped,
 *
 * Recipient file format (JSON, clear-text):
 *   {
 *     "version": 1,
 *     "recipients": [
 *       {
 *         "identity": "<sanitised-key-identity>",
 *         "ephemeral_pub": "<base64, 32 bytes>",
 *         "nonce": "<base64, 24 bytes>",
 *         "ciphertext": "<base64, 48 bytes — 32-byte key + 16-byte MAC>"
 *       }, ...
 *     ]
 *   }
 *
 * Encrypted log file layout:
 *   [24]  crypto_secretstream header  (contains the per-file nonce)
 *   [n]   crypto_secretstream ciphertext chunks  (plaintext + 17 bytes each)
 *   [17]  TAG_FINAL chunk  (written on close)
 *
 * @{
 */

#include "susshid/common.h"


/*
 * Per-file encryption state stored behind SusshiLog.enc_state.
 *
 * A 64-KiB plaintext buffer accumulates writes until full, at which point
 * a secretstream chunk is flushed to disk.  The final flush (TAG_FINAL)
 * happens in log_session_enc_finalize() regardless of how much data is
 * buffered.  This gives the decoder a fixed read stride of
 * (SUSSHI_LOG_ENC_CHUNK_SIZE + SUSSHI_LOG_ENC_ABYTES) bytes per iteration,
 * with the last chunk potentially shorter.
 */

typedef struct {
    crypto_secretstream_xchacha20poly1305_state stream;
    unsigned char buf[SUSSHI_LOG_ENC_CHUNK_SIZE];
    size_t        buf_used;
} LogSessionEncState;


/*
 * One symmetric key is shared by all encrypted log files of a session
 * (.session, .client, .time, …).  It is generated the first time an
 * encrypted log file is opened and reused for every subsequent open,
 * including rotation opens.
 *
 * Each log file still gets its own secretstream state and random header,
 * so the per-file ciphertexts are independent even with the same key.
 *
 * The recipient file (<base>.enc) is written exactly once per session, placed
 * next to the first encrypted log file.  It remains valid for all files in
 * the session regardless of log rotation, because the key never changes
 * within a session.
 *
 * Safe within the fork-per-session model: the statics are zero-initialised
 * in every child process and never shared between sessions.
 */

static unsigned char g_session_key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
static bool          g_session_key_ready = false;


/*
 * Generate the session key and write one sidecar per configured recipient.
 * Called once, on the first encrypted log file open.
 *
 * The sidecar base path is derived from log->filename by stripping the
 * ".<filetype>" suffix, so all log types share the same set of sidecars.
 */

static void
init_session_key(SusshiLog *log)
{
    bstring                   base      = NULL;
    susshi_log_enc_recipient *recipients = NULL;
    int                       n, num_valid;

    crypto_secretstream_xchacha20poly1305_keygen(g_session_key);

    base = bstrcpy(log->filename);

    /* Build the recipient file base: strip ".<filetype>" from the log filename. */
    if (log->filetype && blength(log->filetype) > 0) {
        int suffix_pos = blength(base) - blength(log->filetype) - 1;
        if (suffix_pos > 0 && bchar(base, suffix_pos) == '.')
            btrunc(base, suffix_pos);
    }

    /* Strip the per-channel ID suffix (e.g. -00029) so the .enc sidecar is
       shared by all channels in the session. */
    if (log->ucid >= 0) {
        char cid_suffix[8];
        int  suffix_len;
        snprintf(cid_suffix, sizeof(cid_suffix), "-%05ld", log->ucid);
        suffix_len = (int)strlen(cid_suffix);
        if (blength(base) > suffix_len &&
            memcmp(bdata(base) + blength(base) - suffix_len,
                   cid_suffix, (size_t)suffix_len) == 0)
            btrunc(base, blength(base) - suffix_len);
    }

    n         = susshi_cfg.num_session_log_encryption_keys;
    num_valid = 0;

    if (n > 0) {
        recipients = xmalloc((size_t)n * sizeof(*recipients));

        for (int i = 0; i < n; i++) {
            const char *keystr  = bdata(susshi_cfg.session_log_encryption_keys[i]);
            char       *comment = NULL;

            if (!susshi_log_enc_parse_pubkey(keystr,
                                              recipients[num_valid].ed25519_pub,
                                              &comment)) {
                error("log_session_enc: could not parse encryption key #%d — skipping", i + 1);
                continue;
            }
            recipients[num_valid].identity = comment;
            num_valid++;
        }

        if (num_valid > 0 &&
            !susshi_log_enc_write_recipients(bdata(base), g_session_key,
                                              recipients, num_valid))
            error("log_session_enc: failed to write .enc recipient file");

        for (int i = 0; i < num_valid; i++)
            free((char *)recipients[i].identity);
        xfree(recipients);
    }

    bstrFree(base);
    g_session_key_ready = true;
    debug2("log_session_enc: session key initialised");
}


/*!
 * @brief   Initialise per-file encryption for a log file that has just been opened.
 *
 * On the first call for a session, generates the session key and writes one
 * sidecar file per configured recipient key at the session base path
 * (log->filename with the filetype extension stripped).  On subsequent
 * calls — for other log types (.client, .time) or after log rotation — the
 * existing session key is reused without writing new sidecars.
 *
 * Each call allocates a fresh LogSessionEncState with its own 64-KiB write
 * buffer and secretstream instance (= unique random nonce via the stream
 * header), so per-file ciphertexts are independent.
 *
 * @param[in,out] log   SusshiLog with a valid fd, filename, and filetype.
 * @return              true on success.
 */

bool
log_session_enc_open(SusshiLog *log)
{
	LogSessionEncState *state = NULL;
	unsigned char header[SUSSHI_LOG_ENC_HEADER_BYTES];

	if (log->fd == NULL || log->filename == NULL)
        return false;

    /* Safety: release leftover state (should be NULL after finalize). */
    if (log->enc_state != NULL) {
        xfree(log->enc_state);
        log->enc_state = NULL;
    }

    if (!g_session_key_ready)
        init_session_key(log);

    state = xmalloc(sizeof(LogSessionEncState));
    state->buf_used = 0;

    if (crypto_secretstream_xchacha20poly1305_init_push(&state->stream, header, g_session_key) != 0) {
        xfree(state);
        error("log_session_enc: secretstream init failed for %s", bdata(log->filename));
        return false;
    }

    fwrite(header, sizeof(header), 1, log->fd);
    log->enc_state = state;
    debug2("log_session_enc: encryption active for %s", bdata(log->filename));
    return true;
}


/*!
 * @brief   Encrypt @p state->buf as one secretstream chunk and write it to @p fd.
 *
 * Calls @c crypto_secretstream_xchacha20poly1305_push with the accumulated
 * plaintext buffer, then writes the resulting ciphertext
 * (@c state->buf_used + @c SUSSHI_LOG_ENC_ABYTES bytes) to @p fd.
 * Resets @c state->buf_used to zero after a successful write so the buffer
 * is ready for the next accumulation cycle.
 *
 * @param[in,out] state  Per-file encryption state; @c buf and @c stream are read,
 *                        @c buf_used is reset to zero on return.
 * @param[in]     fd     Open, writable @c FILE* for the encrypted log file.
 * @param[in]     tag    Secretstream tag: @c TAG_MESSAGE for mid-stream chunks,
 *                        @c TAG_FINAL for the closing chunk.
 */

static void
flush_chunk(LogSessionEncState *state, FILE *fd, unsigned char tag)
{
    size_t ct_len = state->buf_used + SUSSHI_LOG_ENC_ABYTES;
    unsigned char *ct = xmalloc(ct_len);

    crypto_secretstream_xchacha20poly1305_push(&state->stream, ct, NULL,
        state->buf, state->buf_used, NULL, 0, tag);

    fwrite(ct, ct_len, 1, fd);
    xfree(ct);
    state->buf_used = 0;
}


/*!
 * @brief   Encrypt @p len bytes from @p data and write them to the log file.
 *
 * Plaintext is accumulated in an internal 64-KiB buffer.  A full buffer
 * triggers a flush of one secretstream chunk (TAG_MESSAGE) to the file.
 * Partial buffers are flushed only when log_session_enc_finalize() is called.
 *
 * @param[in,out] log   SusshiLog with active encryption state.
 * @param[in]     data  Plaintext bytes to encrypt.
 * @param[in]     len   Number of bytes in @p data.
 */

void
log_session_enc_write(SusshiLog *log, const unsigned char *data, size_t len)
{
	LogSessionEncState *state = NULL;

	if (log->enc_state == NULL || log->fd == NULL || len == 0)
        return;

    state = (LogSessionEncState *)log->enc_state;

    while (len > 0) {
        size_t space = SUSSHI_LOG_ENC_CHUNK_SIZE - state->buf_used;
        size_t take  = (len < space) ? len : space;

        memcpy(state->buf + state->buf_used, data, take);
        state->buf_used += take;
        data += take;
        len  -= take;

        if (state->buf_used == SUSSHI_LOG_ENC_CHUNK_SIZE)
            flush_chunk(state, log->fd, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
    }
}


/*!
 * @brief   Finalise and close the encryption stream for a log file.
 *
 * Flushes any remaining buffered plaintext as a TAG_FINAL secretstream chunk,
 * flushing the FILE buffer, then frees the per-file state and zeros
 * log->enc_state.  The session key (g_session_key) is not touched.
 *
 * Must be called before fclose() so the final tag reaches the file.
 * Safe to call when log->enc_state is already NULL.
 *
 * @param[in,out] log   SusshiLog whose encryption stream should be closed.
 */
void
log_session_enc_finalize(SusshiLog *log)
{
	LogSessionEncState *state = NULL;

	if (log->enc_state == NULL || log->fd == NULL)
        return;

    state = (LogSessionEncState *)log->enc_state;

    flush_chunk(state, log->fd, crypto_secretstream_xchacha20poly1305_TAG_FINAL);
    fflush(log->fd);

    xfree(state);
    log->enc_state = NULL;
}

/*! @} */
