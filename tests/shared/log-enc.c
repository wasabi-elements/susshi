/*!
 *
 * @brief       susshid Tests — Session log encryption
 *
 * @ingroup     tests_susshid
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
 * @defgroup    tests_shared_log_enc    Tests for shared library | Session log encryption
 * @{
 */

#include "shared/common.h"
#include "shared/base64.h"
#include "shared/log-enc.h"
#include <sodium.h>
#include <unity/unity.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* Forward declarations for all test functions (required by -Wmissing-prototypes). */
void test_parse_pubkey_valid(void);
void test_parse_pubkey_no_comment_yields_unnamed(void);
void test_parse_pubkey_comment_sanitized(void);
void test_parse_pubkey_blob_too_short(void);
void test_parse_pubkey_no_space(void);
void test_enc_roundtrip(void);
void test_enc_multi_recipient_roundtrip(void);
void test_enc_wrong_key_rejected(void);
void test_enc_missing_file(void);
void test_privkey_roundtrip(void);
void test_privkey_passphrase_protected_rejected(void);
void test_privkey_bad_checkint_rejected(void);
void test_privkey_missing_file(void);
void test_decrypt_roundtrip_small(void);
void test_decrypt_roundtrip_multi_chunk(void);
void test_decrypt_wrong_key_rejected(void);
void test_decrypt_tampered_ciphertext_rejected(void);
void test_decrypt_missing_file(void);
void test_full_roundtrip(void);


/* --------------------------------------------------------------------------
 * Temp-file bookkeeping
 *
 * setUp resets the list.  tearDown unlinks every registered path so no test
 * leaves files behind, even on failure.
 * -------------------------------------------------------------------------- */

#define MAX_TEMP_FILES 32

static char g_tmp[MAX_TEMP_FILES][256];
static int  g_ntmp;

/* Create a unique temp file, register it for cleanup, return its path. */
static void tmp_path(char *buf, size_t buflen)
{
    int fd;

    snprintf(buf, buflen, "/tmp/susshi-enc-test-XXXXXX");
    fd = mkstemp(buf);
    if (fd >= 0)
        close(fd);
    if (g_ntmp < MAX_TEMP_FILES)
        snprintf(g_tmp[g_ntmp++], 256, "%s", buf);
}

/* Register an additional path (e.g. a sidecar) for cleanup without creating it. */
static void register_tmp(const char *path)
{
    if (g_ntmp < MAX_TEMP_FILES)
        snprintf(g_tmp[g_ntmp++], 256, "%s", path);
}

void fatal(const char *fmt, ...) { (void)fmt; }

void setUp(void)
{
    (void)sodium_init();
    g_ntmp = 0;
}

void tearDown(void)
{
    for (int i = 0; i < g_ntmp; i++)
        unlink(g_tmp[i]);
    g_ntmp = 0;
}


/* --------------------------------------------------------------------------
 * Binary serialisation helpers (OpenSSH / SSH wire format)
 * -------------------------------------------------------------------------- */

static void put_u32be(unsigned char *buf, uint32_t v)
{
    buf[0] = (v >> 24) & 0xFF;
    buf[1] = (v >> 16) & 0xFF;
    buf[2] = (v >>  8) & 0xFF;
    buf[3] =  v        & 0xFF;
}

static size_t pack_str(unsigned char *buf, const void *data, uint32_t len)
{
    put_u32be(buf, len);
    memcpy(buf + 4, data, len);
    return 4 + (size_t)len;
}

/*
 * Build a "ssh-ed25519 BASE64 COMMENT" string from a raw ed25519 public key.
 * Caller must free() the returned pointer.
 */
static char *make_ssh_pubkey_str(const unsigned char pub[32], const char *comment)
{
    unsigned char wire[51];
    char         *b64     = NULL;
    char         *out;
    size_t        pos     = 0;
    size_t        b64_len = 0;
    size_t        out_len;

    pos += pack_str(wire + pos, "ssh-ed25519", 11);
    pos += pack_str(wire + pos, pub, 32);

    if (!susshi_base64(wire, pos, &b64, &b64_len))
        return NULL;

    out_len = 12 + b64_len + 1 + strlen(comment) + 1;
    out     = malloc(out_len);
    snprintf(out, out_len, "ssh-ed25519 %s %s", b64, comment);
    free(b64);
    return out;
}


/*
 * Write a secretstream-encrypted file from arbitrary plaintext.
 * Mirrors the chunk-flushing behaviour of log_session_enc_write/finalize
 * so that susshi_log_enc_decrypt_file can read back what we write.
 */
static bool write_encrypted_file(const char *path,
                                  const unsigned char key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES],
                                  const unsigned char *pt, size_t pt_len)
{
    crypto_secretstream_xchacha20poly1305_state state;
    unsigned char        header[SUSSHI_LOG_ENC_HEADER_BYTES];
    unsigned char       *ct;
    const unsigned char *p;
    size_t               rem;
    int                  fd;

    if (crypto_secretstream_xchacha20poly1305_init_push(&state, header, key) != 0)
        return false;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return false;

    write(fd, header, sizeof(header));

    ct  = xmalloc(SUSSHI_LOG_ENC_CHUNK_SIZE + SUSSHI_LOG_ENC_ABYTES);
    p   = pt;
    rem = pt_len;

    do {
        size_t take = (rem > SUSSHI_LOG_ENC_CHUNK_SIZE) ? SUSSHI_LOG_ENC_CHUNK_SIZE : rem;
        bool   last = (take == rem);
        unsigned char tag = last ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
                                 : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
        unsigned long long ct_len;

        crypto_secretstream_xchacha20poly1305_push(&state, ct, &ct_len,
                                                   p, take, NULL, 0, tag);
        write(fd, ct, (size_t)ct_len);
        p   += take;
        rem -= take;
        if (last)
            break;
    } while (true);

    xfree(ct);
    close(fd);
    return true;
}

/* Read an entire file into a heap buffer; *out_len receives the byte count. */
static unsigned char *read_file_contents(const char *path, size_t *out_len)
{
    unsigned char *buf;
    off_t          sz;
    ssize_t        n;
    int            fd = open(path, O_RDONLY);

    if (fd < 0)
        return NULL;
    sz = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    if (sz <= 0) { close(fd); return NULL; }
    buf = malloc((size_t)sz);
    n   = read(fd, buf, (size_t)sz);
    close(fd);
    *out_len = (n > 0) ? (size_t)n : 0;
    return buf;
}

static int generate_ed25519_key(ssh_key *out)
{
    ssh_pki_ctx ctx = ssh_pki_ctx_new();
    int         rc  = ssh_pki_generate_key(SSH_KEYTYPE_ED25519, ctx, out);

    ssh_pki_ctx_free(ctx);
    return rc;
}


/* ==========================================================================
 * Tests: susshi_log_enc_parse_pubkey
 * ========================================================================== */

void test_parse_pubkey_valid(void)
{
    unsigned char pub[32], sk[64];
    unsigned char out_pub[32];
    char         *out_comment = NULL;
    char         *keystr;

    crypto_sign_keypair(pub, sk);
    keystr = make_ssh_pubkey_str(pub, "mykey");
    TEST_ASSERT_NOT_NULL(keystr);
    TEST_ASSERT_TRUE(susshi_log_enc_parse_pubkey(keystr, out_pub, &out_comment));
    TEST_ASSERT_EQUAL_MEMORY(pub, out_pub, 32);
    TEST_ASSERT_EQUAL_STRING("mykey", out_comment);
    free(keystr);
    free(out_comment);
}

void test_parse_pubkey_no_comment_yields_unnamed(void)
{
    unsigned char pub[32], sk[64];
    unsigned char wire[51];
    unsigned char out_pub[32];
    char         *b64         = NULL;
    char         *keystr      = NULL;
    char         *out_comment = NULL;
    size_t        pos         = 0;
    size_t        b64_len     = 0;
    size_t        keystr_len;

    crypto_sign_keypair(pub, sk);

    /* Build the SSH wire blob and base64-encode it without a trailing comment. */
    pos += pack_str(wire + pos, "ssh-ed25519", 11);
    pos += pack_str(wire + pos, pub, 32);
    TEST_ASSERT_TRUE(susshi_base64(wire, pos, &b64, &b64_len));

    keystr_len = 12 + b64_len + 1;
    keystr = malloc(keystr_len);
    snprintf(keystr, keystr_len, "ssh-ed25519 %s", b64);
    free(b64);

    TEST_ASSERT_TRUE(susshi_log_enc_parse_pubkey(keystr, out_pub, &out_comment));
    TEST_ASSERT_EQUAL_STRING("unnamed", out_comment);
    free(keystr);
    free(out_comment);
}

void test_parse_pubkey_comment_sanitized(void)
{
    unsigned char pub[32], sk[64];
    unsigned char out_pub[32];
    char         *out_comment = NULL;
    char         *keystr;

    crypto_sign_keypair(pub, sk);

    /* '@' is not filename-safe and must be replaced with '_'. */
    keystr = make_ssh_pubkey_str(pub, "user@host.example.com");
    TEST_ASSERT_NOT_NULL(keystr);
    TEST_ASSERT_TRUE(susshi_log_enc_parse_pubkey(keystr, out_pub, &out_comment));
    TEST_ASSERT_EQUAL_STRING("user_host.example.com", out_comment);
    free(keystr);
    free(out_comment);
}

void test_parse_pubkey_blob_too_short(void)
{
    /* "AAAA" decodes to 3 bytes — far too short for a valid ed25519 blob. */
    unsigned char out_pub[32];
    TEST_ASSERT_FALSE(susshi_log_enc_parse_pubkey("ssh-ed25519 AAAA comment", out_pub, NULL));
}

void test_parse_pubkey_no_space(void)
{
    unsigned char out_pub[32];
    TEST_ASSERT_FALSE(susshi_log_enc_parse_pubkey("nospacehere", out_pub, NULL));
}


/* ==========================================================================
 * Tests: susshi_log_enc_write_recipients / susshi_log_enc_recover_session_key
 * ========================================================================== */

void test_enc_roundtrip(void)
{
    unsigned char           pub[32], sk[64];
    unsigned char           session_key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
    unsigned char           recovered[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
    char                    base[256];
    char                    enc_path[512];
    susshi_log_enc_recipient r;

    crypto_sign_keypair(pub, sk);
    crypto_secretstream_xchacha20poly1305_keygen(session_key);
    tmp_path(base, sizeof(base));

    r.identity = "testkey";
    memcpy(r.ed25519_pub, pub, sizeof(r.ed25519_pub));
    TEST_ASSERT_TRUE(susshi_log_enc_write_recipients(base, session_key, &r, 1));

    snprintf(enc_path, sizeof(enc_path), "%s.enc", base);
    register_tmp(enc_path);

    TEST_ASSERT_TRUE(susshi_log_enc_recover_session_key(enc_path, sk, recovered));
    TEST_ASSERT_EQUAL_MEMORY(session_key, recovered, SUSSHI_LOG_ENC_SESSION_KEY_BYTES);
}

void test_enc_multi_recipient_roundtrip(void)
{
    unsigned char           pub1[32], sk1[64], pub2[32], sk2[64];
    unsigned char           session_key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
    unsigned char           rec1[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
    unsigned char           rec2[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
    char                    base[256];
    char                    enc_path[512];
    susshi_log_enc_recipient recipients[2];

    crypto_sign_keypair(pub1, sk1);
    crypto_sign_keypair(pub2, sk2);
    crypto_secretstream_xchacha20poly1305_keygen(session_key);
    tmp_path(base, sizeof(base));

    recipients[0].identity = "alice";
    memcpy(recipients[0].ed25519_pub, pub1, sizeof(recipients[0].ed25519_pub));
    recipients[1].identity = "bob";
    memcpy(recipients[1].ed25519_pub, pub2, sizeof(recipients[1].ed25519_pub));
    TEST_ASSERT_TRUE(susshi_log_enc_write_recipients(base, session_key, recipients, 2));

    snprintf(enc_path, sizeof(enc_path), "%s.enc", base);
    register_tmp(enc_path);

    /* Both keys must independently recover the same session key. */
    TEST_ASSERT_TRUE(susshi_log_enc_recover_session_key(enc_path, sk1, rec1));
    TEST_ASSERT_TRUE(susshi_log_enc_recover_session_key(enc_path, sk2, rec2));
    TEST_ASSERT_EQUAL_MEMORY(session_key, rec1, SUSSHI_LOG_ENC_SESSION_KEY_BYTES);
    TEST_ASSERT_EQUAL_MEMORY(session_key, rec2, SUSSHI_LOG_ENC_SESSION_KEY_BYTES);
}

void test_enc_wrong_key_rejected(void)
{
    unsigned char           pub1[32], sk1[64], pub2[32], sk2[64];
    unsigned char           session_key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
    unsigned char           recovered[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
    char                    base[256];
    char                    enc_path[512];
    susshi_log_enc_recipient r;

    crypto_sign_keypair(pub1, sk1);
    crypto_sign_keypair(pub2, sk2);
    crypto_secretstream_xchacha20poly1305_keygen(session_key);
    tmp_path(base, sizeof(base));

    /* Write only for pub1; recovering with sk2 must fail. */
    r.identity = "k1";
    memcpy(r.ed25519_pub, pub1, sizeof(r.ed25519_pub));
    TEST_ASSERT_TRUE(susshi_log_enc_write_recipients(base, session_key, &r, 1));

    snprintf(enc_path, sizeof(enc_path), "%s.enc", base);
    register_tmp(enc_path);

    TEST_ASSERT_FALSE(susshi_log_enc_recover_session_key(enc_path, sk2, recovered));
}

void test_enc_missing_file(void)
{
    unsigned char sk[64], pub[32];
    unsigned char out[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];

    crypto_sign_keypair(pub, sk);
    TEST_ASSERT_FALSE(susshi_log_enc_recover_session_key(
            "/tmp/does-not-exist-susshi-enc", sk, out));
}


/* ==========================================================================
 * Tests: susshi_log_enc_read_privkey
 * ========================================================================== */

void test_privkey_roundtrip(void)
{
    char                    path[256];
    char                    base[256];
    char                    enc_path[512];
    ssh_key                 key;
    unsigned char           sk[SUSSHI_LOG_ENC_ED25519_SK_BYTES];
    unsigned char           session_key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
    unsigned char           result[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
    susshi_log_enc_recipient r;

    tmp_path(path, sizeof(path));

    /* Use libssh's own generation and export — hand-crafting the OpenSSH binary
     * format is unreliable because the patched libssh rejects keys it did not
     * write itself. */
    TEST_ASSERT_EQUAL_INT(SSH_OK, generate_ed25519_key(&key));
    TEST_ASSERT_EQUAL_INT(SSH_OK,
                          ssh_pki_export_privkey_file(key, NULL, NULL, NULL, path));
    ssh_key_free(key);

    TEST_ASSERT_TRUE(susshi_log_enc_read_privkey(path, NULL, sk));

    /* Verify the recovered key is functionally correct: the last 32 bytes of a
     * libsodium ed25519 sk are the public key.  Encrypt a random session key with
     * that public key, then recover it with the full sk. */
    tmp_path(base, sizeof(base));
    snprintf(enc_path, sizeof(enc_path), "%s.enc", base);
    register_tmp(enc_path);

    crypto_secretstream_xchacha20poly1305_keygen(session_key);

    r.identity = "roundtrip";
    memcpy(r.ed25519_pub, sk + 32, 32);
    TEST_ASSERT_TRUE(susshi_log_enc_write_recipients(base, session_key, &r, 1));

    TEST_ASSERT_TRUE(susshi_log_enc_recover_session_key(enc_path, sk, result));
    TEST_ASSERT_EQUAL_MEMORY(session_key, result, SUSSHI_LOG_ENC_SESSION_KEY_BYTES);
}

void test_privkey_passphrase_protected_rejected(void)
{
    char          path[256];
    ssh_key       key;
    unsigned char recovered[SUSSHI_LOG_ENC_ED25519_SK_BYTES];

    tmp_path(path, sizeof(path));

    /* Generate and write a real passphrase-protected ed25519 key via libssh. */
    TEST_ASSERT_EQUAL_INT(SSH_OK, generate_ed25519_key(&key));
    TEST_ASSERT_EQUAL_INT(SSH_OK,
            ssh_pki_export_privkey_file(key, "susshi-test-pass", NULL, NULL, path));
    ssh_key_free(key);

    /* NULL passphrase must fail — key is encrypted. */
    TEST_ASSERT_FALSE(susshi_log_enc_read_privkey(path, NULL, recovered));
    /* Correct passphrase must succeed. */
    TEST_ASSERT_TRUE(susshi_log_enc_read_privkey(path, "susshi-test-pass", recovered));
}

void test_privkey_bad_checkint_rejected(void)
{
    const char     HDR[]       = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
    char           path[256];
    char          *b64s;
    char          *b64e;
    char          *b64buf;
    char          *new_b64     = NULL;
    unsigned char  recovered[SUSSHI_LOG_ENC_ED25519_SK_BYTES];
    unsigned char *raw         = NULL;
    unsigned char *decoded     = NULL;
    ssh_key        key;
    size_t         raw_len     = 0;
    size_t         blen;
    size_t         n           = 0;
    size_t         decoded_len = 0;
    size_t         new_b64_len = 0;
    int            fd;

    /* Write a valid key with libssh, then corrupt one byte in the binary blob
     * so that libssh rejects the file as malformed. */
    tmp_path(path, sizeof(path));
    TEST_ASSERT_EQUAL_INT(SSH_OK, generate_ed25519_key(&key));
    TEST_ASSERT_EQUAL_INT(SSH_OK,
                          ssh_pki_export_privkey_file(key, NULL, NULL, NULL, path));
    ssh_key_free(key);

    /* Read the raw PEM, decode, flip checkint2 byte 0, re-encode. */
    raw = read_file_contents(path, &raw_len);
    TEST_ASSERT_NOT_NULL(raw);

    /* Locate base64 body between the PEM delimiters. */
    b64s = strstr((char *)raw, HDR);
    b64s += strlen(HDR);
    b64e = strstr(b64s, "-----END");

    /* Strip whitespace and decode. */
    blen   = (size_t)(b64e - b64s);
    b64buf = malloc(blen + 1);
    for (size_t i = 0; i < blen; i++) {
        char c = b64s[i];
        if (c != '\n' && c != '\r' && c != ' ')
            b64buf[n++] = c;
    }
    b64buf[n] = '\0';

    TEST_ASSERT_TRUE(susshi_unbase64(b64buf, &decoded, &decoded_len));
    free(b64buf);
    free(raw);

    /* Flip offset 16 (first byte of the ciphername length field, right after the
     * 16-byte magic) to produce an unrecognisable blob that libssh will reject. */
    decoded[16] ^= 0xFF;

    TEST_ASSERT_TRUE(susshi_base64(decoded, decoded_len, &new_b64, &new_b64_len));
    free(decoded);

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    dprintf(fd, "-----BEGIN OPENSSH PRIVATE KEY-----\n");
    write(fd, new_b64, new_b64_len);
    dprintf(fd, "\n-----END OPENSSH PRIVATE KEY-----\n");
    close(fd);
    free(new_b64);

    TEST_ASSERT_FALSE(susshi_log_enc_read_privkey(path, NULL, recovered));
}

void test_privkey_missing_file(void)
{
    unsigned char recovered[SUSSHI_LOG_ENC_ED25519_SK_BYTES];
    TEST_ASSERT_FALSE(susshi_log_enc_read_privkey(
            "/tmp/does-not-exist-susshi-privkey", NULL, recovered));
}


/* ==========================================================================
 * Tests: susshi_log_enc_decrypt_file
 * ========================================================================== */

void test_decrypt_roundtrip_small(void)
{
    const char     pt[]     = "Hello, suSSHi!\nThis tests single-chunk encryption.\n";
    unsigned char  key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
    unsigned char *readback;
    char           enc_path[256], dec_path[256];
    size_t         pt_len   = strlen(pt);
    size_t         read_len = 0;
    int            out_fd;

    crypto_secretstream_xchacha20poly1305_keygen(key);
    tmp_path(enc_path, sizeof(enc_path));
    tmp_path(dec_path, sizeof(dec_path));

    TEST_ASSERT_TRUE(write_encrypted_file(enc_path, key, (const unsigned char *)pt, pt_len));

    out_fd = open(dec_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    TEST_ASSERT_TRUE(out_fd >= 0);
    TEST_ASSERT_TRUE(susshi_log_enc_decrypt_file(enc_path, key, out_fd));
    close(out_fd);

    readback = read_file_contents(dec_path, &read_len);
    TEST_ASSERT_NOT_NULL(readback);
    TEST_ASSERT_EQUAL(pt_len, read_len);
    TEST_ASSERT_EQUAL_MEMORY(pt, readback, pt_len);
    free(readback);
}

void test_decrypt_roundtrip_multi_chunk(void)
{
    /* 2.5 chunks exercises the multi-chunk flush path. */
    size_t         pt_len   = SUSSHI_LOG_ENC_CHUNK_SIZE * 2 + 12345;
    unsigned char *pt       = malloc(pt_len);
    unsigned char  key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
    unsigned char *readback;
    char           enc_path[256], dec_path[256];
    size_t         read_len = 0;
    int            out_fd;

    for (size_t i = 0; i < pt_len; i++)
        pt[i] = (unsigned char)(i & 0xFF);

    crypto_secretstream_xchacha20poly1305_keygen(key);
    tmp_path(enc_path, sizeof(enc_path));
    tmp_path(dec_path, sizeof(dec_path));

    TEST_ASSERT_TRUE(write_encrypted_file(enc_path, key, pt, pt_len));

    out_fd = open(dec_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    TEST_ASSERT_TRUE(out_fd >= 0);
    TEST_ASSERT_TRUE(susshi_log_enc_decrypt_file(enc_path, key, out_fd));
    close(out_fd);

    readback = read_file_contents(dec_path, &read_len);
    TEST_ASSERT_NOT_NULL(readback);
    TEST_ASSERT_EQUAL(pt_len, read_len);
    TEST_ASSERT_EQUAL_MEMORY(pt, readback, pt_len);

    free(pt);
    free(readback);
}

void test_decrypt_wrong_key_rejected(void)
{
    const char    pt[] = "Secret data.";
    unsigned char key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
    unsigned char wrong[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
    char          enc_path[256], dec_path[256];
    int           out_fd;

    crypto_secretstream_xchacha20poly1305_keygen(key);
    crypto_secretstream_xchacha20poly1305_keygen(wrong);
    tmp_path(enc_path, sizeof(enc_path));
    tmp_path(dec_path, sizeof(dec_path));

    TEST_ASSERT_TRUE(write_encrypted_file(enc_path, key,
                                          (const unsigned char *)pt, strlen(pt)));

    out_fd = open(dec_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    TEST_ASSERT_FALSE(susshi_log_enc_decrypt_file(enc_path, wrong, out_fd));
    close(out_fd);
}

void test_decrypt_tampered_ciphertext_rejected(void)
{
    const char    pt[] = "Secret data that must not be tampered.";
    unsigned char key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
    unsigned char b;
    char          enc_path[256], dec_path[256];
    int           tfd;
    int           out_fd;

    crypto_secretstream_xchacha20poly1305_keygen(key);
    tmp_path(enc_path, sizeof(enc_path));
    tmp_path(dec_path, sizeof(dec_path));

    TEST_ASSERT_TRUE(write_encrypted_file(enc_path, key,
                                          (const unsigned char *)pt, strlen(pt)));

    /* Flip a byte in the ciphertext body (after the 24-byte stream header). */
    tfd = open(enc_path, O_RDWR);
    lseek(tfd, SUSSHI_LOG_ENC_HEADER_BYTES + 5, SEEK_SET);
    read(tfd, &b, 1);
    b ^= 0xFF;
    lseek(tfd, -1, SEEK_CUR);
    write(tfd, &b, 1);
    close(tfd);

    out_fd = open(dec_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    TEST_ASSERT_FALSE(susshi_log_enc_decrypt_file(enc_path, key, out_fd));
    close(out_fd);
}

void test_decrypt_missing_file(void)
{
    unsigned char key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
    char          dec_path[256];
    int           out_fd;

    crypto_secretstream_xchacha20poly1305_keygen(key);
    tmp_path(dec_path, sizeof(dec_path));
    out_fd = open(dec_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    TEST_ASSERT_FALSE(susshi_log_enc_decrypt_file(
            "/tmp/does-not-exist-susshi-enc", key, out_fd));
    close(out_fd);
}


/* ==========================================================================
 * Full end-to-end round-trip
 *
 * Exercises every public function in the chain:
 *   read_privkey → parse_pubkey → write_recipients → [encrypt file] →
 *   recover_session_key → decrypt_file
 * ========================================================================== */

void test_full_roundtrip(void)
{
    const char     plaintext[] =
        "Full end-to-end encryption round-trip.\n"
        "This simulates a real susshid session log entry.\n";
    char                    key_file[256];
    char                    base[256];
    char                    enc_path[512];
    char                    enc_file[256], dec_file[256];
    char                   *pubkey_str;
    char                   *comment    = NULL;
    ssh_key                 gen_key;
    unsigned char           sk[SUSSHI_LOG_ENC_ED25519_SK_BYTES];
    unsigned char           pub[32];
    unsigned char           parsed_pub[32];
    unsigned char           session_key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
    unsigned char           recovered_key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
    unsigned char          *readback;
    susshi_log_enc_recipient r;
    size_t                  read_len   = 0;
    int                     out_fd;

    /* 1. Generate a well-formed ed25519 key file using libssh and read back the
     *    key material.  hand-crafted OpenSSH blobs are rejected by the patched
     *    libssh; using libssh's own export guarantees the file is parseable. */
    tmp_path(key_file, sizeof(key_file));
    TEST_ASSERT_EQUAL_INT(SSH_OK, generate_ed25519_key(&gen_key));
    TEST_ASSERT_EQUAL_INT(SSH_OK,
                          ssh_pki_export_privkey_file(gen_key, NULL, NULL, NULL, key_file));
    ssh_key_free(gen_key);

    TEST_ASSERT_TRUE(susshi_log_enc_read_privkey(key_file, NULL, sk));

    /* In libsodium's format sk = seed(32) || pubkey(32). */
    memcpy(pub, sk + 32, 32);

    /* 2. Parse the pubkey string to confirm the round-trip through SSH wire format. */
    pubkey_str = make_ssh_pubkey_str(pub, "e2e-test");
    TEST_ASSERT_TRUE(susshi_log_enc_parse_pubkey(pubkey_str, parsed_pub, &comment));
    TEST_ASSERT_EQUAL_MEMORY(pub, parsed_pub, 32);
    TEST_ASSERT_EQUAL_STRING("e2e-test", comment);
    free(pubkey_str);

    /* 3. Generate a session key and write the recipient file. */
    crypto_secretstream_xchacha20poly1305_keygen(session_key);
    tmp_path(base, sizeof(base));

    r.identity = comment;
    memcpy(r.ed25519_pub, parsed_pub, sizeof(r.ed25519_pub));
    TEST_ASSERT_TRUE(susshi_log_enc_write_recipients(base, session_key, &r, 1));
    free(comment);

    snprintf(enc_path, sizeof(enc_path), "%s.enc", base);
    register_tmp(enc_path);

    /* 4. Encrypt a test log file with the session key. */
    tmp_path(enc_file, sizeof(enc_file));
    tmp_path(dec_file, sizeof(dec_file));
    TEST_ASSERT_TRUE(write_encrypted_file(enc_file, session_key,
                                          (const unsigned char *)plaintext,
                                          strlen(plaintext)));

    /* 5. Recover the session key from the recipient file using the private key. */
    TEST_ASSERT_TRUE(susshi_log_enc_recover_session_key(enc_path, sk, recovered_key));
    TEST_ASSERT_EQUAL_MEMORY(session_key, recovered_key, SUSSHI_LOG_ENC_SESSION_KEY_BYTES);

    /* 6. Decrypt the log file with the recovered session key. */
    out_fd = open(dec_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    TEST_ASSERT_TRUE(out_fd >= 0);
    TEST_ASSERT_TRUE(susshi_log_enc_decrypt_file(enc_file, recovered_key, out_fd));
    close(out_fd);

    /* 7. Verify the recovered plaintext is byte-for-byte identical. */
    readback = read_file_contents(dec_file, &read_len);
    TEST_ASSERT_NOT_NULL(readback);
    TEST_ASSERT_EQUAL(strlen(plaintext), read_len);
    TEST_ASSERT_EQUAL_MEMORY(plaintext, readback, strlen(plaintext));
    free(readback);
}


int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_parse_pubkey_valid);
    RUN_TEST(test_parse_pubkey_no_comment_yields_unnamed);
    RUN_TEST(test_parse_pubkey_comment_sanitized);
    RUN_TEST(test_parse_pubkey_blob_too_short);
    RUN_TEST(test_parse_pubkey_no_space);

    RUN_TEST(test_enc_roundtrip);
    RUN_TEST(test_enc_multi_recipient_roundtrip);
    RUN_TEST(test_enc_wrong_key_rejected);
    RUN_TEST(test_enc_missing_file);

    RUN_TEST(test_privkey_roundtrip);
    RUN_TEST(test_privkey_passphrase_protected_rejected);
    RUN_TEST(test_privkey_bad_checkint_rejected);
    RUN_TEST(test_privkey_missing_file);

    RUN_TEST(test_decrypt_roundtrip_small);
    RUN_TEST(test_decrypt_roundtrip_multi_chunk);
    RUN_TEST(test_decrypt_wrong_key_rejected);
    RUN_TEST(test_decrypt_tampered_ciphertext_rejected);
    RUN_TEST(test_decrypt_missing_file);

    RUN_TEST(test_full_roundtrip);

    return UNITY_END();
}

/*! @} */
