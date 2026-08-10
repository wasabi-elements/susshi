/*!
 *
 * @brief       susshi-decrypt
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
 * @date        2026-06-22
 *
 * @defgroup    susshi_decrypt  susshi-decrypt
 * @brief       Decrypt suSSHi session log files encrypted by susshid.
 * @{
 */

#include "susshi-decrypt/common.h"

/* Prototypes */
static void usage(void);
static bool decrypt_file(const char *filepath, const unsigned char sk[SUSSHI_LOG_ENC_ED25519_SK_BYTES]);
void fatal(const char *fmt, ...);


/*!
 * @brief   Print usage information to stderr.
 */

static void
usage(void)
{
    fprintf(stderr,
        "\n                         __________ __  __     ___"
        "\n             _______  __/ ___/ ___// / / (_)  |__ \\"
        "\n            / ___/ / / /\\__ \\\\__ \\/ /_/ / /   __/ /"
        "\n           (__  ) /_/ /___/ /__/ / __  / /   / __/"
        "\n          /____/\\__,_//____/____/_/ /_/_/   /____/"
        "\n          ----------- by Wasabi Elements GmbH ---"
        "\n"
        "\n" SUSSHI_NAME " " SUSSHI_RELEASE " - " SUSSHI_COPYRIGHT "\n"
        "\nUsage:\t" SUSSHI_DECRYPT_NAME " -k|--key <private-key> <file> [<file> ...]\n\n"
        "\t-k, --key <file>    Private ed25519 key file for decryption.\n"
        "\t-h, --help          This help.\n\n"
        "\tDecrypts one or more suSSHi session log files encrypted by susshid.\n"
        "\tDecrypted files are written to a 'decrypted/' subdirectory next to\n"
        "\teach input file.  A passphrase is prompted when the key is protected.\n\n"
    );
}


/*!
 * @brief   Fatal error handler required by the shared xmalloc/xfree wrappers.
 *
 * @param   fmt     printf-style format string.
 * @param   ...     Variable arguments.
 */

void
fatal(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    _exit(1);
}



/*!
 * @brief   Decrypt one encrypted session log file.
 *
 * Locates the @c .enc sidecar next to @p filepath, recovers the session key
 * using @p sk, then decrypts @p filepath into
 * @c <dir>/decrypted/<filename>.  The @c decrypted/ subdirectory is created
 * with mode 0700 if it does not exist.  A partial output file is removed on
 * decryption failure.
 *
 * @param[in] filepath  Path to the encrypted log file.
 * @param[in] sk        64-byte ed25519 secret key of the recipient.
 * @return              true on success.
 */

static bool
decrypt_file(const char *filepath, const unsigned char sk[SUSSHI_LOG_ENC_ED25519_SK_BYTES])
{
    char          enc_path[PATH_MAX];
    char          out_path[PATH_MAX];
    char          dec_dir[PATH_MAX];
    char          dir_copy[PATH_MAX];
    char          base_copy[PATH_MAX];
    char         *dir;
    char         *base;
    unsigned char session_key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
    int           out_fd;
    bool          rc = false;

    snprintf(dir_copy,  sizeof(dir_copy),  "%s", filepath);
    snprintf(base_copy, sizeof(base_copy), "%s", filepath);
    dir  = dirname(dir_copy);
    base = basename(base_copy);
    snprintf(dec_dir,  sizeof(dec_dir),  "%s/decrypted", dir);
    snprintf(out_path, sizeof(out_path), "%s/%s",        dec_dir, base);

    if (!susshi_log_enc_find_sidecar(filepath, enc_path, sizeof(enc_path))) {
        fprintf(stderr, "susshi-decrypt: no .enc sidecar found for %s\n", filepath);
    } else if (!susshi_log_enc_recover_session_key(enc_path, sk, session_key)) {
        fprintf(stderr, "susshi-decrypt: key does not match any recipient in %s\n", enc_path);
    } else if (mkdir(dec_dir, 0700) == -1 && errno != EEXIST) {
        fprintf(stderr, "susshi-decrypt: cannot create %s: %s\n", dec_dir, strerror(errno));
    } else {
        out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (out_fd < 0) {
            fprintf(stderr, "susshi-decrypt: cannot open %s: %s\n", out_path, strerror(errno));
        } else {
            if (susshi_log_enc_decrypt_file(filepath, session_key, out_fd)) {
                fprintf(stderr, "  -> %s\n", out_path);
                rc = true;
            } else {
                fprintf(stderr, "susshi-decrypt: decryption failed for %s\n", filepath);
                unlink(out_path);
            }
            close(out_fd);
        }
    }
    sodium_memzero(session_key, sizeof(session_key));
    return rc;
}


/*!
 * @brief   susshi-decrypt main.
 *
 * @param   argc    Argument count.
 * @param   argv    Argument values.
 * @return          0 on full success, 1 if any file failed.
 */

int
main(int argc, char **argv)
{
    const char   *keypath   = NULL;
    unsigned char sk[SUSSHI_LOG_ENC_ED25519_SK_BYTES];
    int           decrypted = 0;
    int           failed    = 0;
    int           option_index = 0;
    int           c;

    for (c = 0; c != -1; ) {
        static struct option long_options[] = {
            { "key",  required_argument, 0, 'k' },
            { "help", no_argument,       0, 'h' },
            { 0, 0, 0, 0 }
        };

        c = getopt_long(argc, argv, "k:h", long_options, &option_index);

        switch (c) {
            case -1:
                break;
            case 'k':
                keypath = optarg;
                break;
            case 'h':
                usage();
                exit(0);
            default:
                usage();
                exit(1);
        }
    }

    if (keypath == NULL) {
        fprintf(stderr, "susshi-decrypt: --key is required.\n\n");
        usage();
        exit(1);
    }

    if (optind == argc) {
        fprintf(stderr, "susshi-decrypt: no input files specified.\n\n");
        usage();
        exit(1);
    }

    if (!susshi_log_enc_load_privkey_interactive(keypath, SUSSHI_DECRYPT_NAME, sk))
        exit(1);

    for (int i = optind; i < argc; i++) {
        const char *arg = argv[i];
        size_t      len = strlen(arg);
        if (len >= 4 && memcmp(arg + len - 4, ".enc", 4) == 0)
            continue;
        if (decrypt_file(arg, sk))
            decrypted++;
        else
            failed++;
    }

    sodium_memzero(sk, sizeof(sk));

    if (decrypted > 0)
        fprintf(stderr, "\n%d file(s) decrypted successfully.\n", decrypted);
    if (failed > 0)
        fprintf(stderr, "%d file(s) failed.\n", failed);

    return (failed > 0) ? 1 : 0;
}

/*! @} */
