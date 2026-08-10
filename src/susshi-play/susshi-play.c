/*!
 *
 * @brief       susshi-play
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
 * @defgroup    susshi_play     susshi-play
 * @brief       Universal tool to play, convert and search session file(s)
 * @{
 */
#include "susshi-play/common.h"

/* Prototypes */
static void   usage(void);
static void   cleanup(void);
static void   sig_handler(int sig);
static char  *decrypt_to_tempfile(const char *filepath, const unsigned char session_key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES]);
static bool   decrypt_session_pair(const char *session_path, const char *timing_path,
                                    const unsigned char sk[SUSSHI_LOG_ENC_ED25519_SK_BYTES],
                                    char **out_session, char **out_timing);
void fatal(const char *fmt,...);
void verbose(const char *fmt,...);

static struct {
	bool verbose;
	volatile char *temp_file;
	volatile char *dec_session;
	volatile char *dec_timing;
} int_store = {
	false, NULL, NULL, NULL
};


/*!
 * @brief       Print Usage
 */

static void
usage(void) {
	fprintf(stderr,
		"\n                         __________ __  __     ___"
		"\n             _______  __/ ___/ ___// / / (_)  |__ \\"
		"\n            / ___/ / / /\\__ \\\\__ \\/ /_/ / /   __/ /"
		"\n           (__  ) /_/ /___/ /__/ / __  / /   / __/"
		"\n          /____/\\__,_//____/____/_/ /_/_/   /____/"
		"\n          ----------- by Wasabi Elements GmbH ---"
		"\n"

		"\n" SUSSHI_NAME " " SUSSHI_RELEASE " - " SUSSHI_COPYRIGHT "\n"
		"\nUsage:\t" SUSSHI_PLAY_NAME " [-v] [-k <key>] <session_file>\n"
		"                       [-v] [-k <key>] -r | --raw     <session_file> ...\n"
		"                       [-v] [-k <key>] -t | --ttyrec  <session_file> ...\n"
		"                       [-v] [-k <key>] -w | --html    <session_file> ...\n\n"
		"\tBy default " SUSSHI_PLAY_NAME " replays the session. Please have a look at the keys reference.\n\n"
		"\t-k, --key <file>       Private ed25519 key for decrypting encrypted sessions.\n"
		"\t-r, --raw              Output session log in raw format.\n"
		"\t-s, --suffix           Overwrite default output suffix (.session.ttyrec, .session.html).\n"
		"\t-t, --ttyrec           Convert session log into 'ttyrec' file.\n"
		"\t-w, --html, --web      Convert session log into self-contained HTML file.\n"
		"\t-v, --verbose          Verbose.\n"
		"\t-h, --help             This help.\n\n"

		"\tPlayer keys reference\n"
		"\t---------------------\n"
		"\tp, s\tToggle Pause                  " "\t#x\tSet playback speed to # times\n"
		"\tspc, >\tGo forward by one frame  " "\t#X\tSet playback speed to # nth\n"
		"\t#>\tGo forward by # frames       " "\tx, X\tSet playback speed to normal\n"
		"\tb, <\tGo back by one frame       " "\tl\tToggle logarithmic time compression\n"
		"\t#<\tGo back by # frames          " "\to\tToggle on-screen info display\n"
		"\t#g\tJump to frame #              " "\t/\tSearch forward\n"
		"\tG\tJump to end                   " "\t\\\tSearch backward\n"
		"\t#G\tJump to # frames before end  " "\tn\tSearch for next occurrence\n"
		"\tq\tQuit player\n\n"
	);
}


/*!
 * @brief       Cleanup
 */

static void
cleanup(void) {
	char *p;

	if ((p = (char *) int_store.temp_file) != NULL) {
		int_store.temp_file = NULL;
		unlink(p);
	}
	if ((p = (char *) int_store.dec_session) != NULL) {
		int_store.dec_session = NULL;
		unlink(p);
		free(p);
	}
	if ((p = (char *) int_store.dec_timing) != NULL) {
		int_store.dec_timing = NULL;
		unlink(p);
		free(p);
	}
}


/*!
 * @brief       Signal handler — cleans up temp files then re-raises
 *
 * SA_RESETHAND resets the disposition to SIG_DFL before this handler runs,
 * so raise() delivers the signal with its default action (process termination).
 * free() is technically not async-signal-safe, but for a single-threaded CLI
 * tool the risk is negligible and calling cleanup() is the correct approach.
 */

static void
sig_handler(int sig) {
	cleanup();
	raise(sig);
}


/*!
 * @brief       Fatal function called in fatal situations
 *
 * @param       fmt     Format string
 * @param       ...     Optional parameters referenced by format string
 */

void
fatal(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	cleanup();

	_exit(1);
}


/*!
 * @brief       Verbose output
 *
 * @param       fmt     Format string
 * @param       ...     Optional parameters referenced by format string
 */

void
verbose(const char *fmt,...)
{
	va_list args;

	if (int_store.verbose == false)
		return;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}


/*!
 * @brief   Decrypt @p filepath into a new temporary file.
 *
 * @return  A malloc'd path to the temp file that the caller must @c unlink and
 *          @c free, or @c NULL on error.
 */

static char *
decrypt_to_tempfile(const char *filepath,
                    const unsigned char session_key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES])
{
	char *tmp_path;
	int   fd;
	bool  ok;

	tmp_path = strdup(P_tmpdir "/" SUSSHI_PLAY_NAME "-dec-XXXXXX");

	if (tmp_path != NULL) {
		fd = mkstemp(tmp_path);
		if (fd < 0) {
			free(tmp_path);
			tmp_path = NULL;
		} else {
			ok = susshi_log_enc_decrypt_file(filepath, session_key, fd);
			close(fd);
			if (!ok) {
				unlink(tmp_path);
				free(tmp_path);
				tmp_path = NULL;
			}
		}
	}

	return tmp_path;
}


/*!
 * @brief   Locate the .enc sidecar for @p session_path, recover the session
 *          key with @p sk, and decrypt both the session and timing files into
 *          temporary files.
 *
 * On success, @p *out_session and @p *out_timing receive malloc'd temp paths
 * (caller must @c unlink + @c free).  On failure (no sidecar, wrong key, or
 * decryption error) both are left as @c NULL and an error is printed.
 *
 * Returns @c false with no error when no .enc sidecar is found (the session
 * is simply not encrypted).
 */

static bool
decrypt_session_pair(const char *session_path, const char *timing_path,
                     const unsigned char sk[SUSSHI_LOG_ENC_ED25519_SK_BYTES],
                     char **out_session, char **out_timing)
{
	char          enc_path[PATH_MAX];
	unsigned char session_key[SUSSHI_LOG_ENC_SESSION_KEY_BYTES];
	char         *dec_s;
	char         *dec_t;
	bool          rc;

	dec_s = NULL;
	dec_t = NULL;
	rc    = false;

	if (susshi_log_enc_find_sidecar(session_path, enc_path, sizeof(enc_path))) {
		if (susshi_log_enc_recover_session_key(enc_path, sk, session_key)) {
			dec_s = decrypt_to_tempfile(session_path, session_key);
			dec_t = decrypt_to_tempfile(timing_path,  session_key);
			sodium_memzero(session_key, sizeof(session_key));
			if (dec_s != NULL && dec_t != NULL) {
				*out_session = dec_s;
				*out_timing  = dec_t;
				rc           = true;
			} else {
				fprintf(stderr, "%s: decryption failed\n", session_path);
				if (dec_s != NULL) { unlink(dec_s); free(dec_s); }
				if (dec_t != NULL) { unlink(dec_t); free(dec_t); }
			}
		} else {
			sodium_memzero(session_key, sizeof(session_key));
			fprintf(stderr, "%s: private key does not match any recipient in %s\n",
			        session_path, enc_path);
		}
	}
	return rc;
}


/*!
 * @brief       Write an unsigned 32 Bit into a file in little endian
 *
 * @param       file
 * @param       value
 */

static void
write_uint32_t(FILE *file, uint32_t value) {
	unsigned char *point = (unsigned char *) &value;
#ifdef LITTLE_ENDIAN
	fprintf(file, "%c%c%c%c", *point, *(point+1), *(point+2), *(point+3));
#else
	fprintf(file, "%c%c%c%c", *(point+3), *(point+2), *(point+1), *point);
#endif
}


/*!
 * @brief       Run an external program safely without invoking a shell
 *
 * @param       path    Absolute path to the executable
 * @param       argv    NULL-terminated argument array (argv[0] = program name)
 *
 * @return      Exit status of the child, or -1 on error
 */

#define MAX_CHUNK_SIZE (64 * 1024 * 1024)  /* 64 MiB — sanity limit for session chunks */

static int
run_execv(const char *path, const char *const argv[]) {
	pid_t pid;
	int status;

	pid = fork();
	if (pid == -1)
		return -1;

	if (pid == 0) {
		execv(path, (char *const *)argv);  /* POSIX execv takes char *const[]; cast is safe */
		_exit(127);
	}

	if (waitpid(pid, &status, 0) == -1)
		return -1;

	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}


/*!
 * @brief       Write a chuck of ttyrec output
 *
 * @param       ttyrec
 * @param       session
 * @param       session_filename
 * @param       len
 * @param       timestamp
 */

static void
write_ttyrec_chunk(FILE *ttyrec, FILE *session, const char *session_filename, uint32_t len, float timestamp) {
	uint32_t sec, msec;
	unsigned char *buffer;
	size_t rlen;

	if (len > 0) {
		if (len > MAX_CHUNK_SIZE)
			fatal("Chunk size %u in %s exceeds maximum allowed size.\n", len, session_filename);

		buffer = malloc(len);
		if (buffer == NULL)
			fatal("Memory allocation failed for chunk of size %u.\n", len);

		rlen = fread(buffer, 1, len, session);

		if (rlen < len) {
			fprintf(stderr, "WARNING! In %s some date (%ld bytes) seems to be missing.\n", session_filename, len - rlen);
		}

		sec = (uint32_t) timestamp;
		msec = (uint32_t) ((timestamp - sec) * 1000.0);

		write_uint32_t(ttyrec, sec);
		write_uint32_t(ttyrec, msec);
		write_uint32_t(ttyrec, (uint32_t) rlen);
		fwrite(buffer, 1, rlen, ttyrec);

		free(buffer);
	}
}


/*!
 * @brief       Convert a session file into ttyrec format
 *
 * @param       session_file
 * @param       timing_file
 * @param       ttyrec_file
 * @param       width
 * @param       height
 *
 * @return      Timestamp
 */

static float
convert_session_file_into_ttyrec(const char *session_file, const char *timing_file, const char *ttyrec_file,
								 uint32_t *width, uint32_t *height) {

	FILE *session, *timing, *ttyrec;
	size_t linecap = 0, total_len = 0;
	char *line = NULL;

	char side;
	float delta;
	float timestamp = 0.0;
	uint32_t len;

	if ((session = fopen(session_file, "r"))) {
		if ((timing = fopen(timing_file, "r"))) {
			if ((ttyrec = fopen(ttyrec_file, "w"))) {
				uint32_t w, h, wp, wh;
				char *term = malloc(30);

				/*
				 * Read first line from timing file
				 */
				if (getline(&line, &linecap, timing) > 0) {
					sscanf(line, "%c %f %d %dx%d %dx%d %29s", &side, &delta, &len, &w, &h, &wp, &wh, term);
					timestamp +=delta;
					total_len += len;
					write_ttyrec_chunk(ttyrec, session, session_file, len, timestamp);

					if (width != NULL)
						*width = w;
					if (height != NULL)
						*height = h;

				}

				/*
				 * Read remaining lines
				 */
				while (getline(&line, &linecap, timing) > 0) {
					sscanf(line, "%c %f %d", &side, &delta, &len);
					timestamp +=delta;
					total_len += len;

					if (side == 'S') {
						write_ttyrec_chunk(ttyrec, session, session_file, len, timestamp);
					}
				}

				verbose("\n    Info: Terminal %s %dx%d, Duration %f sec. %ld Characters.\n", term, w, h, timestamp, total_len);
				verbose(" Session: %s\n", session_file);
				verbose("  Timing: %s\n", timing_file);

				free(term);
				free(line);
				fclose(ttyrec);
			} else {
				fatal("%s: Could not open ttyrec file for writing.\n", ttyrec_file);
			}
			fclose(timing);
		} else {
			fatal("%s: Could not open timing file.\n", timing_file);
		}
		fclose(session);
	} else {
		fatal("%s: Could not open session file.\n", session_file);
	}

	return (timestamp);
}



/*!
 * @brief       susshi-play main
 *
 * @param       argc            Argument Count
 * @param       argv            Argument Values
 * @param       envp            Environments
 *
 * @return      Exit code
 */

int
main(int argc, char **argv, char **envp) {
	extern char *optarg;
	int option_index = 0;
	int options = 0;
	struct sigaction sa;

	bstring session_file, timing_file, str_find, str_replace, output_file;
	bstring out_suffix = NULL;
	int files_written = 0;

	char *temp_filename = strdup(P_tmpdir "/" SUSSHI_PLAY_NAME "-XXXXXX");

	Action action = ACT_PLAY_SESSION;

	const char    *keypath     = NULL;
	unsigned char  sk[SUSSHI_LOG_ENC_ED25519_SK_BYTES];
	bool           key_loaded  = false;
	char           enc_path[PATH_MAX];
	bool           is_encrypted;
	const char    *eff_session;
	const char    *eff_timing;
	char          *dec_session;
	char          *dec_timing;

	int c;

	for(c=0; c != -1; ) {

		static struct option long_options[] = {
			{"help", no_argument, 0, 'h'},
			{"html", no_argument, 0, 'w'},
			{"web", no_argument, 0, 'w'},
			{"ttyrec", no_argument, 0, 't'},
			{"raw", no_argument, 0, 'r'},
			{"verbose", no_argument, 0, 'v'},
			{"suffix", required_argument, 0, 's'},
			{"key", required_argument, 0, 'k'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hnrtvws:k:",
						 long_options, &option_index);

		switch (c) {
			case -1:
				break;

			case 0:     /* option set a flag */
				break;
			case 'h':
				usage();
				exit(0);
			case 'r':
				action = ACT_PRINT_FILE_RAW;
				break;
			case 't':
				action = ACT_CONVERT_TTYREC;
				break;
			case 'v':
				options |= OPT_VERBOSE;
				int_store.verbose = true;
				break;
			case 'w':
				action = ACT_CONVERT_HTML;
				break;
			case 's':
				out_suffix = bfromcstr(optarg);
				break;
			case 'k':
				keypath = optarg;
				break;
			case ':':
			default:
				usage();
				exit(1);
		}
	}

	// Signal handler
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESETHAND;
	sigaction(SIGHUP,  &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	if (keypath != NULL) {
		key_loaded = susshi_log_enc_load_privkey_interactive(keypath, SUSSHI_PLAY_NAME, sk);
		if (!key_loaded)
			exit(1);
	}

	if (optind == argc) {
		fatal("Please specify at least one session file.\n");
	}

	if (out_suffix == NULL) {
		switch (action) {
			case ACT_CONVERT_TTYREC:
				out_suffix = bfromcstr(".session.ttyrec");
				break;
			case ACT_CONVERT_HTML:
				out_suffix = bfromcstr(".session.html");
				break;
			default:
				out_suffix = bfromcstr(".unknown");
		}
	}

	if ((action == ACT_PLAY_SESSION) && ((argc-optind) > 1)) {
		fatal("Error in usage! Only one file is allowed in player mode.\n");
	}

	for (int i = optind; i < argc; ++i) {

		dec_session = NULL;
		dec_timing  = NULL;

		if (i > optind) {
			verbose("\n--------------------------------------------------------------------------------\n");
		}

		session_file = bfromcstr(argv[i]);
		if (access(bdata(session_file), F_OK) == -1) {
			bformata(session_file, ".session");
			if (access(bdata(session_file), F_OK) == -1) {
				fprintf(stderr, "%s: Could not open session file. SKIPPING.\n", bdata(session_file));
				continue;
			}
		}

		if (strstr(bdata(session_file), ".session") == NULL) {
			fprintf(stderr, "%s: Does not have correct suffix. SKIPPING.\n", bdata(session_file));
			continue;
		}

		timing_file = bstrcpy(session_file);
		bfindreplace(timing_file, str_find = bfromcstr(".session"), str_replace = bfromcstr(".time"), 0);
		bstrFree(str_find);
		bstrFree(str_replace);

		if (access(bdata(timing_file), F_OK) == -1) {
			fprintf(stderr, "%s: Could not open timing file. SKIPPING.\n", bdata(timing_file));
			continue;
		}

		is_encrypted = susshi_log_enc_find_sidecar(bdata(session_file), enc_path, sizeof(enc_path));


		if (is_encrypted && !key_loaded) {
			fprintf(stderr, "%s: File is encrypted, use -k to specify a private key. SKIPPING.\n",
			        bdata(session_file));
			continue;
		}

		if (is_encrypted) {
			if (decrypt_session_pair(bdata(session_file), bdata(timing_file), sk,
			                         &dec_session, &dec_timing)) {
				int_store.dec_session = dec_session;
				int_store.dec_timing  = dec_timing;
				eff_session = dec_session;
				eff_timing  = dec_timing;
			} else {
				continue;
			}
		} else {
			eff_session  = bdata(session_file);
			eff_timing   = bdata(timing_file);
		}

		output_file = bstrcpy(session_file);
		bfindreplace(output_file, str_find = bfromcstr(".session"), out_suffix, 0);
		bstrFree(str_find);

		switch(action) {
			case ACT_CONVERT_TTYREC: {
				convert_session_file_into_ttyrec(eff_session, eff_timing, bdata(output_file), NULL, NULL);
				verbose("  Output: %s\n", bdata(output_file));
				files_written++;
			} break;

			case ACT_CONVERT_HTML: {
				uint32_t width, height;
				int tmp_fd;
				char height_str[16], width_str[16];

				tmp_fd = mkstemp(temp_filename);
				if (tmp_fd >= 0) {
					int_store.temp_file = temp_filename;
					close(tmp_fd);

					convert_session_file_into_ttyrec(eff_session, eff_timing, temp_filename, &width, &height);

					snprintf(height_str, sizeof(height_str), "%u", height);
					snprintf(width_str, sizeof(width_str), "%u", width);

					{
						const char *args[] = { BIN_PATH_TERMREC, "-b", "ttyrec", "-d", height_str, width_str, "-s", temp_filename, "-o", bdata(output_file), NULL };
						if (run_execv(BIN_PATH_TERMREC, args) == 0) {
							verbose("  Output: %s\n", bdata(output_file));
							files_written++;
						} else {
							fatal("Something went wrong.\n");
						}
					}
				} else {
					fatal("Conversion failed, could not create temporary file.");
				}
			} break;
			case ACT_PLAY_SESSION: {
				uint32_t width, height;
				int tmp_fd;
				char width_str[16], height_str[16];

				tmp_fd = mkstemp(temp_filename);
				if (tmp_fd >= 0) {
					int_store.temp_file = temp_filename;
					close(tmp_fd);
					convert_session_file_into_ttyrec(eff_session, eff_timing, temp_filename, &width, &height);

					if (options & OPT_VERBOSE) {
						printf("\n Press return to start player.");
						getchar();
						verbose("\nStarting replay of %s ...\n", bdata(session_file));
					}

					snprintf(width_str, sizeof(width_str), "%u", width);
					snprintf(height_str, sizeof(height_str), "%u", height);

					{
						const char *args[] = { BIN_PATH_IPBT, "-w", width_str, "-h", height_str, "-T", "-A", temp_filename, NULL };
						if (run_execv(BIN_PATH_IPBT, args) == -1) {
							fatal("Something went wrong.\n");
						}
					}

					verbose("\n");
				} else {
					fatal("Conversion failed, could not create temporary file.");
				}

			} break;

			case ACT_PRINT_FILE_RAW: {
				verbose("%s:\n\n", eff_session);

				{
					const char *args[] = { BIN_PATH_CAT, "-v", eff_session, NULL };
					if (run_execv(BIN_PATH_CAT, args) == -1) {
						fatal("Something went wrong.\n");
					}
				}

				verbose("\n\n");
			} break;

			default:
				fatal("Unknown action\n");
		}

		bstrFree(output_file);
		bstrFree(session_file);
		bstrFree(timing_file);
	}

	if (key_loaded)
		sodium_memzero(sk, sizeof(sk));

	if (files_written > 0) {
		verbose("\n%d (of %d) File(s) generated in total. Please remember that the file(s) may contain sensitive data!\n\n", files_written, argc - optind);
	}

	cleanup();

	free(temp_filename);
}

/*! @} */
