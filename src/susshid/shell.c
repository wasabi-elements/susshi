/*!
 *
 * @brief       Shell
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
 * @date        2026-02-01
 *
 * @defgroup    shell CLI Shell
 * @brief       Functions implementing a basic CLI shell
 * @{
 */

#include "susshid/common.h"


typedef enum {
	SHELL_FATAL = -1,
	SHELL_OK = 0,
	SHELL_ERROR = 1,
	SHELL_EXIT = 2
} ShellReturn;

typedef enum {
	SCOPE_GLOBAL,
	SCOPE_ROOT,
	SCOPE_TARGET
} ShellScope;


/* Prototypes */
static void	shell_prompt_prepare(bstring sub);
static ShellReturn command_exit(int argc, const char **argv);
static ShellReturn command_help(int argc, const char **argv);
static ShellReturn command_history(int argc, const char **argv);
static ShellReturn command_target(int argc, const char **argv);
static ShellReturn command_target_exit(int argc, const char **argv);
static ShellReturn shell_run_command(const char *command);

static struct {
	ShellScope shell_scope;
	bstring shell_prompt;
	bstring shell_prompt_sub;
	Tokenizer *tokenizer;
	History *edit_history;
	HistEvent hist_event;
} int_store = {
		.shell_scope = SCOPE_ROOT,
		.tokenizer = NULL
};

typedef ShellReturn (*ShellCommandFunc)(int argc, const char **argv);

static struct {
	const char *command;
	uint minchars;
	const char *description;
	ShellScope scope;
	ShellCommandFunc command_func;
	int minargs;
	int maxargs;
} commands[] = {
		{"exit",    1, "Change back from target scope", SCOPE_TARGET, command_target_exit, 0, 0},
		{"exit",    1, "Exit from shell",               SCOPE_ROOT, command_exit,        0, 0},
		{"?",       1, "This help",                     SCOPE_GLOBAL, command_help,        0, 0},
		{"help",    2, "This help",                     SCOPE_GLOBAL, command_help,        0, 0},
		{"history", 2, "Show command history",          SCOPE_GLOBAL, command_history,     0, 0},
		{"target",  1, "Change into target scope",      SCOPE_ROOT,   command_target,      1, 1},
		{NULL,      0, NULL,                            SCOPE_ROOT, NULL,                  0, 0}
};


/*!
 * @brief       Command "exit"
 *
 * @param       argc
 * @param       argv
 *
 * @return      ShellReturn
 */

static ShellReturn
command_exit(int argc, const char **argv) {

	printf("Bye bye. Have a nice day.\n\n");
	return SHELL_EXIT;
}


/*!
 * @brief       Command "help"
 *
 * @param       argc
 * @param       argv
 *
 * @return      ShellReturn
 */

static ShellReturn
command_help(int argc, const char **argv) {

	for (int i=0; commands[i].command != NULL; i++) {
		if ((commands[i].scope != SCOPE_GLOBAL) && (commands[i].scope != int_store.shell_scope))
			continue;
		printf("%-15s %s\n", commands[i].command, commands[i].description);
	}

	return SHELL_OK;
}


/*!
 * @brief       Command "history"
 *
 * @param       argc
 * @param       argv
 *
 * @return      ShellReturn
 */

static ShellReturn
command_history(int argc, const char **argv) {

	int rv;

	for (rv = history(int_store.edit_history, &int_store.hist_event, H_FIRST); rv != -1;
		 rv = history(int_store.edit_history, &int_store.hist_event, H_NEXT)) {
		printf("%4d %s", int_store.hist_event.num, int_store.hist_event.str);
	}

	return SHELL_OK;
}


/*!
 * @brief       Command "target"
 *
 * @param       argc
 * @param       argv
 *
 * @return      ShellReturn
 */

static ShellReturn
command_target(int argc, const char **argv) {
	shell_prompt_prepare(bformat("target %s", argv[0]));
	int_store.shell_scope = SCOPE_TARGET;

	return SHELL_OK;
}


/*!
 * @brief       Command "target / exit"
 *
 * @param       argc
 * @param       argv
 *
 * @return      ShellReturn
 */

static ShellReturn
command_target_exit(int argc, const char **argv) {
	shell_prompt_prepare(NULL);
	int_store.shell_scope = SCOPE_ROOT;
	return SHELL_OK;
}


/*!
 * @brief       Prepare prompt
 *
 * @param       sub
 */

static void
shell_prompt_prepare(bstring sub)
{
	if (int_store.shell_prompt_sub)
		bstrFree(int_store.shell_prompt_sub);

	int_store.shell_prompt_sub = sub;

	if (int_store.shell_prompt)
		bstrFree(int_store.shell_prompt);

	if (blength(int_store.shell_prompt_sub) > 0) {
		int_store.shell_prompt = bformat("%s@" SUSSHI_NAME " / %s> ", bdata(susshi_session.susshi_user), bdata(int_store.shell_prompt_sub));
	} else {
		int_store.shell_prompt = bformat("%s@" SUSSHI_NAME " > ", bdata(susshi_session.susshi_user));
	}
}


/*!
 * @brief       Display Prompt
 *
 * @param       editline    EditLine pointer
 *
 * @return      The prompt in cstring
 */

static const char *
shell_prompt(EditLine *editline) {
	return bdata(int_store.shell_prompt);
}


/*!
 * @brief       Shell complete
 *
 * @param       editline    EditLine pointer
 * @param       ch
 *
 * @return      The completion string
 */

static unsigned char
shell_complete(EditLine *editline, int ch) {
	unsigned char res = CC_ERROR;
	const LineInfo *lf = el_line(editline);
	bstring candidates = NULL;

	unsigned long left;

	left = lf->cursor - lf->buffer;

	/* Any space up to cursor? */
	for(unsigned long i=0; i < left; i++) {
		if (isspace(lf->buffer[i]))
			return CC_ERROR;
	}

	candidates = bfromcstr("");

	for (int i=0; commands[i].command != NULL; i++) {
		if ((commands[i].scope != SCOPE_GLOBAL) && (commands[i].scope != int_store.shell_scope))
			continue;
		if (commands[i].minchars <= left) {
			if (strncmp(lf->buffer, commands[i].command, MAX((unsigned long) commands[i].minchars, left)) == 0) {
				/* Command found */
				if (el_insertstr(editline, &commands[i].command[left]) == -1) {
					res = CC_ERROR;
				} else {
					if (el_insertstr(editline, " ") == -1) {
						res = CC_ERROR;
					} else {
						res = CC_REFRESH;
					}
				}
			}
		} else {
			if (strncmp(lf->buffer, commands[i].command, left) == 0) {
				if (blength(candidates))
					bcatcstr(candidates, "  ");
				bcatcstr(candidates, commands[i].command);
			}
		}
	}

	if ((res != CC_REFRESH) && (blength(candidates))) {
		printf("\n%s\n", bdata(candidates));
		res = CC_REDISPLAY;
	}

	if (candidates) bstrFree(candidates);

	return res;
}


/*!
 * @brief       Run a single command entered on CLI
 *
 * @param       cmd     The command to be run
 */

static ShellReturn
shell_run_command(const char *cmd) {

	int argc;
	const char **argv;
	ShellReturn rc;

	tok_reset(int_store.tokenizer);
	tok_str(int_store.tokenizer, cmd, &argc, &argv);

	if (argc > 0) {
		argc--;

		for (int i=0; commands[i].command != NULL; i++) {
			if ((commands[i].scope != SCOPE_GLOBAL) && (commands[i].scope != int_store.shell_scope))
				continue;

			if (strncmp(argv[0], commands[i].command, MAX((unsigned long) commands[i].minchars, strlen(argv[0]))) == 0) {
				/* Command found */
				if ((argc  >=  commands[i].minargs) && (argc <= commands[i].maxargs)) {
					/* Right number of arguments */
					rc = commands[i].command_func(argc, &argv[1]);
					history(int_store.edit_history, &int_store.hist_event, H_ENTER, cmd);
					return rc;
				} else {
					history(int_store.edit_history, &int_store.hist_event, H_ENTER, cmd);
					printf("Wrong number of arguments.\n");
				}
			}
		}
		printf("Command not found.\n");
	}

	return SHELL_OK;
}


/*!
 * @brief       The CLI shell
 *
 * Called from shell-loop handlers
 *
 * @param       cdata       shell_channel_data_struct
 *
 */

void
susshi_shell(struct shell_channel_data_struct *cdata) {

	ShellReturn shell_rc = SHELL_OK;
	EditLine *edit_line;

	const char *command;
	int command_len;

	if ((edit_line = el_init("susshi", stdin, stdout, stderr))) {

		if ((int_store.edit_history = history_init())) {

			el_set(edit_line, EL_PROMPT, &shell_prompt);
			el_set(edit_line, EL_EDITOR, "emacs");
			el_set(edit_line, EL_BIND, "-e", NULL);

			/* Set requested terminal */
			el_set(edit_line, EL_TERMINAL, bdata(cdata->term));

			/* Register complete function and assign TAB key */
			el_set(edit_line, EL_ADDFN, "ed-complete", "Complete argument", shell_complete);
			el_set(edit_line, EL_BIND, "^I", "ed-complete", NULL);

			history(int_store.edit_history, &int_store.hist_event, H_SETSIZE, 100);
			el_set(edit_line, EL_HIST, history, int_store.edit_history);

			int_store.tokenizer = tok_init(NULL);

			/* Prepare prompt */
			shell_prompt_prepare(NULL);

			/* Read & run commands */
			do {
				command = el_gets(edit_line, &command_len);

				if ((command_len > 0) && (command)) {
					shell_rc = shell_run_command(command);
				}

			} while (shell_rc == SHELL_OK);

			if (shell_rc == SHELL_FATAL)
				susshi_disconnect_standard(CLIENT, DISCONNECT_INTERNAL_ERROR);

			/* Cleanup */
			tok_end(int_store.tokenizer);
			history_end(int_store.edit_history);
			el_end(edit_line);
			bstrFree(int_store.shell_prompt);

		} else {
			fatal("Could not initialize editline history");
		}

	} else {
		fatal("Could not initialize editline.");
	}
}

/*! @} */
