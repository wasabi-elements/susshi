/*!
 *
 * @brief       Helper methods for susshi-proxyd
 *
 * @ingroup     susshi_proxyd
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
 * @{
 *
 */

#include "susshi-proxyd/common.h"


/*!
 * @brief       Cleanup proxy and terminate monitor and bastion servers
 */

void
proxy_cleanup(void) {

	if (proxy_session.monitor_pid > 0) {
		/* We have a running reporting daemon */
		log_system(LOG_LEVEL_INFO, "Send SIGTERM signal to monitor daemon with pid %d", proxy_session.monitor_pid);
		kill(proxy_session.monitor_pid, SIGTERM);
	}

	proxy_master_detach_embryonic_slots();

	if (bastion_lookup_daemon_pid(&proxy_session.bastion_pid)) {
		/* We have a running bastion SSHD */
		log_system(LOG_LEVEL_INFO, "Send SIGTERM signal to bastion daemon with pid %d", proxy_session.bastion_pid);
		kill(proxy_session.bastion_pid, SIGTERM);
	}
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

	log_on_stderr = true;
	log_level = LOG_LEVEL_EMERG;

	va_start(args, fmt);
	do_log(LOG_LEVEL_EMERG, false, fmt, args);
	va_end(args);

	proxy_cleanup();

	_exit(255);
}


/*!
 * @brief       Validate string only containing allowed characters
 *
 * @param       string          string to be validated
 * @param       allowed_regex   regex for allowed characters
 *
 * @return      true if key string only contains allowed_chars, otherwise false
 */

bool
validate_string_chars_regex(bstring string, const char *allowed_regex) {
	bool rc = false;
	pcre2_code *code = NULL;
	int errorcode;
	PCRE2_SIZE erroffset;

	code = pcre2_compile((PCRE2_SPTR)allowed_regex, PCRE2_ZERO_TERMINATED, 0, &errorcode, &erroffset, NULL);
	if (code != NULL) {
		pcre2_match_data *md = pcre2_match_data_create_from_pattern(code, NULL);
		if (md != NULL && pcre2_match(code, (PCRE2_SPTR)bdata(string), blength(string), 0, 0, md, NULL) >= 0)
			rc = true;
		pcre2_match_data_free(md);
		pcre2_code_free(code);
	}

	return rc;
}


/*!
 * @brief       Set Socket into blocking or non blocking mode
 *
 * @param       socket
 * @param       is_blocking     true = blocking, false = none-blocking
 */

void
set_socket_blocking_mode(socket_t socket, bool is_blocking) {
	int flags;

	flags = fcntl(socket, F_GETFL, 0);
	fcntl(socket, F_SETFL, is_blocking ? flags ^ O_NONBLOCK : flags | O_NONBLOCK);
}



/*! @} */
