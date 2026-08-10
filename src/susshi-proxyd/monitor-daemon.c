/*!
 *
 * @brief       Monitor Server
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
 * @defgroup    proxy_monitor_server Monitor Server
 * @brief       Functions of the monitor server prowiding a multi-threaded HTTP monitor interface.
 * @{
 *
 */

#include <susshi-proxyd/common.h>

/* Prototypes */
static enum MHD_Result mhd_callback_request(void *cls, struct MHD_Connection *connection, const char *url, const char *method,
								const char *version, const char *upload_data, size_t *upload_data_size, void **ptr);

static enum MHD_Result mhd_callback_check_client_ip(void *cls, const struct sockaddr *addr, socklen_t addrlen);

static void proxy_monitor_daemon_loop(void);


/*! @cond */
static struct {
		struct MHD_Daemon *daemon;
		bool received_sigterm;
} int_store = {
		.daemon = NULL,
		.received_sigterm = false
};
/*! @endcond */


/*!
 * @brief   MHD callback to handle incoming HTTP requests.
 *
 * Accepts only GET and HEAD methods. Checks process health via PID probes,
 * detects localhost requests (Docker HEALTHCHECK), and returns:
 * - 200 OK if healthy
 * - 423 Locked if service is suspended (non-local clients only)
 * - 503 Service Unavailable if a monitored process has failed
 * - 404 Not Found for unknown URLs
 *
 * @param   cls           Unused.
 * @param   connection    Active MHD connection.
 * @param   url           Requested URL path.
 * @param   method        HTTP method string.
 * @param   version       HTTP version string.
 * @param   upload_data   Upload data buffer (must be empty for GET).
 * @param   upload_data_size  Size of upload data.
 * @param   ptr           Per-request context pointer.
 *
 * @return  MHD_YES to continue processing, MHD_NO to close the connection.
 */

static enum MHD_Result
mhd_callback_request(void *cls, struct MHD_Connection *connection, const char *url, const char *method,
					 const char *version, const char *upload_data, size_t *upload_data_size, void **ptr) {
	static int dummy;
	const char *page = MONITOR_STATUS_PAGE;
	const char *not_found_page = MONITOR_NOT_FOUND_PAGE;
	const char *svc_unavailable_page = MONITOR_SVC_UNAVAILABLE_PAGE;
	const char *status_url = MONITOR_STATUS_URL;
	struct MHD_Response *response;
	enum MHD_Result rc = MHD_NO;

	if ((strcmp(method, "GET") != 0) && (strcmp(method, "HEAD") != 0)) {
		debug3("Monitor-Server: Received inacceptable HTTP method.");
		return MHD_NO;
	}

	if (&dummy != *ptr) {
		/* The first time only the headers are valid,
		   do not respond in the first round... */
		*ptr = &dummy;
		return MHD_YES;
	}

	if (*upload_data_size != 0) {
		/* upload data in a GET!? */
		return MHD_NO;
	}

	debug3("Monitor-Server: Received %s %s %s", method, url, version);

	*ptr = NULL; /* clear context pointer */

	if (strcmp(url, status_url) == 0) {

		bool pid_probe_ok = true;

		if (kill(proxy_session.master_pid,0) < 0) {
			if (errno == ESRCH) {
				log_system(LOG_LEVEL_EMERG, "Monitor-Server: Seems that " SUSSHI_PROXYD_NAME " has terminated!");
			} else {
				log_system(LOG_LEVEL_EMERG, "Monitor-Server: Seems that " SUSSHI_PROXYD_NAME " is in trouble (errno = %d) !", errno);
			}
			pid_probe_ok = false;
		}

		if (pid_probe_ok) {
			response = MHD_create_response_from_buffer(strlen(page), (void *) page, MHD_RESPMEM_PERSISTENT);
			rc = MHD_queue_response(connection, MHD_HTTP_OK, response);
			debug3("Monitor-Server: Return 200 OK");
		} else {
			response = MHD_create_response_from_buffer(strlen(svc_unavailable_page), (void *) svc_unavailable_page, MHD_RESPMEM_PERSISTENT);
			rc = MHD_queue_response(connection, MHD_HTTP_SERVICE_UNAVAILABLE, response);
			debug3("Monitor-Server: Return 503 Service Unavailable");
		}

	} else {
		response = MHD_create_response_from_buffer(strlen(not_found_page), (void *) not_found_page, MHD_RESPMEM_PERSISTENT);
		rc = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
		debug3("Monitor-Server: Return 404 Not Found");
	}

	MHD_destroy_response(response);

	return rc;
}


/*!
 * @brief   MHD callback to whitelist client IPs before accepting a connection.
 *
 * Always allows loopback addresses (127.0.0.1, ::1). If the environment
 * variable @c MONITOR_CLIENTS is set, the client IP must match one of the
 * listed CIDR networks (space- or comma-separated); otherwise the connection
 * is denied. IPv4-mapped IPv6 addresses are normalised before comparison.
 *
 * @param   cls     Unused.
 * @param   addr    Client socket address.
 * @param   addrlen Length of @p addr.
 *
 * @return  MHD_YES to allow the connection, MHD_NO to deny it.
 */

static enum MHD_Result
mhd_callback_check_client_ip(void *cls, const struct sockaddr *addr, socklen_t addrlen) {
	char *env;
	bstring networks_string = NULL;
	bstring client_ip = NULL;
	bstrList networks_list = NULL;
	enum MHD_Result rc = MHD_NO;

	if ((env = getenv("MONITOR_CLIENTS")) == NULL) {
		return MHD_YES;
	} else {
		char ipstr[INET6_ADDRSTRLEN], *ix;

		if (addr->sa_family == AF_INET) {
			struct sockaddr_in *s = (struct sockaddr_in *) addr;
			if (inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr) == NULL)
				return false;
		} else { // AF_INET6
			struct sockaddr_in6 *s = (struct sockaddr_in6 *) addr;
			if (inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr) == NULL)
				return false;
		}

		client_ip = bfromcstr(ipstr);
		networks_string = bformat("127.0.0.1 ::1 %s", env);

		/* Replace , with ' ', so we can accept both forms */
		ix = bdata(networks_string);
		while((ix = strchr(ix, ',')) != NULL)
			*ix++ = ' ';

		networks_list = bsplit(networks_string, ' ');

		for(int i=0; (i < networks_list->qty) && (rc == MHD_NO); i++) {
			if (blength(networks_list->entry[i]) == 0)
				continue;
			if (susshi_match_cidr(client_ip, networks_list->entry[i]))
				rc = MHD_YES;
		}

		if (rc == MHD_NO)
			debug3("Denied monitor request because client IP (%s) does not belong to any of %s", bdata(client_ip), bdata(networks_string));

		bstrListDestroy(networks_list);
		bstrFree(networks_string);
		bstrFree(client_ip);
	}

	return rc;
}



/*!
 * @brief   SIGTERM handler for the monitor daemon.
 *
 * Sets the @c received_sigterm flag so the daemon loop exits cleanly.
 *
 * @param   signo   Signal number (unused).
 */

static void
proxy_monitor_daemon_sigterm_handler(int signo) {
	(void) signo;

	int_store.received_sigterm = true;
}


/*!
 * @brief   Main loop of the monitor daemon process.
 *
 * Sets the process title, installs the SIGTERM handler, starts the MHD
 * HTTP server, drops privileges permanently, writes the PID file, and
 * blocks until SIGTERM is received. Cleans up and exits on termination.
 */

static void
proxy_monitor_daemon_loop(void) {

	SETPROCTITLE("Monitor-daemon");

	/* Set up SIGTERM handler. */
	proxy_sigaction(SIGTERM, &proxy_monitor_daemon_sigterm_handler, 0);

	int_store.daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION,
										proxy_cfg.health_monitor_port,
										&mhd_callback_check_client_ip,
										NULL,
										&mhd_callback_request,
										NULL,
										MHD_OPTION_END);

	if (int_store.daemon != NULL) {
		log_system(LOG_LEVEL_INFO, "HTTP health monitor-server ready for query on http://<hostname>:%d", proxy_cfg.health_monitor_port);

		/*
		 * Drop privileges permanently
		 * Even doing this after starting the threats works fine because threats are in same context with process
		 */
		proxy_drop_privileges("Monitor-daemon", true);

		while (!int_store.received_sigterm) {
			pause();
		}

		log_system(LOG_LEVEL_INFO, "Received Terminated signal. Terminating. Bye Bye.");
		MHD_stop_daemon(int_store.daemon);

		exit(0);

	} else {
		log_system(LOG_LEVEL_ERROR, "HTTP health monitor-server initialization failed.");
		exit(1);
	}
}


/*!
 * Fork a monitor daemon
 *
 * @return  true on success
 */

bool
proxy_fork_monitor_daemon(void) {

	int child_pid;

	if (proxy_session.monitor_pid > 0) {
		debug2("Monitor daemon already running with pid %d", proxy_session.monitor_pid);
		return true;
	}

	switch (child_pid = fork()) {
		case 0: { /* I am child = monitor-daemon */
			int fd;

			/* Ignore SIGCONT and SIGHUP used in master process */
			proxy_sigaction(SIGCONT, SIG_IGN, 0);
			proxy_sigaction(SIGHUP, SIG_IGN, 0);

			if ((fd = open(_PATH_DEVNULL, O_RDWR, 0)) != -1) {
				dup2(fd, STDIN_FILENO);
				dup2(fd, STDOUT_FILENO);
				if (fd > STDERR_FILENO)
					close(fd);
			}

			/* Run the monitor daemon */
			proxy_monitor_daemon_loop();

			exit(0);
		}

		case -1: {
			error("Failed to fork monitor daemon");
			return false;
		}	break;

		default: { /* I am parent */

			proxy_session.monitor_pid = child_pid;
			log_system(LOG_LEVEL_INFO, "Forked monitor daemon with pid %d", proxy_session.monitor_pid);
			return true;
		}
	}
}

/*! @} */
