/*!
 *
 * @brief       Master Loop
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
 * @defgroup    master_loop Master Loop
 * @brief       Functions of the master loop handling new connections and process forking.
 * @{
 */

#include <susshid/common.h>


// Pointer to shared memory used to store timestamps of embryonic childs
typedef volatile struct {
	time_t timestamp;  // time, the embryonic child has started, NULL if free
} embryonic_slot;

static embryonic_slot *susshi_embryonic_slots = NULL;
static int volatile current_embryonics = 0;
static volatile sig_atomic_t sigchld_received = 0;

/* Prototypes */
static void susshi_master_init_embryonic_slots(void);
static int  susshi_master_current_embryonics(void);
static int  susshi_master_new_embryonic_slot(void);

static void	susshi_create_master_listen_fds(struct pollfd *pollfds);
static void susshi_close_listen_sockets(struct pollfd *pollfds);

static void susshi_master_store_client_banner_and_product(void);

static bool susshi_master_new_client(socket_t client_fd);

static void susshi_get_connect_command(void);
static void susshi_master_sigchld_handler(int signo);
static void susshi_master_update_proctitle(void);

/*!
 * @brief   SIGCHLD handler for cleaning up dead children.
 *
 * @param   signo
 */

static void susshi_master_sigchld_handler(int signo) {
	(void) signo;
	while (waitpid(-1, NULL, WNOHANG) > 0);
	sigchld_received = 1;
}


/*!
 * @brief   Initialize Embryonic Child slots
 *
 * @details The embryonic slots mechanism is a kind of DOS mechanism to prevent attackers place fork bombs.
 *
 * @details Each time a new connection hits the listen sockets, a new slot is looked up and a timestamp "NOW" is recorded in that slot.
 * The ID of the slot is given to the forking child and the child resets this slot as soon as authentication of the client is
 * completed or (in most situations) the process quits before authentication completion and is able to run its cleanup functions.
 *
 * @details If a forking child somehow dies and is unable to reset the timer anymore, the timer helps to free the slot after "EmbryonicGraceTime".
 *
 * @details suSSHi implements an algorithm that will refuse connection attempts with a probability of ``susshi_cfg.max_embryonics_rate/100'' (%)
 *          if there are currently ``susshi_cfg.max_embryonics_start'' unauthenticated connections.
 *          The probability increases linearly and all connection attempts are refused if the number of unauthenticated
 *          connections reaches ``susshi_cfg.max_embryonics_start''.
 *
 * @details See also MaxEmbryonics and EmbryonicGraceTime configuration parameters:
 *
 *          MaxEmbryonics = "Start:Rate:Max" (default: 30:10:100)
 *          EmbryonicGraceTime = embryonic gracetime in seconds (default: 10);
 *
 */

static void
susshi_master_init_embryonic_slots(void) {

	int shm_id;

	if (flag_no_daemon)
		return;

	shm_id = shmget(IPC_PRIVATE, susshi_cfg.max_embryonics * sizeof(embryonic_slot), IPC_CREAT | 0600);

	if (shm_id > -1) {
		susshi_embryonic_slots = shmat(shm_id, NULL, 0);
		if (susshi_embryonic_slots) {
			for (int i = 0; i < susshi_cfg.max_embryonics; i++) {
				susshi_embryonic_slots[i].timestamp = (time_t) NULL;
			}
		} else {
			fatal("Could not attach shared memory for embryonic childs.");
		}
	} else {
		fatal("Could not get shared memory for embryonic childs: %s", strerror(errno));
	}
}


/*!
 * @brief   Claim a new embryonic slot
 *
 * @return  ID of slot or -1 if no more slots available / ratio results in no slot
 */

static int
susshi_master_new_embryonic_slot(void) {

	int p, ratio;
	time_t now;

	now = time(NULL);

	susshi_master_current_embryonics();

	if (current_embryonics > susshi_cfg.max_embryonics_start) {
		if (susshi_cfg.max_embryonics_rate == 100) {
			log_system(LOG_LEVEL_ALERT, "Embryonic childs at %d (>S:%d) rejecting new client with ratio 100/100.",
					   current_embryonics, susshi_cfg.max_embryonics_start);
			return -1;
		}

		/*
		 * dropping starts at connection #max_embryonics_start with a probability
		 * of (max_embryonics_rate/100). the probability increases linearly until
		 * all connections are dropped for current_embryonics > max_embryonics
		 */

		p  = 100 - susshi_cfg.max_embryonics_rate;
		p *= current_embryonics - susshi_cfg.max_embryonics_start;
		p /= susshi_cfg.max_embryonics - susshi_cfg.max_embryonics_start;
		p += susshi_cfg.max_embryonics_rate;

		ratio = arc4random_uniform(100);

		if (ratio < p) {
			log_system(LOG_LEVEL_ALERT, "Embryonic childs at %d (>S:%d), rejecting new client (probability was %d/100)",
					   current_embryonics, susshi_cfg.max_embryonics_start, p);
			return -1;  /* Drop connection */
		}

	}
	/* Find a free slot */
	for (int i = 0; i < susshi_cfg.max_embryonics; i++) {
		if ((now - (time_t) susshi_cfg.embryonic_grace_time) > susshi_embryonic_slots[i].timestamp) {
			susshi_embryonic_slots[i].timestamp = now;
			return i;
		}
	}

	return -1;
}


/*!
 * @brief   Free embryonic slot with given ID. Called from child after successful authentication or on graceful quit
 *
 * @param   id  ID of slot to be freed.
 */

void
susshi_master_free_embryonic_slot(int id) {
	if (id > -1) {
		susshi_embryonic_slots[id].timestamp = (time_t) NULL;
	}
}


/*!
 * @brief   Detach from shared memory
 *
 * It seems that detaching from embryonic shared memory sometimes causes segfault
 * crashes if called after receiving SIG*
 *
 * Shared memory is detached from the process anyway when it is terminated.
 * Therefore, there is no need to call it explicitly when exiting.
 */

void
susshi_master_detach_embryonic_slots(void) {

	if (flag_no_daemon)
		return;

	/* Detach from shared memory */
	if (susshi_embryonic_slots) {

		debug3("Dettaching embryonic shared memory.");

		if (shmdt((void *) susshi_embryonic_slots) != 0) {
			debug3("Dettaching embryonic shared memory failed: %s", strerror(errno));
		}

		susshi_embryonic_slots = NULL;
	}
}


/*!
 * @brief   Update and return current number of embryonics
 *
 * @return  Number of embryonics
 */

static int
susshi_master_current_embryonics(void) {
	time_t now;

	if (flag_no_daemon)
		return 0;

	current_embryonics = 0;
	now = time(NULL);

	for (int i = 0; i < susshi_cfg.max_embryonics; i++) {
		if ((now - (time_t) susshi_cfg.embryonic_grace_time) < susshi_embryonic_slots[i].timestamp) {
			current_embryonics++;
		} else {
			susshi_embryonic_slots[i].timestamp = (time_t) NULL;
		}
	}

	return current_embryonics;
}


/*!
 * @brief   The Master loop where we listen for new connections and then fork the new client
 */

void
susshi_master_loop(void) {
	struct pollfd poll_fds[SUSSHI_MAX_LISTEN_SOCKS];
	socket_t new_client_fd;
	int rc;
	int embryonic_slot_id;
	pid_t child_pid;

	/* Set up SIGCHLD handler. */
	susshi_sigaction(SIGCHLD, susshi_master_sigchld_handler, SA_RESTART | SA_NOCLDSTOP);

	/* Start-time of master process */
	susshi_report.session_start_time = time(NULL);

	/* Create sockets, assign listen addresses and put them all in the given fd_set */
	susshi_create_master_listen_fds(poll_fds);

	/* Drop privileges until we receive a signal to restart */
	susshi_drop_privileges(SUSSHID_NAME, false);

	/* Register Signals in Master Loop */
	susshi_master_loop_signal_register();

	/* Initialize embryonic pipes */
	susshi_master_init_embryonic_slots();

	/* Update proctitle */
	susshi_master_update_proctitle();

	while (!susshi_session.received_signal_for_restart) {

		if (sigchld_received) {
			sigchld_received = 0;
			susshi_master_current_embryonics();
			susshi_master_update_proctitle();
		}

		/* Blocks until there is a new incoming connection. */
		rc = poll(poll_fds, susshi_session.num_listen_socks,
				  (current_embryonics > 0) ? susshi_cfg.embryonic_grace_time*1000 : -1);

		if (rc < 0) {
			if (errno == EINTR) {
				if (susshi_session.received_signal) {
					log_system(LOG_LEVEL_INFO, "Closing listen sockets");
					susshi_close_listen_sockets(poll_fds);
					susshi_cleanup();
					log_system(LOG_LEVEL_INFO, "Exiting on signal %d (%s)",
							   susshi_session.received_signal, strsignal(susshi_session.received_signal));
					exit(0);
				} else {
					continue;
				}
			} else {
				fatal("Problems with socket poll %s.", strerror(errno));
			}
		}

		if (rc == 0) {
			/* Timeout */
			susshi_master_update_proctitle();
			continue;
		}

		for (nfds_t i = 0; i < susshi_session.num_listen_socks; i++) {

			if (poll_fds[i].revents == 0)
				continue;

			if (poll_fds[i].revents != POLLIN)
				fatal("Problems with socket poll. Got Event %d from poll().", poll_fds[i].revents);

			if ((new_client_fd = accept(poll_fds[i].fd, NULL, NULL)) >= 0) {

				if (!flag_no_daemon) {

					embryonic_slot_id = susshi_master_new_embryonic_slot();

					susshi_master_update_proctitle();

					if (embryonic_slot_id > -1) {

						// New embryonic child;

						switch (child_pid = fork()) {
							case 0: { /* I am child */
								int fd;

								susshi_session.process_role = PROC_ROLE_SESSION;

								susshi_close_listen_sockets(poll_fds);

								/* Drop privileges permanently */
								susshi_drop_privileges(SUSSHID_NAME, true);

								/* Auto-reap hook intermediate children without creating zombies.
								 * Session processes never waitpid their own children, so SIG_IGN
								 * is safe and avoids defunct hook processes during long sessions. */
								susshi_sigaction(SIGCHLD, SIG_IGN, 0);

								/* Ignore SIGCONT used in master process */
								susshi_sigaction(SIGCONT, SIG_IGN, 0);

								/* Write down embryonic pipe id for later closing */
								susshi_session.embryonic_slot_id = embryonic_slot_id;

								/* Prevent child from killing report or monitor daemon or rsyslogd */
								susshi_session.report_pid = -1;
								susshi_session.monitor_pid = -1;
								susshi_session.rsyslog_pid = -1;

								if ((fd = open(_PATH_DEVNULL, O_RDWR, 0)) != -1) {
									dup2(fd, STDIN_FILENO);
									dup2(fd, STDOUT_FILENO);
									if (fd > STDERR_FILENO)
										close(fd);
								}

								// On fork we create a new identifier
								init_susshi_identifier();

								// Init susshi log and report
								init_susshi_log();
								init_susshi_report();

								/* Handle session */
								if (susshi_master_new_client(new_client_fd))
									exit(0);
								else
									exit(1);
							}

							case -1: {
								error("Failed to fork");
							}	break;

							default: { /* I am parent */
								close(new_client_fd);
								susshi_master_update_proctitle();
								log_system(LOG_LEVEL_INFO, "Forked child with pid %d", child_pid);
							}
						}
					} else {
						close(new_client_fd);
					}
				}
				else {
					/* Handle session */
					susshi_close_listen_sockets(poll_fds);

					if (susshi_master_new_client(new_client_fd))
						exit(0);
					else
						exit(1);
				}
			} else {
				fatal("Accept failed.");
			}
		}
	}

	susshi_close_listen_sockets(poll_fds);
}

/*!
 * @brief   Create sockets, assign listen addresses and put them all in the given fd_set
 *
 * @param   pollfds
 */

static void
susshi_create_master_listen_fds(struct pollfd *pollfds) {
	struct addrinfo *ai;
	socket_t listen_sock;
	int on = 1;

	char ipstr[NI_MAXHOST], portstr[NI_MAXSERV];
	int rc;

	susshi_session.num_listen_socks = 0;

	for (ai = susshi_cfg.listen_addrs; ai; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;
		if (susshi_session.num_listen_socks >= SUSSHI_MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. A maximum of %d is supported.", SUSSHI_MAX_LISTEN_SOCKS);

		if ((rc = getnameinfo(ai->ai_addr, ai->ai_addrlen,
							  ipstr, sizeof(ipstr), portstr, sizeof(portstr),
							  NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
			error("Getnameinfo failed: %.100s", susshi_gai_strerror(rc));
			continue;
		}

		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (listen_sock < 0) {
			/* kernel may not support ipv6 */
			log_system(LOG_LEVEL_INFO, "Error creating socket: %.100s", strerror(errno));
			continue;
		}
		if (susshi_socket_set_nonblock(listen_sock) == -1) {
			close(listen_sock);
			continue;
		}

		/* Set socket options */
#ifdef SO_REUSEADDR
		if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
			error("setsockopt SO_REUSEADDR: %s", strerror(errno));
#endif

#ifdef SO_REUSEPORT
		if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) == -1)
			error("setsockopt SO_REUSEPORT: %s", strerror(errno));
#endif

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		if (ai->ai_family == AF_INET6)
			susshi_socket_set_v6only(listen_sock);

		/* Bind the socket to the desired port. */
		debug3("Attempting bind on %s port %s (fd=%d)", ipstr, portstr, listen_sock);
		if (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) < 0) {
			error("Bind to port %s on %s failed: %.200s.",
				  portstr, ipstr, strerror(errno));
			close(listen_sock);
			continue;
		}

		switch(ai->ai_family) {
			case AF_INET6:
				susshi_session.host_has_ipv6 = true;
				break;
			case AF_INET:
				susshi_session.host_has_ipv4 = true;
		}


		susshi_session.listen_socks[susshi_session.num_listen_socks] = listen_sock;

		if (listen(listen_sock, SUSSHI_LISTEN_BACKLOG) < 0)
			fatal("Listen on [%s]:%s: %.100s", ipstr, portstr, strerror(errno));

		debug3("Listening on socket %d for new connections on %s port %s", listen_sock, ipstr, portstr);

		log_system(LOG_LEVEL_INFO, "Listening for new connections on %s port %s", ipstr, portstr);

		/* Add socket to fd_set */
		pollfds[susshi_session.num_listen_socks].fd = listen_sock;
		pollfds[susshi_session.num_listen_socks].events = POLLIN;

		susshi_session.num_listen_socks++;
	}
	freeaddrinfo(susshi_cfg.listen_addrs);
	susshi_cfg.listen_addrs = NULL;
}

/*!
 * @brief   Close listen sockets
 *
 * @param   pollfds
 */

static void
susshi_close_listen_sockets(struct pollfd *pollfds) {
	nfds_t i;

	log_system(LOG_LEVEL_INFO, "Closing %d listen socket(s)", (int) susshi_session.num_listen_socks);
	for(i=0; i < susshi_session.num_listen_socks; i++) {
		if (close(pollfds[i].fd) < 0)
			error("close(fd %d) failed: %s", pollfds[i].fd, strerror(errno));
	}
	susshi_session.num_listen_socks = 0;
}


/*!
 * @brief   Update process proctitle with new process information
 */

static void
susshi_master_update_proctitle(void) {

	/* Update current embryonics */
	susshi_master_current_embryonics();

	SETPROCTITLE("Listening for new connections. (E:%d/S:%d/M:%d)",
				 current_embryonics, susshi_cfg.max_embryonics_start, susshi_cfg.max_embryonics);
}


/*!
 * @brief   Store Client banner and product enum if it can be found out
 */

static void
susshi_master_store_client_banner_and_product(void) {

	susshi_session.client_ssh_identification = bfromcstr(ssh_get_clientbanner(susshi_session.client_session));
	debug2_dir(CLIENT, GATEWAY, "Client Banner: %s", bdata(susshi_session.client_ssh_identification));

	if (strncasecmp(bdata(susshi_session.client_ssh_identification), SSH_IDENTIFICATION_OPENSSH, strlen(SSH_IDENTIFICATION_OPENSSH)) == 0) {
		susshi_session.client_product = CLIENT_IS_OPENSSH;
	} else if (strncasecmp(bdata(susshi_session.client_ssh_identification), SSH_IDENTIFICATION_PUTTY, strlen(SSH_IDENTIFICATION_PUTTY)) == 0) {
		susshi_session.client_product = CLIENT_IS_PUTTY;
	} else if (strncasecmp(bdata(susshi_session.client_ssh_identification), SSH_IDENTIFICATION_SECURECRT, strlen(SSH_IDENTIFICATION_SECURECRT)) == 0) {
		susshi_session.client_product = CLIENT_IS_SECURECRT;
	} else if (strncasecmp(bdata(susshi_session.client_ssh_identification), SSH_IDENTIFICATION_SECUREFX, strlen(SSH_IDENTIFICATION_SECUREFX)) == 0) {
		susshi_session.client_product = CLIENT_IS_SECUREFX;
	} else if (strncasecmp(bdata(susshi_session.client_ssh_identification), SSH_IDENTIFICATION_XSHELL, strlen(SSH_IDENTIFICATION_XSHELL)) == 0) {
		susshi_session.client_product = CLIENT_IS_XSHELL;
	} else if (strncasecmp(bdata(susshi_session.client_ssh_identification), SSH_IDENTIFICATION_WINSCP, strlen(SSH_IDENTIFICATION_WINSCP)) == 0) {
		susshi_session.client_product = CLIENT_IS_WINSCP;
	} else if (strncasecmp(bdata(susshi_session.client_ssh_identification), SSH_IDENTIFICATION_FILEZILLA, strlen(SSH_IDENTIFICATION_FILEZILLA)) == 0) {
		susshi_session.client_product = CLIENT_IS_FILEZILLA;
	} else if (validate_string_chars_regex(susshi_session.client_ssh_identification, SSH_IDENTIFICATION_FLOWSSH_REGEX)) {
		susshi_session.client_product = CLIENT_IS_FLOWSSH;
	} else {
		susshi_session.client_product = CLIENT_IS_UNKNOWN;
	}

}


/*!
 * @brief   Handle connection from new client
 *
 * This is the entrance point after the master process has received a new connection and has forked.
 *
 * @param   client_fd       The socket the client has connected on
 *
 * @return  true on success
 */

static bool
susshi_master_new_client(socket_t client_fd) {

	int SSH_false = 0;
	ssh_bind client_bind;
	long timeout;
	bool rc = false;
	u_int64_t host_key_types_loaded = 0L;

	if ((client_bind = ssh_bind_new()) != NULL) {

		/*
		 * Set Hostkeys to be loaded
		 *
		 * libssh supports only one key per key_type (RSA, DSA, ECDSA ...), so we skip already loaded keys
		 * of the same type. This way only the preferred keys are loaded at any given time and no additional
		 * keys are added that overwrite the previously set keys.
		 */
		for (int i = 0; i < susshi_cfg.num_host_key_files; i++) {
			if ((1<<susshi_cfg.host_key_types[i]) & host_key_types_loaded) {
				debug4("Another Host-Key of same type (%s) has already been loaded. Skipping.", ssh_key_type_to_char(susshi_cfg.host_key_types[i]));
			} else {
				debug3("Setting host_key %s (%s)", bdata(susshi_cfg.host_key_files[i]), ssh_key_type_to_char(susshi_cfg.host_key_types[i]));
				ssh_bind_options_set(client_bind, SSH_BIND_OPTIONS_HOSTKEY, bdata(susshi_cfg.host_key_files[i]));
				host_key_types_loaded |= (1<<susshi_cfg.host_key_types[i]);
			}
		}

		/* Set suSSHi BANNER */
		ssh_bind_options_set(client_bind, SSH_BIND_OPTIONS_BANNER, SUSSHI_SSH_VERSION_BANNER);

		if ((susshi_session.client_session = ssh_new()) != NULL) {

			/* Prevent libssh from reading system / user ssh_config on ssh_connect */
			ssh_options_set(susshi_session.client_session, SSH_OPTIONS_PROCESS_CONFIG, &SSH_false);

			if (ssh_bind_accept_fd(client_bind, susshi_session.client_session, client_fd) != SSH_ERROR) {

				susshi_session.client_phase = PHASE_CONNECTED;      // Client is connected
				susshi_report.session_start_time = time(NULL);      // Start time of child process

				/* Channel-IDs start-range in PubKeyAgent mode (proxied channels) */
				susshi_session.client_session->maxchannel = (uint32_t) SUSSHI_SESSION_CLIENT_CHANNEL_START;

				/* Store Client IP and Port */
				store_client_socket_into_session(ssh_get_fd(susshi_session.client_session));

				log_system(LOG_LEVEL_INFO, "Received new connection from %s, source-port %d",
						   bdata(susshi_session.client_ip), susshi_session.client_port);

				susshi_hooks_run(HOOK_CLIENT_CONNECT);

				SETPROCTITLE("New connection from %s, port %d",
							  bdata(susshi_session.client_ip), susshi_session.client_port);

				/* Look if there is a connect command from client */
				susshi_get_connect_command();

				/* Switch on libssh verbosity based on debug level */
				susshi_libssh_set_verbosity(susshi_session.client_session, CLIENT);

				/* Perform / Validate Key Exchange */
				susshi_session.client_phase = PHASE_KEX;

				/* Set allowed public key algorithms for client authentication */
				if (susshi_cfg.public_key_algorithms != NULL) {
					ssh_options_set(susshi_session.client_session, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES, bdata(susshi_cfg.public_key_algorithms));
				}

				timeout = (long) susshi_cfg.embryonic_grace_time;
				ssh_options_set(susshi_session.client_session, SSH_OPTIONS_TIMEOUT, &timeout);
				debug2_dir(GATEWAY, CLIENT, "Setting bi-directional allowed packet ciphers to %s",
						bdata(susshi_cfg.client_ciphers));
				ssh_options_set(susshi_session.client_session, SSH_OPTIONS_CIPHERS_C_S, bdata(susshi_cfg.client_ciphers));
				ssh_options_set(susshi_session.client_session, SSH_OPTIONS_CIPHERS_S_C, bdata(susshi_cfg.client_ciphers));

				if (susshi_cfg.client_hmacs != NULL) {
					debug2_dir(GATEWAY, CLIENT, "Setting bi-directional allowed hmac algorithms to %s",
							   bdata(susshi_cfg.client_hmacs));
					ssh_options_set(susshi_session.client_session, SSH_OPTIONS_HMAC_C_S, bdata(susshi_cfg.client_hmacs));
					ssh_options_set(susshi_session.client_session, SSH_OPTIONS_HMAC_S_C, bdata(susshi_cfg.client_hmacs));
				}

				if (susshi_cfg.client_kex_algorithms != NULL) {
					ssh_options_set(susshi_session.client_session, SSH_OPTIONS_KEY_EXCHANGE, bdata(susshi_cfg.client_kex_algorithms));
					debug2_dir(GATEWAY, CLIENT, "List of preferred kex algorithms is set to %s",
							   bdata(susshi_cfg.client_kex_algorithms));
				}

				if (susshi_cfg.client_hostkey_algorithms != NULL) {
					/* The first algorithm on the client's name-list that satisfies the requirements and is also supported by the server MUST be chosen. */
					ssh_options_set(susshi_session.client_session, SSH_OPTIONS_HOSTKEYS, bdata(susshi_cfg.client_hostkey_algorithms));
					debug2_dir(GATEWAY, CLIENT, "List of preferred host key algorithms is set to %s",
							   bdata(susshi_cfg.client_hostkey_algorithms));
				}

				if (susshi_cfg.client_compression != -1) {
					ssh_options_set(susshi_session.client_session, SSH_OPTIONS_COMPRESSION,
									susshi_cfg.client_compression ?
									/* yes */ "zlib@openssh.com,zlib,none" :
									/* no */  "none,zlib@openssh.com,zlib");
				}

				if (ssh_handle_key_exchange(susshi_session.client_session) != SSH_OK) {
					log_system(LOG_LEVEL_WARNING, "Client is not speaking our language: %s. Aborting", ssh_get_error(susshi_session.client_session));
					close(client_fd);
					exit(1);
				} else {

					/* Store Client banner */
					susshi_master_store_client_banner_and_product();

					/* Activate Client TCP-Keepalive on request */
					if (susshi_cfg.client_tcp_keep_alive != -1) {
						debug3_dir(CLIENT, GATEWAY, "Setting TCP-Keepalive with Client %s.", susshi_cfg.client_tcp_keep_alive == 0 ? "OFF" : "ON");
						setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, (int[]) {susshi_cfg.client_tcp_keep_alive}, sizeof(int));
					}

					/* Start Client Authentication */
					if (susshi_client_auth_start()) {

						/* On successful authentication we close the embryonic pipe to signal master that we are no longer embryonic */
						susshi_master_free_embryonic_slot(susshi_session.embryonic_slot_id);

						switch(susshi_session.operation_mode) {
							case OP_MODE_GATEWAY: {
								/* Login into target */
								if (susshi_target_login()) {

									/* Finish client auth successfully */
									susshi_client_auth_finish(true);

									susshi_hooks_run(HOOK_SESSION_START);

									/* Register Session Log Rotation & Expiration Alarms */
									susshi_timer_alarms_register();

									/* Send first report */
									susshi_report_client_send_report(REPORT_FIRST);

									/* Start THE loop */
									susshi_session_loop();

									/* Send last report */
									susshi_report_client_send_report(REPORT_LAST);

									rc = true;
								} else {
									susshi_disconnect_standard(BOTH, DISCONNECT_TARGET_CONNECT_FAILED);
								}

							} break;
							case OP_MODE_SHELL: {
								/* Login into suSSHi shell */
								debug2_dir(CLIENT, GATEWAY, "User %s attempts to login on " SUSSHI_NAME " gateway in Shell Mode.", bdata(susshi_session.susshi_user));

								if (susshi_session.susshi_shell_mode_allowed) {
									/* Finish client auth successfully */
									susshi_client_auth_finish(true);

									susshi_hooks_run(HOOK_SESSION_START);

									/* Send first report */
									susshi_report_client_send_report(REPORT_FIRST);

									/* Start the shell loop */
									susshi_shell_loop();

									rc = true;
								} else {
									susshi_disconnect_standard(CLIENT, DISCONNECT_ACL_SHELL_REQUEST_DENIED);
								}

								/* Send last report */
								susshi_report_client_send_report(REPORT_LAST);
							} break;

							case OP_MODE_BASTION: {

								debug2_dir(CLIENT, GATEWAY, "User %s attempts to run in Bastion Mode.", bdata(susshi_session.susshi_user));

								if (susshi_target_login()) {
									/* Finish client auth successfully */
									susshi_client_auth_finish(true);

									susshi_hooks_run(HOOK_SESSION_START);

									/* Register Session Log Rotation & Expiration Alarms */
									susshi_timer_alarms_register();

									/* Send first report */
									susshi_report_client_send_report(REPORT_FIRST);

									/* Start THE loop */
									susshi_session_loop();

									/* Send last report */
									susshi_report_client_send_report(REPORT_LAST);

									rc = true;
								} else {
									susshi_disconnect_standard(BOTH, DISCONNECT_TARGET_CONNECT_FAILED);
								}
							} break;

							case OP_MODE_CHEF_REMOTE: {

								/* suSSHi Chef Remote Commands */
								debug2_dir(CLIENT, GATEWAY, "Got connection from susshi chef (remote command mode).");

								/* Finish client auth successfully */
								susshi_client_auth_finish(true);

								/* Start remote command loop */
								susshi_chef_remote_loop();

								rc = true;
							}
						}
					} else {
						log_system(LOG_LEVEL_WARNING, "Session for '%s@%s' on Host %s (susshid-ID %s) failed with reason 'Authentication failed'. (%s)",
								   bdata(susshi_session.susshi_user), bdata(susshi_session.client_ip),
								   bdata(susshi_session.hostname),
								   bdata(chef_cfg.susshid_id),
								   bdata(susshi_session.susshi_uniqid));

						susshi_hooks_run(HOOK_SESSION_AUTH_FAILED);

						ssh_disconnect(susshi_session.client_session);
					}
				}
				ssh_disconnect(susshi_session.client_session);
				ssh_free(susshi_session.client_session);
			} else {
				error("%s.", ssh_get_error(client_bind));
			}
		} else {
			error("Failed to allocate session.");
		}

		ssh_bind_free(client_bind);
	} else {
		error("Failed to allocate bind.");
	}

	if (rc == true)
		susshi_hooks_run(HOOK_SESSION_FINISHED);
	else
		susshi_hooks_run(HOOK_SESSION_FAILED);

	susshi_cleanup();

	return rc;
}


#define MY_BUFFER_LEN 1024

/*!
 * @brief   Did we get a connect command string from client?
 *
 * Allowed Syntax are:
 *
 * ```
 * susshi-connect »gw_user« »host«:»port« [»proxy_realm«]
 * susshi-connect oliver test-lab-011.lab.susshi.io
 * ```
 */

static void
susshi_get_connect_command(void) {

	bstring connect_string = NULL;
	bstrList connect_list = NULL;
	socket_t socket;
	uint16_t c;
	const char *susshi_pi = SUSSHI_CONNECT_IDENTIFIER;
	char *buffer;

	buffer = xcalloc(1, MY_BUFFER_LEN);

	socket = ssh_get_fd(susshi_session.client_session);

	/* Set socket non-blocking */
	susshi_socket_set_nonblock(socket);

	/* Check first characters without removing data from the queue (MSG_PEEK flag) */
	if (recv(socket, buffer, 3, MSG_PEEK) == 3) {
		for (c = 0; c < 3; c++) {
			buffer[c] = (char) tolower(buffer[c]);
		}
		if (strncmp(buffer, susshi_pi, 3) == 0) {
			/* Looks like our SUSSHI_CONNECT_IDENTIFIER, so read whole line */
			for(c=0; c < MY_BUFFER_LEN; c++) {
				if (recv(socket, &buffer[c], 1, 0) != 1)
					goto decode_error;
				if (buffer[c] == '\n') {
					buffer[c]='\0';
					break;
				}
				buffer[c] = (char) tolower(buffer[c]);
			}

			if (c == MY_BUFFER_LEN) {
				goto decode_error;
			}

			if (strncmp(buffer, susshi_pi, strlen(susshi_pi)) == 0) {
				debug2_dir(CLIENT, GATEWAY, "Received a connect command during identification exchange.");

				connect_string = bfromcstr(buffer);
				connect_list = bsplit(connect_string, ' ');

				for (int i = 0, t = 0; i < connect_list->qty; i++) {
					if (blength(connect_list->entry[i]) == 0)
						continue;
					switch (t) {
						case 0:
							/* susshi-connect */
							t++;
							break;
						case 1:
							/* gateway username */
							susshi_session.susshi_user = bstrcpy(connect_list->entry[i]);
							t++;
							break;
						case 2:
							/* target host
							 *
							 * If target_host also contains port in IPv4 / IPv6 notation, this is separated later in
							 * store_splitted_loginstring_into_session()
							 */
							susshi_session.target_host = bstrcpy(connect_list->entry[i]);
							susshi_report.client_used_connect = true;
							t++;
							break;
						case 3:
							/* proxy realm */
							susshi_session.target_proxy_realm = bstrcpy(connect_list->entry[i]);
							t++;
							break;
						default:
							break;
					}
				}

				bstrListDestroy(connect_list);
				bstrFree(connect_string);

				if (susshi_report.client_used_connect) {
					debug3_dir(CLIENT, GATEWAY, "Connect parameters: susshi_user=%s, target_host=%s proxy_realm=%s",
							   bdata(susshi_session.susshi_user), bdata(susshi_session.target_host),
							   susshi_session.target_proxy_realm ? bdata(susshi_session.target_proxy_realm) : "(not given)");
				} else {
					susshi_disconnect_standard(CLIENT, DISCONNECT_PROTOCOLL_ERROR);
				}
			}
		}
	}
	xfree(buffer);
	return;

	decode_error: {
		susshi_disconnect_standard(CLIENT, DISCONNECT_PROTOCOLL_ERROR);
	}
}

#undef MY_BUFFER_LEN

/*! @} */
