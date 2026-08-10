/*!
 *
 * @brief       Master Loop
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
 * @defgroup    proxy_master_loop Master Loop methods
 * @brief       Functions of the master loop handling new connections and process forking.
 * @{
 *
 */

#include <susshi-proxyd/common.h>


/* Pointer to shared memory used to store timestamps of embryonic childs */
typedef volatile struct {
	time_t timestamp;  // time, the embryonic child has started, NULL if free
} embryonic_slot;

embryonic_slot *proxy_embryonic_slots = NULL;
static int volatile current_embryonics = 0;

/* Prototypes */
static void proxy_master_init_embryonic_slots(void);
static int  proxy_master_current_embryonics(void);
static int  proxy_master_new_embryonic_slot(void);

static void	proxy_create_master_listen_fds(struct pollfd *pollfds);
static void proxy_close_listen_sockets(struct pollfd *pollfds);

static bool proxy_master_new_client(socket_t client_fd);

static void proxy_master_sigchld_handler(int signo);
static void proxy_master_update_proctitle(void);
static bool proxy_master_validate_gateway_ip(socket_t socket, bstring *client_ip);


/*!
 * @brief       SIGCHLD handler for cleaning up dead children.
 *
 * @param       signo
 */

static void proxy_master_sigchld_handler(int signo) {
	(void) signo;
	while (waitpid(-1, NULL, WNOHANG) > 0);

	proxy_master_current_embryonics();
	proxy_master_update_proctitle();
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
 * @details suSSHi implements an algorithm that will refuse connection attempts with a probability of ``proxy_cfg.max_embryonics_rate/100'' (%)
 *          if there are currently ``proxy_cfg.max_embryonics_start'' unauthenticated connections.
 *          The probability increases linearly and all connection attempts are refused if the number of unauthenticated
 *          connections reaches ``proxy_cfg.max_embryonics_start''.
 *
 * @details See also MaxEmbryonics and EmbryonicGraceTime configuration parameters:
 *
 *          MaxEmbryonics = "Start:Rate:Max" (default: 30:10:100)
 *          EmbryonicGraceTime = embryonic gracetime in seconds (default: 10);
 *
 */

static void
proxy_master_init_embryonic_slots(void) {

	int shm_id;

	if (flag_no_daemon)
		return;

	shm_id = shmget(IPC_PRIVATE, proxy_cfg.max_embryonics * sizeof(embryonic_slot), IPC_CREAT | 0666);

	if (shm_id > -1) {
		proxy_embryonic_slots = shmat(shm_id, NULL, 0);
		if (proxy_embryonic_slots) {
			for (int i = 0; i < proxy_cfg.max_embryonics; i++) {
				proxy_embryonic_slots[i].timestamp = (time_t) NULL;
			}
		} else {
			fatal("Could not attach shared memory for embryonic childs.");
		}
	} else {
		fatal("Could not get shared memory for embryonic childs: %s", strerror(errno));
	}
}

/*!
 * @brief       Claim a new embryonic slot
 *
 * @return      ID of slot or -1 if no more slots available / ratio results in no slot
 */

static int
proxy_master_new_embryonic_slot(void) {

	int p, ratio;
	time_t now;

	now = time(NULL);

	proxy_master_current_embryonics();

	if (current_embryonics > proxy_cfg.max_embryonics_start) {
		if (proxy_cfg.max_embryonics_rate == 100) {
			log_system(LOG_LEVEL_ALERT, "Embryonic childs at %d (>S:%d) rejecting new client with ratio 100/100.",
					   current_embryonics, proxy_cfg.max_embryonics_start);
			return -1;
		}

		/*
		 * dropping starts at connection #max_embryonics_start with a probability
		 * of (max_embryonics_rate/100). the probability increases linearly until
		 * all connections are dropped for current_embryonics > max_embryonics
		 */

		p  = 100 - proxy_cfg.max_embryonics_rate;
		p *= current_embryonics - proxy_cfg.max_embryonics_start;
		p /= proxy_cfg.max_embryonics - proxy_cfg.max_embryonics_start;
		p += proxy_cfg.max_embryonics_rate;

		ratio = arc4random_uniform(100);

		if (ratio < p) {
			log_system(LOG_LEVEL_ALERT, "Embryonic childs at %d (>S:%d), rejecting new client (probability was %d/100)",
					   current_embryonics, proxy_cfg.max_embryonics_start, p);
			return -1;  /* Drop connection */
		}

	}
	/* Find a free slot */
	for (int i = 0; i < proxy_cfg.max_embryonics; i++) {
		if ((now - (time_t) proxy_cfg.embryonic_grace_time) > proxy_embryonic_slots[i].timestamp) {
			proxy_embryonic_slots[i].timestamp = now;
			current_embryonics++;
			return i;
		}
	}

	return -1;
}


/*!
 * @brief       Free embryonic slot with given ID. Called from child after successful authentication or on graceful quit
 *
 * @param       id  ID of slot to be freed.
 */

void
proxy_master_free_embryonic_slot(int id) {
	if (proxy_session.embryonic_slot_id > -1) {
		proxy_embryonic_slots[id].timestamp = (time_t) NULL;
	}
}


/*!
 * @brief       Detach from shared memory
 */

void
proxy_master_detach_embryonic_slots(void) {

	if (flag_no_daemon)
		return;

	/* Detach from shared memory */
	if (proxy_embryonic_slots) {

		debug3("Dettaching embryonic shared memory.");

		if (shmdt((void *) proxy_embryonic_slots) != 0) {
			debug3("Dettaching embryonic shared memory failed: %s", strerror(errno));
		}

		proxy_embryonic_slots = NULL;
	}
}


/*!
 * @brief       Update and return current number of embryonics
 *
 * @return      number of embryonics
 */

static int
proxy_master_current_embryonics(void) {
	time_t now;

	if (flag_no_daemon)
		return 0;

	current_embryonics = 0;
	now = time(NULL);

	for (int i = 0; i < proxy_cfg.max_embryonics; i++) {
		if ((now - (time_t) proxy_cfg.embryonic_grace_time) < proxy_embryonic_slots[i].timestamp) {
			current_embryonics++;
		} else {
			proxy_embryonic_slots[i].timestamp = (time_t) NULL;
		}
	}

	return current_embryonics;
}


/*!
 * @brief       The Master loop where we listen for new connections and then fork the new client
 */

void
proxy_master_loop(void) {
	struct pollfd poll_fds[SUSSHI_MAX_LISTEN_SOCKS];
	socket_t new_client_fd;
	int rc;
	int embryonic_slot_id;
	pid_t child_pid;
	bstring client_ip = NULL;

	/* Set up SIGCHLD handler. */
	proxy_sigaction(SIGCHLD, proxy_master_sigchld_handler, SA_RESTART | SA_NOCLDSTOP);

	/* Create sockets, assign listen addresses and put them all in the given fd_set */
	proxy_create_master_listen_fds(poll_fds);

	/* Drop privileges permanently */
	proxy_drop_privileges(SUSSHI_PROXYD_NAME, true);

	/* Register Signals in Master Loop */
	proxy_master_loop_signal_register();

	/* Initialize embryonic pipes */
	proxy_master_init_embryonic_slots();

	/* Update proctitle */
	proxy_master_update_proctitle();

	while (!proxy_session.received_signal_for_restart) {

		/* Blocks until there is a new incoming connection. */
		rc = poll(poll_fds, proxy_session.num_listen_socks,
				  (current_embryonics > 0) ? proxy_cfg.embryonic_grace_time*1000 : -1);

		if (rc < 0) {
			if (errno == EINTR)
				continue;
			fatal("Problems with socket poll %s.", strerror(errno));
		}

		if (rc == 0) {
			/* Timeout */
			proxy_master_update_proctitle();
			continue;
		}

		for (nfds_t i = 0; i < proxy_session.num_listen_socks; i++) {

			if (poll_fds[i].revents == 0)
				continue;

			if (poll_fds[i].revents != POLLIN)
				fatal("Problems with socket poll. Got Event %d from poll().", poll_fds[i].revents);

			if ((new_client_fd = accept(poll_fds[i].fd, NULL, NULL)) >= 0) {

				if (proxy_master_validate_gateway_ip(new_client_fd, &client_ip)) {

					if (!flag_no_daemon) {

						embryonic_slot_id = proxy_master_new_embryonic_slot();

						proxy_master_update_proctitle();

						if (embryonic_slot_id > -1) {

							// New embryonic child;

							switch (child_pid = fork()) {
								case 0: { /* I am child */
									int fd;

									/* Remove the SIGCHLD handler inherited from parent. */
									proxy_sigaction(SIGCHLD, SIG_DFL, 0);

									/* Ignore SIGCONT used in master process */
									proxy_sigaction(SIGCONT, SIG_IGN, 0);

									/* Write down embryonic pipe id for later closing */
									proxy_session.embryonic_slot_id = embryonic_slot_id;

									/* Prevent child from killing monitor daemon */
									proxy_session.monitor_pid = -1;

									proxy_close_listen_sockets(poll_fds);

									if ((fd = open(_PATH_DEVNULL, O_RDWR, 0)) != -1) {
										dup2(fd, STDIN_FILENO);
										dup2(fd, STDOUT_FILENO);
										if (fd > STDERR_FILENO)
											close(fd);
									}

									init_proxy_log();

									/* Handle session */
									if (proxy_master_new_client(new_client_fd))
										exit(0);
									else
										exit(1);
								}

								case -1: {
									error("Failed to fork");
								}	break;

								default: { /* I am parent */
									close(new_client_fd);
									proxy_master_update_proctitle();
									log_system(LOG_LEVEL_INFO, "Forked child with pid %d", child_pid);
								}
							}
						} else {
							close(new_client_fd);
						}
					}
					else {
						/* Handle session */
						proxy_close_listen_sockets(poll_fds);

						if (proxy_master_new_client(new_client_fd))
							exit(0);
						else
							exit(1);
					}

				} else {
					close(new_client_fd);

					if (client_ip) {
						log_system(LOG_LEVEL_EMERG, "Denied connection from IP %s, since not listed in GatewayAddresses.", bdata(client_ip));
						bstrFree(client_ip);
						client_ip = NULL;
					} else {
						log_system(LOG_LEVEL_EMERG, "Connection attempt from unresolvable IP address denied.");
					}

				}

			} else {
				fatal("Accept failed.");
			}
		}
	}

	proxy_close_listen_sockets(poll_fds);
}

/*!
 * @brief       Create sockets, assign listen addresses and put them all in the given fd_set
 *
 * @param       pollfds
 */

static void
proxy_create_master_listen_fds(struct pollfd *pollfds) {
	struct addrinfo *ai;
	socket_t listen_sock;
	int on = 1;

	char ipstr[NI_MAXHOST], portstr[NI_MAXSERV];
	int rc;

	proxy_session.num_listen_socks = 0;

	for (ai = proxy_cfg.listen_addrs; ai; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;
		if (proxy_session.num_listen_socks >= SUSSHI_MAX_LISTEN_SOCKS)
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
			log_system(LOG_LEVEL_INFO, "Error creating Socket: %.100s", strerror(errno));
			continue;
		}

		proxy_set_blocking_mode(listen_sock, false);

		/* Set socket options */
		if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
			error("setsockopt SO_REUSEADDR: %s", strerror(errno));

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		if (ai->ai_family == AF_INET6)
			proxy_socket_set_v6only(listen_sock);

		/* Bind the socket to the desired port. */
		if (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) < 0) {
			error("Bind to port %s on %s failed: %.200s.",
				  portstr, ipstr, strerror(errno));
			close(listen_sock);
			continue;
		}

		switch(ai->ai_family) {
			case AF_INET6:
				proxy_session.host_has_ipv6 = true;
				break;
			case AF_INET:
				proxy_session.host_has_ipv4 = true;
		}

		proxy_session.listen_socks[proxy_session.num_listen_socks] = listen_sock;

		if (listen(listen_sock, SUSSHI_LISTEN_BACKLOG) < 0)
			fatal("Listen on [%s]:%s: %.100s", ipstr, portstr, strerror(errno));

		debug3("Listening on socket %d for new connections on %s port %s", listen_sock, ipstr, portstr);

		log_system(LOG_LEVEL_INFO, "Listening for new connections on %s port %s", ipstr, portstr);

		/* Add socket to fd_set */
		pollfds[proxy_session.num_listen_socks].fd = listen_sock;
		pollfds[proxy_session.num_listen_socks].events = POLLIN;

		proxy_session.num_listen_socks++;
	}
	freeaddrinfo(proxy_cfg.listen_addrs);
	proxy_cfg.listen_addrs = NULL;
}


/*!
 * @brief       Close listen sockets
 *
 * @param       pollfds
 */

static void
proxy_close_listen_sockets(struct pollfd *pollfds) {
	nfds_t i;

	for(i=0; i < proxy_session.num_listen_socks; i++) {
		close(pollfds[i].fd);
	}
	proxy_session.num_listen_socks = 0;
}


/*!
 * @brief       Update process proctitle with new process information
 */

static void
proxy_master_update_proctitle(void) {

	/* Update current embryonics */
	proxy_master_current_embryonics();

	SETPROCTITLE("Listening for new connections. (E:%d/S:%d/M:%d)",
				 current_embryonics, proxy_cfg.max_embryonics_start, proxy_cfg.max_embryonics);

	debug1("Listening for new connections. (E:%d/S:%d/M:%d)",
		   current_embryonics, proxy_cfg.max_embryonics_start, proxy_cfg.max_embryonics);
}


/*!
 * @brief       Handle connection from new client
 *
 * This is the entrance point after the master process has received a new connection and has forked.
 *
 * @param       client_fd       The socket the client has connected on
 * @return      true on success
 */

static bool
proxy_master_new_client(socket_t client_fd) {

	int SSH_false = 0;
	ssh_bind client_bind;
	long timeout;
	bool rc = false;

	if ((client_bind = ssh_bind_new()) != NULL) {

		/* Set Hostkeys to be loaded
		 *
		 * SSH_OPTIONS_HOSTKEYS is ignored by libssh/server implementation, so all Hostkey types given
		 * by list of Hostkey files are candidates (except ED25519, which is not working at least in version 0.7.5)
		 *
		 *  Client decides about algorithms and their preferred order
		 */
		for (int i = 0; i < proxy_cfg.num_host_key_files; i++) {
			debug3("Setting host_key %s", bdata(proxy_cfg.host_key_files[i]));
			ssh_bind_options_set(client_bind, SSH_BIND_OPTIONS_HOSTKEY, bdata(proxy_cfg.host_key_files[i]));
		}

		/* Set suSSHi BANNER */
		ssh_bind_options_set(client_bind, SSH_BIND_OPTIONS_BANNER, SUSSHI_SSH_VERSION_BANNER);

		if ((proxy_session.gateway_session = ssh_new()) != NULL) {

			/* Prevent libssh from reading system / user ssh_config on ssh_connect */
			ssh_options_set(proxy_session.gateway_session, SSH_OPTIONS_PROCESS_CONFIG, &SSH_false);

			if (ssh_bind_accept_fd(client_bind, proxy_session.gateway_session, client_fd) != SSH_ERROR) {

				proxy_session.gateway_phase = PHASE_CONNECTED;      // Client is connected

				/* Store Client IP and Port */
				store_client_socket_into_session(ssh_get_fd(proxy_session.gateway_session));

				log_system(LOG_LEVEL_INFO, "Received new connection from %s, port %d",
						   bdata(proxy_session.gateway_ip), proxy_session.gateway_port);

				SETPROCTITLE("New connection from %s, port %d",
							  bdata(proxy_session.gateway_ip), proxy_session.gateway_port);

				/* Switch on libssh verbosity based on debug level */
				proxy_libssh_set_verbosity(proxy_session.gateway_session);

				/* Perform / Validate Key Exchange */
				proxy_session.gateway_phase = PHASE_KEX;

				timeout = (long) proxy_cfg.embryonic_grace_time;
				ssh_options_set(proxy_session.gateway_session, SSH_OPTIONS_TIMEOUT, &timeout);

				if (ssh_handle_key_exchange(proxy_session.gateway_session) != SSH_OK) {
					log_system(LOG_LEVEL_INFO, "Client is not speaking our language: %s. Aborting", ssh_get_error(proxy_session.gateway_session));
					close(client_fd);
					exit(1);
				} else {

					/* Store Client banner */
					bstring gateway_ssh_identification = bfromcstr(ssh_get_clientbanner(proxy_session.gateway_session));
					debug2_dir(GATEWAY, PROXY, "Client (Gateway) Banner: %s", bdata(gateway_ssh_identification));

					if (strncmp(bdata(gateway_ssh_identification), SUSSHI_SSH_VERSION_PREFIX_FULL, strlen(SUSSHI_SSH_VERSION_PREFIX_FULL)) != 0) {
						log_system(LOG_LEVEL_INFO, "Connecting Client is not a suSSHi Gateway - Received banner %s. Aborting",  bdata(gateway_ssh_identification));
						close(client_fd);
						exit(1);
					} else {

						bstrFree (gateway_ssh_identification);

						/* Start Gateway (Client) Authentication */
						if (proxy_gateway_auth_start()) {

							/* On successful authentication we close the embryonic pipe to signal master that we are no longer embryonic */
							proxy_master_free_embryonic_slot(proxy_session.embryonic_slot_id);

							/* Connect to target */
							if (proxy_connect_target()) {

								/* Finish client auth successfully */
								proxy_gateway_auth_finish();

								/* Start THE loop */
								proxy_session_loop();

								rc = true;
							} else {
								ssh_auth_reply_default(proxy_session.gateway_session, 0);
							}
						}
					}
				}
				ssh_disconnect(proxy_session.gateway_session);
				ssh_free(proxy_session.gateway_session);
			} else {
				error("%s.", ssh_get_error(client_bind));
			}
		} else {
			error("Failed to allocate session.");
		}
	} else {
		error("Failed to allocate bind.");
	}

	proxy_cleanup();

	return rc;
}

#undef MY_BUFFER_LEN


/*!
 * @brief       Get remote IP (of gateway) and check if ip is in list of GatewayAddresses
 *
 * @param       socket      System socket
 * @param       client_ip   Client IP address
 *
 * @return      true on success
 */

static bool
proxy_master_validate_gateway_ip(socket_t socket, bstring *client_ip) {
	socklen_t socket_len;
	struct sockaddr_storage addr;
	char ipstr[INET6_ADDRSTRLEN];

	socket_len = sizeof addr;
	getpeername(socket, (struct sockaddr*)&addr, &socket_len);

	if (addr.ss_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)&addr;
		if (inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr) == NULL)
			return false;
	} else { // AF_INET6
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
		if (inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr) == NULL)
			return false;
	}

	*client_ip = bfromcstr(ipstr);

	if (proxy_cfg.num_gateway_addresses == 0)
		return true;

	for(int i=0; i < proxy_cfg.num_gateway_addresses; i++) {
		if (susshi_match_cidr(*client_ip, proxy_cfg.gateway_addresses[i])) {
			return true;
		}
	}

	return false;
}

/*! @} */
