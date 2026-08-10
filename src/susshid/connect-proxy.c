/*!
 *
 * @brief       Proxy Connection
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
 * @defgroup    connect_proxy Proxy Connection
 * @{
 */

#include <susshid/common.h>


/* Prototypes */
static  SSH_PACKET_CALLBACK(susshi_proxy_debug_message_callback);

static ssh_packet_callback debug_packet_callback_list[1] = {
		susshi_proxy_debug_message_callback };

static struct ssh_packet_callbacks_struct debug_packet_callbacks = {
		.start = SSH2_MSG_DEBUG,
		.n_callbacks = 1,
		.callbacks = debug_packet_callback_list,
		.user = NULL
};

static struct {
	struct addrinfo *proxy_addrs;
	int             num_proxy_ips;
	AddressInfo     proxy_ips[SUSSHI_MAX_TARGET_IPS];
	bstring         proxy_ips_list;
	bstring         proxy_ip;
} int_store = {
		.proxy_addrs = NULL,
		.num_proxy_ips = 0,
		.proxy_ips_list = NULL,
		.proxy_ip = NULL
};


static void store_proxy_ip_into_session(void);
static bool resolve_proxy_ips(void);
static int select_next_proxy_ip(void);

/*!
 * @brief       Callback function to retrieve information from Proxy via Debug Messages
 *
 * Proxy returns JSON blob to be parsed.
 *
 * @return      true if successful
 */

static
SSH_PACKET_CALLBACK(susshi_proxy_debug_message_callback){
	const char *message = NULL;
	int display;
	int language_tag_len;
	json_error_t json_error;
	size_t index;
	json_t *json_text = NULL, *json_element = NULL, *json_target_ips = NULL;
	const char *target_ip = NULL;

	if (type == SSH2_MSG_DEBUG) {

		if (ssh_buffer_get_len(susshi_session.target_proxy_session->in_buffer) > 0) {
			if (ssh_buffer_unpack(susshi_session.target_proxy_session->in_buffer, "bsd", &display, &message, &language_tag_len) == SSH_OK) {
				/* The message should contain a JSON blob */
				debug3("Received Data from Proxy: %s", message);

				// Decode response from Chef as JSON and store JSON for later use in other susshi_chef_* methods
				json_text = json_loads((char *) message, 0, &json_error);

				if (json_text) {
					json_unpack(json_text, "{s?o s?s s?i}",
								"target_ips", &json_target_ips,
								"target_ip", &target_ip,
								"error", &susshi_session.target_proxy_error);

					if (json_target_ips) {
						susshi_session.num_target_ips = 0;
						json_array_foreach(json_target_ips, index, json_element) {
							if (susshi_session.num_target_ips >= SUSSHI_MAX_TARGET_IPS)
								break;
							if (json_is_string(json_element)) {
								bstrList splitip = NULL;
								bstring  ip = NULL;
								ip = bfromcstr(json_string_value(json_element));
								splitip = bsplit(ip, '|');
								if (splitip->qty == 2) {
									const char *errstr;
									long long fam;
									susshi_session.target_ips[susshi_session.num_target_ips].ip = bstrcpy(splitip->entry[0]);
									fam = strtonum(bdata(splitip->entry[1]), 0, INT_MAX, &errstr);
									susshi_session.target_ips[susshi_session.num_target_ips].ai_family = errstr ? AF_UNSPEC : (int)fam;
									susshi_session.num_target_ips++;
								}
								bstrFree(ip);
								bstrListDestroy(splitip);
							}
						}
					}

					if (target_ip) {
						susshi_session.target_ip = bfromcstr(target_ip);
						store_target_identifier_into_session();
					}

				} else {
					log_system(LOG_LEVEL_CRIT, "Could not understand returned data from proxy.");
				}

			} else
				fatal("Error in unpacking debug message from proxy");
		}
	} else {
		fatal("Received wrong message type on debug packet callback.");
	}

	return SSH_PACKET_USED;
}


/*!
 * @brief       Proxy connect phase 1 - Connect to proxy, send unsigned public key(s) and receive target_ips via DEBUG message
 *
 * @return      true if successful
 */

bool
susshi_proxy_connect_phase1(void) {
	bool rc = false;
	time_t now;
	static int SSH_false = 0;
	static int SSH_true = 1;
	const char *proxy_server_banner;

	if (resolve_proxy_ips()) {

		do {
			if (select_next_proxy_ip() != -1) {
				susshi_session.target_proxy_phase = PHASE_NOT_CONNECTED;
				susshi_session.target_proxy_error = 0;

				debug1_dir(GATEWAY, TARGET, "Trying to connect to %s via suSSHi Proxy %s (%s:%d)",
						   bdata(susshi_session.target_host_resolved),
						   bdata(susshi_session.target_proxy_realm),
						   bdata(susshi_session.target_proxy_hostname),
						   susshi_session.target_proxy_port);

				if ((susshi_session.target_proxy_session = ssh_new()) != NULL) {

					debug1_dir(GATEWAY, TARGET, "Trying to connect to susshi-proxyd %s (%s:%d) on IP address %s.",
							   bdata(susshi_session.target_proxy_realm),
							   bdata(susshi_session.target_proxy_hostname),
							   susshi_session.target_proxy_port,
							   bdata(int_store.proxy_ip));

					/* At this moment we do not have max_session_idle from Chef (and we will never get it), so we have to set it fixed */

					if (susshi_session.operation_mode == OP_MODE_BASTION) {
						susshi_session.target_proxy_login_user = bformat("%s@bastion:%d@%d",
																		 bdata(susshi_session.susshi_uniqid),
																		 BASTION_LISTEN_PORT,
																		 4*60*60);
					} else {
						if (susshi_session.target_proxy_login_user == NULL) {
							susshi_session.target_proxy_login_user = bformat("%s@%s@%d",
																			 bdata(susshi_session.susshi_uniqid),
																			 bdata(susshi_session.target_host_orig),
																			 4*60*60);
						}
					}

					debug3("Proxy login user is %s", bdata(susshi_session.target_proxy_login_user));

					ssh_options_set(susshi_session.target_proxy_session, SSH_OPTIONS_HOST, bdata(int_store.proxy_ip));
					ssh_options_set(susshi_session.target_proxy_session, SSH_OPTIONS_PORT, &susshi_session.target_proxy_port);
					ssh_options_set(susshi_session.target_proxy_session, SSH_OPTIONS_TIMEOUT, &susshi_cfg.session.target_connection_timeout);
					ssh_options_set(susshi_session.target_proxy_session, SSH_OPTIONS_SSH2, &SSH_true);
					ssh_options_set(susshi_session.target_proxy_session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &SSH_true);
					ssh_options_set(susshi_session.target_proxy_session, SSH_OPTIONS_USER, bdata(susshi_session.target_proxy_login_user));
					ssh_options_set(susshi_session.target_proxy_session, SSH_OPTIONS_HOSTKEYS, DEFAULT_PREFERRED_HOST_KEY_ALGOS);

					/* Prevent libssh from reading system / user ssh_config on ssh_connect */
					ssh_options_set(susshi_session.target_proxy_session, SSH_OPTIONS_PROCESS_CONFIG, &SSH_false);

					/* Client banner we will send to target */
					susshi_session.target_proxy_session->clientbanner = strdup(SUSSHI_SSH_VERSION_BANNER_FULL);

					susshi_libssh_set_verbosity(susshi_session.target_proxy_session, PROXY);

					/* Register our callback function for debug messages where we receive the target IP, the proxy finally connected to */
					debug_packet_callbacks.user = susshi_session.target_proxy_session;
					ssh_packet_set_callbacks(susshi_session.target_proxy_session, &debug_packet_callbacks);

					/* Prevent from reading local OpenSSH configuration file -> This is not good in debugging :-) ! */
					susshi_session.target_proxy_session->opts.config_processed = true;

					now = time(NULL);

					if (ssh_connect(susshi_session.target_proxy_session) == SSH_OK) {
						susshi_session.target_proxy_phase = PHASE_KEX;
						debug2_dir(GATEWAY, PROXY, "Connected to proxy.");

						/* Store Remote IP Address */
						store_proxy_ip_into_session();

						/* Receive target banner and ensure this is a suSSHi Proxy */
						proxy_server_banner = ssh_get_serverbanner(susshi_session.target_proxy_session);

						if (proxy_server_banner) {
							const char *version_str, *version_str_end;

							if (strncmp(proxy_server_banner, SUSSHI_SSH_VERSION_PREFIX_FULL, strlen(SUSSHI_SSH_VERSION_PREFIX_FULL)) != 0) {
								log_system(LOG_LEVEL_EMERG, "Configured Proxy Server is not a suSSHi Proxy Server - Received banner %s. Aborting",
										   proxy_server_banner);

								if (susshi_session.operation_mode == OP_MODE_CHEF_REMOTE)
									return false;
								else
									susshi_disconnect_standard(CLIENT, DISCONNECT_PROTOCOLL_ERROR);
							}

							version_str = proxy_server_banner + strlen(SUSSHI_SSH_VERSION_PREFIX_FULL);
							version_str_end = strstr(version_str, " - suSSHi2 ");

							if (version_str_end > version_str) {

								susshi_session.proxy_version = bformat("%.*s", version_str_end - version_str, version_str);

								if (!susshi_parse_version_info(susshi_session.proxy_version, &susshi_session.proxy_version_uint32)) {
									log_system(LOG_LEVEL_EMERG, "Proxy returned malformed version string '%s'. Aborting.",
											   bdata(susshi_session.proxy_version));

									if (susshi_session.operation_mode == OP_MODE_CHEF_REMOTE)
										return false;
									else
										susshi_disconnect_standard(CLIENT, DISCONNECT_PROTOCOLL_ERROR);
								}

								debug1_dir(GATEWAY, PROXY, "Connected to proxy with version %s (%d).",
										   bdata(susshi_session.proxy_version), susshi_session.proxy_version_uint32);

								log_system(LOG_LEVEL_INFO, "Connected to proxy @%s (%s:%d) with version %s.",
										   bdata(susshi_session.target_proxy_realm), bdata(susshi_session.target_proxy_hostname),
										   susshi_session.target_proxy_port,
										   bdata(susshi_session.proxy_version));

								if ((susshi_session.operation_mode == OP_MODE_BASTION) && (susshi_session.proxy_version_uint32 < 200300)) {
									log_system(LOG_LEVEL_EMERG, "The proxy server runs on version %s, which does not support the suSSHi Bastion feature yet. "
																"Please contact the administrator of the suSSHi proxy server to update it to a newer version.",
											   bdata(susshi_session.proxy_version));
									susshi_disconnect_standard(CLIENT, DISCONNECT_TARGET_PROXY_BASTION_VERSION);
								}
							}

						} else {
							log_system(LOG_LEVEL_EMERG, "Configured Proxy Server does not respond with a SSH server banner - seems we are not connected to a suSSHi Proxy. Giving up.");
							susshi_disconnect_standard(CLIENT, DISCONNECT_PROTOCOLL_ERROR);
						}

						susshi_session.target_proxy_phase = PHASE_CONNECTED;

						// Verify received host key
						if (susshi_proxy_verify_hostkey() == KEY_OK) {

							if (susshi_proxy_auth_phase1()) {
								/* We are connected to proxy and have received some information about target_ips */
								susshi_session.target_proxy_phase = PHASE_AUTH_PUBKEY_TEST_OK;
								return true;
							} else {
								debug1_dir(PROXY, GATEWAY, "Proxy authentication failed with %s", ssh_get_error(susshi_session.target_proxy_session));
								log_session(TARGET, GATEWAY, "could not authenticate at proxy - unknown error. The proxy may not be configured correctly.");
								susshi_report.message =  bfromcstr("Proxy is not working as expected. The proxy may not be configured correctly.");
								susshi_disconnect_standard(CLIENT, DISCONNECT_TARGET_PROXY_LOGIN_FAILED);
							}

						} else {
							log_session(TARGET, GATEWAY, "Proxy host key could not be verified. Aborting.");
							log_system(LOG_LEVEL_CRIT, "Proxy host key could not be verified. Aborting.");

							if (susshi_session.operation_mode == OP_MODE_CHEF_REMOTE)
								return false;
							else
								susshi_disconnect_standard(CLIENT, DISCONNECT_PROTOCOLL_ERROR);
						}

					} else {
						time_t delta;
						delta = time(NULL) - now;

						susshi_report.message = bformat("Proxy connection failed after %ld seconds: %s.", delta,
														ssh_get_error(susshi_session.target_proxy_session));
						error("Proxy connection failed after %ld seconds: %s.", delta,
							  ssh_get_error(susshi_session.target_proxy_session));
					}
				} else {
					fatal("Failed to allocate target proxy session");
				}

			}
			else {
				return false;
			}
		} while (!rc);
	}

	return false;
}


/*!
 * @brief       Proxy connect phase 2 - Send signed key to proxy and receive target_ip via DEBUG message
 *
 * @return      true if successful
 */

bool
susshi_proxy_connect_phase2(void) {

	if (susshi_session.target_proxy_phase == PHASE_AUTH_PUBKEY_TEST_OK) {

		/* Register our callback function for debug messages where we receive the target IP, the proxy has finally connected to */
		debug_packet_callbacks.user = susshi_session.target_proxy_session;
		ssh_packet_set_callbacks(susshi_session.target_proxy_session, &debug_packet_callbacks);

		if (susshi_proxy_auth_phase2()) {
			susshi_session.target_proxy_phase = PHASE_AUTHENTICATED;
			/* We are logged in and ready for THE loop */
			return true;
		} else {
			if (susshi_session.operation_mode != OP_MODE_CHEF_REMOTE) {
				switch(susshi_session.target_proxy_error) {
					case 0:
						log_session(TARGET, GATEWAY, "Could not authenticate to proxy - signed key was not accepted.");
						susshi_disconnect_standard(CLIENT, DISCONNECT_PROTOCOLL_ERROR);
						break;
					case SUSSHI_PROXY_ERROR_CODE_TARGET_CONNECT_FAILED:
						if (susshi_session.operation_mode == OP_MODE_BASTION) {
							debug1_dir(PROXY, GATEWAY, "Proxy failed to run bastion mode.");
							susshi_report.message = bfromcstr("Proxy failed to run bastion mode.");
							susshi_disconnect_standard(BOTH, DISCONNECT_TARGET_PROXY_BASTION_FAILED);
						} else {
							debug1_dir(PROXY, GATEWAY, "Proxy could not connect to target.");
							susshi_report.message = bfromcstr("Proxy could not connect to target.");
							susshi_disconnect_standard(BOTH, DISCONNECT_TARGET_CONNECT_FAILED);
						}
						break;
					default:
						debug1_dir(PROXY, GATEWAY, "Unknown error returned from proxy.");
						susshi_report.message = bfromcstr("Unknown error returned from proxy.");
						susshi_disconnect_standard(BOTH, DISCONNECT_PROTOCOLL_ERROR);
						break;
				}
			} else {
				ssh_disconnect(susshi_session.target_proxy_session);
			}
		}
	}

	return false;
}


/*!
 * @brief       Verify proxy host key
 *
 * @return      KeyVerifyResponse
 */

KeyVerifyResponse
susshi_proxy_verify_hostkey(void) {

	/* Compare hostkeys with our own hostkeys since we use the same here */

	KeyVerifyResponse resp = KEY_ERROR;
	ssh_key proxy_pubkey;
	const char *dishash = NULL;
	enum ssh_keytypes_e keytype;
	bstring pub_path;
	ssh_key key_from_file;
	int i;

	if (ssh_get_server_publickey(susshi_session.target_proxy_session, &proxy_pubkey) == SSH_OK) {

		/* We received the public key */
		if_debug2() {
			do_debug2_dir(TARGET, GATEWAY, "Received Hostkey of type %s with hash '%s' from target.",
					   susshi_ssh_key_type_to_char(proxy_pubkey), dishash = susshi_display_hash_from_key(proxy_pubkey));
			if (dishash)
				xfree((void *) dishash);
		}

		keytype = ssh_key_type(proxy_pubkey);

		if (keytype != SSH_KEYTYPE_UNKNOWN) {

			for (i = 0; (i < susshi_cfg.num_host_key_files) && (resp != KEY_OK); i++) {
				pub_path = bformat("%s.pub", bdata(susshi_cfg.host_key_files[i]));
				if (ssh_pki_import_pubkey_file(bdata(pub_path), &key_from_file) == SSH_OK) {
					if (ssh_key_cmp(key_from_file, proxy_pubkey, SSH_KEY_CMP_PUBLIC) == 0) {
						resp = KEY_OK;
					}
					SSH_KEY_FREE(key_from_file);
				}
				bstrFree(pub_path);
			}
		}
		xfree(proxy_pubkey);
	}

	return resp;
}


/*!
 * @brief       Store IP of Proxy we are connected to into susshi_session
 *
 */

static void
store_proxy_ip_into_session(void) {
	socklen_t socket_len;
	struct sockaddr_storage addr;
	char ipstr[INET6_ADDRSTRLEN];
	// int port;

	socket_len = sizeof addr;
	if (getpeername(ssh_get_fd(susshi_session.target_proxy_session), (struct sockaddr*)&addr, &socket_len) == 0) {

		if (addr.ss_family == AF_INET) {
			struct sockaddr_in *s = (struct sockaddr_in *)&addr;
			// port = ntohs(s->sin_port);
			inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
		} else { // AF_INET6
			struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
			// port = ntohs(s->sin6_port);
			inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
		}

		susshi_session.target_proxy_ip = bfromcstr(ipstr);
	}

}


/*!
 * @brief       Resolve target addresses
 *
 * Resolve target addresses (from hostname filled in by store_splitted_loginstring_into_session())
 * and store them together with other target information in susshi_session
 *
 * @return      true if successful
 */

static bool
resolve_proxy_ips(void)
{
	bool rc = false;
	struct addrinfo hints_name, hints_ip, *ai;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV];
	int gai_error;

	memset(&hints_ip, 0, sizeof(hints_ip));
	hints_ip.ai_family = AF_UNSPEC;
	hints_ip.ai_socktype = SOCK_STREAM;
	hints_ip.ai_protocol = IPPROTO_TCP;
	hints_ip.ai_flags = AI_ADDRCONFIG | AI_NUMERICHOST;

	memset(&hints_name, 0, sizeof(hints_name));
	hints_name.ai_family = AF_UNSPEC;
	hints_name.ai_socktype = SOCK_STREAM;
	hints_name.ai_protocol = IPPROTO_TCP;
	hints_name.ai_flags = AI_ADDRCONFIG | AI_V4MAPPED | AI_ALL;

	snprintf(strport, sizeof strport, "%u", susshi_session.target_port);

	debug1("Trying to resolve given proxy address into an IP address.");

	if ((gai_error = getaddrinfo(bdata(susshi_session.target_proxy_hostname), strport, &hints_ip, &int_store.proxy_addrs)) == 0) {
		debug3("Given proxy name is an IP address already.");
	} else {
		hints_name.ai_flags |= AI_CANONNAME;
		if ((getaddrinfo(bdata(susshi_session.target_proxy_hostname), strport, &hints_name, &int_store.proxy_addrs)) == 0) {
			debug3("Found proxy hostname with standard system DNS config.");
		}
	}

	if (int_store.proxy_addrs != NULL) {

		/* Loop through addrinfo list and store all IP addresses */
		for (ai = int_store.proxy_addrs; (ai) && (int_store.num_proxy_ips < SUSSHI_MAX_TARGET_IPS); ai = ai->ai_next) {

			if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
				continue;

			/* Skip IPv4 addresses if host has no IPv4 interface */
			if (ai->ai_family == AF_INET && !susshi_session.host_has_ipv4) {
				debug2("DNS IPv4 response skipped since gateway has no IPv4 address.");
				rc = false;
				continue;
			}

			/* Skip IPv6 addresses if host has no IPv6 interface */
			if (ai->ai_family == AF_INET6 && !susshi_session.host_has_ipv6) {
				debug2("DNS IPv6 response skipped since gateway has no IPv6 address.");
				rc = false;
				continue;
			}

			if (getnameinfo(ai->ai_addr, ai->ai_addrlen,
							ntop, sizeof(ntop), strport, sizeof(strport),
							NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
				error("ssh_connect: getnameinfo failed");
				continue;
			}

			int_store.proxy_ips[int_store.num_proxy_ips].ip = bfromcstr(ntop);

			int_store.proxy_ips[int_store.num_proxy_ips].ai_family = ai->ai_family;

			debug2("Resolved %s to %s.", bdata(susshi_session.target_proxy_hostname),
				   bdata(int_store.proxy_ips[int_store.num_proxy_ips].ip));

			if (int_store.num_proxy_ips == 0) {
				int_store.proxy_ips_list = bfromcstr("");
			} else {
				bcatcstr(int_store.proxy_ips_list, ", ");
			}

			bconcat(int_store.proxy_ips_list, int_store.proxy_ips[int_store.num_proxy_ips].ip);

			rc = true;
			int_store.num_proxy_ips++;
		}
	} else {
		rc = false;
	}

	if (int_store.num_proxy_ips == SUSSHI_MAX_TARGET_IPS) {
		error("Warning! More than %d IPs for proxy '%s' found. Only using the first %d ones.",
			  SUSSHI_MAX_TARGET_IPS, bdata(susshi_session.target_proxy_hostname), SUSSHI_MAX_TARGET_IPS);
	}

	if (int_store.proxy_addrs != NULL)
		freeaddrinfo(int_store.proxy_addrs);

	if (rc == false) {
		log_system(LOG_LEVEL_INFO, "Proxy '%s' could not be resolved.", bdata(susshi_session.target_proxy_hostname));
	} else {
		if (int_store.proxy_ips_list) {
			log_system(LOG_LEVEL_INFO, "Proxy '%s' resolved to: %s", bdata(susshi_session.target_proxy_hostname), bdata(int_store.proxy_ips_list));
		}
	}

	return rc;
}


/*!
 * @brief       Select next Proxy IP in list
 *
 * @return      index number or -1 if no more address is found
 */

static int
select_next_proxy_ip(void) {
	int i;

	/* Lookup preferred AFI first */
	for(i=0; (i < int_store.num_proxy_ips); i++) {
		if (int_store.proxy_ips[i].ai_family != susshi_cfg.session.target_preferred_address_family)
			continue;
		if (int_store.proxy_ips[i].used)
			continue;
		int_store.proxy_ips[i].used = true;

		int_store.proxy_ip = int_store.proxy_ips[i].ip;

		return i;
	}

	/* Lookup in remaining IPs */
	for(i=0; i < int_store.num_proxy_ips; i++) {
		if (int_store.proxy_ips[i].used)
			continue;
		int_store.proxy_ips[i].used = true;

		int_store.proxy_ip = int_store.proxy_ips[i].ip;

		return i;
	}

	return -1;
}

/*! @} */
