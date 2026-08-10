/*!
 *
 * @brief       suSSHi Proxy Configuration
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
 * @defgroup    proxy_cfg Susshi Proxy Configuration
 * @brief       Functions for configuration initialization and parsing.
 * @{
 *
 */

#include <susshi-proxyd/common.h>


SusshiProxyCfg proxy_cfg;

/* Prototypes */
static const char *proxy_cfg_lookup_opcode_name(SusshiCfgOpCodes code);
static char *proxy_cfg_derelativise_path(const char *path);

static void proxy_cfg_parse_af(json_t *value, int *intptr, const char *section);
static void proxy_cfg_parse_int(json_t *value, int *intptr, const char *section);
static void proxy_cfg_parse_path(json_t *value, bstring *pathptr, int *countptr, const char *section);
static void proxy_cfg_parse_bstring(json_t *value, bstring *bstrptr, int *countptr, const char *section);
static void proxy_cfg_add_one_listen_addr(char *addr, int port);

static void proxy_cfg_dump_cfg_bstrarray(SusshiCfgOpCodes code, int count, bstring *vals);
static void proxy_cfg_dump_cfg_int(SusshiCfgOpCodes code, int val);
static void proxy_cfg_dump_cfg_string(SusshiCfgOpCodes code, const char *val);


/*!
 * @brief       Mapping Table for tokens
 */

static struct {
	const char *name;
	SusshiCfgOpCodes opcode;
} keywords[] = {
		/* Standard Options in Order they have to be parsed (if in any relationship) */
		{"ListenAddresses",                sListenAddresses,             },
		{"ListenPorts",                    sListenPorts,                 },
		{"EmbryonicGraceTime",             sEmbryonicGraceTime,          },
		{"GatewayAddresses",               sGatewayAddresses,            },
		{"GatewayIdentityKeys",            sGatewayIdentityKeys,         },
		{"InstallationId",                 sInstallationId,              },
		{"MaxEmbryonics",                  sMaxEmbryonics,               },
		{"PidFile",                        sPidFile,                     },
		{"TargetPreferredAddressFamily",   sTargetPreferredAddressFamily },
		{"Version",                        sConfigVersion,               },
		{"HostKeys",                       sHostKeys,                    },
		{NULL,                             _sBadOption,                  }
};


/*!
 * Init proxy_cfg structure
 *
 * @ingroup proxy_cfg
 */

void
proxy_cfg_init(void) {
	memset(&proxy_cfg, 0, sizeof(proxy_cfg));

	proxy_cfg.address_family = -1;

	proxy_cfg.log_level = LOG_LEVEL_NOT_SET;

	proxy_cfg.target_connection_timeout = -1;

	proxy_cfg.max_embryonics = -1;
	proxy_cfg.embryonic_grace_time = -1;
}


/*!
 * @brief       Free proxy_cfg allocated memory (strings etc.)
 */

void
proxy_cfg_free(void) {

	if (proxy_cfg.pid_file)
		bstrFree(proxy_cfg.pid_file);

	if (proxy_cfg.config_path)
		bstrFree(proxy_cfg.config_path);

	for (int i = 0; i < MAX_HOSTKEYS; i++)
		if (proxy_cfg.host_key_files[i])
			bstrFree(proxy_cfg.host_key_files[i]);

	for (int i = 0; i < MAX_USERKEYS; i++) {
		if (proxy_cfg.gateway_identities[i].public_blob)
			bstrFree(proxy_cfg.gateway_identities[i].public_blob);
		if (proxy_cfg.gateway_identities[i].private_blob)
			bstrFree(proxy_cfg.gateway_identities[i].private_blob);
		if (proxy_cfg.gateway_identities[i].key_type)
			bstrFree(proxy_cfg.gateway_identities[i].key_type);
		if (proxy_cfg.gateway_identities[i].fingerprint)
			bstrFree(proxy_cfg.gateway_identities[i].fingerprint);
	}

	for (int i = 0; i < MAX_GATEWAY_ADDRESSES; i++)
		if (proxy_cfg.gateway_addresses[i])
			bstrFree(proxy_cfg.gateway_addresses[i]);

}


/*!
 * @brief       Fill proxy_cfg with defaults after having it filled with global config values from configuration file
 *
 * @param       sic_init   true if called for sic_init
 */

void
proxy_cfg_fill_defaults(bool sic_init) {

	if (proxy_cfg.susshid_id == NULL)
		proxy_cfg.susshid_id = bfromcstr("XXXX");

	if (proxy_cfg.address_family == -1)
		proxy_cfg.address_family = AF_UNSPEC;

	if (proxy_cfg.log_level == LOG_LEVEL_NOT_SET)
		proxy_cfg.log_level = LOG_LEVEL_INFO;

	if (proxy_cfg.pid_file == NULL)
		proxy_cfg.pid_file = bfromcstr((char *) PATH_SUSSHI_PROXYD_DAEMON_PID_FILE);

	if (proxy_cfg.target_connection_timeout == -1)
		proxy_cfg.target_connection_timeout = 3;

	if (proxy_cfg.target_preferred_address_family == -1)
		proxy_cfg.target_preferred_address_family = AF_UNSPEC;

	if (proxy_cfg.max_embryonics == -1) {
		proxy_cfg.max_embryonics_start = 30;
		proxy_cfg.max_embryonics_rate = 10;
		proxy_cfg.max_embryonics = 100;
	}

	if (proxy_cfg.embryonic_grace_time == -1) {
		proxy_cfg.embryonic_grace_time = 10;
	}

	if (proxy_cfg.health_monitor_port == 0) {
		proxy_cfg.health_monitor_port = MONITOR_PORT;
	}
}


/*!
 * @brief       Parse Addressfamily and store in integer
 *
 * @param       value
 * @param       intptr
 * @param       section
 */

static void
proxy_cfg_parse_af(json_t *value, int *intptr, const char *section) {

	const char *string;
	int intvalue;

	if (json_is_string(value)) {
		string = json_string_value(value);
		if (strcasecmp(string, "ipv4") == 0) {
			intvalue = AF_INET;
		} else if (strcasecmp(string, "ipv6") == 0) {
			intvalue = AF_INET6;
		} else if (strcasecmp(string, "any") == 0) {
			intvalue = AF_UNSPEC;
		} else {
			fatal("%s: Unsupported address family", section);
		}
		if (*intptr == -1)
			*intptr = intvalue;
	} else {
		fatal("%s: Please specify either ipv4, ipv6 or any", section);
	}
}


/*!
 * @brief       Parse Integer
 *
 * @param       value
 * @param       intptr
 * @param       section
 */

static void
proxy_cfg_parse_int(json_t *value, int *intptr, const char *section) {

	if (json_is_number(value)) {
		*intptr = (int) json_integer_value(value);
	} else {
		fatal("%s: expected integer", section);
	}
}



/*!
 * @brief       Parse and derelativise (file)path and store in bstring
 *
 * @param       value
 * @param       pathptr
 * @param       countptr
 * @param       section
 */

static void
proxy_cfg_parse_path(json_t *value, bstring *pathptr, int *countptr, const char *section) {

	if (json_is_string(value)) {
		*pathptr = bfromcstr(proxy_cfg_derelativise_path(json_string_value(value)));
		if (countptr != NULL)
			*countptr = *countptr + 1;
	} else {
		fatal("%s: expected path", section);
	}
}


/*!
 * @brief       Parse String and store into bstring
 *
 * @param       value
 * @param       bstrptr
 * @param       countptr
 * @param       section
 */

static void
proxy_cfg_parse_bstring(json_t *value, bstring *bstrptr, int *countptr, const char *section) {

	if (json_is_string(value)) {
		*bstrptr = bfromcstr(json_string_value(value));
		if (countptr != NULL)
			*countptr = *countptr + 1;
	} else {
		fatal("%s: expected string value", section);
	}
}


/*!
 * @brief       Parse SSH Key Hash in Syntax of HostKeys and TargetIdentityKeys
 *
 * @param       element
 * @param       fp_ptr
 * @param       type_ptr
 * @param       pub_ptr
 * @param       priv_ptr
 * @param       section
 *
 * @return      true on success
 */

bool
proxy_cfg_parse_ssh_key(json_t *element, const char **type_ptr, const char **fp_ptr, const char **pub_ptr,
						 const char **priv_ptr, const char *section) {

	int ret;
	if (json_is_object(element)) {

		ret = json_unpack(element, "{s:s s:s s?s s?s}",
						  "key_type", type_ptr,
						  "fingerprint", fp_ptr,
						  "public_blob", pub_ptr,
						  "key_blob", priv_ptr);

		if (ret == 0)
			return true;
	} else {
		fatal("%s: expect hash with ssh-key data", section);
	}
	return false;
}


/*!
 * @brief       Read config from JSON object in current context
 *
 * @param       object      JSON object

* @return       true on success
 */

bool
proxy_cfg_read_json(json_t *object) {

	const char *key;
	json_t *value;

	u_int i;
	size_t index;
	json_t *element;
	const char *string;

	for (i = 0; keywords[i].name; i++) {

		key = keywords[i].name;
		value = json_object_get(object, key);

		if (value) {

			switch(keywords[i].opcode) {

				case sConfigVersion: {
					proxy_cfg_parse_int(value, &proxy_cfg.config_version, "\"Configuration/Version");
				} break;

				case sEmbryonicGraceTime: {
					proxy_cfg_parse_int(value, &proxy_cfg.embryonic_grace_time, "Configuration/EmbryonicGraceTime");
				} break;

				case sMaxEmbryonics: {
					bstring embryonics = NULL;
					proxy_cfg_parse_bstring(value, &embryonics, NULL, "Configuration/MaxEmbryonics");

					if (embryonics) {
						if ((sscanf(bdata(embryonics), "%d:%d:%d",
										&proxy_cfg.max_embryonics_start,
										&proxy_cfg.max_embryonics_rate,
										&proxy_cfg.max_embryonics)) == 3) {

							if (proxy_cfg.max_embryonics > 200)
								fatal("Configuration/MaxEmbryonics: Embryonics-Max exceeded (> 200)");
							if (proxy_cfg.max_embryonics_start > proxy_cfg.max_embryonics)
								fatal("Configuration/MaxEmbryonics: Embryonics-Start > Embryonics-MAx");
							if ((proxy_cfg.max_embryonics_rate > 100) || (proxy_cfg.max_embryonics_rate < 1))
								fatal("Configuration/MaxEmbryonics: Embryonics-Rate out of boundaries (1-100)");
						} else {
							fatal("Configuration/MaxEmbryonics: Wrong syntax, please specifiy 'Start:Rate:Max'");
						}
						bstrFree(embryonics);
					}
				} break;

				case sGatewayIdentityKeys: {
					const char *type_ptr = NULL, *fp_ptr = NULL, *pub_ptr = NULL, *priv_ptr = NULL;

					json_array_foreach(value, index, element) {
						if (index == MAX_USERKEYS)
							fatal("Configuration/GatewayIdentityKeys: Maximal number of gateway-keys (%d) exceeded", MAX_USERKEYS);

						if (proxy_cfg_parse_ssh_key(element, &type_ptr, &fp_ptr, &pub_ptr, &priv_ptr,
													 "Configuration/GatewayIdentityKeys") == true) {

							proxy_cfg.gateway_identities[index].key_type = bfromcstr(type_ptr);
							proxy_cfg.gateway_identities[index].fingerprint = bfromcstr(fp_ptr);
							proxy_cfg.gateway_identities[index].public_blob = bfromcstr(pub_ptr);
							proxy_cfg.num_gateway_identities++;
						} else {
							fatal("Configuration/GatewayIdentityKeys: Could not parse ssh-key hash");
						}
					}
				} break;

				case sGatewayAddresses: {

					json_array_foreach(value, index, element) {
						proxy_cfg_parse_bstring(element, &proxy_cfg.gateway_addresses[index], &proxy_cfg.num_gateway_addresses, "Configuration/GatewayAddresses");
					}
				} break;

				case sHostKeys: {
					const char *type_ptr, *fp_ptr, *pub_ptr, *priv_ptr;
					bstring pub_path = NULL;
					FILE *fp_pub;
					ssh_key ssh_key;
					int rc;
					int remove_rc = 0;

					json_array_foreach(value, index, element) {
						if (index == MAX_HOSTKEYS)
							fatal("Configuration/HostKeys: Maximal number of Hostkeys (%d) exceeded", MAX_HOSTKEYS);

						if (proxy_cfg_parse_ssh_key(element, &type_ptr, &fp_ptr, &pub_ptr, &priv_ptr,
													"Configuration/HostKeys") == true) {

							debug3("Got HostKey from Configfile: %s %s ", type_ptr, fp_ptr);
							proxy_cfg.host_key_files[index] = bformat(
									PATH_SUSSHI_PROXYD_KEYS PREFIX_SUSSHI_PROXYD_HOSTKEYS "%d", index);

							rc = ssh_pki_import_privkey_base64(priv_ptr, NULL, NULL, NULL,
															   &ssh_key);

							if ((rc == SSH_OK) && (ssh_key_is_private(ssh_key) == 1)) {

								pub_path = bformat("%s.pub", bdata(proxy_cfg.host_key_files[index]));
								fp_pub = fopen(bdata(pub_path), "w");

								if (fp_pub) {

									debug3("Saving to file %s and <file>.pub", bdata(proxy_cfg.host_key_files[index]));

									/* Private Key file */
									ssh_pki_export_privkey_file(ssh_key, NULL, NULL, NULL,
																bdata(proxy_cfg.host_key_files[index]));
									chmod(bdata(proxy_cfg.host_key_files[index]), S_IRUSR|S_IWUSR);

									/* Public Key file */
									ssh_pki_export_pubkey_file(ssh_key, bdata(pub_path));
									chmod(bdata(pub_path), S_IRUSR|S_IWUSR|S_IRGRP);

									bstrFree(pub_path);
									proxy_cfg.num_host_key_files++;

								} else {
									fatal("Configuration/HostKeys: Could not write key to (cache) file %s",
										  bdata(proxy_cfg.host_key_files[index]));
								}
							} else {
								fatal("Private Hostkey is not generated by suSSHi Chef. Aborting.");
							}
						} else {
							fatal("Configuration/HostKeys: Could not parse ssh-key hash");
						}
					}

					// Unlink old files if there are any
					for(u_int n = (u_int) proxy_cfg.num_host_key_files; (n < MAX_HOSTKEYS) && (remove_rc != -1); n++) {
						bstring path = bformat(PATH_SUSSHI_PROXYD_KEYS "/" PREFIX_SUSSHI_PROXYD_HOSTKEYS "%d", n );
						remove(bdata(path));
						bformata(path, ".pub");
						remove_rc = remove(bdata(path));
						if (remove_rc != -1)
							debug3("Removed old host key file with ID %d", n);
						bstrFree(path);
					}

				} break;

				case sInstallationId: {
					proxy_cfg_parse_bstring(value, &proxy_cfg.installation_id, NULL, "Configuration/InstallationId");
				} break;

				case sListenAddresses: {

					json_array_foreach(value, index, element) {
						char *p;
						int port;

						string = json_string_value(element);

						if (string == NULL)
							fatal("Configuration/ListenAddresses: No address given.");

						/* check for bare IPv6 address: no "[]" and 2 or more ":" */
						if (strchr(string, '[') == NULL && (p = (char *) strchr(string, ':')) != NULL
							&& strchr(p + 1, ':') != NULL) {
							proxy_cfg_add_listen_addr((char *) string, 0);
							break;
						}

						p = host_port_delimiter((char **) &string);

						if (p == NULL)
							fatal("Configuration/ListenAddresses: bad address:port usage.");

						p = cleanhostname(p);
						if (string == NULL)
							port = 0;
						else if ((port = a2port(string)) <= 0)
							fatal("Configuration/ListenAddresses: bad port number.");

						proxy_cfg_add_listen_addr(p, port);
					}
				} break;

				case sListenPorts: {
					int port = 0;

					// We already have port configurations, so we will not overwrite with new configuration  (e.g. with answer from chef)
					if (proxy_cfg.num_ports > 0)
						continue;

					/* ignore ports from configfile if cmdline specifies ports */
					if (proxy_cfg.ports_from_cmdline)
						return 0;

					if (proxy_cfg.listen_addrs != NULL)
						fatal("Configuration/ListenPorts: Ports must be specified before ListenAddresses.");

					json_array_foreach(value, index, element) {
						if (index == MAX_PORTS)
							fatal("Configuration/ListenPorts: Maximal number of Ports (%d) exceeded", MAX_PORTS);

						proxy_cfg_parse_int(element, &port, "\"Configuration/ListenPorts");

						if ((port > 21) && (port < 65535)) {
							proxy_cfg.ports[index] = port;
							proxy_cfg.num_ports++;
						} else {
							fatal("Configuration/ListenPorts: Could not read port (is integer?)");
						}
					}
				} break;

				case sPidFile: {
					proxy_cfg_parse_path(value, &proxy_cfg.pid_file, NULL, "Configuration/PidFile");
				} break;

				case sTargetPreferredAddressFamily: {
					proxy_cfg_parse_af(value, &proxy_cfg.target_preferred_address_family, "Configuration/TargetPreferredAddressFamily");
				} break;

				case _sBadOption:
				default: {
					debug3("Configuration: Unknown key %s", key);
				}
			}
		}
	}

	return true;
}



static const char *config_file_locations[] = {
		SUSSHI_PROXYD_CONFIG_FILE1, SUSSHI_PROXYD_CONFIG_FILE2, SUSSHI_PROXYD_CONFIG_FILE3,
		NULL
};

/*!
 * @brief       Load and parse susshid configuration file
 *
 * @param       filename
 *
 * @return      true on success
 */

bool
proxy_cfg_load_configfile(const char *filename) {
	const char *files[2];
	const char **filenames;
	json_t *document;
	json_error_t json_error;

	if (filename) {
		files[0] = filename;
		files[1] = NULL;
		filenames = files;
	} else {
		filenames = config_file_locations;
	}

	for (int f = 0; filenames[f]; f++) {
		document = json_load_file(filenames[f], 0, &json_error);

		if (document) {
			char path[PATH_MAX];
			// Under Linux dirname() writes to argument !!! So we make a copy of argument first
			if (strlcpy(path, filenames[f], sizeof(path)) >= sizeof(path))
				fatal("Configuration file path too long: %s", filenames[f]);
			proxy_cfg.config_path = bfromcstr(proxy_cfg_derelativise_path(dirname(path)));
			return proxy_cfg_read_json(document);
		}
	}

	fatal("No configuration file found!\n\n"
		  "Please provide a configuration file at one of these locations:\n\n"
		  "    " SUSSHI_PROXYD_CONFIG_FILE1 "\n"
		  "    " SUSSHI_PROXYD_CONFIG_FILE2 "\n"
		  "    " SUSSHI_PROXYD_CONFIG_FILE3 "\n\n"
		  "... or specify the path of an configuration file with -f,\n"
		  "... or add the environment variable PROXY_CONFIG to your container configuration,\n"
		  "    which contains the configuration file as a Base64 encoded string.\n"
	);

	return false;
}


/*!
 * @brief       Lookup function used by proxy_cfg_dump_* methods
 *
 * @param       code
 *
 * @return      ConfigKey from given Opcode
 */

static const char *
proxy_cfg_lookup_opcode_name(SusshiCfgOpCodes code) {
	u_int i;

	for (i = 0; keywords[i].name != NULL; i++)
		if (keywords[i].opcode == code)
			return (keywords[i].name);
	return "UNKNOWN";
}


/*!
 * @brief       Derelativise file path
 *
 * @param       path
 *
 * @return      derelativated file path
 */

static char *
proxy_cfg_derelativise_path(const char *path) {
	char *expanded, *ret, cwd[MAXPATHLEN];

	expanded = tilde_expand_filename(path, getuid());
	if (*expanded == '/')
		return expanded;
	if (getcwd(cwd, sizeof(cwd)) == NULL)
		fatal("%s: getcwd: %s", __func__, strerror(errno));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	xfree(expanded);
	return ret;
}


/*!
 * @brief       Add one listen address to configuration
 *
 * @param       addr
 * @param       port
 */

static void
proxy_cfg_add_one_listen_addr(char *addr, int port) {
	struct addrinfo hints, *ai, *aitop;
	char strport[NI_MAXSERV];
	int gaierr;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = proxy_cfg.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == NULL) ? AI_PASSIVE : 0;
	snprintf(strport, sizeof strport, "%d", port);
	if ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)", addr ? addr : "<NULL>", gai_strerror(gaierr));
	for (ai = aitop; ai->ai_next; ai = ai->ai_next);
	ai->ai_next = proxy_cfg.listen_addrs;
	proxy_cfg.listen_addrs = aitop;
}


/*!
 * @brief       For each listen port, add a listen address to configuration
 *
 * @param       addr
 * @param       port
 */

void
proxy_cfg_add_listen_addr(char *addr, int port) {
	u_int i;

	if (proxy_cfg.num_ports == 0)
		proxy_cfg.ports[proxy_cfg.num_ports++] = SSH_DEFAULT_PORT;
	if (proxy_cfg.address_family == -1)
		proxy_cfg.address_family = AF_UNSPEC;
	if (port == 0)
		/* Listen address without port --> add address for all ports in configuration */
		for (i = 0; i < proxy_cfg.num_ports; i++)
			proxy_cfg_add_one_listen_addr(addr, proxy_cfg.ports[i]);
	else
		/* Specific listen address with port */
		proxy_cfg_add_one_listen_addr(addr, port);
}


/*!
 * @brief       Dump configuration value of type Integer
 *
 * @param       code
 * @param       val
 */

static void
proxy_cfg_dump_cfg_int(SusshiCfgOpCodes code, int val) {
	debug3("Config %s: %d", proxy_cfg_lookup_opcode_name(code), val);
}


/*!
 * @brief       Dump configuration value of type String
 *
 * @param       code
 * @param       val
 */

static void
proxy_cfg_dump_cfg_string(SusshiCfgOpCodes code, const char *val) {
	if (val == NULL)
		return;
	debug3("Config %s: %s", proxy_cfg_lookup_opcode_name(code), val);
}


/*!
 * @brief       Dump configuration value of type Array of bstrings
 *
 * @param       code
 * @param       count
 * @param       vals
 */

static void
proxy_cfg_dump_cfg_bstrarray(SusshiCfgOpCodes code, int count, bstring *vals) {
	for (int i = 0; i < count; i++)
		debug3("Config %s: %s", proxy_cfg_lookup_opcode_name(code), bdata(vals[i]));
}


/*!
 * @brief       Dump configuration
 */

void
proxy_cfg_dump_config(void) {
	u_int i;
	int ret;
	struct addrinfo *ai;
	char addr[NI_MAXHOST], port[NI_MAXSERV];

	proxy_cfg_dump_cfg_bstrarray(sHostKeys, proxy_cfg.num_host_key_files, proxy_cfg.host_key_files);

	for (ai = proxy_cfg.listen_addrs; ai; ai = ai->ai_next) {
		if ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
							   sizeof(addr), port, sizeof(port),
							   NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
			debug4("getnameinfo failed: %.100s",
				   (ret != EAI_SYSTEM) ? gai_strerror(ret) :
				   strerror(errno));
		} else {
			if (ai->ai_family == AF_INET6) {
				debug3("Config ListenAddress: [%s]:%s", addr, port);
			} else {
				debug3("Config ListenAddress: %s:%s", addr, port);
			}
		}
	}

	for (i = 0; i < proxy_cfg.num_ports; i++)
		debug3("Config ListenPort: %d", proxy_cfg.ports[i]);

	for (i = 0; i < (u_int) proxy_cfg.num_gateway_addresses; i++)
		debug3("Config GatewayAddress: (%d) %s", i + 1, bdata(proxy_cfg.gateway_addresses[i]));

	proxy_cfg_dump_cfg_string(sInstallationId, bdata(proxy_cfg.installation_id));
	proxy_cfg_dump_cfg_string(sPidFile, bdata(proxy_cfg.pid_file));

	for (i = 0; i < (u_int) proxy_cfg.num_gateway_identities; i++)
		debug3("Config GatewayIdentityKeys: (%d) %s %s", i + 1, bdata(proxy_cfg.gateway_identities[i].key_type),
			   bdata(proxy_cfg.gateway_identities[i].fingerprint));

	proxy_cfg_dump_cfg_int(sEmbryonicGraceTime, proxy_cfg.embryonic_grace_time);
	debug3("Config MaxEmbryonics/Start: %d", proxy_cfg.max_embryonics_start);
	debug3("Config MaxEmbryonics/Max: %d", proxy_cfg.max_embryonics);
	debug3("Config MaxEmbryonics/Rate: %d%%", proxy_cfg.max_embryonics_rate);
}

/*! @} */
