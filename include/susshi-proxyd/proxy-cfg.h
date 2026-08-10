/*!
 *
 * @brief       suSSHi Proxy Configuration
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
 * @ingroup     proxy_cfg
 * @{
 *
 */

#ifndef SUSSHI_PROXYD_CFG_H
#define SUSSHI_PROXYD_CFG_H

#include "log.h"

#define SSH_DEFAULT_PORT		22

#define MAX_PORTS				256		// Max # ports
#define MAX_HOSTKEYS			256		// Max # hostkeys
#define MAX_USERKEYS			256		// Max # userkeys
#define MAX_GATEWAY_ADDRESSES	256		// Max # gateway IP addresses

typedef enum {
	CONTEXT_GLOBAL,
	CONTEXT_SESSION,
	CONTEXT_ANY
} SusshiCfgContext;


/* Keyword tokens. */
typedef enum {
	sConfigVersion,
	sEmbryonicGraceTime,
	sGatewayAddresses,
	sGatewayIdentityKeys,
	sHostKeys,
	sInstallationId,
	sListenAddresses,
	sListenPorts,
	sMaxEmbryonics,
	sPidFile,
	sTargetPreferredAddressFamily,
	_sBadOption
} SusshiCfgOpCodes;

typedef KeyIdentity GatewayIdentity;

typedef struct {
	int       config_version;                               // Config version
	bstring   pid_file;										// Where to put our pid
	bstring   susshid_id;                                   // Uniq Identifier used for this susshid instance (host / container)
	bstring   config_path;                                  // Path (dir) to configuration, will be set on config load.
	bstring   installation_id;

	// Listener configs
	int		ports[MAX_PORTS];								// Port number to listen on
	u_int	num_ports;										// Number of listen ports
	bool	ports_from_cmdline;
	struct 	addrinfo *listen_addrs;							// Addresses on which suSSHi listens on
	int     address_family;									// Address family used by suSSHi

	// HostKey configs
	bstring host_key_files[MAX_HOSTKEYS];					// Files containing host keys
	int     num_host_key_files;     						// Number of files for host keys

	// Logging configs
	LogLevel log_level;										// Level for system logging.

	// Gateway configs
	GatewayIdentity gateway_identities[MAX_USERKEYS];       // GatewayIdentities
	int     num_gateway_identities;                         // # of identities loaded
	bstring gateway_addresses[MAX_GATEWAY_ADDRESSES];		// IP Addresses of Gateways (CIDR)
	int     num_gateway_addresses;     						// Number of gateway IPs

	int     embryonic_grace_time;                           // Disconnect if no SSH protocol within time
	int     max_embryonics;                                 // Max # of embryonic childs in total
	int     max_embryonics_start;                           // # of embryonic childs to start with dropping childs
	int     max_embryonics_rate;                            // rate (percentage) of childs to be dropped

	int     target_preferred_address_family;				// Address family preferred by suSSHi when connecting to target
	int		target_connection_timeout;						// Connection timeout to Target

	int     health_monitor_port;                            // Health monitor port (HTTP)

} SusshiProxyCfg;

extern SusshiProxyCfg proxy_cfg;

/* Prototypes */
void proxy_cfg_init(void);

void proxy_cfg_free(void);

bool proxy_cfg_load_configfile(const char *filename);

void proxy_cfg_fill_defaults(bool sic_init);

void proxy_cfg_add_listen_addr(char *addr, int port);

void proxy_cfg_dump_config(void);

bool proxy_cfg_read_json(json_t *object);

bool proxy_cfg_parse_ssh_key(json_t *element, const char **pub_ptr, const char **type_ptr, const char **priv_ptr,
							  const char **fp_ptr, const char *section);


#endif //SUSSHI_PROXYD_CFG_H

/*! @} */
