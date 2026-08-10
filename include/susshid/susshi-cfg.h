/*!
 *
 * @brief       suSSHi Configuration from JSON
 *
 * @ingroup     susshi_cfg
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
 */

#ifndef SUSSHI_SUSSHI_CFG_H
#define SUSSHI_SUSSHI_CFG_H

#include "shared/log.h"

#define SSH_DEFAULT_PORT		22

#define MAX_PORTS				256		// Max # ports
#define MAX_HOSTKEYS			256		// Max # hostkeys
#define MAX_USERKEYS			256		// Max # userkeys
#define MAX_PROXIES				1000    // Max # target proxies
#define MAX_LOG_STOP_PATTERNS 	1024	// Max # of log stop patterns
#define MAX_DNS_SEARCH_DOMAINS	100		// Max # of DNS search domains
#define MAX_DENY_TARGETS	    100		// Max # of deny target addresses
#define MAX_CHEFS               5       // Max # of Chef Servers
#define MAX_PREFAUTHS           5       // Max # of Authentication methods
#define MAX_SESSION_LOG_ENCRYPTION_KEYS		32  // Max # of ed25519 public keys for session log encryption

typedef enum {
	CONTEXT_GLOBAL,
	CONTEXT_SESSION,
	CONTEXT_ANY
} SusshiCfgContext;


/* Keyword tokens. */
typedef enum {
	sBanner,
	sChefServerUrls, sChefCaPath, sChefCertificatePath, sChefVersion,
	sClientCompression, sClientHostkeyAlgorithms, sClientKexAlgorithms,
	sConfigVersion,
	sDebugLevel,
	sEmbryonicGraceTime,
	sMaxEmbryonics,
	sLogFacilitySystem, sLogFacilitySession,
	sLogFileSystem, sLogFileSession, sLogFileAudit,
	sExecLogfileMaxSize, sExecLogStopPatterns,
	sSessionLogEncryptionKeys,
	sListenPorts, sListenAddresses, sAddressFamily, sTargetPreferredAddressFamily, sDenyTargetAddresses, sDnsSearchDomains,
	sLastLogFile, sSubscriptionToken, sLoginGraceTime,
	sPasswordSplitString, sPidFile,
	sPreferredAuthentications,
	sPublicKeyAlgorithms,
	sClientTcpKeepAlive, sClientCiphers, sClientHmacs,
	sClientGatewayAuthPrompt, sClientGatewayAuthInstruction, sClientGatewayAuthTitle,
	sClientHostKeyUpdate,
	sRenewSic, sReportPeriod, sRemoteControlKey,
	sTargetTcpKeepAlive, sTargetCiphers, sTargetHmacs, sTargetHostkeyAlgorithms, sTargetKexAlgorithms,
	sTargetCompression,
	sTargetConnectionTimeout,
	sTargetPreferredAuthentications, sTargetProxies,
	sTargetPassSusshiInformation, sPreserveClientBanner,
	sChefPsk, sChefSpki,
	sSyslogGatewayName, sSyslogTlsCertificate, sSyslogTlsKey,
	sHostKeys, sTargetIdentityKeys,
	sInstallationId, sSusshidId,
	sVerboseDisconnect,
	_sBadOption, _sContextMissmatch, _sSkipOpcode
} SusshiCfgOpCodes;

/* This struct stores global set configurations, so session specific configuration can be reset to this values at any time */
typedef struct {
	int     target_preferred_address_family;			// Address family preferred by suSSHi when connecting to target
	int		target_tcp_keep_alive;						// Target TCP keepalive option. If true, set SO_KEEPALIVE
	int		target_connection_timeout;					// Connection timeout to Target

	int     target_preferred_authentications[MAX_PREFAUTHS];	// Preferred authentication methods (index of target_auth_methods) in order for target auth
	u_int	num_target_preferred_authentications;				// # of authentication methods

	bstring target_ciphers;								// Target cipher algorithms allowed
	bstring target_hmacs;								// Target hmac algorithms allowed
	bstring target_hostkey_algorithms;					// Accepted Target Hostkey algorithms
	bstring target_kex_algorithms;						// Target kex algorithms
	int     target_compression;							// Target compression on/off,  Note: compression level is not supported in SSH2, thus not implemented

	int     preserve_client_banner;						// Flag, if set, forward USERAUTH_BANNER from client to server
} OverwritableSettings;


typedef KeyIdentity TargetIdentity;


typedef struct {
	bstring realm;
	bstring hostname;
	int port;
} TargetProxy;


typedef struct {
	int       config_version;							// Config version
	bstring   banner;									// Login banner message
	bstring   installation_id;							// Uniq Identifier used for this installation (synchronized across Chef and all gateways)
	bstring   syslog_gateway_name;						// Syslog Gateway Hostname as set in suSSHi Chef
	bstring   syslog_tls_certificate;					// Syslog TLS Certificate
	bstring   syslog_tls_key;							// Syslog TLS Key
	int       login_grace_time;							// Disconnect if no auth in this time (sec)
	bstring   config_path;								// Path (dir) to configuration, will be set on config load.
	int		  verbose_disconnect;						// Set to 1 for verbose disconnect messages
	int       feature_audit_log_encryption;

	// Listener configs
	int		ports[MAX_PORTS];							// Port number to listen on
	u_int	num_ports;									// Number of listen ports
	bool	ports_from_cmdline;
	struct 	addrinfo *listen_addrs;						// Addresses on which suSSHi listens on
	int     address_family;								// Address family used by suSSHi

	// HostKey configs
	int     host_key_types[MAX_HOSTKEYS];				// enum ssh_keytypes_e Key-Type set during loading
	ssh_key host_key_pubs[MAX_HOSTKEYS];				// SSH-String containing Pubkey blob
	bstring host_key_files[MAX_HOSTKEYS];				// Files containing host keys
	int     num_host_key_files;     					// Number of files for host keys

	// Authentication Settings
	bstring password_split_string;						// Split User-Password with this string <gw_pw><split_string><target_pw>
	bstring public_key_algorithms;						// Accepted PublicKey algorithms

	// Logging configs
	LogLevel log_level;									// Level for system logging.
	bstring	logfile_system;								// Logfile for System-Logging
	bstring	logfile_session;							// Logfile for Session-Logging
	bstring logfile_audit;								// Logfile for Audit-Trail Logging
	bstring logfile_last;

	int     report_period;								// Period, session fork sends reports to report fork

	SyslogFacility 	log_facility_system;				// Facility for system logging.
	SyslogFacility 	log_facility_session;				// Facility for session logging.
	long int  logfile_exec_max_size;					// Maximum size of logfile in EXEC mode logging

	bstring	exec_log_stop_pattern[MAX_LOG_STOP_PATTERNS];			// Stop patterns (PCRE) for Exec logging
	pcre2_code *exec_log_stop_pattern_pcre[MAX_LOG_STOP_PATTERNS];	// Compiled PCRE2 patterns;
	int		num_exec_log_stop_pattern;								// # of Stop patterns

	// Session log encryption keys (ed25519 public keys)
	bstring session_log_encryption_keys[MAX_SESSION_LOG_ENCRYPTION_KEYS];
	int     num_session_log_encryption_keys;

	// Deny Targets
	bstring	deny_targets[MAX_DENY_TARGETS];				// Deny Targets
	int		num_deny_targets;							// # Deny Targets

	// DNS configs
	bstring	dns_searchdomains[MAX_DNS_SEARCH_DOMAINS];	// DNS search domains
	int		num_dns_searchdomains;						// # DNS search domains

	// Target Proxies
	TargetProxy target_proxies[MAX_PROXIES];			// Target Proxies
	int     num_target_proxies;							// # Target Proxies

	// Client configs
	int		client_tcp_keep_alive;						// Client TCP keepalive option. If true, set SO_KEEPALIVE
	bstring client_ciphers;								// Client cipher algorithms allowed
	bstring client_hmacs;								// Client hmac algorithms allowed
	bstring client_hostkey_algorithms;					// Accepted Hostkey algorithms
	bstring client_kex_algorithms;
	int     client_compression;							// Client compression on/off, Note: compression level is not supported in SSH2, thus not implemented
	int     client_hostkey_update;						// If set, send hostkey update and rotation request "hostkeys-00@openssh.com"

	bstring client_gateway_auth_title;					// Auth Title send on Gateway Password Authentication
	bstring client_gateway_auth_instruction;			// Auth Instruction send on Gateway Password Authentication
	bstring client_gateway_auth_prompt;					// Auth Prompt send on Gateway Password Authentication

	// Target configs
	TargetIdentity target_identities[MAX_USERKEYS];		// TargetIdentities
	int     num_target_identities;						// # of identities loaded

	int 	send_shell_env;							    // If set, SUSSHI_USER and other variables are sent as environment variable to target

	int     embryonic_grace_time;						// Disconnect if no SSH protocol within time
	int     max_embryonics;								// Max # of embryonic childs in total
	int     max_embryonics_start;						// # of embryonic childs to start with dropping childs
	int     max_embryonics_rate;						// rate (percentage) of childs to be dropped

	bstring remote_control_ssh_pubkey;					// SSH Public Key used for suSSHi Chef Remote Control authentication

	int     health_monitor_port;						// Health monitor port (HTTP)

	/*
	 * This two structs are used to store global configuration parameters (into global) and
	 * copy this global parameters into the session specific (per target ip) configuration set before
	 * overwriting some of the parameters with values from chef.
	 */

	OverwritableSettings global;
	OverwritableSettings session;

} SusshiCfg;

extern SusshiCfg susshi_cfg;

/* Prototypes */
void susshi_cfg_init(void);

void susshi_cfg_free(void);

void susshi_cfg_fill_defaults(void);


void susshi_cfg_add_listen_addr(char *addr, int port);

void susshi_cfg_dump_config(SusshiCfgContext current_context);

void susshi_cfg_load_configfile(const char *filename);

bool susshi_cfg_read_json(json_t *object, SusshiCfgContext current_context);

bool susshi_cfg_parse_ssh_key(json_t *element, const char **pub_ptr, const char **type_ptr, const char **priv_ptr,
							  const char **fp_ptr, const char *section);

void susshi_cfg_copy_global_cfg_to_session(void);

#endif //SUSSHI_SUSSHI_CFG_H

/*! @} */
