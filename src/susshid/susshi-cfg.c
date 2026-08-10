/*!
 *
 * @brief       suSSHi Configuration from JSON
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
 * @defgroup    susshi_cfg Susshid configuration
 * @{
 */

#include <susshid/common.h>
#include <susshid/subscription.h>


SusshiCfg susshi_cfg;

/* Prototypes */
static const char *susshi_cfg_lookup_opcode_name(SusshiCfgOpCodes code);
static char *susshi_cfg_derelativise_path(const char *path);

static void susshi_cfg_parse_af(json_t *value, int *intptr, const char *section);
static void susshi_cfg_parse_int(json_t *value, int *intptr, const char *section);
static void susshi_cfg_parse_long_int(json_t *value, long int *intptr, const char *section);
static void susshi_cfg_parse_flag(json_t *value, int *intptr, const char *section);
static void susshi_cfg_parse_log_facility(json_t *value, int *intptr, const char *section);
static void susshi_cfg_parse_path(json_t *value, bstring *pathptr, int *countptr, const char *section);
static void susshi_cfg_parse_bstring(json_t *value, bstring *bstrptr, int *countptr, const char *section);
static void susshi_cfg_parse_chef_url(json_t *hash, const char *key, bstring *bstr, int *num);
static void susshi_cfg_add_one_listen_addr(char *addr, int port);
static bstring susshi_cfg_all_ciphers(void);
bool susshi_cfg_lookup_cipher(bstring cipher);

static void susshi_cfg_dump_cfg_bstrarray(SusshiCfgOpCodes code, int count, bstring *vals);
static void susshi_cfg_dump_cfg_flag(SusshiCfgOpCodes code, int val);
static void susshi_cfg_dump_cfg_af(SusshiCfgOpCodes code, int val);
static void susshi_cfg_dump_cfg_int(SusshiCfgOpCodes code, int val);
static void susshi_cfg_dump_cfg_long_int(SusshiCfgOpCodes code, long int val);
static void susshi_cfg_dump_cfg_string(SusshiCfgOpCodes code, const char *val);


/*!
 * @brief       Mapping Table for tokens
 */

static struct {
	const char *name;
	SusshiCfgOpCodes opcode;
	SusshiCfgContext context;	// CONTEXT_GLOBAL: Only allowed in CONTEXT_GLOBAL call, CONTEXT_ANY: also allowed in CONTEXT_SESSION
	bool locked;                // Set to true if CONTEXT_GLOBAL scoped option has been set
} keywords[] = {
		/* Standard Options in Order they have to be parsed (if in any relationship) */
		{"AddressFamily",                  sAddressFamily,                  CONTEXT_GLOBAL, false},
		{"AuditLogFile",                   sLogFileAudit,                   CONTEXT_GLOBAL, false},
		{"ListenPorts",                    sListenPorts,                    CONTEXT_GLOBAL, false},
		{"ListenAddresses",                sListenAddresses,                CONTEXT_GLOBAL, false},
		{"Banner",                         sBanner,                         CONTEXT_ANY,    false},
		{"ChefCaPath",                     sChefCaPath,                     CONTEXT_GLOBAL, false},
		{"ChefCertificatePath",            sChefCertificatePath,            CONTEXT_GLOBAL, false},
		{"ChefPsk",                        sChefPsk,                        CONTEXT_GLOBAL, false},
		{"ChefServerUrls",                 sChefServerUrls,                 CONTEXT_GLOBAL, false},
		{"ChefSpki",                       sChefSpki,                       CONTEXT_GLOBAL, false},
		{"ChefVersion",                    sChefVersion,                    CONTEXT_GLOBAL, false},
		{"ClientCiphers",                  sClientCiphers,                  CONTEXT_GLOBAL, false},
		{"ClientHmacs",                    sClientHmacs,                    CONTEXT_GLOBAL, false},
		{"ClientCompression",              sClientCompression,              CONTEXT_GLOBAL, false},
		{"ClientHostkeyAlgorithms",        sClientHostkeyAlgorithms,        CONTEXT_GLOBAL, false},
		{"ClientKexAlgorithms",            sClientKexAlgorithms,            CONTEXT_GLOBAL, false},
		{"ClientTcpKeepalive",             sClientTcpKeepAlive,             CONTEXT_GLOBAL, false},
		{"ClientGatewayAuthPrompt",        sClientGatewayAuthPrompt,        CONTEXT_ANY,    false},
		{"ClientGatewayAuthInstruction",   sClientGatewayAuthInstruction,   CONTEXT_ANY,    false},
		{"ClientGatewayAuthTitle",         sClientGatewayAuthTitle,         CONTEXT_ANY,    false},
		{"ClientHostKeyUpdate",            sClientHostKeyUpdate,            CONTEXT_GLOBAL, false},
		{"DebugLevel",                     sDebugLevel,                     CONTEXT_ANY,    false},
		{"DenyTargetAddresses",            sDenyTargetAddresses,            CONTEXT_GLOBAL, false},
		{"DnsSearchDomains",               sDnsSearchDomains,               CONTEXT_GLOBAL, false},
		{"EmbryonicGraceTime",             sEmbryonicGraceTime,             CONTEXT_GLOBAL, false},
		{"MaxEmbryonics",                  sMaxEmbryonics,                  CONTEXT_GLOBAL, false},
		{"ExecLogFileMaxsize",             sExecLogfileMaxSize,             CONTEXT_GLOBAL, false},
		{"ExecLogStopPatterns",            sExecLogStopPatterns,            CONTEXT_ANY,    false},
		{"HostKeys",                       sHostKeys,                       CONTEXT_GLOBAL, false},
		{"InstallationId",                 sInstallationId,                 CONTEXT_GLOBAL, false},
		{"LastLogFile",                    sLastLogFile,                    CONTEXT_GLOBAL, false},
		{"SubscriptionToken",              sSubscriptionToken,              CONTEXT_ANY,    false},
		{"LoginGraceTime",                 sLoginGraceTime,                 CONTEXT_GLOBAL, false},
		{"PasswordSplitString",            sPasswordSplitString,            CONTEXT_GLOBAL, false},
		{"PidFile",                        sPidFile,                        CONTEXT_GLOBAL, false},
		{"PreferredAuthentications",       sPreferredAuthentications,       CONTEXT_ANY,    false},
		{"PreserveClientBanner",           sPreserveClientBanner,           CONTEXT_ANY,    false},
		{"PublicKeyAlgorithms",            sPublicKeyAlgorithms,            CONTEXT_GLOBAL, false},
		{"RenewSic",                       sRenewSic,                       CONTEXT_GLOBAL, false},
		{"RemoteControlKey",               sRemoteControlKey,               CONTEXT_GLOBAL, false},
		{"ReportPeriod",                   sReportPeriod,                   CONTEXT_GLOBAL, false},
		{"SessionLogEncryptionKeys",       sSessionLogEncryptionKeys,       CONTEXT_ANY,    false},
		{"SessionLogFacility",             sLogFacilitySession,             CONTEXT_GLOBAL, false},
		{"SessionLogFile",                 sLogFileSession,                 CONTEXT_GLOBAL, false},
		{"SyslogGatewayName",              sSyslogGatewayName,              CONTEXT_GLOBAL, false},
		{"SyslogTlsCertificate",           sSyslogTlsCertificate,           CONTEXT_GLOBAL, false},
		{"SyslogTlsKey",                   sSyslogTlsKey,                   CONTEXT_GLOBAL, false},
		{"SystemLogFacility",              sLogFacilitySystem,              CONTEXT_GLOBAL, false},
		{"SystemLogFile",                  sLogFileSystem,                  CONTEXT_GLOBAL, false},
		{"SusshidId",                      sSusshidId,                      CONTEXT_GLOBAL, false},
		{"TargetCiphers",                  sTargetCiphers,                  CONTEXT_ANY,    false},
		{"TargetCompression",              sTargetCompression,              CONTEXT_ANY,    false},
		{"TargetConnectionTimeout",        sTargetConnectionTimeout,        CONTEXT_ANY,    false},
		{"TargetHmacs",                    sTargetHmacs,                    CONTEXT_ANY,    false},
		{"TargetIdentityKeys",             sTargetIdentityKeys,             CONTEXT_GLOBAL, false},
		{"TargetHostkeyAlgorithms",        sTargetHostkeyAlgorithms,        CONTEXT_GLOBAL, false},
		{"TargetKexAlgorithms",            sTargetKexAlgorithms,            CONTEXT_GLOBAL, false},
		{"TargetPassSusshiInformation",    sTargetPassSusshiInformation,    CONTEXT_GLOBAL, false},
		{"TargetPreferredAddressFamily",   sTargetPreferredAddressFamily,   CONTEXT_ANY,    false},
		{"TargetPreferredAuthentications", sTargetPreferredAuthentications, CONTEXT_ANY,    false},
		{"TargetProxies",                  sTargetProxies,                  CONTEXT_GLOBAL, false},
		{"TargetTcpKeepAlive",             sTargetTcpKeepAlive,             CONTEXT_ANY,    false},
		{"VerboseDisconnect",              sVerboseDisconnect,              CONTEXT_GLOBAL, false},
		{"Version",                        sConfigVersion,                  CONTEXT_GLOBAL, false},
		{NULL,                             _sBadOption,                     CONTEXT_ANY,    false}
};

static const char* supported_ciphers[] = {
		"aes256-ctr",
		"aes256-cbc",
		"aes256-gcm@openssh.com",
		"aes192-ctr",
		"aes192-cbc",
		"aes128-ctr",
		"aes128-cbc",
		"aes128-gcm@openssh.com",
		"blowfish-cbc",
		"chacha20-poly1305@openssh.com",
		// des & 3des are skipped from now on
		NULL
};


/*!
 * @brief       Initialize susshi_cfg variable
 */

void
susshi_cfg_init(void) {
	int i;

	memset(&susshi_cfg, 0, sizeof(susshi_cfg));

	susshi_cfg.feature_audit_log_encryption = 0;
	susshi_cfg.address_family = -1;
	susshi_cfg.login_grace_time = -1;

	susshi_cfg.log_level = LOG_LEVEL_NOT_SET;
	susshi_cfg.logfile_exec_max_size = -1;

	susshi_cfg.log_facility_system = (SyslogFacility) -1;
	susshi_cfg.log_facility_session = (SyslogFacility) -1;

	susshi_cfg.global.target_connection_timeout = -1;
	susshi_cfg.client_tcp_keep_alive = -1;
	susshi_cfg.client_compression = -1;
	susshi_cfg.global.target_compression = -1;
	susshi_cfg.global.target_preferred_address_family = -1;
	susshi_cfg.global.target_tcp_keep_alive = -1;
	susshi_cfg.send_shell_env = -1;
	susshi_cfg.global.preserve_client_banner = -1;
	susshi_cfg.global.num_target_preferred_authentications = 0;

	susshi_cfg.max_embryonics = -1;
	susshi_cfg.embryonic_grace_time = -1;
	susshi_cfg.report_period = -1;

	for (i = 0; keywords[i].name; i++)
		keywords[i].locked = false;

}


/*!
 * @brief       Free susshi_cfg allocated memory (strings etc.) and wipe
 */

void
susshi_cfg_free(void) {

	if (susshi_cfg.banner)
		bstrFree(susshi_cfg.banner);

	if (susshi_cfg.installation_id)
		bstrFree(susshi_cfg.installation_id);

	if (susshi_cfg.config_path)
		bstrFree(susshi_cfg.config_path);

	if (susshi_cfg.logfile_system)
		bstrFree(susshi_cfg.logfile_system);

	if (susshi_cfg.logfile_session)
		bstrFree(susshi_cfg.logfile_session);

	if (susshi_cfg.logfile_audit)
		bstrFree(susshi_cfg.logfile_audit);

	if (susshi_cfg.logfile_last)
		bstrFree(susshi_cfg.logfile_last);

	if (susshi_cfg.client_ciphers)
		bstrFree(susshi_cfg.client_ciphers);

	if (susshi_cfg.remote_control_ssh_pubkey)
		bstrFree(susshi_cfg.remote_control_ssh_pubkey);

	for (int i = 0; i < MAX_HOSTKEYS; i++)
		if (susshi_cfg.host_key_files[i])
			bstrFree(susshi_cfg.host_key_files[i]);

	for (int i = 0; i < MAX_LOG_STOP_PATTERNS; i++)
		if (susshi_cfg.exec_log_stop_pattern[i])
			bstrFree(susshi_cfg.exec_log_stop_pattern[i]);

	for (int i = 0; i < MAX_DNS_SEARCH_DOMAINS; i++)
		if (susshi_cfg.dns_searchdomains[i])
			bstrFree(susshi_cfg.dns_searchdomains[i]);

	for (int i = 0; i < MAX_SESSION_LOG_ENCRYPTION_KEYS; i++)
		if (susshi_cfg.session_log_encryption_keys[i])
			bstrFree(susshi_cfg.session_log_encryption_keys[i]);

	for (int i = 0; i < MAX_USERKEYS; i++) {
		if (susshi_cfg.target_identities[i].public_blob)
			bstrFree(susshi_cfg.target_identities[i].public_blob);
		if (susshi_cfg.target_identities[i].private_blob)
			bstrFree(susshi_cfg.target_identities[i].private_blob);
		if (susshi_cfg.target_identities[i].key_type)
			bstrFree(susshi_cfg.target_identities[i].key_type);
		if (susshi_cfg.target_identities[i].fingerprint)
			bstrFree(susshi_cfg.target_identities[i].fingerprint);
	}

	memset(&susshi_cfg, 0, sizeof(susshi_cfg));
}


/*!
 * @brief       Fill susshi_cfg with defaults after having it filled with global config values from configuration file
 */

void
susshi_cfg_fill_defaults(void) {
	int i;

	if (chef_cfg.susshid_id == NULL)
		chef_cfg.susshid_id = bfromcstr("XXXX");

	if (susshi_cfg.address_family == -1)
		susshi_cfg.address_family = AF_UNSPEC;

	if (susshi_cfg.log_level == LOG_LEVEL_NOT_SET)
		susshi_cfg.log_level = LOG_LEVEL_INFO;

	if (susshi_cfg.login_grace_time == -1)
		susshi_cfg.login_grace_time = 120;

	if (susshi_cfg.log_facility_system == -1)
		susshi_cfg.log_facility_system = (SyslogFacility) LOG_AUTH;

	if (susshi_cfg.log_facility_session == -1)
		susshi_cfg.log_facility_session = (SyslogFacility) LOG_AUTH;

	if (susshi_cfg.global.target_preferred_address_family == -1)
		susshi_cfg.global.target_preferred_address_family = AF_UNSPEC;

	if (susshi_cfg.client_ciphers == NULL)
		susshi_cfg.client_ciphers = susshi_cfg_all_ciphers();

	if (susshi_cfg.global.target_ciphers == NULL)
		susshi_cfg.global.target_ciphers = susshi_cfg_all_ciphers();

	if (susshi_cfg.global.target_connection_timeout == -1)
		susshi_cfg.global.target_connection_timeout = 3;

	for (i = 0; i < susshi_cfg.num_dns_searchdomains; i++)
		btolower(susshi_cfg.dns_searchdomains[i]);

	if (susshi_cfg.logfile_system == NULL)
		susshi_cfg.logfile_system = bfromcstr(PATH_SUSSHI_LOGDIR "/system/%y/%m/%d/system.log");

	if (susshi_cfg.logfile_session == NULL)
		susshi_cfg.logfile_session = bfromcstr(PATH_SUSSHI_LOGDIR "/sessions/%y/%m/%d/%t/%u-%s.log");

	if (susshi_cfg.logfile_audit == NULL)
		susshi_cfg.logfile_audit = bfromcstr(PATH_SUSSHI_LOGDIR "/audit/%y/%m/%d/%t/%u-%s.%f");

	if (susshi_cfg.logfile_last == NULL)
		susshi_cfg.logfile_last = bfromcstr(PATH_SUSSHI_LOGDIR "/lastlog");

	if (susshi_cfg.client_tcp_keep_alive == -1)
		susshi_cfg.client_tcp_keep_alive = 1;

	if (susshi_cfg.global.target_tcp_keep_alive == -1)
		susshi_cfg.global.target_tcp_keep_alive = 1;

	if (susshi_cfg.logfile_exec_max_size == -1)
		susshi_cfg.logfile_exec_max_size = SUSSHI_LOGFILE_EXEC_MAX_SIZE;

	// a value of '0' specifies unlimited
	if (susshi_cfg.logfile_exec_max_size == 0)
		susshi_cfg.logfile_exec_max_size = -1;

	if (susshi_cfg.send_shell_env == -1)
		susshi_cfg.send_shell_env = 1;

	if (susshi_cfg.global.preserve_client_banner == -1)
		susshi_cfg.global.preserve_client_banner = 0;

	if (susshi_cfg.global.num_target_preferred_authentications == 0) {
		susshi_target_auth_method_fill_susshi_cfg();
	}

	if (susshi_cfg.max_embryonics == -1) {
		susshi_cfg.max_embryonics_start = 30;
		susshi_cfg.max_embryonics_rate = 10;
		susshi_cfg.max_embryonics = 100;
	}

	if (susshi_cfg.embryonic_grace_time == -1) {
		susshi_cfg.embryonic_grace_time = 10;
	}

	if (susshi_cfg.report_period == -1) {
		susshi_cfg.report_period = 900;     // 15m
	}

	if (susshi_cfg.client_gateway_auth_prompt == NULL) {
		susshi_cfg.client_gateway_auth_prompt = bfromcstr("Gateway password: ");
	}

	if (susshi_cfg.client_gateway_auth_instruction == NULL) {
		susshi_cfg.client_gateway_auth_instruction = bfromcstr("Please login with your gateway password.");
	}

	if (susshi_cfg.client_gateway_auth_title == NULL) {
		susshi_cfg.client_gateway_auth_title = bfromcstr("\n" SUSSHI_NAME " Gateway authentication\n");
	}

	chef_cfg_fill_server_urls();

	/* Initialize config directory path if not set */
	if (susshi_cfg.config_path == NULL) {
		susshi_cfg.config_path = bfromcstr(PATH_SUSSHID_CONFIG_DIR);
	}

	if (susshi_cfg.health_monitor_port == 0) {
		susshi_cfg.health_monitor_port = MONITOR_PORT;
	}

	if (susshi_cfg.password_split_string == NULL) {
		susshi_cfg.password_split_string = bfromcstr("::@::");
	}
}


/*!
 * @brief       Parse Addressfamily and store in integer
 *
 * @param       value       json_string object
 * @param       intptr      Pointer to integer return will get stored in
 * @param       section     Section string (for error reporting)
 */

static void
susshi_cfg_parse_af(json_t *value, int *intptr, const char *section) {

	const char *string;
	int intvalue = -1;

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
		*intptr = intvalue;
	} else {
		fatal("%s: Please specify either ipv4, ipv6 or any", section);
	}
}


/*!
 * @brief       Parse Flag (yes/no) and store 1/0 in integer
 *
 * @param       value       json_boolean object
 * @param       intptr      Pointer to integer return will get stored in
 * @param       section     Section string (for error reporting)
 */

static void
susshi_cfg_parse_flag(json_t *value, int *intptr, const char *section) {

	if (json_is_boolean(value)) {
		*intptr = json_boolean_value(value);
	} else {
		fatal("%s: missing true/false argument", section);
	}
}


/*!
 * @brief       Parse Integer
 *
 * @param       value       json_number object
 * @param       intptr      Pointer to integer return will get stored in
 * @param       section     Section string (for error reporting)
 */

static void
susshi_cfg_parse_int(json_t *value, int *intptr, const char *section) {

	if (json_is_number(value)) {
		*intptr = (int) json_integer_value(value);
	} else {
		fatal("%s: expected integer", section);
	}
}


/*!
 * @brief       Parse Long Integer
 *
 * @param       value       json_string object
 * @param       intptr      Pointer to integer return will get stored in
 * @param       section     Section string (for error reporting)
 */

static void
susshi_cfg_parse_long_int(json_t *value, long int *intptr, const char *section) {

	if (json_is_number(value)) {
		*intptr = (long int) json_integer_value(value);
	} else {
		fatal("%s: expected integer", section);
	}
}


/*!
 * @brief       Parse Log Facility and store in integer
 *
 * @param       value       json_string object
 * @param       intptr      Pointer to integer return will get stored in
 * @param       section     Section string (for error reporting)
 */

static void
susshi_cfg_parse_log_facility(json_t *value, int *intptr, const char *section) {

	const char *string;
	int intvalue;

	if (json_is_string(value)) {
		string = json_string_value(value);
		intvalue = syslog_facility_int(string);

		if (intvalue == -1)
			fatal("%s: unsupported log facility '%s'", section, string ? string : "<NONE>");

		if (*intptr == -1)
			*intptr = intvalue;
	} else {
		fatal("%s: expected log facility", section);
	}
}


/*!
 * @brief       Parse and derelativise (file)path and store in bstring
 *
 * @param       value       json_string object
 * @param       pathptr     Pointer to path
 * @param       countptr    Pointer to count
 * @param       section     Section string (for error reporting)
 */

static void
susshi_cfg_parse_path(json_t *value, bstring *pathptr, int *countptr, const char *section) {

	if (json_is_string(value)) {
		*pathptr = bfromcstr(susshi_cfg_derelativise_path(json_string_value(value)));
		if (countptr != NULL)
			*countptr = *countptr + 1;
	} else {
		fatal("%s: expected path", section);
	}
}


/*!
 * @brief       Parse String and store into bstring
 *
 * @param       value       json_string object
 * @param       bstrptr     Pointer to string
 * @param       countptr    Pointer to count
 * @param       section     Section string (for error reporting)
 */

static void
susshi_cfg_parse_bstring(json_t *value, bstring *bstrptr, int *countptr, const char *section) {

	if (json_is_string(value)) {
		*bstrptr = bfromcstr(json_string_value(value));
		if (countptr != NULL)
			*countptr = *countptr + 1;
	} else {
		fatal("%s: expected string value", section);
	}
}


/*!
 * @brief       Parse chef urls hash
 *
 * @param       hash        JSON hash with ChefServerUrls config
 * @param       key         Key to be looked up
 * @param       bstr        Pointer to bstring pointer array
 * @param       num         Pointer to num counter
 */

static void
susshi_cfg_parse_chef_url(json_t *hash, const char *key, bstring *bstr, int *num) {
	int ret;
	json_t *array = NULL;
	json_t *element;
	size_t index;

	ret = json_unpack(hash, "{s?o}", key, &array);

	if (ret == 0) {
		json_array_foreach(array, index, element) {
			if (index == MAX_CHEFS)
				fatal("Configuration/ChefServerUrls/%s: Maximal number of chefs (%d) exceeded", key, MAX_CHEFS);

			susshi_cfg_parse_bstring(element, &bstr[index], num, "Configuration/ChefServerUrls");
		}
	}
}


/*!
 * @brief       Parse SSH Key Hash in Syntax of HostKeys and TargetIdentityKeys
 *
 * @param       element     json_object
 * @param       type_ptr    pointer to pointer to store key-type
 * @param       fp_ptr      pointer to pointer to store fingerprint
 * @param       pub_ptr     pointer to pointer to store public key
 * @param       priv_ptr    pointer to pointer to store private key
 * @param       section     Section string (for error reporting)
 *
 * @return      true on success
 */

bool
susshi_cfg_parse_ssh_key(json_t *element, const char **type_ptr, const char **fp_ptr, const char **pub_ptr,
						 const char **priv_ptr, const char *section) {

	int ret;
	if (json_is_object(element)) {

		ret = json_unpack(element, "{s:s s:s s:s s:s}",
						  "key_type", type_ptr,
						  "fingerprint", fp_ptr,
						  "public_blob", pub_ptr,
						  "private_blob", priv_ptr);

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
 * @param       object              JSON object
 * @param       current_context     CONTEXT_GLOBAL or CONTEXT_SESSION
 *
 * @return      true on success
 */

bool
susshi_cfg_read_json(json_t *object, SusshiCfgContext current_context) {

	const char *key;
	json_t *value;
	SusshiCfgOpCodes opcode;
	SusshiCfgContext context;

	u_int i;
	size_t index;
	json_t *element;
	const char *string = NULL;

	OverwritableSettings *overwritables;

	if (current_context == CONTEXT_SESSION) {
		susshi_cfg_copy_global_cfg_to_session();
		overwritables = &susshi_cfg.session;
	} else {
		overwritables = &susshi_cfg.global;
	}

	for (i = 0; keywords[i].name; i++) {

		key = keywords[i].name;
		value = json_object_get(object, key);

		if (value) {
			context = keywords[i].context;
			opcode = keywords[i].opcode;

			switch (current_context) {

				case CONTEXT_GLOBAL: {
					if (keywords[i].locked == true) {
						opcode = _sSkipOpcode;
					} else {
						/* Can be overriden in branch for sessions that are allowed to be overridden */
						keywords[i].locked = true;
					}
				} break;
				case CONTEXT_SESSION: {
					if (context != CONTEXT_ANY) {
						opcode = _sContextMissmatch;
					}
				} break;
				default: {
					fatal("Called with invalid context %d", context);
				}
			}

			switch(opcode) {

				case sAddressFamily: {
					susshi_cfg_parse_af(value, &susshi_cfg.address_family, "Configuration/AddressFamily");
				} break;

				case sBanner: {
					susshi_cfg_parse_bstring(value, &susshi_cfg.banner, NULL, "Configuration/Banner");
					if (susshi_cfg.banner)
						bformata(susshi_cfg.banner, "\n");
				} break;

				case sChefServerUrls: {
					if (json_is_array(value)) {
						/* We have simple syntax */
						json_array_foreach(value, index, element) {
							if (index == MAX_CHEFS)
								fatal("Configuration/ChefServerUrls: Maximal number of chefs (%d) exceeded", MAX_CHEFS);

							susshi_cfg_parse_bstring(element, &chef_cfg.chef_server_urls.all[index],
													 &chef_cfg.chef_server_urls.num_all, "Configuration/ChefServerUrls");
						}
					} else {
						/* We have hash syntax */
						susshi_cfg_parse_chef_url(value, "default", chef_cfg.chef_server_urls.all, &chef_cfg.chef_server_urls.num_all);
						susshi_cfg_parse_chef_url(value, "gateway", chef_cfg.chef_server_urls.gateway, &chef_cfg.chef_server_urls.num_gateway);
						susshi_cfg_parse_chef_url(value, "session", chef_cfg.chef_server_urls.session, &chef_cfg.chef_server_urls.num_session);
						susshi_cfg_parse_chef_url(value, "report",  chef_cfg.chef_server_urls.report, &chef_cfg.chef_server_urls.num_report);
					}
				} break;

				case sChefCaPath: {
					susshi_cfg_parse_path(value, &chef_cfg.chef_ca_file, NULL, "Configuration/ChefCaPath");
				} break;

				case sChefCertificatePath: {
					susshi_cfg_parse_path(value, &chef_cfg.chef_certificate_file, NULL, "Configuration/ChefCertificatePath");
				} break;

				case sChefPsk: {
					bstring psk = NULL;
					susshi_cfg_parse_bstring(value, &psk, NULL, "Configuration/SicPsk");

					if (psk) {
						/* store psk encrypted for later usage */
						chef_cfg.sic_psk_memcrypt = susshi_memcrypt_encrypt_bstring(psk, NULL);
						bstrWipe(psk);
					}
				} break;


				case sChefSpki: {
					bstring sic_spki = NULL;

					susshi_cfg_parse_bstring(value, &sic_spki, NULL, "Configuration/SicSpki");
					susshi_sic_store_normalized_spki(sic_spki);

					bstrWipe(sic_spki);
				} break;

				case sChefVersion: {

					susshi_cfg_parse_bstring(value, &chef_cfg.chef_version, NULL, "Configuration/ChefVersion");

					if (!susshi_parse_version_info(chef_cfg.chef_version, &chef_cfg.chef_version_uint32)) {
						fatal("Configuration/ChefVersion: malformed version string '%s', expected major.minor[.patch]",
							  bdata(chef_cfg.chef_version));
					}
				} break;

				case sClientCiphers: {
					if (susshi_cfg.client_ciphers) {
						// Overwrite with new values
						bstrFree(susshi_cfg.client_ciphers);
						susshi_cfg.client_ciphers = NULL;
					}
					json_array_foreach(value, index, element) {
						bstring cipher = NULL;
						susshi_cfg_parse_bstring(element, &cipher, NULL, "Configuration/ClientCiphers");
						btolower(cipher);

						if (susshi_cfg_lookup_cipher(cipher)) {
							if (susshi_cfg.client_ciphers) {
								bformata(susshi_cfg.client_ciphers, ",");
							} else {
								susshi_cfg.client_ciphers = bfromcstr("");
							}
							bformata(susshi_cfg.client_ciphers, bdata(cipher));
							bstrFree(cipher);
						} else {
							fatal("Configuration/ClientCiphers: Cipher %s unknown", bdata(cipher));
						}
					}
				} break;

				case sClientCompression: {
					susshi_cfg_parse_flag(value, &susshi_cfg.client_compression, "Configuration/ClientCompression");
				} break;

				case sClientHmacs: {
					if (susshi_cfg.client_hmacs) {
						// Overwrite with new values
						bstrFree(susshi_cfg.client_hmacs);
						susshi_cfg.client_hmacs = NULL;
					}
					json_array_foreach(value, index, element) {
						bstring cipher = NULL;
						susshi_cfg_parse_bstring(element, &cipher, NULL, "Configuration/ClientHmacs");
						btolower(cipher);

						if (susshi_cfg.client_hmacs) {
							bformata(susshi_cfg.client_hmacs, ",");
						} else {
							susshi_cfg.client_hmacs = bfromcstr("");
						}
						bformata(susshi_cfg.client_hmacs, "%s", bdata(cipher));
						bstrFree(cipher);
					}
				} break;

				case sClientHostkeyAlgorithms: {
					if (susshi_cfg.client_hostkey_algorithms) {
						// Overwrite with new values
						bstrFree(susshi_cfg.client_hostkey_algorithms);
						susshi_cfg.client_hostkey_algorithms = NULL;
					}
					json_array_foreach(value, index, element) {
						bstring cipher = NULL;
						susshi_cfg_parse_bstring(element, &cipher, NULL, "Configuration/ClientHostkeyAlgorithms");
						btolower(cipher);

						if (susshi_cfg.client_hostkey_algorithms) {
							bformata(susshi_cfg.client_hostkey_algorithms, ",");
						} else {
							susshi_cfg.client_hostkey_algorithms = bfromcstr("");
						}
						bformata(susshi_cfg.client_hostkey_algorithms, "%s", bdata(cipher));
						bstrFree(cipher);
					}
				} break;

				case sClientKexAlgorithms: {
					if (susshi_cfg.client_kex_algorithms) {
						// Overwrite with new values
						bstrFree(susshi_cfg.client_kex_algorithms);
						susshi_cfg.client_kex_algorithms = NULL;
					}
					json_array_foreach(value, index, element) {
						bstring cipher = NULL;
						susshi_cfg_parse_bstring(element, &cipher, NULL, "Configuration/ClientKexAlgorithms");
						btolower(cipher);

						if (susshi_cfg.client_kex_algorithms) {
							bformata(susshi_cfg.client_kex_algorithms, ",");
						} else {
							susshi_cfg.client_kex_algorithms = bfromcstr("");
						}
						bformata(susshi_cfg.client_kex_algorithms, "%s", bdata(cipher));
						bstrFree(cipher);
					}
				} break;

				case sClientTcpKeepAlive: {
					susshi_cfg_parse_flag(value, &susshi_cfg.client_tcp_keep_alive, "Configuration/ClientTcpKeepalive");
				} break;

				case sClientGatewayAuthInstruction: {
					susshi_cfg_parse_bstring(value, &susshi_cfg.client_gateway_auth_instruction, NULL, "Configuration/ClientGatewayAuthInstruction");
				} break;

				case sClientGatewayAuthPrompt: {
					susshi_cfg_parse_bstring(value, &susshi_cfg.client_gateway_auth_prompt, NULL, "Configuration/ClientGatewayAuthPrompt");
				} break;

				case sClientGatewayAuthTitle: {
					susshi_cfg_parse_bstring(value, &susshi_cfg.client_gateway_auth_title, NULL, "Configuration/ClientGatewayAuthTitle");
				} break;

				case sClientHostKeyUpdate: {
					susshi_cfg_parse_flag(value, &susshi_cfg.client_hostkey_update, "Configuration/ClientHostKeyUpdate");
				} break;

				case sConfigVersion: {
					susshi_cfg_parse_int(value, &susshi_cfg.config_version, "\"Configuration/Version");
				} break;

				case sDnsSearchDomains: {
					json_array_foreach(value, index, element) {
						if (index == MAX_DNS_SEARCH_DOMAINS)
							fatal("Configuration/DnsSearchDomain: Maximal number of DNS domains (%d) exceeded", MAX_DNS_SEARCH_DOMAINS);

						susshi_cfg_parse_bstring(element, &susshi_cfg.dns_searchdomains[index],
												 &susshi_cfg.num_dns_searchdomains, "Configuration/DnsSearchDomain");
					}
				} break;

				case sDebugLevel: {
					int level;

					susshi_cfg_parse_int(value, &level, "\"Configuration/DebugLevel");

					if (level<0)
						level = 0;
					if (level>3)
						level = 3;
					flag_debug = true;

					if (level < (log_level - LOG_LEVEL_INFO)) {
						debug1("Warning Debug level received from Chef (%d) is lower than set globally (%d), thus ignored",
								level, log_level - LOG_LEVEL_INFO);
					} else {
						susshi_cfg.log_level = LOG_LEVEL_INFO + level;

						// Set global log_level
						log_level = susshi_cfg.log_level;
						debug1("Debug log level set to %d", level);
					}
				} break;

				case sDenyTargetAddresses: {
					json_array_foreach(value, index, element) {
						if (index == MAX_DENY_TARGETS)
							fatal("Configuration/DenyTargetAddresses: Maximal number of deny targets (%d) exceeded", MAX_DENY_TARGETS);

						susshi_cfg_parse_bstring(element, &susshi_cfg.deny_targets[index],
												 &susshi_cfg.num_deny_targets, "Configuration/DenyTargetAddresses");
					}
				} break;

				case sSessionLogEncryptionKeys: {
					bstring edkey;

					if (susshi_cfg.num_session_log_encryption_keys > 0) {
						/* Delete old keys when overwriting */
						for (int k = 0; k < susshi_cfg.num_session_log_encryption_keys; k++) {
							bstrFree(susshi_cfg.session_log_encryption_keys[i]);
						}
						susshi_cfg.num_session_log_encryption_keys = 0;
					}

					json_array_foreach(value, index, element) {

						edkey = NULL;

						if (index == MAX_SESSION_LOG_ENCRYPTION_KEYS)
							fatal("Configuration/SessionLogEncryptionKeys: Maximal number of encryption keys (%d) exceeded",
								  MAX_SESSION_LOG_ENCRYPTION_KEYS);

						susshi_cfg_parse_bstring(element, &edkey, NULL, "Configuration/SessionLogEncryptionKeys");

						if (edkey) {
							if (strncmp(bdata(edkey), "ssh-ed25519 ", 12) != 0) {
								bstrFree(edkey);
								fatal("Configuration/SessionLogEncryptionKeys: Key #%zu is not a valid ed25519 public key "
									  "(must start with 'ssh-ed25519 ')", index + 1);
							}
							susshi_cfg.session_log_encryption_keys[index] = edkey;
							susshi_cfg.num_session_log_encryption_keys++;
						}
					}
				} break;

				case sExecLogfileMaxSize: {
					susshi_cfg_parse_long_int(value, &susshi_cfg.logfile_exec_max_size, "Configuration/ExecLogFileMaxSize");
				} break;

				case sEmbryonicGraceTime: {
					susshi_cfg_parse_int(value, &susshi_cfg.embryonic_grace_time, "Configuration/EmbryonicGraceTime");
				} break;

				case sMaxEmbryonics: {
					bstring embryonics = NULL;
					susshi_cfg_parse_bstring(value, &embryonics, NULL, "Configuration/MaxEmbryonics");

					if (embryonics) {
						if ((sscanf(bdata(embryonics), "%d:%d:%d",
										&susshi_cfg.max_embryonics_start,
										&susshi_cfg.max_embryonics_rate,
										&susshi_cfg.max_embryonics)) == 3) {

							if (susshi_cfg.max_embryonics > 200)
								fatal("Configuration/MaxEmbryonics: Embryonics-Max exceeded (> 200)");
							if (susshi_cfg.max_embryonics_start >= susshi_cfg.max_embryonics)
								fatal("Configuration/MaxEmbryonics: Embryonics-Start must be less than Embryonics-Max");
							if ((susshi_cfg.max_embryonics_rate > 100) || (susshi_cfg.max_embryonics_rate < 1))
								fatal("Configuration/MaxEmbryonics: Embryonics-Rate out of boundaries (1-100)");
						} else {
							fatal("Configuration/MaxEmbryonics: Wrong syntax, please specifiy 'Start:Rate:Max'");
						}
						bstrFree(embryonics);
					}
				} break;

				case sExecLogStopPatterns: {
					int pcre_errorcode;
					PCRE2_SIZE pcre_erroffset;

					json_array_foreach(value, index, element) {
						bstring pattern = NULL;
						if (index == MAX_LOG_STOP_PATTERNS)
							fatal("Configuration/ExecLogStopPatterns: Maximal number of stop patterns (%d) exceeded", MAX_LOG_STOP_PATTERNS);

						susshi_cfg_parse_bstring(element, &pattern, NULL, "Configuration/ExecLogStopPatterns");
						susshi_cfg.exec_log_stop_pattern_pcre[index] = pcre2_compile((PCRE2_SPTR)bdata(pattern),
																					PCRE2_ZERO_TERMINATED, 0,
																					&pcre_errorcode,
																					&pcre_erroffset,
																					NULL);
						if (susshi_cfg.exec_log_stop_pattern_pcre[index] != NULL) {
							susshi_cfg.exec_log_stop_pattern[index] = bstrcpy(pattern);
							susshi_cfg.num_exec_log_stop_pattern++;
						} else {
							fatal("Configuration/ExecLogStopPatterns: Error with PCRE pattern #%d", index);
						}
					}
				} break;

				case sHostKeys: {
					const char *type_ptr, *fp_ptr, *pub_ptr, *priv_ptr;
					bstring pub_path = NULL;
					FILE *fp_pub;
					FILE *fp_priv;
					int remove_rc = 0;

					json_array_foreach(value, index, element) {
						if (index == MAX_HOSTKEYS)
							fatal("Configuration/HostKeys: Maximal number of Hostkeys (%d) exceeded", MAX_HOSTKEYS);

						if (susshi_cfg_parse_ssh_key(element, &type_ptr, &fp_ptr, &pub_ptr, &priv_ptr,
													 "Configuration/HostKeys") == true) {
							int fd_priv, fd_pub;

							debug3("Got HostKey from Chef: %s %s ", type_ptr, fp_ptr);
							susshi_cfg.host_key_files[index] = bformat(PATH_SUSSHI_KEYS "/" PREFIX_SUSSHI_HOSTKEYS "%d", index );

							pub_path = bformat("%s.pub", bdata(susshi_cfg.host_key_files[index]));

							fd_priv = open(bdata(susshi_cfg.host_key_files[index]), O_WRONLY|O_CREAT|O_TRUNC, ( S_IRUSR | S_IWUSR ));

							if (fd_priv == -1) {
								int e = errno;
								fatal("Configuration/HostKeys: Could not write key to (cache) file %s as user %s: %s",
									  bdata(susshi_cfg.host_key_files[index]), username(), strerror(e));
							}

							fd_pub = open(bdata(pub_path), O_WRONLY|O_CREAT|O_TRUNC, ( S_IRUSR | S_IWUSR ));

							if (fd_pub == -1) {
								int e = errno;
								fatal("Configuration/HostKeys: Could not write key to (cache) file %s as user %s: %s",
									  bdata(pub_path), username(), strerror(e));
							}

							fp_priv = fdopen(fd_priv, "w");
							fp_pub = fdopen(fd_pub, "w");

							if ((fp_priv) && (fp_pub)) {
								debug3("Saving to file %s and <file>.pub", bdata(susshi_cfg.host_key_files[index]));
								fchmod(fd_priv, S_IRUSR|S_IWUSR);
								fchmod(fd_pub, S_IRUSR|S_IWUSR|S_IRGRP);
								fprintf(fp_priv, "%s", priv_ptr);
								fprintf(fp_pub, "%s", pub_ptr);
								fclose(fp_priv);
								fclose(fp_pub);
								close(fd_priv);
								close(fd_pub);

								/* Import back from file into pubkey list for later use in susshi_hostkeys_update_prove_hostkeys() */
								ssh_pki_import_pubkey_file(bdata(pub_path), &susshi_cfg.host_key_pubs[index]);
								susshi_cfg.host_key_types[index] = ssh_key_type(susshi_cfg.host_key_pubs[index]);
							} else {
								int e = errno;
								fatal("Configuration/HostKeys: Could not write key to (cache) file %s as user: %s",
										bdata(susshi_cfg.host_key_files[index]), strerror(e));
							}

							bstrFree(pub_path);
							susshi_cfg.num_host_key_files++;
						} else {
							fatal("Configuration/HostKeys: Could not parse ssh-key hash");
						}
					}

					// Unlink old files if there are any
					for(u_int n = (u_int) susshi_cfg.num_host_key_files; (n < MAX_HOSTKEYS) && (remove_rc != -1); n++) {
						bstring path = bformat(PATH_SUSSHI_KEYS "/" PREFIX_SUSSHI_HOSTKEYS "%d", n );
						remove(bdata(path));
						bformata(path, ".pub");
						remove_rc = remove(bdata(path));
						if (remove_rc != -1)
							debug3("Removed old host key file with ID %d", n);
						bstrFree(path);
					}

				} break;

				case sInstallationId: {
					susshi_cfg_parse_bstring(value, &susshi_cfg.installation_id, NULL, "Configuration/InstallationId");
				} break;

				case sListenAddresses: {

					// We already have listen sockets, so we will not overwrite with new configuration (e.g. with answer from chef)
					if (susshi_cfg.listen_addrs != NULL)
						continue;

					json_array_foreach(value, index, element) {
						char *p;
						int port;

						string = json_string_value(element);

						if (string == NULL)
							fatal("Configuration/ListenAddresses: No address given.");

						/* check for bare IPv6 address: no "[]" and 2 or more ":" */
						if (strchr(string, '[') == NULL && (p = (char *) strchr(string, ':')) != NULL
							&& strchr(p + 1, ':') != NULL) {
							susshi_cfg_add_listen_addr((char *) string, 0);
							continue;
						}

						p = host_port_delimiter((char **) &string);

						if (p == NULL)
							fatal("Configuration/ListenAddresses: bad address:port usage.");

						p = cleanhostname(p);
						if (string == NULL)
							port = 0;
						else if ((port = a2port(string)) <= 0)
							fatal("Configuration/ListenAddresses: bad port number.");

						susshi_cfg_add_listen_addr(p, port);
					}
				} break;

				case sListenPorts: {

					int port = 0;

					// We already have port configurations, so we will not overwrite with new configuration  (e.g. with answer from chef)
					if (susshi_cfg.num_ports > 0)
						continue;

					/* ignore ports from configfile if cmdline specifies ports */
					if (susshi_cfg.ports_from_cmdline)
						return 0;

					if (susshi_cfg.listen_addrs != NULL)
						fatal("Configuration/ListenPorts: Ports must be specified before ListenAddresses.");

					json_array_foreach(value, index, element) {
						if (index == MAX_PORTS)
							fatal("Configuration/ListenPorts: Maximal number of Ports (%d) exceeded", MAX_PORTS);

						susshi_cfg_parse_int(element, &port, "\"Configuration/ListenPorts");

						if ((port > 21) && (port < 65535)) {
							susshi_cfg.ports[index] = port;
							susshi_cfg.num_ports++;
						} else {
							fatal("Configuration/ListenPorts: Could not read port (is integer?)", MAX_PORTS);
						}
					}
				} break;

				case sLogFacilitySession: {
					susshi_cfg_parse_log_facility(value, (int *) &susshi_cfg.log_facility_session, "Configuration/LogFacilitySession");
				} break;

				case sLogFacilitySystem: {
					susshi_cfg_parse_log_facility(value, (int *) &susshi_cfg.log_facility_system, "Configuration/LogFacilitySystem");
				} break;

				case sLogFileAudit: {
					susshi_cfg_parse_path(value, &susshi_cfg.logfile_audit, NULL, "Configuration/LogFileAudit");
				} break;

				case sLogFileSystem: {
					susshi_cfg_parse_path(value, &susshi_cfg.logfile_system, NULL, "Configuration/LogFileSystem");
				} break;

				case sLogFileSession: {
					susshi_cfg_parse_path(value, &susshi_cfg.logfile_session, NULL, "Configuration/LogFileSession");
				} break;

				case sLoginGraceTime: {
					susshi_cfg_parse_int(value, &susshi_cfg.login_grace_time, "Configuration/LoginGraceTime");
					if ((susshi_cfg.login_grace_time < 3) || (susshi_cfg.login_grace_time > 200))
						fatal("Configuration/LoginGraceTime: specify time value that is between 3 and 200 seconds.");
				} break;

				case sPasswordSplitString: {
					susshi_cfg_parse_bstring(value, &susshi_cfg.password_split_string, NULL, "Configuration/PasswordSplitString");
				} break;

				case sPreferredAuthentications: {
					bstring method = NULL;

					/* In contrast to TargetAuthenticationMethods, the methods specified for Client Authentication can
					 * not be changed in their order but only activated / not activated.
					 */

					susshi_client_auth_disable_all_methods();

					json_array_foreach(value, index, element) {
						susshi_cfg_parse_bstring(element, &method, NULL, "Configuration/PreferredAuthentications");

						if (susshi_client_auth_add_preferred_method(bdata(method))) {
							bstrFree(method);
						} else {
							fatal("Configuration/PreferredAuthentications: Authentication method '%s' unknown.", bdata(method));
						}
					}
				} break;

				case sPreserveClientBanner: {
					susshi_cfg_parse_flag(value, &overwritables->preserve_client_banner, "Configuration/PreserveClientBanner");
				} break;

				case sPublicKeyAlgorithms: {
					if (susshi_cfg.public_key_algorithms) {
						// Overwrite with new values
						bstrFree(susshi_cfg.public_key_algorithms);
						susshi_cfg.public_key_algorithms = NULL;
					}
					json_array_foreach(value, index, element) {
						bstring cipher = NULL;
						susshi_cfg_parse_bstring(element, &cipher, NULL, "Configuration/PublicKeyAlgorithms");
						btolower(cipher);

						if (susshi_cfg.public_key_algorithms) {
							bformata(susshi_cfg.public_key_algorithms, ",");
						} else {
							susshi_cfg.public_key_algorithms = bfromcstr("");
						}
						bformata(susshi_cfg.public_key_algorithms, "%s", bdata(cipher));
						bstrFree(cipher);
					}
				} break;

				case sRenewSic: {
					susshi_cfg_parse_flag(value, &chef_cfg.renew_sic, "Configuration/RenewSic");
				} break;

				case sReportPeriod: {
					susshi_cfg_parse_int(value, &susshi_cfg.report_period, "Configuration/ReportPeriod");
					if ((susshi_cfg.report_period < 30) || (susshi_cfg.report_period > 1800))
						fatal("Configuration/ReportPeriod: specify time value that is between 300 and 1800 seconds.");
				} break;

				case sRemoteControlKey: {
					susshi_cfg_parse_bstring(value, &susshi_cfg.remote_control_ssh_pubkey, NULL, "Configuration/RemoteControlKey");
				} break;


				case sSubscriptionToken: {
					bstring token = NULL;
					SusshiSubscriptionFeatures features;

					susshi_cfg_parse_bstring(value, &token, NULL, "Configuration/SubscriptionToken");

					if (token) {
						if (blength(token) > 0) {
							if (susshi_subscription_verify(bdata(token), &features)) {
								debug4("Configuration/SubscriptionToken: token verification succeeded, subscription features enabled");
							} else {
								error("Configuration/SubscriptionToken: token verification failed, subscription features disabled");
							}
						}
						bstrFree(token);
					}
				} break;


				case sSusshidId: {

					// If we already have a susshid-identifier, we will not overwrite with new configuration  (e.g. with answer from chef)
					if (chef_cfg.susshid_id == NULL) {
						susshi_cfg_parse_bstring(value, &chef_cfg.susshid_id, NULL, "Configuration/SusshidId");
						if (blength(chef_cfg.susshid_id) != 4) {
							fatal("Configuration/SusshidId: Please provide a string with exactly 4 characters.");
						}
					}
				} break;

				case sSyslogGatewayName: {
					susshi_cfg_parse_bstring(value, &susshi_cfg.syslog_gateway_name, NULL, "Configuration/SyslogGatewayName");
				} break;

				case sSyslogTlsCertificate: {
					susshi_cfg_parse_bstring(value, &susshi_cfg.syslog_tls_certificate, NULL, "Configuration/SyslogGatewayCertificate");
				} break;

				case sSyslogTlsKey: {
					susshi_cfg_parse_bstring(value, &susshi_cfg.syslog_tls_key, NULL, "Configuration/SyslogGatewayKey");
				} break;

				case sTargetCiphers: {
					if (overwritables->target_ciphers) {
						// Overwrite with new values
						bstrFree(overwritables->target_ciphers);
						overwritables->target_ciphers = NULL;
					}
					json_array_foreach(value, index, element) {
						bstring cipher = NULL;

						susshi_cfg_parse_bstring(element, &cipher, NULL, "Configuration/TargetCiphers");
						btolower(cipher);

						if (susshi_cfg_lookup_cipher(cipher)) {
							if (overwritables->target_ciphers) {
								bformata(overwritables->target_ciphers, ",");
							} else {
								overwritables->target_ciphers = bfromcstr("");
							}
							bformata(overwritables->target_ciphers, bdata(cipher));
							bstrFree(cipher);
						} else {
							fatal("Configuration/TargetCiphers: Cipher %s unknown", bdata(cipher));
						}
					}
				} break;

				case sTargetConnectionTimeout: {
					susshi_cfg_parse_int(value, &overwritables->target_connection_timeout, "\"Configuration/TargetConnectionTimeout");
				} break;

				case sTargetCompression: {
					susshi_cfg_parse_flag(value, &overwritables->target_compression, "Configuration/TargetCompression");
				} break;

				case sTargetHmacs: {
					if (overwritables->target_hmacs) {
						// Overwrite with new values
						bstrFree(overwritables->target_hmacs);
						overwritables->target_hmacs = NULL;
					}
					json_array_foreach(value, index, element) {
						bstring cipher = NULL;

						susshi_cfg_parse_bstring(element, &cipher, NULL, "Configuration/TargetHmacs");
						btolower(cipher);

						if (overwritables->target_hmacs) {
							bformata(overwritables->target_hmacs, ",");
						} else {
							overwritables->target_hmacs = bfromcstr("");
						}
						bformata(overwritables->target_hmacs, bdata(cipher));
						bstrFree(cipher);
					}
				} break;

				case sTargetHostkeyAlgorithms: {
					if (overwritables->target_hostkey_algorithms) {
						// Overwrite with new values
						bstrFree(overwritables->target_hostkey_algorithms);
						overwritables->target_hostkey_algorithms = NULL;
					}
					json_array_foreach(value, index, element) {
						bstring cipher;

						susshi_cfg_parse_bstring(element, &cipher, NULL, "Configuration/TargetHostkeyAlgorithms");
						btolower(cipher);

						if (overwritables->target_hostkey_algorithms) {
							bformata(overwritables->target_hostkey_algorithms, ",");
						} else {
							overwritables->target_hostkey_algorithms = bfromcstr("");
						}
						bformata(overwritables->target_hostkey_algorithms, bdata(cipher));
						bstrFree(cipher);
					}
				} break;

				case sTargetKexAlgorithms: {
					if (overwritables->target_kex_algorithms) {
						// Overwrite with new values
						bstrFree(overwritables->target_kex_algorithms);
						overwritables->target_kex_algorithms = NULL;
					}
					json_array_foreach(value, index, element) {
						bstring cipher = NULL;

						susshi_cfg_parse_bstring(element, &cipher, NULL, "Configuration/TargetKexAlgorithms");
						btolower(cipher);

						if (overwritables->target_kex_algorithms) {
							bformata(overwritables->target_kex_algorithms, ",");
						} else {
							overwritables->target_kex_algorithms = bfromcstr("");
						}
						bformata(overwritables->target_kex_algorithms, bdata(cipher));
						bstrFree(cipher);
					}
				} break;

				case sTargetIdentityKeys: {
					const char *type_ptr, *fp_ptr, *pub_ptr, *priv_ptr;

					susshi_cfg.num_target_identities = 0;

					json_array_foreach(value, index, element) {
						if (index == MAX_USERKEYS)
							fatal("Configuration/TargetIdentityKeys: Maximal number of user-keys (%d) exceeded", MAX_USERKEYS);

						if (susshi_cfg_parse_ssh_key(element, &type_ptr, &fp_ptr, &pub_ptr, &priv_ptr,
													 "Configuration/HostKeys") == true) {
							debug3("Got Target Identity Key from Chef: %s %s ", type_ptr, fp_ptr);

							susshi_cfg.target_identities[index].key_type = bfromcstr(type_ptr);
							susshi_cfg.target_identities[index].fingerprint = bfromcstr(fp_ptr);
							susshi_cfg.target_identities[index].public_blob = bfromcstr(pub_ptr);
							susshi_cfg.target_identities[index].private_blob = bfromcstr(priv_ptr);
							susshi_cfg.num_target_identities++;
						} else {
							fatal("Configuration/TargetIdentityKeys: Could not parse ssh-key hash");
						}
					}
				} break;

				case sTargetPassSusshiInformation: {
					susshi_cfg_parse_flag(value, &susshi_cfg.send_shell_env, "Configuration/TargetPassSusshiInformation");
				} break;

				case sTargetPreferredAddressFamily: {
					susshi_cfg_parse_af(value, &overwritables->target_preferred_address_family, "Configuration/TargetPreferredAddressFamily");
				} break;

				case sTargetProxies: {
					const char *hostname_ptr, *realm_ptr;
					int ret, port;

					susshi_cfg.num_target_proxies = 0;

					json_array_foreach(value, index, element) {
						if (index == MAX_PROXIES)
							fatal("Configuration/TargetProxies: Maximal number of user-keys (%d) exceeded", MAX_USERKEYS);

						if (json_is_object(element)) {

							ret = json_unpack(element, "{s:s s:s s:i}",
											  "realm", &realm_ptr,
											  "hostname", &hostname_ptr,
											  "port", &port);

							if (ret == 0) {
								susshi_cfg.target_proxies[index].realm = bfromcstr(realm_ptr);
								susshi_cfg.target_proxies[index].hostname = bfromcstr(hostname_ptr);
								susshi_cfg.target_proxies[index].port = port;
								susshi_cfg.num_target_proxies++;
							} else {
								fatal("Configuration/TargetProxies: Could not parse proxies hash");
							}
						}
					}
				} break;

				case sTargetPreferredAuthentications: {
					bstring method = NULL;
					int m;
					// Reset to null, so we can receive it multiple times and overwrite what we've learned before
					overwritables->num_target_preferred_authentications = 0;

					json_array_foreach(value, index, element) {
						if (index == MAX_PREFAUTHS)
							fatal("Configuration/TargetPreferredAuthentications: Maximal number of preferred authentications (%d) exceeded", MAX_PREFAUTHS);

						susshi_cfg_parse_bstring(element, &method, NULL, "Configuration/TargetPreferredAuthentications");

						if ((m = susshi_target_auth_find_method(method)) > -1) {
							overwritables->target_preferred_authentications[index] = m;
							overwritables->num_target_preferred_authentications++;
						} else {
							fatal("Configuration/TargetPreferredAuthentications: Authentication method '%s' unknown.", bdata(method));
						}
						bstrFree(method);
					}
				} break;

				case sTargetTcpKeepAlive: {
					susshi_cfg_parse_flag(value, &overwritables->target_tcp_keep_alive, "Configuration/TargetTcpKeepAlive");
				} break;

				case sVerboseDisconnect: {
					susshi_cfg_parse_flag(value, &susshi_cfg.verbose_disconnect, "Configuration/VerboseDisconnect");
				} break;

				case _sSkipOpcode: {
					debug3("Configuration/%s: Skipped, has already been set locally", key);
				} break;

				case _sContextMissmatch: {
					debug3("Configuration/%s: Not allowed in this context", key);
				} break;

				case _sBadOption:
				default: {
					debug3("Configuration: Unknown key %s", key);
				}
			}
		}
	}

	if (current_context == CONTEXT_GLOBAL) {
		susshi_cfg_copy_global_cfg_to_session();
		json_decref(object);
	}

	return true;
}


/*!
 * @brief       Load and parse susshid configuration file
 *
 * @param       filename        Path to json file
 */

void
susshi_cfg_load_configfile(const char *filename)
{
	json_t *document;
	json_error_t json_error;

	document = json_load_file(filename, 0, &json_error);

	if (document) {
		char path[PATH_MAX];
		// Under Linux dirname() writes to argument !!! So we make a copy of argument first
		if (strlcpy(path, filename, sizeof(path)) >= sizeof(path))
			fatal("Configuration file path too long: %s", filename);
		susshi_cfg.config_path = bfromcstr(susshi_cfg_derelativise_path(dirname(path)));
		susshi_cfg_read_json(document, CONTEXT_GLOBAL);
	} else {
		fatal("Error loading configuration file %s: %s", filename, json_error.text);
	}
}


/*!
 * @brief       Lookup function used by susshi_cfg_dump_* methods
 *
 * @param       code        SusshiCfgOpCodes code
 *
 * @return      String of given code
 */

static const char *
susshi_cfg_lookup_opcode_name(SusshiCfgOpCodes code) {
	u_int i;

	for (i = 0; keywords[i].name != NULL; i++)
		if (keywords[i].opcode == code)
			return (keywords[i].name);
	return "UNKNOWN";
}


/*!
 * @brief       Derelativise file path
 *
 * @param       path    Given file path
 *
 * @return      Derelativated file path
 */

static char *
susshi_cfg_derelativise_path(const char *path) {
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
 * @param       addr        Address string
 * @param       port        Port
 */

static void
susshi_cfg_add_one_listen_addr(char *addr, int port) {
	struct addrinfo hints, *ai, *aitop;
	char strport[NI_MAXSERV];
	int gaierr;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = susshi_cfg.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == NULL) ? AI_PASSIVE : 0;
	snprintf(strport, sizeof strport, "%d", port);
	if ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)", addr ? addr : "<NULL>", gai_strerror(gaierr));
	for (ai = aitop; ai->ai_next; ai = ai->ai_next);
	ai->ai_next = susshi_cfg.listen_addrs;
	susshi_cfg.listen_addrs = aitop;
}


/*!
 * @brief       For each listen port, add a listen address to configuration
 *
 * @param       addr        Address string
 * @param       port        Port
 */

void
susshi_cfg_add_listen_addr(char *addr, int port) {
	u_int i;

	if (susshi_cfg.num_ports == 0)
		susshi_cfg.ports[susshi_cfg.num_ports++] = SSH_DEFAULT_PORT;
	if (susshi_cfg.address_family == -1)
		susshi_cfg.address_family = AF_UNSPEC;
	if (port == 0)
		/* Listen address without port --> add address for all ports in configuration */
		for (i = 0; i < susshi_cfg.num_ports; i++)
			susshi_cfg_add_one_listen_addr(addr, susshi_cfg.ports[i]);
	else
		/* Specific listen address with port */
		susshi_cfg_add_one_listen_addr(addr, port);
}


/*!
 * @brief       Return bstring with comma separated list of all ciphers we allow in code
 *
 * @return      Comma separated list of all ciphers we allow in code
 */

static bstring
susshi_cfg_all_ciphers(void) {
	int i;
	bstring ciphers = bfromcstr("");

	for(i=0; supported_ciphers[i]; i++) {
		bformata(ciphers, "%s", supported_ciphers[i]);
		if (supported_ciphers[i+1] != NULL)
			bformata(ciphers, ",");
	}
	return ciphers;
}


/*!
 * @brief       Lookup cipher and return true if valid
 *
 * @param       cipher  Cipher
 * @return      true if valid
 */

bool
susshi_cfg_lookup_cipher(bstring cipher) {
	int i;
	bstring str = NULL;

	for(i=0; supported_ciphers[i] != NULL; i++) {
		str = bfromcstr(supported_ciphers[i]);
		if (bstrcmp(cipher, str) == 0) {
			bstrFree(str);
			return true;
		} else {
			bstrFree(str);
		}
	}
	return false;
}


/*!
 * @brief       Dump configuration value of type Integer
 *
 * @param       code    SusshiCfgOpCodes code
 * @param       val     Integer value
 */

static void
susshi_cfg_dump_cfg_int(SusshiCfgOpCodes code, int val) {
	debug3("Config %s: %d", susshi_cfg_lookup_opcode_name(code), val);
}


/*!
 * @brief       Dump configuration value of type Long Integer
 *
 * @param       code    SusshiCfgOpCodes code
 * @param       val     Long Integer value
 */

static void
susshi_cfg_dump_cfg_long_int(SusshiCfgOpCodes code, long int val) {
	debug3("Config %s: %ld", susshi_cfg_lookup_opcode_name(code), val);
}


/*!
 * @brief       Format configuration value of type Integer into AF or Flag
 *
 * @param       code    SusshiCfgOpCodes code
 * @param       val     Integer value
 */

static void
susshi_cfg_dump_cfg_af(SusshiCfgOpCodes code, int val) {
	const char *result = "UNKNOWN";

	switch (val) {
		case AF_INET:
			result = "inet";
			break;
		case AF_INET6:
			result = "inet6";
			break;
		case AF_UNSPEC:
			result = "any";
			break;
	}

	debug3("Config %s: %s", susshi_cfg_lookup_opcode_name(code), result);
}


/*!
 * @brief       Dump configuration value of type Integer as AF or Flag
 *
 * @param       code    SusshiCfgOpCodes code
 * @param       val     Integer value
 */

static void
susshi_cfg_dump_cfg_flag(SusshiCfgOpCodes code, int val) {
	const char* result = "UNKNOWN";

	switch (val) {
		case -1:
			result = "unset";
			break;
		case 0:
			result = "no";
			break;
		case 1:
			result = "yes";
			break;
	}

	debug3("Config %s: %s", susshi_cfg_lookup_opcode_name(code), result);
}


/*!
 * @brief       Dump configuration value of type String
 *
 * @param       code    SusshiCfgOpCodes code
 * @param       val     String value
 */

static void
susshi_cfg_dump_cfg_string(SusshiCfgOpCodes code, const char *val) {
	if (val == NULL)
		return;
	debug3("Config %s: %s", susshi_cfg_lookup_opcode_name(code), val);
}


/*!
 * @brief       Dump configuration value of type Array of bstrings
 *
 * @param       code    SusshiCfgOpCodes code
 * @param       count   Number of elements
 * @param       vals    bstring values
 */

static void
susshi_cfg_dump_cfg_bstrarray(SusshiCfgOpCodes code, int count, bstring *vals) {
	for (int i = 0; i < count; i++)
		debug3("Config %s: %s", susshi_cfg_lookup_opcode_name(code), bdata(vals[i]));
}


/*!
 * @brief       Dump configuration
 *
 * @param       current_context     CONTEXT_GLOBAL or CONTEXT_SESSION
 */

void
susshi_cfg_dump_config(SusshiCfgContext current_context) {
	u_int i;
	int ret;
	struct addrinfo *ai;
	char addr[NI_MAXHOST], port[NI_MAXSERV];
	OverwritableSettings *overwritables;

	if (current_context == CONTEXT_SESSION) {
		overwritables = &susshi_cfg.session;
	} else {
		overwritables = &susshi_cfg.global;
	}

	susshi_cfg_dump_cfg_af(sAddressFamily, susshi_cfg.address_family);
	susshi_cfg_dump_cfg_string(sBanner, bdata(susshi_cfg.banner));
	susshi_cfg_dump_cfg_string(sChefCaPath, bdata(chef_cfg.chef_ca_file));
	susshi_cfg_dump_cfg_string(sChefCertificatePath, bdata(chef_cfg.chef_certificate_file));
	susshi_cfg_dump_cfg_string(sChefPsk, bdata(chef_cfg.sic_psk_memcrypt));
	susshi_cfg_dump_cfg_string(sChefSpki, bdata(chef_cfg.sic_spki));

	for (int s = 0; s < chef_cfg.chef_server_urls.num_all; s++)
		debug3("Config ChefServerUrls/default (meta): %s", bdata(chef_cfg.chef_server_urls.all[s]));

	for (int s = 0; s < chef_cfg.chef_server_urls.num_gateway; s++)
		debug3("Config ChefServerUrls/gateway: %s", bdata(chef_cfg.chef_server_urls.gateway[s]));

	for (int s = 0; s < chef_cfg.chef_server_urls.num_report; s++)
		debug3("Config ChefServerUrls/report: %s", bdata(chef_cfg.chef_server_urls.report[s]));

	for (int s = 0; s < chef_cfg.chef_server_urls.num_session; s++)
		debug3("Config ChefServerUrls/session: %s", bdata(chef_cfg.chef_server_urls.session[s]));

	susshi_cfg_dump_cfg_string(sChefVersion, bdata(chef_cfg.chef_version));
	debug3("Config ChefVersion (uint32): %d", chef_cfg.chef_version_uint32);
	susshi_cfg_dump_cfg_string(sClientCiphers, bdata(susshi_cfg.client_ciphers));
	susshi_cfg_dump_cfg_string(sClientHmacs, bdata(susshi_cfg.client_hmacs));
	susshi_cfg_dump_cfg_flag(sClientCompression, susshi_cfg.client_compression);
	susshi_cfg_dump_cfg_string(sClientHostkeyAlgorithms, bdata(susshi_cfg.client_hostkey_algorithms));
	susshi_cfg_dump_cfg_flag(sClientHostKeyUpdate, susshi_cfg.client_hostkey_update);
	susshi_cfg_dump_cfg_string(sClientKexAlgorithms, bdata(susshi_cfg.client_kex_algorithms));
	susshi_cfg_dump_cfg_flag(sClientTcpKeepAlive, susshi_cfg.client_tcp_keep_alive);

	susshi_cfg_dump_cfg_string(sClientGatewayAuthInstruction, bdata(susshi_cfg.client_gateway_auth_instruction));
	susshi_cfg_dump_cfg_string(sClientGatewayAuthPrompt, bdata(susshi_cfg.client_gateway_auth_prompt));
	susshi_cfg_dump_cfg_string(sClientGatewayAuthTitle, bdata(susshi_cfg.client_gateway_auth_title));

	susshi_cfg_dump_cfg_bstrarray(sDenyTargetAddresses, susshi_cfg.num_deny_targets, susshi_cfg.deny_targets);
	susshi_cfg_dump_cfg_bstrarray(sDnsSearchDomains, susshi_cfg.num_dns_searchdomains, susshi_cfg.dns_searchdomains);
	susshi_cfg_dump_cfg_bstrarray(sSessionLogEncryptionKeys, susshi_cfg.num_session_log_encryption_keys, susshi_cfg.session_log_encryption_keys);

	susshi_cfg_dump_cfg_long_int(sExecLogfileMaxSize, susshi_cfg.logfile_exec_max_size);
	susshi_cfg_dump_cfg_bstrarray(sExecLogStopPatterns, susshi_cfg.num_exec_log_stop_pattern, susshi_cfg.exec_log_stop_pattern);

	susshi_cfg_dump_cfg_bstrarray(sHostKeys, susshi_cfg.num_host_key_files, susshi_cfg.host_key_files);
	susshi_cfg_dump_cfg_string(sInstallationId, bdata(susshi_cfg.installation_id));

	for (ai = susshi_cfg.listen_addrs; ai; ai = ai->ai_next) {
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

	for (i = 0; i < susshi_cfg.num_ports; i++)
		debug3("Config ListenPort: %d", susshi_cfg.ports[i]);

	susshi_cfg_dump_cfg_int(sLoginGraceTime, susshi_cfg.login_grace_time);
	susshi_cfg_dump_cfg_string(sLogFacilitySystem, log_facility_name(susshi_cfg.log_facility_system));
	susshi_cfg_dump_cfg_string(sLogFacilitySession, log_facility_name(susshi_cfg.log_facility_session));
	susshi_cfg_dump_cfg_string(sLogFileAudit, bdata(susshi_cfg.logfile_audit));
	susshi_cfg_dump_cfg_string(sLogFileSession, bdata(susshi_cfg.logfile_session));
	susshi_cfg_dump_cfg_string(sLogFileSystem, bdata(susshi_cfg.logfile_system));
	susshi_cfg_dump_cfg_string(sLastLogFile, bdata(susshi_cfg.logfile_last));
	susshi_cfg_dump_cfg_string(sPasswordSplitString, bdata(susshi_cfg.password_split_string));
	susshi_cfg_dump_cfg_string(sPublicKeyAlgorithms, bdata(susshi_cfg.public_key_algorithms));

	if (chef_cfg.renew_sic)
		debug3("Config RenewSic: <received>");

	susshi_cfg_dump_cfg_int(sReportPeriod, susshi_cfg.report_period);
	susshi_cfg_dump_cfg_string(sSusshidId, bdata(chef_cfg.susshid_id));
	susshi_cfg_dump_cfg_string(sSyslogGatewayName, bdata(susshi_cfg.syslog_gateway_name));
	susshi_cfg_dump_cfg_string(sSyslogTlsCertificate, (susshi_cfg.syslog_tls_certificate == NULL ? "-" : "(received)"));
	susshi_cfg_dump_cfg_string(sSyslogTlsKey, (susshi_cfg.syslog_tls_key== NULL ? "-" : "(received)"));

	susshi_cfg_dump_cfg_string(sTargetCiphers, bdata(overwritables->target_ciphers));
	susshi_cfg_dump_cfg_string(sTargetHmacs, bdata(overwritables->target_hmacs));
	susshi_cfg_dump_cfg_flag(sTargetCompression, overwritables->target_compression);
	susshi_cfg_dump_cfg_string(sTargetHostkeyAlgorithms, bdata(overwritables->target_hostkey_algorithms));
	susshi_cfg_dump_cfg_string(sTargetKexAlgorithms, bdata(overwritables->target_kex_algorithms));
	susshi_cfg_dump_cfg_flag(sTargetPassSusshiInformation, susshi_cfg.send_shell_env);

	for (i = 0; i < (u_int) susshi_cfg.num_target_identities; i++)
		debug3("Config TargetIdentityKeys: (%d) %s %s", i + 1, bdata(susshi_cfg.target_identities[i].key_type),
			   bdata(susshi_cfg.target_identities[i].fingerprint));

	susshi_cfg_dump_cfg_af(sTargetPreferredAddressFamily, overwritables->target_preferred_address_family);

	for (i = 0; i < overwritables->num_target_preferred_authentications; i++) {
		debug3("Config TargetPreferredAuthentications: (%d) %s", i + 1,
			   target_auth_methods[overwritables->target_preferred_authentications[i]].alias);
	}

	for (i = 0; i < (u_int) susshi_cfg.num_target_proxies; i++)
		debug3("Config TargetProxies: (%d) @%s -> %s:%d", i + 1, bdata(susshi_cfg.target_proxies[i].realm),
			   bdata(susshi_cfg.target_proxies[i].hostname), susshi_cfg.target_proxies[i].port);

	susshi_cfg_dump_cfg_flag(sTargetTcpKeepAlive, overwritables->target_tcp_keep_alive);

	susshi_cfg_dump_cfg_flag(sVerboseDisconnect, susshi_cfg.verbose_disconnect);

	susshi_cfg_dump_cfg_int(sEmbryonicGraceTime, susshi_cfg.embryonic_grace_time);

	debug3("Config MaxEmbryonics/Start: %d", susshi_cfg.max_embryonics_start);
	debug3("Config MaxEmbryonics/Rate: %d%%", susshi_cfg.max_embryonics_rate);
	debug3("Config MaxEmbryonics/Max: %d", susshi_cfg.max_embryonics);
}

/*!
 * @brief       Copy global parameters into session parameters
 */

void
susshi_cfg_copy_global_cfg_to_session(void) {
	/* On session context, copy global parameters to session parameters */
	bstrFree(susshi_cfg.session.target_ciphers);
	bstrFree(susshi_cfg.session.target_hmacs);
	bstrFree(susshi_cfg.session.target_hostkey_algorithms);
	bstrFree(susshi_cfg.session.target_kex_algorithms);

	memcpy(&susshi_cfg.session, &susshi_cfg.global, sizeof(OverwritableSettings));

	if (susshi_cfg.global.target_ciphers != NULL) {
		susshi_cfg.session.target_ciphers = bstrcpy(susshi_cfg.global.target_ciphers);
	}

	if (susshi_cfg.global.target_hmacs != NULL) {
		susshi_cfg.session.target_hmacs = bstrcpy(susshi_cfg.global.target_hmacs);
	}

	if (susshi_cfg.global.target_hostkey_algorithms != NULL) {
		susshi_cfg.session.target_hostkey_algorithms = bstrcpy(susshi_cfg.global.target_hostkey_algorithms);
	}

	if (susshi_cfg.global.target_kex_algorithms != NULL) {
		susshi_cfg.session.target_kex_algorithms = bstrcpy(susshi_cfg.global.target_kex_algorithms);
	}

}

/*! @} */
