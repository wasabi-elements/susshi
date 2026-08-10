/*!
 *
 * @brief       Chef Communication
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
 * @author      Jens Krabbenhoeft <jens@susshi.io>
 * @date        2026-02-01
 *
 * @ingroup     chef
 * @{
 */


#ifndef SUSSHI_CHEF_H
#define SUSSHI_CHEF_H

#define CHEF_REST_API_VERSION               "v1"
#define CHEF_REST_API_PATH                  "/api/" CHEF_REST_API_VERSION
#define CHEF_REST_GATEWAYS_REGISTER         CHEF_REST_API_PATH "/gateways/register.json"
#define CHEF_REST_GATEWAYS_SIC		        CHEF_REST_API_PATH "/gateways/sic.json"
#define CHEF_REST_CONTEXTS                  CHEF_REST_API_PATH "/sessions/context.json"
#define CHEF_REST_USER_INTERACTIVE          CHEF_REST_API_PATH "/users/interactive.json"
#define CHEF_REST_USER_IP_CACHE             CHEF_REST_API_PATH "/users/ip_cache.json"
#define CHEF_REST_TARGET_HOSTKEY_CREATE		CHEF_REST_API_PATH "/target_hostkeys/create.json"
#define CHEF_REST_TARGET_HOSTKEY_UPDATE		CHEF_REST_API_PATH "/target_hostkeys/update.json"
#define CHEF_REST_REPORTS_SESSIONS          CHEF_REST_API_PATH "/reports/sessions.json"

typedef enum {
	CHEF_REST_METHOD_CREATE,
	CHEF_REST_METHOD_UPDATE
} ChefMethod;

typedef struct {
	const char *key;
	bstring value;
} HttpParameters;

typedef struct {
	bstring   susshid_id;                                   // Uniq Identifier used for this susshid instance (host / container)
	bstring	  sic_psk_memcrypt;								// PSK memcrypt encrypted
	bstring	  sic_spki;								        // SPKI to prevent man-in-the-middle as long we do not have the CA downloaded
	int		  renew_sic;			                        // Set to 1 if a sic renewal is requested by chef

	// List of Chef-Servers
	struct {
		bstring all[MAX_CHEFS];                           // Default, used as fallback
		bstring gateway[MAX_CHEFS];                       // Gateway registration
		bstring session[MAX_CHEFS];                       // Session (PDP)
		bstring report[MAX_CHEFS];                        // Reporting

		int num_all;
		int num_gateway;
		int num_session;
		int num_report;

		bool all_given;
	} chef_server_urls;

	bstring  chef_ca_file;                                  // Path of PEM CA Certificate file (.pem)
	bstring  chef_certificate_file;                         // Path of PKCS12 Certificate file (.p12)
	bstring  chef_version;                                  // suSSHi Chef Version string, i.e. "26.2.1"
	uint32_t chef_version_uint32;                           // suSSHi Chef Version in form of YYMMRR, i.e. 260201
} ChefCfg;

extern ChefCfg chef_cfg;

/* Prototypes */

void chef_cfg_init(void);
void chef_cfg_free(void);
void chef_cfg_fill_server_urls(void);
bool susshi_chef_init(u_int startup_wait, u_int retry, u_int retry_wait);
bool susshi_chef_refresh_chef_relation(u_int wait, u_int retry, u_int retry_wait);

long susshi_chef_json_post(const char *chef_type, bstring *chef_urls, int num_chef_urls, const char *rest_urn,
						   json_t **json_t, HttpParameters *http_parameters, int num_parameters, bool with_client_certificate);
bool susshi_chef_get_session_context(void);
bool susshi_chef_session_check_context_contains_target(void);
bool susshi_chef_session_context_for_target(void);
bool susshi_chef_lookup_proxy(void);

enum ssh_auth_state_e susshi_chef_authn_interactive(bstring password);
bool susshi_chef_authn_verify_pubkey_original(ssh_key key);
bool susshi_chef_authn_verify_pubkey(ssh_key key, const char *key_base64);
bstring susshi_chef_target_hostkey_types(bstring hostip);
KeyVerifyResponse susshi_chef_verify_target_hostkey(ssh_key key, bstring hostip);
bool susshi_chef_upload_target_hostkey(ChefMethod method, bstring target_ip, int target_port, ssh_key hostkey);
bool susshi_chef_upload_report(bstring reports);
bool susshi_chef_create_client_auth_cache(void);
size_t susshi_chef_curlwritefn(void *contents, size_t size, size_t nmemb, void *userp);

AclState susshi_chef_authz_acl_string(const char *attrib, const char *value);
AclState susshi_chef_authz_acl_regex(const char *attrib, const char *value, bool first_match);
AclState susshi_chef_authz_acl_socket(const char *key, const char *host, u_int port);
AclState susshi_chef_authz_acl_bool(const char *key, bool value);

#endif //SUSSHI_CHEF_H

/*! @} */
