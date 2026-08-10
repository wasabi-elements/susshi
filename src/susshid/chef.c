/*!
 *
 * @brief       Chef Communication
 *              Functions handling Communication from susshid to chef
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
 * @author      Jens Krabbenhoeft <jens@susshi.io>
 * @date        2026-02-01
 *
 * @defgroup    chef Chef Communication
 * @{
 */

#include <susshid/common.h>

ChefCfg chef_cfg;

/*!
 * @brief       Initialize chef_cfg variable
 */

void
chef_cfg_init(void) {
	memset(&chef_cfg, 0, sizeof(chef_cfg));
}


/*!
 * @brief       Free chef_cfg allocated memory (strings etc.) and wipe
 */

void
chef_cfg_free(void) {
	if (chef_cfg.susshid_id)
		bstrFree(chef_cfg.susshid_id);

	if (chef_cfg.sic_psk_memcrypt)
		bstrWipe(chef_cfg.sic_psk_memcrypt);

	if (chef_cfg.sic_spki)
		bstrFree(chef_cfg.sic_spki);

	if (chef_cfg.chef_ca_file)
		bstrFree(chef_cfg.chef_ca_file);

	if (chef_cfg.chef_certificate_file)
		bstrFree(chef_cfg.chef_certificate_file);

	if (chef_cfg.chef_version)
		bstrFree(chef_cfg.chef_version);

	for (int i = 0; i < MAX_CHEFS; i++) {
		if (chef_cfg.chef_server_urls.all[i])
			bstrFree(chef_cfg.chef_server_urls.all[i]);
		if (chef_cfg.chef_server_urls.gateway[i])
			bstrFree(chef_cfg.chef_server_urls.gateway[i]);
		if (chef_cfg.chef_server_urls.session[i])
			bstrFree(chef_cfg.chef_server_urls.session[i]);
		if (chef_cfg.chef_server_urls.report[i])
			bstrFree(chef_cfg.chef_server_urls.report[i]);
	}

	memset(&chef_cfg, 0, sizeof(chef_cfg));
}


/*!
 * @brief       Fill gateway/session/report chef URLs from default "all" URL if not individually set
 */

void
chef_cfg_fill_server_urls(void) {
	int i = 0;

	if (chef_cfg.chef_server_urls.num_gateway == 0) {
		for (i = 0; i < chef_cfg.chef_server_urls.num_all; i++)
			chef_cfg.chef_server_urls.gateway[i] = chef_cfg.chef_server_urls.all[i];
		chef_cfg.chef_server_urls.num_gateway = chef_cfg.chef_server_urls.num_all;
	}

	if (chef_cfg.chef_server_urls.num_session == 0) {
		for (i = 0; i < chef_cfg.chef_server_urls.num_all; i++)
			chef_cfg.chef_server_urls.session[i] = chef_cfg.chef_server_urls.all[i];
		chef_cfg.chef_server_urls.num_session = chef_cfg.chef_server_urls.num_all;
	}

	if (chef_cfg.chef_server_urls.num_report == 0) {
		for (i = 0; i < chef_cfg.chef_server_urls.num_all; i++)
			chef_cfg.chef_server_urls.report[i] = chef_cfg.chef_server_urls.all[i];
		chef_cfg.chef_server_urls.num_report = chef_cfg.chef_server_urls.num_all;
	}

	if ((chef_cfg.chef_server_urls.num_gateway > 0) &&
		(chef_cfg.chef_server_urls.num_session > 0) &&
		(chef_cfg.chef_server_urls.num_report > 0)) {
		chef_cfg.chef_server_urls.all_given = true;
	}
}


/*!
 * @brief       "key" in JSON returned from Chef and check for string match in array
 *
 * @param       key         Lookup key
 * @param       cvalue      String value
 *
 * @return      AclState value
 */

AclState
susshi_chef_authz_acl_string(const char *key, const char *cvalue) {
	AclState ret = SUSSHI_ACL_DENY;
	json_t *obj;
	bstring value = bfromcstr(cvalue);

	if (json_unpack(susshi_session.session_context, "{s{s{s?o}}}", "Target",
					susshi_session.target_connected_by_fqdn ? bdata(susshi_session.target_host_resolved) : bdata(
							susshi_session.target_ip), key, &obj) == 0) {
		if (json_is_array(obj)) {
			for (size_t i = 0; i < json_array_size(obj); i++) {
				json_t *elem;
				elem = json_array_get(obj, i);
				if (json_is_string(elem)) {
					if (biseqcstr(value, json_string_value(elem))) {
						ret = SUSSHI_ACL_ALLOW;
					}
				}
			}
			json_decref(obj);
		}
		bstrFree(value);
	}
	return ret;
}


/*!
 * @brief       Find "key" in JSON returned from Chef and check for regex match in array
 *
 * @param       key             Lookup key
 * @param       cvalue          String value
 * @param       on_first_match  If set to true, abort after first check even if no match
 *
 * @return      AclState value
 */

AclState
susshi_chef_authz_acl_regex(const char *key, const char *cvalue, bool on_first_match) {
	AclState ret = SUSSHI_ACL_DENY;
	pcre2_code *re;
	int errorcode;
	PCRE2_SIZE erroffset;
	size_t index;
	json_t *obj, *element;

	if (json_unpack(susshi_session.session_context, "{s{s{s?o}}}", "Target",
					susshi_session.target_connected_by_fqdn ? bdata(susshi_session.target_host_resolved) :
					bdata(susshi_session.target_ip), key, &obj) == 0) {
		if (json_is_array(obj)) {
			json_array_foreach(obj, index, element) {
				if (json_is_string(element)) {
					int rc;

					re = pcre2_compile((PCRE2_SPTR)json_string_value(element), PCRE2_ZERO_TERMINATED, 0, &errorcode, &erroffset, NULL);
					if (re == NULL) {
						if (on_first_match)
							break;
						continue;
					}
					{
						pcre2_match_data *md = pcre2_match_data_create_from_pattern(re, NULL);
						rc = (md != NULL) ? pcre2_match(re, (PCRE2_SPTR)cvalue, strlen(cvalue), 0, 0, md, NULL) : -1;
						pcre2_match_data_free(md);
					}
					pcre2_code_free(re);
					if (rc < 0) {
						if (on_first_match)
							break;
					} else {
						ret = SUSSHI_ACL_ALLOW;
						break;
					}
				}
			}
		}
	}
	return ret;
}


/*!
 * @brief       Find "key" in JSON returned from Chef and check for host and port match in array
 *
 * @param       key     Lookup key
 * @param       host    Host
 * @param       port    Port
 *
 * @return      AclState value
 */

AclState
susshi_chef_authz_acl_socket(const char *key, const char *host, u_int port) {
	AclState ret = SUSSHI_ACL_DENY;
	json_t *obj;

	struct in6_addr ipv6_in_addr;
	struct in_addr ip_in_addr;
	char store_ip[INET6_ADDRSTRLEN];
	const char *ipstr = store_ip;

	/* Normalize IP address */

	if (inet_pton(AF_INET, host, &ip_in_addr) == 1) {
		/* IPv4 */
		inet_ntop(AF_INET, &ip_in_addr, store_ip, INET6_ADDRSTRLEN);
	} else if (inet_pton(AF_INET6, host, &ipv6_in_addr) == 1) {
		/* IPv6 */
		inet_ntop(AF_INET6, &ipv6_in_addr, store_ip, INET6_ADDRSTRLEN);
	} else {
		/* Keep string as provided */
		ipstr = host;
	}

	if (json_unpack(susshi_session.session_context, "{s{s{s?o}}}", "Target",
					susshi_session.target_connected_by_fqdn ? bdata(susshi_session.target_host_resolved) : bdata(
							susshi_session.target_ip), key, &obj) == 0) {
		if (json_is_array(obj)) {
			for (size_t i = 0; (i < json_array_size(obj)) && (ret == SUSSHI_ACL_DENY); i++) {
				json_t *elem;
				elem = json_array_get(obj, i);
				if (json_is_string(elem)) {
					bstring chef_str = bfromcstr(json_string_value(elem));
					bstrList split_chef_str = NULL;
					bool host_match = false;

					split_chef_str = bsplit(chef_str, '|');

					if (split_chef_str->qty == 2) {

						/* Match Host/IP Part */
						if (susshi_session.operation_mode == OP_MODE_BASTION) {
							// Bastion mode
							if ((strcmp(ipstr, "localhost") == 0) ||
								(strncmp(ipstr, "127", 3) == 0)) {
								host_match = false;
							} else if (biseqcstr(split_chef_str->entry[0], "*")) {
								host_match = true;
							} else if (biseqcstr(split_chef_str->entry[0], ipstr)) {
								host_match = true;
							}
						} else {
							// Gateway mode
							if (biseqcstr(split_chef_str->entry[0],"*")) {
								host_match = true;
							} else if (biseqcstr(split_chef_str->entry[0],"localhost")) {
								if ((strcmp(ipstr, "localhost") == 0) ||
									(strcmp(ipstr, "127.0.0.1") == 0) ||
									(strcmp(ipstr, "::1") == 0)) {
									host_match = true;
								}
							} else if (biseqcstr(split_chef_str->entry[0], ipstr)) {
								host_match = true;
							}
						}

						/* Match Port Part */
						if (host_match) {
							if (biseqcstr(split_chef_str->entry[1], "*")) {
								ret = SUSSHI_ACL_ALLOW;
							} else {
								bstring port_str = bformat("%d", port);
								if (bstrcmp(split_chef_str->entry[1], port_str) == 0) {
									ret = SUSSHI_ACL_ALLOW;
								}
								bstrFree(port_str);
							}
						}
					}
					bstrListDestroy(split_chef_str);
				}
			}
		}
	}
	return ret;
}


/*!
 * @brief       Find "key" in JSON returned from Chef and check for int / boolean (0/1) match
 *
 * @param       key     Lookup key
 * @param       value   Boolean value
 *
 * @return      AclState value
 */

AclState
susshi_chef_authz_acl_bool(const char *key, bool value) {
	AclState ret = SUSSHI_ACL_DENY;
	json_t *obj = NULL;

	if (json_unpack(susshi_session.session_context, "{s{s{s?o}}}", "Target",
					susshi_session.target_connected_by_fqdn ? bdata(susshi_session.target_host_resolved) : bdata(
							susshi_session.target_ip), key, &obj) == 0) {
		if (obj && json_is_boolean(obj) && json_boolean_value(obj) == value) {
			ret = SUSSHI_ACL_ALLOW;
		}
	}
	return ret;
}


/*!
 * @brief       Initialize / refresh relationship to Chef (cluster)
 *
 * - Register at chef(s)
 * - Download gateway host & user keys
 *
 * @param       wait        Wait for n seconds before connecting to susshi-chef
 * @param       retry       Retry n times to connect to chef
 * @param       retry_wait  Wait for n seconds before next retry
 *
 * @return      true on success
 */

bool
susshi_chef_refresh_chef_relation(u_int wait, u_int retry, u_int retry_wait) {

	HttpParameters http_params[4];
	bstring memcrypt_key = NULL;
	int num_params = 0;

	json_t *json_reply = NULL;
	long http_code;

	http_params[num_params].key = "SusshidId";
	http_params[num_params++].value = chef_cfg.susshid_id;

	memcrypt_key = susshi_memcrypt_key();
	http_params[num_params].key = "MemcryptKey";
	http_params[num_params++].value = memcrypt_key;

	if (wait > 0) {
		log_system(LOG_LEVEL_INFO, "Waiting for %d seconds before trying to connect to chef.", wait);
		SETPROCTITLE("Initializing chef communication - sleeping for %d seconds.", wait);
		sleep(wait);
	}

	for (u_int i = 0; i <= retry; i++) {

		http_code = susshi_chef_json_post("Gateway", chef_cfg.chef_server_urls.gateway,
										  chef_cfg.chef_server_urls.num_gateway, CHEF_REST_GATEWAYS_REGISTER, &json_reply,
										  http_params, num_params, true);

		if (http_code == 200) {
			int ret;
			json_t *config = NULL;

			// json_unpack will only overwrite values for keys found in answer
			ret = json_unpack(json_reply, "{s:o}",
							  "Configuration", &config);

			if (ret == 0) {
				if (config != NULL) {
					debug3("Received configurations from Chef.");
					bstrWipe(memcrypt_key);
					return susshi_cfg_read_json(config, CONTEXT_GLOBAL);
				}
				bstrWipe(memcrypt_key);
				return true;
			} else {
				log_system(LOG_LEVEL_CRIT, "Error unpacking answer from Chef - wrong format?");
			}

		} else {
			if (http_code == 404) {
				fatal("Gateway is not allowed to talk to chef.");
			}
		}

		if (json_reply)
			json_decref(json_reply);

		log_system(LOG_LEVEL_INFO, "Retrying to connect to susshi-chef, sleeping for %d seconds", retry_wait);
		SETPROCTITLE("Initializing chef communication - %d. retry, sleeping for %d seconds.", i + 1, retry_wait);

		sleep(retry_wait);
	}

	susshi_memcrypt_key_free(memcrypt_key);
	return false;
}


/*!
 * @brief       Init Chef structures
 *
 * @param       wait        Wait for n seconds before connecting to susshi-chef
 * @param       retry       Retry n times to connect to chef
 * @param       retry_wait  Wait for n seconds before next retry
 *
 * @return      true on success
 */

bool
susshi_chef_init(u_int wait, u_int retry, u_int retry_wait) {
	return susshi_chef_refresh_chef_relation(wait, retry, retry_wait);
}


/*!
 * @brief       Callback function called by curl library to fill response buffer
 *
 * @param   contents
 * @param   size
 * @param   nmemb
 * @param   userp
 *
 * @return  size
 */

size_t
susshi_chef_curlwritefn(void *contents, size_t size, size_t nmemb, void *userp) {
	size_t realsize = size * nmemb;
	ssh_buffer_add_data((ssh_buffer) userp, contents, (uint) realsize);
	return realsize;
}


/*!
 * @brief       POST params in http_request_body to Chef URI (URL + rest_urn)
 *
 * @param       chef_type               Chef Type
 * @param       chef_urls               Array of Chef URLs
 * @param       num_chef_urls           Number of Chef URLs in array
 * @param       rest_urn                URN for resource
 * @param       json_text               JSON result will get stored here
 * @param       http_parameters         HTTP Parameters as array of key/value
 * @param       num_parameters          Number of paramters
 * @param       with_client_certificate Use client certificate when talking to chef
 *
 * @return      HTTP error code:
 * @return      200     success
 * @return      400     Bad Request
 * @return      404     Not found
 * @return      406     Not Acceptable (used for too many authentication errors)
 * @return      >500    either an error on decoding JSON occured or all chefs returned with errors >= 500
 */

long
susshi_chef_json_post(const char *chef_type, bstring *chef_urls, int num_chef_urls, const char *rest_urn,
					  json_t **json_text, HttpParameters *http_parameters, int num_parameters, bool with_client_certificate) {

	long http_code = 599;
	bstring curl_url = NULL;
	bstring http_request_body = bfromcstr("");
	bstring memcrypt_key = NULL;

	CURL *curl;
	CURLcode curl_return;
	ssh_buffer http_response;
	char curl_error[CURL_ERROR_SIZE];

	int i;

	http_response = ssh_buffer_new();
	if (!http_response) {
		log_system(LOG_LEVEL_CRIT, "Failed to allocate ssh_buffer.");
		return 599;
	}

	curl = curl_easy_init();

	if (curl) {
		for (int c = 0; c < num_chef_urls && ((http_code < 200) || (http_code > 406)); c++) {
			if (blength(chef_urls[c]) > 0) {

				curl_url = bformat("%s%s", bdata(chef_urls[c]), rest_urn);
				curl_return = curl_easy_setopt(curl, CURLOPT_URL, bdata(curl_url));

				/*
				 * Pinned Public Key
				 *
				 * When negotiating a TLS or SSL connection, the server sends a certificate indicating its identity.
				 * A public key is extracted from this certificate and if it does not exactly match the public key
				 * provided to this option, curl aborts the connection before sending or receiving any data.
				 *
				 * Chrome displays the Hash in Hex, but what we need here is a base64 of the hash
				 *
				 * Format is sha256//<base64>
				 *
				 * You can get the Base64 SHA-256 used here like this:
				 *
				 * echo | openssl s_client -connect localhost:8443 2>/dev/null \
				 *      | openssl x509 -pubkey -noout \
				 *      | openssl pkey -pubin -outform DER \
				 *      | openssl dgst -sha256 -binary
				 *      | base64
				 */

				if (!is_local_http_url(bdata(curl_url)) && chef_cfg.sic_spki) {
					debug1("Pinned Public Key for Chef certificate: %s", bdata(chef_cfg.sic_spki));
					curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, bdata(chef_cfg.sic_spki));
				}

				if (curl_return == CURLE_OK) {
					struct curl_slist *chunk = NULL;
					curl_mime *mime = NULL;
					curl_mimepart *field = NULL;

					if (with_client_certificate) {
						if (chef_cfg.chef_ca_file != NULL) {
							curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
							curl_easy_setopt(curl, CURLOPT_CAINFO, bdata(chef_cfg.chef_ca_file));

							/* Client certificate */
							if (chef_cfg.chef_certificate_file != NULL) {
								debug1("Setting P12 client certificate to %s", bdata(chef_cfg.chef_certificate_file));
								curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "P12");
								curl_easy_setopt(curl, CURLOPT_SSLCERT, bdata(chef_cfg.chef_certificate_file));

								// Broken in libcurl >= 8.16.0, do not set CURLOPT_SSLKEY when CURLOPT_SSLCERTTYPE is set to P12
								// curl_easy_setopt(curl, CURLOPT_SSLKEY, bdata(chef_cfg.chef_certificate_file));

								/*
								 * P12 is encrypted with current memcrypt key
								 * openSSL is limited to 50, so keep SUSSHI_MEMCRYPT_KEY_LEN lower
								 */
								memcrypt_key = susshi_memcrypt_key();
								curl_easy_setopt(curl, CURLOPT_KEYPASSWD, bdata(memcrypt_key));
							} else {
								if (is_local_http_url(bdata(curl_url)))
									curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
								else
									fatal("Warning! No pkcs12 certificate found. Aborting.");
							}
						} else {
							if (is_local_http_url(bdata(curl_url)))
								curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
							else
								fatal("Warning! No CA file found. Aborting.");
						}
					} else {
						curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
					}

					/* API cert is not containing a valid hostname */
					curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

					/* Follow 3xx redirects */
					curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

					if_debug4() {
						do_debug4("Switching libcurl into verbose mode.");
						curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
					}

					chunk = curl_slist_append(chunk, "User-Agent: " SUSSHI_SSH_VERSION_BANNER);
					curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
					curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, susshi_chef_curlwritefn);
					curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) http_response);
					curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_error);

					/* mime handle */
					mime = curl_mime_init(curl);

					for(i=0; i < num_parameters; i++) {
						debug4("Parameter %s: %s", http_parameters[i].key, bdata(http_parameters[i].value));

						field = curl_mime_addpart(mime);

						curl_mime_name(field, http_parameters[i].key);
						curl_mime_data(field, bdata(http_parameters[i].value), CURL_ZERO_TERMINATED);
					}

					curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

					// curl_easy_setopt(curl, CURLOPT_POSTFIELDS, bdata(http_request_body));

					/* Perform curl */
					curl_return = curl_easy_perform(curl);
					curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

					if (memcrypt_key)
						susshi_memcrypt_key_free(memcrypt_key);

					if (mime)
						curl_mime_free(mime);

					if (chunk)
						curl_slist_free_all(chunk);

					if (curl_return == CURLE_OK) {
						json_error_t json_error;
						uint32_t response_len;

						uint8_t nul = '\0';
						ssh_buffer_add_data(http_response, &nul, 1);

						response_len = ssh_buffer_get_len(http_response);

						if (response_len > 1) {

							if_debug4() {
								ssize_t _size;
								fprintf(stderr, "< ");
								_size = write(STDERR_FILENO, ssh_buffer_get(http_response), response_len);
								if (_size > 0)
									fprintf(stderr, "\n");
							}

							*json_text = json_loads((char *) ssh_buffer_get(http_response), 0, &json_error);

							if (!*json_text) {
								log_system(LOG_LEVEL_CRIT, "%s Chef #%d JSON returned with error: %s", chef_type, c + 1, json_error.text);
								http_code = 599;
							}

							if (http_code == 404) {
								log_system(LOG_LEVEL_CRIT, "%s Chef #%d returned with access denied.", chef_type, c + 1);
							} else if (http_code == 406) {
								log_system(LOG_LEVEL_CRIT, "%s Chef #%d returned with too many authentication errors.", chef_type, c + 1);
							} else {
								log_system(LOG_LEVEL_INFO, "%s Chef #%d returned with HTTP code %ld.", chef_type, c + 1, http_code);
							}
						}
					} else {
						log_system(LOG_LEVEL_EMERG, "%s Chef #%d returned with error: %ld - %s", chef_type, c + 1,
								   http_code, curl_easy_strerror(curl_return));
					}

					/* Buffer für nächste Iteration zurücksetzen */
					ssh_buffer_reinit(http_response);
				}
				bstrFree(curl_url);
			} else {
				log_system(LOG_LEVEL_CRIT, "Error in %s Chef server URL#%d.", chef_type, c + 1);
			}
		}
	}

	ssh_buffer_free(http_response);
	curl_easy_cleanup(curl);
	bstrFree(http_request_body);

	return http_code;
}


/*!
 * @brief       Get Session Context from Chef
 *
 * @return      true on success
 */

bool
susshi_chef_get_session_context(void) {

	const char *mode = NULL;
	bstring client_port = NULL;
	bstring target_port = NULL;
	bstring memcrypt_key = NULL;
	long http_code;
	int json_ret;
	bool rc = false;

	HttpParameters http_params[12 + SUSSHI_MAX_TARGET_IPS];
	int num_params = 0;

	// Session context already created. Skipping.
	if (susshi_session.session_context != NULL)
		return true;

	http_params[num_params].key = "SusshidId";
	http_params[num_params++].value = chef_cfg.susshid_id;

	http_params[num_params].key = "SusshiUniqId";
	http_params[num_params++].value = susshi_session.susshi_uniqid;

	memcrypt_key = susshi_memcrypt_key();
	http_params[num_params].key = "MemcryptKey";
	http_params[num_params++].value = memcrypt_key;

	http_params[num_params].key = "ClientIPAddress";
	http_params[num_params++].value = susshi_session.client_ip;

	client_port = bformat("%d", susshi_session.client_port);
	http_params[num_params].key = "ClientPort";
	http_params[num_params++].value = client_port;

	http_params[num_params].key = "SusshiUserName";
	http_params[num_params++].value = susshi_session.susshi_user;

	http_params[num_params].key = "LoginString";
	http_params[num_params++].value = susshi_session.login_string;

	if (susshi_session.target_proxy_realm) {
		http_params[num_params].key = "TargetProxyRealm";
		http_params[num_params++].value = susshi_session.target_proxy_realm;

		http_params[num_params].key = "TargetHostName";
		http_params[num_params++].value = susshi_session.target_host;
	} else {
		if (susshi_session.target_host_resolved) {
			http_params[num_params].key = "TargetHostName";
			http_params[num_params++].value = susshi_session.target_host_resolved;
		}
	}

	if (blength(susshi_session.target_user) > 0) {
		http_params[num_params].key = "TargetUserName";
		http_params[num_params++].value = susshi_session.target_user;

		target_port = bformat("%d", susshi_session.target_port);
		http_params[num_params].key = "TargetPort";
		http_params[num_params++].value = target_port;
	}

	for (int i=0; i < susshi_session.num_target_ips; i++) {
		http_params[num_params].key = "TargetIPAddresses[]";
		http_params[num_params++].value = susshi_session.target_ips[i].ip;
	}

	switch(susshi_session.operation_mode) {
		case OP_MODE_GATEWAY: {
			mode = "gateway";
		} break;
		case OP_MODE_BASTION: {
			mode = "bastion";
		} break;
		case OP_MODE_SHELL: {
			mode = "shell";
		} break;
		default:
			mode = NULL;
	}

	if (mode) {
		http_params[num_params].key = "OperationMode";
		http_params[num_params++].value = bfromcstr(mode);
	}

#ifdef WITH_FULL_DEBUG_OPTIONS
	debug3("Retrieve session context from Chef " CHEF_REST_GATEWAYS_REGISTER);
#else
	debug3("Retrieve session context from Chef.");
#endif

	http_code = susshi_chef_json_post("Session", chef_cfg.chef_server_urls.session,
									  chef_cfg.chef_server_urls.num_session, CHEF_REST_CONTEXTS,
									  &susshi_session.session_context, http_params, num_params,true);

	susshi_memcrypt_key_free(memcrypt_key);

	if (client_port)
		bstrFree(client_port);

	if (target_port)
		bstrFree(target_port);

	if (http_code == 200) {

		json_t *config = NULL;

		/*
		 * For shell mode we do json_unpack here
		 * For non-shell mode json unpack will run later in susshi_chef_session_context_for_target() for specific target ip
		 */

		if (susshi_session.operation_mode == OP_MODE_SHELL) {
			int shell_login;

			json_ret = json_unpack(susshi_session.session_context, "{s{s{s:b s?o}}}",
							  "Target", "Gateway",
							  "ShellLogin", &shell_login,
							  "Configuration", &config);

			if (json_ret == 0) {
				susshi_session.susshi_shell_mode_allowed =
						(shell_login != 0) ? true : false;

				if (config != NULL) {
					debug3("Received configurations in session");
					rc = susshi_cfg_read_json(config, CONTEXT_SESSION);
				} else {
					rc = true;
				}
			} else {
				log_system(LOG_LEVEL_CRIT, "Error unpacking answer from Chef - wrong format?");
			}
		} else {
			int preserve_password = 0;
			const struct json_t *pref_client_auths = NULL, *req_client_auths = NULL;

			json_ret = json_unpack(susshi_session.session_context, "{s?o s?o s?i s?b s?o}",
								   "ClientAuthsPreferred", &pref_client_auths,
								   "ClientAuthsRequired", &req_client_auths,
								   "ClientAuthSetId", &susshi_session.client_auth_set_id,
								   "PreservePassword", &preserve_password,
								   "Configuration", &config);

			if (json_ret == 0) {

				/* Preferred Authentications */
				if (pref_client_auths != NULL) {
					size_t array_size, i;

					susshi_client_auth_disable_all_methods();

					array_size = json_array_size(pref_client_auths);

					for (i = 0; i < array_size; i++) {
						if (json_is_string(json_array_get(pref_client_auths, i))) {
							susshi_client_auth_add_preferred_method(
									json_string_value(json_array_get(pref_client_auths, i)));
						}
					}
				}

				/* Required Authentications */
				if (req_client_auths != NULL) {
					size_t array_size, i;

					array_size = json_array_size(req_client_auths);

					/* If we have a list of required authentications, we activate only them explicitly here */
					if (array_size > 0) {
						susshi_client_auth_disable_all_methods();
					}

					for (i = 0; i < array_size; i++) {
						if (json_is_string(json_array_get(req_client_auths, i))) {
							const char *method;

							method = json_string_value(json_array_get(req_client_auths, i));
							susshi_client_auth_add_preferred_method(method);
							susshi_client_auth_add_required_method(method);
						}
					}
				}

				if (preserve_password == 1)
					susshi_session.preserve_password = true;

				if (config != NULL) {
					debug3("Received configurations in session");
					rc = susshi_cfg_read_json(config, CONTEXT_SESSION);
				} else {
					rc = true;
				}
			} else {
				log_system(LOG_LEVEL_CRIT, "Error unpacking answer from Chef - wrong format?");
			}
		}
	} else {
		bstring target = NULL;
		const char *error_text = NULL;

		if (susshi_session.target_identifier != NULL) {
			target = bstrcpy(susshi_session.target_identifier);
		} else {
			target = bformat("%s@%s",bdata(susshi_session.target_user), bdata(susshi_session.target_host));
		}

		json_ret = json_unpack(susshi_session.session_context, "{s?s}", "error", &error_text);

		if (http_code == 404) {
			log_system(LOG_LEVEL_CRIT, "Session denied for '%s@%s -> %s' on Host %s (susshid-ID %s) with reason '%s'. (%s)",
					   bdata(susshi_session.susshi_user), bdata(susshi_session.client_ip),
					   bdata(target),
					   bdata(susshi_session.hostname),
					   bdata(chef_cfg.susshid_id),
					   error_text,
					   bdata(susshi_session.susshi_uniqid)
					   );
			susshi_disconnect_standard(CLIENT, DISCONNECT_NOT_ALLOWED);
		} else if (http_code == 406) {
			log_system(LOG_LEVEL_CRIT, "Session denied for '%s@%s -> %s' on Host %s (susshid-ID %s) with reason 'Too many authentication failures'. (%s)",
					   bdata(susshi_session.susshi_user), bdata(susshi_session.client_ip),
					   bdata(target),
					   bdata(susshi_session.hostname),
					   bdata(chef_cfg.susshid_id),
					   bdata(susshi_session.susshi_uniqid));
			susshi_disconnect_standard(CLIENT, DISCONNECT_AUTH_TOO_MANY_FAILURES);
		} else {
			log_system(LOG_LEVEL_CRIT, "Chef returned HTTP error %ld for '%s@%s -> %s' on Host %s (susshid-ID %s) with reason '%s'. (%s)",
					   http_code,
					   bdata(susshi_session.susshi_user), bdata(susshi_session.client_ip),
					   bdata(target),
					   bdata(susshi_session.hostname),
					   bdata(chef_cfg.susshid_id),
					   error_text,
					   bdata(susshi_session.susshi_uniqid)
			);
			susshi_disconnect_standard(CLIENT, DISCONNECT_DEFAULT);
		}
	}
	return rc;
}


/*!
 * @brief       Check if Session Context from Chef contains results for specific target ip address, fqdn or bastion
 *
 * @return      true on success
 */

bool
susshi_chef_session_check_context_contains_target(void) {
	int ret = -1;
	json_error_t error;

	// Session context not already loaded?
	if (susshi_session.session_context == NULL)
		return false;

	switch (susshi_session.operation_mode) {
		case OP_MODE_GATEWAY: {

			if (susshi_session.target_ip) {
				/* Try with IP */
				ret = json_unpack_ex(susshi_session.session_context, &error, JSON_VALIDATE_ONLY, "{s{s{}}}",
								  "Target", bdata(susshi_session.target_ip));
			}

			if ((ret != 0) && (susshi_session.target_host_resolved)) {
				/* Try with hostname */
				ret = json_unpack_ex(susshi_session.session_context, &error, JSON_VALIDATE_ONLY, "{s{s{}}}",
								  "Target", bdata(susshi_session.target_host_resolved));
			}

			if (ret == 0)
				return true;
		} break;

		case OP_MODE_BASTION: {
			return true;
		} break;

		default: {
		} break;
	}

	return false;
}



/*!
 * @brief       Apply Session Context from Chef for specific target ip address, fqdn or bastion
 *
 * @return      true on success
 */

bool
susshi_chef_session_context_for_target(void) {
	int ret = -1;
	json_t *config = NULL;
	const char *learning = NULL;

	// Session context not already loaded?
	if (susshi_session.session_context == NULL)
		return false;

	switch (susshi_session.operation_mode) {
		case OP_MODE_GATEWAY: {
			// json_unpack will only overwrite values for keys found in answer

			int tcp_forward_ssh_allowed = -1;
			int target_password_continue = -1;
			const char *target_password_source = NULL;
			const char *target_password = NULL;

			susshi_session.target_connected_by_fqdn = false;
			susshi_session.overwrite_target_user = NULL;
			susshi_session.target_password_continue = true;

			if (susshi_session.target_ip) {
				/* Try with IP */
				ret = json_unpack(susshi_session.session_context, "{s{s{s?I s?i s?i s?i s?b s?s s?I s?s s?s s?s s?s s?b s:o}}}",
								  "Target", bdata(susshi_session.target_ip),
								  "Id", &susshi_session.target_id,
								  "LoggingMask", &susshi_session.logging_mask,
								  "MaxSessionSeconds", &susshi_session.max_session_secs,
								  "MaxSessionIdleSeconds", &susshi_session.max_session_idle_secs,
								  "SSHTcpForwardSsh", &tcp_forward_ssh_allowed,
								  "TargetHostKeyLearning", &learning,
								  "AccessRuleId", &susshi_session.rule_id,
								  "ProfileName", &susshi_session.profile_name,
								  "TargetPasswordSource", &target_password_source,
								  "TargetPassword", &target_password,
								  "OverwriteTargetUser", &susshi_session.overwrite_target_user,
								  "TargetPasswordContinue", &target_password_continue,
								  "Configuration", &config);
			}

			if ((ret != 0) && (susshi_session.target_host_resolved)) {
				/* Try with hostname */

				ret = json_unpack(susshi_session.session_context, "{s{s{s?I s?i s?i s?i s?b s?s s?I s?s s?s s?s s?s s?b s:o}}}",
								  "Target", bdata(susshi_session.target_host_resolved),
								  "Id", &susshi_session.target_id,
								  "LoggingMask", &susshi_session.logging_mask,
								  "MaxSessionSeconds", &susshi_session.max_session_secs,
								  "MaxSessionIdleSeconds", &susshi_session.max_session_idle_secs,
								  "SSHTcpForwardSsh", &tcp_forward_ssh_allowed,
								  "TargetHostKeyLearning", &learning,
								  "AccessRuleId", &susshi_session.rule_id,
								  "ProfileName", &susshi_session.profile_name,
								  "TargetPasswordSource", &target_password_source,
								  "TargetPassword", &target_password,
								  "OverwriteTargetUser", &susshi_session.overwrite_target_user,
								  "TargetPasswordContinue", &target_password_continue,
								  "Configuration", &config);

				susshi_session.target_connected_by_fqdn = true;
			}

			if (ret == 0) {

				/* Transform bool flags */
				if (tcp_forward_ssh_allowed >= 0)
					susshi_session.tcp_forward_ssh_allowed = (bool) tcp_forward_ssh_allowed;

				if (target_password_continue >= 0)
					susshi_session.target_password_continue = (bool) target_password_continue;

				if (susshi_session.target_id > 0)
					susshi_session.target_id_bstr = bformat("%u", susshi_session.target_id);

				/* Target password source defaults to 'user dialog' */
				susshi_session.target_password_source = PWS_DIALOG;

				if (target_password_source != NULL) {
					if (strncmp(target_password_source, "preserve", 8) == 0) {
						susshi_session.target_password_source = PWS_PRESERVE;
					} else if (strncmp(target_password_source, "static", 6) == 0) {
						susshi_session.target_password_source = PWS_STATIC;
					} else if (strncmp(target_password_source, "dotp", 4) == 0) {
						susshi_session.target_password_source = PWS_DOTP;
					}
				}

				/* Copy target password */
				if (target_password != NULL) {
					susshi_session.target_userpw = bfromcstr(target_password);
				}

				/* Overwrite target user */
				if (susshi_session.overwrite_target_user) {
					log_session(GATEWAY, TARGET, "Profile is configured to overwrite target user with '%s'.",
								susshi_session.overwrite_target_user);
					if (susshi_session.target_user)
						bstrFree(susshi_session.target_user);
					susshi_session.target_user = bfromcstr(susshi_session.overwrite_target_user);
					/* Update target identifier string */
					store_target_identifier_into_session();
				}

				/* Hostkey learning */
				if (learning) {
					if (strcmp(learning, "update") == 0) {
						susshi_session.target_hostkey_learning = HK_LEARNING_UPDATE;
					} else if (strcmp(learning, "ifunknown") == 0) {
						susshi_session.target_hostkey_learning = HK_LEARNING_IFUNKNOWN;
					} else if (strcmp(learning, "prompt") == 0) {
						susshi_session.target_hostkey_learning = HK_LEARNING_PROMPT;
					}
				}

				/* Configuration */
				if (config != NULL) {
					if_debug4() {
						char *doc = NULL;
						doc = json_dumps(config, 0);
						if (doc) {
							do_debug3("Applying configurations in session returned from Chef for target '%s': %s",
								   bdata(susshi_session.target_connected_by_fqdn ? susshi_session.target_host_resolved : susshi_session.target_ip) ,doc);
							free(doc);
						}
					}
					return susshi_cfg_read_json(config, CONTEXT_SESSION);
				}
			} else {
				log_system(LOG_LEVEL_CRIT, "Error unpacking answer from Chef - wrong format?");
			}
		} break;

		case OP_MODE_BASTION: {
			int tcp_forward_ssh_allowed = -1;

			susshi_session.target_connected_by_fqdn = false;

			ret = json_unpack(susshi_session.session_context, "{s{s{s?i s?i s?i s?b s?i s?s s:o}}}",
								  "Target", "Bastion",
								  "LoggingMask", &susshi_session.logging_mask,
								  "MaxSessionSeconds", &susshi_session.max_session_secs,
								  "MaxSessionIdleSeconds", &susshi_session.max_session_idle_secs,
								  "SSHTcpForwardSsh", &tcp_forward_ssh_allowed,
								  "BastionRuleId", &susshi_session.bastion_rule_id,
								  "ProfileName", &susshi_session.profile_name,
								  "Configuration", &config);

			if (tcp_forward_ssh_allowed >= 0)
				susshi_session.tcp_forward_ssh_allowed = tcp_forward_ssh_allowed;

			/* Required for further ACL matchings */
			susshi_session.target_connected_by_fqdn = true;

			if (ret == 0) {
				if (config != NULL) {
					debug3("Applying configurations in session returned from Chef.");
					return susshi_cfg_read_json(config, CONTEXT_SESSION);
				}
			} else {
				log_system(LOG_LEVEL_CRIT, "Error unpacking answer from Chef - wrong format?");
			}
		} break;

		default: {

		} break;
	}

	return false;
}


/*!
 * @brief       Look if we have a proxy returned from chef and fill the data into susshi_session
 *
 * @return      true on success
 */


bool
susshi_chef_lookup_proxy(void) {

	for(int i = 0; i < susshi_cfg.num_target_proxies; i++) {
		if (bstrcmp(susshi_cfg.target_proxies[i].realm, susshi_session.target_proxy_realm) == 0) {
			susshi_session.target_proxy_hostname = bstrcpy(susshi_cfg.target_proxies[i].hostname);
			susshi_session.target_proxy_port = susshi_cfg.target_proxies[i].port;
			log_system(LOG_LEVEL_INFO, "Found matching proxy for realm @%s -> %s:%d",
					   bdata(susshi_cfg.target_proxies[i].realm),
					   bdata(susshi_session.target_proxy_hostname),
					   susshi_session.target_proxy_port);
			return true;
		}
	}

	return false;
}


/*!
 * @brief       Verify if "key" is in list of chef's session context
 *
 * Changed from ssh_key_cmp on binary key blobs to strcmp on base64 key blobs, because ssh_key_cmp failed on ECDSA keys
 *
 * @param       key             The userkey received from client
 * @param       key_base64      The userkey known
 *
 * @return      true if key can be found
 */

bool
susshi_chef_authn_verify_pubkey(ssh_key key, const char *key_base64) {
	const char* keytype = NULL;
	const char* base64_key_blob;
	const struct json_t* array;
	size_t array_size, i;
	int ret;

	keytype = susshi_ssh_key_type_to_char(key);

	if (keytype != NULL) {
		if (susshi_session.operation_mode != OP_MODE_CHEF_REMOTE) {
			/* Mode is Gateway or Shell */
			ret = json_unpack(susshi_session.session_context, "{s{s:o}}",
							  "UserAuthorizedKeys", keytype, &array);

			if (ret == 0) {
				// Iterate through keys
				array_size = json_array_size(array);
				for (i = 0; i<array_size; i++) {
					if (json_is_string(json_array_get(array, i))) {
						ssh_key key_from_chef;
						base64_key_blob = json_string_value(json_array_get(array, i));
						if (ssh_pki_import_pubkey_base64(base64_key_blob, ssh_key_type(key), &key_from_chef) == SSH_OK) {

							if_debug4() {
								const char *fp = NULL;
								do_debug4("Received user key from Chef: %s %s", keytype, fp = susshi_display_hash_from_key(key_from_chef));
								if (fp)
									xfree((void *) fp);
							}

							SSH_KEY_FREE(key_from_chef);

							if (strcmp(base64_key_blob, key_base64) == 0) {
								return true;
							}
						}
					}
				}
			}
		} else {
			/* Mode is Chef Remote Control */

			if (susshi_cfg.remote_control_ssh_pubkey) {
				bstrList key_string = NULL;
				key_string = bsplit(susshi_cfg.remote_control_ssh_pubkey, ' ');

				// debug1("Key received: %s", key_base64);
				// debug1("Key loaded:   %s (%s)", bdata(key_string->entry[0]), bdata(susshi_cfg.remote_control_ssh_pubkey));

				if ((strcmp(keytype, bdata(key_string->entry[0])) == 0) &&
					(strcmp(key_base64, bdata(key_string->entry[1])) == 0)) {
					return true;
				}
			}
		}
	}
	return false;
}


/*!
 * @brief       Ask Chef for user/password if valid
 *
 * @param       password
 *
 * @return      AuthState value
 */

enum ssh_auth_state_e
susshi_chef_authn_interactive(bstring password) {
	static int pw_auth_tries = 0;
	HttpParameters http_params[6];
	int num_params = 0;
	long http_code;
	json_t *json_t = NULL;

	bstring client_password = NULL;
	bstring target_password = NULL;
	bstrList passwords = NULL;

	passwords = bsplitstr(password, susshi_cfg.password_split_string);

	if (passwords->qty == 2) {
		debug2("User provided input containing split-string '%s', splitting input for gateway / target authentication.",
				bdata(susshi_cfg.password_split_string));
		client_password = passwords->entry[0];
		target_password = passwords->entry[1];
	} else {
		client_password = password;
	}

	// Prepare Data and ask Chef to check the password
	http_params[num_params].key = "SusshidId";
	http_params[num_params++].value = chef_cfg.susshid_id;

	http_params[num_params].key = "SusshiUserName";
	http_params[num_params++].value = susshi_session.susshi_user;

	http_params[num_params].key = "ClientIPAddress";
	http_params[num_params++].value = susshi_session.client_ip;

	http_params[num_params].key = "LoginString";
	http_params[num_params++].value = susshi_session.login_string;

	http_params[num_params].key = "ClientAuthSetId";
	http_params[num_params++].value = bformat("%d", susshi_session.client_auth_set_id);

	http_params[num_params].key = "SusshiUserInput";
	http_params[num_params++].value = client_password;

	http_code = susshi_chef_json_post("Session", chef_cfg.chef_server_urls.session,
									  chef_cfg.chef_server_urls.num_session, CHEF_REST_USER_INTERACTIVE, &json_t,
									  http_params, num_params,true);

	if (json_t != NULL)
		json_decref(json_t);

	if (http_code == 200) {
		if (target_password) {
			susshi_session.target_userpw = bstrcpy(target_password);
			susshi_session.use_extracted_password = true;
		}
		bstrListDestroy(passwords);
		return SSH_AUTH_STATE_SUCCESS;
	} else if (http_code == 406) {
		susshi_session.too_many_auth_failures = true;
		debug2_dir(GATEWAY, CLIENT, "Too many authentication failures.");
		log_session(GATEWAY, CLIENT, "Too many authentication failures.");
		return SSH_AUTH_STATE_ERROR;
	} else {
		bstrListDestroy(passwords);
		if (++pw_auth_tries > 2) {
			debug2_dir(GATEWAY, CLIENT, "A maximum of 3 password authentications exceeded. Skipping.");
			log_session(GATEWAY, CLIENT, "A maximum of 3 password authentications exceeded. Skipping.");
			return SSH_AUTH_STATE_ERROR;
		} else {
			return SSH_AUTH_STATE_FAILED;
		}
	}
}


/*!
 * @brief       Return list of hostkey types we got from Chef for the specified target IP in (fixed) preferred order
 *
 * @param       hostip  Target IP address suSSHi is going to connect to
 *
 * @return      (bstring) comma separated list of preferred hostkey types or NULL if there are no hostkeys
 */

bstring
susshi_chef_target_hostkey_types(bstring hostip) {
	int ret;
	struct json_t* array;
	bstring keytypes = NULL;
	bstrList kex_algos = NULL;
	bstring preferred_hostkey_algos = NULL;
	const char *key_type;

	if (susshi_cfg.session.target_hostkey_algorithms) {
		preferred_hostkey_algos = bstrcpy(susshi_cfg.session.target_hostkey_algorithms);
	} else {
		// see libssh/kex.c
		preferred_hostkey_algos = bfromcstr(DEFAULT_PREFERRED_HOST_KEY_ALGOS);
	}

	kex_algos = bsplit(preferred_hostkey_algos, ',');

	keytypes = bfromcstr("");

	for (int i=0; i < kex_algos->qty; i++) {
		if(strncmp(bdata(kex_algos->entry[i]), "rsa-sha2-", strlen("rsa-sha2-")) == 0) {
			// rsa-sha2-256 and rsa-sha2-512 algos map to ssh-rsa key type as well
			key_type = "ssh-rsa";
		} else {
			key_type = bdata(kex_algos->entry[i]);
		}
		ret = json_unpack(susshi_session.session_context, "{s{s{s{s:o}}}}",
						  "Target", susshi_session.target_connected_by_fqdn ?
									bdata(susshi_session.target_host_resolved) : bdata(hostip),
						  "TargetHostKeys", key_type, &array);

		if (ret == 0) {

			if (blength(keytypes) > 0)
				bformata(keytypes, ",");
			bformata(keytypes, "%s", bdata(kex_algos->entry[i]));
		}
	}

	/* Add standard list at the end to support key change on target server to other type */

	if (blength(keytypes) > 0)
		bformata(keytypes, ",");
	bformata(keytypes, "%s", bdata(preferred_hostkey_algos));

	bstrListDestroy(kex_algos);
	bstrFree(preferred_hostkey_algos);

	if (blength(keytypes) > 0) {
		return keytypes;
	} else {
		bstrFree(keytypes);
		return NULL;
	}
}


/*!
 * @brief       Verify the target hostkey
 *
 * @ingroup     chef
 *
 * @param       key     The hostkey from Target
 * @param       hostip  IP address of Target, susshid is currently connecting to
 *
 * @return      KeyVerifyResponse value
 */

KeyVerifyResponse
susshi_chef_verify_target_hostkey(ssh_key key, bstring hostip) {
	const char* keytype = NULL;
	const struct json_t* array;
	const char* base64_key_blob;
	size_t array_size, i;
	int ret;

	keytype = susshi_ssh_key_type_to_char(key);

	if (keytype != NULL) {
		ret = json_unpack(susshi_session.session_context, "{s{s{s{s:o}}}}",
						  "Target", susshi_session.target_connected_by_fqdn ?
									bdata(susshi_session.target_host_resolved) : bdata(hostip),
						  "TargetHostKeys", keytype, &array);

		if (ret == 0) {
			KeyVerifyResponse rc;

			rc = KEY_NEW;

			// Iterate through keys
			array_size = json_array_size(array);
			for (i = 0; i<array_size; i++) {
				if (json_is_string(json_array_get(array, i))) {
					ssh_key key_from_chef;

					base64_key_blob = json_string_value(json_array_get(array, i));
					if (ssh_pki_import_pubkey_base64(base64_key_blob, ssh_key_type(key), &key_from_chef) == SSH_OK) {

						if_debug4() {
							const char *fp = NULL;
							do_debug4("Received host key from Chef: %s %s", keytype,
								   fp = susshi_display_hash_from_key(key_from_chef));
							if (fp)
								xfree((void *) fp);
						}

						if (ssh_key_cmp(key_from_chef, key, SSH_KEY_CMP_PUBLIC) == 0) {
							SSH_KEY_FREE(key_from_chef);
							/* Key found and matches */
							return KEY_OK;
						} else {
							/* Key has changed */
							SSH_KEY_FREE(key_from_chef);
							rc = KEY_CHANGED;
						}
					} else {
						log_system(LOG_LEVEL_WARNING, "Received defective host publickey (%s) from Chef for %s.",
								   susshi_ssh_key_type_to_display_string(ssh_key_type(key)), bdata(susshi_session.target_ip));
					}
					SSH_KEY_FREE(key_from_chef);
				}
			}

			return rc;

		} else {
			/* Key of given type not found in JSON */
			return KEY_NEW;
		}
	}
	return KEY_ERROR;
}


/*!
 * @brief       Upload hostkey to chef
 *
 * @ingroup     chef
 *
 * @param       method      CHEF_REST_METHOD_CREATE or .CHEF_REST_METHOD_UPDATE
 * @param       target_ip   Target IP Address
 * @param       target_port Target Port
 * @param       hostkey     The Hostkey to be uploaded
 *
 * @return      true on success
 */

bool
susshi_chef_upload_target_hostkey(ChefMethod method, bstring target_ip, int target_port, ssh_key hostkey) {
	HttpParameters http_params[9];
	int num_params = 0;

	long http_code;
	json_t *json_t = NULL;

	bstring port = NULL;
	char *key_base64 = NULL;
	bstring bstr_key_base64 = NULL;
	bstring bstr_key_type = NULL;

	const char *url = NULL;

	switch(method) {
		case CHEF_REST_METHOD_CREATE:
			url = CHEF_REST_TARGET_HOSTKEY_CREATE;
			break;
		case CHEF_REST_METHOD_UPDATE:
			url = CHEF_REST_TARGET_HOSTKEY_UPDATE;
			break;
		default:
			return false;
		}

	ssh_pki_export_pubkey_base64(hostkey, &key_base64);

	if (key_base64) {

		bstr_key_type = bfromcstr(susshi_ssh_key_type_to_char(hostkey));
		bstr_key_base64 = bfromcstr(key_base64);

		http_params[num_params].key = "SusshidId";
		http_params[num_params++].value = chef_cfg.susshid_id;

		if (susshi_session.target_id_bstr) {
			http_params[num_params].key = "TargetId";
			http_params[num_params++].value = susshi_session.target_id_bstr;
		}

		http_params[num_params].key = "TargetHostKeyType";
		http_params[num_params++].value = bstr_key_type;

		http_params[num_params].key = "TargetHostKey";
		http_params[num_params++].value = bstr_key_base64;

		http_params[num_params].key = "SusshiUserName";
		http_params[num_params++].value = susshi_session.susshi_user;

		if (susshi_session.target_proxy_realm) {
			http_params[num_params].key = "TargetProxyRealm";
			http_params[num_params++].value = susshi_session.target_proxy_realm;
		}

		if (susshi_session.target_connected_by_fqdn) {
			http_params[num_params].key = "TargetHostName";
			http_params[num_params++].value = susshi_session.target_host_resolved;
		} else {
			http_params[num_params].key = "TargetIpAddress";
			http_params[num_params++].value = target_ip;
		}

		if (target_port != 22) {
			port = bformat("%d", target_port);
			http_params[num_params].key = "TargetPort";
			http_params[num_params++].value = port;
		}

		http_code = susshi_chef_json_post("Session", chef_cfg.chef_server_urls.session,
										  chef_cfg.chef_server_urls.num_session, url, &json_t, http_params,
										  num_params,true);

		if (json_t != NULL)
			json_decref(json_t);

		bstrFree(bstr_key_type);
		bstrFree(bstr_key_base64);
		xfree(key_base64);

		return ((http_code == 200) ? true : false);
	}
	return false;
}


/*!
 * @brief       Upload reports to Chef
 *
 * @param       reports     JSON Array of Report Hashes
 *
 * @return      true on success
 */

bool
susshi_chef_upload_report(bstring reports) {
	HttpParameters http_params[2];
	int num_params = 0;

	long http_code;
	json_t *json_t = NULL;

	http_params[num_params].key = "SusshidId";
	http_params[num_params++].value = chef_cfg.susshid_id;

	http_params[num_params].key = "Reports";
	http_params[num_params++].value = reports;

#ifdef WITH_FULL_DEBUG_OPTIONS
	debug3("Uploading report to Chef " CHEF_REST_REPORTS_SESSIONS " with %d bytes.", blength(reports));
#else
	debug3("Uploading report to Chef.");
#endif
	http_code = susshi_chef_json_post("Report", chef_cfg.chef_server_urls.report, chef_cfg.chef_server_urls.num_report,
									  CHEF_REST_REPORTS_SESSIONS, &json_t, http_params, num_params,true);

	if (json_t != NULL)
		json_decref(json_t);

	return ((http_code == 200) ? true : false);
}


/*!
 * @brief       Create Swift Cache entry at Chef
 *
 * This function is currently not in use. The SwiftIpCaching gets updated by reports.
 *
 * We keep code here as we keep code in suSSHi Chef for target controller, so we can
 * easily implement this way if required.
 *
 * @return      true on success
 */

bool
susshi_chef_create_client_auth_cache(void) {
	HttpParameters http_params[5];
	int num_params = 0;

	long http_code;
	json_t *json_t = NULL;

	http_params[num_params].key = "InstallationId";
	http_params[num_params++].value = susshi_cfg.installation_id;

	http_params[num_params].key = "SusshidId";
	http_params[num_params++].value = chef_cfg.susshid_id;

	http_params[num_params].key = "ClientAuthSetId";
	http_params[num_params++].value = bformat("%d", susshi_session.client_auth_set_id);

	http_params[num_params].key = "ClientIPAddress";
	http_params[num_params++].value = susshi_session.client_ip;

	http_params[num_params].key = "SusshiUserName";
	http_params[num_params++].value = susshi_session.susshi_user;

#ifdef WITH_FULL_DEBUG_OPTIONS
	debug3("Create Swift IP cache entry at Chef " CHEF_REST_USER_IP_CACHE ".");
#else
	debug3("Uploading report to Chef.");
#endif
	http_code = susshi_chef_json_post("Session", chef_cfg.chef_server_urls.session, chef_cfg.chef_server_urls.num_session,
									  CHEF_REST_USER_IP_CACHE, &json_t, http_params, num_params,true);

	if (json_t != NULL) xfree(json_t);

	return ((http_code == 200) ? true : false);
}

/*! @} */
