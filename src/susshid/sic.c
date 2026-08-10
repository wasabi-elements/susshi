/*!
 *
 * @brief       Secure Internal Communication
 *              Functions handling Secure Internal Communication between susshid and chef
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
 * @defgroup    sic Secure Internal Communication
 * @{
 */

#include "susshid/common.h"

#define SUSSHI_CHEF_URI_SCHEME_HTTP		"http://"
#define SUSSHI_CHEF_URI_SCHEME_HTTPS	"https://"
#define SUSSHI_CHEF_URI_DEFAULT_PORT	8443


/* Prototypes */
static bool write_data_to_file(bstring file, void *data, size_t len, bool binary);


/*!
 * @brief       Validate, that all Chef SIC information are present
 *
 * @param       show_error      If set to true, no output is made
 *
 * @return      true on success
 */

bool
susshi_sic_validate_params(bool show_error) {
	if (chef_cfg.chef_server_urls.num_all == 0) {
		if (show_error)
			log_system(LOG_EMERG, "Chef Information: Chef Server URL is missing. [ChefServerUrls/default]");
		return false;
	}

	if (chef_cfg.susshid_id == NULL) {
		if (show_error)
			log_system(LOG_EMERG, "Chef Information: Susshi daemon ID is missing. [SusshidID]");
		return false;
	}

	if (chef_cfg.sic_psk_memcrypt == NULL) {
		if (show_error)
			log_system(LOG_EMERG, "Chef Information: PSK is missing. [ChefPsk]");
		return false;
	}

	if (chef_cfg.sic_spki == NULL) {
		if (show_error)
			log_system(LOG_EMERG, "Chef Information: SPKI SHA256 is missing. [ChefSpki]");
		return false;
	}

	return true;
}


/*!
 * @brief       Parse Chef SIC URL
 *
 * Splits the SIC URI in form @c 'http(s)://__fqdn__/__gateway_id__/__base64_secret__/sha256::%SHA256_hash_of_the_SubjectPublicKeyInfo' into @c susshi_cfg
 *
 * @param       sic_url     The SIC URI as given from suSSHi Chef
 *
 * @return      true on success
 */

bool
susshi_sic_parse_url(bstring sic_url) {
	bstring work = NULL;
	int scheme_len = 0;
	bool rc = false;

	/* identify and validate scheme */
	if (strncmp(bdata(sic_url), SUSSHI_CHEF_URI_SCHEME_HTTPS, sizeof(SUSSHI_CHEF_URI_SCHEME_HTTPS)-1) == 0) {
		scheme_len = sizeof(SUSSHI_CHEF_URI_SCHEME_HTTPS)-1;
	} else if (is_local_http_url(bdata(sic_url))) {
		scheme_len = sizeof(SUSSHI_CHEF_URI_SCHEME_HTTP)-1;
	} else
		return false;

	/* strip scheme, split remainder on '/' → host[:port], id, secret */
	work = bmidstr(sic_url, scheme_len, blength(sic_url) - scheme_len);

	if (work) {
		struct bstrList *parts;
		parts = bsplit(work, '/');

		if (parts && (parts->qty == 4)) {
			struct bstrList *hostparts;
			int port = SUSSHI_CHEF_URI_DEFAULT_PORT;

			/* Split host[:port] on ':' to separate optional port */
			hostparts = bsplit(parts->entry[0], ':');

			if (hostparts && (hostparts->qty >= 1)) {
				bstring scheme = NULL;

				if (hostparts->qty == 2) {
					port = a2port(bdata(hostparts->entry[1]));
					if (port <= 0) {
						bstrListWipe(hostparts);
						bstrListWipe(parts);
						bstrWipe(work);
						return false;
					}
				}

				scheme = bmidstr(sic_url, 0, scheme_len);

				/* store chef url */
				chef_cfg.chef_server_urls.all[0] = bformat("%s%s:%d", bdata(scheme), bdata(hostparts->entry[0]), port);
				chef_cfg.chef_server_urls.num_all = 1;

				/* store susshid_id */
				chef_cfg.susshid_id = bstrcpy(parts->entry[1]);

				/* store psk encrypted for later usage */
				chef_cfg.sic_psk_memcrypt = susshi_memcrypt_encrypt_bstring(parts->entry[2], NULL);

				rc = susshi_sic_store_normalized_spki(parts->entry[3]);

				bstrWipe(scheme);
				bstrListWipe(hostparts);
			}
			bstrListWipe(parts);
		}
		bstrWipe(work);
	}
	return rc;
}


/*!
 * @brief       Initialize SIC by downloading SSL certificate and SSL ca from susshi-chef (Loop method)
 *
 * @param       wait        Wait for n seconds before connecting to susshi-chef
 * @param       retry       Retry n times to connect to chef
 * @param       retry_wait  Wait for n seconds before next retry
 *
 * @return      true on success
 */

bool
susshi_sic_initialize(u_int wait, u_int retry, u_int retry_wait) {

	long http_code;
	json_t *json_t = NULL;

	if (wait > 0) {
		log_system(LOG_LEVEL_INFO, "Waiting for %d seconds before trying to connect to chef.", wait);
		SETPROCTITLE("Initializing chef communication - sleeping for %d seconds.", wait);
		sleep(wait);
	}

	for (u_int i = 0; i <= retry; i++) {
		bstring psk = NULL, memcrypt_key = NULL;
		HttpParameters http_params[3];
		int num_params = 0;

		memcrypt_key = susshi_memcrypt_key();
		psk = susshi_memcrypt_decrypt_bstring(chef_cfg.sic_psk_memcrypt, NULL);

		http_params[num_params].key = "SusshidId";
		http_params[num_params++].value = chef_cfg.susshid_id;

		http_params[num_params].key = "Psk";
		http_params[num_params++].value = psk;

		http_params[num_params].key = "MemcryptKey";
		http_params[num_params++].value = memcrypt_key;

		// Uncomment for debugging: debug4("Memcrypt_key: %s", bdata(memcrypt_key));

		debug3("Requesting CA and client certificate.p12 from Chef.");

		http_code = susshi_chef_json_post("Gateway", chef_cfg.chef_server_urls.gateway,
										  chef_cfg.chef_server_urls.num_gateway,
										  CHEF_REST_GATEWAYS_SIC, &json_t,
										  http_params, num_params, false);

		bstrWipe(psk);
		bstrWipe(memcrypt_key);

		if ((http_code == 200) && (json_t != NULL)) {
			char *ca_base64 = NULL, *cert_base64 = NULL;
			unsigned char *ca = NULL, *cert = NULL;
			size_t ca_len, cert_len;
			int json_ret;

			json_ret = json_unpack(json_t, "{s:s s:s}",
								   "Ca", &ca_base64,
								   "Certificate", &cert_base64);

			if (json_ret == 0) {
				/* CA */

				debug4("CA (base64): %s\n", ca_base64);

				if (susshi_unbase64(ca_base64, &ca, &ca_len)) {

					if (chef_cfg.chef_ca_file == NULL) {
						chef_cfg.chef_ca_file = bfromcstr(PATH_SIC_CA_FILE);
					}

					/* overwriting existing file? */
					if (access(bdata(chef_cfg.chef_ca_file), F_OK) != -1) {
						log_system(LOG_LEVEL_WARNING, "Overwriting existing file %s", bdata(chef_cfg.chef_ca_file));
					}

					/* write to file */
					if (write_data_to_file(chef_cfg.chef_ca_file, ca, ca_len, false) == false)
						fatal("Writing to file %s failed.", bdata(chef_cfg.chef_ca_file));

					/* chown to unprivileged user and make it accessible for him */
					if (chown(bdata(chef_cfg.chef_ca_file),
							  susshi_session.unprivileged_user_uid,
							  susshi_session.unprivileged_user_gid) == -1)
						fatal("chown on %s failed: %s", bdata(chef_cfg.chef_ca_file), strerror(errno));
					if (chmod(bdata(chef_cfg.chef_ca_file), S_IRUSR | S_IWUSR) == -1)
						fatal("chmod on %s failed: %s", bdata(chef_cfg.chef_ca_file), strerror(errno));

					xwipe(ca_base64, strlen(ca_base64));
					xwipe(ca, ca_len);
				}

				/* P12 Certificate */

				debug4("Certificate (base64): %s\n", cert_base64);

				if (susshi_unbase64(cert_base64, &cert, &cert_len)) {

					if (chef_cfg.chef_certificate_file == NULL) {
						chef_cfg.chef_certificate_file = bfromcstr("");
						bformata(chef_cfg.chef_certificate_file, PATH_SIC_CERT_FILE, bdata(chef_cfg.susshid_id));
					}

					/* overwriting existing file? */
					if (access(bdata(chef_cfg.chef_certificate_file), F_OK) != -1) {
						log_system(LOG_LEVEL_WARNING, "Overwriting existing file %s",
								   bdata(chef_cfg.chef_certificate_file));
					}

					/* write to file */
					if (write_data_to_file(chef_cfg.chef_certificate_file, cert, cert_len, true) == false)
						fatal("Writing to file %s failed.", bdata(chef_cfg.chef_certificate_file));

					/* chown to unprivileged user and make it accessible for him */
					if (chown(bdata(chef_cfg.chef_certificate_file),
							  susshi_session.unprivileged_user_uid,
							  susshi_session.unprivileged_user_gid) == -1)
						fatal("chown on %s failed: %s", bdata(chef_cfg.chef_certificate_file), strerror(errno));
					if (chmod(bdata(chef_cfg.chef_certificate_file), S_IRUSR | S_IWUSR) == -1)
						fatal("chmod on %s failed: %s", bdata(chef_cfg.chef_certificate_file), strerror(errno));

					xwipe(cert_base64, strlen(cert_base64));
					xwipe(cert, cert_len);
				}

				log_system(LOG_LEVEL_INFO, "Successfully connected to chef.");

				return true;
			}
		}

		if (json_t != NULL)
			json_decref(json_t);

		log_system(LOG_LEVEL_INFO, "Retrying to connect to susshi-chef, sleeping for %d seconds", retry_wait);
		SETPROCTITLE("Initializing chef communication - %d. retry, sleeping for %d seconds.", i + 1, retry_wait);

		sleep(retry_wait);
	}

	return false;
}

/*!
 * @brief       Write data to a file
 *
 * @param       file        filename / path
 * @param       data        data
 * @param       len         len of data
 * @param       binary      binary or text file?
 *
 * @return      true on success, otherwise false
 */

static bool
write_data_to_file(bstring file, void *data, size_t len, bool binary) {
	FILE *ptr_myfile;

	ptr_myfile=fopen(bdata(file), (binary == true) ? "wb" : "w");

	if (ptr_myfile) {
		bool ok = (fwrite(data, 1, len, ptr_myfile) == len);
		fclose(ptr_myfile);
		if (!ok)
			fprintf(stderr, "Writing to file %s failed (short write). Aborting.\n", bdata(file));
		return ok;
	}

	fprintf(stderr, "Opening file %s for writing failed. Aborting.\n", bdata(file));
	return false;
}


/*!
 * @brief      Stores a normalized SPKI into susshi_cfg struct
 *
 * The Base64 part of the SPKI string can be provided in plain Base64 or Base64Url with or without padding
 *
 * @param      spki        The given SPKI string in format __algo__::__base64url_encoded_spki__
 *
 * @return     true on success, otherwise false
 */

bool
susshi_sic_store_normalized_spki(const bstring spki) {
	char *normalized_spki = NULL;
	struct bstrList *spki_parts;
	bstring s = NULL;
	bool rc = false;

	/* Split <algo>::<base64> at "::" into two parts */
	spki_parts = bsplitstr(spki, s = bfromcstr("::"));

	if (spki_parts && (spki_parts->qty == 2)) {
		if (susshi_base64url_normalize(bdata(spki_parts->entry[1]), &normalized_spki, NULL)) {

			/* Reassamble the SPKI */
			chef_cfg.sic_spki = bformat("%s//%s", bdata(spki_parts->entry[0]), normalized_spki);

			xfree(normalized_spki);
			rc = true;
		}
		bstrListWipe(spki_parts);
	}
	bstrFree(s);

	return rc;
}


/*! @} */
