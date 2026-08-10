/*!
 *
 * @brief       Subscription token verification
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
 * @date        2026-07-05
 *
 * @defgroup    subscription Subscription token methods
 * @{
 */

#include <susshid/common.h>

/* Prototypes */
static bool subscription_parse_time(const char *str, time_t *out);


/*!
 * @brief       Parse an RFC 3339 timestamp into epoch seconds
 *
 * Accepts timestamps of the form @c 2026-07-05T12:00:00Z as well as numeric
 * UTC offsets such as @c 2026-07-05T12:00:00+00:00. Fractional seconds are
 * not supported.
 *
 * @param       str     Null-terminated RFC 3339 timestamp
 * @param       out     Receives the epoch seconds (UTC)
 *
 * @return      @c true on success, @c false on invalid arguments or format
 */

static bool
subscription_parse_time(const char *str, time_t *out) {
	bool rc = false;
	struct tm tm;
	time_t t;
	int matched, offset_hours = 0, offset_minutes = 0;
	long offset = 0;
	char tail[8], offset_sign = 0;

	if (str && out) {
		memset(&tm, 0, sizeof(tm));
		memset(tail, 0, sizeof(tail));

		matched = sscanf(str, "%4d-%2d-%2dT%2d:%2d:%2d%7s",
		                 &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
		                 &tm.tm_hour, &tm.tm_min, &tm.tm_sec, tail);

		if (matched == 7) {
			if (strcmp(tail, "Z") == 0) {
				rc = true;
			} else if (sscanf(tail, "%c%2d:%2d", &offset_sign, &offset_hours, &offset_minutes) == 3) {
				if ((offset_sign == '+') || (offset_sign == '-')) {
					offset = (offset_hours * 3600L) + (offset_minutes * 60L);
					if (offset_sign == '-')
						offset = -offset;
					rc = true;
				}
			}
		}

		if (rc) {
			tm.tm_year -= 1900;
			tm.tm_mon  -= 1;

			t = timegm(&tm);
			rc = (t != (time_t) -1);

			if (rc)
				*out = t - offset;
		}
	}

	return rc;
}


/*!
 * @brief       Verify a subscription token and extract the granted features
 *
 * The token is a PASETO v4.public token issued by the vendor. Its Ed25519
 * signature is verified locally, and its claims (vendor, audience, validity
 * period and — when known — the installation identifier) are validated
 * before any feature is granted.
 *
 * @param       token       Null-terminated PASETO subscription token
 * @param       features    Receives the granted features; zeroed on failure
 *
 * @return      @c true if the token is valid, @c false on invalid arguments,
 *              signature mismatch or claim violations
 */

bool
susshi_subscription_verify(const char *token, SusshiSubscriptionFeatures *features) {
	bool rc = false;
	unsigned char pubkey[SUSSHI_PASETO_V4_PUBLIC_PUBKEY_BYTES];
	unsigned char *message = NULL;
	size_t message_len = 0, index;
	json_t *root = NULL, *claim, *feature;
	json_error_t json_error;
	const char *value, *installation_id;
	time_t now, not_before = 0, not_after = 0;
	int i;

	if (token && features) {
		memset(features, 0, sizeof(*features));

		for (i = 0; i < SUSSHI_PASETO_V4_PUBLIC_PUBKEY_BYTES; i++)
			pubkey[i] = susshi_hash_salt[i] ^ susshi_misc_seed[i];

		if (susshi_paseto_v4_public_verify(token, pubkey, &message, &message_len)) {
			root = json_loadb((const char *) message, message_len, 0, &json_error);

			if (json_is_object(root)) {
				rc = true;

				/* Vendor */
				if (rc) {
					value = json_string_value(json_object_get(root, "iss"));
					rc = (value != NULL) && (strcmp(value, SUBSCRIPTION_VENDOR) == 0);
				}

				/* Audience */
				if (rc) {
					value = json_string_value(json_object_get(root, "aud"));
					rc = (value != NULL) && (strcmp(value, SUBSCRIPTION_AUDIENCE) == 0);
				}

				/* Validity period */
				if (rc) {
					now = time(NULL);

					value = json_string_value(json_object_get(root, "nbf"));
					rc = (value != NULL) && subscription_parse_time(value, &not_before) && (now >= not_before);
				}
				if (rc) {
					value = json_string_value(json_object_get(root, "exp"));
					rc = (value != NULL) && subscription_parse_time(value, &not_after) && (now <= not_after);
				}

				/* Installation identifier, when already known */
				if (rc && ((installation_id = bdata(susshi_cfg.installation_id)) != NULL) && (blength(susshi_cfg.installation_id) > 0)) {
					value = json_string_value(json_object_get(root, "sub"));
					rc = (value != NULL) && (strcmp(value, installation_id) == 0);
				}

				/* Granted features */
				if (rc) {
					claim = json_object_get(root, "features");

					if (json_is_array(claim)) {
						json_array_foreach(claim, index, feature) {
							value = json_string_value(feature);

							if (value && (strcmp(value, SUBSCRIPTION_FEATURE_AUDIT_LOG_ENCRYPTION) == 0)) {
								features->audit_log_encryption = 1;
								susshi_cfg.feature_audit_log_encryption = 1;
							}
						}
					}
				}
			}
		}
	}

	if (root)
		json_decref(root);
	if (message)
		xfree(message);

	if (!rc && features)
		memset(features, 0, sizeof(*features));

	return rc;
}

/*! @} */
