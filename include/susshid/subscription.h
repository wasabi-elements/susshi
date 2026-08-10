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
 */

#ifndef SUSSHI_SUBSCRIPTION_H
#define SUSSHI_SUBSCRIPTION_H

#define SUBSCRIPTION_VENDOR                        "Wasabi Elements GmbH"
#define SUBSCRIPTION_AUDIENCE                      "suSSHi"
#define SUBSCRIPTION_FEATURE_AUDIT_LOG_ENCRYPTION  "audit-log-encryption"

typedef struct {
	int audit_log_encryption;							// 1 if the subscription grants the audit-log-encryption feature
} SusshiSubscriptionFeatures;

bool susshi_subscription_verify(const char *token, SusshiSubscriptionFeatures *features);

#endif //SUSSHI_SUBSCRIPTION_H
