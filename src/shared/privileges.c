/*!
 *
 * @brief       Methods to control process privileges
 *
 * @ingroup     shared
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
 * @defgroup    privileges Privileges methods
 * @{
 */

#include "shared/common.h"
#include "shared/misc.h"
#include "shared/privileges.h"

//! @cond
static struct {
	bool  permanent;
	int   orig_ngroups;
	gid_t orig_gid;
	uid_t orig_uid;
	gid_t orig_groups[NGROUPS_MAX];
} int_store = {
		.permanent = false,
		.orig_ngroups = -1,
		.orig_gid = -1,
		.orig_uid = -1
};
//! @endcond


/*!
 * @brief               Drop privileges permanently or temporarily and set it to new uid / gid
 *
 * @param permanent     Flag if to drop permanently or temporarily
 * @param uid           New effective user ID
 * @param gid           New effective group ID
 */

void
drop_privileges(bool permanent, uid_t uid, gid_t gid) {

	gid_t old_egid = getegid();
	uid_t old_euid = geteuid();

	if (permanent) {
		int_store.permanent = true;
	} else {
		/* Save information about the privileges that are being dropped so that they can be restored later.	*/
		/* Save only once, so method can be called multiple times */
		if (int_store.orig_gid == (gid_t) -1) {
			int_store.orig_gid = old_egid;
			int_store.orig_uid = old_euid;
			int_store.orig_ngroups = getgroups(NGROUPS_MAX, int_store.orig_groups);
		}
	}

	if (old_euid == 0) {
		gid_t prim_gid = getgid();
		/* If root privileges are to be dropped, be sure to pare down the ancillary
		 * groups for the process before doing anything else because the setgroups(  )
		 * system call requires root privileges.  Drop ancillary groups regardless of
		 * whether privileges are being dropped temporarily or permanently.
		 */
		setgroups(1, &prim_gid);
	}

	/* GID */
	/* here we override the real GID (-> saved GID) as well if permanent == true */

	if (setregid((permanent ? gid : -1), gid) == -1) {
		fatal("Failed to set GID to %d: %s", gid, strerror(errno));
	}

	/* UID */
	/* here we override the real UID (-> saved UID) as well if permanent == true */

	if (setreuid((permanent ? uid : -1), uid) == -1) {
		fatal("Failed to set UID to %d: %s", uid, strerror(errno));
	}

	/* verify that the changes were successful */
	if (permanent) {
		if (gid != old_egid && (setegid(old_egid) != -1 || getegid() != gid))
			fatal("Failed to set GID permanently to %d.", gid);
		if (uid != old_euid && (seteuid(old_euid) != -1 || geteuid() != uid))
			fatal("Failed to set UID permanently to %d.", uid);
	} else {
		if (gid != old_egid && getegid() != gid)
			fatal("Failed to set GID to %d.", gid);
		if (uid != old_euid && geteuid() != uid)
			fatal("Failed to set UID to %d.", uid);
	}
}


/*!
 * @brief               Restore temporarily dropped privileges
 */

void
restore_privileges(void) {

	if (int_store.permanent)
		fatal("Cannot restore from permanently dropped privileges.");

	if (geteuid() != int_store.orig_uid)
		if (seteuid(int_store.orig_uid) == -1 || geteuid() != int_store.orig_uid)
			fatal("Failed to restore UID privileges.");

	if (getegid() != int_store.orig_gid)
		if (setegid(int_store.orig_gid) == -1 || getegid() != int_store.orig_gid)
			fatal("Failed to restore GID privileges.");

	if (!int_store.orig_uid)
		setgroups(int_store.orig_ngroups, int_store.orig_groups);

}


/*!
 * @brief               Get UID and GID of the susshi unprivileged user
 *
 * Calls @c fatal() if the user defined by @c SUSSHI_UNPRIVILEGED_USERNAME does not exist.
 *
 * @param uid           Receives the user's UID
 * @param gid           Receives the user's GID
 */

void
get_unprivileged_user_uid_gid(uid_t *uid, gid_t *gid) {

	struct passwd *pwd;

	pwd = getpwnam(SUSSHI_UNPRIVILEGED_USERNAME);

	if (pwd) {
		*uid = pwd->pw_uid;
		*gid = pwd->pw_gid;
	} else {
		fatal("Failed to get information about user %s", SUSSHI_UNPRIVILEGED_USERNAME);
	}

}

/*! @} */
