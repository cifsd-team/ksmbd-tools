// SPDX-License-Identifier: LGPL-2.1+
/*
 *   Copyright (c) International Business Machines  Corp., 2007
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *   Copyright (C) 2020 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon (linkinjeon@kernel.org)
 */

#include <dcerpc/dcerpc.h>
#include <dcerpc/dcerpc-dtyp.h>

#include <smbacl.h>
#include <management/user.h>
#include <management/share.h>
#include <tools.h>
#include <glib.h>
#include <inttypes.h>
#include <rpc_lsarpc.h>

static const struct smb_sid sid_domain = {1, 1, {0, 0, 0, 0, 0, 5},
	{21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-22-1 Unmapped Unix users */
static const struct smb_sid sid_unix_users = {1, 1, {0, 0, 0, 0, 0, 22},
	{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-22-2 Unmapped Unix groups */
static const struct smb_sid sid_unix_groups = { 1, 1, {0, 0, 0, 0, 0, 22},
	{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

int smb_valid_user_rid(__u32 rid)
{
	/* Neither an unmapped configured account nor Linux UID -1 is a user SID. */
	return rid != KSMBD_SHARE_INVALID_UID && rid != SMB_LOCAL_USERS_RID;
}

/* Keep the synthetic primary group in the same, unique account namespace. */
char *smb_local_users_name(void)
{
	unsigned int suffix = 0;

	for (;;) {
		char *name = suffix ? g_strdup_printf("Unix Users (%u)", suffix) :
				      g_strdup("Unix Users");
		struct ksmbd_user *user = usm_lookup_user_casefold(name);

		if (!user)
			return name;
		put_ksmbd_user(user);
		g_free(name);
		suffix++;
	}
}

void smb_copy_sid(struct smb_sid *dst, const struct smb_sid *src)
{
	int i;

	dst->revision = src->revision;
	dst->num_subauth = src->num_subauth;
	for (i = 0; i < NUM_AUTHS; ++i)
		dst->authority[i] = src->authority[i];
	for (i = 0; i < dst->num_subauth; ++i)
		dst->sub_auth[i] = src->sub_auth[i];
}

void smb_sid_from_rpc(struct smb_sid *sid, const RPC_SID *rsid)
{
	int i;

	memset(sid, 0, sizeof(*sid));
	sid->revision = rsid->Revision;
	sid->num_subauth = MIN(rsid->SubAuthorityCount, MAXSUBAUTH);
	memcpy(sid->authority, rsid->IdentifierAuthority, NUM_AUTHS);
	for (i = 0; i < sid->num_subauth; i++)
		sid->sub_auth[i] = rsid->SubAuthority[i];
}

RPC_SID *smb_sid_to_rpc(struct dcerpc_pdu *pdu, const struct smb_sid *sid)
{
	RPC_SID *rsid = dcerpc_alloc_data(pdu, sizeof(*rsid));
	int i;

	if (!rsid)
		return NULL;
	rsid->Revision = sid->revision;
	rsid->SubAuthorityCount = MIN(sid->num_subauth, MAXSUBAUTH);
	memcpy(rsid->IdentifierAuthority, sid->authority, NUM_AUTHS);
	for (i = 0; i < rsid->SubAuthorityCount; i++)
		rsid->SubAuthority[i] = sid->sub_auth[i];
	return rsid;
}

void smb_init_domain_sid(struct smb_sid *sid)
{
	int i;

	memset(sid, 0, sizeof(struct smb_sid));
	sid->revision = 1;
	sid->num_subauth = 4;
	sid->authority[5] = 5;
	sid->sub_auth[0] = 21;
	for (i = 0; i < 3; i++)
		sid->sub_auth[i+1] = global_conf.gen_subauth[i];
}

void smb_init_unix_group_sid(struct smb_sid *sid)
{
	memset(sid, 0, sizeof(*sid));
	smb_copy_sid(sid, &sid_unix_groups);
}

int smb_compare_sids(const struct smb_sid *ctsid, const struct smb_sid *cwsid)
{
	int i;
	int num_subauth, num_sat, num_saw;

	if ((!ctsid) || (!cwsid))
		return 1;

	/* compare the revision */
	if (ctsid->revision != cwsid->revision) {
		if (ctsid->revision > cwsid->revision)
			return 1;
		return -1;
	}

	/* compare all of the six auth values */
	for (i = 0; i < NUM_AUTHS; ++i) {
		if (ctsid->authority[i] != cwsid->authority[i]) {
			if (ctsid->authority[i] > cwsid->authority[i])
				return 1;
			return -1;
		}
	}

	/* compare all of the subauth values if any */
	num_sat = ctsid->num_subauth;
	num_saw = cwsid->num_subauth;
	num_subauth = num_sat < num_saw ? num_sat : num_saw;
	if (num_subauth) {
		for (i = 0; i < num_subauth; ++i) {
			if (ctsid->sub_auth[i] != cwsid->sub_auth[i]) {
				if (ctsid->sub_auth[i] >
					cwsid->sub_auth[i])
					return 1;
				return -1;
			}
		}
	}

	if (num_sat != num_saw)
		return num_sat > num_saw ? 1 : -1;

	return 0; /* sids compare/match */
}

static int smb_sid_to_string(char *domain, size_t domain_len,
			     struct smb_sid *sid)
{
	uint64_t authority = 0;
	int i, len;

	if (!domain || !domain_len || !sid ||
	    sid->num_subauth > SID_MAX_SUB_AUTHORITIES)
		return -EINVAL;

	for (i = 0; i < NUM_AUTHS; i++)
		authority = (authority << 8) | sid->authority[i];

	len = snprintf(domain, domain_len, "S-%u-%" PRIu64,
		       sid->revision, authority);

	if (len < 0 || (size_t)len >= domain_len)
		return -ENOMEM;

	for (i = 0; i < sid->num_subauth; i++) {
		len += snprintf(domain + len, domain_len - len, "-%u",
				sid->sub_auth[i]);
		if (len < 0 || (size_t)len >= domain_len)
			return -ENOMEM;
	}

	return len;
}

int set_domain_name(struct smb_sid *sid, char *domain, size_t domain_len,
		    int *type)
{
	struct smb_sid domain_sid;
	int ret;
	char domain_string[DOMAIN_STR_SIZE] = {0};
	g_autofree char *domain_name = NULL;

	if (!sid || !domain || !domain_len || !type)
		return -EINVAL;

	*type = SID_TYPE_UNKNOWN;
	memset(&domain_sid, 0, sizeof(domain_sid));
	domain_sid.revision = sid_domain.revision;
	domain_sid.num_subauth = 4;
	memcpy(domain_sid.authority, sid_domain.authority,
	       sizeof(domain_sid.authority));
	domain_sid.sub_auth[0] = 21;
	memcpy(&domain_sid.sub_auth[1], global_conf.gen_subauth,
	       sizeof(__u32) * 3);

	if ((sid->num_subauth == domain_sid.num_subauth ||
	     sid->num_subauth == domain_sid.num_subauth + 1) &&
	    !memcmp(sid->authority, domain_sid.authority,
		    sizeof(sid->authority)) &&
	    !memcmp(sid->sub_auth, domain_sid.sub_auth,
		    sizeof(__u32) * domain_sid.num_subauth)) {
		if (gethostname(domain_string, sizeof(domain_string) - 1))
			return -ENOMEM;

		domain_name = g_ascii_strup(domain_string, -1);
		if (!domain_name)
			return -ENOMEM;

		ret = snprintf(domain, domain_len, "%s", domain_name);
		if (ret < 0 || ret >= domain_len)
			return -ENOMEM;

		*type = sid->num_subauth == domain_sid.num_subauth ?
			SID_TYPE_DOMAIN :
			sid->sub_auth[domain_sid.num_subauth] == SMB_LOCAL_USERS_RID ?
			SID_TYPE_GROUP : SID_TYPE_USER;
		return 0;
	}

	if (sid->num_subauth == sid_unix_users.num_subauth + 1 &&
	    !memcmp(sid->authority, sid_unix_users.authority,
		    sizeof(sid->authority)) &&
	    !memcmp(sid->sub_auth, sid_unix_users.sub_auth,
		    sizeof(__u32) * sid_unix_users.num_subauth)) {
		ret = snprintf(domain, domain_len, "Unix User");
		if (ret < 0 || ret >= domain_len)
			return -ENOMEM;

		*type = SID_TYPE_USER;
		return 0;
	}

	if ((sid->num_subauth == sid_unix_groups.num_subauth ||
	     sid->num_subauth == sid_unix_groups.num_subauth + 1) &&
	    !memcmp(sid->authority, sid_unix_groups.authority,
		    sizeof(sid->authority)) &&
	    !memcmp(sid->sub_auth, sid_unix_groups.sub_auth,
		    sizeof(__u32) * sid_unix_groups.num_subauth)) {
		ret = snprintf(domain, domain_len, SMB_UNIX_GROUP_DOMAIN);
		if (ret < 0 || ret >= domain_len)
			return -ENOMEM;

		*type = sid->num_subauth == sid_unix_groups.num_subauth ?
			SID_TYPE_DOMAIN : SID_TYPE_ALIAS;
		return 0;
	}

	ret = smb_sid_to_string(domain_string, sizeof(domain_string), sid);
	if (ret < 0)
		return ret;

	domain_name = g_ascii_strup(domain_string, -1);
	if (!domain_name)
		return -ENOMEM;

	ret = snprintf(domain, domain_len, "%s", domain_name);
	if (ret < 0 || (size_t)ret >= domain_len)
		return -ENOMEM;

	return -ENOENT;
}
