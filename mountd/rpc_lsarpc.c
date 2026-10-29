// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2020 Samsung Electronics Co., Ltd.
 *
 *   Author(s): Namjae Jeon (linkinjeon@kernel.org)
 */

/*
 * lsarpc ([MS-LSAT], [MS-LSAD]) and dssetup ([MS-DSSP]) on libdcerpc's
 * server runtime, both on the lsarpc pipe as on Windows. The coders are
 * libdcerpc's, generated from its lsa.idl and dssetup.idl.
 *
 * ksmbd is a standalone server: its account domain is the machine,
 * named after the host, with the SID from ksmbd.subauth. The ksmbd users
 * are that domain's SID plus their uid, and "Unix Users" (RID
 * 0xffffffff) is its one group. The POSIX groups of the users are the
 * aliases of the "Unix Group" domain, S-1-22-2, with their gid as RID;
 * S-1-22-1 names Unix users without a ksmbd account. The predefined
 * SIDs of [MS-LSAT] 3.1.1.1.1 are translated too.
 *
 * The kernel passes no caller identity, so a policy handle gets at most
 * the public access: viewing local information and looking up names.
 */

#include <errno.h>
#include <glib.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include <linux/ksmbd_server.h>

#include <dcerpc/dcerpc.h>
#include <dcerpc/dcerpc-dtyp.h>
#include <dcerpc/server.h>
#include <dcerpc/lsa.h>
#include <dcerpc/dssetup.h>

#include <management/user.h>

#include <rpc.h>
#include <rpc_lsarpc.h>
#include <smbacl.h>
#include <tools.h>

/* [MS-ERREF] 2.2 */
#define WERR_ACCESS_DENIED		5
#define WERR_INVALID_PARAMETER		87

/* [MS-LSAD] 2.2.1.1.2: the policy object's generic mappings */
#define LSA_POLICY_READ_ACCESS		(LSA_READ_CONTROL | \
					 LSA_POLICY_VIEW_LOCAL_INFORMATION | \
					 LSA_POLICY_VIEW_AUDIT_INFORMATION | \
					 LSA_POLICY_GET_PRIVATE_INFORMATION)
#define LSA_POLICY_WRITE_ACCESS		(LSA_READ_CONTROL | \
					 LSA_POLICY_TRUST_ADMIN | \
					 LSA_POLICY_CREATE_ACCOUNT | \
					 LSA_POLICY_CREATE_SECRET | \
					 LSA_POLICY_CREATE_PRIVILEGE | \
					 LSA_POLICY_SET_DEFAULT_QUOTA_LIMITS | \
					 LSA_POLICY_SET_AUDIT_REQUIREMENTS | \
					 LSA_POLICY_AUDIT_LOG_ADMIN | \
					 LSA_POLICY_SERVER_ADMIN)
#define LSA_POLICY_EXECUTE_ACCESS	(LSA_READ_CONTROL | \
					 LSA_POLICY_VIEW_LOCAL_INFORMATION | \
					 LSA_POLICY_LOOKUP_NAMES)
#define LSA_POLICY_ALL_ACCESS		0x000f0fff
#define LSA_READ_CONTROL		0x00020000

/* [MS-LSAT] 2.2.16, 3.1.4.5: lookup options and client revisions */
#define LSA_LOOKUP_ISOLATED_NAMES	0x00000000U
#define LSA_LOOKUP_ISOLATED_NAMES_LOCAL	0x80000000U
#define LSA_CLIENT_REVISION_1		1
#define LSA_CLIENT_REVISION_2		2

/* Unmapped SIDs are named by their RID, in hex, as Windows does */
#define LSA_UNMAPPED_RID_FORMAT		"0x%X"

static gchar *domain_name;
static GMutex group_lookup_lock;

/* ------------------------------------------------------------------ */
/* Policy handles                                                      */
/* ------------------------------------------------------------------ */

struct lsa_policy {
	unsigned int	access;		/* granted */
};

static int lsa_restricted(struct dcerpc_pdu *pdu, uint32_t *status)
{
	if (!rpc_pipe_restricted(rpc_pipe_of_pdu(pdu)))
		return 0;
	*status = KSMBD_NT_STATUS_ACCESS_DENIED;
	return 1;
}

static int lsa_open_policy(struct dcerpc_pdu *pdu,
			   const struct lsa_LSAPR_OBJECT_ATTRIBUTES *attrs,
			   unsigned int desired,
			   struct dcerpc_context_handle *handle,
			   uint32_t *status)
{
	const struct rpc_generic_mapping mapping = {
		LSA_POLICY_READ_ACCESS, LSA_POLICY_WRITE_ACCESS,
		LSA_POLICY_EXECUTE_ACCESS, LSA_POLICY_ALL_ACCESS
	};
	struct lsa_policy *p;
	unsigned int granted;

	if (lsa_restricted(pdu, status))
		return 0;
	/* [MS-LSAD] 2.2.9: only RootDirectory is used, and must be NULL */
	if (attrs->RootDirectory) {
		*status = KSMBD_NT_STATUS_INVALID_PARAMETER;
		return 0;
	}
	/* Public policy ACL: local information, name lookup and READ_CONTROL */
	if (rpc_grant_access(desired, LSA_POLICY_EXECUTE_ACCESS, &mapping,
			     &granted)) {
		*status = KSMBD_NT_STATUS_ACCESS_DENIED;
		return 0;
	}
	p = g_try_malloc0(sizeof(*p));
	if (!p)
		return -1;
	p->access = granted;
	if (rpc_pipe_handle_open(rpc_pipe_of_pdu(pdu), p, g_free, handle)) {
		g_free(p);
		return -1;
	}
	*status = KSMBD_NT_STATUS_SUCCESS;
	return 0;
}

/* The open policy handle granting required, else NULL with the status */
static struct lsa_policy *
lsa_policy_get(struct dcerpc_pdu *pdu,
	       const struct dcerpc_context_handle *handle,
	       unsigned int required, uint32_t *status)
{
	void *data;
	struct lsa_policy *p;

	if (rpc_pipe_handle_lookup(rpc_pipe_of_pdu(pdu), handle, &data)) {
		*status = KSMBD_NT_STATUS_INVALID_HANDLE;
		return NULL;
	}
	p = data;
	if ((p->access & required) != required) {
		*status = KSMBD_NT_STATUS_ACCESS_DENIED;
		return NULL;
	}
	return p;
}

static int lsa_open_policy_stub(struct dcerpc_context *dce,
				struct dcerpc_pdu *pdu,
				void *reqv, void *repv)
{
	struct lsa_OpenPolicy_req *req = reqv;
	struct lsa_OpenPolicy_rep *rep = repv;

	return lsa_open_policy(pdu, &req->ObjectAttributes, req->DesiredAccess,
			       &rep->PolicyHandle, &rep->status);
}

static int lsa_open_policy2_stub(struct dcerpc_context *dce,
				 struct dcerpc_pdu *pdu,
				 void *reqv, void *repv)
{
	struct lsa_OpenPolicy2_req *req = reqv;
	struct lsa_OpenPolicy2_rep *rep = repv;

	return lsa_open_policy(pdu, &req->ObjectAttributes, req->DesiredAccess,
			       &rep->PolicyHandle, &rep->status);
}

/* The handle in the reply stays zeroed, as a closed handle is */
static int lsa_close_stub(struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
			  void *reqv, void *repv)
{
	struct lsa_Close_req *req = reqv;
	struct lsa_Close_rep *rep = repv;

	if (lsa_restricted(pdu, &rep->status))
		return 0;
	if (rpc_pipe_handle_close(rpc_pipe_of_pdu(pdu), &req->PolicyHandle))
		rep->status = KSMBD_NT_STATUS_INVALID_HANDLE;
	else
		rep->status = KSMBD_NT_STATUS_SUCCESS;
	return 0;
}

/* ------------------------------------------------------------------ */
/* QueryInformationPolicy, QueryInformationPolicy2                     */
/* ------------------------------------------------------------------ */

static int lsa_query_info_policy(struct dcerpc_pdu *pdu,
		const struct dcerpc_context_handle *handle,
		enum lsa_POLICY_INFORMATION_CLASS info_class,
		union lsa_LSAPR_POLICY_INFORMATION **infop,
		uint32_t *status)
{
	union lsa_LSAPR_POLICY_INFORMATION *info;
	struct smb_sid sid;

	if (lsa_restricted(pdu, status))
		return 0;
	if (!lsa_policy_get(pdu, handle, LSA_POLICY_VIEW_LOCAL_INFORMATION,
			    status))
		return 0;
	info = dcerpc_alloc_data(pdu, sizeof(*info));
	if (!info)
		return -1;

	switch (info_class) {
	case LSA_PolicyAccountDomainInformation:
	case LSA_PolicyLocalAccountDomainInformation:
		/* The machine's own account domain */
		smb_init_domain_sid(&sid);
		info->PolicyAccountDomainInfo.DomainName =
			rpc_pdu_strdup(pdu, domain_name);
		info->PolicyAccountDomainInfo.DomainSid = smb_sid_to_rpc(pdu, &sid);
		if (!info->PolicyAccountDomainInfo.DomainName ||
		    !info->PolicyAccountDomainInfo.DomainSid)
			return -1;
		break;
	case LSA_PolicyPrimaryDomainInformation:
		/* Not in a domain: the workgroup, and no SID */
		info->PolicyPrimaryDomainInfo.Name =
			rpc_pdu_strdup(pdu, global_conf.work_group);
		break;
	case LSA_PolicyDnsDomainInformation:
		info->PolicyDnsDomainInfo.Name =
			rpc_pdu_strdup(pdu, global_conf.work_group);
		break;
	default:
		*status = KSMBD_NT_STATUS_INVALID_INFO_CLASS;
		return 0;
	}
	*infop = info;
	*status = KSMBD_NT_STATUS_SUCCESS;
	return 0;
}

static int lsa_query_info_policy_stub(struct dcerpc_context *dce,
				      struct dcerpc_pdu *pdu,
				      void *reqv, void *repv)
{
	struct lsa_QueryInformationPolicy_req *req = reqv;
	struct lsa_QueryInformationPolicy_rep *rep = repv;

	return lsa_query_info_policy(pdu, &req->PolicyHandle,
				     req->InformationClass,
				     &rep->PolicyInformation, &rep->status);
}

static int lsa_query_info_policy2_stub(struct dcerpc_context *dce,
				       struct dcerpc_pdu *pdu,
				       void *reqv, void *repv)
{
	struct lsa_QueryInformationPolicy2_req *req = reqv;
	struct lsa_QueryInformationPolicy2_rep *rep = repv;

	return lsa_query_info_policy(pdu, &req->PolicyHandle,
				     req->InformationClass,
				     &rep->PolicyInformation, &rep->status);
}

/* ------------------------------------------------------------------ */
/* Translating SIDs and names                                          */
/* ------------------------------------------------------------------ */

/* A SID or name being translated, and what it translated to */
struct lsa_translation {
	int			index;		/* in the referenced domains */
	int			type;		/* SID_TYPE_* */
	char			domain_str[DOMAIN_STR_SIZE];
	struct smb_sid		sid;
	struct smb_sid		domain_sid;
	struct ksmbd_user	*user;
	char			*resolved_name;
	int			mapped;
	int			domain_known;
};

static void lsa_translation_free(gpointer data)
{
	struct lsa_translation *t = data;

	if (!t)
		return;
	if (t->user)
		put_ksmbd_user(t->user);
	g_free(t->resolved_name);
	g_free(t);
}

static void lsa_init_unix_domain_sid(struct smb_sid *sid, uint32_t rid)
{
	memset(sid, 0, sizeof(*sid));
	sid->revision = 1;
	sid->num_subauth = 1;
	sid->authority[5] = 22;
	sid->sub_auth[0] = rid;
}

/* A POSIX group by name, compared as SAM names are */
static int lsa_lookup_group_casefold(const char *name, uint32_t *gid,
				     char **resolved)
{
	struct group *result;
	int ret = -ENOENT;

	/* Protect the NSS cursor and copy the static result before unlocking */
	g_mutex_lock(&group_lookup_lock);
	setgrent();
	for (;;) {
		errno = 0;
		result = getgrent();
		if (!result) {
			ret = errno ? -errno : -ENOENT;
			break;
		}
		if (ksmbd_name_compare(name, result->gr_name))
			continue;
		*gid = result->gr_gid;
		*resolved = g_strdup(result->gr_name);
		ret = *resolved ? 0 : -ENOMEM;
		break;
	}
	endgrent();
	g_mutex_unlock(&group_lookup_lock);
	return ret;
}

/* A POSIX group by name, or by gid if name is NULL */
static int lsa_lookup_group(const char *name, uint32_t *gid, char **resolved)
{
	struct group group, *result;
	size_t size;
	long suggested = sysconf(_SC_GETGR_R_SIZE_MAX);
	int ret;

	size = suggested > 1024 ? suggested : 1024;
	for (;;) {
		g_autofree char *buf = g_try_malloc(size);

		if (!buf)
			return -ENOMEM;
		if (name)
			ret = getgrnam_r(name, &group, buf, size, &result);
		else
			ret = getgrgid_r(*gid, &group, buf, size, &result);
		if (ret == ERANGE) {
			if (size > G_MAXSIZE / 2)
				return -ENOMEM;
			size *= 2;
			continue;
		}
		if (name && (ret == ENOENT || (!ret && !result)))
			return lsa_lookup_group_casefold(name, gid, resolved);
		if (ret || !result)
			return ret ? -ret : -ENOENT;
		*gid = result->gr_gid;
		*resolved = g_strdup(result->gr_name);
		return *resolved ? 0 : -ENOMEM;
	}
}

/* [MS-LSAT] 3.1.1.1.1, in the daemon's C (English) system locale */
struct lsa_predefined {
	const char *domain, *name;
	unsigned int authority, prefix_count, prefix, rid, type;
};

static const struct lsa_predefined lsa_predefined[] = {
	{ "", "Null Sid", 0, 0, 0, 0, SID_TYPE_WELL_KNOWN_GROUP },
	{ "", "Everyone", 1, 0, 0, 0, SID_TYPE_WELL_KNOWN_GROUP },
	{ "", "Local", 2, 0, 0, 0, SID_TYPE_WELL_KNOWN_GROUP },
	{ "", "Creator Owner", 3, 0, 0, 0, SID_TYPE_WELL_KNOWN_GROUP },
	{ "", "Creator Group", 3, 0, 0, 1, SID_TYPE_WELL_KNOWN_GROUP },
	{ "", "Creator Owner Server", 3, 0, 0, 2, SID_TYPE_WELL_KNOWN_GROUP },
	{ "", "Creator Group Server", 3, 0, 0, 3, SID_TYPE_WELL_KNOWN_GROUP },
	{ "", "Owner Rights", 3, 0, 0, 4, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Pseudo Domain", "NT Pseudo Domain", 5, 0, 0, 0, SID_TYPE_DOMAIN },
	{ "NT Authority", "Dialup", 5, 0, 0, 1, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "Network", 5, 0, 0, 2, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "Batch", 5, 0, 0, 3, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "Interactive", 5, 0, 0, 4, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "Service", 5, 0, 0, 6, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "Anonymous Logon", 5, 0, 0, 7, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "Proxy", 5, 0, 0, 8, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "Enterprise Domain Controllers", 5, 0, 0, 9, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "Self", 5, 0, 0, 10, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "Authenticated Users", 5, 0, 0, 11, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "Restricted", 5, 0, 0, 12, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "Terminal Server User", 5, 0, 0, 13, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "Remote Interactive Logon", 5, 0, 0, 14, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "This Organization", 5, 0, 0, 15, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "System", 5, 0, 0, 18, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "Local Service", 5, 0, 0, 19, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "Network Service", 5, 0, 0, 20, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "Write Restricted", 5, 0, 0, 33, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "Other Organization", 5, 0, 0, 1000, SID_TYPE_WELL_KNOWN_GROUP },
	{ "Builtin", "Builtin", 5, 1, 32, 0, SID_TYPE_DOMAIN },
	{ "Internet$", "Internet$", 7, 0, 0, 0, SID_TYPE_DOMAIN },
	{ "NT Authority", "NTLM Authentication", 5, 1, 64, 10, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "Digest Authentication", 5, 1, 64, 21, SID_TYPE_WELL_KNOWN_GROUP },
	{ "NT Authority", "Channel Authentication", 5, 1, 64, 14, SID_TYPE_WELL_KNOWN_GROUP },
	{ "Mandatory Label", "Mandatory Label", 16, 0, 0, 0, SID_TYPE_DOMAIN },
	{ "Mandatory Label", "Untrusted Mandatory Level", 16, 0, 0, 0, SID_TYPE_LABEL },
	{ "Mandatory Label", "Low Mandatory Level", 16, 0, 0, 4096, SID_TYPE_LABEL },
	{ "Mandatory Label", "Medium Mandatory Level", 16, 0, 0, 8192, SID_TYPE_LABEL },
	{ "Mandatory Label", "High Mandatory Level", 16, 0, 0, 12288, SID_TYPE_LABEL },
	{ "Mandatory Label", "System Mandatory Level", 16, 0, 0, 16384, SID_TYPE_LABEL },
	{ "Mandatory Label", "Protected Process Mandatory Level", 16, 0, 0, 20480, SID_TYPE_LABEL },
};

static void lsa_predefined_sids(const struct lsa_predefined *entry,
				struct smb_sid *domain, struct smb_sid *sid)
{
	memset(domain, 0, sizeof(*domain));
	domain->revision = 1;
	domain->authority[5] = entry->authority;
	domain->num_subauth = entry->prefix_count;
	if (entry->prefix_count)
		domain->sub_auth[0] = entry->prefix;
	smb_copy_sid(sid, domain);
	if (entry->type != SID_TYPE_DOMAIN)
		sid->sub_auth[sid->num_subauth++] = entry->rid;
}

/* The domain called name, if there is one: its SID and canonical name */
static int lsa_find_domain(struct lsa_translation *t, const char *name)
{
	const char *canonical = NULL;
	unsigned int i;

	if (!ksmbd_name_compare(name, domain_name) ||
	    (global_conf.netbios_name &&
	     !ksmbd_name_compare(name, global_conf.netbios_name))) {
		smb_init_domain_sid(&t->domain_sid);
		canonical = domain_name;
	} else if (!ksmbd_name_compare(name, SMB_UNIX_GROUP_DOMAIN)) {
		smb_init_unix_group_sid(&t->domain_sid);
		canonical = SMB_UNIX_GROUP_DOMAIN;
	} else {
		for (i = 0; i < G_N_ELEMENTS(lsa_predefined); i++) {
			const struct lsa_predefined *entry = &lsa_predefined[i];
			struct smb_sid sid;

			if (!entry->domain[0] ||
			    ksmbd_name_compare(name, entry->domain))
				continue;
			lsa_predefined_sids(entry, &t->domain_sid, &sid);
			canonical = entry->domain;
			break;
		}
	}
	if (!canonical)
		return 0;
	g_strlcpy(t->domain_str, canonical, sizeof(t->domain_str));
	t->domain_known = 1;
	return 1;
}

/*
 * A predefined translation of input (a name, or the SID in t if NULL).
 * Returns 1 if it is one, 0 if not, -ENOMEM.
 */
static int lsa_resolve_predefined(struct lsa_translation *t,
				  const char *input)
{
	const char *name = input;
	g_autofree char *qualifier = NULL;
	unsigned int i;

	if (input) {
		const char *separator = strrchr(input, '\\');

		if (separator) {
			qualifier = g_strndup(input, separator - input);
			name = separator + 1;
		}
	}
	for (i = 0; i < G_N_ELEMENTS(lsa_predefined); i++) {
		const struct lsa_predefined *entry = &lsa_predefined[i];
		struct smb_sid domain, sid;

		lsa_predefined_sids(entry, &domain, &sid);
		if (input ? (ksmbd_name_compare(name, entry->name) ||
			     (qualifier &&
			      ksmbd_name_compare(qualifier, entry->domain))) :
			    smb_compare_sids(&t->sid, &sid))
			continue;
		smb_copy_sid(&t->sid, &sid);
		smb_copy_sid(&t->domain_sid, &domain);
		g_strlcpy(t->domain_str, entry->domain, sizeof(t->domain_str));
		t->resolved_name = g_strdup(entry->name);
		t->type = entry->type;
		t->mapped = t->domain_known = 1;
		return t->resolved_name ? 1 : -ENOMEM;
	}
	if (!input && t->sid.num_subauth) {
		struct smb_sid parent = t->sid;
		uint32_t rid = parent.sub_auth[--parent.num_subauth];

		/* A RID of a predefined domain: that domain, and no name */
		for (i = 0; i < G_N_ELEMENTS(lsa_predefined); i++) {
			struct smb_sid domain, sid;
			const struct lsa_predefined *entry = &lsa_predefined[i];

			lsa_predefined_sids(entry, &domain, &sid);
			if (smb_compare_sids(&parent, &domain))
				continue;
			smb_copy_sid(&t->domain_sid, &domain);
			g_strlcpy(t->domain_str, entry->domain,
				  sizeof(t->domain_str));
			t->resolved_name = g_strdup_printf(LSA_UNMAPPED_RID_FORMAT,
							   rid);
			t->domain_known = 1;
			return t->resolved_name ? 1 : -ENOMEM;
		}
	}
	return 0;
}

/* Translate t->sid; 0 (mapped or not), or -ENOMEM */
static int lsa_resolve_sid(struct lsa_translation *t)
{
	int ret;
	uint32_t rid;

	t->index = -1;
	t->type = SID_TYPE_UNKNOWN;
	t->mapped = 0;
	ret = lsa_resolve_predefined(t, NULL);
	if (ret)
		return ret < 0 ? ret : 0;
	ret = set_domain_name(&t->sid, t->domain_str, sizeof(t->domain_str),
			      &t->type);
	if (ret && ret != -ENOENT)
		return ret;
	if (ret == -ENOENT) {
		/* an unknown domain: the SID itself names it */
		t->resolved_name = g_strdup(t->domain_str);
		return t->resolved_name ? 0 : -ENOMEM;
	}
	t->domain_known = 1;

	switch (t->type) {
	case SID_TYPE_DOMAIN:
		smb_copy_sid(&t->domain_sid, &t->sid);
		t->resolved_name = g_strdup(t->domain_str);
		break;
	case SID_TYPE_USER:
		if (!t->sid.num_subauth)
			return 0;
		rid = t->sid.sub_auth[t->sid.num_subauth - 1];
		if (!g_ascii_strcasecmp(t->domain_str, "Unix User")) {
			lsa_init_unix_domain_sid(&t->domain_sid, 1);
		} else {
			smb_copy_sid(&t->domain_sid, &t->sid);
			t->domain_sid.num_subauth--;
		}
		t->user = smb_valid_user_rid(rid) ? usm_lookup_uid(rid) : NULL;
		if (t->user)
			t->resolved_name = g_strdup(t->user->name);
		break;
	case SID_TYPE_GROUP:
		smb_copy_sid(&t->domain_sid, &t->sid);
		t->domain_sid.num_subauth--;
		t->resolved_name = smb_local_users_name();
		break;
	case SID_TYPE_ALIAS:
		if (!t->sid.num_subauth)
			return 0;
		rid = t->sid.sub_auth[t->sid.num_subauth - 1];
		lsa_init_unix_domain_sid(&t->domain_sid, 2);
		ret = lsa_lookup_group(NULL, &rid, &t->resolved_name);
		if (ret == -ENOMEM)
			return ret;
		break;
	default:
		return 0;
	}

	if (!t->resolved_name) {
		rid = t->sid.sub_auth[t->sid.num_subauth - 1];
		t->resolved_name = g_strdup_printf(LSA_UNMAPPED_RID_FORMAT, rid);
		return t->resolved_name ? 0 : -ENOMEM;
	}
	t->mapped = 1;
	return 0;
}

/*
 * The account name of input, which may be qualified by a domain of
 * ours: SID_TYPE_USER for the account domain, SID_TYPE_ALIAS for the
 * Unix Group domain, SID_TYPE_UNKNOWN if unqualified. -ENOENT for
 * another domain, -EINVAL for nothing usable.
 */
static int lsa_extract_account_name(const char *input, char **name,
				    int *type)
{
	const char *separator;
	size_t prefix_len;

	if (!input || !name || !input[0])
		return -EINVAL;

	*type = SID_TYPE_UNKNOWN;
	separator = strrchr(input, '\\');
	if (!separator) {
		*name = g_strdup(input);
		return *name ? 0 : -ENOMEM;
	}
	if (separator == input || !separator[1])
		return -EINVAL;

	prefix_len = separator - input;
	if (prefix_len == strlen(SMB_UNIX_GROUP_DOMAIN) &&
	    !g_ascii_strncasecmp(input, SMB_UNIX_GROUP_DOMAIN, prefix_len)) {
		*type = SID_TYPE_ALIAS;
	} else if ((prefix_len != strlen(domain_name) ||
		    g_ascii_strncasecmp(input, domain_name, prefix_len)) &&
		   (!global_conf.netbios_name ||
		    prefix_len != strlen(global_conf.netbios_name) ||
		    g_ascii_strncasecmp(input, global_conf.netbios_name,
					prefix_len))) {
		return -ENOENT;
	} else {
		*type = SID_TYPE_USER;
	}

	*name = g_strdup(separator + 1);
	return *name ? 0 : -ENOMEM;
}

/* Translate the name input into t; 0 (mapped or not), or -ENOMEM */
static int lsa_resolve_name(struct lsa_translation *t, const char *input)
{
	g_autofree char *name = NULL;
	g_autofree char *qualifier = NULL;
	g_autofree char *local_group = NULL;
	const char *separator = strrchr(input, '\\');
	uint32_t rid = 0;
	int type, ret;

	ret = lsa_resolve_predefined(t, input);
	if (ret)
		return ret < 0 ? ret : 0;
	if (separator) {
		/* A known domain is referenced even if the account isn't */
		qualifier = g_strndup(input, separator - input);
		lsa_find_domain(t, qualifier);
	} else if (lsa_find_domain(t, input)) {
		smb_copy_sid(&t->sid, &t->domain_sid);
		t->type = SID_TYPE_DOMAIN;
		t->mapped = 1;
		t->resolved_name = g_strdup(t->domain_str);
		return t->resolved_name ? 0 : -ENOMEM;
	}
	ret = lsa_extract_account_name(input, &name, &type);
	if (ret)
		return ret == -ENOMEM ? ret : 0;
	if (type != SID_TYPE_ALIAS) {
		local_group = smb_local_users_name();
		t->user = usm_lookup_user_casefold(name);
		if (t->user && !smb_valid_user_rid(t->user->uid)) {
			put_ksmbd_user(t->user);
			t->user = NULL;
		}
	}
	if (local_group && !ksmbd_name_compare(name, local_group)) {
		smb_init_domain_sid(&t->domain_sid);
		rid = SMB_LOCAL_USERS_RID;
		g_strlcpy(t->domain_str, domain_name, sizeof(t->domain_str));
		t->type = SID_TYPE_GROUP;
		t->resolved_name = g_strdup(local_group);
	} else if (t->user) {
		smb_init_domain_sid(&t->domain_sid);
		rid = t->user->uid;
		g_strlcpy(t->domain_str, domain_name, sizeof(t->domain_str));
		t->type = SID_TYPE_USER;
		t->resolved_name = g_strdup(t->user->name);
	} else if (type != SID_TYPE_USER) {
		ret = lsa_lookup_group(name, &rid, &t->resolved_name);
		if (ret)
			return ret == -ENOMEM ? ret : 0;
		smb_init_unix_group_sid(&t->domain_sid);
		g_strlcpy(t->domain_str, SMB_UNIX_GROUP_DOMAIN,
			  sizeof(t->domain_str));
		t->type = SID_TYPE_ALIAS;
	}
	if (!t->resolved_name)
		return t->user || (local_group && t->type == SID_TYPE_GROUP) ?
		       -ENOMEM : 0;
	smb_copy_sid(&t->sid, &t->domain_sid);
	t->sid.sub_auth[t->sid.num_subauth++] = rid;
	t->mapped = t->domain_known = 1;
	return 0;
}

/* The RID of a mapped translation within its domain; -1 if it has none */
static int lsa_relative_id(const struct lsa_translation *t, uint32_t *rid)
{
	unsigned int i;

	if (!t->mapped || t->sid.revision != t->domain_sid.revision ||
	    memcmp(t->sid.authority, t->domain_sid.authority,
		   sizeof(t->sid.authority)))
		return -1;
	if (t->type == SID_TYPE_DOMAIN &&
	    !smb_compare_sids(&t->sid, &t->domain_sid)) {
		*rid = 0; /* undefined for SidTypeDomain in LSAPR_TRANSLATED_SID */
		return 0;
	}
	if (t->sid.num_subauth != t->domain_sid.num_subauth + 1)
		return -1;
	for (i = 0; i < t->domain_sid.num_subauth; i++)
		if (t->sid.sub_auth[i] != t->domain_sid.sub_auth[i])
			return -1;
	*rid = t->sid.sub_auth[t->sid.num_subauth - 1];
	return 0;
}

/*
 * The referenced domains of a lookup: each known domain once, in the
 * order first seen, and each translation's index among them.
 */
static int lsa_ref_domains(struct dcerpc_pdu *pdu, GPtrArray *translations,
			   struct lsa_LSAPR_REFERENCED_DOMAIN_LIST *list,
			   uint32_t *mapped)
{
	GPtrArray *domains = g_ptr_array_new();
	guint i, j;

	*mapped = 0;
	for (i = 0; i < translations->len; i++) {
		struct lsa_translation *t = g_ptr_array_index(translations, i);

		t->index = -1;
		*mapped += !!t->mapped;
		if (!t->domain_known)
			continue;
		for (j = 0; j < domains->len; j++) {
			struct lsa_translation *d = g_ptr_array_index(domains,
								      j);

			if (!smb_compare_sids(&d->domain_sid, &t->domain_sid))
				break;
		}
		if (j == domains->len)
			g_ptr_array_add(domains, t);
		t->index = j;
	}

	list->Entries = domains->len;
	list->MaxEntries = MAX(domains->len, 32);
	list->Domains = NULL;
	if (domains->len) {
		list->Domains = dcerpc_alloc_data(pdu, domains->len *
						  sizeof(*list->Domains));
		if (!list->Domains)
			goto fail;
	}
	for (i = 0; i < domains->len; i++) {
		struct lsa_translation *d = g_ptr_array_index(domains, i);

		list->Domains[i].Name = rpc_pdu_strdup(pdu, d->domain_str);
		list->Domains[i].Sid = smb_sid_to_rpc(pdu, &d->domain_sid);
		if (!list->Domains[i].Name || !list->Domains[i].Sid)
			goto fail;
	}
	g_ptr_array_free(domains, TRUE);
	return 0;
fail:
	g_ptr_array_free(domains, TRUE);
	return -1;
}

/* The status of a lookup that mapped mapped out of count names or SIDs */
static uint32_t lsa_lookup_status(uint32_t mapped, uint32_t count)
{
	if (mapped == count)
		return KSMBD_NT_STATUS_SUCCESS;
	return mapped ? KSMBD_NT_STATUS_SOME_NOT_MAPPED :
			KSMBD_NT_STATUS_NONE_MAPPED;
}

/*
 * What every lookup checks first: the handle, that the lookup is of the
 * scope a standalone server has ([MS-LSAT] 2.2.16: a workstation's), and
 * the options and client revision of the extended calls. names is set
 * for the name lookups, extended for LookupSids2 and LookupNames2 and 3.
 */
static int lsa_lookup_check(struct dcerpc_pdu *pdu,
			    const struct dcerpc_context_handle *handle,
			    uint32_t level, int names, int extended,
			    uint32_t options, uint32_t revision,
			    uint32_t *status)
{
	if (lsa_restricted(pdu, status))
		return -1;
	if (!lsa_policy_get(pdu, handle, LSA_POLICY_LOOKUP_NAMES, status))
		return -1;
	*status = KSMBD_NT_STATUS_INVALID_PARAMETER;
	if (level != LSA_LsapLookupWksta)
		return -1;
	/* LookupSids2 reserves LookupOptions and requires it to be ignored */
	if (extended && names && options != LSA_LOOKUP_ISOLATED_NAMES &&
	    options != LSA_LOOKUP_ISOLATED_NAMES_LOCAL)
		return -1;
	if (extended && revision != 0 && revision != LSA_CLIENT_REVISION_1 &&
	    revision != LSA_CLIENT_REVISION_2)
		return -1;
	return 0;
}

/* The translations of the SIDs of a lookup; NULL if out of memory */
static GPtrArray *lsa_translate_sids(struct lsa_LSAPR_SID_ENUM_BUFFER *sids,
				     uint32_t *status)
{
	GPtrArray *translations;
	uint32_t i;

	translations = g_ptr_array_new_with_free_func(lsa_translation_free);
	for (i = 0; i < sids->Entries; i++) {
		struct lsa_translation *t = g_try_malloc0(sizeof(*t));

		if (!t)
			goto fail;
		g_ptr_array_add(translations, t);
		if (!sids->SidInfo[i]) {
			*status = KSMBD_NT_STATUS_INVALID_PARAMETER;
			g_ptr_array_free(translations, TRUE);
			return NULL;
		}
		smb_sid_from_rpc(&t->sid, sids->SidInfo[i]);
		if (lsa_resolve_sid(t))
			goto fail;
	}
	*status = KSMBD_NT_STATUS_SUCCESS;
	return translations;
fail:
	g_ptr_array_free(translations, TRUE);
	return NULL;
}

/* The translations of the names of a lookup; NULL if out of memory */
static GPtrArray *lsa_translate_names(char **names, uint32_t count)
{
	GPtrArray *translations;
	uint32_t i;

	translations = g_ptr_array_new_with_free_func(lsa_translation_free);
	for (i = 0; i < count; i++) {
		struct lsa_translation *t = g_try_malloc0(sizeof(*t));

		if (!t)
			goto fail;
		g_ptr_array_add(translations, t);
		t->index = -1;
		t->type = SID_TYPE_UNKNOWN;
		if (names[i] && lsa_resolve_name(t, names[i]))
			goto fail;
	}
	return translations;
fail:
	g_ptr_array_free(translations, TRUE);
	return NULL;
}

/* ------------------------------------------------------------------ */
/* LookupSids, LookupSids2                                             */
/* ------------------------------------------------------------------ */

static int lsa_lookup_sids_stub(struct dcerpc_context *dce,
				struct dcerpc_pdu *pdu,
				void *reqv, void *repv)
{
	struct lsa_LookupSids_req *req = reqv;
	struct lsa_LookupSids_rep *rep = repv;
	uint32_t n = req->SidEnumBuffer.Entries, i;
	struct lsa_LSAPR_TRANSLATED_NAME *names;
	GPtrArray *translations;
	int ret = 0;

	if (lsa_lookup_check(pdu, &req->PolicyHandle, req->LookupLevel, 0, 0,
			     0, 0, &rep->status))
		return 0;
	translations = lsa_translate_sids(&req->SidEnumBuffer, &rep->status);
	if (!translations)
		return rep->status ? 0 : -1;
	names = dcerpc_alloc_data(pdu, MAX(n, 1) * sizeof(*names));
	if (!names || lsa_ref_domains(pdu, translations, &rep->ReferencedDomains,
				      &rep->MappedCount)) {
		ret = -1;
		goto out;
	}
	for (i = 0; i < n; i++) {
		struct lsa_translation *t = g_ptr_array_index(translations, i);

		names[i].Use = t->mapped ? t->type : SID_TYPE_UNKNOWN;
		names[i].Name = rpc_pdu_strdup(pdu, t->resolved_name);
		names[i].DomainIndex = t->domain_known ? t->index : -1;
		if (t->resolved_name && !names[i].Name) {
			ret = -1;
			goto out;
		}
	}
	rep->TranslatedNames.Entries = n;
	rep->TranslatedNames.Names = n ? names : NULL;
	rep->status = lsa_lookup_status(rep->MappedCount, n);
out:
	g_ptr_array_free(translations, TRUE);
	return ret;
}

static int lsa_lookup_sids2_stub(struct dcerpc_context *dce,
				 struct dcerpc_pdu *pdu,
				 void *reqv, void *repv)
{
	struct lsa_LookupSids2_req *req = reqv;
	struct lsa_LookupSids2_rep *rep = repv;
	uint32_t n = req->SidEnumBuffer.Entries, i;
	struct lsa_LSAPR_TRANSLATED_NAME_EX *names;
	GPtrArray *translations;
	int ret = 0;

	if (lsa_lookup_check(pdu, &req->PolicyHandle, req->LookupLevel, 0, 1,
			     req->LookupOptions, req->ClientRevision,
			     &rep->status))
		return 0;
	translations = lsa_translate_sids(&req->SidEnumBuffer, &rep->status);
	if (!translations)
		return rep->status ? 0 : -1;
	names = dcerpc_alloc_data(pdu, MAX(n, 1) * sizeof(*names));
	if (!names || lsa_ref_domains(pdu, translations, &rep->ReferencedDomains,
				      &rep->MappedCount)) {
		ret = -1;
		goto out;
	}
	for (i = 0; i < n; i++) {
		struct lsa_translation *t = g_ptr_array_index(translations, i);

		names[i].Use = t->mapped ? t->type : SID_TYPE_UNKNOWN;
		names[i].Name = rpc_pdu_strdup(pdu, t->resolved_name);
		names[i].DomainIndex = t->domain_known ? t->index : -1;
		names[i].Flags = 0;
		if (t->resolved_name && !names[i].Name) {
			ret = -1;
			goto out;
		}
	}
	rep->TranslatedNames.Entries = n;
	rep->TranslatedNames.Names = n ? names : NULL;
	rep->status = lsa_lookup_status(rep->MappedCount, n);
out:
	g_ptr_array_free(translations, TRUE);
	return ret;
}

/* ------------------------------------------------------------------ */
/* LookupNames, LookupNames2, LookupNames3                             */
/* ------------------------------------------------------------------ */

static int lsa_lookup_names_stub(struct dcerpc_context *dce,
				 struct dcerpc_pdu *pdu,
				 void *reqv, void *repv)
{
	struct lsa_LookupNames_req *req = reqv;
	struct lsa_LookupNames_rep *rep = repv;
	struct lsa_LSA_TRANSLATED_SID *sids;
	GPtrArray *translations;
	uint32_t i;
	int ret = 0;

	if (lsa_lookup_check(pdu, &req->PolicyHandle, req->LookupLevel, 1, 0,
			     0, 0, &rep->status))
		return 0;
	translations = lsa_translate_names(req->Names, req->Count);
	if (!translations)
		return -1;
	sids = dcerpc_alloc_data(pdu, MAX(req->Count, 1) * sizeof(*sids));
	if (!sids || lsa_ref_domains(pdu, translations, &rep->ReferencedDomains,
				     &rep->MappedCount)) {
		ret = -1;
		goto out;
	}
	for (i = 0; i < req->Count; i++) {
		struct lsa_translation *t = g_ptr_array_index(translations, i);

		sids[i].Use = t->mapped ? t->type : SID_TYPE_UNKNOWN;
		sids[i].RelativeId = 0;
		if (t->mapped && lsa_relative_id(t, &sids[i].RelativeId)) {
			memset(&rep->ReferencedDomains, 0,
			       sizeof(rep->ReferencedDomains));
			rep->MappedCount = 0;
			rep->status = KSMBD_NT_STATUS_INVALID_PARAMETER;
			goto out;
		}
		sids[i].DomainIndex = t->domain_known ? t->index : -1;
	}
	rep->TranslatedSids.Entries = req->Count;
	rep->TranslatedSids.Sids = req->Count ? sids : NULL;
	rep->status = lsa_lookup_status(rep->MappedCount, req->Count);
out:
	g_ptr_array_free(translations, TRUE);
	return ret;
}

static int lsa_lookup_names2_stub(struct dcerpc_context *dce,
				  struct dcerpc_pdu *pdu,
				  void *reqv, void *repv)
{
	struct lsa_LookupNames2_req *req = reqv;
	struct lsa_LookupNames2_rep *rep = repv;
	struct lsa_LSAPR_TRANSLATED_SID_EX *sids;
	GPtrArray *translations;
	uint32_t i;
	int ret = 0;

	if (lsa_lookup_check(pdu, &req->PolicyHandle, req->LookupLevel, 1, 1,
			     req->LookupOptions, req->ClientRevision,
			     &rep->status))
		return 0;
	translations = lsa_translate_names(req->Names, req->Count);
	if (!translations)
		return -1;
	sids = dcerpc_alloc_data(pdu, MAX(req->Count, 1) * sizeof(*sids));
	if (!sids || lsa_ref_domains(pdu, translations, &rep->ReferencedDomains,
				     &rep->MappedCount)) {
		ret = -1;
		goto out;
	}
	for (i = 0; i < req->Count; i++) {
		struct lsa_translation *t = g_ptr_array_index(translations, i);

		sids[i].Use = t->mapped ? t->type : SID_TYPE_UNKNOWN;
		sids[i].RelativeId = 0;
		if (t->mapped && lsa_relative_id(t, &sids[i].RelativeId)) {
			memset(&rep->ReferencedDomains, 0,
			       sizeof(rep->ReferencedDomains));
			rep->MappedCount = 0;
			rep->status = KSMBD_NT_STATUS_INVALID_PARAMETER;
			goto out;
		}
		sids[i].DomainIndex = t->domain_known ? t->index : -1;
		sids[i].Flags = 0;
	}
	rep->TranslatedSids.Entries = req->Count;
	rep->TranslatedSids.Sids = req->Count ? sids : NULL;
	rep->status = lsa_lookup_status(rep->MappedCount, req->Count);
out:
	g_ptr_array_free(translations, TRUE);
	return ret;
}

static int lsa_lookup_names3_stub(struct dcerpc_context *dce,
				  struct dcerpc_pdu *pdu,
				  void *reqv, void *repv)
{
	struct lsa_LookupNames3_req *req = reqv;
	struct lsa_LookupNames3_rep *rep = repv;
	struct lsa_LSAPR_TRANSLATED_SID_EX2 *sids;
	GPtrArray *translations;
	uint32_t i;
	int ret = 0;

	if (lsa_lookup_check(pdu, &req->PolicyHandle, req->LookupLevel, 1, 1,
			     req->LookupOptions, req->ClientRevision,
			     &rep->status))
		return 0;
	translations = lsa_translate_names(req->Names, req->Count);
	if (!translations)
		return -1;
	sids = dcerpc_alloc_data(pdu, MAX(req->Count, 1) * sizeof(*sids));
	if (!sids || lsa_ref_domains(pdu, translations, &rep->ReferencedDomains,
				     &rep->MappedCount)) {
		ret = -1;
		goto out;
	}
	for (i = 0; i < req->Count; i++) {
		struct lsa_translation *t = g_ptr_array_index(translations, i);

		sids[i].Use = t->mapped ? t->type : SID_TYPE_UNKNOWN;
		if (t->mapped) {
			sids[i].Sid = smb_sid_to_rpc(pdu, &t->sid);
			if (!sids[i].Sid) {
				ret = -1;
				goto out;
			}
		}
		sids[i].DomainIndex = t->domain_known ? t->index : -1;
		sids[i].Flags = 0;
	}
	rep->TranslatedSids.Entries = req->Count;
	rep->TranslatedSids.Sids = req->Count ? sids : NULL;
	rep->status = lsa_lookup_status(rep->MappedCount, req->Count);
out:
	g_ptr_array_free(translations, TRUE);
	return ret;
}

/* ------------------------------------------------------------------ */
/* dssetup                                                             */
/* ------------------------------------------------------------------ */

/* A standalone server, in its workgroup, with nothing in progress */
static int dssetup_get_primary_domain_info_stub(struct dcerpc_context *dce,
						struct dcerpc_pdu *pdu,
						void *reqv, void *repv)
{
	struct dssetup_GetPrimaryDomainInformation_req *req = reqv;
	struct dssetup_GetPrimaryDomainInformation_rep *rep = repv;
	union dssetup_DSROLER_PRIMARY_DOMAIN_INFORMATION *info;

	if (rpc_pipe_restricted(rpc_pipe_of_pdu(pdu))) {
		rep->status = WERR_ACCESS_DENIED;
		return 0;
	}
	info = dcerpc_alloc_data(pdu, sizeof(*info));
	if (!info)
		return -1;

	switch (req->InfoLevel) {
	case DSSETUP_DsRolePrimaryDomainInfoBasic:
		info->DomainInfoBasic.MachineRole =
			DSSETUP_DsRole_RoleStandaloneServer;
		info->DomainInfoBasic.DomainNameFlat =
			rpc_pdu_strdup(pdu, global_conf.work_group);
		if (!info->DomainInfoBasic.DomainNameFlat)
			return -1;
		break;
	case DSSETUP_DsRoleUpgradeStatus:
	case DSSETUP_DsRoleOperationState:
		/* all zero: not upgrading, idle */
		break;
	default:
		rep->status = WERR_INVALID_PARAMETER;
		return 0;
	}
	rep->DomainInfo = info;
	rep->status = KSMBD_RPC_OK;
	return 0;
}

static const struct dcerpc_stub lsa_stubs[] = {
	{ LSA_CLOSE, "Close", lsa_close_stub },
	{ LSA_OPENPOLICY, "OpenPolicy", lsa_open_policy_stub },
	{ LSA_QUERYINFORMATIONPOLICY, "QueryInformationPolicy",
	  lsa_query_info_policy_stub },
	{ LSA_LOOKUPNAMES, "LookupNames", lsa_lookup_names_stub },
	{ LSA_LOOKUPSIDS, "LookupSids", lsa_lookup_sids_stub },
	{ LSA_OPENPOLICY2, "OpenPolicy2", lsa_open_policy2_stub },
	{ LSA_QUERYINFORMATIONPOLICY2, "QueryInformationPolicy2",
	  lsa_query_info_policy2_stub },
	{ LSA_LOOKUPSIDS2, "LookupSids2", lsa_lookup_sids2_stub },
	{ LSA_LOOKUPNAMES2, "LookupNames2", lsa_lookup_names2_stub },
	{ LSA_LOOKUPNAMES3, "LookupNames3", lsa_lookup_names3_stub },
	{ -1, NULL, NULL }
};

static const struct dcerpc_stub dssetup_stubs[] = {
	{ DSSETUP_GETPRIMARYDOMAININFORMATION, "GetPrimaryDomainInformation",
	  dssetup_get_primary_domain_info_stub },
	{ -1, NULL, NULL }
};

struct dcerpc_server *rpc_lsarpc_endpoint(void)
{
	struct dcerpc_server *srv = dcerpc_server_create("lsarpc");

	if (srv && (dcerpc_server_add_interface(srv, &lsa_interface,
						lsa_procs, lsa_stubs,
						DCERPC_SERVER_ALL_NDR) ||
		    dcerpc_server_add_interface(srv, &dssetup_interface,
						dssetup_procs, dssetup_stubs,
						DCERPC_SERVER_ALL_NDR))) {
		dcerpc_server_destroy(srv);
		srv = NULL;
	}
	return srv;
}

void rpc_lsarpc_init(void)
{
	if (!domain_name) {
		char hostname[NAME_MAX] = { 0 };

		/*
		 * ksmbd supports the standalone server and
		 * uses the hostname as the domain name.
		 */
		if (gethostname(hostname, sizeof(hostname) - 1))
			abort();

		domain_name = g_ascii_strup(hostname, -1);
	}
}

void rpc_lsarpc_destroy(void)
{
	g_free(domain_name);
	domain_name = NULL;
}
