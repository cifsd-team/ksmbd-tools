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
 * named after the host, with the SID from ksmbd.subauth. Local users are
 * that domain's SID plus their uid; S-1-22-1 and S-1-22-2 are the Unix
 * users and groups.
 */

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

/* [MS-ERREF] 2.3 */
#define STATUS_SOME_NOT_MAPPED		0x00000107
#define STATUS_INVALID_HANDLE		0xC0000008
#define STATUS_INVALID_PARAMETER	0xC000000D
#define STATUS_NONE_MAPPED		0xC0000073
#define WERR_INVALID_PARAMETER		87

/* How many domains a lookup reply may reference */
#define LSA_MAX_REF_DOMAINS		32

static gchar *domain_name;

static void sid_from_rpc(struct smb_sid *sid, const RPC_SID *rsid)
{
	int i;

	memset(sid, 0, sizeof(*sid));
	sid->revision = rsid->Revision;
	sid->num_subauth = MIN(rsid->SubAuthorityCount, MAXSUBAUTH);
	memcpy(sid->authority, rsid->IdentifierAuthority, NUM_AUTHS);
	for (i = 0; i < sid->num_subauth; i++)
		sid->sub_auth[i] = rsid->SubAuthority[i];
}

static RPC_SID *sid_to_rpc(struct dcerpc_pdu *pdu, const struct smb_sid *sid)
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

/* The status of a lookup that mapped mapped out of count names or SIDs */
static uint32_t lookup_status(uint32_t mapped, uint32_t count)
{
	if (mapped == count)
		return KSMBD_RPC_OK;
	return mapped ? STATUS_SOME_NOT_MAPPED : STATUS_NONE_MAPPED;
}

/*
 * The domains a lookup reply references, each once, in the order they
 * were first seen.
 */
struct ref_domains {
	struct dcerpc_pdu			*pdu;
	struct lsa_LSAPR_REFERENCED_DOMAIN_LIST	*list;
	struct smb_sid				sids[LSA_MAX_REF_DOMAINS];
};

static int ref_domains_init(struct ref_domains *rd, struct dcerpc_pdu *pdu,
			    struct lsa_LSAPR_REFERENCED_DOMAIN_LIST *list)
{
	rd->pdu = pdu;
	rd->list = list;
	list->Entries = 0;
	list->MaxEntries = LSA_MAX_REF_DOMAINS;
	list->Domains = dcerpc_alloc_data(pdu, LSA_MAX_REF_DOMAINS *
					  sizeof(*list->Domains));
	return list->Domains ? 0 : -1;
}

/* The index of domain sid named name, added if new; -1 if full */
static int ref_domains_add(struct ref_domains *rd, const struct smb_sid *sid,
			   const char *name)
{
	struct lsa_LSAPR_TRUST_INFORMATION *d;
	uint32_t i;

	for (i = 0; i < rd->list->Entries; i++) {
		if (!smb_compare_sids(&rd->sids[i], sid))
			return i;
	}
	if (i == LSA_MAX_REF_DOMAINS)
		return -1;

	d = &rd->list->Domains[i];
	d->Name = rpc_pdu_strdup(rd->pdu, name);
	d->Sid = sid_to_rpc(rd->pdu, sid);
	if (!d->Name || !d->Sid)
		return -1;
	smb_copy_sid(&rd->sids[i], sid);
	rd->list->Entries++;
	return i;
}

/*
 * A SID translated to a name, its use, and the index of its domain in
 * the reply's referenced domains (-1 if the domain is not known).
 * Returns 1 if mapped, 0 if not, -1 on error.
 */
static int lookup_sid(struct ref_domains *rd, const RPC_SID *rsid,
		      char **name, enum lsa_SID_NAME_USE *use,
		      int32_t *domain_index)
{
	char domain_str[DOMAIN_STR_SIZE];
	struct smb_sid sid;
	uint32_t rid;
	int type;

	*name = NULL;
	*use = LSA_SidTypeUnknown;
	*domain_index = -1;
	if (!rsid || !rsid->SubAuthorityCount)
		return 0;

	sid_from_rpc(&sid, rsid);
	rid = sid.sub_auth[--sid.num_subauth];
	/* the length of the name, or -ENOENT for a domain it doesn't know */
	if (set_domain_name(&sid, domain_str, sizeof(domain_str), &type) < 0)
		return 0;

	*domain_index = ref_domains_add(rd, &sid, domain_str);
	if (*domain_index < 0)
		return -1;

	if (type == SID_TYPE_GROUP) {
		struct group *gr = getgrgid(rid);

		if (!gr)
			return 0;
		*name = rpc_pdu_strdup(rd->pdu, gr->gr_name);
		*use = LSA_SidTypeGroup;
	} else {
		struct passwd *pw = getpwuid(rid);

		if (!pw)
			return 0;
		*name = rpc_pdu_strdup(rd->pdu, pw->pw_name);
		*use = LSA_SidTypeUser;
	}
	return *name ? 1 : -1;
}

/*
 * A ksmbd user's name, optionally as DOMAIN\name, translated to its RID
 * in the machine domain and the index of that domain in the reply's
 * referenced domains. Returns 1 if mapped, 0 if not, -1 on error.
 */
static int lookup_name(struct ref_domains *rd, const char *name,
		       uint32_t *rid, int32_t *domain_index)
{
	struct ksmbd_user *user;
	struct smb_sid domain_sid;
	const char *sep;

	*domain_index = -1;
	if (!name)
		return 0;
	sep = strrchr(name, '\\');
	if (sep)
		name = sep + 1;

	user = usm_lookup_user((char *)name);
	if (!user)
		return 0;
	*rid = user->uid;
	put_ksmbd_user(user);

	smb_init_domain_sid(&domain_sid);
	*domain_index = ref_domains_add(rd, &domain_sid, domain_name);
	return *domain_index < 0 ? -1 : 1;
}

/* ------------------------------------------------------------------ */
/* Policy handles                                                      */
/* ------------------------------------------------------------------ */

static int policy_valid(struct dcerpc_pdu *pdu,
			const struct dcerpc_context_handle *handle)
{
	return !rpc_pipe_handle_lookup(rpc_pipe_of_pdu(pdu), handle, NULL);
}

static int lsa_open_policy(struct dcerpc_pdu *pdu,
			   struct dcerpc_context_handle *handle,
			   uint32_t *status)
{
	if (rpc_pipe_handle_open(rpc_pipe_of_pdu(pdu), NULL, NULL, handle))
		return -1;
	*status = KSMBD_RPC_OK;
	return 0;
}

static int lsa_open_policy_stub(struct dcerpc_context *dce,
				struct dcerpc_pdu *pdu,
				void *reqv, void *repv)
{
	struct lsa_OpenPolicy_rep *rep = repv;

	return lsa_open_policy(pdu, &rep->PolicyHandle, &rep->status);
}

static int lsa_open_policy2_stub(struct dcerpc_context *dce,
				 struct dcerpc_pdu *pdu,
				 void *reqv, void *repv)
{
	struct lsa_OpenPolicy2_rep *rep = repv;

	return lsa_open_policy(pdu, &rep->PolicyHandle, &rep->status);
}

/* The handle in the reply stays zeroed, as a closed handle is */
static int lsa_close_stub(struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
			  void *reqv, void *repv)
{
	struct lsa_Close_req *req = reqv;
	struct lsa_Close_rep *rep = repv;

	if (rpc_pipe_handle_close(rpc_pipe_of_pdu(pdu), &req->PolicyHandle))
		rep->status = STATUS_INVALID_HANDLE;
	else
		rep->status = KSMBD_RPC_OK;
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

	if (!policy_valid(pdu, handle)) {
		*status = STATUS_INVALID_HANDLE;
		return 0;
	}
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
		info->PolicyAccountDomainInfo.DomainSid = sid_to_rpc(pdu, &sid);
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
		*status = STATUS_INVALID_PARAMETER;
		return 0;
	}
	*infop = info;
	*status = KSMBD_RPC_OK;
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
	struct ref_domains rd;
	int ret;

	if (!policy_valid(pdu, &req->PolicyHandle)) {
		rep->status = STATUS_INVALID_HANDLE;
		return 0;
	}
	names = dcerpc_alloc_data(pdu, MAX(n, 1) * sizeof(*names));
	if (!names || ref_domains_init(&rd, pdu, &rep->ReferencedDomains))
		return -1;

	for (i = 0; i < n; i++) {
		ret = lookup_sid(&rd, req->SidEnumBuffer.SidInfo[i],
				 &names[i].Name, &names[i].Use,
				 &names[i].DomainIndex);
		if (ret < 0)
			return -1;
		rep->MappedCount += ret;
	}
	rep->TranslatedNames.Entries = n;
	rep->TranslatedNames.Names = names;
	rep->status = lookup_status(rep->MappedCount, n);
	return 0;
}

static int lsa_lookup_sids2_stub(struct dcerpc_context *dce,
				 struct dcerpc_pdu *pdu,
				 void *reqv, void *repv)
{
	struct lsa_LookupSids2_req *req = reqv;
	struct lsa_LookupSids2_rep *rep = repv;
	uint32_t n = req->SidEnumBuffer.Entries, i;
	struct lsa_LSAPR_TRANSLATED_NAME_EX *names;
	struct ref_domains rd;
	int ret;

	if (!policy_valid(pdu, &req->PolicyHandle)) {
		rep->status = STATUS_INVALID_HANDLE;
		return 0;
	}
	names = dcerpc_alloc_data(pdu, MAX(n, 1) * sizeof(*names));
	if (!names || ref_domains_init(&rd, pdu, &rep->ReferencedDomains))
		return -1;

	for (i = 0; i < n; i++) {
		ret = lookup_sid(&rd, req->SidEnumBuffer.SidInfo[i],
				 &names[i].Name, &names[i].Use,
				 &names[i].DomainIndex);
		if (ret < 0)
			return -1;
		rep->MappedCount += ret;
	}
	rep->TranslatedNames.Entries = n;
	rep->TranslatedNames.Names = names;
	rep->status = lookup_status(rep->MappedCount, n);
	return 0;
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
	struct ref_domains rd;
	uint32_t i;
	int ret;

	if (!policy_valid(pdu, &req->PolicyHandle)) {
		rep->status = STATUS_INVALID_HANDLE;
		return 0;
	}
	sids = dcerpc_alloc_data(pdu, MAX(req->Count, 1) * sizeof(*sids));
	if (!sids || ref_domains_init(&rd, pdu, &rep->ReferencedDomains))
		return -1;

	for (i = 0; i < req->Count; i++) {
		ret = lookup_name(&rd, req->Names[i], &sids[i].RelativeId,
				  &sids[i].DomainIndex);
		if (ret < 0)
			return -1;
		sids[i].Use = ret ? LSA_SidTypeUser : LSA_SidTypeUnknown;
		rep->MappedCount += ret;
	}
	rep->TranslatedSids.Entries = req->Count;
	rep->TranslatedSids.Sids = sids;
	rep->status = lookup_status(rep->MappedCount, req->Count);
	return 0;
}

static int lsa_lookup_names2_stub(struct dcerpc_context *dce,
				  struct dcerpc_pdu *pdu,
				  void *reqv, void *repv)
{
	struct lsa_LookupNames2_req *req = reqv;
	struct lsa_LookupNames2_rep *rep = repv;
	struct lsa_LSAPR_TRANSLATED_SID_EX *sids;
	struct ref_domains rd;
	uint32_t i;
	int ret;

	if (!policy_valid(pdu, &req->PolicyHandle)) {
		rep->status = STATUS_INVALID_HANDLE;
		return 0;
	}
	sids = dcerpc_alloc_data(pdu, MAX(req->Count, 1) * sizeof(*sids));
	if (!sids || ref_domains_init(&rd, pdu, &rep->ReferencedDomains))
		return -1;

	for (i = 0; i < req->Count; i++) {
		ret = lookup_name(&rd, req->Names[i], &sids[i].RelativeId,
				  &sids[i].DomainIndex);
		if (ret < 0)
			return -1;
		sids[i].Use = ret ? LSA_SidTypeUser : LSA_SidTypeUnknown;
		rep->MappedCount += ret;
	}
	rep->TranslatedSids.Entries = req->Count;
	rep->TranslatedSids.Sids = sids;
	rep->status = lookup_status(rep->MappedCount, req->Count);
	return 0;
}

static int lsa_lookup_names3_stub(struct dcerpc_context *dce,
				  struct dcerpc_pdu *pdu,
				  void *reqv, void *repv)
{
	struct lsa_LookupNames3_req *req = reqv;
	struct lsa_LookupNames3_rep *rep = repv;
	struct lsa_LSAPR_TRANSLATED_SID_EX2 *sids;
	struct ref_domains rd;
	struct smb_sid sid;
	uint32_t i, rid;
	int ret;

	if (!policy_valid(pdu, &req->PolicyHandle)) {
		rep->status = STATUS_INVALID_HANDLE;
		return 0;
	}
	sids = dcerpc_alloc_data(pdu, MAX(req->Count, 1) * sizeof(*sids));
	if (!sids || ref_domains_init(&rd, pdu, &rep->ReferencedDomains))
		return -1;

	for (i = 0; i < req->Count; i++) {
		ret = lookup_name(&rd, req->Names[i], &rid,
				  &sids[i].DomainIndex);
		if (ret < 0)
			return -1;
		if (ret) {
			smb_init_domain_sid(&sid);
			sid.sub_auth[sid.num_subauth++] = rid;
			sids[i].Sid = sid_to_rpc(pdu, &sid);
			if (!sids[i].Sid)
				return -1;
		}
		sids[i].Use = ret ? LSA_SidTypeUser : LSA_SidTypeUnknown;
		rep->MappedCount += ret;
	}
	rep->TranslatedSids.Entries = req->Count;
	rep->TranslatedSids.Sids = sids;
	rep->status = lookup_status(rep->MappedCount, req->Count);
	return 0;
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
		char hostname[NAME_MAX];

		/*
		 * ksmbd supports the standalone server and
		 * uses the hostname as the domain name.
		 */
		if (gethostname(hostname, NAME_MAX))
			abort();

		domain_name = g_ascii_strup(hostname, -1);
	}
}

void rpc_lsarpc_destroy(void)
{
	g_free(domain_name);
	domain_name = NULL;
}
