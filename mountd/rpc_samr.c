// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2020 Samsung Electronics Co., Ltd.
 *
 *   Author(s): Namjae Jeon (linkinjeon@kernel.org)
 */

/*
 * samr ([MS-SAMR]) on libdcerpc's server runtime. The coders are
 * libdcerpc's, generated from its samr.idl.
 *
 * The SAM of a standalone ksmbd: the account domain, named after the
 * host and with the SID from ksmbd.subauth, holds the ksmbd users, each
 * with its uid as RID. Builtin (S-1-5-32) is listed but empty.
 */

#include <glib.h>
#include <limits.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include <linux/ksmbd_server.h>

#include <dcerpc/dcerpc.h>
#include <dcerpc/dcerpc-dtyp.h>
#include <dcerpc/server.h>
#include <dcerpc/samr.h>

#include <management/user.h>

#include <rpc.h>
#include <rpc_samr.h>
#include <smbacl.h>
#include <tools.h>

/* [MS-ERREF] 2.3 */
#define STATUS_SOME_NOT_MAPPED		0x00000107
#define STATUS_INVALID_INFO_CLASS	0xC0000003
#define STATUS_INVALID_HANDLE		0xC0000008
#define STATUS_NO_SUCH_USER		0xC0000064
#define STATUS_NONE_MAPPED		0xC0000073
#define STATUS_NO_SUCH_DOMAIN		0xC00000DF

/* [MS-SAMR] 2.2.1.14: RID of Domain Users */
#define DOMAIN_GROUP_RID_USERS		513
/* SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED */
#define SE_GROUP_DEFAULT		0x00000007

/* S-1-5-32, the Builtin domain */
static const struct smb_sid sid_builtin = {
	1, 1, {0, 0, 0, 0, 0, 5}, {32} };
/* S-1-1-0, Everyone */
static const struct smb_sid sid_everyone = {
	1, 1, {0, 0, 0, 0, 0, 1}, {0} };

static gchar *domain_name;

/* What a samr handle is a handle to */
enum samr_handle_type {
	SAMR_HANDLE_SERVER,
	SAMR_HANDLE_DOMAIN,
	SAMR_HANDLE_BUILTIN,
	SAMR_HANDLE_USER,
};

struct samr_handle {
	enum samr_handle_type	type;
	/* SAMR_HANDLE_USER */
	char			*name;
	uid_t			uid;
};

static void samr_handle_free(struct samr_handle *h)
{
	g_free(h->name);
	g_free(h);
}

static int samr_handle_open(struct dcerpc_pdu *pdu,
			    enum samr_handle_type type, const char *name,
			    uid_t uid, struct dcerpc_context_handle *handle)
{
	struct samr_handle *h = g_try_malloc0(sizeof(*h));

	if (!h)
		return -1;
	h->type = type;
	h->uid = uid;
	if (name) {
		h->name = g_strdup(name);
		if (!h->name) {
			g_free(h);
			return -1;
		}
	}
	if (rpc_pipe_handle_open(rpc_pipe_of_pdu(pdu), h,
				 (GDestroyNotify)samr_handle_free, handle)) {
		samr_handle_free(h);
		return -1;
	}
	return 0;
}

/* The open handle, if it is one of type (or any type if type is -1) */
static struct samr_handle *
samr_handle_get(struct dcerpc_pdu *pdu,
		const struct dcerpc_context_handle *handle, int type)
{
	void *data;
	struct samr_handle *h;

	if (rpc_pipe_handle_lookup(rpc_pipe_of_pdu(pdu), handle, &data))
		return NULL;
	h = data;
	if (type >= 0 && h->type != (enum samr_handle_type)type)
		return NULL;
	return h;
}

/* A ksmbd user by RID; its name is the caller's to free */
static char *samr_user_name(uint32_t rid)
{
	struct ksmbd_user *user;
	struct passwd *pw;
	char *name;

	pw = getpwuid(rid);
	if (!pw)
		return NULL;
	user = usm_lookup_user(pw->pw_name);
	if (!user)
		return NULL;
	name = g_strdup(user->name);
	put_ksmbd_user(user);
	return name;
}

/* ------------------------------------------------------------------ */
/* Server                                                              */
/* ------------------------------------------------------------------ */

static int samr_connect2_stub(struct dcerpc_context *dce,
			      struct dcerpc_pdu *pdu,
			      void *reqv, void *repv)
{
	struct samr_Connect2_rep *rep = repv;

	if (samr_handle_open(pdu, SAMR_HANDLE_SERVER, NULL, 0,
			     &rep->ServerHandle))
		return -1;
	rep->status = KSMBD_RPC_OK;
	return 0;
}

static int samr_connect5_stub(struct dcerpc_context *dce,
			      struct dcerpc_pdu *pdu,
			      void *reqv, void *repv)
{
	struct samr_Connect5_rep *rep = repv;

	if (samr_handle_open(pdu, SAMR_HANDLE_SERVER, NULL, 0,
			     &rep->ServerHandle))
		return -1;
	/* [MS-SAMR] 3.1.5.1.1: version 1, revision 3, no extra features */
	rep->OutVersion = 1;
	rep->OutRevisionInfo.V1.Revision = 3;
	rep->status = KSMBD_RPC_OK;
	return 0;
}

/* The handle in the reply stays zeroed, as a closed handle is */
static int samr_close_handle_stub(struct dcerpc_context *dce,
				  struct dcerpc_pdu *pdu,
				  void *reqv, void *repv)
{
	struct samr_CloseHandle_req *req = reqv;
	struct samr_CloseHandle_rep *rep = repv;

	if (rpc_pipe_handle_close(rpc_pipe_of_pdu(pdu), &req->SamHandle))
		rep->status = STATUS_INVALID_HANDLE;
	else
		rep->status = KSMBD_RPC_OK;
	return 0;
}

static int samr_enum_domains_stub(struct dcerpc_context *dce,
				  struct dcerpc_pdu *pdu,
				  void *reqv, void *repv)
{
	struct samr_EnumerateDomainsInSamServer_req *req = reqv;
	struct samr_EnumerateDomainsInSamServer_rep *rep = repv;
	struct samr_SAMPR_RID_ENUMERATION *e;

	if (!samr_handle_get(pdu, &req->ServerHandle, SAMR_HANDLE_SERVER)) {
		rep->status = STATUS_INVALID_HANDLE;
		return 0;
	}
	e = dcerpc_alloc_data(pdu, 2 * sizeof(*e));
	if (!e)
		return -1;
	e[0].RelativeId = 0;
	e[0].Name = rpc_pdu_strdup(pdu, domain_name);
	e[1].RelativeId = 1;
	e[1].Name = rpc_pdu_strdup(pdu, "Builtin");
	if (!e[0].Name || !e[1].Name)
		return -1;
	rep->Buffer.EntriesRead = 2;
	rep->Buffer.Buffer = e;
	rep->CountReturned = 2;
	rep->status = KSMBD_RPC_OK;
	return 0;
}

static int samr_lookup_domain_stub(struct dcerpc_context *dce,
				   struct dcerpc_pdu *pdu,
				   void *reqv, void *repv)
{
	struct samr_LookupDomainInSamServer_req *req = reqv;
	struct samr_LookupDomainInSamServer_rep *rep = repv;
	struct smb_sid sid;

	if (!samr_handle_get(pdu, &req->ServerHandle, SAMR_HANDLE_SERVER)) {
		rep->status = STATUS_INVALID_HANDLE;
		return 0;
	}
	if (req->Name && !g_ascii_strcasecmp(req->Name, domain_name)) {
		smb_init_domain_sid(&sid);
	} else if (req->Name && !g_ascii_strcasecmp(req->Name, "Builtin")) {
		smb_copy_sid(&sid, &sid_builtin);
	} else {
		rep->status = STATUS_NO_SUCH_DOMAIN;
		return 0;
	}
	rep->DomainId = smb_sid_to_rpc(pdu, &sid);
	if (!rep->DomainId)
		return -1;
	rep->status = KSMBD_RPC_OK;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Domains                                                             */
/* ------------------------------------------------------------------ */

static int samr_open_domain_stub(struct dcerpc_context *dce,
				 struct dcerpc_pdu *pdu,
				 void *reqv, void *repv)
{
	struct samr_OpenDomain_req *req = reqv;
	struct samr_OpenDomain_rep *rep = repv;
	struct smb_sid sid, domain_sid;
	enum samr_handle_type type;

	if (!samr_handle_get(pdu, &req->ServerHandle, SAMR_HANDLE_SERVER)) {
		rep->status = STATUS_INVALID_HANDLE;
		return 0;
	}
	smb_sid_from_rpc(&sid, &req->DomainId);
	smb_init_domain_sid(&domain_sid);
	if (sid.num_subauth == domain_sid.num_subauth &&
	    !smb_compare_sids(&sid, &domain_sid)) {
		type = SAMR_HANDLE_DOMAIN;
	} else if (sid.num_subauth == sid_builtin.num_subauth &&
		   !smb_compare_sids(&sid, &sid_builtin)) {
		type = SAMR_HANDLE_BUILTIN;
	} else {
		rep->status = STATUS_NO_SUCH_DOMAIN;
		return 0;
	}
	if (samr_handle_open(pdu, type, NULL, 0, &rep->DomainHandle))
		return -1;
	rep->status = KSMBD_RPC_OK;
	return 0;
}

/*
 * Names of ksmbd users to their RIDs. Nothing maps in Builtin, which
 * has no members here.
 */
static int samr_lookup_names_stub(struct dcerpc_context *dce,
				  struct dcerpc_pdu *pdu,
				  void *reqv, void *repv)
{
	struct samr_LookupNamesInDomain_req *req = reqv;
	struct samr_LookupNamesInDomain_rep *rep = repv;
	struct samr_handle *h;
	uint32_t *rids, *uses, i, mapped = 0;

	h = samr_handle_get(pdu, &req->DomainHandle, -1);
	if (!h || (h->type != SAMR_HANDLE_DOMAIN &&
		   h->type != SAMR_HANDLE_BUILTIN)) {
		rep->status = STATUS_INVALID_HANDLE;
		return 0;
	}
	rids = dcerpc_alloc_data(pdu, MAX(req->Count, 1) * sizeof(*rids));
	uses = dcerpc_alloc_data(pdu, MAX(req->Count, 1) * sizeof(*uses));
	if (!rids || !uses)
		return -1;

	for (i = 0; i < req->Count; i++) {
		struct ksmbd_user *user = NULL;

		uses[i] = SID_TYPE_UNKNOWN;
		if (h->type == SAMR_HANDLE_DOMAIN && req->Names[i])
			user = usm_lookup_user(req->Names[i]);
		if (!user)
			continue;
		rids[i] = user->uid;
		uses[i] = SID_TYPE_USER;
		mapped++;
		put_ksmbd_user(user);
	}
	rep->RelativeIds.Count = req->Count;
	rep->RelativeIds.Element = rids;
	rep->Use.Count = req->Count;
	rep->Use.Element = uses;
	if (mapped == req->Count)
		rep->status = KSMBD_RPC_OK;
	else
		rep->status = mapped ? STATUS_SOME_NOT_MAPPED :
				       STATUS_NONE_MAPPED;
	return 0;
}

/* The domain's aliases the SIDs are members of: none */
static int samr_get_alias_membership_stub(struct dcerpc_context *dce,
					  struct dcerpc_pdu *pdu,
					  void *reqv, void *repv)
{
	struct samr_GetAliasMembership_req *req = reqv;
	struct samr_GetAliasMembership_rep *rep = repv;
	struct samr_handle *h;

	h = samr_handle_get(pdu, &req->DomainHandle, -1);
	if (!h || (h->type != SAMR_HANDLE_DOMAIN &&
		   h->type != SAMR_HANDLE_BUILTIN)) {
		rep->status = STATUS_INVALID_HANDLE;
		return 0;
	}
	rep->status = KSMBD_RPC_OK;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Users                                                               */
/* ------------------------------------------------------------------ */

static int samr_open_user_stub(struct dcerpc_context *dce,
			       struct dcerpc_pdu *pdu,
			       void *reqv, void *repv)
{
	struct samr_OpenUser_req *req = reqv;
	struct samr_OpenUser_rep *rep = repv;
	g_autofree char *name = NULL;

	if (!samr_handle_get(pdu, &req->DomainHandle, SAMR_HANDLE_DOMAIN)) {
		rep->status = STATUS_INVALID_HANDLE;
		return 0;
	}
	name = samr_user_name(req->UserId);
	if (!name) {
		rep->status = STATUS_NO_SUCH_USER;
		return 0;
	}
	if (samr_handle_open(pdu, SAMR_HANDLE_USER, name, req->UserId,
			     &rep->UserHandle))
		return -1;
	rep->status = KSMBD_RPC_OK;
	return 0;
}

/* UserAllInformation, the level Windows asks for */
static int samr_user_all_info(struct dcerpc_pdu *pdu, struct samr_handle *h,
			      struct samr_SAMPR_USER_ALL_INFORMATION *all)
{
	char hostname[NAME_MAX];
	uint8_t *hours;

	if (gethostname(hostname, sizeof(hostname)))
		return -1;
	hostname[sizeof(hostname) - 1] = '\0';

	all->UserName = rpc_pdu_strdup(pdu, h->name);
	all->FullName = rpc_pdu_strdup(pdu, h->name);
	all->HomeDirectory = dcerpc_alloc_data(pdu, strlen(hostname) +
					       strlen(h->name) + 4);
	all->ProfilePath = dcerpc_alloc_data(pdu, strlen(hostname) +
					     strlen(h->name) + 12);
	hours = dcerpc_alloc_data(pdu, 21);
	if (!all->UserName || !all->FullName || !all->HomeDirectory ||
	    !all->ProfilePath || !hours)
		return -1;
	sprintf(all->HomeDirectory, "\\\\%s\\%s", hostname, h->name);
	sprintf(all->ProfilePath, "\\\\%s\\%s\\profile", hostname, h->name);
	all->HomeDirectoryDrive = rpc_pdu_strdup(pdu, "");
	all->ScriptPath = rpc_pdu_strdup(pdu, "");
	all->AdminComment = rpc_pdu_strdup(pdu, "");
	all->WorkStations = rpc_pdu_strdup(pdu, "");
	all->UserComment = rpc_pdu_strdup(pdu, "");
	all->Parameters = rpc_pdu_strdup(pdu, "");

	all->UserId = h->uid;
	all->PrimaryGroupId = DOMAIN_GROUP_RID_USERS;
	all->UserAccountControl = SAMR_USER_NORMAL_ACCOUNT;
	all->WhichFields = 0x00FFFFFF;

	/* may log on at any hour of the week */
	memset(hours, 0xff, 21);
	all->LogonHours.UnitsPerWeek = 168;
	all->LogonHours.LogonHours.max_count = 1260;
	all->LogonHours.LogonHours.len = 21;
	all->LogonHours.LogonHours.data = hours;
	return 0;
}

static int samr_query_user_info_stub(struct dcerpc_context *dce,
				     struct dcerpc_pdu *pdu,
				     void *reqv, void *repv)
{
	struct samr_QueryInformationUser_req *req = reqv;
	struct samr_QueryInformationUser_rep *rep = repv;
	union samr_SAMPR_USER_INFO_BUFFER *info;
	struct samr_handle *h;

	h = samr_handle_get(pdu, &req->UserHandle, SAMR_HANDLE_USER);
	if (!h) {
		rep->status = STATUS_INVALID_HANDLE;
		return 0;
	}
	if (req->UserInformationClass != SAMR_UserAllInformation) {
		rep->status = STATUS_INVALID_INFO_CLASS;
		return 0;
	}
	info = dcerpc_alloc_data(pdu, sizeof(*info));
	if (!info || samr_user_all_info(pdu, h, &info->All))
		return -1;
	rep->Buffer = info;
	rep->status = KSMBD_RPC_OK;
	return 0;
}

/* Domain Users, the primary group of every user */
static int samr_get_groups_for_user_stub(struct dcerpc_context *dce,
					 struct dcerpc_pdu *pdu,
					 void *reqv, void *repv)
{
	struct samr_GetGroupsForUser_req *req = reqv;
	struct samr_GetGroupsForUser_rep *rep = repv;
	struct samr_GROUP_MEMBERSHIP *g;

	if (!samr_handle_get(pdu, &req->UserHandle, SAMR_HANDLE_USER)) {
		rep->status = STATUS_INVALID_HANDLE;
		return 0;
	}
	g = dcerpc_alloc_data(pdu, sizeof(*g));
	if (!g)
		return -1;
	g->RelativeId = DOMAIN_GROUP_RID_USERS;
	g->Attributes = SE_GROUP_DEFAULT;
	rep->Groups.MembershipCount = 1;
	rep->Groups.Groups = g;
	rep->status = KSMBD_RPC_OK;
	return 0;
}

static int set_ace(struct dcerpc_pdu *pdu, ACCESS_ALLOWED_ACE *ace,
		   ACCESS_MASK mask, const struct smb_sid *domain,
		   uint32_t rid)
{
	struct smb_sid sid;
	RPC_SID *rsid;

	smb_copy_sid(&sid, domain);
	if (rid)
		sid.sub_auth[sid.num_subauth++] = rid;
	rsid = smb_sid_to_rpc(pdu, &sid);
	if (!rsid)
		return -1;
	ace->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
	ace->Mask = mask;
	ace->Sid = *rsid;
	return 0;
}

/*
 * The security descriptor of an object, as Windows gives one for a user:
 * read for everyone, full control for Administrators and Account
 * Operators, and for a user object read and change password for the
 * user.
 */
static int samr_query_security_stub(struct dcerpc_context *dce,
				    struct dcerpc_pdu *pdu,
				    void *reqv, void *repv)
{
	struct samr_QuerySecurityObject_req *req = reqv;
	struct samr_QuerySecurityObject_rep *rep = repv;
	struct samr_handle *h;
	struct smb_sid domain;
	SECURITY_DESCRIPTOR *sd;
	ACL *dacl;

	h = samr_handle_get(pdu, &req->ObjectHandle, -1);
	if (!h) {
		rep->status = STATUS_INVALID_HANDLE;
		return 0;
	}
	sd = dcerpc_alloc_data(pdu, sizeof(*sd));
	dacl = dcerpc_alloc_data(pdu, sizeof(*dacl));
	if (!sd || !dacl)
		return -1;
	dacl->AclRevision = 2;
	dacl->AceCount = h->type == SAMR_HANDLE_USER ? 4 : 3;
	dacl->Aces = dcerpc_alloc_data(pdu, 4 * sizeof(*dacl->Aces));
	if (!dacl->Aces)
		return -1;

	smb_init_domain_sid(&domain);
	if (set_ace(pdu, &dacl->Aces[0], 0x0002035b, &sid_everyone, 0) ||
	    set_ace(pdu, &dacl->Aces[1], 0x000f07ff, &sid_builtin, 544) ||
	    set_ace(pdu, &dacl->Aces[2], 0x000f07ff, &sid_builtin, 548))
		return -1;
	if (h->type == SAMR_HANDLE_USER &&
	    set_ace(pdu, &dacl->Aces[3], 0x00020044, &domain, h->uid))
		return -1;

	sd->Revision = 1;
	sd->Control = SE_SELF_RELATIVE | SE_DACL_PRESENT;
	sd->Dacl = dacl;
	rep->SecurityDescriptor.SecurityDescriptor = sd;
	rep->status = KSMBD_RPC_OK;
	return 0;
}

static const struct dcerpc_stub samr_stubs[] = {
	{ SAMR_CLOSEHANDLE, "CloseHandle", samr_close_handle_stub },
	{ SAMR_QUERYSECURITYOBJECT, "QuerySecurityObject",
	  samr_query_security_stub },
	{ SAMR_LOOKUPDOMAININSAMSERVER, "LookupDomainInSamServer",
	  samr_lookup_domain_stub },
	{ SAMR_ENUMERATEDOMAINSINSAMSERVER, "EnumerateDomainsInSamServer",
	  samr_enum_domains_stub },
	{ SAMR_OPENDOMAIN, "OpenDomain", samr_open_domain_stub },
	{ SAMR_GETALIASMEMBERSHIP, "GetAliasMembership",
	  samr_get_alias_membership_stub },
	{ SAMR_LOOKUPNAMESINDOMAIN, "LookupNamesInDomain",
	  samr_lookup_names_stub },
	{ SAMR_OPENUSER, "OpenUser", samr_open_user_stub },
	{ SAMR_QUERYINFORMATIONUSER, "QueryInformationUser",
	  samr_query_user_info_stub },
	{ SAMR_GETGROUPSFORUSER, "GetGroupsForUser",
	  samr_get_groups_for_user_stub },
	{ SAMR_CONNECT2, "Connect2", samr_connect2_stub },
	{ SAMR_CONNECT5, "Connect5", samr_connect5_stub },
	{ -1, NULL, NULL }
};

struct dcerpc_server *rpc_samr_endpoint(void)
{
	struct dcerpc_server *srv = dcerpc_server_create("samr");

	if (srv && dcerpc_server_add_interface(srv, &samr_interface,
					       samr_procs, samr_stubs,
					       DCERPC_SERVER_ALL_NDR)) {
		dcerpc_server_destroy(srv);
		srv = NULL;
	}
	return srv;
}

void rpc_samr_init(void)
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

void rpc_samr_destroy(void)
{
	g_free(domain_name);
	domain_name = NULL;
}
