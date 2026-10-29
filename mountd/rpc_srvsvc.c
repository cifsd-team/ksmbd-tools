// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

/*
 * srvsvc ([MS-SRVS]) on libdcerpc's server runtime. The coders are
 * libdcerpc's, generated from its srvsvc.idl; the stubs below fill the
 * replies from the share table and the global configuration.
 */

#include <glib.h>
#include <string.h>
#include <linux/ksmbd_server.h>

#include <dcerpc/dcerpc.h>
#include <dcerpc/dcerpc-dtyp.h>
#include <dcerpc/server.h>
#include <dcerpc/srvsvc.h>

#include <management/share.h>

#include <rpc.h>
#include <rpc_srvsvc.h>
#include <smbacl.h>
#include <tools.h>

#define SHARE_TYPE_DISKTREE		0
#define SHARE_TYPE_IPC			3

/* [MS-ERREF] 2.2 */
#define NERR_NET_NAME_NOT_FOUND		2310

#define SRVSVC_VERSION_MAJOR		0x2
#define SRVSVC_VERSION_MINOR		0x1
#define SRVSVC_SERVER_TYPE		(SRVSVC_SV_TYPE_SERVER | \
					 SRVSVC_SV_TYPE_NT | \
					 SRVSVC_SV_TYPE_SERVER_NT)

static int share_level_supported(uint32_t level)
{
	return level == 0 || level == 1 || level == 2 || level == 502;
}

static int __share_type(struct ksmbd_share *share)
{
	if (test_share_flag(share, KSMBD_SHARE_FLAG_PIPE))
		return SHARE_TYPE_IPC;
	if (share->name && !g_ascii_strcasecmp(share->name, "IPC$"))
		return SHARE_TYPE_IPC;
	return SHARE_TYPE_DISKTREE;
}

static uint32_t __share_max_users(const struct ksmbd_share *share)
{
	if (share->max_connections <= 0)
		return (uint32_t)-1;
	return (uint32_t)share->max_connections;
}

static uint32_t __share_current_users(const struct ksmbd_share *share)
{
	if (share->num_connections <= 0)
		return 0;
	return (uint32_t)share->num_connections;
}

/* ------------------------------------------------------------------ */
/* The security descriptor of a share, for level 502                   */
/* ------------------------------------------------------------------ */

/* S-1-1-0, Everyone */
static const struct smb_sid sid_everyone = {
	1, 1, {0, 0, 0, 0, 0, 1}, {0} };
/* S-1-5-32, the Builtin domain */
static const struct smb_sid sid_builtin = {
	1, 1, {0, 0, 0, 0, 0, 5}, {32} };

/* The ACEs: read for Everyone, full control for Administrators and
 * Account Operators, and read for the machine's own domain. */
struct share_ace {
	ACCESS_MASK		mask;
	const struct smb_sid	*domain;
	uint32_t		rid;	/* appended to domain, if not 0 */
};

static void share_ace_sid(const struct share_ace *ace, struct smb_sid *sid)
{
	if (ace->domain)
		smb_copy_sid(sid, ace->domain);
	else
		smb_init_domain_sid(sid);
	if (ace->rid)
		sid->sub_auth[sid->num_subauth++] = ace->rid;
}

static const struct share_ace share_aces[] = {
	{ 0x0002035b, &sid_everyone, 0 },
	{ 0x000f07ff, &sid_builtin, 544 },
	{ 0x000f07ff, &sid_builtin, 548 },
	{ 0x00020044, NULL, 0 },
};

/* The self-relative descriptor's size on the wire */
static size_t share_sd_size(void)
{
	size_t sz = 20 + 8;
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(share_aces); i++) {
		struct smb_sid sid;

		share_ace_sid(&share_aces[i], &sid);
		sz += 8 + 8 + 4 * sid.num_subauth;
	}
	return sz;
}

static SECURITY_DESCRIPTOR *share_sd(struct dcerpc_pdu *pdu)
{
	SECURITY_DESCRIPTOR *sd;
	ACL *dacl;
	size_t i;

	sd = dcerpc_alloc_data(pdu, sizeof(*sd));
	dacl = dcerpc_alloc_data(pdu, sizeof(*dacl));
	if (!sd || !dacl)
		return NULL;
	dacl->AclRevision = ACL_REVISION;
	dacl->AceCount = G_N_ELEMENTS(share_aces);
	dacl->Aces = dcerpc_alloc_data(pdu, dacl->AceCount *
				       sizeof(*dacl->Aces));
	if (!dacl->Aces)
		return NULL;
	for (i = 0; i < G_N_ELEMENTS(share_aces); i++) {
		struct smb_sid sid;
		RPC_SID *rsid;

		share_ace_sid(&share_aces[i], &sid);
		rsid = smb_sid_to_rpc(pdu, &sid);
		if (!rsid)
			return NULL;
		dacl->Aces[i].Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
		dacl->Aces[i].Mask = share_aces[i].mask;
		dacl->Aces[i].Sid = *rsid;
	}
	sd->Revision = 1;
	sd->Control = SE_SELF_RELATIVE | SE_DACL_PRESENT;
	sd->Dacl = dacl;
	return sd;
}

/* ------------------------------------------------------------------ */
/* Share information                                                   */
/* ------------------------------------------------------------------ */

/* Fill a SHARE_INFO_0, _1, _2 or _502_I; returns -1 if out of memory */
static int fill_share_info(struct dcerpc_pdu *pdu, struct ksmbd_share *share,
			   uint32_t level, void *info)
{
	struct srvsvc_SHARE_INFO_0 *info0 = info;
	struct srvsvc_SHARE_INFO_1 *info1 = info;
	struct srvsvc_SHARE_INFO_2 *info2 = info;
	struct srvsvc_SHARE_INFO_502_I *info502 = info;

	switch (level) {
	case 0:
		info0->NetName = rpc_pdu_strdup(pdu, share->name);
		return info0->NetName ? 0 : -1;
	case 1:
		info1->NetName = rpc_pdu_strdup(pdu, share->name);
		info1->Type = __share_type(share);
		info1->Remark = rpc_pdu_strdup(pdu, share->comment ?: "");
		return info1->NetName && info1->Remark ? 0 : -1;
	case 2:
		info2->NetName = rpc_pdu_strdup(pdu, share->name);
		info2->Type = __share_type(share);
		info2->Remark = rpc_pdu_strdup(pdu, share->comment ?: "");
		info2->Permissions = 0;
		info2->MaxUses = __share_max_users(share);
		info2->CurrentUses = __share_current_users(share);
		info2->Path = rpc_pdu_strdup(pdu, share->path ?: "");
		info2->Passwd = rpc_pdu_strdup(pdu, "");
		return info2->NetName && info2->Remark && info2->Path &&
		       info2->Passwd ? 0 : -1;
	case 502:
		if (fill_share_info(pdu, share, 2, info))
			return -1;
		info502->SecurityDescriptor = share_sd(pdu);
		return info502->SecurityDescriptor ? 0 : -1;
	default:
		return -1;
	}
}

/* What a string takes in NDR32: the counts and the UTF-16, with its NUL */
static size_t ndr_string_size(const char *s)
{
	glong units = 0;
	gunichar2 *utf16 = g_utf8_to_utf16(s ?: "", -1, NULL, &units, NULL);

	g_free(utf16);
	return 12 + ((2 * ((size_t)units + 1) + 3) & ~(size_t)3);
}

/* What an entry takes in the reply, for PreferedMaximumLength */
static size_t share_info_size(struct ksmbd_share *share, uint32_t level)
{
	size_t sz;

	switch (level) {
	case 0:
		return 4 + ndr_string_size(share->name);
	case 1:
		return 12 + ndr_string_size(share->name) +
		       ndr_string_size(share->comment ?: "");
	case 2:
	case 502:
		sz = 32 + ndr_string_size(share->name) +
		     ndr_string_size(share->comment ?: "") +
		     ndr_string_size(share->path ?: "") +
		     ndr_string_size("");
		if (level == 502)
			sz += 8 + 4 + ((share_sd_size() + 3) & ~(size_t)3);
		return sz;
	default:
		return 0;
	}
}

static size_t share_info_entry_size(uint32_t level)
{
	switch (level) {
	case 0:
		return sizeof(struct srvsvc_SHARE_INFO_0);
	case 1:
		return sizeof(struct srvsvc_SHARE_INFO_1);
	case 2:
		return sizeof(struct srvsvc_SHARE_INFO_2);
	default:
		return sizeof(struct srvsvc_SHARE_INFO_502_I);
	}
}

static void collect_share(struct ksmbd_share *share, GPtrArray *shares)
{
	if (!test_share_flag(share, KSMBD_SHARE_FLAG_BROWSEABLE) ||
	    !test_share_flag(share, KSMBD_SHARE_FLAG_AVAILABLE))
		return;
	if (get_ksmbd_share(share))
		g_ptr_array_add(shares, share);
}

static gint share_cmp(gconstpointer a, gconstpointer b)
{
	const struct ksmbd_share *sa = *(struct ksmbd_share * const *)a;
	const struct ksmbd_share *sb = *(struct ksmbd_share * const *)b;

	return g_ascii_strcasecmp(sa->name, sb->name);
}

/*
 * NetrShareEnum: the browseable shares in name order, from ResumeHandle
 * on, as many as fit PreferedMaximumLength with the reply's own fixed
 * part. TotalEntries counts the entries from ResumeHandle on.
 */
static int srvsvc_share_enum_stub(struct dcerpc_context *dce,
				  struct dcerpc_pdu *pdu,
				  void *reqv, void *repv)
{
	struct srvsvc_NetrShareEnum_req *req = reqv;
	struct srvsvc_NetrShareEnum_rep *rep = repv;
	uint32_t level = req->InfoStruct.Level;
	size_t entry_sz = share_info_entry_size(level);
	GPtrArray *shares;
	size_t used = 12;
	guint first, n, i;
	uint8_t *buf;
	int ret = 0;

	rep->InfoStruct.Level = level;
	if (!share_level_supported(level)) {
		rep->status = KSMBD_RPC_EINVALID_LEVEL;
		return 0;
	}
	if (rpc_pipe_restricted(rpc_pipe_of_pdu(pdu))) {
		rep->status = KSMBD_RPC_EACCESS_DENIED;
		return 0;
	}

	shares = g_ptr_array_new_with_free_func(
			(GDestroyNotify)put_ksmbd_share);
	shm_iter_shares((share_cb)collect_share, shares);
	g_ptr_array_sort(shares, share_cmp);

	first = MIN(req->ResumeHandle, shares->len);
	for (n = first; n < shares->len; n++) {
		size_t sz = share_info_size(g_ptr_array_index(shares, n),
					    level);

		if (req->PreferedMaximumLength != UINT32_MAX &&
		    (used > req->PreferedMaximumLength ||
		     sz > req->PreferedMaximumLength - used))
			break;
		used += sz;
	}

	buf = dcerpc_alloc_data(pdu, MAX(n - first, 1) * entry_sz);
	if (!buf) {
		ret = -1;
		goto out;
	}
	for (i = first; i < n; i++) {
		if (fill_share_info(pdu, g_ptr_array_index(shares, i), level,
				    buf + (i - first) * entry_sz)) {
			ret = -1;
			goto out;
		}
	}
	switch (level) {
	case 0:
		rep->InfoStruct.ShareInfo.Level0.EntriesRead = n - first;
		rep->InfoStruct.ShareInfo.Level0.Buffer = (void *)buf;
		break;
	case 1:
		rep->InfoStruct.ShareInfo.Level1.EntriesRead = n - first;
		rep->InfoStruct.ShareInfo.Level1.Buffer = (void *)buf;
		break;
	case 2:
		rep->InfoStruct.ShareInfo.Level2.EntriesRead = n - first;
		rep->InfoStruct.ShareInfo.Level2.Buffer = (void *)buf;
		break;
	default:
		rep->InfoStruct.ShareInfo.Level502.EntriesRead = n - first;
		rep->InfoStruct.ShareInfo.Level502.Buffer = (void *)buf;
		break;
	}
	rep->TotalEntries = shares->len - first;
	if (n < shares->len) {
		rep->ResumeHandle = n;
		rep->status = KSMBD_RPC_EMORE_DATA;
	} else {
		rep->ResumeHandle = 0;
		rep->status = KSMBD_RPC_OK;
	}
out:
	g_ptr_array_free(shares, TRUE);
	return ret;
}

static int srvsvc_share_get_info_stub(struct dcerpc_context *dce,
				      struct dcerpc_pdu *pdu,
				      void *reqv, void *repv)
{
	struct srvsvc_NetrShareGetInfo_req *req = reqv;
	struct srvsvc_NetrShareGetInfo_rep *rep = repv;
	struct ksmbd_share *share;
	int ret = 0;

	if (!share_level_supported(req->Level)) {
		rep->status = KSMBD_RPC_EINVALID_LEVEL;
		return 0;
	}
	if (rpc_pipe_restricted(rpc_pipe_of_pdu(pdu))) {
		rep->status = KSMBD_RPC_EACCESS_DENIED;
		return 0;
	}

	share = req->NetName ? shm_lookup_share(req->NetName) : NULL;
	if (!share || !test_share_flag(share, KSMBD_SHARE_FLAG_AVAILABLE)) {
		rep->status = NERR_NET_NAME_NOT_FOUND;
		goto out;
	}
	if (fill_share_info(pdu, share, req->Level, &rep->InfoStruct)) {
		ret = -1;
		goto out;
	}
	rep->status = KSMBD_RPC_OK;
out:
	if (share)
		put_ksmbd_share(share);
	return ret;
}

/* ------------------------------------------------------------------ */
/* Server information                                                  */
/* ------------------------------------------------------------------ */

/* NetrServerGetInfo, levels 100 to 103 */
static int srvsvc_server_get_info_stub(struct dcerpc_context *dce,
				       struct dcerpc_pdu *pdu,
				       void *reqv, void *repv)
{
	struct srvsvc_NetrServerGetInfo_req *req = reqv;
	struct srvsvc_NetrServerGetInfo_rep *rep = repv;
	struct srvsvc_SERVER_INFO_103 info;

	if (req->Level < 100 || req->Level > 103) {
		rep->status = KSMBD_RPC_EINVALID_LEVEL;
		return 0;
	}
	if (rpc_pipe_restricted(rpc_pipe_of_pdu(pdu))) {
		rep->status = KSMBD_RPC_EACCESS_DENIED;
		return 0;
	}

	/*
	 * The levels are prefixes of one another: fill a 103 and copy the
	 * prefix the level asks for into the union's arm.
	 */
	memset(&info, 0, sizeof(info));
	info.PlatformId = SRVSVC_PLATFORM_ID_NT;
	info.Name = rpc_pdu_strdup(pdu, global_conf.netbios_name ?: "");
	info.VersionMajor = SRVSVC_VERSION_MAJOR;
	info.VersionMinor = SRVSVC_VERSION_MINOR;
	info.Type = SRVSVC_SERVER_TYPE;
	info.Comment = rpc_pdu_strdup(pdu, global_conf.server_string ?: "");
	info.Users = global_conf.max_connections;
	info.Disc = global_conf.deadtime;
	info.UserPath = rpc_pdu_strdup(pdu, global_conf.root_dir ?: "");
	if (!info.Name || !info.Comment || !info.UserPath)
		return -1;

	switch (req->Level) {
	case 100:
		memcpy(&rep->InfoStruct.ServerInfo100, &info,
		       sizeof(rep->InfoStruct.ServerInfo100));
		break;
	case 101:
		memcpy(&rep->InfoStruct.ServerInfo101, &info,
		       sizeof(rep->InfoStruct.ServerInfo101));
		break;
	case 102:
		memcpy(&rep->InfoStruct.ServerInfo102, &info,
		       sizeof(rep->InfoStruct.ServerInfo102));
		break;
	default:
		rep->InfoStruct.ServerInfo103 = info;
		break;
	}
	rep->status = KSMBD_RPC_OK;
	return 0;
}

static const struct dcerpc_stub srvsvc_stubs[] = {
	{ SRVSVC_NETRSHAREENUM, "NetrShareEnum", srvsvc_share_enum_stub },
	{ SRVSVC_NETRSHAREGETINFO, "NetrShareGetInfo",
	  srvsvc_share_get_info_stub },
	{ SRVSVC_NETRSERVERGETINFO, "NetrServerGetInfo",
	  srvsvc_server_get_info_stub },
	{ -1, NULL, NULL }
};

struct dcerpc_server *rpc_srvsvc_endpoint(void)
{
	struct dcerpc_server *srv = dcerpc_server_create("srvsvc");

	if (srv && dcerpc_server_add_interface(srv, &srvsvc_interface,
					       srvsvc_procs, srvsvc_stubs,
					       DCERPC_SERVER_ALL_NDR)) {
		dcerpc_server_destroy(srv);
		srv = NULL;
	}
	return srv;
}
