// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

/*
 * srvsvc ([MS-SRVS]) on libdcerpc's server runtime. The coders are
 * libdcerpc's, generated from its srvsvc.idl; the stubs below fill the
 * replies from the share table.
 */

#include <glib.h>
#include <string.h>
#include <linux/ksmbd_server.h>

#include <dcerpc/dcerpc.h>
#include <dcerpc/server.h>
#include <dcerpc/srvsvc.h>

#include <management/share.h>

#include <rpc.h>
#include <rpc_srvsvc.h>
#include <tools.h>

#define SHARE_TYPE_DISKTREE		0
#define SHARE_TYPE_IPC			3

/* [MS-ERREF] 2.2 */
#define NERR_NET_NAME_NOT_FOUND		2310

static int __share_type(struct ksmbd_share *share)
{
	if (test_share_flag(share, KSMBD_SHARE_FLAG_PIPE))
		return SHARE_TYPE_IPC;
	if (!g_ascii_strncasecmp(share->name, "IPC", strlen("IPC")))
		return SHARE_TYPE_IPC;
	return SHARE_TYPE_DISKTREE;
}

/* Fill a SHARE_INFO_0 or _1; returns -1 if out of memory */
static int fill_share_info(struct dcerpc_pdu *pdu, struct ksmbd_share *share,
			   uint32_t level, void *info)
{
	struct srvsvc_SHARE_INFO_0 *info0 = info;
	struct srvsvc_SHARE_INFO_1 *info1 = info;

	if (level == 0) {
		info0->NetName = rpc_pdu_strdup(pdu, share->name);
		return info0->NetName ? 0 : -1;
	}
	info1->NetName = rpc_pdu_strdup(pdu, share->name);
	info1->Type = __share_type(share);
	info1->Remark = rpc_pdu_strdup(pdu, share->comment ?: "");
	return info1->NetName && info1->Remark ? 0 : -1;
}

/* About what an entry takes in the reply, for PreferedMaximumLength */
static size_t share_info_size(struct ksmbd_share *share, uint32_t level)
{
	size_t sz = 12 + 2 * (strlen(share->name) + 1);

	if (level == 1)
		sz += 4 + 12 + 2 * (strlen(share->comment ?: "") + 1);
	return sz;
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
 * on, as many as fit PreferedMaximumLength (at least one).
 */
static int srvsvc_share_enum_stub(struct dcerpc_context *dce,
				  struct dcerpc_pdu *pdu,
				  void *reqv, void *repv)
{
	struct srvsvc_NetrShareEnum_req *req = reqv;
	struct srvsvc_NetrShareEnum_rep *rep = repv;
	uint32_t level = req->InfoStruct.Level;
	size_t entry_sz = level == 0 ? sizeof(struct srvsvc_SHARE_INFO_0) :
				       sizeof(struct srvsvc_SHARE_INFO_1);
	GPtrArray *shares;
	size_t used = 0;
	guint first, n, i;
	uint8_t *buf;
	int ret = 0;

	rep->InfoStruct.Level = level;
	if (rpc_pipe_restricted(rpc_pipe_of_pdu(pdu))) {
		rep->status = KSMBD_RPC_EACCESS_DENIED;
		return 0;
	}
	if (level != 0 && level != 1) {
		rep->status = KSMBD_RPC_EINVALID_LEVEL;
		return 0;
	}

	shares = g_ptr_array_new_with_free_func(
			(GDestroyNotify)put_ksmbd_share);
	shm_iter_shares((share_cb)collect_share, shares);
	g_ptr_array_sort(shares, share_cmp);

	first = MIN(req->ResumeHandle, shares->len);
	for (n = first; n < shares->len; n++) {
		used += share_info_size(g_ptr_array_index(shares, n), level);
		if (n > first && used > req->PreferedMaximumLength)
			break;
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
	if (level == 0) {
		rep->InfoStruct.ShareInfo.Level0.EntriesRead = n - first;
		rep->InfoStruct.ShareInfo.Level0.Buffer = (void *)buf;
	} else {
		rep->InfoStruct.ShareInfo.Level1.EntriesRead = n - first;
		rep->InfoStruct.ShareInfo.Level1.Buffer = (void *)buf;
	}
	rep->TotalEntries = shares->len;
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

/* Hidden from the host the request names, as the old code did */
static int share_hidden_from(struct ksmbd_share *share, char *host)
{
	int ret;

	ret = shm_lookup_hosts_map(share, KSMBD_SHARE_HOSTS_ALLOW_MAP, host);
	if (ret == -ENOENT)
		return 1;
	if (ret)
		return !shm_lookup_hosts_map(share, KSMBD_SHARE_HOSTS_DENY_MAP,
					     host);
	return 0;
}

static int srvsvc_share_get_info_stub(struct dcerpc_context *dce,
				      struct dcerpc_pdu *pdu,
				      void *reqv, void *repv)
{
	struct srvsvc_NetrShareGetInfo_req *req = reqv;
	struct srvsvc_NetrShareGetInfo_rep *rep = repv;
	struct ksmbd_share *share;
	int ret = 0;

	if (rpc_pipe_restricted(rpc_pipe_of_pdu(pdu))) {
		rep->status = KSMBD_RPC_EACCESS_DENIED;
		return 0;
	}
	if (req->Level != 0 && req->Level != 1) {
		rep->status = KSMBD_RPC_EINVALID_LEVEL;
		return 0;
	}

	share = req->NetName ? shm_lookup_share(req->NetName) : NULL;
	if (!share || !test_share_flag(share, KSMBD_SHARE_FLAG_AVAILABLE) ||
	    share_hidden_from(share, req->ServerName ?: "")) {
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

static const struct dcerpc_stub srvsvc_stubs[] = {
	{ SRVSVC_NETRSHAREENUM, "NetrShareEnum", srvsvc_share_enum_stub },
	{ SRVSVC_NETRSHAREGETINFO, "NetrShareGetInfo",
	  srvsvc_share_get_info_stub },
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
