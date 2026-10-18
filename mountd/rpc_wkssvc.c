// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

/*
 * wkssvc ([MS-WKST]) on libdcerpc's server runtime. The coders are
 * libdcerpc's, generated from its wkssvc.idl; the stub below fills the
 * reply from the global configuration.
 */

#include <glib.h>
#include <string.h>
#include <linux/ksmbd_server.h>

#include <dcerpc/dcerpc.h>
#include <dcerpc/server.h>
#include <dcerpc/wkssvc.h>

#include <rpc.h>
#include <rpc_wkssvc.h>
#include <tools.h>

#define WKSSVC_PLATFORM_ID_NT		500

#define WKSSVC_VERSION_MAJOR		0x2
#define WKSSVC_VERSION_MINOR		0x1

/*
 * NetrWkstaGetInfo, level 100 only: 101 and 102 need an administrator
 * on Windows, and nothing asks ksmbd for them.
 */
static int wkssvc_wksta_get_info_stub(struct dcerpc_context *dce,
				      struct dcerpc_pdu *pdu,
				      void *reqv, void *repv)
{
	struct wkssvc_NetrWkstaGetInfo_req *req = reqv;
	struct wkssvc_NetrWkstaGetInfo_rep *rep = repv;
	struct wkssvc_WKSTA_INFO_100 *info = &rep->WkstaInfo.WkstaInfo100;
	const char *name = global_conf.netbios_name;

	if (rpc_pipe_restricted(rpc_pipe_of_pdu(pdu))) {
		rep->status = KSMBD_RPC_EACCESS_DENIED;
		return 0;
	}
	if (req->Level != 100) {
		rep->status = KSMBD_RPC_EINVALID_LEVEL;
		return 0;
	}

	/* Without a netbios name, the name the client called us by */
	if (!name || !name[0]) {
		name = req->ServerName ? req->ServerName : "";
		while (*name == '\\')
			name++;
	}

	info->PlatformId = WKSSVC_PLATFORM_ID_NT;
	info->ComputerName = rpc_pdu_strdup(pdu, name);
	info->LanGroup = rpc_pdu_strdup(pdu, global_conf.work_group ?: "");
	info->VerMajor = WKSSVC_VERSION_MAJOR;
	info->VerMinor = WKSSVC_VERSION_MINOR;
	if (!info->ComputerName || !info->LanGroup)
		return -1;
	rep->status = KSMBD_RPC_OK;
	return 0;
}

static const struct dcerpc_stub wkssvc_stubs[] = {
	{ WKSSVC_NETRWKSTAGETINFO, "NetrWkstaGetInfo",
	  wkssvc_wksta_get_info_stub },
	{ -1, NULL, NULL }
};

struct dcerpc_server *rpc_wkssvc_endpoint(void)
{
	struct dcerpc_server *srv = dcerpc_server_create("wkssvc");

	if (srv && dcerpc_server_add_interface(srv, &wkssvc_interface,
					       wkssvc_procs, wkssvc_stubs,
					       DCERPC_SERVER_ALL_NDR)) {
		dcerpc_server_destroy(srv);
		srv = NULL;
	}
	return srv;
}
