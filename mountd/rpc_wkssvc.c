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

#include <management/session.h>

#include <rpc.h>
#include <rpc_wkssvc.h>
#include <tools.h>

#define WKSSVC_VERSION_MAJOR		0x2
#define WKSSVC_VERSION_MINOR		0x1

/* The name the client called us by, without the leading backslashes */
static const char *called_name(const char *server_name)
{
	const char *name = server_name ? server_name : "";

	while (*name == '\\')
		name++;
	return name;
}

/* NetrWkstaGetInfo, levels 100, 101 and 102 */
static int wkssvc_wksta_get_info_stub(struct dcerpc_context *dce,
				      struct dcerpc_pdu *pdu,
				      void *reqv, void *repv)
{
	struct wkssvc_NetrWkstaGetInfo_req *req = reqv;
	struct wkssvc_NetrWkstaGetInfo_rep *rep = repv;
	struct wkssvc_WKSTA_INFO_102 info;
	const char *name = global_conf.netbios_name;

	if (rpc_pipe_restricted(rpc_pipe_of_pdu(pdu))) {
		rep->status = KSMBD_RPC_EACCESS_DENIED;
		return 0;
	}
	if (req->Level != 100 && req->Level != 101 && req->Level != 102) {
		rep->status = KSMBD_RPC_EINVALID_LEVEL;
		return 0;
	}

	/* Without a netbios name, the name the client called us by */
	if (!name || !name[0])
		name = called_name(req->ServerName);

	/*
	 * The levels are prefixes of one another: fill a 102 and copy the
	 * prefix the level asks for into the union's arm.
	 */
	memset(&info, 0, sizeof(info));
	info.PlatformId = WKSSVC_PLATFORM_ID_NT;
	info.ComputerName = rpc_pdu_strdup(pdu, name);
	info.LanGroup = rpc_pdu_strdup(pdu, global_conf.work_group ?: "");
	info.VerMajor = WKSSVC_VERSION_MAJOR;
	info.VerMinor = WKSSVC_VERSION_MINOR;
	info.LanRoot = rpc_pdu_strdup(pdu, global_conf.root_dir ?: "");
	info.LoggedOnUsers = sm_session_count();
	if (!info.ComputerName || !info.LanGroup || !info.LanRoot)
		return -1;

	switch (req->Level) {
	case 100:
		memcpy(&rep->WkstaInfo.WkstaInfo100, &info,
		       sizeof(rep->WkstaInfo.WkstaInfo100));
		break;
	case 101:
		memcpy(&rep->WkstaInfo.WkstaInfo101, &info,
		       sizeof(rep->WkstaInfo.WkstaInfo101));
		break;
	default:
		rep->WkstaInfo.WkstaInfo102 = info;
		break;
	}
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
