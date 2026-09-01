// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <memory.h>
#include <endian.h>
#include <glib.h>
#include <errno.h>
#include <linux/ksmbd_server.h>

#include <management/session.h>

#include <rpc.h>
#include <rpc_wkssvc.h>
#include <tools.h>

#define WKSSVC_NETWKSTA_GET_INFO	(0)

#define WKSSVC_PLATFORM_ID_DOS		300
#define WKSSVC_PLATFORM_ID_OS2		400
#define WKSSVC_PLATFORM_ID_NT		500
#define WKSSVC_PLATFORM_ID_OSF		600
#define WKSSVC_PLATFORM_ID_VMS		700

#define WKSSVC_VERSION_MAJOR		0x2
#define WKSSVC_VERSION_MINOR		0x1

static int wkssvc_clear_headers(struct ksmbd_rpc_pipe *pipe,
				int status)
{
	ndr_free_uniq_vstring_ptr(&pipe->dce->wi_req.server_name);
	return 0;
}

static void wkssvc_request_cleanup(struct ksmbd_rpc_pipe *pipe)
{
	if (pipe && pipe->dce)
		ndr_free_uniq_vstring_ptr(&pipe->dce->wi_req.server_name);
}

static const char *__wkssvc_computer_name(void)
{
	return global_conf.netbios_name ? global_conf.netbios_name : "";
}

static const char *__wkssvc_lanroot(void)
{
	return global_conf.root_dir ? global_conf.root_dir : "";
}

static int __netwksta_entry_rep(struct ksmbd_dcerpc *dce, gpointer entry)
{
	int ret;

	(void)entry;
	dce->num_pointers++;
	ret = ndr_write_int32(dce, dce->num_pointers);
	if (ret)
		return ret;
	ret = ndr_write_int32(dce, WKSSVC_PLATFORM_ID_NT);
	if (ret)
		return ret;
	dce->num_pointers++;
	ret = ndr_write_int32(dce, dce->num_pointers);
	if (ret)
		return ret;
	dce->num_pointers++;
	ret = ndr_write_int32(dce, dce->num_pointers);
	if (ret)
		return ret;
	ret = ndr_write_int32(dce, WKSSVC_VERSION_MAJOR);
	if (ret)
		return ret;
	ret = ndr_write_int32(dce, WKSSVC_VERSION_MINOR);
	if (ret)
		return ret;

	if (dce->wi_req.level >= 101) {
		dce->num_pointers++;
		ret = ndr_write_int32(dce, dce->num_pointers);
		if (ret)
			return ret;
	}
	if (dce->wi_req.level == 102)
		return ndr_write_int32(dce, sm_session_count());
	return 0;
}

static int __netwksta_entry_data(struct ksmbd_dcerpc *dce,
				 gpointer entry)
{
	int ret;

	(void)entry;
	ret = ndr_write_vstring(dce, __wkssvc_computer_name());
	if (ret)
		return ret;
	ret = ndr_write_vstring(dce, global_conf.work_group);
	if (ret)
		return ret;
	if (dce->wi_req.level >= 101)
		return ndr_write_vstring(dce, __wkssvc_lanroot());
	return 0;
}

static int __wkssvc_level_supported(__u32 level)
{
	return level == 100 || level == 101 || level == 102;
}

static int wkssvc_write_null_info(struct ksmbd_dcerpc *dce)
{
	__u32 level = __wkssvc_level_supported(dce->wi_req.level) ?
		dce->wi_req.level : 100;

	if (ndr_write_int32(dce, level) ||
	    ndr_write_int32(dce, 0))
		return KSMBD_RPC_EBAD_DATA;
	return 0;
}

static int wkssvc_netwksta_get_info_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;

	if (!__wkssvc_level_supported(dce->wi_req.level)) {
		if (wkssvc_write_null_info(dce))
			return KSMBD_RPC_EBAD_DATA;
		return KSMBD_RPC_EINVALID_LEVEL;
	}

	if (ndr_write_int32(dce, dce->wi_req.level))
		return KSMBD_RPC_EBAD_DATA;
	if (__netwksta_entry_rep(dce, NULL))
		return KSMBD_RPC_EBAD_DATA;
	if (__netwksta_entry_data(dce, NULL))
		return KSMBD_RPC_EBAD_DATA;
	return KSMBD_RPC_OK;
}

static int wkssvc_netwksta_info_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int status;

	dce->offset = sizeof(struct dcerpc_header) +
		sizeof(struct dcerpc_response_header);

	if (rpc_restricted_context(dce->rpc_req)) {
		status = KSMBD_RPC_EACCESS_DENIED;
		if (wkssvc_write_null_info(dce))
			return KSMBD_RPC_EBAD_DATA;
	} else {
		status = wkssvc_netwksta_get_info_return(pipe);
	}

	if (status == KSMBD_RPC_EBAD_DATA)
		return status;
	if (ndr_write_int32(dce, status))
		return KSMBD_RPC_EBAD_DATA;

	wkssvc_clear_headers(pipe, status);
	if (dcerpc_write_headers(dce, status))
		return KSMBD_RPC_EBAD_DATA;

	dce->rpc_resp->payload_sz = dce->offset;
	return KSMBD_RPC_OK;
}

static int
wkssvc_netwksta_get_info_invoke(struct ksmbd_rpc_pipe *pipe,
				struct wkssvc_netwksta_info_request *hdr)
{
	(void)pipe;
	(void)hdr;
	return KSMBD_RPC_OK;
}

static int
wkssvc_parse_netwksta_info_req(struct ksmbd_dcerpc *dce,
			       struct wkssvc_netwksta_info_request *hdr)
{
	__u32 level;

	if (ndr_read_uniq_vstring_ptr(dce, &hdr->server_name))
		return -EINVAL;
	if (ndr_read_int32(dce, &level))
		return -EINVAL;
	hdr->level = level;
	return 0;
}

static int wkssvc_netwksta_info_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;

	if (wkssvc_parse_netwksta_info_req(dce, &dce->wi_req))
		return KSMBD_RPC_EBAD_DATA;
	if (ndr_request_end(dce))
		return KSMBD_RPC_EINVALID_PARAMETER;

	if (rpc_restricted_context(dce->rpc_req))
		return KSMBD_RPC_OK;

	if (dce->req_hdr.opnum == WKSSVC_NETWKSTA_GET_INFO)
		return wkssvc_netwksta_get_info_invoke(pipe, &dce->wi_req);
	return KSMBD_RPC_OK;
}

static int wkssvc_invoke(struct ksmbd_rpc_pipe *pipe)
{
	switch (pipe->dce->req_hdr.opnum) {
	case WKSSVC_NETWKSTA_GET_INFO:
		return wkssvc_netwksta_info_invoke(pipe);
	default:
		pr_debug("WKSSVC: unsupported INVOKE method %d\n",
			 pipe->dce->req_hdr.opnum);
		return KSMBD_RPC_OK;
	}
}

static int wkssvc_return(struct ksmbd_rpc_pipe *pipe,
			 struct ksmbd_rpc_command *resp,
			 int max_resp_sz)
{
	struct ksmbd_dcerpc *dce = pipe->dce;

	switch (dce->req_hdr.opnum) {
	case WKSSVC_NETWKSTA_GET_INFO:
		dcerpc_set_ext_payload(dce, resp->payload, max_resp_sz);
		return wkssvc_netwksta_info_return(pipe);
	default:
		dcerpc_set_ext_payload(dce, resp->payload, max_resp_sz);
		if (dcerpc_write_fault(dce, DCERPC_NCA_S_OP_RNG_ERROR))
			return KSMBD_RPC_EBAD_DATA;
		dce->rpc_resp->payload_sz = dce->offset;
		return KSMBD_RPC_OK;
	}
}

int rpc_wkssvc_read_request(struct ksmbd_rpc_pipe *pipe,
			    struct ksmbd_rpc_command *resp,
			    int max_resp_sz)
{
	return wkssvc_return(pipe, resp, max_resp_sz);
}

int rpc_wkssvc_write_request(struct ksmbd_rpc_pipe *pipe)
{
	struct wkssvc_netwksta_info_request *req = &pipe->dce->wi_req;
	int ret;

	pipe->dce->request_cleanup = wkssvc_request_cleanup;
	memset(req, 0, sizeof(*req));
	ret = wkssvc_invoke(pipe);
	if (ret != KSMBD_RPC_OK)
		wkssvc_clear_headers(pipe, ret);
	return ret;
}
