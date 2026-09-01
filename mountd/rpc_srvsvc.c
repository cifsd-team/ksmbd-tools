// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <limits.h>
#include <stdint.h>
#include <memory.h>
#include <endian.h>
#include <glib.h>
#include <errno.h>
#include <linux/ksmbd_server.h>

#include <management/share.h>

#include <rpc.h>
#include <rpc_srvsvc.h>
#include <smbacl.h>
#include <tools.h>

#define SHARE_TYPE_TEMP			0x40000000
#define SHARE_TYPE_HIDDEN		0x80000000

#define SHARE_TYPE_DISKTREE		0
#define SHARE_TYPE_DISKTREE_TEMP	(SHARE_TYPE_DISKTREE|SHARE_TYPE_TEMP)
#define SHARE_TYPE_DISKTREE_HIDDEN	(SHARE_TYPE_DISKTREE|SHARE_TYPE_HIDDEN)
#define SHARE_TYPE_PRINTQ		1
#define SHARE_TYPE_PRINTQ_TEMP		(SHARE_TYPE_PRINTQ|SHARE_TYPE_TEMP)
#define SHARE_TYPE_PRINTQ_HIDDEN	(SHARE_TYPE_PRINTQ|SHARE_TYPE_HIDDEN)
#define SHARE_TYPE_DEVICE		2
#define SHARE_TYPE_DEVICE_TEMP		(SHARE_TYPE_DEVICE|SHARE_TYPE_TEMP)
#define SHARE_TYPE_DEVICE_HIDDEN	(SHARE_TYPE_DEVICE|SHARE_TYPE_HIDDEN)
#define SHARE_TYPE_IPC			3
#define SHARE_TYPE_IPC_TEMP		(SHARE_TYPE_IPC|SHARE_TYPE_TEMP)
#define SHARE_TYPE_IPC_HIDDEN		(SHARE_TYPE_IPC|SHARE_TYPE_HIDDEN)

#define SRVSVC_OPNUM_SHARE_ENUM_ALL	15
#define SRVSVC_OPNUM_GET_SHARE_INFO	16
#define SRVSVC_OPNUM_SHARE_ENUM_STICKY	36

#define SRVSVC_NERR_NET_NAME_NOT_FOUND	0x00000906U
#define SRVSVC_SECURITY_DESCRIPTOR_SIZE	512

static int srvsvc_clear_headers(struct ksmbd_rpc_pipe *pipe,
				int status);

static int __share_level_supported(__u32 level)
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

static int __share_string_size(const char *value)
{
	size_t len = value ? strlen(value) : 0;

	if (len > (INT_MAX - 14) / 2)
		return INT_MAX;
	return (int)(len * 2 + 14);
}

static __u32 __share_max_users(const struct ksmbd_share *share)
{
	if (share->max_connections <= 0)
		return (__u32)-1;
	return (__u32)share->max_connections;
}

static __u32 __share_current_users(const struct ksmbd_share *share)
{
	if (share->num_connections <= 0)
		return 0;
	return (__u32)share->num_connections;
}

static int __share_entry_size_ctr0(struct ksmbd_dcerpc *dce, gpointer entry)
{
	struct ksmbd_share *share = entry;

	return 4 + __share_string_size(share->name);
}

static int __share_entry_size_ctr1(struct ksmbd_dcerpc *dce, gpointer entry)
{
	struct ksmbd_share *share = entry;

	return 3 * sizeof(__u32) +
		__share_string_size(share->name) +
		__share_string_size(share->comment);
}

static int __share_entry_size_ctr2(struct ksmbd_dcerpc *dce, gpointer entry)
{
	struct ksmbd_share *share = entry;

	return 8 * sizeof(__u32) +
		__share_string_size(share->name) +
		__share_string_size(share->comment) +
		__share_string_size(share->path) +
		__share_string_size("");
}

static int __share_entry_size_ctr502(struct ksmbd_dcerpc *dce,
				     gpointer entry)
{
	return __share_entry_size_ctr2(dce, entry) +
		2 * sizeof(__u32) + SRVSVC_SECURITY_DESCRIPTOR_SIZE;
}

static int __share_write_ref(struct ksmbd_dcerpc *dce)
{
	dce->num_pointers++;
	return ndr_write_int32(dce, dce->num_pointers);
}

/*
 * Embedded reference pointers
 *
 * An embedded reference pointer is represented in two parts, a 4 octet
 * value in place and a possibly deferred representation of the referent.
 */
static int __share_entry_rep_ctr0(struct ksmbd_dcerpc *dce, gpointer entry)
{
	(void)entry;
	return __share_write_ref(dce);
}

static int __share_entry_rep_ctr1(struct ksmbd_dcerpc *dce, gpointer entry)
{
	struct ksmbd_share *share = entry;
	int ret;

	ret = __share_write_ref(dce);
	if (ret)
		return ret;
	ret = ndr_write_int32(dce, __share_type(share));
	if (ret)
		return ret;
	return __share_write_ref(dce);
}

static int __share_entry_rep_ctr2(struct ksmbd_dcerpc *dce, gpointer entry)
{
	struct ksmbd_share *share = entry;
	int ret;

	ret = __share_write_ref(dce);
	if (ret)
		return ret;
	ret = ndr_write_int32(dce, __share_type(share));
	if (ret)
		return ret;
	ret = __share_write_ref(dce);
	if (ret)
		return ret;
	if (ndr_write_int32(dce, 0))
		return -EINVAL;
	if (ndr_write_int32(dce, __share_max_users(share)))
		return -EINVAL;
	if (ndr_write_int32(dce, __share_current_users(share)))
		return -EINVAL;
	ret = __share_write_ref(dce);
	if (ret)
		return ret;
	return __share_write_ref(dce);
}

static int __share_entry_rep_ctr502(struct ksmbd_dcerpc *dce,
				    gpointer entry)
{
	struct ksmbd_share *share = entry;
	int ret;

	ret = __share_entry_rep_ctr2(dce, share);
	if (ret)
		return ret;
	if (ndr_write_int32(dce, 0))
		return -EINVAL;
	return __share_write_ref(dce);
}

static int __share_entry_data_ctr0(struct ksmbd_dcerpc *dce, gpointer entry)
{
	struct ksmbd_share *share = entry;

	return ndr_write_vstring(dce, share->name);
}

static int __share_entry_data_ctr1(struct ksmbd_dcerpc *dce, gpointer entry)
{
	struct ksmbd_share *share = entry;
	int ret;

	ret = ndr_write_vstring(dce, share->name);
	if (ret)
		return ret;
	return ndr_write_vstring(dce, share->comment);
}

static int __share_entry_data_ctr2(struct ksmbd_dcerpc *dce, gpointer entry)
{
	struct ksmbd_share *share = entry;
	int ret;

	ret = ndr_write_vstring(dce, share->name);
	if (ret)
		return ret;
	ret = ndr_write_vstring(dce, share->comment);
	if (ret)
		return ret;
	ret = ndr_write_vstring(dce, share->path);
	if (ret)
		return ret;
	return ndr_write_vstring(dce, "");
}

static int __share_write_security_descriptor(struct ksmbd_dcerpc *dce)
{
	size_t length_offset, data_offset, end_offset;
	__u32 sec_desc_len;

	length_offset = dce->offset;
	if (ndr_write_int32(dce, 0))
		return -EINVAL;
	data_offset = dce->offset;
	if (build_sec_desc(dce, &sec_desc_len, 0))
		return -EINVAL;
	end_offset = dce->offset;
	if (end_offset < data_offset ||
	    end_offset - data_offset != sec_desc_len)
		return -EINVAL;

	dce->offset = length_offset;
	if (ndr_write_int32(dce, sec_desc_len))
		return -EINVAL;
	dce->offset = end_offset;
	auto_align_offset(dce);
	return 0;
}

static int __share_entry_data_ctr502(struct ksmbd_dcerpc *dce,
				     gpointer entry)
{
	int ret;

	ret = __share_entry_data_ctr2(dce, entry);
	if (ret)
		return ret;
	return __share_write_security_descriptor(dce);
}

static int srvsvc_share_enum_build_response(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct srvsvc_share_info_request *req = &dce->si_req;
	char *external_payload = dce->payload;
	size_t external_payload_sz = dce->payload_sz;
	unsigned int external_flags = dce->flags;
	char *response_payload;
	__u32 output_level;
	__u32 resume = 0;
	size_t response_size;
	int (*entry_processed)(struct ksmbd_rpc_pipe *pipe, int i);
	int response_entries = 0;
	int response_status;
	int i;
	int ret;

	pipe->num_processed = 0;
	output_level = __share_level_supported(req->level) ?
		req->level : 0;
	if (!req->operation_status)
		response_entries = ndr_max_entries(dce, pipe);
	/* Always advance the resume position when data remains. */
	if (!req->operation_status && !response_entries && pipe->num_entries)
		response_entries = 1;

	response_payload = g_try_malloc0(4096);
	if (!response_payload)
		return KSMBD_RPC_ENOMEM;

	dce->payload = response_payload;
	dce->payload_sz = 4096;
	dce->flags = external_flags & ~(KSMBD_DCERPC_FIXED_PAYLOAD_SZ |
					KSMBD_DCERPC_EXTERNAL_PAYLOAD |
					KSMBD_DCERPC_RETURN_READY);
	dce->offset = sizeof(struct dcerpc_header) +
		sizeof(struct dcerpc_response_header);
	dce->num_pointers = 1;
	entry_processed = pipe->entry_processed;
	pipe->entry_processed = NULL;

	if (ndr_write_int32(dce, output_level) ||
	    ndr_write_int32(dce, output_level))
		goto bad_data;

	if (req->operation_status == KSMBD_RPC_EINVALID_LEVEL) {
		if (ndr_write_int32(dce, 0))
			goto bad_data;
	} else {
		dce->num_pointers++;
		if (ndr_write_int32(dce, dce->num_pointers) ||
		    ndr_write_int32(dce, response_entries))
			goto bad_data;

		if (response_entries) {
			dce->num_pointers++;
			if (ndr_write_int32(dce, dce->num_pointers) ||
			    ndr_write_int32(dce, response_entries))
				goto bad_data;
			ret = __ndr_write_array_of_structs(pipe, response_entries);
			if (ret)
				goto bad_data;
		} else if (ndr_write_int32(dce, 0)) {
			goto bad_data;
		}
	}

	if (req->operation_status)
		response_status = req->operation_status;
	else
		response_status = pipe->num_entries > response_entries ?
			KSMBD_RPC_EMORE_DATA : KSMBD_RPC_OK;

	if (response_status == KSMBD_RPC_EMORE_DATA)
		resume = req->resume_handle + response_entries;

	if (ndr_write_int32(dce,
			    response_status == KSMBD_RPC_EINVALID_LEVEL ?
			    0 : req->total_entries))
		goto bad_data;

	if (req->payload_handle.ref_id) {
		dce->num_pointers++;
		if (ndr_write_int32(dce, dce->num_pointers) ||
		    ndr_write_int32(dce, resume))
			goto bad_data;
	} else if (ndr_write_int32(dce, 0)) {
		goto bad_data;
	}

	if (ndr_write_int32(dce, response_status))
		goto bad_data;

	response_size = dce->offset -
		sizeof(struct dcerpc_header) -
		sizeof(struct dcerpc_response_header);
	if (response_size > UINT32_MAX)
		goto bad_data;

	if (entry_processed) {
		pipe->entry_processed = entry_processed;
		for (i = 0; i < response_entries; i++)
			entry_processed(pipe, 0);
		if (!pipe->num_entries)
			pipe->entry_processed = NULL;
	}
	if (response_status == KSMBD_RPC_EMORE_DATA)
		req->resume_handle = resume;

	response_payload = dce->payload;
	dce->response_payload = response_payload;
	dce->response_payload_sz = response_size;
	dce->response_payload_offset = 0;
	dce->response_alloc_hint = response_size;
	dce->payload = external_payload;
	dce->payload_sz = external_payload_sz;
	dce->flags = external_flags;
	return KSMBD_RPC_OK;

bad_data:
	pipe->entry_processed = entry_processed;
	g_free(dce->payload);
	dce->payload = external_payload;
	dce->payload_sz = external_payload_sz;
	dce->flags = external_flags;
	return KSMBD_RPC_EBAD_DATA;
}

static int srvsvc_share_enum_write_fragment(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	size_t response_header_size = sizeof(struct dcerpc_header) +
		sizeof(struct dcerpc_response_header);
	size_t remaining;
	size_t fragment_payload_sz;
	size_t fragment_size;

	if (!dce->response_payload ||
	    dce->response_payload_offset > dce->response_payload_sz ||
	    dce->payload_sz < response_header_size)
		goto bad_data;
	if (dce->payload_sz == response_header_size &&
	    dce->response_payload_offset < dce->response_payload_sz)
		goto bad_data;

	remaining = dce->response_payload_sz -
		dce->response_payload_offset;
	fragment_payload_sz = MIN(dce->payload_sz - response_header_size,
				  (size_t)UINT16_MAX - response_header_size);
	if (!fragment_payload_sz && remaining)
		goto bad_data;
	fragment_size = MIN(remaining, fragment_payload_sz);
	memcpy(dce->payload + response_header_size,
	       dce->response_payload + response_header_size +
	       dce->response_payload_offset, fragment_size);
	dce->response_payload_offset += fragment_size;

	if (dce->response_payload_offset < dce->response_payload_sz)
		dce->flags |= KSMBD_DCERPC_RETURN_READY;
	else
		dce->flags &= ~KSMBD_DCERPC_RETURN_READY;
	dce->offset = response_header_size + fragment_size;
	if (dcerpc_write_headers(dce, KSMBD_RPC_OK))
		goto bad_data;
	dce->rpc_resp->payload_sz = dce->offset;

	if (dce->flags & KSMBD_DCERPC_RETURN_READY) {
		srvsvc_clear_headers(pipe, KSMBD_RPC_EMORE_DATA);
		return KSMBD_RPC_OK;
	}

	srvsvc_clear_headers(pipe, KSMBD_RPC_OK);
	rpc_pipe_reset(pipe);
	return KSMBD_RPC_OK;

bad_data:
	dce->flags &= ~KSMBD_DCERPC_RETURN_READY;
	srvsvc_clear_headers(pipe, KSMBD_RPC_OK);
	rpc_pipe_reset(pipe);
	return KSMBD_RPC_EBAD_DATA;
}

static int __share_entry_processed(struct ksmbd_rpc_pipe *pipe, int i)
{
	struct ksmbd_share *share;

	share = g_ptr_array_remove_index(pipe->entries, i);
	pipe->num_entries--;
	pipe->num_processed++;
	put_ksmbd_share(share);

	return 0;
}

static void __share_entry_discard(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_share *share;

	if (!pipe->num_entries)
		return;
	share = g_ptr_array_remove_index(pipe->entries, 0);
	pipe->num_entries--;
	put_ksmbd_share(share);
}

static void __enum_all_shares(struct ksmbd_share *share,
			      struct ksmbd_rpc_pipe *pipe)
{
	if (!get_ksmbd_share(share))
		return;

	if (!test_share_flag(share, KSMBD_SHARE_FLAG_BROWSEABLE) ||
	    !test_share_flag(share, KSMBD_SHARE_FLAG_AVAILABLE)) {
		put_ksmbd_share(share);
		return;
	}

	g_ptr_array_add(pipe->entries, share);
	pipe->num_entries++;
}

static int srvsvc_share_enum_all_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct srvsvc_share_info_request *req = &pipe->dce->si_req;
	unsigned int i;

	shm_iter_shares((share_cb)__enum_all_shares, pipe);
	pipe->entry_processed = __share_entry_processed;
	req->total_entries = pipe->num_entries;
	req->resume_handle = req->payload_handle.ptr;

	if (req->resume_handle > (unsigned int)pipe->num_entries) {
		rpc_pipe_reset(pipe);
		req->operation_status = KSMBD_RPC_EINVALID_PARAMETER;
		return KSMBD_RPC_OK;
	}

	for (i = 0; i < req->resume_handle; i++)
		__share_entry_discard(pipe);
	return KSMBD_RPC_OK;
}

static int srvsvc_share_get_info_invoke(struct ksmbd_rpc_pipe *pipe,
					struct srvsvc_share_info_request *hdr)
{
	struct ksmbd_share *share;

	share = shm_lookup_share(STR_VAL(hdr->share_name));
	if (!share || !test_share_flag(share, KSMBD_SHARE_FLAG_AVAILABLE)) {
		if (share)
			put_ksmbd_share(share);
		hdr->operation_status = SRVSVC_NERR_NET_NAME_NOT_FOUND;
		return KSMBD_RPC_OK;
	}

	g_ptr_array_add(pipe->entries, share);
	pipe->num_entries++;
	pipe->entry_processed = __share_entry_processed;
	return KSMBD_RPC_OK;
}

static int srvsvc_share_get_info_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct srvsvc_share_info_request *req = &dce->si_req;
	__u32 output_level = __share_level_supported(req->level) ?
		req->level : 0;
	int status = req->operation_status;

	if (ndr_write_int32(dce, output_level))
		return KSMBD_RPC_EBAD_DATA;

	if (status || !pipe->num_entries) {
		if (ndr_write_int32(dce, 0))
			return KSMBD_RPC_EBAD_DATA;
		if (!status)
			status = KSMBD_RPC_EINVALID_PARAMETER;
		return status;
	}

	dce->num_pointers++;
	if (ndr_write_int32(dce, dce->num_pointers))
		return KSMBD_RPC_EBAD_DATA;

	if (dce->entry_rep(dce, g_ptr_array_index(pipe->entries, 0)) ||
	    dce->entry_data(dce, g_ptr_array_index(pipe->entries, 0)))
		return KSMBD_RPC_EBAD_DATA;

	if (pipe->entry_processed) {
		pipe->entry_processed(pipe, 0);
		pipe->entry_processed = NULL;
	}
	return KSMBD_RPC_OK;
}

static int srvsvc_parse_share_info_req(struct ksmbd_dcerpc *dce,
				       struct srvsvc_share_info_request *hdr)
{
	if (ndr_read_uniq_vstring_ptr(dce, &hdr->server_name))
		return -EINVAL;

	if (dce->req_hdr.opnum == SRVSVC_OPNUM_SHARE_ENUM_ALL ||
	    dce->req_hdr.opnum == SRVSVC_OPNUM_SHARE_ENUM_STICKY) {
		__u32 container, entries, ptr, val;

		/* Read union switch selector */
		if (ndr_read_union_int32(dce, &val))
			return -EINVAL;
		hdr->level = val;
		/* Read the selected union arm's unique container pointer. */
		if (ndr_read_int32(dce, &container))
			return -EINVAL;
		if (container) {
			if (ndr_read_int32(dce, &entries))
				return -EINVAL;
			if (ndr_read_int32(dce, &ptr))
				return -EINVAL;

			if (ptr) {
				if (entries) {
					pr_err("SRVSVC: nonempty input share array is unsupported\n");
					return -EINVAL;
				}

				if (ndr_read_int32(dce, &val) || val)
					return -EINVAL;
			}
		}

		if (ndr_read_int32(dce, &val))
			return -EINVAL;
		hdr->max_size = val;
		if (ndr_read_uniq_ptr(dce, &hdr->payload_handle))
			return -EINVAL;
		hdr->resume_handle = hdr->payload_handle.ptr;
		return 0;
	}

	if (dce->req_hdr.opnum == SRVSVC_OPNUM_GET_SHARE_INFO) {
		__u32 level;

		if (ndr_read_vstring_ptr(dce, &hdr->share_name))
			return -EINVAL;
		if (ndr_read_int32(dce, &level))
			return -EINVAL;
		hdr->level = level;
		return 0;
	}

	return -ENOTSUP;
}

static int srvsvc_share_info_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;

	if (srvsvc_parse_share_info_req(dce, &dce->si_req))
		return KSMBD_RPC_EBAD_DATA;
	if (ndr_request_end(dce))
		return KSMBD_RPC_EINVALID_PARAMETER;

	pipe->entry_processed = __share_entry_processed;
	if (!__share_level_supported(dce->si_req.level)) {
		dce->si_req.operation_status = KSMBD_RPC_EINVALID_LEVEL;
		return KSMBD_RPC_OK;
	}
	if (rpc_restricted_context(dce->rpc_req))
		return KSMBD_RPC_OK;

	if (dce->req_hdr.opnum == SRVSVC_OPNUM_GET_SHARE_INFO)
		return srvsvc_share_get_info_invoke(pipe, &dce->si_req);
	if (dce->req_hdr.opnum == SRVSVC_OPNUM_SHARE_ENUM_ALL ||
	    dce->req_hdr.opnum == SRVSVC_OPNUM_SHARE_ENUM_STICKY)
		return srvsvc_share_enum_all_invoke(pipe);
	return KSMBD_RPC_OK;
}

static int srvsvc_clear_headers(struct ksmbd_rpc_pipe *pipe,
				int status)
{
	struct ksmbd_dcerpc *dce = pipe->dce;

	if (status == KSMBD_RPC_EMORE_DATA &&
	    (dce->flags & KSMBD_DCERPC_RETURN_READY))
		return 0;

	ndr_free_uniq_vstring_ptr(&dce->si_req.server_name);
	if (dce->req_hdr.opnum == SRVSVC_OPNUM_GET_SHARE_INFO)
		ndr_free_vstring_ptr(&dce->si_req.share_name);

	return 0;
}

static void srvsvc_request_cleanup(struct ksmbd_rpc_pipe *pipe)
{
	if (!pipe || !pipe->dce)
		return;

	ndr_free_uniq_vstring_ptr(&pipe->dce->si_req.server_name);
	ndr_free_vstring_ptr(&pipe->dce->si_req.share_name);
}

static int srvsvc_share_info_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int status;

	switch (dce->si_req.level) {
	case 0:
		dce->entry_size = __share_entry_size_ctr0;
		dce->entry_rep = __share_entry_rep_ctr0;
		dce->entry_data = __share_entry_data_ctr0;
		break;
	case 1:
		dce->entry_size = __share_entry_size_ctr1;
		dce->entry_rep = __share_entry_rep_ctr1;
		dce->entry_data = __share_entry_data_ctr1;
		break;
	case 2:
		dce->entry_size = __share_entry_size_ctr2;
		dce->entry_rep = __share_entry_rep_ctr2;
		dce->entry_data = __share_entry_data_ctr2;
		break;
	case 502:
		dce->entry_size = __share_entry_size_ctr502;
		dce->entry_rep = __share_entry_rep_ctr502;
		dce->entry_data = __share_entry_data_ctr502;
		break;
	default:
		dce->entry_size = __share_entry_size_ctr0;
		dce->entry_rep = __share_entry_rep_ctr0;
		dce->entry_data = __share_entry_data_ctr0;
		break;
	}

	if (dce->req_hdr.opnum != SRVSVC_OPNUM_GET_SHARE_INFO) {
		if (!dce->response_payload) {
			dce->response_limit = dce->si_req.max_size ?
				dce->si_req.max_size : SIZE_MAX;
			if (rpc_restricted_context(dce->rpc_req)) {
				if (pipe->num_entries)
					rpc_pipe_reset(pipe);
				dce->si_req.operation_status =
					KSMBD_RPC_EACCESS_DENIED;
			}
			if (srvsvc_share_enum_build_response(pipe))
				return KSMBD_RPC_EBAD_DATA;
		}
		return srvsvc_share_enum_write_fragment(pipe);
	}

	dce->offset = sizeof(struct dcerpc_header) +
		sizeof(struct dcerpc_response_header);
	pipe->num_processed = 0;
	if (rpc_restricted_context(dce->rpc_req)) {
		if (pipe->num_entries)
			rpc_pipe_reset(pipe);
		dce->si_req.operation_status = KSMBD_RPC_EACCESS_DENIED;
	}

	status = srvsvc_share_get_info_return(pipe);

	if (status == KSMBD_RPC_EBAD_DATA)
		return status;

	if (ndr_write_int32(dce, status))
		return KSMBD_RPC_EBAD_DATA;

	srvsvc_clear_headers(pipe, status);
	if (dcerpc_write_headers(dce, status))
		return KSMBD_RPC_EBAD_DATA;

	dce->rpc_resp->payload_sz = dce->offset;
	return KSMBD_RPC_OK;
}

static int srvsvc_invoke(struct ksmbd_rpc_pipe *pipe)
{
	switch (pipe->dce->req_hdr.opnum) {
	case SRVSVC_OPNUM_SHARE_ENUM_ALL:
	case SRVSVC_OPNUM_SHARE_ENUM_STICKY:
	case SRVSVC_OPNUM_GET_SHARE_INFO:
		return srvsvc_share_info_invoke(pipe);
	default:
		pr_debug("SRVSVC: unsupported INVOKE method %d\n",
			 pipe->dce->req_hdr.opnum);
		return KSMBD_RPC_OK;
	}
}

static int srvsvc_return(struct ksmbd_rpc_pipe *pipe,
			 struct ksmbd_rpc_command *resp,
			 int max_resp_sz)
{
	struct ksmbd_dcerpc *dce = pipe->dce;

	switch (dce->req_hdr.opnum) {
	case SRVSVC_OPNUM_SHARE_ENUM_ALL:
	case SRVSVC_OPNUM_SHARE_ENUM_STICKY:
		dcerpc_set_ext_payload(dce, resp->payload, max_resp_sz);
		return srvsvc_share_info_return(pipe);
	case SRVSVC_OPNUM_GET_SHARE_INFO:
		dcerpc_set_ext_payload(dce, resp->payload, max_resp_sz);
		return srvsvc_share_info_return(pipe);
	default:
		dcerpc_set_ext_payload(dce, resp->payload, max_resp_sz);
		if (dcerpc_write_fault(dce, DCERPC_NCA_S_OP_RNG_ERROR))
			return KSMBD_RPC_EBAD_DATA;
		dce->rpc_resp->payload_sz = dce->offset;
		return KSMBD_RPC_OK;
	}
}

int rpc_srvsvc_read_request(struct ksmbd_rpc_pipe *pipe,
			    struct ksmbd_rpc_command *resp,
			    int max_resp_sz)
{
	return srvsvc_return(pipe, resp, max_resp_sz);
}

int rpc_srvsvc_write_request(struct ksmbd_rpc_pipe *pipe)
{
	struct srvsvc_share_info_request *req = &pipe->dce->si_req;
	int ret;

	pipe->dce->request_cleanup = srvsvc_request_cleanup;
	memset(req, 0, sizeof(*req));
	ret = srvsvc_invoke(pipe);
	if (ret != KSMBD_RPC_OK && ret != KSMBD_RPC_EMORE_DATA) {
		srvsvc_clear_headers(pipe, ret);
		rpc_pipe_reset(pipe);
	}
	return ret;
}
