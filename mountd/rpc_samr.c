// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2020 Samsung Electronics Co., Ltd.
 *
 *   Author(s): Namjae Jeon (linkinjeon@kernel.org)
 */

#include <memory.h>
#include <endian.h>
#include <stdint.h>
#include <glib.h>
#include <errno.h>
#include <linux/ksmbd_server.h>

#include <management/user.h>
#include <rpc.h>
#include <rpc_samr.h>
#include <smbacl.h>
#include <tools.h>

#define SAMR_OPNUM_CONNECT5		64
#define SAMR_OPNUM_ENUM_DOMAIN		6
#define SAMR_OPNUM_LOOKUP_DOMAIN	5
#define SAMR_OPNUM_OPEN_DOMAIN		7
#define SAMR_OPNUM_LOOKUP_NAMES		17
#define SAMR_OPNUM_OPEN_USER		34
#define SAMR_OPNUM_QUERY_USER_INFO	36
#define SAMR_OPNUM_QUERY_SECURITY	3
#define SAMR_OPNUM_GET_GROUP_FOR_USER	39
#define SAMR_OPNUM_GET_ALIAS_MEMBERSHIP	16
#define SAMR_OPNUM_CLOSE		1

#define SAMR_MAX_LOOKUP_NAME_COUNT	1000
#define SAMR_MAX_ALIAS_SID_COUNT	1024
#define SAM_SERVER_ENUMERATE_DOMAINS	0x00000010
#define SAMR_STATUS_BUFFER_TOO_SMALL	(-2006)
#define SAM_SERVER_LOOKUP_DOMAIN		0x00000020
#define SAM_DOMAIN_GET_ALIAS_MEMBERSHIP	0x00000080
#define SAM_DOMAIN_LOOKUP		0x00000200
#define SAM_SERVER_ALL_ACCESS		0x000F003F
#define SAM_DOMAIN_ALL_ACCESS		0x000F07FF
#define SAM_USER_ALL_ACCESS		0x000F07FF
#define SAM_USER_READ_GENERAL		0x00000001
#define SAM_USER_READ_LOGON		0x00000008
#define SAM_USER_READ_ACCOUNT		0x00000010
#define SAM_USER_LIST_GROUPS		0x00000100
#define SAM_USER_READ			0x0002031A
#define SAM_READ_CONTROL		0x00020000
#define SAM_STANDARD_WRITE_ACCESS	0x000D0000
#define SAM_GENERIC_READ		0x80000000U
#define SAM_GENERIC_WRITE		0x40000000U
#define SAM_GENERIC_EXECUTE		0x20000000U
#define SAM_GENERIC_ALL		0x10000000U
#define SAM_MAXIMUM_ALLOWED		0x02000000

#define SAMR_STATUS_INVALID_HANDLE	(-1001)
#define SAMR_STATUS_NO_SUCH_DOMAIN	(-1002)
#define SAMR_STATUS_NO_SUCH_USER		(-1003)
#define SAMR_STATUS_INVALID_INFO_CLASS	(-1004)
#define SAMR_STATUS_NONE_MAPPED		(-1005)
#define SAMR_STATUS_SOME_NOT_MAPPED	(-1006)

static GHashTable	*ch_table;
static GRWLock		ch_table_lock;
static GPtrArray	*domain_entries;
static gchar		*domain_name;
static int		num_domain_entries;

static void samr_ch_destroy(struct connect_handle *ch)
{
	struct ksmbd_user *user;

	if (!ch)
		return;

	user = ch->user;
	ch->user = NULL;
	put_ksmbd_user(user);
	g_free(ch);
}

static void samr_ch_put(struct connect_handle *ch)
{
	int destroy = 0;

	if (!ch)
		return;

	g_rw_lock_writer_lock(&ch_table_lock);
	if (ch->refcount && !--ch->refcount)
		destroy = 1;
	g_rw_lock_writer_unlock(&ch_table_lock);

	if (destroy)
		samr_ch_destroy(ch);
}

static struct connect_handle *samr_ch_lookup(struct ksmbd_rpc_pipe *pipe,
					     const unsigned char *handle)
{
	struct connect_handle *ch;

	if (!pipe || !handle)
		return NULL;
	g_rw_lock_writer_lock(&ch_table_lock);
	ch = g_hash_table_lookup(ch_table, handle);
	if (ch && !ch->retired && ch->pipe_id == pipe->id)
		ch->refcount++;
	else
		ch = NULL;
	g_rw_lock_writer_unlock(&ch_table_lock);

	return ch;
}

static int samr_ch_close(struct ksmbd_rpc_pipe *pipe,
			 const unsigned char *handle)
{
	struct connect_handle *ch;
	int destroy = 0;

	if (!pipe || !handle)
		return SAMR_STATUS_INVALID_HANDLE;

	g_rw_lock_writer_lock(&ch_table_lock);
	ch = g_hash_table_lookup(ch_table, handle);
	if (!ch || ch->retired || ch->pipe_id != pipe->id) {
		g_rw_lock_writer_unlock(&ch_table_lock);
		return SAMR_STATUS_INVALID_HANDLE;
	}
	ch->retired = 1;
	g_hash_table_remove(ch_table, &(ch->handle));
	if (ch->refcount && !--ch->refcount)
		destroy = 1;
	g_rw_lock_writer_unlock(&ch_table_lock);

	if (destroy)
		samr_ch_destroy(ch);
	return KSMBD_RPC_OK;
}

static struct connect_handle *samr_ch_alloc(struct ksmbd_rpc_pipe *pipe,
					    enum samr_handle_type type,
					    unsigned int access_mask,
					    const struct smb_sid *domain_sid,
					    struct ksmbd_user *user)
{
	struct connect_handle *ch;

	ch = g_try_malloc0(sizeof(struct connect_handle));
	if (!ch)
		return NULL;

	if (rpc_handle_generate(ch->handle, sizeof(ch->handle), pipe->id)) {
		g_free(ch);
		return NULL;
	}
	ch->pipe_id = pipe->id;
	ch->refcount = 1;
	ch->type = type;
	ch->access_mask = access_mask;
	ch->retired = 0;
	if (domain_sid)
		smb_copy_sid(&ch->domain_sid, domain_sid);
	ch->user = user;
	g_rw_lock_writer_lock(&ch_table_lock);
	if (g_hash_table_lookup(ch_table, ch->handle)) {
		g_rw_lock_writer_unlock(&ch_table_lock);
		g_free(ch);
		return NULL;
	}
	g_hash_table_insert(ch_table, &(ch->handle), ch);
	g_rw_lock_writer_unlock(&ch_table_lock);

	return ch;
}

static unsigned int samr_generic_read_access(enum samr_handle_type type);
static unsigned int samr_generic_write_access(enum samr_handle_type type);
static unsigned int samr_generic_execute_access(enum samr_handle_type type);

static int samr_handle_access(const struct connect_handle *ch,
			      enum samr_handle_type type,
			      unsigned int required)
{
	unsigned int all_access;

	if (!ch || ch->type != type)
		return SAMR_STATUS_INVALID_HANDLE;
	if (type == SAMR_HANDLE_SERVER)
		all_access = SAM_SERVER_ALL_ACCESS;
	else
		all_access = type == SAMR_HANDLE_DOMAIN ?
			SAM_DOMAIN_ALL_ACCESS : SAM_USER_ALL_ACCESS;
	if (required && (ch->access_mask & required) != required &&
	    !(ch->access_mask & SAM_GENERIC_ALL) &&
	    !(ch->access_mask & SAM_MAXIMUM_ALLOWED) &&
	    !((ch->access_mask & SAM_GENERIC_READ) &&
	      (samr_generic_read_access(type) & required) == required) &&
	    !((ch->access_mask & SAM_GENERIC_WRITE) &&
	      (samr_generic_write_access(type) & required) == required) &&
	    !((ch->access_mask & SAM_GENERIC_EXECUTE) &&
	      (samr_generic_execute_access(type) & required) == required) &&
	    (ch->access_mask & all_access) != all_access)
		return KSMBD_RPC_EACCESS_DENIED;
	return KSMBD_RPC_OK;
}

static __u32 samr_wire_status(int status)
{
	switch (status) {
	case KSMBD_RPC_OK:
		return KSMBD_NT_STATUS_SUCCESS;
	case SAMR_STATUS_INVALID_HANDLE:
		return KSMBD_NT_STATUS_INVALID_HANDLE;
	case SAMR_STATUS_NO_SUCH_DOMAIN:
		return KSMBD_NT_STATUS_NO_SUCH_DOMAIN;
	case SAMR_STATUS_NO_SUCH_USER:
		return KSMBD_NT_STATUS_NO_SUCH_USER;
	case SAMR_STATUS_INVALID_INFO_CLASS:
		return KSMBD_NT_STATUS_INVALID_INFO_CLASS;
	case SAMR_STATUS_BUFFER_TOO_SMALL:
		return KSMBD_NT_STATUS_BUFFER_TOO_SMALL;
	case SAMR_STATUS_NONE_MAPPED:
	case KSMBD_RPC_NONE_MAPPED:
		return KSMBD_NT_STATUS_NONE_MAPPED;
	case SAMR_STATUS_SOME_NOT_MAPPED:
	case KSMBD_RPC_SOME_NOT_MAPPED:
		return KSMBD_NT_STATUS_SOME_NOT_MAPPED;
	case KSMBD_RPC_EACCESS_DENIED:
		return KSMBD_NT_STATUS_ACCESS_DENIED;
	case KSMBD_RPC_EBAD_FID:
		return KSMBD_NT_STATUS_INVALID_HANDLE;
	case KSMBD_RPC_EINVALID_PARAMETER:
	case KSMBD_RPC_EBAD_DATA:
		return KSMBD_NT_STATUS_INVALID_PARAMETER;
	case KSMBD_RPC_EINVALID_LEVEL:
		return KSMBD_NT_STATUS_INVALID_INFO_CLASS;
	case KSMBD_RPC_ENOMEM:
		return KSMBD_NT_STATUS_INSUFFICIENT_RESOURCES;
	case KSMBD_RPC_ENOTIMPLEMENTED:
	case KSMBD_RPC_EBAD_FUNC:
		return KSMBD_NT_STATUS_NOT_IMPLEMENTED;
	case KSMBD_RPC_EMORE_DATA:
		return KSMBD_NT_STATUS_MORE_ENTRIES;
	default:
		return KSMBD_NT_STATUS_INVALID_PARAMETER;
	}
}

static unsigned int samr_generic_read_access(enum samr_handle_type type)
{
	switch (type) {
	case SAMR_HANDLE_SERVER:
		return SAM_SERVER_ENUMERATE_DOMAINS | SAM_READ_CONTROL;
	case SAMR_HANDLE_DOMAIN:
		return 0x00000084 | SAM_READ_CONTROL;
	case SAMR_HANDLE_USER:
		return SAM_USER_READ;
	default:
		return 0;
	}
}

static unsigned int samr_generic_write_access(enum samr_handle_type type)
{
	switch (type) {
	case SAMR_HANDLE_SERVER:
		return SAM_STANDARD_WRITE_ACCESS | 0x00000002 | 0x00000004 |
			0x00000008;
	case SAMR_HANDLE_DOMAIN:
		return SAM_STANDARD_WRITE_ACCESS | 0x00000002 | 0x00000008 |
			0x00000010 | 0x00000020 | 0x00000040 |
			0x00000400;
	case SAMR_HANDLE_USER:
		return SAM_STANDARD_WRITE_ACCESS | 0x00000004 | 0x00000020 |
			0x00000040 | 0x00000080 | 0x00000400;
	default:
		return 0;
	}
}

static unsigned int samr_generic_execute_access(enum samr_handle_type type)
{
	switch (type) {
	case SAMR_HANDLE_SERVER:
		return SAM_READ_CONTROL | SAM_SERVER_LOOKUP_DOMAIN | 0x00000001;
	case SAMR_HANDLE_DOMAIN:
		return 0x00000301 | 0x00020000;
	case SAMR_HANDLE_USER:
		return 0x00000041 | 0x00020000;
	default:
		return 0;
	}
}

static int samr_ipc_status(int status)
{
	switch (status) {
	case SAMR_STATUS_INVALID_HANDLE:
		return KSMBD_RPC_EBAD_FID;
	case SAMR_STATUS_NO_SUCH_DOMAIN:
	case SAMR_STATUS_NO_SUCH_USER:
		return KSMBD_RPC_EINVALID_PARAMETER;
	case SAMR_STATUS_INVALID_INFO_CLASS:
		return KSMBD_RPC_EINVALID_LEVEL;
	case SAMR_STATUS_BUFFER_TOO_SMALL:
		return KSMBD_RPC_EINVALID_PARAMETER;
	case SAMR_STATUS_NONE_MAPPED:
		return KSMBD_RPC_NONE_MAPPED;
	case SAMR_STATUS_SOME_NOT_MAPPED:
		return KSMBD_RPC_SOME_NOT_MAPPED;
	default:
		return status;
	}
}

static void samr_free_names(struct samr_info_request *req)
{
	if (req->names) {
		g_ptr_array_free(req->names, 1);
		req->names = NULL;
	}
	ndr_free_uniq_vstring_ptr(&req->name);
}

static void samr_request_cleanup(struct ksmbd_rpc_pipe *pipe)
{
	if (pipe && pipe->dce)
		samr_free_names(&pipe->dce->sm_req);
}

static int samr_write_zero_handle(struct ksmbd_dcerpc *dce)
{
	unsigned char handle[HANDLE_SIZE] = {0};

	return ndr_write_bytes(dce, handle, sizeof(handle));
}

static int samr_write_null_string_rep(struct ksmbd_dcerpc *dce)
{
	if (ndr_write_int16(dce, 0) ||
	    ndr_write_int16(dce, 0) ||
	    ndr_write_int32(dce, 0))
		return -EINVAL;
	return 0;
}

static int samr_write_ulong_array(struct ksmbd_dcerpc *dce,
				  unsigned int count,
				  const __u32 *values);

static int samr_write_error_payload(struct ksmbd_dcerpc *dce,
				    unsigned int opnum)
{
	switch (opnum) {
	case SAMR_OPNUM_CONNECT5:
		if (ndr_write_int32(dce, 0) ||
		    ndr_write_int32(dce, 0) ||
		    ndr_write_int32(dce, 0) ||
		    ndr_write_int32(dce, 0) ||
		    samr_write_zero_handle(dce))
			return KSMBD_RPC_EBAD_DATA;
		return KSMBD_RPC_OK;
	case SAMR_OPNUM_ENUM_DOMAIN:
		if (ndr_write_int32(dce, dce->sm_req.resume_handle) ||
		    ndr_write_int32(dce, 0) ||
		    ndr_write_int32(dce, 0))
			return KSMBD_RPC_EBAD_DATA;
		return KSMBD_RPC_OK;
	case SAMR_OPNUM_LOOKUP_DOMAIN:
	case SAMR_OPNUM_QUERY_USER_INFO:
	case SAMR_OPNUM_QUERY_SECURITY:
	case SAMR_OPNUM_GET_GROUP_FOR_USER:
		return ndr_write_int32(dce, 0) ? KSMBD_RPC_EBAD_DATA :
					 KSMBD_RPC_OK;
	case SAMR_OPNUM_OPEN_DOMAIN:
	case SAMR_OPNUM_OPEN_USER:
	case SAMR_OPNUM_CLOSE:
		return samr_write_zero_handle(dce) ? KSMBD_RPC_EBAD_DATA :
					    KSMBD_RPC_OK;
	case SAMR_OPNUM_LOOKUP_NAMES:
		if (samr_write_ulong_array(dce, 0, NULL) ||
		    samr_write_ulong_array(dce, 0, NULL))
			return KSMBD_RPC_EBAD_DATA;
		return KSMBD_RPC_OK;
	case SAMR_OPNUM_GET_ALIAS_MEMBERSHIP:
		if (samr_write_ulong_array(dce, 0, NULL))
			return KSMBD_RPC_EBAD_DATA;
		return KSMBD_RPC_OK;
	default:
		return KSMBD_RPC_OK;
	}
}

static int samr_read_sid_argument(struct ksmbd_dcerpc *dce,
				  struct smb_sid *sid)
{
	__u32 max_count;

	if (ndr_read_int32(dce, &max_count))
		return -EINVAL;
	if (max_count > SID_MAX_SUB_AUTHORITIES)
		return -EINVAL;
	if (smb_read_sid(dce, sid))
		return -EINVAL;
	if (max_count < sid->num_subauth)
		return -EINVAL;
	return 0;
}

static void samr_init_builtin_sid(struct smb_sid *sid)
{
	memset(sid, 0, sizeof(*sid));
	sid->revision = 1;
	sid->num_subauth = 1;
	sid->authority[5] = 5;
	sid->sub_auth[0] = 32;
}

static int samr_lookup_domain_sid(const char *name, struct smb_sid *sid)
{
	if (!name || !sid)
		return -EINVAL;

	if (!g_ascii_strcasecmp(name, domain_name)) {
		smb_init_domain_sid(sid);
		return 0;
	}
	if (!g_ascii_strcasecmp(name, "Builtin")) {
		samr_init_builtin_sid(sid);
		return 0;
	}
	return -ENOENT;
}

static int samr_syntax_supported(struct ksmbd_rpc_pipe *pipe,
				 __u16 context_id)
{
	const struct dcerpc_syntax *syntax;

	syntax = rpc_pipe_context_syntax(pipe, context_id);
	if (!syntax)
		return 0;

	return syntax->uuid.time_low == 0x12345778 &&
	       syntax->uuid.time_mid == 0x1234 &&
	       syntax->uuid.time_hi_and_version == 0xabcd &&
	       syntax->uuid.clock_seq[0] == 0xef &&
	       syntax->uuid.clock_seq[1] == 0x00 &&
	       syntax->uuid.node[0] == 0x01 &&
	       syntax->uuid.node[1] == 0x23 &&
	       syntax->uuid.node[2] == 0x45 &&
	       syntax->uuid.node[3] == 0x67 &&
	       syntax->uuid.node[4] == 0x89 &&
	       syntax->uuid.node[5] == 0xac &&
	       syntax->ver_major == 1 &&
	       syntax->ver_minor == 0;
}

static int samr_connect5_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct ndr_uniq_char_ptr server_name;
	__u32 revision;

	if (ndr_read_uniq_vstring_ptr(dce, &server_name))
		return KSMBD_RPC_EINVALID_PARAMETER;
	ndr_free_uniq_vstring_ptr(&server_name);

	if (ndr_read_int32(dce, &dce->sm_req.access_mask))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (ndr_read_int32(dce, &dce->sm_req.level))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (ndr_read_int32(dce, &revision))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (revision != dce->sm_req.level)
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (ndr_read_int32(dce, &dce->sm_req.client_version))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (ndr_read_int32(dce, &dce->sm_req.supported_features))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (dce->sm_req.level != 1)
		return KSMBD_RPC_EINVALID_PARAMETER;
	return ndr_request_end(dce) ? KSMBD_RPC_EINVALID_PARAMETER :
				      KSMBD_RPC_OK;
}

static int samr_connect5_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct connect_handle *ch;

	if (ndr_write_int32(dce, dce->sm_req.level)) // level out
		return KSMBD_RPC_EBAD_DATA;

	if (ndr_write_int32(dce, dce->sm_req.level)) // revision info tag
		return KSMBD_RPC_EBAD_DATA;
	if (ndr_write_int32(dce, dce->sm_req.client_version)) // client version
		return KSMBD_RPC_EBAD_DATA;

	if (ndr_write_int32(dce, dce->sm_req.supported_features))
		return KSMBD_RPC_EBAD_DATA;

	ch = samr_ch_alloc(pipe, SAMR_HANDLE_SERVER,
			   dce->sm_req.access_mask, NULL, NULL);
	if (!ch) {
		if (samr_write_zero_handle(dce))
			return KSMBD_RPC_EBAD_DATA;
		return KSMBD_RPC_ENOMEM;
	}

	/* write connect handle */
	if (ndr_write_bytes(dce, ch->handle, HANDLE_SIZE)) {
		samr_ch_close(pipe, ch->handle);
		return KSMBD_RPC_EBAD_DATA;
	}

	return KSMBD_RPC_OK;
}

static int samr_enum_domain_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;

	if (ndr_read_bytes(dce, dce->sm_req.handle, HANDLE_SIZE))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (ndr_read_int32(dce, &dce->sm_req.resume_handle))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (ndr_read_int32(dce, &dce->sm_req.buf_size))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (dce->sm_req.resume_handle > num_domain_entries)
		return KSMBD_RPC_EINVALID_PARAMETER;

	return ndr_request_end(dce) ? KSMBD_RPC_EINVALID_PARAMETER :
				      KSMBD_RPC_OK;
}

static int samr_ndr_write_domain_array(struct ksmbd_rpc_pipe *pipe,
				       unsigned int start,
				       unsigned int count)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int i, ret = 0;

	for (i = 0; i < count; i++) {
		char *entry;
		size_t name_len;

		entry = g_ptr_array_index(domain_entries, start + i);
		ret = ndr_write_int32(dce, start + i);
		if (ret)
			return ret;
		name_len = strlen(entry);
		if (name_len > UINT16_MAX / 2)
			return -EOVERFLOW;
		ret = ndr_write_int16(dce, name_len*2);
		if (ret)
			return ret;

		ret = ndr_write_int16(dce, name_len*2);
		if (ret)
			return ret;

		/* ref pointer for name entry */
		dce->num_pointers++;
		ret = ndr_write_int32(dce, dce->num_pointers);
		if (ret)
			return ret;
	}

	for (i = 0; i < count; i++) {
		char *entry;

		entry = g_ptr_array_index(domain_entries, start + i);
		ret = ndr_write_string(dce, entry);
		if (ret)
			return ret;
	}

	return ret;
}

static int samr_enum_domain_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct connect_handle *ch;
	unsigned int start, count, next;
	int ret;

	ch = samr_ch_lookup(pipe, dce->sm_req.handle);
	ret = samr_handle_access(ch, SAMR_HANDLE_SERVER,
				 SAM_SERVER_ENUMERATE_DOMAINS);
	if (ret)
		goto out;

	start = dce->sm_req.resume_handle;
	if (start > num_domain_entries) {
		ret = KSMBD_RPC_EINVALID_PARAMETER;
		goto out;
	}
	count = num_domain_entries - start;
	if (dce->sm_req.buf_size && count > dce->sm_req.buf_size / 64)
		count = dce->sm_req.buf_size / 64;
	if (count > num_domain_entries - start)
		count = num_domain_entries - start;
	if (start < num_domain_entries && !count) {
		ret = SAMR_STATUS_BUFFER_TOO_SMALL;
		goto out;
	}
	dce->sm_req.enum_start = start;
	dce->sm_req.enum_count = count;
	next = start + count;
	dce->sm_req.resume_handle = next;
	if (next < num_domain_entries)
		dce->sm_req.operation_status = KSMBD_RPC_EMORE_DATA;
	else
		dce->sm_req.operation_status = KSMBD_RPC_OK;

	if (ndr_write_int32(dce, next))
		goto bad_data;

	dce->num_pointers++;
	if (ndr_write_int32(dce, dce->num_pointers)) // ref pointer
		goto bad_data;

	if (ndr_write_int32(dce, count)) // Sam entry count
		goto bad_data;

	if (count) {
		dce->num_pointers++;
		if (ndr_write_int32(dce, dce->num_pointers)) // ref pointer
			goto bad_data;

		if (ndr_write_int32(dce, count)) // Sam max entry count
			goto bad_data;

		if (samr_ndr_write_domain_array(pipe, start, count))
			goto bad_data;
	} else if (ndr_write_int32(dce, 0)) {
		goto bad_data;
	}

	/* [out] DWORD* Num Entries */
	if (ndr_write_int32(dce, count))
		goto bad_data;

	ret = dce->sm_req.operation_status;
	goto out;
bad_data:
	ret = KSMBD_RPC_EBAD_DATA;
out:
	samr_ch_put(ch);
	return ret;
}

static int samr_lookup_domain_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct ndr_string_rep rep;

	if (ndr_read_bytes(dce, dce->sm_req.handle, HANDLE_SIZE))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (ndr_read_string_rep(dce, &rep) || !rep.ref_id)
		return KSMBD_RPC_EINVALID_PARAMETER;
	dce->sm_req.name.ref_id = rep.ref_id;
	dce->sm_req.name.ptr = ndr_read_string_data(dce, &rep);
	if (!dce->sm_req.name.ptr)
		return KSMBD_RPC_EINVALID_PARAMETER;

	if (ndr_request_end(dce)) {
		ndr_free_uniq_vstring_ptr(&dce->sm_req.name);
		return KSMBD_RPC_EINVALID_PARAMETER;
	}
	return KSMBD_RPC_OK;
}

static int samr_lookup_domain_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct connect_handle *ch;
	struct smb_sid sid;
	int ret, write_ret;

	ch = samr_ch_lookup(pipe, dce->sm_req.handle);
	ret = samr_handle_access(ch, SAMR_HANDLE_SERVER,
				 SAM_SERVER_LOOKUP_DOMAIN);
	if (!ret)
		ret = samr_lookup_domain_sid(STR_VAL(dce->sm_req.name), &sid);
	if (ret == -ENOENT)
		ret = SAMR_STATUS_NO_SUCH_DOMAIN;

	if (!ret) {
		dce->num_pointers++;
		write_ret = ndr_write_int32(dce, dce->num_pointers);
		if (!write_ret)
			write_ret = ndr_write_int32(dce, sid.num_subauth);
		if (!write_ret)
			write_ret = smb_write_sid(dce, &sid);
		if (write_ret)
			ret = KSMBD_RPC_EBAD_DATA;
	} else if (ndr_write_int32(dce, 0)) {
		ret = KSMBD_RPC_EBAD_DATA;
	}

	ndr_free_uniq_vstring_ptr(&dce->sm_req.name);
	samr_ch_put(ch);
	return ret;
}

static int samr_open_domain_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct smb_sid sid;

	if (ndr_read_bytes(dce, dce->sm_req.handle, HANDLE_SIZE))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (ndr_read_int32(dce, &dce->sm_req.access_mask))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (samr_read_sid_argument(dce, &sid))
		return KSMBD_RPC_EINVALID_PARAMETER;
	memcpy(dce->sm_req.sid, &sid, sizeof(sid));

	return ndr_request_end(dce) ? KSMBD_RPC_EINVALID_PARAMETER :
				      KSMBD_RPC_OK;
}

static int samr_open_domain_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct connect_handle *ch;
	struct connect_handle *domain;
	struct smb_sid sid;
	struct smb_sid builtin_sid;
	int ret;

	ch = samr_ch_lookup(pipe, dce->sm_req.handle);
	ret = samr_handle_access(ch, SAMR_HANDLE_SERVER,
				 SAM_SERVER_LOOKUP_DOMAIN);
	if (ret)
		goto fail;

	memcpy(&sid, dce->sm_req.sid, sizeof(sid));
	samr_init_builtin_sid(&builtin_sid);
	{
		struct smb_sid local_sid;

		smb_init_domain_sid(&local_sid);
		if (smb_compare_sids(&sid, &builtin_sid) &&
		    smb_compare_sids(&sid, &local_sid)) {
			ret = SAMR_STATUS_NO_SUCH_DOMAIN;
			goto fail;
		}
	}

	domain = samr_ch_alloc(pipe, SAMR_HANDLE_DOMAIN,
			       dce->sm_req.access_mask, &sid, NULL);
	if (!domain) {
		ret = KSMBD_RPC_ENOMEM;
		goto fail;
	}
	if (ndr_write_bytes(dce, domain->handle, HANDLE_SIZE)) {
		samr_ch_close(pipe, domain->handle);
		ret = KSMBD_RPC_EBAD_DATA;
		goto fail;
	}

	ret = KSMBD_RPC_OK;
	samr_ch_put(ch);
	return ret;

fail:
	if (samr_write_zero_handle(dce))
		ret = KSMBD_RPC_EBAD_DATA;
	samr_ch_put(ch);
	return ret;
}

static int samr_lookup_names_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	GPtrArray *reps;
	__u32 count, max_count, offset, actual;
	unsigned int i;

	if (ndr_read_bytes(dce, dce->sm_req.handle, HANDLE_SIZE))
		return KSMBD_RPC_EINVALID_PARAMETER;

	if (ndr_read_int32(dce, &count) ||
	    ndr_read_int32(dce, &max_count) ||
	    ndr_read_int32(dce, &offset) ||
	    ndr_read_int32(dce, &actual))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (count > SAMR_MAX_LOOKUP_NAME_COUNT || max_count < count ||
	    offset != 0 || actual != count)
		return KSMBD_RPC_EINVALID_PARAMETER;

	reps = g_ptr_array_new_with_free_func(g_free);
	if (!reps)
		return KSMBD_RPC_ENOMEM;

	for (i = 0; i < count; i++) {
		struct ndr_string_rep *rep;

		rep = g_try_malloc(sizeof(*rep));
		if (!rep ||
		    ndr_read_string_rep(dce, rep) ||
		    rep->length > 4096 ||
		    rep->size > 4096) {
			g_free(rep);
			g_ptr_array_free(reps, 1);
			return KSMBD_RPC_EINVALID_PARAMETER;
		}
		g_ptr_array_add(reps, rep);
	}

	samr_free_names(&dce->sm_req);
	dce->sm_req.names = g_ptr_array_new_with_free_func(g_free);
	if (!dce->sm_req.names) {
		g_ptr_array_free(reps, 1);
		return KSMBD_RPC_ENOMEM;
	}

	for (i = 0; i < count; i++) {
		struct ndr_string_rep *rep;
		char *name;

		rep = g_ptr_array_index(reps, i);
		name = rep->ref_id ? ndr_read_string_data(dce, rep) : NULL;
		if (rep->ref_id && !name) {
			g_ptr_array_free(reps, 1);
			samr_free_names(&dce->sm_req);
			return KSMBD_RPC_EINVALID_PARAMETER;
		}
		g_ptr_array_add(dce->sm_req.names, name);
	}
	g_ptr_array_free(reps, 1);
	dce->sm_req.name_count = count;

	return ndr_request_end(dce) ? KSMBD_RPC_EINVALID_PARAMETER :
				      KSMBD_RPC_OK;
}

static int samr_write_ulong_array(struct ksmbd_dcerpc *dce,
				  unsigned int count,
				  const __u32 *values)
{
	unsigned int i;

	if (ndr_write_int32(dce, count))
		return -EINVAL;
	if (!count)
		return ndr_write_int32(dce, 0);

	dce->num_pointers++;
	if (ndr_write_int32(dce, dce->num_pointers) ||
	    ndr_write_int32(dce, count))
		return -EINVAL;
	for (i = 0; i < count; i++)
		if (ndr_write_int32(dce, values[i]))
			return -EINVAL;
	return 0;
}

static int samr_write_nonnull_empty_ulong_array(struct ksmbd_dcerpc *dce)
{
	if (ndr_write_int32(dce, 0))
		return -EINVAL;

	dce->num_pointers++;
	if (ndr_write_int32(dce, dce->num_pointers) ||
	    ndr_write_int32(dce, 0))
		return -EINVAL;

	return 0;
}

static int samr_lookup_names_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct connect_handle *ch;
	struct smb_sid local_sid;
	g_autofree __u32 *rids = NULL;
	g_autofree __u32 *types = NULL;
	unsigned int i, mapped = 0;
	int ret = KSMBD_RPC_OK;

	ch = samr_ch_lookup(pipe, dce->sm_req.handle);
	ret = samr_handle_access(ch, SAMR_HANDLE_DOMAIN, SAM_DOMAIN_LOOKUP);
	if (ret)
		goto out;

	rids = g_try_malloc0_n(dce->sm_req.name_count, sizeof(*rids));
	types = g_try_malloc0_n(dce->sm_req.name_count, sizeof(*types));
	if ((dce->sm_req.name_count && !rids) ||
	    (dce->sm_req.name_count && !types)) {
		ret = KSMBD_RPC_ENOMEM;
		goto out;
	}

	smb_init_domain_sid(&local_sid);
	for (i = 0; i < dce->sm_req.name_count; i++) {
		rids[i] = UINT32_MAX;
		types[i] = SID_TYPE_UNKNOWN;
	}
	for (i = 0; i < dce->sm_req.name_count; i++) {
		struct ksmbd_user *user;
		char *name = g_ptr_array_index(dce->sm_req.names, i);

		if (smb_compare_sids(&ch->domain_sid, &local_sid))
			continue;
		user = usm_lookup_user_casefold(name);
		if (!user)
			continue;
		rids[i] = user->uid;
		types[i] = SID_TYPE_USER;
		mapped++;
		put_ksmbd_user(user);
	}

	if (samr_write_ulong_array(dce, dce->sm_req.name_count, rids) ||
	    samr_write_ulong_array(dce, dce->sm_req.name_count, types)) {
		ret = KSMBD_RPC_EBAD_DATA;
		goto out;
	}

	if (mapped != dce->sm_req.name_count)
		ret = mapped ? SAMR_STATUS_SOME_NOT_MAPPED :
			      SAMR_STATUS_NONE_MAPPED;
out:
	samr_free_names(&dce->sm_req);
	samr_ch_put(ch);
	return ret;
}

static int samr_open_user_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;

	if (ndr_read_bytes(dce, dce->sm_req.handle, HANDLE_SIZE))
		return KSMBD_RPC_EINVALID_PARAMETER;

	if (ndr_read_int32(dce, &dce->sm_req.access_mask))
		return KSMBD_RPC_EINVALID_PARAMETER;
	// RID
	if (ndr_read_int32(dce, &dce->sm_req.rid))
		return KSMBD_RPC_EINVALID_PARAMETER;

	return ndr_request_end(dce) ? KSMBD_RPC_EINVALID_PARAMETER :
				      KSMBD_RPC_OK;
}

static int samr_open_user_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct connect_handle *ch;
	struct connect_handle *user_handle;
	struct ksmbd_user *user;
	struct smb_sid local_sid;
	int ret;

	ch = samr_ch_lookup(pipe, dce->sm_req.handle);
	ret = samr_handle_access(ch, SAMR_HANDLE_DOMAIN, SAM_DOMAIN_LOOKUP);
	if (ret)
		goto fail;

	smb_init_domain_sid(&local_sid);
	if (smb_compare_sids(&ch->domain_sid, &local_sid)) {
		ret = SAMR_STATUS_NO_SUCH_USER;
		goto fail;
	}

	user = usm_lookup_uid(dce->sm_req.rid);
	if (!user) {
		ret = SAMR_STATUS_NO_SUCH_USER;
		goto fail;
	}

	user_handle = samr_ch_alloc(pipe, SAMR_HANDLE_USER,
				    dce->sm_req.access_mask,
				    &ch->domain_sid, user);
	if (!user_handle) {
		put_ksmbd_user(user);
		ret = KSMBD_RPC_ENOMEM;
		goto fail;
	}

	if (ndr_write_bytes(dce, user_handle->handle, HANDLE_SIZE)) {
		samr_ch_close(pipe, user_handle->handle);
		ret = KSMBD_RPC_EBAD_DATA;
		goto fail;
	}

	ret = KSMBD_RPC_OK;
	samr_ch_put(ch);
	return ret;

fail:
	if (samr_write_zero_handle(dce))
		ret = KSMBD_RPC_EBAD_DATA;
	samr_ch_put(ch);
	return ret;
}

static int samr_query_user_info_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	__u16 level;

	if (ndr_read_bytes(dce, dce->sm_req.handle, HANDLE_SIZE))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (ndr_read_int16(dce, &level))
		return KSMBD_RPC_EINVALID_PARAMETER;
	dce->sm_req.level = level;

	return ndr_request_end(dce) ? KSMBD_RPC_EINVALID_PARAMETER :
				      KSMBD_RPC_OK;
}

static int samr_write_user_string_rep(struct ksmbd_dcerpc *dce,
				      const char *value)
{
	g_autofree char *converted = NULL;
	gsize bytes_written = 0;
	size_t len;
	int charset = KSMBD_CHARSET_UTF16LE;

	if (!value)
		value = "";
	if (!(dce->flags & KSMBD_DCERPC_LITTLE_ENDIAN))
		charset = KSMBD_CHARSET_UTF16BE;
	if (dce->flags & KSMBD_DCERPC_ASCII_STRING)
		charset = KSMBD_CHARSET_UTF8;

	converted = ksmbd_gconvert(value, strlen(value), charset,
				   KSMBD_CHARSET_DEFAULT, NULL,
				   &bytes_written);
	if (!converted || bytes_written > UINT16_MAX ||
	    bytes_written % 2)
		return -EINVAL;
	len = bytes_written;

	if (ndr_write_int16(dce, len) ||
	    ndr_write_int16(dce, len))
		return -EINVAL;
	dce->num_pointers++;
	if (ndr_write_int32(dce, dce->num_pointers))
		return -EINVAL;
	return 0;
}

static int samr_write_user_info_header(struct ksmbd_dcerpc *dce,
				       unsigned int level)
{
	dce->num_pointers++;
	if (ndr_write_int32(dce, dce->num_pointers) ||
	    ndr_write_int16(dce, level) ||
	    ndr_write_int16(dce, 0))
		return -EINVAL;
	return 0;
}

static int samr_query_user_info_simple(struct ksmbd_dcerpc *dce,
				       struct connect_handle *ch)
{
	const char *home = "\\";
	const char *profile = "\\profile";
	unsigned int level = dce->sm_req.level;
	int ret;

	switch (level) {
	case 1:
	case 6:
	case 7:
	case 8:
	case 9:
	case 10:
	case 11:
	case 12:
	case 13:
	case 14:
		break;
	default:
		return SAMR_STATUS_INVALID_INFO_CLASS;
	}

	if (samr_write_user_info_header(dce, level))
		return KSMBD_RPC_EBAD_DATA;

	switch (level) {
	case 1: /* UserGeneralInformation */
		ret = samr_write_user_string_rep(dce, ch->user->name);
		if (ret)
			return KSMBD_RPC_EBAD_DATA;
		ret = samr_write_user_string_rep(dce, ch->user->name);
		if (ret)
			return KSMBD_RPC_EBAD_DATA;
		if (ndr_write_int32(dce, ch->user->gid))
			return KSMBD_RPC_EBAD_DATA;
		ret = samr_write_user_string_rep(dce, "");
		if (ret)
			return KSMBD_RPC_EBAD_DATA;
		ret = samr_write_user_string_rep(dce, "");
		if (ret)
			return KSMBD_RPC_EBAD_DATA;
		if (ndr_write_string(dce, ch->user->name) ||
		    ndr_write_string(dce, ch->user->name) ||
		    ndr_write_string(dce, "") ||
		    ndr_write_string(dce, ""))
			return KSMBD_RPC_EBAD_DATA;
		break;
	case 6: /* UserNameInformation */
		if (samr_write_user_string_rep(dce, ch->user->name) ||
		    samr_write_user_string_rep(dce, ch->user->name) ||
		    ndr_write_string(dce, ch->user->name) ||
		    ndr_write_string(dce, ch->user->name))
			return KSMBD_RPC_EBAD_DATA;
		break;
	case 7: /* UserAccountNameInformation */
	case 8: /* UserFullNameInformation */
		if (samr_write_user_string_rep(dce, ch->user->name) ||
		    ndr_write_string(dce, ch->user->name))
			return KSMBD_RPC_EBAD_DATA;
		break;
	case 9: /* UserPrimaryGroupInformation */
		if (ndr_write_int32(dce, ch->user->gid))
			return KSMBD_RPC_EBAD_DATA;
		break;
	case 10: /* UserHomeInformation */
		if (samr_write_user_string_rep(dce, home) ||
		    samr_write_user_string_rep(dce, "") ||
		    ndr_write_string(dce, home) ||
		    ndr_write_string(dce, ""))
			return KSMBD_RPC_EBAD_DATA;
		break;
	case 11: /* UserScriptInformation */
		if (samr_write_user_string_rep(dce, "") ||
		    ndr_write_string(dce, ""))
			return KSMBD_RPC_EBAD_DATA;
		break;
	case 12: /* UserProfileInformation */
		if (samr_write_user_string_rep(dce, profile) ||
		    ndr_write_string(dce, profile))
			return KSMBD_RPC_EBAD_DATA;
		break;
	case 13: /* UserAdminCommentInformation */
	case 14: /* UserWorkStationsInformation */
		if (samr_write_user_string_rep(dce, "") ||
		    ndr_write_string(dce, ""))
			return KSMBD_RPC_EBAD_DATA;
		break;
	}
	return KSMBD_RPC_OK;
}

static int samr_query_user_info_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct connect_handle *ch = NULL;
	char *home_dir;
	g_autofree char *profile_path = NULL;
	char hostname[NAME_MAX] = {0};
	size_t home_dir_len;
	unsigned int required;
	int i, ret;

	switch (dce->sm_req.level) {
	case 1:
	case 6:
	case 7:
	case 8:
	case 9:
	case 13:
		required = SAM_USER_READ_GENERAL;
		break;
	case 10:
	case 11:
	case 12:
	case 14:
		required = SAM_USER_READ_LOGON;
		break;
	case 21:
		required = SAM_USER_READ_ACCOUNT;
		break;
	default:
		ret = SAMR_STATUS_INVALID_INFO_CLASS;
		goto invalid;
	}

	ch = samr_ch_lookup(pipe, dce->sm_req.handle);
	ret = samr_handle_access(ch, SAMR_HANDLE_USER, required);
	if (ret)
		goto invalid;
	if (dce->sm_req.level != 21) {
		ret = samr_query_user_info_simple(dce, ch);
		samr_ch_put(ch);
		return ret;
	}

	if (gethostname(hostname, sizeof(hostname) - 1)) {
		samr_ch_put(ch);
		return KSMBD_RPC_ENOMEM;
	}

	home_dir_len = 2 + strlen(hostname) + 1 + strlen(ch->user->name) + 1;

	home_dir = g_try_malloc0(home_dir_len);
	if (!home_dir) {
		samr_ch_put(ch);
		return KSMBD_RPC_ENOMEM;
	}

	/* Make Home dir string */
	strcpy(home_dir, "\\\\");
	strcat(home_dir, hostname);
	strcat(home_dir, "\\");
	strcat(home_dir, ch->user->name);

	profile_path = g_try_malloc0(home_dir_len + 1 + strlen("profile"));
	if (!profile_path) {
		g_free(home_dir);
		samr_ch_put(ch);
		return KSMBD_RPC_ENOMEM;
	}

	/* Make Profile path string */
	strcat(profile_path, "\\\\");
	strcat(profile_path, hostname);
	strcat(profile_path, "\\");
	strcat(profile_path, ch->user->name);
	strcat(profile_path, "\\");
	strcat(profile_path, "profile");

	dce->num_pointers++;
	ret = ndr_write_int32(dce, dce->num_pointers); // ref pointer
	if (ret)
		goto out;

	ret = ndr_write_int16(dce, 0x15); // info
	if (ret)
		goto out;

	ret = ndr_write_int16(dce, 0);
	if (ret)
		goto out;

	/*
	 * Last Logon/Logoff/Password change, Acct Expiry,
	 * Allow Passworkd Change, Force Password Change.
	 */
	for (i = 0; i < 6; i++) {
		ret = ndr_write_int64(dce, 0);
		if (ret)
			goto out;
	}

	/*
	 * SAMPR_USER_ALL_INFORMATION contains ten RPC_UNICODE_STRING values
	 * before the password blobs.  Serialize all fixed representations
	 * together, then emit their deferred bodies in the same order.
	 */
	if (samr_write_user_string_rep(dce, ch->user->name) ||
	    samr_write_user_string_rep(dce, ch->user->name) ||
	    samr_write_user_string_rep(dce, home_dir) ||
	    samr_write_null_string_rep(dce) ||
	    samr_write_null_string_rep(dce) ||
	    samr_write_user_string_rep(dce, profile_path) ||
	    samr_write_null_string_rep(dce) ||
	    samr_write_null_string_rep(dce) ||
	    samr_write_null_string_rep(dce) ||
	    samr_write_null_string_rep(dce))
		goto out;

	/* Lm/Nt OWF passwords and private data are absent. */
	for (i = 0; i < 3; i++) {
		ret = ndr_write_int16(dce, 0);
		if (ret)
			goto out;

		ret = ndr_write_int16(dce, 0);
		if (ret)
			goto out;

		ret = ndr_write_int32(dce, 0);
		if (ret)
			goto out;
	}

	ret = ndr_write_int32(dce, 0); // buf count
	if (ret)
		goto out;

	/* Pointer to Buffer */
	ret = ndr_write_int32(dce, 0);
	if (ret)
		goto out;

	ret = ndr_write_int32(dce, ch->user->uid); // rid
	if (ret)
		goto out;

	ret = ndr_write_int32(dce, ch->user->gid); // primary gid
	if (ret)
		goto out;

	ret = ndr_write_int32(dce, 0x00000010); // Acct Flags : Acb Normal
	if (ret)
		goto out;

	ret = ndr_write_int32(dce, 0x00FFFFFF); // Fields Present
	if (ret)
		goto out;

	ret = ndr_write_int32(dce, 168); // logon hours units per week
	if (ret)
		goto out;

	/* Pointers to Bits */
	dce->num_pointers++;
	ret = ndr_write_int32(dce, dce->num_pointers); //ref pointer
	if (ret)
		goto out;

	/* Bad Password/Logon Count/Country Code/Code Page */
	for (i = 0; i < 4; i++) {
		ret = ndr_write_int16(dce, 0);
		if (ret)
			goto out;
	}


	/* Lm/Nt Password Set, Password Expired/etc */
	ret = ndr_write_int8(dce, 0);
	if (ret)
		goto out;

	ret = ndr_write_int8(dce, 0);
	if (ret)
		goto out;

	ret = ndr_write_int8(dce, 0);
	if (ret)
		goto out;

	ret = ndr_write_int8(dce, 0);
	if (ret)
		goto out;


	ret = ndr_write_string(dce, ch->user->name);
	if (ret)
		goto out;

	ret = ndr_write_string(dce, ch->user->name);
	if (ret)
		goto out;

	ret = ndr_write_string(dce, home_dir);
	if (ret)
		goto out;


	ret = ndr_write_string(dce, profile_path);
	if (ret)
		goto out;

	/* Logon Hours */
	ret = ndr_write_int32(dce, 21);
	if (ret)
		goto out;

	ret = ndr_write_int32(dce, 0);
	if (ret)
		goto out;

	ret = ndr_write_int32(dce, 21);
	if (ret)
		goto out;

	for (i = 0; i < 21; i++) {
		ret = ndr_write_int8(dce, 0xff);
		if (ret)
			break;
	}

out:
	g_free(home_dir);
	samr_ch_put(ch);
	return ret ? KSMBD_RPC_EBAD_DATA: KSMBD_RPC_OK;

invalid:
	if (ndr_write_int32(dce, 0)) {
		samr_ch_put(ch);
		return KSMBD_RPC_EBAD_DATA;
	}
	samr_ch_put(ch);
	return ret;
}

static int samr_query_security_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;

	if (ndr_read_bytes(dce, dce->sm_req.handle, HANDLE_SIZE))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (ndr_read_int32(dce, &dce->sm_req.security_secinfo))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (!dce->sm_req.security_secinfo ||
	    dce->sm_req.security_secinfo & ~0x0000000F)
		return KSMBD_RPC_EINVALID_PARAMETER;

	return ndr_request_end(dce) ? KSMBD_RPC_EINVALID_PARAMETER :
				      KSMBD_RPC_OK;
}

static int samr_query_security_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct connect_handle *ch;
	int sec_desc_len, curr_offset, payload_offset, ret;
	int rid = 0;

	ch = samr_ch_lookup(pipe, dce->sm_req.handle);
	if (!ch) {
		ret = SAMR_STATUS_INVALID_HANDLE;
		goto out;
	}
	ret = samr_handle_access(ch, ch->type, SAM_READ_CONTROL);
	if (ret)
		goto out;
	if (ch->type == SAMR_HANDLE_USER) {
		if (!ch->user) {
			ret = SAMR_STATUS_INVALID_HANDLE;
			goto out;
		}
		rid = ch->user->uid;
	}

	curr_offset = dce->offset;
	dce->offset += 16;
	if (build_sec_desc(dce, &sec_desc_len, rid)) {
		ret = KSMBD_RPC_EBAD_DATA;
		goto out;
	}

	payload_offset = dce->offset;
	dce->offset = curr_offset + 12;
	if (ndr_write_int32(dce, sec_desc_len)) {
		ret = KSMBD_RPC_EBAD_DATA;
		goto out;
	}

	dce->offset = curr_offset;
	dce->num_pointers++;
	if (ndr_write_int32(dce, dce->num_pointers))
		goto bad_data;
	if (ndr_write_int32(dce, sec_desc_len))
		goto bad_data;

	dce->num_pointers++;
	if (ndr_write_int32(dce, dce->num_pointers))
		goto bad_data;

	if (ndr_write_int32(dce, sec_desc_len))
		goto bad_data;

	dce->offset = payload_offset;
	ret = KSMBD_RPC_OK;
out:
	samr_ch_put(ch);
	return ret;
bad_data:
	ret = KSMBD_RPC_EBAD_DATA;
	goto out;
}

static int samr_get_group_for_user_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;

	if (ndr_read_bytes(dce, dce->sm_req.handle, HANDLE_SIZE))
		return KSMBD_RPC_EINVALID_PARAMETER;

	return ndr_request_end(dce) ? KSMBD_RPC_EINVALID_PARAMETER :
				      KSMBD_RPC_OK;
}

static int samr_get_group_for_user_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct connect_handle *ch;
	int ret;

	ch = samr_ch_lookup(pipe, dce->sm_req.handle);
	ret = samr_handle_access(ch, SAMR_HANDLE_USER,
				 SAM_USER_LIST_GROUPS);
	if (ret)
		goto out;

	dce->num_pointers++;
	if (ndr_write_int32(dce, dce->num_pointers)) // ref pointer
		goto bad_data;

	if (ndr_write_int32(dce, 1)) // count
		goto bad_data;

	dce->num_pointers++;
	if (ndr_write_int32(dce, dce->num_pointers)) // ref pointer
		goto bad_data;

	if (ndr_write_int32(dce, 1)) // max count
		goto bad_data;

	if (ndr_write_int32(dce, ch->user->gid)) // group rid
		goto bad_data;

	if (ndr_write_int32(dce, 0x00000007)) // attributes
		goto bad_data;

	ret = KSMBD_RPC_OK;
out:
	samr_ch_put(ch);
	return ret;
bad_data:
	ret = KSMBD_RPC_EBAD_DATA;
	goto out;
}

static int samr_get_alias_membership_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	__u32 count, array_ref, max_count;
	unsigned int i;

	if (ndr_read_bytes(dce, dce->sm_req.handle, HANDLE_SIZE))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (ndr_read_int32(dce, &count) ||
	    ndr_read_int32(dce, &array_ref))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (count > SAMR_MAX_ALIAS_SID_COUNT)
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (count && !array_ref)
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (array_ref) {
		if (ndr_read_int32(dce, &max_count) ||
		    max_count < count)
			return KSMBD_RPC_EINVALID_PARAMETER;
	} else if (count) {
		return KSMBD_RPC_EINVALID_PARAMETER;
	}

	if (!count) {
		dce->sm_req.lookup_count = 0;
		return ndr_request_end(dce) ? KSMBD_RPC_EINVALID_PARAMETER :
					      KSMBD_RPC_OK;
	}

	for (i = 0; i < count; i++) {
		__u32 sid_ref;

		if (ndr_read_int32(dce, &sid_ref) || !sid_ref)
			return KSMBD_RPC_EINVALID_PARAMETER;
	}
	for (i = 0; i < count; i++) {
		struct smb_sid sid;

		if (samr_read_sid_argument(dce, &sid))
			return KSMBD_RPC_EINVALID_PARAMETER;
	}

	dce->sm_req.lookup_count = count;
	return ndr_request_end(dce) ? KSMBD_RPC_EINVALID_PARAMETER :
				      KSMBD_RPC_OK;
}

static int samr_get_alias_membership_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct connect_handle *ch;
	int ret;

	ch = samr_ch_lookup(pipe, dce->sm_req.handle);
	ret = samr_handle_access(ch, SAMR_HANDLE_DOMAIN,
				 SAM_DOMAIN_GET_ALIAS_MEMBERSHIP |
				 SAM_DOMAIN_LOOKUP);
	if (ret)
		goto out;

	if (samr_write_nonnull_empty_ulong_array(dce))
		goto bad_data;

	ret = KSMBD_RPC_OK;
out:
	samr_ch_put(ch);
	return ret;
bad_data:
	ret = KSMBD_RPC_EBAD_DATA;
	goto out;
}

static int samr_close_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	__u32 compatibility_field;

	if (ndr_read_bytes(dce, dce->sm_req.handle, HANDLE_SIZE))
		return KSMBD_RPC_EINVALID_PARAMETER;

	/*
	 * The SAMR IDL defines a handle-only request.  Older clients,
	 * including some Impacket releases, append a zero DesiredAccess
	 * member, so accept that compatibility encoding without accepting
	 * arbitrary trailing data.
	 */
	if (dce->payload_sz - dce->offset == sizeof(compatibility_field)) {
		if (ndr_read_int32(dce, &compatibility_field) ||
		    compatibility_field)
			return KSMBD_RPC_EINVALID_PARAMETER;
	}

	return ndr_request_end(dce) ? KSMBD_RPC_EINVALID_PARAMETER :
				      KSMBD_RPC_OK;
}

static int samr_close_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int ret;

	ret = samr_ch_close(pipe, dce->sm_req.handle);

	/* write connect handle */
	if (samr_write_zero_handle(dce))
		return KSMBD_RPC_EBAD_DATA;

	return ret;
}

static int samr_invoke(struct ksmbd_rpc_pipe *pipe)
{
	if (!samr_syntax_supported(pipe, pipe->dce->req_hdr.context_id))
		return KSMBD_RPC_EINVALID_PARAMETER;

	int ret = KSMBD_RPC_ENOTIMPLEMENTED;

	switch (pipe->dce->req_hdr.opnum) {
	case SAMR_OPNUM_CONNECT5:
		ret = samr_connect5_invoke(pipe);
		break;
	case SAMR_OPNUM_ENUM_DOMAIN:
		ret = samr_enum_domain_invoke(pipe);
		break;
	case SAMR_OPNUM_LOOKUP_DOMAIN:
		ret = samr_lookup_domain_invoke(pipe);
		break;
	case SAMR_OPNUM_OPEN_DOMAIN:
		ret = samr_open_domain_invoke(pipe);
		break;
	case SAMR_OPNUM_LOOKUP_NAMES:
		ret = samr_lookup_names_invoke(pipe);
		break;
	case SAMR_OPNUM_OPEN_USER:
		ret = samr_open_user_invoke(pipe);
		break;
	case SAMR_OPNUM_QUERY_USER_INFO:
		ret = samr_query_user_info_invoke(pipe);
		break;
	case SAMR_OPNUM_QUERY_SECURITY:
		ret = samr_query_security_invoke(pipe);
		break;
	case SAMR_OPNUM_GET_GROUP_FOR_USER:
		ret = samr_get_group_for_user_invoke(pipe);
		break;
	case SAMR_OPNUM_GET_ALIAS_MEMBERSHIP:
		ret = samr_get_alias_membership_invoke(pipe);
		break;
	case SAMR_OPNUM_CLOSE:
		ret = samr_close_invoke(pipe);
		break;
	default:
		pr_err("SAMR: unsupported INVOKE method %d\n",
		       pipe->dce->req_hdr.opnum);
		break;
	}

	return ret;
}

static int samr_return(struct ksmbd_rpc_pipe *pipe,
			 struct ksmbd_rpc_command *resp,
			 int max_resp_sz)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	size_t payload_start;
	__u32 wire_status;
	int ipc_status;
	int status;

	/*
	 * Reserve space for response NDR header. We don't know yet if
	 * the payload buffer is big enough. This will determine if we
	 * can set DCERPC_PFC_FIRST_FRAG|DCERPC_PFC_LAST_FRAG or if we
	 * will have a multi-part response.
	 */
	dce->offset = sizeof(struct dcerpc_header);
	dce->offset += sizeof(struct dcerpc_response_header);
	payload_start = dce->offset;

	if (rpc_restricted_context(dce->rpc_req))
		dce->sm_req.operation_status = KSMBD_RPC_EACCESS_DENIED;

	if (dce->sm_req.operation_status) {
		status = dce->sm_req.operation_status;
		samr_free_names(&dce->sm_req);
		if (samr_write_error_payload(dce, dce->req_hdr.opnum))
			return KSMBD_RPC_EBAD_DATA;
	} else {
		switch (dce->req_hdr.opnum) {
		case SAMR_OPNUM_CONNECT5:
			status = samr_connect5_return(pipe);
			break;
		case SAMR_OPNUM_ENUM_DOMAIN:
			status = samr_enum_domain_return(pipe);
			break;
		case SAMR_OPNUM_LOOKUP_DOMAIN:
			status = samr_lookup_domain_return(pipe);
			break;
		case SAMR_OPNUM_OPEN_DOMAIN:
			status = samr_open_domain_return(pipe);
			break;
		case SAMR_OPNUM_LOOKUP_NAMES:
			status = samr_lookup_names_return(pipe);
			break;
		case SAMR_OPNUM_OPEN_USER:
			status = samr_open_user_return(pipe);
			break;
		case SAMR_OPNUM_QUERY_USER_INFO:
			status = samr_query_user_info_return(pipe);
			break;
		case SAMR_OPNUM_QUERY_SECURITY:
			status = samr_query_security_return(pipe);
			break;
		case SAMR_OPNUM_GET_GROUP_FOR_USER:
			status = samr_get_group_for_user_return(pipe);
			break;
		case SAMR_OPNUM_GET_ALIAS_MEMBERSHIP:
			status = samr_get_alias_membership_return(pipe);
			break;
		case SAMR_OPNUM_CLOSE:
			status = samr_close_return(pipe);
			break;
		default:
			pr_err("SAMR: unsupported RETURN method %d\n",
				dce->req_hdr.opnum);
			status = KSMBD_RPC_EBAD_FUNC;
			break;
		}
	}

	if (status && status != KSMBD_RPC_EMORE_DATA &&
	    status != SAMR_STATUS_NONE_MAPPED &&
	    status != SAMR_STATUS_SOME_NOT_MAPPED &&
	    status != KSMBD_RPC_NONE_MAPPED &&
	    status != KSMBD_RPC_SOME_NOT_MAPPED) {
		dce->offset = payload_start;
		if (samr_write_error_payload(dce, dce->req_hdr.opnum))
			return KSMBD_RPC_EBAD_DATA;
	}

	wire_status = samr_wire_status(status);

	/*
	 * [out] DWORD Return value/code
	 */
	if (ndr_write_int32(dce, wire_status))
		return KSMBD_RPC_EBAD_DATA;

	ipc_status = samr_ipc_status(status);
	if (dcerpc_write_headers(dce, ipc_status))
		return KSMBD_RPC_EBAD_DATA;

	dce->rpc_resp->payload_sz = dce->offset;
	return ipc_status;
}

int rpc_samr_read_request(struct ksmbd_rpc_pipe *pipe,
			    struct ksmbd_rpc_command *resp,
			    int max_resp_sz)
{
	return samr_return(pipe, resp, max_resp_sz);
}

int rpc_samr_write_request(struct ksmbd_rpc_pipe *pipe)
{
	struct samr_info_request *req = &pipe->dce->sm_req;
	int ret;

	pipe->dce->request_cleanup = samr_request_cleanup;
	samr_free_names(req);
	memset(req, 0, sizeof(*req));
	ret = samr_invoke(pipe);
	req->operation_status = ret;
	return KSMBD_RPC_OK;
}

static void rpc_samr_add_domain_entry(char *name)
{
	g_ptr_array_add(domain_entries, g_strdup(name));
	num_domain_entries++;
}

void rpc_samr_init(void)
{
	if (!domain_name) {
		char hostname[NAME_MAX] = {0};

		/*
		 * ksmbd supports the standalone server and
		 * uses the hostname as the domain name.
		 */
		if (gethostname(hostname, sizeof(hostname) - 1))
			abort();

		domain_name = g_ascii_strup(hostname, -1);
	}

	if (!domain_entries) {
		domain_entries = g_ptr_array_new_with_free_func(g_free);
		rpc_samr_add_domain_entry(domain_name);
		rpc_samr_add_domain_entry("Builtin");
	}

	if (!ch_table)
		ch_table = g_hash_table_new(rpc_handle_hash, rpc_handle_equal);
}

static void samr_ch_retire(unsigned int pipe_id, int match_pipe)
{
	if (!ch_table)
		return;

	for (;;) {
		struct connect_handle *ch = NULL;
		GHashTableIter iter;
		int destroy = 0;

		g_rw_lock_writer_lock(&ch_table_lock);
		g_hash_table_iter_init(&iter, ch_table);
		while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&ch)) {
			if (match_pipe && ch->pipe_id != pipe_id) {
				ch = NULL;
				continue;
			}

			ch->retired = 1;
			g_hash_table_iter_remove(&iter);
			if (ch->refcount && !--ch->refcount)
				destroy = 1;
			break;
		}
		g_rw_lock_writer_unlock(&ch_table_lock);

		if (!ch)
			break;
		if (destroy)
			samr_ch_destroy(ch);
	}
}

void rpc_samr_pipe_close(unsigned int pipe_id)
{
	samr_ch_retire(pipe_id, 1);
}

void rpc_samr_destroy(void)
{
	if (ch_table) {
		samr_ch_retire(0, 0);
		g_hash_table_destroy(ch_table);
		ch_table = NULL;
	}

	if (domain_entries) {
		g_ptr_array_free(domain_entries, 1);
		domain_entries = NULL;
	}

	num_domain_entries = 0;

	g_free(domain_name);
	domain_name = NULL;
}
