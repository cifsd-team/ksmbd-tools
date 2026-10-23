// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2020 Samsung Electronics Co., Ltd.
 *
 *   Author(s): Namjae Jeon (linkinjeon@kernel.org)
 */

#include <memory.h>
#include <endian.h>
#include <glib.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <errno.h>
#include <linux/ksmbd_server.h>

#include <management/user.h>
#include <rpc.h>
#include <rpc_lsarpc.h>
#include <smbacl.h>
#include <tools.h>

#define LSARPC_OPNUM_DS_ROLE_GET_PRIMARY_DOMAIN_INFO	0
#define LSARPC_OPNUM_OPEN_POLICY			6
#define LSARPC_OPNUM_OPEN_POLICY2			44
#define LSARPC_OPNUM_QUERY_INFO_POLICY			7
#define LSARPC_OPNUM_LOOKUP_NAMES			14
#define LSARPC_OPNUM_LOOKUP_SID			15
#define LSARPC_OPNUM_LOOKUP_SID2			57
#define LSARPC_OPNUM_LOOKUP_NAMES3			68
#define LSARPC_OPNUM_CLOSE				0

#define DS_ROLE_STANDALONE_SERVER	2
#define DS_ROLE_BASIC_INFORMATION	1

#define LSA_POLICY_INFO_ACCOUNT_DOMAIN	5

#define LSARPC_INTERFACE_LSAD		1
#define LSARPC_INTERFACE_DSSETUP	2
#define LSARPC_MAX_SID_COUNT		20480
#define LSARPC_MAX_NAME_COUNT		1000
#define LSA_REF_DOMAIN_LIST_MULTIPLIER	32
#define LSA_POLICY_VIEW_LOCAL_INFORMATION	0x00000001
#define LSA_POLICY_VIEW_AUDIT_INFORMATION	0x00000002
#define LSA_POLICY_GET_PRIVATE_INFORMATION	0x00000004
#define LSA_POLICY_LOOKUP_NAMES		0x00000800
#define LSA_MAXIMUM_ALLOWED		0x02000000
#define LSA_POLICY_GENERIC_READ		0x80000000U
#define LSA_POLICY_GENERIC_WRITE		0x40000000U
#define LSA_POLICY_GENERIC_EXECUTE	0x20000000U
#define LSA_POLICY_GENERIC_ALL		0x10000000U
#define LSA_POLICY_READ_ACCESS		(0x00020000 | \
					 LSA_POLICY_VIEW_LOCAL_INFORMATION | \
					 LSA_POLICY_VIEW_AUDIT_INFORMATION | \
					 LSA_POLICY_GET_PRIVATE_INFORMATION)
#define LSA_POLICY_WRITE_ACCESS		(0x00020000 | \
					 0x00000008 | 0x00000010 | \
					 0x00000020 | 0x00000040 | \
					 0x00000080 | 0x00000100 | \
					 0x00000200 | 0x00000400)
#define LSA_POLICY_EXECUTE_ACCESS	(0x00020000 | \
					 LSA_POLICY_VIEW_LOCAL_INFORMATION | \
					 LSA_POLICY_LOOKUP_NAMES)
#define LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES		0x00000000U
#define LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES_LOCAL	0x80000000U
#define LSA_CLIENT_REVISION_1				0x00000001U
#define LSA_CLIENT_REVISION_2				0x00000002U

#define LSARPC_STATUS_INVALID_HANDLE	(-2001)
#define LSARPC_STATUS_INVALID_PARAMETER	(-2002)
#define LSARPC_STATUS_INVALID_INFO_CLASS	(-2003)
#define LSARPC_STATUS_NONE_MAPPED		(-2004)
#define LSARPC_STATUS_SOME_NOT_MAPPED	(-2005)

static GHashTable	*ph_table;
static GRWLock		ph_table_lock;
static gchar		*domain_name;

static void lsarpc_request_cleanup(struct ksmbd_rpc_pipe *pipe);

static void lsarpc_ph_destroy(struct policy_handle *ph)
{
	struct ksmbd_user *user;

	if (!ph)
		return;

	user = ph->user;
	ph->user = NULL;
	put_ksmbd_user(user);
	g_free(ph);
}

static void lsarpc_ph_put(struct policy_handle *ph)
{
	int destroy = 0;

	if (!ph)
		return;

	g_rw_lock_writer_lock(&ph_table_lock);
	if (ph->refcount && !--ph->refcount)
		destroy = 1;
	g_rw_lock_writer_unlock(&ph_table_lock);

	if (destroy)
		lsarpc_ph_destroy(ph);
}

static struct policy_handle *lsarpc_ph_lookup(struct ksmbd_rpc_pipe *pipe,
					      const unsigned char *handle)
{
	struct policy_handle *ph;

	if (!pipe || !handle)
		return NULL;
	g_rw_lock_writer_lock(&ph_table_lock);
	ph = g_hash_table_lookup(ph_table, handle);
	if (ph && !ph->retired && ph->pipe_id == pipe->id)
		ph->refcount++;
	else
		ph = NULL;
	g_rw_lock_writer_unlock(&ph_table_lock);

	return ph;
}

static int lsarpc_ph_close(struct ksmbd_rpc_pipe *pipe,
			   const unsigned char *handle)
{
	struct policy_handle *ph;
	int destroy = 0;

	if (!pipe || !handle)
		return LSARPC_STATUS_INVALID_HANDLE;

	g_rw_lock_writer_lock(&ph_table_lock);
	ph = g_hash_table_lookup(ph_table, handle);
	if (!ph || ph->retired || ph->pipe_id != pipe->id) {
		g_rw_lock_writer_unlock(&ph_table_lock);
		return LSARPC_STATUS_INVALID_HANDLE;
	}
	ph->retired = 1;
	g_hash_table_remove(ph_table, &(ph->handle));
	if (ph->refcount && !--ph->refcount)
		destroy = 1;
	g_rw_lock_writer_unlock(&ph_table_lock);

	if (destroy)
		lsarpc_ph_destroy(ph);
	return KSMBD_RPC_OK;
}

static struct policy_handle *lsarpc_ph_alloc(struct ksmbd_rpc_pipe *pipe,
					     unsigned int access_mask)
{
	struct policy_handle *ph;

	ph = g_try_malloc0(sizeof(struct policy_handle));
	if (!ph)
		return NULL;

	if (rpc_handle_generate(ph->handle, sizeof(ph->handle), pipe->id)) {
		g_free(ph);
		return NULL;
	}
	ph->pipe_id = pipe->id;
	ph->refcount = 1;
	ph->type = LSARPC_HANDLE_POLICY;
	ph->access_mask = access_mask;
	ph->retired = 0;
	g_rw_lock_writer_lock(&ph_table_lock);
	if (g_hash_table_lookup(ph_table, ph->handle)) {
		g_rw_lock_writer_unlock(&ph_table_lock);
		g_free(ph);
		return NULL;
	}
	g_hash_table_insert(ph_table, &(ph->handle), ph);
	g_rw_lock_writer_unlock(&ph_table_lock);

	return ph;
}

static int lsarpc_syntax_interface(struct ksmbd_rpc_pipe *pipe,
				   __u16 context_id)
{
	const struct dcerpc_syntax *syntax;

	syntax = rpc_pipe_context_syntax(pipe, context_id);
	if (!syntax)
		return 0;

	if (syntax->uuid.time_low == 0x3919286a &&
	    syntax->uuid.time_mid == 0xb10c &&
	    syntax->uuid.time_hi_and_version == 0x11d0 &&
	    syntax->uuid.clock_seq[0] == 0x9b &&
	    syntax->uuid.clock_seq[1] == 0xa8 &&
	    !memcmp(syntax->uuid.node,
		    (const unsigned char[]){0x00, 0xc0, 0x4f, 0xd9, 0x2e, 0xf5},
		    6) &&
	    syntax->ver_major == 0 &&
	    syntax->ver_minor == 0)
		return LSARPC_INTERFACE_DSSETUP;

	if (syntax->uuid.time_low == 0x12345778 &&
	    syntax->uuid.time_mid == 0x1234 &&
	    syntax->uuid.time_hi_and_version == 0xabcd &&
	    syntax->uuid.clock_seq[0] == 0xef &&
	    syntax->uuid.clock_seq[1] == 0x00 &&
	    syntax->uuid.node[0] == 0x01 &&
	    syntax->uuid.node[1] == 0x23 &&
	    syntax->uuid.node[2] == 0x45 &&
	    syntax->uuid.node[3] == 0x67 &&
	    syntax->uuid.node[4] == 0x89 &&
	    syntax->uuid.node[5] == 0xab &&
	    syntax->ver_major == 0 &&
	    syntax->ver_minor == 0)
		return LSARPC_INTERFACE_LSAD;

	return -1;
}

static int lsarpc_policy_access(const struct policy_handle *ph,
				unsigned int required)
{
	unsigned int access;

	if (!ph)
		return LSARPC_STATUS_INVALID_HANDLE;

	access = ph->access_mask;
	if ((access & required) == required ||
	    (access & LSA_POLICY_GENERIC_ALL) ||
	    (access & LSA_MAXIMUM_ALLOWED))
		return KSMBD_RPC_OK;

	if ((access & LSA_POLICY_GENERIC_READ) &&
	    (LSA_POLICY_READ_ACCESS & required) == required)
		return KSMBD_RPC_OK;

	if ((access & LSA_POLICY_GENERIC_WRITE) &&
	    (LSA_POLICY_WRITE_ACCESS & required) == required)
		return KSMBD_RPC_OK;

	if ((access & LSA_POLICY_GENERIC_EXECUTE) &&
	    (LSA_POLICY_EXECUTE_ACCESS & required) == required)
		return KSMBD_RPC_OK;

	return KSMBD_RPC_EACCESS_DENIED;
}

static __u32 lsarpc_wire_status(int status, int interface_kind)
{
	if (interface_kind == LSARPC_INTERFACE_DSSETUP) {
		switch (status) {
		case KSMBD_RPC_OK:
			return 0;
		case KSMBD_RPC_EBAD_FID:
			return 6; /* ERROR_INVALID_HANDLE */
		case KSMBD_RPC_EACCESS_DENIED:
			return 5; /* ERROR_ACCESS_DENIED */
		case KSMBD_RPC_EINVALID_PARAMETER:
		case KSMBD_RPC_EBAD_DATA:
			return 0x57; /* ERROR_INVALID_PARAMETER */
		case KSMBD_RPC_ENOMEM:
			return 8; /* ERROR_NOT_ENOUGH_MEMORY */
		case KSMBD_RPC_ENOTIMPLEMENTED:
			return 50; /* ERROR_NOT_SUPPORTED */
		default:
			return status < 0 ? 0x57 : status;
		}
	}

	switch (status) {
	case KSMBD_RPC_OK:
		return KSMBD_NT_STATUS_SUCCESS;
	case LSARPC_STATUS_INVALID_HANDLE:
		return KSMBD_NT_STATUS_INVALID_HANDLE;
	case LSARPC_STATUS_INVALID_PARAMETER:
		return KSMBD_NT_STATUS_INVALID_PARAMETER;
	case LSARPC_STATUS_INVALID_INFO_CLASS:
		return KSMBD_NT_STATUS_INVALID_INFO_CLASS;
	case LSARPC_STATUS_NONE_MAPPED:
	case KSMBD_RPC_NONE_MAPPED:
		return KSMBD_NT_STATUS_NONE_MAPPED;
	case LSARPC_STATUS_SOME_NOT_MAPPED:
	case KSMBD_RPC_SOME_NOT_MAPPED:
		return KSMBD_NT_STATUS_SOME_NOT_MAPPED;
	case KSMBD_RPC_EACCESS_DENIED:
		return KSMBD_NT_STATUS_ACCESS_DENIED;
	case KSMBD_RPC_EBAD_FID:
		return KSMBD_NT_STATUS_INVALID_HANDLE;
	case KSMBD_RPC_EINVALID_PARAMETER:
	case KSMBD_RPC_EBAD_DATA:
		return KSMBD_NT_STATUS_INVALID_PARAMETER;
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

static int lsarpc_write_zero_handle(struct ksmbd_dcerpc *dce)
{
	unsigned char handle[HANDLE_SIZE] = {0};

	return ndr_write_bytes(dce, handle, sizeof(handle));
}

static int lsarpc_write_error_payload(struct ksmbd_dcerpc *dce,
				      unsigned int opnum,
				      int interface_kind)
{
	if (opnum == LSARPC_OPNUM_DS_ROLE_GET_PRIMARY_DOMAIN_INFO &&
	    interface_kind == LSARPC_INTERFACE_DSSETUP)
		return ndr_write_int32(dce, 0) ? KSMBD_RPC_EBAD_DATA :
						 KSMBD_RPC_OK;

	switch (opnum) {
	case LSARPC_OPNUM_OPEN_POLICY:
	case LSARPC_OPNUM_OPEN_POLICY2:
	case LSARPC_OPNUM_CLOSE:
		return lsarpc_write_zero_handle(dce) ? KSMBD_RPC_EBAD_DATA :
					      KSMBD_RPC_OK;
	case LSARPC_OPNUM_QUERY_INFO_POLICY:
		return ndr_write_int32(dce, 0) ? KSMBD_RPC_EBAD_DATA :
					 KSMBD_RPC_OK;
	case LSARPC_OPNUM_LOOKUP_NAMES:
	case LSARPC_OPNUM_LOOKUP_SID:
	case LSARPC_OPNUM_LOOKUP_SID2:
	case LSARPC_OPNUM_LOOKUP_NAMES3:
		if (ndr_write_int32(dce, 0) ||
		    ndr_write_int32(dce, 0) ||
		    ndr_write_int32(dce, 0) ||
		    ndr_write_int32(dce, 0))
			return KSMBD_RPC_EBAD_DATA;
		return KSMBD_RPC_OK;
	default:
		return KSMBD_RPC_OK;
	}
}

static int lsa_domain_account_rep(struct ksmbd_dcerpc *dce,
				  const char *domain_name)
{
	int ret;

	ret = ndr_write_lsa_string_rep(dce, domain_name);
	if (ret)
		return ret;
	dce->num_pointers++;
	return ndr_write_int32(dce, dce->num_pointers);
}

static int lsa_domain_account_data(struct ksmbd_dcerpc *dce,
		const char *domain_name,
		struct smb_sid *sid)
{
	int ret;

	ret = ndr_write_lsa_string(dce, domain_name); // domain string
	if (ret)
		return ret;

	ret = ndr_write_int32(dce, sid->num_subauth); // count
	if (ret)
		return ret;

	ret = smb_write_sid(dce, sid); // sid

	return ret;
}

static int lsarpc_get_primary_domain_info_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int interface_kind;
	__u16 val;

	interface_kind = lsarpc_syntax_interface(pipe, dce->req_hdr.context_id);
	if (interface_kind != LSARPC_INTERFACE_DSSETUP)
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (ndr_read_int16(dce, &val))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (val != DS_ROLE_BASIC_INFORMATION)
		return KSMBD_RPC_EINVALID_PARAMETER;

	dce->lr_req.interface_kind = interface_kind;
	dce->lr_req.level = val;

	return ndr_request_end(dce) ? KSMBD_RPC_EINVALID_PARAMETER :
				      KSMBD_RPC_OK;
}

static int lsarpc_get_primary_domain_info_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int i;

	if (dce->lr_req.level != DS_ROLE_BASIC_INFORMATION)
		return KSMBD_RPC_EINVALID_LEVEL;

	dce->num_pointers++;
	if (ndr_write_int32(dce, dce->num_pointers)) // ref pointer
		return KSMBD_RPC_EBAD_DATA;

	if (ndr_write_int16(dce, DS_ROLE_BASIC_INFORMATION) ||
	    ndr_write_int16(dce, 0))
		return KSMBD_RPC_EBAD_DATA;

	if (ndr_write_int16(dce, DS_ROLE_STANDALONE_SERVER) ||
	    ndr_write_int16(dce, 0)) // role
		return KSMBD_RPC_EBAD_DATA;

	if (ndr_write_int32(dce, 0)) // flags
		return KSMBD_RPC_EBAD_DATA;

	dce->num_pointers++;
	if (ndr_write_int32(dce, dce->num_pointers)) // ref pointer
		return KSMBD_RPC_EBAD_DATA;

	if (ndr_write_int32(dce, 0)) // NULL pointer : Pointer to Dns Domain
		return KSMBD_RPC_EBAD_DATA;

	if (ndr_write_int32(dce, 0)) // NULL pointer : Pointer to Forest
		return KSMBD_RPC_EBAD_DATA;


	/* NULL Domain guid */
	for (i = 0; i < 16; i++) {
		if (ndr_write_int8(dce, 0))
			return KSMBD_RPC_EBAD_DATA;
	}

	if (ndr_write_vstring(dce, domain_name)) // domain string
		return KSMBD_RPC_EBAD_DATA;

	return KSMBD_RPC_OK;
}

static int lsarpc_skip_bytes(struct ksmbd_dcerpc *dce, size_t count)
{
	if (dce->offset > dce->payload_sz ||
	    count > dce->payload_sz - dce->offset)
		return -EINVAL;
	dce->offset += count;
	return 0;
}

static int lsarpc_read_attribute_name(struct ksmbd_dcerpc *dce)
{
	__u16 length, size;
	__u32 ref, max_count, offset, actual;

	/* ObjectName points to an ANSI STRING, as defined by MS-LSAD. */
	if (ndr_read_int16(dce, &length) || ndr_read_int16(dce, &size) ||
	    ndr_read_int32(dce, &ref) || length > size)
		return -EINVAL;
	if (!ref)
		return length ? -EINVAL : 0;
	if (ndr_read_int32(dce, &max_count) ||
	    ndr_read_int32(dce, &offset) ||
	    ndr_read_int32(dce, &actual) ||
	    max_count != size || offset || actual != length)
		return -EINVAL;
	return lsarpc_skip_bytes(dce, actual);
}

static int lsarpc_read_attribute_acl(struct ksmbd_dcerpc *dce)
{
	__u32 count;
	__u16 size;

	if (ndr_read_int32(dce, &count) ||
	    ndr_read_int8(dce, NULL) || ndr_read_int8(dce, NULL) ||
	    ndr_read_int16(dce, &size) || size < 4 || count != size - 4)
		return -EINVAL;
	return lsarpc_skip_bytes(dce, count);
}

static int lsarpc_read_attribute_security(struct ksmbd_dcerpc *dce)
{
	__u32 refs[4];
	unsigned int i;

	auto_align_offset(dce);
	if (ndr_read_int8(dce, NULL) || ndr_read_int8(dce, NULL) ||
	    ndr_read_int16(dce, NULL))
		return -EINVAL;
	for (i = 0; i < G_N_ELEMENTS(refs); i++) {
		if (ndr_read_int32(dce, &refs[i]))
			return -EINVAL;
	}
	for (i = 0; i < 2; i++) {
		struct smb_sid sid;
		__u32 count;

		if (!refs[i])
			continue;
		if (ndr_read_int32(dce, &count) || smb_read_sid(dce, &sid) ||
		    count != sid.num_subauth)
			return -EINVAL;
	}
	for (; i < G_N_ELEMENTS(refs); i++) {
		if (refs[i] && lsarpc_read_attribute_acl(dce))
			return -EINVAL;
	}
	return 0;
}

static int lsarpc_read_policy_attributes(struct ksmbd_dcerpc *dce,
					 __u32 *desired_access)
{
	__u32 attributes_length, root_ref, object_ref;
	__u32 attributes, security_ref, qos_ref;

	if (ndr_read_int32(dce, &attributes_length) ||
	    ndr_read_int32(dce, &root_ref) ||
	    ndr_read_int32(dce, &object_ref) ||
	    ndr_read_int32(dce, &attributes) ||
	    ndr_read_int32(dce, &security_ref) ||
	    ndr_read_int32(dce, &qos_ref))
		return -EINVAL;
	/* MS-LSAD uses only RootDirectory, which must be NULL. */
	if (root_ref)
		return -EINVAL;
	if (object_ref && lsarpc_read_attribute_name(dce))
		return -EINVAL;
	if (security_ref && lsarpc_read_attribute_security(dce))
		return -EINVAL;
	if (qos_ref && (ndr_read_int32(dce, NULL) ||
		       ndr_read_int16(dce, NULL) ||
		       ndr_read_int8(dce, NULL) || ndr_read_int8(dce, NULL)))
		return -EINVAL;
	if (ndr_read_int32(dce, desired_access))
		return -EINVAL;
	return 0;
}

static int lsarpc_open_policy_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	__u32 system_ref, desired_access;

	if (lsarpc_syntax_interface(pipe, dce->req_hdr.context_id) !=
	    LSARPC_INTERFACE_LSAD)
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (ndr_read_int32(dce, &system_ref))
		return KSMBD_RPC_EINVALID_PARAMETER;
	/*
	 * The original procedure has a pointer to one UTF-16 code unit,
	 * not a counted string.  Consume that scalar before the following
	 * OBJECT_ATTRIBUTES fields are aligned and decoded.
	 */
	if (system_ref && ndr_read_int16(dce, NULL))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (lsarpc_read_policy_attributes(dce, &desired_access) ||
	    ndr_request_end(dce))
		return KSMBD_RPC_EINVALID_PARAMETER;

	dce->lr_req.access_mask = desired_access;
	dce->lr_req.interface_kind = LSARPC_INTERFACE_LSAD;
	return KSMBD_RPC_OK;
}

static int lsarpc_open_policy2_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	__u32 system_ref, desired_access;
	char *system_name = NULL;

	if (lsarpc_syntax_interface(pipe, dce->req_hdr.context_id) !=
	    LSARPC_INTERFACE_LSAD)
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (ndr_read_int32(dce, &system_ref))
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (system_ref) {
		system_name = ndr_read_vstring_compat(dce);
		if (!system_name)
			return KSMBD_RPC_EINVALID_PARAMETER;
	}
	if (lsarpc_read_policy_attributes(dce, &desired_access) ||
	    ndr_request_end(dce))
		goto fail;

	/* MS-LSAD requires SystemName to be ignored after unmarshalling. */
	dce->lr_req.access_mask = desired_access;
	dce->lr_req.interface_kind = LSARPC_INTERFACE_LSAD;

	g_free(system_name);
	return KSMBD_RPC_OK;
fail:
	g_free(system_name);
	return KSMBD_RPC_EINVALID_PARAMETER;
}

static int lsarpc_open_policy2_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct policy_handle *ph;

	ph = lsarpc_ph_alloc(pipe, dce->lr_req.access_mask);
	if (!ph) {
		if (lsarpc_write_zero_handle(dce))
			return KSMBD_RPC_EBAD_DATA;
		return KSMBD_RPC_ENOMEM;
	}

	/* write connect handle */
	if (ndr_write_bytes(dce, ph->handle, HANDLE_SIZE)) {
		lsarpc_ph_close(pipe, ph->handle);
		return KSMBD_RPC_EBAD_DATA;
	}

	return KSMBD_RPC_OK;
}

static int lsarpc_query_info_policy_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	__u16 val;

	if (lsarpc_syntax_interface(pipe, dce->req_hdr.context_id) !=
	    LSARPC_INTERFACE_LSAD)
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (ndr_read_bytes(dce, dce->lr_req.handle, HANDLE_SIZE))
		return KSMBD_RPC_EINVALID_PARAMETER;
	// level
	if (ndr_read_int16(dce, &val))
		return KSMBD_RPC_EINVALID_PARAMETER;

	dce->lr_req.level = val;
	dce->lr_req.interface_kind = LSARPC_INTERFACE_LSAD;

	return ndr_request_end(dce) ? KSMBD_RPC_EINVALID_PARAMETER :
				      KSMBD_RPC_OK;
}

static int lsarpc_query_info_policy_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct smb_sid sid;
	struct policy_handle *ph = NULL;
	int ret = KSMBD_RPC_OK;

	ph = lsarpc_ph_lookup(pipe, dce->lr_req.handle);
	if (!ph || ph->type != LSARPC_HANDLE_POLICY) {
		ret = LSARPC_STATUS_INVALID_HANDLE;
		goto empty;
	}
	ret = lsarpc_policy_access(ph, LSA_POLICY_VIEW_LOCAL_INFORMATION);
	if (ret) {
		goto empty_with_handle;
	}

	if (dce->lr_req.level != LSA_POLICY_INFO_ACCOUNT_DOMAIN) {
		ret = LSARPC_STATUS_INVALID_INFO_CLASS;
		goto empty_with_handle;
	}

	dce->num_pointers++;
	// ref pointer
	if (ndr_write_int32(dce, dce->num_pointers))
		ret = KSMBD_RPC_EBAD_DATA;

	// level
	if (!ret && ndr_write_int16(dce, LSA_POLICY_INFO_ACCOUNT_DOMAIN))
		ret = KSMBD_RPC_EBAD_DATA;

	if (!ret && ndr_write_int16(dce, 0))
		ret = KSMBD_RPC_EBAD_DATA;

	/* Domain, Sid ref pointer */
	if (!ret && lsa_domain_account_rep(dce, domain_name))
		ret = KSMBD_RPC_EBAD_DATA;

	/* Pointer to domain, Sid */
	smb_init_domain_sid(&sid);
	if (!ret && lsa_domain_account_data(dce, domain_name, &sid))
		ret = KSMBD_RPC_EBAD_DATA;

	if (ph)
		lsarpc_ph_put(ph);
	return ret;

empty_with_handle:
	lsarpc_ph_put(ph);
empty:
	if (ndr_write_int32(dce, 0))
		return KSMBD_RPC_EBAD_DATA;
	return ret;
}

static void lsarpc_name_info_free(struct lsarpc_names_info *ni)
{
	if (!ni)
		return;
	put_ksmbd_user(ni->user);
	g_free(ni->resolved_name);
	g_free(ni);
}

static int __lsarpc_entry_processed(struct ksmbd_rpc_pipe *pipe, int i)
{
	struct lsarpc_names_info *ni;

	if (!pipe || !pipe->entries || i < 0 ||
	    i >= pipe->entries->len || pipe->num_entries <= 0)
		return -EINVAL;
	ni = g_ptr_array_remove_index(pipe->entries, i);
	pipe->num_entries--;
	pipe->num_processed++;
	lsarpc_name_info_free(ni);
	return 0;
}

static void lsarpc_request_cleanup(struct ksmbd_rpc_pipe *pipe)
{
	struct lsarpc_names_info *ni;

	if (!pipe || !pipe->entries)
		return;

	while (pipe->entries->len) {
		ni = g_ptr_array_remove_index(pipe->entries, pipe->entries->len - 1);
		lsarpc_name_info_free(ni);
	}
	pipe->num_entries = 0;
	pipe->num_processed = 0;
	pipe->entry_processed = NULL;
}

static void lsarpc_init_unix_domain_sid(struct smb_sid *sid, __u32 rid)
{
	memset(sid, 0, sizeof(*sid));
	sid->revision = 1;
	sid->num_subauth = 1;
	sid->authority[5] = 22;
	sid->sub_auth[0] = rid;
}

static int lsarpc_lookup_group(const char *name, __u32 *gid, char **resolved)
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
		if (ret || !result)
			return ret ? -ret : -ENOENT;
		*gid = result->gr_gid;
		*resolved = g_strdup(result->gr_name);
		return *resolved ? 0 : -ENOMEM;
	}
}

static int lsarpc_resolve_sid(struct lsarpc_names_info *ni)
{
	int ret;
	__u32 rid;

	ni->index = -1;
	ni->type = SID_TYPE_UNKNOWN;
	ni->mapped = 0;
	ret = set_domain_name(&ni->sid, ni->domain_str,
			      sizeof(ni->domain_str), &ni->type);
	if (ret && ret != -ENOENT)
		return ret;
	if (ret == -ENOENT)
		return 0;

	switch (ni->type) {
	case SID_TYPE_DOMAIN:
		smb_copy_sid(&ni->domain_sid, &ni->sid);
		ni->resolved_name = g_strdup(ni->domain_str);
		break;
	case SID_TYPE_USER:
		if (!ni->sid.num_subauth)
			return 0;
		rid = ni->sid.sub_auth[ni->sid.num_subauth - 1];
		if (!g_ascii_strcasecmp(ni->domain_str, "Unix User")) {
			lsarpc_init_unix_domain_sid(&ni->domain_sid, 1);
		} else {
			smb_copy_sid(&ni->domain_sid, &ni->sid);
			ni->domain_sid.num_subauth--;
		}
		ni->user = usm_lookup_uid(rid);
		if (ni->user)
			ni->resolved_name = g_strdup(ni->user->name);
		break;
	case SID_TYPE_GROUP:
		if (!ni->sid.num_subauth)
			return 0;
		rid = ni->sid.sub_auth[ni->sid.num_subauth - 1];
		lsarpc_init_unix_domain_sid(&ni->domain_sid, 2);
		ret = lsarpc_lookup_group(NULL, &rid, &ni->resolved_name);
		if (ret == -ENOMEM)
			return ret;
		break;
	default:
		return 0;
	}

	if (!ni->resolved_name)
		return 0;
	ni->mapped = 1;
	return 0;
}

static int lsarpc_extract_account_name(const char *input, char **name,
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
		*type = SID_TYPE_GROUP;
	} else if ((prefix_len != strlen(domain_name) ||
		    g_ascii_strncasecmp(input, domain_name, prefix_len)) &&
		   (!global_conf.netbios_name ||
		    prefix_len != strlen(global_conf.netbios_name) ||
		    g_ascii_strncasecmp(input, global_conf.netbios_name, prefix_len))) {
		return -ENOENT;
	} else {
		*type = SID_TYPE_USER;
	}

	*name = g_strdup(separator + 1);
	return *name ? 0 : -ENOMEM;
}

static int lsarpc_resolve_name(struct lsarpc_names_info *ni, const char *input)
{
	g_autofree char *name = NULL;
	__u32 rid = 0;
	int type, ret;

	ret = lsarpc_extract_account_name(input, &name, &type);
	if (ret)
		return ret;
	if (type != SID_TYPE_GROUP)
		ni->user = usm_lookup_user_casefold(name);
	if (ni->user) {
		smb_init_domain_sid(&ni->domain_sid);
		rid = ni->user->uid;
		g_strlcpy(ni->domain_str, domain_name, sizeof(ni->domain_str));
		ni->type = SID_TYPE_USER;
		ni->resolved_name = g_strdup(ni->user->name);
	} else if (type != SID_TYPE_USER) {
		ret = lsarpc_lookup_group(name, &rid, &ni->resolved_name);
		if (ret)
			return ret;
		smb_init_unix_group_sid(&ni->domain_sid);
		g_strlcpy(ni->domain_str, SMB_UNIX_GROUP_DOMAIN,
			  sizeof(ni->domain_str));
		ni->type = SID_TYPE_GROUP;
	}
	if (!ni->resolved_name)
		return ni->user ? -ENOMEM : 0;
	smb_copy_sid(&ni->sid, &ni->domain_sid);
	ni->sid.sub_auth[ni->sid.num_subauth++] = rid;
	ni->mapped = 1;
	return 0;
}

static int lsarpc_sid_relative_id(const struct lsarpc_names_info *ni, __u32 *rid)
{
	unsigned int i;

	if (!ni || !rid || !ni->mapped)
		return -EINVAL;
	if (ni->sid.revision != ni->domain_sid.revision)
		return -EINVAL;
	if (memcmp(ni->sid.authority, ni->domain_sid.authority,
		   sizeof(ni->sid.authority)))
		return -EINVAL;
	if (ni->sid.num_subauth != ni->domain_sid.num_subauth + 1)
		return -EINVAL;
	for (i = 0; i < ni->domain_sid.num_subauth; i++) {
		if (ni->sid.sub_auth[i] != ni->domain_sid.sub_auth[i])
			return -EINVAL;
	}

	*rid = ni->sid.sub_auth[ni->sid.num_subauth - 1];
	return 0;
}

/* These in/out translations are unmarshalled for wire safety, then ignored. */
static int lsarpc_read_translations(struct ksmbd_dcerpc *dce,
				    int names, int extended)
{
	struct ignored_translation {
		struct ndr_string_rep name;
		__u32 sid_ref;
	};
	g_autofree struct ignored_translation *items = NULL;
	__u32 count, ref, max_count, unused;
	unsigned int i;
	__u16 use;

	if (ndr_read_int32(dce, &count) || ndr_read_int32(dce, &ref) ||
	    count > (names ? LSARPC_MAX_NAME_COUNT : LSARPC_MAX_SID_COUNT) ||
	    (count && !ref))
		return -EINVAL;
	if (!ref)
		return 0;
	if (ndr_read_int32(dce, &max_count) || max_count != count)
		return -EINVAL;
	if (count) {
		items = g_try_new0(struct ignored_translation, count);
		if (!items)
			return -ENOMEM;
	}
	for (i = 0; i < count; i++) {
		if (ndr_read_int16(dce, &use))
			return -EINVAL;
		auto_align_offset(dce);
		if (names) {
			if (ndr_read_int32(dce, &items[i].sid_ref))
				return -EINVAL;
		} else if (ndr_read_string_rep(dce, &items[i].name)) {
			return -EINVAL;
		}
		if (ndr_read_int32(dce, &unused) ||
		    (extended && ndr_read_int32(dce, &unused)))
			return -EINVAL;
	}
	for (i = 0; i < count; i++) {
		if (!names && items[i].name.ref_id) {
			g_autofree char *value = ndr_read_string_data(dce, &items[i].name);

			if (!value)
				return -EINVAL;
		} else if (names && extended && items[i].sid_ref) {
			struct smb_sid sid;

			if (ndr_read_int32(dce, &max_count) ||
			    max_count > SID_MAX_SUB_AUTHORITIES ||
			    smb_read_sid(dce, &sid) || max_count != sid.num_subauth)
				return -EINVAL;
		}
	}
	return 0;
}

static int lsarpc_read_lookup_tail(struct ksmbd_dcerpc *dce,
				   int names, int extended)
{
	__u16 level;
	__u32 ignored_mapped_count;

	if (lsarpc_read_translations(dce, names, extended) ||
	    ndr_read_int16(dce, &level) ||
	    ndr_read_int32(dce, &ignored_mapped_count))
		return -EINVAL;
	dce->lr_req.lookup_count = 0;
	dce->lr_req.lookup_options = 0;
	dce->lr_req.client_revision = 0;
	if (extended &&
	    (ndr_read_int32(dce, &dce->lr_req.lookup_options) ||
	     ndr_read_int32(dce, &dce->lr_req.client_revision)))
		return -EINVAL;
	if (level < 1 || level > 7)
		return -EINVAL;
	if (dce->lr_req.lookup_options !=
		    LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES &&
	    dce->lr_req.lookup_options !=
		    LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES_LOCAL)
		return -EINVAL;
	if (dce->lr_req.client_revision != 0 &&
	    dce->lr_req.client_revision != LSA_CLIENT_REVISION_1 &&
	    dce->lr_req.client_revision != LSA_CLIENT_REVISION_2)
		return -EINVAL;
	dce->lr_req.level = level;
	return ndr_request_end(dce);
}

static int lsarpc_lookup_sid2_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct lsarpc_names_info *ni = NULL;
	__u32 num_sid, array_ref, max_count;
	unsigned int i;

	if (lsarpc_syntax_interface(pipe, dce->req_hdr.context_id) !=
	    LSARPC_INTERFACE_LSAD)
		goto fail;
	if (ndr_read_bytes(dce, dce->lr_req.handle, HANDLE_SIZE))
		goto fail;

	if (ndr_read_int32(dce, &num_sid))
		goto fail;
	if (num_sid > LSARPC_MAX_SID_COUNT)
		goto fail;
	if (ndr_read_int32(dce, &array_ref))
		goto fail;
	if (num_sid && !array_ref)
		goto fail;
	if (array_ref) {
		if (ndr_read_int32(dce, &max_count) ||
		    max_count < num_sid)
			goto fail;
	} else if (num_sid) {
		goto fail;
	}

	for (i = 0; i < num_sid; i++) {
		__u32 sid_ref;

		if (ndr_read_int32(dce, &sid_ref) || !sid_ref)
			goto fail;
	}

	for (i = 0; i < num_sid; i++) {
		__u32 sid_max_count;

		ni = g_try_malloc0(sizeof(struct lsarpc_names_info));
		if (!ni)
			goto fail;

		if (ndr_read_int32(dce, &sid_max_count) ||
		    sid_max_count > SID_MAX_SUB_AUTHORITIES)
			goto fail;
		if (smb_read_sid(dce, &ni->sid))
			goto fail;
		if (sid_max_count < ni->sid.num_subauth ||
		    lsarpc_resolve_sid(ni))
			goto fail;

		g_ptr_array_add(pipe->entries, ni);
		ni = NULL;
		pipe->num_entries++;
	}

	if (lsarpc_read_lookup_tail(dce, 0, 1))
		goto fail;
	pipe->entry_processed = __lsarpc_entry_processed;
	return KSMBD_RPC_OK;
fail:
	lsarpc_name_info_free(ni);
	if (pipe->entry_processed)
		rpc_pipe_reset(pipe);
	else {
		while (pipe->entries->len) {
			ni = g_ptr_array_remove_index(pipe->entries, pipe->entries->len - 1);
			lsarpc_name_info_free(ni);
		}
		pipe->num_entries = 0;
	}
	return KSMBD_RPC_EINVALID_PARAMETER;
}

static int lsarpc_lookup_sid_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct lsarpc_names_info *ni = NULL;
	__u32 num_sid, array_ref, max_count;
	unsigned int i;

	if (lsarpc_syntax_interface(pipe, dce->req_hdr.context_id) !=
	    LSARPC_INTERFACE_LSAD)
		goto fail;
	if (ndr_read_bytes(dce, dce->lr_req.handle, HANDLE_SIZE))
		goto fail;

	if (ndr_read_int32(dce, &num_sid))
		goto fail;
	if (num_sid > LSARPC_MAX_SID_COUNT)
		goto fail;
	if (ndr_read_int32(dce, &array_ref))
		goto fail;
	if (num_sid && !array_ref)
		goto fail;
	if (array_ref) {
		if (ndr_read_int32(dce, &max_count) ||
		    max_count < num_sid)
			goto fail;
	} else if (num_sid) {
		goto fail;
	}

	for (i = 0; i < num_sid; i++) {
		__u32 sid_ref;

		if (ndr_read_int32(dce, &sid_ref) || !sid_ref)
			goto fail;
	}

	for (i = 0; i < num_sid; i++) {
		__u32 sid_max_count;

		ni = g_try_malloc0(sizeof(struct lsarpc_names_info));
		if (!ni)
			goto fail;

		if (ndr_read_int32(dce, &sid_max_count) ||
		    sid_max_count > SID_MAX_SUB_AUTHORITIES)
			goto fail;
		if (smb_read_sid(dce, &ni->sid))
			goto fail;
		if (sid_max_count < ni->sid.num_subauth ||
		    lsarpc_resolve_sid(ni))
			goto fail;

		g_ptr_array_add(pipe->entries, ni);
		ni = NULL;
		pipe->num_entries++;
	}

	if (lsarpc_read_lookup_tail(dce, 0, 0))
		goto fail;
	pipe->entry_processed = __lsarpc_entry_processed;
	return KSMBD_RPC_OK;
fail:
	lsarpc_name_info_free(ni);
	if (pipe->entry_processed)
		rpc_pipe_reset(pipe);
	else {
		while (pipe->entries->len) {
			ni = g_ptr_array_remove_index(pipe->entries, pipe->entries->len - 1);
			lsarpc_name_info_free(ni);
		}
		pipe->num_entries = 0;
	}
	return KSMBD_RPC_EINVALID_PARAMETER;
}

static int lsarpc_lookup_sid2_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct policy_handle *ph;
	GPtrArray *domains;
	unsigned int i, j, mapped = 0;
	int rc = KSMBD_RPC_OK;

	ph = lsarpc_ph_lookup(pipe, dce->lr_req.handle);
	if (!ph || ph->type != LSARPC_HANDLE_POLICY) {
		rc = LSARPC_STATUS_INVALID_HANDLE;
		goto empty;
	}
	rc = lsarpc_policy_access(ph, LSA_POLICY_LOOKUP_NAMES);
	if (rc) {
		goto empty_with_handle;
	}

	domains = g_ptr_array_new();
	if (!domains) {
		rc = KSMBD_RPC_ENOMEM;
		goto empty_with_handle;
	}

	for (i = 0; i < pipe->num_entries; i++) {
		struct lsarpc_names_info *ni;
		int domain_index = -1;

		ni = g_ptr_array_index(pipe->entries, i);
		if (!ni->mapped)
			continue;
		mapped++;
		for (j = 0; j < domains->len; j++) {
			struct lsarpc_names_info *domain;

			domain = g_ptr_array_index(domains, j);
			if (!smb_compare_sids(&domain->domain_sid,
					      &ni->domain_sid)) {
				domain_index = j;
				break;
			}
		}
		if (domain_index < 0) {
			domain_index = domains->len;
			g_ptr_array_add(domains, ni);
		}
		ni->index = domain_index;
	}

	if (domains->len) {
		dce->num_pointers++;
		if (ndr_write_int32(dce, dce->num_pointers) ||
		    ndr_write_int32(dce, domains->len)) {
			rc = KSMBD_RPC_EBAD_DATA;
			goto out;
		}
		dce->num_pointers++;
		if (ndr_write_int32(dce, dce->num_pointers) ||
		    ndr_write_int32(dce, domains->len *
					   LSA_REF_DOMAIN_LIST_MULTIPLIER)) {
			rc = KSMBD_RPC_EBAD_DATA;
			goto out;
		}
		if (ndr_write_int32(dce, domains->len)) {
			rc = KSMBD_RPC_EBAD_DATA;
			goto out;
		}
		for (i = 0; i < domains->len; i++) {
			struct lsarpc_names_info *ni;

			ni = g_ptr_array_index(domains, i);
			if (lsa_domain_account_rep(dce, ni->domain_str)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
		}
		for (i = 0; i < domains->len; i++) {
			struct lsarpc_names_info *ni;

			ni = g_ptr_array_index(domains, i);
			if (lsa_domain_account_data(dce, ni->domain_str,
						    &ni->domain_sid)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
		}
	} else if (ndr_write_int32(dce, 0)) {
		rc = KSMBD_RPC_EBAD_DATA;
		goto out;
	}

	if (ndr_write_int32(dce, pipe->num_entries)) {
		rc = KSMBD_RPC_EBAD_DATA;
		goto out;
	}
	if (pipe->num_entries) {
		dce->num_pointers++;
		if (ndr_write_int32(dce, dce->num_pointers) ||
		    ndr_write_int32(dce, pipe->num_entries)) {
			rc = KSMBD_RPC_EBAD_DATA;
			goto out;
		}
		for (i = 0; i < pipe->num_entries; i++) {
			struct lsarpc_names_info *ni;
			int type;

			ni = g_ptr_array_index(pipe->entries, i);
			type = ni->mapped ? ni->type : SID_TYPE_UNKNOWN;
			if (ndr_write_int16(dce, type)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
			auto_align_offset(dce);
			if (ni->mapped && ni->resolved_name) {
				if (ndr_write_string_rep(dce,
							 ni->resolved_name)) {
					rc = KSMBD_RPC_EBAD_DATA;
					goto out;
				}
			} else if (ndr_write_int16(dce, 0) ||
				   ndr_write_int16(dce, 0) ||
				   ndr_write_int32(dce, 0)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
			if (ndr_write_int32(dce, ni->mapped ? ni->index : -1) ||
			    ndr_write_int32(dce, 0)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
		}
		for (i = 0; i < pipe->num_entries; i++) {
			struct lsarpc_names_info *ni;

			ni = g_ptr_array_index(pipe->entries, i);
			if (ni->mapped && ni->resolved_name &&
			    ndr_write_string_data(dce, ni->resolved_name)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
		}
	} else if (ndr_write_int32(dce, 0)) {
		rc = KSMBD_RPC_EBAD_DATA;
		goto out;
	}
	if (ndr_write_int32(dce, mapped)) {
		rc = KSMBD_RPC_EBAD_DATA;
		goto out;
	}
	if (mapped != pipe->num_entries)
		rc = mapped ? LSARPC_STATUS_SOME_NOT_MAPPED :
			      LSARPC_STATUS_NONE_MAPPED;
	goto out;

out:
	g_ptr_array_free(domains, 1);
	if (ph)
		lsarpc_ph_put(ph);
	rpc_pipe_reset(pipe);
	return rc;

empty_with_handle:
	if (ph)
		lsarpc_ph_put(ph);
empty:
	if (ndr_write_int32(dce, 0) ||
	    ndr_write_int32(dce, 0) ||
	    ndr_write_int32(dce, 0) ||
	    ndr_write_int32(dce, 0))
		rc = KSMBD_RPC_EBAD_DATA;
	rpc_pipe_reset(pipe);
	return rc;
}

static int lsarpc_lookup_sid_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct policy_handle *ph;
	GPtrArray *domains;
	unsigned int i, j, mapped = 0;
	int rc = KSMBD_RPC_OK;

	ph = lsarpc_ph_lookup(pipe, dce->lr_req.handle);
	if (!ph || ph->type != LSARPC_HANDLE_POLICY) {
		rc = LSARPC_STATUS_INVALID_HANDLE;
		goto empty;
	}
	rc = lsarpc_policy_access(ph, LSA_POLICY_LOOKUP_NAMES);
	if (rc)
		goto empty_with_handle;

	domains = g_ptr_array_new();
	if (!domains) {
		rc = KSMBD_RPC_ENOMEM;
		goto empty_with_handle;
	}

	for (i = 0; i < pipe->num_entries; i++) {
		struct lsarpc_names_info *ni;
		int domain_index = -1;

		ni = g_ptr_array_index(pipe->entries, i);
		if (!ni->mapped)
			continue;
		mapped++;
		for (j = 0; j < domains->len; j++) {
			struct lsarpc_names_info *domain;

			domain = g_ptr_array_index(domains, j);
			if (!smb_compare_sids(&domain->domain_sid,
					      &ni->domain_sid)) {
				domain_index = j;
				break;
			}
		}
		if (domain_index < 0) {
			domain_index = domains->len;
			g_ptr_array_add(domains, ni);
		}
		ni->index = domain_index;
	}

	if (domains->len) {
		dce->num_pointers++;
		if (ndr_write_int32(dce, dce->num_pointers) ||
		    ndr_write_int32(dce, domains->len)) {
			rc = KSMBD_RPC_EBAD_DATA;
			goto out;
		}
		dce->num_pointers++;
		if (ndr_write_int32(dce, dce->num_pointers) ||
		    ndr_write_int32(dce, domains->len *
					   LSA_REF_DOMAIN_LIST_MULTIPLIER)) {
			rc = KSMBD_RPC_EBAD_DATA;
			goto out;
		}
		if (ndr_write_int32(dce, domains->len)) {
			rc = KSMBD_RPC_EBAD_DATA;
			goto out;
		}
		for (i = 0; i < domains->len; i++) {
			struct lsarpc_names_info *ni;

			ni = g_ptr_array_index(domains, i);
			if (lsa_domain_account_rep(dce, ni->domain_str)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
		}
		for (i = 0; i < domains->len; i++) {
			struct lsarpc_names_info *ni;

			ni = g_ptr_array_index(domains, i);
			if (lsa_domain_account_data(dce, ni->domain_str,
						    &ni->domain_sid)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
		}
	} else if (ndr_write_int32(dce, 0)) {
		rc = KSMBD_RPC_EBAD_DATA;
		goto out;
	}

	if (ndr_write_int32(dce, pipe->num_entries)) {
		rc = KSMBD_RPC_EBAD_DATA;
		goto out;
	}
	if (pipe->num_entries) {
		dce->num_pointers++;
		if (ndr_write_int32(dce, dce->num_pointers) ||
		    ndr_write_int32(dce, pipe->num_entries)) {
			rc = KSMBD_RPC_EBAD_DATA;
			goto out;
		}
		for (i = 0; i < pipe->num_entries; i++) {
			struct lsarpc_names_info *ni;
			int type;

			ni = g_ptr_array_index(pipe->entries, i);
			type = ni->mapped ? ni->type : SID_TYPE_UNKNOWN;
			if (ndr_write_int16(dce, type)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
			auto_align_offset(dce);
			if (ni->mapped && ni->resolved_name) {
				if (ndr_write_string_rep(dce, ni->resolved_name)) {
					rc = KSMBD_RPC_EBAD_DATA;
					goto out;
				}
			} else if (ndr_write_int16(dce, 0) ||
				   ndr_write_int16(dce, 0) ||
				   ndr_write_int32(dce, 0)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
			if (ndr_write_int32(dce, ni->mapped ? ni->index : -1)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
		}
		for (i = 0; i < pipe->num_entries; i++) {
			struct lsarpc_names_info *ni;

			ni = g_ptr_array_index(pipe->entries, i);
			if (ni->mapped && ni->resolved_name &&
			    ndr_write_string_data(dce, ni->resolved_name)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
		}
	} else if (ndr_write_int32(dce, 0)) {
		rc = KSMBD_RPC_EBAD_DATA;
		goto out;
	}
	if (ndr_write_int32(dce, mapped)) {
		rc = KSMBD_RPC_EBAD_DATA;
		goto out;
	}
	if (mapped != pipe->num_entries)
		rc = mapped ? LSARPC_STATUS_SOME_NOT_MAPPED :
			      LSARPC_STATUS_NONE_MAPPED;
	goto out;

out:
	g_ptr_array_free(domains, 1);
	if (ph)
		lsarpc_ph_put(ph);
	rpc_pipe_reset(pipe);
	return rc;

empty_with_handle:
	if (ph)
		lsarpc_ph_put(ph);
empty:
	if (ndr_write_int32(dce, 0) ||
	    ndr_write_int32(dce, 0) ||
	    ndr_write_int32(dce, 0) ||
	    ndr_write_int32(dce, 0))
		rc = KSMBD_RPC_EBAD_DATA;
	rpc_pipe_reset(pipe);
	return rc;
}

static int lsarpc_lookup_names3_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct lsarpc_names_info *ni = NULL;
	GPtrArray *reps;
	__u32 num_names, max_count;
	unsigned int i;

	if (lsarpc_syntax_interface(pipe, dce->req_hdr.context_id) !=
	    LSARPC_INTERFACE_LSAD)
		goto fail;
	if (ndr_read_bytes(dce, dce->lr_req.handle, HANDLE_SIZE))
		goto fail;

	if (ndr_read_int32(dce, &num_names) ||
	    ndr_read_int32(dce, &max_count))
		goto fail;
	if (num_names > LSARPC_MAX_NAME_COUNT ||
	    max_count < num_names)
		goto fail;

	reps = g_ptr_array_new_with_free_func(g_free);
	if (!reps)
		return KSMBD_RPC_ENOMEM;
	for (i = 0; i < num_names; i++) {
		struct ndr_string_rep *rep;

		rep = g_try_malloc(sizeof(*rep));
		if (!rep ||
		    ndr_read_string_rep(dce, rep) ||
		    rep->length > 4096 ||
		    rep->size > 4096) {
			g_free(rep);
			g_ptr_array_free(reps, 1);
			goto fail;
		}
		g_ptr_array_add(reps, rep);
	}
	if (reps->len != num_names) {
		g_ptr_array_free(reps, 1);
		goto fail;
	}

	for (i = 0; i < num_names; i++) {
		struct ndr_string_rep *rep;

		g_autofree char *input_name = NULL;
		int ret;

		rep = g_ptr_array_index(reps, i);
		if (rep->ref_id)
			input_name = ndr_read_string_data(dce, rep);
		if (rep->ref_id && !input_name)
			goto names_fail;
		ni = g_try_malloc0(sizeof(*ni));
		if (!ni)
			goto names_fail;
		ni->index = -1;
		ni->type = SID_TYPE_UNKNOWN;
		ret = input_name ? lsarpc_resolve_name(ni, input_name) : -EINVAL;
		if (ret == -ENOMEM)
			goto names_fail;
		g_ptr_array_add(pipe->entries, ni);
		ni = NULL;
		pipe->num_entries++;
	}
	g_ptr_array_free(reps, 1);
	if (lsarpc_read_lookup_tail(dce, 1, 1))
		goto fail;
	pipe->entry_processed = __lsarpc_entry_processed;
	return KSMBD_RPC_OK;

names_fail:
	g_ptr_array_free(reps, 1);
fail:
	lsarpc_name_info_free(ni);
	if (pipe->entry_processed)
		rpc_pipe_reset(pipe);
	else {
		while (pipe->entries->len) {
			ni = g_ptr_array_remove_index(pipe->entries, pipe->entries->len - 1);
			lsarpc_name_info_free(ni);
		}
		pipe->num_entries = 0;
	}
	return KSMBD_RPC_EINVALID_PARAMETER;
}

static int lsarpc_lookup_names_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct lsarpc_names_info *ni = NULL;
	GPtrArray *reps;
	__u32 num_names, max_count;
	unsigned int i;

	if (lsarpc_syntax_interface(pipe, dce->req_hdr.context_id) !=
	    LSARPC_INTERFACE_LSAD)
		goto fail;
	if (ndr_read_bytes(dce, dce->lr_req.handle, HANDLE_SIZE))
		goto fail;

	if (ndr_read_int32(dce, &num_names) ||
	    ndr_read_int32(dce, &max_count))
		goto fail;
	if (num_names > LSARPC_MAX_NAME_COUNT ||
	    max_count < num_names)
		goto fail;

	reps = g_ptr_array_new_with_free_func(g_free);
	if (!reps)
		return KSMBD_RPC_ENOMEM;
	for (i = 0; i < num_names; i++) {
		struct ndr_string_rep *rep;

		rep = g_try_malloc(sizeof(*rep));
		if (!rep ||
		    ndr_read_string_rep(dce, rep) ||
		    rep->length > 4096 ||
		    rep->size > 4096) {
			g_free(rep);
			g_ptr_array_free(reps, 1);
			goto fail;
		}
		g_ptr_array_add(reps, rep);
	}
	if (reps->len != num_names) {
		g_ptr_array_free(reps, 1);
		goto fail;
	}

	for (i = 0; i < num_names; i++) {
		struct ndr_string_rep *rep;

		g_autofree char *input_name = NULL;
		int ret;

		rep = g_ptr_array_index(reps, i);
		if (rep->ref_id)
			input_name = ndr_read_string_data(dce, rep);
		if (rep->ref_id && !input_name)
			goto names_fail;
		ni = g_try_malloc0(sizeof(*ni));
		if (!ni)
			goto names_fail;
		ni->index = -1;
		ni->type = SID_TYPE_UNKNOWN;
		ret = input_name ? lsarpc_resolve_name(ni, input_name) : -EINVAL;
		if (ret == -ENOMEM)
			goto names_fail;
		g_ptr_array_add(pipe->entries, ni);
		ni = NULL;
		pipe->num_entries++;
	}
	g_ptr_array_free(reps, 1);
	if (lsarpc_read_lookup_tail(dce, 1, 0))
		goto fail;
	pipe->entry_processed = __lsarpc_entry_processed;
	return KSMBD_RPC_OK;

names_fail:
	g_ptr_array_free(reps, 1);
fail:
	lsarpc_name_info_free(ni);
	if (pipe->entry_processed)
		rpc_pipe_reset(pipe);
	else {
		while (pipe->entries->len) {
			ni = g_ptr_array_remove_index(pipe->entries, pipe->entries->len - 1);
			lsarpc_name_info_free(ni);
		}
		pipe->num_entries = 0;
	}
	return KSMBD_RPC_EINVALID_PARAMETER;
}

static int lsarpc_lookup_names3_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct policy_handle *ph;
	GPtrArray *domains;
	unsigned int i, j, mapped = 0;
	int rc = KSMBD_RPC_OK;

	ph = lsarpc_ph_lookup(pipe, dce->lr_req.handle);
	if (!ph || ph->type != LSARPC_HANDLE_POLICY) {
		rc = LSARPC_STATUS_INVALID_HANDLE;
		goto empty;
	}
	rc = lsarpc_policy_access(ph, LSA_POLICY_LOOKUP_NAMES);
	if (rc) {
		goto empty_with_handle;
	}

	domains = g_ptr_array_new();
	if (!domains) {
		rc = KSMBD_RPC_ENOMEM;
		goto empty_with_handle;
	}

	for (i = 0; i < pipe->num_entries; i++) {
		struct lsarpc_names_info *ni;
		int domain_index = -1;

		ni = g_ptr_array_index(pipe->entries, i);
		if (!ni->mapped)
			continue;
		mapped++;
		for (j = 0; j < domains->len; j++) {
			struct lsarpc_names_info *domain;

			domain = g_ptr_array_index(domains, j);
			if (!smb_compare_sids(&domain->domain_sid,
					      &ni->domain_sid)) {
				domain_index = j;
				break;
			}
		}
		if (domain_index < 0) {
			domain_index = domains->len;
			g_ptr_array_add(domains, ni);
		}
		ni->index = domain_index;
	}

	if (domains->len) {
		dce->num_pointers++;
		if (ndr_write_int32(dce, dce->num_pointers) ||
		    ndr_write_int32(dce, domains->len)) {
			rc = KSMBD_RPC_EBAD_DATA;
			goto out;
		}
		dce->num_pointers++;
		if (ndr_write_int32(dce, dce->num_pointers) ||
		    ndr_write_int32(dce, domains->len *
					   LSA_REF_DOMAIN_LIST_MULTIPLIER)) {
			rc = KSMBD_RPC_EBAD_DATA;
			goto out;
		}
		if (ndr_write_int32(dce, domains->len)) {
			rc = KSMBD_RPC_EBAD_DATA;
			goto out;
		}
		for (i = 0; i < domains->len; i++) {
			struct lsarpc_names_info *ni;

			ni = g_ptr_array_index(domains, i);
			if (lsa_domain_account_rep(dce, ni->domain_str)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
		}
		for (i = 0; i < domains->len; i++) {
			struct lsarpc_names_info *ni;

			ni = g_ptr_array_index(domains, i);
			if (lsa_domain_account_data(dce, ni->domain_str,
						    &ni->domain_sid)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
		}
	} else if (ndr_write_int32(dce, 0)) {
		rc = KSMBD_RPC_EBAD_DATA;
		goto out;
	}

	if (ndr_write_int32(dce, pipe->num_entries)) {
		rc = KSMBD_RPC_EBAD_DATA;
		goto out;
	}
	if (pipe->num_entries) {
		dce->num_pointers++;
		if (ndr_write_int32(dce, dce->num_pointers) ||
		    ndr_write_int32(dce, pipe->num_entries)) {
			rc = KSMBD_RPC_EBAD_DATA;
			goto out;
		}
		for (i = 0; i < pipe->num_entries; i++) {
			struct lsarpc_names_info *ni;
			int type;

			ni = g_ptr_array_index(pipe->entries, i);
			type = ni->mapped ? ni->type : SID_TYPE_UNKNOWN;
			if (ndr_write_int16(dce, type)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
			auto_align_offset(dce);
			if (ni->mapped) {
				dce->num_pointers++;
				if (ndr_write_int32(dce, dce->num_pointers)) {
					rc = KSMBD_RPC_EBAD_DATA;
					goto out;
				}
			} else if (ndr_write_int32(dce, 0)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
			if (ndr_write_int32(dce, ni->mapped ? ni->index : -1) ||
			    ndr_write_int32(dce, 0)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
		}
		for (i = 0; i < pipe->num_entries; i++) {
			struct lsarpc_names_info *ni;

			ni = g_ptr_array_index(pipe->entries, i);
			if (!ni->mapped)
				continue;
			if (ndr_write_int32(dce, ni->sid.num_subauth) ||
			    smb_write_sid(dce, &ni->sid)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
		}
	} else if (ndr_write_int32(dce, 0)) {
		rc = KSMBD_RPC_EBAD_DATA;
		goto out;
	}
	if (ndr_write_int32(dce, mapped)) {
		rc = KSMBD_RPC_EBAD_DATA;
		goto out;
	}
	if (mapped != pipe->num_entries)
		rc = mapped ? LSARPC_STATUS_SOME_NOT_MAPPED :
			      LSARPC_STATUS_NONE_MAPPED;
	goto out;

out:
	g_ptr_array_free(domains, 1);
	lsarpc_ph_put(ph);
	rpc_pipe_reset(pipe);
	return rc;

empty_with_handle:
	lsarpc_ph_put(ph);
empty:
	if (ndr_write_int32(dce, 0) ||
	    ndr_write_int32(dce, 0) ||
	    ndr_write_int32(dce, 0) ||
	    ndr_write_int32(dce, 0))
		rc = KSMBD_RPC_EBAD_DATA;
	rpc_pipe_reset(pipe);
	return rc;
}

static int lsarpc_lookup_names_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct policy_handle *ph;
	GPtrArray *domains;
	unsigned int i, j, mapped = 0;
	int rc = KSMBD_RPC_OK;

	ph = lsarpc_ph_lookup(pipe, dce->lr_req.handle);
	if (!ph || ph->type != LSARPC_HANDLE_POLICY) {
		rc = LSARPC_STATUS_INVALID_HANDLE;
		goto empty;
	}
	rc = lsarpc_policy_access(ph, LSA_POLICY_LOOKUP_NAMES);
	if (rc)
		goto empty_with_handle;

	domains = g_ptr_array_new();
	if (!domains) {
		rc = KSMBD_RPC_ENOMEM;
		goto empty_with_handle;
	}

	for (i = 0; i < pipe->num_entries; i++) {
		struct lsarpc_names_info *ni;
		int domain_index = -1;

		ni = g_ptr_array_index(pipe->entries, i);
		if (!ni->mapped)
			continue;
		mapped++;
		for (j = 0; j < domains->len; j++) {
			struct lsarpc_names_info *domain;

			domain = g_ptr_array_index(domains, j);
			if (!smb_compare_sids(&domain->domain_sid,
					      &ni->domain_sid)) {
				domain_index = j;
				break;
			}
		}
		if (domain_index < 0) {
			domain_index = domains->len;
			g_ptr_array_add(domains, ni);
		}
		ni->index = domain_index;
	}

	if (domains->len) {
		dce->num_pointers++;
		if (ndr_write_int32(dce, dce->num_pointers) ||
		    ndr_write_int32(dce, domains->len)) {
			rc = KSMBD_RPC_EBAD_DATA;
			goto out;
		}
		dce->num_pointers++;
		if (ndr_write_int32(dce, dce->num_pointers) ||
		    ndr_write_int32(dce, domains->len *
					   LSA_REF_DOMAIN_LIST_MULTIPLIER)) {
			rc = KSMBD_RPC_EBAD_DATA;
			goto out;
		}
		if (ndr_write_int32(dce, domains->len)) {
			rc = KSMBD_RPC_EBAD_DATA;
			goto out;
		}
		for (i = 0; i < domains->len; i++) {
			struct lsarpc_names_info *ni;

			ni = g_ptr_array_index(domains, i);
			if (lsa_domain_account_rep(dce, ni->domain_str)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
		}
		for (i = 0; i < domains->len; i++) {
			struct lsarpc_names_info *ni;

			ni = g_ptr_array_index(domains, i);
			if (lsa_domain_account_data(dce, ni->domain_str,
						    &ni->domain_sid)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
		}
	} else if (ndr_write_int32(dce, 0)) {
		rc = KSMBD_RPC_EBAD_DATA;
		goto out;
	}

	if (ndr_write_int32(dce, pipe->num_entries)) {
		rc = KSMBD_RPC_EBAD_DATA;
		goto out;
	}
	if (pipe->num_entries) {
		dce->num_pointers++;
		if (ndr_write_int32(dce, dce->num_pointers) ||
		    ndr_write_int32(dce, pipe->num_entries)) {
			rc = KSMBD_RPC_EBAD_DATA;
			goto out;
		}
		for (i = 0; i < pipe->num_entries; i++) {
			struct lsarpc_names_info *ni;
			__u32 rid = 0;
			int type;

			ni = g_ptr_array_index(pipe->entries, i);
			type = ni->mapped ? ni->type : SID_TYPE_UNKNOWN;
			if (ni->mapped && lsarpc_sid_relative_id(ni, &rid)) {
				rc = KSMBD_RPC_EINVALID_PARAMETER;
				goto out;
			}
			if (ndr_write_int16(dce, type) ||
			    ndr_write_int32(dce, rid) ||
			    ndr_write_int32(dce, ni->mapped ? ni->index : -1)) {
				rc = KSMBD_RPC_EBAD_DATA;
				goto out;
			}
		}
	} else if (ndr_write_int32(dce, 0)) {
		rc = KSMBD_RPC_EBAD_DATA;
		goto out;
	}
	if (ndr_write_int32(dce, mapped)) {
		rc = KSMBD_RPC_EBAD_DATA;
		goto out;
	}
	if (mapped != pipe->num_entries)
		rc = mapped ? LSARPC_STATUS_SOME_NOT_MAPPED :
			      LSARPC_STATUS_NONE_MAPPED;
	goto out;

out:
	g_ptr_array_free(domains, 1);
	lsarpc_ph_put(ph);
	rpc_pipe_reset(pipe);
	return rc;

empty_with_handle:
	lsarpc_ph_put(ph);
empty:
	if (ndr_write_int32(dce, 0) ||
	    ndr_write_int32(dce, 0) ||
	    ndr_write_int32(dce, 0) ||
	    ndr_write_int32(dce, 0))
		rc = KSMBD_RPC_EBAD_DATA;
	rpc_pipe_reset(pipe);
	return rc;
}

static int lsarpc_close_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;

	if (lsarpc_syntax_interface(pipe, dce->req_hdr.context_id) !=
	    LSARPC_INTERFACE_LSAD)
		return KSMBD_RPC_EINVALID_PARAMETER;
	if (ndr_read_bytes(dce, dce->lr_req.handle, HANDLE_SIZE))
		return KSMBD_RPC_EINVALID_PARAMETER;

	return ndr_request_end(dce) ? KSMBD_RPC_EINVALID_PARAMETER :
				      KSMBD_RPC_OK;
}

static int lsarpc_close_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	unsigned char handle[HANDLE_SIZE] = {0};
	int ret;

	ret = lsarpc_ph_close(pipe, dce->lr_req.handle);

	if (ndr_write_bytes(dce, handle, sizeof(handle)))
		return KSMBD_RPC_EBAD_DATA;

	return ret;
}

static int lsarpc_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int ret = KSMBD_RPC_ENOTIMPLEMENTED;

	switch (dce->req_hdr.opnum) {
	case 0:
		switch (lsarpc_syntax_interface(pipe, dce->req_hdr.context_id)) {
		case LSARPC_INTERFACE_DSSETUP:
			ret = lsarpc_get_primary_domain_info_invoke(pipe);
			break;
		case LSARPC_INTERFACE_LSAD:
			ret = lsarpc_close_invoke(pipe);
			break;
		default:
			ret = KSMBD_RPC_EINVALID_PARAMETER;
			break;
		}
		break;
	case LSARPC_OPNUM_OPEN_POLICY:
		ret = lsarpc_open_policy_invoke(pipe);
		break;
	case LSARPC_OPNUM_OPEN_POLICY2:
		ret = lsarpc_open_policy2_invoke(pipe);
		break;
	case LSARPC_OPNUM_QUERY_INFO_POLICY:
		ret = lsarpc_query_info_policy_invoke(pipe);
		break;
	case LSARPC_OPNUM_LOOKUP_SID:
		ret = lsarpc_lookup_sid_invoke(pipe);
		break;
	case LSARPC_OPNUM_LOOKUP_SID2:
		ret = lsarpc_lookup_sid2_invoke(pipe);
		break;
	case LSARPC_OPNUM_LOOKUP_NAMES:
		ret = lsarpc_lookup_names_invoke(pipe);
		break;
	case LSARPC_OPNUM_LOOKUP_NAMES3:
		ret = lsarpc_lookup_names3_invoke(pipe);
		break;
	default:
		pr_err("LSARPC: unsupported INVOKE method %d, alloc_hint : %d\n",
		       dce->req_hdr.opnum, dce->req_hdr.alloc_hint);
		break;
	}

	return ret;
}

static int lsarpc_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	size_t payload_start;
	int status = KSMBD_RPC_ENOTIMPLEMENTED;

	dce->offset = sizeof(struct dcerpc_header);
	dce->offset += sizeof(struct dcerpc_response_header);
	payload_start = dce->offset;

	if (rpc_restricted_context(dce->rpc_req))
		dce->lr_req.operation_status = KSMBD_RPC_EACCESS_DENIED;

	if (dce->lr_req.operation_status) {
		status = dce->lr_req.operation_status;
		if (lsarpc_write_error_payload(dce, dce->req_hdr.opnum,
				       lsarpc_syntax_interface(
			       pipe, dce->req_hdr.context_id))) {
		rpc_pipe_reset(pipe);
		return KSMBD_RPC_EBAD_DATA;
		}
		rpc_pipe_reset(pipe);
	} else {
		switch (dce->req_hdr.opnum) {
		case 0:
		if (lsarpc_syntax_interface(pipe, dce->req_hdr.context_id) ==
		    LSARPC_INTERFACE_DSSETUP)
			status = lsarpc_get_primary_domain_info_return(pipe);
		else
			status = lsarpc_close_return(pipe);
		break;
		case LSARPC_OPNUM_OPEN_POLICY:
		status = lsarpc_open_policy2_return(pipe);
		break;
		case LSARPC_OPNUM_OPEN_POLICY2:
		status = lsarpc_open_policy2_return(pipe);
		break;
		case LSARPC_OPNUM_QUERY_INFO_POLICY:
		status = lsarpc_query_info_policy_return(pipe);
		break;
		case LSARPC_OPNUM_LOOKUP_SID:
		status = lsarpc_lookup_sid_return(pipe);
		break;
		case LSARPC_OPNUM_LOOKUP_SID2:
		status = lsarpc_lookup_sid2_return(pipe);
		break;
		case LSARPC_OPNUM_LOOKUP_NAMES:
		status = lsarpc_lookup_names_return(pipe);
		break;
		case LSARPC_OPNUM_LOOKUP_NAMES3:
		status = lsarpc_lookup_names3_return(pipe);
		break;
		default:
		pr_err("LSARPC: unsupported RETURN method %d\n",
			dce->req_hdr.opnum);
		status = KSMBD_RPC_EBAD_FUNC;
		break;
		}
	}

	if (status && status != KSMBD_RPC_EMORE_DATA &&
	    status != LSARPC_STATUS_NONE_MAPPED &&
	    status != LSARPC_STATUS_SOME_NOT_MAPPED &&
	    status != KSMBD_RPC_NONE_MAPPED &&
	    status != KSMBD_RPC_SOME_NOT_MAPPED) {
		dce->offset = payload_start;
		if (lsarpc_write_error_payload(dce, dce->req_hdr.opnum,
				       lsarpc_syntax_interface(
				       pipe, dce->req_hdr.context_id))) {
			rpc_pipe_reset(pipe);
			return KSMBD_RPC_EBAD_DATA;
		}
	}

	/*
	 * [out] DWORD Return value/code
	 */
	if (ndr_write_int32(dce, lsarpc_wire_status(status,
				     lsarpc_syntax_interface(
				     pipe, dce->req_hdr.context_id))))
		return KSMBD_RPC_EBAD_DATA;

	return KSMBD_RPC_OK;
}

int rpc_lsarpc_read_request(struct ksmbd_rpc_pipe *pipe,
			    struct ksmbd_rpc_command *resp,
			    int max_resp_sz)
{
	int ret;

	dcerpc_set_ext_payload(pipe->dce, resp->payload, max_resp_sz);
	ret = rpc_build_response(pipe, lsarpc_return);
	if (ret)
		return ret;
	return rpc_write_response_fragment(pipe);
}

int rpc_lsarpc_write_request(struct ksmbd_rpc_pipe *pipe)
{
	struct lsarpc_info_request *req = &pipe->dce->lr_req;
	int ret;

	pipe->dce->request_cleanup = lsarpc_request_cleanup;
	memset(req, 0, sizeof(*req));
	ret = lsarpc_invoke(pipe);
	req->operation_status = ret;
	return KSMBD_RPC_OK;
}

static void lsarpc_ph_retire(unsigned int pipe_id, int match_pipe)
{
	if (!ph_table)
		return;

	for (;;) {
		struct policy_handle *ph = NULL;
		GHashTableIter iter;
		int destroy = 0;

		g_rw_lock_writer_lock(&ph_table_lock);
		g_hash_table_iter_init(&iter, ph_table);
		while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&ph)) {
			if (match_pipe && ph->pipe_id != pipe_id) {
				ph = NULL;
				continue;
			}

			ph->retired = 1;
			g_hash_table_iter_remove(&iter);
			if (ph->refcount && !--ph->refcount)
				destroy = 1;
			break;
		}
		g_rw_lock_writer_unlock(&ph_table_lock);

		if (!ph)
			break;
		if (destroy)
			lsarpc_ph_destroy(ph);
	}
}

void rpc_lsarpc_pipe_close(unsigned int pipe_id)
{
	lsarpc_ph_retire(pipe_id, 1);
}

void rpc_lsarpc_init(void)
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

	if (!ph_table)
		ph_table = g_hash_table_new(rpc_handle_hash, rpc_handle_equal);
}

void rpc_lsarpc_destroy(void)
{
	if (ph_table) {
		lsarpc_ph_retire(0, 0);
		g_hash_table_destroy(ph_table);
		ph_table = NULL;
	}

	g_free(domain_name);
	domain_name = NULL;
}
