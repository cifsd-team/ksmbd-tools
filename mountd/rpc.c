// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <memory.h>
#include <endian.h>
#include <stdint.h>
#include <glib.h>
#include <errno.h>
#include <linux/ksmbd_server.h>

#include <rpc.h>
#include <rpc_srvsvc.h>
#include <rpc_wkssvc.h>
#include <rpc_samr.h>
#include <rpc_lsarpc.h>
#include <tools.h>

static GHashTable	*pipes_table;
static GRWLock		pipes_table_lock;
static volatile gint	rpc_handle_counter;

static void dcerpc_bind_req_free(struct dcerpc_bind_request *hdr);
static int dcerpc_syntax_cmp(const struct dcerpc_syntax *a,
			     const struct dcerpc_syntax *b);
static void rpc_pipe_clear_input(struct ksmbd_rpc_pipe *pipe);

guint rpc_handle_hash(gconstpointer key)
{
	const unsigned char *p = key;
	guint hash = 2166136261U;
	size_t i;

	for (i = 0; i < KSMBD_RPC_HANDLE_SIZE; i++)
		hash = (hash ^ p[i]) * 16777619U;
	return hash;
}

gboolean rpc_handle_equal(gconstpointer a, gconstpointer b)
{
	return !memcmp(a, b, KSMBD_RPC_HANDLE_SIZE);
}

int rpc_handle_generate(unsigned char *handle, size_t size,
			unsigned int pipe_id)
{
	guint32 sequence;
	guint32 value;
	size_t i;

	if (size < KSMBD_RPC_HANDLE_SIZE)
		return -EINVAL;

	sequence = (guint32)g_atomic_int_add(&rpc_handle_counter, 1) + 1;
	if (!sequence)
		return -EOVERFLOW;

	memset(handle, 0, KSMBD_RPC_HANDLE_SIZE);
	memcpy(handle, &sequence, sizeof(sequence));
	memcpy(handle + sizeof(sequence), &pipe_id, sizeof(pipe_id));

	for (i = sizeof(sequence) + sizeof(pipe_id);
	     i < KSMBD_RPC_HANDLE_SIZE;
	     i += sizeof(value)) {
		value = g_random_int();
		memcpy(handle + i, &value,
		       MIN(sizeof(value), KSMBD_RPC_HANDLE_SIZE - i));
	}

	return 0;
}

/*
 * Version 2.0 data representation protocol
 *
 * UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860
 * VERSION: 2
 *
 *
 * Transfer Syntax: Bind Time Feature Negotiation
 * UUID:6cb71c2c-9812-4540-0300-000000000000
 *
 * 6CB71C2C-9812-4540
 *
 * MUST BE BLOCKED
 * Interface: SRVSVC UUID: 4b324fc8-1670-01d3-1278-5a47bf6ee188
 */
struct dcerpc_syntax_table {
	struct dcerpc_syntax	syn;
	int			ack_result;
};

static struct dcerpc_syntax_table known_syntaxes[] = {
	{
		.syn.uuid.time_low = 0x8a885d04,
		.syn.uuid.time_mid = 0x1ceb,
		.syn.uuid.time_hi_and_version = 0x11c9,
		.syn.uuid.clock_seq = {0x9f, 0xe8},
		.syn.uuid.node = {0x8, 0x0, 0x2b, 0x10, 0x48, 0x60},
		.syn.ver_major = 0x2,
		.syn.ver_minor = 0x0,
		.ack_result = DCERPC_BIND_ACK_RES_ACCEPT,
	},
	{
		.syn.uuid.time_low = 0x6CB71C2C,
		.syn.uuid.time_mid = 0x9812,
		.syn.uuid.time_hi_and_version = 0x4540,
		.syn.uuid.clock_seq = {0x0, 0x0},
		.syn.uuid.node = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		.syn.ver_major = 0x1,
		.syn.ver_minor = 0x0,
		.ack_result = DCERPC_BIND_ACK_RES_NEGOTIATE_ACK,
	},
};

static const struct dcerpc_syntax dcerpc_srvsvc_syntax = {
	.uuid = {
		.time_low = 0x4b324fc8,
		.time_mid = 0x1670,
		.time_hi_and_version = 0x01d3,
		.clock_seq = {0x12, 0x78},
		.node = {0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88},
	},
	.ver_major = 3,
	.ver_minor = 0,
};

static const struct dcerpc_syntax dcerpc_wkssvc_syntax = {
	.uuid = {
		.time_low = 0x6bffd098,
		.time_mid = 0xa112,
		.time_hi_and_version = 0x3610,
		.clock_seq = {0x98, 0x33},
		.node = {0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a},
	},
	.ver_major = 1,
	.ver_minor = 0,
};

static const struct dcerpc_syntax dcerpc_samr_syntax = {
	.uuid = {
		.time_low = 0x12345778,
		.time_mid = 0x1234,
		.time_hi_and_version = 0xabcd,
		.clock_seq = {0xef, 0x00},
		.node = {0x01, 0x23, 0x45, 0x67, 0x89, 0xac},
	},
	.ver_major = 1,
	.ver_minor = 0,
};

static const struct dcerpc_syntax dcerpc_lsad_syntax = {
	.uuid = {
		.time_low = 0x12345778,
		.time_mid = 0x1234,
		.time_hi_and_version = 0xabcd,
		.clock_seq = {0xef, 0x00},
		.node = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab},
	},
	.ver_major = 0,
	.ver_minor = 0,
};

static const struct dcerpc_syntax dcerpc_dssetup_syntax = {
	.uuid = {
		.time_low = 0x3919286a,
		.time_mid = 0xb10c,
		.time_hi_and_version = 0x11d0,
		.clock_seq = {0x9b, 0xa8},
		.node = {0x00, 0xc0, 0x4f, 0xd9, 0x2e, 0xf5},
	},
	.ver_major = 0,
	.ver_minor = 0,
};

/*
 * PNIO uuid
 * Transfer Syntax: PNIO (Implicit Ar)
 *
 * All zero-s.
 */
static struct dcerpc_syntax negotiate_ack_PNIO_uuid;

/*
 * We need a proper DCE RPC (ndr/ndr64) parser. And we also need a proper
 * IDL support...
 * Maybe someone smart and cool enough can do it for us. The one you can
 * find here is just a very simple implementation, which sort of works for
 * us, but we do realize that it sucks.
 *
 * Documentation:
 *
 * http://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagfcjh_39
 * https://msdn.microsoft.com/en-us/library/cc243858.aspx
 */

#define PAYLOAD_HEAD(d)	((d)->payload + (d)->offset)

#define __ALIGN(x, a)							\
	({								\
		typeof(x) ret = (x);					\
		if (((x) & ((typeof(x))(a) - 1)) != 0)			\
			ret = __ALIGN_MASK(x, (typeof(x))(a) - 1);	\
		ret;							\
	})

#define __ALIGN_MASK(x, mask)	(((x) + (mask)) & ~(mask))

static struct ksmbd_rpc_pipe *rpc_pipe_lookup(unsigned int id)
{
	struct ksmbd_rpc_pipe *pipe;

	g_rw_lock_writer_lock(&pipes_table_lock);
	pipe = pipes_table ? g_hash_table_lookup(pipes_table, &id) : NULL;
	if (pipe && !pipe->retired)
		pipe->refcount++;
	else
		pipe = NULL;
	g_rw_lock_writer_unlock(&pipes_table_lock);

	return pipe;
}

const struct dcerpc_syntax *rpc_pipe_context_syntax(
					struct ksmbd_rpc_pipe *pipe,
					__u16 context_id)
{
	int i;

	if (!pipe || !pipe->contexts)
		return NULL;

	for (i = 0; i < pipe->contexts->len; i++) {
		struct dcerpc_context_binding *binding;

		binding = g_ptr_array_index(pipe->contexts, i);
		if (binding->id == context_id)
			return &binding->abstract_syntax;
	}

	return NULL;
}

static void dcerpc_free(struct ksmbd_dcerpc *dce)
{
	if (!(dce->flags & KSMBD_DCERPC_EXTERNAL_PAYLOAD))
		g_free(dce->payload);
	g_free(dce->response_payload);
	g_free(dce);
}

static struct ksmbd_dcerpc *dcerpc_ext_alloc(unsigned int flags,
					     void *payload,
					     int payload_sz)
{
	struct ksmbd_dcerpc *dce;

	dce = g_try_malloc0(sizeof(struct ksmbd_dcerpc));
	if (!dce)
		return NULL;

	dce->payload = payload;
	dce->payload_sz = payload_sz;

	dce->flags = flags;
	dce->flags |= KSMBD_DCERPC_EXTERNAL_PAYLOAD;
	dce->flags |= KSMBD_DCERPC_FIXED_PAYLOAD_SZ;
	return dce;
}

void dcerpc_set_ext_payload(struct ksmbd_dcerpc *dce, void *payload, size_t sz)
{
	dce->num_pointers = 1;
	dce->payload = payload;
	dce->payload_sz = sz;
	dce->offset = 0;
	dce->flags |= KSMBD_DCERPC_EXTERNAL_PAYLOAD;
	dce->flags |= KSMBD_DCERPC_FIXED_PAYLOAD_SZ;
}

static void rpc_pipe_cleanup_request(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce;
	void (*cleanup)(struct ksmbd_rpc_pipe *pipe);

	if (!pipe || !pipe->dce)
		return;

	dce = pipe->dce;
	cleanup = dce->request_cleanup;
	if (!cleanup)
		return;

	dce->request_cleanup = NULL;
	cleanup(pipe);
}

void rpc_pipe_reset(struct ksmbd_rpc_pipe *pipe)
{
	if (!pipe)
		return;

	if (pipe->entry_processed && pipe->entries) {
		while (pipe->num_entries && pipe->entries->len)
			pipe->entry_processed(pipe, pipe->entries->len - 1);
	}
	pipe->num_entries = 0;
	pipe->entry_processed = NULL;

	if (!pipe->dce)
		return;

	pipe->dce->response_started = 0;
	g_clear_pointer(&pipe->dce->response_payload, g_free);
	pipe->dce->response_payload_sz = 0;
	pipe->dce->response_payload_offset = 0;
	pipe->dce->response_alloc_hint = 0;
	pipe->dce->response_limit = 0;
}

static void __rpc_pipe_free(struct ksmbd_rpc_pipe *pipe)
{
	rpc_pipe_clear_input(pipe);
	rpc_pipe_cleanup_request(pipe);
	rpc_pipe_reset(pipe);
	if (pipe->dce) {
		if (pipe->dce->bind_req_active)
			dcerpc_bind_req_free(&pipe->dce->bi_req);
		dcerpc_free(pipe->dce);
	}
	if (pipe->entries)
		g_ptr_array_free(pipe->entries, 1);
	if (pipe->contexts)
		g_ptr_array_free(pipe->contexts, 1);
	g_mutex_clear(&pipe->op_lock);
	g_free(pipe);
}

static void rpc_pipe_put(struct ksmbd_rpc_pipe *pipe)
{
	int destroy = 0;

	if (!pipe)
		return;

	g_rw_lock_writer_lock(&pipes_table_lock);
	if (pipe->refcount && !--pipe->refcount)
		destroy = 1;
	g_rw_lock_writer_unlock(&pipes_table_lock);

	if (destroy)
		__rpc_pipe_free(pipe);
}

static void rpc_pipe_free(struct ksmbd_rpc_pipe *pipe)
{
	int destroy = 0;

	if (!pipe)
		return;

	g_rw_lock_writer_lock(&pipes_table_lock);
	if (!pipe->retired) {
		if (pipe->id != (unsigned int)-1 && pipes_table)
			g_hash_table_remove(pipes_table, &(pipe->id));
		pipe->retired = 1;
		if (pipe->refcount && !--pipe->refcount)
			destroy = 1;
	}
	g_rw_lock_writer_unlock(&pipes_table_lock);

	if (destroy)
		__rpc_pipe_free(pipe);
}

static struct ksmbd_rpc_pipe *rpc_pipe_alloc(void)
{
	struct ksmbd_rpc_pipe *pipe;

	pipe = g_try_malloc0(sizeof(struct ksmbd_rpc_pipe));
	if (!pipe)
		return NULL;

	g_mutex_init(&pipe->op_lock);
	pipe->id = -1;
	pipe->max_xmit_frag_sz = UINT16_MAX;
	pipe->max_recv_frag_sz = KSMBD_RPC_MAX_FRAGMENT_SIZE;
	pipe->entries = g_ptr_array_new();
	pipe->contexts = g_ptr_array_new_with_free_func(g_free);
	if (!pipe->entries || !pipe->contexts) {
		if (pipe->entries)
			g_ptr_array_free(pipe->entries, 1);
		if (pipe->contexts)
			g_ptr_array_free(pipe->contexts, 1);
		g_mutex_clear(&pipe->op_lock);
		g_free(pipe);
		return NULL;
	}
	return pipe;
}

static struct ksmbd_rpc_pipe *rpc_pipe_alloc_bind(struct ksmbd_rpc_command *req)
{
	struct ksmbd_rpc_pipe *pipe = rpc_pipe_alloc();
	unsigned int id = req->handle;

	if (!pipe)
		return NULL;

	pipe->dce = dcerpc_ext_alloc(KSMBD_DCERPC_LITTLE_ENDIAN |
				     KSMBD_DCERPC_ALIGN4,
				     req->payload, req->payload_sz);
	if (!pipe->dce) {
		__rpc_pipe_free(pipe);
		return NULL;
	}
	pipe->id = id;
	pipe->refcount = 1;
	g_rw_lock_writer_lock(&pipes_table_lock);
	if (g_hash_table_lookup(pipes_table, &id)) {
		g_rw_lock_writer_unlock(&pipes_table_lock);
		pipe->id = (unsigned int)-1;
		pipe->refcount = 0;
		__rpc_pipe_free(pipe);
		return NULL;
	}
	g_hash_table_insert(pipes_table, &(pipe->id), pipe);
	g_rw_lock_writer_unlock(&pipes_table_lock);

	return pipe;
}

static void __clear_pipes_table(void)
{
	struct ksmbd_rpc_pipe *pipe;
	GHashTableIter iter;

	g_rw_lock_writer_lock(&pipes_table_lock);
	ghash_for_each_remove(pipe, pipes_table, iter) {
		pipe->retired = 1;
		if (pipe->refcount && !--pipe->refcount)
			__rpc_pipe_free(pipe);
	}
	g_rw_lock_writer_unlock(&pipes_table_lock);
}

/*
 * The current kernel IPC supplies no authenticated caller token. RPC objects
 * therefore grant only their public ACL, independent of caller identity. Never
 * infer an administrator or retain generic/MAXIMUM_ALLOWED bits in a handle.
 */
int rpc_grant_access(unsigned int desired, unsigned int public_access,
		     const struct rpc_generic_mapping *mapping,
		     unsigned int *granted)
{
	unsigned int concrete = desired & ~0xf2000000U;

	*granted = 0;
	if (desired & 0x80000000U)
		concrete |= mapping->read;
	if (desired & 0x40000000U)
		concrete |= mapping->write;
	if (desired & 0x20000000U)
		concrete |= mapping->execute;
	if (desired & 0x10000000U)
		concrete |= mapping->all;
	if (concrete & ~public_access)
		return KSMBD_RPC_EACCESS_DENIED;
	*granted = desired & 0x02000000U ? public_access : concrete;
	return KSMBD_RPC_OK;
}

static void align_offset(struct ksmbd_dcerpc *dce, size_t n)
{
	dce->offset = __ALIGN(dce->offset, n);
}

void auto_align_offset(struct ksmbd_dcerpc *dce)
{
	if (dce->flags & KSMBD_DCERPC_ALIGN8)
		dce->offset = __ALIGN(dce->offset, 8);
	else if (dce->flags & KSMBD_DCERPC_ALIGN4)
		dce->offset = __ALIGN(dce->offset, 4);
}

static int try_realloc_payload(struct ksmbd_dcerpc *dce, size_t data_sz)
{
	char *n;
	size_t required_size, payload_sz;

	if (data_sz > SIZE_MAX - dce->offset)
		return -ENOMEM;
	required_size = dce->offset + data_sz;
	if (required_size <= dce->payload_sz)
		return 0;

	if (dce->flags & KSMBD_DCERPC_FIXED_PAYLOAD_SZ) {
		pr_err("DCE RPC: fixed payload buffer overflow\n");
		return -ENOMEM;
	}

	payload_sz = dce->payload_sz;
	while (payload_sz < required_size) {
		if (payload_sz > SIZE_MAX - 4096)
			return -ENOMEM;
		payload_sz += 4096;
	}

	n = g_try_realloc(dce->payload, payload_sz);
	if (!n)
		return -ENOMEM;

	dce->payload = n;
	dce->payload_sz = payload_sz;
	memset(dce->payload + dce->offset, 0, dce->payload_sz - dce->offset);
	return 0;
}

static __u8 noop_int8(__u8 v)
{
	return v;
}

#define htobe_n noop_int8
#define htole_n noop_int8
#define betoh_n noop_int8
#define letoh_n noop_int8

#define NDR_WRITE_INT(name, type, be, le)				\
int ndr_write_##name(struct ksmbd_dcerpc *dce, type value)		\
{									\
	type converted;							\
									\
	align_offset(dce, sizeof(type));				\
	if (try_realloc_payload(dce, sizeof(value)))			\
		return -ENOMEM;						\
	if (dce->flags & KSMBD_DCERPC_LITTLE_ENDIAN)			\
		converted = le(value);					\
	else								\
		converted = be(value);					\
	memcpy(PAYLOAD_HEAD(dce), &converted, sizeof(converted));		\
	dce->offset += sizeof(value);					\
	return 0;							\
}

NDR_WRITE_INT(int8,  __u8, htobe_n, htole_n);
NDR_WRITE_INT(int16, __u16, htobe16, htole16);
NDR_WRITE_INT(int32, __u32, htobe32, htole32);
NDR_WRITE_INT(int64, __u64, htobe64, htole64);

#define NDR_READ_INT(name, type, be, le)				\
int ndr_read_##name(struct ksmbd_dcerpc *dce, type *value)		\
{									\
	type ret;							\
									\
	align_offset(dce, sizeof(type));				\
	if (dce->offset > dce->payload_sz ||				\
	    sizeof(type) > dce->payload_sz - dce->offset)		\
		return -EINVAL;						\
									\
	memcpy(&ret, PAYLOAD_HEAD(dce), sizeof(ret));			\
	if (dce->flags & KSMBD_DCERPC_LITTLE_ENDIAN)			\
		ret = le(ret);						\
	else								\
		ret = be(ret);						\
	dce->offset += sizeof(type);					\
	if (value)							\
		memcpy(value, &ret, sizeof(ret));				\
	return 0;							\
}

NDR_READ_INT(int8,  __u8, betoh_n, letoh_n);
NDR_READ_INT(int16, __u16, be16toh, le16toh);
NDR_READ_INT(int32, __u32, be32toh, le32toh);
NDR_READ_INT(int64, __u64, be64toh, le64toh);

/*
 * For a non-encapsulated union, the discriminant is marshalled into
 * the transmitted data stream twice: once as the field or parameter,
 * which is referenced by the switch_is construct, in the procedure
 * argument list; and once as the first part of the union
 * representation.
 */
#define NDR_WRITE_UNION(name, type)					\
int ndr_write_union_##name(struct ksmbd_dcerpc *dce, type value)	\
{									\
	int ret;							\
									\
	ret = ndr_write_##name(dce, value);				\
	if (ret)							\
		return ret;						\
	ret = ndr_write_##name(dce, value);				\
	return ret;							\
}

NDR_WRITE_UNION(int16, __u16);
NDR_WRITE_UNION(int32, __u32);

#define NDR_READ_UNION(name, type)					\
int ndr_read_union_##name(struct ksmbd_dcerpc *dce, type *value)	\
{									\
	type val1, val2;						\
									\
	if (ndr_read_##name(dce, &val1))				\
		return -EINVAL;						\
	if (ndr_read_##name(dce, &val2))				\
		return -EINVAL;						\
	if (val1 != val2) {						\
		pr_err("NDR: union representation mismatch %lu\n",	\
				(unsigned long)val1);			\
		return -EINVAL;						\
	}								\
	if (value)							\
		*value = val1;						\
	return 0;							\
}

NDR_READ_UNION(int32, __u32);

int ndr_write_bytes(struct ksmbd_dcerpc *dce, const void *value, size_t sz)
{
	align_offset(dce, 2);
	if (try_realloc_payload(dce, sz))
		return -ENOMEM;

	memcpy(PAYLOAD_HEAD(dce), value, sz);
	dce->offset += sz;
	return 0;
}

int ndr_read_bytes(struct ksmbd_dcerpc *dce, void *value, size_t sz)
{
	align_offset(dce, 2);
	if (dce->offset > dce->payload_sz ||
	    sz > dce->payload_sz - dce->offset)
		return -EINVAL;
	memcpy(value, PAYLOAD_HEAD(dce), sz);
	dce->offset += sz;
	return 0;
}

int ndr_request_end(struct ksmbd_dcerpc *dce)
{
	size_t alignment = 1;
	size_t i;

	if (dce->offset > dce->payload_sz)
		return -EINVAL;

	if (dce->flags & KSMBD_DCERPC_ALIGN8)
		alignment = 8;
	else if (dce->flags & KSMBD_DCERPC_ALIGN4)
		alignment = 4;

	/*
	 * A request may contain only the alignment bytes left after the
	 * procedure arguments.  The request PDU itself does not have to end
	 * on the NDR alignment boundary (for example, DSSETUP's two-byte
	 * information level request).
	 */
	if (dce->payload_sz - dce->offset >= alignment)
		return -EINVAL;

	for (i = dce->offset; i < dce->payload_sz; i++) {
		if (dce->payload[i] != 0)
			return -EINVAL;
	}

	dce->offset = dce->payload_sz;
	return 0;
}

static gchar *ndr_convert_char_to_unicode(struct ksmbd_dcerpc *dce,
		const char *str,
		size_t len, gsize *bytes_written)
{
	gchar *out;
	gsize bytes_read = 0;
	int charset = KSMBD_CHARSET_UTF16LE;

	if (!(dce->flags & KSMBD_DCERPC_LITTLE_ENDIAN))
		charset = KSMBD_CHARSET_UTF16BE;

	if (dce->flags & KSMBD_DCERPC_ASCII_STRING)
		charset = KSMBD_CHARSET_UTF8;

	out = ksmbd_gconvert(str,
			     len,
			     charset,
			     KSMBD_CHARSET_DEFAULT,
			     &bytes_read,
			     bytes_written);

	return out;
}

int ndr_write_vstring(struct ksmbd_dcerpc *dce, const void *value)
{
	g_autofree char *out = NULL;
	gsize bytes_written = 0;

	size_t raw_len, str_len;
	const char *raw_value = value;
	int ret;

	if (!value)
		raw_value = "";

	raw_len = strlen(raw_value) + 1;
	out = ndr_convert_char_to_unicode(dce, raw_value, raw_len,
			&bytes_written);
	if (!out)
		return -EINVAL;

	if (bytes_written % 2)
		return -EINVAL;
	str_len = bytes_written / 2;

	/*
	 * NDR represents a conformant and varying string as an ordered
	 * sequence of representations of the string elements, preceded
	 * by three unsigned long integers. The first integer gives the
	 * maximum number of elements in the string, including the terminator.
	 * The second integer gives the offset from the first index of the
	 * string to the first index of the actual subset being passed.
	 * The third integer gives the actual number of elements being
	 * passed, including the terminator.
	 */
	ret = ndr_write_int32(dce, str_len);
	if (ret)
		return ret;

	ret = ndr_write_int32(dce, 0);
	if (ret)
		return ret;

	ret = ndr_write_int32(dce, str_len);
	if (ret)
		return ret;

	ret = ndr_write_bytes(dce, out, bytes_written);
	if (ret)
		return ret;
	auto_align_offset(dce);

	return ret;
}

int ndr_write_string(struct ksmbd_dcerpc *dce, const char *str)
{
	g_autofree char *out = NULL;
	gsize bytes_written = 0;

	size_t input_len, len;
	int ret;

	if (!str)
		str = "";

	input_len = strlen(str);
	out = ndr_convert_char_to_unicode(dce, str, input_len,
			&bytes_written);
	if (!out)
		return -EINVAL;
	if (bytes_written % 2)
		return -EINVAL;
	len = bytes_written / 2;

	ret = ndr_write_int32(dce, len); // max count
	if (ret)
		return ret;

	ret = ndr_write_int32(dce, 0);
	if (ret)
		return ret;

	ret = ndr_write_int32(dce, len); // actual count
	if (ret)
		return ret;

	ret = ndr_write_bytes(dce, out, bytes_written);
	auto_align_offset(dce);

	return ret;
}

int ndr_write_string_data(struct ksmbd_dcerpc *dce, const char *str)
{
	g_autofree char *out = NULL;
	gsize bytes_written = 0;
	size_t input_len, len;

	if (!str)
		str = "";

	input_len = strlen(str);
	out = ndr_convert_char_to_unicode(dce, str, input_len,
					  &bytes_written);
	if (!out || bytes_written % 2)
		return -EINVAL;
	len = bytes_written / 2;

	if (ndr_write_int32(dce, len) ||
	    ndr_write_int32(dce, 0) ||
	    ndr_write_int32(dce, len) ||
	    ndr_write_bytes(dce, out, bytes_written))
		return -EINVAL;
	auto_align_offset(dce);
	return 0;
}

int ndr_write_string_rep(struct ksmbd_dcerpc *dce, const char *str)
{
	g_autofree char *out = NULL;
	gsize bytes_written = 0;
	int charset = KSMBD_CHARSET_UTF16LE;

	if (!str)
		str = "";
	if (!(dce->flags & KSMBD_DCERPC_LITTLE_ENDIAN))
		charset = KSMBD_CHARSET_UTF16BE;
	if (dce->flags & KSMBD_DCERPC_ASCII_STRING)
		charset = KSMBD_CHARSET_UTF8;

	out = ksmbd_gconvert(str, strlen(str), charset,
			     KSMBD_CHARSET_DEFAULT, NULL, &bytes_written);
	if (!out || bytes_written > UINT16_MAX ||
	    bytes_written % 2)
		return -EINVAL;

	if (ndr_write_int16(dce, bytes_written) ||
	    ndr_write_int16(dce, bytes_written))
		return -EINVAL;
	dce->num_pointers++;
	return ndr_write_int32(dce, dce->num_pointers);
}

int ndr_write_lsa_string(struct ksmbd_dcerpc *dce, const char *str)
{
	g_autofree char *out = NULL;
	gsize bytes_written = 0;

	size_t input_len, len;
	int ret;

	if (!str)
		str = "";

	input_len = strlen(str);
	out = ndr_convert_char_to_unicode(dce, str, input_len,
			&bytes_written);
	if (!out)
		return -EINVAL;
	if (bytes_written % 2)
		return -EINVAL;
	len = bytes_written / 2;

	ret = ndr_write_int32(dce, len + 1); // max count
	if (ret)
		return ret;

	ret = ndr_write_int32(dce, 0);
	if (ret)
		return ret;

	ret = ndr_write_int32(dce, len); // actual count
	if (ret)
		return ret;

	ret = ndr_write_bytes(dce, out, bytes_written);
	auto_align_offset(dce);

	return ret;
}

int ndr_write_lsa_string_rep(struct ksmbd_dcerpc *dce, const char *str)
{
	g_autofree char *out = NULL;
	gsize bytes_written = 0;
	int charset = KSMBD_CHARSET_UTF16LE;

	if (!str)
		str = "";
	if (!(dce->flags & KSMBD_DCERPC_LITTLE_ENDIAN))
		charset = KSMBD_CHARSET_UTF16BE;
	if (dce->flags & KSMBD_DCERPC_ASCII_STRING)
		charset = KSMBD_CHARSET_UTF8;

	out = ksmbd_gconvert(str, strlen(str), charset,
			     KSMBD_CHARSET_DEFAULT, NULL, &bytes_written);
	if (!out || bytes_written > UINT16_MAX - 2 ||
	    bytes_written % 2)
		return -EINVAL;

	if (ndr_write_int16(dce, bytes_written) ||
	    ndr_write_int16(dce, bytes_written + 2))
		return -EINVAL;
	dce->num_pointers++;
	return ndr_write_int32(dce, dce->num_pointers);
}

static char *ndr_read_vstring_internal(struct ksmbd_dcerpc *dce,
				       __u32 *actual_count,
				       int require_terminator)
{
	gchar *out;
	gsize bytes_read = 0;
	gsize bytes_written = 0;

	__u32 max_count, offset, actual;
	int charset = KSMBD_CHARSET_UTF16LE;

	if (ndr_read_int32(dce, &max_count))
		return NULL;
	if (ndr_read_int32(dce, &offset))
		return NULL;
	if (ndr_read_int32(dce, &actual))
		return NULL;
	if (offset > max_count || actual > max_count - offset)
		return NULL;
	if (actual > SIZE_MAX / 2)
		return NULL;

	if (!(dce->flags & KSMBD_DCERPC_LITTLE_ENDIAN))
		charset = KSMBD_CHARSET_UTF16BE;

	if (dce->flags & KSMBD_DCERPC_ASCII_STRING)
		charset = KSMBD_CHARSET_UTF8;

	if (actual == 0) {
		out = g_strdup("");
		if (actual_count)
			*actual_count = 0;
		return out;
	}

	if (actual > (dce->payload_sz - MIN(dce->offset,
					    dce->payload_sz)) / 2)
		return NULL;
	if (require_terminator) {
		__u16 terminator;

		memcpy(&terminator, PAYLOAD_HEAD(dce) + (actual - 1) * 2,
		       sizeof(terminator));
		terminator = (dce->flags & KSMBD_DCERPC_LITTLE_ENDIAN) ?
			le16toh(terminator) : be16toh(terminator);
		if (terminator)
			return NULL;
	}

	out = ksmbd_gconvert(PAYLOAD_HEAD(dce),
			     actual * 2,
			     KSMBD_CHARSET_DEFAULT,
			     charset,
			     &bytes_read,
			     &bytes_written);
	if (!out)
		return NULL;

	dce->offset += actual * 2;
	if (actual_count)
		*actual_count = actual;
	return out;
}

char *ndr_read_vstring(struct ksmbd_dcerpc *dce)
{
	return ndr_read_vstring_internal(dce, NULL, 1);
}

char *ndr_read_vstring_compat(struct ksmbd_dcerpc *dce)
{
	/*
	 * Several NDR clients, including Impacket, omit the terminating
	 * code unit while retaining the counted UTF-16 representation.
	 */
	return ndr_read_vstring_internal(dce, NULL, 0);
}

int ndr_read_vstring_ptr(struct ksmbd_dcerpc *dce, struct ndr_char_ptr *ctr)
{
	ctr->ptr = ndr_read_vstring_compat(dce);
	if (!ctr->ptr)
		return -EINVAL;
	return 0;
}

int ndr_read_uniq_vstring_ptr(struct ksmbd_dcerpc *dce,
			      struct ndr_uniq_char_ptr *ctr)
{
	if (ndr_read_int32(dce, &ctr->ref_id))
		return -EINVAL;

	if (ctr->ref_id == 0) {
		ctr->ptr = NULL;
		return 0;
	}
	ctr->ptr = ndr_read_vstring_compat(dce);
	if (!ctr->ptr)
		return -EINVAL;
	return 0;
}

int ndr_read_string_rep(struct ksmbd_dcerpc *dce,
			struct ndr_string_rep *rep)
{
	if (ndr_read_int16(dce, &rep->length))
		return -EINVAL;
	if (ndr_read_int16(dce, &rep->size))
		return -EINVAL;
	if (ndr_read_int32(dce, &rep->ref_id))
		return -EINVAL;
	if (rep->length > rep->size ||
	    (rep->length & 1) || (rep->size & 1) ||
	    (!rep->ref_id && (rep->length || rep->size)))
		return -EINVAL;
	return 0;
}

char *ndr_read_string_data(struct ksmbd_dcerpc *dce,
			   const struct ndr_string_rep *rep)
{
	char *value;
	__u32 actual_count;

	if (!rep->ref_id)
		return NULL;

	value = ndr_read_vstring_internal(dce, &actual_count, 0);
	if (!value)
		return NULL;
	if (actual_count != rep->length / 2 ||
	    actual_count > rep->size / 2) {
		g_free(value);
		return NULL;
	}
	return value;
}

void ndr_free_vstring_ptr(struct ndr_char_ptr *ctr)
{
	g_free(ctr->ptr);
	ctr->ptr = NULL;
}

void ndr_free_uniq_vstring_ptr(struct ndr_uniq_char_ptr *ctr)
{
	ctr->ref_id = 0;
	g_free(ctr->ptr);
	ctr->ptr = NULL;
}

int ndr_read_ptr(struct ksmbd_dcerpc *dce, struct ndr_ptr *ctr)
{
	if (ndr_read_int32(dce, &ctr->ptr))
		return -EINVAL;
	return 0;
}

int ndr_read_uniq_ptr(struct ksmbd_dcerpc *dce, struct ndr_uniq_ptr *ctr)
{
	if (ndr_read_int32(dce, &ctr->ref_id))
		return -EINVAL;
	if (ctr->ref_id == 0) {
		ctr->ptr = 0;
		return 0;
	}
	if (ndr_read_int32(dce, &ctr->ptr))
		return -EINVAL;
	return 0;
}

int ndr_max_entries(struct ksmbd_dcerpc *dce, struct ksmbd_rpc_pipe *pipe)
{
	size_t current_size, limit, threshold;
	int i;

	if (!(dce->flags & KSMBD_DCERPC_FIXED_PAYLOAD_SZ))
		return pipe->num_entries;

	if (!dce->entry_size) {
		pr_err("No ->entry_size() callback was provided\n");
		return pipe->num_entries;
	}

	limit = dce->response_limit ? dce->response_limit :
		dce->payload_sz;
	threshold = limit - limit / 5;
	current_size = 0;
	for (i = 0; i < pipe->num_entries; i++) {
		void *entry;
		int entry_size;

		entry = g_ptr_array_index(pipe->entries, i);
		entry_size = dce->entry_size(dce, entry);
		if (entry_size < 0 ||
		    current_size > SIZE_MAX - (size_t)entry_size)
			return i;
		current_size += entry_size;

		if (current_size < threshold)
			continue;
		return i;
	}

	return pipe->num_entries;
}

int __ndr_write_array_of_structs(struct ksmbd_rpc_pipe *pipe, int max_entry_nr)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int i;

	for (i = 0; i < max_entry_nr; i++) {
		void *entry;

		entry = g_ptr_array_index(pipe->entries, i);
		if (dce->entry_rep(dce, entry))
			return KSMBD_RPC_EBAD_DATA;
	}

	for (i = 0; i < max_entry_nr; i++) {
		void *entry;

		entry = g_ptr_array_index(pipe->entries, i);
		if (dce->entry_data(dce, entry))
			return KSMBD_RPC_EBAD_DATA;
	}

	if (pipe->entry_processed) {
		for (i = 0; i < max_entry_nr; i++)
			pipe->entry_processed(pipe, 0);
		if (!pipe->num_entries)
			pipe->entry_processed = NULL;
	}

	return KSMBD_RPC_OK;
}

static int ndr_write_empty_array_of_struct(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;

	dce->num_pointers++;
	if (ndr_write_int32(dce, dce->num_pointers))
		return KSMBD_RPC_EBAD_DATA;

	if (ndr_write_int32(dce, 0))
		return KSMBD_RPC_EBAD_DATA;

	if (ndr_write_int32(dce, 0))
		return KSMBD_RPC_EBAD_DATA;

	return KSMBD_RPC_OK;
}

int ndr_write_array_of_structs(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int max_entry_nr;
	int ret;

	/*
	 * In the NDR representation of a structure that contains a
	 * conformant and varying array, the maximum counts for dimensions
	 * of the array are moved to the beginning of the structure, but
	 * the offsets and actual counts remain in place at the end of the
	 * structure, immediately preceding the array elements.
	 */
	if (pipe->num_entries == 0) {
		ret = ndr_write_empty_array_of_struct(pipe);
		if (!ret)
			pipe->entry_processed = NULL;
		return ret;
	}

	max_entry_nr = ndr_max_entries(dce, pipe);
	if (ndr_write_int32(dce, max_entry_nr))
		return KSMBD_RPC_EBAD_DATA;
	/*
	 * ARRAY representation [per dimension]
	 *    max_count
	 *    offset
	 *    actual_count
	 *    element representation [1..N]
	 *    actual elements [1..N]
	 */
	if (ndr_write_int32(dce, max_entry_nr))
		return KSMBD_RPC_EBAD_DATA;

	if (ndr_write_int32(dce, 1))
		return KSMBD_RPC_EBAD_DATA;

	if (ndr_write_int32(dce, max_entry_nr))
		return KSMBD_RPC_EBAD_DATA;

	if (max_entry_nr == 0) {
		pr_err("DCERPC: can't fit any data, buffer is too small\n");
		rpc_pipe_reset(pipe);
		return KSMBD_RPC_EBAD_DATA;
	}

	if (__ndr_write_array_of_structs(pipe, max_entry_nr))
		return KSMBD_RPC_EBAD_DATA;
	return pipe->num_entries ? KSMBD_RPC_EMORE_DATA : KSMBD_RPC_OK;
}

void rpc_init(void)
{
	if (!pipes_table)
		pipes_table = g_hash_table_new(g_int_hash, g_int_equal);

	rpc_samr_init();
	rpc_lsarpc_init();
}

void rpc_destroy(void)
{
	rpc_lsarpc_destroy();
	rpc_samr_destroy();

	if (pipes_table) {
		__clear_pipes_table();
		g_hash_table_destroy(pipes_table);
		pipes_table = NULL;
	}
}

static int dcerpc_hdr_write(struct ksmbd_dcerpc *dce,
			    struct dcerpc_header *hdr)
{
	int ret;

	ret = ndr_write_int8(dce, hdr->rpc_vers);
	if (ret)
		return ret;

	ret = ndr_write_int8(dce, hdr->rpc_vers_minor);
	if (ret)
		return ret;

	ret = ndr_write_int8(dce, hdr->ptype);
	if (ret)
		return ret;

	ret = ndr_write_int8(dce, hdr->pfc_flags);
	if (ret)
		return ret;

	ret = ndr_write_bytes(dce, &hdr->packed_drep,
			      sizeof(hdr->packed_drep));
	if (ret)
		return ret;

	ret = ndr_write_int16(dce, hdr->frag_length);
	if (ret)
		return ret;

	ret = ndr_write_int16(dce, hdr->auth_length);
	if (ret)
		return ret;

	ret = ndr_write_int32(dce, hdr->call_id);

	return ret;
}

static int dcerpc_hdr_read(struct ksmbd_dcerpc *dce,
			   struct dcerpc_header *hdr)
{
	size_t payload_sz = dce->payload_sz;

	/* Common Type Header for the Serialization Stream */

	if (ndr_read_int8(dce, &hdr->rpc_vers))
		return -EINVAL;
	if (ndr_read_int8(dce, &hdr->rpc_vers_minor))
		return -EINVAL;
	if (ndr_read_int8(dce, &hdr->ptype))
		return -EINVAL;
	if (ndr_read_int8(dce, &hdr->pfc_flags))
		return -EINVAL;
	if (hdr->rpc_vers != 5 || hdr->rpc_vers_minor != 0)
		return -EINVAL;
	/*
	 * This common type header MUST be presented by using
	 * little-endian format in the octet stream. The first
	 * byte of the common type header MUST be equal to 1 to
	 * indicate level 1 of type serialization.
	 *
	 * Type serialization version 1 can use either a little-endian
	 * or big-endian integer and floating-pointer byte order but
	 * MUST use the IEEE floating-point format representation and
	 * ASCII character format.
	 */
	if (ndr_read_bytes(dce, &hdr->packed_drep, sizeof(hdr->packed_drep)))
		return -EINVAL;
	if ((hdr->packed_drep[0] != DCERPC_SERIALIZATION_LITTLE_ENDIAN &&
	     hdr->packed_drep[0] != DCERPC_SERIALIZATION_BIG_ENDIAN) ||
	    hdr->packed_drep[1] != 0 ||
	    hdr->packed_drep[2] != 0 ||
	    hdr->packed_drep[3] != 0)
		return -EINVAL;
	if (hdr->pfc_flags & (DCERPC_PFC_RESERVED_1 | DCERPC_PFC_OBJECT_UUID))
		return -EINVAL;

	dce->flags &= ~KSMBD_DCERPC_LITTLE_ENDIAN;
	if (hdr->packed_drep[0] == DCERPC_SERIALIZATION_LITTLE_ENDIAN)
		dce->flags |= KSMBD_DCERPC_LITTLE_ENDIAN;

	if (ndr_read_int16(dce, &hdr->frag_length))
		return -EINVAL;
	if (ndr_read_int16(dce, &hdr->auth_length))
		return -EINVAL;
	if (ndr_read_int32(dce, &hdr->call_id))
		return -EINVAL;
	if (hdr->frag_length < sizeof(struct dcerpc_header) ||
	    hdr->auth_length ||
	    hdr->auth_length > hdr->frag_length -
				    sizeof(struct dcerpc_header))
		return -EINVAL;
	dce->payload_sz = MIN(payload_sz, hdr->frag_length);
	return 0;
}

static int dcerpc_response_hdr_write(struct ksmbd_dcerpc *dce,
				     struct dcerpc_response_header *hdr)
{
	int ret;

	ret = ndr_write_int32(dce, hdr->alloc_hint);
	if (ret)
		return ret;

	ret = ndr_write_int16(dce, hdr->context_id);
	if (ret)
		return ret;

	ret = ndr_write_int8(dce, hdr->cancel_count);
	auto_align_offset(dce);

	return ret;
}

static int dcerpc_request_hdr_read(struct ksmbd_dcerpc *dce,
				   struct dcerpc_request_header *hdr)
{
	if (ndr_read_int32(dce, &hdr->alloc_hint))
		return -EINVAL;
	if (ndr_read_int16(dce, &hdr->context_id))
		return -EINVAL;
	if (ndr_read_int16(dce, &hdr->opnum))
		return -EINVAL;
	return 0;
}

int dcerpc_write_headers(struct ksmbd_dcerpc *dce, int method_status)
{
	struct dcerpc_header hdr;
	struct dcerpc_response_header resp_hdr;
	size_t payload_offset;
	int continuation;
	int ret;

	(void)method_status;
	payload_offset = dce->offset;
	if (payload_offset < sizeof(struct dcerpc_header) +
	    sizeof(struct dcerpc_response_header))
		return -EINVAL;
	if (payload_offset > UINT16_MAX)
		return -EMSGSIZE;
	dce->offset = 0;

	hdr = dce->hdr;
	hdr.ptype = DCERPC_PTYPE_RPC_RESPONSE;
	continuation = !!(dce->flags & KSMBD_DCERPC_RETURN_READY);
	hdr.pfc_flags = continuation ? 0 : DCERPC_PFC_LAST_FRAG;
	if (!dce->response_started)
		hdr.pfc_flags |= DCERPC_PFC_FIRST_FRAG;
	hdr.frag_length = payload_offset;
	ret = dcerpc_hdr_write(dce, &hdr);
	if (ret)
		return ret;

	if (dce->response_alloc_hint) {
		if (dce->response_alloc_hint > UINT32_MAX)
			return -EMSGSIZE;
		resp_hdr.alloc_hint = dce->response_alloc_hint;
	} else {
		resp_hdr.alloc_hint = payload_offset -
			sizeof(struct dcerpc_header) -
			sizeof(struct dcerpc_response_header);
	}
	resp_hdr.context_id = dce->req_hdr.context_id;
	resp_hdr.cancel_count = 0;
	ret = dcerpc_response_hdr_write(dce, &resp_hdr);
	if (ret)
		return ret;

	dce->offset = payload_offset;
	dce->response_started = continuation;
	return 0;
}

int dcerpc_write_fault(struct ksmbd_dcerpc *dce, __u32 status)
{
	struct dcerpc_response_header resp_hdr;
	size_t payload_offset;
	int ret;

	dce->offset = sizeof(struct dcerpc_header) +
		sizeof(struct dcerpc_response_header);
	if (ndr_write_int32(dce, status) ||
	    ndr_write_int32(dce, 0))
		return -EINVAL;

	payload_offset = dce->offset;
	if (payload_offset > UINT16_MAX)
		return -EMSGSIZE;

	dce->offset = 0;
	dce->hdr.ptype = DCERPC_PTYPE_RPC_FAULT;
	dce->hdr.pfc_flags = DCERPC_PFC_FIRST_FRAG |
		DCERPC_PFC_LAST_FRAG;
	dce->hdr.frag_length = payload_offset;
	ret = dcerpc_hdr_write(dce, &dce->hdr);
	if (ret)
		return ret;

	resp_hdr.alloc_hint = payload_offset -
		sizeof(struct dcerpc_header) -
		sizeof(struct dcerpc_response_header);
	resp_hdr.context_id = dce->req_hdr.context_id;
	resp_hdr.cancel_count = 0;
	ret = dcerpc_response_hdr_write(dce, &resp_hdr);
	if (ret)
		return ret;

	dce->offset = payload_offset;
	dce->response_started = 0;
	return 0;
}

static int __dcerpc_read_syntax(struct ksmbd_dcerpc *dce,
				struct dcerpc_syntax *syn)
{
	if (ndr_read_int32(dce, &syn->uuid.time_low))
		return -EINVAL;
	if (ndr_read_int16(dce, &syn->uuid.time_mid))
		return -EINVAL;
	if (ndr_read_int16(dce, &syn->uuid.time_hi_and_version))
		return -EINVAL;
	if (ndr_read_bytes(dce, syn->uuid.clock_seq,
			   sizeof(syn->uuid.clock_seq)))
		return -EINVAL;
	if (ndr_read_bytes(dce, syn->uuid.node, sizeof(syn->uuid.node)))
		return -EINVAL;
	if (ndr_read_int16(dce, &syn->ver_major))
		return -EINVAL;
	if (ndr_read_int16(dce, &syn->ver_minor))
		return -EINVAL;
	return 0;
}

static int __dcerpc_write_syntax(struct ksmbd_dcerpc *dce,
				 const struct dcerpc_syntax *syn)
{
	int ret;

	ret = ndr_write_int32(dce, syn->uuid.time_low);
	if (ret)
		return ret;

	ret = ndr_write_int16(dce, syn->uuid.time_mid);
	if (ret)
		return ret;

	ret = ndr_write_int16(dce, syn->uuid.time_hi_and_version);
	if (ret)
		return ret;

	ret = ndr_write_bytes(dce, syn->uuid.clock_seq,
			      sizeof(syn->uuid.clock_seq));
	if (ret)
		return ret;

	ret = ndr_write_bytes(dce, syn->uuid.node, sizeof(syn->uuid.node));
	if (ret)
		return ret;

	ret = ndr_write_int16(dce, syn->ver_major);
	if (ret)
		return ret;

	ret = ndr_write_int16(dce, syn->ver_minor);

	return ret;
}

static void dcerpc_bind_req_free(struct dcerpc_bind_request *hdr)
{
	int i;

	if (!hdr->list) {
		hdr->num_contexts = 0;
		return;
	}

	for (i = 0; i < hdr->num_contexts; i++)
		g_free(hdr->list[i].transfer_syntaxes);
	g_free(hdr->list);
	hdr->list = NULL;
	hdr->num_contexts = 0;
}

static int dcerpc_parse_bind_req(struct ksmbd_dcerpc *dce,
				 struct dcerpc_bind_request *hdr)
{
	int i, j;
	int ret = -EINVAL;
	__u8 reserved;
	__u16 reserved2;

	memset(hdr, 0, sizeof(*hdr));
	hdr->flags = dce->rpc_req->flags;
	if (ndr_read_int16(dce, &hdr->max_xmit_frag_sz))
		return -EINVAL;
	if (ndr_read_int16(dce, &hdr->max_recv_frag_sz))
		return -EINVAL;
	if (hdr->max_xmit_frag_sz < 24 || hdr->max_recv_frag_sz < 32)
		return -EINVAL;
	if (ndr_read_int32(dce, &hdr->assoc_group_id))
		return -EINVAL;
	if (ndr_read_int8(dce, &hdr->num_contexts))
		return -EINVAL;
	if (ndr_read_int8(dce, &reserved) ||
	    ndr_read_int16(dce, &reserved2) ||
	    reserved || reserved2)
		return -EINVAL;

	if (!hdr->num_contexts)
		return 0;

	hdr->list = g_try_malloc0_n(hdr->num_contexts, sizeof(struct dcerpc_context));
	if (!hdr->list)
		return -ENOMEM;

	for (i = 0; i < hdr->num_contexts; i++) {
		struct dcerpc_context *ctx = &hdr->list[i];

		if (ndr_read_int16(dce, &ctx->id))
			goto fail;
		for (j = 0; j < i; j++) {
			if (hdr->list[j].id == ctx->id) {
				pr_err("BIND: duplicate context id %u\n",
				       ctx->id);
				goto fail;
			}
		}
		if (ndr_read_int8(dce, &ctx->num_syntaxes))
			goto fail;
		if (!ctx->num_syntaxes) {
			pr_err("BIND: zero syntaxes provided\n");
			goto fail;
		}
		if (ndr_read_int8(dce, &reserved) || reserved)
			goto fail;

		if (__dcerpc_read_syntax(dce, &ctx->abstract_syntax))
			goto fail;

		ctx->transfer_syntaxes = g_try_malloc0_n(ctx->num_syntaxes,
						sizeof(struct dcerpc_syntax));
		if (!ctx->transfer_syntaxes) {
			ret = -ENOMEM;
			goto fail;
		}

		for (j = 0; j < ctx->num_syntaxes; j++) {
			if (__dcerpc_read_syntax(dce,
						 &ctx->transfer_syntaxes[j]))
				goto fail;
		}
	}
	return KSMBD_RPC_OK;

fail:
	dcerpc_bind_req_free(hdr);
	return ret;
}

static int dcerpc_bind_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce;
	int ret;

	dce = pipe->dce;
	if (dce->bind_req_active)
		dcerpc_bind_req_free(&dce->bi_req);
	dce->bind_req_active = 0;
	ret = dcerpc_parse_bind_req(dce, &dce->bi_req);
	if (ret) {
		dcerpc_bind_req_free(&dce->bi_req);
		return KSMBD_RPC_EBAD_DATA;
	}
	if (ndr_request_end(dce)) {
		dcerpc_bind_req_free(&dce->bi_req);
		return KSMBD_RPC_EBAD_DATA;
	}

	dce->bind_req_active = 1;
	pipe->entry_processed = NULL;
	return KSMBD_RPC_OK;
}

static int dcerpc_syntax_cmp(const struct dcerpc_syntax *a,
			     const struct dcerpc_syntax *b)
{
	if (a->uuid.time_low != b->uuid.time_low)
		return -1;
	if (a->uuid.time_mid != b->uuid.time_mid)
		return -1;
	if (a->uuid.time_hi_and_version != b->uuid.time_hi_and_version)
		return -1;
	if (memcmp(a->uuid.clock_seq, b->uuid.clock_seq,
		   sizeof(a->uuid.clock_seq)))
		return -1;
	if (memcmp(a->uuid.node, b->uuid.node, sizeof(a->uuid.node)))
		return -1;
	if (a->ver_major != b->ver_major)
		return -1;
	if (a->ver_minor != b->ver_minor)
		return -1;
	return 0;
}

static int dcerpc_syntax_supported(const struct dcerpc_syntax *a)
{
	int k;

	for (k = 0; k < ARRAY_SIZE(known_syntaxes); k++) {
		const struct dcerpc_syntax *b = &known_syntaxes[k].syn;

		if (!dcerpc_syntax_cmp(a, b))
			return known_syntaxes[k].ack_result;
	}
	return -1;
}

static int dcerpc_abstract_syntax_supported(
					struct ksmbd_rpc_pipe *pipe,
					const struct dcerpc_syntax *syntax)
{
	unsigned int flags;

	if (!pipe || !pipe->dce || !syntax)
		return 0;

	flags = pipe->dce->bi_req.flags;
	if ((flags & KSMBD_RPC_SRVSVC_METHOD_INVOKE) &&
	    !dcerpc_syntax_cmp(syntax, &dcerpc_srvsvc_syntax))
		return 1;
	if ((flags & KSMBD_RPC_WKSSVC_METHOD_INVOKE) &&
	    !dcerpc_syntax_cmp(syntax, &dcerpc_wkssvc_syntax))
		return 1;
	if ((flags & KSMBD_RPC_SAMR_METHOD_INVOKE) &&
	    !dcerpc_syntax_cmp(syntax, &dcerpc_samr_syntax))
		return 1;
	if ((flags & KSMBD_RPC_LSARPC_METHOD_INVOKE) &&
	    (!dcerpc_syntax_cmp(syntax, &dcerpc_lsad_syntax) ||
	     !dcerpc_syntax_cmp(syntax, &dcerpc_dssetup_syntax)))
		return 1;

	return 0;
}

static int dcerpc_bind_context_result(struct ksmbd_rpc_pipe *pipe,
				      const struct dcerpc_context *ctx,
				      int *reason,
				      int *selected)
{
	const struct dcerpc_syntax *existing;
	int i;

	if (reason)
		*reason = DCERPC_BIND_ACK_RSN_NOT_SPECIFIED;
	if (selected)
		*selected = -1;

	/* An existing context ID must keep its negotiated abstract syntax. */
	existing = rpc_pipe_context_syntax(pipe, ctx->id);
	if (existing && dcerpc_syntax_cmp(existing, &ctx->abstract_syntax))
		return DCERPC_BIND_ACK_RES_PROVIDER_REJECT;

	if (!dcerpc_abstract_syntax_supported(pipe, &ctx->abstract_syntax)) {
		if (reason)
			*reason =
				DCERPC_BIND_ACK_RSN_ABSTRACT_SYNTAX_NOT_SUPPORTED;
		return DCERPC_BIND_ACK_RES_PROVIDER_REJECT;
	}

	for (i = 0; i < ctx->num_syntaxes; i++) {
		int result;

		result = dcerpc_syntax_supported(&ctx->transfer_syntaxes[i]);
		if (result != DCERPC_BIND_ACK_RES_ACCEPT &&
		    !(result == DCERPC_BIND_ACK_RES_NEGOTIATE_ACK &&
		      ctx->num_syntaxes == 1))
			continue;
		if (selected)
			*selected = i;
		return result;
	}

	if (reason)
		*reason = DCERPC_BIND_ACK_RSN_TRANSFER_SYNTAXES_NOT_SUPPORTED;
	return DCERPC_BIND_ACK_RES_PROVIDER_REJECT;
}

static int dcerpc_install_bind_contexts(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	guint previous_count = pipe->contexts->len;
	int i;

	for (i = 0; i < dce->bi_req.num_contexts; i++) {
		struct dcerpc_context_binding *binding;
		int reason, selected, result;

		result = dcerpc_bind_context_result(pipe, &dce->bi_req.list[i],
						    &reason, &selected);
		if (result != DCERPC_BIND_ACK_RES_ACCEPT &&
		    result != DCERPC_BIND_ACK_RES_NEGOTIATE_ACK)
			continue;
		if (rpc_pipe_context_syntax(pipe, dce->bi_req.list[i].id))
			continue;

		binding = g_try_malloc(sizeof(*binding));
		if (!binding) {
			g_ptr_array_set_size(pipe->contexts, previous_count);
			return KSMBD_RPC_ENOMEM;
		}

		binding->id = dce->bi_req.list[i].id;
		binding->abstract_syntax = dce->bi_req.list[i].abstract_syntax;
		g_ptr_array_add(pipe->contexts, binding);
	}

	return KSMBD_RPC_OK;
}

static int dcerpc_bind_ack_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int num_trans, i;
	size_t payload_offset, addr_len;
	char *addr;

	dce->offset = sizeof(struct dcerpc_header);

	/*
	 * Preserve bind assoc group, if was specified.
	 */
	if (dce->bi_req.assoc_group_id == 0)
		dce->bi_req.assoc_group_id = 0x53f0;

	if (ndr_write_int16(dce, dce->bi_req.max_recv_frag_sz))
		return KSMBD_RPC_EBAD_DATA;

	if (ndr_write_int16(dce, MIN(dce->bi_req.max_xmit_frag_sz,
				    KSMBD_RPC_MAX_FRAGMENT_SIZE)))
		return KSMBD_RPC_EBAD_DATA;

	if (ndr_write_int32(dce, dce->bi_req.assoc_group_id))
		return KSMBD_RPC_EBAD_DATA;

	if (dce->bi_req.flags & KSMBD_RPC_SRVSVC_METHOD_INVOKE)
		addr = "\\PIPE\\srvsvc";
	else if (dce->bi_req.flags & KSMBD_RPC_WKSSVC_METHOD_INVOKE)
		addr = "\\PIPE\\wkssvc";
	else if (dce->bi_req.flags & KSMBD_RPC_SAMR_METHOD_INVOKE)
		addr = "\\PIPE\\samr";
	else if (dce->bi_req.flags & KSMBD_RPC_LSARPC_METHOD_INVOKE)
		addr = "\\PIPE\\lsarpc";
	else
		return KSMBD_RPC_EBAD_FUNC;

	if (dce->hdr.ptype == DCERPC_PTYPE_RPC_ALTCONT) {
		if (ndr_write_int16(dce, 0))
			return KSMBD_RPC_EBAD_DATA;

		if (ndr_write_int16(dce, 0))
			return KSMBD_RPC_EBAD_DATA;
	} else {
		addr_len = strlen(addr) + 1;
		if (addr_len > UINT16_MAX ||
		    ndr_write_int16(dce, addr_len))
			return KSMBD_RPC_EBAD_DATA;

		if (ndr_write_bytes(dce, addr, addr_len))
			return KSMBD_RPC_EBAD_DATA;
	}
	align_offset(dce, 4); /* [flag(NDR_ALIGN4)]    DATA_BLOB _pad1; */

	num_trans = dce->bi_req.num_contexts;
	if (ndr_write_int8(dce, num_trans) ||
	    ndr_write_int8(dce, 0) ||
	    ndr_write_int16(dce, 0))
		return KSMBD_RPC_EBAD_DATA;

	for (i = 0; i < num_trans; i++) {
		const struct dcerpc_context *ctx = &dce->bi_req.list[i];
		const struct dcerpc_syntax *s;
		int reason, selected, result;

		result = dcerpc_bind_context_result(pipe, ctx, &reason,
						    &selected);
		if (result == DCERPC_BIND_ACK_RES_NEGOTIATE_ACK)
			s = &negotiate_ack_PNIO_uuid;
		else if (selected >= 0)
			s = &ctx->transfer_syntaxes[selected];
		else
			s = &ctx->transfer_syntaxes[0];

		if (ndr_write_int16(dce, result) ||
		    ndr_write_int16(dce, reason))
			return KSMBD_RPC_EBAD_DATA;
		if (__dcerpc_write_syntax(dce, s))
			return KSMBD_RPC_EBAD_DATA;
	}

	payload_offset = dce->offset;
	if (payload_offset > UINT16_MAX)
		return KSMBD_RPC_EBAD_DATA;
	dce->offset = 0;

	if (dce->hdr.ptype == DCERPC_PTYPE_RPC_ALTCONT)
		dce->hdr.ptype = DCERPC_PTYPE_RPC_ALTCONTRESP;
	else
		dce->hdr.ptype = DCERPC_PTYPE_RPC_BINDACK;
	dce->hdr.pfc_flags = DCERPC_PFC_FIRST_FRAG | DCERPC_PFC_LAST_FRAG;
	dce->hdr.frag_length = payload_offset;
	if (dcerpc_hdr_write(dce, &dce->hdr))
		return KSMBD_RPC_EBAD_DATA;

	dce->offset = payload_offset;
	dce->rpc_resp->payload_sz = dce->offset;
	return KSMBD_RPC_OK;
}

static int dcerpc_bind_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int ret;

	if (!dce->bi_req.num_contexts)
		ret = KSMBD_RPC_EBAD_DATA;
	else
		ret = dcerpc_bind_ack_return(pipe);
	if (ret == KSMBD_RPC_OK)
		ret = dcerpc_install_bind_contexts(pipe);
	if (ret == KSMBD_RPC_OK)
		pipe->max_xmit_frag_sz = dce->bi_req.max_recv_frag_sz;
	if (ret == KSMBD_RPC_OK)
		pipe->max_recv_frag_sz = MIN(dce->bi_req.max_xmit_frag_sz,
					     KSMBD_RPC_MAX_FRAGMENT_SIZE);

	dcerpc_bind_req_free(&dce->bi_req);
	dce->bind_req_active = 0;
	return ret;
}

int rpc_restricted_context(struct ksmbd_rpc_command *req)
{
	if (global_conf.restrict_anon == 0)
		return 0;

	return req->flags & KSMBD_RPC_RESTRICTED_CONTEXT;
}

int rpc_build_response(struct ksmbd_rpc_pipe *pipe,
		       int (*build)(struct ksmbd_rpc_pipe *pipe))
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	char *external_payload = dce->payload;
	size_t external_payload_sz = dce->payload_sz;
	unsigned int external_flags = dce->flags;
	size_t header_size = sizeof(struct dcerpc_header) +
		sizeof(struct dcerpc_response_header);
	char *response;
	size_t size;
	int ret;

	if (dce->response_payload)
		return KSMBD_RPC_OK;
	dce->payload = g_try_malloc0(4096);
	if (!dce->payload) {
		dce->payload = external_payload;
		return KSMBD_RPC_ENOMEM;
	}
	dce->payload_sz = 4096;
	dce->flags &= ~(KSMBD_DCERPC_EXTERNAL_PAYLOAD |
			KSMBD_DCERPC_FIXED_PAYLOAD_SZ |
			KSMBD_DCERPC_RETURN_READY);
	dce->offset = header_size;
	ret = build(pipe);
	response = dce->payload;
	size = dce->offset;
	dce->payload = external_payload;
	dce->payload_sz = external_payload_sz;
	dce->flags = external_flags;
	if (ret || size < header_size || size - header_size > UINT32_MAX) {
		g_free(response);
		rpc_pipe_reset(pipe);
		return ret ? ret : KSMBD_RPC_EBAD_DATA;
	}
	dce->response_payload = response;
	dce->response_payload_sz = size - header_size;
	dce->response_payload_offset = 0;
	dce->response_alloc_hint = size - header_size;
	return KSMBD_RPC_OK;
}

int rpc_write_response_fragment(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	size_t header_size = sizeof(struct dcerpc_header) +
		sizeof(struct dcerpc_response_header);
	size_t remaining, capacity, size;

	if (!dce->response_payload ||
	    dce->response_payload_offset > dce->response_payload_sz ||
	    dce->payload_sz < header_size)
		goto bad_data;
	remaining = dce->response_payload_sz - dce->response_payload_offset;
	capacity = MIN(dce->payload_sz, (size_t)pipe->max_xmit_frag_sz);
	if (capacity < header_size)
		goto bad_data;
	capacity -= header_size;
	/* Every nonfinal fragment ends on an eight-byte NDR boundary. */
	if (remaining > capacity)
		capacity &= ~(size_t)7;
	if (remaining && !capacity)
		goto bad_data;
	size = MIN(remaining, capacity);
	memcpy(dce->payload + header_size,
	       dce->response_payload + header_size +
	       dce->response_payload_offset, size);
	dce->response_payload_offset += size;
	dce->response_alloc_hint = remaining;
	if (dce->response_payload_offset < dce->response_payload_sz)
		dce->flags |= KSMBD_DCERPC_RETURN_READY;
	else
		dce->flags &= ~KSMBD_DCERPC_RETURN_READY;
	dce->offset = header_size + size;
	if (dcerpc_write_headers(dce, KSMBD_RPC_OK))
		goto bad_data;
	dce->rpc_resp->payload_sz = dce->offset;
	if (!(dce->flags & KSMBD_DCERPC_RETURN_READY))
		rpc_pipe_reset(pipe);
	return KSMBD_RPC_OK;

bad_data:
	dce->flags &= ~KSMBD_DCERPC_RETURN_READY;
	rpc_pipe_reset(pipe);
	return KSMBD_RPC_EBAD_DATA;
}

static int rpc_pipe_read_request(struct ksmbd_rpc_pipe *pipe,
				 struct ksmbd_rpc_command *req,
				 struct ksmbd_rpc_command *resp,
				 int max_resp_sz)
{
	int ret = KSMBD_RPC_ENOTIMPLEMENTED;
	struct ksmbd_dcerpc *dce;

	if (!pipe || pipe->retired || !pipe->dce) {
		pr_err("RPC: no pipe or pipe has no associated DCE [%d]\n",
			req->handle);
		return KSMBD_RPC_EBAD_FID;
	}

	dce = pipe->dce;
	if (!(dce->flags & KSMBD_DCERPC_RETURN_READY))
		return KSMBD_RPC_EBAD_DATA;
	dce->flags &= ~KSMBD_DCERPC_RETURN_READY;
	dce->rpc_req = req;
	dce->rpc_resp = resp;
	dcerpc_set_ext_payload(dce, resp->payload, max_resp_sz);

	if (dce->hdr.ptype == DCERPC_PTYPE_RPC_BIND ||
	    dce->hdr.ptype == DCERPC_PTYPE_RPC_ALTCONT) {
		ret = dcerpc_bind_return(pipe);
		goto out;
	}

	if (dce->hdr.ptype != DCERPC_PTYPE_RPC_REQUEST)
		goto out;

	if (req->flags & KSMBD_RPC_SRVSVC_METHOD_INVOKE)
		ret = rpc_srvsvc_read_request(pipe, resp, max_resp_sz);
	else if (req->flags & KSMBD_RPC_WKSSVC_METHOD_INVOKE)
		ret = rpc_wkssvc_read_request(pipe, resp, max_resp_sz);
	else if (req->flags & KSMBD_RPC_SAMR_METHOD_INVOKE)
		ret = rpc_samr_read_request(pipe, resp, max_resp_sz);
	else if (req->flags & KSMBD_RPC_LSARPC_METHOD_INVOKE)
		ret = rpc_lsarpc_read_request(pipe, resp, max_resp_sz);

out:
	if (!(dce->flags & KSMBD_DCERPC_RETURN_READY))
		rpc_pipe_cleanup_request(pipe);
	return ret;
}

int rpc_read_request(struct ksmbd_rpc_command *req,
		     struct ksmbd_rpc_command *resp,
		     int max_resp_sz)
{
	struct ksmbd_rpc_pipe *pipe;
	int ret;

	pipe = rpc_pipe_lookup(req->handle);
	if (!pipe)
		return KSMBD_RPC_EBAD_FID;

	g_mutex_lock(&pipe->op_lock);
	ret = rpc_pipe_read_request(pipe, req, resp, max_resp_sz);
	g_mutex_unlock(&pipe->op_lock);
	rpc_pipe_put(pipe);
	return ret;
}

static int rpc_write_request_fail(struct ksmbd_rpc_pipe *pipe, int status)
{
	rpc_pipe_clear_input(pipe);
	if (pipe->dce->bind_req_active) {
		dcerpc_bind_req_free(&pipe->dce->bi_req);
		pipe->dce->bind_req_active = 0;
	}
	pipe->dce->flags &= ~KSMBD_DCERPC_RETURN_READY;
	pipe->dce->response_started = 0;
	rpc_pipe_cleanup_request(pipe);
	rpc_pipe_reset(pipe);
	return status;
}

static void rpc_input_buffer_clear(struct rpc_input_buffer *buffer)
{
	g_clear_pointer(&buffer->data, g_free);
	buffer->size = 0;
	buffer->capacity = 0;
}

static void rpc_pipe_clear_input(struct ksmbd_rpc_pipe *pipe)
{
	rpc_input_buffer_clear(&pipe->fragment);
	rpc_input_buffer_clear(&pipe->request);
	pipe->request_in_progress = 0;
}

static int rpc_input_buffer_append(struct rpc_input_buffer *buffer,
				   const void *data, size_t size, size_t limit)
{
	size_t capacity, required;
	char *next;

	if (buffer->size > limit || size > limit - buffer->size)
		return KSMBD_RPC_EBAD_DATA;
	required = buffer->size + size;
	if (required > buffer->capacity) {
		capacity = buffer->capacity ? buffer->capacity : 4096;
		while (capacity < required)
			capacity = capacity > limit / 2 ? limit : capacity * 2;
		capacity = MIN(capacity, limit);
		next = g_try_realloc(buffer->data, capacity);
		if (!next)
			return KSMBD_RPC_ENOMEM;
		buffer->data = next;
		buffer->capacity = capacity;
	}
	if (size)
		memcpy(buffer->data + buffer->size, data, size);
	buffer->size = required;
	return KSMBD_RPC_OK;
}

static int rpc_invoke_request(struct ksmbd_rpc_pipe *pipe,
			      struct ksmbd_rpc_command *req,
			      struct ksmbd_rpc_command *resp,
			      const struct ksmbd_dcerpc *fragment)
{
	struct ksmbd_dcerpc *dce = pipe->dce;

	rpc_pipe_cleanup_request(pipe);
	rpc_pipe_reset(pipe);
	dce->flags = fragment->flags | KSMBD_DCERPC_RETURN_READY;
	dce->rpc_req = req;
	dce->rpc_resp = resp;
	dce->hdr = fragment->hdr;
	if (dce->hdr.ptype == DCERPC_PTYPE_RPC_BIND ||
	    dce->hdr.ptype == DCERPC_PTYPE_RPC_ALTCONT) {
		dcerpc_set_ext_payload(dce, fragment->payload, fragment->payload_sz);
		dce->offset = fragment->offset;
		return dcerpc_bind_invoke(pipe);
	}

	dce->hdr = pipe->request_header;
	dce->req_hdr = pipe->request_method;
	dcerpc_set_ext_payload(dce, pipe->request.data, pipe->request.size);
	if (req->flags & KSMBD_RPC_SRVSVC_METHOD_INVOKE)
		return rpc_srvsvc_write_request(pipe);
	if (req->flags & KSMBD_RPC_WKSSVC_METHOD_INVOKE)
		return rpc_wkssvc_write_request(pipe);
	if (req->flags & KSMBD_RPC_SAMR_METHOD_INVOKE)
		return rpc_samr_write_request(pipe);
	if (req->flags & KSMBD_RPC_LSARPC_METHOD_INVOKE)
		return rpc_lsarpc_write_request(pipe);
	return KSMBD_RPC_ENOTIMPLEMENTED;
}

static int rpc_process_fragment(struct ksmbd_rpc_pipe *pipe,
				struct ksmbd_rpc_command *req,
				struct ksmbd_rpc_command *resp,
				struct ksmbd_dcerpc *fragment)
{
	unsigned int fragment_flags = DCERPC_PFC_FIRST_FRAG | DCERPC_PFC_LAST_FRAG;
	unsigned int interface_flags = KSMBD_RPC_SRVSVC_METHOD_INVOKE |
		KSMBD_RPC_WKSSVC_METHOD_INVOKE | KSMBD_RPC_SAMR_METHOD_INVOKE |
		KSMBD_RPC_LSARPC_METHOD_INVOKE | KSMBD_RPC_RESTRICTED_CONTEXT;
	size_t size;
	int ret;

	if (fragment->hdr.ptype != DCERPC_PTYPE_RPC_REQUEST) {
		if (pipe->request_in_progress ||
		    (fragment->hdr.pfc_flags & fragment_flags) != fragment_flags)
			return KSMBD_RPC_EBAD_DATA;
		if (fragment->hdr.ptype != DCERPC_PTYPE_RPC_BIND &&
		    fragment->hdr.ptype != DCERPC_PTYPE_RPC_ALTCONT)
			return KSMBD_RPC_ENOTIMPLEMENTED;
		return rpc_invoke_request(pipe, req, resp, fragment);
	}
	if (dcerpc_request_hdr_read(fragment, &fragment->req_hdr) ||
	    !rpc_pipe_context_syntax(pipe, fragment->req_hdr.context_id) ||
	    fragment->req_hdr.alloc_hint > KSMBD_RPC_MAX_REQUEST_SIZE)
		return KSMBD_RPC_EBAD_DATA;
	size = fragment->payload_sz - fragment->offset;
	if (!(fragment->hdr.pfc_flags & DCERPC_PFC_LAST_FRAG) &&
	    (!size || size % 8))
		return KSMBD_RPC_EBAD_DATA;

	if (fragment->hdr.pfc_flags & DCERPC_PFC_FIRST_FRAG) {
		if (pipe->request_in_progress)
			return KSMBD_RPC_EBAD_DATA;
		pipe->request_header = fragment->hdr;
		pipe->request_method = fragment->req_hdr;
		pipe->request_flags = req->flags & interface_flags;
	} else if (!pipe->request_in_progress ||
		   pipe->request_header.call_id != fragment->hdr.call_id ||
		   pipe->request_method.context_id != fragment->req_hdr.context_id ||
		   pipe->request_method.opnum != fragment->req_hdr.opnum ||
		   pipe->request_flags != (req->flags & interface_flags) ||
		   ((pipe->request_header.pfc_flags ^ fragment->hdr.pfc_flags) &
		    ~fragment_flags) ||
		   memcmp(pipe->request_header.packed_drep, fragment->hdr.packed_drep,
			  sizeof(fragment->hdr.packed_drep))) {
		return KSMBD_RPC_EBAD_DATA;
	}
	ret = rpc_input_buffer_append(&pipe->request,
		fragment->payload + fragment->offset, size, KSMBD_RPC_MAX_REQUEST_SIZE);
	if (ret)
		return ret;
	pipe->request_in_progress = 1;
	if (!(fragment->hdr.pfc_flags & DCERPC_PFC_LAST_FRAG))
		return KSMBD_RPC_OK;
	if (pipe->request_method.alloc_hint > pipe->request.size)
		return KSMBD_RPC_EBAD_DATA;

	ret = rpc_invoke_request(pipe, req, resp, fragment);
	pipe->request_in_progress = 0;
	dcerpc_set_ext_payload(pipe->dce, NULL, 0);
	rpc_input_buffer_clear(&pipe->request);
	return ret;
}

static int rpc_pipe_write_request(struct ksmbd_rpc_pipe *pipe,
				  struct ksmbd_rpc_command *req,
				  struct ksmbd_rpc_command *resp)
{
	struct ksmbd_dcerpc fragment;
	size_t offset = 0, size;
	int ret = KSMBD_RPC_EBAD_DATA;

	if (!pipe || pipe->retired || !pipe->dce)
		return KSMBD_RPC_EBAD_FID;
	if (pipe->dce->flags & KSMBD_DCERPC_RETURN_READY)
		return KSMBD_RPC_EBAD_DATA;

	while (offset < req->payload_sz) {
		if (pipe->fragment.size < sizeof(struct dcerpc_header)) {
			size = MIN(req->payload_sz - offset,
				sizeof(struct dcerpc_header) - pipe->fragment.size);
			ret = rpc_input_buffer_append(&pipe->fragment,
				req->payload + offset, size, pipe->max_recv_frag_sz);
			if (ret)
				goto fail;
			offset += size;
			if (pipe->fragment.size < sizeof(struct dcerpc_header))
				return KSMBD_RPC_OK;
		}
		memset(&fragment, 0, sizeof(fragment));
		fragment.flags = KSMBD_DCERPC_ALIGN4;
		dcerpc_set_ext_payload(&fragment, pipe->fragment.data,
				       pipe->fragment.size);
		if (dcerpc_hdr_read(&fragment, &fragment.hdr) ||
		    fragment.hdr.frag_length > pipe->max_recv_frag_sz)
			goto bad_data;
		size = MIN(req->payload_sz - offset,
			fragment.hdr.frag_length - pipe->fragment.size);
		ret = rpc_input_buffer_append(&pipe->fragment,
			req->payload + offset, size, pipe->max_recv_frag_sz);
		if (ret)
			goto fail;
		offset += size;
		if (pipe->fragment.size < fragment.hdr.frag_length)
			return KSMBD_RPC_OK;
		fragment.payload = pipe->fragment.data;
		fragment.payload_sz = pipe->fragment.size;
		ret = rpc_process_fragment(pipe, req, resp, &fragment);
		pipe->fragment.size = 0;
		if (ret)
			goto fail;
		if (pipe->dce->flags & KSMBD_DCERPC_RETURN_READY) {
			if (offset != req->payload_sz)
				goto bad_data;
			return KSMBD_RPC_OK;
		}
	}
	if (req->payload_sz)
		return KSMBD_RPC_OK;
bad_data:
	ret = KSMBD_RPC_EBAD_DATA;
fail:
	return rpc_write_request_fail(pipe, ret);
}

int rpc_write_request(struct ksmbd_rpc_command *req,
		      struct ksmbd_rpc_command *resp)
{
	struct ksmbd_rpc_pipe *pipe;
	int ret;

	pipe = rpc_pipe_lookup(req->handle);
	if (!pipe)
		return KSMBD_RPC_EBAD_FID;

	g_mutex_lock(&pipe->op_lock);
	ret = rpc_pipe_write_request(pipe, req, resp);
	g_mutex_unlock(&pipe->op_lock);
	rpc_pipe_put(pipe);
	return ret;
}

int rpc_ioctl_request(struct ksmbd_rpc_command *req,
		      struct ksmbd_rpc_command *resp,
		      int max_resp_sz)
{
	struct ksmbd_rpc_pipe *pipe;
	int ret;

	pipe = rpc_pipe_lookup(req->handle);
	if (!pipe)
		return KSMBD_RPC_EBAD_FID;

	g_mutex_lock(&pipe->op_lock);
	ret = rpc_pipe_write_request(pipe, req, resp);
	if (ret == KSMBD_RPC_OK &&
	    (pipe->dce->flags & KSMBD_DCERPC_RETURN_READY))
		ret = rpc_pipe_read_request(pipe, req, resp, max_resp_sz);
	g_mutex_unlock(&pipe->op_lock);
	rpc_pipe_put(pipe);
	return ret;
}

int rpc_open_request(struct ksmbd_rpc_command *req,
		     struct ksmbd_rpc_command *resp)
{
	struct ksmbd_rpc_pipe *pipe;

	pipe = rpc_pipe_lookup(req->handle);
	if (pipe) {
		rpc_pipe_put(pipe);
		pr_err("RPC: pipe ID collision: %d\n", req->handle);
		return -EEXIST;
	}

	pipe = rpc_pipe_alloc_bind(req);
	if (!pipe)
		return -ENOMEM;
	return KSMBD_RPC_OK;
}

int rpc_close_request(struct ksmbd_rpc_command *req,
		      struct ksmbd_rpc_command *resp)
{
	struct ksmbd_rpc_pipe *pipe;

	pipe = rpc_pipe_lookup(req->handle);
	if (pipe) {
		g_mutex_lock(&pipe->op_lock);
		if (!pipe->retired) {
			unsigned int pipe_id = pipe->id;

			rpc_samr_pipe_close(pipe_id);
			rpc_lsarpc_pipe_close(pipe_id);
			rpc_pipe_cleanup_request(pipe);
			rpc_pipe_free(pipe);
		}
		g_mutex_unlock(&pipe->op_lock);
		rpc_pipe_put(pipe);
		return 0;
	}

	pr_err("RPC: unknown pipe ID: %d\n", req->handle);
	return KSMBD_RPC_OK;
}
