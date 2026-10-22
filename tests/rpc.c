// SPDX-License-Identifier: GPL-2.0-or-later
#include <endian.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <glib.h>

#include "linux/ksmbd_server.h"
#include "management/share.h"
#include "management/user.h"
#include "rpc.h"
#include "tools.h"

struct smbconf_global global_conf;
int log_level = -1;
static GPtrArray *users;
static GPtrArray *shares;
static unsigned int receive_limit;

void __pr_log(int level, const char *fmt, ...)
{
	(void)level;
	(void)fmt;
}

const char *get_tool_name(void)
{
	return "rpc-test";
}

gchar *ksmbd_gconvert(const gchar *str, gssize len, int to, int from,
		     gsize *read, gsize *written)
{
	const char *charsets[] = { "UTF-8", "UTF-16LE", "UCS-2LE",
				   "UTF-16BE", "UCS-2BE" };

	return g_convert(str, len, charsets[to], charsets[from], read, written,
			 NULL);
}

struct ksmbd_user *usm_lookup_uid(uid_t uid)
{
	unsigned int i;

	for (i = 0; i < users->len; i++) {
		struct ksmbd_user *user = g_ptr_array_index(users, i);

		if (user->uid == uid) {
			user->ref_count++;
			return user;
		}
	}
	return NULL;
}

struct ksmbd_user *usm_lookup_user_casefold(const char *name)
{
	unsigned int i;

	for (i = 0; name && i < users->len; i++) {
		struct ksmbd_user *user = g_ptr_array_index(users, i);

		if (!g_ascii_strcasecmp(user->name, name))
			return usm_lookup_uid(user->uid);
	}
	return NULL;
}

void put_ksmbd_user(struct ksmbd_user *user)
{
	if (user) {
		g_assert_cmpint(user->ref_count, >, 0);
		user->ref_count--;
	}
}

void usm_iter_users(user_cb cb, void *data)
{
	unsigned int i;

	for (i = 0; i < users->len; i++)
		cb(g_ptr_array_index(users, i), data);
}

struct ksmbd_share *get_ksmbd_share(struct ksmbd_share *share)
{
	if (share)
		share->ref_count++;
	return share;
}

void put_ksmbd_share(struct ksmbd_share *share)
{
	if (share) {
		g_assert_cmpint(share->ref_count, >, 0);
		share->ref_count--;
	}
}

struct ksmbd_share *shm_lookup_share(char *name)
{
	unsigned int i;

	for (i = 0; name && i < shares->len; i++) {
		struct ksmbd_share *share = g_ptr_array_index(shares, i);

		if (!g_ascii_strcasecmp(name, share->name))
			return get_ksmbd_share(share);
	}
	return NULL;
}

void shm_iter_shares(share_cb cb, void *data)
{
	unsigned int i;

	for (i = 0; i < shares->len; i++)
		cb(g_ptr_array_index(shares, i), data);
}

unsigned int sm_session_count(void)
{
	return 0;
}

static void pad_buffer(GByteArray *buf, unsigned int alignment)
{
	static const guint8 zero[8];

	g_byte_array_append(buf, zero, (alignment - buf->len % alignment) % alignment);
}

static void put16(GByteArray *buf, uint16_t value)
{
	pad_buffer(buf, 2);
	value = htole16(value);
	g_byte_array_append(buf, (void *)&value, sizeof(value));
}

static void put32(GByteArray *buf, uint32_t value)
{
	pad_buffer(buf, 4);
	value = htole32(value);
	g_byte_array_append(buf, (void *)&value, sizeof(value));
}

static uint32_t get32(const void *data)
{
	uint32_t value;

	memcpy(&value, data, sizeof(value));
	return le32toh(value);
}

static struct ksmbd_rpc_command *command(unsigned int id, unsigned int flags,
					 size_t size)
{
	struct ksmbd_rpc_command *cmd = g_malloc0(sizeof(*cmd) + size);

	cmd->handle = id;
	cmd->flags = flags;
	cmd->payload_sz = size;
	return cmd;
}

/* Build the wire requests independently of the production NDR writers. */
static struct ksmbd_rpc_command *request(unsigned int id, unsigned int flags,
					 unsigned int opnum, GByteArray *stub)
{
	const unsigned char header[] = { 5, 0, 0, 3, 0x10, 0, 0, 0 };
	GByteArray *buf = g_byte_array_new();
	struct ksmbd_rpc_command *req;

	g_assert_cmpuint(stub->len + 24, <=, UINT16_MAX);
	g_byte_array_append(buf, header, sizeof(header));
	put16(buf, stub->len + 24);
	put16(buf, 0);
	put32(buf, 1);
	put32(buf, stub->len);
	put16(buf, 0);
	put16(buf, opnum);
	g_byte_array_append(buf, stub->data, stub->len);
	req = command(id, flags | KSMBD_RPC_IOCTL_METHOD, buf->len);
	memcpy(req->payload, buf->data, buf->len);
	g_byte_array_unref(buf);
	return req;
}

static void open_pipe(unsigned int id, unsigned int flags, unsigned int last,
		      unsigned int version)
{
	const unsigned char ndr_syntax[] = {
		0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
		2, 0, 0, 0
	};
	unsigned char syntax[] = {
		0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab,
		0xef, 0, 1, 0x23, 0x45, 0x67, 0x89, 0,
		0, 0, 0, 0
	};
	struct ksmbd_rpc_command *req = command(id, flags, 0);
	struct ksmbd_rpc_command *resp = command(id, flags, 1024);
	GByteArray *stub = g_byte_array_new();

	g_assert_cmpint(rpc_open_request(req, resp), ==, KSMBD_RPC_OK);
	g_free(req);
	/* The request helper supplies the eight-byte bind prefix too. */
	put32(stub, 1);
	put16(stub, 0);
	put16(stub, 1);
	syntax[15] = last;
	syntax[16] = version;
	if (flags & KSMBD_RPC_SRVSVC_METHOD_INVOKE) {
		const guint8 srvsvc[] = {
			0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
			0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88, 3, 0, 0, 0
		};

		memcpy(syntax, srvsvc, sizeof(syntax));
	}
	g_byte_array_append(stub, syntax, sizeof(syntax));
	g_byte_array_append(stub, ndr_syntax, sizeof(ndr_syntax));
	req = request(id, flags, 0, stub);
	req->payload[2] = DCERPC_PTYPE_RPC_BIND;
	/* max_xmit_frag, max_recv_frag, assoc_group_id */
	req->payload[16] = req->payload[17] = 0xff;
	req->payload[18] = receive_limit & 0xff;
	req->payload[19] = receive_limit >> 8;
	req->payload[20] = 0;
	req->payload[24] = 1;
	req->payload[27] = 0;
	g_assert_cmpint(rpc_ioctl_request(req, resp, 1024), ==, KSMBD_RPC_OK);
	g_assert_cmpint(resp->payload[2], ==, DCERPC_PTYPE_RPC_BINDACK);
	g_assert_cmpuint(get32(resp->payload + 16) >> 16, ==, 4096);
	g_assert_cmpuint(get32(resp->payload + 16) & 0xffff, ==, receive_limit);
	g_assert_cmpuint(get32(resp->payload + 44), ==, 0);
	g_byte_array_unref(stub);
	g_free(req);
	g_free(resp);
}

static GByteArray *read_response(struct ksmbd_rpc_command *req,
				 struct ksmbd_rpc_command *resp,
				 int ret, size_t capacity)
{
	GByteArray *result = g_byte_array_new();
	unsigned int fragments = 0;
	size_t total = 0;
	for (;;) {
		g_assert_cmpint(ret, ==, KSMBD_RPC_OK);
		g_assert_cmpuint(resp->payload_sz, >=, 24);
		g_assert_cmpuint(resp->payload_sz, <=, capacity);
		g_assert_cmpuint(resp->payload_sz, <=, receive_limit);
		g_assert_cmpint(resp->payload[2], ==, DCERPC_PTYPE_RPC_RESPONSE);
		g_assert_cmpint(!!(resp->payload[3] & DCERPC_PFC_FIRST_FRAG),
			       ==, fragments == 0);
		if (!fragments)
			total = get32(resp->payload + 16);
		g_assert_cmpuint(get32(resp->payload + 16), ==, total - result->len);
		g_byte_array_append(result, (void *)(resp->payload + 24),
				    resp->payload_sz - 24);
		if (resp->payload[3] & DCERPC_PFC_LAST_FRAG)
			break;
		g_assert_cmpuint(resp->payload_sz - 24, >, 0);
		g_assert_cmpuint((resp->payload_sz - 24) % 8, ==, 0);
		g_assert_cmpuint(++fragments, <, 100000);
		ret = rpc_read_request(req, resp, capacity);
	}
	g_assert_cmpuint(result->len, ==, total);
	return result;
}

static GByteArray *exchange(unsigned int id, unsigned int flags,
			    unsigned int opnum, GByteArray *stub,
			    size_t capacity)
{
	struct ksmbd_rpc_command *req = NULL;
	struct ksmbd_rpc_command *resp = command(id, flags, capacity);
	GByteArray *part = g_byte_array_new(), *result;
	size_t offset = 0, size;
	__u32 hint;
	int ret;

	do {
		g_byte_array_set_size(part, 0);
		size = MIN(stub->len - offset,
			(size_t)(KSMBD_RPC_MAX_FRAGMENT_SIZE - 24) & ~(size_t)7);
		if (size)
			g_byte_array_append(part, stub->data + offset, size);
		g_free(req);
		req = request(id, flags, opnum, part);
		req->payload[3] = offset ? 0 : DCERPC_PFC_FIRST_FRAG;
		if (offset + size == stub->len)
			req->payload[3] |= DCERPC_PFC_LAST_FRAG;
		hint = htole32(stub->len - offset);
		memcpy(req->payload + 16, &hint, sizeof(hint));
		resp->payload_sz = 0;
		if (offset + size == stub->len) {
			ret = rpc_ioctl_request(req, resp, capacity);
		} else {
			req->flags = flags | KSMBD_RPC_WRITE_METHOD;
			ret = rpc_write_request(req, resp);
			g_assert_cmpint(ret, ==, KSMBD_RPC_OK);
			g_assert_cmpuint(resp->payload_sz, ==, 0);
		}
		offset += size;
	} while (offset < stub->len);
	result = read_response(req, resp, ret, capacity);
	g_byte_array_unref(part);
	g_free(req);
	g_free(resp);
	return result;
}

static void fixture_init(void)
{
	unsigned int i;

	memset(&global_conf, 0, sizeof(global_conf));
	global_conf.netbios_name = "SERVER";
	global_conf.work_group = "WORKGROUP";
	global_conf.gen_subauth[0] = 1;
	global_conf.gen_subauth[1] = 2;
	global_conf.gen_subauth[2] = 3;
	users = g_ptr_array_new();
	shares = g_ptr_array_new();
	receive_limit = UINT16_MAX;
	for (i = 0; i < 1000; i++) {
		struct ksmbd_user *user = g_new0(struct ksmbd_user, 1);

		user->uid = 1000 + i;
		user->name = g_strdup_printf("user-%04u-abcdefghijklmnopqrstuvwxyz", i);
		g_ptr_array_add(users, user);
	}
	for (i = 0; i < 3; i++) {
		struct ksmbd_share *share = g_new0(struct ksmbd_share, 1);

		share->name = g_strdup_printf("share%u", i);
		share->comment = g_strdup("공유");
		share->path = g_strdup("/srv/share");
		share->flags = KSMBD_SHARE_FLAG_BROWSEABLE | KSMBD_SHARE_FLAG_AVAILABLE;
		g_ptr_array_add(shares, share);
	}
	rpc_init();
}

static void fixture_destroy(void)
{
	unsigned int i;

	rpc_destroy();
	for (i = 0; i < users->len; i++) {
		struct ksmbd_user *user = g_ptr_array_index(users, i);

		g_assert_cmpint(user->ref_count, ==, 0);
		g_free(user->name);
		g_free(user);
	}
	g_ptr_array_free(users, TRUE);
	for (i = 0; i < shares->len; i++) {
		struct ksmbd_share *share = g_ptr_array_index(shares, i);

		g_assert_cmpint(share->ref_count, ==, 0);
		g_free(share->name);
		g_free(share->comment);
		g_free(share->path);
		g_free(share);
	}
	g_ptr_array_free(shares, TRUE);
}

static void test_samr_invalid_handle(void)
{
	GByteArray *stub = g_byte_array_new();
	GByteArray *result;

	fixture_init();
	open_pipe(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 0xac, 1);
	g_byte_array_set_size(stub, 20);
	memset(stub->data, 0, stub->len);
	put32(stub, 0);
	put32(stub, UINT32_MAX);
	result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 6, stub, 128);
	g_assert_cmpuint(get32(result->data + result->len - 4), ==,
			 KSMBD_NT_STATUS_INVALID_HANDLE);
	g_byte_array_unref(result);
	g_byte_array_unref(stub);
	fixture_destroy();
}

static void test_lsarpc_invalid_handle(void)
{
	GByteArray *stub = g_byte_array_new();
	GByteArray *result;

	fixture_init();
	open_pipe(1, KSMBD_RPC_LSARPC_METHOD_INVOKE, 0xab, 0);
	g_byte_array_set_size(stub, 20);
	memset(stub->data, 0, stub->len);
	put16(stub, 5);
	result = exchange(1, KSMBD_RPC_LSARPC_METHOD_INVOKE, 7, stub, 128);
	g_assert_cmpuint(get32(result->data + result->len - 4), ==,
			 KSMBD_NT_STATUS_INVALID_HANDLE);
	g_byte_array_unref(result);
	g_byte_array_unref(stub);
	fixture_destroy();
}

static void test_samr_fragmentation(void)
{
	unsigned int flags = KSMBD_RPC_SAMR_METHOD_INVOKE;
	unsigned char handle[20];
	const unsigned char sid[] = {
		1, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0,
		1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0
	};
	GByteArray *stub = g_byte_array_new();
	GByteArray *result, *other;

	fixture_init();
	receive_limit = 257;
	open_pipe(1, flags, 0xac, 1);
	put32(stub, 0);
	put32(stub, 0x02000000); /* MAXIMUM_ALLOWED */
	put32(stub, 1);
	put32(stub, 1);
	put32(stub, 3);
	put32(stub, 0);
	result = exchange(1, flags, 64, stub, 128);
	g_assert_cmpuint(result->len, ==, 40);
	memcpy(handle, result->data + 16, sizeof(handle));
	g_byte_array_unref(result);
	g_byte_array_set_size(stub, 0);
	g_byte_array_append(stub, handle, sizeof(handle));
	put32(stub, 0x02000000);
	put32(stub, 4);
	g_byte_array_append(stub, sid, sizeof(sid));
	result = exchange(1, flags, 7, stub, 128);
	g_assert_cmpuint(result->len, ==, 24);
	memcpy(handle, result->data, sizeof(handle));
	g_byte_array_unref(result);
	g_byte_array_set_size(stub, 0);
	g_byte_array_append(stub, handle, sizeof(handle));
	put32(stub, 0);
	put32(stub, 0);
	put32(stub, UINT32_MAX);
	result = exchange(1, flags, 13, stub, 301);
	other = exchange(1, flags, 13, stub, 4096);
	g_assert_cmpmem(result->data, result->len, other->data, other->len);
	g_assert_cmpuint(result->len, >, UINT16_MAX);
	g_assert_cmpuint(get32(result->data), ==, users->len);
	g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0);
	g_byte_array_unref(result);
	g_byte_array_unref(other);
	g_byte_array_unref(stub);
	fixture_destroy();
}

static GByteArray *open_policy(void)
{
	const char *server = "\\\\192.0.2.1";
	GByteArray *stub = g_byte_array_new();
	GByteArray *result;
	unsigned int i;

	put32(stub, 1);
	put32(stub, strlen(server) + 1);
	put32(stub, 0);
	put32(stub, strlen(server) + 1);
	for (i = 0; i <= strlen(server); i++)
		put16(stub, server[i]);
	while (stub->len % 4)
		g_byte_array_append(stub, (const guint8 *)"", 1);
	put32(stub, 24);
	for (i = 0; i < 5; i++)
		put32(stub, 0);
	put32(stub, 0x02000000);
	result = exchange(1, KSMBD_RPC_LSARPC_METHOD_INVOKE, 44, stub, 128);
	g_assert_cmpuint(result->len, ==, 24);
	g_assert_cmpuint(get32(result->data + 20), ==, 0);
	g_byte_array_unref(stub);
	return result;
}

static void test_lsarpc_fragmentation(void)
{
	unsigned int flags = KSMBD_RPC_LSARPC_METHOD_INVOKE;
	const unsigned char sid[] = {
		1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0,
		1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xe8, 3, 0, 0
	};
	GByteArray *stub = g_byte_array_new();
	GByteArray *policy, *result, *other;
	unsigned int i;

	fixture_init();
	receive_limit = 257;
	open_pipe(1, flags, 0xab, 0);
	policy = open_policy();
	g_byte_array_append(stub, policy->data, 20);
	put32(stub, 300);
	put32(stub, 1);
	put32(stub, 300);
	for (i = 0; i < 300; i++)
		put32(stub, i + 2);
	for (i = 0; i < 300; i++) {
		put32(stub, 5);
		g_byte_array_append(stub, sid, sizeof(sid));
	}
	put32(stub, 0);
	put32(stub, 0);
	put16(stub, 1);
	put16(stub, 0);
	put32(stub, 0);
	/* Exercise the legacy and versioned lookup tails. */
	for (i = 0; i < 2; i++) {
		unsigned int opnum = i ? 57 : 15;

		if (i) {
			put32(stub, 0);
			put32(stub, 1);
		}
		result = exchange(1, flags, opnum, stub, 301);
		other = exchange(1, flags, opnum, stub, 4096);
		g_assert_cmpmem(result->data, result->len, other->data, other->len);
		g_assert_cmpuint(result->len, >, 16 * 1024);
		g_assert_cmpuint(get32(result->data + result->len - 8), ==, 300);
		g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0);
		g_byte_array_unref(result);
		g_byte_array_unref(other);
	}
	g_byte_array_unref(policy);
	g_byte_array_unref(stub);
	fixture_destroy();
}

static void test_read_without_request(void)
{
	struct ksmbd_rpc_command *req = command(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 0);
	struct ksmbd_rpc_command *resp = command(1, 0, 128);

	fixture_init();
	open_pipe(1, req->flags, 0xac, 1);
	g_assert_cmpint(rpc_read_request(req, resp, 128), ==, KSMBD_RPC_EBAD_DATA);
	g_assert_cmpuint(resp->payload_sz, ==, 128);
	g_free(req);
	g_free(resp);
	fixture_destroy();
}

static void test_policy_handle_lifetime(void)
{
	unsigned int flags = KSMBD_RPC_LSARPC_METHOD_INVOKE;
	struct ksmbd_rpc_command *close_req = command(1, flags, 0);
	struct ksmbd_rpc_command *close_resp = command(1, flags, 0);
	GByteArray *stub = g_byte_array_new();
	GByteArray *policy, *result;

	fixture_init();
	open_pipe(1, flags, 0xab, 0);
	policy = open_policy();
	g_byte_array_append(stub, policy->data, 20);
	put16(stub, 5);
	open_pipe(2, flags, 0xab, 0);
	result = exchange(2, flags, 7, stub, 128);
	g_assert_cmpuint(get32(result->data + result->len - 4), ==,
			 KSMBD_NT_STATUS_INVALID_HANDLE);
	g_byte_array_unref(result);
	g_assert_cmpint(rpc_close_request(close_req, close_resp), ==, 0);
	open_pipe(1, flags, 0xab, 0);
	result = exchange(1, flags, 7, stub, 128);
	g_assert_cmpuint(get32(result->data + result->len - 4), ==,
			 KSMBD_NT_STATUS_INVALID_HANDLE);
	g_byte_array_unref(result);
	g_byte_array_unref(policy);
	g_byte_array_unref(stub);
	g_free(close_req);
	g_free(close_resp);
	fixture_destroy();
}

static void test_unaligned_scalars(void)
{
	union {
		uint64_t alignment;
		char bytes[32];
	} storage = { 0 };
	struct ksmbd_dcerpc dce = {
		.payload = storage.bytes + 1,
		.payload_sz = sizeof(storage.bytes) - 1,
	};
	__u16 value16;
	__u32 value32;
	__u64 value64;
	unsigned int i;

	for (i = 0; i < 2; i++) {
		dce.flags = KSMBD_DCERPC_FIXED_PAYLOAD_SZ |
			(i ? KSMBD_DCERPC_LITTLE_ENDIAN : 0);
		dce.offset = 0;
		g_assert_cmpint(ndr_write_int16(&dce, 0x1234), ==, 0);
		g_assert_cmpint(ndr_write_int32(&dce, 0x12345678), ==, 0);
		g_assert_cmpint(ndr_write_int64(&dce, 0x123456789abcdef0ULL), ==, 0);
		dce.offset = 0;
		g_assert_cmpint(ndr_read_int16(&dce, &value16), ==, 0);
		g_assert_cmpint(ndr_read_int32(&dce, &value32), ==, 0);
		g_assert_cmpint(ndr_read_int64(&dce, &value64), ==, 0);
		g_assert_cmpuint(value16, ==, 0x1234);
		g_assert_cmpuint(value32, ==, 0x12345678);
		g_assert_true(value64 == 0x123456789abcdef0ULL);
	}
}

static GByteArray *policy_attributes(unsigned int all)
{
	const guint8 sid[] = { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };
	const guint8 acl[] = { 2, 0, 8, 0, 0, 0, 0, 0 };
	const guint8 security[] = { 1, 0, 0x14, 0 };
	GByteArray *stub = g_byte_array_new();
	unsigned int i;

	put32(stub, 0); /* NULL SystemName for both OpenPolicy variants. */
	put32(stub, 1); /* Length is ignored. */
	put32(stub, 0);
	put32(stub, all ? 1 : 0);
	put32(stub, UINT32_MAX);
	put32(stub, all ? 2 : 0);
	put32(stub, 3);
	if (all) {
		put16(stub, 3);
		put16(stub, 5);
		put32(stub, 4);
		put32(stub, 5);
		put32(stub, 0);
		put32(stub, 3);
		g_byte_array_append(stub, (const guint8 *)"abc", 3);
		pad_buffer(stub, 4);
		g_byte_array_append(stub, security, sizeof(security));
		for (i = 0; i < 4; i++)
			put32(stub, 5 + i);
		for (i = 0; i < 2; i++) {
			put32(stub, 1);
			g_byte_array_append(stub, sid, sizeof(sid));
		}
		for (i = 0; i < 2; i++) {
			put32(stub, sizeof(acl) - 4);
			g_byte_array_append(stub, acl, sizeof(acl));
		}
	}
	put32(stub, 12);
	put16(stub, 2);
	g_byte_array_append(stub, (const guint8 *)"\0\1", 2);
	put32(stub, 0x00000800);
	return stub;
}

static void test_policy_attributes(void)
{
	unsigned int flags = KSMBD_RPC_LSARPC_METHOD_INVOKE;
	unsigned int opnum, all, length;
	GByteArray *stub, *result;

	fixture_init();
	open_pipe(1, flags, 0xab, 0);
	for (opnum = 6; opnum <= 44; opnum += 38) {
		for (all = 0; all < 2; all++) {
			stub = policy_attributes(all);
			result = exchange(1, flags, opnum, stub, 128);
			g_assert_cmpuint(get32(result->data + 20), ==, 0);
			g_byte_array_unref(result);
			for (length = 0; length < stub->len; length++) {
				GByteArray partial = { .data = stub->data, .len = length };

				result = exchange(1, flags, opnum, &partial, 128);
				g_assert_cmpuint(get32(result->data + 20), ==,
						 KSMBD_NT_STATUS_INVALID_PARAMETER);
				g_byte_array_unref(result);
			}
			stub->data[8] = 1; /* RootDirectory must be NULL. */
			result = exchange(1, flags, opnum, stub, 128);
			g_assert_cmpuint(get32(result->data + 20), ==,
					 KSMBD_NT_STATUS_INVALID_PARAMETER);
			g_byte_array_unref(result);
			g_byte_array_unref(stub);
		}
	}
	fixture_destroy();
}

static GByteArray *share_enum(unsigned int level, unsigned int size,
			     unsigned int resume)
{
	GByteArray *stub = g_byte_array_new();
	GByteArray *result;

	put32(stub, 0);
	put32(stub, level);
	put32(stub, level);
	put32(stub, 1);
	put32(stub, 0);
	put32(stub, 0);
	put32(stub, size);
	put32(stub, 2);
	put32(stub, resume);
	result = exchange(1, KSMBD_RPC_SRVSVC_METHOD_INVOKE, 15, stub, 4096);
	g_byte_array_unref(stub);
	return result;
}

static void test_share_enum_limits(void)
{
	const unsigned int levels[] = { 0, 1, 2, 502 };
	GByteArray *result;
	unsigned int i, j, entry_size;

	fixture_init();
	open_pipe(1, KSMBD_RPC_SRVSVC_METHOD_INVOKE, 0, 3);
	for (i = 0; i < G_N_ELEMENTS(levels); i++) {
		result = share_enum(levels[i], UINT32_MAX, 0);
		g_assert_cmpuint(get32(result->data + 12), ==, 3);
		entry_size = (result->len - 40) / 3;
		g_assert_cmpuint(result->len, ==, 40 + entry_size * 3);
		g_byte_array_unref(result);
		for (j = 0; j < 3; j++) {
			unsigned int size = j == 2 ? 12 + entry_size - 1 : j;

			result = share_enum(levels[i], size, 0);
			g_assert_cmpuint(get32(result->data + 12), ==, 0);
			g_assert_cmpuint(get32(result->data + result->len - 16), ==, 3);
			g_assert_cmpuint(get32(result->data + result->len - 8), ==, 0);
			g_assert_cmpuint(get32(result->data + result->len - 4), ==,
					 KSMBD_RPC_EMORE_DATA);
			g_byte_array_unref(result);
		}
		for (j = 0; j < 3; j++) {
			result = share_enum(levels[i], 12 + entry_size, j);
			g_assert_cmpuint(get32(result->data + 12), ==, 1);
			g_assert_cmpuint(result->len - 28, ==, 12 + entry_size);
			g_assert_cmpuint(get32(result->data + result->len - 16), ==, 3 - j);
			g_assert_cmpuint(get32(result->data + result->len - 8), ==,
					 j == 2 ? 0 : j + 1);
			g_assert_cmpuint(get32(result->data + result->len - 4), ==,
					 j == 2 ? 0 : KSMBD_RPC_EMORE_DATA);
			g_byte_array_unref(result);
		}
		for (j = 0; j < 3; j++) {
			result = share_enum(levels[i], UINT32_MAX, j == 2 ? UINT32_MAX : j + 3);
			g_assert_cmpuint(get32(result->data + 12), ==, 0);
			g_assert_cmpuint(get32(result->data + result->len - 16), ==, 0);
			g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0);
			g_byte_array_unref(result);
		}
	}
	fixture_destroy();
}

static GByteArray *connect_stub(void)
{
	const unsigned int values[] = { 0, 0x02000000, 1, 1, 3, 0 };
	GByteArray *stub = g_byte_array_new();
	unsigned int i;

	for (i = 0; i < G_N_ELEMENTS(values); i++)
		put32(stub, values[i]);
	return stub;
}

static struct ksmbd_rpc_command *request_part(GByteArray *stub, unsigned int offset,
					      unsigned int size, unsigned int bits)
{
	GByteArray part = { .data = stub->data + offset, .len = size };
	struct ksmbd_rpc_command *req = request(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 64, &part);
	__u32 hint = htole32(stub->len - offset);

	req->payload[3] = bits;
	memcpy(req->payload + 16, &hint, sizeof(hint));
	return req;
}

static void test_request_fragments(void)
{
	unsigned int flags = KSMBD_RPC_SAMR_METHOD_INVOKE;
	struct ksmbd_rpc_command *first, *last, *resp = command(1, flags, 128);
	GByteArray *stub = connect_stub(), *result;
	unsigned int i;
	int ret;

	fixture_init();
	open_pipe(1, flags, 0xac, 1);
	for (i = 0; i < 7; i++) {
		first = request_part(stub, 0, 8, DCERPC_PFC_FIRST_FRAG);
		last = request_part(stub, 8, 16, DCERPC_PFC_LAST_FRAG);
		g_assert_cmpint(rpc_write_request(first, resp), ==, 0);
		g_assert_cmpint(rpc_read_request(first, resp, 128), ==, KSMBD_RPC_EBAD_DATA);
		switch (i) {
		case 0:
			last->payload[12] ^= 1;
			break;
		case 1:
			last->payload[22] ^= 1;
			break;
		case 2:
			last->payload[20] = 1;
			break;
		case 3:
			last->payload[4] = 0;
			last->payload[8] = 0;
			last->payload[9] = last->payload_sz;
			memset(last->payload + 12, 0, 12);
			last->payload[15] = 1;
			last->payload[19] = 16;
			last->payload[23] = 64;
			break;
		case 4:
			last->payload[3] |= DCERPC_PFC_FIRST_FRAG;
			break;
		case 5:
			last->flags ^= flags | KSMBD_RPC_LSARPC_METHOD_INVOKE;
			break;
		case 6:
			last->flags |= KSMBD_RPC_RESTRICTED_CONTEXT;
			break;
		}
		g_assert_cmpint(rpc_write_request(last, resp), ==, KSMBD_RPC_EBAD_DATA);
		result = exchange(1, flags, 64, stub, 128);
		g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0);
		g_byte_array_unref(result);
		g_free(first);
		g_free(last);
	}
	first = request_part(stub, 0, 8, DCERPC_PFC_FIRST_FRAG);
	last = request_part(stub, 8, 16, DCERPC_PFC_LAST_FRAG);
	g_assert_cmpint(rpc_write_request(last, resp), ==, KSMBD_RPC_EBAD_DATA);
	/* Two complete fragments can arrive in one SMB write. */
	result = g_byte_array_new();
	g_byte_array_append(result, (void *)first->payload, first->payload_sz);
	g_byte_array_append(result, (void *)last->payload, last->payload_sz);
	g_free(first);
	first = command(1, flags | KSMBD_RPC_WRITE_METHOD, result->len);
	memcpy(first->payload, result->data, result->len);
	g_assert_cmpint(rpc_write_request(first, resp), ==, 0);
	ret = rpc_read_request(first, resp, 128);
	g_byte_array_unref(result);
	result = read_response(first, resp, ret, 128);
	g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0);
	g_byte_array_unref(result);
	g_free(first);
	g_free(last);
	g_free(resp);
	g_byte_array_unref(stub);
	fixture_destroy();
}

static void test_request_stream(void)
{
	unsigned int flags = KSMBD_RPC_SAMR_METHOD_INVOKE;
	const unsigned int splits[] = { 1, 3, 8, 15, 16, 23, 31 };
	struct ksmbd_rpc_command *req, *tail, *resp = command(1, flags, 128);
	GByteArray *stub = connect_stub(), *result;
	unsigned int i, length;
	int ret;

	fixture_init();
	open_pipe(1, flags, 0xac, 1);
	for (i = 0; i < G_N_ELEMENTS(splits); i++) {
		req = request(1, flags, 64, stub);
		length = req->payload_sz;
		req->payload_sz = splits[i];
		g_assert_cmpint(rpc_write_request(req, resp), ==, 0);
		g_assert_cmpint(rpc_read_request(req, resp, 128), ==, KSMBD_RPC_EBAD_DATA);
		tail = command(1, flags | KSMBD_RPC_IOCTL_METHOD, length - splits[i]);
		memcpy(tail->payload, req->payload + splits[i], tail->payload_sz);
		ret = rpc_ioctl_request(tail, resp, 128);
		result = read_response(tail, resp, ret, 128);
		g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0);
		g_byte_array_unref(result);
		g_free(req);
		g_free(tail);
	}
	g_free(resp);
	g_byte_array_unref(stub);
	fixture_destroy();
}

static void test_request_size_limit(void)
{
	unsigned int flags = KSMBD_RPC_SAMR_METHOD_INVOKE;
	struct ksmbd_rpc_command *req, *resp = command(1, flags, 128);
	GByteArray *stub = g_byte_array_new(), *result;
	size_t total = 0;
	int ret;

	fixture_init();
	open_pipe(1, flags, 0xac, 1);
	g_byte_array_set_size(stub, KSMBD_RPC_MAX_FRAGMENT_SIZE - 24);
	memset(stub->data, 0, stub->len);
	req = request(1, flags, 64, stub);
	memset(req->payload + 16, 0, 4); /* An alloc_hint of zero is valid. */
	do {
		req->payload[3] = total ? 0 : DCERPC_PFC_FIRST_FRAG;
		ret = rpc_write_request(req, resp);
		total += stub->len;
	} while (ret == 0 && total <= KSMBD_RPC_MAX_REQUEST_SIZE);
	g_assert_cmpint(ret, ==, KSMBD_RPC_EBAD_DATA);
	g_assert_cmpuint(total, >, KSMBD_RPC_MAX_REQUEST_SIZE);
	g_free(req);
	g_byte_array_unref(stub);
	stub = connect_stub();
	result = exchange(1, flags, 64, stub, 128);
	g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0);
	g_byte_array_unref(result);
	g_byte_array_unref(stub);
	g_free(resp);
	fixture_destroy();
}

static void test_full_sid_range(void)
{
	unsigned int flags = KSMBD_RPC_LSARPC_METHOD_INVOKE;
	const guint8 sid[68] = { 1, 15, 0, 0, 0, 0, 0, 5 };
	GByteArray *stub = g_byte_array_new(), *policy, *result;
	unsigned int i, version;

	fixture_init();
	open_pipe(1, flags, 0xab, 0);
	policy = open_policy();
	g_byte_array_append(stub, policy->data, 20);
	put32(stub, 20480);
	put32(stub, 1);
	put32(stub, 20480);
	for (i = 0; i < 20480; i++)
		put32(stub, i + 2);
	for (i = 0; i < 20480; i++) {
		put32(stub, 15);
		g_byte_array_append(stub, sid, sizeof(sid));
	}
	put32(stub, 0);
	put32(stub, 0);
	put16(stub, 1);
	put32(stub, 0);
	g_assert_cmpuint(stub->len, >, 1024 * 1024);
	for (version = 0; version < 2; version++) {
		if (version) {
			put32(stub, 0);
			put32(stub, 1);
		}
		result = exchange(1, flags, version ? 57 : 15, stub, 4096);
		g_assert_cmpuint(get32(result->data + 4), ==, 20480);
		g_assert_cmpuint(result->len, ==, 24 + 20480 * (version ? 20 : 16));
		g_assert_cmpuint(get32(result->data + result->len - 8), ==, 0);
		g_assert_cmpuint(get32(result->data + result->len - 4), ==,
				 KSMBD_NT_STATUS_NONE_MAPPED);
		g_byte_array_unref(result);
	}
	g_byte_array_unref(policy);
	g_byte_array_unref(stub);
	fixture_destroy();
}

static void test_request_bounds(void)
{
	unsigned int flags = KSMBD_RPC_SAMR_METHOD_INVOKE;
	struct ksmbd_rpc_command *req, *resp = command(1, flags, 128);
	GByteArray *stub = connect_stub(), *result;
	unsigned int i;
	__u32 hint;
	__u16 length;

	fixture_init();
	open_pipe(1, flags, 0xac, 1);
	for (i = 0; i < 6; i++) {
		req = request(1, flags, 64, stub);
		switch (i) {
		case 0:
			hint = htole32(KSMBD_RPC_MAX_REQUEST_SIZE + 1);
			memcpy(req->payload + 16, &hint, sizeof(hint));
			break;
		case 1:
			hint = htole32(stub->len + 1);
			memcpy(req->payload + 16, &hint, sizeof(hint));
			break;
		case 2:
			length = htole16(4097);
			memcpy(req->payload + 8, &length, sizeof(length));
			req->payload_sz = 16;
			break;
		case 3:
			req->payload[10] = 1;
			break;
		case 4:
		case 5:
			g_free(req);
			req = request_part(stub, 0, i == 4 ? 0 : 7,
					   DCERPC_PFC_FIRST_FRAG);
			break;
		}
		g_assert_cmpint(rpc_write_request(req, resp), ==, KSMBD_RPC_EBAD_DATA);
		g_free(req);
		result = exchange(1, flags, 64, stub, 128);
		g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0);
		g_byte_array_unref(result);
	}
	/* Closing a pipe also frees an incomplete request. */
	req = request_part(stub, 0, 8, DCERPC_PFC_FIRST_FRAG);
	g_assert_cmpint(rpc_write_request(req, resp), ==, 0);
	g_free(req);
	g_free(resp);
	g_byte_array_unref(stub);
	fixture_destroy();
}

/* Independent readers for the response types exercised below. */
struct wire_reader {
	const guint8 *data;
	size_t size;
	size_t offset;
};

static void wire_skip(struct wire_reader *wire, size_t size)
{
	g_assert_cmpuint(wire->offset, <=, wire->size);
	g_assert_cmpuint(size, <=, wire->size - wire->offset);
	wire->offset += size;
}

static void wire_align(struct wire_reader *wire, unsigned int alignment)
{
	wire_skip(wire, (alignment - wire->offset % alignment) % alignment);
}

static unsigned int wire16(struct wire_reader *wire)
{
	__u16 value;

	wire_align(wire, 2);
	wire_skip(wire, 2);
	memcpy(&value, wire->data + wire->offset - 2, 2);
	return le16toh(value);
}

static unsigned int wire32(struct wire_reader *wire)
{
	wire_align(wire, 4);
	wire_skip(wire, 4);
	return get32(wire->data + wire->offset - 4);
}

static char *wire_string(struct wire_reader *wire)
{
	unsigned int max = wire32(wire);
	unsigned int offset = wire32(wire);
	unsigned int actual = wire32(wire);
	char *value;

	g_assert_cmpuint(offset, ==, 0);
	g_assert_cmpuint(actual, <=, max);
	wire_skip(wire, (size_t)actual * 2);
	value = g_convert((const char *)wire->data + wire->offset - actual * 2,
			  actual * 2, "UTF-8", "UTF-16LE", NULL, NULL, NULL);
	g_assert_nonnull(value);
	wire_align(wire, 4);
	return value;
}

static GByteArray *samr_connect_handle(void)
{
	GByteArray *stub = connect_stub();
	GByteArray *result, *handle = g_byte_array_new();

	result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 64, stub, 128);
	g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0);
	g_byte_array_append(handle, result->data + 16, 20);
	g_byte_array_unref(result);
	g_byte_array_unref(stub);
	return handle;
}

static GByteArray *samr_open_domain(GByteArray *server, const guint8 *sid,
				    unsigned int length)
{
	GByteArray *stub = g_byte_array_new();
	GByteArray *result;

	g_byte_array_append(stub, server->data, 20);
	put32(stub, 0x02000000);
	put32(stub, sid[1]);
	g_byte_array_append(stub, sid, length);
	result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 7, stub, 128);
	g_assert_cmpuint(get32(result->data + 20), ==, 0);
	g_byte_array_unref(stub);
	return result;
}

static GByteArray *samr_open_account(GByteArray *domain, unsigned int opnum,
				     unsigned int rid)
{
	GByteArray *stub = g_byte_array_new();
	GByteArray *result;

	g_byte_array_append(stub, domain->data, 20);
	put32(stub, 0x02000000);
	put32(stub, rid);
	result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, opnum, stub, 128);
	g_byte_array_unref(stub);
	return result;
}

static const guint8 local_domain_sid[] = {
	1, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0,
	1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0
};
static void test_user_all_information(void)
{
	GByteArray *server, *domain, *user, *result, *stub = g_byte_array_new();
	struct wire_reader wire;
	unsigned int refs[13], lengths[13], sizes[13], i;

	fixture_init();
	receive_limit = 257;
	open_pipe(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 0xac, 1);
	server = samr_connect_handle();
	domain = samr_open_domain(server, local_domain_sid, sizeof(local_domain_sid));
	user = samr_open_account(domain, 34, 1000);
	g_assert_cmpuint(get32(user->data + 20), ==, 0);
	g_byte_array_append(stub, user->data, 20);
	put16(stub, 21);
	result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 36, stub, 128);
	wire = (struct wire_reader){ .data = result->data, .size = result->len };
	g_assert_cmpuint(wire32(&wire), !=, 0);
	g_assert_cmpuint(wire16(&wire), ==, 21);
	wire_align(&wire, 8);
	wire_skip(&wire, 6 * 8);
	for (i = 0; i < 13; i++) {
		lengths[i] = wire16(&wire);
		sizes[i] = wire16(&wire);
		refs[i] = wire32(&wire);
	}
	wire_skip(&wire, 8); /* SecurityDescriptor */
	g_assert_cmpuint(wire32(&wire), ==, 1000);
	wire_skip(&wire, 3 * 4); /* PrimaryGroupId, UserAccountControl, WhichFields */
	g_assert_cmpuint(wire16(&wire), ==, 168);
	g_assert_cmpuint(wire32(&wire), !=, 0); /* LogonHours pointer */
	wire_skip(&wire, 4 * 2 + 4);
	for (i = 0; i < 13; i++) {
		g_autofree char *value = NULL;

		if (!refs[i]) {
			g_assert_cmpuint(lengths[i], ==, 0);
			continue;
		}
		g_assert_cmpuint(get32(wire.data + wire.offset), ==, sizes[i] / 2);
		g_assert_cmpuint(get32(wire.data + wire.offset + 8), ==, lengths[i] / 2);
		value = wire_string(&wire);
		if (i < 2)
			g_assert_cmpstr(value, ==, ((struct ksmbd_user *)users->pdata[0])->name);
	}
	/* The maximum count is fixed by the IDL, independently of actual_count. */
	g_assert_cmpuint(wire32(&wire), ==, 1260);
	g_assert_cmpuint(wire32(&wire), ==, 0);
	g_assert_cmpuint(wire32(&wire), ==, 21);
	for (i = 0; i < 21; i++) {
		wire_skip(&wire, 1);
		g_assert_cmpuint(wire.data[wire.offset - 1], ==, 0xff);
	}
	g_assert_cmpuint(wire32(&wire), ==, 0);
	g_assert_cmpuint(wire.offset, ==, wire.size);
	g_byte_array_unref(stub);
	g_byte_array_unref(result);
	g_byte_array_unref(user);
	g_byte_array_unref(domain);
	g_byte_array_unref(server);
	fixture_destroy();
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/rpc/samr/invalid-handle", test_samr_invalid_handle);
	g_test_add_func("/rpc/lsarpc/invalid-handle", test_lsarpc_invalid_handle);
	g_test_add_func("/rpc/samr/fragmentation", test_samr_fragmentation);
	g_test_add_func("/rpc/lsarpc/fragmentation", test_lsarpc_fragmentation);
	g_test_add_func("/rpc/read-without-request", test_read_without_request);
	g_test_add_func("/rpc/lsarpc/handle-lifetime", test_policy_handle_lifetime);
	g_test_add_func("/rpc/ndr/unaligned-scalars", test_unaligned_scalars);
	g_test_add_func("/rpc/lsarpc/policy-attributes", test_policy_attributes);
	g_test_add_func("/rpc/srvsvc/enum-limits", test_share_enum_limits);
	g_test_add_func("/rpc/input/fragments", test_request_fragments);
	g_test_add_func("/rpc/input/stream", test_request_stream);
	g_test_add_func("/rpc/input/size-limit", test_request_size_limit);
	g_test_add_func("/rpc/input/bounds", test_request_bounds);
	g_test_add_func("/rpc/lsarpc/full-sid-range", test_full_sid_range);
	g_test_add_func("/rpc/samr/user-all-information", test_user_all_information);
	return g_test_run();
}
