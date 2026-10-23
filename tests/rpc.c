// SPDX-License-Identifier: GPL-2.0-or-later
#include <endian.h>
#include <errno.h>
#include <grp.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
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

/* Keep group identity tests independent of the host's NSS database. */
static int mock_group(gid_t gid, struct group *group, char *buf, size_t size,
		      struct group **result)
{
	const char *name;

	*result = NULL;
	if (gid == 0)
		name = "root";
	else if (gid == 1000)
		name = "test-group";
	else
		return 0;
	if (strlen(name) + 1 > size)
		return ERANGE;
	strcpy(buf, name);
	memset(group, 0, sizeof(*group));
	group->gr_name = buf;
	group->gr_gid = gid;
	*result = group;
	return 0;
}

int getgrgid_r(gid_t gid, struct group *group, char *buf, size_t size,
		struct group **result)
{
	return mock_group(gid, group, buf, size, result);
}

int getgrnam_r(const char *name, struct group *group, char *buf, size_t size,
		struct group **result)
{
	if (!strcmp(name, "root"))
		return mock_group(0, group, buf, size, result);
	if (!strcmp(name, "test-group"))
		return mock_group(1000, group, buf, size, result);
	*result = NULL;
	return 0;
}

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

		if (!ksmbd_name_compare(user->name, name))
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
	} else if (flags & KSMBD_RPC_WKSSVC_METHOD_INVOKE) {
		const guint8 wkssvc[] = {
			0x98, 0xd0, 0xff, 0x6b, 0x12, 0xa1, 0x10, 0x36,
			0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a, 1, 0, 0, 0
		};

		memcpy(syntax, wkssvc, sizeof(syntax));
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
	g_assert_cmpuint(get32(result->data), ==, 1000 + users->len);
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
		g_assert_cmpuint(result->len, ==, 24 + 20480 * (84 + (version ? 20 : 16)));
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

static GByteArray *wire_sid(struct wire_reader *wire)
{
	unsigned int count = wire32(wire);
	size_t start = wire->offset;
	GByteArray *sid = g_byte_array_new();

	wire_skip(wire, 8);
	g_assert_cmpuint(wire->data[start], ==, 1);
	g_assert_cmpuint(wire->data[start + 1], ==, count);
	g_assert_cmpuint(count, <=, 15);
	wire_skip(wire, count * 4);
	g_byte_array_append(sid, wire->data + start, 8 + count * 4);
	return sid;
}

static void put_string(GByteArray *stub, const char *value, int terminate)
{
	glong length;
	gunichar2 *utf16 = g_utf8_to_utf16(value, -1, NULL, &length, NULL);
	unsigned int i;

	g_assert_nonnull(utf16);
	put32(stub, length + terminate);
	put32(stub, 0);
	put32(stub, length + terminate);
	for (i = 0; i < length + terminate; i++)
		put16(stub, utf16[i]);
	pad_buffer(stub, 4);
	g_free(utf16);
}

static void put_rpc_string(GByteArray *stub, const char *name)
{
	glong length;
	gunichar2 *utf16 = g_utf8_to_utf16(name, -1, NULL, &length, NULL);

	g_assert_nonnull(utf16);
	put16(stub, length * 2);
	put16(stub, length * 2);
	put32(stub, 1);
	g_free(utf16);
	put_string(stub, name, 0);
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

static GByteArray *samr_open_domain_access(GByteArray *server, const guint8 *sid,
				    unsigned int length, unsigned int access)
{
	GByteArray *stub = g_byte_array_new();
	GByteArray *result;

	g_byte_array_append(stub, server->data, 20);
	put32(stub, access);
	put32(stub, sid[1]);
	g_byte_array_append(stub, sid, length);
	result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 7, stub, 128);
	g_byte_array_unref(stub);
	return result;
}

static GByteArray *samr_open_domain(GByteArray *server, const guint8 *sid,
				    unsigned int length)
{
	GByteArray *result = samr_open_domain_access(server, sid, length, 0x02000000);

	g_assert_cmpuint(get32(result->data + 20), ==, 0);
	return result;
}

static GByteArray *samr_open_account_access(GByteArray *domain, unsigned int opnum,
				     unsigned int rid, unsigned int access)
{
	GByteArray *stub = g_byte_array_new();
	GByteArray *result;

	g_byte_array_append(stub, domain->data, 20);
	put32(stub, access);
	put32(stub, rid);
	result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, opnum, stub, 128);
	g_byte_array_unref(stub);
	return result;
}

static GByteArray *samr_open_account(GByteArray *domain, unsigned int opnum,
				     unsigned int rid)
{
	return samr_open_account_access(domain, opnum, rid, 0x02000000);
}

static const guint8 local_domain_sid[] = {
	1, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0,
	1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0
};
static const guint8 unix_group_sid[] = { 1, 1, 0, 0, 0, 0, 0, 22, 2, 0, 0, 0 };

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

static GByteArray *share_get_info(unsigned int level, size_t capacity)
{
	GByteArray *stub = g_byte_array_new(), *result;

	put32(stub, 0);
	put_string(stub, "share0", 1);
	put32(stub, level);
	result = exchange(1, KSMBD_RPC_SRVSVC_METHOD_INVOKE, 16, stub, capacity);
	g_byte_array_unref(stub);
	return result;
}

static void check_share_descriptor(struct wire_reader *wire, unsigned int size)
{
	unsigned int i;

	for (i = 0; i < 4; i++) {
		g_autofree char *value = wire_string(wire);
	}
	g_assert_cmpuint(size, >, 20);
	g_assert_cmpuint(wire32(wire), ==, size);
	wire_skip(wire, size);
	g_assert_cmpuint(wire->data[wire->offset - size], ==, 1);
	wire_align(wire, 4);
}

static void test_share_security_descriptor(void)
{
	GByteArray *result;
	struct wire_reader wire;
	unsigned int size, sizes[3], i;

	fixture_init();
	open_pipe(1, KSMBD_RPC_SRVSVC_METHOD_INVOKE, 0, 3);
	result = share_get_info(502, 4096);
	wire = (struct wire_reader){ .data = result->data, .size = result->len };
	g_assert_cmpuint(wire32(&wire), ==, 502);
	g_assert_cmpuint(wire32(&wire), !=, 0);
	wire_skip(&wire, 8 * 4);
	size = wire32(&wire);
	g_assert_cmpuint(wire32(&wire), !=, 0);
	check_share_descriptor(&wire, size);
	g_assert_cmpuint(wire32(&wire), ==, 0);
	g_assert_cmpuint(wire.offset, ==, wire.size);
	g_byte_array_unref(result);
	result = share_enum(502, UINT32_MAX, 0);
	wire = (struct wire_reader){ .data = result->data, .size = result->len };
	g_assert_cmpuint(wire32(&wire), ==, 502);
	g_assert_cmpuint(wire32(&wire), ==, 502);
	g_assert_cmpuint(wire32(&wire), !=, 0);
	g_assert_cmpuint(wire32(&wire), ==, 3);
	g_assert_cmpuint(wire32(&wire), !=, 0);
	g_assert_cmpuint(wire32(&wire), ==, 3);
	for (i = 0; i < 3; i++) {
		wire_skip(&wire, 8 * 4);
		sizes[i] = wire32(&wire);
		g_assert_cmpuint(wire32(&wire), !=, 0);
	}
	for (i = 0; i < 3; i++)
		check_share_descriptor(&wire, sizes[i]);
	g_assert_cmpuint(wire32(&wire), ==, 3);
	g_assert_cmpuint(wire32(&wire), !=, 0);
	g_assert_cmpuint(wire32(&wire), ==, 0);
	g_assert_cmpuint(wire32(&wire), ==, 0);
	g_assert_cmpuint(wire.offset, ==, wire.size);
	g_byte_array_unref(result);
	fixture_destroy();
}

static void samr_check_name(GByteArray *domain, const char *name,
			    unsigned int rid, unsigned int type)
{
	GByteArray *stub = g_byte_array_new(), *result;
	struct wire_reader wire;

	g_byte_array_append(stub, domain->data, 20);
	put32(stub, 1);
	put32(stub, 1000);
	put32(stub, 0);
	put32(stub, 1);
	put_rpc_string(stub, name);
	result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 17, stub, 128);
	wire = (struct wire_reader){ .data = result->data, .size = result->len };
	g_assert_cmpuint(wire32(&wire), ==, 1);
	g_assert_cmpuint(wire32(&wire), !=, 0);
	g_assert_cmpuint(wire32(&wire), ==, 1);
	g_assert_cmpuint(wire32(&wire), ==, rid);
	g_assert_cmpuint(wire32(&wire), ==, 1);
	g_assert_cmpuint(wire32(&wire), !=, 0);
	g_assert_cmpuint(wire32(&wire), ==, 1);
	g_assert_cmpuint(wire32(&wire), ==, type);
	g_assert_cmpuint(wire32(&wire), ==, type == 8 ? KSMBD_NT_STATUS_NONE_MAPPED : 0);
	g_assert_cmpuint(wire.offset, ==, wire.size);
	g_byte_array_unref(result);
	g_byte_array_unref(stub);
}

static void samr_check_rid(GByteArray *domain, unsigned int rid,
			   const char *name, unsigned int type)
{
	GByteArray *stub = g_byte_array_new(), *result;
	struct wire_reader wire;
	g_autofree char *value = NULL;
	unsigned int length;

	g_byte_array_append(stub, domain->data, 20);
	put32(stub, 1);
	put32(stub, 1000);
	put32(stub, 0);
	put32(stub, 1);
	put32(stub, rid);
	result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 18, stub, 128);
	wire = (struct wire_reader){ .data = result->data, .size = result->len };
	g_assert_cmpuint(wire32(&wire), ==, 1);
	g_assert_cmpuint(wire32(&wire), !=, 0);
	g_assert_cmpuint(wire32(&wire), ==, 1);
	length = wire16(&wire);
	g_assert_cmpuint(wire16(&wire), >=, length);
	g_assert_cmpuint(wire32(&wire), !=, 0);
	value = wire_string(&wire);
	g_assert_cmpstr(value, ==, name);
	g_assert_cmpuint(wire32(&wire), ==, 1);
	g_assert_cmpuint(wire32(&wire), !=, 0);
	g_assert_cmpuint(wire32(&wire), ==, 1);
	g_assert_cmpuint(wire32(&wire), ==, type);
	g_assert_cmpuint(wire32(&wire), ==, 0);
	g_assert_cmpuint(wire.offset, ==, wire.size);
	g_byte_array_unref(result);
	g_byte_array_unref(stub);
}

static void test_account_namespaces(void)
{
	GByteArray *server, *local, *groups, *result, *sid, *stub = g_byte_array_new();
	struct wire_reader wire;
	struct ksmbd_user *user;
	unsigned int i;

	fixture_init();
	/* Both the name and numeric ID may be shared by a user and a group. */
	user = users->pdata[0];
	g_free(user->name);
	user->name = g_strdup("test-group");
	for (i = 0; i < users->len; i++)
		((struct ksmbd_user *)users->pdata[i])->gid = 1000;
	user = users->pdata[users->len - 1];
	user->uid = UINT32_MAX;
	g_free(user->name);
	user->name = g_strdup("invalid-uid-account");
	user = users->pdata[users->len - 2];
	user->uid = 65535; /* The configured-user manager's unmapped UID marker. */
	g_free(user->name);
	user->name = g_strdup("unmapped-uid-account");
	open_pipe(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 0xac, 1);
	server = samr_connect_handle();
	g_byte_array_append(stub, server->data, 20);
	put32(stub, 0);
	put32(stub, UINT32_MAX);
	result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 6, stub, 128);
	wire = (struct wire_reader){ .data = result->data, .size = result->len };
	g_assert_cmpuint(wire32(&wire), ==, 3);
	g_assert_cmpuint(wire32(&wire), !=, 0);
	g_assert_cmpuint(wire32(&wire), ==, 3);
	g_assert_cmpuint(wire32(&wire), !=, 0);
	g_assert_cmpuint(wire32(&wire), ==, 3);
	wire_skip(&wire, 3 * 12);
	for (i = 0; i < 3; i++) {
		g_autofree char *name = wire_string(&wire);

		if (i == 2)
			g_assert_cmpstr(name, ==, "Unix Group");
	}
	g_assert_cmpuint(wire32(&wire), ==, 3);
	g_assert_cmpuint(wire32(&wire), ==, 0);
	g_assert_cmpuint(wire.offset, ==, wire.size);
	g_byte_array_unref(result);
	g_byte_array_set_size(stub, 0);
	g_byte_array_append(stub, server->data, 20);
	put_rpc_string(stub, "Unix Group");
	result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 5, stub, 128);
	wire = (struct wire_reader){ .data = result->data, .size = result->len };
	g_assert_cmpuint(wire32(&wire), !=, 0);
	sid = wire_sid(&wire);
	g_assert_cmpmem(sid->data, sid->len, unix_group_sid, sizeof(unix_group_sid));
	g_assert_cmpuint(wire32(&wire), ==, 0);
	g_byte_array_unref(sid);
	g_byte_array_unref(result);
	local = samr_open_domain(server, local_domain_sid, sizeof(local_domain_sid));
	groups = samr_open_domain(server, unix_group_sid, sizeof(unix_group_sid));
	for (i = 0; i < 2; i++) {
		g_autofree char *name = NULL;

		g_byte_array_set_size(stub, 0);
		g_byte_array_append(stub, i ? groups->data : local->data, 20);
		put32(stub, 0);
		put32(stub, UINT32_MAX);
		result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, i ? 15 : 11, stub, 128);
		wire = (struct wire_reader){ .data = result->data, .size = result->len };
		g_assert_cmpuint(wire32(&wire), ==, i ? 1001 : 0);
		g_assert_cmpuint(wire32(&wire), !=, 0);
		g_assert_cmpuint(wire32(&wire), ==, 1);
		{
			g_assert_cmpuint(wire32(&wire), !=, 0);
			g_assert_cmpuint(wire32(&wire), ==, 1);
			g_assert_cmpuint(wire32(&wire), ==, i ? 1000 : UINT32_MAX);
			wire_skip(&wire, 8);
			name = wire_string(&wire);
			g_assert_cmpstr(name, ==, i ? "test-group" : "Unix Users");
		}
		g_assert_cmpuint(wire32(&wire), ==, 1);
		g_assert_cmpuint(wire32(&wire), ==, 0);
		g_assert_cmpuint(wire.offset, ==, wire.size);
		g_byte_array_unref(result);
	}
	samr_check_name(local, "invalid-uid-account", UINT32_MAX, 8);
	samr_check_name(local, "unmapped-uid-account", UINT32_MAX, 8);
	result = samr_open_account(local, 34, 65535);
	g_assert_cmpuint(get32(result->data + 20), ==, KSMBD_NT_STATUS_NO_SUCH_USER);
	g_byte_array_unref(result);
	samr_check_rid(local, UINT32_MAX, "Unix Users", 2);
	result = samr_open_account(local, 34, UINT32_MAX);
	g_assert_cmpuint(get32(result->data + 20), ==, KSMBD_NT_STATUS_NO_SUCH_USER);
	g_byte_array_unref(result);
	samr_check_name(local, "test-group", 1000, 1);
	samr_check_name(groups, "test-group", 1000, 4);
	samr_check_name(groups, "user-0001-abcdefghijklmnopqrstuvwxyz", UINT32_MAX, 8);
	samr_check_rid(local, 1000, "test-group", 1);
	samr_check_rid(groups, 1000, "test-group", 4);
	result = samr_open_account(groups, 27, 1000);
	g_assert_cmpuint(get32(result->data + 20), ==, 0);
	g_byte_array_unref(result);
	result = samr_open_account(local, 19, UINT32_MAX);
	g_assert_cmpuint(get32(result->data + 20), ==, 0);
	g_byte_array_unref(result);
	result = samr_open_account(groups, 19, 1000);
	g_assert_cmpuint(get32(result->data + 20), !=, 0);
	g_byte_array_unref(result);
	result = samr_open_account(local, 19, 1000);
	g_assert_cmpuint(get32(result->data + 20), !=, 0);
	g_byte_array_unref(result);
	result = samr_open_account(groups, 34, 1000);
	g_assert_cmpuint(get32(result->data + 20), ==, KSMBD_NT_STATUS_NO_SUCH_USER);
	g_byte_array_unref(result);
	g_byte_array_unref(stub);
	g_byte_array_unref(groups);
	g_byte_array_unref(local);
	g_byte_array_unref(server);
	fixture_destroy();
}

static GByteArray *lsa_lookup_name(GByteArray *policy, const char *name,
				   unsigned int version)
{
	GByteArray *stub = g_byte_array_new(), *result;

	g_byte_array_append(stub, policy->data, 20);
	put32(stub, 1);
	put32(stub, 1);
	put_rpc_string(stub, name);
	put32(stub, 0);
	put32(stub, 0);
	put16(stub, 1);
	put32(stub, 0);
	if (version) {
		put32(stub, 0);
		put32(stub, 1);
	}
	result = exchange(1, KSMBD_RPC_LSARPC_METHOD_INVOKE, version ? 68 : 14, stub, 128);
	g_byte_array_unref(stub);
	return result;
}

static void check_lsa_name_rid(GByteArray *result, unsigned int version,
			       unsigned int type, const guint8 *domain, size_t domain_size,
			       unsigned int rid)
{
	struct wire_reader wire = { .data = result->data, .size = result->len };
	GByteArray *sid;
	unsigned int ref, mapped = type != 8;

	ref = wire32(&wire);
	g_assert_cmpuint(!!ref, ==, mapped);
	if (ref) {
		g_autofree char *name = NULL;

		g_assert_cmpuint(wire32(&wire), ==, 1);
		g_assert_cmpuint(wire32(&wire), !=, 0);
		g_assert_cmpuint(wire32(&wire), >=, 1);
		g_assert_cmpuint(wire32(&wire), ==, 1);
		wire_skip(&wire, 8); /* Domain name representation */
		g_assert_cmpuint(wire32(&wire), !=, 0);
		name = wire_string(&wire);
		sid = wire_sid(&wire);
		g_assert_cmpmem(sid->data, sid->len, domain, domain_size);
		g_byte_array_unref(sid);
	}
	g_assert_cmpuint(wire32(&wire), ==, 1);
	g_assert_cmpuint(wire32(&wire), !=, 0);
	g_assert_cmpuint(wire32(&wire), ==, 1);
	g_assert_cmpuint(wire16(&wire), ==, type);
	ref = wire32(&wire);
	if (version)
		g_assert_cmpuint(!!ref, ==, mapped);
	else
		g_assert_cmpuint(ref, ==, mapped ? rid : 0);
	g_assert_cmpuint(wire32(&wire), ==, mapped ? 0 : UINT32_MAX);
	if (version) {
		g_assert_cmpuint(wire32(&wire), ==, 0);
		if (mapped) {
			sid = wire_sid(&wire);
			g_assert_cmpuint(sid->len, ==, domain_size + 4);
			g_assert_cmpmem(sid->data + 2, domain_size - 2, domain + 2, domain_size - 2);
			g_assert_cmpuint(get32(sid->data + sid->len - 4), ==, rid);
			g_byte_array_unref(sid);
		}
	}
	g_assert_cmpuint(wire32(&wire), ==, mapped);
	g_assert_cmpuint(wire32(&wire), ==, mapped ? 0 : KSMBD_NT_STATUS_NONE_MAPPED);
	g_assert_cmpuint(wire.offset, ==, wire.size);
}

static void check_lsa_name(GByteArray *result, unsigned int version,
			   unsigned int type, const guint8 *domain, size_t domain_size)
{
	check_lsa_name_rid(result, version, type, domain, domain_size, 1000);
}

static void test_lsa_account_names(void)
{
	const char *prefixes[] = { "", "sErVeR\\", NULL, "OTHER\\", "SERVER-extra\\" };
	char hostname[256] = { 0 };
	g_autofree char *host_prefix = NULL;
	GByteArray *policy, *result;
	struct ksmbd_user *user;
	unsigned int version, i;

	g_assert_cmpint(gethostname(hostname, sizeof(hostname) - 1), ==, 0);
	host_prefix = g_strdup_printf("%s\\", hostname);
	prefixes[2] = host_prefix;
	fixture_init();
	user = users->pdata[0];
	g_free(user->name);
	user->name = g_strdup("test-group");
	user = users->pdata[users->len - 1];
	user->uid = UINT32_MAX;
	g_free(user->name);
	user->name = g_strdup("invalid-uid-account");
	user = users->pdata[users->len - 2];
	user->uid = 65535; /* The configured-user manager's unmapped UID marker. */
	g_free(user->name);
	user->name = g_strdup("unmapped-uid-account");
	open_pipe(1, KSMBD_RPC_LSARPC_METHOD_INVOKE, 0xab, 0);
	policy = open_policy();
	for (version = 0; version < 2; version++) {
		for (i = 0; i < G_N_ELEMENTS(prefixes); i++) {
			g_autofree char *name = g_strconcat(prefixes[i], "test-group", NULL);

			result = lsa_lookup_name(policy, name, version);
			check_lsa_name(result, version, i < 3 ? 1 : 8,
					local_domain_sid, sizeof(local_domain_sid));
			g_byte_array_unref(result);
		}
		result = lsa_lookup_name(policy, "SERVER\\unmapped-uid-account", version);
		check_lsa_name(result, version, 8, local_domain_sid, sizeof(local_domain_sid));
		g_byte_array_unref(result);
		result = lsa_lookup_name(policy, "SERVER\\invalid-uid-account", version);
		check_lsa_name(result, version, 8, local_domain_sid, sizeof(local_domain_sid));
		g_byte_array_unref(result);
		result = lsa_lookup_name(policy, "uNiX gRoUp\\test-group", version);
		check_lsa_name(result, version, 4, unix_group_sid, sizeof(unix_group_sid));
		g_byte_array_unref(result);
	}
	g_byte_array_unref(policy);
	fixture_destroy();
}

static void test_info_fragmentation(void)
{
	const unsigned int capacities[] = { 80, 301, 4096, 16360 };
	const unsigned int levels[] = { 2, 502 };
	GByteArray *stub, *result, *expected;
	g_autofree char *path = g_strnfill(3000, 'a');
	struct ksmbd_share *share;
	unsigned int i, j, flags;

	/* A valid long path, with individual components below NAME_MAX. */
	for (i = 0; i < 3000; i += 2)
		path[i] = '/';
	fixture_init();
	receive_limit = 257;
	open_pipe(1, KSMBD_RPC_SRVSVC_METHOD_INVOKE, 0, 3);
	share = shares->pdata[0];
	g_free(share->path);
	share->path = g_strdup(path);
	for (i = 0; i < G_N_ELEMENTS(levels); i++) {
		expected = share_get_info(levels[i], 4096);
		g_assert_cmpuint(expected->len, >, 4096);
		g_assert_cmpuint(get32(expected->data + expected->len - 4), ==, 0);
		for (j = 0; j < G_N_ELEMENTS(capacities); j++) {
			result = share_get_info(levels[i], capacities[j]);
			g_assert_cmpmem(result->data, result->len, expected->data, expected->len);
			g_byte_array_unref(result);
		}
		g_byte_array_unref(expected);
	}
	fixture_destroy();
	for (i = 0; i < 2; i++) {
		flags = i ? KSMBD_RPC_WKSSVC_METHOD_INVOKE : KSMBD_RPC_SRVSVC_METHOD_INVOKE;
		fixture_init();
		receive_limit = 257;
		global_conf.root_dir = path;
		open_pipe(1, flags, 0, 0);
		stub = g_byte_array_new();
		put32(stub, 0);
		put32(stub, 102);
		expected = exchange(1, flags, i ? 0 : 21, stub, 4096);
		g_assert_cmpuint(expected->len, >, 4096);
		g_assert_cmpuint(get32(expected->data + expected->len - 4), ==, 0);
		for (j = 0; j < G_N_ELEMENTS(capacities); j++) {
			result = exchange(1, flags, i ? 0 : 21, stub, capacities[j]);
			g_assert_cmpmem(result->data, result->len, expected->data, expected->len);
			g_byte_array_unref(result);
		}
		g_byte_array_unref(expected);
		g_byte_array_unref(stub);
		fixture_destroy();
	}
}

static const guint8 lsad_syntax[] = {
	0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab,
	0xef, 0, 1, 0x23, 0x45, 0x67, 0x89, 0xab, 0, 0, 0, 0
};
static const guint8 dssetup_syntax[] = {
	0x6a, 0x28, 0x19, 0x39, 0x0c, 0xb1, 0xd0, 0x11,
	0x9b, 0xa8, 0, 0xc0, 0x4f, 0xd9, 0x2e, 0xf5, 0, 0, 0, 0
};

static void alter_context(unsigned int context, const guint8 *syntax,
			   unsigned int expected)
{
	const guint8 ndr_syntax[] = {
		0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0, 0x2b, 0x10, 0x48, 0x60, 2, 0, 0, 0
	};
	unsigned int flags = KSMBD_RPC_LSARPC_METHOD_INVOKE;
	struct ksmbd_rpc_command *req, *resp = command(1, flags, 1024);
	GByteArray *stub = g_byte_array_new();

	put32(stub, 1);
	put16(stub, context);
	put16(stub, 1);
	g_byte_array_append(stub, syntax, 20);
	g_byte_array_append(stub, ndr_syntax, sizeof(ndr_syntax));
	req = request(1, flags, 0, stub);
	req->payload[2] = DCERPC_PTYPE_RPC_ALTCONT;
	req->payload[16] = req->payload[17] = 0xff;
	req->payload[18] = receive_limit & 0xff;
	req->payload[19] = receive_limit >> 8;
	req->payload[20] = 0;
	g_assert_cmpint(rpc_ioctl_request(req, resp, 1024), ==, 0);
	g_assert_cmpint(resp->payload[2], ==, DCERPC_PTYPE_RPC_ALTCONTRESP);
	g_assert_cmpuint(get32(resp->payload + 32) & 0xffff, ==, expected);
	g_byte_array_unref(stub);
	g_free(req);
	g_free(resp);
}

static GByteArray *exchange_context(unsigned int context, unsigned int opnum,
				    GByteArray *stub)
{
	unsigned int flags = KSMBD_RPC_LSARPC_METHOD_INVOKE;
	struct ksmbd_rpc_command *req = request(1, flags, opnum, stub);
	struct ksmbd_rpc_command *resp = command(1, flags, 1024);
	GByteArray *result;
	int ret;

	req->payload[20] = context;
	req->payload[21] = context >> 8;
	ret = rpc_ioctl_request(req, resp, 1024);
	result = read_response(req, resp, ret, 1024);
	g_free(req);
	g_free(resp);
	return result;
}

static void test_alter_context(void)
{
	GByteArray *policy, *result, *stub = g_byte_array_new();
	unsigned int i, context;

	fixture_init();
	open_pipe(1, KSMBD_RPC_LSARPC_METHOD_INVOKE, 0xab, 0);
	policy = open_policy();
	alter_context(1, dssetup_syntax, 0);
	alter_context(2, lsad_syntax, 0);
	/* Repeating a binding must not replace it or add a duplicate. */
	alter_context(2, lsad_syntax, 0);
	for (i = 0; i < 2; i++) {
		context = i ? 2 : 0;
		g_byte_array_set_size(stub, 0);
		g_byte_array_append(stub, policy->data, 20);
		put16(stub, 5);
		result = exchange_context(context, 7, stub);
		g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0);
		g_byte_array_unref(result);
	}
	/* A conflicting proposal must leave every existing binding intact. */
	alter_context(0, dssetup_syntax, 2);
	result = exchange_context(0, 7, stub);
	g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0);
	g_byte_array_unref(result);
	g_byte_array_set_size(stub, 0);
	put16(stub, 1);
	result = exchange_context(1, 0, stub);
	g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0);
	g_byte_array_unref(result);
	g_byte_array_unref(stub);
	g_byte_array_unref(policy);
	fixture_destroy();
}

static GByteArray *samr_enum(GByteArray *handle, unsigned int opnum,
			    unsigned int cookie, unsigned int size)
{
	GByteArray *stub = g_byte_array_new(), *result;

	g_byte_array_append(stub, handle->data, 20);
	put32(stub, cookie);
	if (opnum == 13)
		put32(stub, 0);
	put32(stub, size);
	result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, opnum, stub, 4096);
	g_byte_array_unref(stub);
	return result;
}

static void test_samr_enum_sizes(void)
{
	const unsigned int sizes[] = { 0, 1, 95, 96, 191, 192, 256 };
	GByteArray *server, *domain, *result;
	unsigned int i;

	fixture_init();
	open_pipe(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 0xac, 1);
	server = samr_connect_handle();
	domain = samr_open_domain(server, local_domain_sid, sizeof(local_domain_sid));
	for (i = 0; i < G_N_ELEMENTS(sizes); i++) {
		result = samr_enum(domain, 13, 0, sizes[i]);
		g_assert_cmpuint(get32(result->data + result->len - 4), ==,
				 sizes[i] < 96 ? 0xc0000023 : 0x105);
		if (sizes[i] >= 96) {
			g_assert_cmpuint(get32(result->data + 8), ==, sizes[i] / 96);
			g_assert_cmpuint(result->len - 28, ==, sizes[i] / 96 * 96);
		}
		g_byte_array_unref(result);
	}
	/* UTF-16 code units, rather than UTF-8 bytes or Unicode scalar values. */
	g_free(((struct ksmbd_user *)users->pdata[0])->name);
	((struct ksmbd_user *)users->pdata[0])->name = g_strdup("é𐐨é");
	result = samr_enum(domain, 13, 0, 32);
	g_assert_cmpuint(get32(result->data + 8), ==, 1);
	g_assert_cmpuint(result->len - 28, ==, 32);
	g_byte_array_unref(result);
	result = samr_enum(server, 6, 0, 0);
	g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0xc0000023);
	g_byte_array_unref(result);
	result = samr_enum(server, 6, 0, UINT32_MAX);
	g_assert_cmpuint(get32(result->data + 8), ==, 3);
	g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0);
	g_byte_array_unref(result);
	g_byte_array_unref(domain);
	g_byte_array_unref(server);
	fixture_destroy();
}

static void fixture_remove_user(unsigned int index)
{
	struct ksmbd_user *user = users->pdata[index];

	g_assert_cmpint(user->ref_count, ==, 0);
	g_ptr_array_remove_index(users, index);
	g_free(user->name);
	g_free(user);
}

static void test_samr_enum_mutation(void)
{
	GByteArray *server, *domain, *result;
	struct ksmbd_user *added;
	unsigned int cookie;

	fixture_init();
	while (users->len > 6)
		fixture_remove_user(users->len - 1);
	open_pipe(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 0xac, 1);
	server = samr_connect_handle();
	domain = samr_open_domain(server, local_domain_sid, sizeof(local_domain_sid));
	result = samr_enum(domain, 13, 0, 384);
	g_assert_cmpuint(get32(result->data + 8), ==, 4);
	g_assert_cmpuint(get32(result->data + 20), ==, 1000);
	cookie = get32(result->data);
	g_assert_cmpuint(cookie, ==, 1004);
	g_byte_array_unref(result);
	fixture_remove_user(0); /* An already returned account. */
	fixture_remove_user(users->len - 1); /* An account not yet returned. */
	added = g_new0(struct ksmbd_user, 1);
	added->uid = 2000;
	added->name = g_strdup("new-account");
	g_ptr_array_add(users, added);
	result = samr_enum(domain, 13, cookie, 384);
	g_assert_cmpuint(get32(result->data + 8), ==, 2);
	g_assert_cmpuint(get32(result->data + 20), ==, 1004);
	g_assert_cmpuint(get32(result->data + 32), ==, 2000);
	g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0);
	g_byte_array_unref(result);
	/* UID zero must advance, and the last usable UID must not wrap. */
	while (users->len > 2)
		fixture_remove_user(users->len - 1);
	((struct ksmbd_user *)users->pdata[0])->uid = 0;
	((struct ksmbd_user *)users->pdata[1])->uid = UINT32_MAX - 1;
	result = samr_enum(domain, 13, 0, 96);
	g_assert_cmpuint(get32(result->data + 20), ==, 0);
	g_assert_cmpuint(get32(result->data), ==, 1);
	g_byte_array_unref(result);
	result = samr_enum(domain, 13, 1, 96);
	g_assert_cmpuint(get32(result->data + 20), ==, UINT32_MAX - 1);
	g_assert_cmpuint(get32(result->data), ==, UINT32_MAX);
	g_byte_array_unref(result);
	result = samr_enum(domain, 13, UINT32_MAX, 96);
	g_assert_cmpuint(get32(result->data + 8), ==, 0);
	g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0);
	g_byte_array_unref(result);
	g_byte_array_unref(domain);
	g_byte_array_unref(server);
	fixture_destroy();
}

static void put_local_user_sid(GByteArray *stub, unsigned int rid)
{
	put32(stub, 5);
	g_byte_array_append(stub, local_domain_sid, sizeof(local_domain_sid));
	stub->data[stub->len - sizeof(local_domain_sid) + 1] = 5;
	put32(stub, rid);
}

static GByteArray *lsa_lookup_request(GByteArray *policy, unsigned int opnum,
				      unsigned int ignored, unsigned int mapped,
				      unsigned int level, unsigned int options)
{
	GByteArray *stub = g_byte_array_new(), *result;
	int names = opnum == 14 || opnum == 68;
	int extended = opnum == 57 || opnum == 68;

	g_byte_array_append(stub, policy->data, 20);
	put32(stub, 1);
	if (names) {
		put32(stub, 1);
		put_rpc_string(stub, ((struct ksmbd_user *)users->pdata[0])->name);
	} else {
		put32(stub, 1);
		put32(stub, 1);
		put32(stub, 1);
		put_local_user_sid(stub, 1000);
	}
	put32(stub, ignored && ignored != 2 ? 1 : 0);
	put32(stub, ignored ? 1 : 0);
	if (ignored) {
		put32(stub, ignored == 2 ? 0 : ignored == 3 ? 2 : 1);
		if (ignored != 2) {
			put16(stub, 8);
			pad_buffer(stub, 4);
			if (names) {
				put32(stub, extended ? 1 : 7);
				put32(stub, UINT32_MAX);
				if (extended) {
					put32(stub, 123);
					put_local_user_sid(stub, 1234);
				}
			} else {
				/* String body follows all fixed entry fields. */
				put16(stub, 14);
				put16(stub, 14);
				put32(stub, 1);
				put32(stub, UINT32_MAX);
				if (extended)
					put32(stub, 123);
				put_string(stub, "ignored", 0);
				/* The next argument is a short; there is no 4-byte tail pad. */
				g_byte_array_set_size(stub, stub->len - 2);
			}
		}
	}
	put16(stub, level);
	put32(stub, mapped);
	if (extended) {
		put32(stub, options);
		put32(stub, 1);
	}
	result = exchange(1, KSMBD_RPC_LSARPC_METHOD_INVOKE, opnum, stub, 4096);
	g_byte_array_unref(stub);
	return result;
}

static void test_lsa_ignored_translations(void)
{
	const unsigned int opnums[] = { 14, 15, 57, 68 };
	GByteArray *policy, *baseline, *result;
	unsigned int i, ignored;

	fixture_init();
	open_pipe(1, KSMBD_RPC_LSARPC_METHOD_INVOKE, 0xab, 0);
	policy = open_policy();
	for (i = 0; i < G_N_ELEMENTS(opnums); i++) {
		baseline = lsa_lookup_request(policy, opnums[i], 0, 0, 1, 0);
		g_assert_cmpuint(get32(baseline->data + baseline->len - 4), ==, 0);
		for (ignored = 0; ignored <= 3; ignored++) {
			result = lsa_lookup_request(policy, opnums[i], ignored, 99, 1, 0);
			if (ignored == 3)
				g_assert_cmpuint(get32(result->data + result->len - 4), ==,
						 KSMBD_NT_STATUS_INVALID_PARAMETER);
			else
				g_assert_cmpmem(result->data, result->len,
						baseline->data, baseline->len);
			g_byte_array_unref(result);
		}
		g_byte_array_unref(baseline);
	}
	g_byte_array_unref(policy);
	fixture_destroy();
}

static void test_lsa_lookup_scope(void)
{
	const unsigned int opnums[] = { 14, 15, 57, 68 };
	const unsigned int options[] = { 0, 1, 0x80000000, UINT32_MAX };
	GByteArray *policy, *result;
	unsigned int i, level, j;

	fixture_init();
	open_pipe(1, KSMBD_RPC_LSARPC_METHOD_INVOKE, 0xab, 0);
	policy = open_policy();
	for (i = 0; i < G_N_ELEMENTS(opnums); i++) {
		for (level = 0; level <= 8; level++) {
			result = lsa_lookup_request(policy, opnums[i], 0, 0, level, 0);
			g_assert_cmpuint(get32(result->data + result->len - 4), ==,
					 level == 1 ? 0 : KSMBD_NT_STATUS_INVALID_PARAMETER);
			g_byte_array_unref(result);
		}
		for (j = 0; j < G_N_ELEMENTS(options); j++) {
			result = lsa_lookup_request(policy, opnums[i], 0, 0, 1, options[j]);
			g_assert_cmpuint(get32(result->data + result->len - 4), ==,
					 opnums[i] == 68 && (j == 1 || j == 3) ?
					 KSMBD_NT_STATUS_INVALID_PARAMETER : 0);
			g_byte_array_unref(result);
		}
		result = lsa_lookup_request(policy, opnums[i], 0, 0, 2, 0x80000000);
		g_assert_cmpuint(get32(result->data + result->len - 4), ==,
				 KSMBD_NT_STATUS_INVALID_PARAMETER);
		g_byte_array_unref(result);
	}
	g_byte_array_unref(policy);
	fixture_destroy();
}

static void test_lsa_unmapped_sids(void)
{
	const guint8 foreign[] = { 1, 2, 0, 0, 0, 0, 0, 5,
		0x0f, 0x27, 0, 0, 42, 0, 0, 0 };
	GByteArray *policy, *result, *stub = g_byte_array_new();
	unsigned int version, mixed, i, count;
	struct wire_reader wire;

	fixture_init();
	open_pipe(1, KSMBD_RPC_LSARPC_METHOD_INVOKE, 0xab, 0);
	policy = open_policy();
	for (version = 0; version < 2; version++) {
		for (mixed = 0; mixed < 2; mixed++) {
			g_autofree char *domain_name = NULL;
			GByteArray *domain_sid;

			count = 2 + mixed;
			g_byte_array_set_size(stub, 0);
			g_byte_array_append(stub, policy->data, 20);
			put32(stub, count);
			put32(stub, 1);
			put32(stub, count);
			for (i = 0; i < count; i++)
				put32(stub, 1);
			put_local_user_sid(stub, 777777);
			put32(stub, 2);
			g_byte_array_append(stub, foreign, sizeof(foreign));
			if (mixed)
				put_local_user_sid(stub, 1000);
			put32(stub, 0);
			put32(stub, 0);
			put16(stub, 1);
			put32(stub, 0);
			if (version) {
				put32(stub, 0);
				put32(stub, 1);
			}
			result = exchange(1, KSMBD_RPC_LSARPC_METHOD_INVOKE,
					  version ? 57 : 15, stub, 4096);
			wire = (struct wire_reader){ .data = result->data, .size = result->len };
			g_assert_cmpuint(wire32(&wire), !=, 0);
			g_assert_cmpuint(wire32(&wire), ==, 1);
			wire_skip(&wire, 12 + 8 + 4);
			domain_name = wire_string(&wire);
			domain_sid = wire_sid(&wire);
			g_assert_cmpmem(domain_sid->data, domain_sid->len,
					local_domain_sid, sizeof(local_domain_sid));
			g_byte_array_unref(domain_sid);
			g_assert_cmpuint(wire32(&wire), ==, count);
			g_assert_cmpuint(wire32(&wire), !=, 0);
			g_assert_cmpuint(wire32(&wire), ==, count);
			for (i = 0; i < count; i++) {
				g_assert_cmpuint(wire16(&wire), ==, i == 2 ? 1 : 8);
				wire_align(&wire, 4);
				wire_skip(&wire, 4);
				g_assert_cmpuint(wire32(&wire), !=, 0);
				g_assert_cmpuint(wire32(&wire), ==, i == 1 ? UINT32_MAX : 0);
				if (version)
					g_assert_cmpuint(wire32(&wire), ==, 0);
			}
			for (i = 0; i < count; i++) {
				g_autofree char *name = wire_string(&wire);

				g_assert_cmpstr(name, ==, i == 0 ? "0xBDE31" :
						i == 1 ? "S-1-5-9999-42" :
						((struct ksmbd_user *)users->pdata[0])->name);
			}
			g_assert_cmpuint(wire32(&wire), ==, mixed);
			g_assert_cmpuint(wire32(&wire), ==,
					 mixed ? 0x107 : KSMBD_NT_STATUS_NONE_MAPPED);
			g_assert_cmpuint(wire.offset, ==, wire.size);
			g_byte_array_unref(result);
		}
	}
	g_byte_array_unref(policy);
	g_byte_array_unref(stub);
	fixture_destroy();
}

static void test_lsa_predefined(void)
{
	static const struct {
		const char *domain, *name;
		unsigned int authority, prefix_count, prefix, rid, type;
	} cases[] = {
	{ "", "Null Sid", 0, 0, 0, 0, 5 },
	{ "", "Everyone", 1, 0, 0, 0, 5 },
	{ "", "Local", 2, 0, 0, 0, 5 },
	{ "", "Creator Owner", 3, 0, 0, 0, 5 },
	{ "", "Creator Group", 3, 0, 0, 1, 5 },
	{ "", "Creator Owner Server", 3, 0, 0, 2, 5 },
	{ "", "Creator Group Server", 3, 0, 0, 3, 5 },
	{ "", "Owner Rights", 3, 0, 0, 4, 5 },
	{ "NT Pseudo Domain", "NT Pseudo Domain", 5, 0, 0, 0, 3 },
	{ "NT Authority", "Dialup", 5, 0, 0, 1, 5 },
	{ "NT Authority", "Network", 5, 0, 0, 2, 5 },
	{ "NT Authority", "Batch", 5, 0, 0, 3, 5 },
	{ "NT Authority", "Interactive", 5, 0, 0, 4, 5 },
	{ "NT Authority", "Service", 5, 0, 0, 6, 5 },
	{ "NT Authority", "Anonymous Logon", 5, 0, 0, 7, 5 },
	{ "NT Authority", "Proxy", 5, 0, 0, 8, 5 },
	{ "NT Authority", "Enterprise Domain Controllers", 5, 0, 0, 9, 5 },
	{ "NT Authority", "Self", 5, 0, 0, 10, 5 },
	{ "NT Authority", "Authenticated Users", 5, 0, 0, 11, 5 },
	{ "NT Authority", "Restricted", 5, 0, 0, 12, 5 },
	{ "NT Authority", "Terminal Server User", 5, 0, 0, 13, 5 },
	{ "NT Authority", "Remote Interactive Logon", 5, 0, 0, 14, 5 },
	{ "NT Authority", "This Organization", 5, 0, 0, 15, 5 },
	{ "NT Authority", "System", 5, 0, 0, 18, 5 },
	{ "NT Authority", "Local Service", 5, 0, 0, 19, 5 },
	{ "NT Authority", "Network Service", 5, 0, 0, 20, 5 },
	{ "NT Authority", "Write Restricted", 5, 0, 0, 33, 5 },
	{ "NT Authority", "Other Organization", 5, 0, 0, 1000, 5 },
	{ "Builtin", "Builtin", 5, 1, 32, 0, 3 },
	{ "Internet$", "Internet$", 7, 0, 0, 0, 3 },
	{ "NT Authority", "NTLM Authentication", 5, 1, 64, 10, 5 },
	{ "NT Authority", "Digest Authentication", 5, 1, 64, 21, 5 },
	{ "NT Authority", "Channel Authentication", 5, 1, 64, 14, 5 },
	{ "Mandatory Label", "Mandatory Label", 16, 0, 0, 0, 3 },
	{ "Mandatory Label", "Untrusted Mandatory Level", 16, 0, 0, 0, 10 },
	{ "Mandatory Label", "Low Mandatory Level", 16, 0, 0, 4096, 10 },
	{ "Mandatory Label", "Medium Mandatory Level", 16, 0, 0, 8192, 10 },
	{ "Mandatory Label", "High Mandatory Level", 16, 0, 0, 12288, 10 },
	{ "Mandatory Label", "System Mandatory Level", 16, 0, 0, 16384, 10 },
	{ "Mandatory Label", "Protected Process Mandatory Level", 16, 0, 0, 20480, 10 },
	};
	GByteArray *policy, *stub = g_byte_array_new(), *result;
	unsigned int i, version, direction;

	fixture_init();
	/* Predefined translations take precedence over configured accounts. */
	g_free(((struct ksmbd_user *)users->pdata[0])->name);
	((struct ksmbd_user *)users->pdata[0])->name = g_strdup("Everyone");
	open_pipe(1, KSMBD_RPC_LSARPC_METHOD_INVOKE, 0xab, 0);
	policy = open_policy();
	for (i = 0; i < G_N_ELEMENTS(cases); i++) {
		GByteArray *sid = g_byte_array_new();
		guint8 header[] = { 1, cases[i].prefix_count + (cases[i].type != 3),
			0, 0, 0, 0, 0, cases[i].authority };
		g_autofree char *input = cases[i].domain[0] ?
			g_strdup_printf("%s\\%s", cases[i].domain, cases[i].name) :
			g_strdup(cases[i].name);

		g_byte_array_append(sid, header, 8);
		if (cases[i].prefix_count)
			put32(sid, cases[i].prefix);
		if (cases[i].type != 3)
			put32(sid, cases[i].rid);
		for (version = 0; version < 2; version++) {
			for (direction = 0; direction < 2; direction++) {
				struct wire_reader wire;
				GByteArray *decoded;
				g_autofree char *domain_name = NULL, *name = NULL;

				if (direction) {
					g_byte_array_set_size(stub, 0);
					g_byte_array_append(stub, policy->data, 20);
					put32(stub, 1);
					put32(stub, 1);
					put32(stub, 1);
					put32(stub, 1);
					put32(stub, sid->data[1]);
					g_byte_array_append(stub, sid->data, sid->len);
					put32(stub, 0);
					put32(stub, 0);
					put16(stub, 1);
					put32(stub, 0);
					if (version) {
						put32(stub, 0);
						put32(stub, 1);
					}
					result = exchange(1, KSMBD_RPC_LSARPC_METHOD_INVOKE,
							  version ? 57 : 15, stub, 4096);
				} else {
					result = lsa_lookup_name(policy, input, version);
				}
				wire = (struct wire_reader){ .data = result->data, .size = result->len };
				g_assert_cmpuint(wire32(&wire), !=, 0);
				g_assert_cmpuint(wire32(&wire), ==, 1);
				wire_skip(&wire, 12 + 8 + 4);
				domain_name = wire_string(&wire);
				g_assert_cmpstr(domain_name, ==, cases[i].domain);
				decoded = wire_sid(&wire);
				g_assert_cmpuint(decoded->data[1], ==, cases[i].prefix_count);
				g_assert_cmpuint(decoded->data[7], ==, cases[i].authority);
				if (cases[i].prefix_count)
					g_assert_cmpuint(get32(decoded->data + 8), ==, cases[i].prefix);
				g_byte_array_unref(decoded);
				g_assert_cmpuint(wire32(&wire), ==, 1);
				g_assert_cmpuint(wire32(&wire), !=, 0);
				g_assert_cmpuint(wire32(&wire), ==, 1);
				g_assert_cmpuint(wire16(&wire), ==, cases[i].type);
				wire_align(&wire, 4);
				if (direction) {
					wire_skip(&wire, 4);
					g_assert_cmpuint(wire32(&wire), !=, 0);
				} else if (version) {
					g_assert_cmpuint(wire32(&wire), !=, 0);
				} else {
					g_assert_cmpuint(wire32(&wire), ==,
							 cases[i].type == 3 ? 0 : cases[i].rid);
				}
				g_assert_cmpuint(wire32(&wire), ==, 0);
				if (version)
					g_assert_cmpuint(wire32(&wire), ==, 0);
				if (direction) {
					name = wire_string(&wire);
					g_assert_cmpstr(name, ==, cases[i].name);
				} else if (version) {
					decoded = wire_sid(&wire);
					g_assert_cmpmem(decoded->data, decoded->len, sid->data, sid->len);
					g_byte_array_unref(decoded);
				}
				g_assert_cmpuint(wire32(&wire), ==, 1);
				g_assert_cmpuint(wire32(&wire), ==, 0);
				g_assert_cmpuint(wire.offset, ==, wire.size);
				g_byte_array_unref(result);
			}
		}
		g_byte_array_unref(sid);
	}
	g_byte_array_unref(stub);
	g_byte_array_unref(policy);
	fixture_destroy();
}

static void test_group_alias_membership(void)
{
	GByteArray *server, *domain, *groups, *user, *group, *alias, *result;
	GByteArray *stub = g_byte_array_new();
	struct wire_reader wire;
	static gid_t supplementary[] = { 1000, 1000 };
	unsigned int i;

	fixture_init();
	while (users->len > 3)
		fixture_remove_user(users->len - 1);
	((struct ksmbd_user *)users->pdata[0])->gid = 1000;
	((struct ksmbd_user *)users->pdata[1])->ngroups = 2;
	((struct ksmbd_user *)users->pdata[1])->sgid = supplementary;
	open_pipe(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 0xac, 1);
	server = samr_connect_handle();
	domain = samr_open_domain(server, local_domain_sid, sizeof(local_domain_sid));
	groups = samr_open_domain(server, unix_group_sid, sizeof(unix_group_sid));
	user = samr_open_account(domain, 34, 1000);
	group = samr_open_account(domain, 19, UINT32_MAX);
	alias = samr_open_account(groups, 27, 1000);
	g_assert_cmpuint(get32(group->data + 20), ==, 0);
	g_assert_cmpuint(get32(alias->data + 20), ==, 0);
	samr_check_name(domain, "Unix Users", UINT32_MAX, 2);
	samr_check_rid(domain, UINT32_MAX, "Unix Users", 2);
	samr_check_rid(domain, 1000, ((struct ksmbd_user *)users->pdata[0])->name, 1);
	g_byte_array_append(stub, user->data, 20);
	result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 39, stub, 4096);
	g_assert_cmpuint(get32(result->data + 4), ==, 1);
	g_assert_cmpuint(get32(result->data + 16), ==, UINT32_MAX);
	g_assert_cmpuint(get32(result->data + 24), ==, 0);
	g_byte_array_unref(result);
	for (i = 0; i < 3; i++) {
		unsigned int levels[] = { 1, 9, 21 }, offsets[] = { 24, 8, 172 };

		g_byte_array_set_size(stub, 20);
		put16(stub, levels[i]);
		result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 36, stub, 4096);
		g_assert_cmpuint(get32(result->data + offsets[i]), ==, UINT32_MAX);
		g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0);
		g_byte_array_unref(result);
	}
	g_byte_array_set_size(stub, 0);
	g_byte_array_append(stub, group->data, 20);
	result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 25, stub, 4096);
	wire = (struct wire_reader){ .data = result->data, .size = result->len };
	g_assert_cmpuint(wire32(&wire), !=, 0);
	g_assert_cmpuint(wire32(&wire), ==, 3);
	g_assert_cmpuint(wire32(&wire), !=, 0);
	g_assert_cmpuint(wire32(&wire), !=, 0);
	g_assert_cmpuint(wire32(&wire), ==, 3);
	for (i = 0; i < 3; i++)
		g_assert_cmpuint(wire32(&wire), ==, 1000 + i);
	g_assert_cmpuint(wire32(&wire), ==, 3);
	for (i = 0; i < 3; i++)
		g_assert_cmpuint(wire32(&wire), ==, 7);
	g_assert_cmpuint(wire32(&wire), ==, 0);
	g_assert_cmpuint(wire.offset, ==, wire.size);
	g_byte_array_unref(result);
	g_byte_array_set_size(stub, 0);
	g_byte_array_append(stub, alias->data, 20);
	result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 33, stub, 4096);
	wire = (struct wire_reader){ .data = result->data, .size = result->len };
	g_assert_cmpuint(wire32(&wire), ==, 2);
	g_assert_cmpuint(wire32(&wire), !=, 0);
	g_assert_cmpuint(wire32(&wire), ==, 2);
	wire_skip(&wire, 8);
	for (i = 0; i < 2; i++) {
		GByteArray *sid = wire_sid(&wire);

		g_assert_cmpuint(sid->data[1], ==, 5);
		g_assert_cmpmem(sid->data + 2, 22, local_domain_sid + 2, 22);
		g_assert_cmpuint(get32(sid->data + 24), ==, 1000 + i);
		g_byte_array_unref(sid);
	}
	g_assert_cmpuint(wire32(&wire), ==, 0);
	g_assert_cmpuint(wire.offset, ==, wire.size);
	g_byte_array_unref(result);
	/* A duplicate SID is idempotent; supplementary and primary aliases unite. */
	g_byte_array_set_size(stub, 0);
	g_byte_array_append(stub, groups->data, 20);
	put32(stub, 3);
	put32(stub, 1);
	put32(stub, 3);
	for (i = 0; i < 3; i++)
		put32(stub, 1);
	put_local_user_sid(stub, 1000);
	put_local_user_sid(stub, 1000);
	put_local_user_sid(stub, 1001);
	result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 16, stub, 4096);
	g_assert_cmpuint(get32(result->data), ==, 2);
	g_assert_cmpuint(get32(result->data + 12), ==, 0);
	g_assert_cmpuint(get32(result->data + 16), ==, 1000);
	g_assert_cmpuint(get32(result->data + 20), ==, 0);
	g_byte_array_unref(result);
	/* A group-domain SID with the same last component is not a local user. */
	g_byte_array_set_size(stub, 20);
	put32(stub, 1);
	put32(stub, 1);
	put32(stub, 1);
	put32(stub, 1);
	put32(stub, 2);
	g_byte_array_append(stub, unix_group_sid, sizeof(unix_group_sid));
	stub->data[stub->len - sizeof(unix_group_sid) + 1] = 2;
	put32(stub, 1000);
	result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 16, stub, 4096);
	g_assert_cmpuint(get32(result->data), ==, 0);
	g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0);
	g_byte_array_unref(result);
	g_byte_array_unref(alias);
	g_byte_array_unref(group);
	g_byte_array_unref(user);
	g_byte_array_unref(groups);
	/* The synthetic name must remain unique in the local account namespace. */
	g_free(((struct ksmbd_user *)users->pdata[0])->name);
	((struct ksmbd_user *)users->pdata[0])->name = g_strdup("uNiX uSeRs");
	samr_check_name(domain, "Unix Users", 1000, 1);
	samr_check_name(domain, "Unix Users (1)", UINT32_MAX, 2);
	samr_check_rid(domain, UINT32_MAX, "Unix Users (1)", 2);
	g_byte_array_unref(domain);
	g_byte_array_unref(server);
	g_byte_array_unref(stub);
	fixture_destroy();
	fixture_init();
	open_pipe(1, KSMBD_RPC_LSARPC_METHOD_INVOKE, 0xab, 0);
	server = open_policy();
	for (i = 0; i < 2; i++) {
		result = lsa_lookup_name(server, "SERVER\\Unix Users", i);
		check_lsa_name_rid(result, i, 2, local_domain_sid, sizeof(local_domain_sid), UINT32_MAX);
		g_byte_array_unref(result);
	}
	g_byte_array_unref(server);
	fixture_destroy();
}

static void test_handle_grants(void)
{
	const unsigned int masks[] = {
		0x00800000, 0x01000000, 0x10000000, 0x40000000,
		0x02000000, 0x00020000, 0
	};
	GByteArray *server, *domain, *groups, *result, *stub;
	unsigned int i, kind, opnum;
	const guint8 zero_handle[20] = { 0 };

	fixture_init();
	((struct ksmbd_user *)users->pdata[0])->gid = 1000;
	open_pipe(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 0xac, 1);
	server = samr_connect_handle();
	domain = samr_open_domain(server, local_domain_sid, sizeof(local_domain_sid));
	groups = samr_open_domain(server, unix_group_sid, sizeof(unix_group_sid));
	for (i = 0; i < G_N_ELEMENTS(masks); i++) {
		for (kind = 0; kind < 5; kind++) {
			if (!kind) {
				__u32 access = htole32(masks[i]);

				stub = connect_stub();
				memcpy(stub->data + 4, &access, 4);
				result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 64, stub, 128);
				g_byte_array_unref(stub);
			} else if (kind == 1) {
				result = samr_open_domain_access(server, local_domain_sid,
							 sizeof(local_domain_sid), masks[i]);
			} else {
				result = samr_open_account_access(kind == 4 ? groups : domain,
						 kind == 2 ? 34 : kind == 3 ? 19 : 27,
						 kind == 3 ? UINT32_MAX : 1000, masks[i]);
			}
			g_assert_cmpuint(get32(result->data + result->len - 4), ==,
					 i < 4 ? KSMBD_NT_STATUS_ACCESS_DENIED : 0);
			if (i < 4)
				g_assert_cmpmem(result->data + (kind ? 0 : 16), 20,
						zero_handle, sizeof(zero_handle));
			g_byte_array_unref(result);
		}
	}
	g_byte_array_unref(groups);
	g_byte_array_unref(domain);
	g_byte_array_unref(server);
	fixture_destroy();
	fixture_init();
	open_pipe(1, KSMBD_RPC_LSARPC_METHOD_INVOKE, 0xab, 0);
	for (opnum = 6; opnum <= 44; opnum += 38) {
		for (i = 0; i < G_N_ELEMENTS(masks) + 2; i++) {
			unsigned int desired = i < G_N_ELEMENTS(masks) ? masks[i] :
					       i == G_N_ELEMENTS(masks) ? 0x80000000 : 0x20000000;
			__u32 access = htole32(desired);

			stub = policy_attributes(0);
			memcpy(stub->data + stub->len - 4, &access, 4);
			result = exchange(1, KSMBD_RPC_LSARPC_METHOD_INVOKE, opnum, stub, 128);
			g_assert_cmpuint(get32(result->data + 20), ==,
					 i < 4 || i == G_N_ELEMENTS(masks) ?
					 KSMBD_NT_STATUS_ACCESS_DENIED : 0);
			if (i < 4 || i == G_N_ELEMENTS(masks))
				g_assert_cmpmem(result->data, 20, zero_handle, sizeof(zero_handle));
			g_byte_array_unref(result);
			g_byte_array_unref(stub);
		}
	}
	fixture_destroy();
	/* Combining generic rights must map to concrete bits before subset checks. */
	{
		const struct rpc_generic_mapping mapping = { 1, 2, 4, 7 };
		unsigned int granted = UINT32_MAX;

		g_assert_cmpint(rpc_grant_access(0xa0000000, 5, &mapping, &granted), ==, 0);
		g_assert_cmpuint(granted, ==, 5);
		g_assert_cmpint(rpc_grant_access(0x02000000, 5, &mapping, &granted), ==, 0);
		g_assert_cmpuint(granted, ==, 5);
		g_assert_cmpint(rpc_grant_access(2, 5, &mapping, &granted), ==,
			       KSMBD_RPC_EACCESS_DENIED);
		g_assert_cmpuint(granted, ==, 0);
	}
}

static void test_user_all_access_fields(void)
{
	GByteArray *server, *domain, *user, *stub = g_byte_array_new(), *result;
	unsigned int combination, i;

	fixture_init();
	open_pipe(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 0xac, 1);
	server = samr_connect_handle();
	domain = samr_open_domain(server, local_domain_sid, sizeof(local_domain_sid));
	for (combination = 0; combination < 16; combination++) {
		unsigned int access = (combination & 3) | ((combination & 12) << 1);
		unsigned int expected = (combination & 1 ? 0x3f : 0) |
			(combination & 2 ? 0xc00000 : 0) |
			(combination & 4 ? 0x3ffc0 : 0) |
			(combination & 8 ? 0x3c0000 : 0);
		struct wire_reader wire;
		unsigned int refs[13];

		user = samr_open_account_access(domain, 34, 1000, access);
		g_assert_cmpuint(get32(user->data + 20), ==, 0);
		g_byte_array_set_size(stub, 0);
		g_byte_array_append(stub, user->data, 20);
		put16(stub, 21);
		result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 36, stub, 4096);
		g_byte_array_unref(user);
		if (!combination) {
			g_assert_cmpuint(get32(result->data + result->len - 4), ==,
					 KSMBD_NT_STATUS_ACCESS_DENIED);
			g_byte_array_unref(result);
			continue;
		}
		wire = (struct wire_reader){ .data = result->data, .size = result->len };
		g_assert_cmpuint(wire32(&wire), !=, 0);
		g_assert_cmpuint(wire16(&wire), ==, 21);
		wire_align(&wire, 8);
		for (i = 0; i < 12; i++)
			g_assert_cmpuint(wire32(&wire), ==, 0);
		for (i = 0; i < 13; i++) {
			unsigned int length = wire16(&wire);

			g_assert_cmpuint(wire16(&wire), >=, length);
			refs[i] = wire32(&wire);
			g_assert_cmpuint(!!refs[i], ==,
				(i < 2 && (combination & 1)) ||
				((i == 2 || i == 5) && (combination & 4)));
			if (!refs[i])
				g_assert_cmpuint(length, ==, 0);
		}
		g_assert_cmpuint(wire32(&wire), ==, 0);
		g_assert_cmpuint(wire32(&wire), ==, 0);
		g_assert_cmpuint(wire32(&wire), ==, combination & 1 ? 1000 : 0);
		g_assert_cmpuint(wire32(&wire), ==, combination & 1 ? UINT32_MAX : 0);
		g_assert_cmpuint(wire32(&wire), ==, combination & 8 ? 16 : 0);
		g_assert_cmpuint(wire32(&wire), ==, expected);
		g_assert_cmpuint(wire16(&wire), ==, combination & 4 ? 168 : 0);
		g_assert_cmpuint(!!wire32(&wire), ==, !!(combination & 4));
		for (i = 0; i < 3; i++)
			g_assert_cmpuint(wire32(&wire), ==, 0);
		for (i = 0; i < 13; i++) {
			g_autofree char *value = refs[i] ? wire_string(&wire) : NULL;

			if (refs[i] && i < 2)
				g_assert_cmpstr(value, ==, ((struct ksmbd_user *)users->pdata[0])->name);
		}
		if (combination & 4) {
			g_assert_cmpuint(wire32(&wire), ==, 1260);
			g_assert_cmpuint(wire32(&wire), ==, 0);
			g_assert_cmpuint(wire32(&wire), ==, 21);
			wire_skip(&wire, 21);
		}
		g_assert_cmpuint(wire32(&wire), ==, 0);
		g_assert_cmpuint(wire.offset, ==, wire.size);
		g_byte_array_unref(result);
	}
	g_byte_array_unref(stub);
	g_byte_array_unref(domain);
	g_byte_array_unref(server);
	fixture_destroy();
}

static void test_user_path_consistency(void)
{
	GByteArray *server, *domain, *user, *stub = g_byte_array_new(), *result;
	char *home = NULL, *profile = NULL;
	struct wire_reader wire;
	unsigned int i, refs[13];

	fixture_init();
	open_pipe(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 0xac, 1);
	server = samr_connect_handle();
	domain = samr_open_domain(server, local_domain_sid, sizeof(local_domain_sid));
	user = samr_open_account(domain, 34, 1000);
	g_byte_array_append(stub, user->data, 20);
	put16(stub, 21);
	result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 36, stub, 4096);
	wire = (struct wire_reader){ .data = result->data, .size = result->len };
	wire_skip(&wire, 8 + 6 * 8);
	for (i = 0; i < 13; i++) {
		wire_skip(&wire, 4);
		refs[i] = wire32(&wire);
	}
	wire_skip(&wire, 8 + 4 * 4 + 8 + 12);
	for (i = 0; i < 13; i++) {
		char *value;

		if (!refs[i])
			continue;
		value = wire_string(&wire);
		if (i == 2)
			home = value;
		else if (i == 5)
			profile = value;
		else
			g_free(value);
	}
	g_byte_array_unref(result);
	g_assert_nonnull(home);
	g_assert_nonnull(profile);
	for (i = 10; i <= 12; i += 2) {
		g_autofree char *value = NULL;

		g_byte_array_set_size(stub, 20);
		put16(stub, i);
		result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 36, stub, 4096);
		wire = (struct wire_reader){ .data = result->data, .size = result->len };
		wire_skip(&wire, 8 + (i == 10 ? 16 : 8));
		value = wire_string(&wire);
		g_assert_cmpstr(value, ==, i == 10 ? home : profile);
		g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0);
		g_byte_array_unref(result);
	}
	g_free(home);
	g_free(profile);
	g_byte_array_unref(stub);
	g_byte_array_unref(user);
	g_byte_array_unref(domain);
	g_byte_array_unref(server);
	fixture_destroy();
}

static void test_unicode_account_names(void)
{
	const char *names[][2] = {
		{ "tést", "TÉST" }, { "οδυσσεύς", "ΟΔΥΣΣΕΎΣ" },
		{ "straße", "STRASSE" }, { "𐐨name", "𐐀NAME" }
	};
	GByteArray *server, *domain, *policy, *result;
	struct ksmbd_user *user;
	unsigned int i, version;

	fixture_init();
	open_pipe(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 0xac, 1);
	server = samr_connect_handle();
	domain = samr_open_domain(server, local_domain_sid, sizeof(local_domain_sid));
	user = users->pdata[0];
	for (i = 0; i < G_N_ELEMENTS(names); i++) {
		g_free(user->name);
		user->name = g_strdup(names[i][0]);
		samr_check_name(domain, names[i][1], 1000, 1);
	}
	g_byte_array_unref(domain);
	g_byte_array_unref(server);
	fixture_destroy();
	fixture_init();
	user = users->pdata[0];
	open_pipe(1, KSMBD_RPC_LSARPC_METHOD_INVOKE, 0xab, 0);
	policy = open_policy();
	for (i = 0; i < G_N_ELEMENTS(names); i++) {
		g_free(user->name);
		user->name = g_strdup(names[i][0]);
		for (version = 0; version < 2; version++) {
			result = lsa_lookup_name(policy, names[i][1], version);
			check_lsa_name(result, version, 1, local_domain_sid,
					 sizeof(local_domain_sid));
			g_byte_array_unref(result);
		}
	}
	g_byte_array_unref(policy);
	fixture_destroy();
}

static void test_user_all_big_endian(void)
{
	GByteArray *server, *domain, *user, *stub = g_byte_array_new();
	struct ksmbd_rpc_command *req, *resp;
	__u16 value16;
	__u32 value32;

	fixture_init();
	open_pipe(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 0xac, 1);
	server = samr_connect_handle();
	domain = samr_open_domain(server, local_domain_sid, sizeof(local_domain_sid));
	user = samr_open_account(domain, 34, 1000);
	/* A context handle is an opaque 20-byte token, even across byte orders. */
	g_byte_array_append(stub, user->data, 20);
	put16(stub, 0x1500);
	req = request(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 36, stub);
	req->payload[4] = 0;
	value16 = htobe16(req->payload_sz);
	memcpy(req->payload + 8, &value16, 2);
	value16 = htobe16(36);
	memcpy(req->payload + 22, &value16, 2);
	value32 = htobe32(1);
	memcpy(req->payload + 12, &value32, 4);
	value32 = htobe32(stub->len);
	memcpy(req->payload + 16, &value32, 4);
	resp = command(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 4096);
	g_assert_cmpint(rpc_ioctl_request(req, resp, 4096), ==, 0);
	g_assert_cmpuint(resp->payload_sz, >, 212);
	g_assert_cmpuint(resp->payload[4], ==, 0);
	g_assert_cmpuint(resp->payload[208], ==, 0);
	g_assert_cmpuint(resp->payload[209], ==, 168);
	g_assert_cmpuint(resp->payload[210], ==, 0);
	g_assert_cmpuint(resp->payload[211], ==, 0);
	g_assert_cmpuint(get32(resp->payload + resp->payload_sz - 4), ==, 0);
	g_free(req);
	g_free(resp);
	g_byte_array_unref(stub);
	g_byte_array_unref(user);
	g_byte_array_unref(domain);
	g_byte_array_unref(server);
	fixture_destroy();
}

static void test_alias_membership_access(void)
{
	GByteArray *server, *domain, *stub = g_byte_array_new(), *result;
	unsigned int access;

	fixture_init();
	open_pipe(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 0xac, 1);
	server = samr_connect_handle();
	for (access = 0; access <= 0x80; access += 0x80) {
		g_byte_array_set_size(stub, 0);
		g_byte_array_append(stub, server->data, 20);
		put32(stub, access);
		put32(stub, local_domain_sid[1]);
		g_byte_array_append(stub, local_domain_sid, sizeof(local_domain_sid));
		domain = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 7, stub, 128);
		g_assert_cmpuint(get32(domain->data + 20), ==, 0);
		g_byte_array_set_size(stub, 0);
		g_byte_array_append(stub, domain->data, 20);
		put32(stub, 0);
		put32(stub, 0);
		result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 16, stub, 128);
		g_assert_cmpuint(get32(result->data + result->len - 4), ==,
				 access ? 0 : KSMBD_NT_STATUS_ACCESS_DENIED);
		if (access)
			g_assert_cmpuint(get32(result->data), ==, 0);
		g_byte_array_unref(result);
		g_byte_array_unref(domain);
	}
	g_byte_array_unref(server);
	g_byte_array_unref(stub);
	fixture_destroy();
}

static void test_connect_revision(void)
{
	GByteArray *stub, *result;
	unsigned int revisions[] = { 0, 1, 3, 0xffffffff };
	unsigned int i;

	fixture_init();
	open_pipe(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 0xac, 1);
	for (i = 0; i < G_N_ELEMENTS(revisions); i++) {
		__u32 revision = htole32(revisions[i]);
		__u32 features = htole32(10);

		stub = connect_stub();
		memcpy(stub->data + 16, &revision, 4);
		memcpy(stub->data + 20, &features, 4);
		result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 64, stub, 128);
		g_assert_cmpuint(get32(result->data), ==, 1);
		g_assert_cmpuint(get32(result->data + 4), ==, 1);
		g_assert_cmpuint(get32(result->data + 8), ==, 3);
		g_assert_cmpuint(get32(result->data + 12), ==, 0);
		g_assert_cmpuint(get32(result->data + result->len - 4), ==, 0);
		g_byte_array_unref(result);
		/* Even an error must contain a valid revision union discriminator. */
		g_byte_array_set_size(stub, 8);
		result = exchange(1, KSMBD_RPC_SAMR_METHOD_INVOKE, 64, stub, 128);
		g_assert_cmpuint(get32(result->data), ==, 1);
		g_assert_cmpuint(get32(result->data + 4), ==, 1);
		g_assert_cmpuint(get32(result->data + result->len - 4), ==,
				 KSMBD_NT_STATUS_INVALID_PARAMETER);
		g_byte_array_unref(result);
		g_byte_array_unref(stub);
	}
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
	g_test_add_func("/rpc/srvsvc/security-descriptor", test_share_security_descriptor);
	g_test_add_func("/rpc/info-fragmentation", test_info_fragmentation);
	g_test_add_func("/rpc/samr/account-namespaces", test_account_namespaces);
	g_test_add_func("/rpc/lsarpc/account-names", test_lsa_account_names);
	g_test_add_func("/rpc/alter-context", test_alter_context);
	g_test_add_func("/rpc/samr/connect-revision", test_connect_revision);
	g_test_add_func("/rpc/samr/alias-membership-access", test_alias_membership_access);
	g_test_add_func("/rpc/samr/user-all-big-endian", test_user_all_big_endian);
	g_test_add_func("/rpc/unicode-account-names", test_unicode_account_names);
	g_test_add_func("/rpc/samr/user-path-consistency", test_user_path_consistency);
	g_test_add_func("/rpc/samr/enum-sizes", test_samr_enum_sizes);
	g_test_add_func("/rpc/samr/enum-mutation", test_samr_enum_mutation);
	g_test_add_func("/rpc/lsarpc/ignored-translations", test_lsa_ignored_translations);
	g_test_add_func("/rpc/lsarpc/lookup-scope", test_lsa_lookup_scope);
	g_test_add_func("/rpc/lsarpc/unmapped-sids", test_lsa_unmapped_sids);
	g_test_add_func("/rpc/lsarpc/predefined", test_lsa_predefined);
	g_test_add_func("/rpc/samr/group-alias-membership", test_group_alias_membership);
	g_test_add_func("/rpc/handle-grants", test_handle_grants);
	g_test_add_func("/rpc/samr/user-all-access-fields", test_user_all_access_fields);
	return g_test_run();
}
