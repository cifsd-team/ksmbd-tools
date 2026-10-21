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
	return share;
}

void put_ksmbd_share(struct ksmbd_share *share)
{
	(void)share;
}

struct ksmbd_share *shm_lookup_share(char *name)
{
	(void)name;
	return NULL;
}

void shm_iter_shares(share_cb cb, void *data)
{
	(void)cb;
	(void)data;
}

unsigned int sm_session_count(void)
{
	return 0;
}

static void put16(GByteArray *buf, uint16_t value)
{
	value = htole16(value);
	g_byte_array_append(buf, (void *)&value, sizeof(value));
}

static void put32(GByteArray *buf, uint32_t value)
{
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
	g_assert_cmpuint(get32(resp->payload + 44), ==, 0);
	g_byte_array_unref(stub);
	g_free(req);
	g_free(resp);
}

static GByteArray *exchange(unsigned int id, unsigned int flags,
			    unsigned int opnum, GByteArray *stub,
			    size_t capacity)
{
	struct ksmbd_rpc_command *req = request(id, flags, opnum, stub);
	struct ksmbd_rpc_command *resp = command(id, flags, capacity);
	GByteArray *result = g_byte_array_new();
	unsigned int fragments = 0;
	size_t total = 0;
	int ret;

	ret = rpc_ioctl_request(req, resp, capacity);
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
		g_assert_cmpuint(get32(resp->payload + 16), ==, total);
		g_byte_array_append(result, (void *)(resp->payload + 24),
				    resp->payload_sz - 24);
		if (resp->payload[3] & DCERPC_PFC_LAST_FRAG)
			break;
		g_assert_cmpuint(resp->payload_sz - 24, >, 0);
		g_assert_cmpuint((resp->payload_sz - 24) % 8, ==, 0);
		g_assert_cmpuint(++fragments, <, 10000);
		ret = rpc_read_request(req, resp, capacity);
	}
	g_assert_cmpuint(result->len, ==, total);
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
	receive_limit = UINT16_MAX;
	for (i = 0; i < 1000; i++) {
		struct ksmbd_user *user = g_new0(struct ksmbd_user, 1);

		user->uid = 1000 + i;
		user->name = g_strdup_printf("user-%04u-abcdefghijklmnopqrstuvwxyz", i);
		g_ptr_array_add(users, user);
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
	return g_test_run();
}
