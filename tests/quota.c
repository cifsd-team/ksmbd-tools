// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/quota.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <linux/btrfs.h>
#include <linux/btrfs_tree.h>
#include <linux/magic.h>
#include <glib.h>
#include "quota.h"
#include "tools.h"
#include "management/share.h"
#include "management/session.h"

_Static_assert(sizeof(struct ksmbd_quota_request) == 144, "quota request ABI");
_Static_assert(offsetof(struct ksmbd_quota_request, path) == 144, "quota path ABI");
_Static_assert(sizeof(struct ksmbd_quota_response) == 112, "quota response ABI");
_Static_assert(KSMBD_EVENT_QUOTA_REQUEST == 18, "quota event ABI");
_Static_assert(KSMBD_EVENT_QUOTA_RESPONSE == 19, "quota response event ABI");

struct smbconf_global global_conf;
static struct ksmbd_share share;
static uid_t session_uid;
static unsigned int conn_flags;
static int session_error, calls, updates, stale, other_volume;
static int is_btrfs, short_item, missing, quota_error;
static int open_error;
static uint64_t status_flags, qgroup_limit, last_qgroup, limit_flags;
static struct if_nextdqblk native;
static struct if_dqblk native_update;

int sm_get_quota_context(unsigned long long session, unsigned long long tree,
			 struct ksmbd_share **result, uid_t *uid,
			 unsigned int *flags)
{
	g_assert_cmpuint(session, ==, 7);
	g_assert_cmpuint(tree, ==, 8);
	if (session_error)
		return session_error;
	*result = &share;
	*uid = session_uid;
	*flags = conn_flags;
	return 0;
}

void put_ksmbd_share(struct ksmbd_share *unused)
{
	(void)unused;
}

int __wrap_open(const char *path, int flags, ...)
{
	g_assert_true(flags & O_CLOEXEC);
	if (!strcmp(path, "/share"))
		return 112;
	g_assert_cmpstr(path, ==, "/target");
	g_assert_true(flags & O_NOFOLLOW);
	if (open_error) {
		errno = open_error;
		return -1;
	}
	return 111;
}

int __wrap_open64(const char *path, int flags, ...)
{
	return __wrap_open(path, flags);
}

int __wrap_close(int fd)
{
	g_assert_true(fd == 111 || fd == 112);
	return 0;
}

int __wrap_fstat(int fd, struct stat *st)
{
	g_assert_cmpint(fd, ==, 111);
	memset(st, 0, sizeof(*st));
	st->st_ino = 99 + (stale == 1);
	st->st_dev = makedev(8, 1 + (stale == 2));
	st->st_mode = S_IFDIR | 0755;
	return 0;
}

int __wrap_fstatfs(int fd, struct statfs *st)
{
	memset(st, 0, sizeof(*st));
	st->f_type = is_btrfs ? BTRFS_SUPER_MAGIC : EXT4_SUPER_MAGIC;
	st->f_fsid.__val[0] = 123 + (stale == 3) + (fd == 112 && other_volume);
	st->f_fsid.__val[1] = 456;
	if (fd == 112 && is_btrfs)
		st->f_fsid.__val[1] ^= 256;
	return 0;
}

int __wrap_fstat64(int fd, struct stat64 *st)
{
	g_assert_cmpint(fd, ==, 111);
	memset(st, 0, sizeof(*st));
	st->st_ino = 99 + (stale == 1);
	st->st_dev = makedev(8, 1 + (stale == 2));
	st->st_mode = S_IFDIR | 0755;
	return 0;
}

int __wrap_fstatfs64(int fd, struct statfs64 *st)
{
	memset(st, 0, sizeof(*st));
	st->f_type = is_btrfs ? BTRFS_SUPER_MAGIC : EXT4_SUPER_MAGIC;
	st->f_fsid.__val[0] = 123 + (stale == 3) + (fd == 112 && other_volume);
	st->f_fsid.__val[1] = 456;
	if (fd == 112 && is_btrfs)
		st->f_fsid.__val[1] ^= 256;
	return 0;
}

long __wrap_syscall(long number, ...)
{
	va_list args;
	int fd;
	unsigned int op, uid;
	void *data;

#ifdef SYS_quotactl_fd
	g_assert_cmpint(number, ==, SYS_quotactl_fd);
#else
	g_assert_cmpint(number, ==, 443);
#endif
	calls++;
	va_start(args, number);
	fd = va_arg(args, int);
	op = va_arg(args, unsigned int);
	uid = va_arg(args, unsigned int);
	data = va_arg(args, void *);
	va_end(args);
	g_assert_cmpint(fd, ==, 111);
	g_assert_cmpuint(uid, ==, op == (unsigned int)QCMD((unsigned int)Q_GETINFO, USRQUOTA) ? 0 : 1000);
	if (quota_error) {
		errno = quota_error;
		return -1;
	}
	if (op == (unsigned int)QCMD((unsigned int)Q_GETINFO, USRQUOTA)) {
		memset(data, 0, sizeof(struct if_dqinfo));
	} else if (op == (unsigned int)QCMD((unsigned int)Q_SETQUOTA, USRQUOTA)) {
		native_update = *(struct if_dqblk *)data;
		updates++;
	} else {
		g_assert_cmpuint(op, ==, (unsigned int)QCMD((unsigned int)Q_GETNEXTQUOTA, USRQUOTA));
		*(struct if_nextdqblk *)data = native;
	}
	return 0;
}

int __wrap_ioctl(int fd, unsigned long command, ...)
{
	va_list args;
	void *data;

	calls++;
	va_start(args, command);
	data = va_arg(args, void *);
	va_end(args);
	if (command == BTRFS_IOC_FS_INFO) {
		struct btrfs_ioctl_fs_info_args *info = data;

		g_assert_true(fd == 111 || fd == 112);
		memset(info, 0, sizeof(*info));
		info->fsid[0] = 42 + (fd == 112 && other_volume);
		return 0;
	}
	g_assert_cmpint(fd, ==, 111);
	if (command == BTRFS_IOC_QGROUP_LIMIT) {
		struct btrfs_ioctl_qgroup_limit_args *limit = data;

		g_assert_cmpuint(limit->lim.flags, ==, BTRFS_QGROUP_LIMIT_MAX_RFER);
		updates++;
		last_qgroup = limit->qgroupid;
		qgroup_limit = limit->lim.max_rfer;
		return 0;
	} else {
		struct btrfs_ioctl_search_args *search = data;
		struct btrfs_ioctl_search_header header = { 0 };
		struct btrfs_qgroup_status_item status = { 0 };
		struct btrfs_qgroup_info_item info = { 0 };
		struct btrfs_qgroup_limit_item limit = { 0 };
		void *item;

		g_assert_cmpuint(command, ==, BTRFS_IOC_TREE_SEARCH);
		g_assert_cmpuint(search->key.tree_id, ==, BTRFS_QUOTA_TREE_OBJECTID);
		g_assert_cmpuint(search->key.min_type, ==, search->key.max_type);
		g_assert_cmpuint(search->key.min_offset, ==, search->key.max_offset);
		g_assert_cmpuint(search->key.nr_items, ==, 1);
		search->key.nr_items = 1;
		header.type = search->key.min_type;
		header.offset = search->key.min_offset;
		if (header.type == BTRFS_QGROUP_STATUS_KEY) {
			header.len = sizeof(status);
			status.flags = htole64(status_flags);
			item = &status;
		} else if (header.type == BTRFS_QGROUP_INFO_KEY) {
			if (missing && header.offset == 256) {
				search->key.nr_items = 0;
				return 0;
			}
			header.len = sizeof(info);
			info.rfer = htole64(12345);
			info.rfer_cmpr = htole64(10000);
			item = &info;
		} else {
			g_assert_cmpuint(header.type, ==, BTRFS_QGROUP_LIMIT_KEY);
			header.len = sizeof(limit);
			limit.flags = htole64(limit_flags);
			limit.max_rfer = htole64(qgroup_limit);
			item = &limit;
		}
		memcpy(search->buf + sizeof(header), item, header.len);
		if (short_item)
			header.len = 0;
		memcpy(search->buf, &header, sizeof(header));
		return 0;
	}
}

static struct ksmbd_quota_request *request(unsigned int command)
{
	struct ksmbd_quota_request *req;

	req = g_malloc0(sizeof(*req) + sizeof("/target"));
	req->handle = 42;
	req->cookie = 0x123456789abcdef0ULL;
	req->command = command;
	req->session_id = 7;
	req->connect_id = 8;
	req->ino = 99;
	req->uid = 1000;
	req->dev_major = 8;
	req->dev_minor = 1;
	req->fsid[0] = 123;
	req->fsid[1] = 456;
	req->path_len = sizeof("/target");
	memcpy(req->path, "/target", req->path_len);
	req->threshold = -1;
	req->limit = 1048576;
	return req;
}

static int run(struct ksmbd_quota_request *req, struct ksmbd_quota_response *resp)
{
	quota_handle_request(req, sizeof(*req) + sizeof("/target"), resp);
	g_assert_cmpuint(resp->handle, ==, req->handle);
	g_assert_cmpuint(resp->cookie, ==, req->cookie);
	return resp->status;
}

static void reset(void)
{
	memset(&global_conf, 0, sizeof(global_conf));
	memset(&share, 0, sizeof(share));
	share.path = "/share";
	share.btrfs_quota_map = "1001:0/257, 1000:0/256";
	session_uid = 0;
	conn_flags = KSMBD_TREE_CONN_FLAG_WRITABLE;
	session_error = calls = updates = stale = other_volume = 0;
	is_btrfs = short_item = missing = quota_error = 0;
	open_error = 0;
	status_flags = BTRFS_QGROUP_STATUS_FLAG_ON;
	qgroup_limit = 1000000;
	limit_flags = BTRFS_QGROUP_LIMIT_MAX_RFER;
	memset(&native, 0, sizeof(native));
	memset(&native_update, 0, sizeof(native_update));
	native.dqb_id = 1000;
	native.dqb_curspace = 2048;
	native.dqb_bsoftlimit = 3;
	native.dqb_bhardlimit = 4;
}

static void test_auth(void)
{
	struct ksmbd_quota_request *req = request(KSMBD_QUOTA_SET);
	struct ksmbd_quota_response resp;

	reset();
	session_uid = 1000;
	g_assert_cmpint(run(req, &resp), ==, -EACCES);
	req->command = KSMBD_QUOTA_GET_NEXT;
	g_assert_cmpint(run(req, &resp), ==, -EACCES);
	req->command = KSMBD_QUOTA_GET;
	session_uid = 1001;
	g_assert_cmpint(run(req, &resp), ==, -EACCES);
	session_uid = 1000;
	conn_flags |= KSMBD_TREE_CONN_FLAG_GUEST_ACCOUNT;
	g_assert_cmpint(run(req, &resp), ==, -EACCES);
	g_assert_cmpint(calls, ==, 0);
	conn_flags = 0;
	session_uid = 0;
	req->command = KSMBD_QUOTA_SET;
	g_assert_cmpint(run(req, &resp), ==, -EACCES);
	conn_flags = KSMBD_TREE_CONN_FLAG_WRITABLE;
	session_error = -ENOENT;
	g_assert_cmpint(run(req, &resp), ==, -EACCES);
	g_assert_cmpint(updates, ==, 0);
	g_free(req);
}

static void test_identity(void)
{
	struct ksmbd_quota_request *req = request(KSMBD_QUOTA_SET);
	struct ksmbd_quota_response resp;

	reset();
	for (stale = 1; stale <= 3; stale++)
		g_assert_cmpint(run(req, &resp), ==, -ESTALE);
	g_assert_cmpint(calls, ==, 0);
	stale = 0;
	open_error = ENOENT;
	g_assert_cmpint(run(req, &resp), ==, -ESTALE);
	open_error = ENOTDIR;
	g_assert_cmpint(run(req, &resp), ==, -ESTALE);
	open_error = EACCES;
	g_assert_cmpint(run(req, &resp), ==, -EACCES);
	open_error = 0;
	is_btrfs = other_volume = 1;
	g_assert_cmpint(run(req, &resp), ==, -EOPNOTSUPP);
	g_assert_cmpint(updates, ==, 0);
	g_free(req);
}

static void test_request(void)
{
	struct ksmbd_quota_request *req = request(KSMBD_QUOTA_SET);
	struct ksmbd_quota_response resp;

	reset();
	req->path_len = UINT32_MAX;
	g_assert_cmpint(run(req, &resp), ==, -EINVAL);
	req->path_len = sizeof("/target");
	req->path[3] = 0;
	g_assert_cmpint(run(req, &resp), ==, -EINVAL);
	req->path[3] = 'r';
	req->command = 99;
	g_assert_cmpint(run(req, &resp), ==, -EINVAL);
	req->command = KSMBD_QUOTA_SET;
	req->limit = -2;
	g_assert_cmpint(run(req, &resp), ==, -EOPNOTSUPP);
	g_assert_cmpint(calls, ==, 0);
	quota_handle_request(req, 4, &resp);
	g_assert_cmpint(resp.status, ==, -EINVAL);
	g_free(req);
}

static void test_reserved(void)
{
	struct ksmbd_quota_request *req = request(KSMBD_QUOTA_GET);
	struct ksmbd_quota_response resp;
	unsigned int i;

	reset();
	memset(req->reserved, 0xa5, sizeof(req->reserved));
	memset(&resp, 0xa5, sizeof(resp));
	g_assert_cmpint(run(req, &resp), ==, 0);
	g_assert_cmpuint(resp.used, ==, 2048);
	g_assert_cmpint(resp.limit, ==, 4096);
	for (i = 0; i < G_N_ELEMENTS(resp.reserved); i++)
		g_assert_cmpuint(resp.reserved[i], ==, 0);
	g_free(req);
}

static void test_native(void)
{
	struct ksmbd_quota_request *req = request(KSMBD_QUOTA_GET);
	struct ksmbd_quota_response resp;

	reset();
	session_uid = 1000;
	g_assert_cmpint(run(req, &resp), ==, 0);
	g_assert_cmpuint(resp.used, ==, 2048);
	g_assert_cmpint(resp.threshold, ==, 3072);
	g_assert_cmpint(resp.limit, ==, 4096);
	native.dqb_id = 1001;
	g_assert_cmpint(run(req, &resp), ==, -ENOENT);
	session_uid = 0;
	req->command = KSMBD_QUOTA_GET_NEXT;
	g_assert_cmpint(run(req, &resp), ==, 0);
	g_assert_cmpuint(resp.uid, ==, 1001);
	native.dqb_id = 1000;
	native.dqb_bhardlimit = UINT64_MAX;
	g_assert_cmpint(run(req, &resp), ==, -EOVERFLOW);
	req->command = KSMBD_QUOTA_SET;
	req->threshold = 1025;
	g_assert_cmpint(run(req, &resp), ==, 0);
	g_assert_cmpuint(native_update.dqb_bsoftlimit, ==, 2);
	g_assert_cmpuint(native_update.dqb_bhardlimit, ==, 1024);
	g_assert_cmpuint(native_update.dqb_valid, ==, QIF_BLIMITS);
	req->threshold = -1;
	req->limit = -1;
	g_assert_cmpint(run(req, &resp), ==, 0);
	g_assert_cmpuint(native_update.dqb_bhardlimit, ==, 0);
	req->limit = 0;
	g_assert_cmpint(run(req, &resp), ==, -EOPNOTSUPP);
	req->limit = INT64_MAX;
	g_assert_cmpint(run(req, &resp), ==, -EOVERFLOW);
	req->limit = 1024;
	quota_error = EROFS;
	g_assert_cmpint(run(req, &resp), ==, -EROFS);
	g_free(req);
}

static void test_btrfs(void)
{
	struct ksmbd_quota_request *req = request(KSMBD_QUOTA_GET_NEXT);
	struct ksmbd_quota_response resp;

	reset();
	is_btrfs = 1;
	g_assert_cmpint(run(req, &resp), ==, 0);
	g_assert_cmpuint(resp.uid, ==, 1000);
	g_assert_cmpuint(resp.used, ==, 12345);
	g_assert_cmpint(resp.threshold, ==, -1);
	g_assert_cmpint(resp.limit, ==, 1000000);
	missing = 1;
	g_assert_cmpint(run(req, &resp), ==, 0);
	g_assert_cmpuint(resp.uid, ==, 1001);
	req->command = KSMBD_QUOTA_GET;
	g_assert_cmpint(run(req, &resp), ==, -ENOENT);
	missing = 0;
	limit_flags = BTRFS_QGROUP_LIMIT_RFER_CMPR;
	g_assert_cmpint(run(req, &resp), ==, 0);
	g_assert_cmpuint(resp.used, ==, 12345);
	g_assert_cmpint(resp.limit, ==, -1);
	req->command = KSMBD_QUOTA_SET;
	req->limit = 0;
	g_assert_cmpint(run(req, &resp), ==, 0);
	g_assert_cmpuint(last_qgroup, ==, 256);
	g_assert_cmpuint(qgroup_limit, ==, 0);
	req->limit = -1;
	g_assert_cmpint(run(req, &resp), ==, 0);
	g_assert_cmpuint(qgroup_limit, ==, UINT64_MAX);
	req->threshold = 1;
	g_assert_cmpint(run(req, &resp), ==, -EOPNOTSUPP);
	g_assert_cmpint(updates, ==, 2);
	g_free(req);
}

static void test_btrfs_errors(void)
{
	struct ksmbd_quota_request *req = request(KSMBD_QUOTA_GET);
	struct ksmbd_quota_response resp;
	const char *bad_maps[] = {"1000:0/256 1000:0/257", "1000:0/256 1001:0/256",
		"-1:0/256", "1000:65536/256", "1000:0/281474976710656", "1000:0/256x"};
	unsigned int i;

	reset();
	is_btrfs = 1;
	for (i = 0; i < G_N_ELEMENTS(bad_maps); i++) {
		share.btrfs_quota_map = (char *)bad_maps[i];
		g_assert_cmpint(run(req, &resp), ==, -EINVAL);
	}
	share.btrfs_quota_map = "";
	g_assert_cmpint(run(req, &resp), ==, -EOPNOTSUPP);
	share.btrfs_quota_map = "1000:0/256";
	short_item = 1;
	g_assert_cmpint(run(req, &resp), ==, -EIO);
	short_item = 0;
	status_flags = 0;
	g_assert_cmpint(run(req, &resp), ==, -EOPNOTSUPP);
	status_flags = BTRFS_QGROUP_STATUS_FLAG_ON | BTRFS_QGROUP_STATUS_FLAG_RESCAN;
	g_assert_cmpint(run(req, &resp), ==, -EAGAIN);
	g_assert_cmpint(updates, ==, 0);
	g_free(req);
}

static void test_probe(void)
{
	struct ksmbd_quota_request *req = request(KSMBD_QUOTA_PROBE);
	struct ksmbd_quota_response resp;

	reset();
	session_uid = 1001;
	conn_flags = KSMBD_TREE_CONN_FLAG_GUEST_ACCOUNT;
	g_assert_cmpint(run(req, &resp), ==, 0);
	quota_error = ESRCH;
	g_assert_cmpint(run(req, &resp), ==, -ESRCH);
	quota_error = 0;
	is_btrfs = 1;
	g_assert_cmpint(run(req, &resp), ==, 0);
	share.btrfs_quota_map = "";
	g_assert_cmpint(run(req, &resp), ==, -EOPNOTSUPP);
	g_assert_cmpint(updates, ==, 0);
	g_free(req);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/quota/probe", test_probe);
	g_test_add_func("/quota/auth", test_auth);
	g_test_add_func("/quota/open-identity", test_identity);
	g_test_add_func("/quota/request-validation", test_request);
	g_test_add_func("/quota/reserved", test_reserved);
	g_test_add_func("/quota/native", test_native);
	g_test_add_func("/quota/btrfs", test_btrfs);
	g_test_add_func("/quota/btrfs-errors", test_btrfs_errors);
	return g_test_run();
}
