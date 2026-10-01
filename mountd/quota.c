// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/quota.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <linux/btrfs.h>
#include <linux/btrfs_tree.h>
#include <linux/magic.h>
#include <glib.h>

#include "quota.h"
#include "tools.h"
#include "management/share.h"
#include "management/session.h"

/* Allow building with headers predating quotactl_fd on these Linux ABIs. */
#ifndef SYS_quotactl_fd
#if (defined(__x86_64__) && !defined(__ILP32__)) || defined(__i386__) || \
    defined(__aarch64__) || defined(__arm__) || defined(__riscv)
#define SYS_quotactl_fd 443
#endif
#endif

struct quota_map {
	uint32_t uid;
	uint64_t qgroup;
};

static int quota_fd(int fd, unsigned int command, uint32_t uid, void *data)
{
#ifdef SYS_quotactl_fd
	if (syscall(SYS_quotactl_fd, fd, QCMD(command, USRQUOTA), uid, data))
		return -errno;
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

static int quota_bytes(uint64_t blocks, __s64 *bytes)
{
	if (blocks > INT64_MAX / QIF_DQBLKSIZE)
		return -EOVERFLOW;
	*bytes = blocks ? (__s64)(blocks * QIF_DQBLKSIZE) : -1;
	return 0;
}

static int quota_native(int fd, const struct ksmbd_quota_request *req,
			struct ksmbd_quota_response *resp)
{
	struct if_nextdqblk next = { 0 };
	struct if_dqblk limits = { 0 };
	int ret;

	if (req->command == KSMBD_QUOTA_PROBE) {
		struct if_dqinfo info;

		return quota_fd(fd, Q_GETINFO, 0, &info);
	}
	if (req->command == KSMBD_QUOTA_SET) {
		/* Zero in this API disables a limit rather than prohibiting writes. */
		if (!req->threshold || !req->limit)
			return -EOPNOTSUPP;
		if (req->threshold > INT64_MAX - (QIF_DQBLKSIZE - 1) ||
		    req->limit > INT64_MAX - (QIF_DQBLKSIZE - 1))
			return -EOVERFLOW;
		limits.dqb_bsoftlimit = req->threshold == -1 ? 0 :
			((uint64_t)req->threshold + QIF_DQBLKSIZE - 1) /
			QIF_DQBLKSIZE;
		limits.dqb_bhardlimit = req->limit == -1 ? 0 :
			((uint64_t)req->limit + QIF_DQBLKSIZE - 1) /
			QIF_DQBLKSIZE;
		limits.dqb_valid = QIF_BLIMITS;
		return quota_fd(fd, Q_SETQUOTA, req->uid, &limits);
	}

	/* GETNEXT avoids creating a record when an explicit SID has no quota. */
	ret = quota_fd(fd, Q_GETNEXTQUOTA, req->uid, &next);
	if (ret)
		return ret;
	if (next.dqb_id < req->uid || next.dqb_id == UINT32_MAX)
		return -EIO;
	if (req->command == KSMBD_QUOTA_GET && next.dqb_id != req->uid)
		return -ENOENT;
	if (next.dqb_curspace > INT64_MAX)
		return -EOVERFLOW;
	ret = quota_bytes(next.dqb_bsoftlimit, &resp->threshold);
	if (ret)
		return ret;
	ret = quota_bytes(next.dqb_bhardlimit, &resp->limit);
	if (ret)
		return ret;
	resp->uid = next.dqb_id;
	resp->used = next.dqb_curspace;
	return 0;
}

static int quota_map_cmp(const void *a, const void *b)
{
	const struct quota_map *ma = a, *mb = b;

	return (ma->uid > mb->uid) - (ma->uid < mb->uid);
}

static int quota_number(const char *str, char **end, uint64_t *value)
{
	if (!g_ascii_isdigit(*str))
		return -EINVAL;
	errno = 0;
	*value = g_ascii_strtoull(str, end, 10);
	return errno || *end == str ? -EINVAL : 0;
}

static int quota_parse_map(const char *text, GArray **result)
{
	g_auto(GStrv) tokens = NULL;
	GArray *maps;
	unsigned int i, j;
	int ret = -EINVAL;

	if (!text || !*text)
		return -EOPNOTSUPP;
	maps = g_array_new(FALSE, FALSE, sizeof(struct quota_map));
	tokens = g_strsplit_set(text, " ,\t", -1);
	for (i = 0; tokens[i]; i++) {
		struct quota_map map;
		uint64_t uid, level, id;
		char *end, *p = tokens[i];

		if (!*p)
			continue;
		if (quota_number(p, &end, &uid) || *end != ':' ||
		    uid >= UINT32_MAX)
			goto out;
		p = end + 1;
		if (quota_number(p, &end, &level) || *end != '/' ||
		    level > UINT16_MAX)
			goto out;
		p = end + 1;
		if (quota_number(p, &end, &id) || *end || !id ||
		    id >= (1ULL << 48))
			goto out;
		map.uid = uid;
		map.qgroup = (level << 48) | id;
		/* Two users must not change the same qgroup through this share. */
		for (j = 0; j < maps->len; j++) {
			struct quota_map *old = &g_array_index(maps, struct quota_map, j);

			if (old->uid == map.uid || old->qgroup == map.qgroup)
				goto out;
		}
		g_array_append_val(maps, map);
	}
	if (!maps->len)
		goto out;
	g_array_sort(maps, quota_map_cmp);
	*result = maps;
	return 0;
out:
	g_array_free(maps, TRUE);
	return ret;
}

static int quota_btrfs_item(int fd, unsigned int type, uint64_t qgroup,
			    void *item, size_t size)
{
	struct btrfs_ioctl_search_args args = { 0 };
	struct btrfs_ioctl_search_header hdr;

	args.key.tree_id = BTRFS_QUOTA_TREE_OBJECTID;
	args.key.min_objectid = 0;
	args.key.max_objectid = 0;
	args.key.min_type = type;
	args.key.max_type = type;
	args.key.min_offset = qgroup;
	args.key.max_offset = qgroup;
	args.key.max_transid = UINT64_MAX;
	args.key.nr_items = 1;
	if (ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args))
		return -errno;
	if (!args.key.nr_items)
		return -ENOENT;
	memcpy(&hdr, args.buf, sizeof(hdr));
	if (args.key.nr_items != 1 || hdr.objectid || hdr.type != type ||
	    hdr.offset != qgroup || hdr.len < size ||
	    hdr.len > sizeof(args.buf) - sizeof(hdr))
		return -EIO;
	memcpy(item, args.buf + sizeof(hdr), size);
	return 0;
}

static int quota_btrfs_get(int fd, uint64_t qgroup,
			   struct ksmbd_quota_response *resp)
{
	struct btrfs_qgroup_info_item info;
	struct btrfs_qgroup_limit_item limit;
	uint64_t flags, used, max;
	int ret;

	ret = quota_btrfs_item(fd, BTRFS_QGROUP_INFO_KEY, qgroup, &info, sizeof(info));
	if (ret)
		return ret;
	ret = quota_btrfs_item(fd, BTRFS_QGROUP_LIMIT_KEY, qgroup, &limit, sizeof(limit));
	if (ret)
		return ret;
	flags = le64toh(limit.flags);
	used = le64toh(info.rfer);
	max = le64toh(limit.max_rfer);
	if (used > INT64_MAX ||
	    ((flags & BTRFS_QGROUP_LIMIT_MAX_RFER) && max > INT64_MAX))
		return -EOVERFLOW;
	resp->used = used;
	resp->threshold = -1;
	resp->limit = flags & BTRFS_QGROUP_LIMIT_MAX_RFER ? (__s64)max : -1;
	return 0;
}

static int quota_btrfs_volume(int target_fd, struct ksmbd_share *share)
{
	struct btrfs_ioctl_fs_info_args root_info = { 0 }, target_info = { 0 };
	struct statfs fs;
	g_autofree char *path = NULL;
	int fd, ret = 0;

	if (!share->path)
		return -EINVAL;
	path = global_conf.root_dir ?
		g_strdup_printf("%s/%s", global_conf.root_dir, share->path) :
		g_strdup(share->path);
	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT || errno == ENOTDIR ? -ESTALE : -errno;
	if (fstatfs(fd, &fs))
		ret = -errno;
	else if (fs.f_type != BTRFS_SUPER_MAGIC)
		ret = -EOPNOTSUPP;
	else if (ioctl(fd, BTRFS_IOC_FS_INFO, &root_info) ||
		 ioctl(target_fd, BTRFS_IOC_FS_INFO, &target_info))
		ret = -errno;
	/* statfs fsid also includes the subvolume ID on Btrfs. */
	else if (memcmp(root_info.fsid, target_info.fsid, sizeof(root_info.fsid)))
		ret = -EOPNOTSUPP;
	close(fd);
	return ret;
}

static int quota_btrfs(int fd, struct ksmbd_share *share,
		       const struct ksmbd_quota_request *req,
		       struct ksmbd_quota_response *resp)
{
	struct btrfs_qgroup_status_item status;
	GArray *maps = NULL;
	uint64_t flags;
	unsigned int i;
	int ret;

	ret = quota_btrfs_volume(fd, share);
	if (ret)
		return ret;
	ret = quota_parse_map(share->btrfs_quota_map, &maps);
	if (ret)
		return ret;
	ret = quota_btrfs_item(fd, BTRFS_QGROUP_STATUS_KEY, 0, &status, sizeof(status));
	if (ret) {
		if (ret == -ENOENT)
			ret = -EOPNOTSUPP;
		goto out;
	}
	flags = le64toh(status.flags);
	if (!(flags & BTRFS_QGROUP_STATUS_FLAG_ON)) {
		ret = -EOPNOTSUPP;
		goto out;
	}
	if (req->command == KSMBD_QUOTA_PROBE) {
		ret = 0;
		goto out;
	}
	if (req->command != KSMBD_QUOTA_SET &&
	    (flags & (BTRFS_QGROUP_STATUS_FLAG_INCONSISTENT |
		      BTRFS_QGROUP_STATUS_FLAG_RESCAN))) {
		ret = -EAGAIN;
		goto out;
	}
	ret = -ENOENT;
	for (i = 0; i < maps->len; i++) {
		struct quota_map *map = &g_array_index(maps, struct quota_map, i);

		if (map->uid < req->uid)
			continue;
		if (req->command != KSMBD_QUOTA_GET_NEXT && map->uid != req->uid)
			break;
		if (req->command == KSMBD_QUOTA_SET) {
			struct btrfs_ioctl_qgroup_limit_args args = { 0 };

			if (req->threshold != -1) {
				ret = -EOPNOTSUPP;
				break;
			}
			args.qgroupid = map->qgroup;
			args.lim.flags = BTRFS_QGROUP_LIMIT_MAX_RFER;
			args.lim.max_rfer = req->limit == -1 ? UINT64_MAX : (uint64_t)req->limit;
			ret = ioctl(fd, BTRFS_IOC_QGROUP_LIMIT, &args) ? -errno : 0;
			break;
		}
		ret = quota_btrfs_get(fd, map->qgroup, resp);
		if (ret == -ENOENT && req->command == KSMBD_QUOTA_GET_NEXT)
			continue;
		if (!ret)
			resp->uid = map->uid;
		break;
	}
out:
	g_array_free(maps, TRUE);
	return ret;
}

void quota_handle_request(const struct ksmbd_quota_request *req, size_t size,
			  struct ksmbd_quota_response *resp)
{
	struct ksmbd_share *share = NULL;
	struct stat st;
	struct statfs fs;
	uid_t uid;
	unsigned int flags;
	int fd = -1, ret = -EINVAL;

	memset(resp, 0, sizeof(*resp));
	if (size >= sizeof(req->handle))
		resp->handle = req->handle;
	if (size < sizeof(*req))
		goto out;
	resp->cookie = req->cookie;
	resp->uid = req->uid;
	if (req->path_len < 2 || req->path_len > KSMBD_QUOTA_MAX_PATH ||
	    size != sizeof(*req) + req->path_len || req->path[0] != '/' ||
	    strnlen((const char *)req->path, req->path_len) != req->path_len - 1 ||
	    req->uid == UINT32_MAX || req->command < KSMBD_QUOTA_GET ||
	    req->command > KSMBD_QUOTA_PROBE)
		goto out;
	if (req->command == KSMBD_QUOTA_SET &&
	    (req->threshold < -1 || req->limit < -1)) {
		ret = -EOPNOTSUPP;
		goto out;
	}
	ret = sm_get_quota_context(req->session_id, req->connect_id,
				   &share, &uid, &flags);
	if (ret) {
		if (ret == -ENOENT)
			ret = -EACCES;
		goto out;
	}
	ret = -EACCES;
	if ((flags & KSMBD_TREE_CONN_FLAG_GUEST_ACCOUNT) &&
	    req->command != KSMBD_QUOTA_PROBE)
		goto out;
	if ((req->command == KSMBD_QUOTA_GET_NEXT ||
	     req->command == KSMBD_QUOTA_SET) && uid != 0)
		goto out;
	if (req->command == KSMBD_QUOTA_GET && uid != 0 && req->uid != uid)
		goto out;
	if (req->command == KSMBD_QUOTA_SET &&
	    !(flags & KSMBD_TREE_CONN_FLAG_WRITABLE))
		goto out;

	fd = open((const char *)req->path,
		  O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
	if (fd < 0) {
		ret = errno == ENOENT || errno == ENOTDIR ? -ESTALE : -errno;
		goto out;
	}
	if (fstat(fd, &st) || fstatfs(fd, &fs)) {
		ret = -errno;
		goto out;
	}
	/* Refuse a renamed/replaced path or a different mount namespace. */
	if (st.st_ino != req->ino || major(st.st_dev) != req->dev_major ||
	    minor(st.st_dev) != req->dev_minor ||
	    fs.f_fsid.__val[0] != req->fsid[0] || fs.f_fsid.__val[1] != req->fsid[1]) {
		ret = -ESTALE;
		goto out;
	}
	if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) {
		ret = -EOPNOTSUPP;
		goto out;
	}
	if (fs.f_type == BTRFS_SUPER_MAGIC)
		ret = quota_btrfs(fd, share, req, resp);
	else
		ret = quota_native(fd, req, resp);
out:
	if (fd >= 0)
		close(fd);
	put_ksmbd_share(share);
	resp->status = ret;
}
