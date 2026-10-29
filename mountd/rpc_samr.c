// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2020 Samsung Electronics Co., Ltd.
 *
 *   Author(s): Namjae Jeon (linkinjeon@kernel.org)
 */

/*
 * samr ([MS-SAMR]) on libdcerpc's server runtime. The coders are
 * libdcerpc's, generated from its samr.idl.
 *
 * The SAM of a standalone ksmbd has three domains:
 *
 * - The account domain, named after the host and with the SID from
 *   ksmbd.subauth, holds the ksmbd users, each with its uid as RID, and
 *   one group, "Unix Users" (RID 0xffffffff, which no uid can be), the
 *   primary group of every user.
 * - Builtin (S-1-5-32) is listed but empty.
 * - "Unix Group" (S-1-22-2) holds the POSIX groups of the ksmbd users as
 *   aliases, each with its gid as RID; their members are account domain
 *   users.
 *
 * The kernel passes no caller identity, so every handle gets at most its
 * object's public access: the read and execute rights, without changing
 * passwords.
 */

#include <errno.h>
#include <glib.h>
#include <grp.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <linux/ksmbd_server.h>

#include <dcerpc/dcerpc.h>
#include <dcerpc/dcerpc-dtyp.h>
#include <dcerpc/server.h>
#include <dcerpc/samr.h>

#include <management/share.h>
#include <management/user.h>

#include <rpc.h>
#include <rpc_samr.h>
#include <smbacl.h>
#include <tools.h>

/* [MS-SAMR] 2.2.1.3 to 2.2.1.7: the objects' all-access masks */
#define SAM_SERVER_ALL_ACCESS		0x000F003F
#define SAM_DOMAIN_ALL_ACCESS		0x000F07FF
#define SAM_USER_ALL_ACCESS		0x000F07FF
#define SAM_GROUP_ALL_ACCESS		0x000F001F
#define SAM_ALIAS_ALL_ACCESS		0x000F001F
/* and their generic mappings, [MS-SAMR] 3.1.5.1 */
#define SAM_USER_READ			0x0002031A
#define SAM_GROUP_READ			0x00020010
#define SAM_GROUP_WRITE			0x0002000E
#define SAM_GROUP_EXECUTE		0x00020001
#define SAM_ALIAS_READ			0x00020004
#define SAM_ALIAS_WRITE			0x00020013
#define SAM_ALIAS_EXECUTE		0x00020008

/* SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED */
#define SE_GROUP_DEFAULT		0x00000007

/* The fields of UserAllInformation each read right lets a caller see */
#define USER_ALL_GENERAL_FIELDS		0x0000003f
#define USER_ALL_LOGON_FIELDS		0x0003ffc0
#define USER_ALL_ACCOUNT_FIELDS		0x003c0000
#define USER_ALL_PREFERENCES_FIELDS	0x00c00000

/* S-1-5-32, the Builtin domain */
static const struct smb_sid sid_builtin = {
	1, 1, {0, 0, 0, 0, 0, 5}, {32} };
/* S-1-1-0, Everyone */
static const struct smb_sid sid_everyone = {
	1, 1, {0, 0, 0, 0, 0, 1}, {0} };
/* S-1-5-7, Anonymous Logon */
static const struct smb_sid sid_anonymous = {
	1, 1, {0, 0, 0, 0, 0, 5}, {7} };
/* S-1-5-18, Local System */
static const struct smb_sid sid_system = {
	1, 1, {0, 0, 0, 0, 0, 5}, {18} };

static gchar *domain_name;

/* The domains, in enumeration order */
enum samr_domain_kind {
	SAMR_DOMAIN_LOCAL,
	SAMR_DOMAIN_BUILTIN,
	SAMR_DOMAIN_UNIX_GROUP,
	SAMR_DOMAIN_OTHER,
};

#define SAMR_NUM_DOMAINS		3

static void samr_domain_sid(enum samr_domain_kind kind, struct smb_sid *sid)
{
	switch (kind) {
	case SAMR_DOMAIN_LOCAL:
		smb_init_domain_sid(sid);
		break;
	case SAMR_DOMAIN_BUILTIN:
		smb_copy_sid(sid, &sid_builtin);
		break;
	default:
		smb_init_unix_group_sid(sid);
		break;
	}
}

static const char *samr_domain_name(enum samr_domain_kind kind)
{
	switch (kind) {
	case SAMR_DOMAIN_LOCAL:
		return domain_name;
	case SAMR_DOMAIN_BUILTIN:
		return "Builtin";
	default:
		return SMB_UNIX_GROUP_DOMAIN;
	}
}

static enum samr_domain_kind samr_domain_of_sid(const struct smb_sid *sid)
{
	enum samr_domain_kind kind;

	for (kind = 0; kind < SAMR_NUM_DOMAINS; kind++) {
		struct smb_sid domain;

		samr_domain_sid(kind, &domain);
		if (!smb_compare_sids(sid, &domain))
			return kind;
	}
	return SAMR_DOMAIN_OTHER;
}

/* The local domain is also known by the configured NetBIOS name */
static int samr_domain_of_name(const char *name, enum samr_domain_kind *kind)
{
	if (!name)
		return -1;
	if (!ksmbd_name_compare(name, domain_name) ||
	    (global_conf.netbios_name &&
	     !ksmbd_name_compare(name, global_conf.netbios_name))) {
		*kind = SAMR_DOMAIN_LOCAL;
		return 0;
	}
	if (!ksmbd_name_compare(name, "Builtin")) {
		*kind = SAMR_DOMAIN_BUILTIN;
		return 0;
	}
	if (!ksmbd_name_compare(name, SMB_UNIX_GROUP_DOMAIN)) {
		*kind = SAMR_DOMAIN_UNIX_GROUP;
		return 0;
	}
	return -1;
}

/* ------------------------------------------------------------------ */
/* Handles and their access                                            */
/* ------------------------------------------------------------------ */

/* What a samr handle is a handle to */
enum samr_handle_type {
	SAMR_HANDLE_SERVER,
	SAMR_HANDLE_DOMAIN,
	SAMR_HANDLE_USER,
	SAMR_HANDLE_GROUP,
	SAMR_HANDLE_ALIAS,
};

struct samr_handle {
	enum samr_handle_type	type;
	unsigned int		access;		/* granted */
	/* SAMR_HANDLE_DOMAIN and the accounts: the domain */
	enum samr_domain_kind	kind;
	struct smb_sid		domain_sid;
	/* SAMR_HANDLE_USER: a reference to the user */
	struct ksmbd_user	*user;
	/* the accounts: the RID */
	uint32_t		rid;
};

static unsigned int samr_generic_read_access(enum samr_handle_type type)
{
	switch (type) {
	case SAMR_HANDLE_SERVER:
		return SAMR_SAM_SERVER_ENUMERATE_DOMAINS | SAMR_READ_CONTROL;
	case SAMR_HANDLE_DOMAIN:
		return SAMR_DOMAIN_READ_OTHER_PARAMETERS |
		       SAMR_DOMAIN_GET_ALIAS_MEMBERSHIP | SAMR_READ_CONTROL;
	case SAMR_HANDLE_USER:
		return SAM_USER_READ;
	case SAMR_HANDLE_GROUP:
		return SAM_GROUP_READ;
	case SAMR_HANDLE_ALIAS:
		return SAM_ALIAS_READ;
	}
	return 0;
}

static unsigned int samr_generic_write_access(enum samr_handle_type type)
{
	switch (type) {
	case SAMR_HANDLE_SERVER:
		return SAMR_READ_CONTROL | SAMR_SAM_SERVER_SHUTDOWN |
		       SAMR_SAM_SERVER_INITIALIZE |
		       SAMR_SAM_SERVER_CREATE_DOMAIN;
	case SAMR_HANDLE_DOMAIN:
		return SAMR_READ_CONTROL | SAMR_DOMAIN_WRITE_PASSWORD_PARAMS |
		       SAMR_DOMAIN_WRITE_OTHER_PARAMETERS |
		       SAMR_DOMAIN_CREATE_USER | SAMR_DOMAIN_CREATE_GROUP |
		       SAMR_DOMAIN_CREATE_ALIAS |
		       SAMR_DOMAIN_ADMINISTER_SERVER;
	case SAMR_HANDLE_USER:
		return SAMR_READ_CONTROL | SAMR_USER_WRITE_PREFERENCES |
		       SAMR_USER_WRITE_ACCOUNT | SAMR_USER_CHANGE_PASSWORD |
		       SAMR_USER_FORCE_PASSWORD_CHANGE |
		       SAMR_USER_WRITE_GROUP_INFORMATION;
	case SAMR_HANDLE_GROUP:
		return SAM_GROUP_WRITE;
	case SAMR_HANDLE_ALIAS:
		return SAM_ALIAS_WRITE;
	}
	return 0;
}

static unsigned int samr_generic_execute_access(enum samr_handle_type type)
{
	switch (type) {
	case SAMR_HANDLE_SERVER:
		return SAMR_READ_CONTROL | SAMR_SAM_SERVER_LOOKUP_DOMAIN |
		       SAMR_SAM_SERVER_CONNECT;
	case SAMR_HANDLE_DOMAIN:
		return SAMR_READ_CONTROL | SAMR_DOMAIN_LIST_ACCOUNTS |
		       SAMR_DOMAIN_LOOKUP | SAMR_DOMAIN_READ_PASSWORD_PARAMETERS;
	case SAMR_HANDLE_USER:
		return SAMR_READ_CONTROL | SAMR_USER_READ_GENERAL |
		       SAMR_USER_CHANGE_PASSWORD;
	case SAMR_HANDLE_GROUP:
		return SAM_GROUP_EXECUTE;
	case SAMR_HANDLE_ALIAS:
		return SAM_ALIAS_EXECUTE;
	}
	return 0;
}

static unsigned int samr_all_access(enum samr_handle_type type)
{
	switch (type) {
	case SAMR_HANDLE_SERVER:
		return SAM_SERVER_ALL_ACCESS;
	case SAMR_HANDLE_DOMAIN:
		return SAM_DOMAIN_ALL_ACCESS;
	case SAMR_HANDLE_USER:
		return SAM_USER_ALL_ACCESS;
	case SAMR_HANDLE_GROUP:
		return SAM_GROUP_ALL_ACCESS;
	case SAMR_HANDLE_ALIAS:
		return SAM_ALIAS_ALL_ACCESS;
	}
	return 0;
}

/* What anyone may do with an object: read and execute, as Windows grants
 * Everyone, but not change a user's password. */
static unsigned int samr_public_access(enum samr_handle_type type)
{
	unsigned int access = samr_generic_read_access(type) |
			      samr_generic_execute_access(type);

	if (type == SAMR_HANDLE_USER)
		access &= ~SAMR_USER_CHANGE_PASSWORD;
	return access;
}

static int samr_grant_access(enum samr_handle_type type, unsigned int desired,
			     unsigned int *granted)
{
	struct rpc_generic_mapping mapping = {
		.read = samr_generic_read_access(type),
		.write = samr_generic_write_access(type),
		.execute = samr_generic_execute_access(type),
		.all = samr_all_access(type),
	};

	return rpc_grant_access(desired, samr_public_access(type), &mapping,
				granted);
}

static void samr_handle_free(struct samr_handle *h)
{
	if (h->user)
		put_ksmbd_user(h->user);
	g_free(h);
}

/*
 * Open a handle of type, with as much of desired as the object grants.
 * user is the handle's reference. Returns 0 with the status of the
 * open, or -1 if out of memory.
 */
static int samr_handle_open(struct dcerpc_pdu *pdu,
			    enum samr_handle_type type, unsigned int desired,
			    const struct samr_handle *domain,
			    struct ksmbd_user *user, uint32_t rid,
			    struct dcerpc_context_handle *handle,
			    uint32_t *status)
{
	struct samr_handle *h;
	unsigned int granted;

	if (samr_grant_access(type, desired, &granted)) {
		if (user)
			put_ksmbd_user(user);
		*status = KSMBD_NT_STATUS_ACCESS_DENIED;
		return 0;
	}
	h = g_try_malloc0(sizeof(*h));
	if (!h) {
		if (user)
			put_ksmbd_user(user);
		return -1;
	}
	h->type = type;
	h->access = granted;
	if (domain) {
		h->kind = domain->kind;
		smb_copy_sid(&h->domain_sid, &domain->domain_sid);
	}
	h->user = user;
	h->rid = rid;
	if (rpc_pipe_handle_open(rpc_pipe_of_pdu(pdu), h,
				 (GDestroyNotify)samr_handle_free, handle)) {
		samr_handle_free(h);
		return -1;
	}
	*status = KSMBD_NT_STATUS_SUCCESS;
	return 0;
}

/*
 * The open handle, if it is one of type (or any type if type is -1) and
 * grants the required access; else NULL with the status set.
 */
static struct samr_handle *
samr_handle_get(struct dcerpc_pdu *pdu,
		const struct dcerpc_context_handle *handle, int type,
		unsigned int required, uint32_t *status)
{
	void *data;
	struct samr_handle *h;

	if (rpc_pipe_handle_lookup(rpc_pipe_of_pdu(pdu), handle, &data)) {
		*status = KSMBD_NT_STATUS_INVALID_HANDLE;
		return NULL;
	}
	h = data;
	if (type >= 0 && h->type != (enum samr_handle_type)type) {
		*status = KSMBD_NT_STATUS_INVALID_HANDLE;
		return NULL;
	}
	if ((h->access & required) != required) {
		*status = KSMBD_NT_STATUS_ACCESS_DENIED;
		return NULL;
	}
	return h;
}

/* A domain handle, of the local domain for local_only */
static struct samr_handle *
samr_domain_get(struct dcerpc_pdu *pdu,
		const struct dcerpc_context_handle *handle,
		unsigned int required, uint32_t *status)
{
	return samr_handle_get(pdu, handle, SAMR_HANDLE_DOMAIN, required,
			       status);
}

/* ------------------------------------------------------------------ */
/* The accounts                                                        */
/* ------------------------------------------------------------------ */

struct samr_account {
	uint32_t	rid;
	char		*name;
};

static void samr_account_free(gpointer data)
{
	struct samr_account *a = data;

	if (a) {
		g_free(a->name);
		g_free(a);
	}
}

static gint samr_account_cmp(gconstpointer a, gconstpointer b)
{
	const struct samr_account *ea = *(const struct samr_account *const *)a;
	const struct samr_account *eb = *(const struct samr_account *const *)b;

	if (ea->rid != eb->rid)
		return ea->rid < eb->rid ? -1 : 1;
	return ksmbd_name_compare(ea->name, eb->name);
}

static GPtrArray *samr_accounts_new(void)
{
	return g_ptr_array_new_with_free_func(samr_account_free);
}

/* Add rid as name, once; -1 if out of memory */
static int samr_accounts_add(GPtrArray *accounts, GHashTable *seen,
			     uint32_t rid, const char *name)
{
	struct samr_account *a;
	gpointer key = GUINT_TO_POINTER(rid + 1);

	if (seen && g_hash_table_contains(seen, key))
		return 0;
	a = g_try_malloc0(sizeof(*a));
	if (!a)
		return -1;
	a->rid = rid;
	a->name = g_strdup(name);
	if (!a->name) {
		g_free(a);
		return -1;
	}
	if (seen)
		g_hash_table_add(seen, key);
	g_ptr_array_add(accounts, a);
	return 0;
}

static struct samr_account *samr_accounts_by_rid(GPtrArray *accounts,
						 uint32_t rid)
{
	guint i;

	for (i = 0; accounts && i < accounts->len; i++) {
		struct samr_account *a = g_ptr_array_index(accounts, i);

		if (a->rid == rid)
			return a;
	}
	return NULL;
}

static struct samr_account *samr_accounts_by_name(GPtrArray *accounts,
						  const char *name)
{
	guint i;

	for (i = 0; name && accounts && i < accounts->len; i++) {
		struct samr_account *a = g_ptr_array_index(accounts, i);

		if (!ksmbd_name_compare(a->name, name))
			return a;
	}
	return NULL;
}

struct samr_collect {
	GPtrArray	*accounts;
	GHashTable	*seen;
	int		failed;
};

static void samr_collect_user(struct ksmbd_user *user, void *data)
{
	struct samr_collect *c = data;

	if (c->failed || !user->name || !smb_valid_user_rid(user->uid))
		return;
	c->failed = samr_accounts_add(c->accounts, c->seen, user->uid,
				      user->name);
}

/* The POSIX group gid as name, or GID-<gid> if NSS doesn't know it */
static char *samr_group_name(gid_t gid)
{
	struct group grp, *result = NULL;
	long suggested = sysconf(_SC_GETGR_R_SIZE_MAX);
	size_t size = suggested > 1024 ? suggested : 1024;
	int rc;

	for (;;) {
		g_autofree char *buf = g_try_malloc(size);

		if (!buf)
			return NULL;
		rc = getgrgid_r(gid, &grp, buf, size, &result);
		if (rc != ERANGE)
			return !rc && result && result->gr_name &&
			       result->gr_name[0] ?
			       g_strdup(result->gr_name) :
			       g_strdup_printf("GID-%u", (unsigned int)gid);
		if (size > G_MAXSIZE / 2)
			return NULL;
		size *= 2;
	}
}

static int samr_collect_gid(struct samr_collect *c, gid_t gid)
{
	g_autofree char *name = NULL;

	if (gid == (gid_t)KSMBD_SHARE_INVALID_GID ||
	    g_hash_table_contains(c->seen, GUINT_TO_POINTER(gid + 1)))
		return 0;
	name = samr_group_name(gid);
	if (!name)
		return -1;
	return samr_accounts_add(c->accounts, c->seen, gid, name);
}

static void samr_collect_groups(struct ksmbd_user *user, void *data)
{
	struct samr_collect *c = data;
	int i;

	if (c->failed)
		return;
	c->failed = samr_collect_gid(c, user->gid);
	for (i = 0; !c->failed && i < user->ngroups; i++)
		c->failed = samr_collect_gid(c, user->sgid[i]);
}

/* The accounts user_cb collects, by RID; NULL if out of memory */
static GPtrArray *samr_collect(user_cb cb)
{
	struct samr_collect c = { samr_accounts_new(), NULL, 0 };

	c.seen = g_hash_table_new(g_direct_hash, g_direct_equal);
	usm_iter_users(cb, &c);
	g_hash_table_destroy(c.seen);
	if (c.failed) {
		g_ptr_array_free(c.accounts, TRUE);
		return NULL;
	}
	g_ptr_array_sort(c.accounts, samr_account_cmp);
	return c.accounts;
}

/*
 * The local domain's users: the ksmbd users with a usable uid, if the
 * filter asks for normal accounts (its two volatile bits are ignored,
 * [MS-SAMR] 3.1.5.2.5).
 */
static GPtrArray *samr_local_users(uint32_t user_account_control)
{
	user_account_control &= ~(SAMR_USER_ACCOUNT_AUTO_LOCKED |
				  SAMR_USER_PASSWORD_EXPIRED);
	if (user_account_control & ~SAMR_USER_NORMAL_ACCOUNT)
		return samr_accounts_new();
	return samr_collect(samr_collect_user);
}

/* The local domain's one group */
static GPtrArray *samr_local_groups(void)
{
	GPtrArray *accounts = samr_accounts_new();
	g_autofree char *name = smb_local_users_name();

	if (!name || samr_accounts_add(accounts, NULL, SMB_LOCAL_USERS_RID,
				       name)) {
		g_ptr_array_free(accounts, TRUE);
		return NULL;
	}
	return accounts;
}

/* The Unix Group domain's aliases: the POSIX groups of the ksmbd users */
static GPtrArray *samr_unix_groups(void)
{
	return samr_collect(samr_collect_groups);
}

struct samr_members {
	GArray		*uids;
	uint32_t	gid;
	int		all;
};

static int samr_user_in_group(const struct ksmbd_user *user, uint32_t gid)
{
	int i;

	if (user->gid == gid)
		return 1;
	for (i = 0; i < user->ngroups; i++)
		if (user->sgid[i] == gid)
			return 1;
	return 0;
}

static void samr_collect_member(struct ksmbd_user *user, void *data)
{
	struct samr_members *m = data;
	uint32_t uid = user->uid;
	guint i;

	if (!smb_valid_user_rid(uid) ||
	    (!m->all && !samr_user_in_group(user, m->gid)))
		return;
	for (i = 0; i < m->uids->len; i++)
		if (g_array_index(m->uids, uint32_t, i) == uid)
			return;
	g_array_append_val(m->uids, uid);
}

static gint samr_uint32_cmp(gconstpointer a, gconstpointer b)
{
	uint32_t va = *(const uint32_t *)a, vb = *(const uint32_t *)b;

	return va < vb ? -1 : va > vb;
}

/* The uids of the users in POSIX group gid (or of all users), sorted */
static GArray *samr_group_members(uint32_t gid, int all)
{
	struct samr_members m = { g_array_new(FALSE, FALSE, sizeof(uint32_t)),
				  gid, all };

	usm_iter_users(samr_collect_member, &m);
	g_array_sort(m.uids, samr_uint32_cmp);
	return m.uids;
}

/* ------------------------------------------------------------------ */
/* Enumeration                                                         */
/* ------------------------------------------------------------------ */

/*
 * What an entry takes in the reply: the fixed SAMPR_RID_ENUMERATION and
 * its deferred UTF-16, in NDR32.
 */
static size_t samr_enum_entry_size(const char *name)
{
	glong units;
	g_autofree gunichar2 *utf16 = g_utf8_to_utf16(name, -1, NULL, &units,
						     NULL);

	if (!utf16 || units > UINT16_MAX / 2)
		return SIZE_MAX;
	return 12 + 12 + (((size_t)units * 2 + 3) & ~(size_t)3);
}

/*
 * The page of accounts from the enumeration context on that fits
 * PreferedMaximumLength. The context is the next RID to return (by_rid),
 * so a page is right whatever the database did in the meantime, or the
 * next index. Fills the reply's buffer, count and status.
 */
static int samr_enum_reply(struct dcerpc_pdu *pdu, GPtrArray *accounts,
			   int by_rid, uint32_t *context, uint32_t pref_max,
			   struct samr_SAMPR_ENUMERATION_BUFFER *buffer,
			   uint32_t *count_returned, uint32_t *status)
{
	guint total = accounts->len, start, count, i;
	size_t remaining = pref_max;
	uint32_t next;

	if (by_rid) {
		for (start = 0; start < total; start++) {
			struct samr_account *a = g_ptr_array_index(accounts,
								   start);

			if (a->rid >= *context)
				break;
		}
	} else {
		if (*context > total) {
			*status = KSMBD_NT_STATUS_INVALID_PARAMETER;
			return 0;
		}
		start = *context;
	}
	for (count = 0; start + count < total; count++) {
		struct samr_account *a = g_ptr_array_index(accounts,
							   start + count);
		size_t size = samr_enum_entry_size(a->name);

		if (size > remaining)
			break;
		remaining -= size;
	}
	if (start < total && !count) {
		*status = KSMBD_NT_STATUS_BUFFER_TOO_SMALL;
		return 0;
	}

	next = *context;
	if (count) {
		struct samr_account *last = g_ptr_array_index(accounts,
							      start + count - 1);

		/* UINT32_MAX can only be the last RID: it ends the enumeration */
		next = by_rid ? (last->rid == UINT32_MAX ? 0 : last->rid + 1) :
				start + count;
	}
	*context = next;

	buffer->EntriesRead = count;
	buffer->Buffer = dcerpc_alloc_data(pdu, MAX(count, 1) *
					   sizeof(*buffer->Buffer));
	if (!buffer->Buffer)
		return -1;
	for (i = 0; i < count; i++) {
		struct samr_account *a = g_ptr_array_index(accounts, start + i);

		buffer->Buffer[i].RelativeId = a->rid;
		buffer->Buffer[i].Name = rpc_pdu_strdup(pdu, a->name);
		if (!buffer->Buffer[i].Name)
			return -1;
	}
	if (!count)
		buffer->Buffer = NULL;
	*count_returned = count;
	*status = start + count < total ? KSMBD_NT_STATUS_MORE_ENTRIES :
					  KSMBD_NT_STATUS_SUCCESS;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Server                                                              */
/* ------------------------------------------------------------------ */

static int samr_restricted(struct dcerpc_pdu *pdu, uint32_t *status)
{
	if (!rpc_pipe_restricted(rpc_pipe_of_pdu(pdu)))
		return 0;
	*status = KSMBD_NT_STATUS_ACCESS_DENIED;
	return 1;
}

static int samr_connect2_stub(struct dcerpc_context *dce,
			      struct dcerpc_pdu *pdu,
			      void *reqv, void *repv)
{
	struct samr_Connect2_req *req = reqv;
	struct samr_Connect2_rep *rep = repv;

	if (samr_restricted(pdu, &rep->status))
		return 0;
	return samr_handle_open(pdu, SAMR_HANDLE_SERVER, req->DesiredAccess,
				NULL, NULL, 0, &rep->ServerHandle,
				&rep->status);
}

static int samr_connect5_stub(struct dcerpc_context *dce,
			      struct dcerpc_pdu *pdu,
			      void *reqv, void *repv)
{
	struct samr_Connect5_req *req = reqv;
	struct samr_Connect5_rep *rep = repv;

	/* [MS-SAMR] 3.1.5.1.1: version 1, revision 3, no extra features */
	rep->OutVersion = 1;
	rep->OutRevisionInfo.V1.Revision = 3;
	rep->OutRevisionInfo.V1.SupportedFeatures = 0;
	if (samr_restricted(pdu, &rep->status))
		return 0;
	if (req->InVersion != 1) {
		rep->status = KSMBD_NT_STATUS_INVALID_PARAMETER;
		return 0;
	}
	return samr_handle_open(pdu, SAMR_HANDLE_SERVER, req->DesiredAccess,
				NULL, NULL, 0, &rep->ServerHandle,
				&rep->status);
}

/* The handle in the reply stays zeroed, as a closed handle is */
static int samr_close_handle_stub(struct dcerpc_context *dce,
				  struct dcerpc_pdu *pdu,
				  void *reqv, void *repv)
{
	struct samr_CloseHandle_req *req = reqv;
	struct samr_CloseHandle_rep *rep = repv;

	if (samr_restricted(pdu, &rep->status))
		return 0;
	if (rpc_pipe_handle_close(rpc_pipe_of_pdu(pdu), &req->SamHandle))
		rep->status = KSMBD_NT_STATUS_INVALID_HANDLE;
	else
		rep->status = KSMBD_NT_STATUS_SUCCESS;
	return 0;
}

static int samr_enum_domains_stub(struct dcerpc_context *dce,
				  struct dcerpc_pdu *pdu,
				  void *reqv, void *repv)
{
	struct samr_EnumerateDomainsInSamServer_req *req = reqv;
	struct samr_EnumerateDomainsInSamServer_rep *rep = repv;
	GPtrArray *domains;
	enum samr_domain_kind kind;
	int ret = 0;

	rep->EnumerationContext = req->EnumerationContext;
	if (samr_restricted(pdu, &rep->status))
		return 0;
	if (!samr_handle_get(pdu, &req->ServerHandle, SAMR_HANDLE_SERVER,
			     SAMR_SAM_SERVER_ENUMERATE_DOMAINS, &rep->status))
		return 0;
	domains = samr_accounts_new();
	for (kind = 0; kind < SAMR_NUM_DOMAINS; kind++) {
		if (samr_accounts_add(domains, NULL, kind,
				      samr_domain_name(kind))) {
			ret = -1;
			goto out;
		}
	}
	ret = samr_enum_reply(pdu, domains, 0, &rep->EnumerationContext,
			      req->PreferedMaximumLength, &rep->Buffer,
			      &rep->CountReturned, &rep->status);
out:
	g_ptr_array_free(domains, TRUE);
	return ret;
}

static int samr_lookup_domain_stub(struct dcerpc_context *dce,
				   struct dcerpc_pdu *pdu,
				   void *reqv, void *repv)
{
	struct samr_LookupDomainInSamServer_req *req = reqv;
	struct samr_LookupDomainInSamServer_rep *rep = repv;
	enum samr_domain_kind kind;
	struct smb_sid sid;

	if (samr_restricted(pdu, &rep->status))
		return 0;
	if (!samr_handle_get(pdu, &req->ServerHandle, SAMR_HANDLE_SERVER,
			     SAMR_SAM_SERVER_LOOKUP_DOMAIN, &rep->status))
		return 0;
	if (samr_domain_of_name(req->Name, &kind)) {
		rep->status = KSMBD_NT_STATUS_NO_SUCH_DOMAIN;
		return 0;
	}
	samr_domain_sid(kind, &sid);
	rep->DomainId = smb_sid_to_rpc(pdu, &sid);
	if (!rep->DomainId)
		return -1;
	rep->status = KSMBD_NT_STATUS_SUCCESS;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Domains                                                             */
/* ------------------------------------------------------------------ */

static int samr_open_domain_stub(struct dcerpc_context *dce,
				 struct dcerpc_pdu *pdu,
				 void *reqv, void *repv)
{
	struct samr_OpenDomain_req *req = reqv;
	struct samr_OpenDomain_rep *rep = repv;
	struct samr_handle domain;

	if (samr_restricted(pdu, &rep->status))
		return 0;
	if (!samr_handle_get(pdu, &req->ServerHandle, SAMR_HANDLE_SERVER,
			     SAMR_SAM_SERVER_LOOKUP_DOMAIN, &rep->status))
		return 0;
	smb_sid_from_rpc(&domain.domain_sid, &req->DomainId);
	domain.kind = samr_domain_of_sid(&domain.domain_sid);
	if (domain.kind == SAMR_DOMAIN_OTHER) {
		rep->status = KSMBD_NT_STATUS_NO_SUCH_DOMAIN;
		return 0;
	}
	return samr_handle_open(pdu, SAMR_HANDLE_DOMAIN, req->DesiredAccess,
				&domain, NULL, 0, &rep->DomainHandle,
				&rep->status);
}

/* The accounts of the domain an enumeration lists; NULL if out of memory */
static GPtrArray *samr_domain_accounts(struct samr_handle *domain,
				       enum samr_handle_type type,
				       uint32_t user_account_control)
{
	switch (type) {
	case SAMR_HANDLE_USER:
		if (domain->kind == SAMR_DOMAIN_LOCAL)
			return samr_local_users(user_account_control);
		break;
	case SAMR_HANDLE_GROUP:
		if (domain->kind == SAMR_DOMAIN_LOCAL)
			return samr_local_groups();
		break;
	case SAMR_HANDLE_ALIAS:
		if (domain->kind == SAMR_DOMAIN_UNIX_GROUP)
			return samr_unix_groups();
		break;
	default:
		break;
	}
	return samr_accounts_new();
}

static int samr_enum_accounts(struct dcerpc_pdu *pdu,
			      const struct dcerpc_context_handle *handle,
			      enum samr_handle_type type,
			      uint32_t user_account_control,
			      uint32_t *context, uint32_t pref_max,
			      struct samr_SAMPR_ENUMERATION_BUFFER *buffer,
			      uint32_t *count_returned, uint32_t *status)
{
	struct samr_handle *domain;
	GPtrArray *accounts;
	int ret;

	if (samr_restricted(pdu, status))
		return 0;
	domain = samr_domain_get(pdu, handle, SAMR_DOMAIN_LIST_ACCOUNTS,
				 status);
	if (!domain)
		return 0;
	accounts = samr_domain_accounts(domain, type, user_account_control);
	if (!accounts)
		return -1;
	ret = samr_enum_reply(pdu, accounts, 1, context, pref_max, buffer,
			      count_returned, status);
	g_ptr_array_free(accounts, TRUE);
	return ret;
}

static int samr_enum_groups_stub(struct dcerpc_context *dce,
				 struct dcerpc_pdu *pdu,
				 void *reqv, void *repv)
{
	struct samr_EnumerateGroupsInDomain_req *req = reqv;
	struct samr_EnumerateGroupsInDomain_rep *rep = repv;

	rep->EnumerationContext = req->EnumerationContext;
	return samr_enum_accounts(pdu, &req->DomainHandle, SAMR_HANDLE_GROUP,
				  0, &rep->EnumerationContext,
				  req->PreferedMaximumLength, &rep->Buffer,
				  &rep->CountReturned, &rep->status);
}

static int samr_enum_users_stub(struct dcerpc_context *dce,
				struct dcerpc_pdu *pdu,
				void *reqv, void *repv)
{
	struct samr_EnumerateUsersInDomain_req *req = reqv;
	struct samr_EnumerateUsersInDomain_rep *rep = repv;

	rep->EnumerationContext = req->EnumerationContext;
	return samr_enum_accounts(pdu, &req->DomainHandle, SAMR_HANDLE_USER,
				  req->UserAccountControl,
				  &rep->EnumerationContext,
				  req->PreferedMaximumLength, &rep->Buffer,
				  &rep->CountReturned, &rep->status);
}

static int samr_enum_aliases_stub(struct dcerpc_context *dce,
				  struct dcerpc_pdu *pdu,
				  void *reqv, void *repv)
{
	struct samr_EnumerateAliasesInDomain_req *req = reqv;
	struct samr_EnumerateAliasesInDomain_rep *rep = repv;

	rep->EnumerationContext = req->EnumerationContext;
	return samr_enum_accounts(pdu, &req->DomainHandle, SAMR_HANDLE_ALIAS,
				  0, &rep->EnumerationContext,
				  req->PreferedMaximumLength, &rep->Buffer,
				  &rep->CountReturned, &rep->status);
}

/* The status of a lookup that mapped mapped out of count */
static uint32_t samr_lookup_status(uint32_t mapped, uint32_t count)
{
	if (mapped == count)
		return KSMBD_NT_STATUS_SUCCESS;
	return mapped ? KSMBD_NT_STATUS_SOME_NOT_MAPPED :
			KSMBD_NT_STATUS_NONE_MAPPED;
}

/* The groups (local) or aliases (Unix Group) of a domain, else NULL */
static GPtrArray *samr_domain_groups(struct samr_handle *domain, int *failed)
{
	GPtrArray *groups = NULL;

	*failed = 0;
	if (domain->kind == SAMR_DOMAIN_LOCAL)
		groups = samr_local_groups();
	else if (domain->kind == SAMR_DOMAIN_UNIX_GROUP)
		groups = samr_unix_groups();
	else
		return NULL;
	*failed = !groups;
	return groups;
}

static uint32_t samr_group_sid_type(struct samr_handle *domain)
{
	return domain->kind == SAMR_DOMAIN_LOCAL ? SID_TYPE_GROUP :
						   SID_TYPE_ALIAS;
}

/*
 * Names to RIDs: the local domain's users and its one group, the Unix
 * Group domain's aliases. Nothing maps in Builtin.
 */
static int samr_lookup_names_stub(struct dcerpc_context *dce,
				  struct dcerpc_pdu *pdu,
				  void *reqv, void *repv)
{
	struct samr_LookupNamesInDomain_req *req = reqv;
	struct samr_LookupNamesInDomain_rep *rep = repv;
	struct samr_handle *domain;
	GPtrArray *groups;
	uint32_t *rids, *uses, i, mapped = 0;
	int failed, ret = 0;

	if (samr_restricted(pdu, &rep->status))
		return 0;
	domain = samr_domain_get(pdu, &req->DomainHandle, SAMR_DOMAIN_LOOKUP,
				 &rep->status);
	if (!domain)
		return 0;
	groups = samr_domain_groups(domain, &failed);
	if (failed)
		return -1;
	rids = dcerpc_alloc_data(pdu, MAX(req->Count, 1) * sizeof(*rids));
	uses = dcerpc_alloc_data(pdu, MAX(req->Count, 1) * sizeof(*uses));
	if (!rids || !uses) {
		ret = -1;
		goto out;
	}

	for (i = 0; i < req->Count; i++) {
		const char *name = req->Names[i];
		struct ksmbd_user *user = NULL;
		struct samr_account *group;

		rids[i] = UINT32_MAX;
		uses[i] = SID_TYPE_UNKNOWN;
		if (!name)
			continue;
		if (domain->kind == SAMR_DOMAIN_LOCAL)
			user = usm_lookup_user_casefold(name);
		if (user) {
			if (smb_valid_user_rid(user->uid)) {
				rids[i] = user->uid;
				uses[i] = SID_TYPE_USER;
				mapped++;
			}
			put_ksmbd_user(user);
			if (uses[i] == SID_TYPE_USER)
				continue;
		}
		group = samr_accounts_by_name(groups, name);
		if (group) {
			rids[i] = group->rid;
			uses[i] = samr_group_sid_type(domain);
			mapped++;
		}
	}
	rep->RelativeIds.Count = req->Count;
	rep->RelativeIds.Element = req->Count ? rids : NULL;
	rep->Use.Count = req->Count;
	rep->Use.Element = req->Count ? uses : NULL;
	rep->status = samr_lookup_status(mapped, req->Count);
out:
	if (groups)
		g_ptr_array_free(groups, TRUE);
	return ret;
}

/* RIDs to names, the reverse of LookupNamesInDomain */
static int samr_lookup_ids_stub(struct dcerpc_context *dce,
				struct dcerpc_pdu *pdu,
				void *reqv, void *repv)
{
	struct samr_LookupIdsInDomain_req *req = reqv;
	struct samr_LookupIdsInDomain_rep *rep = repv;
	struct samr_handle *domain;
	GPtrArray *groups;
	char **names;
	uint32_t *uses, i, mapped = 0;
	int failed, ret = 0;

	if (samr_restricted(pdu, &rep->status))
		return 0;
	domain = samr_domain_get(pdu, &req->DomainHandle, SAMR_DOMAIN_LOOKUP,
				 &rep->status);
	if (!domain)
		return 0;
	groups = samr_domain_groups(domain, &failed);
	if (failed)
		return -1;
	names = dcerpc_alloc_data(pdu, MAX(req->Count, 1) * sizeof(*names));
	uses = dcerpc_alloc_data(pdu, MAX(req->Count, 1) * sizeof(*uses));
	if (!names || !uses) {
		ret = -1;
		goto out;
	}

	for (i = 0; i < req->Count; i++) {
		uint32_t rid = req->RelativeIds[i];
		struct ksmbd_user *user = NULL;
		struct samr_account *group;

		names[i] = NULL;
		uses[i] = SID_TYPE_UNKNOWN;
		if (domain->kind == SAMR_DOMAIN_LOCAL &&
		    smb_valid_user_rid(rid))
			user = usm_lookup_uid(rid);
		if (user) {
			names[i] = rpc_pdu_strdup(pdu, user->name);
			put_ksmbd_user(user);
			if (!names[i]) {
				ret = -1;
				goto out;
			}
			uses[i] = SID_TYPE_USER;
			mapped++;
			continue;
		}
		group = samr_accounts_by_rid(groups, rid);
		if (group) {
			names[i] = rpc_pdu_strdup(pdu, group->name);
			if (!names[i]) {
				ret = -1;
				goto out;
			}
			uses[i] = samr_group_sid_type(domain);
			mapped++;
		}
	}
	rep->Names.Count = req->Count;
	rep->Names.Element = req->Count ? names : NULL;
	rep->Use.Count = req->Count;
	rep->Use.Element = req->Count ? uses : NULL;
	rep->status = samr_lookup_status(mapped, req->Count);
out:
	if (groups)
		g_ptr_array_free(groups, TRUE);
	return ret;
}

/*
 * The aliases of the Unix Group domain the SIDs are members of: the
 * POSIX groups of the local users among them.
 */
static int samr_get_alias_membership_stub(struct dcerpc_context *dce,
					  struct dcerpc_pdu *pdu,
					  void *reqv, void *repv)
{
	struct samr_GetAliasMembership_req *req = reqv;
	struct samr_GetAliasMembership_rep *rep = repv;
	struct samr_handle *domain;
	struct smb_sid local;
	GArray *gids;
	uint32_t i;
	int j;

	if (samr_restricted(pdu, &rep->status))
		return 0;
	domain = samr_domain_get(pdu, &req->DomainHandle,
				 SAMR_DOMAIN_GET_ALIAS_MEMBERSHIP,
				 &rep->status);
	if (!domain)
		return 0;
	gids = g_array_new(FALSE, FALSE, sizeof(uint32_t));
	smb_init_domain_sid(&local);
	for (i = 0; domain->kind == SAMR_DOMAIN_UNIX_GROUP &&
	     i < req->SidArray.Count; i++) {
		struct smb_sid sid;
		struct ksmbd_user *user;
		uint32_t uid;

		if (!req->SidArray.Sids[i])
			continue;
		smb_sid_from_rpc(&sid, req->SidArray.Sids[i]);
		if (sid.num_subauth != local.num_subauth + 1)
			continue;
		uid = sid.sub_auth[--sid.num_subauth];
		if (!smb_valid_user_rid(uid) || smb_compare_sids(&sid, &local))
			continue;
		user = usm_lookup_uid(uid);
		if (!user)
			continue;
		for (j = -1; j < user->ngroups; j++) {
			uint32_t gid = j < 0 ? user->gid : user->sgid[j];
			guint k;

			if (gid == KSMBD_SHARE_INVALID_GID)
				continue;
			for (k = 0; k < gids->len; k++)
				if (g_array_index(gids, uint32_t, k) == gid)
					break;
			if (k == gids->len)
				g_array_append_val(gids, gid);
		}
		put_ksmbd_user(user);
	}
	g_array_sort(gids, samr_uint32_cmp);

	/* an empty array is sent as one, not as a NULL pointer */
	rep->Membership.Count = gids->len;
	rep->Membership.Element = dcerpc_alloc_data(pdu, MAX(gids->len, 1) *
						    sizeof(uint32_t));
	if (!rep->Membership.Element) {
		g_array_free(gids, TRUE);
		return -1;
	}
	memcpy(rep->Membership.Element, gids->data,
	       gids->len * sizeof(uint32_t));
	g_array_free(gids, TRUE);
	rep->status = KSMBD_NT_STATUS_SUCCESS;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Groups and aliases                                                  */
/* ------------------------------------------------------------------ */

/* Open the local domain's group or the Unix Group domain's alias rid */
static int samr_open_group_or_alias(struct dcerpc_pdu *pdu,
				    const struct dcerpc_context_handle *handle,
				    enum samr_handle_type type,
				    unsigned int desired, uint32_t rid,
				    struct dcerpc_context_handle *out,
				    uint32_t *status)
{
	struct samr_handle *domain;
	GPtrArray *groups = NULL;
	int ret = 0;

	if (samr_restricted(pdu, status))
		return 0;
	domain = samr_domain_get(pdu, handle, SAMR_DOMAIN_LOOKUP, status);
	if (!domain)
		return 0;
	if (type == SAMR_HANDLE_GROUP && domain->kind == SAMR_DOMAIN_LOCAL)
		groups = samr_local_groups();
	else if (type == SAMR_HANDLE_ALIAS &&
		 domain->kind == SAMR_DOMAIN_UNIX_GROUP)
		groups = samr_unix_groups();
	else {
		*status = type == SAMR_HANDLE_GROUP ?
			KSMBD_NT_STATUS_NO_SUCH_GROUP :
			KSMBD_NT_STATUS_NO_SUCH_ALIAS;
		return 0;
	}
	if (!groups)
		return -1;
	if (!samr_accounts_by_rid(groups, rid))
		*status = type == SAMR_HANDLE_GROUP ?
			KSMBD_NT_STATUS_NO_SUCH_GROUP :
			KSMBD_NT_STATUS_NO_SUCH_ALIAS;
	else
		ret = samr_handle_open(pdu, type, desired, domain, NULL, rid,
				       out, status);
	g_ptr_array_free(groups, TRUE);
	return ret;
}

static int samr_open_group_stub(struct dcerpc_context *dce,
				struct dcerpc_pdu *pdu,
				void *reqv, void *repv)
{
	struct samr_OpenGroup_req *req = reqv;
	struct samr_OpenGroup_rep *rep = repv;

	return samr_open_group_or_alias(pdu, &req->DomainHandle,
					SAMR_HANDLE_GROUP, req->DesiredAccess,
					req->GroupId, &rep->GroupHandle,
					&rep->status);
}

static int samr_open_alias_stub(struct dcerpc_context *dce,
				struct dcerpc_pdu *pdu,
				void *reqv, void *repv)
{
	struct samr_OpenAlias_req *req = reqv;
	struct samr_OpenAlias_rep *rep = repv;

	return samr_open_group_or_alias(pdu, &req->DomainHandle,
					SAMR_HANDLE_ALIAS, req->DesiredAccess,
					req->AliasId, &rep->AliasHandle,
					&rep->status);
}

/* Every user is a member of the local domain's one group */
static int samr_get_members_in_group_stub(struct dcerpc_context *dce,
					  struct dcerpc_pdu *pdu,
					  void *reqv, void *repv)
{
	struct samr_GetMembersInGroup_req *req = reqv;
	struct samr_GetMembersInGroup_rep *rep = repv;
	struct samr_handle *group;
	GArray *uids;
	guint i;

	if (samr_restricted(pdu, &rep->status))
		return 0;
	group = samr_handle_get(pdu, &req->GroupHandle, SAMR_HANDLE_GROUP,
				SAMR_GROUP_LIST_MEMBERS, &rep->status);
	if (!group)
		return 0;
	uids = samr_group_members(group->rid, 1);
	rep->Members.MemberCount = uids->len;
	if (uids->len) {
		rep->Members.Members = dcerpc_alloc_data(pdu, uids->len *
							 sizeof(uint32_t));
		rep->Members.Attributes = dcerpc_alloc_data(pdu, uids->len *
							    sizeof(uint32_t));
		if (!rep->Members.Members || !rep->Members.Attributes) {
			g_array_free(uids, TRUE);
			return -1;
		}
		for (i = 0; i < uids->len; i++) {
			rep->Members.Members[i] = g_array_index(uids, uint32_t,
								i);
			rep->Members.Attributes[i] = SE_GROUP_DEFAULT;
		}
	}
	g_array_free(uids, TRUE);
	rep->status = KSMBD_NT_STATUS_SUCCESS;
	return 0;
}

/* The members of a POSIX group, as SIDs of the local domain */
static int samr_get_members_in_alias_stub(struct dcerpc_context *dce,
					  struct dcerpc_pdu *pdu,
					  void *reqv, void *repv)
{
	struct samr_GetMembersInAlias_req *req = reqv;
	struct samr_GetMembersInAlias_rep *rep = repv;
	struct samr_handle *alias;
	GArray *uids;
	guint i;

	if (samr_restricted(pdu, &rep->status))
		return 0;
	alias = samr_handle_get(pdu, &req->AliasHandle, SAMR_HANDLE_ALIAS,
				SAMR_ALIAS_LIST_MEMBERS, &rep->status);
	if (!alias)
		return 0;
	uids = samr_group_members(alias->rid, 0);
	rep->Members.Count = uids->len;
	if (uids->len) {
		rep->Members.Sids = dcerpc_alloc_data(pdu, uids->len *
						      sizeof(RPC_SID *));
		if (!rep->Members.Sids) {
			g_array_free(uids, TRUE);
			return -1;
		}
		for (i = 0; i < uids->len; i++) {
			struct smb_sid sid;

			smb_init_domain_sid(&sid);
			sid.sub_auth[sid.num_subauth++] =
				g_array_index(uids, uint32_t, i);
			rep->Members.Sids[i] = smb_sid_to_rpc(pdu, &sid);
			if (!rep->Members.Sids[i]) {
				g_array_free(uids, TRUE);
				return -1;
			}
		}
	}
	g_array_free(uids, TRUE);
	rep->status = KSMBD_NT_STATUS_SUCCESS;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Users                                                               */
/* ------------------------------------------------------------------ */

static int samr_open_user_stub(struct dcerpc_context *dce,
			       struct dcerpc_pdu *pdu,
			       void *reqv, void *repv)
{
	struct samr_OpenUser_req *req = reqv;
	struct samr_OpenUser_rep *rep = repv;
	struct samr_handle *domain;
	struct ksmbd_user *user = NULL;

	if (samr_restricted(pdu, &rep->status))
		return 0;
	domain = samr_domain_get(pdu, &req->DomainHandle, SAMR_DOMAIN_LOOKUP,
				 &rep->status);
	if (!domain)
		return 0;
	if (domain->kind == SAMR_DOMAIN_LOCAL && smb_valid_user_rid(req->UserId))
		user = usm_lookup_uid(req->UserId);
	if (!user) {
		rep->status = KSMBD_NT_STATUS_NO_SUCH_USER;
		return 0;
	}
	return samr_handle_open(pdu, SAMR_HANDLE_USER, req->DesiredAccess,
				domain, user, req->UserId, &rep->UserHandle,
				&rep->status);
}

/* A user's home directory and profile path, on this host */
static int samr_user_paths(struct dcerpc_pdu *pdu, const char *name,
			   char **home, char **profile)
{
	char hostname[NAME_MAX] = { 0 };

	if (gethostname(hostname, sizeof(hostname) - 1))
		return -1;
	*home = dcerpc_alloc_data(pdu, strlen(hostname) + strlen(name) + 4);
	*profile = dcerpc_alloc_data(pdu, strlen(hostname) + strlen(name) + 12);
	if (!*home || !*profile)
		return -1;
	sprintf(*home, "\\\\%s\\%s", hostname, name);
	sprintf(*profile, "%s\\profile", *home);
	return 0;
}

/* The read right a user information class needs, 0 for none in particular */
static unsigned int samr_user_info_access(uint32_t info_class)
{
	switch (info_class) {
	case SAMR_UserGeneralInformation:
	case SAMR_UserNameInformation:
	case SAMR_UserAccountNameInformation:
	case SAMR_UserFullNameInformation:
	case SAMR_UserPrimaryGroupInformation:
	case SAMR_UserAdminCommentInformation:
		return SAMR_USER_READ_GENERAL;
	case SAMR_UserHomeInformation:
	case SAMR_UserScriptInformation:
	case SAMR_UserProfileInformation:
	case SAMR_UserWorkStationsInformation:
		return SAMR_USER_READ_LOGON;
	default:
		return 0;
	}
}

/*
 * UserAllInformation, the level Windows asks for: the fields the
 * handle's read rights allow, the rest zero.
 */
static int samr_user_all_info(struct dcerpc_pdu *pdu, struct samr_handle *h,
			      struct samr_SAMPR_USER_ALL_INFORMATION *all,
			      uint32_t *status)
{
	const char *name = h->user->name;
	unsigned int fields = 0;
	char *home, *profile;
	uint8_t *hours;

	if (h->access & SAMR_USER_READ_GENERAL)
		fields |= USER_ALL_GENERAL_FIELDS;
	if (h->access & SAMR_USER_READ_LOGON)
		fields |= USER_ALL_LOGON_FIELDS;
	if (h->access & SAMR_USER_READ_ACCOUNT)
		fields |= USER_ALL_ACCOUNT_FIELDS;
	if (h->access & SAMR_USER_READ_PREFERENCES)
		fields |= USER_ALL_PREFERENCES_FIELDS;
	if (!fields) {
		*status = KSMBD_NT_STATUS_ACCESS_DENIED;
		return 0;
	}

	if (h->access & SAMR_USER_READ_GENERAL) {
		all->UserName = rpc_pdu_strdup(pdu, name);
		all->FullName = rpc_pdu_strdup(pdu, name);
		if (!all->UserName || !all->FullName)
			return -1;
		all->UserId = h->rid;
		all->PrimaryGroupId = SMB_LOCAL_USERS_RID;
	}
	if (h->access & SAMR_USER_READ_LOGON) {
		if (samr_user_paths(pdu, name, &home, &profile))
			return -1;
		all->HomeDirectory = home;
		all->ProfilePath = profile;
		/* may log on at any hour of the week */
		hours = dcerpc_alloc_data(pdu, 21);
		if (!hours)
			return -1;
		memset(hours, 0xff, 21);
		all->LogonHours.UnitsPerWeek = 168;
		all->LogonHours.LogonHours.max_count = 1260;
		all->LogonHours.LogonHours.len = 21;
		all->LogonHours.LogonHours.data = hours;
	}
	if (h->access & SAMR_USER_READ_ACCOUNT)
		all->UserAccountControl = SAMR_USER_NORMAL_ACCOUNT;
	all->WhichFields = fields;
	*status = KSMBD_NT_STATUS_SUCCESS;
	return 0;
}

static int samr_query_user_info_stub(struct dcerpc_context *dce,
				     struct dcerpc_pdu *pdu,
				     void *reqv, void *repv)
{
	struct samr_QueryInformationUser_req *req = reqv;
	struct samr_QueryInformationUser_rep *rep = repv;
	uint32_t info_class = req->UserInformationClass;
	union samr_SAMPR_USER_INFO_BUFFER *info;
	struct samr_handle *h;
	const char *name;
	char *home, *profile;

	if (samr_restricted(pdu, &rep->status))
		return 0;
	switch (info_class) {
	case SAMR_UserGeneralInformation:
	case SAMR_UserNameInformation:
	case SAMR_UserAccountNameInformation:
	case SAMR_UserFullNameInformation:
	case SAMR_UserPrimaryGroupInformation:
	case SAMR_UserHomeInformation:
	case SAMR_UserScriptInformation:
	case SAMR_UserProfileInformation:
	case SAMR_UserAdminCommentInformation:
	case SAMR_UserWorkStationsInformation:
	case SAMR_UserAllInformation:
		break;
	default:
		rep->status = KSMBD_NT_STATUS_INVALID_INFO_CLASS;
		return 0;
	}
	h = samr_handle_get(pdu, &req->UserHandle, SAMR_HANDLE_USER,
			    samr_user_info_access(info_class), &rep->status);
	if (!h)
		return 0;
	info = dcerpc_alloc_data(pdu, sizeof(*info));
	if (!info)
		return -1;
	name = h->user->name;

	switch (info_class) {
	case SAMR_UserGeneralInformation:
		info->General.UserName = rpc_pdu_strdup(pdu, name);
		info->General.FullName = rpc_pdu_strdup(pdu, name);
		info->General.PrimaryGroupId = SMB_LOCAL_USERS_RID;
		info->General.AdminComment = rpc_pdu_strdup(pdu, "");
		info->General.UserComment = rpc_pdu_strdup(pdu, "");
		if (!info->General.UserName || !info->General.FullName ||
		    !info->General.AdminComment || !info->General.UserComment)
			return -1;
		break;
	case SAMR_UserNameInformation:
		info->Name.UserName = rpc_pdu_strdup(pdu, name);
		info->Name.FullName = rpc_pdu_strdup(pdu, name);
		if (!info->Name.UserName || !info->Name.FullName)
			return -1;
		break;
	case SAMR_UserAccountNameInformation:
		info->AccountName.UserName = rpc_pdu_strdup(pdu, name);
		if (!info->AccountName.UserName)
			return -1;
		break;
	case SAMR_UserFullNameInformation:
		info->FullName.FullName = rpc_pdu_strdup(pdu, name);
		if (!info->FullName.FullName)
			return -1;
		break;
	case SAMR_UserPrimaryGroupInformation:
		info->PrimaryGroup.PrimaryGroupId = SMB_LOCAL_USERS_RID;
		break;
	case SAMR_UserHomeInformation:
		if (samr_user_paths(pdu, name, &home, &profile))
			return -1;
		info->Home.HomeDirectory = home;
		info->Home.HomeDirectoryDrive = rpc_pdu_strdup(pdu, "");
		if (!info->Home.HomeDirectoryDrive)
			return -1;
		break;
	case SAMR_UserScriptInformation:
		info->Script.ScriptPath = rpc_pdu_strdup(pdu, "");
		if (!info->Script.ScriptPath)
			return -1;
		break;
	case SAMR_UserProfileInformation:
		if (samr_user_paths(pdu, name, &home, &profile))
			return -1;
		info->Profile.ProfilePath = profile;
		break;
	case SAMR_UserAdminCommentInformation:
		info->AdminComment.AdminComment = rpc_pdu_strdup(pdu, "");
		if (!info->AdminComment.AdminComment)
			return -1;
		break;
	case SAMR_UserWorkStationsInformation:
		info->WorkStations.WorkStations = rpc_pdu_strdup(pdu, "");
		if (!info->WorkStations.WorkStations)
			return -1;
		break;
	default:
		if (samr_user_all_info(pdu, h, &info->All, &rep->status))
			return -1;
		if (rep->status)
			return 0;
		break;
	}
	rep->Buffer = info;
	rep->status = KSMBD_NT_STATUS_SUCCESS;
	return 0;
}

/* The local domain's one group, the primary group of every user */
static int samr_get_groups_for_user_stub(struct dcerpc_context *dce,
					 struct dcerpc_pdu *pdu,
					 void *reqv, void *repv)
{
	struct samr_GetGroupsForUser_req *req = reqv;
	struct samr_GetGroupsForUser_rep *rep = repv;
	struct samr_GROUP_MEMBERSHIP *g;

	if (samr_restricted(pdu, &rep->status))
		return 0;
	if (!samr_handle_get(pdu, &req->UserHandle, SAMR_HANDLE_USER,
			     SAMR_USER_LIST_GROUPS, &rep->status))
		return 0;
	g = dcerpc_alloc_data(pdu, sizeof(*g));
	if (!g)
		return -1;
	g->RelativeId = SMB_LOCAL_USERS_RID;
	g->Attributes = SE_GROUP_DEFAULT;
	rep->Groups.MembershipCount = 1;
	rep->Groups.Groups = g;
	rep->status = KSMBD_NT_STATUS_SUCCESS;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Security descriptors                                                */
/* ------------------------------------------------------------------ */

static int set_ace(struct dcerpc_pdu *pdu, ACCESS_ALLOWED_ACE *ace,
		   ACCESS_MASK mask, const struct smb_sid *sid)
{
	RPC_SID *rsid = smb_sid_to_rpc(pdu, sid);

	if (!rsid)
		return -1;
	ace->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
	ace->Mask = mask;
	ace->Sid = *rsid;
	return 0;
}

/*
 * The security descriptor of an object, the parts SecurityInformation
 * asks for: owned by Local System and Everyone, and letting Everyone
 * and Anonymous Logon do what the object lets anyone do.
 */
static int samr_query_security_stub(struct dcerpc_context *dce,
				    struct dcerpc_pdu *pdu,
				    void *reqv, void *repv)
{
	struct samr_QuerySecurityObject_req *req = reqv;
	struct samr_QuerySecurityObject_rep *rep = repv;
	/* [MS-SAMR] 3.1.5.12.2: unrecognized bits are ignored */
	uint32_t secinfo = req->SecurityInformation & 0xf;
	unsigned int required = 0;
	struct samr_handle *h;
	SECURITY_DESCRIPTOR *sd;

	if (samr_restricted(pdu, &rep->status))
		return 0;
	if (secinfo & (SAMR_OWNER_SECURITY_INFORMATION |
		       SAMR_GROUP_SECURITY_INFORMATION |
		       SAMR_DACL_SECURITY_INFORMATION))
		required |= SAMR_READ_CONTROL;
	if (secinfo & SAMR_SACL_SECURITY_INFORMATION)
		required |= SAMR_ACCESS_SYSTEM_SECURITY;
	h = samr_handle_get(pdu, &req->ObjectHandle, -1, required,
			    &rep->status);
	if (!h)
		return 0;

	sd = dcerpc_alloc_data(pdu, sizeof(*sd));
	if (!sd)
		return -1;
	sd->Revision = 1;
	sd->Control = SE_SELF_RELATIVE;
	if (secinfo & SAMR_OWNER_SECURITY_INFORMATION) {
		sd->Owner = smb_sid_to_rpc(pdu, &sid_system);
		if (!sd->Owner)
			return -1;
	}
	if (secinfo & SAMR_GROUP_SECURITY_INFORMATION) {
		sd->Group = smb_sid_to_rpc(pdu, &sid_everyone);
		if (!sd->Group)
			return -1;
	}
	if (secinfo & SAMR_DACL_SECURITY_INFORMATION) {
		unsigned int access = samr_public_access(h->type);
		ACL *dacl = dcerpc_alloc_data(pdu, sizeof(*dacl));

		if (!dacl)
			return -1;
		dacl->AclRevision = ACL_REVISION;
		dacl->AceCount = 2;
		dacl->Aces = dcerpc_alloc_data(pdu, 2 * sizeof(*dacl->Aces));
		if (!dacl->Aces ||
		    set_ace(pdu, &dacl->Aces[0], access, &sid_everyone) ||
		    set_ace(pdu, &dacl->Aces[1], access, &sid_anonymous))
			return -1;
		sd->Control |= SE_DACL_PRESENT;
		sd->Dacl = dacl;
	}
	rep->SecurityDescriptor.SecurityDescriptor = sd;
	rep->status = KSMBD_NT_STATUS_SUCCESS;
	return 0;
}

static const struct dcerpc_stub samr_stubs[] = {
	{ SAMR_CLOSEHANDLE, "CloseHandle", samr_close_handle_stub },
	{ SAMR_QUERYSECURITYOBJECT, "QuerySecurityObject",
	  samr_query_security_stub },
	{ SAMR_LOOKUPDOMAININSAMSERVER, "LookupDomainInSamServer",
	  samr_lookup_domain_stub },
	{ SAMR_ENUMERATEDOMAINSINSAMSERVER, "EnumerateDomainsInSamServer",
	  samr_enum_domains_stub },
	{ SAMR_OPENDOMAIN, "OpenDomain", samr_open_domain_stub },
	{ SAMR_ENUMERATEGROUPSINDOMAIN, "EnumerateGroupsInDomain",
	  samr_enum_groups_stub },
	{ SAMR_ENUMERATEUSERSINDOMAIN, "EnumerateUsersInDomain",
	  samr_enum_users_stub },
	{ SAMR_ENUMERATEALIASESINDOMAIN, "EnumerateAliasesInDomain",
	  samr_enum_aliases_stub },
	{ SAMR_GETALIASMEMBERSHIP, "GetAliasMembership",
	  samr_get_alias_membership_stub },
	{ SAMR_LOOKUPNAMESINDOMAIN, "LookupNamesInDomain",
	  samr_lookup_names_stub },
	{ SAMR_LOOKUPIDSINDOMAIN, "LookupIdsInDomain", samr_lookup_ids_stub },
	{ SAMR_OPENGROUP, "OpenGroup", samr_open_group_stub },
	{ SAMR_GETMEMBERSINGROUP, "GetMembersInGroup",
	  samr_get_members_in_group_stub },
	{ SAMR_OPENALIAS, "OpenAlias", samr_open_alias_stub },
	{ SAMR_GETMEMBERSINALIAS, "GetMembersInAlias",
	  samr_get_members_in_alias_stub },
	{ SAMR_OPENUSER, "OpenUser", samr_open_user_stub },
	{ SAMR_QUERYINFORMATIONUSER, "QueryInformationUser",
	  samr_query_user_info_stub },
	{ SAMR_GETGROUPSFORUSER, "GetGroupsForUser",
	  samr_get_groups_for_user_stub },
	{ SAMR_CONNECT2, "Connect2", samr_connect2_stub },
	{ SAMR_CONNECT5, "Connect5", samr_connect5_stub },
	{ -1, NULL, NULL }
};

struct dcerpc_server *rpc_samr_endpoint(void)
{
	struct dcerpc_server *srv = dcerpc_server_create("samr");

	if (srv && dcerpc_server_add_interface(srv, &samr_interface,
					       samr_procs, samr_stubs,
					       DCERPC_SERVER_ALL_NDR)) {
		dcerpc_server_destroy(srv);
		srv = NULL;
	}
	return srv;
}

void rpc_samr_init(void)
{
	if (!domain_name) {
		char hostname[NAME_MAX] = { 0 };

		/*
		 * ksmbd supports the standalone server and
		 * uses the hostname as the domain name.
		 */
		if (gethostname(hostname, sizeof(hostname) - 1))
			abort();

		domain_name = g_ascii_strup(hostname, -1);
	}
}

void rpc_samr_destroy(void)
{
	g_free(domain_name);
	domain_name = NULL;
}
