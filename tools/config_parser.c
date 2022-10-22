// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <glib.h>
#include <string.h>
#include <glib/gstdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/ksmbd_server.h>

#include <config_parser.h>
#include <tools.h>
#include <management/user.h>
#include <management/share.h>

struct smbconf_global global_conf;
struct smbconf_parser parser;
struct smbconf_group *global_group, *ipc_group;

unsigned long long memparse(const char *v)
{
	char *eptr;

	unsigned long long ret = strtoull(v, &eptr, 0);

	switch (*eptr) {
	case 'E':
	case 'e':
		ret <<= 10;
	case 'P':
	case 'p':
		ret <<= 10;
	case 'T':
	case 't':
		ret <<= 10;
	case 'G':
	case 'g':
		ret <<= 10;
	case 'M':
	case 'm':
		ret <<= 10;
	case 'K':
	case 'k':
		ret <<= 10;
	}

	return ret;
}

static void kv_release_cb(gpointer p)
{
	g_free(p);
}

static int is_ascii_space_tab(char c)
{
	return c == ' ' || c == '\t';
}

static int is_a_comment(char *line)
{
	return (*line == 0x00 || *line == ';' || *line == '\n' || *line == '#');
}

static int is_a_group(char *line)
{
	char *p = line;

	if (*p != '[')
		return 0;
	p++;
	while (*p && *p != ']')
		p = g_utf8_find_next_char(p, NULL);
	if (*p != ']')
		return 0;
	return 1;
}

static int add_new_group(char *line)
{
	char *begin = line;
	char *end = line;
	char *name = NULL;
	struct smbconf_group *group = NULL;
	struct smbconf_group *lookup;

	while (*end && *end != ']')
		end = g_utf8_find_next_char(end, NULL);

	name = g_strndup(begin + 1, end - begin - 1);
	if (!name)
		goto out_free;

	lookup = g_hash_table_lookup(parser.groups, name);
	if (lookup) {
		parser.current = lookup;
		pr_info("Multiple definitions for group `%s'\n", name);
		g_free(name);
		return 0;
	}

	group = g_malloc(sizeof(struct smbconf_group));
	group->cb_mode = GROUPS_CALLBACK_NONE;
	group->name = name;
	group->kv = g_hash_table_new_full(g_str_hash,
					  g_str_equal,
					  kv_release_cb,
					  kv_release_cb);
	if (!group->kv)
		goto out_free;

	parser.current = group;
	g_hash_table_insert(parser.groups, group->name, group);
	return 0;

out_free:
	g_free(name);
	if (group && group->kv)
		g_hash_table_destroy(group->kv);
	g_free(group);
	return -ENOMEM;
}

static int add_group_key_value(char *line)
{
	char *key, *value;

	key = strchr(line, '=');
	if (!key)
		return -EINVAL;

	value = key;
	*key = 0x00;
	key--;
	value++;

	while (is_ascii_space_tab(*key))
		key--;
	while (is_ascii_space_tab(*value))
		value++;

	if (is_a_comment(value))
		return 0;

	key = g_strndup(line, key - line + 1);
	value = g_strdup(value);

	if (!key || !value) {
		g_free(key);
		g_free(value);
		return -ENOMEM;
	}

	if (g_hash_table_lookup(parser.current->kv, key)) {
		pr_info("Multiple key-value definitions for `%s' in group `%s'\n",
			key, parser.current->name);
		g_free(key);
		g_free(value);
		return 0;
	}

	g_hash_table_insert(parser.current->kv, key, value);
	return 0;
}

static int process_smbconf_entry(char *data)
{
	while (is_ascii_space_tab(*data))
		data++;

	if (is_a_comment(data))
		return 0;

	if (is_a_group(data))
		return add_new_group(data);

	return add_group_key_value(data);
}

static int __mmap_parse_file(const char *fname, int (*callback)(char *data))
{
	GMappedFile *file;
	GError *err = NULL;
	gchar *contents;
	int len;
	char *delim;
	int fd, ret = 0;

	fd = g_open(fname, O_RDONLY, 0);
	if (fd == -1) {
		ret = -errno;
		pr_debug("Can't open `%s': %m\n", fname);
		return ret;
	}

	file = g_mapped_file_new_from_fd(fd, FALSE, &err);
	if (err) {
		pr_err("Can't map `%s' to memory: %s\n", fname, err->message);
		g_error_free(err);
		ret = -EINVAL;
		goto out;
	}

	contents = g_mapped_file_get_contents(file);
	if (!contents)
		goto out;

	len = g_mapped_file_get_length(file);
	while (len > 0) {
		delim = strchr(contents, '\n');
		if (!delim)
			delim = contents + len - 1;

		if (delim) {
			size_t sz = delim - contents;
			char *data;

			if (delim == contents) {
				contents = delim + 1;
				len--;
				continue;
			}

			if (!sz)
				break;

			data = g_strndup(contents, sz);
			ret = callback(data);
			if (ret) {
				g_free(data);
				goto out;
			}

			g_free(data);
			contents = delim + 1;
			len -= (sz + 1);
		}
	}

	ret = 0;
out:
	if (file)
		g_mapped_file_unref(file);

	if (fd) {
		g_close(fd, &err);
		if (err) {
			pr_err("Can't close `%s': %s\n", fname, err->message);
			g_error_free(err);
		}
	}
	return ret;
}

static int init_smbconf_parser(void)
{
	if (parser.groups)
		return 0;

	parser.groups = g_hash_table_new(shm_share_name_hash,
					 shm_share_name_equal);
	if (!parser.groups)
		return -ENOMEM;
	return 0;
}

static void release_smbconf_group(gpointer k, gpointer v, gpointer user_data)
{
	struct smbconf_group *g = v;

	g_hash_table_destroy(g->kv);
	g_free(g->name);
	g_free(g);
}

static void release_smbconf_parser(void)
{
	if (!parser.groups)
		return;

	g_hash_table_foreach(parser.groups, release_smbconf_group, NULL);
	g_hash_table_destroy(parser.groups);
	parser.groups = NULL;
}

char *cp_ltrim(char *v)
{
	if (!v)
		return NULL;

	while (*v && *v == ' ')
		v++;
	if (*v == 0x00)
		return NULL;
	return v;
}

int cp_key_cmp(char *k, char *v)
{
	if (!k || !v)
		return -1;
	return g_ascii_strncasecmp(k, v, strlen(v));
}

char *cp_get_group_kv_string(char *v)
{
	return g_strdup(v);
}

int cp_get_group_kv_bool(char *v)
{
	if (!g_ascii_strncasecmp(v, "yes", 3) ||
		!g_ascii_strncasecmp(v, "1", 1) ||
		!g_ascii_strncasecmp(v, "true", 4) ||
		!g_ascii_strncasecmp(v, "enable", 6))
		return 1;
	return 0;
}

int cp_get_group_kv_config_opt(char *v)
{
	if (!g_ascii_strncasecmp(v, "disabled", 8))
		return KSMBD_CONFIG_OPT_DISABLED;
	if (!g_ascii_strncasecmp(v, "enabled", 7))
		return KSMBD_CONFIG_OPT_ENABLED;
	if (!g_ascii_strncasecmp(v, "auto", 4))
		return KSMBD_CONFIG_OPT_AUTO;
	if (!g_ascii_strncasecmp(v, "mandatory", 9))
		return KSMBD_CONFIG_OPT_MANDATORY;
	return KSMBD_CONFIG_OPT_DISABLED;
}

unsigned long cp_get_group_kv_long_base(char *v, int base)
{
	return strtoul(v, NULL, base);
}

unsigned long cp_get_group_kv_long(char *v)
{
	return cp_get_group_kv_long_base(v, 10);
}

char **cp_get_group_kv_list(char *v)
{
	/*
	 * SMB conf lists are "tabs, spaces, commas" separated.
	 */
	return g_strsplit_set(v, "\t ,", -1);
}

void cp_group_kv_list_free(char **list)
{
	g_strfreev(list);
}

static int cp_add_global_guest_account(gpointer _v)
{
	struct ksmbd_user *user;

	if (usm_add_new_user(cp_get_group_kv_string(_v),
			     g_strdup("NULL"))) {
		pr_err("Unable to add new user `%s'\n", (char *) _v);
		return -ENOMEM;
	}

	user = usm_lookup_user(_v);
	if (!user) {
		pr_err("Unable to find user `%s'\n", (char *) _v);
		return -EINVAL;
	}

	set_user_flag(user, KSMBD_USER_FLAG_GUEST_ACCOUNT);
	put_ksmbd_user(user);
	global_conf.guest_account = cp_get_group_kv_string(_v);
	return 0;
}

static gboolean global_group_kv(gpointer _k, gpointer _v, gpointer user_data)
{
	if (!cp_key_cmp(_k, "server string")) {
		global_conf.server_string = cp_get_group_kv_string(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "workgroup")) {
		global_conf.work_group = cp_get_group_kv_string(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "netbios name")) {
		global_conf.netbios_name = cp_get_group_kv_string(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "server min protocol")) {
		global_conf.server_min_protocol = cp_get_group_kv_string(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "server signing")) {
		global_conf.server_signing = cp_get_group_kv_config_opt(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "server max protocol")) {
		global_conf.server_max_protocol = cp_get_group_kv_string(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "guest account")) {
		if (cp_add_global_guest_account(_v))
			pr_err("Unable to add global guest account\n");
		return TRUE;
	}

	if (!cp_key_cmp(_k, "max active sessions")) {
		global_conf.sessions_cap = cp_get_group_kv_long(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "tcp port")) {
		if (!global_conf.tcp_port)
			global_conf.tcp_port = cp_get_group_kv_long(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "ipc timeout")) {
		global_conf.ipc_timeout = cp_get_group_kv_long(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "max open files")) {
		global_conf.file_max = cp_get_group_kv_long(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "restrict anonymous")) {
		global_conf.restrict_anon = cp_get_group_kv_long(_v);
		if (global_conf.restrict_anon > KSMBD_RESTRICT_ANON_TYPE_2 ||
				global_conf.restrict_anon < 0) {
			global_conf.restrict_anon = 0;
			pr_err("Invalid restrict anonymous value\n");
		}

		return TRUE;
	}

	if (!cp_key_cmp(_k, "map to guest")) {
		global_conf.map_to_guest = KSMBD_CONF_MAP_TO_GUEST_NEVER;
		if (!cp_key_cmp(_v, "bad user"))
			global_conf.map_to_guest =
				KSMBD_CONF_MAP_TO_GUEST_BAD_USER;
		if (!cp_key_cmp(_v, "bad password"))
			global_conf.map_to_guest =
				KSMBD_CONF_MAP_TO_GUEST_BAD_PASSWORD;
		if (!cp_key_cmp(_v, "bad uid"))
			global_conf.map_to_guest =
				KSMBD_CONF_MAP_TO_GUEST_BAD_UID;
		return TRUE;
	}

	if (!cp_key_cmp(_k, "bind interfaces only")) {
		global_conf.bind_interfaces_only = cp_get_group_kv_bool(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "interfaces")) {
		global_conf.interfaces = cp_get_group_kv_list(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "deadtime")) {
		global_conf.deadtime = cp_get_group_kv_long(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "smb2 leases")) {
		if (cp_get_group_kv_bool(_v))
			global_conf.flags |= KSMBD_GLOBAL_FLAG_SMB2_LEASES;
		else
			global_conf.flags &= ~KSMBD_GLOBAL_FLAG_SMB2_LEASES;

		return TRUE;
	}

	if (!cp_key_cmp(_k, "root directory")) {
		global_conf.root_dir = cp_get_group_kv_string(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "smb2 max read")) {
		global_conf.smb2_max_read = memparse(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "smb2 max write")) {
		global_conf.smb2_max_write = memparse(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "smb2 max trans")) {
		global_conf.smb2_max_trans = memparse(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "smb3 encryption")) {
		if (cp_get_group_kv_bool(_v))
			global_conf.flags |= KSMBD_GLOBAL_FLAG_SMB3_ENCRYPTION;
		else
			global_conf.flags &= ~KSMBD_GLOBAL_FLAG_SMB3_ENCRYPTION;

		return TRUE;
	}

	if (!cp_key_cmp(_k, "share:fake_fscaps")) {
		global_conf.share_fake_fscaps = cp_get_group_kv_long(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "kerberos service name")) {
		global_conf.krb5_service_name = cp_get_group_kv_string(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "kerberos keytab file")) {
		global_conf.krb5_keytab_file = cp_get_group_kv_string(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "server multi channel support")) {
		if (cp_get_group_kv_bool(_v))
			global_conf.flags |= KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL;
		else
			global_conf.flags &= ~KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL;

		return TRUE;
	}

	if (!cp_key_cmp(_k, "smb2 max credits")) {
		global_conf.smb2_max_credits = memparse(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "smbd max io size")) {
		global_conf.smbd_max_io_size = memparse(_v);
		return TRUE;
	}

	/* At this point, this is an option that must be applied to all shares */
	return FALSE;
}

static void global_conf_default(void)
{
	/* The SPARSE_FILES file system capability flag is set by default */
	global_conf.share_fake_fscaps = 64;
}

static void global_conf_create(void)
{
	if (!global_group || global_group->cb_mode != GROUPS_CALLBACK_INIT)
		return;

	/*
	 * This will transfer server options to global_conf, and leave behind
	 * in the global parser group, the options that must be applied to every
	 * share
	 */
	g_hash_table_foreach_remove(global_group->kv, global_group_kv, NULL);
}

static void append_key_value(gpointer _k, gpointer _v, gpointer user_data)
{
	GHashTable *receiver = (GHashTable *)user_data;

	/* Don't override local share options */
	if (!g_hash_table_lookup(receiver, _k))
		g_hash_table_insert(receiver, g_strdup(_k), g_strdup(_v));
}

static void global_conf_update(struct smbconf_group *group)
{
	if (!global_group)
		return;

	g_hash_table_foreach(global_group->kv, append_key_value, group->kv);
}

static void global_conf_fixup_missing(void)
{
	struct ksmbd_user *user;

	/*
	 * Set default global parameters which were not specified
	 * in smb.conf
	 */
	if (!global_conf.file_max)
		global_conf.file_max = KSMBD_CONF_FILE_MAX;
	if (!global_conf.server_string)
		global_conf.server_string =
			cp_get_group_kv_string(
					KSMBD_CONF_DEFAULT_SERVER_STRING);
	if (!global_conf.netbios_name)
		global_conf.netbios_name =
			cp_get_group_kv_string(KSMBD_CONF_DEFAULT_NETBIOS_NAME);
	if (!global_conf.work_group)
		global_conf.work_group =
			cp_get_group_kv_string(KSMBD_CONF_DEFAULT_WORK_GROUP);
	if (!global_conf.tcp_port)
		global_conf.tcp_port = KSMBD_CONF_DEFAULT_TCP_PORT;

	if (global_conf.sessions_cap <= 0)
		global_conf.sessions_cap = KSMBD_CONF_DEFAULT_SESS_CAP;

	user = usm_lookup_user(global_conf.guest_account);
	if (user)
		put_ksmbd_user(user);
	else if (cp_add_global_guest_account(KSMBD_CONF_DEFAULT_GUEST_ACCOUNT))
		pr_err("Unable to add default global guest account\n");
}

static void groups_callback(gpointer _k, gpointer _v, gpointer user_data)
{
	struct smbconf_group *group = (struct smbconf_group *)_v;
	unsigned short cb_mode = *(unsigned short *)user_data;

	if (group == global_group)
		return;

	group->cb_mode = cb_mode;

	if (group != ipc_group)
		global_conf_update(group);

	shm_add_new_share(group);
}

static int cp_add_ipc_group(void)
{
	char *comment = NULL, *guest = NULL;
	int ret = 0;

	ipc_group = g_hash_table_lookup(parser.groups, "ipc$");
	if (ipc_group)
		return ret;

	comment = g_strdup("comment = IPC share");
	guest = g_strdup("guest ok = yes");
	ret = add_new_group("[IPC$]");
	ret |= add_group_key_value(comment);
	ret |= add_group_key_value(guest);
	if (ret) {
		pr_err("Unable to add IPC$ share\n");
		ret = -EINVAL;
		goto out;
	}

	ipc_group = g_hash_table_lookup(parser.groups, "ipc$");
out:
	g_free(comment);
	g_free(guest);
	return ret;
}

static int __cp_parse_smbconfig(const char *smbconf, GHFunc cb,
				unsigned short cb_mode)
{
	int ret;

	global_conf_default();

	ret = cp_smbconfig_hash_create(smbconf);
	if (ret)
		return ret;

	ret = cp_add_ipc_group();
	if (ret)
		goto out;

	global_group = g_hash_table_lookup(parser.groups, "global");
	if (global_group)
		global_group->cb_mode = cb_mode;

	global_conf_create();
	g_hash_table_foreach(parser.groups, groups_callback, &cb_mode);
	global_conf_fixup_missing();
out:
	cp_smbconfig_destroy();
	return ret;
}

int cp_parse_reload_smbconf(const char *smbconf)
{
	return __cp_parse_smbconfig(smbconf, groups_callback,
				    GROUPS_CALLBACK_REINIT);
}

int cp_parse_smbconf(const char *smbconf)
{
	return __cp_parse_smbconfig(smbconf, groups_callback,
				    GROUPS_CALLBACK_INIT);
}

int cp_parse_pwddb(const char *pwddb)
{
	return __mmap_parse_file(pwddb, usm_add_update_user_from_pwdentry);
}

int cp_smbconfig_hash_create(const char *smbconf)
{
	int ret = init_smbconf_parser();

	if (ret)
		return ret;
	return __mmap_parse_file(smbconf, process_smbconf_entry);
}

int cp_parse_subauth(void)
{
	return __mmap_parse_file(PATH_SUBAUTH, usm_add_subauth_global_conf);
}

void cp_smbconfig_destroy(void)
{
	release_smbconf_parser();
}

int cp_parse_external_smbconf_group(char *name, char *opts)
{
	char *pos;
	int i, len;

	if (init_smbconf_parser())
		return -EINVAL;

	if (!opts || !name)
		return -EINVAL;

	len = strlen(opts);
	/* fake smb.conf input */
	for (i = 0; i < KSMBD_SHARE_CONF_MAX; i++) {
		pos = strstr(opts, KSMBD_SHARE_CONF[i]);
		if (!pos)
			continue;
		if (pos != opts)
			*(pos - 1) = '\n';
	}

	if (add_new_group(name))
		goto error;

	/* split input and feed to normal process_smbconf_entry() */
	while (len) {
		char *delim = strchr(opts, '\n');

		if (delim) {
			*delim = 0x00;
			len -= delim - opts;
		} else {
			len = 0;
		}

		process_smbconf_entry(opts);
		if (delim)
			opts = delim + 1;
	}
	return 0;

error:
	cp_smbconfig_destroy();
	return -EINVAL;
}
