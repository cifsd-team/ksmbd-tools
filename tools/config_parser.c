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

typedef int process_entry_fn(char *entry);
static process_entry_fn process_smbconf_entry,
			process_pwddb_entry,
			process_subauth_entry;

unsigned long long cp_memparse(char *v)
{
	char *cp;
	unsigned long long ull = strtoull(v, &cp, 0);

	switch (*cp) {
	case 'E':
	case 'e':
		ull <<= 10;
		/* Fall through */
	case 'P':
	case 'p':
		ull <<= 10;
		/* Fall through */
	case 'T':
	case 't':
		ull <<= 10;
		/* Fall through */
	case 'G':
	case 'g':
		ull <<= 10;
		/* Fall through */
	case 'M':
	case 'm':
		ull <<= 10;
		/* Fall through */
	case 'K':
	case 'k':
		ull <<= 10;
	}

	return ull;
}

static int is_ascii_space_tab(char c)
{
	return c == ' ' || c == '\t';
}

static int is_a_group(char *entry)
{
	char *delim;
	int is_group;

	is_group = *entry == '[';
	if (!is_group)
		goto out;
	entry++;
	delim = strchr(entry, ']');
	is_group = shm_share_name(entry, delim);
	if (!is_group)
		goto out;
	entry = cp_ltrim(delim + 1);
	is_group = cp_smbconf_eol(entry);
	if (!is_group) {
		pr_err("Group contains `%c' [0x%2X]\n",
		       *entry,
		       *entry);
		goto out;
	}
	*entry = 0x00;
out:
	return is_group;
}

static int is_a_key_value(char *entry)
{
	char *delim;
	int is_key_value;

	delim = strchr(entry, '=');
	is_key_value = delim > entry;
	if (!is_key_value)
		goto out;
	for (; entry < delim; entry++) {
		is_key_value = cp_printable(entry) && !cp_smbconf_eol(entry);
		if (!is_key_value) {
			pr_err("Key contains `%c' [0x%2X]\n",
			       *entry,
			       *entry);
			goto out;
		}
	}
	entry = cp_ltrim(entry + 1);
	for (; !cp_smbconf_eol(entry); entry++) {
		is_key_value = cp_printable(entry) || *entry == '\t';
		if (!is_key_value) {
			pr_err("Value contains `%c' [0x%2X]\n",
			       *entry,
			       *entry);
			goto out;
		}
	}
	*entry = 0x00;
out:
	return is_key_value;
}

static void add_group(const char *entry)
{
	g_autofree char *name =
		g_strndup(entry + 1, strchr(entry, ']') - entry - 1);
	struct smbconf_group *g =
		g_hash_table_lookup(parser.groups, name);

	if (g) {
		parser.current = g;
		return;
	}

	g = g_malloc(sizeof(struct smbconf_group));
	g->name = name;
	g->kv = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	g_hash_table_insert(parser.groups, name, g);
	name = NULL;

	parser.current = g;
}

static void add_group_key_value(const char *entry)
{
	const char *delim = strchr(entry, '=');
	g_autofree char *k =
		g_strndup(entry, cp_rtrim(entry, delim - 1) + 1 - entry);
	g_autofree char *v =
		g_strdup(cp_ltrim(delim + 1));

	if (!parser.current) {
		pr_info("No group for key `%s'\n", k);
		return;
	}

	if (cp_smbconf_eol(v) || g_hash_table_lookup(parser.current->kv, k))
		return;

	g_hash_table_insert(parser.current->kv, k, v);
	k = v = NULL;
}

static int process_smbconf_entry(char *entry)
{
	entry = cp_ltrim(entry);

	if (cp_smbconf_eol(entry))
		return 0;

	if (is_a_group(entry)) {
		add_group(entry);
		return 0;
	}

	if (is_a_key_value(entry)) {
		add_group_key_value(entry);
		return 0;
	}

	pr_err("Invalid smbconf entry `%s'\n", entry);
	return -EINVAL;
}

static int __mmap_parse_file(const char *path, process_entry_fn *process_entry)
{
	GError *error = NULL;
	GMappedFile *file;
	char *contents, *delim;
	size_t len;
	int fd, ret;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		pr_debug("Can't open `%s': %m\n", path);
		goto out;
	}

	file = g_mapped_file_new_from_fd(fd, 0, &error);
	if (error) {
		pr_err("%s\n", error->message);
		g_error_free(error);
		ret = -EINVAL;
		goto out_close;
	}

	contents = g_mapped_file_get_contents(file);
	if (!contents) {
		ret = 0;
		goto out_unref;
	}

	for (len = g_mapped_file_get_length(file);
	     len > 0 && len != (size_t)-1;
	     len -= delim - contents + 1, contents = delim + 1) {
		g_autofree char *entry = NULL;

		delim = memchr(contents, '\n', len) ?: contents + len;
		entry = g_strndup(contents, delim - contents);
		ret = process_entry(entry);
		if (ret)
			goto out_unref;
	}

out_unref:
	g_mapped_file_unref(file);
out_close:
	close(fd);
out:
	return ret;
}

static void init_smbconf_parser(void)
{
	if (parser.groups)
		return;

	parser.groups = g_hash_table_new(shm_share_name_hash,
					 shm_share_name_equal);
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

char *cp_ltrim(const char *v)
{
	while (is_ascii_space_tab(*v))
		v++;
	return (char *)v;
}

char *cp_rtrim(const char *v, const char *p)
{
	while (p != v && is_ascii_space_tab(*p))
		p--;
	return (char *)p;
}

int cp_key_cmp(const char *lk, const char *rk)
{
	return g_ascii_strncasecmp(lk, rk, strlen(rk));
}

char *cp_get_group_kv_string(char *v)
{
	return g_strdup(v);
}

int cp_get_group_kv_bool(char *v)
{
	return !cp_key_cmp(v, "yes") ||
	       !cp_key_cmp(v, "1") ||
	       !cp_key_cmp(v, "true") ||
	       !cp_key_cmp(v, "enable");
}

int cp_get_group_kv_config_opt(char *v)
{
	if (!cp_key_cmp(v, "enabled"))
		return KSMBD_CONFIG_OPT_ENABLED;
	if (!cp_key_cmp(v, "auto"))
		return KSMBD_CONFIG_OPT_AUTO;
	if (!cp_key_cmp(v, "mandatory"))
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
		global_conf.guest_account = cp_get_group_kv_string(_v);
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
		global_conf.smb2_max_read = cp_memparse(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "smb2 max write")) {
		global_conf.smb2_max_write = cp_memparse(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "smb2 max trans")) {
		global_conf.smb2_max_trans = cp_memparse(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "smb3 encryption")) {
		switch (cp_get_group_kv_config_opt(_v)) {
		case KSMBD_CONFIG_OPT_DISABLED:
			global_conf.flags |= KSMBD_GLOBAL_FLAG_SMB3_ENCRYPTION_OFF;
			global_conf.flags &= ~KSMBD_GLOBAL_FLAG_SMB3_ENCRYPTION;
			break;
		case KSMBD_CONFIG_OPT_MANDATORY:
			global_conf.flags |= KSMBD_GLOBAL_FLAG_SMB3_ENCRYPTION;
			global_conf.flags &= ~KSMBD_GLOBAL_FLAG_SMB3_ENCRYPTION_OFF;
			break;
		default:
			global_conf.flags &= ~KSMBD_GLOBAL_FLAG_SMB3_ENCRYPTION;
			global_conf.flags &= ~KSMBD_GLOBAL_FLAG_SMB3_ENCRYPTION_OFF;
			break;
		}

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
		global_conf.smb2_max_credits = cp_memparse(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "smbd max io size")) {
		global_conf.smbd_max_io_size = cp_memparse(_v);
		return TRUE;
	}

	if (!cp_key_cmp(_k, "max connections")) {
		global_conf.max_connections = cp_memparse(_v);
		if (!global_conf.max_connections ||
		    global_conf.max_connections > KSMBD_CONF_MAX_CONNECTIONS) {
			pr_info("Limits exceeding the maximum simultaneous connections(%d)\n",
				KSMBD_CONF_MAX_CONNECTIONS);
			global_conf.max_connections = KSMBD_CONF_MAX_CONNECTIONS;
		}
		return TRUE;
	}

	/* At this point, this is an option that must be applied to all shares */
	return FALSE;
}

static void global_conf_default(void)
{
	/* The SPARSE_FILES file system capability flag is set by default */
	global_conf.share_fake_fscaps = 64;
	global_conf.max_connections = KSMBD_CONF_DEFAULT_CONNECTIONS;
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

	g_hash_table_remove(global_group->kv, "guest account");
	g_hash_table_remove(global_group->kv, "max connections");
	g_hash_table_foreach(global_group->kv, append_key_value, group->kv);
}

static void global_conf_fixup_missing(void)
{
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

	if (!global_conf.guest_account)
		global_conf.guest_account =
			cp_get_group_kv_string(
					KSMBD_CONF_DEFAULT_GUEST_ACCOUNT);

	if (usm_add_guest_account(g_strdup(global_conf.guest_account))) {
		g_free(global_conf.guest_account);
		global_conf.guest_account = NULL;
	}
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

static void cp_add_ipc_group(void)
{
	ipc_group = g_hash_table_lookup(parser.groups, "ipc$");
	if (ipc_group)
		return;

	add_group("[ipc$]");
	add_group_key_value("comment = IPC share");
	add_group_key_value("guest ok = yes");
	ipc_group = g_hash_table_lookup(parser.groups, "ipc$");
}

static int __cp_parse_smbconfig(const char *smbconf, GHFunc cb,
				unsigned short cb_mode)
{
	int ret;

	global_conf_default();

	ret = cp_smbconfig_hash_create(smbconf);
	if (ret)
		goto out;

	cp_add_ipc_group();

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

static int is_a_user_password(char *entry)
{
	char *delim;
	int is_user_password;

	delim = strchr(entry, ':');
	is_user_password = usm_user_name(entry, delim);
	if (!is_user_password)
		goto out;
	entry = delim + 1;
	delim = strchr(entry, 0x00);
	for (; delim > entry; delim--)
		if (delim[-1] != '=')
			break;
	is_user_password = delim > entry;
	if (!is_user_password) {
		pr_err("Password is missing\n");
		goto out;
	}
	for (; entry < delim; entry++) {
		is_user_password =
			*entry >= '0' && *entry <= '9' ||
			*entry >= 'A' && *entry <= 'Z' ||
			*entry >= 'a' && *entry <= 'z' ||
			*entry == '+' ||
			*entry == '/';
		if (!is_user_password) {
			pr_err("Password contains `%c' [0x%2X]\n",
			       *entry,
			       *entry);
			goto out;
		}
	}
out:
	return is_user_password;
}

static void add_user_password(const char *entry)
{
	const char *delim = strchr(entry, ':');
	g_autofree char *name = g_strndup(entry, delim - entry);
	g_autofree char *pwd = g_strdup(delim + 1);
	struct ksmbd_user *user = usm_lookup_user(name);

	if (user) {
		usm_update_user_password(user, pwd);
		put_ksmbd_user(user);
		return;
	}

	usm_add_new_user(name, pwd);
	name = pwd = NULL;
}

static int process_pwddb_entry(char *entry)
{
	if (is_a_user_password(entry)) {
		add_user_password(entry);
		return 0;
	}

	pr_err("Invalid pwddb entry `%s'\n", entry);
	return -EINVAL;
}

int cp_parse_pwddb(const char *pwddb)
{
	return __mmap_parse_file(pwddb, process_pwddb_entry);
}

int cp_smbconfig_hash_create(const char *smbconf)
{
	init_smbconf_parser();
	return __mmap_parse_file(smbconf, process_smbconf_entry);
}

static int is_a_subauth(char *entry)
{
	int num_subauth = ARRAY_SIZE(global_conf.gen_subauth), is_subauth = 0;
	int i;

	for (i = 0; i < num_subauth; i++) {
		char *delim = strchr(entry, i + 1 < num_subauth ? ':' : 0x00);

		is_subauth = delim > entry;
		if (!is_subauth) {
			pr_err("Subauth is missing\n");
			goto out;
		}
		for (; entry < delim; entry++) {
			is_subauth = *entry >= '0' && *entry <= '9';
			if (!is_subauth) {
				pr_err("Subauth contains `%c' [0x%2X]\n",
				       *entry,
				       *entry);
				goto out;
			}
		}
		entry++;
	}
out:
	return is_subauth;
}

static void add_subauth(const char *entry)
{
	int num_subauth = ARRAY_SIZE(global_conf.gen_subauth);
	int i;

	for (i = 0; i < num_subauth; i++) {
		const char *delim =
			strchr(entry, i + 1 < num_subauth ? ':' : 0x00);

		global_conf.gen_subauth[i] = 0;
		for (; entry < delim; entry++) {
			global_conf.gen_subauth[i] *= 10;
			global_conf.gen_subauth[i] += *entry - '0';
		}
		entry++;
	}
}

static int process_subauth_entry(char *entry)
{
	if (is_a_subauth(entry)) {
		add_subauth(entry);
		return 0;
	}

	pr_err("Invalid subauth entry `%s'\n", entry);
	return -EINVAL;
}

int cp_parse_subauth(void)
{
	return __mmap_parse_file(PATH_SUBAUTH, process_subauth_entry);
}

void cp_smbconfig_destroy(void)
{
	release_smbconf_parser();
}

void cp_parse_external_smbconf_group(char *name, char *opts)
{
	char *pos;
	int i, len;

	len = strlen(opts);
	/* fake smb.conf input */
	for (i = 0; i < KSMBD_SHARE_CONF_MAX; i++) {
		pos = strstr(opts, KSMBD_SHARE_CONF[i]);
		if (!pos)
			continue;
		if (pos != opts)
			*(pos - 1) = '\n';
	}

	add_group(name);

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
}
