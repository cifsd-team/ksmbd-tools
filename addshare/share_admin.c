// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2019 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <config_parser.h>
#include <ksmbdtools.h>

#include <management/share.h>

#include <linux/ksmbd_server.h>
#include <share_admin.h>

static int conf_fd = -1;
static char wbuf[16384];
static size_t wsz;

#define AUX_GROUP_PREFIX	"_a_u_x_grp_"

static char *new_group_name(char *name)
{
	if (strchr(name, '['))
		return name;

	return g_strdup_printf("[%s]", name);
}

static char *aux_group_name(char *name)
{
	return g_strdup_printf("[%s%s]", AUX_GROUP_PREFIX, name);
}

static int __open_smbconf(char *smbconf)
{
	conf_fd = open(smbconf, O_WRONLY);
	if (conf_fd == -1) {
		pr_err("Can't open `%s': %m\n", smbconf);
		return -EINVAL;
	}

	if (ftruncate(conf_fd, 0) == -1) {
		pr_err("Can't truncate `%s': %m\n", smbconf);
		close(conf_fd);
		return -EINVAL;
	}

	return 0;
}

static void __write(void)
{
	int nr = 0;
	int ret;

	while (wsz && (ret = write(conf_fd, wbuf + nr, wsz)) != 0) {
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			pr_err("Failed to write share entry: %m\n");
			exit(EXIT_FAILURE);
		}

		nr += ret;
		wsz -= ret;
	}
}

static void __write_share(gpointer key, gpointer value, gpointer buf)
{
	char *k = (char *)key;
	char *v = (char *)value;

	wsz = snprintf(wbuf, sizeof(wbuf), "\t%s = %s\n", k, v);
	if (wsz > sizeof(wbuf)) {
		pr_err("Share entry size is above limit: %zu > %zu\n",
		       wsz, sizeof(wbuf));
		exit(EXIT_FAILURE);
	}
	__write();
}

static void write_share(struct smbconf_group *g)
{
	wsz = snprintf(wbuf, sizeof(wbuf), "[%s]\n", g->name);
	__write();
	g_hash_table_foreach(g->kv, __write_share, NULL);
}

static void write_share_cb(gpointer key, gpointer value, gpointer share_data)
{
	struct smbconf_group *g = (struct smbconf_group *)value;

	/*
	 * Do not write AUX group
	 */
	if (!strstr(g->name, AUX_GROUP_PREFIX))
		write_share(g);
}

static void write_remove_share_cb(gpointer key,
				  gpointer value,
				  gpointer name)
{
	struct smbconf_group *g = (struct smbconf_group *)value;

	if (!g_ascii_strcasecmp(g->name, name)) {
		pr_info("Share `%s' removed\n", g->name);
		return;
	}

	write_share(g);
}

static void update_share_cb(gpointer key,
			    gpointer value,
			    gpointer g)
{
	char *nk, *nv;

	nk = g_strdup(key);
	nv = g_strdup(value);
	if (!nk || !nv)
		exit(EXIT_FAILURE);

	/* This will call .dtor for already existing key/value pairs */
	g_hash_table_insert(g, nk, nv);
}

int command_add_share(char *smbconf, char *name, char *opts)
{
	char *new_name = NULL;

	if (g_hash_table_lookup(parser.groups, name)) {
		pr_err("Share `%s' already exists\n", name);
		return -EEXIST;
	}

	new_name = new_group_name(name);
	if (cp_parse_external_smbconf_group(new_name, opts))
		goto error;

	if (__open_smbconf(smbconf))
		goto error;

	pr_info("Adding share `%s'\n", name);
	g_hash_table_foreach(parser.groups, write_share_cb, NULL);
	close(conf_fd);
	g_free(new_name);
	return 0;

error:
	g_free(new_name);
	return -EINVAL;
}

int command_update_share(char *smbconf, char *name, char *opts)
{
	struct smbconf_group *existing_group;
	struct smbconf_group *update_group;
	char *aux_name = NULL;

	existing_group = g_hash_table_lookup(parser.groups, name);
	if (!existing_group) {
		pr_err("Share `%s' does not exist\n", name);
		goto error;
	}

	aux_name = aux_group_name(name);
	if (cp_parse_external_smbconf_group(aux_name, opts))
		goto error;

	/* get rid of [] */
	sprintf(aux_name, "%s%s", AUX_GROUP_PREFIX, name);
	update_group = g_hash_table_lookup(parser.groups, aux_name);
	if (!update_group) {
		pr_err("External group `%s' does not exist\n", aux_name);
		goto error;
	}

	g_hash_table_foreach(update_group->kv,
			     update_share_cb,
			     existing_group->kv);

	if (__open_smbconf(smbconf))
		goto error;

	pr_info("Updating share `%s'\n", name);
	g_hash_table_foreach(parser.groups, write_share_cb, NULL);
	close(conf_fd);
	g_free(aux_name);
	return 0;

error:
	g_free(aux_name);
	return -EINVAL;
}

int command_del_share(char *smbconf, char *name)
{
	if (__open_smbconf(smbconf))
		return -EINVAL;

	g_hash_table_foreach(parser.groups,
			     write_remove_share_cb,
			     name);
	close(conf_fd);
	return 0;
}
