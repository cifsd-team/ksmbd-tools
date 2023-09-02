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
#include <tools.h>

#include <management/share.h>

#include <linux/ksmbd_server.h>
#include <share_admin.h>

static int conf_fd = -1;
static char wbuf[16384];
static size_t wsz;

#define AUX_GROUP_PREFIX	"_a_u_x_grp_"

static char *new_group_name(char *name)
{
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

	if (shm_share_name_equal(g->name, name)) {
		pr_info("Share `%s' removed\n", (char *)name);
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

	/* This will call .dtor for already existing key/value pairs */
	g_hash_table_insert(g, nk, nv);
}

int command_add_share(char *smbconf, char *name, char *opts)
{
	g_autofree char *new_name = NULL;

	if (g_hash_table_lookup(parser.groups, name)) {
		pr_err("Share `%s' already exists\n", name);
		return -EEXIST;
	}

	new_name = new_group_name(name);
	cp_parse_external_smbconf_group(new_name, opts);

	if (__open_smbconf(smbconf))
		return -EINVAL;

	pr_info("Adding share `%s'\n", name);
	g_hash_table_foreach(parser.groups, write_share_cb, NULL);
	close(conf_fd);
	return 0;
}

int command_update_share(char *smbconf, char *name, char *opts)
{
	struct smbconf_group *existing_group;
	struct smbconf_group *update_group;
	g_autofree char *aux_name = NULL;

	existing_group = g_hash_table_lookup(parser.groups, name);
	if (!existing_group) {
		pr_err("Share `%s' does not exist\n", name);
		return -EINVAL;
	}

	aux_name = aux_group_name(name);
	cp_parse_external_smbconf_group(aux_name, opts);

	/* get rid of [] */
	sprintf(aux_name, "%s%s", AUX_GROUP_PREFIX, name);
	update_group = g_hash_table_lookup(parser.groups, aux_name);
	if (!update_group) {
		pr_err("External group `%s' does not exist\n", aux_name);
		return -EINVAL;
	}

	g_free(existing_group->name);
	existing_group->name = g_strdup(name);

	g_hash_table_foreach(update_group->kv,
			     update_share_cb,
			     existing_group->kv);

	if (__open_smbconf(smbconf))
		return -EINVAL;

	pr_info("Updating share `%s'\n", name);
	g_hash_table_foreach(parser.groups, write_share_cb, NULL);
	close(conf_fd);
	return 0;
}

int command_del_share(char *smbconf, char *name, char *unused)
{
	struct smbconf_group *g;
	(void)unused;

	g = g_hash_table_lookup(parser.groups, name);
	if (!g) {
		pr_err("Share `%s' does not exist\n", name);
		return -EINVAL;
	}

	if (__open_smbconf(smbconf))
		return -EINVAL;

	g_hash_table_foreach(parser.groups,
			     write_remove_share_cb,
			     name);
	close(conf_fd);
	return 0;
}
