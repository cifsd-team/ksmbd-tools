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

static char **__get_options(GHashTable *kv, int is_global)
{
	GPtrArray *options = g_ptr_array_new();
	enum KSMBD_SHARE_CONF c;

	for (c = 0; c < KSMBD_SHARE_CONF_MAX; c++) {
		const char *k = KSMBD_SHARE_CONF[c], *v = NULL, *pre;

		if (is_global && KSMBD_SHARE_CONF_IS_GLOBAL(c) ||
		    KSMBD_SHARE_CONF_IS_BROKEN(c))
			pre = "; ";
		else
			pre = "";

		if (kv)
			v = g_hash_table_lookup(kv, k);
		if (!v)
			v = "";

		gptrarray_printf(options, "%s%s = %s", pre, k, v);
	}

	return gptrarray_to_strv(options);
}

static GList *new_share_nl(void)
{
	GList *nl = g_hash_table_get_keys(parser.groups), *l = NULL;

	nl = g_list_sort(nl, (GCompareFunc)strcmp);
	if (parser.ipc) {
		l = g_list_find(nl, parser.ipc->name);
		nl = g_list_remove_link(nl, l);
	}
	nl = g_list_concat(l, nl);
	if (parser.global) {
		l = g_list_find(nl, parser.global->name);
		nl = g_list_remove_link(nl, l);
	}
	return g_list_concat(l, nl);
}

static GList *new_share_kl(struct smbconf_group *g)
{
	GList *l = g_hash_table_get_keys(g->kv), *kl = NULL;
	int is_global = g == parser.global;
	enum KSMBD_SHARE_CONF c;
	char *k;

	for (c = 0; c < KSMBD_SHARE_CONF_MAX; c++)
		if ((!is_global || !KSMBD_SHARE_CONF_IS_GLOBAL(c)) &&
		    !KSMBD_SHARE_CONF_IS_BROKEN(c) &&
		    g_hash_table_lookup_extended(g->kv,
						 KSMBD_SHARE_CONF[c],
						 (gpointer *)&k,
						 NULL)) {
			l = g_list_remove(l, k);
			kl = g_list_insert_sorted(kl, k, (GCompareFunc)strcmp);
		}
	l = g_list_sort(l, (GCompareFunc)strcmp);
	if (kl)
		kl = g_list_insert(kl, NULL, 0);
	return g_list_concat(l, kl);
}

static void __gptrarray_add_share_kl(GPtrArray *gptrarray,
				     GList *kl,
				     GHashTable *kv,
				     int is_global)
{
	GList *l;

	if (kl && kl->data)
		gptrarray_printf(
			gptrarray,
			"\t" "; " "%s" "parameters\n",
			is_global ? "global " : "");

	for (l = kl; l; l = l->next) {
		char *k, *v;

		if (!l->data) {
			gptrarray_printf(
				gptrarray,
				"%s" "\t" "; " "%s" "share parameters\n",
				kl->data ? "\n" : "",
				is_global ? "default " : "");
			continue;
		}

		k = l->data;
		v = g_hash_table_lookup(kv, k);
		gptrarray_printf(gptrarray, "\t" "%s = %s\n", k, v);
	}
}

static char *get_conf_contents(void)
{
	GPtrArray *lines = g_ptr_array_new();
	g_autoptr(GList) nl = new_share_nl();
	GList *l;

	gptrarray_printf(lines, "; see ksmbd.conf(5) for details\n" "\n");
	for (l = nl; l; l = l->next) {
		struct smbconf_group *g =
			g_hash_table_lookup(parser.groups, l->data);
		g_autoptr(GList) kl = new_share_kl(g);

		gptrarray_printf(lines, "[%s]\n", g->name);
		__gptrarray_add_share_kl(lines, kl, g->kv, g == parser.global);
		gptrarray_printf(lines, "\n");
	}
	return gptrarray_to_str(lines);
}

int command_add_share(char *smbconf, char *name, char **options)
{
	g_autofree char *contents = NULL;
	int ret;

	if (g_hash_table_lookup(parser.groups, name)) {
		pr_err("Share `%s' already exists\n", name);
		ret = -EEXIST;
		goto out;
	}

	cp_parse_external_smbconf_group(name, options);

	contents = get_conf_contents();
	ret = set_conf_contents(smbconf, contents);
	if (ret)
		goto out;

	pr_info("Added share `%s'\n", name);
out:
	g_free(smbconf);
	g_free(name);
	g_strfreev(options);
	return ret;
}

int command_update_share(char *smbconf, char *name, char **options)
{
	g_autofree char *contents = NULL;
	struct smbconf_group *g;
	int ret;

	g = g_hash_table_lookup(parser.groups, name);
	if (!g) {
		pr_err("Share `%s' does not exist\n", name);
		ret = -EINVAL;
		goto out;
	}

	cp_parse_external_smbconf_group(name, options);

	contents = get_conf_contents();
	ret = set_conf_contents(smbconf, contents);
	if (ret)
		goto out;

	pr_info("Updated share `%s'\n", name);
out:
	g_free(smbconf);
	g_free(name);
	g_strfreev(options);
	return ret;
}

int command_del_share(char *smbconf, char *name, char **options)
{
	g_autofree char *contents = NULL;
	struct smbconf_group *g;
	int ret, is_global;

	g = g_hash_table_lookup(parser.groups, name);
	if (!g) {
		pr_err("Share `%s' does not exist\n", name);
		ret = -EINVAL;
		goto out;
	}

	is_global = g == parser.global;
	if (is_global) {
		g_strfreev(options);
		options = __get_options(NULL, is_global);
		return command_update_share(smbconf, name, options);
	}

	g_hash_table_remove(parser.groups, name);

	contents = get_conf_contents();
	ret = set_conf_contents(smbconf, contents);
	if (ret)
		goto out;

	pr_info("Deleted share `%s'\n", name);
out:
	g_free(smbconf);
	g_free(name);
	g_strfreev(options);
	return ret;
}
