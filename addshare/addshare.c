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
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>

#include "config_parser.h"
#include "ksmbdtools.h"
#include "management/share.h"
#include "linux/ksmbd_server.h"
#include "share_admin.h"
#include "version.h"

static char *arg_name;
static char *arg_opts;

enum {
	COMMAND_ADD_SHARE = 1,
	COMMAND_DEL_SHARE,
	COMMAND_UPDATE_SHARE,
};

static void usage(int status)
{
	int i;

	g_printerr(
		"Usage: ksmbd.addshare {-a SHARE | -u SHARE} {-o OPTIONS} [-c SMBCONF] [-v]\n"
		"       ksmbd.addshare {-d SHARE} [-c SMBCONF] [-v]\n"
		"       ksmbd.addshare {-V | -h}\n");

	if (status != EXIT_SUCCESS)
		g_printerr("Try `ksmbd.addshare --help' for more information.\n");
	else {
		g_printerr(
			"Configure shares for config file of ksmbd.mountd user mode daemon.\n"
			"\n"
			"Mandatory arguments to long options are mandatory for short options too.\n"
			"  -a, --add-share=SHARE       add SHARE to config file;\n"
			"                              SHARE is 1 to " STR(KSMBD_REQ_MAX_SHARE_NAME) " characters;\n"
			"                              SHARE cannot be `global';\n"
			"                              you must also give option `options'\n"
			"  -d, --del-share=SHARE       delete SHARE from config file\n"
			"  -u, --update-share=SHARE    update SHARE in config file;\n"
			"                              you must also give option `options'\n"
			"  -o, --options=OPTIONS       provide OPTIONS for share;\n"
			"                              OPTIONS is one argument and has format\n"
			"                              `1st op = 1st val<newline>2nd op = 2nd val...';\n"
			"                              separators other than newline create ambiguity\n"
			"  -c, --config=SMBCONF        use SMBCONF as config file instead of\n"
			"                              `" PATH_SMBCONF "'\n"
			"  -v, --verbose               be verbose\n"
			"  -V, --version               output version information and exit\n"
			"  -h, --help                  display this help and exit\n"
			"\n"
			"ksmbd.addshare notifies ksmbd.mountd of any made changes.\n"
			"\n"
			"Following options are supported for use in OPTIONS:\n");
		for (i = 0; i < KSMBD_SHARE_CONF_MAX; i++)
			g_printerr("  %s\n", KSMBD_SHARE_CONF[i]);
		g_printerr(
			"\n"
			"ksmbd-tools home page: <https://github.com/cifsd-team/ksmbd-tools>\n");
	}
}

static const struct option opts[] = {
	{"add-share",		required_argument,	NULL,	'a' },
	{"del-share",		required_argument,	NULL,	'd' },
	{"update-share",	required_argument,	NULL,	'u' },
	{"options",		required_argument,	NULL,	'o' },
	{"config",		required_argument,	NULL,	'c' },
	{"verbose",		no_argument,		NULL,	'v' },
	{"version",		no_argument,		NULL,	'V' },
	{"help",		no_argument,		NULL,	'h' },
	{NULL,			0,			NULL,	 0  }
};

static int show_version(void)
{
	g_print("ksmbd-tools version : %s\n", KSMBD_TOOLS_VERSION);
	return 0;
}

static int parse_configs(char *smbconf)
{
	int ret;

	ret = test_file_access(smbconf);
	if (ret)
		return ret;

	ret = cp_smbconfig_hash_create(smbconf);
	return ret;
}

static int sanity_check_share_name_simple(char *name)
{
	int sz;

	if (!name)
		return -EINVAL;

	sz = strlen(name);
	if (sz < 1)
		return -EINVAL;
	if (sz >= KSMBD_REQ_MAX_SHARE_NAME)
		return -EINVAL;

	if (!g_ascii_strcasecmp(name, "global"))
		return -EINVAL;

	return 0;
}

int main(int argc, char *argv[])
{
	int ret = -EINVAL;
	char *smbconf = PATH_SMBCONF;
	int c, cmd = 0;

	set_logger_app_name("ksmbd.addshare");

	while ((c = getopt_long(argc, argv, "a:d:u:o:c:vVh", opts, NULL)) != EOF)
		switch (c) {
		case 'a':
			arg_name = g_ascii_strdown(optarg, strlen(optarg));
			cmd = COMMAND_ADD_SHARE;
			break;
		case 'd':
			arg_name = g_ascii_strdown(optarg, strlen(optarg));
			cmd = COMMAND_DEL_SHARE;
			break;
		case 'u':
			arg_name = g_ascii_strdown(optarg, strlen(optarg));
			cmd = COMMAND_UPDATE_SHARE;
			break;
		case 'o':
			arg_opts = strdup(optarg);
			break;
		case 'c':
			smbconf = strdup(optarg);
			break;
		case 'v':
			set_log_level(PR_DEBUG);
			break;
		case 'V':
			ret = show_version();
			goto out;
		case 'h':
			ret = 0;
			/* Fall through */
		case '?':
		default:
			usage(ret ? EXIT_FAILURE : EXIT_SUCCESS);
			goto out;
		}

	if (argc < 2 || argc > optind) {
		usage(ret ? EXIT_FAILURE : EXIT_SUCCESS);
		goto out;
	}

	if (!arg_name) {
		pr_err("No option with share name given\n");
		goto out;
	}

	if (cmd != COMMAND_DEL_SHARE && !arg_opts) {
		pr_err("No options for share given\n");
		goto out;
	}

	if (sanity_check_share_name_simple(arg_name)) {
		pr_err("Share name sanity check failure\n");
		goto out;
	}

	if (!smbconf) {
		pr_err("Out of memory\n");
		goto out;
	}

	ret = parse_configs(smbconf);
	if (ret) {
		pr_err("Unable to parse configuration files\n");
		goto out;
	}

	if (cmd == COMMAND_ADD_SHARE)
		ret = command_add_share(smbconf, arg_name, arg_opts);
	if (cmd == COMMAND_DEL_SHARE)
		ret = command_del_share(smbconf, arg_name);
	if (cmd == COMMAND_UPDATE_SHARE)
		ret = command_update_share(smbconf, arg_name, arg_opts);

	if (cmd && !ret) {
		int old_level;

		old_level = set_log_level(PR_NONE);
		if (send_signal_to_ksmbd_mountd(SIGHUP))
			pr_err("Failed to notify ksmbd.mountd of changes\n");
		set_log_level(old_level);
	}
out:
	cp_smbconfig_destroy();
	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
