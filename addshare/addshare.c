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
#include "tools.h"
#include "management/share.h"
#include "linux/ksmbd_server.h"
#include "share_admin.h"
#include "version.h"

static void usage(int status)
{
	printf(
		"Usage: ksmbd.addshare [-v] {-a SHARE | -u SHARE} {-o OPTIONS} [-c SMBCONF]\n"
		"       ksmbd.addshare [-v] {-d SHARE} [-c SMBCONF]\n"
		"       ksmbd.addshare {-V | -h}\n");

	if (status != EXIT_SUCCESS)
		printf("Try `ksmbd.addshare --help' for more information.\n");
	else
		printf(
			"\n"
			"  -a, --add-share=SHARE       add SHARE to configuration file;\n"
			"                              SHARE must be UTF-8 and [1, " STR(KSMBD_REQ_MAX_SHARE_NAME) ") bytes;\n"
			"                              SHARE is case-insensitive;\n"
			"                              SHARE cannot be `global';\n"
			"                              initial parameters must be given with `--options'\n"
			"  -d, --del-share=SHARE       delete SHARE from configuration file\n"
			"  -u, --update-share=SHARE    update SHARE in configuration file;\n"
			"                              updated parameters must be given with `--options'\n"
			"  -o, --options=OPTIONS       use OPTIONS as parameters;\n"
			"                              OPTIONS is one argument and follows format\n"
			"                              `1st par = 1st val<newline>2nd par = 2nd val...';\n"
			"                              separators other than newline create ambiguity;\n"
			"                              global parameters cannot be given\n"
			"  -c, --config=SMBCONF        use SMBCONF as configuration file instead of\n"
			"                              `" PATH_SMBCONF "'\n"
			"  -v, --verbose               be verbose\n"
			"  -V, --version               output version information and exit\n"
			"  -h, --help                  display this help and exit\n"
			"\n"
			"See ksmbd.addshare(8) for more details.\n");
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
	printf("ksmbd-tools version : %s\n", KSMBD_TOOLS_VERSION);
	return 0;
}

static int parse_configs(char *smbconf)
{
	int ret;

	ret = test_file_access(smbconf);
	if (ret) {
		pr_err("Failed to access configuration file\n");
		return ret;
	}

	ret = cp_smbconfig_hash_create(smbconf);
	if (ret)
		pr_err("Failed to parse configuration file\n");
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

int addshare_main(int argc, char **argv)
{
	int ret = -EINVAL;
	char *share = NULL, *options = NULL, *smbconf = NULL;
	command_fn command = NULL;
	int c;

	set_logger_app_name("ksmbd.addshare");

	while ((c = getopt_long(argc, argv, "a:d:u:o:c:vVh", opts, NULL)) != EOF)
		switch (c) {
		case 'a':
			g_free(share);
			share = g_strdup(optarg);
			command = command_add_share;
			break;
		case 'd':
			g_free(share);
			share = g_strdup(optarg);
			command = command_del_share;
			break;
		case 'u':
			g_free(share);
			share = g_strdup(optarg);
			command = command_update_share;
			break;
		case 'o':
			g_free(options);
			options = g_strdup(optarg);
			break;
		case 'c':
			g_free(smbconf);
			smbconf = g_strdup(optarg);
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

	if (!share) {
		pr_err("No option with share name given\n");
		goto out;
	}

	if ((command == command_add_share || command == command_update_share) &&
	    !options) {
		pr_err("No parameters given\n");
		goto out;
	}

	if (sanity_check_share_name_simple(share)) {
		pr_err("Share name sanity check failure\n");
		goto out;
	}

	if (!smbconf) {
		smbconf = g_strdup(PATH_SMBCONF);
		if (!g_file_test(smbconf, G_FILE_TEST_EXISTS) &&
		    g_file_test(PATH_SMBCONF_FALLBACK, G_FILE_TEST_EXISTS)) {
			pr_err("Use of `%s' is deprecated, rename it to `%s' now!\n",
					PATH_SMBCONF_FALLBACK, PATH_SMBCONF);
			g_free(smbconf);
			smbconf = g_strdup(PATH_SMBCONF_FALLBACK);
		}
	}

	ret = parse_configs(smbconf);
	if (ret)
		goto out;

	if (command) {
		ret = command(smbconf, share, options);
		if (!ret && send_signal_to_ksmbd_mountd(SIGHUP))
			pr_debug("Unable to notify ksmbd.mountd of changes\n");
	}

out:
	cp_smbconfig_destroy();
	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
