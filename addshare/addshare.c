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
#include "management/user.h"
#include "linux/ksmbd_server.h"
#include "share_admin.h"
#include "version.h"

static void usage(int status)
{
	printf(
		"Usage: ksmbd.addshare [-v] {-a SHARE | -u SHARE} [-c SMBCONF] [-i PWDDB] [-o OPTION]...\n"
		"       ksmbd.addshare [-v] {-d SHARE} [-c SMBCONF] [-i PWDDB]\n"
		"       ksmbd.addshare {-V | -h}\n");

	if (status != EXIT_SUCCESS)
		printf("Try `ksmbd.addshare --help' for more information.\n");
	else
		printf(
			"\n"
			"  -a, --add-share=SHARE       add SHARE to configuration file;\n"
			"                              SHARE must be UTF-8 and [1, " STR(KSMBD_REQ_MAX_SHARE_NAME) ") bytes;\n"
			"                              SHARE is case-insensitive\n"
			"  -d, --del-share=SHARE       delete SHARE from configuration file\n"
			"  -u, --update-share=SHARE    update SHARE in configuration file\n"
			"  -o, --option=OPTION         use OPTION as parameter instead of prompting;\n"
			"                              global parameters cannot be given;\n"
			"                              this option can be given multiple times\n"
			"  -c, --config=SMBCONF        use SMBCONF as configuration file instead of\n"
			"                              `" PATH_SMBCONF "'\n"
			"  -i, --import-users=PWDDB    use PWDDB as user database instead of\n"
			"                              `" PATH_PWDDB "'\n"
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
	{"option",		required_argument,	NULL,	'o' },
	{"config",		required_argument,	NULL,	'c' },
	{"import-users",	required_argument,	NULL,	'i' },
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

static int parse_configs(char *smbconf, char *pwddb)
{
	int ret;

	ret = test_file_access(smbconf);
	if (ret) {
		pr_err("Failed to access configuration file\n");
		return ret;
	}

	ret = cp_parse_pwddb(pwddb);
	if (ret == -ENOENT) {
		pr_info("User database does not exist, "
			"cannot provide user completions\n");
	} else if (ret) {
		pr_err("Failed to parse user database\n");
		return ret;
	}

	ret = cp_parse_smbconf(smbconf);
	if (!ret) {
		cp_init_smbconf_parser();
		ret = cp_parse_smbconf(smbconf);
	}
	if (ret)
		pr_err("Failed to parse configuration file\n");
	return ret;
}

int addshare_main(int argc, char **argv)
{
	int ret = -EINVAL;
	g_autofree char *smbconf = NULL, *name = NULL, *pwddb = NULL;
	g_auto(GStrv) options = NULL;
	g_autoptr(GPtrArray) __options =
		g_ptr_array_new_with_free_func(g_free);
	command_fn *command = NULL;
	int c;

	set_logger_app_name("ksmbd.addshare");

	while ((c = getopt_long(argc, argv, "a:d:u:o:c:i:vVh", opts, NULL)) != EOF)
		switch (c) {
		case 'a':
			g_free(name);
			name = g_strdup(optarg);
			command = command_add_share;
			break;
		case 'd':
			g_free(name);
			name = g_strdup(optarg);
			command = command_del_share;
			break;
		case 'u':
			g_free(name);
			name = g_strdup(optarg);
			command = command_update_share;
			break;
		case 'o':
			gptrarray_printf(__options, "%s", optarg);
			break;
		case 'c':
			g_free(smbconf);
			smbconf = g_strdup(optarg);
			break;
		case 'i':
			g_free(pwddb);
			pwddb = g_strdup(optarg);
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

	options = gptrarray_to_strv(__options);
	__options = NULL;

	if (argc < 2 || argc > optind || !name) {
		usage(ret ? EXIT_FAILURE : EXIT_SUCCESS);
		goto out;
	}

	if (!shm_share_name(name, strchr(name, 0x00)))
		goto out;

	if (!smbconf)
		smbconf = g_strdup(PATH_SMBCONF);

	if (!pwddb)
		pwddb = g_strdup(PATH_PWDDB);

	ret = usm_init();
	if (ret) {
		pr_err("Failed to init user management\n");
		goto out;
	}

	ret = shm_init();
	if (ret) {
		pr_err("Failed to init share management\n");
		goto out;
	}

	ret = parse_configs(smbconf, pwddb);
	if (ret)
		goto out;

	if (command) {
		ret = command(smbconf, name, options);
		smbconf = name = (char *)(options = NULL);
		if (!ret && send_signal_to_ksmbd_mountd(SIGHUP))
			pr_debug("Unable to notify ksmbd.mountd of changes\n");
	}

out:
	cp_release_smbconf_parser();
	shm_destroy();
	usm_destroy();
	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
