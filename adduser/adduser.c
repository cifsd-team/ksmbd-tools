// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
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
#include "management/user.h"
#include "management/share.h"
#include "user_admin.h"
#include "linux/ksmbd_server.h"
#include "version.h"

static void usage(int status)
{
	printf(
		"Usage: ksmbd.adduser [-v] [-P PWDDB] [-c CONF] [-a | -u | -d] [-p PWD] USER\n");

	if (status != EXIT_SUCCESS)
		printf("Try `ksmbd.adduser --help' for more information.\n");
	else
		printf(
			"\n"
			"If neither `-a', `-u', nor `-d' is given, either add or update USER.\n"
			"USER must be UTF-8 and [1, " STR(KSMBD_REQ_MAX_ACCOUNT_NAME_SZ) ") bytes.\n"
			"USER cannot contain colon (`:').\n"
			"\n"
			"  -a, --add             add USER to user database\n"
			"  -u, --update          update USER in user database\n"
			"  -d, --delete          delete USER from user database\n"
			"  -p, --password=PWD    use PWD as user password instead of prompting;\n"
			"                        PWD must be UTF-8 and [0, " STR(MAX_NT_PWD_LEN) ") bytes\n"
			"  -P, --pwddb=PWDDB     use PWDDB as user database instead of\n"
			"                        `" PATH_PWDDB "'\n"
			"  -C, --config=CONF     use CONF as configuration file instead of\n"
			"                        `" PATH_SMBCONF "'\n"
			"  -v, --verbose         be verbose\n"
			"  -V, --version         output version information and exit\n"
			"  -h, --help            display this help and exit\n"
			"\n"
			"See ksmbd.adduser(8) for more details.\n");
}

static const struct option opts[] = {
	{"add",			no_argument,		NULL,	'a' },
	{"delete",		no_argument,		NULL,	'd' },
	{"update",		no_argument,		NULL,	'u' },
	{"password",		required_argument,	NULL,	'p' },
	{"pwddb",		required_argument,	NULL,	'P' },
	{"config",		required_argument,	NULL,	'C' },
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

static int parse_configs(char *pwddb, char *smbconf)
{
	int ret;

	ret = test_file_access(pwddb);
	if (ret) {
		pr_err("Failed to access user database\n");
		return ret;
	}

	ret = cp_parse_pwddb(pwddb);
	if (ret) {
		pr_err("Failed to parse user database\n");
		return ret;
	}

	ret = cp_parse_smbconf(smbconf);
	if (ret == -ENOENT) {
		pr_info("Configuration file does not exist, "
			"cannot guard against user deletion\n");
		ret = 0;
	} else if (ret)
		pr_err("Failed to parse configuration file\n");
	return ret;
}

int adduser_main(int argc, char **argv)
{
	int ret = -EINVAL;
	g_autofree char *pwddb = NULL, *name = NULL, *password = NULL;
	g_autofree char *smbconf = NULL;
	command_fn *command = NULL;
	int c;

	set_logger_app_name("ksmbd.adduser");

	while ((c = getopt_long(argc, argv, "audp:P:C:vVh", opts, NULL)) != EOF)
		switch (c) {
		case 'a':
			command = command_add_user;
			break;
		case 'u':
			command = command_update_user;
			break;
		case 'd':
			command = command_delete_user;
			break;
		case 'p':
			g_free(password);
			password = g_strdup(optarg);
			break;
		case 'P':
			g_free(pwddb);
			pwddb = g_strdup(optarg);
			break;
		case 'C':
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

	if (optind == argc - 1) {
		name = g_strdup(argv[optind]);
	} else {
		usage(ret ? EXIT_FAILURE : EXIT_SUCCESS);
		goto out;
	}

	if (!usm_user_name(name, strchr(name, 0x00)))
		goto out;

	if (!pwddb)
		pwddb = g_strdup(PATH_PWDDB);

	if (!smbconf)
		smbconf = g_strdup(PATH_SMBCONF);

	ret = usm_init();
	if (ret) {
		pr_err("Failed to init user management\n");
		goto out;
	}

	ret = shm_init();
	if (ret) {
		pr_err("Failed to init net share management\n");
		goto out;
	}

	ret = parse_configs(pwddb, smbconf);
	if (ret)
		goto out;

	if (!command) {
		struct ksmbd_user *user = usm_lookup_user(name);

		if (user) {
			put_ksmbd_user(user);
			command = command_update_user;
		} else {
			command = command_add_user;
		}
	}

	ret = command(pwddb, name, password);
	pwddb = name = password = NULL;
	if (!ret) {
		if (!send_signal_to_ksmbd_mountd(SIGHUP))
			pr_info("Notified mountd\n");
		else
			pr_info("Unable to notify mountd\n");
	}
out:
	shm_destroy();
	usm_destroy();
	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
