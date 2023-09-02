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
		"Usage: ksmbd.adduser [-v] {-a USER | -u USER} [-p PWD] [-i PWDDB] [-c SMBCONF]\n"
		"       ksmbd.adduser [-v] {-d USER} [-i PWDDB] [-c SMBCONF]\n"
		"       ksmbd.adduser {-V | -h}\n");

	if (status != EXIT_SUCCESS)
		printf("Try `ksmbd.adduser --help' for more information.\n");
	else
		printf(
			"\n"
			"  -a, --add-user=USER         add USER to user database;\n"
			"                              USER must be UTF-8 and [1, " STR(KSMBD_REQ_MAX_ACCOUNT_NAME_SZ) ") bytes;\n"
			"                              USER cannot contain colon (`:')\n"
			"  -d, --del-user=USER         delete USER from user database\n"
			"  -u, --update-user=USER      update USER in user database\n"
			"  -p, --password=PWD          use PWD as user password instead of prompting;\n"
			"                              PWD must be UTF-8 and [0, " STR(MAX_NT_PWD_LEN) ") bytes\n"
			"  -i, --import-users=PWDDB    use PWDDB as user database instead of\n"
			"                              `" PATH_PWDDB "'\n"
			"                              this option does nothing by itself\n"
			"  -c, --config=SMBCONF        use SMBCONF as configuration file instead of\n"
			"                              `" PATH_SMBCONF "'\n"
			"  -v, --verbose               be verbose\n"
			"  -V, --version               output version information and exit\n"
			"  -h, --help                  display this help and exit\n"
			"\n"
			"See ksmbd.adduser(8) for more details.\n");
}

static const struct option opts[] = {
	{"add-user",		required_argument,	NULL,	'a' },
	{"del-user",		required_argument,	NULL,	'd' },
	{"update-user",		required_argument,	NULL,	'u' },
	{"password",		required_argument,	NULL,	'p' },
	{"import-users",	required_argument,	NULL,	'i' },
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
	char *pwddb = NULL, *name = NULL, *password = NULL;
	char *smbconf = NULL;
	command_fn *command = NULL;
	int c;

	set_logger_app_name("ksmbd.adduser");

	while ((c = getopt_long(argc, argv, "c:i:a:d:u:p:vVh", opts, NULL)) != EOF)
		switch (c) {
		case 'a':
			g_free(name);
			name = g_strdup(optarg);
			command = command_add_user;
			break;
		case 'd':
			g_free(name);
			name = g_strdup(optarg);
			command = command_del_user;
			break;
		case 'u':
			g_free(name);
			name = g_strdup(optarg);
			command = command_update_user;
			break;
		case 'p':
			g_free(password);
			password = g_strdup(optarg);
			break;
		case 'i':
			g_free(pwddb);
			pwddb = g_strdup(optarg);
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

	if (argc < 2 || argc > optind || !name) {
		usage(ret ? EXIT_FAILURE : EXIT_SUCCESS);
		goto out;
	}

	if (!usm_user_name(name, strchr(name, 0x00)))
		goto out;

	if (!pwddb)
		pwddb = g_strdup(PATH_PWDDB);

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

	if (command) {
		ret = command(pwddb, name, password);
		if (!ret && send_signal_to_ksmbd_mountd(SIGHUP))
			pr_debug("Unable to notify ksmbd.mountd of changes\n");
	}

out:
	shm_destroy();
	usm_destroy();
	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
