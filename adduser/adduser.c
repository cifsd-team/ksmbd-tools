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
#include "ksmbdtools.h"
#include "management/user.h"
#include "management/share.h"
#include "user_admin.h"
#include "linux/ksmbd_server.h"
#include "version.h"

static char *arg_account = NULL;
static char *arg_password = NULL;

enum {
	COMMAND_ADD_USER = 1,
	COMMAND_DEL_USER,
	COMMAND_UPDATE_USER,
};

static void usage(int status)
{
	g_printerr(
		"Usage: ksmbd.adduser {-a USER | -u USER} [-p PWD] [-i PWDDB] [-c SMBCONF] [-v]\n"
		"       ksmbd.adduser {-d USER} [-i PWDDB] [-c SMBCONF] [-v]\n"
		"       ksmbd.adduser {-V | -h}\n");

	if (status != EXIT_SUCCESS)
		g_printerr("Try `ksmbd.adduser --help' for more information.\n");
	else
		g_printerr(
			"Configure users for user database of ksmbd.mountd user mode daemon.\n"
			"\n"
			"Mandatory arguments to long options are mandatory for short options too.\n"
			"  -a, --add-user=USER         add USER to user database;\n"
			"                              USER is 1 to " STR(KSMBD_REQ_MAX_ACCOUNT_NAME_SZ) " characters;\n"
			"                              USER cannot contain `:' or newline;\n"
			"                              USER cannot be `root'\n"
			"  -d, --del-user=USER         delete USER from user database\n"
			"  -u, --update-user=USER      update USER in user database\n"
			"  -p, --password=PWD          provide PWD for user;\n"
			"                              PWD is 0 to " STR(MAX_NT_PWD_LEN) " characters;\n"
			"                              PWD cannot contain newline\n"
			"  -i, --import-users=PWDDB    use PWDDB as user database instead of\n"
			"                              `" PATH_PWDDB "';\n"
			"                              this option does nothing by itself\n"
			"  -c, --config=SMBCONF        use SMBCONF as config file instead of\n"
			"                              `" PATH_SMBCONF "'\n"
			"  -v, --verbose               be more verbose; unimplemented\n"
			"  -V, --version               output version information and exit\n"
			"  -h, --help                  display this help and exit\n"
			"\n"
			"ksmbd-tools home page: <https://github.com/cifsd-team/ksmbd-tools>\n");
}

static const struct option opts[] = {
	{"add-user",		required_argument,	NULL,	'a' },
	{"del-user",		required_argument,	NULL,	'd' },
	{"update-user",		required_argument,	NULL,	'u' },
	{"password",		required_argument,	NULL,	'p' },
	{"import-users",	required_argument,	NULL,	'i' },
	{"config",		required_argument,	NULL,	'c' },
	{"version",		no_argument,		NULL,	'V' },
	{"verbose",		no_argument,		NULL,	'v' },
	{"help",		no_argument,		NULL,	'h' },
	{NULL,			0,			NULL,	 0  }
};

static int show_version(void)
{
	g_print("ksmbd-tools version : %s\n", KSMBD_TOOLS_VERSION);
	return EXIT_SUCCESS;
}

static int parse_configs(char *pwddb, char *smbconf)
{
	int ret;

	ret = test_file_access(pwddb);
	if (ret)
		return ret;

	ret = cp_parse_pwddb(pwddb);
	if (ret)
		return ret;

	ret = cp_parse_smbconf(smbconf);
	if (ret == -ENOENT) {
		pr_info("Config file does not exist, "
			"cannot check if user is a global guest account\n");
		return 0;
	}
	return ret;
}

static int sanity_check_user_name_simple(char *uname)
{
	int sz, i;

	if (!uname)
		return -EINVAL;

	sz = strlen(uname);
	if (sz < 1)
		return -EINVAL;
	if (sz >= KSMBD_REQ_MAX_ACCOUNT_NAME_SZ)
		return -EINVAL;

	/* 1'; Drop table users -- */
	if (!strcmp(uname, "root"))
		return -EINVAL;

	if (strpbrk(uname, ":\n"))
		return -EINVAL;

	return 0;
}

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	char *pwddb = PATH_PWDDB;
	char *smbconf = PATH_SMBCONF;
	int c, cmd = 0;

	set_logger_app_name("ksmbd.adduser");

	while ((c = getopt_long(argc, argv, "c:i:a:d:u:p:Vvh", opts, NULL)) != EOF)
		switch (c) {
		case 'a':
			arg_account = g_strdup(optarg);
			cmd = COMMAND_ADD_USER;
			break;
		case 'd':
			arg_account = g_strdup(optarg);
			cmd = COMMAND_DEL_USER;
			break;
		case 'u':
			arg_account = g_strdup(optarg);
			cmd = COMMAND_UPDATE_USER;
			break;
		case 'p':
			arg_password = g_strdup(optarg);
			break;
		case 'i':
			pwddb = g_strdup(optarg);
			break;
		case 'c':
			smbconf = g_strdup(optarg);
			break;
		case 'V':
			ret = show_version();
			goto out;
		case 'v':
			break;
		case 'h':
			ret = EXIT_SUCCESS;
			/* Fall through */
		case '?':
		default:
			usage(ret);
			goto out;
		}

	if (argc < 2 || argc > optind) {
		usage(ret);
		goto out;
	}

	if (!arg_account) {
		pr_err("No option with user name given\n");
		goto out;
	}

	if (sanity_check_user_name_simple(arg_account)) {
		pr_err("User name sanity check failure\n");
		goto out;
	}

	if (!pwddb) {
		pr_err("Out of memory\n");
		goto out;
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
	if (ret) {
		pr_err("Unable to parse configuration files\n");
		goto out;
	}

	if (cmd == COMMAND_ADD_USER)
		ret = command_add_user(pwddb, arg_account, arg_password);
	if (cmd == COMMAND_DEL_USER)
		ret = command_del_user(pwddb, arg_account);
	if (cmd == COMMAND_UPDATE_USER)
		ret = command_update_user(pwddb, arg_account, arg_password);

	if (cmd && !ret)
		notify_ksmbd_daemon();
out:
	shm_destroy();
	usm_destroy();
	return ret;
}
