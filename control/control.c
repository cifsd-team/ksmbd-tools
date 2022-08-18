// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2020 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <getopt.h>
#include <fcntl.h>
#include <errno.h>

#include "ksmbdtools.h"
#include "version.h"

static void usage(int status)
{
	g_printerr(
		"Usage: ksmbd.control {-s | -r | -d COMPONENT | -c} [-v]\n"
		"       ksmbd.control {-V | -h}\n");

	if (status != EXIT_SUCCESS)
		g_printerr("Try `ksmbd.control --help' for more information.\n");
	else
		g_printerr(
			"Control ksmbd.mountd user mode and ksmbd kernel mode daemons.\n"
			"\n"
			"Mandatory arguments to long options are mandatory for short options too.\n"
			"  -s, --shutdown           shutdown daemons and exit\n"
			"  -r, --reload             notify ksmbd.mountd of changes and exit\n"
			"  -d, --debug=COMPONENT    toggle debug printing for COMPONENT and exit;\n"
			"                           COMPONENT is `all', `smb', `auth', `vfs',\n"
			"                           `oplock', `ipc', `conn', or `rdma';\n"
			"                           output also status of all components;\n"
			"                           enabled components are enclosed in brackets\n"
			"  -c, --ksmbd-version      output ksmbd version information and exit\n"
			"  -v, --verbose            be verbose\n"
			"  -V, --version            output version information and exit\n"
			"  -h, --help               display this help and exit\n"
			"\n"
			"ksmbd-tools home page: <https://github.com/cifsd-team/ksmbd-tools>\n");
}

static const struct option opts[] = {
	{"shutdown",		no_argument,		NULL,	's' },
	{"reload",		no_argument,		NULL,	'r' },
	{"debug",		required_argument,	NULL,	'd' },
	{"ksmbd-version",	no_argument,		NULL,	'c' },
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

static int ksmbd_control_shutdown(void)
{
	int fd, ret = -EINVAL;
	const char *path = "/sys/class/ksmbd-control/kill_server";

	if (send_signal_to_ksmbd_mountd(SIGTERM))
		pr_err("Failed to terminate ksmbd.mountd\n");

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		pr_err("Can't open `%s': %m\n", path);
		return ret;
	}

	if (write(fd, "hard", 4) == -1)
		goto out;

	ret = 0;
out:
	close(fd);
	return ret;
}

static int ksmbd_control_reload(void)
{
	return send_signal_to_ksmbd_mountd(SIGHUP);
}

static int ksmbd_control_show_version(void)
{
	int fd, ret = -EINVAL;
	const char *path = "/sys/module/ksmbd/version";
	char ver[255] = {0};

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_err("Can't open `%s': %m\n", path);
		return ret;
	}

	if (read(fd, ver, 255) == -1)
		goto out;

	pr_info("ksmbd version : %s\n", ver);
	ret = 0;
out:
	close(fd);
	return ret;
}

static int ksmbd_control_debug(char *comp)
{
	int fd, ret = -EINVAL;
	const char *path = "/sys/class/ksmbd-control/debug";
	char buf[255] = {0};

	fd = open(path, O_RDWR);
	if (fd < 0) {
		pr_err("Can't open `%s': %m\n", path);
		return ret;
	}

	if (write(fd, comp, strlen(comp)) == -1)
		goto out;
	if (lseek(fd, 0, SEEK_SET) == -1)
		goto out;
	if (read(fd, buf, 255) == -1)
		goto out;

	pr_info("%s\n", buf);
	ret = 0;
out:
	close(fd);
	return ret;
}

int main(int argc, char *argv[])
{
	int ret = -EINVAL;
	int c;

	set_logger_app_name("ksmbd.control");

	if (getuid() != 0) {
		pr_err("Please try it as root.\n");
		return ret;
	}

	while ((c = getopt_long(argc, argv, "srd:cvVh", opts, NULL)) != EOF)
		switch (c) {
		case 's':
			ret = ksmbd_control_shutdown();
			goto out;
		case 'r':
			ret = ksmbd_control_reload();
			goto out;
		case 'd':
			ret = ksmbd_control_debug(optarg);
			goto out;
		case 'c':
			ret = ksmbd_control_show_version();
			goto out;
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

	if (argc < 2 || argc > optind)
		usage(ret ? EXIT_FAILURE : EXIT_SUCCESS);
out:
	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
