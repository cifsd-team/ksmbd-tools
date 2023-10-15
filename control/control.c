// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2020 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <glib.h>

#include "tools.h"
#include "version.h"

#define PATH_CLASS_ATTR_KILL_SERVER	"/sys/class/ksmbd-control/kill_server"
#define PATH_CLASS_ATTR_DEBUG		"/sys/class/ksmbd-control/debug"
#define PATH_MODULE_VERSION		"/sys/module/ksmbd/version"

static void usage(int status)
{
	printf(
		"Usage: ksmbd.control [-v] -s\n"
		"       ksmbd.control [-v] -r\n"
		"       ksmbd.control [-v] -d COMPONENT\n"
		"       ksmbd.control [-v] -c\n");

	if (status != EXIT_SUCCESS)
		printf("Try `ksmbd.control --help' for more information.\n");
	else
		printf(
			"\n"
			"  -s, --shutdown           shutdown both ksmbd.mountd and ksmbd and exit\n"
			"  -r, --reload             notify ksmbd.mountd of changes and exit\n"
			"  -d, --debug=COMPONENT    toggle ksmbd debug printing for COMPONENT and exit;\n"
			"                           COMPONENT is `all', `smb', `auth', `vfs', `oplock',\n"
			"                           `ipc', `conn', or `rdma';\n"
			"                           enabled ones are output enclosed in brackets (`[]')\n"
			"  -c, --ksmbd-version      output ksmbd version information and exit\n"
			"  -v, --verbose            be verbose\n"
			"  -V, --version            output version information and exit\n"
			"  -h, --help               display this help and exit\n"
			"\n"
			"See ksmbd.control(8) for more details.\n");
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
	printf("ksmbd-tools version : %s\n", KSMBD_TOOLS_VERSION);
	return 0;
}

static int control_shutdown(void)
{
	int ret, fd;

	ret = send_signal_to_ksmbd_mountd(SIGTERM);
	if (ret)
		pr_err("Can't terminate mountd\n");
	else
		pr_info("Terminated mountd\n");

	fd = open(PATH_CLASS_ATTR_KILL_SERVER, O_WRONLY);
	if (fd < 0) {
		ret = -errno;
		pr_debug("Can't open `%s': %m\n",
			 PATH_CLASS_ATTR_KILL_SERVER);
		goto err_kill;
	}

	if (write(fd, "hard", sizeof("hard") - 1) < 0) {
		ret = -errno;
		pr_debug("Can't write `%s': %m\n",
			 PATH_CLASS_ATTR_KILL_SERVER);
		close(fd);
		goto err_kill;
	}

	close(fd);
	pr_info("Killed ksmbd\n");
	return ret;

err_kill:
	pr_err("Can't kill ksmbd\n");
	return ret;
}

static int control_reload(void)
{
	int ret;

	ret = send_signal_to_ksmbd_mountd(SIGHUP);
	if (ret)
		pr_err("Can't notify mountd\n");
	else
		pr_info("Notified mountd\n");
	return ret;
}

static int control_show_version(void)
{
	g_autofree char *version = NULL;
	int fd, ret;
	off_t len;

	fd = open(PATH_MODULE_VERSION, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		pr_debug("Can't open `%s': %m\n", PATH_MODULE_VERSION);
		goto err;
	}

	len = lseek(fd, 0, SEEK_END);
	if (len == (off_t)-1 || lseek(fd, 0, SEEK_SET) == (off_t)-1) {
		ret = -errno;
		pr_debug("Can't seek `%s': %m\n", PATH_MODULE_VERSION);
		close(fd);
		goto err;
	}

	version = g_malloc0(len + 1);
	if (read(fd, version, len) < 0) {
		ret = -errno;
		pr_debug("Can't read `%s': %m\n", PATH_MODULE_VERSION);
		close(fd);
		goto err;
	}

	ret = 0;
	close(fd);
	pr_info("ksmbd version : " "%s", version);
	return ret;

err:
	pr_err("Can't output ksmbd version\n");
	return ret;
}

static int control_debug(char *comp)
{
	g_autofree char *debug = NULL;
	int fd, ret;
	off_t len;

	fd = open(PATH_CLASS_ATTR_DEBUG, O_RDWR);
	if (fd < 0) {
		ret = -errno;
		pr_debug("Can't open `%s': %m\n", PATH_CLASS_ATTR_DEBUG);
		goto err;
	}

	if (write(fd, comp, strlen(comp)) < 0) {
		ret = -errno;
		pr_debug("Can't write `%s': %m\n", PATH_CLASS_ATTR_DEBUG);
		close(fd);
		goto err;
	}

	len = lseek(fd, 0, SEEK_END);
	if (len == (off_t)-1 || lseek(fd, 0, SEEK_SET) == (off_t)-1) {
		ret = -errno;
		pr_debug("Can't seek `%s': %m\n", PATH_CLASS_ATTR_DEBUG);
		close(fd);
		goto err;
	}

	debug = g_malloc0(len + 1);
	if (read(fd, debug, len) < 0) {
		ret = -errno;
		pr_debug("Can't read `%s': %m\n", PATH_CLASS_ATTR_DEBUG);
		close(fd);
		goto err;
	}

	ret = 0;
	close(fd);
	pr_info("%s", debug);
	return ret;

err:
	pr_err("Can't toggle ksmbd debug component\n");
	return ret;
}

int control_main(int argc, char **argv)
{
	int ret = -EINVAL;
	int c;

	while ((c = getopt_long(argc, argv, "srd:cvVh", opts, NULL)) != EOF)
		switch (c) {
		case 's':
			ret = control_shutdown();
			goto out;
		case 'r':
			ret = control_reload();
			goto out;
		case 'd':
			ret = control_debug(optarg);
			goto out;
		case 'c':
			ret = control_show_version();
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

	usage(ret ? EXIT_FAILURE : EXIT_SUCCESS);
out:
	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
