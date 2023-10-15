// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <tools.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#include "ipc.h"
#include "config_parser.h"
#include "version.h"

static void usage(int status)
{
	printf(
		"Usage: ksmbd.mountd [-v] [-p PORT] [-n[WAY]] [-C CONF] [-P PWDDB]\n");

	if (status != EXIT_SUCCESS)
		printf("Try `ksmbd.mountd --help' for more information.\n");
	else
		printf(
			"\n"
			"  -p, --port=PORT         bind to PORT instead of TCP port 445\n"
			"  -n, --nodetach[=WAY]    do not detach process from foreground;\n"
			"                          if WAY is 1, become process group leader (default);\n"
			"                          if WAY is 0, detach\n"
			"  -C, --config=CONF       use CONF as configuration file instead of\n"
			"                          `" PATH_SMBCONF "'\n"
			"  -P, --pwddb=PWDDB       use PWDDB as user database instead of\n"
			"                          `" PATH_PWDDB "'\n"
			"  -v, --verbose           be verbose\n"
			"  -V, --version           output version information and exit\n"
			"  -h, --help              display this help and exit\n"
			"\n"
			"See ksmbd.mountd(8) for more details.\n");
}

static struct option opts[] = {
	{"port",	required_argument,	NULL,	'p' },
	{"nodetach",	optional_argument,	NULL,	'n' },
	{"config",	required_argument,	NULL,	'C' },
	{"pwddb",	required_argument,	NULL,	'P' },
	{"verbose",	no_argument,		NULL,	'v' },
	{"version",	no_argument,		NULL,	'V' },
	{"help",	no_argument,		NULL,	'h' },
	{NULL,		0,			NULL,	 0  }
};

static int show_version(void)
{
	printf("ksmbd-tools version : %s\n", KSMBD_TOOLS_VERSION);
	return 0;
}

static void worker_sa_sigaction(int signo, siginfo_t *siginfo, void *ucontext)
{
	switch (signo) {
	case SIGCHLD:
		return;
	case SIGHUP:
		ksmbd_health_status |= KSMBD_SHOULD_RELOAD_CONFIG;
		return;
	case SIGINT:
	case SIGQUIT:
	case SIGTERM:
		ksmbd_health_status &= ~KSMBD_HEALTH_RUNNING;
		return;
	}

	_Exit(128 + signo);
}

static int worker_init_sa_handler(sigset_t sigset)
{
	int signo;

	for (signo = 1; signo < _NSIG; signo++)
		if (sigismember(&sigset, signo)) {
			struct sigaction act = {
				.sa_sigaction = worker_sa_sigaction,
				.sa_flags = SA_SIGINFO,
			};

			sigfillset(&act.sa_mask);
			sigaction(signo, &act, NULL);
		}
}

static int worker_init_wait(pid_t pid, sigset_t sigset)
{
	int ret = -ECHILD;

	pr_info("Started worker\n");

	for (;;) {
		siginfo_t siginfo;

		if (sigwaitinfo(&sigset, &siginfo) < 0)
			continue;

		if (siginfo.si_signo == SIGCHLD) {
			if (siginfo.si_code == CLD_KILLED)
				siginfo.si_status += 128;
			else if (siginfo.si_code != CLD_EXITED &&
				 siginfo.si_code != CLD_DUMPED)
				continue;
			if (siginfo.si_status > 128) {
				int signo = siginfo.si_status - 128;

				if (!sigismember(&sigset, signo))
					ret = -EIO;
				pr_err("Worker " "%s" "killed: %s\n",
				       ret == -EIO ? "fatally " : "",
				       strsignal(signo));
			} else if (siginfo.si_status != EXIT_SUCCESS) {
				ret = -EIO;
			}
			return ret;
		}

		if (siginfo.si_signo == SIGINT ||
		    siginfo.si_signo == SIGQUIT ||
		    siginfo.si_signo == SIGTERM)
			ret = 0;

		kill(pid, siginfo.si_signo);
	}
}

static int worker_init(void)
{
	sigset_t sigset;
	pid_t pid;
	int ret;

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGCHLD);
	sigaddset(&sigset, SIGHUP);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGQUIT);
	sigaddset(&sigset, SIGTERM);
	sigaddset(&sigset, SIGABRT);
	pthread_sigmask(SIG_BLOCK, &sigset, NULL);

	pid = fork();
	if (pid < 0) {
		ret = -errno;
		pr_err("Can't fork worker: %m\n");
		return ret;
	}
	if (pid > 0)
		return worker_init_wait(pid, sigset);

	worker_init_sa_handler(sigset);

	ret = load_config(global_conf.pwddb, global_conf.smbconf);
	if (ret)
		goto out;

	for (;;) {
		pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

		ret = ipc_process_event();

		pthread_sigmask(SIG_BLOCK, &sigset, NULL);

		if (ret || !(ksmbd_health_status & KSMBD_HEALTH_RUNNING))
			goto out;

		if (ksmbd_health_status & KSMBD_SHOULD_RELOAD_CONFIG) {
			ret = load_config(global_conf.pwddb,
					  global_conf.smbconf);
			if (!ret) {
				pr_info("Reloaded config\n");
				ksmbd_health_status &=
					~KSMBD_SHOULD_RELOAD_CONFIG;
			}
		}
	}

out:
	remove_config();
	return ret;
}

static int manager_init_wait(sigset_t sigset)
{
	pr_info("Started manager\n");

	for (;;) {
		siginfo_t siginfo;

		if (sigwaitinfo(&sigset, &siginfo) < 0)
			continue;

		if (siginfo.si_signo == SIGCHLD) {
			if (siginfo.si_code != CLD_KILLED &&
			    siginfo.si_code != CLD_EXITED &&
			    siginfo.si_code != CLD_DUMPED)
				continue;
			pr_err("Can't init manager, check syslog\n");
			return -ECHILD;
		}

		if (siginfo.si_signo == SIGUSR1) {
			if (siginfo.si_pid != global_conf.pid)
				continue;
			return 0;
		}
	}
}

static int manager_init(int nodetach)
{
	int signo;
	sigset_t sigset;
	int ret;

	for (signo = 1; signo < _NSIG; signo++) {
		struct sigaction act = {
			.sa_handler = SIG_DFL,
			.sa_flags = signo == SIGCHLD ? SA_NOCLDWAIT : 0,
		};

		sigfillset(&act.sa_mask);
		sigaction(signo, &act, NULL);
	}

	sigemptyset(&sigset);
	pthread_sigmask(SIG_SETMASK, &sigset, NULL);

	switch (nodetach) {
	case 0:
		sigaddset(&sigset, SIGCHLD);
		sigaddset(&sigset, SIGUSR1);
		pthread_sigmask(SIG_BLOCK, &sigset, NULL);

		global_conf.pid = fork();
		if (global_conf.pid < 0) {
			ret = -errno;
			pr_err("Can't fork manager: %m\n");
			return ret;
		}
		if (global_conf.pid > 0)
			return manager_init_wait(sigset);

		setsid();
		freopen("/dev/null", "r", stdin);
		freopen("/dev/null", "w", stdout);
		freopen("/dev/null", "w", stderr);
		pr_logger_init(PR_LOGGER_SYSLOG);

		pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);
		break;
	case 1:
		setpgid(0, 0);
	}

	ret = cp_parse_lock();
	if (ret)
		return ret;

	if (cp_parse_subauth())
		pr_info("Ignored subauth file\n");

	if (!nodetach) {
		pid_t ppid = getppid();

		if (ppid == 1)
			return -ESRCH;
		if (kill(ppid, SIGUSR1) < 0) {
			ret = -errno;
			pr_err("Can't send SIGUSR1 to PID %d: %m\n", ppid);
			return ret;
		}
	}

	for (;;) {
		ret = worker_init();
		switch (ret) {
		case -ECHILD:
			sleep(1);
			continue;
		default:
			pr_info("Terminated\n");
			return ret;
		}
	}
}

int mountd_main(int argc, char **argv)
{
	int ret = -EINVAL;
	int nodetach = 0;
	int c;

	while ((c = getopt_long(argc, argv, "p:n::C:P:vVh", opts, NULL)) != EOF)
		switch (c) {
		case 'p':
			global_conf.tcp_port = cp_get_group_kv_long(optarg);
			break;
		case 'n':
			nodetach = !optarg ?: cp_get_group_kv_long(optarg);
			break;
		case 'C':
			g_free(global_conf.smbconf);
			global_conf.smbconf = g_strdup(optarg);
			break;
		case 'P':
			g_free(global_conf.pwddb);
			global_conf.pwddb = g_strdup(optarg);
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

	if (argc > optind) {
		usage(ret ? EXIT_FAILURE : EXIT_SUCCESS);
		goto out;
	}

	if (!global_conf.smbconf)
		global_conf.smbconf = g_strdup(PATH_SMBCONF);

	if (!global_conf.pwddb)
		global_conf.pwddb = g_strdup(PATH_PWDDB);

	ret = manager_init(nodetach);
out:
	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
