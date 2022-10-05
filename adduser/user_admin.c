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
#include <termios.h>

#include <config_parser.h>
#include <tools.h>

#include <md4_hash.h>
#include <user_admin.h>
#include <management/user.h>
#include <management/share.h>

#include <linux/ksmbd_server.h>

static int conf_fd = -1;
static char wbuf[2 * MAX_NT_PWD_LEN + 2 * KSMBD_REQ_MAX_ACCOUNT_NAME_SZ];

static int __opendb_file(char *pwddb)
{
	conf_fd = open(pwddb, O_WRONLY);
	if (conf_fd == -1) {
		pr_err("Can't open `%s': %m\n", pwddb);
		return -EINVAL;
	}

	if (ftruncate(conf_fd, 0) == -1) {
		pr_err("Can't truncate `%s': %m\n", pwddb);
		close(conf_fd);
		return -EINVAL;
	}

	return 0;
}

static void term_toggle_echo(int on_off)
{
	struct termios term;

	tcgetattr(STDIN_FILENO, &term);

	if (on_off)
		term.c_lflag |= ECHO;
	else
		term.c_lflag &= ~ECHO;

	tcsetattr(STDIN_FILENO, TCSAFLUSH, &term);
}

static int __sanity_check_sz_raw(size_t sz_raw)
{
	if (!sz_raw)
		pr_info("Empty password was provided\n");
	else if (sz_raw >= MAX_NT_PWD_LEN) {
		pr_err("Password exceeds maximum length of %d bytes\n",
				MAX_NT_PWD_LEN - 1);
		return -EINVAL;
	}
	return 0;
}

static char *__prompt_password_stdin(size_t *sz)
{
	char *pswd_raw, *pswd_raw_re, *pswd_raw_cur;
	size_t i, len;

	pswd_raw = g_try_malloc0(MAX_NT_PWD_LEN + 1);
	pswd_raw_re = g_try_malloc0(MAX_NT_PWD_LEN + 1);
	if (!pswd_raw || !pswd_raw_re) {
		g_free(pswd_raw);
		g_free(pswd_raw_re);
		pr_err("Out of memory\n");
		return NULL;
	}

	for (pswd_raw_cur = pswd_raw;;
	     pswd_raw_cur = pswd_raw_cur == pswd_raw ? pswd_raw_re : pswd_raw) {
		if (pswd_raw_cur == pswd_raw)
			g_print("New password (UTF-8): ");
		else if (pswd_raw_cur == pswd_raw_re)
			g_print("Retype password (UTF-8): ");

		memset(pswd_raw_cur, 0, MAX_NT_PWD_LEN + 1);

		term_toggle_echo(0);
		if (!fgets(pswd_raw_cur, MAX_NT_PWD_LEN + 1, stdin) &&
		    !feof(stdin)) {
			char *fgets_m;

			fgets_m = g_strdup_printf("%m");
			term_toggle_echo(1);
			g_print("\n");
			pr_err("fgets() returned an error: %s\n",
			       fgets_m ? fgets_m : "Out of memory");
			g_free(fgets_m);
			g_free(pswd_raw);
			g_free(pswd_raw_re);
			pswd_raw_cur = NULL;
			len = 0;
			break;
		}

		clearerr(stdin);

		for (i = 0; i < MAX_NT_PWD_LEN; i++)
			if (pswd_raw_cur[i] == '\n')
				pswd_raw_cur[i] = 0x00;

		if (pswd_raw_cur[MAX_NT_PWD_LEN - 1] != 0x00) {
			int c;

			len = MAX_NT_PWD_LEN;
			while ((c = fgetc(stdin)) != '\n') {
				if (c == EOF)
					break;
				len++;
			}
		} else
			len = strlen(pswd_raw_cur);

		term_toggle_echo(1);
		g_print("\n");
		if (__sanity_check_sz_raw(len))
			pswd_raw_cur = NULL;

		if (pswd_raw_cur == pswd_raw_re) {
			if (!memcmp(pswd_raw, pswd_raw_re, MAX_NT_PWD_LEN + 1)) {
				pswd_raw_cur = pswd_raw;
				g_free(pswd_raw_re);
				break;
			}
			pr_err("Passwords don't match\n");
		}
	}

	*sz = len;
	return pswd_raw_cur;
}

static char *prompt_password(char *pswd_raw_opt, size_t *sz_raw)
{
	if (!pswd_raw_opt)
		return __prompt_password_stdin(sz_raw);

	*sz_raw = strlen(pswd_raw_opt);
	if (__sanity_check_sz_raw(*sz_raw))
		exit(EXIT_FAILURE);
	return pswd_raw_opt;
}

static char *get_utf16le_password(char *pswd_raw_opt, long *len)
{
	size_t sz_raw;
	g_autofree char *pswd_raw = NULL;
	char *pswd_utf16le;
	gsize bytes_read = 0;
	gsize bytes_written = 0;

	pswd_raw = prompt_password(pswd_raw_opt, &sz_raw);
	if (!pswd_raw)
		return NULL;

	pswd_utf16le = ksmbd_gconvert(pswd_raw,
				      sz_raw,
				      KSMBD_CHARSET_UTF16LE,
				      KSMBD_CHARSET_DEFAULT,
				      &bytes_read,
				      &bytes_written);
	if (!pswd_utf16le)
		return NULL;

	*len = bytes_written;
	return pswd_utf16le;
}

static void __sanity_check(char *pswd_hash, char *pswd_b64)
{
	size_t pass_sz;
	g_autofree char *pass = base64_decode(pswd_b64, &pass_sz);

	if (!pass) {
		pr_err("Unable to decode NT hash\n");
		exit(EXIT_FAILURE);
	}

	if (memcmp(pass, pswd_hash, pass_sz)) {
		pr_err("NT hash encoding error\n");
		exit(EXIT_FAILURE);
	}
}

static char *get_base64_password(char *pswd_raw_opt)
{
	struct md4_ctx mctx;
	long len;
	g_autofree char *pswd_utf16le = NULL;
	g_autofree char *pswd_hash = NULL;
	char *pswd_b64;

	pswd_utf16le = get_utf16le_password(pswd_raw_opt, &len);
	if (!pswd_utf16le)
		return NULL;

	pswd_hash = g_try_malloc0(sizeof(mctx.hash) + 1);
	if (!pswd_hash) {
		pr_err("Out of memory\n");
		return NULL;
	}

	md4_init(&mctx);
	md4_update(&mctx, pswd_utf16le, len);
	md4_final(&mctx, pswd_hash);

	pswd_b64 = base64_encode(pswd_hash,
				 MD4_HASH_WORDS * sizeof(unsigned int));

	__sanity_check(pswd_hash, pswd_b64);
	return pswd_b64;
}

static void write_user(struct ksmbd_user *user)
{
	int ret, nr = 0;
	size_t wsz;

	if (test_user_flag(user, KSMBD_USER_FLAG_GUEST_ACCOUNT))
		return;

	wsz = snprintf(wbuf, sizeof(wbuf), "%s:%s\n", user->name,
			user->pass_b64);
	if (wsz > sizeof(wbuf)) {
		pr_err("User entry size is above limit: %zu > %zu\n",
		       wsz, sizeof(wbuf));
		exit(EXIT_FAILURE);
	}

	while (wsz && (ret = write(conf_fd, wbuf + nr, wsz)) != 0) {
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			pr_err("Failed to write user entry: %m\n");
			exit(EXIT_FAILURE);
		}

		nr += ret;
		wsz -= ret;
	}
}

static void write_user_cb(gpointer key, gpointer value, gpointer user_data)
{
	struct ksmbd_user *user = (struct ksmbd_user *)value;
	(void)user_data;

	write_user(user);
}

static void write_remove_user_cb(gpointer key,
				 gpointer value,
				 gpointer user_data)
{
	struct ksmbd_user *user = (struct ksmbd_user *)value;
	char **account = (char **)user_data;

	if (!strcmp(user->name, *account)) {
		pr_info("User `%s' removed\n", user->name);
		return;
	}

	write_user_cb(key, value, user_data);
}

static void lookup_can_del_user(gpointer key,
				gpointer value,
				gpointer user_data)
{
	struct ksmbd_share *share = (struct ksmbd_share *)value;
	char **account = (char **)user_data;
	int ret;

	if (!*account)
		return;

	ret = !share->guest_account || strcmp(share->guest_account, *account);
	if (!ret)
		goto conflict;

	ret = shm_lookup_users_map(share,
				   KSMBD_SHARE_ADMIN_USERS_MAP,
				   *account);
	if (!ret)
		goto conflict;

	ret = shm_lookup_users_map(share,
				   KSMBD_SHARE_WRITE_LIST_MAP,
				   *account);
	if (!ret)
		goto conflict;

	ret = shm_lookup_users_map(share,
				   KSMBD_SHARE_VALID_USERS_MAP,
				   *account);
	if (!ret)
		goto conflict;

	return;
conflict:
	pr_err("Share `%s' requires user `%s' to exist\n",
			share->name, *account);
	*account = NULL;
}

int command_add_user(char *pwddb, char *account, char *password)
{
	struct ksmbd_user *user;
	char *pswd;

	user = usm_lookup_user(account);
	if (user) {
		put_ksmbd_user(user);
		pr_err("User `%s' already exists\n", account);
		return -EEXIST;
	}

	pswd = get_base64_password(password);
	if (!pswd) {
		pr_err("Out of memory\n");
		return -ENOMEM;
	}

	/* pswd is already g_strdup-ed */
	if (usm_add_new_user(account, pswd)) {
		pr_err("Unable to add new user `%s'\n", account);
		return -EINVAL;
	}

	if (__opendb_file(pwddb))
		return -EINVAL;

	pr_info("Adding user `%s'\n", account);
	for_each_ksmbd_user(write_user_cb, NULL);
	close(conf_fd);
	return 0;
}

int command_update_user(char *pwddb, char *account, char *password)
{
	struct ksmbd_user *user;
	g_autofree char *pswd = NULL;

	user = usm_lookup_user(account);
	if (!user) {
		pr_err("User `%s' does not exist\n", account);
		return -EINVAL;
	}

	pswd = get_base64_password(password);
	if (!pswd) {
		pr_err("Out of memory\n");
		put_ksmbd_user(user);
		return -ENOMEM;
	}

	if (usm_update_user_password(user, pswd)) {
		pr_err("Out of memory\n");
		put_ksmbd_user(user);
		return -ENOMEM;
	}

	put_ksmbd_user(user);

	if (__opendb_file(pwddb))
		return -EINVAL;

	pr_info("Updating user `%s'\n", account);
	for_each_ksmbd_user(write_user_cb, NULL);
	close(conf_fd);
	return 0;
}

int command_del_user(char *pwddb, char *account, char *unused)
{
	char *del_account = account;
	(void)unused;

	if (global_conf.guest_account &&
	    !strcmp(global_conf.guest_account, account)) {
		pr_err("User `%s' is the global guest account, "
		       "aborting user deletion\n", account);
		return -EINVAL;
	}

	for_each_ksmbd_share(lookup_can_del_user, &del_account);
	if (!del_account) {
		pr_err("Aborting deletion of user `%s'\n", account);
		return -EINVAL;
	}

	if (__opendb_file(pwddb))
		return -EINVAL;

	for_each_ksmbd_user(write_remove_user_cb, &del_account);
	close(conf_fd);
	return 0;
}
