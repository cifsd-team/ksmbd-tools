/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#ifndef __MANAGEMENT_USER_H__
#define __MANAGEMENT_USER_H__

#include <sys/types.h>
#include <pwd.h>
#include <glib.h>

#include "linux/ksmbd_server.h"

struct ksmbd_user {
	char		*name;
	char		*pass_b64;

	char		*pass;
	int		pass_sz;

	uid_t		uid;
	gid_t		gid;

	int		ref_count;
	int		flags;
	int		state;
	GRWLock		update_lock;
	unsigned int	failed_login_count;
};

static inline void set_user_flag(struct ksmbd_user *user, int flag)
{
	if (flag == KSMBD_USER_FLAG_INVALID)
		user->flags = flag;
	else
		user->flags |= flag;
}

static inline int test_user_flag(struct ksmbd_user *user, int flag)
{
	if (flag == KSMBD_USER_FLAG_INVALID)
		return user->flags == flag;
	return user->flags & flag;
}

int usm_remove_user(struct ksmbd_user *user);
struct ksmbd_user *get_ksmbd_user(struct ksmbd_user *user);
void put_ksmbd_user(struct ksmbd_user *user);

struct ksmbd_user *usm_lookup_user(char *name);

void usm_update_user_password(struct ksmbd_user *user, char *pass);

int usm_user_name(char *name, char *p);
int usm_add_new_user(char *name, char *pwd);
int usm_add_guest_account(char *name);

void usm_remove_all_users(void);

void usm_destroy(void);
int usm_init(void);

typedef void (*walk_users)(gpointer key,
			   gpointer value,
			   gpointer user_data);
void for_each_ksmbd_user(walk_users cb, gpointer user_data);

struct ksmbd_login_request;
struct ksmbd_login_response;
struct ksmbd_logout_request;

int usm_handle_login_request(struct ksmbd_login_request *req,
			     struct ksmbd_login_response *resp);
int usm_handle_logout_request(struct ksmbd_logout_request *req);

#endif /* __MANAGEMENT_USER_H__ */
