/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2020 Samsung Electronics Co., Ltd.
 *
 *   Author(s): Namjae Jeon (linkinjeon@kernel.org)
 */

#ifndef __KSMBD_RPC_LSARPC_H__
#define __KSMBD_RPC_LSARPC_H__

#include <smbacl.h>

#define HANDLE_SIZE	KSMBD_RPC_HANDLE_SIZE
#define DOMAIN_STR_SIZE	257

struct ksmbd_rpc_command;
struct ksmbd_rpc_pipe;

enum lsarpc_handle_type {
	LSARPC_HANDLE_POLICY,
};

struct policy_handle {
	unsigned char handle[HANDLE_SIZE];
	unsigned int pipe_id;
	unsigned int refcount;
	enum lsarpc_handle_type type;
	unsigned int access_mask;
	int retired;
	struct ksmbd_user *user;
};

struct lsarpc_names_info {
	int index;
	int type;
	char domain_str[DOMAIN_STR_SIZE];
	struct smb_sid sid;
	struct smb_sid domain_sid;
	struct ksmbd_user *user;
	char *resolved_name;
	int mapped;
};

int rpc_lsarpc_read_request(struct ksmbd_rpc_pipe *pipe,
			  struct ksmbd_rpc_command *resp,
			  int max_resp_sz);

int rpc_lsarpc_write_request(struct ksmbd_rpc_pipe *pipe);
void rpc_lsarpc_init(void);
void rpc_lsarpc_destroy(void);
void rpc_lsarpc_pipe_close(unsigned int pipe_id);

#endif /* __KSMBD_RPC_LSARPC_H__ */
