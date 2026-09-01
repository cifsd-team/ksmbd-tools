/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2020 Samsung Electronics Co., Ltd.
 *
 *   Author(s): Namjae Jeon (linkinjeon@kernel.org)
 */

#ifndef __KSMBD_RPC_SAMR_H__
#define __KSMBD_RPC_SAMR_H__

#include <smbacl.h>

#define HANDLE_SIZE	KSMBD_RPC_HANDLE_SIZE

struct ksmbd_rpc_command;
struct ksmbd_rpc_pipe;

enum samr_handle_type {
	SAMR_HANDLE_SERVER,
	SAMR_HANDLE_DOMAIN,
	SAMR_HANDLE_USER,
	SAMR_HANDLE_GROUP,
	SAMR_HANDLE_ALIAS,
};

struct connect_handle {
	unsigned char handle[HANDLE_SIZE];
	unsigned int pipe_id;
	unsigned int refcount;
	enum samr_handle_type type;
	unsigned int access_mask;
	int retired;
	struct smb_sid domain_sid;
	struct ksmbd_user *user;
	unsigned int rid;
};

int rpc_samr_read_request(struct ksmbd_rpc_pipe *pipe,
			  struct ksmbd_rpc_command *resp,
			  int max_resp_sz);

int rpc_samr_write_request(struct ksmbd_rpc_pipe *pipe);

void rpc_samr_init(void);
void rpc_samr_destroy(void);
void rpc_samr_pipe_close(unsigned int pipe_id);
#endif /* __KSMBD_RPC_SAMR_H__ */
