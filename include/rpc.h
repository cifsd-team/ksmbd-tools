/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#ifndef __KSMBD_RPC_H__
#define __KSMBD_RPC_H__

#include <glib.h>

/*
 * The named pipes the kernel passes on to mountd. Their DCE/RPC (BIND,
 * fragments, NDR, dispatch to the stubs) is libdcerpc's server runtime;
 * rpc_srvsvc.c, rpc_wkssvc.c, rpc_lsarpc.c and rpc_samr.c hold the stubs.
 */

struct ksmbd_rpc_command;
struct dcerpc_server;
struct dcerpc_server_pipe;
struct dcerpc_pdu;
struct dcerpc_context_handle;

struct ksmbd_rpc_pipe {
	unsigned int			id;

	/*
	 * This open's libdcerpc endpoint and DCE/RPC pipe, and the flags
	 * of the request being handled.
	 */
	struct dcerpc_server		*srv;
	struct dcerpc_server_pipe	*rpc;
	unsigned int			req_flags;
	GMutex				lock;
	/* the context handles its stubs gave out, by id */
	GHashTable			*handles;
	unsigned int			next_handle;
};

/* A copy of s for a libdcerpc reply, freed with the pdu; NULL stays NULL */
char *rpc_pdu_strdup(struct dcerpc_pdu *pdu, const char *s);

/* For libdcerpc stubs: the pipe the call came on, and its restriction */
struct ksmbd_rpc_pipe *rpc_pipe_of_pdu(struct dcerpc_pdu *pdu);
int rpc_pipe_restricted(struct ksmbd_rpc_pipe *pipe);

/*
 * Context handles for libdcerpc stubs, valid on the pipe that gave them
 * out. A handle carries data, freed with free_data (if not NULL) when
 * the handle is closed or the pipe goes away. All return 0, or -1: out
 * of memory for open, not an open handle for lookup and close.
 */
int rpc_pipe_handle_open(struct ksmbd_rpc_pipe *pipe, void *data,
			 GDestroyNotify free_data,
			 struct dcerpc_context_handle *handle);
int rpc_pipe_handle_lookup(struct ksmbd_rpc_pipe *pipe,
			   const struct dcerpc_context_handle *handle,
			   void **data);
int rpc_pipe_handle_close(struct ksmbd_rpc_pipe *pipe,
			  const struct dcerpc_context_handle *handle);

void rpc_init(void);
void rpc_destroy(void);

int rpc_ioctl_request(struct ksmbd_rpc_command *req,
		      struct ksmbd_rpc_command *resp,
		      int max_resp_sz);
int rpc_read_request(struct ksmbd_rpc_command *req,
		     struct ksmbd_rpc_command *resp,
		     int max_resp_sz);
int rpc_write_request(struct ksmbd_rpc_command *req,
		      struct ksmbd_rpc_command *resp);
int rpc_open_request(struct ksmbd_rpc_command *req,
		     struct ksmbd_rpc_command *resp);
int rpc_close_request(struct ksmbd_rpc_command *req,
		      struct ksmbd_rpc_command *resp);
#endif /* __KSMBD_RPC_H__ */
