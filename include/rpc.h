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

/*
 * The kernel answers FSCTL_PIPE_TRANSCEIVE with at most this much of a
 * reply, so no fragment may be larger. A READ takes the whole reply.
 */
#define KSMBD_RPC_MAX_FRAGMENT_SIZE	4096
/* libdcerpc's limit on a reassembled request */
#define KSMBD_RPC_MAX_REQUEST_SIZE	(4 * 1024 * 1024)

/*
 * Wire status values used by SAMR and LSAD (the IPC status values in
 * linux/ksmbd_server.h are intentionally kept separate from these
 * protocol return codes).
 */
#define KSMBD_NT_STATUS_SUCCESS			0x00000000U
#define KSMBD_NT_STATUS_MORE_ENTRIES		0x00000105U
#define KSMBD_NT_STATUS_SOME_NOT_MAPPED		0x00000107U
#define KSMBD_NT_STATUS_NOT_IMPLEMENTED		0xC0000002U
#define KSMBD_NT_STATUS_INVALID_INFO_CLASS	0xC0000003U
#define KSMBD_NT_STATUS_INVALID_HANDLE		0xC0000008U
#define KSMBD_NT_STATUS_INVALID_PARAMETER	0xC000000DU
#define KSMBD_NT_STATUS_ACCESS_DENIED		0xC0000022U
#define KSMBD_NT_STATUS_BUFFER_TOO_SMALL	0xC0000023U
#define KSMBD_NT_STATUS_NO_SUCH_USER		0xC0000064U
#define KSMBD_NT_STATUS_NO_SUCH_GROUP		0xC0000066U
#define KSMBD_NT_STATUS_NONE_MAPPED		0xC0000073U
#define KSMBD_NT_STATUS_INSUFFICIENT_RESOURCES	0xC000009AU
#define KSMBD_NT_STATUS_NO_SUCH_DOMAIN		0xC00000DFU
#define KSMBD_NT_STATUS_NO_SUCH_ALIAS		0xC0000151U

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

/*
 * The access an RPC object grants a handle opened with desired access:
 * the generic rights mapped to the object's concrete ones, and all of
 * them within public_access, the object's public ACL. MAXIMUM_ALLOWED
 * gets public_access.
 */
struct rpc_generic_mapping {
	unsigned int read, write, execute, all;
};

int rpc_grant_access(unsigned int desired, unsigned int public_access,
		     const struct rpc_generic_mapping *mapping,
		     unsigned int *granted);

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
