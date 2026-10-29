// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <errno.h>
#include <string.h>
#include <glib.h>
#include <linux/ksmbd_server.h>

#include <dcerpc/dcerpc.h>
#include <dcerpc/server.h>

#include <rpc.h>
#include <rpc_srvsvc.h>
#include <rpc_wkssvc.h>
#include <rpc_samr.h>
#include <rpc_lsarpc.h>
#include <tools.h>

static GHashTable	*pipes_table;
static GRWLock		pipes_table_lock;

static struct ksmbd_rpc_pipe *rpc_pipe_lookup(unsigned int id)
{
	struct ksmbd_rpc_pipe *pipe;

	g_rw_lock_reader_lock(&pipes_table_lock);
	pipe = g_hash_table_lookup(pipes_table, &id);
	g_rw_lock_reader_unlock(&pipes_table_lock);

	return pipe;
}

static void __rpc_pipe_free(struct ksmbd_rpc_pipe *pipe)
{
	if (pipe->rpc)
		dcerpc_server_pipe_destroy(pipe->rpc);
	if (pipe->srv)
		dcerpc_server_destroy(pipe->srv);
	if (pipe->handles)
		g_hash_table_destroy(pipe->handles);
	g_mutex_clear(&pipe->lock);
	g_free(pipe);
}

static void rpc_pipe_free(struct ksmbd_rpc_pipe *pipe)
{
	if (pipe->id != (unsigned int)-1) {
		g_rw_lock_writer_lock(&pipes_table_lock);
		g_hash_table_remove(pipes_table, &(pipe->id));
		g_rw_lock_writer_unlock(&pipes_table_lock);
	}

	__rpc_pipe_free(pipe);
}

static struct ksmbd_rpc_pipe *rpc_pipe_alloc(void)
{
	struct ksmbd_rpc_pipe *pipe;

	pipe = g_try_malloc0(sizeof(struct ksmbd_rpc_pipe));
	if (!pipe)
		return NULL;

	pipe->id = -1;
	g_mutex_init(&pipe->lock);
	return pipe;
}

static struct ksmbd_rpc_pipe *rpc_pipe_alloc_bind(unsigned int id)
{
	struct ksmbd_rpc_pipe *pipe = rpc_pipe_alloc();
	int ret;

	if (!pipe)
		return NULL;

	pipe->id = id;
	g_rw_lock_writer_lock(&pipes_table_lock);
	ret = g_hash_table_insert(pipes_table, &(pipe->id), pipe);
	g_rw_lock_writer_unlock(&pipes_table_lock);

	if (!ret) {
		pipe->id = (unsigned int)-1;
		rpc_pipe_free(pipe);
		pipe = NULL;
	}
	return pipe;
}

static void __clear_pipes_table(void)
{
	struct ksmbd_rpc_pipe *pipe;
	GHashTableIter iter;

	g_rw_lock_writer_lock(&pipes_table_lock);
	ghash_for_each_remove(pipe, pipes_table, iter)
		__rpc_pipe_free(pipe);
	g_rw_lock_writer_unlock(&pipes_table_lock);
}

void rpc_init(void)
{
	if (!pipes_table)
		pipes_table = g_hash_table_new(g_int_hash, g_int_equal);

	rpc_samr_init();
	rpc_lsarpc_init();
}

void rpc_destroy(void)
{
	rpc_lsarpc_destroy();
	rpc_samr_destroy();

	if (pipes_table) {
		__clear_pipes_table();
		g_hash_table_destroy(pipes_table);
		pipes_table = NULL;
	}
}

/*
 * Services on libdcerpc's server runtime (<dcerpc/server.h>), by the
 * kernel's method flag. The runtime does BIND, fragments and every NDR
 * flavor; the service's stubs fill in the replies. Each open of a pipe
 * gets its own endpoint, so pipes on different worker threads share
 * nothing.
 */
static const struct {
	unsigned int		method;
	struct dcerpc_server	*(*endpoint)(void);
} libdcerpc_services[] = {
	{ KSMBD_RPC_SRVSVC_METHOD_INVOKE, rpc_srvsvc_endpoint },
	{ KSMBD_RPC_WKSSVC_METHOD_INVOKE, rpc_wkssvc_endpoint },
	{ KSMBD_RPC_LSARPC_METHOD_INVOKE, rpc_lsarpc_endpoint },
	{ KSMBD_RPC_SAMR_METHOD_INVOKE, rpc_samr_endpoint },
};

char *rpc_pdu_strdup(struct dcerpc_pdu *pdu, const char *s)
{
	size_t len;
	char *d;

	if (!s)
		return NULL;
	len = strlen(s) + 1;
	d = dcerpc_alloc_data(pdu, len);
	if (d)
		memcpy(d, s, len);
	return d;
}

struct ksmbd_rpc_pipe *rpc_pipe_of_pdu(struct dcerpc_pdu *pdu)
{
	struct dcerpc_server_call *call = dcerpc_pdu_server_call(pdu);
	struct dcerpc_server_pipe *rpc;

	rpc = call ? dcerpc_server_call_get_pipe(call) : NULL;
	return rpc ? dcerpc_server_pipe_get_private(rpc) : NULL;
}

int rpc_pipe_restricted(struct ksmbd_rpc_pipe *pipe)
{
	if (global_conf.restrict_anon == 0)
		return 0;

	return !pipe || pipe->req_flags & KSMBD_RPC_RESTRICTED_CONTEXT;
}

/*
 * The current kernel IPC supplies no authenticated caller token. RPC
 * objects therefore grant only their public ACL, independent of caller
 * identity. Never infer an administrator or retain generic or
 * MAXIMUM_ALLOWED bits in a handle.
 */
int rpc_grant_access(unsigned int desired, unsigned int public_access,
		     const struct rpc_generic_mapping *mapping,
		     unsigned int *granted)
{
	unsigned int concrete = desired & ~0xf2000000U;

	*granted = 0;
	if (desired & 0x80000000U)
		concrete |= mapping->read;
	if (desired & 0x40000000U)
		concrete |= mapping->write;
	if (desired & 0x20000000U)
		concrete |= mapping->execute;
	if (desired & 0x10000000U)
		concrete |= mapping->all;
	if (concrete & ~public_access)
		return KSMBD_RPC_EACCESS_DENIED;
	*granted = desired & 0x02000000U ? public_access : concrete;
	return KSMBD_RPC_OK;
}

struct rpc_handle {
	struct dcerpc_context_handle	handle;
	void				*data;
	GDestroyNotify			free_data;
};

static void rpc_handle_free(struct rpc_handle *h)
{
	if (h->free_data)
		h->free_data(h->data);
	g_free(h);
}

int rpc_pipe_handle_open(struct ksmbd_rpc_pipe *pipe, void *data,
			 GDestroyNotify free_data,
			 struct dcerpc_context_handle *handle)
{
	struct rpc_handle *h;
	int i;

	if (!pipe->handles)
		pipe->handles = g_hash_table_new_full(NULL, NULL, NULL,
				(GDestroyNotify)rpc_handle_free);
	h = g_try_malloc0(sizeof(*h));
	if (!h)
		return -1;

	/* The id, and random bytes so that a handle can't be guessed */
	h->handle.context_handle_uuid.v1 = ++pipe->next_handle;
	h->handle.context_handle_uuid.v2 = g_random_int();
	h->handle.context_handle_uuid.v3 = g_random_int();
	for (i = 0; i < 8; i++)
		h->handle.context_handle_uuid.v4[i] = g_random_int();
	h->data = data;
	h->free_data = free_data;
	g_hash_table_insert(pipe->handles,
			    GUINT_TO_POINTER(h->handle.context_handle_uuid.v1),
			    h);
	*handle = h->handle;
	return 0;
}

static struct rpc_handle *
rpc_handle_find(struct ksmbd_rpc_pipe *pipe,
		const struct dcerpc_context_handle *handle)
{
	struct rpc_handle *h;

	if (!pipe || !pipe->handles)
		return NULL;
	h = g_hash_table_lookup(pipe->handles,
			GUINT_TO_POINTER(handle->context_handle_uuid.v1));
	if (!h || memcmp(&h->handle.context_handle_uuid,
			 &handle->context_handle_uuid,
			 sizeof(handle->context_handle_uuid)))
		return NULL;
	return h;
}

int rpc_pipe_handle_lookup(struct ksmbd_rpc_pipe *pipe,
			   const struct dcerpc_context_handle *handle,
			   void **data)
{
	struct rpc_handle *h = rpc_handle_find(pipe, handle);

	if (!h)
		return -1;
	if (data)
		*data = h->data;
	return 0;
}

int rpc_pipe_handle_close(struct ksmbd_rpc_pipe *pipe,
			  const struct dcerpc_context_handle *handle)
{
	struct rpc_handle *h = rpc_handle_find(pipe, handle);

	if (!h)
		return -1;
	g_hash_table_remove(pipe->handles,
			    GUINT_TO_POINTER(handle->context_handle_uuid.v1));
	return 0;
}

/* libdcerpc's messages about a pipe, at mountd's log levels */
static void libdcerpc_log(void *private_data, int level, const char *msg)
{
	struct ksmbd_rpc_pipe *pipe = private_data;

	if (level == DCERPC_SERVER_LOG_ERROR)
		pr_err("RPC: pipe %u: %s\n", pipe->id, msg);
	else if (level == DCERPC_SERVER_LOG_INFO)
		pr_info("RPC: pipe %u: %s\n", pipe->id, msg);
	else
		pr_debug("RPC: pipe %u: %s\n", pipe->id, msg);
}

/* 1 if flags name a service and the pipe is now its, else 0 */
static int libdcerpc_pipe_open(struct ksmbd_rpc_pipe *pipe,
			       unsigned int flags)
{
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(libdcerpc_services); i++) {
		if (flags & libdcerpc_services[i].method)
			break;
	}
	if (i == G_N_ELEMENTS(libdcerpc_services))
		return 0;

	pipe->srv = libdcerpc_services[i].endpoint();
	if (!pipe->srv ||
	    dcerpc_server_set_max_xmit_frag(pipe->srv,
					    KSMBD_RPC_MAX_FRAGMENT_SIZE))
		return -ENOMEM;
	/* the hex dumps and YAML of debug only with -v */
	dcerpc_server_set_log(pipe->srv,
			      log_level >= PR_DEBUG ? DCERPC_SERVER_LOG_DEBUG :
			      log_level >= PR_INFO ? DCERPC_SERVER_LOG_INFO :
			      DCERPC_SERVER_LOG_ERROR,
			      libdcerpc_log, pipe);
	pipe->rpc = dcerpc_server_pipe_create(pipe->srv, pipe);
	if (!pipe->rpc)
		return -ENOMEM;
	return 1;
}

/* What the client wrote: every complete request is handled before return */
static int libdcerpc_pipe_write(struct ksmbd_rpc_pipe *pipe,
				struct ksmbd_rpc_command *req)
{
	int ret = KSMBD_RPC_OK;

	g_mutex_lock(&pipe->lock);
	pipe->req_flags = req->flags;
	if (dcerpc_server_pipe_write(pipe->rpc, req->payload,
				     req->payload_sz)) {
		pr_err("RPC: pipe %u: not DCE/RPC\n", pipe->id);
		ret = KSMBD_RPC_EBAD_DATA;
	}
	g_mutex_unlock(&pipe->lock);
	return ret;
}

/*
 * The next fragment for the client, into the max_resp_sz bytes of
 * resp->payload; an error if there is none, as a read of a pipe with
 * nothing to read is.
 */
static int libdcerpc_pipe_read(struct ksmbd_rpc_pipe *pipe,
			       struct ksmbd_rpc_command *resp,
			       int max_resp_sz)
{
	size_t max = max_resp_sz > 0 ? max_resp_sz : 0;
	int more;

	g_mutex_lock(&pipe->lock);
	resp->payload_sz = dcerpc_server_pipe_read(pipe->rpc, resp->payload,
						   max, &more);
	g_mutex_unlock(&pipe->lock);
	if (more)
		pr_err("RPC: pipe %u: fragment larger than %zu\n",
		       pipe->id, max);
	if (!resp->payload_sz) {
		pr_debug("RPC: pipe %u: nothing to read\n", pipe->id);
		return KSMBD_RPC_EBAD_DATA;
	}
	return KSMBD_RPC_OK;
}

int rpc_ioctl_request(struct ksmbd_rpc_command *req,
		      struct ksmbd_rpc_command *resp,
		      int max_resp_sz)
{
	struct ksmbd_rpc_pipe *pipe = rpc_pipe_lookup(req->handle);
	int ret;

	if (!pipe)
		return KSMBD_RPC_EBAD_FID;
	ret = libdcerpc_pipe_write(pipe, req);
	if (ret == KSMBD_RPC_OK)
		ret = libdcerpc_pipe_read(pipe, resp, max_resp_sz);
	return ret;
}

int rpc_read_request(struct ksmbd_rpc_command *req,
		     struct ksmbd_rpc_command *resp,
		     int max_resp_sz)
{
	struct ksmbd_rpc_pipe *pipe = rpc_pipe_lookup(req->handle);

	if (!pipe) {
		pr_err("RPC: unknown pipe ID: %d\n", req->handle);
		return KSMBD_RPC_EBAD_FID;
	}
	return libdcerpc_pipe_read(pipe, resp, max_resp_sz);
}

int rpc_write_request(struct ksmbd_rpc_command *req,
		      struct ksmbd_rpc_command *resp)
{
	struct ksmbd_rpc_pipe *pipe = rpc_pipe_lookup(req->handle);

	if (!pipe) {
		pr_err("RPC: unknown pipe ID: %d\n", req->handle);
		return KSMBD_RPC_EBAD_FID;
	}
	return libdcerpc_pipe_write(pipe, req);
}

int rpc_open_request(struct ksmbd_rpc_command *req,
		     struct ksmbd_rpc_command *resp)
{
	struct ksmbd_rpc_pipe *pipe;
	int ret;

	pipe = rpc_pipe_lookup(req->handle);
	if (pipe) {
		pr_err("RPC: pipe ID collision: %d\n", req->handle);
		return -EEXIST;
	}

	pipe = rpc_pipe_alloc_bind(req->handle);
	if (!pipe)
		return -ENOMEM;

	ret = libdcerpc_pipe_open(pipe, req->flags);
	if (ret <= 0) {
		if (!ret)
			pr_err("RPC: no service for pipe flags 0x%x\n",
			       req->flags);
		rpc_pipe_free(pipe);
		return ret ? KSMBD_RPC_ENOMEM : KSMBD_RPC_ENOTIMPLEMENTED;
	}
	return KSMBD_RPC_OK;
}

int rpc_close_request(struct ksmbd_rpc_command *req,
		      struct ksmbd_rpc_command *resp)
{
	struct ksmbd_rpc_pipe *pipe;

	pipe = rpc_pipe_lookup(req->handle);
	if (pipe) {
		rpc_pipe_free(pipe);
		return 0;
	}

	pr_err("RPC: unknown pipe ID: %d\n", req->handle);
	return KSMBD_RPC_OK;
}
