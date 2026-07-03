/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Minimal MDSSVC (Apple Spotlight) RPC stub for Time Machine support.
 *   Enough to pass macOS's Spotlight availability check so TM proceeds.
 */
#ifndef __KSMBD_RPC_MDSSVC_H__
#define __KSMBD_RPC_MDSSVC_H__

struct ksmbd_rpc_command;
struct ksmbd_rpc_pipe;

int rpc_mdssvc_read_request(struct ksmbd_rpc_pipe *pipe,
			    struct ksmbd_rpc_command *resp,
			    int max_resp_sz);

int rpc_mdssvc_write_request(struct ksmbd_rpc_pipe *pipe);

#endif /* __KSMBD_RPC_MDSSVC_H__ */
