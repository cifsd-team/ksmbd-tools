/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2020 Samsung Electronics Co., Ltd.
 *
 *   Author(s): Namjae Jeon (linkinjeon@kernel.org)
 */

#ifndef __KSMBD_RPC_SAMR_H__
#define __KSMBD_RPC_SAMR_H__

struct dcerpc_server;

/* A new endpoint serving samr, for one open of the pipe */
struct dcerpc_server *rpc_samr_endpoint(void);

void rpc_samr_init(void);
void rpc_samr_destroy(void);
#endif /* __KSMBD_RPC_SAMR_H__ */
