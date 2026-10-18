/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2020 Samsung Electronics Co., Ltd.
 *
 *   Author(s): Namjae Jeon (linkinjeon@kernel.org)
 */

#ifndef __KSMBD_RPC_LSARPC_H__
#define __KSMBD_RPC_LSARPC_H__

#define DOMAIN_STR_SIZE	257

struct dcerpc_server;

/* A new endpoint serving lsarpc and dssetup, for one open of the pipe */
struct dcerpc_server *rpc_lsarpc_endpoint(void);

void rpc_lsarpc_init(void);
void rpc_lsarpc_destroy(void);

#endif /* __KSMBD_RPC_LSARPC_H__ */
