/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#ifndef __KSMBD_RPC_WKSSVC_H__
#define __KSMBD_RPC_WKSSVC_H__

struct dcerpc_server;

/* A new endpoint serving wkssvc, for one open of the pipe */
struct dcerpc_server *rpc_wkssvc_endpoint(void);

#endif /* __KSMBD_RPC_WKSSVC_H__ */
