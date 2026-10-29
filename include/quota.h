/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __KSMBD_QUOTA_H__
#define __KSMBD_QUOTA_H__

#include <stddef.h>
#include <linux/ksmbd_server.h>

void quota_handle_request(const struct ksmbd_quota_request *req, size_t size,
			  struct ksmbd_quota_response *resp);

#endif
