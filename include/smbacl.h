/* SPDX-License-Identifier: LGPL-2.1+ */
/*
 *   Copyright (c) International Business Machines  Corp., 2007
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *   Copyright (C) 2020 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon (linkinjeon@kernel.org)
 */

#ifndef __KSMBD_SMBACL_H__
#define __KSMBD_SMBACL_H__

#include <linux/types.h>
#include <glib.h>

#define NUM_AUTHS (6)	/* number of authority fields */
#define SID_MAX_SUB_AUTHORITIES (15) /* max number of sub authority fields */

#define SID_TYPE_USER		1
#define SID_TYPE_GROUP		2
#define SID_TYPE_UNKNOWN	8

struct smb_sid {
	__u8 revision; /* revision level */
	__u8 num_subauth;
	__u8 authority[NUM_AUTHS];
	__u32 sub_auth[SID_MAX_SUB_AUTHORITIES]; /* sub_auth[num_subauth] */
};

void smb_init_domain_sid(struct smb_sid *sid);
void smb_copy_sid(struct smb_sid *dst, const struct smb_sid *src);
int smb_compare_sids(const struct smb_sid *ctsid, const struct smb_sid *cwsid);
int set_domain_name(struct smb_sid *sid, char *domain, size_t domain_len, int *type);

/* Conversion to and from libdcerpc's RPC_SID; the RPC_SID is the pdu's */
struct dcerpc_pdu;
struct RPC_SID;
struct RPC_SID *smb_sid_to_rpc(struct dcerpc_pdu *pdu,
			       const struct smb_sid *sid);
void smb_sid_from_rpc(struct smb_sid *sid, const struct RPC_SID *rsid);
#endif /* __KSMBD_SMBACL_H__ */
