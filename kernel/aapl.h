/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   SMB2 Apple AAPL create context — Time Machine support for KSMBD
 *
 *   Implements the proprietary Apple SMB2 AAPL extension needed for
 *   macOS Time Machine and Finder metadata interoperability.
 *
 *   Wire format source: Apple SMB2 Extensions specification (public).
 *   Implemented independently for KSMBD; no Samba code used.
 *
 *   Place this file at: fs/smb/server/aapl.h
 */

#ifndef __KSMBD_AAPL_H__
#define __KSMBD_AAPL_H__

#include <linux/types.h>

/* Create context name — 4 bytes, no NUL terminator in the wire format */
#define SMB2_CREATE_AAPL		"AAPL"
#define SMB2_CREATE_AAPL_LEN		4

/* AAPL sub-commands (CommandCode field) */
#define AAPL_SERVER_QUERY		1
#define AAPL_RESOLVE_ID			2

/*
 * Request bitmap: which fields the client wants in the server response.
 * Re-used as reply bitmap: which fields the server is actually providing.
 */
#define AAPL_BITMAP_SERVER_CAPS		0x01ULL
#define AAPL_BITMAP_VOL_CAPS		0x02ULL
#define AAPL_BITMAP_MODEL_INFO		0x04ULL

/*
 * Server capability flags (ServerCaps in the response).
 * AAPL_CAPS_OSX_METADATA is the critical one: it tells macOS the server
 * stores xattrs (FinderInfo, ResourceFork, etc.) as named data streams,
 * which is required for Time Machine metadata integrity.
 */
#define AAPL_CAPS_READDIR_ATTR		0x01ULL
#define AAPL_CAPS_OSX_METADATA		0x02ULL
#define AAPL_CAPS_UNIX_BASED		0x04ULL
#define AAPL_CAPS_NFS_ACE		0x08ULL

/* Volume capability flags (VolCaps in the response) */
#define AAPL_VOLCAPS_RESOLVE_ID		0x01ULL
#define AAPL_VOLCAPS_CASE_SENSITIVE	0x02ULL
#define AAPL_VOLCAPS_FULL_SYNC		0x04ULL

/*
 * AAPL SERVER_QUERY request payload — follows the create context header.
 * Total wire size: 24 bytes.
 */
struct aapl_server_query_req {
	__le32	cmd;		/* AAPL_SERVER_QUERY */
	__le32	reserved;	/* must be 0 */
	__le64	req_bitmap;	/* AAPL_BITMAP_* items client requests */
	__le64	client_caps;	/* client capability flags (informational) */
} __packed;

/*
 * AAPL SERVER_QUERY response payload — fixed header, optional fields follow.
 * server_caps / vol_caps / model string are present only when their
 * corresponding AAPL_BITMAP_* bit is set in reply_bitmap.
 * Total wire size (with all fields + "Linux" model): ~58 bytes.
 */
struct aapl_server_query_rsp {
	__le32	cmd;			/* AAPL_SERVER_QUERY */
	__le32	reserved;		/* 0 */
	__le64	reply_bitmap;		/* which optional fields follow */
	__le64	server_caps;		/* AAPL_CAPS_* flags */
	__le64	vol_caps;		/* AAPL_VOLCAPS_* flags */
	__le32	pad;			/* 0 */
	__le32	model_string_bytes;	/* byte count of UTF-16LE model, 0 if absent */
	/* UTF-16LE model string follows if AAPL_BITMAP_MODEL_INFO in reply_bitmap */
} __packed;

struct ksmbd_work;
struct smb2_create_req;
struct smb2_create_rsp;

int smb2_aapl_create_ctx(struct ksmbd_work *work,
			  struct smb2_create_req *req,
			  struct smb2_create_rsp *rsp);

#endif /* __KSMBD_AAPL_H__ */
