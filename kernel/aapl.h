/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   SMB2 Apple AAPL create context — Time Machine support for KSMBD
 *
 *   Wire format source: "Time Machine Over SMB Spec"
 *   https://developer.apple.com/library/archive/releasenotes/
 *   NetworkingInternetWeb/Time_Machine_SMB_Spec/
 *
 *   Implemented independently for KSMBD; no Samba code used.
 *
 *   Place this file at: fs/smb/server/aapl.h
 */

#ifndef __KSMBD_AAPL_H__
#define __KSMBD_AAPL_H__

#include <linux/types.h>

/* Create context name — 4 bytes, no NUL terminator on the wire */
#define SMB2_CREATE_AAPL		"AAPL"
#define SMB2_CREATE_AAPL_LEN		4

/* Sub-commands (CommandCode field) */
#define AAPL_SERVER_QUERY		1

/*
 * Request bitmap: which fields the client wants in the server response.
 * Re-used as reply bitmap: which fields the server is providing.
 *
 * kAAPL_MODEL_INFO is intentionally omitted from the reply: the spec
 * example shows ReplyBitmap = 0x03 even when the client requests 0x07.
 */
#define AAPL_BITMAP_SERVER_CAPS		0x01ULL
#define AAPL_BITMAP_VOL_CAPS		0x02ULL
#define AAPL_BITMAP_MODEL_INFO		0x04ULL	/* client-only; server ignores */

/*
 * Server capability flags (ServerCapabilities in the response).
 * Per spec: "Reserved for future use; respond with 0x0 if requested."
 */
#define AAPL_SERVER_CAPS_RESERVED	0x0ULL

/*
 * Volume capability flags (VolumeCapabilities in the response).
 * kAAPL_SUPPORTS_FULL_SYNC: server handles SMB2 FLUSH with Reserved1=0xFFFF
 * by calling F_FULLFSYNC, flushing data to stable storage.  This is required
 * for Time Machine backup consistency.
 */
#define AAPL_VOLCAPS_FULL_SYNC		0x04ULL

/*
 * F_FULLFSYNC extension to SMB2 FLUSH.
 * When a client sets Reserved1 to this value in an SMB2 FLUSH request,
 * the server must flush to stable storage (not just the page cache).
 * Advertised via kAAPL_SUPPORTS_FULL_SYNC in the AAPL volume capabilities.
 */
#define SMB2_FLUSH_FULL_SYNC_MAGIC	0xFFFF

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
 * AAPL SERVER_QUERY response payload.
 * server_caps and vol_caps are present only when the corresponding
 * AAPL_BITMAP_* bit is set in reply_bitmap.  model string is never sent.
 * Total wire size: 32 bytes (fixed; no trailing model string).
 */
struct aapl_server_query_rsp {
	__le32	cmd;		/* AAPL_SERVER_QUERY */
	__le32	reserved;	/* 0 */
	__le64	reply_bitmap;	/* AAPL_BITMAP_SERVER_CAPS | AAPL_BITMAP_VOL_CAPS */
	__le64	server_caps;	/* always AAPL_SERVER_CAPS_RESERVED (0x0) */
	__le64	vol_caps;	/* AAPL_VOLCAPS_FULL_SYNC when supported */
} __packed;

struct ksmbd_work;
struct smb2_create_req;
struct smb2_create_rsp;

int smb2_aapl_create_ctx(struct ksmbd_work *work,
			  struct smb2_create_req *req,
			  struct smb2_create_rsp *rsp);

#endif /* __KSMBD_AAPL_H__ */
