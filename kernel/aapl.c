// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   SMB2 Apple AAPL create context — Time Machine support for KSMBD
 *
 *   Wire format source: "Time Machine Over SMB Spec"
 *   https://developer.apple.com/library/archive/releasenotes/
 *   NetworkingInternetWeb/Time_Machine_SMB_Spec/
 *
 *   Implemented independently for KSMBD; no Samba code used.
 *
 *   Place this file at: fs/smb/server/aapl.c
 *   Add to fs/smb/server/Makefile: ksmbd-y += aapl.o
 *
 *
 *   INTEGRATION SUMMARY
 *   ===================
 *
 *   1. AAPL create context (this file):
 *      In smb2_create() in smb2pdu.c, after durable/lease context handling:
 *
 *        #include "aapl.h"
 *        ...
 *        err = smb2_aapl_create_ctx(work, req, rsp);
 *        if (err)
 *            pr_debug("ksmbd: AAPL context: %d\n", err);
 *
 *   2. F_FULLFSYNC (SMB2 FLUSH extension):
 *      In smb2_flush() in smb2pdu.c, before calling vfs_fsync():
 *
 *        #include "aapl.h"
 *        ...
 *        struct smb2_flush_req *req = smb2_get_msg(work->request_buf);
 *        bool full_sync = (le16_to_cpu(req->Reserved1) == SMB2_FLUSH_FULL_SYNC_MAGIC);
 *        // pass full_sync to ksmbd_vfs_fsync(); if true, call vfs_fsync(fp, 1)
 *        // (the '1' argument triggers F_FULLFSYNC / SYNC_FILE_RANGE_WAIT_BEFORE)
 *
 *   3. Durable handles:
 *      Set 'durable handles = yes' in ksmbd.conf [global] — Time Machine
 *      requires SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2 with timeout negotiation.
 *
 *   4. Bonjour advertisement (outside kernel scope):
 *      Register _adisk._tcp via avahi-daemon with TXT record:
 *        dk0=adVN=<share_name>,adVF=0x82
 *      This is how macOS discovers Time Machine targets over the network.
 */

#include <linux/slab.h>
#include <linux/string.h>

#include "aapl.h"
#include "smb2pdu.h"		/* struct smb2_create_req/rsp, create_context */
#include "smb_common.h"		/* test_share_config_flag */
#include "connection.h"		/* struct ksmbd_work */
#include "mgmt/share_config.h"	/* KSMBD_SHARE_FLAG_* */

/*
 * Layout of the AAPL create context wrapper around a payload:
 *
 *   struct create_context header  : 16 bytes  (Next/Name*/Data*/DataLength)
 *   name "AAPL"                   :  4 bytes
 *   padding to 8-byte align       :  4 bytes
 *   data starts at offset         : 24 bytes
 *
 * Total = ALIGN(24 + payload_len, 8).
 */
#define AAPL_CTX_NAME_OFF	16	/* == sizeof(struct create_context) */
#define AAPL_CTX_DATA_OFF	24	/* == ALIGN(16 + 4, 8) */

static inline u32 aapl_ctx_total(u32 payload_len)
{
	return ALIGN(AAPL_CTX_DATA_OFF + payload_len, 8);
}

/*
 * Walk the create context chain in the response and return a pointer to
 * the last entry (whose ->Next is 0).  Returns NULL when no contexts exist.
 */
static struct create_context *aapl_last_rsp_ctx(struct smb2_create_rsp *rsp)
{
	struct create_context *cc;
	u32 next;

	if (!le32_to_cpu(rsp->CreateContextsLength))
		return NULL;

	cc = (struct create_context *)
		((u8 *)rsp + le32_to_cpu(rsp->CreateContextsOffset));

	while ((next = le32_to_cpu(cc->Next)) != 0)
		cc = (struct create_context *)((u8 *)cc + next);

	return cc;
}

/*
 * Append an AAPL create context to the CREATE response.
 * The caller must have verified the response buffer has room for
 * aapl_ctx_total(payload_len) additional bytes.
 */
static int aapl_append_rsp_ctx(struct ksmbd_work *work,
				struct smb2_create_rsp *rsp,
				const void *payload, u32 payload_len)
{
	struct create_context *prev, *cc;
	u32 ctx_len = aapl_ctx_total(payload_len);
	u8 *dst;

	if (le32_to_cpu(rsp->CreateContextsLength)) {
		dst = (u8 *)rsp + le32_to_cpu(rsp->CreateContextsOffset)
		      + le32_to_cpu(rsp->CreateContextsLength);
	} else {
		/*
		 * First context in this response: anchor CreateContextsOffset
		 * to the byte immediately following the fixed CREATE response
		 * header (rsp->Buffer[0]).
		 */
		rsp->CreateContextsOffset = cpu_to_le32(
			(u32)((u8 *)rsp->Buffer - (u8 *)rsp));
		dst = rsp->Buffer;
	}

	/* Link the previous last context forward to this one */
	prev = aapl_last_rsp_ctx(rsp);
	if (prev) {
		u32 prev_off = (u32)((u8 *)prev -
				     ((u8 *)rsp + le32_to_cpu(rsp->CreateContextsOffset)));
		prev->Next = cpu_to_le32(
			le32_to_cpu(rsp->CreateContextsLength) - prev_off);
	}

	/* Build the create context header */
	cc = (struct create_context *)dst;
	memset(cc, 0, ctx_len);
	cc->Next	= 0;	/* last in chain */
	cc->NameOffset	= cpu_to_le16(AAPL_CTX_NAME_OFF);
	cc->NameLength	= cpu_to_le16(SMB2_CREATE_AAPL_LEN);
	cc->DataOffset	= cpu_to_le16(AAPL_CTX_DATA_OFF);
	cc->DataLength	= cpu_to_le32(payload_len);
	memcpy(dst + AAPL_CTX_NAME_OFF, SMB2_CREATE_AAPL, SMB2_CREATE_AAPL_LEN);
	memcpy(dst + AAPL_CTX_DATA_OFF, payload, payload_len);

	le32_add_cpu(&rsp->CreateContextsLength, ctx_len);
	inc_rfc1001_len(work->response_buf, ctx_len);
	return 0;
}

/*
 * Handle kAAPL_SERVER_QUERY.
 *
 * Per spec:
 *   - ServerCapabilities: "Reserved for future use; respond with 0x0"
 *   - VolumeCapabilities: kAAPL_SUPPORTS_FULL_SYNC (0x04) when supported
 *   - Model string: server does not include it (ReplyBitmap omits bit 2)
 *
 * The F_FULLFSYNC bit tells macOS it can rely on SMB2 FLUSH with
 * Reserved1=0xFFFF to ensure backup data reaches stable storage — this
 * is the consistency guarantee Time Machine requires.
 */
static int aapl_handle_server_query(struct ksmbd_work *work,
				     const struct aapl_server_query_req *req,
				     struct smb2_create_rsp *rsp)
{
	u64 req_bitmap = le64_to_cpu(req->req_bitmap);
	u64 reply_bitmap = 0, vol_caps = 0;
	struct aapl_server_query_rsp arsp = {};

	if (req_bitmap & AAPL_BITMAP_SERVER_CAPS)
		reply_bitmap |= AAPL_BITMAP_SERVER_CAPS;
	/* server_caps stays 0 — reserved per spec */

	if (req_bitmap & AAPL_BITMAP_VOL_CAPS) {
		reply_bitmap |= AAPL_BITMAP_VOL_CAPS;
		vol_caps = AAPL_VOLCAPS_FULL_SYNC;
	}

	/* kAAPL_MODEL_INFO: server never sets this bit in ReplyBitmap */

	arsp.cmd		= cpu_to_le32(AAPL_SERVER_QUERY);
	arsp.reserved		= 0;
	arsp.reply_bitmap	= cpu_to_le64(reply_bitmap);
	arsp.server_caps	= cpu_to_le64(AAPL_SERVER_CAPS_RESERVED);
	arsp.vol_caps		= cpu_to_le64(vol_caps);

	return aapl_append_rsp_ctx(work, rsp, &arsp, sizeof(arsp));
}

/**
 * smb2_aapl_create_ctx - process the AAPL create context from a CREATE request
 * @work: the current KSMBD work item
 * @req:  the SMB2 CREATE request
 * @rsp:  the SMB2 CREATE response being built
 *
 * Called from smb2_create() after the file has been opened and before the
 * response is sent.  Does nothing if the share does not have TIME_MACHINE
 * set, or if the client did not include an AAPL context.
 */
int smb2_aapl_create_ctx(struct ksmbd_work *work,
			  struct smb2_create_req *req,
			  struct smb2_create_rsp *rsp)
{
	struct create_context *cc;
	const struct aapl_server_query_req *aapl_req;

	if (!test_share_config_flag(work->tcon->share_conf,
				    KSMBD_SHARE_FLAG_TIME_MACHINE))
		return 0;

	cc = smb2_find_context_vals(req, SMB2_CREATE_AAPL, SMB2_CREATE_AAPL_LEN);
	if (IS_ERR_OR_NULL(cc))
		return 0;

	if (le32_to_cpu(cc->DataLength) < sizeof(struct aapl_server_query_req))
		return -EINVAL;

	aapl_req = (const struct aapl_server_query_req *)
			((u8 *)cc + le16_to_cpu(cc->DataOffset));

	switch (le32_to_cpu(aapl_req->cmd)) {
	case AAPL_SERVER_QUERY:
		return aapl_handle_server_query(work, aapl_req, rsp);
	default:
		return 0;
	}
}
