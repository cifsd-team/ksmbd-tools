// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   SMB2 Apple AAPL create context — Time Machine support for KSMBD
 *
 *   Wire format source: Apple SMB2 Extensions specification (public).
 *   Implemented independently for KSMBD; no Samba code used.
 *
 *   Place this file at: fs/smb/server/aapl.c
 *   Add to fs/smb/server/Makefile: ksmbd-y += aapl.o
 */

#include <linux/slab.h>
#include <linux/string.h>

#include "aapl.h"
#include "smb2pdu.h"		/* struct smb2_create_req/rsp, create_context */
#include "smb_common.h"		/* test_share_config_flag */
#include "connection.h"		/* struct ksmbd_work */
#include "mgmt/share_config.h"	/* KSMBD_SHARE_FLAG_* */

/*
 * UTF-16LE "Linux" — the model string macOS uses for the Finder icon.
 * "Xserve" triggers an Apple server icon; "Linux" shows a generic NAS.
 * Neither affects Time Machine functionality.
 */
static const __le16 aapl_model[] = {
	cpu_to_le16('L'), cpu_to_le16('i'), cpu_to_le16('n'),
	cpu_to_le16('u'), cpu_to_le16('x'),
};
#define AAPL_MODEL_BYTES	sizeof(aapl_model)

/*
 * Size of the full create context wrapper around an AAPL payload.
 *
 *   struct create_context header  : 16 bytes
 *   name "AAPL" (4 bytes)
 *   padding to 8-byte align       :  4 bytes
 *   ------------------------------------------
 *   data starts at offset          : 24 bytes
 *
 * Total = ALIGN(24 + payload_len, 8).
 */
#define AAPL_CTX_NAME_OFF	16	/* sizeof(struct create_context) */
#define AAPL_CTX_DATA_OFF	24	/* ALIGN(16 + 4, 8) */

static inline u32 aapl_ctx_total(u32 payload_len)
{
	return ALIGN(AAPL_CTX_DATA_OFF + payload_len, 8);
}

/*
 * Walk the create context chain in the response and return a pointer to
 * the last entry (the one whose ->Next is 0).  Returns NULL when there
 * are no response contexts yet.
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
 * Build and append an AAPL server-query response context to the CREATE
 * response.  The caller must have verified that the response buffer has
 * room for aapl_ctx_total(payload_len) additional bytes.
 */
static int aapl_append_rsp_ctx(struct ksmbd_work *work,
				struct smb2_create_rsp *rsp,
				const void *payload, u32 payload_len)
{
	struct create_context *prev, *cc;
	u32 ctx_len = aapl_ctx_total(payload_len);
	u8 *dst;

	/* Destination: immediately after any existing response contexts */
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

	/* Link previous last context to this one */
	prev = aapl_last_rsp_ctx(rsp);
	if (prev) {
		u32 prev_start = (u32)((u8 *)prev -
				 ((u8 *)rsp + le32_to_cpu(rsp->CreateContextsOffset)));
		prev->Next = cpu_to_le32(
			le32_to_cpu(rsp->CreateContextsLength) - prev_start);
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
 * Handle AAPL_SERVER_QUERY: respond with server and volume capabilities.
 *
 * We advertise AAPL_CAPS_OSX_METADATA so macOS stores Apple xattrs
 * (com.apple.FinderInfo, com.apple.ResourceFork, etc.) as SMB2 named
 * data streams — a prerequisite for Time Machine metadata integrity.
 *
 * AAPL_VOLCAPS_FULL_SYNC tells macOS it may rely on fsync for TM
 * backup consistency.
 */
static int aapl_handle_server_query(struct ksmbd_work *work,
				     const struct aapl_server_query_req *req,
				     struct smb2_create_rsp *rsp)
{
	struct ksmbd_share_config *share = work->tcon->share_conf;
	u64 req_bitmap = le64_to_cpu(req->req_bitmap);
	u64 reply_bitmap = 0, server_caps = 0, vol_caps = 0;
	u32 model_bytes = 0;

	/*
	 * Build capability fields only for what the client asked for;
	 * mirror the request bitmap into the reply bitmap for each item
	 * we include.
	 */
	if (req_bitmap & AAPL_BITMAP_SERVER_CAPS) {
		reply_bitmap  |= AAPL_BITMAP_SERVER_CAPS;
		server_caps    = AAPL_CAPS_OSX_METADATA | AAPL_CAPS_UNIX_BASED;
	}

	if (req_bitmap & AAPL_BITMAP_VOL_CAPS) {
		reply_bitmap  |= AAPL_BITMAP_VOL_CAPS;
		vol_caps       = AAPL_VOLCAPS_FULL_SYNC;
		if (share->flags & KSMBD_SHARE_FLAG_TIME_MACHINE)
			vol_caps |= AAPL_VOLCAPS_RESOLVE_ID;
	}

	if (req_bitmap & AAPL_BITMAP_MODEL_INFO) {
		reply_bitmap  |= AAPL_BITMAP_MODEL_INFO;
		model_bytes    = AAPL_MODEL_BYTES;
	}

	/* Build the response payload into a stack buffer — it's small */
	u32 payload_len = sizeof(struct aapl_server_query_rsp) + model_bytes;
	u8 payload[sizeof(struct aapl_server_query_rsp) + AAPL_MODEL_BYTES];
	struct aapl_server_query_rsp *arsp = (struct aapl_server_query_rsp *)payload;

	memset(payload, 0, sizeof(payload));
	arsp->cmd		= cpu_to_le32(AAPL_SERVER_QUERY);
	arsp->reserved		= 0;
	arsp->reply_bitmap	= cpu_to_le64(reply_bitmap);
	arsp->server_caps	= cpu_to_le64(server_caps);
	arsp->vol_caps		= cpu_to_le64(vol_caps);
	arsp->pad		= 0;
	arsp->model_string_bytes = cpu_to_le32(model_bytes);

	if (model_bytes)
		memcpy(payload + sizeof(*arsp), aapl_model, model_bytes);

	return aapl_append_rsp_ctx(work, rsp, payload, payload_len);
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
 *
 * Integration point in fs/smb/server/smb2pdu.c — add near the end of
 * smb2_create(), after durable/lease context handling:
 *
 *   #include "aapl.h"
 *   ...
 *   err = smb2_aapl_create_ctx(work, req, rsp);
 *   if (err)
 *       pr_debug("ksmbd: AAPL context: %d\n", err);
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
		/* AAPL_RESOLVE_ID and future commands: ignore gracefully */
		return 0;
	}
}
