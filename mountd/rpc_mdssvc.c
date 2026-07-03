// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MDSSVC (Apple Spotlight) RPC stub for KSMBD.
 *
 * mdssvc is Apple's metadata search (Spotlight) RPC service — it has nothing
 * to do with Time Machine backup functionality.  macOS opens the mdssvc pipe
 * after the TM iotest succeeds, as a separate Spotlight connection.  TM backup
 * proceeds normally when mdssvc is absent (macOS falls back gracefully), as
 * confirmed by Ralph Boehme (Samba mdssvc author) in ksmbd issue #502 and
 * consistent with the Apple TM SMB spec (which lists no RPC endpoint requirement)
 * and Samba's own documentation (Spotlight is explicitly optional for TM).
 *
 * This stub is currently NOT enabled (user_session.c returns 0 for mdssvc).
 * If Spotlight support is ever desired, enable it there and note:
 *   - The volume path in the open response must be dynamic (per-share), not hardcoded
 *   - opnum 0 : open    — echoes device_id/unkn2/unkn3 + share path + UUID handle
 *   - opnum 2 : unknown1 — returns flags=0x6b000001 (hardcoded in Samba too)
 *   - opnum 3 : cmd     — returns empty search results
 *
 * Body structure reverse-engineered from native macOS smbd captures.
 * Reference: Samba source3/rpc_server/mdssvc/mdssvc.c
 */

#include <memory.h>
#include <string.h>
#include <endian.h>
#include <glib.h>
#include <errno.h>
#include <linux/ksmbd_server.h>

#include <rpc.h>
#include <rpc_mdssvc.h>
#include <tools.h>

#define MDSSVC_OPNUM_OPEN	0
#define MDSSVC_OPNUM_UNKNOWN1	2
#define MDSSVC_OPNUM_CMD	3

/*
 * 22-byte fixed prefix for the mdssvc_open response body, derived from
 * native macOS smbd captures:
 *   bytes[0-3]  : device_id (constant value observed in native: 0x00060000)
 *   bytes[4-7]  : unkn2     (constant: 0x001e3600)
 *   bytes[8-11] : unkn3     = 0
 *   bytes[12-15]: unkn4     = 0  (undocumented field not in Samba IDL)
 *   bytes[16-19]: max_count = 1025 (size_is of share_path conformant array)
 *   bytes[20-21]: offset    = 0   (uint16 field before actual_count)
 */
static const unsigned char mdssvc_open_prefix[22] = {
	0x00, 0x00, 0x06, 0x00,   /* device_id */
	0x00, 0x36, 0x1e, 0x00,   /* unkn2 */
	0x00, 0x00, 0x00, 0x00,   /* unkn3 */
	0x00, 0x00, 0x00, 0x00,   /* unkn4 */
	0x01, 0x04, 0x00, 0x00,   /* max_count = 1025 */
	0x00, 0x00,               /* offset uint16 = 0 */
};

/*
 * Share path returned in the open response.  This must be the actual filesystem
 * path of the share (e.g. "/srv/timemachine") to match the native macOS smbd
 * packet layout (17-byte path + 3-byte NDR pad → 64-byte body / 88-byte fragment).
 * If this stub is ever enabled, replace the placeholder with the real share path
 * obtained from the ksmbd_session / tree_connect at call time.
 */
#define MDSSVC_VOLUME_PATH	"/srv/timemachine"  /* placeholder: make dynamic */

static int mdssvc_invoke(struct ksmbd_rpc_pipe *pipe)
{
	return KSMBD_RPC_OK;
}

static int mdssvc_return(struct ksmbd_rpc_pipe *pipe,
			  struct ksmbd_rpc_command *resp,
			  int max_resp_sz)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int ret = 0;

	dcerpc_set_ext_payload(dce, resp->payload, max_resp_sz);

	dce->offset = sizeof(struct dcerpc_header);
	dce->offset += sizeof(struct dcerpc_response_header);

	switch (dce->req_hdr.opnum) {
	case MDSSVC_OPNUM_OPEN: {
		/*
		 * mdssvc_open response body (64 bytes for 17-byte path):
		 *   [22]  fixed prefix (device_id + unkn2 + unkn3 + unkn4 +
		 *                       max_count + offset)
		 *   [4]   actual_count uint32 (via ndr_write_bytes — avoids the
		 *         2-byte alignment gap that ndr_write_int32 inserts at
		 *         the unaligned offset-46 position)
		 *   [N]   path string, null-terminated
		 *   [pad] NDR padding to 4-byte boundary
		 *   [2]   trailing uint16 = 0  (handle type, NOT uint32)
		 *   [16]  UUID context handle (zeros)
		 *
		 * For MDSSVC_VOLUME_PATH = "/srv/timemachine" (17 bytes incl null):
		 *   17 + 3 pad = 20 effective bytes  →  body = 64, frag = 88
		 *   This matches the native macOS smbd 270-byte packet exactly.
		 */
		const char *path = MDSSVC_VOLUME_PATH;
		__u32 pathlen = strlen(path) + 1;
		__u32 pathlen_le = htole32(pathlen);
		__u32 pad = (4 - (pathlen % 4)) % 4;
		static const char uuid[16] = {0};
		__u16 trailing = 0;

		ret |= ndr_write_bytes(dce, (void *)mdssvc_open_prefix,
				       sizeof(mdssvc_open_prefix));
		ret |= ndr_write_bytes(dce, &pathlen_le, sizeof(pathlen_le));
		ret |= ndr_write_bytes(dce, (void *)path, pathlen);
		while (pad--)
			ret |= ndr_write_int8(dce, 0);
		ret |= ndr_write_int16(dce, trailing);
		ret |= ndr_write_bytes(dce, (void *)uuid, sizeof(uuid));
		break;
	}

	case MDSSVC_OPNUM_UNKNOWN1:
		/*
		 * Exact 12-byte body from native macOS smbd (frame 3824):
		 *   status = 0, flags = 0x6b000001, unkn7 = 0
		 * Matches Samba's _mdssvc_unknown1 which hardcodes flags=0x6b000001.
		 * TM starts the backup after receiving this reply.
		 */
		ret |= ndr_write_bytes(dce, (void *)((unsigned char[]){
			0x00, 0x00, 0x00, 0x00,   /* status = 0 */
			0x01, 0x00, 0x00, 0x6b,   /* flags = 0x6b000001 LE */
			0x00, 0x00, 0x00, 0x00,   /* unkn7 = 0 */
		}), 12);
		break;

	case MDSSVC_OPNUM_CMD:
		/* Empty Spotlight results — TM backup data doesn't use these */
		ret |= ndr_write_int32(dce, 0);  /* flags */
		ret |= ndr_write_int32(dce, 0);  /* blob length = 0 */
		ret |= ndr_write_int32(dce, 0);  /* status */
		break;

	default:
		pr_debug("MDSSVC: unsupported opnum %d\n", dce->req_hdr.opnum);
		ret |= ndr_write_int32(dce, 0);
		break;
	}

	if (ret)
		return KSMBD_RPC_EBAD_DATA;

	if (dcerpc_write_headers(dce, KSMBD_RPC_OK))
		return KSMBD_RPC_EBAD_DATA;

	dce->rpc_resp->payload_sz = dce->offset;
	return KSMBD_RPC_OK;
}

int rpc_mdssvc_read_request(struct ksmbd_rpc_pipe *pipe,
			    struct ksmbd_rpc_command *resp,
			    int max_resp_sz)
{
	return mdssvc_return(pipe, resp, max_resp_sz);
}

int rpc_mdssvc_write_request(struct ksmbd_rpc_pipe *pipe)
{
	return mdssvc_invoke(pipe);
}
