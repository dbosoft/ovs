/*
 * Copyright (c) 2026 dbosoft GmbH.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

/* Drives the native dpif-windows provider against an in-process mock that
 * imitates the ovsext kernel datapath's IOCTL/netlink contract.  No driver and
 * no VM are involved, so the provider's userspace marshalling can be exercised
 * (and ASAN-checked: configure with -DOVS_ASAN=ON) on a dev box.
 *
 * The mock reproduces the kernel quirks that the marshalling must cope with:
 *   - READ copies the dequeued message TRUNCATED to the caller's output length
 *     (so an undersized recv buffer drops the trailing attribute);
 *   - the dump cursor is PER FILE HANDLE (so a dump must use its own handle);
 *   - a dump is a WRITE(NLM_F_DUMP) that arms the cursor, then one record per
 *     READ, ended by a zero-length read (no NLMSG_DONE).
 *
 * Each test programs the mock's dump/packet/transact content, drives the
 * provider through the public dpif API, and asserts the contract. */

#include <config.h>

#ifdef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_MSC_VER) && defined(_DEBUG)
#include <crtdbg.h>
#endif
#include <windows.h>

#include "dpif.h"
#include "ct-dpif.h"
#include "netdev.h"
#include "netdev-provider.h"
#include "openvswitch/ofp-meter.h"
#include "ovsext-channel.h"
#include "dp-packet.h"
#include "flow.h"
#include "odp-util.h"
#include "netlink.h"
#include "netlink-protocol.h"
#include "odp-netlink.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "unaligned.h"
#include "util.h"
#include "ovs-atomic.h"
#include "ovs-thread.h"
#include "timeval.h"

/* The ovsext ABI (IOCTL codes, fixed genl family ids, struct ovs_header). */
#include "OvsDpInterfaceExt.h"

#define MOCK_DP_IFINDEX 1
#define MOCK_PID        0x1234u

#define MOCK_MAX_HANDLES 8
#define MOCK_MAX_RECORDS 8
#define MOCK_RECORD_CAP  8192

/* ---- test bookkeeping ---------------------------------------------------- */

static int failures;

#define CHECK(cond) do {                                                    \
        if (cond) {                                                         \
            printf("    ok: %s\n", #cond);                                  \
        } else {                                                           \
            printf("    FAIL: %s (%s:%d)\n", #cond, __FILE__, __LINE__);    \
            failures++;                                                    \
        }                                                                  \
    } while (0)

/* ---- mock "kernel" state ------------------------------------------------- */

enum mock_dump { DUMP_NONE, DUMP_VPORT, DUMP_FLOW, DUMP_DP };

/* How an OVS_IOCTL_TRANSACT against the FLOW family answers. */
enum flow_reply {
    FR_ACK,         /* Success, empty reply (no NLM_F_ECHO output). */
    FR_ECHO,        /* Success, return m->flow_echo (a full flow w/ stats). */
    FR_EMPTYECHO,   /* Echo requested but driver returns 0 bytes (a fault). */
    FR_ENOENT,      /* In-band NLMSG_ERROR, -ENOENT (a genuine miss). */
    FR_MALFORMED,   /* Non-error reply that fails to decode (protocol fault). */
};

struct mock_record {
    uint8_t data[MOCK_RECORD_CAP];
    size_t len;
};

/* The kernel dump cursor lives on the file handle, so model per-handle. */
struct mock_handle {
    bool in_use;
    enum mock_dump dump;        /* Which family's dump this handle is walking. */
    int cursor;                 /* Next record index for that dump. */
};

struct mock_kernel {
    struct mock_handle handles[MOCK_MAX_HANDLES];
    int n_open;                 /* Currently open handles. */
    int peak_open;              /* High-water mark of n_open. */
    bool fail_open;             /* Force the next device open to fail (ENODEV). */

    /* Programmable dump content. */
    struct mock_record dp[MOCK_MAX_RECORDS];    int n_dp;
    struct mock_record vport[MOCK_MAX_RECORDS]; int n_vport;
    struct mock_record flow[MOCK_MAX_RECORDS];  int n_flow;
    bool flow_dump_done;        /* FLOW dump ends with an NLMSG_DONE record
                                 * (as the kernel does), not a zero-length read. */

    /* Queued packet upcalls, delivered one per OVS_IOCTL_READ_PACKET. */
    struct mock_record pkt[MOCK_MAX_RECORDS];   int pkt_head, pkt_len;

    /* Queued vport-change events, delivered one per OVS_IOCTL_READ_EVENT. */
    struct mock_record evt[MOCK_MAX_RECORDS];   int evt_head, evt_len;

    /* OVS_IOCTL_TRANSACT scripting for the FLOW family. */
    enum flow_reply flow_reply;
    struct mock_record flow_echo;
    struct mock_record flow_bad;
    bool flow_require_key;      /* Model ovsext nlFlowPolicy: a flow command
                                 * without OVS_FLOW_ATTR_KEY is rejected EINVAL
                                 * (the current kernel has no UFID lookup). */
    bool flow_req_had_key;      /* Last flow request carried OVS_FLOW_ATTR_KEY. */
    bool flow_req_had_ufid;     /* Last flow request carried OVS_FLOW_ATTR_UFID. */

    /* Set when a validateDpIndex control command (subscribe/pend) arrives with a
     * dp_ifindex that is not the mock datapath -- the kernel rejects these. */
    bool validate_dp_failed;

    /* OVS_CT_LIMIT family state.  SET records the requested zone+limit; GET
     * echoes ct_limit/ct_count back for the requested zone (or the default zone
     * when the request carries none). */
    int      ct_last_cmd;
    int32_t  ct_zone;
    uint32_t ct_limit;
    uint32_t ct_count;

    /* OVS_METER family state.  SET records the meter id and its first band;
     * GET/DEL echo back fixed meter and band stats. */
    int      meter_last_cmd;
    uint32_t meter_id;
    uint32_t meter_n_bands;
    uint32_t meter_band_type;
    uint32_t meter_band_rate;
    uint32_t meter_band_burst;

    /* OVS_DP_F_* handshake.  A SET request stores its (validated) feature mask
     * here; when 'dp_echo_features' is set the DP reply carries USER_FEATURES
     * and MEGAFLOW_STATS back (modelling the feature-aware kernel), otherwise it
     * omits them (modelling an older kernel that never negotiates). */
    uint32_t dp_user_features;
    bool     dp_echo_features;

    /* OVS_WIN_NETDEV family state.  The netdev provider's construct and its
     * periodic netdev_windows_run() refresh query this; the latter commits it to
     * the netdev's cached admin flags / MAC / MTU / carrier. */
    bool     nd_present;       /* GET succeeds (the vport exists). */
    uint32_t nd_type;
    uint32_t nd_port_no;
    struct eth_addr nd_mac;
    uint32_t nd_mtu;
    uint32_t nd_flags;         /* OVS_WIN_NETDEV_IFF_*. */
};

/* ---- record builders ----------------------------------------------------- */

/* Finalizes 'b' (a request/reply under construction) into 'r'. */
static void
finish_record(struct mock_record *r, struct ofpbuf *b)
{
    nl_msg_nlmsghdr(b)->nlmsg_len = b->size;
    ovs_assert(b->size <= sizeof r->data);
    memcpy(r->data, b->data, b->size);
    r->len = b->size;
    ofpbuf_uninit(b);
}

/* Builds an OVS_DP_CMD_GET reply (name + stats), as OvsDpFillInfo does. */
static void
build_dp_record(struct mock_record *r)
{
    uint64_t stub[1024 / 8];
    struct ofpbuf b;
    struct ovs_header *ovs_header;
    struct ovs_dp_stats stats;

    ofpbuf_use_stub(&b, stub, sizeof stub);
    nl_msg_put_genlmsghdr(&b, 0, OVS_WIN_NL_DATAPATH_FAMILY_ID, 0,
                          OVS_DP_CMD_GET, OVS_DATAPATH_VERSION);
    ovs_header = ofpbuf_put_uninit(&b, sizeof *ovs_header);
    ovs_header->dp_ifindex = MOCK_DP_IFINDEX;
    nl_msg_put_string(&b, OVS_DP_ATTR_NAME, "ovs-system");
    memset(&stats, 0, sizeof stats);
    nl_msg_put_unspec(&b, OVS_DP_ATTR_STATS, &stats, sizeof stats);
    finish_record(r, &b);
}

/* Builds an OVS_FLOW record with a distinct key (varying 'in_port').  When
 * 'rich' it also carries a mask, padded actions and stats (so it round-trips a
 * full flow), used to exercise the FLOW_GET copy path. */
static void
build_flow_record(struct mock_record *r, uint32_t in_port, bool rich)
{
    uint64_t stub[MOCK_RECORD_CAP / 8];
    struct ofpbuf b;
    struct ovs_header *ovs_header;
    size_t key_ofs;

    ofpbuf_use_stub(&b, stub, sizeof stub);
    nl_msg_put_genlmsghdr(&b, 0, OVS_WIN_NL_FLOW_FAMILY_ID, 0,
                          OVS_FLOW_CMD_NEW, OVS_FLOW_VERSION);
    ovs_header = ofpbuf_put_uninit(&b, sizeof *ovs_header);
    ovs_header->dp_ifindex = MOCK_DP_IFINDEX;

    key_ofs = nl_msg_start_nested(&b, OVS_FLOW_ATTR_KEY);
    nl_msg_put_u32(&b, OVS_KEY_ATTR_IN_PORT, in_port);
    nl_msg_end_nested(&b, key_ofs);

    if (rich) {
        size_t mask_ofs = nl_msg_start_nested(&b, OVS_FLOW_ATTR_MASK);
        nl_msg_put_u32(&b, OVS_KEY_ATTR_IN_PORT, 0xffffffff);
        nl_msg_end_nested(&b, mask_ofs);

        /* OVS_FLOW_ATTR_ACTIONS is validated as NL_A_NESTED (any length); a big
         * blob forces the caller's get->buffer to realloc while copying. */
        uint8_t acts[1500];
        memset(acts, 0xCD, sizeof acts);
        nl_msg_put_unspec(&b, OVS_FLOW_ATTR_ACTIONS, acts, sizeof acts);

        struct ovs_flow_stats fstats;
        put_32aligned_u64(&fstats.n_packets, 5);
        put_32aligned_u64(&fstats.n_bytes, 500);
        nl_msg_put_unspec(&b, OVS_FLOW_ATTR_STATS, &fstats, sizeof fstats);
    }
    finish_record(r, &b);
}

/* Builds a FLOW record carrying neither a key nor a ufid: a structurally valid
 * netlink message that dpif_windows_flow_from_ofpbuf rejects (EINVAL). */
static void
build_flow_bad(struct mock_record *r)
{
    uint64_t stub[256 / 8];
    struct ofpbuf b;
    struct ovs_header *ovs_header;

    ofpbuf_use_stub(&b, stub, sizeof stub);
    nl_msg_put_genlmsghdr(&b, 0, OVS_WIN_NL_FLOW_FAMILY_ID, 0,
                          OVS_FLOW_CMD_NEW, OVS_FLOW_VERSION);
    ovs_header = ofpbuf_put_uninit(&b, sizeof *ovs_header);
    ovs_header->dp_ifindex = MOCK_DP_IFINDEX;
    finish_record(r, &b);
}

/* Builds an OVS_PACKET_CMD_ACTION upcall on datapath 'dp_ifindex' whose total
 * size exceeds 'frame_len'.  The PACKET attribute is written LAST (as the
 * kernel's OvsCreateQueueNlPacket does), so a truncating read drops it and the
 * policy parse fails. */
static void
build_packet_upcall(struct mock_record *r, int dp_ifindex, size_t frame_len)
{
    uint64_t stub[MOCK_RECORD_CAP / 8];
    struct ofpbuf b;
    struct ovs_header *ovs_header;
    size_t key_ofs;
    uint8_t *frame;

    ofpbuf_use_stub(&b, stub, sizeof stub);
    nl_msg_put_genlmsghdr(&b, 0, OVS_WIN_NL_PACKET_FAMILY_ID, 0,
                          OVS_PACKET_CMD_ACTION, OVS_PACKET_VERSION);
    ovs_header = ofpbuf_put_uninit(&b, sizeof *ovs_header);
    ovs_header->dp_ifindex = dp_ifindex;

    key_ofs = nl_msg_start_nested(&b, OVS_PACKET_ATTR_KEY);
    nl_msg_put_u32(&b, OVS_KEY_ATTR_IN_PORT, 7);
    nl_msg_end_nested(&b, key_ofs);

    frame = nl_msg_put_unspec_uninit(&b, OVS_PACKET_ATTR_PACKET, frame_len);
    memset(frame, 0xAB, frame_len);
    memset(frame, 0, 12);           /* dst+src MAC */
    frame[12] = 0x08;               /* ethertype = IPv4 */
    frame[13] = 0x00;
    finish_record(r, &b);
}

/* ---- mock IOCTL handlers ------------------------------------------------- */

/* Copies 'r' into the IOCTL output buffer, truncated to 'out_len' exactly as
 * the driver copies a dequeued message into the caller's buffer. */
static BOOL
record_copy(const struct mock_record *r, void *out, DWORD out_len, DWORD *bytes)
{
    DWORD n = r->len < out_len ? (DWORD) r->len : out_len;

    memcpy(out, r->data, n);
    *bytes = n;
    return TRUE;
}

/* Builds an in-band NLMSG_ERROR reply carrying errno 'err'. */
static BOOL
reply_nlmsgerr(int err, void *out, DWORD out_len, DWORD *bytes)
{
    struct nlmsghdr *nlh;
    struct nlmsgerr *e;
    size_t len = NLMSG_HDRLEN + sizeof *e;

    if (out_len < len) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    memset(out, 0, len);
    nlh = out;
    nlh->nlmsg_len = (uint32_t) len;
    nlh->nlmsg_type = NLMSG_ERROR;
    e = (struct nlmsgerr *) ((char *) out + NLMSG_HDRLEN);
    e->error = -err;
    *bytes = (DWORD) len;
    return TRUE;
}

/* Extracts the first 'struct ovs_zone_limit' from a CT_LIMIT request's nested
 * OVS_CT_LIMIT_ATTR_ZONE_LIMIT array, returning false when the request carries
 * no zone (the "all zones / default" form). */
static bool
ct_parse_first_zone(const void *in, DWORD in_len, struct ovs_zone_limit *zlp)
{
    struct ofpbuf b = ofpbuf_const_initializer(in, in_len);
    static const struct nl_policy pol[] = {
        [OVS_CT_LIMIT_ATTR_ZONE_LIMIT] = { .type = NL_A_NESTED,
                                           .optional = true },
    };
    struct nlattr *attr[ARRAY_SIZE(pol)];

    if (!ofpbuf_try_pull(&b, NLMSG_HDRLEN)
        || !ofpbuf_try_pull(&b, GENL_HDRLEN)
        || !ofpbuf_try_pull(&b, sizeof(struct ovs_header))
        || !nl_policy_parse(&b, 0, pol, attr, ARRAY_SIZE(pol))
        || !attr[OVS_CT_LIMIT_ATTR_ZONE_LIMIT]
        || nl_attr_get_size(attr[OVS_CT_LIMIT_ATTR_ZONE_LIMIT]) < sizeof *zlp) {
        return false;
    }
    memcpy(zlp, nl_attr_get(attr[OVS_CT_LIMIT_ATTR_ZONE_LIMIT]), sizeof *zlp);
    return true;
}

/* Answers an OVS_CT_LIMIT_CMD_GET, laid out as the kernel's
 * OvsCreateNlMsgFromCtLimit does: a request naming a zone echoes that one zone;
 * a bare request (no zone) enumerates the default zone plus a configured zone
 * (zone 7), exercising the multi-record parse the kernel's enumeration emits. */
static BOOL
mock_ct_limit_get(struct mock_kernel *m, const void *in, DWORD in_len,
                  void *out, DWORD out_len, DWORD *bytes)
{
    struct ovs_zone_limit req;
    bool have_zone = ct_parse_first_zone(in, in_len, &req);
    uint64_t stub[256 / 8];
    struct ofpbuf r;
    struct ovs_header *oh;
    size_t nest;
    DWORD n;

    ofpbuf_use_stub(&r, stub, sizeof stub);
    nl_msg_put_genlmsghdr(&r, 0, OVS_WIN_NL_CTLIMIT_FAMILY_ID, 0,
                          OVS_CT_LIMIT_CMD_GET, OVS_CT_LIMIT_VERSION);
    oh = ofpbuf_put_uninit(&r, sizeof *oh);
    oh->dp_ifindex = 0;
    nest = nl_msg_start_nested(&r, OVS_CT_LIMIT_ATTR_ZONE_LIMIT);
    if (have_zone) {
        struct ovs_zone_limit zl = { .zone_id = req.zone_id,
                                     .limit = m->ct_limit,
                                     .count = m->ct_count };
        nl_msg_put(&r, &zl, sizeof zl);
    } else {
        struct ovs_zone_limit def = {
            .zone_id = OVS_ZONE_LIMIT_DEFAULT_ZONE, .limit = m->ct_limit,
            .count = 0 };
        struct ovs_zone_limit z7 = { .zone_id = 7, .limit = 77,
                                     .count = m->ct_count };
        nl_msg_put(&r, &def, sizeof def);
        nl_msg_put(&r, &z7, sizeof z7);
    }
    nl_msg_end_nested(&r, nest);
    nl_msg_nlmsghdr(&r)->nlmsg_len = r.size;

    n = r.size < out_len ? (DWORD) r.size : out_len;
    memcpy(out, r.data, n);
    *bytes = n;
    ofpbuf_uninit(&r);
    return TRUE;
}

/* Records the meter id and first band of an OVS_METER_CMD_SET request. */
static void
mock_meter_parse_set(struct mock_kernel *m, const void *in, DWORD in_len)
{
    struct ofpbuf b = ofpbuf_const_initializer(in, in_len);
    static const struct nl_policy pol[] = {
        [OVS_METER_ATTR_ID] = { .type = NL_A_U32, .optional = true },
        [OVS_METER_ATTR_BANDS] = { .type = NL_A_NESTED, .optional = true },
    };
    struct nlattr *attr[ARRAY_SIZE(pol)];

    m->meter_id = 0;
    m->meter_n_bands = 0;
    m->meter_band_type = 0;
    m->meter_band_rate = 0;
    m->meter_band_burst = 0;

    if (!ofpbuf_try_pull(&b, NLMSG_HDRLEN)
        || !ofpbuf_try_pull(&b, GENL_HDRLEN)
        || !ofpbuf_try_pull(&b, sizeof(struct ovs_header))
        || !nl_policy_parse(&b, 0, pol, attr, ARRAY_SIZE(pol))) {
        return;
    }
    if (attr[OVS_METER_ATTR_ID]) {
        m->meter_id = nl_attr_get_u32(attr[OVS_METER_ATTR_ID]);
    }
    if (attr[OVS_METER_ATTR_BANDS]) {
        const struct nlattr *nla;
        size_t left;

        NL_NESTED_FOR_EACH (nla, left, attr[OVS_METER_ATTR_BANDS]) {
            const struct nlattr *t, *rate, *burst;

            m->meter_n_bands++;
            if (m->meter_n_bands > 1) {
                continue;       /* Record only the first band. */
            }
            t     = nl_attr_find_nested(nla, OVS_BAND_ATTR_TYPE);
            rate  = nl_attr_find_nested(nla, OVS_BAND_ATTR_RATE);
            burst = nl_attr_find_nested(nla, OVS_BAND_ATTR_BURST);
            if (t)     { m->meter_band_type  = nl_attr_get_u32(t); }
            if (rate)  { m->meter_band_rate  = nl_attr_get_u32(rate); }
            if (burst) { m->meter_band_burst = nl_attr_get_u32(burst); }
        }
    }
}

/* Answers an OVS_METER_CMD_*: FEATURES advertises one DROP band; SET echoes the
 * meter id; GET/DEL return fixed meter and per-band stats. */
static BOOL
mock_meter(struct mock_kernel *m, const void *in, DWORD in_len,
           void *out, DWORD out_len, DWORD *bytes)
{
    const struct genlmsghdr *genl = ALIGNED_CAST(const struct genlmsghdr *,
                                        (const char *) in + NLMSG_HDRLEN);
    uint64_t stub[512 / 8];
    struct ofpbuf r;
    struct ovs_header *oh;
    DWORD n;

    m->meter_last_cmd = genl->cmd;

    ofpbuf_use_stub(&r, stub, sizeof stub);
    nl_msg_put_genlmsghdr(&r, 0, OVS_WIN_NL_METER_FAMILY_ID, 0,
                          genl->cmd, OVS_METER_VERSION);
    oh = ofpbuf_put_uninit(&r, sizeof *oh);
    oh->dp_ifindex = 0;

    if (genl->cmd == OVS_METER_CMD_FEATURES) {
        size_t bands, band;

        nl_msg_put_u32(&r, OVS_METER_ATTR_MAX_METERS, 32);
        nl_msg_put_u32(&r, OVS_METER_ATTR_MAX_BANDS, 1);
        bands = nl_msg_start_nested(&r, OVS_METER_ATTR_BANDS);
        band = nl_msg_start_nested(&r, OVS_BAND_ATTR_UNSPEC);
        nl_msg_put_u32(&r, OVS_BAND_ATTR_TYPE, OVS_METER_BAND_TYPE_DROP);
        nl_msg_end_nested(&r, band);
        nl_msg_end_nested(&r, bands);
    } else if (genl->cmd == OVS_METER_CMD_SET) {
        mock_meter_parse_set(m, in, in_len);
        nl_msg_put_u32(&r, OVS_METER_ATTR_ID, m->meter_id);
    } else {                    /* GET or DEL: return stats. */
        struct ovs_flow_stats mstats, bstats;
        size_t bands, band;

        put_32aligned_u64(&mstats.n_packets, 10);
        put_32aligned_u64(&mstats.n_bytes, 1000);
        put_32aligned_u64(&bstats.n_packets, 3);
        put_32aligned_u64(&bstats.n_bytes, 300);

        nl_msg_put_u32(&r, OVS_METER_ATTR_ID, m->meter_id);
        nl_msg_put_unspec(&r, OVS_METER_ATTR_STATS, &mstats, sizeof mstats);
        bands = nl_msg_start_nested(&r, OVS_METER_ATTR_BANDS);
        band = nl_msg_start_nested(&r, OVS_BAND_ATTR_UNSPEC);
        nl_msg_put_unspec(&r, OVS_BAND_ATTR_STATS, &bstats, sizeof bstats);
        nl_msg_end_nested(&r, band);
        nl_msg_end_nested(&r, bands);
    }
    nl_msg_nlmsghdr(&r)->nlmsg_len = r.size;

    n = r.size < out_len ? (DWORD) r.size : out_len;
    memcpy(out, r.data, n);
    *bytes = n;
    ofpbuf_uninit(&r);
    return TRUE;
}

/* The datapath features the mock kernel honours, matching the ovsext
 * OVSEXT_SUPPORTED_DP_FEATURES set. */
#define MOCK_SUPPORTED_DP_FEATURES (OVS_DP_F_UNALIGNED | OVS_DP_F_VPORT_PIDS)

/* Answers an OVS_DP_CMD_GET/SET transaction as OvsDpFillInfo +
 * HandleDpTransactionCommon do: a SET validates the requested USER_FEATURES
 * against the supported mask (rejecting unknown bits with EOPNOTSUPP) and
 * stores it; every reply carries NAME + STATS, plus MEGAFLOW_STATS and the
 * echoed USER_FEATURES when 'dp_echo_features' is set. */
static BOOL
mock_dp_transact(struct mock_kernel *m, const void *in, DWORD in_len,
                 void *out, DWORD out_len, DWORD *bytes)
{
    const struct genlmsghdr *genl = ALIGNED_CAST(const struct genlmsghdr *,
                                        (const char *) in + NLMSG_HDRLEN);
    static const struct nl_policy pol[] = {
        [OVS_DP_ATTR_NAME] = { .type = NL_A_STRING, .optional = true },
        [OVS_DP_ATTR_UPCALL_PID] = { .type = NL_A_U32, .optional = true },
        [OVS_DP_ATTR_USER_FEATURES] = { .type = NL_A_U32, .optional = true },
    };
    struct nlattr *attr[ARRAY_SIZE(pol)];
    struct ofpbuf b = ofpbuf_const_initializer(in, in_len);
    bool parsed = ofpbuf_try_pull(&b, NLMSG_HDRLEN)
        && ofpbuf_try_pull(&b, GENL_HDRLEN)
        && ofpbuf_try_pull(&b, sizeof(struct ovs_header))
        && nl_policy_parse(&b, 0, pol, attr, ARRAY_SIZE(pol));

    if (genl->cmd == OVS_DP_CMD_SET && parsed
        && attr[OVS_DP_ATTR_USER_FEATURES]) {
        uint32_t req = nl_attr_get_u32(attr[OVS_DP_ATTR_USER_FEATURES]);

        if (req & ~MOCK_SUPPORTED_DP_FEATURES) {
            return reply_nlmsgerr(EOPNOTSUPP, out, out_len, bytes);
        }
        m->dp_user_features = req;
    }

    uint64_t stub[1024 / 8];
    struct ofpbuf r;
    struct ovs_header *ovs_header;
    struct ovs_dp_stats stats;
    DWORD n;

    ofpbuf_use_stub(&r, stub, sizeof stub);
    nl_msg_put_genlmsghdr(&r, 0, OVS_WIN_NL_DATAPATH_FAMILY_ID, 0,
                          OVS_DP_CMD_GET, OVS_DATAPATH_VERSION);
    ovs_header = ofpbuf_put_uninit(&r, sizeof *ovs_header);
    ovs_header->dp_ifindex = MOCK_DP_IFINDEX;
    nl_msg_put_string(&r, OVS_DP_ATTR_NAME, "ovs-system");
    memset(&stats, 0, sizeof stats);
    nl_msg_put_unspec(&r, OVS_DP_ATTR_STATS, &stats, sizeof stats);
    if (m->dp_echo_features) {
        struct ovs_dp_megaflow_stats mf;

        memset(&mf, 0, sizeof mf);
        mf.n_masks = 1;
        nl_msg_put_unspec(&r, OVS_DP_ATTR_MEGAFLOW_STATS, &mf, sizeof mf);
        nl_msg_put_u32(&r, OVS_DP_ATTR_USER_FEATURES, m->dp_user_features);
    }
    nl_msg_nlmsghdr(&r)->nlmsg_len = r.size;

    n = r.size < out_len ? (DWORD) r.size : out_len;
    memcpy(out, r.data, n);
    *bytes = n;
    ofpbuf_uninit(&r);
    return TRUE;
}

/* Answers an OVS_WIN_NETDEV_CMD_GET as OvsCreateMsgFromVport does: NL_ERROR_NODEV
 * when the vport is absent, else a reply carrying the programmed
 * port_no/type/name/mac/mtu/if_flags. */
static BOOL
mock_netdev_get(struct mock_kernel *m, const void *in OVS_UNUSED,
                DWORD in_len OVS_UNUSED, void *out, DWORD out_len, DWORD *bytes)
{
    uint64_t stub[512 / 8];
    struct ofpbuf r;
    struct ovs_header *ovs_header;
    DWORD n;

    if (!m->nd_present) {
        return reply_nlmsgerr(ENODEV, out, out_len, bytes);
    }

    ofpbuf_use_stub(&r, stub, sizeof stub);
    nl_msg_put_genlmsghdr(&r, 0, OVS_WIN_NL_NETDEV_FAMILY_ID, 0,
                          OVS_WIN_NETDEV_CMD_GET, OVS_WIN_NETDEV_VERSION);
    ovs_header = ofpbuf_put_uninit(&r, sizeof *ovs_header);
    ovs_header->dp_ifindex = MOCK_DP_IFINDEX;
    nl_msg_put_u32(&r, OVS_WIN_NETDEV_ATTR_PORT_NO, m->nd_port_no);
    nl_msg_put_u32(&r, OVS_WIN_NETDEV_ATTR_TYPE, m->nd_type);
    nl_msg_put_string(&r, OVS_WIN_NETDEV_ATTR_NAME, "nd-test");
    nl_msg_put_unspec(&r, OVS_WIN_NETDEV_ATTR_MAC_ADDR, &m->nd_mac,
                      sizeof m->nd_mac);
    nl_msg_put_u32(&r, OVS_WIN_NETDEV_ATTR_MTU, m->nd_mtu);
    nl_msg_put_u32(&r, OVS_WIN_NETDEV_ATTR_IF_FLAGS, m->nd_flags);
    nl_msg_nlmsghdr(&r)->nlmsg_len = r.size;

    n = r.size < out_len ? (DWORD) r.size : out_len;
    memcpy(out, r.data, n);
    *bytes = n;
    ofpbuf_uninit(&r);
    return TRUE;
}

static BOOL
mock_transact(struct mock_kernel *m, const void *in, DWORD in_len,
              void *out, DWORD out_len, DWORD *bytes)
{
    const struct nlmsghdr *nlh = in;

    *bytes = 0;
    if (in_len < NLMSG_HDRLEN + GENL_HDRLEN) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    switch (nlh->nlmsg_type) {
    case OVS_WIN_NL_CTLIMIT_FAMILY_ID: {
        const struct genlmsghdr *genl = ALIGNED_CAST(const struct genlmsghdr *,
                                            (const char *) in + NLMSG_HDRLEN);
        struct ovs_zone_limit req;

        m->ct_last_cmd = genl->cmd;
        if (genl->cmd == OVS_CT_LIMIT_CMD_GET) {
            return mock_ct_limit_get(m, in, in_len, out, out_len, bytes);
        }
        if (ct_parse_first_zone(in, in_len, &req)) {
            m->ct_zone = req.zone_id;
            if (genl->cmd == OVS_CT_LIMIT_CMD_SET) {
                m->ct_limit = req.limit;
            } else {
                m->ct_limit = 0;       /* DEL resets to unbounded. */
            }
        }
        return TRUE;                   /* ack, empty reply */
    }

    case OVS_WIN_NL_METER_FAMILY_ID:
        return mock_meter(m, in, in_len, out, out_len, bytes);

    case OVS_WIN_NL_DATAPATH_FAMILY_ID:
        return mock_dp_transact(m, in, in_len, out, out_len, bytes);

    case OVS_WIN_NL_NETDEV_FAMILY_ID:
        return mock_netdev_get(m, in, in_len, out, out_len, bytes);

    case OVS_WIN_NL_FLOW_FAMILY_ID: {
        size_t hdrlen = NLMSG_HDRLEN + GENL_HDRLEN + sizeof(struct ovs_header);

        /* Record what the provider put on the wire and, when modelling the
         * current kernel, enforce its nlFlowPolicy: OVS_FLOW_ATTR_KEY is
         * mandatory and there is no OVS_FLOW_ATTR_UFID lookup, so a UFID-only
         * (terse) request is rejected with EINVAL. */
        if (in_len >= hdrlen) {
            const struct nlattr *attrs =
                ALIGNED_CAST(const struct nlattr *, (const char *) in + hdrlen);
            size_t alen = in_len - hdrlen;
            m->flow_req_had_key =
                nl_attr_find__(attrs, alen, OVS_FLOW_ATTR_KEY) != NULL;
            m->flow_req_had_ufid =
                nl_attr_find__(attrs, alen, OVS_FLOW_ATTR_UFID) != NULL;
        }
        if (m->flow_require_key && !m->flow_req_had_key) {
            return reply_nlmsgerr(EINVAL, out, out_len, bytes);
        }

        switch (m->flow_reply) {
        case FR_ECHO:      return record_copy(&m->flow_echo, out, out_len, bytes);
        case FR_MALFORMED: return record_copy(&m->flow_bad, out, out_len, bytes);
        case FR_ENOENT:    return reply_nlmsgerr(ENOENT, out, out_len, bytes);
        case FR_EMPTYECHO: return TRUE;   /* 0 bytes despite echo request */
        case FR_ACK:
        default:           return TRUE;   /* ack, empty reply */
        }
    }

    case OVS_WIN_NL_VPORT_FAMILY_ID:
    case OVS_WIN_NL_PACKET_FAMILY_ID:
    default:
        return TRUE;            /* success, empty reply */
    }
}

static BOOL
mock_write(struct mock_kernel *m, struct mock_handle *h,
           const void *in, DWORD in_len, DWORD *bytes)
{
    const struct nlmsghdr *nlh = in;

    *bytes = 0;
    if (in_len < NLMSG_HDRLEN) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* A WRITE carrying NLM_F_DUMP arms this handle's dump cursor. */
    if (nlh->nlmsg_flags & NLM_F_DUMP) {
        h->cursor = 0;
        switch (nlh->nlmsg_type) {
        case OVS_WIN_NL_VPORT_FAMILY_ID:    h->dump = DUMP_VPORT; break;
        case OVS_WIN_NL_FLOW_FAMILY_ID:     h->dump = DUMP_FLOW;  break;
        case OVS_WIN_NL_DATAPATH_FAMILY_ID: h->dump = DUMP_DP;    break;
        default:                            h->dump = DUMP_NONE;  break;
        }
    }

    /* The kernel validates these control commands (validateDpIndex) against a
     * live datapath and rejects an ovs_header whose dp_ifindex is not one.  Model
     * that so a hardcoded-0 subscribe or pend (the default datapath is not always
     * slot 0) is caught instead of silently targeting the wrong datapath. */
    if (nlh->nlmsg_type == OVS_WIN_NL_CTRL_FAMILY_ID
        && in_len >= NLMSG_HDRLEN + GENL_HDRLEN + sizeof(struct ovs_header)) {
        const struct genlmsghdr *genl = ALIGNED_CAST(const struct genlmsghdr *,
                                            (const char *) in + NLMSG_HDRLEN);
        if (genl->cmd == OVS_CTRL_CMD_MC_SUBSCRIBE_REQ
            || genl->cmd == OVS_CTRL_CMD_PACKET_SUBSCRIBE_REQ
            || genl->cmd == OVS_CTRL_CMD_WIN_PEND_REQ
            || genl->cmd == OVS_CTRL_CMD_WIN_PEND_PACKET_REQ) {
            const struct ovs_header *oh = ALIGNED_CAST(const struct ovs_header *,
                                 (const char *) in + NLMSG_HDRLEN + GENL_HDRLEN);
            if (oh->dp_ifindex != MOCK_DP_IFINDEX) {
                m->validate_dp_failed = true;
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
        }
    }
    /* Other writes just succeed. */
    return TRUE;
}

/* OVS_IOCTL_READ: one record from this handle's armed dump, or 0 bytes (EOF). */
static BOOL
mock_read_dump(struct mock_kernel *m, struct mock_handle *h,
               void *out, DWORD out_len, DWORD *bytes)
{
    const struct mock_record *recs = NULL;
    int n = 0;

    *bytes = 0;
    switch (h->dump) {
    case DUMP_DP:    recs = m->dp;    n = m->n_dp;    break;
    case DUMP_VPORT: recs = m->vport; n = m->n_vport; break;
    case DUMP_FLOW:  recs = m->flow;  n = m->n_flow;  break;
    case DUMP_NONE:  default:         return TRUE;    /* nothing armed */
    }

    if (h->cursor >= n) {
        if (h->dump == DUMP_FLOW && m->flow_dump_done) {
            /* The flow dump ends with an NLMSG_DONE record (Flow.c); emit it
             * once, then the next read is the zero-length EOF. */
            struct nlmsghdr *nlh = out;
            if (out_len < NLMSG_HDRLEN) {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return FALSE;       /* leave the dump armed so a retry works */
            }
            h->dump = DUMP_NONE;
            memset(out, 0, NLMSG_HDRLEN);
            nlh->nlmsg_len = NLMSG_HDRLEN;
            nlh->nlmsg_type = NLMSG_DONE;
            *bytes = NLMSG_HDRLEN;
            return TRUE;
        }
        h->dump = DUMP_NONE;        /* exhausted: zero-length read = EOF */
        return TRUE;
    }
    return record_copy(&recs[h->cursor++], out, out_len, bytes);
}

/* OVS_IOCTL_READ_PACKET: dequeue one queued upcall, truncated to out_len. */
static BOOL
mock_read_packet(struct mock_kernel *m, void *out, DWORD out_len, DWORD *bytes)
{
    *bytes = 0;
    if (m->pkt_len == 0) {
        return TRUE;                /* nothing queued: 0 bytes = EAGAIN */
    }
    record_copy(&m->pkt[m->pkt_head], out, out_len, bytes);
    m->pkt_head = (m->pkt_head + 1) % MOCK_MAX_RECORDS;
    m->pkt_len--;
    return TRUE;
}

/* OVS_IOCTL_READ_EVENT: dequeue one queued vport event, truncated to out_len. */
static BOOL
mock_read_event(struct mock_kernel *m, void *out, DWORD out_len, DWORD *bytes)
{
    *bytes = 0;
    if (m->evt_len == 0) {
        return TRUE;                /* nothing queued: 0 bytes = EAGAIN */
    }
    record_copy(&m->evt[m->evt_head], out, out_len, bytes);
    m->evt_head = (m->evt_head + 1) % MOCK_MAX_RECORDS;
    m->evt_len--;
    return TRUE;
}

static BOOL
mock_ioctl(void *aux, HANDLE handle, DWORD code,
           const void *in, DWORD in_len, void *out, DWORD out_len, DWORD *bytes)
{
    struct mock_kernel *m = aux;
    int slot = (int) (intptr_t) handle - 1;
    struct mock_handle *h;

    ovs_assert(slot >= 0 && slot < MOCK_MAX_HANDLES);
    h = &m->handles[slot];
    ovs_assert(h->in_use);

    switch (code) {
    case OVS_IOCTL_GET_PID: {
        uint32_t pid = MOCK_PID;
        if (out_len < sizeof pid) {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
        memcpy(out, &pid, sizeof pid);
        *bytes = sizeof pid;
        return TRUE;
    }
    case OVS_IOCTL_TRANSACT:
        return mock_transact(m, in, in_len, out, out_len, bytes);
    case OVS_IOCTL_WRITE:
        return mock_write(m, h, in, in_len, bytes);
    case OVS_IOCTL_READ:
        return mock_read_dump(m, h, out, out_len, bytes);
    case OVS_IOCTL_READ_PACKET:
        return mock_read_packet(m, out, out_len, bytes);
    case OVS_IOCTL_READ_EVENT:
        return mock_read_event(m, out, out_len, bytes);
    default:
        SetLastError(ERROR_INVALID_FUNCTION);
        return FALSE;
    }
}

static HANDLE
mock_open(void *aux)
{
    struct mock_kernel *m = aux;
    int i;

    if (m->fail_open) {
        return INVALID_HANDLE_VALUE;    /* model a device-open failure */
    }
    for (i = 0; i < MOCK_MAX_HANDLES; i++) {
        if (!m->handles[i].in_use) {
            m->handles[i].in_use = true;
            m->handles[i].dump = DUMP_NONE;
            m->handles[i].cursor = 0;
            m->n_open++;
            if (m->n_open > m->peak_open) {
                m->peak_open = m->n_open;
            }
            return (HANDLE) (intptr_t) (i + 1);
        }
    }
    return INVALID_HANDLE_VALUE;
}

static void
mock_close(void *aux, HANDLE handle)
{
    struct mock_kernel *m = aux;
    int slot = (int) (intptr_t) handle - 1;

    if (slot >= 0 && slot < MOCK_MAX_HANDLES && m->handles[slot].in_use) {
        m->handles[slot].in_use = false;
        m->n_open--;
    }
}

/* Clears per-test programmable content (not the live handle table). */
static void
mock_reset_content(struct mock_kernel *m)
{
    m->n_vport = 0;
    m->n_flow = 0;
    m->pkt_head = 0;
    m->pkt_len = 0;
    m->evt_head = 0;
    m->evt_len = 0;
    m->fail_open = false;
    m->validate_dp_failed = false;
    m->flow_dump_done = false;
    m->flow_reply = FR_ACK;
    m->flow_require_key = false;
    m->flow_req_had_key = false;
    m->flow_req_had_ufid = false;
    /* Default to the feature-aware kernel: echo USER_FEATURES/MEGAFLOW_STATS so
     * dpif_open()'s feature negotiation succeeds.  A SET clears this back to the
     * negotiated value; tests that exercise the old-kernel path clear it. */
    m->dp_echo_features = true;
    m->dp_user_features = 0;
    /* Keep one datapath so dpif_open()'s resolve dump always succeeds. */
    m->n_dp = 1;
    build_dp_record(&m->dp[0]);
    m->peak_open = m->n_open;
}

static void
mock_queue_packet(struct mock_kernel *m, const struct mock_record *r)
{
    int tail = (m->pkt_head + m->pkt_len) % MOCK_MAX_RECORDS;
    ovs_assert(m->pkt_len < MOCK_MAX_RECORDS);
    m->pkt[tail] = *r;
    m->pkt_len++;
}

/* Queues a vport-change event message (OVS_VPORT_CMD_NEW/DEL), as the kernel's
 * OvsReadEventCmdHandler/OvsPortFillInfo emit it: a genl vport message with the
 * standard nlmsg/genl/ovs_header + PORT_NO/TYPE/UPCALL_PID/NAME attributes. */
static void
mock_queue_vport_event(struct mock_kernel *m, int dp_ifindex, uint8_t cmd,
                       uint32_t port_no, const char *name)
{
    uint64_t stub[1024 / 8];
    struct ofpbuf b;
    struct ovs_header *ovs_header;
    uint32_t pid = MOCK_PID;
    int tail = (m->evt_head + m->evt_len) % MOCK_MAX_RECORDS;

    ovs_assert(m->evt_len < MOCK_MAX_RECORDS);

    ofpbuf_use_stub(&b, stub, sizeof stub);
    nl_msg_put_genlmsghdr(&b, 0, OVS_WIN_NL_VPORT_FAMILY_ID, 0, cmd,
                          OVS_VPORT_VERSION);
    ovs_header = ofpbuf_put_uninit(&b, sizeof *ovs_header);
    ovs_header->dp_ifindex = dp_ifindex;
    nl_msg_put_u32(&b, OVS_VPORT_ATTR_PORT_NO, port_no);
    nl_msg_put_u32(&b, OVS_VPORT_ATTR_TYPE, OVS_VPORT_TYPE_NETDEV);
    nl_msg_put_unspec(&b, OVS_VPORT_ATTR_UPCALL_PID, &pid, sizeof pid);
    nl_msg_put_string(&b, OVS_VPORT_ATTR_NAME, name);
    finish_record(&m->evt[tail], &b);
    m->evt_len++;
}

/* ---- tests --------------------------------------------------------------- */

/* The bring-up sequence open_dpif_backer drives: flush, port dump, a flow_put
 * probe and recv_set.  Smoke test that the provider survives it. */
static void
test_bringup(struct dpif *dpif)
{
    struct dpif_port_dump port_dump;
    struct dpif_port port;
    struct flow flow;
    struct odputil_keybuf keybuf;
    struct ofpbuf key;
    struct odp_flow_key_parms parms;
    struct dpif_flow_put put;
    struct dpif_op op;
    struct dpif_op *ops[1];

    printf("test_bringup:\n");
    CHECK(dpif_flow_flush(dpif) == 0);

    DPIF_PORT_FOR_EACH (&port, &port_dump, dpif) {
        /* No ports on the mock datapath. */
    }

    memset(&flow, 0, sizeof flow);
    flow.dl_type = htons(ETH_TYPE_IP);
    ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
    memset(&parms, 0, sizeof parms);
    parms.flow = &flow;
    odp_flow_key_from_flow(&parms, &key);

    memset(&put, 0, sizeof put);
    put.flags = DPIF_FP_CREATE | DPIF_FP_PROBE;
    put.key = key.data;
    put.key_len = key.size;

    memset(&op, 0, sizeof op);
    op.type = DPIF_OP_FLOW_PUT;
    op.flow_put = put;
    ops[0] = &op;
    dpif_operate(dpif, ops, 1, DPIF_OFFLOAD_NEVER);
    CHECK(op.error == 0);

    CHECK(dpif_recv_set(dpif, true) == 0);
}

/* A full-frame upcall larger than the caller's recv stub must arrive whole: the
 * provider reads into its own 64 kB buffer and grows the caller's ofpbuf.
 * Reading straight into the small stub lets the kernel's truncate-to-output-
 * length drop the trailing PACKET attribute and fail the parse. */
static void
test_recv_large_upcall(struct dpif *dpif, struct mock_kernel *m)
{
    struct mock_record rec;
    struct dpif_upcall upcall;
    uint64_t stub[512 / 8];     /* matches recv_upcalls' undersized stub */
    struct ofpbuf buf;
    const size_t frame_len = 1480;
    int error;

    printf("test_recv_large_upcall:\n");
    mock_reset_content(m);
    build_packet_upcall(&rec, MOCK_DP_IFINDEX, frame_len);
    mock_queue_packet(m, &rec);

    ofpbuf_use_stub(&buf, stub, sizeof stub);
    memset(&upcall, 0xff, sizeof upcall);   /* poison: nothing pre-zeroed */
    error = dpif_recv(dpif, 0, &upcall, &buf);

    CHECK(error == 0);
    CHECK(upcall.type == DPIF_UC_ACTION);
    CHECK(dp_packet_size(&upcall.packet) == frame_len);

    /* pid must be explicitly cleared even though the caller's upcall is not
     * zero-initialized. */
    CHECK(upcall.pid == 0);

    /* Queue is now drained. */
    ofpbuf_clear(&buf);
    CHECK(dpif_recv(dpif, 0, &upcall, &buf) == EAGAIN);
    ofpbuf_uninit(&buf);
}

/* dpif_windows_recv drains upcalls destined for another datapath and returns
 * only the one matching this dpif's dp_ifindex.  Queue a foreign-datapath
 * upcall ahead of a matching one and check the foreign one is skipped. */
static void
test_recv_multi_dp_filter(struct dpif *dpif, struct mock_kernel *m)
{
    struct mock_record other, mine;
    struct dpif_upcall upcall;
    uint64_t stub[2048 / 8];
    struct ofpbuf buf;
    int error;

    printf("test_recv_multi_dp_filter:\n");
    mock_reset_content(m);
    build_packet_upcall(&other, MOCK_DP_IFINDEX + 7, 256);   /* foreign dp */
    build_packet_upcall(&mine, MOCK_DP_IFINDEX, 256);        /* this dp */
    mock_queue_packet(m, &other);
    mock_queue_packet(m, &mine);

    ofpbuf_use_stub(&buf, stub, sizeof stub);
    memset(&upcall, 0, sizeof upcall);
    error = dpif_recv(dpif, 0, &upcall, &buf);
    CHECK(error == 0);                       /* the foreign one was drained */
    CHECK(upcall.type == DPIF_UC_ACTION);

    ofpbuf_clear(&buf);
    CHECK(dpif_recv(dpif, 0, &upcall, &buf) == EAGAIN);
    ofpbuf_uninit(&buf);
}

/* A batch of N dumped flows must each stay valid and distinct.  The transport
 * reuses one buffer per record, so a loop that kept decoded pointers would
 * return N aliases of the last record.  Program three flows with distinct keys
 * and check they differ. */
static void
test_flow_dump_multi_record(struct dpif *dpif, struct mock_kernel *m)
{
    struct dpif_flow_dump_types types = { .ovs_flows = true };
    struct dpif_flow_dump *dump;
    struct dpif_flow_dump_thread *thread;
    struct dpif_flow batch[8];
    uint8_t keys[8][256];       /* copied out while the thread is alive */
    size_t key_lens[8];
    int total = 0;
    int n, i;

    printf("test_flow_dump_multi_record:\n");
    mock_reset_content(m);
    m->n_flow = 3;
    build_flow_record(&m->flow[0], 100, false);
    build_flow_record(&m->flow[1], 200, false);
    build_flow_record(&m->flow[2], 300, false);

    dump = dpif_flow_dump_create(dpif, false, &types);
    thread = dpif_flow_dump_thread_create(dump);

    /* A returned flow's key points into the thread's batch buffer and is only
     * valid until the next dump_next / thread_destroy, so snapshot the bytes
     * here.  Aliasing (the bug) makes every key in the batch identical. */
    while ((n = dpif_flow_dump_next(thread, batch, ARRAY_SIZE(batch))) > 0) {
        for (i = 0; i < n && total < ARRAY_SIZE(keys); i++) {
            ovs_assert(batch[i].key_len <= sizeof keys[0]);
            memcpy(keys[total], batch[i].key, batch[i].key_len);
            key_lens[total] = batch[i].key_len;
            total++;
        }
    }

    dpif_flow_dump_thread_destroy(thread);
    CHECK(dpif_flow_dump_destroy(dump) == 0);

    CHECK(total == 3);
    if (total == 3) {
        CHECK(key_lens[0] > 0);
        CHECK(key_lens[0] == key_lens[1] && key_lens[1] == key_lens[2]);
        CHECK(memcmp(keys[0], keys[1], key_lens[0]) != 0);
        CHECK(memcmp(keys[1], keys[2], key_lens[1]) != 0);
        CHECK(memcmp(keys[0], keys[2], key_lens[0]) != 0);
    }
}

/* The flow dump terminates with an NLMSG_DONE record (unlike vport/datapath
 * dumps, which end with a zero-length read).  The transport must treat that
 * record as end-of-dump, not feed it back as a flow whose decode then fails and
 * makes dpif_flow_dump_destroy report EINVAL.  Covers the zero-flow case (the
 * lone record is the terminator) and a non-empty dump. */
static void
test_flow_dump_done_terminator(struct dpif *dpif, struct mock_kernel *m)
{
    struct dpif_flow_dump_types types = { .ovs_flows = true };
    struct dpif_flow_dump *dump;
    struct dpif_flow_dump_thread *thread;
    struct dpif_flow batch[8];
    int total, n;

    printf("test_flow_dump_done_terminator:\n");

    /* Zero flows: the only record read is the NLMSG_DONE terminator. */
    mock_reset_content(m);
    m->flow_dump_done = true;
    m->n_flow = 0;
    dump = dpif_flow_dump_create(dpif, false, &types);
    thread = dpif_flow_dump_thread_create(dump);
    total = 0;
    while ((n = dpif_flow_dump_next(thread, batch, ARRAY_SIZE(batch))) > 0) {
        total += n;
    }
    dpif_flow_dump_thread_destroy(thread);
    CHECK(total == 0);
    CHECK(dpif_flow_dump_destroy(dump) == 0);   /* NLMSG_DONE is not an error */

    /* Two flows followed by the NLMSG_DONE terminator. */
    mock_reset_content(m);
    m->flow_dump_done = true;
    m->n_flow = 2;
    build_flow_record(&m->flow[0], 100, false);
    build_flow_record(&m->flow[1], 200, false);
    dump = dpif_flow_dump_create(dpif, false, &types);
    thread = dpif_flow_dump_thread_create(dump);
    total = 0;
    while ((n = dpif_flow_dump_next(thread, batch, ARRAY_SIZE(batch))) > 0) {
        total += n;
    }
    dpif_flow_dump_thread_destroy(thread);
    CHECK(total == 2);
    CHECK(dpif_flow_dump_destroy(dump) == 0);
}

/* Each dump must run on its own kernel handle, because the dump cursor is per
 * handle.  Sharing the dpif's channel would race concurrent transactions and
 * parallel revalidator dumps.  Observe that a flow dump opens a second handle
 * (peak concurrency rises above the lone main channel). */
static void
test_per_dump_channel(struct dpif *dpif, struct mock_kernel *m)
{
    struct dpif_flow_dump_types types = { .ovs_flows = true };
    struct dpif_flow_dump *dump;
    struct dpif_flow_dump_thread *thread;
    struct dpif_flow batch[8];

    printf("test_per_dump_channel:\n");
    mock_reset_content(m);
    m->n_flow = 1;
    build_flow_record(&m->flow[0], 111, false);

    /* Baseline: only the dpif's main channel is open. */
    CHECK(m->n_open == 1);
    m->peak_open = m->n_open;

    dump = dpif_flow_dump_create(dpif, false, &types);
    thread = dpif_flow_dump_thread_create(dump);
    while (dpif_flow_dump_next(thread, batch, ARRAY_SIZE(batch)) > 0) {
        /* drain */
    }
    /* The dump's dedicated handle was open during the walk. */
    CHECK(m->peak_open >= 2);

    dpif_flow_dump_thread_destroy(thread);
    CHECK(dpif_flow_dump_destroy(dump) == 0);
}

/* A malformed record encountered mid-dump is reported by flow_dump_destroy (the
 * dump interface defers all error reporting to it). */
static void
test_flow_dump_deferred_error(struct dpif *dpif, struct mock_kernel *m)
{
    struct dpif_flow_dump_types types = { .ovs_flows = true };
    struct dpif_flow_dump *dump;
    struct dpif_flow_dump_thread *thread;
    struct dpif_flow batch[8];

    printf("test_flow_dump_deferred_error:\n");
    mock_reset_content(m);
    m->n_flow = 2;
    build_flow_record(&m->flow[0], 123, false);   /* good */
    build_flow_bad(&m->flow[1]);                   /* undecodable */

    dump = dpif_flow_dump_create(dpif, false, &types);
    thread = dpif_flow_dump_thread_create(dump);
    while (dpif_flow_dump_next(thread, batch, ARRAY_SIZE(batch)) > 0) {
        /* drain */
    }
    dpif_flow_dump_thread_destroy(thread);
    CHECK(dpif_flow_dump_destroy(dump) == EINVAL);
}

/* A dump opens its own channel; if that device open fails, the error must
 * propagate: flow_dump_next yields nothing and flow_dump_destroy returns it. */
static void
test_flow_dump_open_failure(struct dpif *dpif, struct mock_kernel *m)
{
    struct dpif_flow_dump_types types = { .ovs_flows = true };
    struct dpif_flow_dump *dump;
    struct dpif_flow_dump_thread *thread;
    struct dpif_flow batch[8];
    int n_flows = 0;

    printf("test_flow_dump_open_failure:\n");
    mock_reset_content(m);
    m->n_flow = 1;
    build_flow_record(&m->flow[0], 55, false);

    m->fail_open = true;        /* the dump's dedicated channel open fails */
    dump = dpif_flow_dump_create(dpif, false, &types);
    thread = dpif_flow_dump_thread_create(dump);
    while (dpif_flow_dump_next(thread, batch, ARRAY_SIZE(batch)) > 0) {
        n_flows++;
    }
    dpif_flow_dump_thread_destroy(thread);
    CHECK(n_flows == 0);
    CHECK(dpif_flow_dump_destroy(dump) == ENODEV);
    m->fail_open = false;
    /* The main channel is still healthy. */
    CHECK(dpif_flow_flush(dpif) == 0);
}

/* FLOW_GET copies the reply's key/mask/actions into the caller's buffer.  All
 * ofpbuf_put()s must happen before the pointers are captured (a later put can
 * realloc and move the base) and the copy must be unconditional.  A rich flow
 * plus a tiny output buffer forces a realloc; ASAN catches a dangling read, and
 * the field checks catch a wrong/missing copy. */
static void
test_flow_get_hit(struct dpif *dpif, struct mock_kernel *m)
{
    struct dpif_flow_get get;
    struct dpif_flow result;
    struct dpif_op op;
    struct dpif_op *ops[1];
    uint64_t keybuf[64 / 8];     /* deliberately tiny: forces realloc on put */
    struct ofpbuf buffer;
    uint64_t reqkey_stub[64 / 8];
    struct ofpbuf reqkey;
    const struct nlattr *in_port;

    printf("test_flow_get_hit:\n");
    mock_reset_content(m);
    m->flow_reply = FR_ECHO;
    build_flow_record(&m->flow_echo, 42, true);

    /* A minimal request key (the mock ignores it and returns flow_echo). */
    ofpbuf_use_stub(&reqkey, reqkey_stub, sizeof reqkey_stub);
    nl_msg_put_u32(&reqkey, OVS_KEY_ATTR_IN_PORT, 42);

    ofpbuf_use_stub(&buffer, keybuf, sizeof keybuf);
    memset(&result, 0, sizeof result);
    memset(&get, 0, sizeof get);
    get.key = reqkey.data;
    get.key_len = reqkey.size;
    get.buffer = &buffer;
    get.flow = &result;

    memset(&op, 0, sizeof op);
    op.type = DPIF_OP_FLOW_GET;
    op.flow_get = get;
    ops[0] = &op;
    dpif_operate(dpif, ops, 1, DPIF_OFFLOAD_NEVER);

    CHECK(op.error == 0);
    CHECK(result.key_len > 0);
    CHECK(result.mask != NULL && result.mask_len > 0);
    CHECK(result.actions != NULL && result.actions_len == 1500);
    /* Dereference every copied region: a dangling pointer left by a realloc
     * between captures is a heap-use-after-free here (caught under ASAN), and a
     * corrupt copy fails the content checks even without ASAN. */
    in_port = nl_attr_find__(result.key, result.key_len, OVS_KEY_ATTR_IN_PORT);
    CHECK(in_port != NULL && nl_attr_get_u32(in_port) == 42);
    if (result.actions && result.actions_len == 1500) {
        const uint8_t *acts = (const uint8_t *) result.actions;
        bool all_cd = true;
        size_t k;
        for (k = 0; k < result.actions_len; k++) {
            if (acts[k] != 0xCD) {
                all_cd = false;
                break;
            }
        }
        CHECK(all_cd);
    }
    if (result.mask && result.mask_len) {
        const struct nlattr *m_in =
            nl_attr_find__(result.mask, result.mask_len, OVS_KEY_ATTR_IN_PORT);
        CHECK(m_in != NULL && nl_attr_get_u32(m_in) == 0xffffffff);
    }
    CHECK(result.stats.n_packets == 5 && result.stats.n_bytes == 500);

    ofpbuf_uninit(&buffer);
    ofpbuf_uninit(&reqkey);
}

/* FLOW_GET with no caller storage (get->buffer == NULL): the provider must not
 * hand back key/mask/actions pointers into the freed reply.  They are returned
 * as NULL while stats stay valid.  Without the guard these dangle (ASAN). */
static void
test_flow_get_null_buffer(struct dpif *dpif, struct mock_kernel *m)
{
    struct dpif_flow_get get;
    struct dpif_flow result;
    struct dpif_op op;
    struct dpif_op *ops[1];
    uint64_t reqkey_stub[64 / 8];
    struct ofpbuf reqkey;

    printf("test_flow_get_null_buffer:\n");
    mock_reset_content(m);
    m->flow_reply = FR_ECHO;
    build_flow_record(&m->flow_echo, 42, true);

    ofpbuf_use_stub(&reqkey, reqkey_stub, sizeof reqkey_stub);
    nl_msg_put_u32(&reqkey, OVS_KEY_ATTR_IN_PORT, 42);

    memset(&result, 0, sizeof result);
    memset(&get, 0, sizeof get);
    get.key = reqkey.data;
    get.key_len = reqkey.size;
    get.buffer = NULL;
    get.flow = &result;

    memset(&op, 0, sizeof op);
    op.type = DPIF_OP_FLOW_GET;
    op.flow_get = get;
    ops[0] = &op;
    dpif_operate(dpif, ops, 1, DPIF_OFFLOAD_NEVER);

    CHECK(op.error == 0);
    CHECK(result.key == NULL && result.key_len == 0);
    CHECK(result.mask == NULL && result.mask_len == 0);
    CHECK(result.actions == NULL && result.actions_len == 0);
    CHECK(result.stats.n_packets == 5 && result.stats.n_bytes == 500);

    ofpbuf_uninit(&reqkey);
}

/* A genuine miss is the in-band NLMSG_ERROR -> ENOENT; a non-NULL reply that
 * fails to decode is a protocol error (EINVAL), not a miss reported as
 * ENOENT. */
static void
test_flow_get_miss_vs_malformed(struct dpif *dpif, struct mock_kernel *m)
{
    struct dpif_flow_get get;
    struct dpif_flow result;
    struct dpif_op op;
    struct dpif_op *ops[1];
    uint64_t buf_stub[256 / 8];
    struct ofpbuf buffer;
    uint64_t reqkey_stub[64 / 8];
    struct ofpbuf reqkey;

    printf("test_flow_get_miss_vs_malformed:\n");
    mock_reset_content(m);
    build_flow_bad(&m->flow_bad);

    ofpbuf_use_stub(&reqkey, reqkey_stub, sizeof reqkey_stub);
    nl_msg_put_u32(&reqkey, OVS_KEY_ATTR_IN_PORT, 9);

    for (int malformed = 0; malformed <= 1; malformed++) {
        m->flow_reply = malformed ? FR_MALFORMED : FR_ENOENT;

        ofpbuf_use_stub(&buffer, buf_stub, sizeof buf_stub);
        memset(&result, 0, sizeof result);
        memset(&get, 0, sizeof get);
        get.key = reqkey.data;
        get.key_len = reqkey.size;
        get.buffer = &buffer;
        get.flow = &result;

        memset(&op, 0, sizeof op);
        op.type = DPIF_OP_FLOW_GET;
        op.flow_get = get;
        ops[0] = &op;
        dpif_operate(dpif, ops, 1, DPIF_OFFLOAD_NEVER);

        CHECK(op.error == (malformed ? EINVAL : ENOENT));
        ofpbuf_uninit(&buffer);
    }
    ofpbuf_uninit(&reqkey);
}

/* A stats-requested FLOW_PUT must surface a bad/missing echo as an error, not
 * report success with zeroed stats.  A good echo must populate the stats. */
static void
test_flow_put_stats(struct dpif *dpif, struct mock_kernel *m)
{
    struct dpif_flow_stats stats;
    struct dpif_flow_put put;
    struct dpif_op op;
    struct dpif_op *ops[1];
    uint64_t keybuf[64 / 8];
    struct ofpbuf key;

    printf("test_flow_put_stats:\n");

    ofpbuf_use_stub(&key, keybuf, sizeof keybuf);
    nl_msg_put_u32(&key, OVS_KEY_ATTR_IN_PORT, 1);

    /* Missing echo -> error (not success-with-zeros). */
    mock_reset_content(m);
    m->flow_reply = FR_EMPTYECHO;
    memset(&stats, 0xab, sizeof stats);
    memset(&put, 0, sizeof put);
    put.flags = DPIF_FP_CREATE;
    put.key = key.data;
    put.key_len = key.size;
    put.stats = &stats;
    memset(&op, 0, sizeof op);
    op.type = DPIF_OP_FLOW_PUT;
    op.flow_put = put;
    ops[0] = &op;
    dpif_operate(dpif, ops, 1, DPIF_OFFLOAD_NEVER);
    CHECK(op.error == EINVAL);

    /* Good echo -> stats populated. */
    mock_reset_content(m);
    m->flow_reply = FR_ECHO;
    build_flow_record(&m->flow_echo, 1, true);
    memset(&stats, 0, sizeof stats);
    memset(&put, 0, sizeof put);
    put.flags = DPIF_FP_CREATE;
    put.key = key.data;
    put.key_len = key.size;
    put.stats = &stats;
    memset(&op, 0, sizeof op);
    op.type = DPIF_OP_FLOW_PUT;
    op.flow_put = put;
    ops[0] = &op;
    dpif_operate(dpif, ops, 1, DPIF_OFFLOAD_NEVER);
    CHECK(op.error == 0);
    CHECK(stats.n_packets == 5 && stats.n_bytes == 500);

    ofpbuf_uninit(&key);
}

/* The FLOW_DEL stats path mirrors FLOW_PUT: a bad/missing echo must surface as
 * an error, and a good echo must populate the stats. */
static void
test_flow_del_stats(struct dpif *dpif, struct mock_kernel *m)
{
    struct dpif_flow_stats stats;
    struct dpif_flow_del del;
    struct dpif_op op;
    struct dpif_op *ops[1];
    uint64_t keybuf[64 / 8];
    struct ofpbuf key;

    printf("test_flow_del_stats:\n");

    ofpbuf_use_stub(&key, keybuf, sizeof keybuf);
    nl_msg_put_u32(&key, OVS_KEY_ATTR_IN_PORT, 1);

    /* Missing echo -> error. */
    mock_reset_content(m);
    m->flow_reply = FR_EMPTYECHO;
    memset(&stats, 0xab, sizeof stats);
    memset(&del, 0, sizeof del);
    del.key = key.data;
    del.key_len = key.size;
    del.stats = &stats;
    memset(&op, 0, sizeof op);
    op.type = DPIF_OP_FLOW_DEL;
    op.flow_del = del;
    ops[0] = &op;
    dpif_operate(dpif, ops, 1, DPIF_OFFLOAD_NEVER);
    CHECK(op.error == EINVAL);

    /* Good echo -> stats populated. */
    mock_reset_content(m);
    m->flow_reply = FR_ECHO;
    build_flow_record(&m->flow_echo, 1, true);
    memset(&stats, 0, sizeof stats);
    memset(&del, 0, sizeof del);
    del.key = key.data;
    del.key_len = key.size;
    del.stats = &stats;
    memset(&op, 0, sizeof op);
    op.type = DPIF_OP_FLOW_DEL;
    op.flow_del = del;
    ops[0] = &op;
    dpif_operate(dpif, ops, 1, DPIF_OFFLOAD_NEVER);
    CHECK(op.error == 0);
    CHECK(stats.n_packets == 5 && stats.n_bytes == 500);

    ofpbuf_uninit(&key);
}

/* Reproduces the live revalidator failure: after a terse flow dump the
 * revalidator deletes stale flows by UFID only (dpif_flow_del.terse = true,
 * .key = NULL).  The provider then omits OVS_FLOW_ATTR_KEY and sends only
 * OVS_FLOW_ATTR_UFID -- exactly like dpif-netlink.  The ovsext kernel, however,
 * makes OVS_FLOW_ATTR_KEY mandatory and has no UFID lookup, so it rejects the
 * request with EINVAL (the `failed to flow_del (Invalid argument) ufid:...`
 * spam).  The fix belongs in the kernel (add UFID lookup); userspace is correct. */
static void
test_flow_del_ufid_terse(struct dpif *dpif, struct mock_kernel *m)
{
    struct dpif_flow_del del;
    struct dpif_op op;
    struct dpif_op *ops[1];
    ovs_u128 ufid = { .u32 = { 1, 2, 3, 4 } };

    printf("test_flow_del_ufid_terse:\n");

    mock_reset_content(m);
    m->flow_require_key = true;          /* model current ovsext nlFlowPolicy */
    memset(&del, 0, sizeof del);
    del.ufid = &ufid;
    del.terse = true;                    /* UFID-only delete: no key */
    memset(&op, 0, sizeof op);
    op.type = DPIF_OP_FLOW_DEL;
    op.flow_del = del;
    ops[0] = &op;
    dpif_operate(dpif, ops, 1, DPIF_OFFLOAD_NEVER);

    /* The provider put a UFID on the wire and (correctly, per the dpif
     * contract) omitted the key... */
    CHECK(m->flow_req_had_ufid);
    CHECK(!m->flow_req_had_key);
    /* ...and the key-requiring kernel rejected it -- the reproduced bug. */
    CHECK(op.error == EINVAL);
}

/* The class 'operate' is the 3-arg contract; dpif_operate resolves offload
 * before dispatch.  Drive a multi-op batch through the public path to exercise
 * it end to end. */
static void
test_operate_batch(struct dpif *dpif, struct mock_kernel *m)
{
    struct dpif_flow_put put;
    struct dpif_op op[2];
    struct dpif_op *ops[2];
    uint64_t keybuf[64 / 8];
    struct ofpbuf key;
    int i;

    printf("test_operate_batch:\n");
    mock_reset_content(m);

    ofpbuf_use_stub(&key, keybuf, sizeof keybuf);
    nl_msg_put_u32(&key, OVS_KEY_ATTR_IN_PORT, 1);

    for (i = 0; i < 2; i++) {
        memset(&put, 0, sizeof put);
        put.flags = DPIF_FP_CREATE;
        put.key = key.data;
        put.key_len = key.size;
        memset(&op[i], 0, sizeof op[i]);
        op[i].type = DPIF_OP_FLOW_PUT;
        op[i].flow_put = put;
        ops[i] = &op[i];
    }
    dpif_operate(dpif, ops, 2, DPIF_OFFLOAD_NEVER);
    CHECK(op[0].error == 0);
    CHECK(op[1].error == 0);

    ofpbuf_uninit(&key);
}

/* port_poll lazily subscribes to the vport event channel (returning ENOBUFS so
 * ofproto re-dumps), then surfaces each queued OVS_VPORT_CMD_NEW/DEL for this
 * datapath as a port name; events for another datapath are filtered out. */
static void
test_port_poll(struct dpif *dpif, struct mock_kernel *m)
{
    char *devname;
    int error;

    printf("test_port_poll:\n");
    mock_reset_content(m);

    /* First call subscribes and asks ofproto to reconcile the full port set. */
    devname = NULL;
    error = dpif_port_poll(dpif, &devname);
    CHECK(error == ENOBUFS);

    /* A matching NEW event surfaces its port name. */
    mock_queue_vport_event(m, MOCK_DP_IFINDEX, OVS_VPORT_CMD_NEW, 7, "vport7");
    devname = NULL;
    error = dpif_port_poll(dpif, &devname);
    CHECK(error == 0);
    CHECK(devname != NULL && !strcmp(devname, "vport7"));
    free(devname);

    /* A DEL for this datapath also surfaces. */
    mock_queue_vport_event(m, MOCK_DP_IFINDEX, OVS_VPORT_CMD_DEL, 7, "vport7");
    devname = NULL;
    CHECK(dpif_port_poll(dpif, &devname) == 0);
    CHECK(devname != NULL && !strcmp(devname, "vport7"));
    free(devname);

    /* An event for another datapath is drained and not reported. */
    mock_queue_vport_event(m, MOCK_DP_IFINDEX + 9, OVS_VPORT_CMD_NEW, 3, "other");
    devname = NULL;
    CHECK(dpif_port_poll(dpif, &devname) == EAGAIN);

    /* Drained queue: no change. */
    devname = NULL;
    CHECK(dpif_port_poll(dpif, &devname) == EAGAIN);

    /* port_poll_wait arms the event pend on the notifier channel; the kernel
     * validates that command's dp_ifindex too, so it must carry the resolved
     * index (the mock flags a 0/foreign-dp pend). */
    dpif_port_poll_wait(dpif);
    CHECK(!m->validate_dp_failed);
}

/* Conntrack zone-limit management round-trips through the OVS_CT_LIMIT genl
 * family: SET records a per-zone limit, GET reads it back with the current
 * count, DEL removes it, and an empty GET request targets the default zone.
 * ct_get_features reports no extra capabilities on Windows. */
static void
test_ct_limits(struct dpif *dpif, struct mock_kernel *m)
{
    struct ovs_list req = OVS_LIST_INITIALIZER(&req);
    struct ovs_list reply = OVS_LIST_INITIALIZER(&reply);
    struct ct_dpif_zone_limit *zl;
    enum ct_features feat = 0xdead;

    printf("test_ct_limits:\n");
    m->ct_last_cmd = -1;
    m->ct_zone = 0;
    m->ct_limit = 0;
    m->ct_count = 0;

    /* SET zone 5 -> limit 200 reaches the kernel as CMD_SET. */
    ct_dpif_push_zone_limit(&req, 5, 200, 0);
    CHECK(ct_dpif_set_limits(dpif, &req) == 0);
    CHECK(m->ct_last_cmd == OVS_CT_LIMIT_CMD_SET);
    CHECK(m->ct_zone == 5);
    CHECK(m->ct_limit == 200);
    ct_dpif_free_zone_limits(&req);

    /* GET zone 5 reads back the limit and the live count. */
    m->ct_count = 7;
    ovs_list_init(&req);
    ct_dpif_push_zone_limit(&req, 5, 0, 0);
    CHECK(ct_dpif_get_limits(dpif, &req, &reply) == 0);
    CHECK(m->ct_last_cmd == OVS_CT_LIMIT_CMD_GET);
    CHECK(!ovs_list_is_empty(&reply));
    zl = CONTAINER_OF(ovs_list_front(&reply), struct ct_dpif_zone_limit, node);
    CHECK(zl->zone == 5);
    CHECK(zl->limit == 200);
    CHECK(zl->count == 7);
    ct_dpif_free_zone_limits(&req);
    ct_dpif_free_zone_limits(&reply);

    /* DEL zone 5 reaches the kernel as CMD_DEL. */
    ovs_list_init(&req);
    ct_dpif_push_zone_limit(&req, 5, 0, 0);
    CHECK(ct_dpif_del_limits(dpif, &req) == 0);
    CHECK(m->ct_last_cmd == OVS_CT_LIMIT_CMD_DEL);
    CHECK(m->ct_zone == 5);
    ct_dpif_free_zone_limits(&req);

    /* An empty GET request lists all zones: the kernel enumerates the default
     * zone plus each configured zone, so the reply carries several records.
     * Exercise the multi-record parse (default first, then zone 7). */
    ovs_list_init(&reply);
    CHECK(ct_dpif_get_limits(dpif, &req, &reply) == 0);
    CHECK(!ovs_list_is_empty(&reply));
    int n_zones = 0;
    bool saw_default = false, saw_zone7 = false;
    LIST_FOR_EACH (zl, node, &reply) {
        n_zones++;
        if (zl->zone == OVS_ZONE_LIMIT_DEFAULT_ZONE) {
            saw_default = true;
        } else if (zl->zone == 7) {
            saw_zone7 = true;
            CHECK(zl->limit == 77);
            CHECK(zl->count == 7);
        }
    }
    CHECK(n_zones == 2);
    CHECK(saw_default);
    CHECK(saw_zone7);
    ct_dpif_free_zone_limits(&reply);

    /* Windows advertises no extra conntrack features. */
    CHECK(ct_dpif_get_features(dpif, &feat) == 0);
    CHECK(feat == 0);
}

/* Datapath feature negotiation: the open requested OVS_DP_F_UNALIGNED |
 * OVS_DP_F_VPORT_PIDS, the kernel stored and echoed them, and
 * get_features/get_stats reflect the negotiated mask.  An unsupported bit is
 * rejected with EOPNOTSUPP, and a kernel that does not echo features falls back
 * to the "no megaflow stats" sentinel. */
static void
test_feature_negotiation(struct dpif *dpif, struct mock_kernel *m)
{
    uint32_t want = OVS_DP_F_UNALIGNED | OVS_DP_F_VPORT_PIDS;
    struct dpif_dp_stats stats;

    mock_reset_content(m);

    /* The request carries USER_FEATURES (proven by the kernel storing exactly
     * the requested mask), the reply echoes it, and get_features returns the
     * cached value. */
    CHECK(dpif_set_features(dpif, want) == 0);
    CHECK(m->dp_user_features == want);
    CHECK(dpif_get_features(dpif) == want);

    /* MEGAFLOW_STATS present -> get_stats reports the single implicit mask, not
     * the UINT32_MAX "no megaflow stats" sentinel. */
    CHECK(dpif_get_dp_stats(dpif, &stats) == 0);
    CHECK(stats.n_masks == 1);

    /* An unsupported bit is rejected and leaves the negotiated mask intact. */
    CHECK(dpif_set_features(dpif, OVS_DP_F_TC_RECIRC_SHARING) == EOPNOTSUPP);
    CHECK(dpif_get_features(dpif) == want);

    /* Kernel without feature echo: set_features sees the bit never come back
     * (EOPNOTSUPP) and get_stats falls back to the sentinel. */
    m->dp_echo_features = false;
    CHECK(dpif_set_features(dpif, want) == EOPNOTSUPP);
    CHECK(dpif_get_dp_stats(dpif, &stats) == 0);
    CHECK(stats.n_masks == UINT32_MAX);
}

/* OpenFlow meters round-trip through the OVS_METER genl family: features
 * advertises the kernel's limits, a single-band DROP meter is set (and the
 * request marshals id/rate/burst correctly), and get/del read back stats. */
static void
test_meters(struct dpif *dpif, struct mock_kernel *m)
{
    struct ofputil_meter_features features;
    struct ofputil_meter_band band = { .type = OFPMBT13_DROP, .rate = 1000,
                                       .burst_size = 100 };
    struct ofputil_meter_config config = {
        .flags = OFPMF13_KBPS | OFPMF13_BURST, .n_bands = 1, .bands = &band };
    struct ofputil_meter_band_stats band_stats[2];
    struct ofputil_meter_stats stats = { .bands = band_stats };
    ofproto_meter_id mid = { .uint32 = 7 };

    printf("test_meters:\n");
    m->meter_last_cmd = -1;

    /* FEATURES advertises the kernel's truthful limits and the DROP band. */
    memset(&features, 0, sizeof features);
    dpif_meter_get_features(dpif, &features);
    CHECK(m->meter_last_cmd == OVS_METER_CMD_FEATURES);
    CHECK(features.max_meters == 32);
    CHECK(features.max_bands == 1);
    CHECK((features.band_types & (1 << OFPMBT13_DROP)) != 0);
    CHECK(features.capabilities != 0);

    /* SET a single-band DROP meter; the request must carry id/rate/burst. */
    CHECK(dpif_meter_set(dpif, mid, &config) == 0);
    CHECK(m->meter_last_cmd == OVS_METER_CMD_SET);
    CHECK(m->meter_id == 7);
    CHECK(m->meter_n_bands == 1);
    CHECK(m->meter_band_type == OVS_METER_BAND_TYPE_DROP);
    CHECK(m->meter_band_rate == 1000);
    CHECK(m->meter_band_burst == 100);

    /* GET reads back meter and per-band stats. */
    memset(band_stats, 0, sizeof band_stats);
    CHECK(dpif_meter_get(dpif, mid, &stats, 2) == 0);
    CHECK(m->meter_last_cmd == OVS_METER_CMD_GET);
    CHECK(stats.packet_in_count == 10);
    CHECK(stats.byte_in_count == 1000);
    CHECK(stats.n_bands == 1);
    CHECK(stats.bands[0].packet_count == 3);
    CHECK(stats.bands[0].byte_count == 300);

    /* DEL reaches the kernel as CMD_DEL and still returns stats. */
    memset(band_stats, 0, sizeof band_stats);
    CHECK(dpif_meter_del(dpif, mid, &stats, 2) == 0);
    CHECK(m->meter_last_cmd == OVS_METER_CMD_DEL);
    CHECK(stats.n_bands == 1);
}

/* The "system" netdev provider refreshes its cached admin flags / MAC / MTU /
 * carrier from the kernel in netdev_windows_run().  Construct one against the
 * mock, change the kernel-reported state, run one refresh tick, and confirm the
 * new MAC/MTU are committed, carrier follows the link bit, and change_seq is
 * bumped -- exercising the lock-free snapshot/gather/commit path. */
static void
test_netdev_refresh(struct mock_kernel *m)
{
    const struct eth_addr mac_a = { .ea = { 0x02, 0, 0, 0, 0, 0x0a } };
    const struct eth_addr mac_b = { .ea = { 0x02, 0, 0, 0, 0, 0x0b } };
    struct netdev *netdev;
    struct eth_addr got;
    uint64_t seq0;
    int mtu;

    printf("test_netdev_refresh:\n");
    mock_reset_content(m);

    /* Construct-time state: admin-up, link-up, MAC A, MTU 1400. */
    m->nd_present = true;
    m->nd_type = OVS_VPORT_TYPE_NETDEV;
    m->nd_port_no = 7;
    m->nd_mac = mac_a;
    m->nd_mtu = 1400;
    m->nd_flags = OVS_WIN_NETDEV_IFF_UP | OVS_WIN_NETDEV_IFF_RUNNING;

    CHECK(netdev_open("nd-test", "system", &netdev) == 0);
    CHECK(netdev_get_etheraddr(netdev, &got) == 0 && eth_addr_equals(got, mac_a));
    seq0 = netdev_get_change_seq(netdev);

    /* The kernel now reports a new MAC and MTU and the link going down (no
     * RUNNING).  'nd-test' has no host interface matching its synthetic MAC, so
     * carrier resolves purely from the kernel link state. */
    m->nd_mac = mac_b;
    m->nd_mtu = 1500;
    m->nd_flags = OVS_WIN_NETDEV_IFF_UP;

    /* Jump past the 1s refresh gate so this run() executes regardless of any
     * earlier test having armed netdev_windows_next_refresh. */
    timeval_warp(2000);
    netdev_windows_class.run(&netdev_windows_class);

    CHECK(netdev_get_etheraddr(netdev, &got) == 0 && eth_addr_equals(got, mac_b));
    CHECK(netdev_get_mtu(netdev, &mtu) == 0 && mtu == 1500);
    CHECK(!netdev_get_carrier(netdev));
    CHECK(netdev_get_change_seq(netdev) != seq0);

    netdev_close(netdev);

    /* A userspace-first ghost (the device is absent at construct) has no kernel
     * MTU yet; get_mtu must report it unknown rather than a bogus 0. */
    m->nd_present = false;
    CHECK(netdev_open("nd-ghost", "system", &netdev) == 0);
    CHECK(netdev_get_mtu(netdev, &mtu) != 0);
    netdev_close(netdev);
}

/* Concurrency for the refactored refresh: netdev_windows_run() now does its
 * per-port I/O without holding netdev_windows_list_mutex and re-takes it only to
 * commit, so a reader calling netdev APIs must coexist with it.  A reader thread
 * hammers the cached fields while the main thread drives many refresh/commit
 * cycles (time is warped past the 1s gate), each flipping the kernel-reported
 * MAC.  The commit writes the 6-byte MAC under the lock, so the locked reader
 * must only ever see a fully-written MAC (0xAA.. or 0xBB..); a torn value means
 * the lock was dropped.  The test also wedges if the lock discipline can
 * deadlock against a concurrent reader. */
#define NDC_REFRESH_ITERS 2000

static struct netdev *ndc_netdev;
static const struct eth_addr ndc_mac_a = { .ea = { 0xaa, 0xaa, 0xaa, 0xaa,
                                                   0xaa, 0xaa } };
static const struct eth_addr ndc_mac_b = { .ea = { 0xbb, 0xbb, 0xbb, 0xbb,
                                                   0xbb, 0xbb } };
static atomic_bool ndc_stop;
static atomic_bool ndc_torn;
static atomic_bool ndc_saw_a;       /* reader observed MAC A while refreshing. */
static atomic_bool ndc_saw_b;       /* reader observed MAC B while refreshing. */

static void *
ndc_reader(void *arg OVS_UNUSED)
{
    bool stop = false;

    while (!stop) {
        struct eth_addr got;
        int mtu;

        if (netdev_get_etheraddr(ndc_netdev, &got) == 0) {
            if (eth_addr_equals(got, ndc_mac_a)) {
                atomic_store_relaxed(&ndc_saw_a, true);
            } else if (eth_addr_equals(got, ndc_mac_b)) {
                atomic_store_relaxed(&ndc_saw_b, true);
            } else {
                atomic_store_relaxed(&ndc_torn, true);
            }
        }
        netdev_get_mtu(ndc_netdev, &mtu);
        netdev_get_carrier(ndc_netdev);
        atomic_read_relaxed(&ndc_stop, &stop);
    }
    return NULL;
}

static void
test_netdev_refresh_concurrent(struct mock_kernel *m)
{
    pthread_t reader;
    bool torn, saw_a, saw_b;
    int i;

    printf("test_netdev_refresh_concurrent:\n");
    mock_reset_content(m);
    m->nd_present = true;
    m->nd_type = OVS_VPORT_TYPE_NETDEV;
    m->nd_port_no = 9;
    m->nd_mac = ndc_mac_a;
    m->nd_mtu = 1400;
    m->nd_flags = OVS_WIN_NETDEV_IFF_UP | OVS_WIN_NETDEV_IFF_RUNNING;

    CHECK(netdev_open("nd-conc", "system", &ndc_netdev) == 0);

    atomic_init(&ndc_stop, false);
    atomic_init(&ndc_torn, false);
    atomic_init(&ndc_saw_a, false);
    atomic_init(&ndc_saw_b, false);
    reader = ovs_thread_create("nd-reader", ndc_reader, NULL);

    for (i = 0; i < NDC_REFRESH_ITERS; i++) {
        m->nd_mac = (i & 1) ? ndc_mac_b : ndc_mac_a;
        netdev_windows_class.run(&netdev_windows_class);
        /* Jump past the refresh gate so the next run() actually executes. */
        timeval_warp(2000);
    }

    atomic_store_relaxed(&ndc_stop, true);
    xpthread_join(reader, NULL);

    atomic_read_relaxed(&ndc_torn, &torn);
    atomic_read_relaxed(&ndc_saw_a, &saw_a);
    atomic_read_relaxed(&ndc_saw_b, &saw_b);
    CHECK(!torn);            /* the reader never saw a partially-written MAC. */
    /* The reader observed BOTH alternating MACs, proving it actually overlapped
     * the refresh/commit cycles (not merely ran before or after them). */
    CHECK(saw_a && saw_b);

    /* The last iteration set MAC B; if it committed, the gate was really
     * defeated and run() executed every iteration (not skipped as a no-op). */
    struct eth_addr final_mac;
    CHECK(netdev_get_etheraddr(ndc_netdev, &final_mac) == 0
          && eth_addr_equals(final_mac, ndc_mac_b));

    netdev_close(ndc_netdev);
}

int
main(int argc, char *argv[])
{
    static struct mock_kernel mock;
    static struct ovsext_transport mock_transport;
    struct dpif *dpif;
    int error;

#if defined(_MSC_VER) && defined(_DEBUG)
    /* Route the Debug CRT's assert / runtime-check (/RTC1) reports to stderr
     * instead of a modal dialog, so the test runs unattended under CTest/CI
     * rather than blocking on an invisible message box.  These APIs exist only
     * in the MSVC Debug CRT; other toolchains/Release builds emit no such
     * dialog. */
    for (int rt = 0; rt <= _CRT_ASSERT; rt++) {
        _CrtSetReportMode(rt, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(rt, _CRTDBG_FILE_STDERR);
    }
#endif

    set_program_name(argv[0]);
    vlog_set_levels(NULL, VLF_ANY_DESTINATION, VLL_WARN);

    memset(&mock, 0, sizeof mock);
    mock_transport.open = mock_open;
    mock_transport.ioctl = mock_ioctl;
    mock_transport.close = mock_close;
    mock_transport.aux = &mock;
    mock_reset_content(&mock);
    ovsext_set_transport(&mock_transport);

    error = dpif_open("ovs-system", "system", &dpif);
    if (error) {
        fprintf(stderr, "dpif_open(system) failed: %s\n", ovs_strerror(error));
        return 1;
    }
    printf("dpif_open ok (%s)\n", dpif_name(dpif));

    test_bringup(dpif);
    test_recv_large_upcall(dpif, &mock);
    test_recv_multi_dp_filter(dpif, &mock);
    test_flow_dump_multi_record(dpif, &mock);
    test_flow_dump_done_terminator(dpif, &mock);
    test_per_dump_channel(dpif, &mock);
    test_flow_dump_deferred_error(dpif, &mock);
    test_flow_dump_open_failure(dpif, &mock);
    test_flow_get_hit(dpif, &mock);
    test_flow_get_null_buffer(dpif, &mock);
    test_flow_get_miss_vs_malformed(dpif, &mock);
    test_flow_put_stats(dpif, &mock);
    test_flow_del_stats(dpif, &mock);
    test_flow_del_ufid_terse(dpif, &mock);
    test_operate_batch(dpif, &mock);
    test_port_poll(dpif, &mock);
    test_ct_limits(dpif, &mock);
    test_meters(dpif, &mock);
    test_feature_negotiation(dpif, &mock);

    /* The "system" netdev provider shares the mock ovsext transport; it is
     * registered by netdev_initialize() the first time a netdev is opened. */
    test_netdev_refresh(&mock);
    test_netdev_refresh_concurrent(&mock);

    dpif_close(dpif);
    ovsext_set_transport(NULL);

    if (failures) {
        printf("test-dpif-windows: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("test-dpif-windows: OK\n");
    return 0;
}

#else  /* !_WIN32 */
int main(void) { return 0; }
#endif
