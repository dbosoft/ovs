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
 * The mock reproduces the kernel quirks that hid real bugs:
 *   - READ copies the dequeued message TRUNCATED to the caller's output length
 *     (so an undersized recv buffer drops the trailing attribute);
 *   - the dump cursor is PER FILE HANDLE (so a dump must use its own handle);
 *   - a dump is a WRITE(NLM_F_DUMP) that arms the cursor, then one record per
 *     READ, ended by a zero-length read (no NLMSG_DONE).
 *
 * Each test programs the mock's dump/packet/transact content, drives the
 * provider through the public dpif API, and asserts the contract.  The tests
 * regression-guard the divergences fixed in commits f18d4e34 (recv truncation)
 * and b7d08a2f (the dpif-netlink contract audit). */

#include <config.h>

#ifdef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "dpif.h"
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

    /* Queued packet upcalls, delivered one per OVS_IOCTL_READ_PACKET. */
    struct mock_record pkt[MOCK_MAX_RECORDS];   int pkt_head, pkt_len;

    /* OVS_IOCTL_TRANSACT scripting for the FLOW family. */
    enum flow_reply flow_reply;
    struct mock_record flow_echo;
    struct mock_record flow_bad;
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
    case OVS_WIN_NL_DATAPATH_FAMILY_ID:
        return record_copy(&m->dp[0], out, out_len, bytes);

    case OVS_WIN_NL_FLOW_FAMILY_ID:
        switch (m->flow_reply) {
        case FR_ECHO:      return record_copy(&m->flow_echo, out, out_len, bytes);
        case FR_MALFORMED: return record_copy(&m->flow_bad, out, out_len, bytes);
        case FR_ENOENT:    return reply_nlmsgerr(ENOENT, out, out_len, bytes);
        case FR_EMPTYECHO: return TRUE;   /* 0 bytes despite echo request */
        case FR_ACK:
        default:           return TRUE;   /* ack, empty reply */
        }

    case OVS_WIN_NL_VPORT_FAMILY_ID:
    case OVS_WIN_NL_PACKET_FAMILY_ID:
    default:
        return TRUE;            /* success, empty reply */
    }
}

static BOOL
mock_write(struct mock_handle *h, const void *in, DWORD in_len, DWORD *bytes)
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
    /* Other writes (subscribe/pend) just succeed. */
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
        return mock_write(h, in, in_len, bytes);
    case OVS_IOCTL_READ:
        return mock_read_dump(m, h, out, out_len, bytes);
    case OVS_IOCTL_READ_PACKET:
        return mock_read_packet(m, out, out_len, bytes);
    case OVS_IOCTL_READ_EVENT:
        *bytes = 0;
        return TRUE;
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
    m->fail_open = false;
    m->flow_reply = FR_ACK;
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

/* Regression (commit f18d4e34): a full-frame upcall larger than the caller's
 * recv stub must arrive whole.  The provider reads into its own 64 kB buffer
 * and grows the caller's ofpbuf; reading straight into the small stub would let
 * the mock's truncate-to-output-length drop the trailing PACKET attribute and
 * fail the parse, exactly as it dropped DHCP/controller upcalls on eryph. */
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

    /* Regression (audit #11): pid must be explicitly cleared even though the
     * caller's upcall was not zero-initialized. */
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

/* Regression (audit, flow_dump_next aliasing): a batch of N dumped flows must
 * each stay valid and distinct.  The transport reuses one buffer per record, so
 * a naive loop that kept decoded pointers would return N aliases of the last
 * record.  Program three flows with distinct keys and check they differ. */
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

/* Regression (audit #3): each dump must run on its own kernel handle, because
 * the dump cursor is per handle.  Sharing the dpif's channel would race
 * concurrent transactions and parallel revalidator dumps.  Observe that a flow
 * dump opens a second handle (peak concurrency rises above the lone main
 * channel). */
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

/* Regression (audit #6): a malformed record encountered mid-dump is reported by
 * flow_dump_destroy (the dump interface defers all error reporting to it). */
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

/* Regression (audit #7/#10): FLOW_GET copies the reply's key/mask/actions into
 * the caller's buffer.  All ofpbuf_put()s must happen before the pointers are
 * captured (a later put can realloc and move the base) and the copy must be
 * unconditional.  A rich flow plus a tiny output buffer forces a realloc; ASAN
 * catches a dangling read, and the field checks catch a wrong/missing copy. */
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

/* Regression (audit #9): a genuine miss is the in-band NLMSG_ERROR -> ENOENT; a
 * non-NULL reply that fails to decode is a protocol error (EINVAL), not a miss
 * reported as ENOENT. */
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

/* Regression (audit #8): a stats-requested FLOW_PUT must surface a bad/missing
 * echo as an error, not report success with zeroed stats.  A good echo must
 * populate the stats. */
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

/* Regression (audit #8): the FLOW_DEL stats path is identical to FLOW_PUT and
 * was fixed in the same commit -- a bad/missing echo must surface as an error,
 * and a good echo must populate the stats. */
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

/* Regression (audit, operate signature): the class 'operate' is the 3-arg
 * contract; dpif_operate resolves offload before dispatch.  Drive a multi-op
 * batch through the public path to exercise it end to end. */
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

int
main(int argc, char *argv[])
{
    static struct mock_kernel mock;
    static struct ovsext_transport mock_transport;
    struct dpif *dpif;
    int error;

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
    test_per_dump_channel(dpif, &mock);
    test_flow_dump_deferred_error(dpif, &mock);
    test_flow_dump_open_failure(dpif, &mock);
    test_flow_get_hit(dpif, &mock);
    test_flow_get_null_buffer(dpif, &mock);
    test_flow_get_miss_vs_malformed(dpif, &mock);
    test_flow_put_stats(dpif, &mock);
    test_flow_del_stats(dpif, &mock);
    test_operate_batch(dpif, &mock);

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
