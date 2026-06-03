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
 * The mock answers just what ofproto's backer bring-up drives: GET_PID, the
 * datapath OVS_DP_CMD_GET, an (empty) vport dump, flow flush/put, and the
 * packet-subscribe write.  That sequence is replayed by main(). */

#include <config.h>

#ifdef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "dpif.h"
#include "ovsext-channel.h"
#include "flow.h"
#include "odp-util.h"
#include "netlink.h"
#include "netlink-protocol.h"
#include "odp-netlink.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "util.h"

/* The ovsext ABI (IOCTL codes, fixed genl family ids, struct ovs_header). */
#include "OvsDpInterfaceExt.h"

#define MOCK_DP_IFINDEX 1
#define MOCK_PID        0x1234u

/* ---- mock "kernel" state ------------------------------------------------- */

enum mock_dump { DUMP_NONE, DUMP_VPORT, DUMP_FLOW, DUMP_DP };

struct mock_kernel {
    enum mock_dump dump;    /* Armed by an OVS_IOCTL_WRITE w/ NLM_F_DUMP. */
    int dp_records_left;    /* DP dump emits one record, then EOF. */
};

/* Finalize 'b' as a reply and copy it to the IOCTL output buffer. */
static BOOL
reply_copy(struct ofpbuf *b, void *out, DWORD out_len, DWORD *bytes)
{
    nl_msg_nlmsghdr(b)->nlmsg_len = b->size;
    if (b->size > out_len) {
        ofpbuf_uninit(b);
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    memcpy(out, b->data, b->size);
    *bytes = (DWORD) b->size;
    ofpbuf_uninit(b);
    return TRUE;
}

/* Build an OVS_DP_CMD_GET reply (name + stats), as OvsDpFillInfo does. */
static BOOL
mock_dp_get(void *out, DWORD out_len, DWORD *bytes)
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
    return reply_copy(&b, out, out_len, bytes);
}

static BOOL
mock_transact(struct mock_kernel *m OVS_UNUSED, const void *in, DWORD in_len,
              void *out, DWORD out_len, DWORD *bytes)
{
    const struct nlmsghdr *nlh = in;
    const struct genlmsghdr *genl;

    *bytes = 0;
    if (in_len < NLMSG_HDRLEN + GENL_HDRLEN) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    genl = ALIGNED_CAST(const struct genlmsghdr *,
                        (const char *) in + NLMSG_HDRLEN);

    switch (nlh->nlmsg_type) {
    case OVS_WIN_NL_DATAPATH_FAMILY_ID:
        if (genl->cmd == OVS_DP_CMD_GET || genl->cmd == OVS_DP_CMD_SET) {
            return mock_dp_get(out, out_len, bytes);
        }
        return TRUE;            /* ack with no payload */

    case OVS_WIN_NL_FLOW_FAMILY_ID:
    case OVS_WIN_NL_VPORT_FAMILY_ID:
    case OVS_WIN_NL_PACKET_FAMILY_ID:
    default:
        /* Success with empty reply (the driver returns 0 bytes for ops that
         * neither fail nor carry NLM_F_ECHO output). */
        return TRUE;
    }
}

static BOOL
mock_write(struct mock_kernel *m, const void *in, DWORD in_len, DWORD *bytes)
{
    const struct nlmsghdr *nlh = in;

    *bytes = 0;
    if (in_len < NLMSG_HDRLEN) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* A WRITE carrying NLM_F_DUMP arms the per-handle dump cursor. */
    if (nlh->nlmsg_flags & NLM_F_DUMP) {
        switch (nlh->nlmsg_type) {
        case OVS_WIN_NL_VPORT_FAMILY_ID:   m->dump = DUMP_VPORT; break;
        case OVS_WIN_NL_FLOW_FAMILY_ID:    m->dump = DUMP_FLOW;  break;
        case OVS_WIN_NL_DATAPATH_FAMILY_ID:
            m->dump = DUMP_DP;
            m->dp_records_left = 1;
            break;
        default: break;
        }
    }
    /* Other writes (e.g. OVS_CTRL_CMD_PACKET_SUBSCRIBE_REQ) just succeed. */
    return TRUE;
}

static BOOL
mock_read(struct mock_kernel *m, void *out, DWORD out_len, DWORD *bytes)
{
    *bytes = 0;

    if (m->dump == DUMP_DP && m->dp_records_left > 0) {
        m->dp_records_left--;
        return mock_dp_get(out, out_len, bytes);   /* one DP record */
    }

    /* Empty read = end of dump (no vports/flows on this mock datapath). */
    m->dump = DUMP_NONE;
    return TRUE;
}

static BOOL
mock_ioctl(void *aux, HANDLE handle OVS_UNUSED, DWORD code,
           const void *in, DWORD in_len, void *out, DWORD out_len, DWORD *bytes)
{
    struct mock_kernel *m = aux;

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
        return mock_write(m, in, in_len, bytes);
    case OVS_IOCTL_READ:
    case OVS_IOCTL_READ_EVENT:
    case OVS_IOCTL_READ_PACKET:
        return mock_read(m, out, out_len, bytes);
    default:
        SetLastError(ERROR_INVALID_FUNCTION);
        return FALSE;
    }
}

static HANDLE
mock_open(void *aux OVS_UNUSED)
{
    /* Any non-INVALID token; the channel only passes it back to mock_ioctl. */
    return (HANDLE) (intptr_t) 0x4242;
}

static void
mock_close(void *aux OVS_UNUSED, HANDLE handle OVS_UNUSED)
{
}

/* ---- bring-up replay ----------------------------------------------------- */

static void
replay_bringup(struct dpif *dpif)
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

    /* 1. flow_flush (first datapath op open_dpif_backer performs). */
    dpif_flow_flush(dpif);
    printf("  flow_flush ok\n");

    /* 2. enumerate stale ports (empty on the mock). */
    DPIF_PORT_FOR_EACH (&port, &port_dump, dpif) {
        printf("  port %s\n", port.name);
    }
    printf("  port_dump ok\n");

    /* 3. a flow_put probe, like check_recirc()/check_support(). */
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
    printf("  flow_put op error=%d\n", op.error);

    /* 4. enable upcalls (OVS_CTRL_CMD_PACKET_SUBSCRIBE_REQ write). */
    dpif_recv_set(dpif, true);
    printf("  recv_set ok\n");
}

int
main(int argc, char *argv[])
{
    static struct mock_kernel mock;
    static const struct ovsext_transport mock_transport = {
        .open = mock_open,
        .ioctl = mock_ioctl,
        .close = mock_close,
        .aux = &mock,
    };
    struct dpif *dpif;
    int error;

    set_program_name(argv[0]);
    vlog_set_levels(NULL, VLF_ANY_DESTINATION, VLL_WARN);

    memset(&mock, 0, sizeof mock);
    ovsext_set_transport(&mock_transport);

    error = dpif_open("ovs-system", "windows", &dpif);
    if (error) {
        fprintf(stderr, "dpif_open(windows) failed: %s\n", ovs_strerror(error));
        return 1;
    }
    printf("dpif_open ok (%s)\n", dpif_name(dpif));

    replay_bringup(dpif);

    dpif_close(dpif);
    ovsext_set_transport(NULL);
    printf("test-dpif-windows: OK\n");
    return 0;
}

#else  /* !_WIN32 */
int main(void) { return 0; }
#endif
