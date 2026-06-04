/*
 * Copyright (c) 2026 dbosoft GmbH.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

/* Native Windows datapath provider.
 *
 * Implements 'struct dpif_class' directly against the ovsext kernel datapath,
 * replacing the Windows use of dpif_netlink_class and the faked nl_sock
 * transport.  The kernel driver and its IOCTL/netlink-message ABI are
 * unchanged; this provider talks to it through lib/ovsext-channel.c and builds
 * message bodies with the shared nl_msg / odp-util encoders.
 *
 * The datapath/vport/flow/packet message (de)serialization mirrors
 * lib/dpif-netlink.c exactly; the only substitution is the transport layer:
 * ovsext_transact()/ovsext_dump_*() in place of nl_transact()/nl_dump_*(), and
 * the fixed Windows genl family IDs (OVS_WIN_NL_*_FAMILY_ID) in place of the
 * runtime-resolved Linux genl families.
 *
 * Operations that dpif-netlink itself stubs out under '#ifdef _WIN32' (the
 * conntrack/meter/bond/timeout-policy management members) are simply absent
 * from this class' initializer, exactly as the corresponding members default
 * to NULL.  Upcalls use a single handler, as Windows always has.
 *
 * See datapath-windows/NATIVE-DPIF-EXPERIMENT.md for the full spec. */

#include <config.h>

#ifdef _WIN32

#include <errno.h>
#include <stdio.h>              /* EOF */
#include <net/if.h>             /* IFNAMSIZ */

#include "dpif-provider.h"
#include "odp-netlink.h"        /* struct ovs_header, OVS_*_ATTR_*. */
#include "ovsext-channel.h"
#include "flow.h"
#include "netdev.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "odp-util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/match.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "sset.h"
#include "unaligned.h"
#include "util.h"
#include "wmi.h"

/* The ovsext ABI: fixed family IDs, command/attr enums, struct ovs_header. */
#include "OvsDpInterfaceExt.h"

VLOG_DEFINE_THIS_MODULE(dpif_windows);

static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(9999, 5);

#define FLOW_DUMP_MAX_BATCH 50
#define OPERATE_MAX_OPS 50

/* The ovsext kernel backs one datapath per Hyper-V switch, each addressed on
 * the wire by its dp_ifindex and named by its switch identity. ofproto-dpif
 * opens its backer under the name "ovs-<datapath_type>" (e.g. "ovs-system")
 * and dpctl callers may pass an arbitrary name. dpif_windows_open resolves that
 * name to a dp_ifindex by dumping the datapaths and matching: the default
 * suffix ("system") selects the lowest-numbered datapath, otherwise
 * the suffix must match a datapath's reported name. The resolved name and
 * dp_ifindex are then used to address the kernel for the lifetime of the dpif.
 *
 * Names can be a switch GUID, longer than IFNAMSIZ; the datapath-name parse and
 * the resolver buffers are sized accordingly. */
#define OVS_DP_NAME_MAX 64

/* The kernel addresses datapaths by dp_ifindex; for the OVS_DP_ATTR_NAME on the
 * wire it accepts only this fixed name (any other is rejected with NODEV). We
 * resolve the caller's name to a dp_ifindex via DP_DUMP, then target that
 * dp_ifindex while sending this fixed name. */
#define OVS_WINDOWS_KERNEL_DP_NAME "ovs-system"

/* The base datapath type for the native Windows provider.  Matches Linux's
 * "system" type so a bridge with no datapath_type (normalized to "system")
 * resolves here and "ovs-dpctl show" reads "system@ovs-system", as on Linux.
 * Per-switch datapaths register additional alias types named by the switch
 * GUID; this base type is the default, resolving to the lowest-numbered
 * datapath. */
#define OVS_WINDOWS_DEFAULT_DP_TYPE "system"

/* Upper bound on datapaths to enumerate when resolving a name; matches the
 * driver's OVS_MAX_DATAPATHS. */
#define DPIF_WINDOWS_MAX_DPS 16

struct dpif_windows {
    struct dpif dpif;
    struct ovsext_channel channel;
    int dp_ifindex;
    char *dp_name;              /* Kernel-reported datapath name. */
    uint32_t user_features;
    bool upcalls_enabled;       /* recv_set() state. */
};

/* 'dpif_windows_class' is declared in dpif-provider.h and defined at the
 * bottom of this file. */

static int dpif_windows_open(const struct dpif_class *class, const char *name,
                             bool create, struct dpif **dpifp);

static struct dpif_windows *
dpif_windows_cast(const struct dpif *dpif)
{
    /* Besides 'dpif_windows_class' itself, the provider is also registered under
     * per-switch alias classes (one per Hyper-V switch GUID, see
     * dpif_windows_register_switch_type), which share these same methods. Accept
     * any class backed by this provider rather than the base class alone. */
    ovs_assert(dpif->dpif_class->open == dpif_windows_open);
    return CONTAINER_OF(dpif, struct dpif_windows, dpif);
}

/* ====================================================================
 * Datapath messages (mirrors struct dpif_netlink_dp and its helpers).
 * ==================================================================== */

struct dpif_windows_dp {
    /* Generic Netlink header. */
    uint8_t cmd;

    /* struct ovs_header. */
    int dp_ifindex;

    /* Attributes. */
    const char *name;                  /* OVS_DP_ATTR_NAME. */
    const uint32_t *upcall_pid;        /* OVS_DP_ATTR_UPCALL_PID. */
    uint32_t user_features;            /* OVS_DP_ATTR_USER_FEATURES. */
    const struct ovs_dp_stats *stats;  /* OVS_DP_ATTR_STATS. */
    const struct ovs_dp_megaflow_stats *megaflow_stats;
};

static void
dpif_windows_dp_init(struct dpif_windows_dp *dp)
{
    memset(dp, 0, sizeof *dp);
}

/* Appends to 'buf' the Generic Netlink message described by 'dp'. */
static void
dpif_windows_dp_to_ofpbuf(const struct dpif_windows_dp *dp, struct ofpbuf *buf)
{
    struct ovs_header *ovs_header;

    nl_msg_put_genlmsghdr(buf, 0, OVS_WIN_NL_DATAPATH_FAMILY_ID,
                          NLM_F_REQUEST | NLM_F_ECHO, dp->cmd,
                          OVS_DATAPATH_VERSION);

    ovs_header = ofpbuf_put_uninit(buf, sizeof *ovs_header);
    ovs_header->dp_ifindex = dp->dp_ifindex;

    if (dp->name) {
        nl_msg_put_string(buf, OVS_DP_ATTR_NAME, dp->name);
    }
    if (dp->upcall_pid) {
        nl_msg_put_u32(buf, OVS_DP_ATTR_UPCALL_PID, *dp->upcall_pid);
    }
    if (dp->user_features) {
        nl_msg_put_u32(buf, OVS_DP_ATTR_USER_FEATURES, dp->user_features);
    }
    /* Skip OVS_DP_ATTR_STATS; never serialized. */
}

/* Parses 'buf' (struct ovs_header + attrs) into 'dp'.  'dp' points into
 * 'buf'. */
static int
dpif_windows_dp_from_ofpbuf(struct dpif_windows_dp *dp,
                            const struct ofpbuf *buf)
{
    static const struct nl_policy ovs_datapath_policy[] = {
        [OVS_DP_ATTR_NAME] = { .type = NL_A_STRING, .max_len = OVS_DP_NAME_MAX },
        [OVS_DP_ATTR_STATS] = { NL_POLICY_FOR(struct ovs_dp_stats),
                                .optional = true },
        [OVS_DP_ATTR_MEGAFLOW_STATS] = {
                        NL_POLICY_FOR(struct ovs_dp_megaflow_stats),
                        .optional = true },
        [OVS_DP_ATTR_USER_FEATURES] = {
                        .type = NL_A_U32,
                        .optional = true },
    };

    dpif_windows_dp_init(dp);

    struct ofpbuf b = ofpbuf_const_initializer(buf->data, buf->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(&b, sizeof *genl);
    struct ovs_header *ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);

    struct nlattr *a[ARRAY_SIZE(ovs_datapath_policy)];
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != OVS_WIN_NL_DATAPATH_FAMILY_ID
        || !nl_policy_parse(&b, 0, ovs_datapath_policy, a,
                            ARRAY_SIZE(ovs_datapath_policy))) {
        return EINVAL;
    }

    dp->cmd = genl->cmd;
    dp->dp_ifindex = ovs_header->dp_ifindex;
    dp->name = nl_attr_get_string(a[OVS_DP_ATTR_NAME]);
    if (a[OVS_DP_ATTR_STATS]) {
        dp->stats = nl_attr_get(a[OVS_DP_ATTR_STATS]);
    }
    if (a[OVS_DP_ATTR_MEGAFLOW_STATS]) {
        dp->megaflow_stats = nl_attr_get(a[OVS_DP_ATTR_MEGAFLOW_STATS]);
    }
    if (a[OVS_DP_ATTR_USER_FEATURES]) {
        dp->user_features = nl_attr_get_u32(a[OVS_DP_ATTR_USER_FEATURES]);
    }
    return 0;
}

/* Transacts 'request' against the channel.  If 'reply'/'bufp' are nonnull the
 * reply is decoded into them; the caller frees '*bufp'. */
static int
dpif_windows_dp_transact(struct dpif_windows *dpif,
                         const struct dpif_windows_dp *request,
                         struct dpif_windows_dp *reply, struct ofpbuf **bufp)
{
    struct ofpbuf *request_buf;
    int error;

    ovs_assert((reply != NULL) == (bufp != NULL));

    request_buf = ofpbuf_new(1024);
    dpif_windows_dp_to_ofpbuf(request, request_buf);
    error = ovsext_transact(&dpif->channel, request_buf, bufp);
    ofpbuf_delete(request_buf);

    if (reply) {
        dpif_windows_dp_init(reply);
        if (!error) {
            if (*bufp) {
                error = dpif_windows_dp_from_ofpbuf(reply, *bufp);
            } else {
                error = EINVAL;
            }
        }
        if (error) {
            ofpbuf_delete(*bufp);
            *bufp = NULL;
        }
    }
    return error;
}

static int
dpif_windows_dp_get(struct dpif_windows *dpif, struct dpif_windows_dp *reply,
                    struct ofpbuf **bufp)
{
    struct dpif_windows_dp request;

    dpif_windows_dp_init(&request);
    request.cmd = OVS_DP_CMD_GET;
    request.dp_ifindex = dpif->dp_ifindex;
    request.name = OVS_WINDOWS_KERNEL_DP_NAME;

    return dpif_windows_dp_transact(dpif, &request, reply, bufp);
}

/* ====================================================================
 * Vport messages (mirrors struct dpif_netlink_vport and its helpers).
 * ==================================================================== */

struct dpif_windows_vport {
    uint8_t cmd;
    int dp_ifindex;
    odp_port_t port_no;                  /* OVS_VPORT_ATTR_PORT_NO. */
    enum ovs_vport_type type;            /* OVS_VPORT_ATTR_TYPE. */
    const char *name;                    /* OVS_VPORT_ATTR_NAME. */
    const uint32_t *upcall_pids;         /* OVS_VPORT_ATTR_UPCALL_PID. */
    uint32_t n_upcall_pids;
    const struct ovs_vport_stats *stats; /* OVS_VPORT_ATTR_STATS. */
    const struct nlattr *options;        /* OVS_VPORT_ATTR_OPTIONS. */
    size_t options_len;
};

static void
dpif_windows_vport_init(struct dpif_windows_vport *vport)
{
    memset(vport, 0, sizeof *vport);
    vport->port_no = ODPP_NONE;
}

static const char *
get_vport_type(const struct dpif_windows_vport *vport)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

    switch (vport->type) {
    case OVS_VPORT_TYPE_NETDEV: {
        const char *type = netdev_get_type_from_name(vport->name);
        return type ? type : "system";
    }
    case OVS_VPORT_TYPE_INTERNAL:
        return "internal";
    case OVS_VPORT_TYPE_GENEVE:
        return "geneve";
    case OVS_VPORT_TYPE_GRE:
        return "gre";
    case OVS_VPORT_TYPE_VXLAN:
        return "vxlan";
    case OVS_VPORT_TYPE_ERSPAN:
        return "erspan";
    case OVS_VPORT_TYPE_IP6ERSPAN:
        return "ip6erspan";
    case OVS_VPORT_TYPE_IP6GRE:
        return "ip6gre";
    case OVS_VPORT_TYPE_GTPU:
        return "gtpu";
    case OVS_VPORT_TYPE_SRV6:
        return "srv6";
    case OVS_VPORT_TYPE_BAREUDP:
        return "bareudp";
    case OVS_VPORT_TYPE_UNSPEC:
    case __OVS_VPORT_TYPE_MAX:
        break;
    }

    VLOG_WARN_RL(&rl, "dp%d: port `%s' has unsupported type %u",
                 vport->dp_ifindex, vport->name, (unsigned int) vport->type);
    return "unknown";
}

static enum ovs_vport_type
netdev_to_ovs_vport_type(const char *type)
{
    if (!strcmp(type, "tap") || !strcmp(type, "system")) {
        return OVS_VPORT_TYPE_NETDEV;
    } else if (!strcmp(type, "internal")) {
        return OVS_VPORT_TYPE_INTERNAL;
    } else if (!strcmp(type, "geneve")) {
        return OVS_VPORT_TYPE_GENEVE;
    } else if (!strcmp(type, "vxlan")) {
        return OVS_VPORT_TYPE_VXLAN;
    } else if (!strcmp(type, "erspan")) {
        return OVS_VPORT_TYPE_ERSPAN;
    } else if (!strcmp(type, "ip6erspan")) {
        return OVS_VPORT_TYPE_IP6ERSPAN;
    } else if (!strcmp(type, "ip6gre")) {
        return OVS_VPORT_TYPE_IP6GRE;
    } else if (!strcmp(type, "gre")) {
        return OVS_VPORT_TYPE_GRE;
    } else if (!strcmp(type, "gtpu")) {
        return OVS_VPORT_TYPE_GTPU;
    } else if (!strcmp(type, "srv6")) {
        return OVS_VPORT_TYPE_SRV6;
    } else if (!strcmp(type, "bareudp")) {
        return OVS_VPORT_TYPE_BAREUDP;
    } else {
        return OVS_VPORT_TYPE_UNSPEC;
    }
}

static void
dpif_windows_vport_to_ofpbuf(const struct dpif_windows_vport *vport,
                             struct ofpbuf *buf)
{
    struct ovs_header *ovs_header;

    nl_msg_put_genlmsghdr(buf, 0, OVS_WIN_NL_VPORT_FAMILY_ID,
                          NLM_F_REQUEST | NLM_F_ECHO,
                          vport->cmd, OVS_VPORT_VERSION);

    ovs_header = ofpbuf_put_uninit(buf, sizeof *ovs_header);
    ovs_header->dp_ifindex = vport->dp_ifindex;

    if (vport->port_no != ODPP_NONE) {
        nl_msg_put_odp_port(buf, OVS_VPORT_ATTR_PORT_NO, vport->port_no);
    }
    if (vport->type != OVS_VPORT_TYPE_UNSPEC) {
        nl_msg_put_u32(buf, OVS_VPORT_ATTR_TYPE, vport->type);
    }
    if (vport->name) {
        nl_msg_put_string(buf, OVS_VPORT_ATTR_NAME, vport->name);
    }
    if (vport->upcall_pids) {
        nl_msg_put_unspec(buf, OVS_VPORT_ATTR_UPCALL_PID,
                          vport->upcall_pids,
                          vport->n_upcall_pids * sizeof *vport->upcall_pids);
    }
    if (vport->stats) {
        nl_msg_put_unspec(buf, OVS_VPORT_ATTR_STATS,
                          vport->stats, sizeof *vport->stats);
    }
    if (vport->options) {
        nl_msg_put_nested(buf, OVS_VPORT_ATTR_OPTIONS,
                          vport->options, vport->options_len);
    }
}

static int
dpif_windows_vport_from_ofpbuf(struct dpif_windows_vport *vport,
                               const struct ofpbuf *buf)
{
    static const struct nl_policy ovs_vport_policy[] = {
        [OVS_VPORT_ATTR_PORT_NO] = { .type = NL_A_U32 },
        [OVS_VPORT_ATTR_TYPE] = { .type = NL_A_U32 },
        [OVS_VPORT_ATTR_NAME] = { .type = NL_A_STRING, .max_len = IFNAMSIZ },
        [OVS_VPORT_ATTR_UPCALL_PID] = { .type = NL_A_UNSPEC },
        [OVS_VPORT_ATTR_STATS] = { NL_POLICY_FOR(struct ovs_vport_stats),
                                   .optional = true },
        [OVS_VPORT_ATTR_OPTIONS] = { .type = NL_A_NESTED, .optional = true },
    };

    dpif_windows_vport_init(vport);

    struct ofpbuf b = ofpbuf_const_initializer(buf->data, buf->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(&b, sizeof *genl);
    struct ovs_header *ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);

    struct nlattr *a[ARRAY_SIZE(ovs_vport_policy)];
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != OVS_WIN_NL_VPORT_FAMILY_ID
        || !nl_policy_parse(&b, 0, ovs_vport_policy, a,
                            ARRAY_SIZE(ovs_vport_policy))) {
        return EINVAL;
    }

    vport->cmd = genl->cmd;
    vport->dp_ifindex = ovs_header->dp_ifindex;
    vport->port_no = nl_attr_get_odp_port(a[OVS_VPORT_ATTR_PORT_NO]);
    vport->type = nl_attr_get_u32(a[OVS_VPORT_ATTR_TYPE]);
    vport->name = nl_attr_get_string(a[OVS_VPORT_ATTR_NAME]);
    if (a[OVS_VPORT_ATTR_UPCALL_PID]) {
        vport->n_upcall_pids = nl_attr_get_size(a[OVS_VPORT_ATTR_UPCALL_PID])
                               / (sizeof *vport->upcall_pids);
        vport->upcall_pids = nl_attr_get(a[OVS_VPORT_ATTR_UPCALL_PID]);
    }
    if (a[OVS_VPORT_ATTR_STATS]) {
        vport->stats = nl_attr_get(a[OVS_VPORT_ATTR_STATS]);
    }
    if (a[OVS_VPORT_ATTR_OPTIONS]) {
        vport->options = nl_attr_get(a[OVS_VPORT_ATTR_OPTIONS]);
        vport->options_len = nl_attr_get_size(a[OVS_VPORT_ATTR_OPTIONS]);
    }
    return 0;
}

static int
dpif_windows_vport_transact(struct dpif_windows *dpif,
                            const struct dpif_windows_vport *request,
                            struct dpif_windows_vport *reply,
                            struct ofpbuf **bufp)
{
    struct ofpbuf *request_buf;
    int error;

    ovs_assert((reply != NULL) == (bufp != NULL));

    request_buf = ofpbuf_new(1024);
    dpif_windows_vport_to_ofpbuf(request, request_buf);
    error = ovsext_transact(&dpif->channel, request_buf, bufp);
    ofpbuf_delete(request_buf);

    if (reply) {
        dpif_windows_vport_init(reply);
        if (!error) {
            if (*bufp) {
                error = dpif_windows_vport_from_ofpbuf(reply, *bufp);
            } else {
                error = EINVAL;
            }
        }
        if (error) {
            dpif_windows_vport_init(reply);
            ofpbuf_delete(*bufp);
            *bufp = NULL;
        }
    }
    return error;
}

/* ====================================================================
 * Flow messages (mirrors struct dpif_netlink_flow and its helpers).
 * ==================================================================== */

struct dpif_windows_flow {
    uint8_t cmd;
    unsigned int nlmsg_flags;
    int dp_ifindex;

    const struct nlattr *key;           /* OVS_FLOW_ATTR_KEY. */
    size_t key_len;
    const struct nlattr *mask;          /* OVS_FLOW_ATTR_MASK. */
    size_t mask_len;
    const struct nlattr *actions;       /* OVS_FLOW_ATTR_ACTIONS. */
    size_t actions_len;
    ovs_u128 ufid;                      /* OVS_FLOW_ATTR_UFID. */
    bool ufid_present;
    bool ufid_terse;
    const struct ovs_flow_stats *stats; /* OVS_FLOW_ATTR_STATS. */
    const uint8_t *tcp_flags;           /* OVS_FLOW_ATTR_TCP_FLAGS. */
    const ovs_32aligned_u64 *used;      /* OVS_FLOW_ATTR_USED. */
    bool clear;
    bool probe;
};

static void
dpif_windows_flow_init(struct dpif_windows_flow *flow)
{
    memset(flow, 0, sizeof *flow);
}

/* Filters out OVS_KEY_ATTR_PACKET_TYPE; copied verbatim from dpif-netlink. */
static void
put_exclude_packet_type(struct ofpbuf *buf, uint16_t type,
                        const struct nlattr *data, uint16_t data_len)
{
    const struct nlattr *packet_type;

    packet_type = nl_attr_find__(data, data_len, OVS_KEY_ATTR_PACKET_TYPE);

    if (packet_type) {
        ovs_assert(NLA_ALIGN(packet_type->nla_len) == NL_A_U32_SIZE);
        size_t packet_type_len = NL_A_U32_SIZE;
        size_t first_chunk_size = (uint8_t *) packet_type - (uint8_t *) data;
        size_t second_chunk_size = data_len - first_chunk_size
                                   - packet_type_len;
        struct nlattr *next_attr = nl_attr_next(packet_type);
        size_t ofs;

        ofs = nl_msg_start_nested(buf, type);
        nl_msg_put(buf, data, first_chunk_size);
        nl_msg_put(buf, next_attr, second_chunk_size);
        if (!nl_attr_find__(data, data_len, OVS_KEY_ATTR_ETHERNET)) {
            ovs_be16 pt = pt_ns_type_be(nl_attr_get_be32(packet_type));
            const struct nlattr *nla;

            nla = nl_attr_find(buf, ofs + NLA_HDRLEN, OVS_KEY_ATTR_ETHERTYPE);
            if (nla) {
                ovs_be16 *ethertype;

                ethertype = CONST_CAST(ovs_be16 *, nl_attr_get(nla));
                *ethertype = pt;
            } else {
                nl_msg_put_be16(buf, OVS_KEY_ATTR_ETHERTYPE, pt);
            }
        }
        nl_msg_end_nested(buf, ofs);
    } else {
        nl_msg_put_unspec(buf, type, data, data_len);
    }
}

static void
dpif_windows_flow_to_ofpbuf(const struct dpif_windows_flow *flow,
                            struct ofpbuf *buf)
{
    struct ovs_header *ovs_header;

    nl_msg_put_genlmsghdr(buf, 0, OVS_WIN_NL_FLOW_FAMILY_ID,
                          NLM_F_REQUEST | flow->nlmsg_flags,
                          flow->cmd, OVS_FLOW_VERSION);

    ovs_header = ofpbuf_put_uninit(buf, sizeof *ovs_header);
    ovs_header->dp_ifindex = flow->dp_ifindex;

    if (flow->ufid_present) {
        nl_msg_put_u128(buf, OVS_FLOW_ATTR_UFID, flow->ufid);
    }
    if (flow->ufid_terse) {
        nl_msg_put_u32(buf, OVS_FLOW_ATTR_UFID_FLAGS,
                       OVS_UFID_F_OMIT_KEY | OVS_UFID_F_OMIT_MASK
                       | OVS_UFID_F_OMIT_ACTIONS);
    }
    if (!flow->ufid_terse || !flow->ufid_present) {
        if (flow->key_len) {
            put_exclude_packet_type(buf, OVS_FLOW_ATTR_KEY, flow->key,
                                    flow->key_len);
        }
        if (flow->mask_len) {
            put_exclude_packet_type(buf, OVS_FLOW_ATTR_MASK, flow->mask,
                                    flow->mask_len);
        }
        if (flow->actions || flow->actions_len) {
            nl_msg_put_unspec(buf, OVS_FLOW_ATTR_ACTIONS,
                              flow->actions, flow->actions_len);
        }
    }

    /* We never need to send these to the kernel. */
    ovs_assert(!flow->stats);
    ovs_assert(!flow->tcp_flags);
    ovs_assert(!flow->used);

    if (flow->clear) {
        nl_msg_put_flag(buf, OVS_FLOW_ATTR_CLEAR);
    }
    if (flow->probe) {
        nl_msg_put_flag(buf, OVS_FLOW_ATTR_PROBE);
    }
}

static int
dpif_windows_flow_from_ofpbuf(struct dpif_windows_flow *flow,
                              const struct ofpbuf *buf)
{
    static const struct nl_policy ovs_flow_policy[__OVS_FLOW_ATTR_MAX] = {
        [OVS_FLOW_ATTR_KEY] = { .type = NL_A_NESTED, .optional = true },
        [OVS_FLOW_ATTR_MASK] = { .type = NL_A_NESTED, .optional = true },
        [OVS_FLOW_ATTR_ACTIONS] = { .type = NL_A_NESTED, .optional = true },
        [OVS_FLOW_ATTR_STATS] = { NL_POLICY_FOR(struct ovs_flow_stats),
                                  .optional = true },
        [OVS_FLOW_ATTR_TCP_FLAGS] = { .type = NL_A_U8, .optional = true },
        [OVS_FLOW_ATTR_USED] = { .type = NL_A_U64, .optional = true },
        [OVS_FLOW_ATTR_UFID] = { .type = NL_A_U128, .optional = true },
    };

    dpif_windows_flow_init(flow);

    struct ofpbuf b = ofpbuf_const_initializer(buf->data, buf->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(&b, sizeof *genl);
    struct ovs_header *ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);

    struct nlattr *a[ARRAY_SIZE(ovs_flow_policy)];
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != OVS_WIN_NL_FLOW_FAMILY_ID
        || !nl_policy_parse(&b, 0, ovs_flow_policy, a,
                            ARRAY_SIZE(ovs_flow_policy))) {
        return EINVAL;
    }
    if (!a[OVS_FLOW_ATTR_KEY] && !a[OVS_FLOW_ATTR_UFID]) {
        return EINVAL;
    }

    flow->nlmsg_flags = nlmsg->nlmsg_flags;
    flow->dp_ifindex = ovs_header->dp_ifindex;
    if (a[OVS_FLOW_ATTR_KEY]) {
        flow->key = nl_attr_get(a[OVS_FLOW_ATTR_KEY]);
        flow->key_len = nl_attr_get_size(a[OVS_FLOW_ATTR_KEY]);
    }
    if (a[OVS_FLOW_ATTR_UFID]) {
        flow->ufid = nl_attr_get_u128(a[OVS_FLOW_ATTR_UFID]);
        flow->ufid_present = true;
    }
    if (a[OVS_FLOW_ATTR_MASK]) {
        flow->mask = nl_attr_get(a[OVS_FLOW_ATTR_MASK]);
        flow->mask_len = nl_attr_get_size(a[OVS_FLOW_ATTR_MASK]);
    }
    if (a[OVS_FLOW_ATTR_ACTIONS]) {
        flow->actions = nl_attr_get(a[OVS_FLOW_ATTR_ACTIONS]);
        flow->actions_len = nl_attr_get_size(a[OVS_FLOW_ATTR_ACTIONS]);
    }
    if (a[OVS_FLOW_ATTR_STATS]) {
        flow->stats = nl_attr_get(a[OVS_FLOW_ATTR_STATS]);
    }
    if (a[OVS_FLOW_ATTR_TCP_FLAGS]) {
        flow->tcp_flags = nl_attr_get(a[OVS_FLOW_ATTR_TCP_FLAGS]);
    }
    if (a[OVS_FLOW_ATTR_USED]) {
        flow->used = nl_attr_get(a[OVS_FLOW_ATTR_USED]);
    }
    return 0;
}

static int
dpif_windows_flow_transact(struct dpif_windows *dpif,
                           struct dpif_windows_flow *request,
                           struct dpif_windows_flow *reply,
                           struct ofpbuf **bufp)
{
    struct ofpbuf *request_buf;
    int error;

    ovs_assert((reply != NULL) == (bufp != NULL));

    if (reply) {
        request->nlmsg_flags |= NLM_F_ECHO;
    }

    request_buf = ofpbuf_new(1024);
    dpif_windows_flow_to_ofpbuf(request, request_buf);
    error = ovsext_transact(&dpif->channel, request_buf, bufp);
    ofpbuf_delete(request_buf);

    if (reply) {
        if (!error) {
            if (*bufp) {
                error = dpif_windows_flow_from_ofpbuf(reply, *bufp);
            } else {
                error = EINVAL;
            }
        }
        if (error) {
            dpif_windows_flow_init(reply);
            ofpbuf_delete(*bufp);
            *bufp = NULL;
        }
    }
    return error;
}

static void
dpif_windows_flow_get_stats(const struct dpif_windows_flow *flow,
                            struct dpif_flow_stats *stats)
{
    if (flow->stats) {
        stats->n_packets = get_32aligned_u64(&flow->stats->n_packets);
        stats->n_bytes = get_32aligned_u64(&flow->stats->n_bytes);
    } else {
        stats->n_packets = 0;
        stats->n_bytes = 0;
    }
    stats->used = flow->used ? get_32aligned_u64(flow->used) : 0;
    stats->tcp_flags = flow->tcp_flags ? *flow->tcp_flags : 0;
}

static void
dpif_windows_flow_to_dpif_flow(struct dpif_flow *dpif_flow,
                               const struct dpif_windows_flow *datapath_flow)
{
    dpif_flow->key = datapath_flow->key;
    dpif_flow->key_len = datapath_flow->key_len;
    dpif_flow->mask = datapath_flow->mask;
    dpif_flow->mask_len = datapath_flow->mask_len;
    dpif_flow->actions = datapath_flow->actions;
    dpif_flow->actions_len = datapath_flow->actions_len;
    dpif_flow->ufid_present = datapath_flow->ufid_present;
    dpif_flow->pmd_id = PMD_ID_NULL;
    if (datapath_flow->ufid_present) {
        dpif_flow->ufid = datapath_flow->ufid;
    } else {
        ovs_assert(datapath_flow->key && datapath_flow->key_len);
        odp_flow_key_hash(datapath_flow->key, datapath_flow->key_len,
                          &dpif_flow->ufid);
    }
    dpif_windows_flow_get_stats(datapath_flow, &dpif_flow->stats);
    dpif_flow->attrs.offloaded = false;
    dpif_flow->attrs.dp_layer = "ovs";
    dpif_flow->attrs.dp_extra_info = NULL;
}

static void
dpif_windows_init_flow_get__(const struct dpif_windows *dpif,
                             const struct nlattr *key, size_t key_len,
                             const ovs_u128 *ufid, bool terse,
                             struct dpif_windows_flow *request)
{
    dpif_windows_flow_init(request);
    request->cmd = OVS_FLOW_CMD_GET;
    request->dp_ifindex = dpif->dp_ifindex;
    request->key = key;
    request->key_len = key_len;
    if (ufid) {
        request->ufid = *ufid;
        request->ufid_present = true;
    }
    request->ufid_terse = terse;
}

static void
dpif_windows_init_flow_get(const struct dpif_windows *dpif,
                           const struct dpif_flow_get *get,
                           struct dpif_windows_flow *request)
{
    dpif_windows_init_flow_get__(dpif, get->key, get->key_len, get->ufid,
                                 false, request);
}

static void
dpif_windows_init_flow_put(struct dpif_windows *dpif,
                           const struct dpif_flow_put *put,
                           struct dpif_windows_flow *request)
{
    static const struct nlattr dummy_action;

    dpif_windows_flow_init(request);
    request->cmd = (put->flags & DPIF_FP_CREATE
                    ? OVS_FLOW_CMD_NEW : OVS_FLOW_CMD_SET);
    request->dp_ifindex = dpif->dp_ifindex;
    request->key = put->key;
    request->key_len = put->key_len;
    request->mask = put->mask;
    request->mask_len = put->mask_len;
    if (put->ufid) {
        request->ufid = *put->ufid;
        request->ufid_present = true;
    }

    /* Ensure that OVS_FLOW_ATTR_ACTIONS will always be included. */
    request->actions = (put->actions
                        ? put->actions
                        : CONST_CAST(struct nlattr *, &dummy_action));
    request->actions_len = put->actions_len;
    if (put->flags & DPIF_FP_ZERO_STATS) {
        request->clear = true;
    }
    if (put->flags & DPIF_FP_PROBE) {
        request->probe = true;
    }
    request->nlmsg_flags = put->flags & DPIF_FP_MODIFY ? 0 : NLM_F_CREATE;
}

static void
dpif_windows_init_flow_del(struct dpif_windows *dpif,
                           const struct dpif_flow_del *del,
                           struct dpif_windows_flow *request)
{
    dpif_windows_flow_init(request);
    request->cmd = OVS_FLOW_CMD_DEL;
    request->dp_ifindex = dpif->dp_ifindex;
    request->key = del->key;
    request->key_len = del->key_len;
    if (del->ufid) {
        request->ufid = *del->ufid;
        request->ufid_present = true;
    }
    request->ufid_terse = del->terse;
}

/* ====================================================================
 * Lifecycle.
 * ==================================================================== */

/* Lists the names of all datapaths the kernel exposes, mirroring
 * dpif_netlink_enumerate().  dpctl commands that take an optional datapath
 * argument gate on dp_exists()/dp_enumerate_names(): without this method the
 * set comes back empty and even a valid "system@ovs-system" is rejected with
 * "datapath not found".  We dump the datapaths from the kernel rather than
 * hard-coding the name. */
static int
dpif_windows_enumerate(struct sset *all_dps,
                       const struct dpif_class *dpif_class)
{
    struct ovsext_channel channel;
    struct ovsext_dump dump;
    struct dpif_windows_dp request;
    struct ofpbuf *buf;
    struct ofpbuf msg;
    int error;

    /* Every datapath is reported with the conventional name "ovs-system" (as on
     * Linux); the switch identity lives in the dpif type.  A per-switch alias
     * class (type == a switch GUID) reports "ovs-system" iff its switch's
     * datapath exists, so it shows as "<switch-guid>@ovs-system".  The base
     * "system" class reports "ovs-system" for the default (lowest) datapath
     * ("system@ovs-system").  Thus "ovs-dpctl show" lists each switch once plus
     * the default. */
    bool specific = strcmp(dpif_class->type, OVS_WINDOWS_DEFAULT_DP_TYPE) != 0;

    error = ovsext_channel_open(&channel);
    if (error) {
        return error;
    }

    dpif_windows_dp_init(&request);
    request.cmd = OVS_DP_CMD_GET;

    buf = ofpbuf_new(1024);
    dpif_windows_dp_to_ofpbuf(&request, buf);
    nl_msg_nlmsghdr(buf)->nlmsg_flags |= NLM_F_DUMP;
    ovsext_dump_start(&dump, &channel, buf);
    ofpbuf_delete(buf);

    bool any = false;
    while (ovsext_dump_next(&dump, &msg)) {
        struct dpif_windows_dp dp;

        if (!dpif_windows_dp_from_ofpbuf(&dp, &msg) && dp.name) {
            if (specific) {
                if (!strcmp(dp.name, dpif_class->type)) {
                    any = true;
                }
            } else {
                any = true;
            }
        }
    }

    /* Report the conventional datapath name when this class' datapath exists:
     * for a per-switch class that is its own switch ("<guid>@ovs-system"); for
     * the base "system" class the default (lowest) datapath ("system@ovs-
     * system").  dpif_windows_open resolves a per-switch class by its type and
     * the base class by the "ovs-system" name. */
    if (any) {
        sset_add(all_dps, "ovs-system");
    }

    error = ovsext_dump_done(&dump);
    ovsext_channel_close(&channel);
    return error;
}

/* One datapath as reported by an OVS_DP_CMD_GET dump. */
struct dpif_windows_dp_entry {
    int dp_ifindex;
    char name[OVS_DP_NAME_MAX];
};

/* Dumps all datapaths on 'channel' into 'entries' (capacity 'max').  Returns
 * the number collected, or a negative errno on dump failure. */
static int
dpif_windows_dump_dps(struct ovsext_channel *channel,
                      struct dpif_windows_dp_entry *entries, int max)
{
    struct ovsext_dump dump;
    struct dpif_windows_dp request;
    struct ofpbuf *buf;
    struct ofpbuf msg;
    int n = 0;
    int error;

    dpif_windows_dp_init(&request);
    request.cmd = OVS_DP_CMD_GET;

    buf = ofpbuf_new(1024);
    dpif_windows_dp_to_ofpbuf(&request, buf);
    nl_msg_nlmsghdr(buf)->nlmsg_flags |= NLM_F_DUMP;
    ovsext_dump_start(&dump, channel, buf);
    ofpbuf_delete(buf);

    while (ovsext_dump_next(&dump, &msg)) {
        struct dpif_windows_dp dp;

        if (!dpif_windows_dp_from_ofpbuf(&dp, &msg) && n < max) {
            entries[n].dp_ifindex = dp.dp_ifindex;
            ovs_strlcpy(entries[n].name, dp.name ? dp.name : "",
                        sizeof entries[n].name);
            n++;
        }
    }

    error = ovsext_dump_done(&dump);
    return error ? -error : n;
}

/* Resolves the userspace dpif 'name' to a kernel datapath by dumping all
 * datapaths and matching.  The backer name is "ovs-<datapath_type>"; the
 * default suffix ("system") selects the lowest-numbered datapath,
 * otherwise the suffix must exactly match a datapath's reported name.  On
 * success sets '*dp_ifindex' and '*dp_name' (the caller frees '*dp_name'). */
static int
dpif_windows_resolve_dp(struct ovsext_channel *channel, const char *name,
                        int *dp_ifindex, char **dp_name)
{
    struct dpif_windows_dp_entry entries[DPIF_WINDOWS_MAX_DPS];
    const char *suffix;
    bool is_default;
    int n, i, best = -1;

    n = dpif_windows_dump_dps(channel, entries, ARRAY_SIZE(entries));
    if (n < 0) {
        return -n;
    }
    if (n == 0) {
        return ENODEV;
    }

    suffix = name;
    if (!strncmp(suffix, "ovs-", 4)) {
        suffix += 4;
    }
    is_default = !strcmp(suffix, "system");

    for (i = 0; i < n; i++) {
        if (is_default) {
            if (best < 0 || entries[i].dp_ifindex < entries[best].dp_ifindex) {
                best = i;
            }
        } else if (!strcmp(entries[i].name, suffix)) {
            best = i;
            break;
        }
    }

    if (best < 0) {
        return ENODEV;
    }

    *dp_ifindex = entries[best].dp_ifindex;
    *dp_name = xstrdup(entries[best].name);
    return 0;
}

/* The ovsext kernel backs one datapath per Hyper-V switch, named by the switch
 * GUID.  ofproto-dpif shares one dpif backer per datapath_type and looks the
 * type up as a registered dpif class, so a bridge that selects a specific
 * switch with datapath_type=<switch-guid> needs a dpif provider registered
 * under that GUID.  This registers an alias of 'dpif_windows_class' whose type
 * is 'type', provided a kernel datapath currently carries that GUID name.
 * Returns 0 if an alias is (or already was) registered, EAFNOSUPPORT if no
 * datapath has that name, or another positive errno on failure. */
int
dpif_windows_register_switch_type(const char *type)
{
    struct dpif_windows_dp_entry entries[DPIF_WINDOWS_MAX_DPS];
    struct ovsext_channel channel;
    struct dpif_class *alias;
    bool found = false;
    int n, i, error;

    error = ovsext_channel_open(&channel);
    if (error) {
        return error;
    }
    n = dpif_windows_dump_dps(&channel, entries, ARRAY_SIZE(entries));
    ovsext_channel_close(&channel);
    if (n < 0) {
        return -n;
    }

    for (i = 0; i < n; i++) {
        if (!strcmp(entries[i].name, type)) {
            found = true;
            break;
        }
    }
    if (!found) {
        return EAFNOSUPPORT;
    }

    alias = xmemdup(&dpif_windows_class, sizeof dpif_windows_class);
    alias->type = xstrdup(type);
    error = dp_register_provider(alias);
    if (error) {
        /* EEXIST means a concurrent open already registered it; treat as OK. */
        free(CONST_CAST(char *, alias->type));
        free(alias);
        return error == EEXIST ? 0 : error;
    }
    return 0;
}

/* Registers a per-switch alias of 'dpif_windows_class' for every Hyper-V switch
 * the kernel currently exposes a datapath for.  ofproto resolves a bridge's
 * datapath_type by enumerating registered dpif types before opening a backer,
 * so the switch-GUID types must be registered up front (lazy registration at
 * open time would be rejected earlier as an "unknown datapath type").  Already
 * registered types are skipped; failures are non-fatal. */
void
dpif_windows_register_all_switch_types(void)
{
    struct dpif_windows_dp_entry entries[DPIF_WINDOWS_MAX_DPS];
    struct ovsext_channel channel;
    int n, i;

    if (ovsext_channel_open(&channel)) {
        return;
    }
    n = dpif_windows_dump_dps(&channel, entries, ARRAY_SIZE(entries));
    ovsext_channel_close(&channel);

    for (i = 0; i < n; i++) {
        struct dpif_class *alias;

        if (!entries[i].name[0] || dp_class_is_registered(entries[i].name)) {
            continue;
        }
        /* Any registration failure just means we free the unused alias. */
        alias = xmemdup(&dpif_windows_class, sizeof dpif_windows_class);
        alias->type = xstrdup(entries[i].name);
        if (dp_register_provider(alias)) {
            free(CONST_CAST(char *, alias->type));
            free(alias);
        }
    }
}

static int
dpif_windows_open(const struct dpif_class *class, const char *name,
                  bool create, struct dpif **dpifp)
{
    struct dpif_windows *dpif;
    struct dpif_windows_dp dp_request, dp;
    struct ofpbuf *buf = NULL;
    uint32_t upcall_pid;
    char *dp_name = NULL;
    int dp_ifindex = 0;
    int error;

    dpif = xzalloc(sizeof *dpif);
    error = ovsext_channel_open(&dpif->channel);
    if (error) {
        free(dpif);
        return error;
    }

    /* Initialize 'dpif' enough that the transact helpers (which read
     * dpif->channel and dpif->dp_ifindex) work; dp_ifindex stays 0 until the
     * kernel tells us otherwise. */
    dpif_init(&dpif->dpif, class, name, 0, 0);
    dpif->dp_ifindex = 0;

    /* Resolve to a concrete kernel datapath. The driver owns datapath lifetime
     * (one per Hyper-V switch), so we never create one here; an OVS_DP_CMD_NEW
     * for an existing datapath returns EEXIST, which lets dpif_create_and_open()
     * fall back to the open path unchanged.
     *
     * A per-switch alias class carries the switch identity (its GUID) in the
     * class type, while its datapaths are named with the conventional
     * "ovs-system"; resolve by the type so the right switch is selected
     * regardless of the (cosmetic) name.  The base "system" class resolves by
     * name, mapping the "system" suffix to the lowest datapath. */
    const char *resolve_key =
        strcmp(class->type, OVS_WINDOWS_DEFAULT_DP_TYPE) ? class->type : name;
    error = dpif_windows_resolve_dp(&dpif->channel, resolve_key, &dp_ifindex,
                                    &dp_name);
    if (error) {
        ovsext_channel_close(&dpif->channel);
        dpif_uninit(&dpif->dpif, false);
        free(dpif);
        return error;
    }

    dpif_windows_dp_init(&dp_request);
    upcall_pid = dpif->channel.pid;
    dp_request.upcall_pid = &upcall_pid;
    dp_request.name = OVS_WINDOWS_KERNEL_DP_NAME;
    dp_request.dp_ifindex = dp_ifindex;
    dp_request.cmd = create ? OVS_DP_CMD_NEW : OVS_DP_CMD_GET;

    error = dpif_windows_dp_transact(dpif, &dp_request, &dp, &buf);
    if (error) {
        free(dp_name);
        ovsext_channel_close(&dpif->channel);
        dpif_uninit(&dpif->dpif, false);
        free(dpif);
        return error;
    }

    dpif->dp_ifindex = dp.dp_ifindex;
    dpif->dp_name = dp_name;
    dpif->user_features = dp.user_features;
    /* The channel stamps this on the packet subscribe/pend requests, which the
     * kernel validates against a live datapath.  The default datapath need not
     * be slot 0 (it is promoted on detach), so use the resolved index. */
    dpif->channel.dp_ifindex = dp.dp_ifindex;
    ofpbuf_delete(buf);

    *dpifp = &dpif->dpif;
    return 0;
}

static void
dpif_windows_close(struct dpif *dpif_)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);

    /* dpif_close() -> dpif_uninit() invokes this method and then frees
     * base_name/full_name itself; the class 'close' must only release its own
     * resources and the containing struct (mirrors dpif_netlink_close).
     * Calling dpif_uninit() here double-frees base_name. */
    ovsext_channel_close(&dpif->channel);
    free(dpif->dp_name);
    free(dpif);
}

static int
dpif_windows_destroy(struct dpif *dpif_)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    struct dpif_windows_dp dp;

    dpif_windows_dp_init(&dp);
    dp.cmd = OVS_DP_CMD_DEL;
    dp.dp_ifindex = dpif->dp_ifindex;
    return dpif_windows_dp_transact(dpif, &dp, NULL, NULL);
}

static int
dpif_windows_get_stats(const struct dpif *dpif_, struct dpif_dp_stats *stats)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    struct dpif_windows_dp dp;
    struct ofpbuf *buf;
    int error;

    error = dpif_windows_dp_get(dpif, &dp, &buf);
    if (!error) {
        memset(stats, 0, sizeof *stats);

        if (dp.stats) {
            stats->n_hit    = get_32aligned_u64(&dp.stats->n_hit);
            stats->n_missed = get_32aligned_u64(&dp.stats->n_missed);
            stats->n_lost   = get_32aligned_u64(&dp.stats->n_lost);
            stats->n_flows  = get_32aligned_u64(&dp.stats->n_flows);
        }
        if (dp.megaflow_stats) {
            stats->n_masks = dp.megaflow_stats->n_masks;
            stats->n_mask_hit =
                get_32aligned_u64(&dp.megaflow_stats->n_mask_hit);
            stats->n_cache_hit = UINT64_MAX;
        } else {
            stats->n_masks = UINT32_MAX;
            stats->n_mask_hit = UINT64_MAX;
            stats->n_cache_hit = UINT64_MAX;
        }
        ofpbuf_delete(buf);
    }
    return error;
}

static char *
dpif_windows_get_datapath_version(void)
{
    return xstrdup("ovsext-native-dpif");
}

static bool
dpif_windows_run(struct dpif *dpif_ OVS_UNUSED)
{
    return false;
}

/* ====================================================================
 * Ports.
 * ==================================================================== */

static int
dpif_windows_port_add__(struct dpif_windows *dpif, const char *name,
                        enum ovs_vport_type type, struct ofpbuf *options,
                        odp_port_t *port_nop)
{
    struct dpif_windows_vport request, reply;
    struct ofpbuf *buf;
    uint32_t upcall_pid;
    int error;

    /* The ovsext driver routes upcalls to the single subscribed userspace pid
     * (this channel's pid); there is no per-vport socket as on Linux. */
    upcall_pid = dpif->channel.pid;

    dpif_windows_vport_init(&request);
    request.cmd = OVS_VPORT_CMD_NEW;
    request.dp_ifindex = dpif->dp_ifindex;
    request.type = type;
    request.name = name;
    request.port_no = *port_nop;
    request.n_upcall_pids = 1;
    request.upcall_pids = &upcall_pid;
    if (options) {
        request.options = options->data;
        request.options_len = options->size;
    }

    error = dpif_windows_vport_transact(dpif, &request, &reply, &buf);
    if (!error) {
        *port_nop = reply.port_no;
        ofpbuf_delete(buf);
    } else if (error == EBUSY && *port_nop != ODPP_NONE) {
        VLOG_INFO("%s: requested port %"PRIu32" is in use",
                  dpif_name(&dpif->dpif), *port_nop);
    }
    return error;
}

static int
dpif_windows_port_add(struct dpif *dpif_, struct netdev *netdev,
                      odp_port_t *port_nop)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    const struct netdev_tunnel_config *tnl_cfg;
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *type = netdev_get_type(netdev);
    uint64_t options_stub[64 / 8];
    enum ovs_vport_type ovs_type;
    struct ofpbuf options;
    const char *name;

    name = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);

    ovs_type = netdev_to_ovs_vport_type(type);
    if (ovs_type == OVS_VPORT_TYPE_UNSPEC) {
        VLOG_WARN_RL(&error_rl, "%s: cannot create port `%s' because it has "
                     "unsupported type `%s'",
                     dpif_name(dpif_), name, type);
        return EINVAL;
    }

    /* Internal ports are backed by a Hyper-V WMI interface created here, as in
     * dpif-netlink's _WIN32 path. */
    if (ovs_type == OVS_VPORT_TYPE_INTERNAL) {
        /* dpif->dp_name is the bridge datapath's switch identity (the Hyper-V
         * switch GUID), so the internal port is created on that exact switch. */
        if (!create_wmi_port(CONST_CAST(char *, name), dpif->dp_name)) {
            VLOG_ERR("Could not create wmi internal port with name: %s", name);
            return EINVAL;
        }
    }

    tnl_cfg = netdev_get_tunnel_config(netdev);
    if (tnl_cfg && (tnl_cfg->dst_port != 0 || tnl_cfg->exts)) {
        ofpbuf_use_stack(&options, options_stub, sizeof options_stub);
        if (tnl_cfg->dst_port) {
            nl_msg_put_u16(&options, OVS_TUNNEL_ATTR_DST_PORT,
                           ntohs(tnl_cfg->dst_port));
        }
        if (tnl_cfg->exts) {
            size_t ext_ofs;
            int i;

            ext_ofs = nl_msg_start_nested(&options, OVS_TUNNEL_ATTR_EXTENSION);
            for (i = 0; i < 32; i++) {
                if (tnl_cfg->exts & (UINT32_C(1) << i)) {
                    nl_msg_put_flag(&options, i);
                }
            }
            nl_msg_end_nested(&options, ext_ofs);
        }
        return dpif_windows_port_add__(dpif, name, ovs_type, &options,
                                       port_nop);
    } else {
        return dpif_windows_port_add__(dpif, name, ovs_type, NULL, port_nop);
    }
}

static int
dpif_windows_port_query__(const struct dpif_windows *dpif, odp_port_t port_no,
                          const char *port_name, struct dpif_port *dpif_port)
{
    struct dpif_windows_vport request, reply;
    struct ofpbuf *buf;
    int error;

    dpif_windows_vport_init(&request);
    request.cmd = OVS_VPORT_CMD_GET;
    request.dp_ifindex = dpif->dp_ifindex;
    request.port_no = port_no;
    request.name = port_name;

    error = dpif_windows_vport_transact(CONST_CAST(struct dpif_windows *, dpif),
                                        &request, &reply, &buf);
    if (!error) {
        if (reply.dp_ifindex != request.dp_ifindex) {
            error = ENODEV;
        } else if (dpif_port) {
            dpif_port->name = xstrdup(reply.name);
            dpif_port->type = xstrdup(get_vport_type(&reply));
            dpif_port->port_no = reply.port_no;
        }
        ofpbuf_delete(buf);
    }
    return error;
}

static int
dpif_windows_port_del(struct dpif *dpif_, odp_port_t port_no)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    struct dpif_windows_vport vport;
    struct dpif_port dpif_port;
    int error;

    error = dpif_windows_port_query__(dpif, port_no, NULL, &dpif_port);
    if (error) {
        return error;
    }

    dpif_windows_vport_init(&vport);
    vport.cmd = OVS_VPORT_CMD_DEL;
    vport.dp_ifindex = dpif->dp_ifindex;
    vport.port_no = port_no;

    if (!strcmp(dpif_port.type, "internal")) {
        if (!delete_wmi_port(CONST_CAST(char *, dpif_port.name))) {
            VLOG_ERR("Could not delete wmi port with name: %s",
                     dpif_port.name);
        }
    }

    error = dpif_windows_vport_transact(dpif, &vport, NULL, NULL);

    dpif_port_destroy(&dpif_port);
    return error;
}

static int
dpif_windows_port_query_by_number(const struct dpif *dpif_, odp_port_t port_no,
                                  struct dpif_port *dpif_port)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);

    return dpif_windows_port_query__(dpif, port_no, NULL, dpif_port);
}

static int
dpif_windows_port_query_by_name(const struct dpif *dpif_, const char *devname,
                                struct dpif_port *dpif_port)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);

    return dpif_windows_port_query__(dpif, 0, devname, dpif_port);
}

static uint32_t
dpif_windows_port_get_pid(const struct dpif *dpif_,
                          odp_port_t port_no OVS_UNUSED)
{
    const struct dpif_windows *dpif = dpif_windows_cast(dpif_);

    /* All upcalls are routed to this channel's single subscribed pid. */
    return dpif->channel.pid;
}

struct dpif_windows_port_state {
    struct ovsext_dump dump;
    struct ofpbuf buf;
};

static int
dpif_windows_port_dump_start(const struct dpif *dpif_, void **statep)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    struct dpif_windows_port_state *state;
    struct dpif_windows_vport request;
    struct ofpbuf *buf;

    *statep = state = xmalloc(sizeof *state);

    dpif_windows_vport_init(&request);
    request.cmd = OVS_VPORT_CMD_GET;
    request.dp_ifindex = dpif->dp_ifindex;

    buf = ofpbuf_new(1024);
    dpif_windows_vport_to_ofpbuf(&request, buf);
    /* NLM_F_DUMP requests every vport. */
    nl_msg_nlmsghdr(buf)->nlmsg_flags |= NLM_F_DUMP;
    ovsext_dump_start(&state->dump, &dpif->channel, buf);
    ofpbuf_delete(buf);

    ofpbuf_init(&state->buf, 4096);
    return 0;
}

static int
dpif_windows_port_dump_next(const struct dpif *dpif_ OVS_UNUSED, void *state_,
                            struct dpif_port *dpif_port)
{
    struct dpif_windows_port_state *state = state_;
    struct dpif_windows_vport vport;
    struct ofpbuf buf;
    int error;

    if (!ovsext_dump_next(&state->dump, &buf)) {
        return EOF;
    }

    error = dpif_windows_vport_from_ofpbuf(&vport, &buf);
    if (error) {
        VLOG_WARN_RL(&error_rl, "failed to parse vport record (%s)",
                     ovs_strerror(error));
        return error;
    }

    dpif_port->name = CONST_CAST(char *, vport.name);
    dpif_port->type = CONST_CAST(char *, get_vport_type(&vport));
    dpif_port->port_no = vport.port_no;
    return 0;
}

static int
dpif_windows_port_dump_done(const struct dpif *dpif_ OVS_UNUSED, void *state_)
{
    struct dpif_windows_port_state *state = state_;
    int error = ovsext_dump_done(&state->dump);

    ofpbuf_uninit(&state->buf);
    free(state);
    return error;
}

static int
dpif_windows_port_poll(const struct dpif *dpif_ OVS_UNUSED,
                       char **devnamep OVS_UNUSED)
{
    /* The ovsext driver has no vport-change multicast notification channel;
     * dpif-netlink relies on OVS_VPORT_MCGROUP which the Windows driver does
     * not expose.  Report "no change". */
    return EAGAIN;
}

static void
dpif_windows_port_poll_wait(const struct dpif *dpif_ OVS_UNUSED)
{
}

/* ====================================================================
 * Flows.
 * ==================================================================== */

static int
dpif_windows_flow_flush(struct dpif *dpif_)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    struct dpif_windows_flow flow;

    dpif_windows_flow_init(&flow);
    flow.cmd = OVS_FLOW_CMD_DEL;
    flow.dp_ifindex = dpif->dp_ifindex;

    return dpif_windows_flow_transact(dpif, &flow, NULL, NULL);
}

struct dpif_windows_flow_dump {
    struct dpif_flow_dump up;
    struct ovsext_dump dump;
    int status;
};

static struct dpif_windows_flow_dump *
dpif_windows_flow_dump_cast(struct dpif_flow_dump *dump)
{
    return CONTAINER_OF(dump, struct dpif_windows_flow_dump, up);
}

static struct dpif_flow_dump *
dpif_windows_flow_dump_create(const struct dpif *dpif_, bool terse,
                              struct dpif_flow_dump_types *types)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    struct dpif_windows_flow_dump *dump;
    struct dpif_windows_flow request;
    struct ofpbuf *buf;

    dump = xzalloc(sizeof *dump);
    dpif_flow_dump_init(&dump->up, dpif_, terse, types);

    dpif_windows_flow_init(&request);
    request.cmd = OVS_FLOW_CMD_GET;
    request.dp_ifindex = dpif->dp_ifindex;
    request.ufid_present = false;
    request.ufid_terse = terse;

    buf = ofpbuf_new(1024);
    dpif_windows_flow_to_ofpbuf(&request, buf);
    nl_msg_nlmsghdr(buf)->nlmsg_flags |= NLM_F_DUMP;
    ovsext_dump_start(&dump->dump, &dpif->channel, buf);
    ofpbuf_delete(buf);

    dump->status = 0;
    return &dump->up;
}

static int
dpif_windows_flow_dump_destroy(struct dpif_flow_dump *dump_)
{
    struct dpif_windows_flow_dump *dump = dpif_windows_flow_dump_cast(dump_);
    int status = ovsext_dump_done(&dump->dump);

    free(dump);
    return status;
}

struct dpif_windows_flow_dump_thread {
    struct dpif_flow_dump_thread up;
    struct dpif_windows_flow_dump *dump;
    struct ofpbuf nl_flows;     /* Borrowed views of the dump buffer. */
};

static struct dpif_windows_flow_dump_thread *
dpif_windows_flow_dump_thread_cast(struct dpif_flow_dump_thread *thread)
{
    return CONTAINER_OF(thread, struct dpif_windows_flow_dump_thread, up);
}

static struct dpif_flow_dump_thread *
dpif_windows_flow_dump_thread_create(struct dpif_flow_dump *dump_)
{
    struct dpif_windows_flow_dump *dump = dpif_windows_flow_dump_cast(dump_);
    struct dpif_windows_flow_dump_thread *thread;

    thread = xmalloc(sizeof *thread);
    dpif_flow_dump_thread_init(&thread->up, &dump->up);
    thread->dump = dump;
    ofpbuf_init(&thread->nl_flows, 0);
    return &thread->up;
}

static void
dpif_windows_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread_)
{
    struct dpif_windows_flow_dump_thread *thread
        = dpif_windows_flow_dump_thread_cast(thread_);

    ofpbuf_uninit(&thread->nl_flows);
    free(thread);
}

static int
dpif_windows_flow_dump_next(struct dpif_flow_dump_thread *thread_,
                            struct dpif_flow *flows, int max_flows)
{
    struct dpif_windows_flow_dump_thread *thread
        = dpif_windows_flow_dump_thread_cast(thread_);
    struct dpif_windows_flow_dump *dump = thread->dump;
    int n_flows = 0;

    max_flows = MIN(max_flows, FLOW_DUMP_MAX_BATCH);

    while (n_flows < max_flows) {
        struct dpif_windows_flow datapath_flow;
        struct ofpbuf nl_flow;
        int error;

        if (!ovsext_dump_next(&dump->dump, &nl_flow)) {
            break;
        }

        error = dpif_windows_flow_from_ofpbuf(&datapath_flow, &nl_flow);
        if (error) {
            dump->status = error;
            break;
        }
        dpif_windows_flow_to_dpif_flow(&flows[n_flows++], &datapath_flow);
    }
    return n_flows;
}

static void
dpif_windows_encode_execute(int dp_ifindex, const struct dpif_execute *d_exec,
                            struct ofpbuf *buf)
{
    struct ovs_header *k_exec;
    size_t key_ofs;

    ofpbuf_prealloc_tailroom(buf, (64
                                   + dp_packet_size(d_exec->packet)
                                   + ODP_KEY_METADATA_SIZE
                                   + d_exec->actions_len));

    nl_msg_put_genlmsghdr(buf, 0, OVS_WIN_NL_PACKET_FAMILY_ID, NLM_F_REQUEST,
                          OVS_PACKET_CMD_EXECUTE, OVS_PACKET_VERSION);

    k_exec = ofpbuf_put_uninit(buf, sizeof *k_exec);
    k_exec->dp_ifindex = dp_ifindex;

    nl_msg_put_unspec(buf, OVS_PACKET_ATTR_PACKET,
                      dp_packet_data(d_exec->packet),
                      dp_packet_size(d_exec->packet));

    key_ofs = nl_msg_start_nested(buf, OVS_PACKET_ATTR_KEY);
    odp_key_from_dp_packet(buf, d_exec->packet);
    nl_msg_end_nested(buf, key_ofs);

    nl_msg_put_unspec(buf, OVS_PACKET_ATTR_ACTIONS,
                      d_exec->actions, d_exec->actions_len);
    if (d_exec->probe) {
        nl_msg_put_flag(buf, OVS_PACKET_ATTR_PROBE);
    }
    if (d_exec->mtu) {
        nl_msg_put_u16(buf, OVS_PACKET_ATTR_MRU, d_exec->mtu);
    }
    if (d_exec->hash) {
        nl_msg_put_u64(buf, OVS_PACKET_ATTR_HASH, d_exec->hash);
    }
}

/* Executes up to OPERATE_MAX_OPS operations.  The ovsext transport has no
 * batched/pipelined transaction primitive (nl_transact_multiple), so we issue
 * one OVS_IOCTL_TRANSACT per op.  Returns the number processed. */
static size_t
dpif_windows_operate__(struct dpif_windows *dpif, struct dpif_op **ops,
                       size_t n_ops)
{
    size_t i;

    n_ops = MIN(n_ops, OPERATE_MAX_OPS);

    for (i = 0; i < n_ops; i++) {
        struct dpif_op *op = ops[i];
        struct ofpbuf request;
        uint64_t request_stub[1024 / 8];
        struct ofpbuf *reply = NULL;
        struct dpif_windows_flow flow;
        int error = 0;

        ofpbuf_use_stub(&request, request_stub, sizeof request_stub);

        switch (op->type) {
        case DPIF_OP_FLOW_PUT: {
            struct dpif_flow_put *put = &op->flow_put;

            dpif_windows_init_flow_put(dpif, put, &flow);
            if (put->stats) {
                flow.nlmsg_flags |= NLM_F_ECHO;
            }
            dpif_windows_flow_to_ofpbuf(&flow, &request);
            error = ovsext_transact(&dpif->channel, &request,
                                    put->stats ? &reply : NULL);
            if (!error && put->stats) {
                struct dpif_windows_flow reply_flow;

                if (reply
                    && !dpif_windows_flow_from_ofpbuf(&reply_flow, reply)) {
                    dpif_windows_flow_get_stats(&reply_flow, put->stats);
                } else {
                    memset(put->stats, 0, sizeof *put->stats);
                }
            }
            break;
        }

        case DPIF_OP_FLOW_DEL: {
            struct dpif_flow_del *del = &op->flow_del;

            dpif_windows_init_flow_del(dpif, del, &flow);
            if (del->stats) {
                flow.nlmsg_flags |= NLM_F_ECHO;
            }
            dpif_windows_flow_to_ofpbuf(&flow, &request);
            error = ovsext_transact(&dpif->channel, &request,
                                    del->stats ? &reply : NULL);
            if (!error && del->stats) {
                struct dpif_windows_flow reply_flow;

                if (reply
                    && !dpif_windows_flow_from_ofpbuf(&reply_flow, reply)) {
                    dpif_windows_flow_get_stats(&reply_flow, del->stats);
                } else {
                    memset(del->stats, 0, sizeof *del->stats);
                }
            }
            break;
        }

        case DPIF_OP_FLOW_GET: {
            struct dpif_flow_get *get = &op->flow_get;
            struct dpif_windows_flow request_flow;

            dpif_windows_init_flow_get(dpif, get, &request_flow);
            request_flow.nlmsg_flags |= NLM_F_ECHO;
            dpif_windows_flow_to_ofpbuf(&request_flow, &request);
            error = ovsext_transact(&dpif->channel, &request, &reply);
            if (!error) {
                struct dpif_windows_flow reply_flow;

                if (reply
                    && !dpif_windows_flow_from_ofpbuf(&reply_flow, reply)) {
                    dpif_windows_flow_to_dpif_flow(get->flow, &reply_flow);
                    /* The decoded flow points into 'reply'; copy the actions
                     * into the caller-provided buffer and leave 'reply'
                     * attached below is not possible, so copy here. */
                    if (get->buffer && reply_flow.key) {
                        ofpbuf_clear(get->buffer);
                        if (reply_flow.actions_len) {
                            ofpbuf_put(get->buffer, reply_flow.actions,
                                       reply_flow.actions_len);
                            get->flow->actions =
                                ofpbuf_at(get->buffer, 0, 0);
                            get->flow->actions_len = reply_flow.actions_len;
                        }
                        if (reply_flow.key_len) {
                            get->flow->key =
                                ofpbuf_put(get->buffer, reply_flow.key,
                                           reply_flow.key_len);
                            get->flow->key_len = reply_flow.key_len;
                        }
                        if (reply_flow.mask_len) {
                            get->flow->mask =
                                ofpbuf_put(get->buffer, reply_flow.mask,
                                           reply_flow.mask_len);
                            get->flow->mask_len = reply_flow.mask_len;
                        }
                    }
                } else {
                    error = ENOENT;
                }
            }
            break;
        }

        case DPIF_OP_EXECUTE:
            if (OVS_UNLIKELY(nl_attr_oversized(
                                 dp_packet_size(op->execute.packet)))) {
                if (i == 0) {
                    VLOG_ERR_RL(&error_rl,
                                "dropping oversized %"PRIu32"-byte packet",
                                dp_packet_size(op->execute.packet));
                    op->error = ENOBUFS;
                    ofpbuf_uninit(&request);
                    return 1;
                }
                ofpbuf_uninit(&request);
                return i;
            }
            dpif_windows_encode_execute(dpif->dp_ifindex, &op->execute,
                                        &request);
            error = ovsext_transact(&dpif->channel, &request, NULL);
            break;

        default:
            OVS_NOT_REACHED();
        }

        op->error = error;
        ofpbuf_delete(reply);
        ofpbuf_uninit(&request);
    }

    return n_ops;
}

static void
dpif_windows_operate(struct dpif *dpif_, struct dpif_op **ops, size_t n_ops,
                     enum dpif_offload_type offload_type)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);

    /* Windows has no hardware-offload (netdev flow API) path; behave as the
     * DPIF_OFFLOAD_NEVER branch of dpif-netlink. */
    if (offload_type == DPIF_OFFLOAD_ALWAYS) {
        for (size_t i = 0; i < n_ops; i++) {
            ops[i]->error = EOPNOTSUPP;
        }
        return;
    }

    while (n_ops > 0) {
        size_t chunk = dpif_windows_operate__(dpif, ops, n_ops);

        ops += chunk;
        n_ops -= chunk;
    }
}

/* ====================================================================
 * Upcalls.  Single handler, ovsext packet subscription.
 * ==================================================================== */

static int
parse_odp_packet(struct dpif_windows *dpif, struct ofpbuf *buf,
                 struct dpif_upcall *upcall, int *dp_ifindex)
{
    static const struct nl_policy ovs_packet_policy[] = {
        [OVS_PACKET_ATTR_PACKET] = { .type = NL_A_UNSPEC,
                                     .min_len = ETH_HEADER_LEN },
        [OVS_PACKET_ATTR_KEY] = { .type = NL_A_NESTED },
        [OVS_PACKET_ATTR_USERDATA] = { .type = NL_A_UNSPEC, .optional = true },
        [OVS_PACKET_ATTR_EGRESS_TUN_KEY] = { .type = NL_A_NESTED,
                                             .optional = true },
        [OVS_PACKET_ATTR_ACTIONS] = { .type = NL_A_NESTED, .optional = true },
        [OVS_PACKET_ATTR_MRU] = { .type = NL_A_U16, .optional = true },
        [OVS_PACKET_ATTR_HASH] = { .type = NL_A_U64, .optional = true },
    };

    struct ofpbuf b = ofpbuf_const_initializer(buf->data, buf->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(&b, sizeof *genl);
    struct ovs_header *ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);

    struct nlattr *a[ARRAY_SIZE(ovs_packet_policy)];
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != OVS_WIN_NL_PACKET_FAMILY_ID
        || !nl_policy_parse(&b, 0, ovs_packet_policy, a,
                            ARRAY_SIZE(ovs_packet_policy))) {
        return EINVAL;
    }

    int type = (genl->cmd == OVS_PACKET_CMD_MISS ? DPIF_UC_MISS
                : genl->cmd == OVS_PACKET_CMD_ACTION ? DPIF_UC_ACTION
                : -1);
    if (type < 0) {
        return EINVAL;
    }

    /* (Re)set ALL fields of '*upcall' on successful return. */
    upcall->type = type;
    upcall->key = CONST_CAST(struct nlattr *,
                             nl_attr_get(a[OVS_PACKET_ATTR_KEY]));
    upcall->key_len = nl_attr_get_size(a[OVS_PACKET_ATTR_KEY]);
    odp_flow_key_hash(upcall->key, upcall->key_len, &upcall->ufid);
    upcall->userdata = a[OVS_PACKET_ATTR_USERDATA];
    upcall->out_tun_key = a[OVS_PACKET_ATTR_EGRESS_TUN_KEY];
    upcall->actions = a[OVS_PACKET_ATTR_ACTIONS];
    upcall->mru = a[OVS_PACKET_ATTR_MRU];
    upcall->hash = a[OVS_PACKET_ATTR_HASH];

    /* Allow overwriting the netlink attribute header without reallocating. */
    dp_packet_use_stub(&upcall->packet,
                    CONST_CAST(struct nlattr *,
                               nl_attr_get(a[OVS_PACKET_ATTR_PACKET])) - 1,
                    nl_attr_get_size(a[OVS_PACKET_ATTR_PACKET]) +
                    sizeof(struct nlattr));
    dp_packet_set_data(&upcall->packet,
                    (char *) dp_packet_data(&upcall->packet)
                    + sizeof(struct nlattr));
    dp_packet_set_size(&upcall->packet,
                       nl_attr_get_size(a[OVS_PACKET_ATTR_PACKET]));

    if (nl_attr_find__(upcall->key, upcall->key_len, OVS_KEY_ATTR_ETHERNET)) {
        upcall->packet.packet_type = htonl(PT_ETH);
    } else {
        ovs_be16 ethertype = 0;
        const struct nlattr *et_nla = nl_attr_find__(upcall->key,
                                                     upcall->key_len,
                                                     OVS_KEY_ATTR_ETHERTYPE);
        if (et_nla) {
            ethertype = nl_attr_get_be16(et_nla);
        }
        upcall->packet.packet_type = PACKET_TYPE_BE(OFPHTN_ETHERTYPE,
                                                    ntohs(ethertype));
        dp_packet_set_l3(&upcall->packet, dp_packet_data(&upcall->packet));
    }

    *dp_ifindex = ovs_header->dp_ifindex;
    return 0;
}

/*
 * Re-stamps the upcall pid on every existing vport to this dpif's channel pid.
 *
 * ovs-vswitchd does not re-create the kernel-owned vports (VM NICs, the
 * external/internal Hyper-V ports) when it (re)starts, so without this they
 * keep the previous, now-dead vswitchd's upcall pid and every packet miss is
 * dropped -- the datapath wedges until a reboot.  This mirrors dpif-netlink's
 * dpif_netlink_refresh_handlers_vport_dispatch, which Linux runs from
 * recv_set() for the same reason.
 *
 * The ovsext channel has a single stateful dump cursor, so the port numbers are
 * collected first and the SETs issued only after the dump completes; a transact
 * issued mid-dump would re-arm and destroy the cursor.  recv_set() runs on the
 * main thread before the upcall handler threads are started, so the channel is
 * not used concurrently here.
 */
static void
dpif_windows_refresh_port_upcall_pids(struct dpif_windows *dpif)
{
    struct ovsext_dump dump;
    struct dpif_windows_vport request;
    struct ofpbuf *buf;
    odp_port_t *ports = NULL;
    size_t n = 0, allocated = 0;
    uint32_t pid = dpif->channel.pid;
    size_t i;

    dpif_windows_vport_init(&request);
    request.cmd = OVS_VPORT_CMD_GET;
    request.dp_ifindex = dpif->dp_ifindex;
    buf = ofpbuf_new(1024);
    dpif_windows_vport_to_ofpbuf(&request, buf);
    /* NLM_F_DUMP requests every vport. */
    nl_msg_nlmsghdr(buf)->nlmsg_flags |= NLM_F_DUMP;
    ovsext_dump_start(&dump, &dpif->channel, buf);
    ofpbuf_delete(buf);

    for (;;) {
        struct dpif_windows_vport vport;
        struct ofpbuf rec;

        if (!ovsext_dump_next(&dump, &rec)) {
            break;
        }
        if (dpif_windows_vport_from_ofpbuf(&vport, &rec)) {
            continue;
        }
        if (vport.n_upcall_pids == 1 && vport.upcall_pids
            && vport.upcall_pids[0] == pid) {
            continue;       /* Already points at this vswitchd. */
        }
        if (n >= allocated) {
            allocated = allocated ? allocated * 2 : 16;
            ports = xrealloc(ports, allocated * sizeof *ports);
        }
        ports[n++] = vport.port_no;
    }
    ovsext_dump_done(&dump);

    for (i = 0; i < n; i++) {
        struct dpif_windows_vport set;
        int error;

        dpif_windows_vport_init(&set);
        set.cmd = OVS_VPORT_CMD_SET;
        set.dp_ifindex = dpif->dp_ifindex;
        set.port_no = ports[i];
        set.n_upcall_pids = 1;
        set.upcall_pids = &pid;
        error = dpif_windows_vport_transact(dpif, &set, NULL, NULL);
        if (error && error != ENODEV && error != ENOENT) {
            VLOG_WARN_RL(&error_rl,
                         "failed to refresh upcall pid for port %"PRIu32" (%s)",
                         odp_to_u32(ports[i]), ovs_strerror(error));
        }
    }
    free(ports);
}

static int
dpif_windows_recv_set(struct dpif *dpif_, bool enable)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    int error;

    error = ovsext_subscribe_packets(&dpif->channel, enable);
    if (!error) {
        dpif->upcalls_enabled = enable;
        if (enable) {
            dpif_windows_refresh_port_upcall_pids(dpif);
        }
    }
    return error;
}

static int
dpif_windows_handlers_set(struct dpif *dpif_ OVS_UNUSED,
                          uint32_t n_handlers OVS_UNUSED)
{
    /* The ovsext driver supports a single upcall handler.  Mirror
     * dpif-netlink's _WIN32 handlers_set, which is a no-op success. */
    return 0;
}

static bool
dpif_windows_number_handlers_required(struct dpif *dpif_ OVS_UNUSED,
                                      uint32_t *n_handlers)
{
    *n_handlers = 1;            /* Windows uses a single upcall handler. */
    return true;
}

#define PACKET_RECV_BATCH_SIZE 50
static int
dpif_windows_recv(struct dpif *dpif_, uint32_t handler_id,
                  struct dpif_upcall *upcall, struct ofpbuf *buf)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    int read_tries = 0;

    /* Only a single handler is supported. */
    if (handler_id >= 1 || !dpif->upcalls_enabled) {
        return EAGAIN;
    }

    for (;;) {
        int dp_ifindex;
        int error;

        if (++read_tries > PACKET_RECV_BATCH_SIZE) {
            return EAGAIN;
        }

        ofpbuf_clear(buf);
        error = ovsext_recv(&dpif->channel, buf);
        if (error) {
            if (error == EAGAIN) {
                break;
            }
            return error;
        }

        error = parse_odp_packet(dpif, buf, upcall, &dp_ifindex);
        if (!error && dp_ifindex == dpif->dp_ifindex) {
            return 0;
        } else if (error) {
            return error;
        }
        /* Packet was for another datapath; keep draining. */
    }

    return EAGAIN;
}

static void
dpif_windows_recv_wait(struct dpif *dpif_, uint32_t handler_id)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);

    if (handler_id >= 1 || !dpif->upcalls_enabled) {
        return;
    }
    ovsext_recv_wait(&dpif->channel);
}

static void
dpif_windows_recv_purge(struct dpif *dpif_)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    uint64_t buf_stub[2048 / 8];
    struct ofpbuf buf;

    if (!dpif->upcalls_enabled) {
        return;
    }

    /* Drain any queued upcalls. */
    ofpbuf_use_stub(&buf, buf_stub, sizeof buf_stub);
    while (ovsext_recv(&dpif->channel, &buf) == 0) {
        ofpbuf_clear(&buf);
    }
    ofpbuf_uninit(&buf);
}

/* ====================================================================
 * Class.
 * ==================================================================== */

const struct dpif_class dpif_windows_class = {
    .type = OVS_WINDOWS_DEFAULT_DP_TYPE,
    .cleanup_required = false,
    .enumerate = dpif_windows_enumerate,
    .open = dpif_windows_open,
    .close = dpif_windows_close,
    .destroy = dpif_windows_destroy,
    .run = dpif_windows_run,
    .get_stats = dpif_windows_get_stats,
    .port_add = dpif_windows_port_add,
    .port_del = dpif_windows_port_del,
    .port_query_by_number = dpif_windows_port_query_by_number,
    .port_query_by_name = dpif_windows_port_query_by_name,
    .port_get_pid = dpif_windows_port_get_pid,
    .port_dump_start = dpif_windows_port_dump_start,
    .port_dump_next = dpif_windows_port_dump_next,
    .port_dump_done = dpif_windows_port_dump_done,
    .port_poll = dpif_windows_port_poll,
    .port_poll_wait = dpif_windows_port_poll_wait,
    .flow_flush = dpif_windows_flow_flush,
    .flow_dump_create = dpif_windows_flow_dump_create,
    .flow_dump_destroy = dpif_windows_flow_dump_destroy,
    .flow_dump_thread_create = dpif_windows_flow_dump_thread_create,
    .flow_dump_thread_destroy = dpif_windows_flow_dump_thread_destroy,
    .flow_dump_next = dpif_windows_flow_dump_next,
    .operate = dpif_windows_operate,
    .recv_set = dpif_windows_recv_set,
    .handlers_set = dpif_windows_handlers_set,
    .number_handlers_required = dpif_windows_number_handlers_required,
    .recv = dpif_windows_recv,
    .recv_wait = dpif_windows_recv_wait,
    .recv_purge = dpif_windows_recv_purge,
    .get_datapath_version = dpif_windows_get_datapath_version,
};

#endif /* _WIN32 */
