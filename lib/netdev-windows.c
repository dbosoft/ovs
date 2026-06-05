/*
 * Copyright (c) 2014, 2016 VMware, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <config.h>
#include <errno.h>
#include <iphlpapi.h>

#include <net/if.h>

#include "coverage.h"
#include "fatal-signal.h"
#include "netdev-provider.h"
#include "openvswitch/list.h"
#include "openvswitch/ofpbuf.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/shash.h"
#include "svec.h"
#include "openvswitch/vlog.h"
#include "odp-netlink.h"
#include "netlink.h"
#include "ovsext-channel.h"
#include "timeval.h"

VLOG_DEFINE_THIS_MODULE(netdev_windows);
static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(9999, 5);

enum {
    VALID_ETHERADDR         = 1 << 0,
    VALID_MTU               = 1 << 1,
    VALID_IFFLAG            = 1 << 5,
};

/* Caches the information of a netdev. */
struct netdev_windows {
    struct netdev up;
    int32_t dev_type;
    uint32_t port_no;

    unsigned int change_seq;

    unsigned int cache_valid;
    int ifindex;
    struct eth_addr mac;
    uint32_t mtu;
    unsigned int ifi_flags;

    struct ovs_list list_node;       /* In 'netdev_windows_list'. */
    bool carrier;                    /* Last observed media carrier state. */
    long long int carrier_resets;    /* # of carrier transitions observed. */
    NET_LUID if_luid;                /* Host interface LUID (carrier lookup). */
    bool if_luid_valid;              /* 'if_luid' has been resolved. */
};

/* All constructed netdev_windows, so the periodic carrier refresh in
 * netdev_windows_run()/wait() can iterate them. */
static struct ovs_list netdev_windows_list
    = OVS_LIST_INITIALIZER(&netdev_windows_list);
static struct ovs_mutex netdev_windows_list_mutex = OVS_MUTEX_INITIALIZER;

/* How often the media carrier of each netdev is re-queried from the kernel.
 * The kernel learns link-state changes from NDIS indications immediately; this
 * is just the userspace poll cadence that bounds bond failover latency. */
#define NETDEV_WINDOWS_CARRIER_INTERVAL_MS 1000

/* time_msec() at which the next carrier refresh is due (shared by run/wait). */
static long long int netdev_windows_next_refresh = 0;

/* Utility structure for netdev commands. */
struct netdev_windows_netdev_info {
    /* Generic Netlink header. */
    uint8_t cmd;

    /* Information that is relevant to ovs. */
    uint32_t dp_ifindex;
    uint32_t port_no;
    uint32_t ovs_type;

    /* General information of a network device. */
    const char *name;
    struct eth_addr mac_address;
    uint32_t mtu;
    uint32_t ifi_flags;
};

static int query_netdev(const char *devname,
                        struct netdev_windows_netdev_info *reply,
                        struct ofpbuf **bufp);
static struct netdev *netdev_windows_alloc(void);
static int netdev_windows_init_(void);

/* Transport to the ovsext datapath device, opened once by
 * netdev_windows_init_().  The netdev generic-netlink family is the fixed
 * OVS_WIN_NL_NETDEV_FAMILY_ID. */
static struct ovsext_channel ovs_win_netdev_channel;

/* Result of the one-time 'ovs_win_netdev_channel' open (0 on success), ENODEV
 * until first attempted.  Lets the construct path tell an absent device (the
 * channel is open, the kernel just has no such vport -> ENODEV) from a failed
 * open (non-zero here), so the latter is not silently deferred into a
 * placeholder, while preserving the real errno for callers and logs. */
static int netdev_windows_channel_error = ENODEV;


static bool
is_netdev_windows_class(const struct netdev_class *netdev_class)
{
    return netdev_class->alloc == netdev_windows_alloc;
}

static struct netdev_windows *
netdev_windows_cast(const struct netdev *netdev_)
{
    ovs_assert(is_netdev_windows_class(netdev_get_class(netdev_)));
    return CONTAINER_OF(netdev_, struct netdev_windows, up);
}

static int
netdev_windows_init_(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        /* XXX: The channel lives for the process lifetime; there is no
         * netdev-provider teardown hook to close it. */
        netdev_windows_channel_error =
            ovsext_channel_open(&ovs_win_netdev_channel);
        if (netdev_windows_channel_error) {
            VLOG_ERR("Failed to open the ovsext datapath device (%s). "
                     "The Open vSwitch kernel extension is probably not loaded.",
                     ovs_strerror(netdev_windows_channel_error));
        }

        ovsthread_once_done(&once);
    }

    /* The open result is assigned only inside the once-block, so a caller after
     * the first attempt would otherwise see success; return the persisted errno
     * so driver-not-loaded is distinguishable from other open failures. */
    return netdev_windows_channel_error;
}

static struct netdev *
netdev_windows_alloc(void)
{
    struct netdev_windows *netdev = xzalloc(sizeof *netdev);
    return netdev ? &netdev->up : NULL;
}

static uint32_t
dp_to_netdev_ifi_flags(uint32_t dp_flags)
{
    uint32_t nd_flags = 0;

    if (dp_flags & OVS_WIN_NETDEV_IFF_UP) {
        nd_flags |= NETDEV_UP;
    }

    if (dp_flags & OVS_WIN_NETDEV_IFF_PROMISC) {
        nd_flags |= NETDEV_PROMISC;
    }

    return nd_flags;
}

static int
netdev_windows_system_construct(struct netdev *netdev_)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);
    struct netdev_windows_netdev_info info;
    struct ofpbuf *buf;
    int ret;
    const char    *type = NULL;

    /* Query the attributes and runtime status of the netdev. */
    ret = query_netdev(netdev_get_name(&netdev->up), &info, &buf);
    /* Build a placeholder netdev only when the kernel reports the device truly
     * absent (ENODEV).  An "internal" netdev does not exist in the kernel yet:
     * it is created later by passing the netdev object to dpif_port_add().  A
     * "system" (NETDEV) port whose backing Hyper-V adapter is not present yet
     * is deferred the same way so dpif_port_add() pre-creates a userspace-first
     * ghost vport, resurrected when the Hyper-V port appears.  This mirrors
     * netdev-linux.c, which ignores ENODEV at construct only for these cases;
     * any other query error -- or an absent device of a non-deferrable type --
     * is a real failure and must fail netdev_open().  On the deferred path
     * query_netdev() zero-initializes 'info' and NULLs 'buf', so the netdev is
     * built from sane defaults and resynced from the kernel by the periodic
     * refresh in netdev_windows_run() once the device appears. */
    {
        const char *t = netdev_get_type(&netdev->up);
        /* Only defer when the channel is open, so a real ENODEV (the kernel has
         * no such vport) is deferred but a missing kernel extension (the channel
         * never opened) still fails netdev_open() instead of producing a
         * placeholder that hides the unavailable datapath. */
        bool deferrable = (!strcmp(t, "internal") || !strcmp(t, "system"))
                          && !netdev_windows_channel_error;
        if (ret && !(deferrable && ret == ENODEV)) {
            return ret;
        }
    }
    ofpbuf_delete(buf);

    /* Don't create netdev if ovs-type is "internal"
     * but the type of netdev->up is "system". */
    type = netdev_get_type(&netdev->up);
    if (type && !strcmp(type, "system") &&
        (info.ovs_type == OVS_VPORT_TYPE_INTERNAL)) {
        VLOG_DBG("construct device %s, ovs_type: %u failed",
                 netdev_get_name(&netdev->up), info.ovs_type);
        return 1;
    }

    netdev->change_seq = 1;
    netdev->dev_type = info.ovs_type;
    netdev->port_no = info.port_no;

    netdev->mac = info.mac_address;
    netdev->cache_valid = VALID_ETHERADDR;
    netdev->ifindex = -EOPNOTSUPP;

    netdev->mtu = info.mtu;
    netdev->cache_valid |= VALID_MTU;

    netdev->ifi_flags = dp_to_netdev_ifi_flags(info.ifi_flags);
    netdev->cache_valid |= VALID_IFFLAG;

    /* Default carrier up (the historical always-up behavior); the periodic
     * refresh in netdev_windows_run() corrects it from the kernel's media link
     * state, so a startup race never falsely disables a bond member. */
    netdev->carrier = true;
    netdev->carrier_resets = 0;
    ovs_mutex_lock(&netdev_windows_list_mutex);
    ovs_list_push_back(&netdev_windows_list, &netdev->list_node);
    ovs_mutex_unlock(&netdev_windows_list_mutex);

    VLOG_DBG("construct device %s, ovs_type: %u.",
             netdev_get_name(&netdev->up), info.ovs_type);
    return 0;
}

static int
netdev_windows_netdev_to_ofpbuf(struct netdev_windows_netdev_info *info,
                                struct ofpbuf *buf)
{
    struct ovs_header *ovs_header;
    int error = EINVAL;

    nl_msg_put_genlmsghdr(buf, 0, OVS_WIN_NL_NETDEV_FAMILY_ID,
                          NLM_F_REQUEST | NLM_F_ECHO,
                          info->cmd, OVS_WIN_NETDEV_VERSION);

    ovs_header = ofpbuf_put_uninit(buf, sizeof *ovs_header);
    ovs_header->dp_ifindex = info->dp_ifindex;

    if (info->name) {
        nl_msg_put_string(buf, OVS_WIN_NETDEV_ATTR_NAME, info->name);
        error = 0;
    }

    return error;
}

static void
netdev_windows_info_init(struct netdev_windows_netdev_info *info)
{
    memset(info, 0, sizeof *info);
}

static int
netdev_windows_netdev_from_ofpbuf(struct netdev_windows_netdev_info *info,
                                  struct ofpbuf *buf)
{
    static const struct nl_policy ovs_netdev_policy[] = {
        [OVS_WIN_NETDEV_ATTR_PORT_NO] = { .type = NL_A_U32 },
        [OVS_WIN_NETDEV_ATTR_TYPE] = { .type = NL_A_U32 },
        [OVS_WIN_NETDEV_ATTR_NAME] = { .type = NL_A_STRING, .max_len = IFNAMSIZ },
        [OVS_WIN_NETDEV_ATTR_MAC_ADDR] = { NL_POLICY_FOR(info->mac_address) },
        [OVS_WIN_NETDEV_ATTR_MTU] = { .type = NL_A_U32 },
        [OVS_WIN_NETDEV_ATTR_IF_FLAGS] = { .type = NL_A_U32 },
    };

    netdev_windows_info_init(info);

    struct ofpbuf b = ofpbuf_const_initializer(buf->data, buf->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(&b, sizeof *genl);
    struct ovs_header *ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);

    struct nlattr *a[ARRAY_SIZE(ovs_netdev_policy)];
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != OVS_WIN_NL_NETDEV_FAMILY_ID
        || !nl_policy_parse(&b, 0, ovs_netdev_policy, a,
                            ARRAY_SIZE(ovs_netdev_policy))) {
        return EINVAL;
    }

    info->cmd = genl->cmd;
    info->dp_ifindex = ovs_header->dp_ifindex;
    info->port_no = nl_attr_get_odp_port(a[OVS_WIN_NETDEV_ATTR_PORT_NO]);
    info->ovs_type = nl_attr_get_u32(a[OVS_WIN_NETDEV_ATTR_TYPE]);
    info->name = nl_attr_get_string(a[OVS_WIN_NETDEV_ATTR_NAME]);
    memcpy(&info->mac_address, nl_attr_get_unspec(a[OVS_WIN_NETDEV_ATTR_MAC_ADDR],
               sizeof(info->mac_address)), sizeof(info->mac_address));
    info->mtu = nl_attr_get_u32(a[OVS_WIN_NETDEV_ATTR_MTU]);
    info->ifi_flags = nl_attr_get_u32(a[OVS_WIN_NETDEV_ATTR_IF_FLAGS]);

    return 0;
}

static int
query_netdev(const char *devname,
             struct netdev_windows_netdev_info *info,
             struct ofpbuf **bufp)
{
    int error = 0;
    struct ofpbuf *request_buf;

    ovs_assert(info != NULL);
    netdev_windows_info_init(info);

    error = netdev_windows_init_();
    if (error) {
        if (info) {
            *bufp = NULL;
            netdev_windows_info_init(info);
        }
        return error;
    }

    request_buf = ofpbuf_new(1024);
    info->cmd = OVS_WIN_NETDEV_CMD_GET;
    info->name = devname;
    error = netdev_windows_netdev_to_ofpbuf(info, request_buf);
    if (error) {
        ofpbuf_delete(request_buf);
        return error;
    }

    error = ovsext_transact(&ovs_win_netdev_channel, request_buf, bufp);
    ofpbuf_delete(request_buf);

    if (info) {
        if (!error) {
            error = netdev_windows_netdev_from_ofpbuf(info, *bufp);
        }
        if (error) {
            netdev_windows_info_init(info);
            ofpbuf_delete(*bufp);
            *bufp = NULL;
        }
    }

    return error;
}

static void
netdev_windows_destruct(struct netdev *netdev_)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);

    ovs_mutex_lock(&netdev_windows_list_mutex);
    ovs_list_remove(&netdev->list_node);
    ovs_mutex_unlock(&netdev_windows_list_mutex);
}

static void
netdev_windows_dealloc(struct netdev *netdev_)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);
    free(netdev);
}

static int
netdev_windows_get_etheraddr(const struct netdev *netdev_,
                             struct eth_addr *mac)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);
    int error = 0;

    /* netdev_windows_run() re-syncs 'mac'/'cache_valid' from the kernel under
     * this mutex; read them under the same lock since netdev APIs may be called
     * from other threads. */
    ovs_mutex_lock(&netdev_windows_list_mutex);
    ovs_assert((netdev->cache_valid & VALID_ETHERADDR) != 0);
    if (netdev->cache_valid & VALID_ETHERADDR) {
        *mac = netdev->mac;
    } else {
        error = EINVAL;
    }
    ovs_mutex_unlock(&netdev_windows_list_mutex);
    return error;
}

static int
netdev_windows_get_mtu(const struct netdev *netdev_, int *mtup)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);
    int error = 0;

    ovs_mutex_lock(&netdev_windows_list_mutex);
    ovs_assert((netdev->cache_valid & VALID_MTU) != 0);
    if (netdev->cache_valid & VALID_MTU) {
        *mtup = netdev->mtu;
    } else {
        error = EINVAL;
    }
    ovs_mutex_unlock(&netdev_windows_list_mutex);
    return error;
}

/* This functionality is not really required by the datapath.
 * But vswitchd bringup expects this to be implemented. */
static int
netdev_windows_set_etheraddr(const struct netdev *netdev_,
                             const struct eth_addr mac)
{
    return 0;
}

/* This functionality is not really required by the datapath.
 * But vswitchd bringup expects this to be implemented. */
static int
netdev_windows_update_flags(struct netdev *netdev_,
                            enum netdev_flags off,
                            enum netdev_flags on,
                            enum netdev_flags *old_flagsp)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);
    int error = 0;

    ovs_mutex_lock(&netdev_windows_list_mutex);
    ovs_assert((netdev->cache_valid & VALID_IFFLAG) != 0);
    if (netdev->cache_valid & VALID_IFFLAG) {
        *old_flagsp = netdev->ifi_flags;
        /* Setting the interface flags is not supported. */
    } else {
        error = EINVAL;
    }
    ovs_mutex_unlock(&netdev_windows_list_mutex);
    return error;
}

/* Looks up in the ARP table entry for a given 'ip'. If it is found, the
 * corresponding MAC address will be copied in 'mac' and return 0. If no
 * matching entry is found or an error occurs it will log it and return ENXIO.
 */
static int
netdev_windows_arp_lookup(const struct netdev *netdev,
                          ovs_be32 ip, struct eth_addr *mac)
{
    PMIB_IPNETTABLE arp_table = NULL;
    /* The buffer length of all ARP entries */
    uint32_t buffer_length = 0;
    uint32_t ret_val = 0;
    uint32_t counter = 0;

    ret_val = GetIpNetTable(arp_table, &buffer_length, false);

    if (ret_val != ERROR_INSUFFICIENT_BUFFER ) {
        VLOG_ERR("Call to GetIpNetTable failed with error: %s",
                 ovs_format_message(ret_val));
        return ENXIO;
    }

    arp_table = (MIB_IPNETTABLE *) xmalloc(buffer_length);

    ret_val = GetIpNetTable(arp_table, &buffer_length, false);

    if (ret_val == NO_ERROR) {
        for (counter = 0; counter < arp_table->dwNumEntries; counter++) {
            if (arp_table->table[counter].dwAddr == ip) {
                memcpy(mac, arp_table->table[counter].bPhysAddr, ETH_ADDR_LEN);

                free(arp_table);
                return 0;
            }
        }
    } else {
        VLOG_ERR("Call to GetIpNetTable failed with error: %s",
                 ovs_format_message(ret_val));
    }

    free(arp_table);
    return ENXIO;
}

static int
netdev_windows_get_next_hop(const struct in_addr *host,
                            struct in_addr *next_hop,
                            char **netdev_name)
{
    uint32_t ret_val = 0;
    /* The buffer length of all addresses */
    uint32_t buffer_length = 0;
    PIP_ADAPTER_ADDRESSES all_addr = NULL;
    PIP_ADAPTER_ADDRESSES cur_addr = NULL;

    ret_val = GetAdaptersAddresses(AF_INET,
                                   GAA_FLAG_INCLUDE_PREFIX |
                                   GAA_FLAG_INCLUDE_GATEWAYS,
                                   NULL, NULL, &buffer_length);

    if (ret_val != ERROR_BUFFER_OVERFLOW ) {
        VLOG_ERR("Call to GetAdaptersAddresses failed with error: %s",
                 ovs_format_message(ret_val));
        return ENXIO;
    }

    all_addr = (IP_ADAPTER_ADDRESSES *) xmalloc(buffer_length);

    ret_val = GetAdaptersAddresses(AF_INET,
                                   GAA_FLAG_INCLUDE_PREFIX |
                                   GAA_FLAG_INCLUDE_GATEWAYS,
                                   NULL, all_addr, &buffer_length);

    if (ret_val == NO_ERROR) {
        cur_addr = all_addr;
        while (cur_addr) {
            if(cur_addr->FirstGatewayAddress &&
               cur_addr->FirstGatewayAddress->Address.lpSockaddr) {
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)
                                           cur_addr->FirstGatewayAddress->Address.lpSockaddr;
                next_hop->s_addr = ipv4->sin_addr.S_un.S_addr;
                *netdev_name = xstrdup((char *)cur_addr->FriendlyName);

                free(all_addr);

                return 0;
            }

            cur_addr = cur_addr->Next;
        }
    } else {
        VLOG_ERR("Call to GetAdaptersAddresses failed with error: %s",
                 ovs_format_message(ret_val));
    }

    if (all_addr) {
        free(all_addr);
    }
    return ENXIO;
}

static int
netdev_windows_internal_construct(struct netdev *netdev_)
{
    return netdev_windows_system_construct(netdev_);
}


/* One netdev's link state, gathered by the periodic refresh without holding
 * netdev_windows_list_mutex (the per-port kernel/host I/O would otherwise block
 * every netdev API call for the duration of all the round trips) and committed
 * back under the lock.  'name' is the stable identity used to match the result
 * to the still-listed netdev; the 'in_*' fields are the cached inputs the probe
 * needs, snapshotted under the lock. */
struct netdev_windows_probe {
    char *name;                        /* owned; the netdev's unique identity. */
    struct eth_addr in_mac;            /* cached MAC, to reuse a resolved LUID. */
    NET_LUID in_luid;
    bool in_luid_valid;

    bool kernel_valid;                 /* the OVS_WIN_NETDEV_CMD_GET succeeded. */
    uint32_t ifi_flags;
    struct eth_addr mac;
    int mtu;
    bool carrier_valid;                /* a link state was determined. */
    bool carrier;
    bool luid_valid;                   /* resolved host-interface LUID. */
    NET_LUID if_luid;
};

/* Finds the host interface LUID whose MAC is 'mac' by matching the system
 * interface table.  Returns true and stores it in '*luid' on a match.  Touches
 * no netdev state, so it is safe to call without netdev_windows_list_mutex. */
static bool
netdev_windows_lookup_luid(struct eth_addr mac, NET_LUID *luid)
{
    MIB_IF_TABLE2 *table = NULL;
    bool found = false;
    ULONG i;

    if (eth_addr_is_zero(mac)
        || GetIfTable2(&table) != NO_ERROR || table == NULL) {
        /* No usable MAC to match (e.g. a ghost constructed while its device was
         * absent) -- do not match a host pseudo-interface with a zero MAC. */
        return false;
    }
    for (i = 0; i < table->NumEntries; i++) {
        const MIB_IF_ROW2 *row = &table->Table[i];

        if (row->PhysicalAddressLength == ETH_ADDR_LEN
            && !memcmp(row->PhysicalAddress, mac.ea, ETH_ADDR_LEN)) {
            *luid = row->InterfaceLuid;
            found = true;
            break;
        }
    }
    FreeMibTable(table);
    return found;
}

/* Gathers 'p''s link state from the kernel vport and the host interface,
 * performing all the I/O without touching any netdev or the list mutex.
 *
 * The kernel GET re-syncs admin flags, MAC and MTU; this matters for a
 * userspace-first ghost (constructed while its Hyper-V adapter was absent, so
 * the flags came up empty): once the port is resurrected the vport reports
 * OVS_WIN_NETDEV_IFF_UP, without which netdev_get_carrier() would short-circuit
 * the interface to admin-down.
 *
 * Two link-state sources are combined.  A physical adapter / SET member
 * resolves to a host interface whose MIB_IF_ROW2.MediaConnectState detects a
 * physical link-down that the datapath port state cannot see -- the Hyper-V
 * switch consumes the NIC status indication at its miniport/protocol edge and
 * never delivers it to the forwarding extension.  A virtual port (a VM vNIC, or
 * a userspace-first ghost awaiting attach) has no host interface and no host
 * MAC to match, so the kernel datapath link state (IFF_RUNNING) is the only
 * truth.  Carrier is media-up AND kernel-up where both apply, else whichever is
 * available. */
static void
netdev_windows_probe_gather(struct netdev_windows_probe *p)
{
    struct netdev_windows_netdev_info info;
    struct ofpbuf *buf;
    bool kernel_up = false;
    struct eth_addr mac;
    NET_LUID luid = p->in_luid;
    bool luid_valid;
    MIB_IF_ROW2 row;

    if (!query_netdev(p->name, &info, &buf)) {
        p->kernel_valid = true;
        p->ifi_flags = dp_to_netdev_ifi_flags(info.ifi_flags);
        p->mac = info.mac_address;
        p->mtu = info.mtu;
        kernel_up = (info.ifi_flags & OVS_WIN_NETDEV_IFF_RUNNING) != 0;
        ofpbuf_delete(buf);
    }

    /* Match the host interface on the freshest MAC.  A changed MAC (a ghost
     * gaining its real address at resurrection) invalidates a cached LUID. */
    mac = p->kernel_valid ? p->mac : p->in_mac;
    luid_valid = p->in_luid_valid && eth_addr_equals(mac, p->in_mac);
    if (!luid_valid) {
        luid_valid = netdev_windows_lookup_luid(mac, &luid);
    }

    if (luid_valid) {
        memset(&row, 0, sizeof row);
        row.InterfaceLuid = luid;
        if (GetIfEntry2(&row) != NO_ERROR) {
            /* The adapter likely went away; re-resolve the LUID next tick. */
            luid_valid = false;
        } else {
            bool media = (row.MediaConnectState == MediaConnectStateConnected);
            p->carrier = p->kernel_valid ? (kernel_up && media) : media;
            p->carrier_valid = true;
        }
    }
    if (!p->carrier_valid && p->kernel_valid) {
        p->carrier = kernel_up;
        p->carrier_valid = true;
    }
    p->luid_valid = luid_valid;
    p->if_luid = luid;
}

/* Commits a gathered probe to its 'netdev', returning true if anything the
 * change sequence covers (admin flags, MAC, MTU or carrier) changed. */
static bool
netdev_windows_probe_commit(struct netdev_windows *netdev,
                            const struct netdev_windows_probe *p)
    OVS_REQUIRES(netdev_windows_list_mutex)
{
    bool changed = false;

    if (p->kernel_valid) {
        changed = netdev->ifi_flags != p->ifi_flags
                  || !eth_addr_equals(netdev->mac, p->mac)
                  || netdev->mtu != p->mtu;
        netdev->ifi_flags = p->ifi_flags;
        netdev->mac = p->mac;
        netdev->mtu = p->mtu;
        netdev->cache_valid |= VALID_IFFLAG | VALID_ETHERADDR | VALID_MTU;
    }
    netdev->if_luid = p->if_luid;
    netdev->if_luid_valid = p->luid_valid;

    if (p->carrier_valid && p->carrier != netdev->carrier) {
        netdev->carrier = p->carrier;
        netdev->carrier_resets++;
        changed = true;
        VLOG_DBG("%s: carrier %s", p->name, p->carrier ? "up" : "down");
    }
    return changed;
}

static int
netdev_windows_get_carrier(const struct netdev *netdev_, bool *carrier)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);

    /* netdev_windows_run() updates 'carrier' under this mutex; guard the read
     * with the same lock since netdev APIs may be called from other threads. */
    ovs_mutex_lock(&netdev_windows_list_mutex);
    *carrier = netdev->carrier;
    ovs_mutex_unlock(&netdev_windows_list_mutex);
    return 0;
}

static long long int
netdev_windows_get_carrier_resets(const struct netdev *netdev_)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);
    long long int resets;

    ovs_mutex_lock(&netdev_windows_list_mutex);
    resets = netdev->carrier_resets;
    ovs_mutex_unlock(&netdev_windows_list_mutex);
    return resets;
}

/* Periodically re-queries every Windows netdev's link state and, on a change to
 * carrier / admin flags / MAC / MTU, bumps the change sequence so dependent
 * logic (notably bonding) re-evaluates it.  The whole list is refreshed
 * together regardless of which class triggered the tick.
 *
 * The per-port kernel/host I/O runs outside netdev_windows_list_mutex: the lock
 * is taken only to snapshot the probe inputs and again to commit the results,
 * so it never spans the DeviceIoControl/GetIfEntry2 round trips and cannot
 * block unrelated netdev API calls for their duration.  Results are matched
 * back by the netdev's stable, unique name, so a port deleted during the probe
 * window is simply skipped (no reference is held across the I/O, avoiding a
 * lock-order inversion with netdev_unref()'s destruct path). */
static void
netdev_windows_run(const struct netdev_class *netdev_class OVS_UNUSED)
{
    struct netdev_windows_probe *probes;
    struct netdev_windows *netdev;
    long long int now = time_msec();
    size_t n = 0, cap, i;

    if (now < netdev_windows_next_refresh) {
        return;
    }
    netdev_windows_next_refresh = now + NETDEV_WINDOWS_CARRIER_INTERVAL_MS;

    ovs_mutex_lock(&netdev_windows_list_mutex);
    cap = ovs_list_size(&netdev_windows_list);
    probes = cap ? xmalloc(cap * sizeof *probes) : NULL;
    LIST_FOR_EACH (netdev, list_node, &netdev_windows_list) {
        struct netdev_windows_probe *p = &probes[n++];

        memset(p, 0, sizeof *p);
        p->name = xstrdup(netdev_get_name(&netdev->up));
        p->in_mac = netdev->mac;
        p->in_luid = netdev->if_luid;
        p->in_luid_valid = netdev->if_luid_valid;
    }
    ovs_mutex_unlock(&netdev_windows_list_mutex);

    for (i = 0; i < n; i++) {
        netdev_windows_probe_gather(&probes[i]);
    }

    ovs_mutex_lock(&netdev_windows_list_mutex);
    LIST_FOR_EACH (netdev, list_node, &netdev_windows_list) {
        for (i = 0; i < n; i++) {
            if (!strcmp(probes[i].name, netdev_get_name(&netdev->up))) {
                if (netdev_windows_probe_commit(netdev, &probes[i])) {
                    netdev_change_seq_changed(&netdev->up);
                }
                break;
            }
        }
    }
    ovs_mutex_unlock(&netdev_windows_list_mutex);

    for (i = 0; i < n; i++) {
        free(probes[i].name);
    }
    free(probes);
}

static void
netdev_windows_wait(const struct netdev_class *netdev_class OVS_UNUSED)
{
    poll_timer_wait_until(netdev_windows_next_refresh);
}

#define NETDEV_WINDOWS_CLASS(NAME, CONSTRUCT)                           \
{                                                                       \
    .type               = NAME,                                         \
    .is_pmd             = false,                                        \
    .alloc              = netdev_windows_alloc,                         \
    .construct          = CONSTRUCT,                                    \
    .destruct           = netdev_windows_destruct,                      \
    .dealloc            = netdev_windows_dealloc,                       \
    .run                = netdev_windows_run,                           \
    .wait               = netdev_windows_wait,                          \
    .get_etheraddr      = netdev_windows_get_etheraddr,                 \
    .set_etheraddr      = netdev_windows_set_etheraddr,                 \
    .get_carrier        = netdev_windows_get_carrier,                   \
    .get_carrier_resets = netdev_windows_get_carrier_resets,            \
    .update_flags       = netdev_windows_update_flags,                  \
    .get_next_hop       = netdev_windows_get_next_hop,                  \
    .arp_lookup         = netdev_windows_arp_lookup,                    \
}

const struct netdev_class netdev_windows_class =
    NETDEV_WINDOWS_CLASS(
        "system",
        netdev_windows_system_construct);

const struct netdev_class netdev_internal_class =
    NETDEV_WINDOWS_CLASS(
        "internal",
        netdev_windows_internal_construct);
