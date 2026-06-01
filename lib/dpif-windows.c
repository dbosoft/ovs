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
 * replacing the Windows (ab)use of dpif_netlink_class + the faked nl_sock
 * transport.  The kernel driver and its IOCTL/netlink-message ABI are
 * unchanged; this provider talks to it through lib/ovsext-channel.c and builds
 * message bodies with the shared nl_msg / odp-util encoders.
 *
 * PHASE 0 (this file): lifecycle (open/close/get_stats/version) is real; ports,
 * flows, conntrack and the upcall path are benign stubs.  The provider
 * registers as datapath type "windows" so it coexists with the existing
 * dpif_netlink "system" path during bring-up; Phase 4 renames it to "system"
 * and removes dpif-netlink/netlink-socket from the Windows build.
 *
 * See datapath-windows/NATIVE-DPIF-EXPERIMENT.md for the full spec. */

#include <config.h>

#ifdef _WIN32

#include <stdio.h>              /* EOF */

#include "dpif-provider.h"
#include "ovsext-channel.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(dpif_windows);

struct dpif_windows {
    struct dpif dpif;
    struct ovsext_channel channel;
};

/* Forward declaration (defined at the bottom). Kept local so the provider is
 * self-contained and needs no edit to the shared dpif-provider.h. */
extern const struct dpif_class dpif_windows_class;

static struct dpif_windows *
dpif_windows_cast(const struct dpif *dpif)
{
    dpif_assert_class(dpif, &dpif_windows_class);
    return CONTAINER_OF(dpif, struct dpif_windows, dpif);
}

/* Lifecycle. ----------------------------------------------------------- */

static int
dpif_windows_open(const struct dpif_class *class, const char *name,
                  bool create OVS_UNUSED, struct dpif **dpifp)
{
    struct dpif_windows *dpif;
    int error;

    dpif = xzalloc(sizeof *dpif);
    error = ovsext_channel_open(&dpif->channel);
    if (error) {
        free(dpif);
        return error;
    }

    dpif_init(&dpif->dpif, class, name, 0, 0);
    *dpifp = &dpif->dpif;
    return 0;
}

static void
dpif_windows_close(struct dpif *dpif_)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);

    ovsext_channel_close(&dpif->channel);
    dpif_uninit(dpif_, false);
    free(dpif);
}

static int
dpif_windows_destroy(struct dpif *dpif_ OVS_UNUSED)
{
    /* Phase 1: OVS_DP_CMD_DEL.  The single global datapath is owned by the
     * driver for now, so nothing to tear down here yet. */
    return 0;
}

static int
dpif_windows_get_stats(const struct dpif *dpif_ OVS_UNUSED,
                       struct dpif_dp_stats *stats)
{
    /* Phase 1: OVS_DP_CMD_GET -> OVS_DP_ATTR_STATS. */
    memset(stats, 0, sizeof *stats);
    return 0;
}

static char *
dpif_windows_get_datapath_version(void)
{
    return xstrdup("ovsext-native-dpif (experimental)");
}

static bool
dpif_windows_run(struct dpif *dpif_ OVS_UNUSED)
{
    return false;
}

/* Ports (Phase 1 stubs). ----------------------------------------------- */

static int
dpif_windows_port_add(struct dpif *dpif_ OVS_UNUSED,
                      struct netdev *netdev OVS_UNUSED,
                      odp_port_t *port_no OVS_UNUSED)
{
    return EOPNOTSUPP;
}

static int
dpif_windows_port_del(struct dpif *dpif_ OVS_UNUSED,
                      odp_port_t port_no OVS_UNUSED)
{
    return EOPNOTSUPP;
}

static int
dpif_windows_port_query_by_number(const struct dpif *dpif_ OVS_UNUSED,
                                  odp_port_t port_no OVS_UNUSED,
                                  struct dpif_port *port OVS_UNUSED)
{
    return ENODEV;
}

static int
dpif_windows_port_query_by_name(const struct dpif *dpif_ OVS_UNUSED,
                                const char *devname OVS_UNUSED,
                                struct dpif_port *port OVS_UNUSED)
{
    return ENODEV;
}

static uint32_t
dpif_windows_port_get_pid(const struct dpif *dpif_, odp_port_t port_no OVS_UNUSED)
{
    const struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    return dpif->channel.pid;
}

static int
dpif_windows_port_dump_start(const struct dpif *dpif_ OVS_UNUSED, void **statep)
{
    *statep = NULL;
    return 0;
}

static int
dpif_windows_port_dump_next(const struct dpif *dpif_ OVS_UNUSED,
                            void *state OVS_UNUSED,
                            struct dpif_port *port OVS_UNUSED)
{
    return EOF;
}

static int
dpif_windows_port_dump_done(const struct dpif *dpif_ OVS_UNUSED,
                            void *state OVS_UNUSED)
{
    return 0;
}

static int
dpif_windows_port_poll(const struct dpif *dpif_ OVS_UNUSED,
                       char **devnamep OVS_UNUSED)
{
    return EAGAIN;
}

static void
dpif_windows_port_poll_wait(const struct dpif *dpif_ OVS_UNUSED)
{
}

/* Flows (Phase 2 stubs). ----------------------------------------------- */

static int
dpif_windows_flow_flush(struct dpif *dpif_ OVS_UNUSED)
{
    return 0;
}

static struct dpif_flow_dump *
dpif_windows_flow_dump_create(const struct dpif *dpif_, bool terse,
                              struct dpif_flow_dump_types *types)
{
    struct dpif_flow_dump *dump = xzalloc(sizeof *dump);
    dpif_flow_dump_init(dump, dpif_, terse, types);   /* 4-arg form on OVS >=3.6 */
    return dump;
}

static int
dpif_windows_flow_dump_destroy(struct dpif_flow_dump *dump)
{
    free(dump);
    return 0;
}

static struct dpif_flow_dump_thread *
dpif_windows_flow_dump_thread_create(struct dpif_flow_dump *dump)
{
    struct dpif_flow_dump_thread *thread = xzalloc(sizeof *thread);
    dpif_flow_dump_thread_init(thread, dump);
    return thread;
}

static void
dpif_windows_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread)
{
    free(thread);
}

static int
dpif_windows_flow_dump_next(struct dpif_flow_dump_thread *thread OVS_UNUSED,
                            struct dpif_flow *flows OVS_UNUSED,
                            int max_flows OVS_UNUSED)
{
    return 0;
}

static void
dpif_windows_operate(struct dpif *dpif_ OVS_UNUSED, struct dpif_op **ops,
                     size_t n_ops, enum dpif_offload_type offload_type OVS_UNUSED)
{
    for (size_t i = 0; i < n_ops; i++) {
        ops[i]->error = EOPNOTSUPP;
    }
}

/* Upcalls (Phase 2 stubs). --------------------------------------------- */

static int
dpif_windows_recv_set(struct dpif *dpif_ OVS_UNUSED, bool enable OVS_UNUSED)
{
    return 0;
}

static int
dpif_windows_handlers_set(struct dpif *dpif_ OVS_UNUSED,
                          uint32_t n_handlers OVS_UNUSED)
{
    return 0;
}

static bool
dpif_windows_number_handlers_required(struct dpif *dpif_ OVS_UNUSED,
                                      uint32_t *n_handlers)
{
    *n_handlers = 1;            /* Windows uses a single upcall handler. */
    return true;
}

static int
dpif_windows_recv(struct dpif *dpif_ OVS_UNUSED, uint32_t handler_id OVS_UNUSED,
                  struct dpif_upcall *upcall OVS_UNUSED,
                  struct ofpbuf *buf OVS_UNUSED)
{
    return EAGAIN;
}

static void
dpif_windows_recv_wait(struct dpif *dpif_ OVS_UNUSED,
                       uint32_t handler_id OVS_UNUSED)
{
}

static void
dpif_windows_recv_purge(struct dpif *dpif_ OVS_UNUSED)
{
}

/* Class. --------------------------------------------------------------- */

const struct dpif_class dpif_windows_class = {
    .type = "windows",
    .cleanup_required = false,
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
