/*
 * Copyright (c) 2026 dbosoft GmbH.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

#include <config.h>

#ifdef _WIN32

#include "ovsext-channel.h"

#include "odp-netlink.h"

#include "netlink.h"
#include "netlink-protocol.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "util.h"

/* The ovsext device name and IOCTL/command contract (unchanged ABI). */
#include "OvsDpInterfaceExt.h"

VLOG_DEFINE_THIS_MODULE(ovsext_channel);

/* Generous bound for a single transact reply, and for one dump record (a
 * netlink message is at most 64 kB -- the max length of a netlink attribute). */
#define OVSEXT_REPLY_MAX (64 * 1024)

/* The device the channel opens.  Overridable at compile time so a test build
 * can retarget the channel; the default is the real ovsext device. */
#ifndef OVSEXT_DEVICE_NAME
#define OVSEXT_DEVICE_NAME OVS_DEVICE_NAME_USER
#endif

/* Transport seam (see ovsext-channel.h).  NULL => the real Windows device. */
static const struct ovsext_transport *ovsext_transport;

void
ovsext_set_transport(const struct ovsext_transport *transport)
{
    ovsext_transport = transport;
}

static HANDLE
ovsext_dev_open(void)
{
    if (ovsext_transport) {
        return ovsext_transport->open(ovsext_transport->aux);
    }
    return CreateFile(OVSEXT_DEVICE_NAME,
                      GENERIC_READ | GENERIC_WRITE,
                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                      NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
}

/* When 'last_err' is ERROR_NOT_FOUND the ovsext device handle is gone (driver
 * reload / NDIS detach) and cannot even be closed; the only recovery is to
 * crash so the service manager restarts us and re-opens the device.  Mirrors
 * netlink-socket.c lost_communication(). */
static void
ovsext_check_lost_communication(DWORD last_err)
{
    if (last_err == ERROR_NOT_FOUND) {
        ovs_abort(0, "lost communication with the ovsext kernel device");
    }
}

/* Wraps DeviceIoControl so the mock can intercept it.  'in' is logically const
 * (the request); DeviceIoControl's prototype is non-const, hence the cast. */
static BOOL
ovsext_dev_ioctl(struct ovsext_channel *ch, DWORD code,
                 const void *in, DWORD in_len,
                 void *out, DWORD out_len, DWORD *bytes)
{
    BOOL ok;

    if (ovsext_transport) {
        return ovsext_transport->ioctl(ovsext_transport->aux, ch->handle, code,
                                       in, in_len, out, out_len, bytes);
    }
    ok = DeviceIoControl(ch->handle, code, CONST_CAST(void *, in), in_len,
                         out, out_len, bytes, NULL);
    if (!ok) {
        /* A lost kernel handle (driver reload, NDIS detach-promote race)
         * surfaces as ERROR_NOT_FOUND; there is no recovery and no reopen path
         * in this provider, so abort instead of returning EINVAL forever (which
         * would wedge vswitchd with a dead handle -- no flows, no upcalls). */
        ovsext_check_lost_communication(GetLastError());
    }
    return ok;
}

static void
ovsext_dev_close(struct ovsext_channel *ch)
{
    if (ovsext_transport) {
        ovsext_transport->close(ovsext_transport->aux, ch->handle);
    } else {
        CloseHandle(ch->handle);
    }
}

static int
ovsext_get_pid(struct ovsext_channel *ch)
{
    uint32_t pid = 0;
    DWORD bytes = 0;

    if (!ovsext_dev_ioctl(ch, OVS_IOCTL_GET_PID,
                          NULL, 0, &pid, sizeof pid, &bytes)
        || bytes < sizeof pid) {
        VLOG_ERR("OVS_IOCTL_GET_PID failed (%s)", ovs_lasterror_to_string());
        return EINVAL;
    }
    ch->pid = pid;
    return 0;
}

int
ovsext_channel_open(struct ovsext_channel *ch)
{
    memset(ch, 0, sizeof *ch);

    ch->handle = ovsext_dev_open();
    if (ch->handle == INVALID_HANDLE_VALUE) {
        VLOG_ERR("could not open ovsext device (%s)",
                 ovs_lasterror_to_string());
        return ENODEV;
    }

    /* Auto-reset event, mirroring the nl_sock overlapped event used by the
     * faked-socket transport in lib/netlink-socket.c. */
    ch->rx_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!ch->rx_event) {
        CloseHandle(ch->handle);
        ch->handle = INVALID_HANDLE_VALUE;
        return ENOMEM;
    }
    ch->overlapped.hEvent = ch->rx_event;
    ch->read_ioctl = OVS_IOCTL_READ;

    return ovsext_get_pid(ch);
}

void
ovsext_channel_close(struct ovsext_channel *ch)
{
    if (!ch || ch->handle == INVALID_HANDLE_VALUE) {
        return;
    }
    if (ch->rx_pending) {
        CancelIoEx(ch->handle, &ch->overlapped);
        ch->rx_pending = false;
    }
    if (ch->rx_event) {
        CloseHandle(ch->rx_event);
        ch->rx_event = NULL;
    }
    ovsext_dev_close(ch);
    ch->handle = INVALID_HANDLE_VALUE;
}

/* Stamps the netlink header of an outgoing request with a fresh sequence
 * number and this channel's pid, exactly as nl_sock_send__ does for the faked
 * transport.  Returns the seq used. */
static uint32_t
ovsext_stamp_request(struct ovsext_channel *ch, const struct ofpbuf *request)
{
    struct nlmsghdr *nlmsg = nl_msg_nlmsghdr(request);
    uint32_t seq = ++ch->next_seq;

    nlmsg->nlmsg_len = request->size;
    nlmsg->nlmsg_seq = seq;
    nlmsg->nlmsg_pid = ch->pid;
    return seq;
}

int
ovsext_transact(struct ovsext_channel *ch, const struct ofpbuf *request,
                struct ofpbuf **replyp)
{
    struct ofpbuf *reply = ofpbuf_new(OVSEXT_REPLY_MAX);
    DWORD reply_len = 0;
    int error = 0;

    ovsext_stamp_request(ch, request);

    if (!ovsext_dev_ioctl(ch, OVS_IOCTL_TRANSACT,
                          request->data, request->size,
                          reply->data, OVSEXT_REPLY_MAX,
                          &reply_len)) {
        /* XXX: GetLastError() could be mapped more precisely; the faked
         * transport in netlink-socket.c also collapses this to EINVAL. */
        error = EINVAL;
        VLOG_DBG("OVS_IOCTL_TRANSACT failed (%s)", ovs_lasterror_to_string());
        goto exit;
    }

    reply->size = reply_len;

    if (reply_len == 0) {
        /* Command succeeded but produced no payload (e.g. a SET/DEL with no
         * NLM_F_ECHO).  Mirror nl_transact_multiple's handling: success, empty
         * reply. */
        error = 0;
    } else if (reply_len < sizeof(struct nlmsghdr)) {
        error = EINVAL;
        VLOG_DBG("OVS_IOCTL_TRANSACT short reply (%lu bytes)",
                 (unsigned long) reply_len);
    } else {
        /* The kernel reports per-command failures as an in-band NLMSG_ERROR.
         * Extract it the same way nl_transact_multiple does. */
        int nl_error = 0;
        if (nl_msg_nlmsgerr(reply, &nl_error, NULL)) {
            error = nl_error;       /* 0 means it was an ACK, not a NAK. */
            if (error) {
                VLOG_DBG("OVS_IOCTL_TRANSACT NAK error=%d (%s)",
                         error, ovs_strerror(error));
            }
        }
    }

exit:
    if (error || !replyp) {
        ofpbuf_delete(reply);
        if (replyp) {
            *replyp = NULL;
        }
    } else {
        *replyp = reply;
    }
    return error;
}

int
ovsext_send(struct ovsext_channel *ch, const struct ofpbuf *msg)
{
    DWORD bytes = 0;

    ovsext_stamp_request(ch, msg);

    if (!ovsext_dev_ioctl(ch, OVS_IOCTL_WRITE,
                          msg->data, msg->size, NULL, 0, &bytes)) {
        VLOG_DBG("OVS_IOCTL_WRITE failed (%s)", ovs_lasterror_to_string());
        return EINVAL;
    }
    return 0;
}

/* DUMP. -------------------------------------------------------------------
 *
 * The ovsext driver implements a dump the same way the Linux kernel does over
 * a netlink socket: an OVS_IOCTL_WRITE carrying the NLM_F_DUMP request arms a
 * per-handle dump cursor (OvsSetupDumpStart), then each OVS_IOCTL_READ returns
 * the next single record.  A zero-length read marks end-of-dump; the driver
 * does not send an NLMSG_DONE (see OvsGetVportDumpNext in
 * datapath-windows/ovsext/Vport.c).  This mirrors nl_dump_start/nl_dump_next. */
void
ovsext_dump_start(struct ovsext_dump *dump, struct ovsext_channel *ch,
                  const struct ofpbuf *request)
{
    dump->status = 0;
    dump->buf = NULL;
    dump->own_channel_open = false;

    /* Open a dedicated channel for this dump.  The kernel dump cursor is per
     * file handle (OvsSetupDumpStart), so sharing 'ch' (the dpif's main
     * channel) with concurrent transactions or with other in-flight dumps
     * would race the cursor.  This mirrors netlink's per-dump pooled socket
     * (nl_pool_alloc).  'ch' supplies only the datapath the request is already
     * addressed to; the dump uses its own pid/seq/handle. */
    dump->status = ovsext_channel_open(&dump->own_channel);
    if (dump->status) {
        dump->channel = NULL;
        return;
    }
    dump->own_channel_open = true;
    dump->own_channel.dp_ifindex = ch->dp_ifindex;
    dump->channel = &dump->own_channel;
    dump->buf = ofpbuf_new(OVSEXT_REPLY_MAX);

    /* OVS_IOCTL_WRITE (OVS_WRITE_DEV_OP) -> OvsSetupDumpStart in the driver.
     * ovsext_send() stamps the request's len/seq/pid, as nl_sock_send does. */
    dump->status = ovsext_send(dump->channel, request);
}

bool
ovsext_dump_next(struct ovsext_dump *dump, struct ofpbuf *reply)
{
    struct ovsext_channel *ch = dump->channel;
    const struct nlmsghdr *nlmsg;
    DWORD bytes = 0;

    if (dump->status) {
        return false;
    }

    /* Pull the next record with OVS_IOCTL_READ.  The driver returns at most one
     * record per read into the output buffer's start. */
    ofpbuf_clear(dump->buf);
    if (!ovsext_dev_ioctl(ch, OVS_IOCTL_READ, NULL, 0,
                          dump->buf->base, dump->buf->allocated,
                          &bytes)) {
        dump->status = EINVAL;
        VLOG_DBG("OVS_IOCTL_READ (dump) failed (%s)",
                 ovs_lasterror_to_string());
        return false;
    }

    if (bytes == 0) {
        /* End-of-dump: the driver replies with zero bytes once the cursor is
         * exhausted (no NLMSG_DONE record is sent). */
        return false;
    }
    if (bytes < sizeof *nlmsg) {
        dump->status = EINVAL;
        VLOG_DBG("OVS_IOCTL_READ (dump) short record (%lu bytes)",
                 (unsigned long) bytes);
        return false;
    }

    dump->buf->size = bytes;

    nlmsg = dump->buf->data;
    if (nlmsg->nlmsg_type == NLMSG_ERROR) {
        int nl_error = EINVAL;
        nl_msg_nlmsgerr(dump->buf, &nl_error, NULL);
        dump->status = nl_error ? nl_error : EINVAL;
        return false;
    }

    /* Hand the caller a borrowed, read-only view of this record. */
    ofpbuf_use_const(reply, dump->buf->data, bytes);
    return true;
}

int
ovsext_dump_done(struct ovsext_dump *dump)
{
    ofpbuf_delete(dump->buf);
    dump->buf = NULL;
    if (dump->own_channel_open) {
        ovsext_channel_close(&dump->own_channel);
        dump->own_channel_open = false;
    }
    dump->channel = NULL;
    return dump->status;
}

/* Upcalls. ---------------------------------------------------------------- */

/* Sends OVS_CTRL_CMD_PACKET_SUBSCRIBE_REQ with this channel's pid, mirroring
 * nl_sock_subscribe_packet__() in lib/netlink-socket.c. */
static int
ovsext_subscribe_packets__(struct ovsext_channel *ch, bool subscribe)
{
    struct ofpbuf request;
    uint64_t request_stub[128];
    struct ovs_header *ovs_header;
    int error;

    ofpbuf_use_stub(&request, request_stub, sizeof request_stub);
    nl_msg_put_genlmsghdr(&request, 0, OVS_WIN_NL_CTRL_FAMILY_ID, 0,
                          OVS_CTRL_CMD_PACKET_SUBSCRIBE_REQ,
                          OVS_WIN_CONTROL_VERSION);

    ovs_header = ofpbuf_put_uninit(&request, sizeof *ovs_header);
    ovs_header->dp_ifindex = ch->dp_ifindex;
    nl_msg_put_u8(&request, OVS_NL_ATTR_PACKET_SUBSCRIBE, subscribe ? 1 : 0);
    nl_msg_put_u32(&request, OVS_NL_ATTR_PACKET_PID, ch->pid);

    error = ovsext_send(ch, &request);
    ofpbuf_uninit(&request);
    return error;
}

int
ovsext_subscribe_packets(struct ovsext_channel *ch, bool enable)
{
    int error;

    if (enable) {
        if (ch->read_ioctl == OVS_IOCTL_READ_PACKET) {
            return 0;
        }
        error = ovsext_subscribe_packets__(ch, true);
        if (error) {
            VLOG_WARN("could not subscribe packets (%s)",
                      ovs_strerror(error));
            return error;
        }
        ch->read_ioctl = OVS_IOCTL_READ_PACKET;
    } else {
        if (ch->read_ioctl != OVS_IOCTL_READ_PACKET) {
            return 0;
        }
        error = ovsext_subscribe_packets__(ch, false);
        if (error) {
            VLOG_WARN("could not unsubscribe packets (%s)",
                      ovs_strerror(error));
            return error;
        }
        ch->read_ioctl = OVS_IOCTL_READ;
    }
    return 0;
}

int
ovsext_recv(struct ovsext_channel *ch, struct ofpbuf *buf)
{
    DWORD bytes = 0;

    /* The driver dequeues one queued message and copies it into the supplied
     * output buffer, truncating it to the output length.  The caller's buffer
     * can be small (the upcall handler hands us a 512-byte stub), while a packet
     * upcall carries a full frame plus its flow key and so is frequently larger;
     * reading straight into that stub would silently truncate the message and
     * drop its trailing OVS_PACKET_ATTR_PACKET, failing the netlink policy parse.
     * Mirror nl_sock_recv__()'s _WIN32 path: read into a buffer large enough for
     * any Netlink message (64 kB, the max attribute length), then grow 'buf' to
     * hold the result. */
    uint8_t tail[65536];

    if (!ovsext_dev_ioctl(ch, ch->read_ioctl, NULL, 0,
                          tail, sizeof tail, &bytes)) {
        VLOG_DBG("read IOCTL failed (%s)", ovs_lasterror_to_string());
        return EINVAL;
    }
    if (bytes == 0) {
        return EAGAIN;
    }
    if (bytes < sizeof(struct nlmsghdr)) {
        return EINVAL;
    }
    ofpbuf_put(buf, tail, bytes);
    return 0;
}

void
ovsext_recv_wait(struct ovsext_channel *ch)
{
    /* Mirror nl_sock_wait()/pend_io_request(): if no overlapped read is
     * pending, arm one with OVS_CTRL_CMD_WIN_PEND_PACKET_REQ so the driver
     * signals 'rx_event' when a packet is ready; then park on the event. */
    if (ch->overlapped.Internal != STATUS_PENDING) {
        struct ofpbuf request;
        uint64_t request_stub[128];
        struct ovs_header *ovs_header;
        DWORD bytes = 0;
        BOOL ok;

        ofpbuf_use_stub(&request, request_stub, sizeof request_stub);
        nl_msg_put_genlmsghdr(&request, 0, OVS_WIN_NL_CTRL_FAMILY_ID, 0,
                              OVS_CTRL_CMD_WIN_PEND_PACKET_REQ,
                              OVS_WIN_CONTROL_VERSION);
        ovs_header = ofpbuf_put_uninit(&request, sizeof *ovs_header);
        ovs_header->dp_ifindex = ch->dp_ifindex;
        ovsext_stamp_request(ch, &request);

        ok = DeviceIoControl(ch->handle, OVS_IOCTL_WRITE,
                             request.data, request.size,
                             NULL, 0, &bytes, &ch->overlapped);
        ofpbuf_uninit(&request);

        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING || err == ERROR_IO_INCOMPLETE) {
                ch->rx_pending = true;
                poll_wevent_wait(ch->rx_event);
            } else {
                VLOG_ERR("ovsext_recv_wait pend failed (%s)",
                         ovs_lasterror_to_string());
                poll_immediate_wake();
            }
        } else {
            /* Completed synchronously: data is already available. */
            poll_immediate_wake();
        }
    } else {
        poll_wevent_wait(ch->rx_event);
    }
}

#endif /* _WIN32 */
