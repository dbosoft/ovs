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

#include "openvswitch/ofpbuf.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "util.h"

/* The ovsext device name and IOCTL/command contract (unchanged ABI). */
#include "OvsDpInterfaceExt.h"

VLOG_DEFINE_THIS_MODULE(ovsext_channel);

/* Generous bound for a single transact reply.  Dumps use a different path. */
#define OVSEXT_REPLY_MAX (64 * 1024)

static int
ovsext_get_pid(struct ovsext_channel *ch)
{
    uint32_t pid = 0;
    DWORD bytes = 0;

    if (!DeviceIoControl(ch->handle, OVS_IOCTL_GET_PID,
                         NULL, 0, &pid, sizeof pid, &bytes, NULL)
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

    ch->handle = CreateFile(OVS_DEVICE_NAME_USER,
                            GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (ch->handle == INVALID_HANDLE_VALUE) {
        VLOG_ERR("could not open %s (%s)", OVS_DEVICE_NAME_USER,
                 ovs_lasterror_to_string());
        return ENODEV;
    }

    ch->rx_event = CreateEvent(NULL, TRUE, FALSE, NULL);
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
    CloseHandle(ch->handle);
    ch->handle = INVALID_HANDLE_VALUE;
}

int
ovsext_transact(struct ovsext_channel *ch, const struct ofpbuf *request,
                struct ofpbuf **replyp)
{
    struct ofpbuf *reply = ofpbuf_new(OVSEXT_REPLY_MAX);
    DWORD reply_len = 0;
    int error = 0;

    if (!DeviceIoControl(ch->handle, OVS_IOCTL_TRANSACT,
                         request->data, request->size,
                         reply->data, OVSEXT_REPLY_MAX,
                         &reply_len, NULL)) {
        error = EINVAL;
        VLOG_DBG("OVS_IOCTL_TRANSACT failed (%s)", ovs_lasterror_to_string());
    } else {
        reply->size = reply_len;
    }

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

    if (!DeviceIoControl(ch->handle, OVS_IOCTL_WRITE,
                         msg->data, msg->size, NULL, 0, &bytes, NULL)) {
        VLOG_DBG("OVS_IOCTL_WRITE failed (%s)", ovs_lasterror_to_string());
        return EINVAL;
    }
    return 0;
}

int
ovsext_subscribe_packets(struct ovsext_channel *ch, bool enable)
{
    /* Phase 1: send OVS_CTRL_CMD_PACKET_SUBSCRIBE_REQ and flip read_ioctl.
     * For the Phase 0 skeleton we only track the desired mode. */
    ch->read_ioctl = enable ? OVS_IOCTL_READ_PACKET : OVS_IOCTL_READ;
    return 0;
}

int
ovsext_recv(struct ovsext_channel *ch, struct ofpbuf *buf)
{
    DWORD bytes = 0;

    if (!DeviceIoControl(ch->handle, ch->read_ioctl, NULL, 0,
                         ofpbuf_tail(buf), ofpbuf_tailroom(buf),
                         &bytes, NULL)) {
        return EINVAL;
    }
    if (bytes == 0) {
        return EAGAIN;
    }
    buf->size += bytes;
    return 0;
}

void
ovsext_recv_wait(struct ovsext_channel *ch)
{
    /* Phase 1 will arm a pended overlapped READ and wait on the event.  The
     * Phase 0 skeleton parks the event unconditionally so the poll loop is
     * wired even before the pend logic lands. */
    poll_wevent_wait(ch->rx_event);
}

#endif /* _WIN32 */
