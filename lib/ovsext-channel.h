/*
 * Copyright (c) 2026 dbosoft GmbH.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef OVSEXT_CHANNEL_H
#define OVSEXT_CHANNEL_H 1

/* Native transport to the ovsext kernel datapath device.
 *
 * This replaces the faked-netlink transport in lib/netlink-socket.c (its
 * _WIN32 paths) for the datapath path.  It speaks the *existing*, unchanged
 * ovsext IOCTL/netlink-message ABI (datapath-windows/include/OvsDpInterface*.h)
 * but does not pretend a Windows device handle is a Linux netlink socket.
 *
 * Message bodies are still built/parsed with nl_msg / odp-util (the stable,
 * shared encoders); only the transport (the six OVS_IOCTL_* operations on
 * \\.\DbosoftOVSD) lives here. */

#ifdef _WIN32

#include <windows.h>
#include <stdbool.h>
#include <stdint.h>

struct ofpbuf;

struct ovsext_channel {
    HANDLE handle;          /* CreateFile(OVS_DEVICE_NAME_USER, FILE_FLAG_OVERLAPPED). */
    OVERLAPPED overlapped;  /* For a pended READ_PACKET / READ_EVENT. */
    HANDLE rx_event;        /* Manual-reset event; parked in poll_wevent_wait(). */
    uint32_t pid;           /* From OVS_IOCTL_GET_PID; the upcall routing key. */
    uint32_t next_seq;      /* Netlink sequence allocator for this channel. */
    DWORD read_ioctl;       /* OVS_IOCTL_READ | _READ_EVENT | _READ_PACKET. */
    bool rx_pending;        /* True while an overlapped read is armed. */
};

/* Lifecycle: open the device and obtain the upcall PID. */
int  ovsext_channel_open(struct ovsext_channel *);
void ovsext_channel_close(struct ovsext_channel *);

/* Synchronous command -> reply (wraps OVS_IOCTL_TRANSACT).  On success stores a
 * newly allocated reply in '*replyp' (caller frees with ofpbuf_delete), or NULL
 * if no reply was requested. */
int  ovsext_transact(struct ovsext_channel *, const struct ofpbuf *request,
                     struct ofpbuf **replyp);

/* Fire-and-forget command (wraps OVS_IOCTL_WRITE). */
int  ovsext_send(struct ovsext_channel *, const struct ofpbuf *msg);

/* Switch the channel into packet- or event-receive mode (subscribe). */
int  ovsext_subscribe_packets(struct ovsext_channel *, bool enable);

/* Non-blocking receive of one queued message using the current read_ioctl.
 * Returns 0 on success (message in 'buf'), EAGAIN if nothing is queued, or a
 * positive errno on error. */
int  ovsext_recv(struct ovsext_channel *, struct ofpbuf *buf);

/* Arrange for poll_block() to wake when ovsext_recv() may succeed. */
void ovsext_recv_wait(struct ovsext_channel *);

#endif /* _WIN32 */
#endif /* ovsext-channel.h */
