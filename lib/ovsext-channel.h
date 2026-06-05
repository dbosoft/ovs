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
    uint32_t dp_ifindex;    /* Datapath this channel targets; stamped on the
                             * packet subscribe/pend requests, which the kernel
                             * validates against a live datapath.  The default
                             * datapath is not always slot 0 (it is promoted on
                             * detach), so this must carry the resolved index,
                             * not a hardcoded 0. */
    uint32_t next_seq;      /* Netlink sequence allocator for this channel. */
    DWORD read_ioctl;       /* OVS_IOCTL_READ | _READ_EVENT | _READ_PACKET. */
    bool rx_pending;        /* True while an overlapped read is armed. */
};

/* State for a netlink-style DUMP over the ovsext transport.
 *
 * The ovsext driver implements a dump as a *stateful* sequence, exactly like
 * nl_dump over a real netlink socket: a single OVS_IOCTL_WRITE that carries the
 * NLM_F_DUMP request (which arms the driver's per-handle dump cursor), followed
 * by repeated OVS_IOCTL_READ calls that each return one record.  End-of-dump is
 * signalled by a zero-length read -- the driver does NOT emit an NLMSG_DONE
 * message (see OvsGetVportDumpNext in datapath-windows/ovsext/Vport.c).
 *
 * A single OVS_IOCTL_TRANSACT does NOT work for dumps: under the transact
 * dev-op the driver routes e.g. OVS_VPORT_CMD_GET to the single-object getter,
 * which fails with EINVAL when no port is named. */
struct ovsext_dump {
    struct ovsext_channel *channel;   /* Points at 'own_channel', or NULL if the
                                       * dump channel failed to open. */
    struct ovsext_channel own_channel; /* Dedicated handle: the kernel dump
                                        * cursor is per file handle, so a dump
                                        * must not share a channel with
                                        * concurrent transactions or with other
                                        * dumps (parallel revalidators). */
    bool own_channel_open;
    struct ofpbuf *buf;         /* Per-record read buffer, owned here. */
    int status;                 /* 0, or first error encountered. */
};

/* Transport seam.  Production talks to the real ovsext device via
 * CreateFile(OVSEXT_DEVICE_NAME) + DeviceIoControl.  A test build can install a
 * mock that imitates the kernel's command handlers in-process, so the provider
 * can be exercised (and ASAN-checked) on a dev box with no driver loaded.
 *
 * 'open' returns an opaque handle token (INVALID_HANDLE_VALUE on failure);
 * 'ioctl' answers one OVS_IOCTL_* like DeviceIoControl; 'close' releases it. */
struct ovsext_transport {
    HANDLE (*open)(void *aux);
    BOOL   (*ioctl)(void *aux, HANDLE handle, DWORD code,
                    const void *in, DWORD in_len,
                    void *out, DWORD out_len, DWORD *bytes);
    void   (*close)(void *aux, HANDLE handle);
    void   *aux;
};

/* Install a mock transport, or NULL to restore the real Windows device.
 * Test-only; not thread-safe (set once before opening any channel). */
void ovsext_set_transport(const struct ovsext_transport *);

/* Lifecycle: open the device and obtain the upcall PID. */
int  ovsext_channel_open(struct ovsext_channel *);
void ovsext_channel_close(struct ovsext_channel *);

/* Synchronous command -> reply (wraps OVS_IOCTL_TRANSACT).  On success stores a
 * newly allocated reply in '*replyp' (caller frees with ofpbuf_delete), or NULL
 * if no reply was requested.  Returns 0, or a positive errno (with the kernel's
 * netlink error code mapped through when available). */
int  ovsext_transact(struct ovsext_channel *, const struct ofpbuf *request,
                     struct ofpbuf **replyp);

/* Fire-and-forget command (wraps OVS_IOCTL_WRITE). */
int  ovsext_send(struct ovsext_channel *, const struct ofpbuf *msg);

/* Netlink-style DUMP.  'request' is the genl request message with NLM_F_DUMP;
 * ovsext_dump_start() arms the driver's dump cursor via OVS_IOCTL_WRITE.
 * Iterate with ovsext_dump_next() (one record per OVS_IOCTL_READ) until it
 * returns false, then finish with ovsext_dump_done() which returns the dump's
 * final status. */
void ovsext_dump_start(struct ovsext_dump *, struct ovsext_channel *,
                       const struct ofpbuf *request);
bool ovsext_dump_next(struct ovsext_dump *, struct ofpbuf *reply);
int  ovsext_dump_done(struct ovsext_dump *);

/* Switch the channel into packet-receive mode (subscribe) by sending
 * OVS_CTRL_CMD_PACKET_SUBSCRIBE_REQ and flipping the read IOCTL. */
int  ovsext_subscribe_packets(struct ovsext_channel *, bool enable);

/* Non-blocking receive of one queued message using the current read_ioctl.
 * Returns 0 on success (message appended to 'buf'), EAGAIN if nothing is
 * queued, or a positive errno on error. */
int  ovsext_recv(struct ovsext_channel *, struct ofpbuf *buf);

/* Arrange for poll_block() to wake when ovsext_recv() may succeed, using the
 * overlapped pend pattern (OVS_CTRL_CMD_WIN_PEND_PACKET_REQ). */
void ovsext_recv_wait(struct ovsext_channel *);

#endif /* _WIN32 */
#endif /* ovsext-channel.h */
