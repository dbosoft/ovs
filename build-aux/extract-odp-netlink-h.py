#!/usr/bin/env python3
# Portable, pure-Python reimplementation of the "sed" script
# build-aux/extract-odp-netlink-h.
#
# It transforms <linux/openvswitch.h> into a form suitable for inclusion
# within the Open vSwitch tree on both Linux and non-Linux systems.
#
# Usage (matches the original sed invocation):
#   python3 build-aux/extract-odp-netlink-h.py < include/linux/openvswitch.h \
#       > include/odp-netlink.h
# or:
#   python3 build-aux/extract-odp-netlink-h.py include/linux/openvswitch.h \
#       > include/odp-netlink.h
#
# Only the Python standard library is used.

import re
import sys

# Header inserted before the first line (sed "1i\").
HEADER = """\
/* -*- mode: c; buffer-read-only: t -*- */
/* Generated automatically from <linux/openvswitch.h> -- do not modify! */



"""

# Block inserted before the last line (sed "$i\").
LAST_INSERT = """\
#ifdef _WIN32
#include "OvsDpInterfaceExt.h"
#include "OvsDpInterfaceCtExt.h"
#endif

/* IPCT_* enums may not be defined in all platforms, so do not use them. */
#define OVS_CT_EVENT_NEW\t(1 << 0)   /* 1 << IPCT_NEW */
#define OVS_CT_EVENT_RELATED\t(1 << 1)   /* 1 << IPCT_RELATED */
#define OVS_CT_EVENT_DESTROY\t(1 << 2)   /* 1 << IPCT_DESTROY */
#define OVS_CT_EVENT_REPLY\t(1 << 3)   /* 1 << IPCT_REPLY */
#define OVS_CT_EVENT_ASSURED\t(1 << 4)   /* 1 << IPCT_ASSURED */
#define OVS_CT_EVENT_PROTOINFO\t(1 << 5)   /* 1 << IPCT_PROTOINFO */
#define OVS_CT_EVENT_HELPER\t(1 << 6)   /* 1 << IPCT_HELPER */
#define OVS_CT_EVENT_MARK\t(1 << 7)   /* 1 << IPCT_MARK */
#define OVS_CT_EVENT_SEQADJ\t(1 << 8)   /* 1 << IPCT_SEQADJ */
#define OVS_CT_EVENT_SECMARK\t(1 << 9)   /* 1 << IPCT_SECMARK */
#define OVS_CT_EVENT_LABEL\t(1 << 10)  /* 1 << IPCT_LABEL */

#define OVS_CT_EVENTMASK_DEFAULT \\
  (OVS_CT_EVENT_NEW | OVS_CT_EVENT_RELATED | OVS_CT_EVENT_DESTROY |\\
   OVS_CT_EVENT_MARK | OVS_CT_EVENT_LABEL)
"""

# POSIX [[:space:]] inside the byte-oriented patterns of the original sed
# script means the horizontal/vertical whitespace characters.  The C "locale"
# whitespace set is: space, tab, newline, vertical tab, form feed, carriage
# return.  Within a single line there are no newlines, so [ \t\v\f\r] is
# equivalent; we use the explicit class to stay byte-identical and locale
# independent.
SPACE = r"[ \t\v\f\r]"


def apply_substitutions(line):
    # s/_LINUX_OPENVSWITCH_H/ODP_NETLINK_H/   (first occurrence only)
    line = line.replace("_LINUX_OPENVSWITCH_H", "ODP_NETLINK_H", 1)

    # s,<linux/types\.h>,"openvswitch/types.h"\n#include <netinet/in.h>,
    # (first occurrence only)
    line = re.sub(
        r"<linux/types\.h>",
        '"openvswitch/types.h"\n#include <netinet/in.h>',
        line,
        count=1,
    )

    # s,#.*<linux/if_ether\.h>,,   (first occurrence only)
    line = re.sub(r"#.*<linux/if_ether\.h>", "", line, count=1)

    # s/__u8<sp>*(name)<sp>*[<sp>*ETH_ALEN<sp>*]/struct eth_addr \1/
    line = re.sub(
        r"__u8" + SPACE + r"*([a-zA-Z0-9_]*)" + SPACE + r"*\[" + SPACE +
        r"*ETH_ALEN" + SPACE + r"*\]",
        r"struct eth_addr \1",
        line,
        count=1,
    )

    # s/__be32<sp>*(name{2,})<sp>*[<sp>*4<sp>*]/struct in6_addr \1/
    # Only member names with two or more characters (special-cases the
    # single-char "c[4]" member of struct ovs_key_nsh).
    line = re.sub(
        r"__be32" + SPACE + r"*([a-zA-Z0-9_]{2,})" + SPACE + r"*\[" + SPACE +
        r"*4" + SPACE + r"*\]",
        r"struct in6_addr \1",
        line,
        count=1,
    )

    # The remaining substitutions are global (sed "g" flag).
    line = line.replace("__u32", "uint32_t")
    line = line.replace("__u16", "uint16_t")
    line = line.replace("__u8", "uint8_t")
    line = line.replace("__be32", "ovs_be32")
    line = line.replace("__be16", "ovs_be16")
    line = line.replace("__u64", "ovs_32aligned_u64")
    line = line.replace("__be64", "ovs_32aligned_be64")

    return line


def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r", newline="") as f:
            data = f.read()
    else:
        data = sys.stdin.read()

    # Split into lines preserving knowledge of a trailing newline.  We operate
    # on logical lines exactly as sed would, where each "line" excludes its
    # terminating newline.
    if data == "":
        lines = []
        trailing_newline = False
    else:
        trailing_newline = data.endswith("\n")
        body = data[:-1] if trailing_newline else data
        lines = body.split("\n")
        # Normalize line endings: drop a trailing CR so that CRLF input
        # produces LF-only output, matching the reference generator which
        # ran on LF-normalized input.
        lines = [ln[:-1] if ln.endswith("\r") else ln for ln in lines]

    out = []
    last_index = len(lines) - 1
    for i, line in enumerate(lines):
        if i == 0:
            out.append(HEADER)  # ends with its own newlines
        if i == last_index:
            out.append(LAST_INSERT)  # multi-line, no trailing newline here
            out.append("\n")
        out.append(apply_substitutions(line))
        # Re-add the newline that terminated this input line.
        if i != last_index or trailing_newline:
            out.append("\n")

    # Write raw bytes so that no platform-specific newline translation occurs
    # (Python's text-mode stdout would turn "\n" into "\r\n" on Windows).
    sys.stdout.buffer.write("".join(out).encode("utf-8"))


if __name__ == "__main__":
    main()
