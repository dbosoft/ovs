# Open vSwitch for Windows (dbosoft)

[![Build and Test (Windows)](https://github.com/dbosoft/ovs/workflows/Build%20and%20Test%20(Windows)/badge.svg)](https://github.com/dbosoft/ovs/actions)

## What is this fork?

This repository is **dbosoft's Windows-focused fork of Open vSwitch**. It is
**not** an official Open vSwitch release and is **not** affiliated with or
endorsed by the upstream Open vSwitch project.

Upstream Open vSwitch deprecated Windows support in v3.7 and removed it from
the `main` branch entirely. This fork re-establishes and continues development of:

- the **ovsext** NDIS forwarding extension (the Windows kernel datapath), and
- the Windows userspace components (`ovs-vswitchd`, `ovsdb-server`, and the
  `ovs-*` tools) together with a native, MSYS-free CMake build.

The fork is based on upstream Open vSwitch `main` (after the Windows removal)
and is periodically resynced with upstream. All non-Windows platforms (Linux,
FreeBSD, DPDK, userspace datapath) continue to inherit upstream behaviour
unchanged; our additions are Windows-specific. See
[NEWS_WINDOWS](NEWS_WINDOWS) for the changes that are unique to this fork on
top of the upstream baseline tracked in [NEWS](NEWS).

If you are running Open vSwitch on Linux, FreeBSD, or with DPDK, you almost
certainly want the upstream project at <https://github.com/openvswitch/ovs>
instead of this fork.

## What is Open vSwitch?

Open vSwitch is a multilayer software switch licensed under the open source
Apache 2 license. Its goal is to implement a production quality switch
platform that supports standard management interfaces and opens the forwarding
functions to programmatic extension and control.

On Windows, Open vSwitch integrates with Hyper-V as an NDIS forwarding
extension on the virtual switch, providing flow-based forwarding for virtual
machine traffic. Open vSwitch supports, among other features:

- Standard 802.1Q VLAN model with trunk and access ports
- NIC bonding with or without LACP on the upstream switch
- NetFlow, sFlow(R), and mirroring for increased visibility
- QoS (Quality of Service) configuration, plus policing
- Geneve, GRE, VXLAN, ERSPAN, GTP-U, SRv6, and Bareudp tunneling
- OpenFlow 1.0 plus numerous extensions
- Transactional configuration database with C and Python bindings

> **Two READMEs?** The upstream `README.rst` is left untouched to keep this
> fork's divergence from upstream minimal. This Windows-specific `README.md`
> is added alongside it. 

## What's here?

The main components of this distribution are:

- **ovsext**, the Windows NDIS forwarding extension implementing the kernel
  datapath, under `datapath-windows/`.
- `ovs-vswitchd`, a daemon that implements the switch.
- `ovsdb-server`, a lightweight database server that `ovs-vswitchd` queries to
  obtain its configuration.
- `ovs-vsctl`, a utility for querying and updating the configuration of
  `ovs-vswitchd`.
- `ovs-appctl`, a utility that sends commands to running Open vSwitch daemons.
- `ovs-dpctl`, a tool for configuring the switch datapath.

Open vSwitch also provides some tools:

- `ovs-ofctl`, a utility for querying and controlling OpenFlow switches and
  controllers.
- `ovs-pki`, a utility for creating and managing the public-key infrastructure
  for OpenFlow switches.
- `ovs-testcontroller`, a simple OpenFlow controller that may be useful for
  testing (though not for production).

## Building on Windows

The Windows build uses CMake with Visual Studio 2022 (no MSYS/autotools). The
ovsext driver is built with the Windows Driver Kit (WDK). The
**Build and Test (Windows)** GitHub Actions workflow shows the canonical build
and test steps.

For background on Open vSwitch concepts, the upstream documentation under
`Documentation/` remains a useful reference. **Note:** that documentation is
inherited from upstream and is **not** maintained for this Windows fork — it
may describe Linux-specific procedures or features that do not apply here, and
may be stale with respect to the Windows port.

## License

Open vSwitch is licensed under the open source Apache 2 license. Some files may
be marked specifically with a different license, in which case that license
applies to the file in question.

- Files under the `datapath` directory are licensed under the GNU General
  Public License, version 2.
- `lib/conntrack-tcp.c` is licensed under the 2-clause BSD license.
- `lib/sflow*.[ch]` are licensed under the terms of either the Sun Industry
  Standards Source License 1.1
  (<http://host-sflow.sourceforge.net/sissl.html>) or the InMon sFlow License
  (<http://www.inmon.com/technology/sflowlicense.txt>).

## Contact

For issues specific to this Windows fork, please use the issue tracker at
<https://github.com/dbosoft/ovs/issues>.

Upstream Open vSwitch can be reached at bugs@openvswitch.org.
