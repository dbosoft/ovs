# Windows OVS diagnostic utilities

PowerShell helpers that bring `ovs-tcpdump`-style capture and `ovn-trace` /
`ofproto/trace`-style tracing to the Windows (ovsext) datapath. They are
standalone scripts - no Python or .NET runtime to install - and drive the in-box
Windows tools plus the OVS/OVN binaries that already ship on Windows.

## ovs-pcap.ps1 - packet capture (the `ovs-tcpdump` replacement)

`ovs-tcpdump` works on Linux by adding an OVS mirror to a tap and running
tcpdump on it; neither the tap nor that mirror path exists on the Windows
datapath. `ovs-pcap.ps1` instead drives the Windows packet monitor (`pktmon`),
which observes a Hyper-V switch port - including internal VM-to-VM traffic that
never touches a physical NIC - with no OVS mirror, and converts the result to a
`.pcapng` for Wireshark. An OVS port is matched to its `pktmon` component by MAC
address (the same on the OVS interface, the VM NIC and the component).

```powershell
# 30s capture of ub1's NIC, open in Wireshark
./ovs-pcap.ps1 -Vm ub1 -Open

# Only ICMP to/from 10.0.0.101 on a specific OVS port
./ovs-pcap.ps1 -Port ovs_..._eth0 -Protocol ICMP -Ip 10.0.0.101 -Seconds 15

# Live, on-screen capture until Ctrl+C
./ovs-pcap.ps1 -Vm ub1 -RealTime

# Show the OVS-port / VM-NIC / pktmon-component map
./ovs-pcap.ps1 -List
```

Requires an elevated session (pktmon needs admin). pktmon has a single global
capture session; the tool takes it over (`-Force` evicts a leftover one).

## ovs-trace.ps1 - logical and datapath tracing

The trace engines (`ovn-trace`, `ovs-appctl ofproto/trace`) already work on
Windows; this wraps them with the Windows-specific socket paths and microflow
quoting handled for you.

```powershell
# Logical (OVN) pipeline, with the matching physical OpenFlow flows (--ovs)
./ovs-trace.ps1 -Logical -LsDatapath <ls> -WithOvs -Microflow '<expr>'

# Build the microflow automatically from a source port + destination
# (-FromVm resolves the inport, source MAC, logical switch and the port's bound
#  source IP from the OVN southbound DB, so the trace clears port security)
./ovs-trace.ps1 -FromVm -Vm ub1 -DstIp 10.0.0.101 -DstMac <dst-mac> -L4 icmp

# OVS datapath actions for a flow through a bridge
./ovs-trace.ps1 -Datapath -Bridge br-int -Flow 'in_port=4,icmp,nw_dst=10.0.0.101'
```

## Windows layout notes

- The OVS DB socket (`db.sock`) lives under `C:\ProgramData\openvswitch\...`,
  while the per-bridge management sockets (`br-int.mgmt`) and the system-wide
  `OVS_RUNDIR` live under `C:\openvswitch\...`. The scripts connect to each
  explicitly (`--db` for the DB, the bridge `.mgmt` path for `--ovs`) rather than
  relying on `OVS_RUNDIR`. Override with `-OvsDb` / `-SbDb` / `-OvsRemote` if your
  layout differs.
- Binary locations (`ovs-vsctl`, `ovn-trace`, `ovs-appctl`, `ovn-sbctl`) are
  auto-detected (PATH, then the eryph and `C:\openvswitch` install trees); pass
  `-BinDir` / `-OvsCtl` to point at a specific build.
