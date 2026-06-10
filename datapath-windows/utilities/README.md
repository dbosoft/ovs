# Windows OVS diagnostic utilities

## ovs-tcpdump.ps1 - packet capture for the Windows datapath

`ovs-tcpdump` is unavailable on Windows: it works on Linux by adding an OVS
mirror to a tap device and running tcpdump on it, and neither the tap nor that
mirror path exists on the Windows (ovsext) datapath (it also needs Python +
libpcap, which are not present). `ovs-tcpdump.ps1` is a standalone PowerShell
replacement - no runtime to install - that drives the in-box Windows packet
monitor (`pktmon`), which observes a Hyper-V switch port (including internal
VM-to-VM traffic that never touches a physical NIC) with no OVS mirror, and
converts the result to a `.pcapng` for Wireshark.

An OVS port is matched to its `pktmon` component by MAC address - the same on
the OVS interface (`mac_in_use`), the Hyper-V VM NIC and the component - so
resolution is robust regardless of naming.

```powershell
# 30s capture of ub1's NIC, open in Wireshark
./ovs-tcpdump.ps1 -Vm ub1 -Open

# Only ICMP to/from 10.0.0.101 on a specific OVS port
./ovs-tcpdump.ps1 -Port ovs_..._eth0 -Protocol ICMP -Ip 10.0.0.101 -Seconds 15

# Live, on-screen capture until Ctrl+C
./ovs-tcpdump.ps1 -Vm ub1 -RealTime

# Show the OVS-port / VM-NIC / pktmon-component map
./ovs-tcpdump.ps1 -List
```

Requires an elevated session (pktmon needs admin). pktmon has a single global
capture session; the tool takes it over (`-Force` evicts a leftover one).

## ovs-drvtrace.ps1 - driver log capture (ETW)

The forwarding extension routes every `OvsLog()` line through an ETW
TraceLogging provider (`Dbosoft.OVS.Ovsext`,
`{b2d1f6a4-9c3e-4f7a-a15b-6d8e2c4f7093}`), so the driver's logs can be captured
on a production/headless box **without a kernel debugger or DebugView**. The
events are self-describing (no PDB/TMF needed); `ovs-drvtrace.ps1` uses only the
in-box `logman` + `tracerpt`, so it runs on a stock VM with no WDK.

```powershell
# capture 20s around a repro, decode to a .csv next to the .etl
./ovs-drvtrace.ps1 -Seconds 20

# bracket a specific test
./ovs-drvtrace.ps1 -Start;  <run the test>;  ./ovs-drvtrace.ps1 -Stop

# errors+warnings only (level 3)
./ovs-drvtrace.ps1 -Seconds 60 -Level 3
```

Each decoded row carries the `Module` (OVS_DBG_* subsystem bitmask), `Function`,
`Line` and the formatted `Message`. The `.etl` also opens directly in WPA. Needs
an elevated session (ETW kernel sessions need admin).

The driver's `DbgPrintEx` verbosity is tunable in the field via the service
`Parameters` key (read once at load — reload the driver to apply):

```powershell
$pk = 'HKLM:\SYSTEM\CurrentControlSet\Services\DBO_OVSE\Parameters'
New-Item $pk -Force | Out-Null
Set-ItemProperty $pk LogLevel      -Type DWord -Value 4        # 0=Error..4=Loud
Set-ItemProperty $pk LogModuleMask -Type DWord -Value 0x008000 # OVS_DBG_* mask
```

These knobs gate the DbgPrint sink only; ETW capture is controlled by the
session (above) and records every module/level, so post-filter on the `Module`
field rather than narrowing here. Absent values keep the built-in defaults.

## Tracing

Flow tracing already works on Windows with the binaries that ship today, so no
wrapper is included here:

- `ovn-trace` - the OVN logical pipeline (add `--ovs` to fuse in the matching
  physical OpenFlow flows).
- `ovs-appctl ofproto/trace <bridge> <flow>` - the OpenFlow tables and the
  resulting datapath actions.

The one Windows wrinkle is the run-directory layout: the OVS DB socket
(`db.sock`) lives under `C:\ProgramData\openvswitch\...` while the per-bridge
management sockets (`br-int.mgmt`) and the system-wide `OVS_RUNDIR` live under
`C:\openvswitch\...`, so pass the socket paths explicitly (`--db` for the OVN
southbound DB, the bridge `.mgmt` path for `ovn-trace --ovs`) rather than
relying on `OVS_RUNDIR`.

## Locating ovs-vsctl

`ovs-tcpdump.ps1` calls `ovs-vsctl` (for `-Port` / `-List`); it is auto-detected
(PATH, then the eryph and `C:\openvswitch` install trees). Pass `-OvsCtl` to
point at a specific build, and `-OvsDb` if your DB socket is elsewhere.
