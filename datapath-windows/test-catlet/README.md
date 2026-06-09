# Windows OVS datapath test harness (eryph catlet)

Scripts that validate the CMake/MSVC-built Windows OVS against the **live kernel
datapath** (the "dbosoft Open vSwitch Extension" Hyper-V forwarding extension),
inside an eryph dev catlet. They run **inside** the catlet; copy your freshly
built binaries in and invoke them over SSH from the host.

## Layout assumed inside the catlet

- `C:\ovs-test\native\` — your built binaries + DLLs + `vswitch.ovsschema`
  (`ovsdb-server.exe`, `ovs-vswitchd.exe`, `ovs-vsctl.exe`, `ovsdb-tool.exe`,
  `ovs-appctl.exe`, `ovs-dpctl.exe`, `pthreadVC3.dll`, `libcrypto-3-x64.dll`,
  `libssl-3-x64.dll`).
- `C:\ovs-test\run\` — runtime dir (db, sockets, pidfiles, logs).
- The OVS forwarding extension must be installed and enabled on the eryph switch.

## Deploy + run from the host

```powershell
$ssh = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'   # pin Windows OpenSSH
$scp = Join-Path $env:WINDIR 'System32\OpenSSH\scp.exe'
$rel = 'F:\path\to\build\Release'
$exes = 'ovs-dpctl','ovs-vswitchd','ovsdb-server','ovs-vsctl','ovsdb-tool','ovs-appctl'
& $scp -O ($exes | ForEach-Object { "$rel\$_.exe" }) vswitchd\vswitch.ovsschema `
    "<catlet>:C:/ovs-test/native/"
& $scp -O datapath-windows\test-catlet\run-full-mgmt-dp-test.ps1 `
    datapath-windows\utilities\ovs-tcpdump.ps1 "<catlet>:C:/ovs-test/"
& $ssh <catlet> "powershell -NoProfile -ExecutionPolicy Bypass -File C:\ovs-test\run-full-mgmt-dp-test.ps1"
```

`scp -O` (legacy protocol) is required — the eryph guest-services sshd has no
SFTP subsystem.

## Scripts

- **`run-full-mgmt-dp-test.ps1`** — the main test. Exercises the management plane
  (db-init, schema upgrade, `--detach`, logs, `ovs-vsctl` db interaction,
  `ovs-appctl`) and the kernel datapath (`add-br datapath_type=system`,
  `ovs-dpctl show`, flow put/dump/del against `system@ovs-system`).
- **`test-vsctl.ps1`** — cross-version check: eryph's packaged `ovs-vsctl` against
  our `ovsdb-server`.
- **`wait-ips.ps1` / `ping-ubuntu.ps1`** — nested-VM forwarding test: wait for
  guest catlets to get IPs, then ping through the nested datapath. The guest
  catlet IDs are environment-specific — pass them as args or set
  `OVS_TEST_UB1_ID` / `OVS_TEST_UB2_ID`.
- **`gather.ps1`** — diagnostics: `ovs-dpctl show` + per-VM OVS port mapping (WMI).
- **`ovs-tcpdump.ps1`** — packet capture on an OVS port via pktmon, exported to
  `.pcapng` (the `ovs-tcpdump` replacement; see `../utilities/README.md`). Copied
  to `C:\ovs-test\` by the deploy steps above and by `deploy-driver.ps1`. Point
  `-OvsCtl C:\ovs-test\native\ovs-vsctl.exe` at the test build when needed.

These are manual/dev tools; they are not wired into CI.
