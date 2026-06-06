# RFC-0029 NETDEV pre-create ("ghost") validation, run inside ovs-kerneldev.
# Brings up OVS on the LANbond switch, adds a NETDEV port whose Hyper-V adapter
# does not exist, and checks it is accepted (ofport > 0, link-down, no error)
# rather than rejected (ofport = -1). Then deletes it to exercise the ghost
# delete/counter-balance path. Self-stopping so the SSH session returns.
$ErrorActionPreference = 'Continue'
$native = 'C:\ovs-test\native'; $run = 'C:\ovs-test\run'
$env:Path = "$native;$env:Path"
foreach ($v in 'OVS_RUNDIR','OVS_LOGDIR','OVS_DBDIR','OVS_SYSCONFDIR') { Set-Item "env:$v" $run }
$vsctl = "$native\ovs-vsctl.exe"; $dpctl = "$native\ovs-dpctl.exe"; $tool = "$native\ovsdb-tool.exe"
$dp = (Get-VMSwitch -Name LANbond).Id.ToString().ToUpper()

Get-Process ovs-vswitchd,ovsdb-server -EA SilentlyContinue | Stop-Process -Force
Start-Sleep 1
foreach ($f in 'conf.db','ovsdb-server.log','ovs-vswitchd.log','ovsdb-server.pid','ovs-vswitchd.pid') {
    $p = Join-Path $run $f
    if (Test-Path $p) { Remove-Item $p -Force -EA SilentlyContinue }
}
& $tool create "$run\conf.db" "$native\vswitch.ovsschema" | Out-Null
& "$native\ovsdb-server.exe" "$run\conf.db" -vconsole:off --remote=punix:db.sock --log-file="$run\ovsdb-server.log" --pidfile --detach | Out-Null
Start-Sleep 1
& $vsctl --no-wait init
& "$native\ovs-vswitchd.exe" -vconsole:off -vfile:info --log-file="$run\ovs-vswitchd.log" --pidfile --detach | Out-Null
Start-Sleep 2

& $vsctl --timeout=25 add-br br-int -- set bridge br-int datapath_type=$dp
Start-Sleep 2

"=== TEST: pre-create NETDEV port 'ghost_test' with NO Hyper-V backing ==="
& $vsctl --timeout=25 add-port br-int ghost_test
Start-Sleep 2
"ofport     (NEW driver: expect > 0 ; OLD would be -1): " + (& $vsctl --timeout=10 get interface ghost_test ofport)
"error      (expect empty / []):                        " + (& $vsctl --timeout=10 get interface ghost_test error)
"link_state (expect down):                              " + (& $vsctl --timeout=10 get interface ghost_test link_state)
"=== ovs-dpctl show (ghost_test should appear under the datapath) ==="
& $dpctl show
"=== del-port ghost_test (ghost delete / counter balance / no bugcheck) ==="
& $vsctl --timeout=25 del-port br-int ghost_test
Start-Sleep 1
"=== ovs-dpctl show after del ==="
& $dpctl show
"=== driver state after add+del ==="
(Get-CimInstance Win32_SystemDriver -Filter "Name='DBO_OVSE'").State

& $vsctl --timeout=10 del-br br-int 2>&1 | Out-Null
Get-Process ovs-vswitchd,ovsdb-server -EA SilentlyContinue | Stop-Process -Force
"PRECREATE-TEST-DONE"
