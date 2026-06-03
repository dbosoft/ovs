# Two-switch forwarding demo, run INSIDE the ovs-kerneldev catlet.
# Proves the ovsext multi-datapath stack end to end: one bridge per Hyper-V
# switch, each selected by datapath_type=<switch-guid>, opening that switch's
# own kernel datapath and forwarding independently.
#
#   br-int   datapath_type=<eryph_overlay GUID>  ports ovs_ub1, ovs_ub2
#   br-test2 datapath_type=<ovs-test2 GUID>      internal port on ovs-test2
#
# The kernel reports datapath names as the switch GUID in UPPERCASE; the bridge
# datapath_type must match that spelling (resolve is case-sensitive).
$ErrorActionPreference = 'Continue'
$native = 'C:\ovs-test\native'; $run = 'C:\ovs-test\run'
$env:Path = "$native;$env:Path"
foreach ($v in 'OVS_RUNDIR','OVS_LOGDIR','OVS_DBDIR','OVS_SYSCONFDIR') { Set-Item "env:$v" $run }
$vsctl = "$native\ovs-vsctl.exe"; $dpctl = "$native\ovs-dpctl.exe"; $tool = "$native\ovsdb-tool.exe"

$DP1 = '3D2A3FE1-1C10-4067-9067-BFCA27F869FB'   # eryph_overlay (ub1/ub2 live here)
$DP2 = '9B6AA6B7-2242-43FF-8764-EA6FA9C6FEAF'   # ovs-test2 (internal)

Get-Process ovs-vswitchd,ovsdb-server -EA SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 700
Remove-Item "$run\conf.db","$run\ovsdb-server.log","$run\ovs-vswitchd.log","$run\*.pid" -EA SilentlyContinue
& $tool create "$run\conf.db" "$native\vswitch.ovsschema" | Out-Null
& "$native\ovsdb-server.exe" "$run\conf.db" -vconsole:off --remote=punix:db.sock --log-file="$run\ovsdb-server.log" --pidfile --detach | Out-Null
Start-Sleep 1
& $vsctl --no-wait init
& "$native\ovs-vswitchd.exe" -vconsole:off -vfile:info --log-file="$run\ovs-vswitchd.log" --pidfile --detach | Out-Null
Start-Sleep 2

"=== create br-int on switch 1 ($DP1) ==="
& $vsctl --timeout=25 add-br br-int -- set bridge br-int datapath_type=$DP1
Start-Sleep 3
foreach ($p in 'ovs_ub1','ovs_ub2') {
    & $vsctl --timeout=25 add-port br-int $p
    Start-Sleep 1
    $ofport = (& $vsctl --timeout=10 get interface $p ofport) 2>&1
    if ($ofport -match '-1') {
        & $vsctl --timeout=25 del-port br-int $p; Start-Sleep 1
        & $vsctl --timeout=25 add-port br-int $p; Start-Sleep 1
    }
}

"=== create br-test2 on switch 2 ($DP2) ==="
& $vsctl --timeout=25 add-br br-test2 -- set bridge br-test2 datapath_type=$DP2
Start-Sleep 3

Enable-NetAdapter -Name br-int -EA Continue
Enable-NetAdapter -Name br-test2 -EA Continue
Start-Sleep 3

"=== ovs-vsctl show ==="
& $vsctl show 2>&1

"=== dpctl show (each datapath lists only its own ports) ==="
& $dpctl show 2>&1

"=== br-test2 internal adapter must be bound to ovs-test2 ==="
Get-VMNetworkAdapter -ManagementOS -EA SilentlyContinue |
    Where-Object Name -match 'br-test2|br-int' |
    Select-Object Name,SwitchName | Format-Table -Auto | Out-String

$ifIdx = (Get-NetAdapter -Name br-int -EA SilentlyContinue).ifIndex
"br-int host ifIndex = $ifIdx"
$targets = @{ ub1 = 'fe80::d0ab:bfff:fef2:a0bd'; ub2 = 'fe80::d0ab:6fff:fe99:3fd' }
foreach ($name in $targets.Keys) {
    "=== ping $name through switch-1 datapath ==="
    ping -6 -n 4 "$($targets[$name])%$ifIdx"
    "ping exit=$LASTEXITCODE"
}

"=== flows on switch-1 datapath (forwarding evidence) ==="
& $dpctl dump-flows "${DP1}@ovs-system" 2>&1 | Select-Object -First 6

"=== driver state ==="
(Get-CimInstance Win32_SystemDriver -Filter "Name='DBO_OVSE'").State
"DEMO-DONE"
