# Host<->nested-VM forwarding test through the live Windows OVS datapath, run
# INSIDE the ovs-kerneldev catlet. Brings up our ovsdb+vswitchd, builds a
# datapath_type=system bridge, adds the nested guests' OVS ports (already named
# ovs_ub1/ovs_ub2), enables the bridge host adapter, then pings each guest's
# IPv6 link-local through the datapath. Stops the daemons at the end so the
# invoking SSH session (whose pipe the --detach'd daemons inherit) returns.
$ErrorActionPreference = 'Continue'
$native = 'C:\ovs-test\native'; $run = 'C:\ovs-test\run'
$env:Path = "$native;$env:Path"
foreach ($v in 'OVS_RUNDIR','OVS_LOGDIR','OVS_DBDIR','OVS_SYSCONFDIR') { Set-Item "env:$v" $run }
$vsctl = "$native\ovs-vsctl.exe"; $dpctl = "$native\ovs-dpctl.exe"; $tool = "$native\ovsdb-tool.exe"
$br = 'br-int'

Get-Process ovs-vswitchd,ovsdb-server -EA SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 700
Remove-Item "$run\conf.db","$run\ovsdb-server.log","$run\ovs-vswitchd.log","$run\*.pid" -EA SilentlyContinue
& $tool create "$run\conf.db" "$native\vswitch.ovsschema" | Out-Null
& "$native\ovsdb-server.exe" "$run\conf.db" -vconsole:off --remote=punix:db.sock --log-file="$run\ovsdb-server.log" --pidfile --detach | Out-Null
Start-Sleep 1
& $vsctl --no-wait init
& "$native\ovs-vswitchd.exe" -vconsole:off -vfile:info --log-file="$run\ovs-vswitchd.log" --pidfile --detach | Out-Null
Start-Sleep 2

& $vsctl --timeout=25 add-br $br -- set bridge $br datapath_type=system
Start-Sleep 3
foreach ($p in 'ovs_ub1','ovs_ub2') {
    & $vsctl --timeout=25 add-port $br $p
    Start-Sleep 1
    $ofport = (& $vsctl --timeout=10 get interface $p ofport) 2>&1
    if ($ofport -match '-1') {
        # ofport=-1 "No such device": one clean del+re-add, never churn reconnect.
        & $vsctl --timeout=25 del-port $br $p
        Start-Sleep 1
        & $vsctl --timeout=25 add-port $br $p
        Start-Sleep 1
    }
}

Enable-NetAdapter -Name $br -EA Continue
Start-Sleep 3
$ifIdx = (Get-NetAdapter -Name $br -EA SilentlyContinue).ifIndex
"=== dpctl show ==="
& $dpctl show system@ovs-system 2>&1
"$br host ifIndex = $ifIdx"

$targets = @{ ub1 = 'fe80::d0ab:bfff:fef2:a0bd'; ub2 = 'fe80::d0ab:6fff:fe99:3fd' }
foreach ($name in $targets.Keys) {
    "=== ping $name ($($targets[$name])) through datapath ==="
    ping -6 -n 4 "$($targets[$name])%$ifIdx"
    "ping exit=$LASTEXITCODE"
}

"=== flows on datapath (forwarding evidence) ==="
& $dpctl dump-flows system@ovs-system 2>&1 | Select-Object -First 8

"=== cleanup ==="
& $vsctl --timeout=25 del-br $br 2>&1 | Out-Null
Get-Process ovs-vswitchd,ovsdb-server -EA SilentlyContinue | Stop-Process -Force
"driver state = " + (Get-CimInstance Win32_SystemDriver -Filter "Name='DBO_OVSE'").State
"DONE"
