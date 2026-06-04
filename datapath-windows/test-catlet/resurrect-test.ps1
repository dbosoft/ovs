# RFC-0029 ghost RESURRECTION validation, run inside ovs-kerneldev.
# Pre-creates ghost port 'ghost_ub1' while ub1 is Off, starts ub1 (whose vNIC is
# named ghost_ub1 on LANbond), and checks the ghost resurrects in place (same
# ofport, single port) and actually forwards (ping ub1 link-local through the
# datapath = proof the kernel vport went OVS_STATE_CONNECTED). Self-stopping.
$ErrorActionPreference = 'Continue'
$native = 'C:\ovs-test\native'; $run = 'C:\ovs-test\run'
$env:Path = "$native;$env:Path"
foreach ($v in 'OVS_RUNDIR','OVS_LOGDIR','OVS_DBDIR','OVS_SYSCONFDIR') { Set-Item "env:$v" $run }
$vsctl = "$native\ovs-vsctl.exe"; $dpctl = "$native\ovs-dpctl.exe"; $tool = "$native\ovsdb-tool.exe"
$dp = (Get-VMSwitch -Name LANbond).Id.ToString().ToUpper()
$port = 'ghost_ub1'

Get-Process ovs-vswitchd,ovsdb-server -EA SilentlyContinue | Stop-Process -Force
Start-Sleep 1
foreach ($f in 'conf.db','ovsdb-server.log','ovs-vswitchd.log','ovsdb-server.pid','ovs-vswitchd.pid') {
    $p = Join-Path $run $f; if (Test-Path $p) { Remove-Item $p -Force -EA SilentlyContinue }
}
& $tool create "$run\conf.db" "$native\vswitch.ovsschema" | Out-Null
& "$native\ovsdb-server.exe" "$run\conf.db" -vconsole:off --remote=punix:db.sock --log-file="$run\ovsdb-server.log" --pidfile --detach | Out-Null
Start-Sleep 1
& $vsctl --no-wait init
& "$native\ovs-vswitchd.exe" -vconsole:off -vfile:info --log-file="$run\ovs-vswitchd.log" --pidfile --detach | Out-Null
Start-Sleep 2
& $vsctl --timeout=25 add-br br-int -- set bridge br-int datapath_type=$dp
Start-Sleep 2

"=== pre-create ghost '$port' (ub1 Off, no HV port yet) ==="
& $vsctl --timeout=25 add-port br-int $port
Start-Sleep 2
$ofBefore = (& $vsctl --timeout=10 get interface $port ofport)
"ofport BEFORE start: $ofBefore"
"link_state BEFORE:   " + (& $vsctl --timeout=10 get interface $port link_state)

"=== start ub1 (its vNIC 'ghost_ub1' on LANbond should resurrect the ghost) ==="
Start-VM -Name ub1 -EA Continue
# wait for boot + vNIC connect + guest link-local
for ($i=0; $i -lt 14; $i++) {
    Start-Sleep 6
    $ll = (Get-VMNetworkAdapter -VMName ub1 -EA SilentlyContinue).IPAddresses | Where-Object { $_ -match '^fe80' } | Select-Object -First 1
    if ($ll) { break }
}
Start-Sleep 3
$ofAfter = (& $vsctl --timeout=10 get interface $port ofport)
"ofport AFTER start:  $ofAfter   (resurrection = SAME ofport, no churn)"
"link_state AFTER:    " + (& $vsctl --timeout=10 get interface $port link_state)
"ub1 vNIC status:     " + ((Get-VMNetworkAdapter -VMName ub1).Status -join ',')
"ub1 link-local:      $ll"
"=== dpctl show (expect single '$port', no duplicate) ==="
& $dpctl show

"=== forwarding proof: ping ub1 link-local through br-int ==="
Enable-NetAdapter -Name br-int -EA Continue
Start-Sleep 3
$idx = (Get-NetAdapter -Name br-int -EA SilentlyContinue).ifIndex
if ($ll -and $idx) {
    ping -6 -n 4 "$ll%$idx"
    "ping exit=$LASTEXITCODE  (0 = forwarded through the resurrected datapath port)"
} else { "no link-local or br-int ifIndex; ll=$ll idx=$idx" }

"=== driver state ==="
(Get-CimInstance Win32_SystemDriver -Filter "Name='DBO_OVSE'").State

Stop-VM -Name ub1 -Force -TurnOff -EA Continue
& $vsctl --timeout=10 del-port br-int $port 2>&1 | Out-Null
& $vsctl --timeout=10 del-br br-int 2>&1 | Out-Null
Get-Process ovs-vswitchd,ovsdb-server -EA SilentlyContinue | Stop-Process -Force
"RESURRECT-TEST-DONE"
