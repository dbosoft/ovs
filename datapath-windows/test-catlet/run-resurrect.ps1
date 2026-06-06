# RFC-0029 ghost->live + carrier validation, designed to run as a detached
# scheduled task (no ssh pipe to hang). Writes progress incrementally to
# C:\ovs-test\rr-result.txt and ALWAYS self-stops via try/finally.
$ErrorActionPreference = 'Continue'
$out = 'C:\ovs-test\rr-result.txt'
Set-Content -Path $out -Value "RR start $(Get-Date -Format o)" -Encoding utf8
function Log($m) { Add-Content -Path $out -Value $m -Encoding utf8 }

$native = 'C:\ovs-test\native'; $run = 'C:\ovs-test\run'
$env:Path = "$native;$env:Path"
'OVS_RUNDIR','OVS_LOGDIR','OVS_DBDIR','OVS_SYSCONFDIR' | ForEach-Object { Set-Item "env:$_" $run }
$vsctl = "$native\ovs-vsctl.exe"; $port = 'ovs_ub1'

try {
    Stop-VM -Name ub1 -Force -TurnOff -EA SilentlyContinue
    Get-Process ovs-vswitchd,ovsdb-server -EA SilentlyContinue | Stop-Process -Force
    Start-Sleep 1
    foreach ($f in 'conf.db','ovs-vswitchd.log','ovsdb-server.log','ovsdb-server.pid','ovs-vswitchd.pid') {
        $p = Join-Path $run $f; if (Test-Path $p) { Remove-Item $p -Force }
    }
    & "$native\ovsdb-tool.exe" create "$run\conf.db" "$native\vswitch.ovsschema" | Out-Null
    Start-Process -FilePath "$native\ovsdb-server.exe" -WindowStyle Hidden `
        -RedirectStandardOutput "$run\dbo.out" -RedirectStandardError "$run\dbo.err" -ArgumentList `
        "$run\conf.db",'-vconsole:off','--remote=punix:db.sock',"--log-file=$run\ovsdb-server.log",'--pidfile'
    Start-Sleep 2
    & $vsctl --no-wait init
    Start-Process -FilePath "$native\ovs-vswitchd.exe" -WindowStyle Hidden `
        -RedirectStandardOutput "$run\vsw.out" -RedirectStandardError "$run\vsw.err" -ArgumentList `
        '-vconsole:off','-vfile:info',"--log-file=$run\ovs-vswitchd.log",'--pidfile'
    Start-Sleep 3
    $dp = (Get-VMSwitch -Name LANbond).Id.ToString().ToUpper()
    & $vsctl --timeout=25 add-br br-int -- set bridge br-int datapath_type=$dp
    Start-Sleep 2
    & $vsctl --timeout=25 add-port br-int $port
    Start-Sleep 2
    Log "GHOST  ofport=$(& $vsctl get interface $port ofport)  link_state=$(& $vsctl get interface $port link_state)"

    Log "Start-VM ub1..."
    Start-VM -Name ub1
    for ($i=0; $i -lt 14; $i++) {
        Start-Sleep 6
        $ll = (Get-VMNetworkAdapter -VMName ub1 -EA SilentlyContinue).IPAddresses | Where-Object { $_ -match '^fe80' } | Select-Object -First 1
        if ($ll) { break }
    }
    Start-Sleep 3
    Log "LIVE t0  ofport=$(& $vsctl get interface $port ofport)  link_state=$(& $vsctl get interface $port link_state)"
    Start-Sleep 4
    Log "LIVE t1  link_state=$(& $vsctl get interface $port link_state)"
    Start-Sleep 4
    Log "LIVE t2  link_state=$(& $vsctl get interface $port link_state)"
    Log "ub1 vNIC status=$((Get-VMNetworkAdapter -VMName ub1 | Select-Object -Expand Status) -join ',')  ll=$ll"
    Log "--- interface row ---"
    foreach($c in 'admin_state','link_state','link_resets','mtu','mac_in_use','error','ofport','ifindex'){
        Log "$c = $(& $vsctl get interface $port $c)"
    }
}
catch { Log "ERROR: $_" }
finally {
    Stop-VM -Name ub1 -Force -TurnOff -EA SilentlyContinue
    & $vsctl --timeout=10 del-br br-int 2>&1 | Out-Null
    Get-Process ovs-vswitchd,ovsdb-server -EA SilentlyContinue | Stop-Process -Force
    Log "RR-DONE"
}
