# Bilateral proof: move ub2 onto switch 2 (ovs-test2), bind it to br-test2, and
# ping it through switch-2's INDEPENDENT datapath while ub1 still forwards on
# switch 1. Restores ub2 to eryph_overlay at the end no matter what.
$ErrorActionPreference = 'Continue'
$native = 'C:\ovs-test\native'; $run = 'C:\ovs-test\run'
$env:Path = "$native;$env:Path"
foreach ($v in 'OVS_RUNDIR','OVS_LOGDIR','OVS_DBDIR','OVS_SYSCONFDIR') { Set-Item "env:$v" $run }
$vsctl = "$native\ovs-vsctl.exe"; $dpctl = "$native\ovs-dpctl.exe"
$DP2 = '9B6AA6B7-2242-43FF-8764-EA6FA9C6FEAF'
$ub2ll = 'fe80::d0ab:6fff:fe99:3fd'

try {
    "=== move ub2 -> ovs-test2 ==="
    Connect-VMNetworkAdapter -VMName ub2 -SwitchName ovs-test2 -EA Continue
    Start-Sleep 4
    Get-VMNetworkAdapter -VMName ub2 | Select-Object VMName,SwitchName | Format-Table -Auto | Out-String

    "=== add ub2 port to br-test2 ==="
    & $vsctl --timeout=25 add-port br-test2 ovs_ub2
    Start-Sleep 2
    $ofport = (& $vsctl --timeout=10 get interface ovs_ub2 ofport) 2>&1
    "ovs_ub2 ofport = $ofport"
    if ($ofport -match '-1') {
        & $vsctl --timeout=25 del-port br-test2 ovs_ub2; Start-Sleep 1
        & $vsctl --timeout=25 add-port br-test2 ovs_ub2; Start-Sleep 2
    }

    Enable-NetAdapter -Name br-test2 -EA Continue
    Start-Sleep 3
    "=== dpctl show switch-2 datapath (must list br-test2 + ovs_ub2) ==="
    & $dpctl show "windows@$DP2" 2>&1

    $ifIdx = (Get-NetAdapter -Name br-test2 -EA SilentlyContinue).ifIndex
    "br-test2 host ifIndex = $ifIdx"
    "=== ping ub2 through SWITCH-2 datapath ==="
    ping -6 -n 4 "$ub2ll%$ifIdx"
    "ping exit=$LASTEXITCODE"

    "=== flows on switch-2 datapath ==="
    & $dpctl dump-flows "windows@$DP2" 2>&1 | Select-Object -First 6
}
finally {
    "=== RESTORE: ub2 -> eryph_overlay ==="
    & $vsctl --timeout=25 del-port br-test2 ovs_ub2 2>&1 | Out-Null
    Connect-VMNetworkAdapter -VMName ub2 -SwitchName eryph_overlay -EA Continue
    Start-Sleep 2
    Get-VMNetworkAdapter -VMName ub2 | Select-Object VMName,SwitchName | Format-Table -Auto | Out-String
    "driver state = " + (Get-CimInstance Win32_SystemDriver -Filter "Name='DBO_OVSE'").State
}
"SW2-DONE"
