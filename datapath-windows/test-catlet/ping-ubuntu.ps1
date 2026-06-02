# Wait for ub1's nested IP, then ping it from the catlet (nested eryph host /
# gateway). The ping traverses the nested OVS datapath. Runs INSIDE the catlet.
# The catlet id is environment-specific: pass it as an arg (or set OVS_TEST_UB1_ID).
param(
  [string]$Ub1Id = $env:OVS_TEST_UB1_ID
)
$ErrorActionPreference = 'Continue'
Import-Module Eryph.ComputeClient -ErrorAction SilentlyContinue
if (-not $Ub1Id) { Write-Output 'No catlet id supplied (set -Ub1Id or $env:OVS_TEST_UB1_ID).'; return }

$ip = $null
for ($i = 0; $i -lt 36; $i++) {
    try {
        $r = Get-CatletIp -Id $Ub1Id -ErrorAction Stop
        $ip = ($r | Select-Object -First 1).IpAddress
    } catch { }
    if ($ip) { break }
    Start-Sleep -Seconds 10
}
Write-Output "ub1 IP = $ip"
if ($ip) {
    Write-Output '=== ping ub1 from catlet (through nested OVS) ==='
    ping -n 4 $ip
    Write-Output "ping exit=$LASTEXITCODE"
}
Write-Output '=== nested OVS bridges/ports (ovs-vsctl) ==='
$vsctl = Get-ChildItem 'C:\Program Files\eryph' -Recurse -Filter ovs-vsctl.exe -ErrorAction SilentlyContinue | Select-Object -First 1
if ($vsctl) { & $vsctl.FullName show 2>&1 } else { Write-Output 'ovs-vsctl not found under C:\Program Files\eryph' }
