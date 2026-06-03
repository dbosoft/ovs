# Wait for two nested guest catlets to acquire IPs, then dump their VM adapters.
# Runs INSIDE the kernel-dev catlet. The catlet IDs are environment-specific:
# pass them as args (or set OVS_TEST_UB1_ID / OVS_TEST_UB2_ID).
param(
  [string]$Ub1Id = $env:OVS_TEST_UB1_ID,
  [string]$Ub2Id = $env:OVS_TEST_UB2_ID
)
$ErrorActionPreference='Continue'
Import-Module Eryph.ComputeClient -ErrorAction SilentlyContinue
foreach ($p in @(@{n='ub1';id=$Ub1Id},@{n='ub2';id=$Ub2Id})) {
  if (-not $p.id) { Write-Output "$($p.n): no catlet id supplied (skipping)"; continue }
  $ip=$null
  for ($i=0;$i -lt 30;$i++){ try{$ip=(Get-CatletIp -Id $p.id -EA Stop|Select -First 1).IpAddress}catch{}; if($ip){break}; Start-Sleep 10 }
  Write-Output "$($p.n) IP=$ip"
}
Write-Output "=== VM adapters (switch + MAC) ==="
Get-VMNetworkAdapter -VMName ub1,ub2 | Select-Object VMName,SwitchName,MacAddress,@{n='IPs';e={$_.IPAddresses -join ','}} | Format-Table -Auto
