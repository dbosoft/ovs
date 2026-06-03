$ErrorActionPreference='Continue'
$run='C:\ProgramData\eryph\ovs\run_1'
Write-Output '=== eryph ovs-dpctl show (datapath vports) ==='
& "$run\bin\ovs-dpctl.exe" show 2>&1
Write-Output '=== OVS port ElementName per VM adapter (WMI) ==='
$ns='root\virtualization\v2'
foreach($vm in 'ub1','ub2'){
  $vssd = gwmi -ns $ns -class Msvm_VirtualSystemSettingData -Filter "ElementName='$vm'"
  $ports = gwmi -ns $ns -Query "Associators of {$vssd} Where ResultClass=Msvm_EthernetPortAllocationSettingData"
  foreach($p in $ports){ Write-Output "$vm ovsport='$($p.ElementName)'" }
}
Write-Output '=== ub2 guest IPs ==='
(Get-VMNetworkAdapter -VMName ub2).IPAddresses -join ','
Write-Output '=== egs-tool in catlet? ==='
(Get-Command egs-tool -EA Ignore).Source
