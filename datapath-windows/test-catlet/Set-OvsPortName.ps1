<#
.SYNOPSIS
  Set (or list) the OVS port name on a Hyper-V VM network adapter so the Windows
  OVS forwarding extension (ovsext) binds that adapter to the named OVS port.
  Multi-switch aware.

.DESCRIPTION
  ovsext matches an OVS port to a Hyper-V switch port by the port's *friendly
  name*, which is the ElementName of the Msvm_EthernetPortAllocationSettingData
  (the adapter<->switch CONNECTION) -- NOT the VM-adapter name that
  Rename-VMNetworkAdapter / Set-VMNetworkAdapter -Name sets (that is the
  SyntheticEthernetPortSettingData ElementName, which ovsext ignores).

  This script sets the connection ElementName via
  Msvm_VirtualSystemManagementService.ModifyResourceSettings -- the same property
  dotnet-ovn's HyperVOvsPortManager drives (eryph prefixes the name with 'ovs_').

  A VM may have several vNICs on different switches; select the target adapter
  with -SwitchName (recommended), -MacAddress, or -AdapterName. With no -PortName
  (or -List) it prints the current adapter -> OVS-port mapping and exits.

.PARAMETER VMName       Target VM (Msvm ElementName).
.PARAMETER PortName     Desired OVS port name (the name you pass to ovs-vsctl add-port).
.PARAMETER SwitchName   Select the adapter connected to this vSwitch.
.PARAMETER MacAddress   Select the adapter with this MAC (any separators ok).
.PARAMETER AdapterName  Select the adapter by its current VM-adapter name.
.PARAMETER List         Only list the current mapping; make no change.

.EXAMPLE
  .\Set-OvsPortName.ps1 -VMName ub1 -List
.EXAMPLE
  .\Set-OvsPortName.ps1 -VMName ub1 -PortName ovs_ub1 -SwitchName LANbond
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$VMName,
    [string]$PortName,
    [string]$SwitchName,
    [string]$MacAddress,
    [string]$AdapterName,
    [switch]$List
)
$ErrorActionPreference = 'Stop'
$ns = 'root\virtualization\v2'

function ConvertTo-CimText($instance) {
    $ser = [Microsoft.Management.Infrastructure.Serialization.CimSerializer]::Create()
    $opt = [Microsoft.Management.Infrastructure.Serialization.InstanceSerializationOptions]::None
    [System.Text.Encoding]::Unicode.GetString($ser.Serialize($instance, $opt))
}
function Resolve-SwitchName($hostResource) {
    # HostResource looks like:
    #   Msvm_VirtualEthernetSwitch.CreationClassName="Msvm_VirtualEthernetSwitch",Name="<switch-guid>"
    # Match the standalone Name= (the GUID), not the "Name" inside CreationClassName.
    if ($hostResource -match '(?<![A-Za-z])Name="([^"]+)"') {
        $id = $Matches[1]
        $sw = Get-VMSwitch -Id $id -ErrorAction SilentlyContinue
        if ($sw) { return $sw.Name } else { return $id }
    }
    return $null
}

$vm = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "ElementName='$VMName'"
if (-not $vm) { throw "VM '$VMName' not found." }
$vssd = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_VirtualSystemSettingData |
        Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' } | Select-Object -First 1

$rows = foreach ($sepsd in (Get-CimAssociatedInstance -InputObject $vssd -ResultClassName Msvm_SyntheticEthernetPortSettingData)) {
    foreach ($epasd in (Get-CimAssociatedInstance -InputObject $sepsd -ResultClassName Msvm_EthernetPortAllocationSettingData)) {
        [pscustomobject]@{
            Adapter  = $sepsd.ElementName
            Mac      = $sepsd.Address
            PortName = $epasd.ElementName
            Switch   = Resolve-SwitchName ($epasd.HostResource -join ';')
            Epasd    = $epasd
        }
    }
}

if ($List -or -not $PortName) {
    $rows | Select-Object Adapter, Mac, PortName, Switch | Format-Table -Auto
    if (-not $PortName) { return }
}

$targets = $rows
if ($SwitchName)  { $targets = $targets | Where-Object Switch -eq $SwitchName }
if ($MacAddress)  { $m = ($MacAddress -replace '[^0-9A-Fa-f]', '').ToUpper(); $targets = $targets | Where-Object { ($_.Mac -replace '[^0-9A-Fa-f]', '').ToUpper() -eq $m } }
if ($AdapterName) { $targets = $targets | Where-Object Adapter -eq $AdapterName }

if (-not $targets) { throw "No adapter on '$VMName' matches (switch=$SwitchName mac=$MacAddress adapter=$AdapterName)." }
if (($targets | Measure-Object).Count -gt 1) {
    throw "Ambiguous match ($(($targets | ForEach-Object { "$($_.Adapter)@$($_.Switch)" }) -join ', ')). Narrow with -SwitchName / -MacAddress / -AdapterName."
}

$t = $targets[0]
$epasd = $t.Epasd
$old = $epasd.ElementName
if ($old -eq $PortName) { "No change: '$($t.Adapter)' on '$($t.Switch)' OVS port name already = '$PortName'."; return }
$epasd.ElementName = $PortName

if ($PSCmdlet.ShouldProcess("$VMName adapter '$($t.Adapter)' on '$($t.Switch)'", "set OVS port name '$old' -> '$PortName'")) {
    $vmms = Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemManagementService
    $res = $vmms | Invoke-CimMethod -MethodName ModifyResourceSettings -Arguments @{ ResourceSettings = @((ConvertTo-CimText $epasd)) }
    switch ($res.ReturnValue) {
        0    { "OK: '$($t.Adapter)' on '$($t.Switch)' OVS port name = '$PortName' (was '$old')." }
        4096 { "Job started ($($res.Job)); change applied asynchronously." }
        default { throw "ModifyResourceSettings failed, ReturnValue=$($res.ReturnValue)." }
    }
}
