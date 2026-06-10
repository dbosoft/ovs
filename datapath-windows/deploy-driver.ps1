<#
.SYNOPSIS
  Hot-swap the freshly built DBO_OVSE.sys into the ovs-kerneldev test VM and
  reload it, without a reboot.

.DESCRIPTION
  Iteration loop for kernel driver dev. Assumes ONE-TIME setup is already done on
  the VM (see datapath-windows/test-catlet and project memory):
    * WDKTestCert imported into LocalMachine\Root + TrustedPublisher
    * testsigning active at runtime (VBS disabled + rebooted once)
    * our package staged once via `pnputil /add-driver ovsext.inf` so its catalog
      is registered and the DBO_OVSE service ImagePath points at our ovsext.inf_*
      DriverStore folder.

  Because the .sys is embedded test-signed and testsigning is active, we can simply
  overwrite the bound .sys in place after unloading it. Sequence that works:
    1. (optional) stop nested guests so the switch is quiescent
    2. Disable-VMSwitchExtension  -> detach the filter
    3. Stop-Service DBO_OVSE      -> unload image, unlock the .sys
    4. overwrite the bound .sys (path read from the service ImagePath)
    5. Start-Service DBO_OVSE; Enable-VMSwitchExtension -> reattach with new code
    6. verify Running + hash match
    7. (optional) restart nested guests

.EXAMPLE
  pwsh -File deploy-driver.ps1                 # build already done; swap + reload
  pwsh -File deploy-driver.ps1 -Build          # build first, then swap
#>
[CmdletBinding()]
param(
    [switch]$Build,
    [string]$Alias   = 'ovs-kerneldev',
    [string]$VmId    = '80cfe34e-d27d-4c77-89f7-79608f901cb8',
    [string[]]$NestedVMs = @('ub1','ub2'),
    [switch]$KeepNestedRunning
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$ssh  = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'
$egs  = "$env:USERPROFILE\AppData\Local\Eryph\egs-tool\bin\egs-tool.exe"
$pkg  = Join-Path $here 'x64\Win10Debug\package'

function Invoke-Remote([string]$script) {
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    & $ssh -o BatchMode=yes -o ConnectTimeout=25 $Alias "powershell -NoProfile -EncodedCommand $enc"
    if ($LASTEXITCODE -ne 0) { throw "remote command failed ($LASTEXITCODE)" }
}

if ($Build) {
    & (Join-Path $here 'build-driver.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'build failed' }
}

$localHash = (Get-FileHash (Join-Path $pkg 'DBO_OVSE.sys') -Algorithm SHA256).Hash
Write-Host "local DBO_OVSE.sys = $localHash" -ForegroundColor DarkGray

# stage the fresh files (egs-tool: scp-over-proxy hangs; upload-* does not).
Invoke-Remote 'Get-ChildItem C:\ovs-test\driver -File -EA SilentlyContinue | Remove-Item -Force'
& $egs upload-directory $VmId $pkg 'C:\ovs-test\driver' | Select-Object -Last 1

# refresh the diagnostics helpers alongside it: ovs-tcpdump.ps1 (pktmon capture)
# and ovs-drvtrace.ps1 (driver ETW log capture).
& $egs upload-file $VmId (Join-Path $here 'utilities\ovs-tcpdump.ps1') 'C:\ovs-test\ovs-tcpdump.ps1' --overwrite | Select-Object -Last 1
& $egs upload-file $VmId (Join-Path $here 'utilities\ovs-drvtrace.ps1') 'C:\ovs-test\ovs-drvtrace.ps1' --overwrite | Select-Object -Last 1

$stopList = if ($KeepNestedRunning) { '@()' } else { "@('" + ($NestedVMs -join "','") + "')" }
$startBackLit = if ($KeepNestedRunning) { '$false' } else { '$true' }

$swap = @"
`$ErrorActionPreference='Continue'
`$ext = 'dbosoft Open vSwitch Extension'
`$sw  = (Get-VMSwitch | Get-VMSwitchExtension | Where-Object Name -eq `$ext | Select-Object -First 1).SwitchName
`$nested = $stopList
if (`$nested.Count) { Get-VM `$nested -EA SilentlyContinue | Stop-VM -Force -TurnOff -EA SilentlyContinue }
Disable-VMSwitchExtension -VMSwitchName `$sw -Name `$ext -EA Continue | Out-Null
# OVS userspace holds the driver's netlink device open; the I/O Manager will not
# unload a driver while any handle to its device object exists, so Stop-Service
# parks in STOP_PENDING forever if ovs-vswitchd/ovsdb-server are still running.
# Release the handle first.
Stop-Process -Name ovs-vswitchd,ovsdb-server -Force -EA SilentlyContinue
Stop-Service DBO_OVSE -Force -EA Continue
Start-Sleep 2
`$bound = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\DBO_OVSE').ImagePath) -replace '^\\SystemRoot','C:\Windows'
Copy-Item C:\ovs-test\driver\DBO_OVSE.sys `$bound -Force
Copy-Item C:\ovs-test\driver\dbo_ovse.cat (Split-Path `$bound) -Force -EA SilentlyContinue
`$h = (Get-FileHash `$bound -Algorithm SHA256).Hash
"bound hash = `$h"
"HASH MATCH = " + (`$h -eq '$localHash')
Start-Service DBO_OVSE -EA Continue
Enable-VMSwitchExtension -VMSwitchName `$sw -Name `$ext -EA Continue | Out-Null
Start-Sleep 2
"driver state = " + (Get-CimInstance Win32_SystemDriver -Filter "Name='DBO_OVSE'").State
Get-VMSwitch | Get-VMSwitchExtension | Where-Object Name -eq `$ext | Select-Object Enabled,Running | Format-List
if ($startBackLit -and `$nested.Count) { Start-VM `$nested -EA SilentlyContinue }
"@
Invoke-Remote $swap
Write-Host "`nDeploy complete." -ForegroundColor Green
