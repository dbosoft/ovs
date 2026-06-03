# Multi-switch datapath test console, run INSIDE the ovs-kerneldev catlet.
#
# Wraps the OVS run-dir env + binary paths so you can fire ovs-vsctl / ovs-dpctl
# commands by hand, and gives up/down/info/ping helpers for a two-switch
# topology (a bridge per Hyper-V switch, each selected by datapath_type=<switch
# GUID>).  The kernel names each datapath by its switch GUID in UPPERCASE and
# datapath_type resolution is case-sensitive, so this script always uses the
# uppercased Get-VMSwitch Id.
#
# USAGE (from the catlet, or: ssh ovs-kerneldev powershell -File C:\ovs-test\ms-dp.ps1 <action>)
#   ms-dp.ps1 up                 enable both exts, start OVS, build br-int (sw1) + br-test2 (sw2)
#   ms-dp.ps1 info               switches + GUIDs + ext state + datapaths (copy the GUIDs from here)
#   ms-dp.ps1 dpctl show         run ovs-dpctl with the env already set
#   ms-dp.ps1 vsctl show         run ovs-vsctl  with the env already set
#   ms-dp.ps1 dpctl dump-flows windows@<GUID>
#   ms-dp.ps1 ping               ping ub1/ub2 link-local through br-int (switch 1)
#   ms-dp.ps1 down               del bridges, stop daemons, disable the ovs-test2 ext
#
# Any unknown first word is treated as help.  vsctl/dpctl/ofctl/appctl pass all
# remaining arguments straight through.

param(
    [string]$Action = 'help',
    [Parameter(ValueFromRemainingArguments = $true)] [string[]]$Rest
)

$ErrorActionPreference = 'Continue'
$native = 'C:\ovs-test\native'; $run = 'C:\ovs-test\run'
$env:Path = "$native;$env:Path"
foreach ($v in 'OVS_RUNDIR','OVS_LOGDIR','OVS_DBDIR','OVS_SYSCONFDIR') { Set-Item "env:$v" $run }
$vsctl = "$native\ovs-vsctl.exe"; $dpctl = "$native\ovs-dpctl.exe"
$ofctl = "$native\ovs-ofctl.exe"; $appctl = "$native\ovs-appctl.exe"; $tool = "$native\ovsdb-tool.exe"
$ext = 'dbosoft Open vSwitch Extension'

# Switches to wire up (edit these two names if your switches differ).
$SW1 = 'eryph_overlay'   # bridge br-int; ub1/ub2 live here
$SW2 = 'ovs-test2'       # bridge br-test2

function DpType($switchName) {
    $s = Get-VMSwitch -Name $switchName -EA SilentlyContinue
    if ($s) { return $s.Id.ToString().ToUpper() }
    return $null
}
function EnableExt($switchName) {
    Enable-VMSwitchExtension -VMSwitchName $switchName -Name $ext -EA Continue | Out-Null
}
function StartDaemons {
    Get-Process ovs-vswitchd,ovsdb-server -EA SilentlyContinue | Stop-Process -Force
    Start-Sleep -Milliseconds 700
    Remove-Item "$run\conf.db","$run\*.log","$run\*.pid" -EA SilentlyContinue
    & $tool create "$run\conf.db" "$native\vswitch.ovsschema" | Out-Null
    & "$native\ovsdb-server.exe" "$run\conf.db" -vconsole:off --remote=punix:db.sock --log-file="$run\ovsdb-server.log" --pidfile --detach | Out-Null
    Start-Sleep 1
    & $vsctl --no-wait init
    & "$native\ovs-vswitchd.exe" -vconsole:off -vfile:info --log-file="$run\ovs-vswitchd.log" --pidfile --detach | Out-Null
    Start-Sleep 2
}
function AddPort($br, $port) {
    & $vsctl --timeout=25 add-port $br $port
    Start-Sleep 1
    if ((& $vsctl --timeout=10 get interface $port ofport) -match '-1') {
        & $vsctl --timeout=25 del-port $br $port; Start-Sleep 1
        & $vsctl --timeout=25 add-port $br $port; Start-Sleep 1
    }
}

switch ($Action) {

  'up' {
    $dp1 = DpType $SW1; $dp2 = DpType $SW2
    if (-not $dp1 -or -not $dp2) { "ERROR: could not resolve switch GUIDs ($SW1=$dp1, $SW2=$dp2)"; break }
    "switch 1 '$SW1' datapath_type = $dp1"
    "switch 2 '$SW2' datapath_type = $dp2"
    EnableExt $SW1; EnableExt $SW2; Start-Sleep 2
    StartDaemons
    "=== br-int on $SW1 ==="
    & $vsctl --timeout=25 add-br br-int -- set bridge br-int datapath_type=$dp1
    Start-Sleep 3
    AddPort 'br-int' 'ovs_ub1'; AddPort 'br-int' 'ovs_ub2'
    "=== br-test2 on $SW2 ==="
    & $vsctl --timeout=25 add-br br-test2 -- set bridge br-test2 datapath_type=$dp2
    Start-Sleep 3
    Enable-NetAdapter -Name br-int -EA Continue
    Enable-NetAdapter -Name br-test2 -EA Continue
    Start-Sleep 2
    "=== ovs-vsctl show ==="; & $vsctl show
    "=== ovs-dpctl show ==="; & $dpctl show
    "UP-DONE"
  }

  'down' {
    & $vsctl --timeout=10 del-br br-test2 2>&1 | Out-Null
    & $vsctl --timeout=10 del-br br-int 2>&1 | Out-Null
    Get-Process ovs-vswitchd,ovsdb-server -EA SilentlyContinue | Stop-Process -Force
    Start-Sleep 1
    Disable-VMSwitchExtension -VMSwitchName $SW2 -Name $ext -EA Continue | Out-Null
    "stopped daemons; deleted bridges; disabled '$SW2' ext (left '$SW1' ext as-is)"
    "driver = " + (Get-CimInstance Win32_SystemDriver -Filter "Name='DBO_OVSE'").State
    "DOWN-DONE"
  }

  'info' {
    "=== switches (use the UPPERCASE Id as datapath_type) ==="
    Get-VMSwitch | Select-Object Name,@{n='datapath_type';e={$_.Id.ToString().ToUpper()}},SwitchType | Format-Table -Auto | Out-String
    "=== extension state ==="
    Get-VMSwitch | ForEach-Object { $s=$_; Get-VMSwitchExtension -VMSwitchName $s.Name | Where-Object Name -match 'Open vSwitch' | Select-Object @{n='Switch';e={$s.Name}},Enabled,Running } | Format-Table -Auto | Out-String
    "=== VM NIC connections ==="
    Get-VMNetworkAdapter -VMName ub1,ub2 -EA SilentlyContinue | Select-Object VMName,SwitchName,MacAddress | Format-Table -Auto | Out-String
    "=== driver ==="; (Get-CimInstance Win32_SystemDriver -Filter "Name='DBO_OVSE'").State
    "=== ovs-dpctl show (one block per datapath; ports listed under each) ==="
    & $dpctl show 2>&1
  }

  'ping' {
    $idx = (Get-NetAdapter -Name br-int -EA SilentlyContinue).ifIndex
    if (-not $idx) { "br-int adapter not found - run 'up' first"; break }
    foreach ($vm in 'ub1','ub2') {
      $ll = (Get-VMNetworkAdapter -VMName $vm -EA SilentlyContinue).IPAddresses | Where-Object { $_ -match '^fe80' } | Select-Object -First 1
      if ($ll) { "=== ping $vm ($ll) via br-int ==="; ping -6 -n 4 "$ll%$idx"; "exit=$LASTEXITCODE" }
      else { "no link-local found for $vm (is it running?)" }
    }
  }

  'vsctl'  { & $vsctl  @Rest }
  'dpctl'  { & $dpctl  @Rest }
  'ofctl'  { & $ofctl  @Rest }
  'appctl' { & $appctl @Rest }

  default {
    @"
ms-dp.ps1 - multi-switch datapath test console (run inside ovs-kerneldev)

  up            enable both exts, start OVS, build br-int ($SW1) + br-test2 ($SW2)
  down          del bridges, stop daemons, disable the '$SW2' ext
  info          switches + GUIDs (datapath_type values) + ext state + datapaths
  ping          ping ub1/ub2 link-local through br-int (switch 1)
  vsctl  <...>  run ovs-vsctl  with the OVS env already set
  dpctl  <...>  run ovs-dpctl  with the OVS env already set
  ofctl  <...>  run ovs-ofctl
  appctl <...>  run ovs-appctl

Examples:
  ms-dp.ps1 up
  ms-dp.ps1 info
  ms-dp.ps1 dpctl show
  ms-dp.ps1 vsctl show
  ms-dp.ps1 dpctl dump-flows windows@<GUID-from-info>
  ms-dp.ps1 vsctl -- add-br br3 -- set bridge br3 datapath_type=<GUID-from-info>
  ms-dp.ps1 ping
  ms-dp.ps1 down

Note: datapath_type must be the switch Id in UPPERCASE (the kernel names each
datapath by that GUID and resolution is case-sensitive). 'info' prints them.
"@
  }
}
