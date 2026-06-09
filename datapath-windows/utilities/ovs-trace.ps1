<#
.SYNOPSIS
  Trace a packet through the OVN logical pipeline and/or the OVS datapath on
  Windows - a convenience wrapper over the (already working) `ovn-trace` and
  `ovs-appctl ofproto/trace` binaries, with the Windows-specific socket paths
  and microflow quoting handled for you.

.DESCRIPTION
  The trace engines themselves ship and work on Windows; what was awkward was
  invoking them: the OVN southbound DB and the per-bridge management socket live
  under different run directories than the OVS DB, and building an ovn-trace
  "microflow" by hand is quoting-sensitive from PowerShell. This script resolves
  those and offers three modes:

    -Logical    ovn-trace: simulate a packet through the OVN logical pipeline.
                With -WithOvs it also pulls the matching OVS OpenFlow flows, so
                you see logical and physical in one trace.
    -Datapath   ovs-appctl ofproto/trace: simulate a flow through a bridge's
                OpenFlow tables and show the resulting datapath actions.
    -FromVm     like -Logical, but builds the microflow for you from a source
                OVS port / VM NIC (resolves inport + source MAC) plus the
                destination you give.

.EXAMPLE
  # Logical trace, summary form, with the physical OpenFlow flows too
  ./ovs-trace.ps1 -Logical -LsDatapath <ls> -WithOvs `
      -Microflow 'inport == "ovs_..._eth0" && eth.src == d2:ab:4f:cd:59:10 && ip4.dst == 10.0.0.101 && ip.ttl == 64'

.EXAMPLE
  # Build the microflow automatically from ub1's port to 10.0.0.101 (ICMP)
  ./ovs-trace.ps1 -FromVm -SrcPort ovs_a0b24961-..._eth0 -DstIp 10.0.0.101 -L4 icmp

.EXAMPLE
  # OVS datapath trace of a flow through br-int
  ./ovs-trace.ps1 -Datapath -Bridge br-int -Flow 'in_port=4,icmp,nw_src=10.0.0.100,nw_dst=10.0.0.101'
#>
[CmdletBinding(DefaultParameterSetName = 'Logical')]
param(
    [Parameter(ParameterSetName = 'Logical', Mandatory)]  [switch]$Logical,
    [Parameter(ParameterSetName = 'Datapath', Mandatory)] [switch]$Datapath,
    [Parameter(ParameterSetName = 'FromVm', Mandatory)]   [switch]$FromVm,

    # --- Logical (ovn-trace) ---
    [Parameter(ParameterSetName = 'Logical')]
    [Parameter(ParameterSetName = 'FromVm')]
    [string]$LsDatapath,                       # logical switch (datapath) name or uuid
    [Parameter(ParameterSetName = 'Logical', Mandatory)]
    [string]$Microflow,                        # raw ovn microflow expression

    # --- FromVm convenience ---
    [Parameter(ParameterSetName = 'FromVm')] [string]$SrcPort,   # OVS interface name
    [Parameter(ParameterSetName = 'FromVm')] [string]$Vm,        # or a VM (uses its first NIC's port)
    [Parameter(ParameterSetName = 'FromVm')] [string]$SrcIp,
    [Parameter(ParameterSetName = 'FromVm', Mandatory)] [string]$DstIp,
    [Parameter(ParameterSetName = 'FromVm')] [string]$DstMac,
    [Parameter(ParameterSetName = 'FromVm')] [ValidateSet('icmp', 'icmp6', 'tcp', 'udp')] [string]$L4 = 'icmp',
    [Parameter(ParameterSetName = 'FromVm')] [int]$DstPort = 0,

    # --- Datapath (ovs-appctl ofproto/trace) ---
    [Parameter(ParameterSetName = 'Datapath')] [string]$Bridge = 'br-int',
    [Parameter(ParameterSetName = 'Datapath', Mandatory)] [string]$Flow,

    # --- shared options / Windows paths ---
    [ValidateSet('Detailed', 'Summary', 'Minimal', 'All')] [string]$Detail = 'Summary',
    [switch]$WithOvs,                          # ovn-trace --ovs (pull matching OpenFlow flows)
    [switch]$NoFriendlyNames,
    [string]$SbDb     = 'unix:C:\ProgramData\openvswitch\var\run\ovn\ovnsb_db.sock',
    [string]$OvsDb    = 'unix:C:\ProgramData\openvswitch\var\run\openvswitch\db.sock',
    [string]$OvsRemote = 'unix:C:\openvswitch\var\run\openvswitch\br-int.mgmt',
    [string]$VswitchdCtl = 'C:\ProgramData\openvswitch\var\run\openvswitch\ovs-vswitchd.ctl',
    [string]$BinDir                            # dir holding ovn-trace.exe / ovs-appctl.exe / ovs-vsctl.exe
)

$ErrorActionPreference = 'Stop'

function Resolve-Bin([string]$exe) {
    if ($BinDir) {
        $p = Join-Path $BinDir $exe
        if (Test-Path $p) { return $p } else { throw "$exe not found in -BinDir '$BinDir'" }
    }
    $cmd = Get-Command $exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($g in @('C:\ProgramData\eryph\ovn\run_*\usr\bin', 'C:\openvswitch\usr\bin')) {
        $hit = Get-ChildItem (Join-Path $g $exe) -ErrorAction SilentlyContinue |
               Sort-Object FullName -Descending | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    throw "Could not locate $exe; pass -BinDir <dir>."
}

# Bulletproof native invocation: build the command line per CommandLineToArgvW
# escaping rules and run via ProcessStartInfo.Arguments, so an argument that
# contains spaces and embedded double-quotes (an ovn microflow) survives intact
# on both Windows PowerShell 5.1 and PowerShell 7.
function Format-NativeArg([string]$a) {
    if ($a -notmatch '[\s"]') { return $a }
    $sb = [Text.StringBuilder]::new()
    [void]$sb.Append('"')
    $bs = 0
    foreach ($ch in $a.ToCharArray()) {
        if ($ch -eq '\') { $bs++; continue }
        if ($ch -eq '"') { [void]$sb.Append('\' * ($bs * 2 + 1)); [void]$sb.Append('"'); $bs = 0; continue }
        if ($bs) { [void]$sb.Append('\' * $bs); $bs = 0 }
        [void]$sb.Append($ch)
    }
    [void]$sb.Append('\' * ($bs * 2))
    [void]$sb.Append('"')
    return $sb.ToString()
}

function Invoke-Native([string]$exe, [string[]]$argv) {
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $exe
    $psi.Arguments = ($argv | ForEach-Object { Format-NativeArg $_ }) -join ' '
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    Write-Verbose "$exe $($psi.Arguments)"
    $p = [Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEnd()
    $err = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    if ($err) { $err.TrimEnd() | Write-Host -ForegroundColor DarkYellow }
    return $out
}

function Get-OvsCtl { Resolve-Bin 'ovs-vsctl.exe' }
function Get-OvsInterfaceField([string]$name, [string]$field) {
    $vsctl = Get-OvsCtl
    return ("$(& $vsctl --timeout=5 --db=$OvsDb get interface $name $field 2>$null)").Trim().Trim('"')
}

# ---- Datapath mode (ovs-appctl ofproto/trace) ------------------------------
if ($PSCmdlet.ParameterSetName -eq 'Datapath') {
    $appctl = Resolve-Bin 'ovs-appctl.exe'
    Write-Host "=== ofproto/trace $Bridge ===" -ForegroundColor Cyan
    Invoke-Native $appctl @("--target=$VswitchdCtl", 'ofproto/trace', $Bridge, $Flow)
    return
}

# ---- FromVm: resolve inport + src MAC, build the microflow ------------------
if ($PSCmdlet.ParameterSetName -eq 'FromVm') {
    if (-not $SrcPort) {
        if (-not $Vm) { throw "Provide -SrcPort or -Vm." }
        $mac = (Get-VMNetworkAdapter -VMName $Vm -EA Stop | Select-Object -First 1).MacAddress
        $macColon = ($mac -replace '(..)(?=.)', '$1:').ToLower()
        # find the OVS interface with this mac_in_use
        $vsctl = Get-OvsCtl
        foreach ($br in (& $vsctl --timeout=5 --db=$OvsDb list-br)) {
            foreach ($p in (& $vsctl --timeout=5 --db=$OvsDb list-ports ("$br".Trim()))) {
                $pn = "$p".Trim()
                if ((Get-OvsInterfaceField $pn 'mac_in_use') -eq $macColon) { $SrcPort = $pn; break }
            }
            if ($SrcPort) { break }
        }
        if (-not $SrcPort) { throw "Could not find an OVS port for VM '$Vm' (mac $macColon)." }
    }

    $inport = Get-OvsInterfaceField $SrcPort 'external_ids:iface-id'
    if (-not $inport) { $inport = $SrcPort }   # fall back to the port name
    $srcMac = Get-OvsInterfaceField $SrcPort 'mac_in_use'

    if (-not $LsDatapath) {
        # best-effort: resolve the logical switch (datapath) from the SB port_binding
        try {
            $sbctl = Resolve-Bin 'ovn-sbctl.exe'
            # port -> its SB datapath_binding -> the NB logical switch id ovn-trace wants
            $dp = ("$(& $sbctl --timeout=5 --db=$SbDb --bare --columns=datapath find port_binding logical_port=$inport 2>$null)").Trim()
            if ($dp) {
                $ls = ("$(& $sbctl --timeout=5 --db=$SbDb --if-exists get datapath_binding $dp 'external_ids:logical-switch' 2>$null)").Trim().Trim('"')
                if ($ls) { $LsDatapath = $ls }
            }
        } catch { }
        if (-not $LsDatapath) { throw "Could not auto-resolve the logical switch; pass -LsDatapath." }
    }

    $parts = @("inport == `"$inport`"", "eth.src == $srcMac")
    if ($DstMac) { $parts += "eth.dst == $DstMac" }
    if ($SrcIp)  { $parts += "ip4.src == $SrcIp" }
    switch ($L4) {
        'icmp'  { $parts += "ip4.dst == $DstIp"; $parts += 'ip.ttl == 64'; $parts += 'icmp4.type == 8' }
        'icmp6' { $parts += "ip6.dst == $DstIp"; $parts += 'ip.ttl == 64'; $parts += 'icmp6.type == 128' }
        'tcp'   { $parts += "ip4.dst == $DstIp"; $parts += 'ip.ttl == 64'; if ($DstPort) { $parts += "tcp.dst == $DstPort" } }
        'udp'   { $parts += "ip4.dst == $DstIp"; $parts += 'ip.ttl == 64'; if ($DstPort) { $parts += "udp.dst == $DstPort" } }
    }
    $Microflow = $parts -join ' && '
    Write-Host "inport=$inport  src-mac=$srcMac  datapath=$LsDatapath" -ForegroundColor DarkGray
    Write-Host "microflow: $Microflow" -ForegroundColor DarkGray
}

# ---- Logical / FromVm: run ovn-trace ---------------------------------------
if (-not $LsDatapath) { throw "Provide -LsDatapath (the logical switch name/uuid)." }
$ovntrace = Resolve-Bin 'ovn-trace.exe'
$argv = @("--db=$SbDb")
switch ($Detail) {
    'Detailed' { $argv += '--detailed' }
    'Summary'  { $argv += '--summary' }
    'Minimal'  { $argv += '--minimal' }
    'All'      { $argv += '--all' }
}
if ($WithOvs)         { $argv += "--ovs=$OvsRemote" }
if ($NoFriendlyNames) { $argv += '--no-friendly-names' }
$argv += @($LsDatapath, $Microflow)

Write-Host "=== ovn-trace ($Detail$(if($WithOvs){' +ovs'})) ===" -ForegroundColor Cyan
Invoke-Native $ovntrace $argv
