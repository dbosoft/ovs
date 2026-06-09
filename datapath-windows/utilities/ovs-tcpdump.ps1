<#
.SYNOPSIS
  Capture packets on an Open vSwitch port (a Hyper-V VM NIC) on Windows and
  write a .pcapng you can open in Wireshark - the Windows counterpart to
  Linux `ovs-tcpdump`.

.DESCRIPTION
  ovs-tcpdump works on Linux by adding an OVS mirror to a tap device and running
  tcpdump on it; neither the tap nor that mirror path exists on the Windows
  (ovsext) datapath. Instead this script drives the in-box Windows packet
  monitor (pktmon), which can observe traffic on a Hyper-V switch port -
  including internal VM-to-VM traffic that never touches a physical NIC - with
  no OVS mirror required, and converts the result to .pcapng.

  The bridge between "OVS port" and "pktmon component" is the MAC address, which
  is the same on the OVS interface (`mac_in_use`), the Hyper-V VM NIC, and the
  pktmon component, so resolution is robust regardless of naming.

  Selection (one of):
    -Port       an OVS interface name (resolved to its MAC via ovs-vsctl)
    -Vm         a Hyper-V VM name (captures every NIC of the VM)
    -Mac        a MAC address (any of aa:bb:.., aa-bb-.., aabb..)
    -Component  a raw pktmon component id (from -List)
    -List       just print the OVS-port / VM-NIC / pktmon-component map and exit

  Requires an elevated session (pktmon needs admin). pktmon has a single global
  capture session; this tool takes it over (use -Force to evict a leftover one).

.EXAMPLE
  # 30s capture of everything on ub1's port, open in Wireshark
  ./ovs-tcpdump.ps1 -Vm ub1 -Open

.EXAMPLE
  # Only ICMP to/from 10.0.0.101 on a specific OVS port, 15s
  ./ovs-tcpdump.ps1 -Port ovs_a0b24961-..._eth0 -Protocol ICMP -Ip 10.0.0.101 -Seconds 15

.EXAMPLE
  # Live, tcpdump-style screen output until Ctrl+C
  ./ovs-tcpdump.ps1 -Vm ub1 -RealTime

.EXAMPLE
  ./ovs-tcpdump.ps1 -List
#>
[CmdletBinding(DefaultParameterSetName = 'Port')]
param(
    [Parameter(ParameterSetName = 'Port', Mandatory)]      [string]$Port,
    [Parameter(ParameterSetName = 'Vm', Mandatory)]        [string]$Vm,
    [Parameter(ParameterSetName = 'Mac', Mandatory)]       [string]$Mac,
    [Parameter(ParameterSetName = 'Component', Mandatory)] [int[]]$Component,
    [Parameter(ParameterSetName = 'List', Mandatory)]      [switch]$List,

    # Capture duration in seconds (ignored with -RealTime). 0 waits for Ctrl+C.
    [int]$Seconds = 30,
    # Output .pcapng path. Default: %TEMP%\ovs-tcpdump-<target>-<timestamp>.pcapng
    [string]$Out,

    # Optional pktmon narrowing filters (applied on top of the component).
    [ValidateSet('IPv4', 'IPv6', 'ARP')] [string]$EtherType,
    [ValidateSet('TCP', 'UDP', 'ICMP', 'ICMPv6')] [string]$Protocol,
    [string]$Ip,
    [int]$TcpUdpPort,

    # Live, on-screen capture (pktmon real-time) instead of file capture.
    [switch]$RealTime,
    # Open the resulting .pcapng when done (whatever is associated with .pcapng).
    [switch]$Open,
    # Evict any pktmon capture session already running.
    [switch]$Force,
    # Path to ovs-vsctl.exe (only needed for -Port/-List). Auto-detected if omitted.
    [string]$OvsCtl,
    # OVS DB connection (only needed for -Port/-List). The Windows OVS DB socket
    # lives under ProgramData even though the bridge sockets (and the system-wide
    # OVS_RUNDIR eryph sets) point elsewhere, so connect to the DB explicitly.
    [string]$OvsDb = 'unix:C:\ProgramData\openvswitch\var\run\openvswitch\db.sock'
)

$ErrorActionPreference = 'Stop'

function Convert-Mac([string]$m) {
    # Normalize any MAC spelling to 12 uppercase hex chars, or $null.
    if (-not $m) { return $null }
    $h = ($m -replace '[^0-9A-Fa-f]', '').ToUpper()
    if ($h.Length -eq 12) { return $h } else { return $null }
}

function Get-PktmonComponents {
    # Parse `pktmon list` into [pscustomobject]@{ Id; Mac; Name }.
    $rows = @()
    foreach ($line in (pktmon list 2>&1)) {
        $s = [string]$line
        $m = [regex]::Match($s,
            '^\s*(?<id>\d+)\s+(?<mac>[0-9A-Fa-f]{2}(-[0-9A-Fa-f]{2}){5})\s+(?<name>.+?)\s*$')
        if ($m.Success) {
            $rows += [pscustomobject]@{
                Id   = [int]$m.Groups['id'].Value
                Mac  = Convert-Mac $m.Groups['mac'].Value
                Name = $m.Groups['name'].Value.Trim()
            }
        }
    }
    return $rows
}

function Resolve-OvsCtl {
    if ($OvsCtl) {
        if (-not (Test-Path $OvsCtl)) { throw "ovs-vsctl not found at -OvsCtl '$OvsCtl'" }
        return $OvsCtl
    }
    $cmd = Get-Command ovs-vsctl.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $candidates = @(
        'C:\ProgramData\eryph\ovn\run_*\usr\bin\ovs-vsctl.exe',
        'C:\ProgramData\eryph\ovs\run_*\bin\ovs-vsctl.exe',
        'C:\openvswitch\usr\bin\ovs-vsctl.exe'
    )
    foreach ($g in $candidates) {
        $hit = Get-ChildItem $g -ErrorAction SilentlyContinue |
               Sort-Object FullName -Descending | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    throw "Could not locate ovs-vsctl.exe; pass -OvsCtl <path>."
}

function Get-OvsPortMac([string]$portName) {
    $vsctl = Resolve-OvsCtl
    $mac = (& $vsctl --timeout=5 --db=$OvsDb get interface $portName mac_in_use) 2>&1
    $mac = ($mac | Out-String).Trim().Trim('"')
    $norm = Convert-Mac $mac
    if (-not $norm) { throw "Could not read mac_in_use for OVS interface '$portName' (got '$mac')." }
    return $norm
}

function Get-VmMacs([string]$vmName) {
    $nics = Get-VMNetworkAdapter -VMName $vmName -ErrorAction Stop
    if (-not $nics) { throw "No NICs found for VM '$vmName'." }
    return @($nics | ForEach-Object { Convert-Mac $_.MacAddress } | Where-Object { $_ })
}

# ---- list mode --------------------------------------------------------------
$components = Get-PktmonComponents
if ($List) {
    "=== pktmon components (network adapters) ==="
    $components | Sort-Object Id | Format-Table Id, @{n='MAC';e={$_.Mac}}, Name -Auto | Out-String | Write-Host
    "=== OVS interfaces (name -> mac -> pktmon component) ==="
    try {
        $vsctl = Resolve-OvsCtl
        foreach ($name in (& $vsctl --timeout=5 --db=$OvsDb list-br | ForEach-Object { & $vsctl --timeout=5 --db=$OvsDb list-ports ("$_".Trim()) })) {
            $n = "$name".Trim(); if (-not $n) { continue }
            $mac = Convert-Mac (("$(& $vsctl --timeout=5 --db=$OvsDb get interface $n mac_in_use 2>$null)").Trim().Trim('"'))
            $comp = if ($mac) { ($components | Where-Object Mac -eq $mac | Select-Object -First 1).Id } else { $null }
            "{0,-55} {1,-14} comp={2}" -f $n, $(if ($mac) { $mac } else { '-' }), $(if ($null -ne $comp) { $comp } else { '-' })
        }
    } catch { Write-Warning "OVS port enumeration skipped: $($_.Exception.Message)" }
    return
}

# ---- resolve target component(s) -------------------------------------------
$targetMacs = @()
switch ($PSCmdlet.ParameterSetName) {
    'Port'      { $targetMacs = @(Get-OvsPortMac $Port);  $label = $Port }
    'Vm'        { $targetMacs = Get-VmMacs $Vm;           $label = $Vm }
    'Mac'       { $targetMacs = @(Convert-Mac $Mac);      $label = $Mac
                  if (-not $targetMacs[0]) { throw "Invalid -Mac '$Mac'." } }
    'Component' { $compIds = $Component;                  $label = "comp$($Component -join '-')" }
}

if ($PSCmdlet.ParameterSetName -ne 'Component') {
    $compIds = @()
    foreach ($tm in $targetMacs) {
        $c = $components | Where-Object Mac -eq $tm | Select-Object -First 1
        if (-not $c) { throw "No pktmon component has MAC $tm (is the VM/port up? try -List)." }
        $compIds += $c.Id
        Write-Host "Target: $($c.Name)  MAC $tm  -> pktmon component $($c.Id)" -ForegroundColor Cyan
    }
}
$compIds = @($compIds | Sort-Object -Unique)

# ---- pktmon session ---------------------------------------------------------
function Stop-PktmonQuietly { try { pktmon stop 2>&1 | Out-Null } catch { } }

# pktmon filters are a single global, persistent set. Clear them up front so a
# run without narrowing filters captures everything deterministically instead of
# silently inheriting a stale filter from an earlier session, then add this run's
# optional filters (and clear again in finally so we leave no residue).
function Clear-Filters { pktmon filter remove 2>&1 | Out-Null }
function Add-Filters {
    $fargs = @('ovs-tcpdump')
    if ($EtherType)  { $fargs += @('-d', $EtherType) }
    if ($Protocol)   { $fargs += @('-t', $Protocol) }
    if ($Ip)         { $fargs += @('-i', $Ip) }
    if ($TcpUdpPort) { $fargs += @('-p', "$TcpUdpPort") }
    if ($fargs.Count -gt 1) { pktmon filter add @fargs 2>&1 | Out-Null }
}

if ($Force) { Stop-PktmonQuietly }
Clear-Filters
Add-Filters

$compArg = @('--comp') + ($compIds | ForEach-Object { "$_" })

try {
    if ($RealTime) {
        Write-Host "Live capture on component(s) $($compIds -join ',') - press Ctrl+C to stop." -ForegroundColor Green
        pktmon start --capture @compArg --pkt-size 0 --log-mode real-time
    }
    else {
        if (-not $Out) {
            $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
            $safe = ($label -replace '[^0-9A-Za-z_.-]', '_')
            $Out = Join-Path $env:TEMP "ovs-tcpdump-$safe-$stamp.pcapng"
        }
        $etl = [IO.Path]::ChangeExtension($Out, '.etl')
        $outDir = Split-Path -Parent $Out
        if ($outDir -and -not (Test-Path $outDir)) {
            New-Item -ItemType Directory -Force -Path $outDir | Out-Null
        }

        $start = pktmon start --capture @compArg --pkt-size 0 --file-name $etl 2>&1
        if ($LASTEXITCODE -ne 0) {
            # most likely a leftover session; evict and retry once
            Write-Warning "pktmon start failed ($start). Retrying after stopping the current session."
            Stop-PktmonQuietly
            $start = pktmon start --capture @compArg --pkt-size 0 --file-name $etl 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "pktmon start failed ($start)."
            }
        }
        $wait = if ($Seconds -gt 0) { "$Seconds s" } else { "until Ctrl+C" }
        Write-Host "Capturing on component(s) $($compIds -join ',') -> $etl ($wait)..." -ForegroundColor Green
        if ($Seconds -gt 0) { Start-Sleep -Seconds $Seconds }
        else { Write-Host "Press Ctrl+C to stop..."; try { while ($true) { Start-Sleep 1 } } catch { } }

        $stopOut = (pktmon stop 2>&1 | Out-String).Trim()
        if ($stopOut) { Write-Host $stopOut -ForegroundColor DarkGray }
        Write-Host "Converting to pcapng..." -ForegroundColor Green
        pktmon pcapng $etl -o $Out 2>&1 | Out-Null
        if (Test-Path $Out) {
            $size = (Get-Item $Out).Length
            Write-Host "Wrote $Out ($size bytes)." -ForegroundColor Green
            if ($Open) { Start-Process $Out }
        }
        else {
            Write-Warning "pcapng conversion produced no file; the raw capture is at $etl"
        }
    }
}
finally {
    Clear-Filters
}
