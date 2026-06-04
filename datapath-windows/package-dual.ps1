<#
.SYNOPSIS
  Build and package BOTH NDIS tiers of the dbosoft OVS forwarding extension into a
  single OS-decorated driver package (test-signed).

.DESCRIPTION
  Produces one driver package whose INF (packaging\ovsext-dual.inf) installs:
    * DBO_OVSE.sys   - NDIS 6.85 "modern" binary - on Server 2022 / Windows 11
    * DBO_OVSE60.sys - NDIS 6.60 "floor"  binary - on older Windows

  Steps: build each tier with build-driver.ps1 -NdisLevel, stage both .sys under
  distinct names, stamp + catalog (inf2cat) + test-sign the package.

  This is the shippable artifact; the per-config build (build-driver.ps1) still
  produces single-binary dev packages used by deploy-driver.ps1.

.EXAMPLE
  pwsh -File package-dual.ps1
  pwsh -File package-dual.ps1 -Config Release -Version 3.99.0.0
#>
[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')]
    [string]$Config  = 'Release',
    # Empty => derive from the OVS source version in configure.ac (AC_INIT), the
    # same source the vcxproj uses. Override only to force a specific DriverVer.
    [string]$Version = ''
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$cfg  = "Win10$Config"

# Derive the DriverVer version from the OVS source (configure.ac) when not given,
# so the INF stamp, both binaries and the catalog all carry the real version.
if (-not $Version) {
    $acPath = Join-Path $here '..\configure.ac'
    $ac = Get-Content -Raw -LiteralPath $acPath
    if ($ac -match 'AC_INIT\(openvswitch,\s*([0-9]+\.[0-9]+\.[0-9]+)') {
        $Version = "$($Matches[1]).0"
        Write-Host "Driver version derived from configure.ac: $Version" -ForegroundColor DarkGray
    } else {
        throw "Could not derive version from $acPath (no AC_INIT match); pass -Version."
    }
}

# Locate the WDK signing/cataloging tools (x86 flavor, as the WDK build uses).
$wdkBin = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Directory |
    Where-Object { Test-Path (Join-Path $_.FullName 'x86\inf2cat.exe') } |
    Sort-Object Name -Descending | Select-Object -First 1
if (-not $wdkBin) { throw 'No WDK bin with inf2cat.exe found.' }
$inf2cat  = Join-Path $wdkBin.FullName 'x86\inf2cat.exe'
$stampinf = Join-Path $wdkBin.FullName 'x86\stampinf.exe'
$signtool = Join-Path $wdkBin.FullName 'x86\signtool.exe'
Write-Host "WDK tools: $($wdkBin.Name)" -ForegroundColor DarkGray

# Test-signing certificate (the WDK self-signed dev cert the per-config build uses).
$cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My |
    Where-Object { $_.Subject -match 'WDKTestCert' } | Select-Object -First 1
if (-not $cert) { throw 'WDKTestCert not found in CurrentUser\My or LocalMachine\My.' }
$thumb = $cert.Thumbprint
Write-Host "Signing cert: $($cert.Subject) [$thumb]" -ForegroundColor DarkGray

# 1. Build both tiers.
Write-Host "`n== Building NDIS 6.60 floor ($cfg) ==" -ForegroundColor Cyan
& (Join-Path $here 'build-driver.ps1') -Config $cfg -NdisLevel 660 -Version $Version -Rebuild
if ($LASTEXITCODE) { throw 'floor build failed' }
$floorSys    = Join-Path $here "x64\$cfg\package\DBO_OVSE.sys"
$floorPdb    = Join-Path $here "ovsext\x64\$cfg\DBO_OVSE.pdb"
$floorSysTmp = Join-Path $here "x64\$cfg\DBO_OVSE60.sys"
$floorPdbTmp = Join-Path $here "x64\$cfg\DBO_OVSE60.pdb"
# Stash the floor binary + symbols before the modern build overwrites them.
Copy-Item $floorSys $floorSysTmp -Force
Copy-Item $floorPdb $floorPdbTmp -Force

Write-Host "`n== Building NDIS 6.85 modern ($cfg) ==" -ForegroundColor Cyan
& (Join-Path $here 'build-driver.ps1') -Config $cfg -NdisLevel 685 -Version $Version -Rebuild
if ($LASTEXITCODE) { throw 'modern build failed' }
$modernSys = Join-Path $here "x64\$cfg\package\DBO_OVSE.sys"

# 2. Assemble the combined package.
$pkg = Join-Path $here "x64\dual-$Config\package"
if (Test-Path $pkg) { Remove-Item $pkg -Recurse -Force }
New-Item -ItemType Directory -Force $pkg | Out-Null
Copy-Item $modernSys (Join-Path $pkg 'DBO_OVSE.sys')   -Force   # 6.85 modern
Copy-Item $floorSysTmp (Join-Path $pkg 'DBO_OVSE60.sys') -Force # 6.60 floor
Copy-Item (Join-Path $here 'packaging\ovsext-dual.inf') (Join-Path $pkg 'ovsext.inf') -Force
# Symbols + the test certificate, so this dir is a complete driver/ staging set
# that build-ovn-package.ps1 can consume verbatim.
Copy-Item (Join-Path $here "ovsext\x64\$cfg\DBO_OVSE.pdb") (Join-Path $pkg 'DBO_OVSE.pdb')   -Force
Copy-Item $floorPdbTmp                                     (Join-Path $pkg 'DBO_OVSE60.pdb') -Force
$cer = Join-Path $here "x64\$cfg\package.cer"
if (Test-Path $cer) { Copy-Item $cer (Join-Path $pkg 'package.cer') -Force }

# 3. Stamp the INF version, embed-sign both binaries, catalog, sign the catalog.
# Check every external tool: a silent failure here would leave an unstamped or
# unsigned package that only fails much later (at install/load on the VM).
& $stampinf -f (Join-Path $pkg 'ovsext.inf') -d '*' -v $Version
if ($LASTEXITCODE) { throw "stampinf failed ($LASTEXITCODE)" }
foreach ($s in 'DBO_OVSE.sys','DBO_OVSE60.sys') {
    & $signtool sign /fd SHA256 /sha1 $thumb /ph (Join-Path $pkg $s) | Out-Null
    if ($LASTEXITCODE) { throw "signtool sign $s failed ($LASTEXITCODE)" }
}

$osTokens = '10_X64,Server2016_X64,ServerRS5_X64,10_VB_X64,ServerFE_X64,10_NI_X64,10_GE_X64,10_CO_X64'
& $inf2cat "/driver:$pkg" "/os:$osTokens" /uselocaltime
if ($LASTEXITCODE) { throw 'inf2cat failed' }
& $signtool sign /fd SHA256 /sha1 $thumb /ph (Join-Path $pkg 'DBO_OVSE.cat')
if ($LASTEXITCODE) { throw "signtool sign DBO_OVSE.cat failed ($LASTEXITCODE)" }

# 4. Verify the catalog covers both binaries.
Write-Host "`n== Package ==" -ForegroundColor Green
Get-ChildItem $pkg | Select-Object Name, Length, LastWriteTime
& $signtool verify /pa /c (Join-Path $pkg 'DBO_OVSE.cat') (Join-Path $pkg 'DBO_OVSE.sys')
if ($LASTEXITCODE) { throw "catalog verify failed for DBO_OVSE.sys ($LASTEXITCODE)" }
& $signtool verify /pa /c (Join-Path $pkg 'DBO_OVSE.cat') (Join-Path $pkg 'DBO_OVSE60.sys')
if ($LASTEXITCODE) { throw "catalog verify failed for DBO_OVSE60.sys ($LASTEXITCODE)" }
Write-Host "`nDual-binary package: $pkg" -ForegroundColor Green
