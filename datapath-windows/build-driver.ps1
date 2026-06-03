<#
.SYNOPSIS
  Dev build for the dbosoft OVS Hyper-V forwarding extension (DBO_OVSE.sys).

.DESCRIPTION
  Wraps the MSBuild invocation with the two settings the WDK 10.0.26100 build
  on this machine needs:
    -p:Version=...                a concrete DriverVer version, because the
                                  vcxproj's <Inf><TimeStamp>$(Version)</TimeStamp>
                                  is empty and stampinf.exe rejects an empty -v.
    -p:SkipPackageVerification    skips the DPVerifier/InfVerif step, whose x86
                                  InfVerif.dll is not present in this WDK install.
                                  (Verification is a packaging lint, not a build
                                  or signing requirement.)

  Produces a test-signed package under:
    ovsext\x64\<Config>\package\   and   x64\<Config>\package\

.EXAMPLE
  pwsh -File build-driver.ps1                 # Win10Debug (checked, asserts on)
  pwsh -File build-driver.ps1 -Config Win10Release
#>
[CmdletBinding()]
param(
    [ValidateSet('Win10Debug', 'Win10Release')]
    [string]$Config = 'Win10Debug',
    # Dev DriverVer must outrank the eryph-shipped 3.3.90 in the test VM so
    # pnputil/PnP prefers our build when superseding the installed extension.
    [string]$Version = '3.99.0.0',
    [switch]$Rebuild
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# Pin VS2022 (-version '[17.0,18.0)'): the VS18 toolset ships a broken
# Microsoft.DriverKit.Build.Tasks.18.0.dll in this WDK install, so its MSBuild
# cannot run the WDK targets.  VS2022's 17.0 DriverKit tasks work.
$msbuild = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
    -version '[17.0,18.0)' -requires Microsoft.Component.MSBuild `
    -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
if (-not $msbuild) { throw 'VS2022 MSBuild.exe not found via vswhere.' }
Write-Host "MSBuild: $msbuild" -ForegroundColor DarkGray

$target = if ($Rebuild) { 'Rebuild' } else { 'Build' }

$msbuildArgs = @(
    (Join-Path $here 'ovsext.sln')
    "-t:$target"
    "-p:Configuration=$Config"
    '-p:Platform=x64'
    "-p:Version=$Version"
    '-p:SkipPackageVerification=true'
    '-m'
    '-nologo'
)

& $msbuild @msbuildArgs

if ($LASTEXITCODE -ne 0) { throw "Build failed ($LASTEXITCODE)." }

$pkg = Join-Path $here "x64\$Config\package"
Write-Host "`nPackage: $pkg" -ForegroundColor Green
Get-ChildItem $pkg -ErrorAction SilentlyContinue | Select-Object Name, Length, LastWriteTime
