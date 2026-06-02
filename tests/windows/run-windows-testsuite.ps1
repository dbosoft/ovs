<#
.SYNOPSIS
  Run the owned, Windows-reduced autotest build-smoke suite (tests/windows-testsuite.at)
  against CMake/MSVC-built OVS binaries, under MSYS2 -- no full autotools build needed.

.DESCRIPTION
  Surface (III) of the Windows test framework (see datapath-windows/WINDOWS-TEST-SETUP-PLAN.md).
  This wraps the non-obvious incantation:
    1. autom4te-generate tests/windows-testsuite from the manifest (MSYS2).
    2. Patch tests/atconfig's abs_* paths to THIS checkout (the relocated-checkout trap:
       atconfig bakes the path the tree was ./configure'd at, which breaks $abs_top_srcdir
       lookups after a move).  A real ./configure would do this; we fix it surgically so
       no full autotools reconfigure is required.
    3. Run the generated POSIX-sh suite via MSYS2 bash with AUTOTEST_PATH pointed at the
       CMake Release dir + the pthreads/OpenSSL DLL dirs, -j1 (the -jN dispatcher patch is
       intentionally not applied).

  Prereqs: MSYS2 at C:\MSYS64 (autoconf/autom4te/perl/m4), a configured tree (config.status +
  tests/atconfig present from an earlier ./configure, even at a stale path), and a CMake
  Release build of ovsdb-server/ovs-vswitchd/ovs-vsctl/ovs-ofctl/ovsdb-tool/ovstest.

.EXAMPLE
  .\run-windows-testsuite.ps1 -BuildDir C:\path\to\cmake-build -Keywords ovsdb-tool
  .\run-windows-testsuite.ps1 -BuildDir C:\path\to\cmake-build -Groups '457 1093 1154'
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$BuildDir,       # CMake build root (contains Release\)
  [string]$Keywords = '',                          # -k filter, e.g. 'ovsdb-tool'
  [string]$Groups = '',                            # explicit group numbers, e.g. '457 1093'
  [string]$PthreadsBin = 'C:\PTHREADS-BUILT\bin',
  [string]$OpenSslDir = 'C:\OpenSSL-Win64',
  [string]$Msys2 = 'C:\MSYS64',
  [switch]$List                                    # just list matching groups
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path "$PSScriptRoot\..\..").Path
$rel  = Join-Path $BuildDir 'Release'
if (-not (Test-Path (Join-Path $rel 'ovsdb-tool.exe'))) {
  throw "No ovsdb-tool.exe under '$rel' -- build the CMake targets first."
}
$bash = Join-Path $Msys2 'usr\bin\bash.exe'
if (-not (Test-Path $bash)) { throw "MSYS2 bash not found at $bash" }

# Windows path -> MSYS path (C:\x\y -> /c/x/y).
function To-Msys([string]$p) {
  $p = (Resolve-Path $p).Path
  '/' + $p.Substring(0,1).ToLower() + ($p.Substring(2) -replace '\\','/')
}
$repoMsys = To-Msys $repo
$ap = @((To-Msys $rel), (To-Msys $PthreadsBin), (To-Msys $OpenSslDir)) -join ':'
$flags = if ($List) { '-l' } else { '-j1' }
$sel = ($Groups.Trim() + ' ' + $(if ($Keywords) { "-k $Keywords" } else { '' })).Trim()

$script = @"
set -e
cd '$repoMsys'
# 1. generate the suite from the manifest
/usr/bin/autom4te --language=autotest -I . -o tests/windows-testsuite tests/windows-testsuite.at
chmod +x tests/windows-testsuite
# 2. repoint atconfig abs_* vars at THIS checkout (relocated-checkout fix)
sed -i -E "s#^(abs_top_srcdir=).*#\1'$repoMsys'#;  \
           s#^(abs_top_builddir=).*#\1'$repoMsys'#; \
           s#^(abs_srcdir=).*#\1'$repoMsys/tests'#; \
           s#^(abs_builddir=).*#\1'$repoMsys/tests'#" tests/atconfig
# 3. run
sh tests/windows-testsuite -C tests AUTOTEST_PATH='$ap' $sel $flags
"@
& $bash -lc $script
exit $LASTEXITCODE
