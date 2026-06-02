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
  [int]$Jobs = 1,                                  # autotest parallelism (-jN)
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
# AUTOTEST_PATH: CMake Release bins first, then pthreads/OpenSSL DLLs, then the
# tests/ source dir so script helpers invoked bare (test-dpparse.py, ...) resolve
# (our absolute override otherwise drops the default relative "tests" entry).
$ap = @((To-Msys $rel), (To-Msys $PthreadsBin), (To-Msys $OpenSslDir),
        (To-Msys (Join-Path $repo 'tests'))) -join ':'
# Run a bash script BODY via a temp LF file: a multi-line body (sed continuations,
# regex parens) through `bash -lc` mangles the quoting.
function Invoke-MsysBash([string]$body) {
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("ovs-winsuite-" + [Guid]::NewGuid().ToString('N') + ".sh")
  [IO.File]::WriteAllText($tmp, ($body -replace "`r", ""), (New-Object Text.UTF8Encoding($false)))
  try   { & $bash -l (To-Msys $tmp) }
  finally { Remove-Item -Force $tmp -ErrorAction SilentlyContinue }
}

# 1. Generate the suite from the manifest + repoint atconfig abs_* at THIS checkout.
Invoke-MsysBash @"
set -e
cd '$repoMsys'
/usr/bin/autom4te --language=autotest -I . -o tests/windows-testsuite tests/windows-testsuite.at
chmod +x tests/windows-testsuite
sed -i -E "s#^(abs_top_srcdir=).*#\1'$repoMsys'#; s#^(abs_top_builddir=).*#\1'$repoMsys'#; s#^(abs_srcdir=).*#\1'$repoMsys/tests'#; s#^(abs_builddir=).*#\1'$repoMsys/tests'#" tests/atconfig
"@ | Out-Null

if ($List) {
  Invoke-MsysBash "cd '$repoMsys' && sh tests/windows-testsuite -C tests -l"
  exit $LASTEXITCODE
}

# 2. Compute the run set = ALL tests MINUS those whose feature/method is not testable
# on Windows: by autotest keyword (excluded-keywords.txt) or group-title substring
# (excluded-tests.txt).  Fixable failures are NOT skipped -- they run and must be fixed.
$exclKw = @(); $kf = Join-Path $PSScriptRoot 'excluded-keywords.txt'
if (Test-Path $kf) { $exclKw = Get-Content $kf | ForEach-Object { ($_ -replace '#.*','').Trim() } | Where-Object { $_ } }
$exclTitle = @(); $tf = Join-Path $PSScriptRoot 'excluded-tests.txt'
if (Test-Path $tf) { $exclTitle = Get-Content $tf | ForEach-Object { ($_ -replace '#.*','').Trim() } | Where-Object { $_ } }

$listing = Invoke-MsysBash "cd '$repoMsys' && sh tests/windows-testsuite -C tests -l"
$tests = @(); $cur = $null
foreach ($ln in $listing) {
  if ($ln -match '^\s*(\d+):\s+[A-Za-z0-9_.\-]+\.at:\d+\s+(.*?)\s*$') {
    if ($cur) { $tests += $cur }
    $cur = @{ num = $Matches[1]; title = $Matches[2]; kws = '' }
  } elseif ($cur) { $cur.kws = $ln.Trim() }
}
if ($cur) { $tests += $cur }

$run = New-Object System.Collections.Generic.List[string]; $skip = 0
foreach ($t in $tests) {
  $ex = $false
  foreach ($p in $exclTitle) { if ($t.title -like "*$p*") { $ex = $true; break } }
  if (-not $ex) { $kw = $t.kws -split '\s+'; foreach ($k in $exclKw) { if ($kw -contains $k) { $ex = $true; break } } }
  if ($ex) { $skip++ } else { $run.Add($t.num) }
}
Write-Host "windows-testsuite: running $($run.Count), skipping $skip (feature/method not testable on Windows)"

# 3. Run the complement (or an explicit -Groups override).
$sel = if ($Groups.Trim()) { $Groups.Trim() } else { ($run -join ' ') }
Invoke-MsysBash "cd '$repoMsys' && sh tests/windows-testsuite -C tests AUTOTEST_PATH='$ap' $sel -j$Jobs"
exit $LASTEXITCODE
