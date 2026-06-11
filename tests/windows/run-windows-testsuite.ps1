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
# AUTOTEST_PATH REPLACES PATH inside the suite, so also add python3's directory
# (some tests use '#!/usr/bin/env python3' helpers) -- otherwise it's dropped.
$apDirs = @((To-Msys $rel), (To-Msys $PthreadsBin), (To-Msys $OpenSslDir),
            (To-Msys (Join-Path $repo 'tests')))
$py3 = Get-Command python3 -ErrorAction SilentlyContinue
if ($py3) { $apDirs += (To-Msys (Split-Path $py3.Source)) }
$ap = $apDirs -join ':'
# Run a bash script BODY via a temp LF file: a multi-line body (sed continuations,
# regex parens) through `bash -lc` mangles the quoting.
function Invoke-MsysBash([string]$body) {
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("ovs-winsuite-" + [Guid]::NewGuid().ToString('N') + ".sh")
  [IO.File]::WriteAllText($tmp, ($body -replace "`r", ""), (New-Object Text.UTF8Encoding($false)))
  try   { & $bash -l (To-Msys $tmp) }
  finally { Remove-Item -Force $tmp -ErrorAction SilentlyContinue }
}

# 0. Synthesize the autotest harness files (atconfig/atlocal) if this is a
#    CMake-only tree with no ./configure output (e.g. CI). atconfig is a small
#    shell-var file; atlocal is atlocal.in with its @VAR@ set substituted for the
#    values the Windows reduced suite needs. When present (a configured dev tree)
#    they are left as-is and only repointed by the sed below. LF-only (bash sources them).
function Write-LF([string]$path, [string]$text) {
  [IO.File]::WriteAllText($path, ($text -replace "`r", ""), (New-Object Text.UTF8Encoding($false)))
}
$atconfig = Join-Path $repo 'tests\atconfig'
if (-not (Test-Path $atconfig)) {
  Write-LF $atconfig @"
at_testdir='tests'
abs_builddir='$repoMsys/tests'
at_srcdir='.'
abs_srcdir='$repoMsys/tests'
at_top_srcdir='..'
abs_top_srcdir='$repoMsys'
at_top_build_prefix='../'
abs_top_builddir='$repoMsys'
at_top_builddir=`$at_top_build_prefix
EXEEXT='.exe'
AUTOTEST_PATH='tests'
SHELL=`${CONFIG_SHELL-'/bin/sh'}
"@
}
$atlocal = Join-Path $repo 'tests\atlocal'
if (-not (Test-Path $atlocal)) {
  $py3cmd = Get-Command python3 -ErrorAction SilentlyContinue
  $py3msys = if ($py3cmd) { To-Msys $py3cmd.Source } else { 'python3' }
  $al = Get-Content (Join-Path $repo 'tests\atlocal.in') -Raw
  @{ '@HAVE_OPENSSL@'='yes'; '@PYTHON3@'=$py3msys; '@EGREP@'='grep -E'; '@CFLAGS@'='';
     '@DPDK_MBUF_HEADROOM@'='0'; '@HAVE_BACKTRACE@'='no'; '@HAVE_TCA_HTB_RATE64@'='no';
     '@HAVE_TCA_POLICE_PKTRATE64@'='no'; '@HAVE_UNBOUND@'='no'; '@HAVE_UNWIND@'='no'
   }.GetEnumerator() | ForEach-Object { $al = $al.Replace($_.Key, $_.Value) }
  Write-LF $atlocal $al
}

# 1. Generate the suite from the manifest + repoint atconfig abs_* at THIS checkout,
#    and generate the test-PKI certs the ssl/tls tests need (ovs-pki via OpenSSL; the
#    Windows chmod/ACL shim in ovs-pki.in is required for this to work).
$opensslBin = To-Msys (Join-Path $OpenSslDir 'bin')
Invoke-MsysBash @"
set -e
cd '$repoMsys'
# Generate to the conventional name 'testsuite' (NOT 'windows-testsuite'): the
# autotest per-group verbose log is named '<suite>.log', and the upstream
# check_logs helper (tests/ofproto-macros.at) only excludes 'testsuite.log'
# from its '*.log' scan.  A 'windows-testsuite.log' sitting in the group dir
# would be scanned and its captured WARN/ERR lines (e.g. an expected
# test-stream connect failure) reported as spurious failures.  Both names are
# gitignored; this just reuses the stale autotools-generated artifact slot.
/usr/bin/autom4te --language=autotest -I . -o tests/testsuite tests/windows-testsuite.at
chmod +x tests/testsuite
sed -i -E "s#^(abs_top_srcdir=).*#\1'$repoMsys'#; s#^(abs_top_builddir=).*#\1'$repoMsys'#; s#^(abs_srcdir=).*#\1'$repoMsys/tests'#; s#^(abs_builddir=).*#\1'$repoMsys/tests'#" tests/atconfig
if [ ! -e tests/testpki-cacert.pem ]; then
    export PATH='$opensslBin':"\$PATH"
    P="sh utilities/ovs-pki.in --dir=tests/pki --log=tests/ovs-pki.log"
    \$P init && \$P req+sign tests/pki/test && \$P req+sign tests/pki/test2
    cp tests/pki/switchca/cacert.pem tests/testpki-cacert.pem
    cp tests/pki/test-cert.pem       tests/testpki-cert.pem
    cp tests/pki/test-req.pem        tests/testpki-req.pem
    cp tests/pki/test-privkey.pem    tests/testpki-privkey.pem
    cp tests/pki/test2-cert.pem      tests/testpki-cert2.pem
    cp tests/pki/test2-req.pem       tests/testpki-req2.pem
    cp tests/pki/test2-privkey.pem   tests/testpki-privkey2.pem
fi
"@ | Out-Null

if ($List) {
  Invoke-MsysBash "cd '$repoMsys' && sh tests/testsuite -C tests -l"
  exit $LASTEXITCODE
}

# 2. Compute the run set = ALL tests MINUS those whose feature/method is not testable
# on Windows: by autotest keyword (excluded-keywords.txt) or group-title substring
# (excluded-tests.txt).  Fixable failures are NOT skipped -- they run and must be fixed.
$exclKw = @(); $kf = Join-Path $PSScriptRoot 'excluded-keywords.txt'
if (Test-Path $kf) { $exclKw = Get-Content $kf | ForEach-Object { ($_ -replace '#.*','').Trim() } | Where-Object { $_ } }
$exclTitle = @(); $tf = Join-Path $PSScriptRoot 'excluded-tests.txt'
if (Test-Path $tf) { $exclTitle = Get-Content $tf | ForEach-Object { ($_ -replace '#.*','').Trim() } | Where-Object { $_ } }

$listing = Invoke-MsysBash "cd '$repoMsys' && sh tests/testsuite -C tests -l"
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
Invoke-MsysBash "cd '$repoMsys' && sh tests/testsuite -C tests AUTOTEST_PATH='$ap' $sel -j$Jobs"
exit $LASTEXITCODE
