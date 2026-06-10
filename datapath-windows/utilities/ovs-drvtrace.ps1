<#
.SYNOPSIS
  Capture the dbosoft OVS forwarding-extension (DBO_OVSE.sys) ETW log to a
  .etl and decode it to text -- the production/headless replacement for
  attaching a kernel debugger or running DebugView to read OvsLog() output.

.DESCRIPTION
  The driver routes every OvsLog() (OVS_LOG_ERROR/WARN/INFO/...) through an ETW
  TraceLogging provider:

      Name: Dbosoft.OVS.Ovsext
      GUID: {b2d1f6a4-9c3e-4f7a-a15b-6d8e2c4f7093}

  TraceLogging events are self-describing, so no PDB/TMF is needed to decode --
  this script uses only the in-box logman + tracerpt, so it runs on a stock
  test VM with no WDK installed.

  Each decoded event carries: Module (the OVS_DBG_* subsystem bitmask), Function,
  Line, and the formatted Message.

.PARAMETER Seconds
  One-shot mode: start the session, capture for N seconds, stop, decode.

.PARAMETER Start
  Start a capture session and return immediately (pair with -Stop).

.PARAMETER Stop
  Stop the running session and decode its .etl.

.PARAMETER Level
  Max ETW level to capture (2=Error 3=Warning 4=Info 5=Verbose). Default 5.

.EXAMPLE
  .\ovs-drvtrace.ps1 -Seconds 20                 # capture 20s around a repro
.EXAMPLE
  .\ovs-drvtrace.ps1 -Start; <run a test>; .\ovs-drvtrace.ps1 -Stop
#>
[CmdletBinding(DefaultParameterSetName = 'OneShot')]
param(
    [Parameter(ParameterSetName = 'OneShot')] [ValidateRange(1, [int]::MaxValue)] [int]$Seconds = 15,
    [Parameter(ParameterSetName = 'Start')]   [switch]$Start,
    [Parameter(ParameterSetName = 'Stop')]    [switch]$Stop,
    # The driver emits no events below Error (2), so 2..5 is the useful range.
    [ValidateRange(2, 5)] [int]$Level = 5,
    [string]$OutFile = 'C:\ovs-test\ovs-drvtrace.etl',
    [string]$TextFile = ''
)
$ErrorActionPreference = 'Stop'
$session  = 'OvsExt'
$provider = '{b2d1f6a4-9c3e-4f7a-a15b-6d8e2c4f7093}'
if (-not $TextFile) { $TextFile = [IO.Path]::ChangeExtension($OutFile, '.csv') }

function Start-Capture {
    $dir = Split-Path $OutFile
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
    # logman stop is best-effort: a stale session from a killed run must not block a new one.
    & logman stop $session -ets 2>$null | Out-Null
    # Driver events carry keyword 0 (the OVS_DBG_* module is a payload field, not
    # a keyword), so keyword-0 events bypass keyword filtering and the keywordsAny
    # mask is immaterial — pass all-ones. level per -Level; -ow overwrites the .etl.
    & logman start $session -p $provider 0xFFFFFFFFFFFFFFFF $Level -ets -o $OutFile -ow
    if ($LASTEXITCODE -ne 0) { throw "logman start failed ($LASTEXITCODE)" }
    Write-Host "[ovs-drvtrace] capturing -> $OutFile (level $Level)" -ForegroundColor Green
}

function Stop-Capture {
    & logman stop $session -ets
    if ($LASTEXITCODE -ne 0) { throw "logman stop failed ($LASTEXITCODE) -- session '$session' running?" }
    if (-not (Test-Path $OutFile)) { throw "no .etl at $OutFile" }
    & tracerpt $OutFile -o $TextFile -of CSV -y | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "tracerpt failed ($LASTEXITCODE) decoding $OutFile" }
    Write-Host "[ovs-drvtrace] decoded -> $TextFile" -ForegroundColor Green
    $n = [Math]::Max(0, (@(Get-Content $TextFile -EA SilentlyContinue)).Count - 1)
    Write-Host "[ovs-drvtrace] ~$n event row(s); open $TextFile or load $OutFile in WPA." -ForegroundColor DarkGray
}

switch ($PSCmdlet.ParameterSetName) {
    'Start'   { Start-Capture }
    'Stop'    { Stop-Capture }
    'OneShot' {
        Start-Capture
        Write-Host "[ovs-drvtrace] capturing for ${Seconds}s ..." -ForegroundColor DarkGray
        Start-Sleep -Seconds $Seconds
        Stop-Capture
    }
}
