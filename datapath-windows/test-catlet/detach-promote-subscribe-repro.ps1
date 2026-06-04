# Focused repro for the detach-promote packet-subscribe EINVAL bug, adapted to a
# VM that has only LANbond (+ OVS ext).  Proves the FIX: after the default (slot-0)
# datapath detaches and the survivor is promoted to a non-zero slot, a freshly
# opened ovs-vswitchd can still subscribe for upcalls (it stamps the resolved
# dp_ifindex, not a hardcoded 0).  No nested-VM forwarding needed -- the subscribe
# itself is the discriminator: the old binary exits with "could not subscribe
# packets (Invalid argument)" here; the fixed binary stays up.
$ErrorActionPreference = 'Continue'
$native='C:\ovs-test\native'; $run='C:\ovs-test\run'
$env:Path = "$native;$env:Path"
foreach ($v in 'OVS_RUNDIR','OVS_LOGDIR','OVS_DBDIR','OVS_SYSCONFDIR') { Set-Item "env:$v" $run }
$vsctl="$native\ovs-vsctl.exe"; $dpctl="$native\ovs-dpctl.exe"; $tool="$native\ovsdb-tool.exe"
$ext='dbosoft Open vSwitch Extension'
$ANCHOR='ovs-promote-a'   # temp internal switch, enabled FIRST -> dp0 (detached)
$SURV='LANbond'           # enabled SECOND -> dp1 (promoted survivor)

function DrvState { (Get-CimInstance Win32_SystemDriver -Filter "Name='DBO_OVSE'").State }
# Records a regression so the script exits non-zero (see the tail). Cleanup still
# runs, so the test VM is restored before we report failure.
$script:Failed = $false
function AssertVswitchd($where) {
    if (Get-Process ovs-vswitchd -EA SilentlyContinue) { "vswitchd alive ($where): OK" }
    else { "*** FAIL: vswitchd NOT running ($where) ***"; $script:Failed = $true }
    $bad = Select-String -Path "$run\ovs-vswitchd.log" -EA SilentlyContinue `
        -Pattern 'could not subscribe packets','failed to listen on datapath'
    if ($bad) {
        "*** FAIL: subscribe/listen error in log ($where) ***"; $bad.Line | Select-Object -Last 2
        $script:Failed = $true
    }
    else { "log clean ($where): no subscribe/listen error" }
}

"=== 0. binary under test ==="
& $native\ovs-vswitchd.exe --version 2>&1 | Select-Object -First 1
(Get-FileHash $native\ovs-vswitchd.exe -Algorithm SHA256).Hash

"=== 1. clean slate ==="
Get-Process ovs-vswitchd,ovsdb-server -EA SilentlyContinue | Stop-Process -Force
Disable-VMSwitchExtension -VMSwitchName $SURV -Name $ext -EA Continue | Out-Null
if (Get-VMSwitch -Name $ANCHOR -EA SilentlyContinue) {
    Disable-VMSwitchExtension -VMSwitchName $ANCHOR -Name $ext -EA Continue | Out-Null
} else {
    New-VMSwitch -Name $ANCHOR -SwitchType Internal | Out-Null
}
Start-Sleep 3
"driver = $(DrvState)"

"=== 2. enable ANCHOR ext FIRST (-> default dp0) ==="
Enable-VMSwitchExtension -VMSwitchName $ANCHOR -Name $ext -EA Continue | Out-Null
Start-Sleep 3
"=== 3. enable SURVIVOR ext SECOND (-> dp1) ==="
Enable-VMSwitchExtension -VMSwitchName $SURV -Name $ext -EA Continue | Out-Null
Start-Sleep 3
"driver = $(DrvState)"
$SURVID = (Get-VMSwitch -Name $SURV).Id.ToString().ToUpper()
"--- datapaths (expect two: $ANCHOR GUID + $SURV GUID=$SURVID) ---"
& $dpctl show 2>&1

"=== 4. bring up OVS, br-probe on the SURVIVOR (dp1) ==="
Remove-Item "$run\conf.db","$run\*.log","$run\*.pid" -EA SilentlyContinue
& $tool create "$run\conf.db" "$native\vswitch.ovsschema" | Out-Null
& "$native\ovsdb-server.exe" "$run\conf.db" -vconsole:off --remote=punix:db.sock --log-file="$run\ovsdb-server.log" --pidfile --detach | Out-Null
Start-Sleep 1
& $vsctl --no-wait init
& "$native\ovs-vswitchd.exe" -vconsole:off -vfile:info --log-file="$run\ovs-vswitchd.log" --pidfile --detach | Out-Null
Start-Sleep 2
& $vsctl --timeout=25 add-br br-probe -- set bridge br-probe datapath_type=$SURVID
Start-Sleep 2
"=== 5. BASELINE (both dps live): vswitchd must subscribe cleanly ==="
AssertVswitchd 'baseline'

"=== 6. DETACH THE DEFAULT: disable ANCHOR ext (dp0) -> promotion ==="
Disable-VMSwitchExtension -VMSwitchName $ANCHOR -Name $ext -EA Continue | Out-Null
Start-Sleep 4
"driver = $(DrvState)   (MUST be Running -> no BSOD)"
"--- datapaths now (expect only $SURV) ---"
& $dpctl show 2>&1

"=== 7. THE REGRESSION CASE: restart vswitchd, FRESH subscribe vs PROMOTED dp ==="
Get-Process ovs-vswitchd -EA SilentlyContinue | Stop-Process -Force
Start-Sleep 2
Remove-Item "$run\ovs-vswitchd.log" -EA SilentlyContinue   # log scan sees only this run
& "$native\ovs-vswitchd.exe" -vconsole:off -vfile:info --log-file="$run\ovs-vswitchd.log" --pidfile --detach | Out-Null
Start-Sleep 4
AssertVswitchd 'after restart post-promotion'
"--- bridge/datapath still usable (recv_set succeeded) ---"
& $vsctl --timeout=15 show 2>&1 | Select-Object -First 6
& $dpctl show 2>&1

"=== cleanup: stop daemons, drop temp switch, restore baseline (survivor ext on) ==="
& $vsctl --timeout=20 del-br br-probe 2>&1 | Out-Null
Get-Process ovs-vswitchd,ovsdb-server -EA SilentlyContinue | Stop-Process -Force
Remove-VMSwitch -Name $ANCHOR -Force -EA SilentlyContinue
"driver = $(DrvState)"
if ($script:Failed) { "REPRO-DONE (FAILED)"; exit 1 }
"REPRO-DONE (PASSED)"
