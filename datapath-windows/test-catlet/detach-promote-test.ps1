# SAFE detach/promotion test (run INSIDE ovs-kerneldev, NEW DBO_OVSE.sys loaded).
#
# Proves: when the DEFAULT datapath (gOvsSwitchContext) detaches while another
# datapath is live, the driver promotes the survivor (no BSOD) and the global
# upcall pid-hash survives, so forwarding + flow-miss upcalls keep working.
#
# Topology trick: enable ovs-test2's ext FIRST so it becomes the default (dp0),
# and host ub1/ub2 on eryph_overlay (dp1). Detaching ovs-test2 then exercises
# the promotion path while ub1/ub2 (on the survivor) remain pingable.
$ErrorActionPreference = 'Continue'
$native='C:\ovs-test\native'; $run='C:\ovs-test\run'
$env:Path = "$native;$env:Path"
foreach ($v in 'OVS_RUNDIR','OVS_LOGDIR','OVS_DBDIR','OVS_SYSCONFDIR') { Set-Item "env:$v" $run }
$vsctl="$native\ovs-vsctl.exe"; $dpctl="$native\ovs-dpctl.exe"; $tool="$native\ovsdb-tool.exe"
$ext='dbosoft Open vSwitch Extension'
$OVERLAY = (Get-VMSwitch -Name eryph_overlay).Id.ToString().ToUpper()

function DrvState { (Get-CimInstance Win32_SystemDriver -Filter "Name='DBO_OVSE'").State }
# A subscribe/listen failure makes ovs-vswitchd exit; without this assert a ping
# can still pass from the kernel flow cache and mask the crash (false green).
function AssertVswitchd($where) {
    if (Get-Process ovs-vswitchd -EA SilentlyContinue) { "vswitchd alive ($where): OK" }
    else { "*** FAIL: vswitchd NOT running ($where) ***" }
    $bad = Select-String -Path "$run\ovs-vswitchd.log" -EA SilentlyContinue `
        -Pattern 'could not subscribe packets','failed to listen on datapath'
    if ($bad) { "*** FAIL: subscribe/listen error in log ($where) ***"; $bad.Line | Select-Object -Last 2 }
}
function PingVMs($idx) {
    foreach ($vm in 'ub1','ub2') {
        $ll = (Get-VMNetworkAdapter -VMName $vm -EA SilentlyContinue).IPAddresses | Where-Object { $_ -match '^fe80' } | Select-Object -First 1
        if ($ll) { ping -6 -n 3 "$ll%$idx" | Out-Null; "$vm ($ll): exit=$LASTEXITCODE" }
    }
}

"=== 1. clean slate: stop daemons, disable both exts ==="
Get-Process ovs-vswitchd,ovsdb-server -EA SilentlyContinue | Stop-Process -Force
Disable-VMSwitchExtension -VMSwitchName ovs-test2 -Name $ext -EA Continue | Out-Null
Disable-VMSwitchExtension -VMSwitchName eryph_overlay -Name $ext -EA Continue | Out-Null
Start-Sleep 3
"driver = $(DrvState)"

"=== 2. enable ovs-test2 FIRST (-> default dp0) ==="
Enable-VMSwitchExtension -VMSwitchName ovs-test2 -Name $ext -EA Continue | Out-Null
Start-Sleep 3
"=== 3. enable eryph_overlay (-> dp1, hosts ub1/ub2) ==="
Enable-VMSwitchExtension -VMSwitchName eryph_overlay -Name $ext -EA Continue | Out-Null
Start-Sleep 3
"driver = $(DrvState)"
"--- datapaths (expect ovs-test2 GUID + eryph_overlay GUID) ---"
& $dpctl show 2>&1

"=== 4. bring up OVS, br-int on eryph_overlay (the survivor) ==="
Remove-Item "$run\conf.db","$run\*.log","$run\*.pid" -EA SilentlyContinue
& $tool create "$run\conf.db" "$native\vswitch.ovsschema" | Out-Null
& "$native\ovsdb-server.exe" "$run\conf.db" -vconsole:off --remote=punix:db.sock --log-file="$run\ovsdb-server.log" --pidfile --detach | Out-Null
Start-Sleep 1
& $vsctl --no-wait init
& "$native\ovs-vswitchd.exe" -vconsole:off -vfile:info --log-file="$run\ovs-vswitchd.log" --pidfile --detach | Out-Null
Start-Sleep 2
& $vsctl --timeout=25 add-br br-int -- set bridge br-int datapath_type=$OVERLAY
Start-Sleep 3
foreach ($p in 'ovs_ub1','ovs_ub2') {
    & $vsctl --timeout=25 add-port br-int $p; Start-Sleep 1
    if ((& $vsctl --timeout=10 get interface $p ofport) -match '-1') {
        & $vsctl --timeout=25 del-port br-int $p; Start-Sleep 1; & $vsctl --timeout=25 add-port br-int $p; Start-Sleep 1
    }
}
Enable-NetAdapter -Name br-int -EA Continue | Out-Null
Start-Sleep 3
$idx = (Get-NetAdapter -Name br-int -EA SilentlyContinue).ifIndex
"=== 5. BASELINE forwarding (default=ovs-test2 anchor, traffic on eryph_overlay dp1) ==="
AssertVswitchd 'baseline'
PingVMs $idx

"=== 6. DETACH THE DEFAULT: disable ovs-test2 ext (dp0) -> promotion ==="
Disable-VMSwitchExtension -VMSwitchName ovs-test2 -Name $ext -EA Continue | Out-Null
Start-Sleep 4
"driver = $(DrvState)   (MUST be Running -> no BSOD)"
"--- datapaths now (expect only eryph_overlay) ---"
& $dpctl show 2>&1

"=== 7. POST-PROMOTION: forwarding must continue + fresh upcall must work ==="
& $dpctl del-flows "${OVERLAY}@ovs-system" 2>&1 | Out-Null   # force flow misses -> upcalls
Start-Sleep 1
PingVMs $idx
"--- flows re-installed by upcalls (forwarding evidence) ---"
& $dpctl dump-flows "${OVERLAY}@ovs-system" 2>&1 | Select-Object -First 4

"=== 8. vswitchd RESTART after promotion (FRESH subscribe against promoted dp) ==="
# This is the regression case: the restarted vswitchd re-opens the dpif and
# re-subscribes for upcalls.  The default datapath is now the PROMOTED survivor
# (not slot 0), so a packet-subscribe carrying a hardcoded dp_ifindex=0 is
# rejected EINVAL and vswitchd exits ("could not subscribe packets").
Get-Process ovs-vswitchd -EA SilentlyContinue | Stop-Process -Force
Start-Sleep 2
Remove-Item "$run\ovs-vswitchd.log" -EA SilentlyContinue   # so the log scan only sees this run
& "$native\ovs-vswitchd.exe" -vconsole:off -vfile:info --log-file="$run\ovs-vswitchd.log" --pidfile --detach | Out-Null
Start-Sleep 4
AssertVswitchd 'after restart post-promotion'
& $dpctl del-flows "${OVERLAY}@ovs-system" 2>&1 | Out-Null   # force fresh upcall, not cache
Start-Sleep 1
PingVMs $idx
"--- flows must be re-installed by the restarted vswitchd's upcalls ---"
& $dpctl dump-flows "${OVERLAY}@ovs-system" 2>&1 | Select-Object -First 4

"=== cleanup: stop daemons, restore baseline (overlay ext on, test2 off) ==="
& $vsctl --timeout=20 del-br br-int 2>&1 | Out-Null
Get-Process ovs-vswitchd,ovsdb-server -EA SilentlyContinue | Stop-Process -Force
"driver = $(DrvState)"
"DETACH-TEST-DONE"
