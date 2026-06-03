# Verify the "system" datapath-type rename end to end.
$ErrorActionPreference = 'Continue'
$native='C:\ovs-test\native'; $run='C:\ovs-test\run'
$env:Path = "$native;$env:Path"
foreach ($v in 'OVS_RUNDIR','OVS_LOGDIR','OVS_DBDIR','OVS_SYSCONFDIR') { Set-Item "env:$v" $run }
$vsctl="$native\ovs-vsctl.exe"; $dpctl="$native\ovs-dpctl.exe"

& C:\ovs-test\ms-dp.ps1 down | Out-Null
Start-Sleep 2
& C:\ovs-test\ms-dp.ps1 up | Out-Null
Start-Sleep 2

"=== (1) dpctl show: expect system@ovs-system + <GUID>@ovs-system, NO windows@ ==="
& $dpctl show 2>&1

"=== (2) switch-1 forwarding ==="
& C:\ovs-test\ms-dp.ps1 ping

"=== (3) DEFAULT bridge bug fix: add-br with NO datapath_type ==="
& $vsctl --timeout=25 add-br br-default
Start-Sleep 3
"br-default datapath_type = '" + (& $vsctl --timeout=10 get bridge br-default datapath_type) + "'"
"br-default local ofport   = " + (& $vsctl --timeout=10 get interface br-default ofport 2>&1)
"unknown-datapath-type errors in log (expect NONE):"
Select-String -Path "$run\ovs-vswitchd.log" -Pattern 'unknown datapath type|could not create datapath br-default' -EA SilentlyContinue | ForEach-Object { $_.Line }
"=== dpctl show after default bridge ==="
& $dpctl show 2>&1

& $vsctl --timeout=10 del-br br-default 2>&1 | Out-Null
"VERIFY-DONE"
