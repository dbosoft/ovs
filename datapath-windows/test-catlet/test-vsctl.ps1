# Does eryph's ovs-vsctl (3.3) work against OUR ovsdb-server (3.5)? Runs INSIDE catlet.
$ErrorActionPreference = 'Continue'
$native='C:\ovs-test\native'; $run='C:\ovs-test\run'; $erun='C:\ProgramData\eryph\ovs\run_1'
$env:Path="$native;$env:Path"
foreach($v in 'OVS_RUNDIR','OVS_LOGDIR','OVS_DBDIR','OVS_SYSCONFDIR'){Set-Item "env:$v" $run}
New-Item -ItemType Directory -Force -Path $run | Out-Null
Get-Process ovsdb-server,ovs-vswitchd -EA SilentlyContinue | Stop-Process -Force
Start-Sleep 1
Remove-Item "$run\conf.db" -EA SilentlyContinue
& "$erun\bin\ovsdb-tool.exe" create "$run\conf.db" "$native\vswitch.ovsschema"
Start-Process "$native\ovsdb-server.exe" -ArgumentList @("$run\conf.db","-vconsole:off","--remote=punix:db.sock","--log-file=$run\ovsdb.log","--pidfile") -WindowStyle Hidden -RedirectStandardOutput "$run\o.txt" -RedirectStandardError "$run\e.txt"
Start-Sleep 2
$ev = "$erun\bin\ovs-vsctl.exe"
Write-Output '=== eryph vsctl (3.3) show against our ovsdb (3.5) ==='
& $ev --timeout=10 show 2>&1; Write-Output "show exit=$LASTEXITCODE"
Write-Output '=== eryph vsctl add-br br-test datapath_type=system ==='
& $ev --timeout=10 add-br br-test -- set bridge br-test datapath_type=system 2>&1; Write-Output "add-br exit=$LASTEXITCODE"
& $ev --timeout=10 show 2>&1
