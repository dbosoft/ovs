# Comprehensive Windows OVS validation, run INSIDE the ovs-kerneldev catlet.
# Covers management-plane (db-init, detach, logs, db interaction, schema upgrade)
# AND the kernel datapath (driver) via add-br datapath_type=windows + ovs-dpctl.
$ErrorActionPreference = 'Continue'
$native = 'C:\ovs-test\native'
$run    = 'C:\ovs-test\run'
$env:Path = "$native;$env:Path"
foreach ($v in 'OVS_RUNDIR','OVS_LOGDIR','OVS_DBDIR','OVS_SYSCONFDIR') { Set-Item "env:$v" $run }
New-Item -ItemType Directory -Force -Path $run | Out-Null
$vsctl='C:\ovs-test\native\ovs-vsctl.exe'; $tool='C:\ovs-test\native\ovsdb-tool.exe'
$appctl='C:\ovs-test\native\ovs-appctl.exe'; $dpctl='C:\ovs-test\native\ovs-dpctl.exe'
$schema="$native\vswitch.ovsschema"

function Step($t){ Write-Output ""; Write-Output "########## $t ##########" }

Get-Process ovs-vswitchd,ovsdb-server -EA SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 700
Remove-Item "$run\conf.db","$run\ovsdb-server.log","$run\ovs-vswitchd.log","$run\*.pid" -EA SilentlyContinue

Step "version"
& $vsctl --version | Select-Object -First 1

Step "DB-INIT: ovsdb-tool create + versions"
& $tool create "$run\conf.db" $schema;            Write-Output "create exit=$LASTEXITCODE"
Write-Output ("db-version:     " + (& $tool db-version "$run\conf.db"))
Write-Output ("schema-version: " + (& $tool schema-version $schema))

Step "UPGRADE: needs-conversion + convert (schema upgrade codepath)"
& $tool needs-conversion "$run\conf.db" $schema;  Write-Output "needs-conversion exit=$LASTEXITCODE"
& $tool convert "$run\conf.db" $schema;           Write-Output "convert(no-op) exit=$LASTEXITCODE"
# Real upgrade: if eryph ships an older schema, create with it then convert to ours.
$eschema = Get-ChildItem 'C:\ProgramData\eryph\ovs' -Recurse -Filter vswitch.ovsschema -EA SilentlyContinue | Select-Object -First 1
if ($eschema) {
    Write-Output ("eryph schema-version: " + (& $tool schema-version $eschema.FullName))
    Remove-Item "$run\old.db" -EA SilentlyContinue
    & $tool create "$run\old.db" $eschema.FullName; Write-Output "create(old) exit=$LASTEXITCODE"
    & $tool convert "$run\old.db" $schema;          Write-Output "UPGRADE old->ours exit=$LASTEXITCODE"
    Write-Output ("upgraded db-version: " + (& $tool db-version "$run\old.db"))
}

Step "DETACH: start ovsdb-server + ovs-vswitchd detached, with log files"
& "$native\ovsdb-server.exe" "$run\conf.db" -vconsole:off --remote=punix:db.sock --log-file="$run\ovsdb-server.log" --pidfile --detach
Write-Output "ovsdb-server --detach exit=$LASTEXITCODE"
Start-Sleep -Seconds 1
& $vsctl --no-wait init; Write-Output "vsctl init exit=$LASTEXITCODE"
& "$native\ovs-vswitchd.exe" -vconsole:off -vfile:info --log-file="$run\ovs-vswitchd.log" --pidfile --detach
Write-Output "ovs-vswitchd --detach exit=$LASTEXITCODE"
Start-Sleep -Seconds 2
Write-Output ("ovsdb-server.pid = " + (Get-Content "$run\ovsdb-server.pid" -EA SilentlyContinue))
Write-Output ("ovs-vswitchd.pid = " + (Get-Content "$run\ovs-vswitchd.pid" -EA SilentlyContinue))
Get-Process ovs-vswitchd,ovsdb-server -EA SilentlyContinue | Select-Object Name,Id | Format-Table -Auto | Out-String

Step "DB INTERACTION: add-br/add-port/set/get/list (datapath_type=windows -> driver)"
& $vsctl --timeout=25 add-br br-test -- set bridge br-test datapath_type=windows; Write-Output "add-br exit=$LASTEXITCODE"
Start-Sleep -Seconds 2
& $vsctl --timeout=25 add-port br-test p1 -- set interface p1 type=internal; Write-Output "add-port exit=$LASTEXITCODE"
& $vsctl --timeout=25 set bridge br-test other-config:probe=hello; Write-Output "set exit=$LASTEXITCODE"
Write-Output ("get datapath_type = " + (& $vsctl --timeout=25 get bridge br-test datapath_type))
Write-Output ("get other-config:probe = " + (& $vsctl --timeout=25 get bridge br-test other-config:probe))
Write-Output "list-br:"; & $vsctl --timeout=25 list-br
Write-Output "show:"; & $vsctl --timeout=25 show

Step "APPCTL: live daemon interaction"
& $appctl --timeout=10 -t ovs-vswitchd version 2>&1
& $appctl --timeout=10 -t ovs-vswitchd vlog/list 2>&1 | Select-Object -First 2

Step "DATAPATH (DRIVER): ovs-dpctl show + flow put/dump/del"
& $dpctl show windows@ovs-system 2>&1
& $dpctl add-flow windows@ovs-system "in_port(2),eth(),eth_type(0x0800),ipv4()" "1"; Write-Output "dp add-flow exit=$LASTEXITCODE"
Write-Output "dump-flows (expect 1):"; & $dpctl dump-flows windows@ovs-system 2>&1
& $dpctl del-flow windows@ovs-system "in_port(2),eth(),eth_type(0x0800),ipv4()"; Write-Output "dp del-flow exit=$LASTEXITCODE"
Write-Output "dump-flows (expect empty):"; & $dpctl dump-flows windows@ovs-system 2>&1

Step "LOGS: tails"
Write-Output "--- ovsdb-server.log ---"; Get-Content "$run\ovsdb-server.log" -Tail 6 -EA SilentlyContinue
Write-Output "--- ovs-vswitchd.log ---"; Get-Content "$run\ovs-vswitchd.log" -Tail 20 -EA SilentlyContinue

Step "CLEANUP"
& $vsctl --timeout=25 del-br br-test 2>&1; Write-Output "del-br exit=$LASTEXITCODE"
Get-Process ovs-vswitchd,ovsdb-server -EA SilentlyContinue | Stop-Process -Force
Write-Output "DONE"
