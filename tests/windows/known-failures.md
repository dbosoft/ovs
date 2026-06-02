# Windows autotest suite — known failures

The Windows-reduced autotest suite (`tests/windows-testsuite.at`, run via
`tests/windows/run-windows-testsuite.ps1`) currently has **10 failing tests**.
They are **real bugs to fix**, not platform incompatibilities — the latter are
skipped instead, see `excluded-tests.txt` / `excluded-keywords.txt`.

The suite is **not yet wired into CI**, so these failures block nothing. This
file tracks them so they are not silently forgotten. Baseline: 947 -> 10 after
the CMake-overlay Windows port work.

| # | Test (file) | Root cause | Direction |
|---|---|---|---|
| 520 | SSL/TLS db: implementation (`ovsdb-server.at`) | `--private-key=db:...` etc. read the cert/key **path from a database column**; under MSYS that value is an `/f/...` MSYS path, which native OpenSSL cannot open (command-line paths work only because MSYS rewrites argv to `F:\...`, but db-stored values bypass that). | Test-environment path-format issue; needs the db seeded with a native path, or a path-normalization shim. |
| 521 | SSL/TLS db: implementation (TLSv1.3 only) | Same as 520. | Same as 520. |
| 721 | ovsdb-server record/replay (`ovsdb-server.at`) | Not yet diagnosed. | Investigate. |
| 769 | monitor-cond-since found but no new rows (`ovsdb-monitor.at`) | `kill` the detached `ovsdb-client` then wait for its pidfile to disappear; the Windows `--detach` pidfile-removal-on-exit races the harness check. | Ensure the pidfile is unlinked before exit on the Windows signal path. |
| 820 | IDL writing via IDL with unicode - C (`ovsdb-idl.at`) | MSYS passes UTF-8 argv, but the MSVC CRT decodes `main()` args as the ANSI code page (CP1252), corrupting multi-byte characters before they reach the JSON layer. | Add a UTF-8 `activeCodePage` application manifest to the OVS executables (Win10 1903+), or `wmain()` + UTF-16->UTF-8 conversion. |
| 821 | ...unicode - write-changed-only - C | Same as 820. | Same as 820. |
| 822 | ...unicode - C - tcp | Same as 820 (fails on all variants incl. plain C, so not transport-related). | Same as 820. |
| 823 | ...unicode - C - tcp6 | Same as 820. | Same as 820. |
| 1129 | ovsdb lock -- steal (`ovsdb-lock.at`) | After a steal+unlock, the detached `ovsdb-client` reports `{}` instead of the expected `locked` / lock-list notification — the detached client may not process the async lock-regained notification on Windows. | Verify a detached `ovsdb-client` stays in its event loop for async notifications. |
| 1167 | database commands -- conditions (`ovs-vsctl.at`) | `echo \`ovs-vsctl --bare find ... | sort\`` yields leading spaces vs. the expected joined list — likely empty/`\r`-terminated lines from the native binary confusing the shell pipeline. | Check whether ovs-vsctl emits `\r` / trailing blank lines on Windows. |

`652` (equality wait with missing row - relay - clustered) is **flaky** under
`-j4` but passes when run on its own; it is timing-sensitive, not a hard failure.

## How to reproduce one test

```powershell
.\tests\windows\run-windows-testsuite.ps1 -BuildDir <cmake-build> -Groups '1129'
# detailed log: tests/testsuite.dir/1129/testsuite.log
```

## Debugging native crashes (no PDBs in Release by default)

```powershell
$env:_CL_='/Zi'; $env:_LINK_='/DEBUG:FULL'
& <cmake> --build <build> --config Release --target ovstest --clean-first
# NOTE: --clean-first wipes the other exes; rebuild the full set afterward.
# Repro with DLLs on PATH (C:\PTHREADS-BUILT\bin;C:\OpenSSL-Win64\bin), then:
cdb -g -c "g; .lastevent; kn 30; q" ovstest.exe <args>   # pipe stdin in
```
