# Windows autotest suite — known failures

The Windows-reduced autotest suite (`tests/windows-testsuite.at`, run via
`tests/windows/run-windows-testsuite.ps1`) currently has **0 unexpected
failures**. It runs in CI (`.github/workflows/build-and-test-windows.yml`):
`ctest` first (the CMake unit-test net: `ovstest` exit-code cases + the
`dpif-windows` mock test), then the full reduced suite. Any unexpected failure
fails the job. Genuine platform/method incompatibilities are skipped via
`excluded-tests.txt` / `excluded-keywords.txt`. CI is a **driverless** runner
(no ovsext kernel driver), so it passes `-NoDatapath`, which additionally skips
the ovs-vswitchd/ofproto tests in `excluded-no-datapath.txt` (they log "could
not open ovsext device" and trip check_logs without the driver). Those tests
still run on a driver-equipped host via a plain `run-windows-testsuite.ps1`.

## Fixed (were failing, now pass)

- **820–823 — IDL unicode (`ovsdb-idl.at`).** A UTF-8 argv was decoded by the
  MSVC CRT as the ANSI code page (`°` → `0xB0`), so the insert failed UTF-8
  validation and cascaded to exit 1. Fixed by embedding a UTF-8 `activeCodePage`
  manifest in every executable (`cmake/windows-utf8.manifest`, via `ovs_setup`).
- **1167 — ovs-vsctl conditions (`ovs-vsctl.at`).** Native tools emitted CRLF on
  stdout; `echo \`ovs-vsctl … | sort\`` merged the `\r`-terminated tokens into
  one line with embedded `\r`s, past the suite's end-of-line CRLF normalization.
  Fixed by putting stdout/stderr in binary mode at startup
  (`ovs_set_program_name`) — output is LF-only, byte-identical to Unix.

## Excluded (excluded-tests.txt — platform/method, not OVS bugs)

- **520/521 — SSL/TLS db.** Cert/key paths are stored in an OVSDB column and read
  back via `--private-key=db:…`; under MSYS the stored value is an MSYS `/f/…`
  path that native OpenSSL cannot open (MSYS rewrites argv paths but not
  DB-stored values). A product install stores native paths.
- **769 — monitor-cond-since.** The monitor works; the failure is the post-`kill`
  (taskkill `/F`) wait for the client pidfile to vanish — force-terminate can't
  run the pidfile-removal handler, and there is no SIGTERM for a console-less
  detached process.
- **721 — record/replay.** Asserts byte-identical logs between the record and
  replay runs, but one logs a timing-dependent, localized `recv()` OS-error line
  ("connection reset"); byte-identical replay of that diagnostic isn't
  achievable on Windows.
- **1129 — ovsdb lock steal.** The original holder must print the regained lock
  after the stealer unlocks, but the regain round-trip races
  `OVSDB_SERVER_SHUTDOWN` over the higher-latency Windows named pipe; the
  unchanged upstream test has no synchronization point to wait on.

**Flaky (timing/state-sensitive, not product bugs):** a few tests occasionally
fail in the long `-j1` sweep but pass in isolation — `508` ("truncating database
log with bad transaction") and `652` ("equality wait ... relay - clustered").
The runner has a **flake guard**: it re-runs only the failed groups once, so a
flake passes on retry while a genuine failure (which fails twice) still fails
the job. These stay in coverage rather than being excluded.

## How to reproduce one test

```powershell
.\tests\windows\run-windows-testsuite.ps1 -BuildDir <cmake-build> -Groups '1167'
# detailed log: tests/testsuite.dir/<NNNN>/testsuite.log
```

## Debugging native crashes (no PDBs in Release by default)

```powershell
$env:_CL_='/Zi'; $env:_LINK_='/DEBUG:FULL'
& <cmake> --build <build> --config Release --target ovstest --clean-first
# NOTE: --clean-first wipes the other exes; rebuild the full set afterward.
# Repro with DLLs on PATH (C:\PTHREADS-BUILT\bin;C:\OpenSSL-Win64\bin), then:
cdb -g -c "g; .lastevent; kn 30; q" ovstest.exe <args>   # pipe stdin in
```
