# Windows autotest suite — known failures

The Windows-reduced autotest suite (`tests/windows-testsuite.at`, run via
`tests/windows/run-windows-testsuite.ps1`) currently has **2 failing tests**,
down from 10. They are tracked here so they are not silently forgotten; the
suite is not yet wired into CI, so they block nothing. Real platform/method
incompatibilities are skipped instead (`excluded-tests.txt` /
`excluded-keywords.txt`), never listed here.

## Remaining failures (2)

| # | Test (file) | Root cause | Direction |
|---|---|---|---|
| 721 | ovsdb-server record/replay (`ovsdb-server.at`) | Replay log differs from the recorded log by one `stream_fd\|DBG\|recv:` line carrying a **localized** OS error string ("Eine vorhandene Verbindung wurde …" = WSAECONNRESET) that is observed in one run but not the other. Record/replay asserts byte-identical logs; a timing-dependent, locale-dependent recv-diagnostic line breaks that on Windows. | Make the recv error path deterministic in record/replay (don't log the localized per-recv OS string, or normalize it), or confirm record/replay is unsupported on Windows. |
| 1129 | ovsdb lock -- steal (`ovsdb-lock.at`) | The original (detached) lock holder `c1` should print `locked` + the lock list when it **regains** the lock after the stealer `c2` unlocks. On Windows it prints `{}` instead — the regain notification round-trip (c2 unlock → server grants c1 → server notifies c1 → c1 writes output) does not complete before `OVSDB_SERVER_SHUTDOWN`. Likely a Windows named-pipe latency race rather than a lost notification, but unconfirmed. | Determine race vs. lost-notification (instrument c1); if a race in the unchanged upstream test, it needs a synchronization point the test does not provide on Windows. |

## Fixed (were failing, now pass)

- **820–823 — IDL unicode (`ovsdb-idl.at`).** A UTF-8 argv was decoded by the
  MSVC CRT as the ANSI code page (`°` → `0xB0`), so the insert failed UTF-8
  validation and cascaded to exit 1. Fixed by embedding a UTF-8 `activeCodePage`
  application manifest in every executable (`cmake/windows-utf8.manifest`, wired
  through `ovs_setup`), so argv is delivered as UTF-8.
- **1167 — ovs-vsctl conditions (`ovs-vsctl.at`).** Native tools emitted CRLF on
  stdout (text mode); `echo \`ovs-vsctl … | sort\`` merged the `\r`-terminated
  tokens into one line with embedded `\r`s, past the suite's end-of-line CRLF
  normalization. Fixed by putting stdout/stderr in binary mode at startup
  (`ovs_set_program_name`), so output is LF-only and byte-identical to Unix.

## Excluded (moved to excluded-tests.txt — platform/method, not OVS bugs)

- **520/521 — SSL/TLS db.** The cert/key paths are stored in an OVSDB column and
  read back via `--private-key=db:…`; under MSYS the stored value is an MSYS
  path (`/f/…`) that native OpenSSL cannot open (MSYS rewrites argv paths but not
  DB-stored values). A product install stores native paths.
- **769 — monitor-cond-since found but no new rows.** The monitor works (prints
  `found`/`last_id`); the failure is the post-`kill` wait for the client pidfile
  to vanish. `kill` is `taskkill /F`, and a console-less detached process has no
  SIGTERM to run the pidfile-removal handler, so the pidfile lingers.

`652` (equality wait with missing row - relay - clustered) is **flaky** under
`-j4` but passes on its own; timing-sensitive, not a hard failure.

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
