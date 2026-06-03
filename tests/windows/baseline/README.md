# Windows test baseline — OVS 3.5.90 (`spike/windows-native-dpif`)

Regression reference for the Windows test framework, captured on the 3.5.90 tree.
These files are the "what was green on Windows" yardstick the de-weaving work and
the resync-to-3.7.90 acid test are measured against. See
`datapath-windows/WINDOWS-TEST-SETUP-PLAN.md` for the full strategy.

## Files

- **`ovstest-modules.txt`** — sorted list of every unit-test module registered in
  the CMake-built `ovstest.exe` (via `OVSTEST_REGISTER` → `OVS_CONSTRUCTOR`). This is
  the `/Zc:inline-` registration completeness reference: if a resync makes this list
  shrink, module self-registration broke (the `reconnect`/`ovstest --help` canary).
  `.CRT$XCU` order is not stable across MSVC builds, so the list is **sorted**.
  Regenerate: `ovstest.exe --help`, extract `test-*` names, `sort -u`.

- **`ctest-pass.txt`** — the surface-(I)/(II) MSYS-free CTest cases that pass green
  in `Release`: the self-checking `ovstest` exit-code modules, the `ovstest-help`
  registration canary, and the `test-dpif-windows` provider unit test (mock kernel).
  Regenerate: `ctest --test-dir <build> -C Release`.

## Not captured here (captured elsewhere / later)

- The autotools selective `make check` baseline for the build-smoke `.at` groups
  (ovsdb / ovs-vsctl / ovs-vswitchd / ofproto) — captured when the owned
  `windows-testsuite.at` lands (needs the MSYS build).
- The catlet smoke / forwarding baseline — under
  `datapath-windows/test-catlet/` (the 7/7 Pester result + `ovs-dpctl show`).
