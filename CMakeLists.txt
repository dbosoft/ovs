# dbosoft Windows build for Open vSwitch — CMake + MSVC, no MSYS/autotools/cccl.
#
# Clean OVERLAY build: touches no upstream autotools file, so resyncing onto an
# upstream that removed Windows support yields ZERO build-glue conflicts. It
# compiles upstream's portable sources plus the dbosoft Windows overlay
# (include/windows shims, lib/*-windows.c, the native dpif-windows provider).
#
# Every generated input is produced here at configure time with python3 only:
# config.h, openvswitch/version.h, the string.h/stdio.h MSVC shims, the OVSDB IDL,
# the ofp-*.inc and odp-netlink*.h extractors, and dirs.c.  No autotools, no shell.
# Generated files land in ${CMAKE_BINARY_DIR}/gen, searched ahead of the source tree.
cmake_minimum_required(VERSION 3.20)
project(ovs_windows C)

if(NOT MSVC)
  message(FATAL_ERROR "The dbosoft Windows CMake build targets MSVC (cl).")
endif()

set(OVS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(PTHREADS_ROOT "C:/PTHREADS-BUILT" CACHE PATH "pthreads4w install prefix")
set(OPENSSL_ROOT  "C:/OpenSSL-Win64"  CACHE PATH "OpenSSL install prefix")
set(CMAKE_C_STANDARD 11)
set(GEN "${CMAKE_BINARY_DIR}/gen")
file(MAKE_DIRECTORY "${GEN}" "${GEN}/lib" "${GEN}/include")

# config.h + openvswitch/version.h — generated from templates (no autotools).
set(OVS_VERSION "3.7.90")   # OVS main (Windows-removed base); re-added via revert overlay
configure_file("${OVS_ROOT}/cmake/config.h.in" "${GEN}/config.h" @ONLY)

set(PACKAGE_STRING  "openvswitch ${OVS_VERSION}")
set(PACKAGE_VERSION "${OVS_VERSION}")
set(VERSION_SUFFIX  "")
set(LT_CURRENT 0)
set(LT_REVISION 90)
set(LT_AGE 0)
file(MAKE_DIRECTORY "${GEN}/include/openvswitch")
configure_file("${OVS_ROOT}/include/openvswitch/version.h.in"
               "${GEN}/include/openvswitch/version.h" @ONLY)

# lib/string.h + lib/stdio.h — gnulib-style shims that intercept <string.h>/
# <stdio.h> to add MSVC compat (strcasecmp->_stricmp, strtok_r->strtok_s, ...).
# They #include the real ucrt header by absolute path (@NEXT_*@); derive the SDK
# ucrt include dir here. Generated into ${GEN}/lib (searched first), so they win.
set(_wk "C:/Program Files (x86)/Windows Kits/10/include")
set(_sdkver "${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}")
if(NOT _sdkver OR NOT IS_DIRECTORY "${_wk}/${_sdkver}/ucrt")
  file(GLOB _vers RELATIVE "${_wk}" "${_wk}/10.*")
  list(SORT _vers)
  list(REVERSE _vers)
  list(GET _vers 0 _sdkver)
endif()
if(NOT IS_DIRECTORY "${_wk}/${_sdkver}/ucrt")
  message(FATAL_ERROR "Windows SDK ucrt include dir not found under ${_wk}")
endif()
set(INCLUDE_NEXT "include")
set(NEXT_STRING_H "\"${_wk}/${_sdkver}/ucrt/string.h\"")
set(NEXT_STDIO_H  "\"${_wk}/${_sdkver}/ucrt/stdio.h\"")
configure_file("${OVS_ROOT}/lib/string.h.in" "${GEN}/lib/string.h" @ONLY)
configure_file("${OVS_ROOT}/lib/stdio.h.in"  "${GEN}/lib/stdio.h"  @ONLY)

# --- CMake-native codegen: pure python3, no shell ---------------------------
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(ENV{PYTHONPATH} "${OVS_ROOT}/python")   # ovsdb-idlc imports ovs.* from here

# Run an OVS python generator at configure time, capturing stdout to 'out'.
# (Configure-time is fine for these rarely-changing generated sources; can be
# converted to build-time custom commands later for incremental rebuilds.)
function(ovs_gen out)
  execute_process(
    COMMAND "${Python3_EXECUTABLE}" ${ARGN}
    OUTPUT_FILE "${out}"
    WORKING_DIRECTORY "${OVS_ROOT}"
    RESULT_VARIABLE _rc)
  if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "codegen failed (rc=${_rc}) for ${out}\n  ${Python3_EXECUTABLE} ${ARGN}")
  endif()
endfunction()

# python/ovs/dirs.py — prerequisite for ovsdb-idlc (it imports ovs.dirs)
file(READ "${OVS_ROOT}/python/ovs/dirs.py.template" _dpy)
string(REPLACE "@pkgdatadir@" "C:/openvswitch/usr/share/openvswitch"        _dpy "${_dpy}")
string(REPLACE "@RUNDIR@"     "C:/ProgramData/openvswitch/var/run/openvswitch" _dpy "${_dpy}")
string(REPLACE "@LOGDIR@"     "C:/ProgramData/openvswitch/var/log/openvswitch" _dpy "${_dpy}")
string(REPLACE "@bindir@"     "C:/openvswitch/usr/bin"                       _dpy "${_dpy}")
string(REPLACE "@sysconfdir@" "C:/ProgramData/openvswitch/etc"              _dpy "${_dpy}")
string(REPLACE "@DBDIR@"      "C:/ProgramData/openvswitch/etc/openvswitch"  _dpy "${_dpy}")
file(WRITE "${OVS_ROOT}/python/ovs/dirs.py" "${_dpy}")

set(BA "${OVS_ROOT}/build-aux")
set(INCO "${OVS_ROOT}/include/openvswitch")
# OpenFlow field/action/error/msg extractors (all pure python3)
ovs_gen("${GEN}/lib/meta-flow.inc"    "${BA}/extract-ofp-fields"  meta-flow "${INCO}/meta-flow.h")
ovs_gen("${GEN}/lib/nx-match.inc"     "${BA}/extract-ofp-fields"  nx-match  "${INCO}/meta-flow.h")
ovs_gen("${GEN}/lib/ofp-actions.inc1" "${BA}/extract-ofp-actions" prototypes  "${OVS_ROOT}/lib/ofp-actions.c")
ovs_gen("${GEN}/lib/ofp-actions.inc2" "${BA}/extract-ofp-actions" definitions "${OVS_ROOT}/lib/ofp-actions.c")
ovs_gen("${GEN}/lib/ofp-errors.inc"   "${BA}/extract-ofp-errors"  "${INCO}/ofp-errors.h" "${OVS_ROOT}/include/openflow/openflow-common.h")
ovs_gen("${GEN}/lib/ofp-msgs.inc"     "${BA}/extract-ofp-msgs"    "${INCO}/ofp-msgs.h" lib/ofp-msgs.inc)

# OVSDB IDL: annotate schema -> .ovsidl, then emit C source + header.
set(IDLC "${OVS_ROOT}/ovsdb/ovsdb-idlc.in")
ovs_gen("${GEN}/lib/vswitch-idl.ovsidl" "${IDLC}" annotate "${OVS_ROOT}/vswitchd/vswitch.ovsschema" "${OVS_ROOT}/lib/vswitch-idl.ann")
ovs_gen("${GEN}/lib/vswitch-idl.c" "${IDLC}" c-idl-source "${GEN}/lib/vswitch-idl.ovsidl")
ovs_gen("${GEN}/lib/vswitch-idl.h" "${IDLC}" c-idl-header "${GEN}/lib/vswitch-idl.ovsidl")
ovs_gen("${GEN}/lib/ovsdb-server-idl.ovsidl" "${IDLC}" annotate "${OVS_ROOT}/ovsdb/_server.ovsschema" "${OVS_ROOT}/lib/ovsdb-server-idl.ann")
ovs_gen("${GEN}/lib/ovsdb-server-idl.c" "${IDLC}" c-idl-source "${GEN}/lib/ovsdb-server-idl.ovsidl")
ovs_gen("${GEN}/lib/ovsdb-server-idl.h" "${IDLC}" c-idl-header "${GEN}/lib/ovsdb-server-idl.ovsidl")

# idltest IDL — drives the test-ovsdb / ovsdb-idl test program (tests/ovsdb-idl.at).
file(MAKE_DIRECTORY "${GEN}/tests")
ovs_gen("${GEN}/tests/idltest.ovsidl" "${IDLC}" annotate "${OVS_ROOT}/tests/idltest.ovsschema" "${OVS_ROOT}/tests/idltest.ann")
ovs_gen("${GEN}/tests/idltest.c" "${IDLC}" c-idl-source "${GEN}/tests/idltest.ovsidl")
ovs_gen("${GEN}/tests/idltest.h" "${IDLC}" c-idl-header "${GEN}/tests/idltest.ovsidl")

# odp-netlink headers — via the python3 ports of the sed/awk generators
ovs_gen("${GEN}/include/odp-netlink.h"        "${BA}/extract-odp-netlink-h.py"        "${OVS_ROOT}/include/linux/openvswitch.h")
ovs_gen("${GEN}/include/odp-netlink-macros.h" "${BA}/extract-odp-netlink-macros-h.py" "${GEN}/include/odp-netlink.h")

# daemon/lib codegen (pure python3)
file(MAKE_DIRECTORY "${GEN}/ofproto" "${GEN}/ovsdb")
ovs_gen("${GEN}/ofproto/ipfix-entities.def" "${OVS_ROOT}/ofproto/ipfix-gen-entities" "${OVS_ROOT}/ofproto/ipfix.xml")
execute_process(                                   # text2c reads the schema on stdin
  COMMAND "${Python3_EXECUTABLE}" "${BA}/text2c"
  INPUT_FILE "${OVS_ROOT}/ovsdb/_server.ovsschema"
  OUTPUT_FILE "${GEN}/ovsdb/_server.ovsschema.inc"
  WORKING_DIRECTORY "${OVS_ROOT}" RESULT_VARIABLE _rc)
if(NOT _rc EQUAL 0)
  message(FATAL_ERROR "text2c failed (rc=${_rc}) for _server.ovsschema.inc")
endif()

# --- lib/dirs.c — install/runtime paths, generated from lib/dirs.c.in -------
set(srcdir      ".")
set(LOGDIR      "\"C:/ProgramData/openvswitch/var/log/openvswitch\"")
set(RUNDIR      "\"C:/ProgramData/openvswitch/var/run/openvswitch\"")
set(DBDIR       "\"C:/ProgramData/openvswitch/etc/openvswitch\"")
set(bindir      "\"C:/openvswitch/usr/bin\"")
set(sysconfdir  "\"C:/ProgramData/openvswitch/etc\"")
set(pkgdatadir  "\"C:/openvswitch/usr/share/openvswitch\"")
configure_file("${OVS_ROOT}/lib/dirs.c.in" "${GEN}/dirs.c" @ONLY)

# --- generated sources (CMake-produced into ${GEN}) -------------------------
set(OVS_GENERATED_SOURCES
  "${GEN}/dirs.c"
  "${GEN}/lib/vswitch-idl.c"
  "${GEN}/lib/ovsdb-server-idl.c")

# --- libopenvswitch portable sources (Windows set) --------------------------
set(OVS_LIB_SOURCES
  lib/aes128.c lib/async-append-null.c lib/backtrace.c lib/bfd.c lib/bundle.c
  lib/byteq.c lib/cfm.c lib/classifier.c lib/ccmap.c lib/cmap.c lib/colors.c
  lib/command-line.c lib/connectivity.c lib/conntrack-icmp.c lib/conntrack-tcp.c
  lib/conntrack-tp.c lib/conntrack-other.c lib/conntrack.c
  lib/cooperative-multitasking.c lib/coverage.c lib/crc32c.c lib/csum.c
  lib/ct-dpif.c lib/daemon.c lib/db-ctl-base.c lib/dummy.c lib/dpctl.c
  lib/dp-packet.c lib/dp-packet-gso.c lib/dpdk-stub.c
  lib/dpif-netdev.c lib/dpif-netdev-dfc.c lib/dpif-netdev-dpcls.c
  lib/dpif-netdev-perf.c lib/dpif.c lib/dpif-offload.c lib/dpif-offload-dummy.c
  lib/dynamic-string.c lib/entropy.c lib/fat-rwlock.c lib/fatal-signal.c lib/flow.c
  lib/guarded-list.c lib/hash.c lib/heap.c lib/hindex.c lib/hmap.c lib/hmapx.c
  lib/id-fpool.c lib/rconn.c
  lib/id-pool.c lib/if-notifier-manual.c lib/ipf.c lib/jhash.c lib/json.c
  lib/jsonrpc.c lib/lacp.c lib/learn.c lib/learning-switch.c lib/lockfile.c
  lib/mac-learning.c lib/match.c lib/mcast-snooping.c lib/memory.c lib/meta-flow.c
  lib/mpsc-queue.c lib/multipath.c lib/namemap.c lib/netdev-dummy.c
  lib/netdev-vport.c lib/netdev.c lib/netlink.c lib/nx-match.c
  lib/object-collection.c lib/odp-execute.c lib/odp-util.c
  lib/ofp-actions.c lib/ofp-bundle.c lib/ofp-connection.c lib/ofp-ct.c
  lib/ofp-ed-props.c lib/ofp-errors.c lib/ofp-flow.c lib/ofp-group.c lib/ofp-ipfix.c
  lib/ofp-match.c lib/ofp-meter.c lib/ofp-monitor.c lib/ofp-msgs.c lib/ofp-packet.c
  lib/ofp-parse.c lib/ofp-port.c lib/ofp-print.c lib/ofp-prop.c lib/ofp-protocol.c
  lib/ofp-queue.c lib/ofp-switch.c lib/ofp-table.c lib/ofp-util.c
  lib/ofp-version-opt.c lib/ofpbuf.c lib/ovs-atomic-locked.c lib/ovs-lldp.c
  lib/ovs-numa.c lib/ovs-rcu.c lib/ovs-replay.c lib/ovs-router.c lib/ovs-thread.c
  lib/ovsdb-cs.c lib/ovsdb-data.c lib/ovsdb-error.c lib/ovsdb-idl.c
  lib/ovsdb-map-op.c lib/ovsdb-set-op.c lib/ovsdb-condition.c lib/ovsdb-parser.c
  lib/ovsdb-session.c lib/ovsdb-types.c lib/ox-stat.c lib/packets.c lib/pcap-file.c
  lib/perf-counter.c lib/stopwatch.c lib/poll-loop.c lib/process.c lib/pvector.c
  lib/random.c lib/reconnect.c lib/rstp.c lib/rstp-state-machines.c lib/seq.c
  lib/sha1.c lib/shash.c lib/simap.c lib/skiplist.c lib/smap.c lib/socket-util.c
  lib/sort.c lib/sset.c lib/stp.c lib/stream-fd.c lib/stream-replay.c
  lib/stream-tcp.c lib/stream.c lib/stdio.c lib/string.c lib/svec.c
  lib/syslog-direct.c lib/syslog-libc.c lib/syslog-null.c lib/table.c lib/timer.c
  lib/timeval.c lib/tnl-neigh-cache.c lib/tnl-ports.c lib/netdev-native-tnl.c
  lib/token-bucket.c lib/tun-metadata.c lib/unicode.c lib/unixctl.c
  lib/userspace-tso.c lib/util.c lib/uuid.c lib/uuidset.c lib/vconn-stream.c
  lib/vconn.c lib/vlan-bitmap.c lib/vlog.c
  # lldp
  lib/lldp/lldp.c lib/lldp/lldpd.c lib/lldp/lldpd-structs.c
  # OpenSSL (HAVE_OPENSSL)
  lib/stream-ssl.c lib/dhparams.c
  # DNS (no unbound)
  lib/dns-resolve-stub.c
  # --- Windows overlay (the WIN32 automake block) ---
  lib/daemon-windows.c lib/getopt_long.c lib/getrusage-windows.c
  lib/latch-windows.c lib/route-table-stub.c lib/if-notifier-stub.c
  lib/stream-windows.c lib/strsep.c
  lib/netdev-windows.c lib/wmi.c
  # --- dbosoft native dpif provider ---
  # The Windows datapath is the native dpif-windows provider talking to the ovsext
  # driver via ovsext-channel, so the netlink datapath transport is not built on
  # Windows: dpif-netlink.c, netlink-socket.c, netlink-conntrack.c and
  # netlink-notifier.c are omitted.  netlink.c (the message codec) IS built -- the
  # ovsext ABI is netlink-message-framed and message bodies use nl_msg_*.
  lib/dpif-windows.c lib/ovsext-channel.c)

add_library(openvswitch STATIC ${OVS_LIB_SOURCES} ${OVS_GENERATED_SOURCES})

# Shared include dirs + defs for every OVS target. Generated dirs (${GEN}*) come
# first so CMake-produced files win over any in-tree autotools leftovers.
set(OVS_INCLUDES
  "${GEN}/lib" "${GEN}/include" "${GEN}" "${GEN}/ofproto" "${GEN}/ovsdb"
  "${OVS_ROOT}" "${OVS_ROOT}/include" "${OVS_ROOT}/include/windows"
  "${OVS_ROOT}/lib" "${OVS_ROOT}/ofproto" "${OVS_ROOT}/ovsdb"
  "${OVS_ROOT}/datapath-windows/include"
  "${PTHREADS_ROOT}/include" "${OPENSSL_ROOT}/include")
set(OVS_DEFS HAVE_CONFIG_H _CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_WARNINGS
             _WINSOCK_DEPRECATED_NO_WARNINGS)
function(ovs_setup t)
  target_include_directories(${t} PRIVATE ${OVS_INCLUDES})
  target_compile_definitions(${t} PRIVATE ${OVS_DEFS})
  target_compile_options(${t} PRIVATE /W1)
  # /Zc:inline- keeps unreferenced .CRT$XCU constructors (the OVS_CONSTRUCTOR that
  # VLOG_DEFINE_THIS_MODULE plants); the VS-generator Release default /Zc:inline
  # strips them at compile time -> vlog module self-registration dies and ovs-vsctl
  # aborts ('no destination, level, or module "reconnect"').
  target_compile_options(${t} PRIVATE /Zc:inline-)
endfunction()
ovs_setup(openvswitch)

# ---- convenience libs ------------------------------------------------------
add_library(sflow STATIC
  lib/sflow_agent.c lib/sflow_sampler.c lib/sflow_poller.c lib/sflow_receiver.c)
ovs_setup(sflow)
target_compile_definitions(sflow PRIVATE _BSD_SOURCE _DEFAULT_SOURCE)

add_library(ofproto STATIC
  ofproto/bond.c ofproto/collectors.c ofproto/connmgr.c ofproto/fail-open.c
  ofproto/in-band.c ofproto/names.c ofproto/netflow.c ofproto/ofproto.c
  ofproto/ofproto-dpif.c ofproto/ofproto-dpif-ipfix.c ofproto/ofproto-dpif-lsample.c
  ofproto/ofproto-dpif-mirror.c ofproto/ofproto-dpif-monitor.c
  ofproto/ofproto-dpif-rid.c ofproto/ofproto-dpif-sflow.c
  ofproto/ofproto-dpif-trace.c ofproto/ofproto-dpif-upcall.c
  ofproto/ofproto-dpif-xlate.c ofproto/ofproto-dpif-xlate-cache.c
  ofproto/pinsched.c ofproto/tunnel.c ofproto/bundles.c)
ovs_setup(ofproto)

add_library(ovsdb STATIC
  ovsdb/column.c ovsdb/condition.c ovsdb/execution.c ovsdb/file.c
  ovsdb/jsonrpc-server.c ovsdb/log.c ovsdb/mutation.c ovsdb/ovsdb.c
  ovsdb/monitor.c ovsdb/query.c ovsdb/raft.c ovsdb/raft-private.c
  ovsdb/raft-rpc.c ovsdb/rbac.c ovsdb/replication.c ovsdb/relay.c ovsdb/row.c
  ovsdb/server.c ovsdb/storage.c ovsdb/table.c ovsdb/trigger.c
  ovsdb/transaction.c ovsdb/transaction-forward.c ovsdb/ovsdb-util.c)
ovs_setup(ovsdb)

# ---- executables -----------------------------------------------------------
set(OVS_SYS_LIBS ws2_32 Shlwapi iphlpapi wbemuuid ole32 oleaut32)
set(OVS_EXT_LIBDIRS "${OPENSSL_ROOT}/lib" "${OPENSSL_ROOT}/lib/VC/x64/MT" "${PTHREADS_ROOT}/lib")

add_executable(ovs-vswitchd vswitchd/bridge.c vswitchd/ovs-vswitchd.c vswitchd/system-stats.c)
ovs_setup(ovs-vswitchd)
target_link_directories(ovs-vswitchd PRIVATE ${OVS_EXT_LIBDIRS})
target_link_libraries(ovs-vswitchd PRIVATE ofproto sflow openvswitch libssl libcrypto pthreadVC3 ${OVS_SYS_LIBS})

add_executable(ovsdb-server ovsdb/ovsdb-server.c)
ovs_setup(ovsdb-server)
target_link_directories(ovsdb-server PRIVATE ${OVS_EXT_LIBDIRS})
target_link_libraries(ovsdb-server PRIVATE ovsdb openvswitch libssl libcrypto pthreadVC3 ${OVS_SYS_LIBS})

add_executable(ovs-vsctl utilities/ovs-vsctl.c)
ovs_setup(ovs-vsctl)
target_link_directories(ovs-vsctl PRIVATE ${OVS_EXT_LIBDIRS})
target_link_libraries(ovs-vsctl PRIVATE openvswitch libssl libcrypto pthreadVC3 ${OVS_SYS_LIBS})

# ovs-dpctl drives the dpif layer directly -- the test tool for dpif-windows
# ("ovs-dpctl show windows@<dp>" routes straight to dpif_windows_class).
add_executable(ovs-dpctl utilities/ovs-dpctl.c)
ovs_setup(ovs-dpctl)
target_link_directories(ovs-dpctl PRIVATE ${OVS_EXT_LIBDIRS})
target_link_libraries(ovs-dpctl PRIVATE openvswitch libssl libcrypto pthreadVC3 ${OVS_SYS_LIBS})

# Remaining production utilities (single-source over the libs we already build),
# so the CMake overlay is a self-sufficient OVS userspace.
add_executable(ovsdb-tool ovsdb/ovsdb-tool.c)
ovs_setup(ovsdb-tool)
target_link_directories(ovsdb-tool PRIVATE ${OVS_EXT_LIBDIRS})
target_link_libraries(ovsdb-tool PRIVATE ovsdb openvswitch libssl libcrypto pthreadVC3 ${OVS_SYS_LIBS})

add_executable(ovsdb-client ovsdb/ovsdb-client.c)
ovs_setup(ovsdb-client)
target_link_directories(ovsdb-client PRIVATE ${OVS_EXT_LIBDIRS})
target_link_libraries(ovsdb-client PRIVATE ovsdb openvswitch libssl libcrypto pthreadVC3 ${OVS_SYS_LIBS})

add_executable(ovs-appctl utilities/ovs-appctl.c)
ovs_setup(ovs-appctl)
target_link_directories(ovs-appctl PRIVATE ${OVS_EXT_LIBDIRS})
target_link_libraries(ovs-appctl PRIVATE openvswitch libssl libcrypto pthreadVC3 ${OVS_SYS_LIBS})

add_executable(ovs-ofctl utilities/ovs-ofctl.c)
ovs_setup(ovs-ofctl)
target_link_directories(ovs-ofctl PRIVATE ${OVS_EXT_LIBDIRS})
target_link_libraries(ovs-ofctl PRIVATE ofproto openvswitch libssl libcrypto pthreadVC3 ${OVS_SYS_LIBS})

# ---- tests (MSYS-free unit-test net) ---------------------------------------
# test-dpif-windows drives the native provider against an in-process mock kernel
# (no driver, no VM); build with -DOVS_ASAN=ON to catch marshalling overruns.
add_executable(test-dpif-windows tests/test-dpif-windows.c)
ovs_setup(test-dpif-windows)
target_link_directories(test-dpif-windows PRIVATE ${OVS_EXT_LIBDIRS})
target_link_libraries(test-dpif-windows PRIVATE openvswitch libssl libcrypto pthreadVC3 ${OVS_SYS_LIBS})

# ovstest — multi-call harness over libopenvswitch; validates the shared "brain"
# (hash/classifier/cmap/odp/flows/json/ovsdb codecs/...).  Source list mirrors the
# unconditional tests_ovstest_SOURCES, minus the !WIN32 file (test-unix-socket.c)
# and the LINUX-only files (test-lib-route-table.c, test-netlink-conntrack.c,
# test-psample.c).  test-netlink-policy.c was LINUX-only in automake but is portable
# (netlink message codec) and is built here.  /Zc:inline- (via ovs_setup) is mandatory
# so the OVSTEST_REGISTER .CRT$XCU constructor survives.
set(OVSTEST_SOURCES
  tests/ovstest.c
  tests/test-aes128.c tests/test-atomic.c tests/test-barrier.c
  tests/test-bundle.c tests/test-byte-order.c tests/test-byteq.c
  tests/test-classifier.c tests/test-ccmap.c tests/test-cmap.c
  tests/test-conntrack.c tests/test-cooperative-multitasking.c tests/test-csum.c
  tests/test-flows.c tests/test-hash.c tests/test-heap.c tests/test-hindex.c
  tests/test-hmap.c tests/test-id-fpool.c tests/test-json.c tests/test-jsonrpc.c
  tests/test-list.c tests/test-lockfile.c tests/test-multipath.c
  tests/test-mpsc-queue.c tests/test-netflow.c tests/test-netlink-policy.c
  tests/test-odp.c tests/test-ofpbuf.c
  tests/test-packets.c tests/test-random.c tests/test-rcu.c tests/test-rculist.c
  tests/test-reconnect.c tests/test-rstp.c tests/test-sflow.c tests/test-sha1.c
  tests/test-skiplist.c tests/test-stp.c tests/test-unixctl.c tests/test-util.c
  tests/test-uuid.c tests/test-uuidset.c tests/test-bitmap.c tests/test-vconn.c
  tests/test-aa.c tests/test-stopwatch.c)
add_executable(ovstest ${OVSTEST_SOURCES})
ovs_setup(ovstest)
target_link_directories(ovstest PRIVATE ${OVS_EXT_LIBDIRS})
target_link_libraries(ovstest PRIVATE openvswitch libssl libcrypto pthreadVC3 ${OVS_SYS_LIBS})

# Configure-time drift guard: FATAL if a tests/test-*.c that registers an ovstest
# module is missing from OVSTEST_SOURCES (catches upstream-added modules).
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/check-ovstest-list.cmake)

# ---- CTest: self-checking modules (pass/fail by exit code) -----------------
enable_testing()
set(_ovstest_dll_path
  "PATH=path_list_prepend:${PTHREADS_ROOT}/bin;PATH=path_list_prepend:${OPENSSL_ROOT}")
set(OVSTEST_EXIT_CASES
  "test-hash"          "test-hmap"           "test-hindex"
  "test-uuid"          "test-uuidset"        "test-skiplist"
  "test-list"          "test-rculist"        "test-sha1"
  "test-csum"          "test-byte-order"     "test-packets"
  "test-random"        "test-barrier"        "test-atomic"
  "test-rcu"           "test-stopwatch"      "test-aa"
  "test-cmap check 1"  "test-ccmap check 1"  "test-bitmap check"
  "test-id-fpool check" "test-byteq basic")
foreach(_case IN LISTS OVSTEST_EXIT_CASES)
  separate_arguments(_argv UNIX_COMMAND "${_case}")
  string(REPLACE " " "_" _tname "ovstest_${_case}")
  add_test(NAME ${_tname} COMMAND ovstest ${_argv})
  set_tests_properties(${_tname} PROPERTIES ENVIRONMENT_MODIFICATION "${_ovstest_dll_path}")
endforeach()

# /Zc:inline- registration canary: a stripped OVS_CONSTRUCTOR => empty module list.
add_test(NAME ovstest-help COMMAND ovstest --help)
set_tests_properties(ovstest-help PROPERTIES
  PASS_REGULAR_EXPRESSION "test-hash"
  ENVIRONMENT_MODIFICATION "${_ovstest_dll_path}")

# dpif-windows provider unit test (mock kernel; ASAN under -DOVS_ASAN=ON).
add_test(NAME test-dpif-windows COMMAND test-dpif-windows)
set_tests_properties(test-dpif-windows PROPERTIES ENVIRONMENT_MODIFICATION "${_ovstest_dll_path}")

# ---- standalone test programs the .at build-smoke suite invokes ------------
# test-ovsdb drives the ovsdb-*.at "C" variants via the generated idltest IDL.
add_executable(test-ovsdb tests/test-ovsdb.c ${GEN}/tests/idltest.c)
ovs_setup(test-ovsdb)
target_link_directories(test-ovsdb PRIVATE ${OVS_EXT_LIBDIRS})
target_link_libraries(test-ovsdb PRIVATE ovsdb openvswitch libssl libcrypto pthreadVC3 ${OVS_SYS_LIBS})

foreach(_t test-stream test-type-props test-lib)
  add_executable(${_t} tests/${_t}.c)
  ovs_setup(${_t})
  target_link_directories(${_t} PRIVATE ${OVS_EXT_LIBDIRS})
  target_link_libraries(${_t} PRIVATE openvswitch libssl libcrypto pthreadVC3 ${OVS_SYS_LIBS})
endforeach()

add_executable(test-strtok_r tests/test-strtok_r.c)
ovs_setup(test-strtok_r)
target_link_directories(test-strtok_r PRIVATE ${OVS_EXT_LIBDIRS})
target_link_libraries(test-strtok_r PRIVATE openvswitch libssl libcrypto pthreadVC3 ${OVS_SYS_LIBS})
