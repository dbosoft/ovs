# Source-list drift guard for the CMake `ovstest` target.
#
# The CMake overlay hand-maintains OVSTEST_SOURCES (it cannot read the autotools
# tests/automake.mk).  The `ovstest --help` runtime canary catches a *removed*
# module, but not upstream *adding* a new tests/test-*.c + OVSTEST_REGISTER that
# our list silently lacks -- that loses coverage with no signal.  This guard
# fails configuration if any tests/test-*.c that registers an ovstest module is
# absent from OVSTEST_SOURCES, modulo the documented platform exclusions that
# mirror the `if !WIN32` / `if LINUX` blocks in tests/automake.mk.
#
# Requires OVSTEST_SOURCES to be set by the caller (CMakeLists.txt).

# Excluded on purpose (built into the autotools ovstest only on other platforms):
set(_ovstest_excluded
  test-unix-socket.c          # tests/automake.mk: if !WIN32
  test-lib-route-table.c      # tests/automake.mk: if LINUX
  test-netlink-conntrack.c    # tests/automake.mk: if LINUX
  test-netlink-policy.c       # tests/automake.mk: if LINUX
  test-psample.c)             # tests/automake.mk: if LINUX

# Names already in our target source list.
set(_ovstest_have "")
foreach(_s ${OVSTEST_SOURCES})
  get_filename_component(_n "${_s}" NAME)
  list(APPEND _ovstest_have "${_n}")
endforeach()

file(GLOB _ovstest_all "${CMAKE_CURRENT_SOURCE_DIR}/tests/test-*.c")
set(_ovstest_missing "")
foreach(_f ${_ovstest_all})
  file(READ "${_f}" _txt)
  if(_txt MATCHES "OVSTEST_REGISTER")
    get_filename_component(_base "${_f}" NAME)
    list(FIND _ovstest_have "${_base}" _h)
    list(FIND _ovstest_excluded "${_base}" _e)
    if(_h EQUAL -1 AND _e EQUAL -1)
      list(APPEND _ovstest_missing "${_base}")
    endif()
  endif()
endforeach()

if(_ovstest_missing)
  message(FATAL_ERROR
    "ovstest source-list drift: these tests/test-*.c register OVSTEST modules but "
    "are missing from OVSTEST_SOURCES in CMakeLists.txt. Add them to the target, or "
    "(if platform-specific) to the exclusion list in cmake/check-ovstest-list.cmake: "
    "${_ovstest_missing}")
endif()
