# Copyright (c) 2022 Cisco and/or its affiliates.

cmake_minimum_required(VERSION 3.9)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

#Required for VAPI header generation

project(vcdp)

if(NOT DEFINED CMAKE_INSTALL_LIBDIR AND EXISTS "/etc/debian_version")
  set(CMAKE_INSTALL_LIBDIR "lib/${CMAKE_LIBRARY_ARCHITECTURE}")
endif()
set(VPP_BINARY_DIR ${CMAKE_BINARY_DIR}/CMakeFiles)
set(VPP_LIBRARY_DIR ${CMAKE_INSTALL_LIBDIR} CACHE STRING "Relative library directory path")
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
find_package(VPP)

##############################################################################
# sanitizers
##############################################################################

option(VCDP_SANITIZE_ADDR "Enable Address Sanitizer" OFF)
set(VCDP_SANITIZE_ADDR_OPTIONS
  "unmap_shadow_on_exit=1:disable_coredump=0:abort_on_error=1:detect_leaks=0"
  CACHE
  STRING "Address sanitizer arguments"
)
add_compile_options(-Werror -Wall)

# Add this line to find the CBOR library
include(FetchContent)

# Find libcbor using pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBCBOR REQUIRED libcbor)

if (VCDP_SANITIZE_ADDR)
  add_compile_options(-fsanitize=address -fsanitize=undefined)
  add_compile_definitions(CLIB_SANITIZE_ADDR)
  set(CMAKE_EXE_LINKER_FLAGS "-fsanitize=address ${CMAKE_EXE_LINKER_FLAGS}")
  set(CMAKE_SHARED_LINKER_FLAGS "-fsanitize=address ${CMAKE_SHARED_LINKER_FLAGS}")
endif (VCDP_SANITIZE_ADDR)

include(CTest)

file(STRINGS "${VPP_INCLUDE_DIR}/vpp/app/version.h" VERSION_H_CONTENTS REGEX "#define VPP_BUILD_VER .+")
if (VERSION_H_CONTENTS)
  string(REGEX REPLACE "#define VPP_BUILD_VER " "" CPACK_PACKAGE_VERSION "${VERSION_H_CONTENTS}")
endif()
string(REPLACE "\"" "" CPACK_PACKAGE_VERSION ${CPACK_PACKAGE_VERSION})
message(STATUS, "CPACK_PACKAGE_VERSION: ${CPACK_PACKAGE_VERSION}")

set(CPACK_PACKAGE_NAME "nataasvpp")
set(CPACK_PACKAGE_VENDOR "Cisco Systems Inc")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
	"NATaaS/VPP Plugin")
set(CPACK_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION})
set(CPACK_PACKAGE_CONTACT "otroan@employees.org")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Ole Troan")
include(CPack)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

# include_directories(${CMAKE_BINARY_DIR})


# Copyright (c) 2022 Cisco and/or its affiliates.

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_BINARY_DIR})

include(cmake/counter.cmake)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

# Install scapy in the virtual environment
message(STATUS "Python executable: ${Python3_EXECUTABLE}")
message(STATUS "Python libraries: ${Python3_LIBRARIES}")
execute_process(COMMAND ${Python3_EXECUTABLE} -m pip install scapy)
include_directories(${Python3_INCLUDE_DIRS})

# Print out the path to the Python executable

add_vpp_plugin(vcdp
  VAT_AUTO_TEST OFF

  SOURCES
  vcdp/plugin.c
  vcdp/cli.c
  vcdp/api.c
  # vcdp_services/tcp-check/cli.c
  # vcdp_services/tcp-check/api.c
  vcdp_services/nat/cli.c
  vcdp_services/nat/api.c
  gateway/cli.c
  gateway/api.c
  vcdp_services/tcp-mss/api.c

  vcdp/lookup/node.c
  vcdp/session.c
  vcdp/create.c
  vcdp/drop/node.c
  vcdp/format.c
  vcdp/vcdp.c
  vcdp/service.c
  vcdp/export.c
  vcdp/bypass/node.c
  vcdp/vcdp_counter.json.c
  vcdp/icmp/icmp4.c
  vcdp/icmp/node.c

  # vcdp_services/tcp-check/node.c
  # vcdp_services/tcp-check/tcp_check.c
  # vcdp_services/tcp-check/format.c

  vcdp_services/tcp-check-lite/api.c
  vcdp_services/tcp-check-lite/node.c
  vcdp_services/tcp-check-lite/tcp_check_lite.c

  vcdp_services/l4-lifecycle/api.c
  vcdp_services/l4-lifecycle/node.c

  vcdp_services/nat/nat.c
  vcdp_services/nat/format.c
  vcdp_services/nat/fastpath_node.c
  vcdp_services/nat/slowpath_node.c
  vcdp_services/nat/icmp_error_node.c
  vcdp_services/nat/nat64_icmp_error.c
  vcdp_services/nat/nat_counter.json.c
  vcdp_services/nat/vcdp_nat_dpo.c

  vcdp_services/nat/nat64_slowpath.c
  vcdp_services/nat/nat64_fastpath.c

  gateway/gateway.c
  gateway/interface.c
  gateway/vcdp_dpo.c
  gateway/tunnel/tunnel.c
  gateway/tunnel/node.c

  vcdp_services/tcp-mss/tcp_mss.c
  vcdp_services/tcp-mss/node.c

  # Unit tests
  unittest/vcdp_unittest.c
  unittest/scapy.c

  # vcdp_services/stats/api.c
  # vcdp_services/stats/stats.c
  # vcdp_services/stats/node.c

  API_FILES
  vcdp/vcdp_types.api
  vcdp/vcdp.api
  vcdp_services/nat/nat.api
  vcdp_services/tcp-check/tcp_check.api
  gateway/gateway.api
  vcdp_services/tcp-mss/tcp_mss.api
  vcdp_services/l4-lifecycle/l4_lifecycle.api
  vcdp_services/tcp-check-lite/tcp_check_lite.api
  vcdp_services/stats/stats.api

  LINK_LIBRARIES cbor
  LINK_LIBRARIES ${Python3_LIBRARIES}
  INSTALL_HEADERS
  vcdp/vcdp.h
  vcdp/service.h
  vcdp/vcdp_funcs.h
  vcdp/vcdp_types_funcs.h
  vcdp/common.h
  vcdp/timer.h
)
add_dependencies(vcdp_plugin vcdp_plugin_api_headers)
add_vpp_counters(
  COUNTERS
  vcdp_services/nat/nat_counter.json
  vcdp/vcdp_counter.json
)

# find_library(VPPINFRA_LIBRARY vppinfra)
# find_library(VLIB_LIBRARY vlib)
# add_compile_options(-Werror -Wall)
# # add_compile_options(-fsanitize=address)
# # set(CMAKE_EXE_LINKER_FLAGS "-fsanitize=address ${CMAKE_EXE_LINKER_FLAGS}")
# # set(CMAKE_SHARED_LINKER_FLAGS "-fsanitize=address ${CMAKE_SHARED_LINKER_FLAGS}")
# #set(CMAKE_C_CLANG_TIDY clang-tidy -checks=-*,readability-*,-readability-identifier-length)
# # add_executable(test_tunnel gateway/tunnel/test.c gateway/tunnel/tunnel.c gateway/tunnel/node.c)
# add_executable(test_tunnel test/test.c test/test_tcp_state.c)
# target_link_libraries(test_tunnel vcdpcore ${VPPINFRA_LIBRARY} ${VLIB_LIBRARY})
# add_test(NAME test_tunnel
#          COMMAND test_tunnel)
