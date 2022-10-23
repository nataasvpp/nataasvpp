# Copyright (c) 2022 Cisco and/or its affiliates.

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_BINARY_DIR})

add_vpp_library(vcdp
  SOURCES
  vcdp/lookup/node.c
  vcdp/lookup/sv_reass_node.c
  vcdp/drop/node.c
  vcdp/format.c
  vcdp/vcdp.c
  vcdp/service.c
  vcdp/cli.c
  vcdp/api.c
  vcdp/timer/node.c

  MULTIARCH_SOURCES
  vcdp/lookup/node.c
  vcdp/lookup/sv_reass_node.c
  vcdp/drop/node.c

  API_FILES
  vcdp/vcdp_types.api
  vcdp/vcdp.api

  INSTALL_HEADERS
  vcdp/vcdp.h
  vcdp/service.h
  vcdp/vcdp_funcs.h
  vcdp/vcdp_types_funcs.h
  vcdp/common.h
  vcdp/timer/timer.h

  ####################
  # This is a hack   #
  # remove when VPP  #
  # fixed            #
  ####################
  DEPENDS
  vcdp_api_headers
)

add_vpp_test_library(vcdp
  vcdp/vcdp_types.api
  vcdp/vcdp.api
)

add_vpp_plugin(vcdp_gateway
  SOURCES
  vcdp_services/tcp-check/node.c
  vcdp_services/tcp-check/tcp_check.c
  vcdp_services/tcp-check/format.c
  vcdp_services/tcp-check/cli.c
  vcdp_services/tcp-check/api.c

  vcdp_services/l4-lifecycle/node.c

  vcdp_services/nat/nat.c
  vcdp_services/nat/cli.c
  vcdp_services/nat/api.c
  vcdp_services/nat/format.c
  vcdp_services/nat/fastpath_node.c
  vcdp_services/nat/slowpath_node.c

  dummy/dot1q.c

  gateway/gateway.c
  gateway/cli.c
  gateway/api.c
  gateway/interface.c
  gateway/tunnel/tunnel.c
  gateway/tunnel/node.c

  MULTIARCH_SOURCES
  vcdp_services/tcp-check/node.c
  vcdp_services/l4-lifecycle/node.c
  dummy/dot1q.c

  API_FILES
  vcdp_services/nat/nat.api
  vcdp_services/tcp-check/tcp_check.api
  gateway/gateway.api

  LINK_LIBRARIES
  vcdp
)

find_library(VPPINFRA_LIBRARY vppinfra)
find_library(VLIB_LIBRARY vlib)
#VPP_LIBRARY_DIR
add_compile_options(-Werror -Wall)
message(STATUS "foo include dir: ${VPP_LIBRARY_DIR}")
message(STATUS "foo include dir: ${VPPINFRA_LIBRARY}")
message(STATUS "foo include dir: ${VLIB_LIBRARY}")
#set(CMAKE_C_CLANG_TIDY clang-tidy -checks=-*,readability-*)
add_executable(test_tunnel gateway/tunnel/test.c gateway/tunnel/test_stubs.c gateway/tunnel/tunnel.c gateway/tunnel/node.c)
target_link_libraries(test_tunnel ${VPPINFRA_LIBRARY} ${VLIB_LIBRARY})
add_test(NAME test_tunnel
         COMMAND test_tunnel)
