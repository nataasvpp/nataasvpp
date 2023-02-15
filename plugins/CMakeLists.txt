# Copyright (c) 2022 Cisco and/or its affiliates.

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_BINARY_DIR})

include(cmake/counter.cmake)
#
# Core VCDP library. None of these files can depend on APIs
#
add_vpp_library(vcdpcore
  SOURCES
  vcdp/lookup/node.c
  vcdp/drop/node.c
  vcdp/format.c
  vcdp/vcdp.c
  vcdp/service.c
  vcdp/timer/node.c
  vcdp/bypass/node.c
  vcdp/vcdp_counter.json.c


  vcdp_services/tcp-check/node.c
  vcdp_services/tcp-check/tcp_check.c
  vcdp_services/tcp-check/format.c

  vcdp_services/tcp-check-lite/node.c
  vcdp_services/tcp-check-lite/tcp_check_lite.c

  vcdp_services/l4-lifecycle/node.c

  vcdp_services/nat/nat.c
  vcdp_services/nat/format.c
  vcdp_services/nat/fastpath_node.c
  vcdp_services/nat/slowpath_node.c
  vcdp_services/nat/icmp_error_node.c
  vcdp_services/nat/vcdp_nat_dpo.c
  vcdp_services/nat/nat_counter.json.c

  gateway/gateway.c
  gateway/interface.c
  gateway/tunnel/tunnel.c
  gateway/tunnel/node.c

  vcdp_services/tcp-mss/tcp_mss.c
  vcdp_services/tcp-mss/node.c


  INSTALL_HEADERS
  vcdp/vcdp.h
  vcdp/service.h
  vcdp/vcdp_funcs.h
  vcdp/vcdp_types_funcs.h
  vcdp/common.h
  vcdp/timer/timer.h
)

add_vpp_plugin(vcdp
  SOURCES
  vcdp/plugin.c
  vcdp/cli.c
  vcdp/api.c
  vcdp_services/tcp-check/cli.c
  vcdp_services/tcp-check/api.c
  vcdp_services/nat/cli.c
  vcdp_services/nat/api.c
  gateway/cli.c
  gateway/api.c
  vcdp_services/tcp-mss/api.c

  API_FILES
  vcdp/vcdp_types.api
  vcdp/vcdp.api
  vcdp_services/nat/nat.api
  vcdp_services/tcp-check/tcp_check.api
  gateway/gateway.api
  vcdp_services/tcp-mss/tcp_mss.api

  # DEPENDS
  # vcdp_api_headers

  LINK_LIBRARIES
  vcdpcore

)

add_vpp_counters(
  COUNTERS
  vcdp_services/nat/nat_counter.json
  vcdp/vcdp_counter.json
)

# add_vpp_library(vcdp
#   SOURCES

#   INSTALL_HEADERS

#   ####################
#   # This is a hack   #
#   # remove when VPP  #
#   # fixed            #
#   ####################
#   # DEPENDS
#   # vcdp_api_headers
# )


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
