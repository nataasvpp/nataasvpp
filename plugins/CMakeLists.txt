# Copyright (c) 2018 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_vpp_plugin(vcdp_gateway
  SOURCES
  vcdp/lookup/node.c

  vcdp/drop/node.c

  vcdp_services/tcp-check/node.c
  vcdp_services/tcp-check/tcp_check.c
  vcdp_services/tcp-check/format.c
  vcdp_services/tcp-check/cli.c
  vcdp_services/tcp-check/api.c

  vcdp/timer/node.c

  vcdp_services/l4-lifecycle/node.c

  vcdp_services/nat/nat.c
  vcdp_services/nat/cli.c
  vcdp_services/nat/api.c
  vcdp_services/nat/format.c
  vcdp_services/nat/fastpath_node.c
  vcdp_services/nat/slowpath_node.c
  vcdp_services/nat/external_input_node.c

#  vcdp_services/sample/node.c

  vcdp/format.c
  vcdp/vcdp.c
  vcdp/service.c
  vcdp/cli.c
  vcdp/api.c
  dummy/dot1q.c

  gateway/gateway.c
  gateway/cli.c
  gateway/api.c
  gateway/geneve_input/node.c
  gateway/geneve_output/node.c

  MULTIARCH_SOURCES
  vcdp/lookup/node.c
  vcdp/drop/node.c
  vcdp_services/tcp-check/node.c
  vcdp_services/l4-lifecycle/node.c
  gateway/geneve_input/node.c
  gateway/geneve_output/node.c
  dummy/dot1q.c

  API_FILES
  vcdp/vcdp_types.api
  vcdp/vcdp.api
  vcdp_services/nat/nat.api
  vcdp_services/tcp-check/tcp_check.api
  gateway/gateway.api
)
