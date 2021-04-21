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
  vcdp/tcp-check/node.c
  vcdp/tcp-check/tcp_check.c
  vcdp/tcp-check/format.c
  vcdp/tcp-check/cli.c
  vcdp/timer/node.c
  vcdp/l4-lifecycle/node.c
  vcdp/format.c
  vcdp/vcdp.c
  vcdp/cli.c
  dummy/dot1q.c

  gateway/gateway.c
  gateway/cli.c
  gateway/geneve_input/node.c
  gateway/geneve_input/cli.c
  gateway/geneve_output/node.c

  MULTIARCH_SOURCES
  vcdp/lookup/node.c
  vcdp/drop/node.c
  vcdp/tcp-check/node.c
  vcdp/l4-lifecycle/node.c
  gateway/geneve_input/node.c
  gateway/geneve_output/node.c
  dummy/dot1q.c
)
