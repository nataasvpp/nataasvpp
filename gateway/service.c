/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <gateway/service.h>
#include <gateway/gateway.h>
u8 vcdp_base_next_index;

void
vcdp_service_init (vlib_main_t *vm)
{
  u32 idx[VCDP_SERVICE_N];
#define _(x, y, z)                                                            \
  if (vlib_get_node_by_name (vm, (u8 *) (y)))                                 \
    idx[z] = vlib_node_add_named_next (vm, gw_lookup_node.index, (y));        \
  else                                                                        \
    idx[z] = vlib_node_add_named_next (vm, gw_lookup_node.index, "vcdp-drop");

  foreach_service
#undef _
    vcdp_base_next_index = idx[VCDP_SERVICE_DROP];
}