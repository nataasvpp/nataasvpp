/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <gateway/gateway.h>

/*
 * Add CLI:
 *  gateway geneve-input interface <ifname> <enable-disable>
 *
 *  calls udp_register_dst_port for vcdp-geneve-input node
 */

static clib_error_t *
gateway_enable_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
    }
  return 0;
}

VLIB_CLI_COMMAND (gateway_geneve_input_enable_disable_command, static) = {
  .path = "gateway geneve-input",
  .short_help = "gateway geneve-input interface <ifname> <enable|disable>",
  .function = gateway_enable_disable_command_fn,
};