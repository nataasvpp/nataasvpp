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
gateway_geneve_enable_disable_command_fn (vlib_main_t *vm,
					  unformat_input_t *input,
					  vlib_cli_command_t *cmd)
{
  int enable_disable = -1;
  gw_enable_disable_geneve_input_args_t args;
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  args.sw_if_index = ~0;
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "interface %U", unformat_vnet_sw_interface,
		    vnet_get_main (), &args.sw_if_index))
	;
      else if (unformat (line_input, "enable"))
	enable_disable = 1;
      else if (unformat (line_input, "disable"))
	enable_disable = 0;
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }
  if (enable_disable == -1)
    {
      err = clib_error_return (0, "enable or disable?");
      goto done;
    }
  if (args.sw_if_index == ~0)
    {
      err = clib_error_return (0, "valid interface name required");
      goto done;
    }
  args.enable_disable = enable_disable;
  gw_enable_disable_geneve_input (&args);
  err = args.err;

done:
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (gateway_geneve_input_enable_disable_command, static) = {
  .path = "gateway geneve-input",
  .short_help = "gateway geneve-input interface <ifname> <enable|disable>",
  .function = gateway_geneve_enable_disable_command_fn,
};