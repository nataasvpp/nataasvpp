/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <gateway/gateway.h>
#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>

/*
 * add CLI:
 * set gateway geneve-output tenant <tenant-id> src <src ip> dst <dst ip>
 *      src-port <src-port> dst-port <dst-port> <forward|backward>
 *
 * it sets the geneve output data in each direction
 */

static clib_error_t *
gateway_set_output_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
    }
  return 0;
}

VLIB_CLI_COMMAND (gateway_set_output_command, static) = {
  .path = "set gateway geneve-output",
  .short_help = "set gateway geneve-output tenant <tenant-id> "
		"src <src ip> dst <dst ip> "
		"src-port <src-port> dst-port <dst-port> "
		"<forward|backward>",
  .function = gateway_set_output_command_fn,
};

/*static clib_error_t *
show_gateway_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  gw_main_t *gm = &gateway_main;
  gw_per_thread_data_t *ptd;
  int verbose = 0, i;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      clib_error_t *err = 0;
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	if (unformat (line_input, "verbose"))
	  verbose = 1;
	else
	  {
	    err = clib_error_return (0, "invalid params");
	    break;
	  }
      unformat_free (line_input);
      if (err)
	return err;
    }

  vlib_cli_output (vm, "%U", format_bihash_24_8, &gm->table4, 0);
  vec_foreach (ptd, gm->per_thread_data)
    {
      vlib_cli_output (vm, "Thread %u: %u sessions\n",
		       ptd - gm->per_thread_data, pool_elts (ptd->sessions));
      if (verbose)
	pool_foreach_index (i, ptd->sessions)
	  {
	    gw_session_t *session = pool_elt_at_index (ptd->sessions, i);
	    vlib_cli_output (vm, "%7u: %U\n", i, format_gw_session, session);
	  }
    }

  return 0;
}

VLIB_CLI_COMMAND (show_flow_handoff, static) = {
  .path = "show vcdp gateway",
  .short_help = "show vcdp gateway",
  .function = show_gateway_command_fn,
}; */
