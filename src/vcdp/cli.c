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
#include <vcdp/service.h>
/*
 * add CLI:
 * vcdp tenant <add/del> <tenant-id>
 *
 * it creates entry in the tenant pool. Default service chains in both
 * directions is "vcdp-drop"
 *
 *
 * add CLI:
 * set vcdp services tenant <tenant-id> (SERVICE_NAME)+ <forward|backwards>
 *
 * configure tenant with a service chain for a given direction (forward or
 * backwards)
 *
 */

static clib_error_t *
vcdp_tenant_add_del_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  vcdp_main_t *vcdp = &vcdp_main;
  u8 is_del = 0;
  u32 tenant_id = ~0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add %d", &tenant_id))
	is_del = 0;
      else if (unformat (line_input, "del %d", &tenant_id))
	is_del = 1;
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }
  if (tenant_id == ~0)
    {
      err = clib_error_return (0, "missing tenant id");
      goto done;
    }
  err = vcdp_tenant_add_del (vcdp, tenant_id, is_del);
done:
  unformat_free (line_input);
  return err;
}

static clib_error_t *
vcdp_set_services_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  vcdp_main_t *vcdp = &vcdp_main;
  u32 tenant_id = ~0;
  u32 bitmap = 0;
  u8 direction = ~0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "tenant %d", &tenant_id))
	;
#define _(n, s, idx) else if (unformat (line_input, (s))) bitmap |= 1 << (idx);

      foreach_vcdp_service
#undef _
	else if (unformat (line_input, "forward")) direction =
	  VCDP_FLOW_FORWARD;
      else if (unformat (line_input, "backwards")) direction =
	VCDP_FLOW_BACKWARD;
    }
  if (tenant_id == ~0)
    {
      err = clib_error_return (0, "missing tenant id");
      goto done;
    }
  if (direction == (u8) ~0)
    {
      err = clib_error_return (0, "missing direction");
      goto done;
    }
  vcdp_set_services (vcdp, tenant_id, bitmap, direction);
done:
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (vcdp_tenant_add_del_command, static) = {
  .path = "vcdp tenant",
  .short_help = "vcdp tenant <add|del> <tenant-id>",
  .function = vcdp_tenant_add_del_command_fn,
};

VLIB_CLI_COMMAND (vcdp_set_services_command, static) = {
  .path = "set vcdp services",
  .short_help = "set vcdp services tenant <tenant-id>"
		" [SERVICE_NAME]+ <forward|backwards>",
  .function = vcdp_set_services_command_fn,
};

/*
static clib_error_t *
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
};
*/