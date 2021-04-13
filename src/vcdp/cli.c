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

static clib_error_t *
vcdp_show_sessions_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_per_thread_data_t *ptd;
  vcdp_session_t *session;
  u32 thread_index;
  u32 tenant_id = ~0;
  u8 first;
  f64 now = vlib_time_now (vm);
  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "tenant %d", &tenant_id))
	    ;
	  else
	    {
	      err = unformat_parse_error (line_input);
	      break;
	    }
	}
      unformat_free (line_input);
    }

  if (!err)
    vec_foreach_index (thread_index, vcdp->per_thread_data)
      {
	ptd = vec_elt_at_index (vcdp->per_thread_data, thread_index);
	first = 1;
	pool_foreach (session, ptd->sessions)
	  {
	    if (tenant_id != ~0 && tenant_id != session->key.tenant_id)
	      continue;
	    if (first)
	      {
		first = 0;
		vlib_cli_output (vm, "Thread #%d:", thread_index);
		vlib_cli_output (
		  vm, "id\t\t\ttenant\tindex\ttype\t"
		      "prot\tingress\t\t\t-> egress\t\tstate\t\tTTL(s)");
	      }
	    vlib_cli_output (vm, "%U", format_vcdp_session,
			     session - ptd->sessions, session, now);
	  }
      }

  return err;
}

static clib_error_t *
vcdp_show_session_detail_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_per_thread_data_t *ptd;
  clib_bihash_kv_8_8_t kv = { 0 };
  u32 thread_index;
  f64 now = vlib_time_now (vm);
  u32 session_index;
  u64 session_id;
  if (unformat_user (input, unformat_line_input, line_input))
    {
      if (unformat_check_input (line_input) == UNFORMAT_END_OF_INPUT ||
	  unformat (line_input, "0x%X", sizeof (session_id), &session_id) == 0)
	err = unformat_parse_error (line_input);
      unformat_free (line_input);
    }
  else
    err = unformat_parse_error (line_input);

  if (!err)
    {
      kv.key = session_id;
      if (!clib_bihash_search_inline_8_8 (&vcdp->session_index_by_id, &kv))
	{
	  thread_index = vcdp_thread_index_from_lookup (kv.value);
	  session_index = vcdp_session_index_from_lookup (kv.value);
	  ptd = vec_elt_at_index (vcdp->per_thread_data, thread_index);
	  vlib_cli_output (vm, "%U", format_vcdp_session_detail, ptd,
			   session_index, now);
	}
      else
	{
	  err =
	    clib_error_return (0, "Session id 0x%llx not found", session_id);
	}
    }
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

VLIB_CLI_COMMAND (show_vcdp_sessions, static) = {
  .path = "show vcdp session-table",
  .short_help = "show vcdp session-table [tenant <tenant-id>]",
  .function = vcdp_show_sessions_command_fn,
};

VLIB_CLI_COMMAND (show_vcdp_detail, static) = {
  .path = "show vcdp session-detail",
  .short_help = "show vcdp session-detail 0x<session-id>",
  .function = vcdp_show_session_detail_command_fn,
};
