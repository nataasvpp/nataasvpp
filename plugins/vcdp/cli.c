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
 * set vcdp services tenant <tenant-id> (SERVICE_NAME)+ <forward|reverse>
 *
 * configure tenant with a service chain for a given direction (forward or
 * reverse)
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
  u32 context_id = ~0;
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add %d", &tenant_id))
	is_del = 0;
      else if (unformat (line_input, "del %d", &tenant_id))
	is_del = 1;
      else if (unformat (line_input, "context %d", &context_id))
	;
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
  if (context_id == ~0)
    context_id = tenant_id;
  err = vcdp_tenant_add_del (vcdp, tenant_id, context_id, is_del);
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
      else if (unformat_user (line_input, unformat_vcdp_service_bitmap,
			      &bitmap))
	;
      else if (unformat (line_input, "forward"))
	direction = VCDP_FLOW_FORWARD;
      else if (unformat (line_input, "reverse"))
	direction = VCDP_FLOW_REVERSE;
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
vcdp_set_timeout_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  vcdp_main_t *vcdp = &vcdp_main;
  u32 tenant_id = ~0;
  u32 timeout_idx = ~0;
  u32 timeout_val = ~0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "tenant %d", &tenant_id))
	;
#define _(x, y, z)                                                            \
  else if (unformat (line_input, z " %d", &timeout_val)) timeout_idx =        \
    VCDP_TIMEOUT_##x;
      foreach_vcdp_timeout
#undef _
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
  if (timeout_idx == ~0)
    {
      err = clib_error_return (0, "missing timeout");
      goto done;
    }

  err = vcdp_set_timeout (vcdp, tenant_id, timeout_idx, timeout_val);
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
  vcdp_tenant_t *tenant;
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
	    tenant = vcdp_tenant_at_index (vcdp, session->tenant_idx);
	    if (tenant_id != ~0 && tenant_id != tenant->tenant_id)
	      continue;
	    if (first)
	      {
		first = 0;
		vlib_cli_output (vm, "Thread #%d:", thread_index);
		vlib_cli_output (vm, "id\t\t\ttenant\tindex\ttype\t"
				     "prot\tcontext\tingress\t\t\t->"
				     "\tegress\t\t\tstate\t\tTTL(s)");
	      }
	    vlib_cli_output (vm, "%U", format_vcdp_session,
			     session - ptd->sessions, session,
			     tenant->tenant_id, now);
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
    err = clib_error_return (0, "No session id provided");

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

static clib_error_t *
vcdp_show_tenant_detail_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_tenant_t *tenant;
  u32 tenant_id = ~0;
  u16 tenant_idx;
  u8 detail = 0;
  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "%d detail", &tenant_id))
	    detail = 1;
	  else if (unformat (line_input, "%d", &tenant_id))
	    ;
	  else
	    {
	      err = unformat_parse_error (line_input);
	      break;
	    }
	}
      unformat_free (line_input);
    }
  if (err)
    return err;

  pool_foreach_index (tenant_idx, vcdp->tenants)
    {
      tenant = vcdp_tenant_at_index (vcdp, tenant_idx);

      if (tenant_id != ~0 && tenant->tenant_id != tenant_id)
	continue;

      vlib_cli_output (vm, "Tenant %d", tenant->tenant_id);
      vlib_cli_output (vm, "  %U", format_vcdp_tenant, vcdp, tenant_idx,
		       tenant);
      if (detail)
	vlib_cli_output (vm, "  %U", format_vcdp_tenant_extra, vcdp,
			 tenant_idx, tenant);
    }

  return err;
}

VLIB_CLI_COMMAND (vcdp_tenant_add_del_command, static) = {
  .path = "vcdp tenant",
  .short_help = "vcdp tenant <add|del> <tenant-id> context <context-id>",
  .function = vcdp_tenant_add_del_command_fn,
};

VLIB_CLI_COMMAND (vcdp_set_services_command, static) = {
  .path = "set vcdp services",
  .short_help = "set vcdp services tenant <tenant-id>"
		" [SERVICE_NAME]+ <forward|reverse>",
  .function = vcdp_set_services_command_fn,
};

VLIB_CLI_COMMAND (show_vcdp_sessions_command, static) = {
  .path = "show vcdp session-table",
  .short_help = "show vcdp session-table [tenant <tenant-id>]",
  .function = vcdp_show_sessions_command_fn,
};

VLIB_CLI_COMMAND (show_vcdp_detail_command, static) = {
  .path = "show vcdp session-detail",
  .short_help = "show vcdp session-detail 0x<session-id>",
  .function = vcdp_show_session_detail_command_fn,
};

VLIB_CLI_COMMAND (show_vcdp_tenant, static) = {
  .path = "show vcdp tenant",
  .short_help = "show vcdp tenant [<tenant-id> [detail]]",
  .function = vcdp_show_tenant_detail_command_fn,
};

VLIB_CLI_COMMAND (vcdp_set_timeout_command, static) = {
  .path = "set vcdp timeout",
  .short_help = "set vcdp timeout tenant <tenant-id>"
		" <timeout-name> <timeout-value>",
  .function = vcdp_set_timeout_command_fn
};
